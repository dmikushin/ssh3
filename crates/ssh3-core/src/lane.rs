//! Reliable, resumable lanes with absolute credit limits (SPEC §4, §5).
//!
//! One `Lane` is one bidirectional byte conversation. Per direction:
//!
//! * **sender**: `sbuf` holds bytes read from the local source that the peer
//!   has not yet `accepted` (`[sbase, send_end)`). The source is read only
//!   while the lane holds peer credit (`send_end < peer_limit`) and the
//!   server-wide send budget has room. Bytes are kept until accepted so a
//!   resume can resend from the peer's accepted offset.
//! * **receiver**: `rbuf` holds bytes read from QUIC but not yet delivered
//!   to the local sink (`[delivered, received)`). The receiver advertises an
//!   absolute, monotone `limit = delivered + granted` with
//!   `limit − delivered ≤ ring capacity`, so the ring cannot overflow. QUIC
//!   streams are read unconditionally (never waiting on the sink); a byte at
//!   or beyond `limit` is a protocol error. Connection credit is therefore
//!   never held hostage by a stalled sink (review D2).
//!
//! Lane state is session state and survives carrier death. Tasks bound to a
//! carrier's QUIC streams carry an `epoch`; a resume bumps it under the lock
//! that snapshots `received`, fencing off stragglers of the old carrier.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};

use crate::budget::{Budget, Permit};
use crate::error::{Error, Result, close};
use crate::frame;
use crate::msg::{LaneHeader, LanePos, Message};
use crate::ring::{CHUNK, ChunkPermit, ChunkSlice, Ring, Tail};

/// Chunks a lane may hold beyond the budget: enough to store its floor grant
/// (16 KiB, which may straddle two chunks) so that budget exhaustion caused
/// by other sessions never starves a lane's floor (SPEC §4).
const RECV_FLOOR_CHUNKS: u32 = 2;
/// One chunk so every lane — in particular the session event lane — can
/// always make progress on its send side.
const SEND_FLOOR_CHUNKS: u32 = 1;
const CH: u64 = CHUNK as u64;

fn round_up(n: u64) -> u64 {
    n.div_ceil(CH) * CH
}

/// Byte counters (SPEC §8 I6) — the memory-bound tests assert on these.
#[derive(Default, Debug)]
pub struct Stats {
    pub send_ring_bytes: AtomicU64,
    pub recv_ring_bytes: AtomicU64,
    /// Σ (limit − delivered) over lanes: credit this side has outstanding.
    pub credit_outstanding: AtomicU64,
    pub channels: AtomicU64,
    pub lane_bytes_sent: AtomicU64,
    /// Current connection window (§1 scheduler), what is charged for it,
    /// and how often it was raised / lowered.
    pub conn_window: AtomicU64,
    pub conn_window_charged: AtomicU64,
    pub window_raises: AtomicU64,
    pub window_lowers: AtomicU64,
    /// §6: live UDP flows (channels), datagrams, drops, reassembly and LRU
    /// evictions.
    pub udp_flows: AtomicU64,
    pub dgrams_sent: AtomicU64,
    pub dgrams_received: AtomicU64,
    pub dgrams_dropped: AtomicU64,
    pub reasm_evicted: AtomicU64,
    pub udp_evicted: AtomicU64,
}

/// Lanes whose ack should be sent: `urgent` now, `lazy` on the next tick.
#[derive(Default)]
pub struct AckQueue {
    pub(crate) urgent: Mutex<Vec<Arc<Lane>>>,
    pub(crate) lazy: Mutex<Vec<Arc<Lane>>>,
    pub(crate) notify: Notify,
}

/// Shared parameters of every lane of a session.
#[derive(Clone)]
pub(crate) struct LaneEnv {
    pub cap: u64,
    pub floor: u64,
    pub ack_bytes: u64,
    pub ack_interval: Duration,
    pub stats: Arc<Stats>,
    pub acks: Arc<AckQueue>,
    /// Receive-ring chunk storage (LaneCreditBudget).
    pub recv_budget: Arc<Budget>,
    /// Send-ring chunk storage (LaneSendBudget).
    pub send_budget: Arc<Budget>,
    /// Floor chunks: not limited, counted for introspection.
    pub floor_budget: Arc<Budget>,
    /// Session event queue (LaneFin is an event, SPEC §5).
    pub events: mpsc::Sender<Message>,
}

/// A local source that can say "data is waiting" without a buffer, so an
/// idle source does not pin a budget chunk while it waits (SPEC §4: the
/// chunk is reserved before the read, so reserve only when a read will
/// return promptly).
pub(crate) trait Readable {
    fn readable(&self) -> impl std::future::Future<Output = std::io::Result<()>> + Send;
}

impl Readable for tokio::net::tcp::OwnedReadHalf {
    async fn readable(&self) -> std::io::Result<()> {
        tokio::net::tcp::OwnedReadHalf::readable(self).await
    }
}

impl Readable for tokio::net::unix::OwnedReadHalf {
    async fn readable(&self) -> std::io::Result<()> {
        tokio::net::unix::OwnedReadHalf::readable(self).await
    }
}

/// In-memory pipes and boxed process streams cannot report readiness
/// without a read: treated as ready (one floor chunk per such lane).
impl Readable for tokio::io::DuplexStream {
    fn readable(&self) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
        std::future::ready(Ok(()))
    }
}

impl Readable for Box<dyn tokio::io::AsyncRead + Send + Unpin> {
    fn readable(&self) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
        std::future::ready(Ok(()))
    }
}

impl Readable for tokio::io::Empty {
    fn readable(&self) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
        std::future::ready(Ok(()))
    }
}

/// SPEC §5 "pty lanes": what a pty output lane does when it cannot take
/// more bytes (no peer credit or no send budget). The terminal-emulator
/// crate implements screen mode; the default blocks (stream mode).
pub trait PtyOverflow: Send + Sync {
    /// The lane is full. `true`: keep reading the pty and pass the bytes to
    /// [`feed`](Self::feed) until the lane has room again (screen mode);
    /// `false`: stop reading the pty (backpressure).
    fn ring_full(&self) -> bool;
    /// Bytes read from the pty while the lane is full (screen mode only).
    fn feed(&self, bytes: &[u8]);
    /// The lane has room again after a full episode.
    fn ring_has_room(&self) {}
}

/// Stream mode only: a full lane blocks the pty.
pub struct BlockingOverflow;

impl PtyOverflow for BlockingOverflow {
    fn ring_full(&self) -> bool {
        false
    }
    fn feed(&self, _bytes: &[u8]) {}
}

/// A QUIC send stream that is **reset**, not finished, when dropped without
/// an explicit finish: quinn's `SendStream` finishes on drop, which would
/// look like a clean end to the peer.
pub(crate) struct LaneSend {
    s: Option<SendStream>,
}

impl LaneSend {
    fn get(&mut self) -> &mut SendStream {
        self.s.as_mut().expect("LaneSend used after finish")
    }
    fn finish(&mut self) {
        if let Some(mut s) = self.s.take() {
            let _ = s.finish();
        }
    }
}

impl Drop for LaneSend {
    fn drop(&mut self) {
        if let Some(mut s) = self.s.take() {
            let _ = s.reset(0u32.into());
        }
    }
}

struct LaneState {
    // ---- send direction
    sbuf: Ring,
    sbase: u64,
    sent_hi: u64,
    s_eof: bool,
    peer_limit: u64,
    send_from: u64,
    send_done: bool,
    sfloor: Arc<AtomicU32>,
    // ---- receive direction
    rbuf: Ring,
    delivered: u64,
    received: u64,
    limit: u64,
    granted: u64,
    /// Grant auto-tuning: start of the current epoch (in delivered bytes)
    /// and whether the sink drained the ring empty during it.
    epoch_start: u64,
    epoch_emptied: bool,
    /// Undelivered bytes have waited in the ring since this instant (set
    /// when the ring becomes non-empty, renewed by every delivery). A sink is
    /// stalled only if this is old while the ring is non-empty — merely not
    /// delivering while waiting for the network is not a stall.
    sink_progress: Instant,
    fin_offset: Option<u64>,
    sink_done: bool,
    /// Receive storage reserved (from `recv_budget`) for credit that is
    /// granted but not yet backed by chunks.
    reserve: Permit,
    rfloor: Arc<AtomicU32>,
    last_ack_accepted: u64,
    last_ack_limit: u64,
    queued_lazy: bool,
    queued_urgent: bool,
    // ---- lifecycle
    ever_attached: bool,
    epoch: u64,
    closed: bool,
}

pub struct Lane {
    pub chan_id: u64,
    pub lane: u8,
    env: LaneEnv,
    st: Mutex<LaneState>,
    wake_sender: Notify,
    wake_source: Notify,
    wake_sink: Notify,
    wake_rx: Notify,
    pub(crate) done: Notify,
    attach_tx: mpsc::UnboundedSender<(LaneSend, u64)>,
    attach_rx: Mutex<Option<mpsc::UnboundedReceiver<(LaneSend, u64)>>>,
    /// Set on pty output lanes (SPEC §5 hybrid pty lanes).
    overflow: Mutex<Option<Arc<dyn PtyOverflow>>>,
}

async fn wait_for<T>(n: &Notify, mut f: impl FnMut() -> Option<T>) -> T {
    loop {
        let fut = n.notified();
        tokio::pin!(fut);
        fut.as_mut().enable();
        if let Some(v) = f() {
            return v;
        }
        fut.await;
    }
}

impl Lane {
    pub(crate) fn new(chan_id: u64, lane: u8, env: LaneEnv) -> Arc<Self> {
        let (attach_tx, attach_rx) = mpsc::unbounded_channel();
        let floor = env.floor;
        env.stats.credit_outstanding.fetch_add(floor, Ordering::Relaxed);
        Arc::new(Self {
            chan_id,
            lane,
            st: Mutex::new(LaneState {
                sbuf: Ring::default(),
                sbase: 0,
                sent_hi: 0,
                s_eof: false,
                peer_limit: 0,
                send_from: 0,
                send_done: false,
                sfloor: Arc::new(AtomicU32::new(0)),
                rbuf: Ring::default(),
                delivered: 0,
                received: 0,
                limit: floor,
                granted: floor,
                epoch_start: 0,
                epoch_emptied: false,
                sink_progress: Instant::now(),
                fin_offset: None,
                sink_done: false,
                reserve: Permit::empty(env.recv_budget.clone()),
                rfloor: Arc::new(AtomicU32::new(0)),
                last_ack_accepted: 0,
                last_ack_limit: floor,
                queued_lazy: false,
                queued_urgent: false,
                ever_attached: false,
                epoch: 0,
                closed: false,
            }),
            env,
            wake_sender: Notify::new(),
            wake_source: Notify::new(),
            wake_sink: Notify::new(),
            wake_rx: Notify::new(),
            done: Notify::new(),
            attach_tx,
            attach_rx: Mutex::new(Some(attach_rx)),
            overflow: Mutex::new(None),
        })
    }

    pub(crate) fn set_overflow(&self, o: Arc<dyn PtyOverflow>) {
        *self.overflow.lock().unwrap() = Some(o);
    }

    /// Our send side is finished (all bytes accepted after EOF, or the peer
    /// completed the channel).
    pub(crate) fn send_complete(&self) -> bool {
        self.st.lock().unwrap().send_done
    }

    /// The absolute limit this side grants before any ack (ChannelOpen/Ok).
    pub fn initial_limit(&self) -> u64 {
        self.env.floor
    }

    pub(crate) fn set_peer_limit(&self, limit: u64) {
        let mut st = self.st.lock().unwrap();
        st.peer_limit = st.peer_limit.max(limit);
        drop(st);
        self.wake_source.notify_waiters();
        self.wake_sender.notify_waiters();
    }

    pub fn is_complete(&self) -> bool {
        let st = self.st.lock().unwrap();
        st.send_done && st.sink_done
    }

    fn wake_all(&self) {
        self.wake_sender.notify_waiters();
        self.wake_source.notify_waiters();
        self.wake_sink.notify_waiters();
        self.wake_rx.notify_waiters();
        self.done.notify_waiters();
    }

    /// Stop every task of this lane and give back its ring memory and
    /// budget permits.
    pub(crate) fn close(&self) {
        let mut st = self.st.lock().unwrap();
        if !st.closed {
            st.closed = true;
            self.env.stats.send_ring_bytes.fetch_sub(st.sbuf.len() as u64, Ordering::Relaxed);
            self.env.stats.recv_ring_bytes.fetch_sub(st.rbuf.len() as u64, Ordering::Relaxed);
            self.env.stats.credit_outstanding.fetch_sub(st.limit - st.delivered, Ordering::Relaxed);
            st.sbuf.clear();
            st.rbuf.clear();
            let n = st.reserve.amount();
            st.reserve.shrink(n);
        }
        drop(st);
        self.wake_all();
    }

    // ------------------------------------------------------------- credit

    /// Storage that can take bytes without touching the budget: the spare
    /// part of the tail chunk plus unused floor chunks.
    fn free_cover(&self, st: &LaneState) -> u64 {
        st.rbuf.tail_space() as u64 + (RECV_FLOOR_CHUNKS - st.rfloor.load(Ordering::Acquire)) as u64 * CH
    }

    /// Keep the receive reservation exactly covering outstanding credit and
    /// raise `limit` towards `delivered + granted` as far as storage can be
    /// reserved. `limit` never goes down (monotone credit).
    fn recompute_limit(&self, st: &mut LaneState) {
        let free = self.free_cover(st);
        // Release reservation beyond what the current credit needs.
        let need = round_up((st.limit - st.received).saturating_sub(free));
        if st.reserve.amount() > need {
            let n = st.reserve.amount() - need;
            st.reserve.shrink(n);
        }
        let target = st.delivered + st.granted;
        if target > st.limit {
            let need = round_up((target - st.received).saturating_sub(free));
            if need > st.reserve.amount() {
                let want = need - st.reserve.amount();
                let got = st.reserve.grow_upto(want);
                let partial = got % CH;
                st.reserve.shrink(partial);
            }
            let cover = free + st.reserve.amount();
            let new_limit = target.min(st.received + cover);
            if new_limit > st.limit {
                self.env.stats.credit_outstanding.fetch_add(new_limit - st.limit, Ordering::Relaxed);
                st.limit = new_limit;
                self.wake_rx.notify_waiters();
            }
        }
    }

    /// A chunk for the receive tail: from the lane's reservation, else a
    /// floor chunk. Credit is only granted when one of the two exists.
    fn recv_chunk(&self, st: &mut LaneState) -> Option<Tail> {
        if st.reserve.amount() >= CH {
            let p = st.reserve.split(CH);
            return Some(Tail::new(ChunkPermit { _permit: p, floor: None }));
        }
        floor_chunk(&self.env.floor_budget, &st.rfloor, RECV_FLOOR_CHUNKS)
    }

    /// Decide whether to ack: urgent if the limit rose by ≥ 1/4 of the grant
    /// (liveness) or accepted rose by ≥ 1/4 of capacity (send-ring release);
    /// lazy otherwise.
    fn ack_need(&self, st: &mut LaneState) -> Option<bool> {
        let limit_up = st.limit - st.last_ack_limit;
        let acc_up = st.received - st.last_ack_accepted;
        if limit_up >= (st.granted / 4).max(1) || acc_up >= self.env.ack_bytes {
            if st.queued_urgent {
                return None;
            }
            st.queued_urgent = true;
            Some(true)
        } else if (limit_up > 0 || acc_up > 0) && !st.queued_lazy {
            st.queued_lazy = true;
            Some(false)
        } else {
            None
        }
    }

    fn queue_ack(self: &Arc<Self>, urgent: Option<bool>) {
        match urgent {
            Some(true) => {
                self.env.acks.urgent.lock().unwrap().push(self.clone());
                self.env.acks.notify.notify_waiters();
            }
            Some(false) => self.env.acks.lazy.lock().unwrap().push(self.clone()),
            None => {}
        }
    }

    pub(crate) fn force_ack(self: &Arc<Self>) {
        self.st.lock().unwrap().queued_urgent = true;
        self.queue_ack(Some(true));
    }

    /// The `(accepted, limit)` to send now. Works on closed lanes too: the
    /// final ack of a completed lane must still go out.
    pub(crate) fn take_ack(&self) -> (u64, u64) {
        let mut st = self.st.lock().unwrap();
        st.queued_lazy = false;
        st.queued_urgent = false;
        st.last_ack_accepted = st.received;
        st.last_ack_limit = st.limit;
        (st.received, st.limit)
    }

    /// Sender side: LaneAck from the peer.
    pub(crate) fn on_ack(&self, accepted: u64, limit: u64) -> Result<()> {
        let mut st = self.st.lock().unwrap();
        if st.closed {
            return Ok(());
        }
        if accepted > st.sent_hi.max(st.sbase) {
            return Err(Error::Protocol(format!(
                "lane {}/{}: peer accepted {accepted} bytes but only {} were ever sent",
                self.chan_id, self.lane, st.sent_hi
            )));
        }
        // `accepted < sbase` is a stale ack, not a violation: a ChannelDone
        // event (event-lane stream) may overtake an earlier LaneAck (control
        // stream) — QUIC orders bytes within a stream, never across streams.
        let accepted = accepted.max(st.sbase);
        if limit < st.peer_limit {
            return Err(Error::Protocol(format!(
                "lane {}/{}: limit went down from {} to {limit}",
                self.chan_id, self.lane, st.peer_limit
            )));
        }
        self.release_accepted(&mut st, accepted);
        st.peer_limit = limit;
        drop(st);
        self.wake_source.notify_waiters();
        self.wake_sender.notify_waiters();
        self.done.notify_waiters();
        Ok(())
    }

    fn release_accepted(&self, st: &mut LaneState, accepted: u64) {
        let n = (accepted - st.sbase) as usize;
        st.sbuf.drain(n);
        st.sbase = accepted;
        self.env.stats.send_ring_bytes.fetch_sub(n as u64, Ordering::Relaxed);
        if st.s_eof && st.sbuf.is_empty() {
            st.send_done = true;
        }
    }

    /// Receiver side: the peer's LaneFin event.
    pub(crate) fn on_fin(&self, final_offset: u64) -> Result<()> {
        let mut st = self.st.lock().unwrap();
        if st.closed {
            return Ok(());
        }
        if final_offset < st.received || st.fin_offset.is_some_and(|f| f != final_offset) {
            return Err(Error::Protocol(format!(
                "lane {}/{}: LaneFin at {final_offset} but {} bytes already received",
                self.chan_id, self.lane, st.received
            )));
        }
        st.fin_offset = Some(final_offset);
        drop(st);
        self.wake_sink.notify_waiters();
        Ok(())
    }

    // ------------------------------------------------------------- resume

    /// Fence off tasks of the previous carrier and report our position.
    pub(crate) fn fence(&self) -> LanePos {
        let mut st = self.st.lock().unwrap();
        st.epoch += 1;
        LanePos { chan_id: self.chan_id, lane: self.lane, accepted: st.received, limit: st.limit }
    }

    /// Would the peer's position be acceptable? No mutation (resume is
    /// validated as a whole before the session is touched).
    pub(crate) fn check_resume(&self, p: &LanePos) -> Result<()> {
        let st = self.st.lock().unwrap();
        let send_end = st.sbase + st.sbuf.len() as u64;
        if p.accepted < st.sbase || p.accepted > send_end {
            return Err(Error::Protocol(format!(
                "lane {}/{}: peer accepted {} outside [{}, {send_end}]",
                self.chan_id, self.lane, p.accepted, st.sbase
            )));
        }
        if p.limit < st.peer_limit {
            return Err(Error::Protocol(format!(
                "lane {}/{}: resumed limit {} below the {} granted before",
                self.chan_id, self.lane, p.limit, st.peer_limit
            )));
        }
        Ok(())
    }

    /// Apply the peer's position after a resume.
    pub(crate) fn on_resume(&self, p: &LanePos) -> Result<()> {
        self.check_resume(p)?;
        let mut st = self.st.lock().unwrap();
        self.release_accepted(&mut st, p.accepted);
        st.peer_limit = p.limit;
        st.send_from = p.accepted;
        drop(st);
        self.wake_source.notify_waiters();
        self.done.notify_waiters();
        Ok(())
    }

    /// The peer completed this channel (ChannelDone event): it has accepted
    /// every byte we sent, so our send side is complete even if its final
    /// ack was lost with a carrier.
    /// The peer completed the channel: it will read nothing more from us, so
    /// our send side is finished (e.g. a session's stdin after the process
    /// exited) and the local source is no longer read.
    pub(crate) fn peer_done(&self) {
        let mut st = self.st.lock().unwrap();
        if st.closed {
            return;
        }
        st.s_eof = true;
        let end = st.sbase + st.sbuf.len() as u64;
        self.release_accepted(&mut st, end);
        st.send_done = true;
        drop(st);
        self.wake_source.notify_waiters();
        self.done.notify_waiters();
    }

    pub(crate) fn send_from(&self) -> u64 {
        self.st.lock().unwrap().send_from
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.st.lock().unwrap().epoch
    }

    // -------------------------------------------------------------- attach

    /// Attach a fresh stream pair. `send` already carries our header; `recv`
    /// is positioned after the peer's header, which announced
    /// `peer_offset_out` (must equal our received offset).
    pub(crate) fn attach(self: &Arc<Self>, conn: Connection, send: SendStream, recv: RecvStream, peer_offset_out: u64, epoch: u64) -> Result<()> {
        let from = {
            let mut st = self.st.lock().unwrap();
            if st.epoch != epoch {
                return Ok(()); // a newer carrier took over meanwhile
            }
            if peer_offset_out != st.received {
                return Err(Error::Protocol(format!(
                    "lane {}/{}: peer resumes at {peer_offset_out}, we hold {}",
                    self.chan_id, self.lane, st.received
                )));
            }
            st.ever_attached = true;
            st.send_from
        };
        let _ = self.attach_tx.send((LaneSend { s: Some(send) }, from));
        let lane = self.clone();
        tokio::spawn(async move {
            if let Err(e) = lane.quic_reader(recv, epoch).await {
                conn.close(close::PROTOCOL.into(), e.to_string().as_bytes());
            }
        });
        self.force_ack();
        Ok(())
    }

    // --------------------------------------------------------------- tasks

    /// Local source → send ring, only within peer credit, reading directly
    /// into a budget-charged chunk.
    pub(crate) async fn source_task<R: AsyncReadExt + Readable + Unpin>(self: Arc<Self>, mut src: R) -> Result<()> {
        loop {
            // Wait for data (or EOF) before reserving storage for it.
            src.readable().await?;
            let mut full_episode = false;
            let (mut tail, want) = loop {
                let lane_fut = self.wake_source.notified();
                let budget_fut = self.env.send_budget.freed.notified();
                tokio::pin!(lane_fut, budget_fut);
                lane_fut.as_mut().enable();
                budget_fut.as_mut().enable();
                {
                    let mut st = self.st.lock().unwrap();
                    if st.closed || st.send_done {
                        return Ok(());
                    }
                    let send_end = st.sbase + st.sbuf.len() as u64;
                    let credit = st.peer_limit.saturating_sub(send_end);
                    let room = self.env.cap.saturating_sub(st.sbuf.len() as u64);
                    let want = credit.min(room) as usize;
                    if want > 0 {
                        let tail = match st.sbuf.take_tail() {
                            Some(t) => Some(t),
                            None => match Permit::try_new(&self.env.send_budget, CH) {
                                Some(p) => Some(Tail::new(ChunkPermit { _permit: p, floor: None })),
                                None => floor_chunk(&self.env.floor_budget, &st.sfloor, SEND_FLOOR_CHUNKS),
                            },
                        };
                        if let Some(t) = tail {
                            let want = want.min(t.space());
                            if full_episode && let Some(o) = self.overflow.lock().unwrap().clone() {
                                o.ring_has_room();
                            }
                            break (t, want);
                        }
                    }
                }
                // The lane is full. A pty output lane asks its overflow
                // policy whether to keep reading the pty (screen mode).
                let overflow = self.overflow.lock().unwrap().clone();
                if let Some(o) = overflow {
                    full_episode = true;
                    if o.ring_full() {
                        let mut scratch = [0u8; 4096];
                        let n = src.read(&mut scratch).await?;
                        if n > 0 {
                            o.feed(&scratch[..n]);
                            continue;
                        }
                        // EOF: wait for room; the normal path then reads the
                        // EOF again and sends LaneFin.
                    }
                }
                tokio::select! {
                    _ = lane_fut => {}
                    _ = budget_fut => {}
                }
            };
            let r = src.read(tail.spare(want)).await;
            let fin = {
                let mut st = self.st.lock().unwrap();
                if st.closed {
                    return Ok(());
                }
                let n = match r {
                    Ok(n) => n,
                    Err(e) => {
                        st.sbuf.commit(tail, 0);
                        return Err(e.into());
                    }
                };
                st.sbuf.commit(tail, n);
                if n == 0 {
                    st.s_eof = true;
                    let final_offset = st.sbase + st.sbuf.len() as u64;
                    if st.sbuf.is_empty() {
                        st.send_done = true;
                    }
                    Some(final_offset)
                } else {
                    self.env.stats.send_ring_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    None
                }
            };
            self.wake_sender.notify_waiters();
            if let Some(final_offset) = fin {
                self.done.notify_waiters();
                let _ = self.env.events.send(Message::LaneFin { chan_id: self.chan_id, lane: self.lane, final_offset }).await;
                return Ok(());
            }
        }
    }

    /// Send ring → current QUIC stream; lives as long as the lane, across
    /// carriers. Each attach replaces the stream and rewinds to `send_from`.
    pub(crate) async fn sender_task(self: Arc<Self>) {
        let mut rx = self.attach_rx.lock().unwrap().take().expect("sender_task started twice");
        let mut cur: Option<(LaneSend, u64)> = None;
        let mut buf: Option<ChunkSlice> = None;
        loop {
            enum Next {
                Attach(LaneSend, u64),
                Data(u64),
                Finish,
                Closed,
            }
            let fut = self.wake_sender.notified();
            tokio::pin!(fut);
            fut.as_mut().enable();
            let ready = {
                let st = self.st.lock().unwrap();
                if st.closed {
                    Some(Next::Closed)
                } else if let Some((s, sent)) = cur.as_ref() {
                    let send_end = st.sbase + st.sbuf.len() as u64;
                    let upto = send_end.min(st.peer_limit);
                    let sent = (*sent).max(st.sbase);
                    if upto > sent {
                        let off = (sent - st.sbase) as usize;
                        buf = Some(st.sbuf.peek(off, (upto - sent) as usize).expect("offset inside the send ring"));
                        Some(Next::Data(sent))
                    } else if st.send_done && s.s.is_some() {
                        Some(Next::Finish)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            let next = match ready {
                Some(n) => match rx.try_recv() {
                    Ok((s, from)) => Next::Attach(s, from),
                    Err(_) => n,
                },
                None => tokio::select! {
                    a = rx.recv() => match a {
                        Some((s, from)) => Next::Attach(s, from),
                        None => Next::Closed,
                    },
                    _ = fut => continue,
                },
            };
            match next {
                Next::Closed => return,
                Next::Attach(s, from) => cur = Some((s, from)),
                // All bytes accepted and LaneFin sent: end the stream cleanly.
                Next::Finish => cur.as_mut().unwrap().0.finish(),
                Next::Data(sent) => {
                    let slice = buf.take().expect("Data carries a slice");
                    let end = sent + slice.len() as u64;
                    // Raise the bound first: the peer may accept part of
                    // this chunk before write_all returns.
                    {
                        let mut st = self.st.lock().unwrap();
                        st.sent_hi = st.sent_hi.max(end);
                    }
                    let c = cur.as_mut().unwrap();
                    match c.0.get().write_all(&slice).await {
                        Ok(()) => {
                            c.1 = end;
                            self.env.stats.lane_bytes_sent.fetch_add(slice.len() as u64, Ordering::Relaxed);
                        }
                        Err(e) => {
                            tracing::debug!(chan = self.chan_id, lane = self.lane, "lane write failed ({e}); waiting for a new carrier");
                            cur = None;
                        }
                    }
                }
            }
        }
    }

    /// QUIC stream → receive ring, reading directly into a reserved chunk.
    /// Never waits on the sink: credit guarantees storage. One per attach,
    /// fenced by `epoch`.
    async fn quic_reader(self: Arc<Self>, mut recv: RecvStream, epoch: u64) -> Result<()> {
        loop {
            let (mut tail, want) = {
                let fut = self.wake_rx.notified();
                tokio::pin!(fut);
                fut.as_mut().enable();
                let got = {
                    let mut st = self.st.lock().unwrap();
                    if st.closed || st.epoch != epoch {
                        return Ok(());
                    }
                    let allowed = (st.limit - st.received) as usize;
                    if allowed == 0 {
                        None
                    } else {
                        let tail = match st.rbuf.take_tail() {
                            Some(t) => t,
                            None => match self.recv_chunk(&mut st) {
                                Some(t) => t,
                                None => {
                                    return Err(Error::Protocol(format!(
                                        "lane {}/{}: internal: credit {allowed} granted without storage",
                                        self.chan_id, self.lane
                                    )));
                                }
                            },
                        };
                        let want = allowed.min(tail.space());
                        Some((tail, want))
                    }
                };
                match got {
                    Some(v) => v,
                    None => {
                        // No credit left: keep polling QUIC anyway. A
                        // conforming peer sends nothing now; any byte that
                        // arrives while we are still at the limit is a
                        // violation and cuts the connection (bytes left in
                        // quinn would hold connection credit hostage).
                        let mut probe = [0u8; 1];
                        tokio::select! {
                            _ = fut => continue,
                            r = recv.read(&mut probe) => {
                                let n = match r {
                                    Ok(Some(n)) => n,
                                    Ok(None) => return Ok(()),
                                    Err(e) => {
                                        tracing::debug!(chan = self.chan_id, lane = self.lane, "lane read ended: {e}");
                                        return Ok(());
                                    }
                                };
                                let mut st = self.st.lock().unwrap();
                                if st.closed || st.epoch != epoch {
                                    return Ok(());
                                }
                                if st.received + n as u64 > st.limit {
                                    return Err(Error::Protocol(format!(
                                        "lane {}/{}: peer sent beyond limit {} (received {}, +{n})",
                                        self.chan_id, self.lane, st.limit, st.received
                                    )));
                                }
                                // Credit grew meanwhile: a legitimate byte.
                                let mut tail = match st.rbuf.take_tail() {
                                    Some(t) => t,
                                    None => self.recv_chunk(&mut st).ok_or_else(|| {
                                        Error::Protocol(format!("lane {}/{}: internal: credit granted without storage", self.chan_id, self.lane))
                                    })?,
                                };
                                tail.spare(n).copy_from_slice(&probe[..n]);
                                st.rbuf.commit(tail, n);
                                st.received += n as u64;
                                self.env.stats.recv_ring_bytes.fetch_add(n as u64, Ordering::Relaxed);
                                let u = self.ack_need(&mut st);
                                drop(st);
                                self.queue_ack(u);
                                self.wake_sink.notify_waiters();
                                continue;
                            }
                        }
                    }
                }
            };
            let r = recv.read(tail.spare(want)).await;
            let mut st = self.st.lock().unwrap();
            if st.closed || st.epoch != epoch {
                return Ok(());
            }
            let n = match r {
                Ok(Some(n)) => n,
                Ok(None) => {
                    st.rbuf.commit(tail, 0);
                    return Ok(()); // end of this carrier's stream; LaneFin is an event
                }
                Err(e) => {
                    st.rbuf.commit(tail, 0);
                    tracing::debug!(chan = self.chan_id, lane = self.lane, "lane read ended: {e}");
                    return Ok(());
                }
            };
            if let Some(f) = st.fin_offset
                && st.received + n as u64 > f
            {
                return Err(Error::Protocol(format!("lane {}/{}: data beyond LaneFin offset {f}", self.chan_id, self.lane)));
            }
            let was_empty = st.rbuf.is_empty();
            if was_empty {
                st.sink_progress = Instant::now();
            }
            st.rbuf.commit(tail, n);
            st.received += n as u64;
            self.env.stats.recv_ring_bytes.fetch_add(n as u64, Ordering::Relaxed);
            // A sink holding bytes for longer than ack_interval is stalled:
            // stop granting it more than the floor.
            if !was_empty && st.sink_progress.elapsed() > self.env.ack_interval && st.granted > self.env.floor {
                tracing::trace!(chan = self.chan_id, lane = self.lane, granted = st.granted, "grant collapsed: sink stalled");
                st.granted = self.env.floor;
            }
            let u = self.ack_need(&mut st);
            drop(st);
            self.queue_ack(u);
            self.wake_sink.notify_waiters();
        }
    }

    /// Receive ring → local sink.
    pub(crate) async fn sink_task<W: AsyncWriteExt + Unpin>(self: Arc<Self>, mut sink: W) -> Result<()> {
        let mut buf: Option<ChunkSlice> = None;
        loop {
            let fin = wait_for(&self.wake_sink, || {
                let st = self.st.lock().unwrap();
                if st.closed {
                    return Some(None);
                }
                if !st.rbuf.is_empty() {
                    buf = Some(st.rbuf.peek(0, CHUNK).expect("non-empty ring"));
                    return Some(Some(false));
                }
                (st.fin_offset == Some(st.delivered)).then_some(Some(true))
            })
            .await;
            match fin {
                None => return Ok(()),
                Some(true) => {
                    sink.shutdown().await?;
                    self.st.lock().unwrap().sink_done = true;
                    self.done.notify_waiters();
                    return Ok(());
                }
                Some(false) => {
                    let slice = buf.take().expect("a slice to deliver");
                    sink.write_all(&slice).await?;
                    let n = slice.len() as u64;
                    let mut st = self.st.lock().unwrap();
                    // Release the chunk only after the ring has dropped it
                    // too: the slice keeps its permit until here.
                    if st.closed {
                        return Ok(());
                    }
                    st.rbuf.drain(n as usize);
                    drop(slice);
                    st.delivered += n;
                    st.sink_progress = Instant::now();
                    self.env.stats.recv_ring_bytes.fetch_sub(n, Ordering::Relaxed);
                    self.env.stats.credit_outstanding.fetch_sub(n, Ordering::Relaxed);
                    // Auto-tune: after each `granted` bytes delivered, if the
                    // sink drained the ring empty at least once, it keeps up
                    // and credit is what limits the sender — double the grant
                    // (cap and budgets bound it). A sink-limited lane never
                    // empties its ring. (`received == limit` is no signal:
                    // every delivery moves the limit ahead; peak occupancy is
                    // none either: a floor grant always arrives as one burst.)
                    st.epoch_emptied |= st.rbuf.is_empty();
                    if st.delivered - st.epoch_start >= st.granted {
                        if st.epoch_emptied && st.granted < self.env.cap {
                            st.granted = (st.granted * 2).min(self.env.cap);
                            tracing::trace!(chan = self.chan_id, lane = self.lane, granted = st.granted, "grant grown");
                        }
                        st.epoch_start = st.delivered;
                        st.epoch_emptied = false;
                    }
                    self.recompute_limit(&mut st);
                    let u = self.ack_need(&mut st);
                    drop(st);
                    self.queue_ack(u);
                }
            }
        }
    }
}

/// Write our header on a fresh lane stream.
pub(crate) async fn write_header(send: &mut SendStream, h: &LaneHeader) -> Result<()> {
    send.write_all(&frame::encode(h)).await.map_err(|e| Error::Stream(format!("writing lane header: {e}")))
}

pub(crate) async fn read_header(recv: &mut RecvStream) -> Result<LaneHeader> {
    let b = frame::read_frame(recv, frame::MAX_LANE_HEADER)
        .await?
        .ok_or_else(|| Error::Protocol("lane stream ended before its header".into()))?;
    frame::decode(&b, "lane header")
}

/// A floor chunk if the lane holds fewer than `max`.
fn floor_chunk(budget: &Arc<Budget>, count: &Arc<AtomicU32>, max: u32) -> Option<Tail> {
    let mut cur = count.load(Ordering::Acquire);
    loop {
        if cur >= max {
            return None;
        }
        match count.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(v) => cur = v,
        }
    }
    let p = Permit::try_new(budget, CH).expect("the floor budget is unlimited");
    Some(Tail::new(ChunkPermit { _permit: p, floor: Some(count.clone()) }))
}
