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
    /// §4 fenced retraction: completed (acked or unilateral), and peers cut
    /// for not acknowledging one in time.
    pub credit_retractions: AtomicU64,
    pub retract_timeouts: AtomicU64,
    /// §5 pty lanes: bytes consumed in screen mode (emulator only) and
    /// redraws appended when leaving it.
    pub pty_screen_bytes: AtomicU64,
    pub pty_redraws: AtomicU64,
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
    /// Retract a lane's credit to the floor after this long without arrivals.
    pub credit_idle: Duration,
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

/// A Retract sent and not yet acknowledged.
#[derive(Clone, Copy)]
struct Retracting {
    seq: u64,
    new_limit: u64,
    deadline: Instant,
}

/// What the periodic credit check wants done for a lane.
pub(crate) enum CreditAction {
    None,
    /// Send `Retract{seq, new_limit}`.
    Retract { seq: u64, new_limit: u64 },
    /// The peer did not acknowledge a Retract in time.
    Violation(String),
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
    /// Fence seq of the last Retract we acknowledged: grants with an older
    /// seq are stale and ignored.
    peer_seq: u64,
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
    /// Receiver: current fence seq, the outstanding Retract (one per lane),
    /// and when bytes last arrived (demand-driven grants).
    seq: u64,
    retract: Option<Retracting>,
    last_arrival: Instant,
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
                peer_seq: 0,
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
                seq: 0,
                retract: None,
                last_arrival: Instant::now(),
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
        })
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
        // No new credit while a Retract is outstanding (SPEC §4).
        if target > st.limit && st.retract.is_none() {
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

    /// The `(accepted, limit, seq)` to send now. Works on closed lanes too:
    /// the final ack of a completed lane must still go out. While a Retract
    /// is outstanding the advertised limit is at most its new limit.
    pub(crate) fn take_ack(&self) -> (u64, u64, u64) {
        let mut st = self.st.lock().unwrap();
        st.queued_lazy = false;
        st.queued_urgent = false;
        st.last_ack_accepted = st.received;
        st.last_ack_limit = st.limit;
        let limit = match st.retract {
            Some(r) => st.limit.min(r.new_limit.max(st.received)),
            None => st.limit,
        };
        (st.received, limit, st.seq)
    }

    // ---------------------------------------------------------- retraction

    /// Receiver, periodic: retract an idle lane's credit to the floor
    /// (demand-driven grants), or report a Retract that timed out.
    pub(crate) fn credit_check(&self, retract_timeout: Duration) -> CreditAction {
        let mut st = self.st.lock().unwrap();
        if st.closed {
            return CreditAction::None;
        }
        if let Some(r) = st.retract {
            if Instant::now() > r.deadline {
                return CreditAction::Violation(format!(
                    "lane {}/{}: Retract seq {} not acknowledged within {retract_timeout:?}",
                    self.chan_id, self.lane, r.seq
                ));
            }
            return CreditAction::None;
        }
        let floor = self.env.floor;
        if st.limit - st.delivered <= floor || st.last_arrival.elapsed() < self.env.credit_idle {
            return CreditAction::None;
        }
        let new_limit = st.received.max(st.delivered + floor);
        if new_limit >= st.limit {
            return CreditAction::None;
        }
        st.seq += 1;
        st.granted = floor;
        st.retract = Some(Retracting { seq: st.seq, new_limit, deadline: Instant::now() + retract_timeout });
        CreditAction::Retract { seq: st.seq, new_limit }
    }

    /// Receiver: the sender stopped at `sent`. The effective limit is
    /// max(sent, new_limit); reservations above it are released only now.
    pub(crate) fn on_retract_ack(&self, seq: u64, sent: u64) -> Result<()> {
        let mut st = self.st.lock().unwrap();
        if st.closed {
            return Ok(());
        }
        let r = match st.retract {
            Some(r) if r.seq == seq => r,
            _ => return Err(Error::Protocol(format!("lane {}/{}: RetractAck seq {seq} without that Retract outstanding", self.chan_id, self.lane))),
        };
        if sent > st.limit || sent < st.received {
            return Err(Error::Protocol(format!(
                "lane {}/{}: RetractAck says {sent} bytes sent; limit {} received {}",
                self.chan_id, self.lane, st.limit, st.received
            )));
        }
        self.lower_limit(&mut st, sent.max(r.new_limit));
        st.retract = None;
        self.env.stats.credit_retractions.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn lower_limit(&self, st: &mut LaneState, new_limit: u64) {
        if new_limit < st.limit {
            self.env.stats.credit_outstanding.fetch_sub(st.limit - new_limit, Ordering::Relaxed);
            st.limit = new_limit;
            st.last_ack_limit = st.last_ack_limit.min(new_limit);
        }
        st.rbuf.release_budget_tail();
        // Releases the reservation no longer backing credit.
        self.recompute_limit(st);
    }

    /// Receiver while detached: retract to the floor without a message (no
    /// byte can be in flight once the old carrier's tasks are fenced; the
    /// new limit travels in Resume).
    pub(crate) fn retract_unilaterally(&self) {
        let mut st = self.st.lock().unwrap();
        st.epoch += 1; // fence the old carrier's readers first
        let new_limit = st.received.max(st.delivered + self.env.floor);
        if st.closed || (new_limit >= st.limit && st.retract.is_none()) {
            return;
        }
        st.seq += 1;
        st.retract = None;
        st.granted = self.env.floor;
        self.lower_limit(&mut st, new_limit);
        self.env.stats.credit_retractions.fetch_add(1, Ordering::Relaxed);
    }

    /// Sender: stop at once at max(sent, new_limit) and report what was sent.
    pub(crate) fn on_retract(&self, seq: u64, new_limit: u64) -> Result<u64> {
        let mut st = self.st.lock().unwrap();
        if seq <= st.peer_seq {
            return Err(Error::Protocol(format!("lane {}/{}: Retract seq {seq} not newer than {}", self.chan_id, self.lane, st.peer_seq)));
        }
        if new_limit < st.sbase {
            return Err(Error::Protocol(format!("lane {}/{}: Retract to {new_limit} below accepted {}", self.chan_id, self.lane, st.sbase)));
        }
        // sent_hi already covers a chunk being written right now.
        let sent = st.sent_hi.max(st.sbase);
        st.peer_limit = sent.max(new_limit);
        st.peer_seq = seq;
        Ok(sent)
    }

    /// Sender side: LaneAck from the peer. A grant from an older fence seq
    /// than the last Retract we acknowledged is stale: its limit is ignored.
    pub(crate) fn on_ack(&self, accepted: u64, limit: u64, seq: u64) -> Result<()> {
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
        self.release_accepted(&mut st, accepted);
        if seq >= st.peer_seq {
            if seq == st.peer_seq && limit < st.peer_limit {
                return Err(Error::Protocol(format!(
                    "lane {}/{}: limit went down from {} to {limit} within fence {seq}",
                    self.chan_id, self.lane, st.peer_limit
                )));
            }
            st.peer_seq = seq;
            st.peer_limit = st.peer_limit.max(limit);
        }
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
        LanePos { chan_id: self.chan_id, lane: self.lane, accepted: st.received, limit: st.limit, seq: st.seq }
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
        // A lower limit than before is valid: Resume is a new fence epoch,
        // and the peer may have retracted unilaterally while detached.
        if p.limit < p.accepted || p.seq < st.peer_seq {
            return Err(Error::Protocol(format!(
                "lane {}/{}: resumed limit {} below accepted {} or seq {} older than {}",
                self.chan_id, self.lane, p.limit, p.accepted, p.seq, st.peer_seq
            )));
        }
        Ok(())
    }

    /// Apply the peer's position after a resume.
    pub(crate) fn on_resume(&self, p: &LanePos) -> Result<()> {
        self.check_resume(p)?;
        let mut st = self.st.lock().unwrap();
        self.release_accepted(&mut st, p.accepted);
        // Replay only up to the NEW limit; the old high-water mark grants
        // nothing (SPEC §4).
        st.peer_limit = p.limit;
        st.peer_seq = p.seq;
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
                            break (t, want);
                        }
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

    /// Append `data` to the send ring if the storage for it can be charged
    /// now (budget chunks, or one floor chunk); all or nothing.
    fn append_send(&self, st: &mut LaneState, data: &[u8]) -> bool {
        let need = data.len().saturating_sub(st.sbuf.tail_space());
        let k = need.div_ceil(CHUNK);
        let mut chunks = Vec::with_capacity(k);
        if k > 0 {
            match Permit::try_new(&self.env.send_budget, k as u64 * CH) {
                Some(mut p) => {
                    for _ in 0..k {
                        chunks.push(Tail::new(ChunkPermit { _permit: p.split(CH), floor: None }));
                    }
                }
                None if k == 1 => match floor_chunk(&self.env.floor_budget, &st.sfloor, SEND_FLOOR_CHUNKS) {
                    Some(t) => chunks.push(t),
                    None => return false,
                },
                None => return false,
            }
        }
        let mut chunks = chunks.into_iter();
        let mut off = 0;
        while off < data.len() {
            let mut t = match st.sbuf.take_tail() {
                Some(t) => t,
                None => chunks.next().expect("chunks reserved for every byte"),
            };
            let m = t.space().min(data.len() - off);
            t.spare(m).copy_from_slice(&data[off..off + m]);
            st.sbuf.commit(t, m);
            off += m;
        }
        self.env.stats.send_ring_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        true
    }

    /// pty output → send ring (SPEC §5 hybrid pty lanes). The pty is read
    /// all the time, whatever the client does: a program never blocks on its
    /// terminal. Every byte is fed to `screen`. In stream mode the bytes also
    /// go into the ring, byte-exact — while peer credit and storage allow.
    /// Otherwise the lane enters screen mode: bytes go to the emulator only.
    /// Once the sender has caught up with the peer's credit and the ring has
    /// room for a redraw, the redraw is generated and appended and the lane
    /// returns to stream mode. Snapshot, append and switch happen under the
    /// screen lock in this task, so no pty byte falls between them.
    pub(crate) async fn pty_source_task<R: AsyncReadExt + Unpin>(self: Arc<Self>, mut src: R, screen: Arc<Mutex<ssh3_term::Screen>>, eof_flag: Arc<std::sync::atomic::AtomicBool>) -> Result<()> {
        let mut buf = vec![0u8; CHUNK];
        let mut screen_mode = false;
        let mut eof = false;
        loop {
            let lane_fut = self.wake_source.notified();
            let budget_fut = self.env.send_budget.freed.notified();
            tokio::pin!(lane_fut, budget_fut);
            lane_fut.as_mut().enable();
            budget_fut.as_mut().enable();
            if screen_mode {
                let sc = screen.lock().unwrap();
                let mut st = self.st.lock().unwrap();
                if st.closed || st.send_done {
                    return Ok(());
                }
                let send_end = st.sbase + st.sbuf.len() as u64;
                if send_end <= st.peer_limit {
                    let redraw = sc.resync();
                    if self.env.cap - st.sbuf.len() as u64 >= redraw.len() as u64 && self.append_send(&mut st, &redraw) {
                        screen_mode = false;
                        self.env.stats.pty_redraws.fetch_add(1, Ordering::Relaxed);
                        drop(st);
                        drop(sc);
                        self.wake_sender.notify_waiters();
                        continue;
                    }
                }
            }
            if eof {
                if screen_mode {
                    // The final screen must reach the client: wait for room.
                    tokio::select! {
                        _ = lane_fut => {}
                        _ = budget_fut => {}
                    }
                    continue;
                }
                let final_offset = {
                    let mut st = self.st.lock().unwrap();
                    if st.closed {
                        return Ok(());
                    }
                    st.s_eof = true;
                    if st.sbuf.is_empty() {
                        st.send_done = true;
                    }
                    st.sbase + st.sbuf.len() as u64
                };
                self.done.notify_waiters();
                self.wake_sender.notify_waiters();
                let _ = self.env.events.send(Message::LaneFin { chan_id: self.chan_id, lane: self.lane, final_offset }).await;
                return Ok(());
            }
            let n = if screen_mode {
                tokio::select! {
                    r = src.read(&mut buf) => r?,
                    _ = lane_fut => continue,
                    _ = budget_fut => continue,
                }
            } else {
                // Read no more than the credit takes, so stream mode is left
                // only when there is really no credit (then read a chunk).
                let want = {
                    let st = self.st.lock().unwrap();
                    let send_end = st.sbase + st.sbuf.len() as u64;
                    let credit = st.peer_limit.saturating_sub(send_end).min(self.env.cap - st.sbuf.len() as u64);
                    if credit == 0 { CHUNK } else { (credit as usize).min(CHUNK) }
                };
                src.read(&mut buf[..want]).await?
            };
            if n == 0 {
                eof = true;
                eof_flag.store(true, Ordering::Release);
                continue;
            }
            let sc_guard = {
                let mut sc = screen.lock().unwrap();
                sc.feed(&buf[..n]);
                sc
            };
            let mut st = self.st.lock().unwrap();
            if st.closed || st.send_done {
                return Ok(());
            }
            if !screen_mode {
                let send_end = st.sbase + st.sbuf.len() as u64;
                let credit = st.peer_limit.saturating_sub(send_end);
                let room = self.env.cap - st.sbuf.len() as u64;
                if credit >= n as u64 && room >= n as u64 && self.append_send(&mut st, &buf[..n]) {
                    drop(st);
                    drop(sc_guard);
                    self.wake_sender.notify_waiters();
                    continue;
                }
                screen_mode = true;
            }
            drop(st);
            drop(sc_guard);
            self.env.stats.pty_screen_bytes.fetch_add(n as u64, Ordering::Relaxed);
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

    /// QUIC stream → receive ring. Waits for data holding none of our
    /// storage (an idle lane must not pin a chunk), then copies it into
    /// chunks allocated from the lane's reservation or floor — credit
    /// guarantees they exist. Keeps reading at zero credit, so a byte beyond
    /// the limit is detected (and a byte made legitimate by credit that grew
    /// meanwhile is kept). Never waits on the sink. One per attach, fenced by
    /// `epoch`.
    async fn quic_reader(self: Arc<Self>, mut recv: RecvStream, epoch: u64) -> Result<()> {
        loop {
            let fut = self.wake_rx.notified();
            tokio::pin!(fut);
            fut.as_mut().enable();
            let allowed = {
                let st = self.st.lock().unwrap();
                if st.closed || st.epoch != epoch {
                    return Ok(());
                }
                (st.limit - st.received) as usize
            };
            let r = if allowed == 0 {
                tokio::select! {
                    r = recv.read_chunk(1, true) => r,
                    _ = fut => continue, // credit changed: read larger chunks
                }
            } else {
                recv.read_chunk(allowed.min(CHUNK), true).await
            };
            let data = match r {
                Ok(Some(c)) => c.bytes,
                Ok(None) => return Ok(()), // end of this carrier's stream; LaneFin is an event
                Err(e) => {
                    tracing::debug!(chan = self.chan_id, lane = self.lane, "lane read ended: {e}");
                    return Ok(());
                }
            };
            let n = data.len();
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
            if let Some(f) = st.fin_offset
                && st.received + n as u64 > f
            {
                return Err(Error::Protocol(format!("lane {}/{}: data beyond LaneFin offset {f}", self.chan_id, self.lane)));
            }
            let was_empty = st.rbuf.is_empty();
            if was_empty {
                st.sink_progress = Instant::now();
            }
            st.last_arrival = Instant::now();
            let mut off = 0;
            while off < n {
                let mut tail = match st.rbuf.take_tail() {
                    Some(t) => t,
                    None => self.recv_chunk(&mut st).ok_or_else(|| {
                        Error::Protocol(format!("lane {}/{}: internal: credit granted without storage", self.chan_id, self.lane))
                    })?,
                };
                let k = tail.space().min(n - off);
                tail.spare(k).copy_from_slice(&data[off..off + k]);
                st.rbuf.commit(tail, k);
                off += k;
            }
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
