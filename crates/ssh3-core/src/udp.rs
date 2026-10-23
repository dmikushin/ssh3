//! UDP forwarding over QUIC datagrams (SPEC §6).
//!
//! Datagram payload: `varint chan_id || frag_hdr || bytes`, with `frag_hdr`
//! 0 = whole, 1 = fragment `{id u16, idx u8, count u8}`. Fragmentation and
//! reassembly happen only at the endpoints; reassembly memory is charged to
//! a server-wide budget, groups expire after `reassembly_max_age` and the
//! oldest are evicted when the budget is full — all counted.
//!
//! A UDP channel has no lanes: it carries datagrams only and ends by an
//! explicit close (flow expiry / LRU eviction on either side). Every flow
//! table — the client's -L UDP listener, the server's -R UDP listener, and
//! the per-channel sockets — is bounded by count, idle time and LRU.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::{BufMut, Bytes, BytesMut};
use quinn::Connection;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::budget::{Budget, Permit};
use crate::error::{Error, Result};
use crate::msg::{ChannelKind, FailReason, Message};
use crate::session::{Completion, SessionShared};

/// Largest UDP payload (IPv4 limit); larger never exists on the wire.
pub const MAX_UDP_PAYLOAD: usize = 65_507;
const FRAG_HDR: usize = 5;

fn put_varint(out: &mut BytesMut, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.put_u8(b);
            return;
        }
        out.put_u8(b | 0x80);
    }
}

fn get_varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, x) in b.iter().take(10).enumerate() {
        v |= ((x & 0x7f) as u64) << (7 * i);
        if x & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// Inbound datagrams of one UDP channel, delivered locally by its task.
/// Counts as one live flow for exactly its lifetime.
pub(crate) struct UdpExt {
    pub(crate) tx: mpsc::Sender<Bytes>,
    stats: Arc<crate::lane::Stats>,
}

impl UdpExt {
    pub(crate) fn new(tx: mpsc::Sender<Bytes>, stats: Arc<crate::lane::Stats>) -> Self {
        stats.udp_flows.fetch_add(1, Ordering::Relaxed);
        Self { tx, stats }
    }
}

impl Drop for UdpExt {
    fn drop(&mut self) {
        self.stats.udp_flows.fetch_sub(1, Ordering::Relaxed);
    }
}

/// One received fragment.
struct Fragment {
    chan: u64,
    id: u16,
    idx: u8,
    count: u8,
    data: Bytes,
}

struct Group {
    parts: Vec<Option<Bytes>>,
    have: usize,
    first: Instant,
    _charge: Permit,
}

/// Per-session reassembly; storage charged to the server-wide budget.
pub(crate) struct Reassembly {
    groups: HashMap<(u64, u16), Group>,
    order: VecDeque<(u64, u16)>,
}

impl Reassembly {
    pub(crate) fn new() -> Self {
        Self { groups: HashMap::new(), order: VecDeque::new() }
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some(k) = self.order.pop_front() {
            if self.groups.remove(&k).is_some() {
                return true;
            }
        }
        false
    }

    /// Insert one fragment; returns the whole datagram when complete.
    /// `evicted` counts groups dropped for age or budget.
    fn insert(&mut self, budget: &Arc<Budget>, max_age: std::time::Duration, f: Fragment, evicted: &mut u64) -> Option<Vec<u8>> {
        let Fragment { chan, id, idx, count, data } = f;
        // Age-out first.
        while let Some(k) = self.order.front() {
            match self.groups.get(k) {
                Some(g) if g.first.elapsed() > max_age => {
                    let k = *k;
                    self.order.pop_front();
                    self.groups.remove(&k);
                    *evicted += 1;
                }
                Some(_) => break,
                None => {
                    self.order.pop_front();
                }
            }
        }
        let key = (chan, id);
        if !self.groups.contains_key(&key) {
            let mut charge = Permit::empty(budget.clone());
            // Charge the whole group up front: count × this fragment's size
            // bounds it (fragments are equal except the last).
            let need = data.len() as u64 * count as u64;
            loop {
                charge.grow_upto(need - charge.amount());
                if charge.amount() == need {
                    break;
                }
                // Budget full: evict the oldest group; if none is left, this
                // group itself cannot be held.
                *evicted += 1;
                if !self.evict_oldest() {
                    return None;
                }
            }
            self.groups.insert(key, Group { parts: vec![None; count as usize], have: 0, first: Instant::now(), _charge: charge });
            self.order.push_back(key);
        }
        let g = self.groups.get_mut(&key)?;
        if g.parts.len() != count as usize || idx as usize >= g.parts.len() {
            self.groups.remove(&key);
            *evicted += 1;
            return None;
        }
        if g.parts[idx as usize].is_none() {
            g.parts[idx as usize] = Some(data);
            g.have += 1;
        }
        if g.have == g.parts.len() {
            let g = self.groups.remove(&key)?;
            let mut out = Vec::new();
            for p in g.parts.into_iter().flatten() {
                out.extend_from_slice(&p);
            }
            return Some(out);
        }
        None
    }
}

/// One entry of a listener's flow table.
enum Flow {
    Opening,
    Open(u64),
}

struct FlowEntry {
    flow: Flow,
    last: Instant,
}

/// A listener's flows by source address: bounded count, LRU, idle expiry.
struct FlowTable {
    map: HashMap<SocketAddr, FlowEntry>,
}

/// Removes a listener's flow entry when its channel's task ends.
struct ForgetFlow {
    table: Arc<Mutex<FlowTable>>,
    src: SocketAddr,
    chan: u64,
}

impl Drop for ForgetFlow {
    fn drop(&mut self) {
        let mut t = self.table.lock().unwrap();
        if matches!(t.map.get(&self.src), Some(FlowEntry { flow: Flow::Open(c), .. }) if *c == self.chan) {
            t.map.remove(&self.src);
        }
    }
}

static FRAG_IDS: AtomicU16 = AtomicU16::new(0);

impl SessionShared {
    /// Send one UDP payload on channel `chan_id`, fragmenting to the path's
    /// datagram limit. False (and counted) if it was dropped.
    pub(crate) fn send_datagram(&self, chan_id: u64, data: &[u8]) -> bool {
        let ok = self.try_send_datagram(chan_id, data);
        if ok {
            self.stats.dgrams_sent.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.dgrams_dropped.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    fn try_send_datagram(&self, chan_id: u64, data: &[u8]) -> bool {
        let Some((conn, _)) = self.current_conn() else { return false };
        let Some(max) = conn.max_datagram_size() else { return false };
        if data.len() > MAX_UDP_PAYLOAD {
            return false;
        }
        let mut hdr = BytesMut::with_capacity(10);
        put_varint(&mut hdr, chan_id);
        if hdr.len() + 1 + data.len() <= max {
            let mut d = BytesMut::with_capacity(hdr.len() + 1 + data.len());
            d.put_slice(&hdr);
            d.put_u8(0);
            d.put_slice(data);
            return conn.send_datagram(d.freeze()).is_ok();
        }
        let room = max.saturating_sub(hdr.len() + FRAG_HDR);
        if room == 0 {
            return false;
        }
        let count = data.len().div_ceil(room);
        if count > 255 {
            return false;
        }
        let id = FRAG_IDS.fetch_add(1, Ordering::Relaxed);
        for (idx, part) in data.chunks(room).enumerate() {
            let mut d = BytesMut::with_capacity(hdr.len() + FRAG_HDR + part.len());
            d.put_slice(&hdr);
            d.put_u8(1);
            d.put_u16(id);
            d.put_u8(idx as u8);
            d.put_u8(count as u8);
            d.put_slice(part);
            if conn.send_datagram(d.freeze()).is_err() {
                return false;
            }
        }
        true
    }

    /// The carrier's datagram reader: reassemble and hand each payload to
    /// its channel's queue; a full queue drops (never blocks the reader).
    pub(crate) async fn datagram_rx(self: Arc<Self>, conn: Connection) {
        while let Ok(d) = conn.read_datagram().await {
            self.stats.dgrams_received.fetch_add(1, Ordering::Relaxed);
            let Some((chan_id, n)) = get_varint(&d) else {
                self.stats.dgrams_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let payload = match d.get(n) {
                Some(0) => d.slice(n + 1..),
                Some(1) if d.len() >= n + FRAG_HDR => {
                    let id = u16::from_be_bytes([d[n + 1], d[n + 2]]);
                    let (idx, count) = (d[n + 3], d[n + 4]);
                    let mut evicted = 0;
                    let frag = Fragment { chan: chan_id, id, idx, count, data: d.slice(n + FRAG_HDR..) };
                    let whole = self.reasm.lock().unwrap().insert(&self.budgets.reasm, self.limits.reassembly_max_age, frag, &mut evicted);
                    self.stats.reasm_evicted.fetch_add(evicted, Ordering::Relaxed);
                    match whole {
                        Some(w) => Bytes::from(w),
                        None => continue,
                    }
                }
                _ => {
                    self.stats.dgrams_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let tx = self.channel_by_id(chan_id).and_then(|ch| match &*ch.ext.lock().unwrap() {
                Some(crate::sesschan::ChanExt::Udp(u)) => Some(u.tx.clone()),
                _ => None,
            });
            match tx {
                Some(tx) if tx.try_send(payload).is_ok() => {}
                _ => {
                    self.stats.dgrams_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Accept a peer's UDP channel: a socket connected to `host:port` (the
    /// server for direct-udp, the client for forwarded-udp), idle-expired.
    pub(crate) fn accept_udp_channel(self: &Arc<Self>, chan_id: u64, host: String, port: u16) -> Result<()> {
        let (tx, mut rx) = mpsc::channel::<Bytes>(self.limits.udp_queue);
        let ch = match self.new_channel(chan_id, 0, Completion::Manual) {
            Ok(ch) => ch,
            Err(FailReason::Protocol(m)) => return Err(Error::Protocol(m)),
            Err(reason) => return self.reply_ev(Message::ChannelFail { chan_id, reason }),
        };
        *ch.ext.lock().unwrap() = Some(crate::sesschan::ChanExt::Udp(UdpExt::new(tx, self.stats.clone())));
        let me = Arc::downgrade(self);
        let ch2 = ch.clone();
        let idle = self.limits.udp_flow_idle;
        ch.spawn(async move {
            let Some(s) = me.upgrade() else { return };
            let sock = async {
                let addr = tokio::net::lookup_host((host.as_str(), port)).await?.next().ok_or_else(|| std::io::Error::other("no address"))?;
                let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
                let sock = UdpSocket::bind(bind).await?;
                sock.connect(addr).await?;
                Ok::<_, std::io::Error>(sock)
            }
            .await;
            let sock = match sock {
                Ok(sock) => Arc::new(sock),
                Err(e) => {
                    drop(ch2);
                    drop(s.drop_channel(chan_id));
                    let _ = s.send_event(Message::ChannelFail { chan_id, reason: FailReason::ConnectFailed(format!("{host}:{port}: {e}")) }).await;
                    return;
                }
            };
            let _ = s.send_event(Message::ChannelOk { chan_id, limit: 0 }).await;
            drop(s);
            let last = Arc::new(Mutex::new(Instant::now()));
            let (sock2, last2) = (sock.clone(), last.clone());
            ch2.spawn(async move {
                while let Some(d) = rx.recv().await {
                    *last2.lock().unwrap() = Instant::now();
                    let _ = sock2.send(&d).await;
                }
            });
            let me2 = me.clone();
            let last3 = last.clone();
            ch2.spawn(async move {
                let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
                while let Ok(n) = sock.recv(&mut buf).await {
                    *last3.lock().unwrap() = Instant::now();
                    let Some(s) = me2.upgrade() else { return };
                    s.send_datagram(chan_id, &buf[..n]);
                }
            });
            // This task is owned by the channel: holding the channel here
            // would keep it (and its JoinSet, socket, flow count) alive
            // after it is closed — a cycle. Let go before the idle loop.
            drop(ch2);
            // Idle expiry (SPEC §6: every UDP association is bounded).
            loop {
                tokio::time::sleep(idle / 4).await;
                if last.lock().unwrap().elapsed() > idle {
                    if let Some(s) = me.upgrade() {
                        s.abort_channel(chan_id, "udp flow idle".into()).await;
                    }
                    return;
                }
            }
        });
        Ok(())
    }

    /// A UDP listener (client -L UDP / server -R UDP): one channel per source
    /// address, opened with `kind_for(src)`, in a bounded flow table.
    pub(crate) fn run_udp_listener(self: &Arc<Self>, sock: UdpSocket, kind_for: impl Fn(SocketAddr) -> ChannelKind + Send + Sync + 'static) -> tokio::task::JoinHandle<()> {
        let me = Arc::downgrade(self);
        let sock = Arc::new(sock);
        let table = Arc::new(Mutex::new(FlowTable { map: HashMap::new() }));
        let kind_for = Arc::new(kind_for);
        tokio::spawn(async move {
            let (cap, idle) = match me.upgrade() {
                Some(s) => (s.limits.udp_flows_max, s.limits.udp_flow_idle),
                None => return,
            };
            let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
            let mut sweep = tokio::time::interval(idle / 4);
            loop {
                let (n, src) = tokio::select! {
                    r = sock.recv_from(&mut buf) => match r {
                        Ok(v) => v,
                        Err(_) => return,
                    },
                    _ = sweep.tick() => {
                        let Some(s) = me.upgrade() else { return };
                        let expired: Vec<u64> = {
                            let mut t = table.lock().unwrap();
                            let gone: Vec<SocketAddr> = t.map.iter().filter(|(_, e)| e.last.elapsed() > idle).map(|(a, _)| *a).collect();
                            gone.into_iter().filter_map(|a| match t.map.remove(&a) { Some(FlowEntry { flow: Flow::Open(c), .. }) => Some(c), _ => None }).collect()
                        };
                        for c in expired {
                            s.abort_channel(c, "udp flow idle".into()).await;
                        }
                        continue;
                    }
                };
                let Some(s) = me.upgrade() else { return };
                let existing = {
                    let mut t = table.lock().unwrap();
                    match t.map.get_mut(&src) {
                        Some(e) => {
                            e.last = Instant::now();
                            Some(match e.flow {
                                Flow::Open(c) => Some(c),
                                Flow::Opening => None,
                            })
                        }
                        None => None,
                    }
                };
                match existing {
                    Some(Some(chan)) => {
                        s.send_datagram(chan, &buf[..n]);
                    }
                    Some(None) => {
                        // Still opening: the first datagram waits, later ones drop.
                        s.stats.dgrams_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {
                        // New flow; evict the least recently used one if full.
                        let evict = {
                            let mut t = table.lock().unwrap();
                            let mut ev = None;
                            if t.map.len() >= cap
                                && let Some((&a, _)) = t.map.iter().min_by_key(|(_, e)| e.last)
                            {
                                ev = match t.map.remove(&a) {
                                    Some(FlowEntry { flow: Flow::Open(c), .. }) => Some(c),
                                    _ => None,
                                };
                                s.stats.udp_evicted.fetch_add(1, Ordering::Relaxed);
                            }
                            t.map.insert(src, FlowEntry { flow: Flow::Opening, last: Instant::now() });
                            ev
                        };
                        if let Some(c) = evict {
                            s.abort_channel(c, "udp flow evicted (LRU)".into()).await;
                        }
                        let first = buf[..n].to_vec();
                        let (s2, sock2, table2, kind_for) = (s.clone(), sock.clone(), table.clone(), kind_for.clone());
                        tokio::spawn(async move {
                            let (tx, mut rx) = mpsc::channel::<Bytes>(s2.limits.udp_queue);
                            let ext = crate::sesschan::ChanExt::Udp(UdpExt::new(tx, s2.stats.clone()));
                            match s2.open_channel(kind_for(src), 0, Completion::Manual, Some(ext)).await {
                                Ok(ch) => {
                                    let chan = ch.chan_id;
                                    if let Some(e) = table2.lock().unwrap().map.get_mut(&src) {
                                        e.flow = Flow::Open(chan);
                                    }
                                    s2.send_datagram(chan, &first);
                                    // The guard lives in the channel's delivery
                                    // task: when the channel ends (peer expiry,
                                    // close) the task is aborted, the guard drops
                                    // and the flow is forgotten, so the next
                                    // datagram opens a new one.
                                    let guard = ForgetFlow { table: table2, src, chan };
                                    ch.spawn(async move {
                                        let _guard = guard;
                                        while let Some(d) = rx.recv().await {
                                            let _ = sock2.send_to(&d, src).await;
                                        }
                                    });
                                }
                                Err(e) => {
                                    table2.lock().unwrap().map.remove(&src);
                                    tracing::debug!(%src, "udp flow not opened: {e}");
                                }
                            }
                        });
                    }
                }
            }
        })
    }
}
