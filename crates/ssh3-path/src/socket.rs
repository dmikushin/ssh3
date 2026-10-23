//! The path socket (SPEC §7.2): the one `AsyncUdpSocket` under a quinn endpoint that carries
//! the gateway connection, any number of inner (peer-to-peer) connections, and the punch side
//! channel.
//!
//! Started from the X8 prototype (`quic-probe/src/pathsock.rs`) and the E3 demultiplexer
//! (`quic-probe/src/punch.rs`), generalised to many routes and to a relay real path.
//!
//! * Every inner connection has a **route**: quinn talks to a constant *virtual* peer address
//!   from `fd00::/8`; the route maps it to the current *real* path — the relay carrier
//!   ([`RelayLink`]) or a direct UDP address. Swapping the real path is one table update.
//! * Inbound datagrams with the QUIC fixed bit clear are side channel: punch traffic goes to the
//!   path manager of the route named by its tag, other types to an optional extra sink.
//! * Inbound QUIC from the route's current direct address is rewritten to the virtual address;
//!   from a *previous* direct address of any route it is dropped (strict, X8); from anyone else it
//!   passes unchanged (the gateway connection, new incoming connections).
//! * Inner packets from the relay are injected with [`Shared::relay_input`] and appear to quinn
//!   as coming from the route's virtual address.
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use arc_swap::ArcSwap;
use bytes::Bytes;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::mpsc;

use crate::wire::{self, T_EXTRA_MIN, TAG_LEN};

/// Receiver of inner QUIC datagrams travelling over the gateway (relay real path).
///
/// The implementation wraps each packet for the carrier (in ssh3-core: a `jump` channel
/// datagram with end-to-end fragmentation, SPEC §7.2). It must not block; dropping a packet is
/// acceptable (QUIC recovers) and should be counted by the implementation.
pub trait RelayLink: Send + Sync + 'static {
    fn send(&self, packet: &[u8]);
}

/// Where packets for a route's virtual address really go.
#[derive(Clone)]
pub enum Real {
    Relay(Arc<dyn RelayLink>),
    Direct(SocketAddr),
}

impl Real {
    fn canonical(self) -> Self {
        match self {
            Real::Direct(a) => Real::Direct(canonical(a)),
            r => r,
        }
    }
}

impl fmt::Debug for Real {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Real::Relay(_) => f.write_str("Relay"),
            Real::Direct(a) => write!(f, "Direct({a})"),
        }
    }
}

pub type RouteId = u64;

/// How many previous direct addresses of a route are remembered as stale (inbound dropped).
const STALE_DIRECT: usize = 16;
/// Capacity of the relay inbound queue; beyond it packets are dropped and counted.
pub const RELAY_INBOX: usize = 1024;

struct Route {
    virt: SocketAddr,
    real: Real,
    /// Addresses inbound inner packets are accepted from (rewritten to `virt`): the selected
    /// direct pair and the peer's addresses validated in the current round. The peer may switch
    /// to the direct pair a moment before us (it acknowledged the nomination first), so its
    /// direct packets must already be heard while our egress is still on the relay.
    accept: Vec<SocketAddr>,
    stale: VecDeque<SocketAddr>,
}

/// Bound of accepted inbound addresses per route.
const MAX_ACCEPT: usize = 16;

#[derive(Default)]
struct Routes {
    next: RouteId,
    by_id: HashMap<RouteId, Route>,
    by_virt: HashMap<SocketAddr, RouteId>,
    by_accept: HashMap<SocketAddr, RouteId>,
    by_stale: HashMap<SocketAddr, RouteId>,
}

/// Counters of the shared socket layer (SPEC I6).
#[derive(Default, Debug)]
pub struct SocketCounters {
    pub rx_rewritten: AtomicU64,
    pub rx_stale_dropped: AtomicU64,
    pub rx_passed: AtomicU64,
    pub relay_in: AtomicU64,
    pub relay_in_dropped: AtomicU64,
    pub relay_out: AtomicU64,
    pub direct_out: AtomicU64,
    pub tx_unrouted: AtomicU64,
    pub side_in: AtomicU64,
    pub side_unknown_tag: AtomicU64,
    pub side_dropped: AtomicU64,
    pub side_out: AtomicU64,
    pub side_out_dropped: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketStats {
    pub rx_rewritten: u64,
    pub rx_stale_dropped: u64,
    pub rx_passed: u64,
    pub relay_in: u64,
    pub relay_in_dropped: u64,
    pub relay_out: u64,
    pub direct_out: u64,
    pub tx_unrouted: u64,
    pub side_in: u64,
    pub side_unknown_tag: u64,
    pub side_dropped: u64,
    pub side_out: u64,
    pub side_out_dropped: u64,
}

pub(crate) type SideTx = mpsc::Sender<(SocketAddr, Vec<u8>)>;
/// Capacity of each side-channel queue.
pub(crate) const SIDE_QUEUE: usize = 256;

struct IoBox(Arc<dyn AsyncUdpSocket>);

/// State shared by every incarnation of the path socket of one endpoint (a rebind creates a new
/// [`PathSocket`] over a new UDP socket with the same `Shared`).
pub struct Shared {
    io: ArcSwap<IoBox>,
    routes: Mutex<Routes>,
    relay_tx: mpsc::Sender<(SocketAddr, Bytes)>,
    relay_rx: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    punch_sinks: Mutex<HashMap<[u8; TAG_LEN], SideTx>>,
    extra_sink: Mutex<Option<SideTx>>,
    rng: SystemRandom,
    pub counters: SocketCounters,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

/// quinn refuses IPv6 remotes on an endpoint whose socket reports an IPv4 local address, and the
/// virtual addresses are IPv6; so the path socket always presents an IPv6 (dual-stack) face to
/// quinn: IPv4 addresses appear as `::ffff:a.b.c.d` above it and canonical below it. Routes,
/// candidates and side-channel peers are kept canonical (X1: one form per address).
fn upward(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        v6 => v6,
    }
}

/// Canonical form: `::ffff:a.b.c.d` → `a.b.c.d`.
pub fn canonical(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip().to_canonical(), a.port())
}

/// The form the underlying socket needs: canonical for an IPv4 socket, mapped for IPv6.
fn downward(io: &dyn AsyncUdpSocket, a: SocketAddr) -> SocketAddr {
    match io.local_addr() {
        Ok(l) if l.is_ipv6() => upward(a),
        _ => canonical(a),
    }
}

/// True for the `fd00::/8` virtual addresses the path layer presents to quinn.
pub fn is_virtual(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.octets()[0] == 0xfd)
}

impl Shared {
    pub(crate) fn new(io: Arc<dyn AsyncUdpSocket>) -> Arc<Self> {
        let (relay_tx, relay_rx) = mpsc::channel(RELAY_INBOX);
        Arc::new(Self {
            io: ArcSwap::from_pointee(IoBox(io)),
            routes: Mutex::new(Routes::default()),
            relay_tx,
            relay_rx: Mutex::new(relay_rx),
            punch_sinks: Mutex::new(HashMap::new()),
            extra_sink: Mutex::new(None),
            rng: SystemRandom::new(),
            counters: SocketCounters::default(),
        })
    }

    pub(crate) fn io(&self) -> Arc<dyn AsyncUdpSocket> {
        self.io.load().0.clone()
    }

    pub(crate) fn set_io(&self, io: Arc<dyn AsyncUdpSocket>) {
        self.io.store(Arc::new(IoBox(io)));
    }

    pub(crate) fn random<const N: usize>(&self) -> [u8; N] {
        let mut b = [0; N];
        self.rng.fill(&mut b).expect("system RNG");
        b
    }

    fn fresh_virt(&self) -> SocketAddr {
        let mut o: [u8; 16] = self.random();
        o[0] = 0xfd;
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), 1)
    }

    /// Register a new route on `real`; returns its id and the virtual peer address quinn must
    /// use (dial it, or expect an incoming connection from it).
    pub fn add_route(&self, real: Real) -> (RouteId, SocketAddr) {
        let real = real.canonical();
        let virt = self.fresh_virt();
        let mut r = self.routes.lock().unwrap();
        let id = r.next;
        r.next += 1;
        let accept = match &real {
            Real::Direct(a) => {
                r.by_accept.insert(*a, id);
                vec![*a]
            }
            Real::Relay(_) => Vec::new(),
        };
        r.by_virt.insert(virt, id);
        r.by_id.insert(id, Route { virt, real, accept, stale: VecDeque::new() });
        (id, virt)
    }

    pub fn remove_route(&self, id: RouteId) {
        let mut r = self.routes.lock().unwrap();
        if let Some(route) = r.by_id.remove(&id) {
            r.by_virt.remove(&route.virt);
            for a in route.accept {
                r.by_accept.remove(&a);
            }
            for a in route.stale {
                if r.by_stale.get(&a) == Some(&id) {
                    r.by_stale.remove(&a);
                }
            }
        }
    }

    /// Switch the real path of a route. A direct address is also accepted inbound.
    pub fn set_real(&self, id: RouteId, real: Real) {
        let real = real.canonical();
        if let Real::Direct(a) = real {
            self.accept_inbound(id, a);
        }
        if let Some(route) = self.routes.lock().unwrap().by_id.get_mut(&id) {
            route.real = real;
        }
    }

    /// Accept inbound inner packets of route `id` from `addr` (an address the path manager has
    /// validated with authenticated punches).
    pub fn accept_inbound(&self, id: RouteId, addr: SocketAddr) {
        let addr = canonical(addr);
        let mut guard = self.routes.lock().unwrap();
        let r = &mut *guard;
        let Some(route) = r.by_id.get_mut(&id) else { return };
        if route.accept.contains(&addr) || route.accept.len() >= MAX_ACCEPT {
            return;
        }
        if r.by_stale.get(&addr) == Some(&id) {
            r.by_stale.remove(&addr);
            route.stale.retain(|a| *a != addr);
        }
        route.accept.push(addr);
        r.by_accept.insert(addr, id);
    }

    /// Stop accepting inbound from every address of route `id` except `keep`; they become stale
    /// (strict inbound, X8: packets still in flight on an old path are dropped).
    pub fn clear_accept(&self, id: RouteId, keep: Option<SocketAddr>) {
        let keep = keep.map(canonical);
        let mut guard = self.routes.lock().unwrap();
        let r = &mut *guard;
        let Some(route) = r.by_id.get_mut(&id) else { return };
        for a in std::mem::take(&mut route.accept) {
            if Some(a) == keep {
                route.accept.push(a);
                continue;
            }
            r.by_accept.remove(&a);
            route.stale.push_back(a);
            r.by_stale.insert(a, id);
            if route.stale.len() > STALE_DIRECT {
                let gone = route.stale.pop_front().unwrap();
                if r.by_stale.get(&gone) == Some(&id) {
                    r.by_stale.remove(&gone);
                }
            }
        }
    }

    pub fn route_real(&self, id: RouteId) -> Option<Real> {
        self.routes.lock().unwrap().by_id.get(&id).map(|r| r.real.clone())
    }

    pub fn route_virt(&self, id: RouteId) -> Option<SocketAddr> {
        self.routes.lock().unwrap().by_id.get(&id).map(|r| r.virt)
    }

    /// Deliver an inner QUIC datagram that arrived over the relay for route `id`.
    pub fn relay_input(&self, id: RouteId, packet: Bytes) {
        let Some(virt) = self.route_virt(id) else {
            self.counters.relay_in_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match self.relay_tx.try_send((virt, packet)) {
            Ok(()) => {
                self.counters.relay_in.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.counters.relay_in_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Send a side-channel datagram from the same UDP port quinn uses (so it rides the NAT
    /// mapping the gateway observed). Never blocks; a full socket drops it (counted).
    pub fn send_side(&self, to: SocketAddr, payload: &[u8]) {
        debug_assert!(wire::is_side_channel(payload[0]));
        let io = self.io();
        let t = Transmit { destination: downward(&*io, to), ecn: None, contents: payload, segment_size: None, src_ip: None };
        match io.try_send(&t) {
            Ok(()) => {
                self.counters.side_out.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.counters.side_out_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn register_punch(&self, tag: [u8; TAG_LEN], tx: SideTx) {
        self.punch_sinks.lock().unwrap().insert(tag, tx);
    }

    pub(crate) fn unregister_punch(&self, tag: &[u8; TAG_LEN]) {
        self.punch_sinks.lock().unwrap().remove(tag);
    }

    /// Receive side-channel datagrams of types `0x10..=0x3f` (not used by the path manager).
    pub fn set_extra_sink(&self, tx: mpsc::Sender<(SocketAddr, Vec<u8>)>) {
        *self.extra_sink.lock().unwrap() = Some(tx);
    }

    fn dispatch_side(&self, from: SocketAddr, d: &[u8]) {
        self.counters.side_in.fetch_add(1, Ordering::Relaxed);
        let sink = if let Some(tag) = wire::peek_tag(d) {
            self.punch_sinks.lock().unwrap().get(&tag).cloned()
        } else if d[0] >= T_EXTRA_MIN {
            self.extra_sink.lock().unwrap().clone()
        } else {
            None
        };
        match sink {
            Some(tx) => {
                if tx.try_send((from, d.to_vec())).is_err() {
                    self.counters.side_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                self.counters.side_unknown_tag.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn stats(&self) -> SocketStats {
        let c = &self.counters;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        SocketStats {
            rx_rewritten: g(&c.rx_rewritten),
            rx_stale_dropped: g(&c.rx_stale_dropped),
            rx_passed: g(&c.rx_passed),
            relay_in: g(&c.relay_in),
            relay_in_dropped: g(&c.relay_in_dropped),
            relay_out: g(&c.relay_out),
            direct_out: g(&c.direct_out),
            tx_unrouted: g(&c.tx_unrouted),
            side_in: g(&c.side_in),
            side_unknown_tag: g(&c.side_unknown_tag),
            side_dropped: g(&c.side_dropped),
            side_out: g(&c.side_out),
            side_out_dropped: g(&c.side_out_dropped),
        }
    }
}

/// One incarnation of the path socket over one UDP socket. Give it to
/// `quinn::Endpoint::new_with_abstract_socket` (and to `rebind_abstract` on rebind).
pub struct PathSocket {
    io: Arc<dyn AsyncUdpSocket>,
    shared: Arc<Shared>,
}

impl fmt::Debug for PathSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PathSocket").field("local", &self.io.local_addr().ok()).finish()
    }
}

impl PathSocket {
    pub(crate) fn new(io: Arc<dyn AsyncUdpSocket>, shared: Arc<Shared>) -> Arc<Self> {
        Arc::new(Self { io, shared })
    }
}

enum Verdict {
    Keep(SocketAddr),
    Drop,
}

impl PathSocket {
    fn classify(&self, src: SocketAddr) -> Verdict {
        let src = canonical(src);
        let r = self.shared.routes.lock().unwrap();
        if let Some(id) = r.by_accept.get(&src) {
            self.shared.counters.rx_rewritten.fetch_add(1, Ordering::Relaxed);
            return Verdict::Keep(r.by_id[id].virt);
        }
        if r.by_stale.contains_key(&src) {
            self.shared.counters.rx_stale_dropped.fetch_add(1, Ordering::Relaxed);
            return Verdict::Drop;
        }
        self.shared.counters.rx_passed.fetch_add(1, Ordering::Relaxed);
        Verdict::Keep(upward(src))
    }
}

impl AsyncUdpSocket for PathSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.io.clone().create_io_poller()
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        if !is_virtual(t.destination.ip()) {
            return self.io.try_send(&Transmit { destination: downward(&*self.io, t.destination), ..*t });
        }
        let real = {
            let r = self.shared.routes.lock().unwrap();
            r.by_virt.get(&t.destination).map(|id| r.by_id[id].real.clone())
        };
        match real {
            Some(Real::Direct(addr)) => {
                self.shared.counters.direct_out.fetch_add(1, Ordering::Relaxed);
                self.io.try_send(&Transmit { destination: downward(&*self.io, addr), src_ip: None, ..*t })
            }
            Some(Real::Relay(link)) => {
                let seg = t.segment_size.unwrap_or(t.contents.len()).max(1);
                for chunk in t.contents.chunks(seg) {
                    self.shared.counters.relay_out.fetch_add(1, Ordering::Relaxed);
                    link.send(chunk);
                }
                Ok(())
            }
            None => {
                // An address of a removed route: behave like a black hole (QUIC recovers or
                // times out), never like an error that would kill the whole endpoint.
                self.shared.counters.tx_unrouted.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            // Relay first: it is a bounded queue filled by the carrier.
            let mut n = 0;
            {
                let mut rx = self.shared.relay_rx.lock().unwrap();
                while n < bufs.len().min(meta.len()) {
                    match rx.poll_recv(cx) {
                        Poll::Ready(Some((src, pkt))) => {
                            if pkt.len() > bufs[n].len() {
                                self.shared.counters.relay_in_dropped.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            bufs[n][..pkt.len()].copy_from_slice(&pkt);
                            meta[n] = RecvMeta {
                                addr: src,
                                len: pkt.len(),
                                stride: pkt.len(),
                                ecn: None,
                                dst_ip: None,
                            };
                            n += 1;
                        }
                        _ => break,
                    }
                }
            }
            if n > 0 {
                return Poll::Ready(Ok(n));
            }

            let got = match self.io.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(got)) => got,
                other => return other,
            };
            let mut kept = 0;
            for i in 0..got {
                let mut m = meta[i];
                if m.len == 0 {
                    continue;
                }
                if wire::is_side_channel(bufs[i][0]) {
                    let stride = m.stride.max(1);
                    let mut off = 0;
                    while off < m.len {
                        let end = (off + stride).min(m.len);
                        let seg = &bufs[i][off..end];
                        if !seg.is_empty() && wire::is_side_channel(seg[0]) {
                            self.shared.dispatch_side(canonical(m.addr), seg);
                        }
                        off = end;
                    }
                    continue;
                }
                match self.classify(m.addr) {
                    Verdict::Drop => continue,
                    Verdict::Keep(addr) => m.addr = addr,
                }
                if kept != i {
                    let (lo, hi) = bufs.split_at_mut(i);
                    lo[kept][..m.len].copy_from_slice(&hi[0][..m.len]);
                }
                meta[kept] = m;
                kept += 1;
            }
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
            // Everything was side channel or stale: poll again so the wakers are re-registered.
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr().map(upward)
    }

    fn max_transmit_segments(&self) -> usize {
        self.io.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.io.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.io.may_fragment()
    }
}
