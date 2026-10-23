//! In-memory UDP network with NATs, for deterministic tests of NAT traversal without root,
//! network namespaces or `tc`.
//!
//! * Hosts own [`SimSocket`]s (quinn `AsyncUdpSocket`s) on simulated addresses; a host is either
//!   public or behind a [`NatConfig`].
//! * NAT behaviour follows RFC 4787 terms: mapping is endpoint-independent (EIM) or
//!   endpoint-dependent ("symmetric", common in CGNAT); filtering is endpoint-independent (full
//!   cone), address-dependent or address-and-port-dependent; mappings expire after an idle
//!   timeout refreshed by outbound traffic only. No hairpinning.
//! * Links: per-IP one-way delay, per-IP MTU (larger datagrams are dropped, like a PMTU black
//!   hole), deterministic loss, and blocks between IP pairs (to cut a direct path while the
//!   gateway stays reachable).
//! * [`SimGateway`] is a public rendezvous: it reflects the observed address of every registered
//!   peer and relays frames between peers by name — standing in for the carrier QUIC connection
//!   and the gateway's `jump` relay of SPEC §7.2.
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::socket::{RelayLink, RouteId};
use crate::PathManager;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mapping {
    EndpointIndependent,
    /// A new public port per destination (symmetric NAT).
    EndpointDependent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filtering {
    /// Full cone.
    EndpointIndependent,
    /// Restricted cone: inbound only from IPs the mapping has sent to.
    AddressDependent,
    /// Port-restricted cone: inbound only from exact IP:port the mapping has sent to.
    AddressAndPortDependent,
}

#[derive(Clone, Copy, Debug)]
pub struct NatConfig {
    pub public_ip: Ipv4Addr,
    pub mapping: Mapping,
    pub filtering: Filtering,
    pub timeout: Duration,
}

impl NatConfig {
    pub fn new(public_ip: Ipv4Addr, mapping: Mapping, filtering: Filtering) -> Self {
        Self { public_ip, mapping, filtering, timeout: Duration::from_secs(30) }
    }
    pub fn kind(&self) -> &'static str {
        match (self.mapping, self.filtering) {
            (Mapping::EndpointIndependent, Filtering::EndpointIndependent) => "full-cone",
            (Mapping::EndpointIndependent, Filtering::AddressDependent) => "restricted-cone",
            (Mapping::EndpointIndependent, Filtering::AddressAndPortDependent) => "port-restricted-cone",
            (Mapping::EndpointDependent, _) => "symmetric",
        }
    }
}

pub type NatId = usize;

struct MapEntry {
    private: SocketAddr,
    last_out: Instant,
    perms: HashSet<SocketAddr>,
}

struct Nat {
    cfg: NatConfig,
    next_port: u16,
    by_key: HashMap<(SocketAddr, Option<SocketAddr>), u16>,
    by_port: HashMap<u16, MapEntry>,
}

impl Nat {
    fn outbound(&mut self, src: SocketAddr, dst: SocketAddr, now: Instant) -> SocketAddr {
        let key = (src, if self.cfg.mapping == Mapping::EndpointDependent { Some(dst) } else { None });
        let port = match self.by_key.get(&key) {
            Some(&p) if self.by_port.get(&p).is_some_and(|e| now < e.last_out + self.cfg.timeout) => p,
            _ => {
                let p = self.next_port;
                self.next_port = self.next_port.wrapping_add(1).max(20000);
                self.by_key.insert(key, p);
                self.by_port.insert(p, MapEntry { private: src, last_out: now, perms: HashSet::new() });
                p
            }
        };
        let e = self.by_port.get_mut(&port).unwrap();
        e.last_out = now;
        e.perms.insert(dst);
        SocketAddr::new(IpAddr::V4(self.cfg.public_ip), port)
    }

    fn inbound(&self, port: u16, from: SocketAddr, now: Instant) -> Option<SocketAddr> {
        let e = self.by_port.get(&port)?;
        if now >= e.last_out + self.cfg.timeout {
            return None;
        }
        let ok = match self.cfg.filtering {
            Filtering::EndpointIndependent => true,
            Filtering::AddressDependent => e.perms.iter().any(|p| p.ip() == from.ip()),
            Filtering::AddressAndPortDependent => e.perms.contains(&from),
        };
        ok.then_some(e.private)
    }
}

struct Host {
    tx: mpsc::UnboundedSender<(SocketAddr, Bytes)>,
    nat: Option<NatId>,
}

#[derive(Default, Debug)]
pub struct NetCounters {
    pub delivered: AtomicU64,
    pub dropped_filtered: AtomicU64,
    pub dropped_no_host: AtomicU64,
    pub dropped_blocked: AtomicU64,
    pub dropped_mtu: AtomicU64,
    pub dropped_loss: AtomicU64,
}

#[derive(Default)]
struct State {
    hosts: HashMap<SocketAddr, Host>,
    nats: Vec<Nat>,
    blocks: HashSet<(IpAddr, IpAddr)>,
    delay: HashMap<IpAddr, Duration>,
    mtu: HashMap<IpAddr, usize>,
    /// Loss permille per IP (applied to datagrams from or to it).
    loss: HashMap<IpAddr, u32>,
    rng: u64,
}

pub struct SimNet {
    st: Mutex<State>,
    pub counters: NetCounters,
    /// The most recent datagrams a NAT filtered out: (destination, source) — diagnostics.
    filtered: Mutex<std::collections::VecDeque<(SocketAddr, SocketAddr)>>,
}

impl fmt::Debug for SimNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimNet").finish_non_exhaustive()
    }
}

/// Largest UDP payload the simulator carries when no MTU is set for an IP (1500-byte link).
pub const DEFAULT_MTU: usize = 1472;

impl SimNet {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            st: Mutex::new(State { rng: 0x9e37_79b9_7f4a_7c15, ..Default::default() }),
            counters: NetCounters::default(),
            filtered: Mutex::new(std::collections::VecDeque::new()),
        })
    }

    pub fn add_nat(&self, cfg: NatConfig) -> NatId {
        let mut st = self.st.lock().unwrap();
        st.nats.push(Nat { cfg, next_port: 20000, by_key: HashMap::new(), by_port: HashMap::new() });
        st.nats.len() - 1
    }

    /// Bind a socket at `addr` (a private address when `nat` is set).
    pub fn bind(self: &Arc<Self>, addr: SocketAddr, nat: Option<NatId>) -> Arc<SimSocket> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.st.lock().unwrap().hosts.insert(addr, Host { tx, nat });
        Arc::new(SimSocket { net: self.clone(), addr, rx: Mutex::new(rx) })
    }

    /// Cut (or restore) all traffic between two public IPs, both directions.
    pub fn block(&self, a: IpAddr, b: IpAddr, on: bool) {
        let mut st = self.st.lock().unwrap();
        if on {
            st.blocks.insert((a, b));
            st.blocks.insert((b, a));
        } else {
            st.blocks.remove(&(a, b));
            st.blocks.remove(&(b, a));
        }
    }

    /// One-way delay added to every datagram from or to `ip` (public IPs).
    pub fn set_delay(&self, ip: IpAddr, d: Duration) {
        self.st.lock().unwrap().delay.insert(ip, d);
    }

    /// Datagrams larger than `mtu` from or to `ip` are dropped.
    pub fn set_mtu(&self, ip: IpAddr, mtu: usize) {
        self.st.lock().unwrap().mtu.insert(ip, mtu);
    }

    pub fn set_loss_permille(&self, ip: IpAddr, permille: u32) {
        self.st.lock().unwrap().loss.insert(ip, permille);
    }

    fn send(&self, src: SocketAddr, dst: SocketAddr, data: Bytes) {
        let now = Instant::now();
        let mut st = self.st.lock().unwrap();
        let src_nat = st.hosts.get(&src).and_then(|h| h.nat);
        // Same private network: delivered directly, no translation.
        if let Some(n) = src_nat
            && st.hosts.get(&dst).and_then(|h| h.nat) == Some(n) {
                let tx = st.hosts[&dst].tx.clone();
                drop(st);
                self.counters.delivered.fetch_add(1, Ordering::Relaxed);
                let _ = tx.send((src, data));
                return;
            }
        let pub_src = match src_nat {
            Some(n) => st.nats[n].outbound(src, dst, now),
            None => src,
        };
        if st.blocks.contains(&(pub_src.ip(), dst.ip())) {
            self.counters.dropped_blocked.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mtu = |ip: &IpAddr| st.mtu.get(ip).copied().unwrap_or(DEFAULT_MTU);
        if data.len() > mtu(&pub_src.ip()).min(mtu(&dst.ip())) {
            self.counters.dropped_mtu.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let loss = st.loss.get(&pub_src.ip()).copied().unwrap_or(0) + st.loss.get(&dst.ip()).copied().unwrap_or(0);
        if loss > 0 {
            st.rng ^= st.rng << 13;
            st.rng ^= st.rng >> 7;
            st.rng ^= st.rng << 17;
            if (st.rng % 1000) < loss as u64 {
                self.counters.dropped_loss.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Resolve the destination: a NAT's public address or a public host.
        let nat_of_dst = st.nats.iter().position(|n| IpAddr::V4(n.cfg.public_ip) == dst.ip());
        let target = match nat_of_dst {
            Some(n) => match st.nats[n].inbound(dst.port(), pub_src, now) {
                Some(p) => p,
                None => {
                    self.counters.dropped_filtered.fetch_add(1, Ordering::Relaxed);
                    let mut f = self.filtered.lock().unwrap();
                    f.push_back((dst, pub_src));
                    if f.len() > 64 {
                        f.pop_front();
                    }
                    return;
                }
            },
            None => {
                if st.hosts.get(&dst).is_some_and(|h| h.nat.is_some()) {
                    // A private address is not reachable from outside its NAT.
                    self.counters.dropped_no_host.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                dst
            }
        };
        let Some(h) = st.hosts.get(&target) else {
            self.counters.dropped_no_host.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let tx = h.tx.clone();
        let delay = st.delay.get(&pub_src.ip()).copied().unwrap_or_default()
            + st.delay.get(&dst.ip()).copied().unwrap_or_default();
        drop(st);
        self.counters.delivered.fetch_add(1, Ordering::Relaxed);
        if delay.is_zero() {
            let _ = tx.send((pub_src, data));
        } else {
            tokio::spawn(async move {
                tokio::time::sleep_until(now + delay).await;
                let _ = tx.send((pub_src, data));
            });
        }
    }

    /// Recently filtered datagrams (destination, source).
    pub fn filtered(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.filtered.lock().unwrap().iter().copied().collect()
    }

    /// Live mappings of a NAT: (public port, private address, permissions).
    pub fn mappings(&self, nat: NatId) -> Vec<(u16, SocketAddr, Vec<SocketAddr>)> {
        let st = self.st.lock().unwrap();
        let mut v: Vec<_> = st.nats[nat].by_port.iter().map(|(p, e)| (*p, e.private, e.perms.iter().copied().collect())).collect();
        v.sort_by_key(|x| x.0);
        v
    }

    fn unbind(&self, addr: SocketAddr) {
        self.st.lock().unwrap().hosts.remove(&addr);
    }
}

/// A simulated UDP socket.
pub struct SimSocket {
    net: Arc<SimNet>,
    addr: SocketAddr,
    rx: Mutex<mpsc::UnboundedReceiver<(SocketAddr, Bytes)>>,
}

impl fmt::Debug for SimSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SimSocket({})", self.addr)
    }
}

impl Drop for SimSocket {
    fn drop(&mut self) {
        self.net.unbind(self.addr);
    }
}

impl SimSocket {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    /// Plain send for non-quinn users (the gateway).
    pub fn send_to(&self, to: SocketAddr, data: &[u8]) {
        self.net.send(self.addr, to, Bytes::copy_from_slice(data));
    }
    pub async fn recv_from(&self) -> Option<(SocketAddr, Bytes)> {
        std::future::poll_fn(|cx| self.rx.lock().unwrap().poll_recv(cx)).await
    }
}

#[derive(Debug)]
struct Writable;

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for SimSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable)
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        let seg = t.segment_size.unwrap_or(t.contents.len()).max(1);
        for chunk in t.contents.chunks(seg) {
            self.net.send(self.addr, t.destination, Bytes::copy_from_slice(chunk));
        }
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let mut rx = self.rx.lock().unwrap();
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            match rx.poll_recv(cx) {
                Poll::Ready(Some((src, d))) => {
                    let len = d.len().min(bufs[n].len());
                    bufs[n][..len].copy_from_slice(&d[..len]);
                    meta[n] = RecvMeta { addr: src, len, stride: len, ecn: None, dst_ip: None };
                    n += 1;
                }
                Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Poll::Pending => break,
            }
        }
        if n == 0 { Poll::Pending } else { Poll::Ready(Ok(n)) }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        1
    }
    fn may_fragment(&self) -> bool {
        false
    }
}

/// Gateway frame types (side channel, fixed bit clear, ≥ `wire::T_EXTRA_MIN`).
pub const G_RELAY: u8 = 0x10;
pub const G_REGISTER: u8 = 0x11;
pub const G_REFLECT: u8 = 0x12;
pub const G_RELAYED: u8 = 0x13;

/// Public rendezvous + relay for tests.
pub struct SimGateway {
    pub addr: SocketAddr,
    pub relayed: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for SimGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SimGateway {
    pub fn spawn(net: &Arc<SimNet>, addr: SocketAddr) -> Self {
        let sock = net.bind(addr, None);
        let relayed = Arc::new(AtomicU64::new(0));
        let r2 = relayed.clone();
        let task = tokio::spawn(async move {
            let mut peers: HashMap<Vec<u8>, SocketAddr> = HashMap::new();
            while let Some((from, d)) = sock.recv_from().await {
                match d.first() {
                    Some(&G_REGISTER) => {
                        peers.insert(d[1..].to_vec(), from);
                        let mut f = vec![G_REFLECT];
                        f.extend_from_slice(from.to_string().as_bytes());
                        sock.send_to(from, &f);
                    }
                    Some(&G_RELAY) if d.len() > 2 => {
                        let n = d[1] as usize;
                        if d.len() < 2 + n {
                            continue;
                        }
                        let to = &d[2..2 + n];
                        let Some(&dst) = peers.get(to) else { continue };
                        let Some(src_name) = peers.iter().find(|(_, a)| **a == from).map(|(k, _)| k.clone()) else { continue };
                        let mut f = vec![G_RELAYED, src_name.len() as u8];
                        f.extend_from_slice(&src_name);
                        f.extend_from_slice(&d[2 + n..]);
                        r2.fetch_add(1, Ordering::Relaxed);
                        sock.send_to(dst, &f);
                    }
                    _ => {}
                }
            }
        });
        Self { addr, relayed, task }
    }
}

/// Relay link of a simulated peer: frames inner packets to the gateway on the peer's own path
/// socket (so they ride the same NAT mapping, like the carrier connection would).
pub struct SimRelayLink {
    pub mgr: Arc<PathManager>,
    pub gateway: SocketAddr,
    pub to: Vec<u8>,
}

impl RelayLink for SimRelayLink {
    fn send(&self, packet: &[u8]) {
        let mut f = Vec::with_capacity(2 + self.to.len() + packet.len());
        f.push(G_RELAY);
        f.push(self.to.len() as u8);
        f.extend_from_slice(&self.to);
        f.extend_from_slice(packet);
        self.mgr.shared().send_side(self.gateway, &f);
    }
}

/// Glue for a simulated peer: registers at the gateway periodically (keeping its NAT mapping
/// alive and refreshing the reflexive address) and delivers relayed frames to the right route.
pub struct SimPeerAgent {
    pub reflexive: tokio::sync::watch::Receiver<Option<SocketAddr>>,
    routes: Arc<Mutex<HashMap<Vec<u8>, RouteId>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for SimPeerAgent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SimPeerAgent {
    pub fn spawn(mgr: Arc<PathManager>, gateway: SocketAddr, name: &[u8], every: Duration) -> Self {
        let (tx, mut rx) = mpsc::channel(1024);
        mgr.shared().set_extra_sink(tx);
        let (refl_tx, refl_rx) = tokio::sync::watch::channel(None);
        let routes: Arc<Mutex<HashMap<Vec<u8>, RouteId>>> = Arc::default();
        let r2 = routes.clone();
        let mut reg = vec![G_REGISTER];
        reg.extend_from_slice(name);
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tokio::select! {
                    _ = tick.tick() => mgr.shared().send_side(gateway, &reg),
                    m = rx.recv() => {
                        let Some((_, d)) = m else { break };
                        match d.first() {
                            Some(&G_REFLECT) => {
                                if let Some(a) = std::str::from_utf8(&d[1..]).ok().and_then(|s| s.parse().ok()) {
                                    refl_tx.send_if_modified(|v| { let ch = *v != Some(a); *v = Some(a); ch });
                                }
                            }
                            Some(&G_RELAYED) if d.len() > 2 => {
                                let n = d[1] as usize;
                                if d.len() < 2 + n { continue; }
                                let id = r2.lock().unwrap().get(&d[2..2 + n]).copied();
                                if let Some(id) = id {
                                    mgr.relay_input(id, Bytes::copy_from_slice(&d[2 + n..]));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
        Self { reflexive: refl_rx, routes, task }
    }

    /// Deliver relayed frames from peer `from` to route `id`.
    pub fn route_from(&self, from: &[u8], id: RouteId) {
        self.routes.lock().unwrap().insert(from.to_vec(), id);
    }
}
