//! Test world: two peers behind simulated NATs, a public gateway that reflects and relays, an
//! inner QUIC connection between the peers over the relay, and the path machinery on both ends
//! with its signals carried over the inner connection itself (as ssh3-core will do).
#![allow(dead_code)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig};
use ring::digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use ssh3_path::sim::{Filtering, Mapping, NatConfig, NatId, SimGateway, SimNet, SimPeerAgent, SimRelayLink};
use ssh3_path::{wire, PathConfig, PathManager, PeerPath, PeerSetup, PeerStatus, RelayLink, RouteId};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

pub const GW: &str = "203.0.113.1:443";
pub const NAT_A: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
pub const NAT_B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
/// Upper bound of every wait in these tests.
pub const BOUND: Duration = Duration::from_secs(10);

pub fn cfg() -> PathConfig {
    PathConfig {
        punch_interval: Duration::from_millis(20),
        round_timeout: Duration::from_millis(800),
        retry_interval: Duration::from_millis(300),
        keepalive_interval: Duration::from_millis(80),
        direct_timeout: Duration::from_millis(400),
        reset_on_switch: true,
    }
}

pub fn nat(ip: Ipv4Addr, kind: &str) -> NatConfig {
    let (m, f) = match kind {
        "full-cone" => (Mapping::EndpointIndependent, Filtering::EndpointIndependent),
        "restricted-cone" => (Mapping::EndpointIndependent, Filtering::AddressDependent),
        "port-restricted-cone" => (Mapping::EndpointIndependent, Filtering::AddressAndPortDependent),
        "symmetric" => (Mapping::EndpointDependent, Filtering::AddressAndPortDependent),
        other => panic!("unknown NAT kind {other}"),
    };
    NatConfig::new(ip, m, f)
}

struct Identity {
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

fn identity() -> Identity {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ck = rcgen::generate_simple_self_signed(vec!["peer".into()]).unwrap();
    Identity { cert: ck.cert.der().clone(), key: PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()) }
}

pub fn transport() -> TransportConfig {
    let mut tc = TransportConfig::default();
    tc.initial_rtt(Duration::from_millis(30));
    tc.keep_alive_interval(Some(Duration::from_millis(100)));
    tc.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));
    tc
}

pub fn endpoint_config() -> EndpointConfig {
    let mut ec = EndpointConfig::default();
    ec.grease_quic_bit(false);
    ec
}

pub struct Peer {
    pub name: &'static [u8],
    pub mgr: Arc<PathManager>,
    pub ep: Endpoint,
    pub agent: SimPeerAgent,
    pub nat: Option<NatId>,
    pub ip: IpAddr,
}

pub struct World {
    pub net: Arc<SimNet>,
    pub gw: SimGateway,
    pub a: Peer,
    pub b: Peer,
}

impl World {
    /// `kind_a`/`kind_b`: NAT kind or "public".
    pub fn new(kind_a: &str, kind_b: &str) -> Self {
        let net = SimNet::new();
        let gw_addr: SocketAddr = GW.parse().unwrap();
        // Relay path long and narrow, direct path short and wide.
        net.set_delay(gw_addr.ip(), Duration::from_millis(15));
        net.set_delay(IpAddr::V4(NAT_A), Duration::from_millis(2));
        net.set_delay(IpAddr::V4(NAT_B), Duration::from_millis(2));
        let gw = SimGateway::spawn(&net, gw_addr);
        let id = identity();
        let mut sc = ServerConfig::with_single_cert(vec![id.cert.clone()], PrivateKeyDer::Pkcs8(id.key.clone_key())).unwrap();
        sc.transport_config(Arc::new(transport()));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(id.cert.clone()).unwrap();
        let crypto = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let mut cc = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
        cc.transport_config(Arc::new(transport()));
        let a = Self::peer(&net, b"A", kind_a, NAT_A, "10.0.1.2:5000", "198.51.100.11:5000", Some(cc), None);
        let b = Self::peer(&net, b"B", kind_b, NAT_B, "10.0.2.2:6000", "198.51.100.12:6000", None, Some(sc));
        Self { net, gw, a, b }
    }

    #[allow(clippy::too_many_arguments)]
    fn peer(
        net: &Arc<SimNet>,
        name: &'static [u8],
        kind: &str,
        nat_ip: Ipv4Addr,
        private: &str,
        public: &str,
        cc: Option<ClientConfig>,
        sc: Option<ServerConfig>,
    ) -> Peer {
        let (nat, addr): (Option<NatId>, SocketAddr) = if kind == "public" {
            (None, public.parse().unwrap())
        } else {
            (Some(net.add_nat(nat(nat_ip, kind))), private.parse().unwrap())
        };
        let sock = net.bind(addr, nat);
        let mgr = PathManager::new(sock);
        let mut ep = Endpoint::new_with_abstract_socket(endpoint_config(), sc, mgr.socket(), Arc::new(TokioRuntime)).unwrap();
        if let Some(cc) = cc {
            ep.set_default_client_config(cc);
        }
        mgr.attach_endpoint(ep.clone());
        let agent = SimPeerAgent::spawn(mgr.clone(), GW.parse().unwrap(), name, Duration::from_millis(50));
        let ip = if kind == "public" { addr.ip() } else { IpAddr::V4(nat_ip) };
        Peer { name, mgr, ep, agent, nat, ip }
    }

    /// Establish the inner connection over the relay and start the path machinery on both
    /// sides. `a_controls`: A is the controlling peer.
    pub async fn connect(&self, a_controls: bool, path_cfg: PathConfig) -> Pair {
        let gw: SocketAddr = GW.parse().unwrap();
        let link_a: Arc<CountingLink> = CountingLink::new(SimRelayLink { mgr: self.a.mgr.clone(), gateway: gw, to: b"B".to_vec() });
        let link_b: Arc<CountingLink> = CountingLink::new(SimRelayLink { mgr: self.b.mgr.clone(), gateway: gw, to: b"A".to_vec() });
        let (route_a, virt_b) = self.a.mgr.add_relay_route(link_a.clone());
        self.a.agent.route_from(b"B", route_a);
        let (route_b, _virt_a) = self.b.mgr.add_relay_route(link_b.clone());
        self.b.agent.route_from(b"A", route_b);
        let refl_a = wait_reflexive(&self.a.agent).await;
        let refl_b = wait_reflexive(&self.b.agent).await;

        let (ca, cb) = tokio::join!(
            async { timeout(BOUND, self.a.ep.connect(virt_b, "peer").unwrap()).await.expect("dial over relay: timed out").expect("dial over relay") },
            async {
                let inc = timeout(BOUND, self.b.ep.accept()).await.expect("accept over relay: timed out").expect("endpoint closed");
                inc.await.expect("inner handshake")
            }
        );
        let mut sa = [0u8; 32];
        let mut sb = [0u8; 32];
        ca.export_keying_material(&mut sa, wire::EXPORTER_LABEL, b"").unwrap();
        cb.export_keying_material(&mut sb, wire::EXPORTER_LABEL, b"").unwrap();
        assert_eq!(sa, sb);

        let (sig_a_tx, sig_a_rx) = mpsc::unbounded_channel();
        let (sig_b_tx, sig_b_rx) = mpsc::unbounded_channel();
        let pa = Arc::new(self.a.mgr.start_peer(PeerSetup {
            route: route_a,
            relay: link_a.clone(),
            conn: ca.clone(),
            secret: sa,
            controlling: a_controls,
            signals: sig_a_tx,
            reflexive: Some(refl_a),
            cfg: path_cfg.clone(),
        }));
        let pb = Arc::new(self.b.mgr.start_peer(PeerSetup {
            route: route_b,
            relay: link_b.clone(),
            conn: cb.clone(),
            secret: sb,
            controlling: !a_controls,
            signals: sig_b_tx,
            reflexive: Some(refl_b),
            cfg: path_cfg,
        }));
        spawn_signal_pump(ca.clone(), sig_a_rx, pa.clone());
        spawn_signal_pump(cb.clone(), sig_b_rx, pb.clone());
        Pair { ca, cb, pa, pb, route_a, route_b, link_a, link_b, secret: sa }
    }
}

async fn wait_reflexive(agent: &SimPeerAgent) -> SocketAddr {
    let mut rx = agent.reflexive.clone();
    let v = timeout(BOUND, rx.wait_for(|v| v.is_some())).await.expect("no reflexive address from gateway").unwrap();
    v.unwrap()
}

/// Signals go over the inner connection: one uni stream per signal, both directions.
fn spawn_signal_pump(conn: quinn::Connection, mut out: mpsc::UnboundedReceiver<Vec<u8>>, me: Arc<PeerPath>) {
    let c2 = conn.clone();
    tokio::spawn(async move {
        while let Some(b) = out.recv().await {
            let Ok(mut s) = c2.open_uni().await else { break };
            if s.write_all(&b).await.is_err() || s.finish().is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Ok(mut s) = conn.accept_uni().await {
            let me = me.clone();
            tokio::spawn(async move {
                if let Ok(b) = s.read_to_end(wire::MAX_SIGNAL_LEN).await {
                    me.signal_in(b);
                }
            });
        }
    });
}

/// Relay link wrapper that counts packets (to see which carrier is in use).
pub struct CountingLink {
    pub inner: SimRelayLink,
    pub sent: AtomicU64,
}

impl CountingLink {
    pub fn new(inner: SimRelayLink) -> Arc<Self> {
        Arc::new(Self { inner, sent: AtomicU64::new(0) })
    }
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}

impl RelayLink for CountingLink {
    fn send(&self, packet: &[u8]) {
        self.sent.fetch_add(1, Ordering::Relaxed);
        self.inner.send(packet)
    }
}

pub struct Pair {
    pub ca: quinn::Connection,
    pub cb: quinn::Connection,
    pub pa: Arc<PeerPath>,
    pub pb: Arc<PeerPath>,
    pub route_a: RouteId,
    pub route_b: RouteId,
    pub link_a: Arc<CountingLink>,
    pub link_b: Arc<CountingLink>,
    /// The exporter-derived punch secret (same on both peers).
    pub secret: [u8; 32],
}

impl World {
    /// Network-side diagnostics for failure messages.
    pub fn diag(&self) -> String {
        let m = |n: Option<NatId>| n.map(|n| self.net.mappings(n)).unwrap_or_default();
        format!(
            "net {:?}\n filtered {:?}\n NAT A {:?}\n NAT B {:?}\n sock A {:?}\n sock B {:?}",
            self.net.counters, self.net.filtered(), m(self.a.nat), m(self.b.nat), self.a.mgr.socket_stats(), self.b.mgr.socket_stats()
        )
    }
}

/// Like [`until`], with the network state in the failure message and the other peer's state.
pub async fn until_w(w: &World, p: &PeerPath, other: &PeerPath, what: &str, pred: impl Fn(&PeerStatus) -> bool) -> PeerStatus {
    let mut rx: watch::Receiver<PeerStatus> = p.watch();
    match timeout(BOUND, rx.wait_for(|s| pred(s))).await {
        Ok(Ok(s)) => s.clone(),
        _ => panic!(
            "timed out waiting for {what}: status {:?}, counters {:?}\nother: {:?} {:?}\n{}",
            p.status(), p.counters, other.status(), other.counters, w.diag()
        ),
    }
}

/// Wait until `pred` holds for a peer status, or fail naming the state and counters.
pub async fn until(p: &PeerPath, what: &str, pred: impl Fn(&PeerStatus) -> bool) -> PeerStatus {
    let mut rx: watch::Receiver<PeerStatus> = p.watch();
    match timeout(BOUND, rx.wait_for(|s| pred(s))).await {
        Ok(Ok(s)) => s.clone(),
        _ => panic!("timed out waiting for {what}: status {:?}, counters {:?}", p.status(), p.counters),
    }
}

pub fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

pub fn sha(d: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, d).as_ref().to_vec()
}

/// A transfer A → B running in the background; `finish` checks the SHA-256 on B.
pub struct Transfer {
    expect: Vec<u8>,
    writer: tokio::task::JoinHandle<()>,
    reader: tokio::task::JoinHandle<Vec<u8>>,
}

pub async fn start_transfer(pair: &Pair, len: usize) -> Transfer {
    let data = pattern(len);
    let expect = sha(&data);
    let (mut s, _r) = pair.ca.open_bi().await.unwrap();
    let writer = tokio::spawn(async move {
        s.write_all(&data).await.expect("write");
        s.finish().unwrap();
        let _ = s.stopped().await;
        drop(_r);
    });
    let cb = pair.cb.clone();
    let reader = tokio::spawn(async move {
        let (_w, mut r) = cb.accept_bi().await.expect("accept_bi");
        let got = r.read_to_end(len + 1).await.expect("read");
        sha(&got)
    });
    Transfer { expect, writer, reader }
}

impl Transfer {
    pub async fn finish(self) {
        let got = timeout(BOUND * 3, self.reader).await.expect("transfer timed out").unwrap();
        assert_eq!(got, self.expect, "SHA-256 of the transferred data differs");
        let _ = timeout(BOUND, self.writer).await;
    }
}
