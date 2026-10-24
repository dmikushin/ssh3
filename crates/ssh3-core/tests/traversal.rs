//! Jump to a registered peer and upgrade to a direct path (SPEC §7.1–7.3),
//! end to end through real ssh3 servers and sessions on the ssh3-path NAT
//! simulator: a public gateway, a client behind NAT A, a target server
//! behind NAT B registered at the gateway.
mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use ssh3_core::client::HostCheck;
use ssh3_core::path::sim::{Filtering, Mapping, NatConfig, SimNet};
use ssh3_core::path::{PathConfig, PathManager, PathMode};
use ssh3_core::{ClientOptions, ClientSession, Server};
use ssh3_keys::verifier::StrictHostKeyChecking;

const GW: &str = "203.0.113.1:443";
const NAT_A: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const NAT_B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const BOUND: Duration = Duration::from_secs(15);

fn nat(ip: Ipv4Addr, kind: &str) -> NatConfig {
    let (m, f) = match kind {
        "port-restricted-cone" => (Mapping::EndpointIndependent, Filtering::AddressAndPortDependent),
        "symmetric" => (Mapping::EndpointDependent, Filtering::AddressAndPortDependent),
        "full-cone" => (Mapping::EndpointIndependent, Filtering::EndpointIndependent),
        k => panic!("unknown NAT kind {k}"),
    };
    NatConfig::new(ip, m, f)
}

fn path_cfg() -> PathConfig {
    PathConfig {
        punch_interval: Duration::from_millis(20),
        round_timeout: Duration::from_millis(800),
        retry_interval: Duration::from_millis(300),
        keepalive_interval: Duration::from_millis(80),
        direct_timeout: Duration::from_millis(400),
        reset_on_switch: true,
    }
}

struct World {
    net: Arc<SimNet>,
    gw: Env,
    target: Env,
    /// The target's registration session at the gateway.
    _reg: ClientSession,
    client_mgr: Arc<PathManager>,
}

fn host(name: &str, port: u16, env: &Env) -> HostCheck {
    ssh3_keys::known_hosts::append(&env.known_hosts, name, port, env.host.public_key(), false).unwrap();
    HostCheck { name: name.into(), port, files: vec![env.known_hosts.clone()], mode: StrictHostKeyChecking::Yes, hash_known_hosts: false, prompt: None }
}

fn opts(env: &Env, addr: SocketAddr, host: HostCheck, path: Option<Arc<PathManager>>) -> ClientOptions {
    ClientOptions { server_addr: addr, host, path, ..env.opts(&env.key) }
}

impl World {
    async fn new(kind_a: &str, kind_b: &str) -> Self {
        let net = SimNet::new();
        let gw_addr: SocketAddr = GW.parse().unwrap();
        // Relay long and narrow, direct short (as ssh3-path's own tests).
        net.set_delay(gw_addr.ip(), Duration::from_millis(15));
        net.set_delay(IpAddr::V4(NAT_A), Duration::from_millis(2));
        net.set_delay(IpAddr::V4(NAT_B), Duration::from_millis(2));
        let gw_mgr = PathManager::new(net.bind(gw_addr, None));
        let gw = env_bind(fast_limits(), session_env(), |o| Server::bind_path(o, gw_mgr).unwrap());
        let nb = net.add_nat(nat(NAT_B, kind_b));
        let b_mgr = PathManager::new(net.bind("10.0.2.2:6000".parse().unwrap(), Some(nb)));
        let target = env_bind(fast_limits(), session_env(), |o| Server::bind_path(o, b_mgr).unwrap());
        let reg = target.server.register_at(opts(&gw, gw_addr, host("gw", 443, &gw), None), "B", path_cfg()).await.unwrap();
        let na = net.add_nat(nat(NAT_A, kind_a));
        let client_mgr = PathManager::new(net.bind("10.0.1.2:5000".parse().unwrap(), Some(na)));
        Self { net, gw, target, _reg: reg, client_mgr }
    }

    /// Gateway session of the client, the jump path to peer B and the inner
    /// session over it with the direct-path machinery started.
    async fn connect(&self) -> (ClientSession, ssh3_core::jump::JumpPath, ClientSession) {
        let gw_addr: SocketAddr = GW.parse().unwrap();
        let c = ClientSession::connect(opts(&self.gw, gw_addr, host("gw", 443, &self.gw), Some(self.client_mgr.clone())), self.client_mgr.socket()).await.unwrap();
        let path = c.jump_peer("B").await.unwrap();
        let inner_opts = path.inner_opts(opts(&self.target, path.virt, host("B", 22, &self.target), None));
        let inner = tokio::time::timeout(BOUND, ClientSession::connect(inner_opts, path.socket())).await.expect("inner connect timed out").unwrap();
        path.start_direct_path(&inner, path_cfg()).unwrap();
        (c, path, inner)
    }
}

fn session_env() -> ssh3_core::ServerSessionEnv {
    ssh3_core::ServerSessionEnv::new(ssh3_session::SessionConfig::default())
}

async fn wait_mode(inner: &ClientSession, want: impl Fn(PathMode) -> bool, what: &str) {
    wait_until(what, BOUND, || inner.path_status().is_some_and(|s| want(s.mode)), || format!("{:?}", inner.path_status())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_then_direct_through_port_restricted_nats() {
    let w = World::new("port-restricted-cone", "port-restricted-cone").await;
    assert_eq!(w.gw.server.stats().peers_registered, 1);
    let (_c, path, inner) = w.connect().await;
    assert_eq!(w.target.server.stats().relay_routes, 1);
    wait_mode(&inner, |m| matches!(m, PathMode::Direct(_)), "direct path").await;
    // On the direct path the relay route carries nothing more.
    let relayed = path.relayed();
    let echo = echo_server().await;
    let l = forward(&inner, echo).await;
    let data = Arc::new(pattern(4 << 20, 81));
    assert_same(&echo_roundtrip(l, data.clone()).await, &data);
    assert!(matches!(inner.path_status().unwrap().mode, PathMode::Direct(_)), "{:?}", inner.path_status());
    let more = path.relayed() - relayed;
    assert!(more < 16, "{more} packets still went over the relay after the switch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_path_loss_falls_back_to_relay() {
    let w = World::new("port-restricted-cone", "port-restricted-cone").await;
    let (_c, path, inner) = w.connect().await;
    wait_mode(&inner, |m| matches!(m, PathMode::Direct(_)), "direct path").await;
    // Cut the direct path between the two NATs; the gateway stays reachable.
    w.net.block(IpAddr::V4(NAT_A), IpAddr::V4(NAT_B), true);
    wait_mode(&inner, |m| m == PathMode::Relay, "fallback to relay").await;
    let before = path.relayed();
    let echo = echo_server().await;
    let l = forward(&inner, echo).await;
    let data = Arc::new(pattern(1 << 20, 82));
    assert_same(&echo_roundtrip(l, data.clone()).await, &data);
    assert!(path.relayed() > before + 100, "the session did not continue over the relay");
    assert!(inner.shared.is_attached());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symmetric_nats_stay_on_relay_and_work() {
    let w = World::new("symmetric", "symmetric").await;
    let (_c, path, inner) = w.connect().await;
    // Let at least one round finish.
    wait_until("a finished round", BOUND, || inner.path_status().is_some_and(|s| s.last_outcome != ssh3_core::path::RoundOutcome::None), || format!("{:?}", inner.path_status())).await;
    let st = inner.path_status().unwrap();
    assert_eq!(st.mode, PathMode::Relay, "{st:?}");
    assert!(matches!(st.last_outcome, ssh3_core::path::RoundOutcome::NoValidatedPair { .. }), "{st:?}");
    let echo = echo_server().await;
    let l = forward(&inner, echo).await;
    let data = Arc::new(pattern(1 << 20, 83));
    assert_same(&echo_roundtrip(l, data.clone()).await, &data);
    assert!(path.relayed() > 100);
}

/// The gateway goes away (process restart: every session it held is gone)
/// and a new one takes over at another address. The target registers again,
/// the client opens a relay through the new gateway under the SAME route
/// (carrier replacement), and the inner session resumes end to end — same
/// session, data intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_restart_inner_session_survives_via_resume() {
    let w = World::new("symmetric", "symmetric").await;
    let (c, path, inner) = w.connect().await;
    let echo = echo_server().await;
    let l = forward(&inner, echo).await;
    let data = Arc::new(pattern(256 << 10, 84));
    assert_same(&echo_roundtrip(l, data.clone()).await, &data);
    let id = inner.session_id();

    // The old gateway dies with every session it held.
    w.gw.server.shutdown();
    drop(c);
    let gw2_addr: SocketAddr = "203.0.113.2:443".parse().unwrap();
    w.net.set_delay(gw2_addr.ip(), Duration::from_millis(15));
    let gw2_mgr = PathManager::new(w.net.bind(gw2_addr, None));
    let gw2 = env_bind(fast_limits(), session_env(), |o| Server::bind_path(o, gw2_mgr).unwrap());
    let _reg2 = w.target.server.register_at(opts(&gw2, gw2_addr, host("gw2", 443, &gw2), None), "B", path_cfg()).await.unwrap();
    let c2 = ClientSession::connect(opts(&gw2, gw2_addr, host("gw2", 443, &gw2), Some(w.client_mgr.clone())), w.client_mgr.socket()).await.unwrap();
    c2.rejump_peer(&path, "B").await.unwrap();

    let epoch = tokio::time::timeout(BOUND, inner.resume(path.socket())).await.expect("inner resume timed out").unwrap();
    assert!(epoch >= 2, "epoch {epoch}");
    assert_eq!(inner.session_id(), id);
    let l = forward(&inner, echo).await;
    let data = Arc::new(pattern(1 << 20, 85));
    assert_same(&echo_roundtrip(l, data.clone()).await, &data);
    let ts = w.target.server.stats();
    assert_eq!((ts.sessions, ts.resumes_accepted), (1, 1), "{ts:?}");
    assert_eq!(gw2.server.stats().peers_registered, 1);
}
