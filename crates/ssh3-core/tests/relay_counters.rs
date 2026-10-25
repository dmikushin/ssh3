//! Gateway datagram counters on a relayed transfer (SPEC §7.2): both legs of
//! a JumpPeer ↔ PeerRelay relay count in the same unit (UDP payloads, i.e.
//! inner QUIC packets), so at a pure relay every payload received is either
//! sent on or dropped: received == sent + dropped.
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use ssh3_core::path::{PathConfig, PathManager};
use ssh3_core::transport::dual_stack_socket;
use ssh3_core::{ClientOptions, ClientSession, Server};

const BOUND: Duration = Duration::from_secs(20);

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

#[tokio::test(flavor = "multi_thread")]
async fn relay_counters_balance() {
    let gw = env_with(fast_limits());
    let mgr = PathManager::new(ssh3_core::udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap());
    let peer = env_bind(fast_limits(), ssh3_core::ServerSessionEnv::new(ssh3_session::SessionConfig::default()), |o| Server::bind_path(o, mgr).unwrap());
    let _reg = peer.server.register_at(ClientOptions { user: current_user(), ..gw.opts(&gw.key) }, "box", path_cfg()).await.unwrap();
    let c = gw.client().await;
    // No direct-path machinery on the client: everything stays on the relay.
    let path = c.jump("box.peer", 443).await.unwrap();
    let mut o = peer.opts(&peer.key);
    o.server_addrs = vec![path.virt];
    let inner = tokio::time::timeout(BOUND, ClientSession::connect(path.inner_opts(o), path.socket())).await.expect("inner connect timed out").unwrap();
    let echo = echo_server().await;
    let local = forward(&inner, echo).await;
    let data = Arc::new(pattern(2 << 20, 5));
    let got = tokio::time::timeout(BOUND, echo_roundtrip(local, data.clone())).await.expect("relayed echo timed out");
    assert_same(&got, &data);
    // The relay keeps carrying the inner connection's keep-alives, so the
    // books are read while traffic flows: a snapshot can fall between a
    // payload's receive and its send, but must balance exactly at some
    // snapshot within the bound (before the unit fix received ≈ 2 × sent
    // never did).
    let mut last = gw.server.stats();
    let end = tokio::time::Instant::now() + BOUND;
    while last.datagrams_received != last.datagrams_sent + last.datagrams_dropped {
        assert!(tokio::time::Instant::now() < end, "gateway relay counters do not balance: {last:?}");
        tokio::time::sleep(Duration::from_millis(5)).await;
        last = gw.server.stats();
    }
    let s = last;
    eprintln!("gateway: received {} sent {} dropped {} fragments in {} out {}", s.datagrams_received, s.datagrams_sent, s.datagrams_dropped, s.datagram_fragments_received, s.datagram_fragments_sent);
    assert!(s.datagrams_received > 1000, "relay carried too little to judge: {s:?}");
    assert!(s.datagram_fragments_received >= s.datagrams_received && s.datagram_fragments_sent >= s.datagrams_sent, "{s:?}");
}
