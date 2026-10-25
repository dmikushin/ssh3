//! Dials race every address of the server (RFC 8305), as observed on the
//! oracle gateway: its name has AAAA + A and the IPv6 path to the test port
//! is filtered — a dial that tried addresses one after the other spent the
//! whole handshake timeout on IPv6 before reaching IPv4.
mod common;

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use ssh3_core::client::attempt_order;
use ssh3_core::transport::dual_stack_socket;
use ssh3_core::{ClientSession, Error, Limits, udp_socket};

/// A bound socket that never answers: a filtered path (packets vanish, no
/// ICMP). Kept alive by the caller.
fn silent(addr: &str) -> (UdpSocket, SocketAddr) {
    let s = UdpSocket::bind(addr).unwrap();
    let a = s.local_addr().unwrap();
    (s, a)
}

fn sock() -> Arc<dyn quinn::AsyncUdpSocket> {
    udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap()
}

#[test]
fn attempt_order_interleaves_families_ipv6_first() {
    let v4a: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let v4b: SocketAddr = "192.0.2.2:443".parse().unwrap();
    let v6a: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let v6b: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
    let mapped: SocketAddr = "[::ffff:192.0.2.3]:443".parse().unwrap();
    assert_eq!(attempt_order(&[v4a, v4b, v6a, v6b]), vec![v6a, v4a, v6b, v4b]);
    assert_eq!(attempt_order(&[v4a, v4a, v6a]), vec![v6a, v4a], "duplicates removed");
    assert_eq!(attempt_order(&[mapped, v6a]), vec![v6a, mapped], "v4-mapped counts as IPv4");
    assert_eq!(attempt_order(&[v4a, v4b]), vec![v4a, v4b]);
}

/// AAAA unreachable (filtered), A reachable: the IPv4 attempt starts
/// `connect_attempt_delay` after the IPv6 one and wins at once, instead of
/// after the whole handshake timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filtered_ipv6_does_not_delay_reachable_ipv4() {
    let env = env_with(Limits { idle_timeout: Duration::from_secs(5), ..fast_limits() });
    let (_hold, dead_v6) = silent("[::1]:0");
    let mut opts = env.opts(&env.key);
    opts.server_addrs = vec![dead_v6, env.server_addr()];
    let t = Instant::now();
    let c = ClientSession::connect(opts, sock()).await.unwrap();
    let took = t.elapsed();
    assert!(took < Duration::from_secs(1), "connect took {took:?}: the filtered IPv6 address was waited for");
    assert!(took >= Duration::from_millis(200), "connect took {took:?}: IPv4 was not started after the attempt delay");
    assert_eq!(c.server_addr(), env.server_addr());
    let st = env.server.stats();
    assert_eq!((st.sessions, st.conns_accepted, st.auth_failures), (1, 1, 0), "{st:?}");
}

/// Two reachable addresses where the first is slow: the second wins, the
/// first attempt is aborted before authentication — the server ends up
/// with exactly one session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_losing_attempt_never_authenticates() {
    let env = env_with(Limits { idle_timeout: Duration::from_secs(5), ..fast_limits() });
    let slow = common::delay::relay(env.server_addr(), Duration::from_millis(1200)).await;
    let mut opts = env.opts(&env.key);
    opts.server_addrs = vec![slow, env.server_addr()];
    let c = ClientSession::connect(opts, sock()).await.unwrap();
    assert_eq!(c.server_addr(), env.server_addr(), "the slow address won");
    // Let the slow path's packets arrive: the aborted attempt must not turn
    // into a second session or an authentication.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let st = env.server.stats();
    assert_eq!((st.sessions, st.auth_failures), (1, 0), "{st:?}");
}

/// Nothing reachable: the error names every address with its outcome, and
/// the attempts ran in parallel — two dead addresses take about as long as
/// one (a handshake timeout is at least 3 PTO, ~3 s on a fresh path), not
/// twice as long.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_error_names_every_address() {
    let env = env_with(Limits { idle_timeout: Duration::from_millis(800), ..fast_limits() });
    let (_h1, a) = silent("[::1]:0");
    let (_h2, b) = silent("127.0.0.1:0");
    let dial = |addrs: Vec<SocketAddr>| {
        let mut opts = env.opts(&env.key);
        opts.server_addrs = addrs;
        async move {
            let t = Instant::now();
            let r = ClientSession::connect(opts, sock()).await;
            (r.err().expect("connected to a silent socket"), t.elapsed())
        }
    };
    let (_, one) = dial(vec![b]).await;
    let (e, both) = dial(vec![b, a]).await;
    let msg = e.to_string();
    assert!(matches!(e, Error::Unreachable(_)), "{msg}");
    assert!(msg.contains(&format!("tried {a}:")) && msg.contains(&format!("tried {b}:")), "{msg}");
    assert!(both < one + Duration::from_millis(800), "attempts were sequential: one address {one:?}, two {both:?}");
}
