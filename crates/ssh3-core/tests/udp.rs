//! §6 UDP: direct and reverse flows, fragmentation, bounded flow tables,
//! drop counters, reassembly budget against a hostile peer.
mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use ssh3_core::Limits;
use ssh3_core::msg::Intent;
use tokio::net::UdpSocket;

const LIMIT: Duration = Duration::from_secs(10);

async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    a
}

/// Send `data` from `sock` to `to` until the echo comes back (UDP may drop
/// the first datagrams while the flow is being opened).
async fn roundtrip(sock: &UdpSocket, to: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Instant::now() + LIMIT;
    loop {
        sock.send_to(data, to).await.unwrap();
        match tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => return buf[..n].to_vec(),
            _ => assert!(tokio::time::Instant::now() < deadline, "no echo within {LIMIT:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_udp_flows_and_fragmentation() {
    let env = env_with(fast_limits());
    let c = env.client().await;
    let echo = udp_echo().await;
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fwd = local.local_addr().unwrap();
    c.forward_local_udp(local, "127.0.0.1".into(), echo.port());
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(roundtrip(&a, fwd, b"from a").await, b"from a");
    assert_eq!(roundtrip(&b, fwd, b"from b").await, b"from b");
    // Larger than any datagram limit: fragmented and reassembled both ways.
    let big = pattern(30_000, 71);
    assert_same(&roundtrip(&a, fwd, &big).await, &big);
    let st = env.server.stats();
    assert_eq!(st.udp_flows, 2, "{st:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_udp_flow() {
    let env = env_with(fast_limits());
    let c = env.client().await;
    let echo = udp_echo().await;
    let port = c.forward_remote_udp("127.0.0.1", 0, "127.0.0.1", echo.port()).await.unwrap();
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(roundtrip(&s, format!("127.0.0.1:{port}").parse().unwrap(), b"reverse").await, b"reverse");
    assert_eq!(env.server.stats().listeners, 1);
}

/// The flow table is bounded by count (LRU) and idle time, on both ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flow_table_is_bounded_and_expires() {
    let env = env_with(Limits { udp_flows_max: 3, udp_flow_idle: Duration::from_millis(300), ..fast_limits() });
    let c = env.client().await;
    let echo = udp_echo().await;
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fwd = local.local_addr().unwrap();
    c.forward_local_udp(local, "127.0.0.1".into(), echo.port());
    let mut socks = Vec::new();
    for i in 0..8u8 {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(roundtrip(&s, fwd, &[i]).await, [i]);
        socks.push(s);
        let st = env.server.stats();
        assert!(st.udp_flows <= 3 + 1, "server flows {st:?}"); // +1: an evicted flow's close in flight
        assert!(c.shared.stats.udp_flows.load(std::sync::atomic::Ordering::Relaxed) <= 3);
    }
    assert!(c.shared.stats.udp_evicted.load(std::sync::atomic::Ordering::Relaxed) >= 5);
    wait_until("flows expired", LIMIT, || env.server.stats().udp_flows == 0 && c.shared.stats.udp_flows.load(std::sync::atomic::Ordering::Relaxed) == 0, || format!("{:?}", env.server.stats())).await;
}

/// Datagrams that cannot be sent (detached carrier) are dropped and counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn datagrams_while_detached_are_counted_as_dropped() {
    let env = env_with(Limits { idle_timeout: Duration::from_millis(400), ..fast_limits() });
    let (c, bh) = client_bh(&env).await;
    let echo = udp_echo().await;
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fwd = local.local_addr().unwrap();
    c.forward_local_udp(local, "127.0.0.1".into(), echo.port());
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(roundtrip(&s, fwd, b"up").await, b"up");
    bh.set_down(true);
    c.carrier_lost().await;
    let before = c.shared.stats.dgrams_dropped.load(std::sync::atomic::Ordering::Relaxed);
    for _ in 0..5 {
        s.send_to(b"lost", fwd).await.unwrap();
    }
    wait_until("drops counted", LIMIT, || c.shared.stats.dgrams_dropped.load(std::sync::atomic::Ordering::Relaxed) >= before + 5, || "not counted".into()).await;
}

/// A peer sending only first fragments of huge datagrams cannot hold more
/// than the reassembly budget; old groups are evicted and counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reassembly_is_bounded_against_partial_fragments() {
    let budget = 256 * 1024;
    let env = env_with(Limits { reassembly_budget: budget, reassembly_max_age: Duration::from_secs(30), ..fast_limits() });
    let conn = raw_conn(&env).await;
    let (_s, _r, m) = raw_auth(&conn, &env.key, Intent::New).await;
    assert!(matches!(m, ssh3_core::msg::Message::AuthOk { .. }));
    let max = conn.max_datagram_size().unwrap();
    for id in 0..200u16 {
        // chan 0 (event channel: not UDP, but reassembly happens first),
        // fragment 0 of 255 — never completed.
        let mut d = vec![0x00, 0x01];
        d.extend_from_slice(&id.to_be_bytes());
        d.extend_from_slice(&[0, 255]);
        d.resize(max, 0x5a);
        conn.send_datagram(d.into()).unwrap();
    }
    wait_until("groups evicted", LIMIT, || env.server.stats().reassembly_evicted > 0, || format!("{:?}", env.server.stats())).await;
    let st = env.server.stats();
    assert!(st.reassembly_bytes <= budget, "{st:?}");
}
