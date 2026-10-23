//! -R forwarded-tcp (SPEC §4 channel kinds, §5 detached listeners, I5).
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use ssh3_core::msg::FailReason;
use ssh3_core::{Error, Limits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_forward_carries_data() {
    let env = env_with(fast_limits());
    let c = env.client().await;
    let echo = echo_server().await;
    let port = c.forward_remote("127.0.0.1", 0, "127.0.0.1", echo.port()).await.unwrap();
    assert_ne!(port, 0);
    assert_eq!(env.server.stats().listeners, 1);
    let data = Arc::new(pattern(1 << 20, 41));
    let out = echo_roundtrip(format!("127.0.0.1:{port}").parse().unwrap(), data.clone()).await;
    assert_same(&out, &data);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permitlisten_is_enforced() {
    let env = env_with(fast_limits());
    env.authorize_only(&env.key, "permitlisten=\"127.0.0.1:1\"");
    let c = env.client().await;
    match c.forward_remote("127.0.0.1", 0, "127.0.0.1", 9).await {
        Err(Error::Refused(FailReason::Prohibited)) => {}
        other => panic!("expected Prohibited, got {other:?}"),
    }
    assert_eq!(env.server.stats().listeners, 0);
}

/// SPEC I5: listeners are released as soon as the session ends, and on
/// server shutdown — no lingering ports.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listeners_released_on_session_end_and_shutdown() {
    let env = env_with(Limits { linger: Duration::from_millis(50), idle_timeout: Duration::from_millis(300), ..fast_limits() });
    let c = env.client().await;
    let p1 = c.forward_remote("127.0.0.1", 0, "127.0.0.1", 9).await.unwrap();
    drop(c);
    wait_until("session gone", Duration::from_secs(10), || env.server.stats().sessions == 0, || format!("{:?}", env.server.stats())).await;
    assert!(TcpStream::connect(("127.0.0.1", p1)).await.is_err(), "port {p1} still listening after the session ended");
    let c2 = env.client().await;
    let p2 = c2.forward_remote("127.0.0.1", 0, "127.0.0.1", 9).await.unwrap();
    // R2: shutdown and wait until the closes are out; the client learns why.
    assert!(env.server.shutdown_and_wait(Duration::from_secs(5)).await);
    match tokio::time::timeout(Duration::from_secs(5), c2.carrier_lost()).await {
        Ok(()) => {}
        Err(_) => panic!("client not told about the shutdown"),
    }
    assert!(TcpStream::connect(("127.0.0.1", p2)).await.is_err(), "port {p2} still listening after shutdown");
}

/// While detached, each listener keeps at most DetachedAcceptMax waiting
/// connections and closes the rest at once; after the resume the waiting
/// ones are forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detached_listener_bounds_waiting_connections() {
    let env = env_with(Limits { detached_accept_max: 2, idle_timeout: Duration::from_millis(400), ..fast_limits() });
    let (c, bh) = client_bh(&env).await;
    let echo = echo_server().await;
    let port = c.forward_remote("127.0.0.1", 0, "127.0.0.1", echo.port()).await.unwrap();
    bh.set_down(true);
    c.carrier_lost().await;
    wait_until("server detached", Duration::from_secs(10), || env.server.stats().detached == 1, || format!("{:?}", env.server.stats())).await;
    let mut waiting = Vec::new();
    for _ in 0..2 {
        waiting.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
    }
    // Let the listener count them before the excess arrives.
    wait_until("two waiting channels", Duration::from_secs(5), || env.server.stats().channels == 2, || format!("{:?}", env.server.stats())).await;
    for _ in 0..3 {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut b = [0u8; 1];
        // Closed at once by the server: EOF or reset, never data.
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            other => panic!("excess connection not closed: {other:?}"),
        }
    }
    assert_eq!(env.server.stats().refused_detached, 3);
    c.resume(other_socket()).await.unwrap();
    for (i, s) in waiting.iter_mut().enumerate() {
        let msg = format!("waiting connection {i}");
        s.write_all(msg.as_bytes()).await.unwrap();
        let mut b = vec![0u8; msg.len()];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(b, msg.as_bytes());
    }
}
