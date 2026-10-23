//! Auth, pre-auth limits, lanes end to end, credit and budgets.
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use ssh3_core::error::close;
use ssh3_core::msg::{Intent, Message};
use ssh3_core::transport::dual_stack_socket;
use ssh3_core::{ClientSession, Error, Limits, udp_socket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn app_close(e: &quinn::ConnectionError) -> (u64, String) {
    match e {
        quinn::ConnectionError::ApplicationClosed(c) => (c.error_code.into_inner(), String::from_utf8_lossy(&c.reason).into_owned()),
        other => panic!("expected an application close, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_success_and_failure() {
    let env = env_with(fast_limits());
    let c = env.client().await;
    assert!(c.shared.is_attached());
    let stranger = TestKey::new(99);
    let r = ClientSession::connect(env.opts(&stranger), udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap()).await;
    match r {
        Err(Error::Auth(m)) => assert!(m.contains("not authorized"), "{m}"),
        Err(e) => panic!("expected an auth error, got {e}"),
        Ok(_) => panic!("unauthorized key was accepted"),
    }
    assert!(env.server.stats().auth_failures >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preauth_oversize_frame_is_refused_before_allocation() {
    let env = env_with(fast_limits());
    let conn = raw_conn(&env).await;
    let (mut s, _r) = conn.open_bi().await.unwrap();
    // LEB128 length 8 MiB, no body follows.
    s.write_all(&[0x80, 0x80, 0x80, 0x04]).await.unwrap();
    let (code, reason) = app_close(&conn.closed().await);
    assert_eq!(code, close::PROTOCOL as u64);
    assert!(reason.contains("frame length 8388608 exceeds cap 16384; refused before allocation"), "{reason}");
    assert_eq!(env.server.stats().sessions, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preauth_second_stream_closes_connection() {
    let env = env_with(fast_limits());
    let conn = raw_conn(&env).await;
    let (mut c, _cr) = conn.open_bi().await.unwrap();
    c.write_all(&[0x01]).await.unwrap(); // a partial frame: control stream exists
    let (mut s2, _r2) = conn.open_bi().await.unwrap();
    s2.write_all(b"x").await.unwrap();
    let (code, reason) = app_close(&conn.closed().await);
    assert_eq!(code, close::PROTOCOL as u64);
    assert!(reason.contains("stream opened before authentication"), "{reason}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_message_type_after_auth_closes_naming_it() {
    let env = env_with(fast_limits());
    let conn = raw_conn(&env).await;
    let (mut s, _r, m) = raw_auth(&conn, &env.key, Intent::New).await;
    assert!(matches!(m, Message::AuthOk { .. }), "{m:?}");
    s.write_all(&[0x02, 0xc8, 0x01]).await.unwrap(); // type 200
    let (code, reason) = app_close(&conn.closed().await);
    assert_eq!(code, close::PROTOCOL as u64);
    assert!(reason.contains("unknown control message type 200"), "{reason}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_tcp_echo_64_mib() {
    let env = env_with(Limits { idle_timeout: Duration::from_secs(10), ..fast_limits() });
    let c = env.client().await;
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let data = Arc::new(pattern(64 << 20, 1));
    let out = echo_roundtrip(fwd, data.clone()).await;
    assert_eq!(out.len(), data.len());
    assert_eq!(sha(&out), sha(&data));
    // Channel completes and is removed on both sides; its chunks are freed.
    wait_until("channel removed", Duration::from_secs(10), || env.server.stats().channels == 0 && c.shared.channel_count() == 0, || format!("{:?}", env.server.stats())).await;
}

/// Review D2: lanes whose local sinks stall must not block other lanes or
/// the acks. 32 stalled lanes hold 32 × 16 KiB floor credit = 512 KiB, more
/// than the 256 KiB connection receive window, so this only passes if the
/// receiver drains QUIC into its rings regardless of its sinks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_lanes_do_not_block_others() {
    let env = env_with(Limits { idle_timeout: Duration::from_secs(10), ..fast_limits() });
    let c = env.client().await;
    let (stalled, mut accepted) = stalled_server(true).await;
    let fwd_stalled = forward(&c, stalled).await;
    let n = 32u64;
    assert!(n * env.limits.lane_floor > env.limits.floor_window);
    let mut writers = Vec::new();
    let mut held = Vec::new();
    for _ in 0..n {
        let mut s = TcpStream::connect(fwd_stalled).await.unwrap();
        writers.push(tokio::spawn(async move {
            let chunk = vec![7u8; 65536];
            while s.write_all(&chunk).await.is_ok() {}
        }));
        held.push(accepted.recv().await.unwrap());
    }
    let mut last = 0;
    let mut stable = 0;
    wait_until("stalled lanes at their limits", Duration::from_secs(20), || {
        let b = c.shared.stats.lane_bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
        if b == last { stable += 1 } else { stable = 0; last = b }
        stable > 40
    }, || format!("{:?}", env.server.stats())).await;
    let st = env.server.stats();
    assert!(st.credit_outstanding > env.limits.floor_window, "stalled lanes hold {} B of credit, not more than the connection window; the test would not discriminate: {st:?}", st.credit_outstanding);
    // Another channel moves 8 MiB meanwhile.
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let data = Arc::new(pattern(8 << 20, 2));
    let out = tokio::time::timeout(Duration::from_secs(30), echo_roundtrip(fwd, data.clone()))
        .await
        .unwrap_or_else(|_| panic!("8 MiB echo did not complete beside {n} stalled lanes: {:?}", env.server.stats()));
    assert_eq!(sha(&out), sha(&data));
    let cap = env.limits.lane_buffer as u64;
    let st = env.server.stats();
    assert!(st.recv_ring_bytes <= n * cap, "{st:?}");
    for w in writers {
        w.abort();
    }
}

/// The receive ring never exceeds its capacity and storage stays within the
/// budget, across many stalled lanes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_sinks_never_overflow_and_stay_in_budget() {
    let budget = 1 << 20;
    let env = env_with(Limits { idle_timeout: Duration::from_secs(10), lane_credit_budget: budget, ..fast_limits() });
    let c = env.client().await;
    let (stalled, mut accepted) = stalled_server(true).await;
    let fwd = forward(&c, stalled).await;
    let n = 16;
    let mut writers = Vec::new();
    for _ in 0..n {
        let mut s = TcpStream::connect(fwd).await.unwrap();
        writers.push(tokio::spawn(async move {
            let chunk = vec![1u8; 65536];
            while s.write_all(&chunk).await.is_ok() {}
        }));
    }
    let mut held = Vec::new();
    for _ in 0..n {
        held.push(accepted.recv().await.unwrap());
    }
    // Let credit settle: nothing more can arrive once every lane is at limit.
    let mut last = 0;
    let mut stable = 0;
    wait_until("buffering settles", Duration::from_secs(20), || {
        let b = env.server.stats().recv_ring_bytes;
        if b == last { stable += 1 } else { stable = 0; last = b }
        stable > 40
    }, || format!("{:?}", env.server.stats())).await;
    let st = env.server.stats();
    let ring_cap = env.limits.lane_buffer as u64;
    assert!(st.recv_ring_bytes <= n as u64 * ring_cap, "{st:?}");
    assert!(st.recv_budget_used <= budget, "{st:?}");
    // Floor chunks: ≤ 2 per receive lane and 1 per send lane (+ event lane).
    assert!(st.floor_chunks_bytes <= (n as u64 + 1) * 3 * 16384, "{st:?}");
    // Storage charged is at least what is occupied (chunks, not bytes).
    assert!(st.recv_budget_used + st.floor_chunks_bytes >= st.recv_ring_bytes, "{st:?}");
    for w in writers {
        w.abort();
    }
    drop(held);
}

/// Liveness: a lane at its limit with a stalled sink resumes when the sink
/// drains, with no inbound traffic needed to trigger the credit update.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limit_reached_then_sink_drains_no_deadlock() {
    let env = env_with(Limits { idle_timeout: Duration::from_secs(10), ..fast_limits() });
    let c = env.client().await;
    let (stalled, mut accepted) = stalled_server(false).await;
    let fwd = forward(&c, stalled).await;
    // Larger than every kernel buffer on the path, so the lane does reach
    // its limit while the sink is stalled.
    let data = Arc::new(pattern(48 << 20, 3));
    let mut s = TcpStream::connect(fwd).await.unwrap();
    let d = data.clone();
    let writer = tokio::spawn(async move {
        s.write_all(&d).await.unwrap();
        s.shutdown().await.unwrap();
        s
    });
    let mut sink = accepted.recv().await.unwrap();
    // At limit: the server ring holds bytes and nothing moves any more.
    let mut last = 0;
    let mut stable = 0;
    wait_until("lane at limit", Duration::from_secs(20), || {
        let b = c.shared.stats.lane_bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
        if b == last { stable += 1 } else { stable = 0; last = b }
        stable > 40 && env.server.stats().recv_ring_bytes > 0
    }, || format!("{:?}", env.server.stats())).await;
    // Now drain everything.
    let mon = if std::env::var("SSH3_TEST_TRACE").is_ok() {
        let srv = env.server.session(&c.session_id()).unwrap();
        let cs = c.shared.clone();
        Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                eprintln!("server recv_ring={} credit={} | client sent={} send_ring={}",
                    srv.stats.recv_ring_bytes.load(std::sync::atomic::Ordering::Relaxed),
                    srv.stats.credit_outstanding.load(std::sync::atomic::Ordering::Relaxed),
                    cs.stats.lane_bytes_sent.load(std::sync::atomic::Ordering::Relaxed),
                    cs.stats.send_ring_bytes.load(std::sync::atomic::Ordering::Relaxed));
            }
        }))
    } else {
        None
    };
    let mut got = Vec::new();
    sink.read_to_end(&mut got).await.unwrap();
    if let Some(m) = mon {
        m.abort();
    }
    assert_eq!(sha(&got), sha(&data));
    let _ = writer.await.unwrap();
}

/// One session exhausting the receive budget does not starve another
/// session's floor grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn budget_exhaustion_does_not_starve_floor() {
    let budget = 32 * 1024;
    let env = env_with(Limits { idle_timeout: Duration::from_secs(10), lane_credit_budget: budget, ..fast_limits() });
    let hog = env.client().await;
    let (stalled, mut accepted) = stalled_server(true).await;
    let fwd = forward(&hog, stalled).await;
    let mut writers = Vec::new();
    let mut held = Vec::new();
    for _ in 0..8 {
        let mut s = TcpStream::connect(fwd).await.unwrap();
        writers.push(tokio::spawn(async move {
            let chunk = vec![1u8; 65536];
            while s.write_all(&chunk).await.is_ok() {}
        }));
        held.push(accepted.recv().await.unwrap());
    }
    wait_until("budget exhausted", Duration::from_secs(20), || env.server.stats().recv_budget_used == budget, || format!("{:?}", env.server.stats())).await;
    let other = env.client().await;
    let echo = echo_server().await;
    let fwd2 = forward(&other, echo).await;
    let data = Arc::new(pattern(1 << 20, 4));
    let out = echo_roundtrip(fwd2, data.clone()).await;
    assert_eq!(sha(&out), sha(&data));
    let st = env.server.stats();
    assert!(st.recv_budget_used <= budget, "{st:?}");
    for w in writers {
        w.abort();
    }
}

/// Chunks and permits all come back once channels are gone and sessions are
/// torn down.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunks_and_permits_return_to_zero() {
    let env = env_with(Limits { idle_timeout: Duration::from_millis(300), linger: Duration::from_millis(50), ..fast_limits() });
    let c = env.client().await;
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let mut tasks = Vec::new();
    for i in 0..8 {
        tasks.push(tokio::spawn(echo_roundtrip(fwd, Arc::new(pattern(2 << 20, 10 + i)))));
    }
    for t in tasks {
        t.await.unwrap();
    }
    wait_until("channels removed", Duration::from_secs(10), || env.server.stats().channels == 0, || format!("{:?}", env.server.stats())).await;
    drop(c);
    wait_until("session expired", Duration::from_secs(10), || env.server.stats().sessions == 0, || format!("{:?}", env.server.stats())).await;
    let st = env.server.stats();
    assert_eq!((st.recv_budget_used, st.send_budget_used, st.floor_chunks_bytes, st.recv_ring_bytes, st.send_ring_bytes), (0, 0, 0, 0, 0), "{st:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_failure_is_reported() {
    let env = env_with(fast_limits());
    let c = env.client().await;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = l.local_addr().unwrap();
    drop(l);
    let s = TcpStream::connect(echo_server().await).await.unwrap();
    match c.open_direct_tcp(s, "127.0.0.1", dead.port()).await {
        Err(Error::Refused(ssh3_core::msg::FailReason::ConnectFailed(m))) => assert!(m.contains(&dead.port().to_string()), "{m}"),
        other => panic!("expected ConnectFailed, got {other:?}"),
    }
    assert_eq!(c.shared.channel_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authz_permitopen_is_enforced() {
    use ssh3_core::auth::{Authz, PermitList};
    let env = env_with(fast_limits());
    let echo = echo_server().await;
    *env.auth.authz.lock().unwrap() = Some(Authz::new(true, PermitList::Only(vec![("127.0.0.1".into(), Some(1))]), PermitList::Any, true, None));
    let c = env.client().await;
    let s = TcpStream::connect(echo).await.unwrap();
    match c.open_direct_tcp(s, "127.0.0.1", echo.port()).await {
        Err(Error::Refused(ssh3_core::msg::FailReason::Prohibited)) => {}
        other => panic!("expected Prohibited, got {other:?}"),
    }
}
