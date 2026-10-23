//! Auth, pre-auth limits, lanes end to end, credit and budgets.
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use ssh3_core::auth::Signer as _;
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
    let stranger = user_key(99);
    let r = ClientSession::connect(env.opts(&stranger), udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap()).await;
    match r {
        Err(Error::Auth(m)) => assert!(m.contains("key not present in authorized_keys"), "{m}"),
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
async fn direct_tcp_echo_16_mib() {
    let env = env_with(Limits { idle_timeout: Duration::from_secs(10), ..fast_limits() });
    let c = env.client().await;
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    // 16 MiB = 64 × the lane ring: many credit rounds and chunk reuses.
    let data = Arc::new(pattern(16 << 20, 1));
    let out = echo_roundtrip(fwd, data.clone()).await;
    assert_eq!(out.len(), data.len());
    assert_same(&out, &data);
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
    assert_same(&out, &data);
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
    let (stalled, mut accepted) = stalled_server(true).await;
    let fwd = forward(&c, stalled).await;
    // The sink's 4 KiB receive buffer makes the lane reach its limit with
    // little data; it is enlarged before draining (a 4 KiB window drains at
    // ~40 KB/s on loopback, measured).
    let data = Arc::new(pattern(4 << 20, 3));
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
    socket2::SockRef::from(&sink).set_recv_buffer_size(4 << 20).unwrap();
    let mut got = Vec::new();
    sink.read_to_end(&mut got).await.unwrap();
    if let Some(m) = mon {
        m.abort();
    }
    assert_same(&got, &data);
    let _ = writer.await.unwrap();
}

/// Budget exhaustion never starves a floor grant: with a zero receive
/// budget (exhausted from the start, deterministically) a session with
/// stalled lanes and another session moving 1 MiB both live on floor
/// credit alone, and nothing is ever charged to the budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn budget_exhaustion_does_not_starve_floor() {
    let env = env_with(Limits { idle_timeout: Duration::from_secs(10), lane_credit_budget: 0, ..fast_limits() });
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
    wait_until("hog lanes hold data", Duration::from_secs(20), || env.server.stats().recv_ring_bytes > 0, || format!("{:?}", env.server.stats())).await;
    let other = env.client().await;
    let echo = echo_server().await;
    let fwd2 = forward(&other, echo).await;
    let data = Arc::new(pattern(1 << 20, 4));
    let out = echo_roundtrip(fwd2, data.clone()).await;
    assert_same(&out, &data);
    let st = env.server.stats();
    assert_eq!(st.recv_budget_used, 0, "{st:?}");
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
        tokio::time::timeout(Duration::from_secs(20), t)
            .await
            .unwrap_or_else(|_| panic!("echo stuck: server {:?}; client channels {}", env.server.stats(), c.shared.channel_count()))
            .unwrap();
    }
    wait_until("channels removed", Duration::from_secs(10), || env.server.stats().channels == 0 && c.shared.channel_count() == 0, || format!("server {:?}; client channels {}", env.server.stats(), c.shared.channel_count())).await;
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
    let env = env_with(fast_limits());
    let echo = echo_server().await;
    env.authorize_only(&env.key, "permitopen=\"127.0.0.1:1\"");
    let c = env.client().await;
    let s = TcpStream::connect(echo).await.unwrap();
    match c.open_direct_tcp(s, "127.0.0.1", echo.port()).await {
        Err(Error::Refused(ssh3_core::msg::FailReason::Prohibited)) => {}
        other => panic!("expected Prohibited, got {other:?}"),
    }
}

/// QA A6: with MaxAuthTries = N the client receives N AuthFail replies —
/// the last one is delivered before the server closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_auth_refusal_is_delivered_before_close() {
    for n in [1u32, 3] {
        let env = env_with(Limits { max_auth_tries: n, ..fast_limits() });
        let conn = raw_conn(&env).await;
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        let mut got = 0;
        for _ in 0..n {
            let bad = Message::Auth { user: "tester".into(), pubkey: ssh3_core::auth::pubkey_blob(env.key.public_key()).unwrap(), sig: vec![0; 64], intent: Intent::New };
            ssh3_core::frame::write_message(&mut s, &bad).await.unwrap();
            match ssh3_core::frame::read_message(&mut r, 65536).await {
                Ok(Some(Message::AuthFail { .. })) => got += 1,
                other => panic!("MaxAuthTries={n}: refusal {} not received: {other:?}", got + 1),
            }
        }
        assert_eq!(got, n);
        let (code, _) = app_close(&conn.closed().await);
        assert_eq!(code, close::AUTH_FAILED as u64, "MaxAuthTries={n}");
    }
}

/// Verdict (b): a peer that sends beyond its lane credit is cut — even while
/// the lane's sink is blocked — and other sessions keep working.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn over_credit_peer_is_cut_while_others_work() {
    use ssh3_core::frame;
    use ssh3_core::msg::{ChannelKind, LaneHeader};
    let env = env_with(Limits { idle_timeout: Duration::from_secs(10), ..fast_limits() });
    let (stalled, mut accepted) = stalled_server(true).await;
    let conn = raw_conn(&env).await;
    let (mut ctl, _ctl_r, m) = raw_auth(&conn, &env.key, Intent::New).await;
    assert!(matches!(m, Message::AuthOk { session: Some(_) }), "{m:?}");
    // Event lane (channel 0), and credit for the server's events.
    let (mut ev, mut ev_r) = conn.open_bi().await.unwrap();
    ev.write_all(&frame::encode(&LaneHeader { chan_id: 0, lane: 0, offset_out: 0 })).await.unwrap();
    frame::read_frame(&mut ev_r, 64).await.unwrap().unwrap();
    frame::write_message(&mut ctl, &Message::LaneAck { chan_id: 0, lane: 0, accepted: 0, limit: 1 << 20, seq: 0 }).await.unwrap();
    let open = Message::ChannelOpen { chan_id: 2, kind: ChannelKind::DirectTcp { host: "127.0.0.1".into(), port: stalled.port() }, limit: 1 << 20 };
    ev.write_all(&frame::encode(&open)).await.unwrap();
    let server_limit = loop {
        match frame::read_message(&mut ev_r, 65536).await.unwrap().unwrap() {
            Message::ChannelOk { chan_id: 2, limit } => break limit,
            _ => continue,
        }
    };
    let _held = accepted.recv().await.unwrap(); // the sink: never read
    let (mut lane, mut lane_r) = conn.open_bi().await.unwrap();
    lane.write_all(&frame::encode(&LaneHeader { chan_id: 2, lane: 0, offset_out: 0 })).await.unwrap();
    frame::read_frame(&mut lane_r, 64).await.unwrap().unwrap();
    // Far beyond the grant.
    let blast = vec![0x55u8; 2 << 20];
    assert!(blast.len() as u64 > server_limit * 4);
    let w = tokio::spawn(async move {
        let _ = lane.write_all(&blast).await;
    });
    let closed = tokio::time::timeout(Duration::from_secs(10), conn.closed())
        .await
        .unwrap_or_else(|_| panic!("over-credit peer was not cut within 10 s: {:?}", env.server.stats()));
    w.abort();
    let (code, reason) = app_close(&closed);
    assert_eq!(code, close::PROTOCOL as u64, "{reason}");
    assert!(reason.contains("lane 2/0") && reason.contains("beyond limit"), "{reason}");
    // The server is fine for everyone else.
    let c = env.client().await;
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let data = Arc::new(pattern(256 << 10, 21));
    assert_same(&echo_roundtrip(fwd, data.clone()).await, &data);
}

fn host_check_with(env: &Env, files: Vec<std::path::PathBuf>, mode: ssh3_keys::verifier::StrictHostKeyChecking) -> ssh3_core::client::HostCheck {
    ssh3_core::client::HostCheck { files, mode, ..env.host_check() }
}

/// SPEC §2.1: a different key of the same type in known_hosts aborts the
/// connect before anything is signed, naming the file:line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_key_mismatch_aborts_before_auth() {
    use ssh3_keys::verifier::StrictHostKeyChecking;
    let env = env_with(fast_limits());
    let wrong = env.dir.join("known_hosts_wrong");
    let other = ssh3_keys::host::HostIdentity::from_private_key(&ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[201; 32]))).unwrap();
    ssh3_keys::known_hosts::append(&wrong, "127.0.0.1", env.server.local_addr().port(), other.public_key(), false).unwrap();
    let mut opts = env.opts(&env.key);
    opts.host = host_check_with(&env, vec![wrong.clone()], StrictHostKeyChecking::Yes);
    match ClientSession::connect(opts, udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap()).await {
        // R1: a distinct error, so the client can say "Host key verification failed."
        Err(Error::HostKey(m)) => assert!(m.contains("HOST KEY MISMATCH") && m.contains(&format!("{}:1", wrong.display())), "{m}"),
        Err(e) => panic!("expected Error::HostKey, got {e:?}"),
        Ok(_) => panic!("connected despite a host key mismatch"),
    }
    let st = env.server.stats();
    assert_eq!((st.sessions, st.auth_failures), (0, 0), "no Auth may be sent: {st:?}");
}

/// Integration obligation: a commit I/O error (accept-new cannot write
/// known_hosts) aborts the dial; nothing is signed or sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn known_hosts_commit_error_aborts_auth() {
    use ssh3_keys::verifier::StrictHostKeyChecking;
    let env = env_with(fast_limits());
    // A read-only directory: append() cannot create the file in it.
    let ro = env.dir.join("read-only");
    std::fs::create_dir(&ro).unwrap();
    std::fs::set_permissions(&ro, std::os::unix::fs::PermissionsExt::from_mode(0o500)).unwrap();
    let unwritable = ro.join("known_hosts");
    let mut opts = env.opts(&env.key);
    opts.host = host_check_with(&env, vec![unwritable], StrictHostKeyChecking::AcceptNew);
    match ClientSession::connect(opts, udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap()).await {
        Err(Error::HostKey(m)) => assert!(m.contains("read-only/known_hosts"), "{m}"),
        Err(e) => panic!("expected a host key error, got {e}"),
        Ok(_) => panic!("connected although known_hosts could not be written"),
    }
    let st = env.server.stats();
    assert_eq!((st.sessions, st.auth_failures), (0, 0), "{st:?}");
}

/// accept-new writes the key once the server has proved possession.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_new_records_the_host_key() {
    use ssh3_keys::verifier::StrictHostKeyChecking;
    let env = env_with(fast_limits());
    let fresh = env.dir.join("known_hosts_fresh");
    let mut opts = env.opts(&env.key);
    opts.host = host_check_with(&env, vec![fresh.clone()], StrictHostKeyChecking::AcceptNew);
    let c = ClientSession::connect(opts, udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap()).await.unwrap();
    assert!(ssh3_keys::spki::same_key(c.host_key(), env.host.public_key()));
    let kh = ssh3_keys::known_hosts::KnownHosts::load(&[fresh]).unwrap();
    assert_eq!(kh.lookup("127.0.0.1", env.server.local_addr().port()).len(), 1);
}

/// QA: Limits that the engine cannot honour fail loudly, naming the field.
#[test]
fn invalid_limits_are_rejected() {
    for (l, field) in [
        (Limits { lane_floor: 8 * 1024, ..Limits::default() }, "lane_floor"),
        (Limits { lane_floor: 64 * 1024, ..Limits::default() }, "lane_floor"),
        (Limits { lane_buffer: 20_000, ..Limits::default() }, "lane_buffer"),
        (Limits { lane_ack_bytes: 0, ..Limits::default() }, "lane_ack_bytes"),
    ] {
        let e = l.validate().unwrap_err();
        assert!(e.contains(field), "{e}");
    }
    Limits::default().validate().unwrap();
}
