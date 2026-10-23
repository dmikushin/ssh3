//! Session resume (SPEC §5): byte integrity, FIN and events across a carrier
//! death, key ownership, serialized attach.
mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use ssh3_core::error::close;
use ssh3_core::frame;
use ssh3_core::msg::{FailReason, Intent, Message};
use ssh3_core::{Error, Limits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn limits() -> Limits {
    Limits { idle_timeout: Duration::from_millis(500), keep_alive: Duration::from_millis(100), ..fast_limits() }
}

/// Outage mid-transfer; resume from another local address; the echoed
/// stream is byte-identical (no loss, no duplication).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_mid_transfer_from_new_address() {
    let env = env_with(limits());
    let (c, bh) = client_bh(&env).await;
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let data = Arc::new(pattern(32 << 20, 5));
    let rt = tokio::spawn(echo_roundtrip(fwd, data.clone()));
    let sent = || c.shared.stats.lane_bytes_sent.load(Ordering::Relaxed);
    wait_until("8 MiB through before the outage", Duration::from_secs(20), || sent() > 8 << 20, || format!("{:?}", env.server.stats())).await;
    bh.set_down(true);
    c.carrier_lost().await;
    wait_until("server detached", Duration::from_secs(10), || env.server.stats().detached == 1, || format!("{:?}", env.server.stats())).await;
    let before = env.server.stats();
    assert!(before.resumes_accepted == 0);
    let epoch = c.resume(other_socket()).await.unwrap();
    assert_eq!(epoch, 2);
    let out = rt.await.unwrap();
    assert_eq!(out.len(), data.len());
    assert_eq!(sha(&out), sha(&data));
    let st = env.server.stats();
    assert_eq!((st.resumes_accepted, st.attached, st.detached), (1, 1, 0), "{st:?}");
    let sess = env.server.session(&c.session_id()).unwrap();
    assert_eq!(sess.epoch(), 2);
}

/// A half-close issued while detached travels as a LaneFin event: the
/// server's peer sees EOF only after all bytes, after the resume — never as a
/// result of the carrier dying.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fin_across_resume_is_not_confused_with_carrier_death() {
    let env = env_with(limits());
    let (c, bh) = client_bh(&env).await;
    let counter = count_server().await;
    let fwd = forward(&c, counter).await;
    let data = Arc::new(pattern(2 << 20, 6));
    let s = TcpStream::connect(fwd).await.unwrap();
    let (mut r, mut w) = s.into_split();
    w.write_all(&data[..1 << 20]).await.unwrap();
    wait_until("first MiB sent", Duration::from_secs(10), || c.shared.stats.lane_bytes_sent.load(Ordering::Relaxed) >= 1 << 20, || format!("{:?}", env.server.stats())).await;
    bh.set_down(true);
    c.carrier_lost().await;
    let d = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&d[1 << 20..]).await.unwrap();
        w.shutdown().await.unwrap(); // FIN while the carrier is dead
    });
    // While detached, the server's peer must not have seen EOF.
    wait_until("server detached", Duration::from_secs(10), || env.server.stats().detached == 1, || format!("{:?}", env.server.stats())).await;
    c.resume(other_socket()).await.unwrap();
    writer.await.unwrap();
    let mut reply = String::new();
    r.read_to_string(&mut reply).await.unwrap();
    assert_eq!(reply, format!("{} {}", data.len(), sha(&data)));
}

/// Session events queued while detached (ChannelOpen) are replayed after the
/// resume, and so are the peer's answers (ChannelFail / ChannelOk).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_queued_while_detached_are_replayed() {
    let env = env_with(limits());
    let (c, bh) = client_bh(&env).await;
    bh.set_down(true);
    c.carrier_lost().await;
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let echo = echo_server().await;
    let c = Arc::new(c);
    let (c1, c2) = (c.clone(), c.clone());
    let failing = tokio::spawn(async move {
        let s = TcpStream::connect(echo).await.unwrap();
        c1.open_direct_tcp(s, "127.0.0.1", dead.port()).await
    });
    let (mut a, b) = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (a, b) = tokio::join!(TcpStream::connect(addr), l.accept());
        (a.unwrap(), b.unwrap().0)
    };
    let working = tokio::spawn(async move { c2.open_direct_tcp(b, "127.0.0.1", echo.port()).await });
    wait_until("server detached", Duration::from_secs(10), || env.server.stats().detached == 1, || format!("{:?}", env.server.stats())).await;
    c.resume(other_socket()).await.unwrap();
    match failing.await.unwrap() {
        Err(Error::Refused(FailReason::ConnectFailed(m))) => assert!(m.contains(&dead.port().to_string()), "{m}"),
        other => panic!("expected ConnectFailed after replay, got {other:?}"),
    }
    working.await.unwrap().unwrap();
    a.write_all(b"ping after resume").await.unwrap();
    let mut buf = [0u8; 17];
    a.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping after resume");
}

/// SPEC §5: a session is owned by the exact key that created it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_with_another_authorized_key_fails() {
    let env = env_with(limits());
    let other = user_key(8);
    env.authorize_also(&other);
    let c = env.client().await;
    let conn = raw_conn(&env).await;
    let (mut s, mut r, m) = raw_auth(&conn, &other, Intent::Resume).await;
    assert_eq!(m, Message::AuthOk { session: None });
    frame::write_message(&mut s, &Message::Resume { session_id: c.session_id(), lanes: vec![] }).await.unwrap();
    assert_eq!(frame::read_message(&mut r, 65536).await.unwrap(), Some(Message::Fail { reason: FailReason::Prohibited }));
    let st = env.server.stats();
    assert_eq!((st.resumes_rejected, st.resumes_accepted, st.attached), (1, 0, 1), "{st:?}");
    assert!(c.shared.is_attached());
}

/// Two simultaneous resumes of one session: attach is serialized, the later
/// one supersedes the earlier, exactly one carrier stays attached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_resumes_exactly_one_stays_attached() {
    let env = env_with(Limits { idle_timeout: Duration::from_secs(10), ..limits() });
    let c = env.client().await;
    let sid = c.session_id();
    let attempt = |env_conn: quinn::Connection, key: Arc<TestKey>| async move {
        let (mut s, mut r, m) = raw_auth(&env_conn, &key, Intent::Resume).await;
        assert_eq!(m, Message::AuthOk { session: None });
        frame::write_message(&mut s, &Message::Resume { session_id: sid, lanes: vec![] }).await.unwrap();
        let m = frame::read_message(&mut r, 65536).await.unwrap();
        (env_conn, s, r, m)
    };
    let (c1, c2) = tokio::join!(raw_conn(&env), raw_conn(&env));
    let (a, b) = tokio::join!(attempt(c1, env.key.clone()), attempt(c2, env.key.clone()));
    let epoch = |m: &Option<Message>| match m {
        Some(Message::Resumed { epoch, .. }) => *epoch,
        other => panic!("expected Resumed, got {other:?}"),
    };
    let (ea, eb) = (epoch(&a.3), epoch(&b.3));
    assert_ne!(ea, eb);
    let (loser, winner) = if ea < eb { (&a.0, &b.0) } else { (&b.0, &a.0) };
    let reason = loser.closed().await;
    match reason {
        quinn::ConnectionError::ApplicationClosed(ac) => assert_eq!(ac.error_code.into_inner(), close::SUPERSEDED as u64),
        other => panic!("loser closed with {other:?}"),
    }
    assert!(winner.close_reason().is_none(), "winner was closed: {:?}", winner.close_reason());
    let st = env.server.stats();
    assert_eq!((st.attached, st.resumes_accepted), (1, 2), "{st:?}");
    assert_eq!(env.server.session(&sid).unwrap().epoch(), ea.max(eb));
    // The original client's carrier was superseded too.
    wait_until("original carrier closed", Duration::from_secs(5), || !c.shared.is_attached(), || "still attached".into()).await;
}

/// Long outage beyond linger: the session is gone and resume is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_after_linger_is_refused() {
    let env = env_with(Limits { linger: Duration::from_millis(100), ..limits() });
    let (c, bh) = client_bh(&env).await;
    bh.set_down(true);
    c.carrier_lost().await;
    wait_until("session expired", Duration::from_secs(10), || env.server.stats().sessions == 0, || format!("{:?}", env.server.stats())).await;
    match c.resume(other_socket()).await {
        Err(Error::Refused(FailReason::Protocol(m))) => assert!(m.contains("unknown or expired session"), "{m}"),
        other => panic!("expected refusal, got {other:?}"),
    }
    assert_eq!(env.server.stats().resumes_rejected, 1);
}

/// Reviewer P1: a key shared by two accounts is legitimate, so a session is
/// bound to the user AND the exact key; another user with the same key must
/// not attach it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_must_bind_user_as_well_as_key() {
    let env = env_with(limits());
    let client = env.client().await;
    let sid = client.session_id();
    assert_eq!(env.server.session(&sid).unwrap().user, "tester");
    let conn = raw_conn(&env).await;
    let (mut send, mut recv, first) = raw_auth_as(&conn, &env.key, "other-user", Intent::Resume).await;
    assert!(matches!(first, Message::AuthOk { .. }), "{first:?}");
    frame::write_message(&mut send, &Message::Resume { session_id: sid, lanes: vec![] }).await.unwrap();
    let resumed = frame::read_message(&mut recv, 65536).await.unwrap();
    assert!(matches!(resumed, Some(Message::Fail { .. })), "server attached a different user's session: {resumed:?}");
    assert!(client.shared.is_attached());
    assert_eq!(env.server.stats().resumes_accepted, 0);
}

/// A malformed Resume is rejected before the session is touched: the valid
/// carrier stays attached and keeps working.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_resume_does_not_detach_the_session() {
    let env = env_with(limits());
    let client = env.client().await;
    let sid = client.session_id();
    let conn = raw_conn(&env).await;
    let (mut send, _recv, first) = raw_auth(&conn, &env.key, Intent::Resume).await;
    assert!(matches!(first, Message::AuthOk { .. }), "{first:?}");
    let bogus = ssh3_core::msg::LanePos { chan_id: 0, lane: 9, accepted: 0, limit: 0 };
    frame::write_message(&mut send, &Message::Resume { session_id: sid, lanes: vec![bogus] }).await.unwrap();
    let reason = conn.closed().await;
    match reason {
        quinn::ConnectionError::ApplicationClosed(c) => assert_eq!(c.error_code.into_inner(), close::PROTOCOL as u64, "{c:?}"),
        other => panic!("expected a protocol close, got {other:?}"),
    }
    assert!(client.shared.is_attached(), "valid carrier was detached by a malformed Resume");
    let st = env.server.stats();
    assert_eq!((st.attached, st.resumes_accepted), (1, 0), "{st:?}");
    let echo = echo_server().await;
    let fwd = forward(&client, echo).await;
    let data = Arc::new(pattern(64 << 10, 9));
    assert_eq!(sha(&echo_roundtrip(fwd, data.clone()).await), sha(&data));
}

/// Verdict (a): competing snapshots. While a real client is mid-transfer, a
/// competing resumer (same user and key) attaches with a stale, empty
/// snapshot; then the real client resumes again. No byte may be lost or
/// duplicated (a snapshot never releases unlisted data), and the superseded
/// carrier is cut by epoch: nothing it sends reaches the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn competing_snapshot_is_fenced_and_loses_no_data() {
    let env = env_with(limits());
    let (c, bh) = client_bh(&env).await;
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let data = Arc::new(pattern(8 << 20, 31));
    let rt = tokio::spawn(echo_roundtrip(fwd, data.clone()));
    wait_until("transfer under way", Duration::from_secs(20), || c.shared.stats.lane_bytes_sent.load(Ordering::Relaxed) > 1 << 20, || format!("{:?}", env.server.stats())).await;
    let sid = c.session_id();
    // Make the server hold unacked bytes: the client stops hearing it.
    bh.set_down(true);
    let srv = env.server.session(&sid).unwrap();
    wait_until("server holds unacked send bytes", Duration::from_secs(10), || srv.stats.send_ring_bytes.load(Ordering::Relaxed) > 0, || format!("{:?}", env.server.stats())).await;
    // The competitor.
    let rival = raw_conn(&env).await;
    let (mut s, mut r, m) = raw_auth(&rival, &env.key, Intent::Resume).await;
    assert_eq!(m, Message::AuthOk { session: None });
    frame::write_message(&mut s, &Message::Resume { session_id: sid, lanes: vec![] }).await.unwrap();
    let rival_epoch = match frame::read_message(&mut r, 65536).await.unwrap() {
        Some(Message::Resumed { epoch, .. }) => epoch,
        other => panic!("expected Resumed, got {other:?}"),
    };
    // The real client lost its carrier to the rival and takes it back.
    c.carrier_lost().await;
    let epoch = c.resume(other_socket()).await.unwrap();
    assert!(epoch > rival_epoch);
    match rival.closed().await {
        quinn::ConnectionError::ApplicationClosed(ac) => assert_eq!(ac.error_code.into_inner(), close::SUPERSEDED as u64),
        other => panic!("rival closed with {other:?}"),
    }
    // Fenced: the superseded carrier cannot carry anything any more.
    assert!(rival.open_bi().await.is_err());
    let out = rt.await.unwrap();
    assert_eq!(out.len(), data.len());
    assert_eq!(sha(&out), sha(&data));
    assert_eq!(env.server.session(&sid).unwrap().epoch(), epoch);
}

/// SPEC §5: lane streams are accepted only after `Resumed`. A resuming peer
/// that opens one before (here: without ever sending Resume) is closed, and
/// the session's real carrier is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lane_stream_before_resumed_closes_the_connection() {
    use ssh3_core::msg::LaneHeader;
    let env = env_with(limits());
    let c = env.client().await;
    let conn = raw_conn(&env).await;
    let (_s, _r, m) = raw_auth(&conn, &env.key, Intent::Resume).await;
    assert_eq!(m, Message::AuthOk { session: None });
    let (mut lane, _lr) = conn.open_bi().await.unwrap();
    // A stream is invisible to the server until a byte is written.
    lane.write_all(&frame::encode(&LaneHeader { chan_id: 0, lane: 0, offset_out: 0 })).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(10), conn.closed()).await.expect("not closed") {
        quinn::ConnectionError::ApplicationClosed(ac) => {
            assert_eq!(ac.error_code.into_inner(), close::PROTOCOL as u64);
            assert!(String::from_utf8_lossy(&ac.reason).contains("stream opened before authentication"), "{ac:?}");
        }
        other => panic!("expected a protocol close, got {other:?}"),
    }
    assert!(c.shared.is_attached());
    assert_eq!(env.server.stats().resumes_accepted, 0);
}
