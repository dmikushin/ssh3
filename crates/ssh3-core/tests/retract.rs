//! §4 fenced credit retraction and demand-driven grants, including the
//! reviewer's forced orders (raw-protocol peers for the races).
mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::*;
use ssh3_core::error::close;
use ssh3_core::frame;
use ssh3_core::msg::{ChannelKind, Intent, LaneHeader, Message};
use ssh3_core::Limits;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const LIMIT: Duration = Duration::from_secs(10);

fn retracting(base: Limits) -> Limits {
    Limits { credit_idle: Duration::from_millis(300), retract_timeout_min: Duration::from_millis(400), idle_timeout: Duration::from_secs(10), ..base }
}

/// Counts every byte it receives.
async fn counting_sink() -> (SocketAddr, Arc<AtomicU64>) {
    let (a, n, _) = pausable_sink().await;
    (a, n)
}

/// Counts every byte it receives; stops reading while `paused`. (No small
/// receive buffer: a 4 KiB one drains at ~40 KB/s on loopback, measured.)
async fn pausable_sink() -> (SocketAddr, Arc<AtomicU64>, Arc<std::sync::atomic::AtomicBool>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let n = Arc::new(AtomicU64::new(0));
    let paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (n2, p2) = (n.clone(), paused.clone());
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let (n, p) = (n2.clone(), p2.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    if p.load(Ordering::Relaxed) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        continue;
                    }
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(k) => {
                            n.fetch_add(k as u64, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    });
    (a, n, paused)
}

/// Writes forever.
async fn endless_source() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0x42u8; 65536];
                while s.write_all(&chunk).await.is_ok() {}
            });
        }
    });
    a
}

/// A hand-driven client: auth, event lane, one direct-tcp channel (id 2).
struct Raw {
    conn: quinn::Connection,
    ctl: quinn::SendStream,
    ctl_in: mpsc::UnboundedReceiver<Message>,
    lane: quinn::SendStream,
    lane_in: quinn::RecvStream,
    /// The event lane (we write raw event frames within the server's 1 MiB
    /// grant) and the server's events.
    ev: quinn::SendStream,
    ev_in: mpsc::UnboundedReceiver<Message>,
    /// The server's latest grant on channel 2 lane 0 (when we send).
    server_limit: u64,
}

async fn raw_session(env: &Env, target: SocketAddr, our_limit: u64) -> Raw {
    let conn = raw_conn(env).await;
    let (mut ctl, mut ctl_r, m) = raw_auth(&conn, &env.key, Intent::New).await;
    assert!(matches!(m, Message::AuthOk { session: Some(_) }), "{m:?}");
    let (mut ev, mut ev_r) = conn.open_bi().await.unwrap();
    ev.write_all(&frame::encode(&LaneHeader { chan_id: 0, lane: 0, offset_out: 0 })).await.unwrap();
    frame::read_frame(&mut ev_r, 64).await.unwrap().unwrap();
    frame::write_message(&mut ctl, &Message::LaneAck { chan_id: 0, lane: 0, accepted: 0, limit: 1 << 20, seq: 0 }).await.unwrap();
    let open = Message::ChannelOpen { chan_id: 2, kind: ChannelKind::DirectTcp { host: "127.0.0.1".into(), port: target.port() }, limit: our_limit };
    ev.write_all(&frame::encode(&open)).await.unwrap();
    let server_limit = loop {
        match frame::read_message(&mut ev_r, 65536).await.unwrap().unwrap() {
            Message::ChannelOk { chan_id: 2, limit } => break limit,
            _ => continue,
        }
    };
    let (mut lane, mut lane_in) = conn.open_bi().await.unwrap();
    lane.write_all(&frame::encode(&LaneHeader { chan_id: 2, lane: 0, offset_out: 0 })).await.unwrap();
    frame::read_frame(&mut lane_in, 64).await.unwrap().unwrap();
    let (tx, ctl_in) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(Some(m)) = frame::read_message(&mut ctl_r, 65536).await {
            if tx.send(m).is_err() {
                return;
            }
        }
    });
    let (etx, ev_in) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(Some(m)) = frame::read_message(&mut ev_r, 65536).await {
            if etx.send(m).is_err() {
                return;
            }
        }
    });
    Raw { conn, ctl, ctl_in, lane, lane_in, ev, ev_in, server_limit }
}

impl Raw {
    /// Process pending control messages; returns the first Retract for
    /// channel 2 if one is seen.
    fn drain_control(&mut self) -> Option<(u64, u64)> {
        while let Ok(m) = self.ctl_in.try_recv() {
            match m {
                Message::LaneAck { chan_id: 2, lane: 0, limit, .. } => self.server_limit = self.server_limit.max(limit),
                Message::Retract { chan_id: 2, lane: 0, seq, new_limit } => return Some((seq, new_limit)),
                _ => {}
            }
        }
        None
    }

    /// Send `n` bytes within the server's credit (waiting for grants).
    async fn send_within_credit(&mut self, sent: &mut u64, n: u64) {
        let target = *sent + n;
        let chunk = vec![7u8; 16384];
        let t = tokio::time::Instant::now();
        while *sent < target {
            let _ = self.drain_control();
            let room = self.server_limit.saturating_sub(*sent).min(target - *sent).min(chunk.len() as u64);
            if room == 0 {
                assert!(t.elapsed() < LIMIT, "no credit to send");
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
            self.lane.write_all(&chunk[..room as usize]).await.unwrap();
            *sent += room;
        }
    }

    async fn wait_retract(&mut self) -> (u64, u64) {
        let t = tokio::time::Instant::now();
        loop {
            if let Some(r) = self.drain_control() {
                return r;
            }
            assert!(t.elapsed() < LIMIT, "no Retract");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// Retract racing in-flight bytes: after the server retracts, the peer sends
/// up to its OLD limit before acknowledging. The effective limit is
/// max(sent, new_limit): nothing is lost or rejected. A byte beyond it, after
/// the ack, cuts the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retract_racing_in_flight_bytes_loses_nothing() {
    // Only the first Retract is under test: later ones (the grant regrows
    // with the extra bytes, then idles) must not cut this silent peer.
    let env = env_with(Limits { retract_timeout_min: Duration::from_secs(30), lane_buffer: 64 << 10, ..retracting(fast_limits()) });
    let (sink, count, paused) = pausable_sink().await;
    let mut r = raw_session(&env, sink, 1 << 20).await;
    let mut sent = 0u64;
    r.send_within_credit(&mut sent, 256 << 10).await; // grows the grant
    let (seq, new_limit) = r.wait_retract().await;
    let old_limit = r.server_limit;
    assert!(new_limit < old_limit, "retract to {new_limit} from {old_limit}");
    // In flight: everything up to the old limit, sent before the ack.
    let extra = old_limit - sent;
    assert!(extra > 0, "nothing left to race with");
    let chunk = vec![9u8; extra as usize];
    r.lane.write_all(&chunk).await.unwrap();
    sent += extra;
    frame::write_message(&mut r.ctl, &Message::RetractAck { chan_id: 2, lane: 0, seq, sent }).await.unwrap();
    wait_until("all bytes delivered", LIMIT, || count.load(Ordering::Relaxed) == sent, || format!("{} of {sent}; {:?}", count.load(Ordering::Relaxed), env.server.stats())).await;
    wait_until("retraction completed", LIMIT, || env.server.stats().credit_retractions >= 1, || format!("{:?}", env.server.stats())).await;
    assert!(r.conn.close_reason().is_none(), "{:?}", r.conn.close_reason());
    // Pin the receiver's limit (the sink stops reading; at most the kernel
    // buffers on the path — 64 KiB server send buffer plus the sink's
    // autotuned receive buffer, a few MiB — are still delivered), then send
    // 16 MiB: far beyond any credit (lane cap 64 KiB). A violation.
    paused.store(true, Ordering::Relaxed);
    let mut last = u64::MAX;
    wait_until("delivery stopped", LIMIT, || {
        let c = count.load(Ordering::Relaxed);
        let still = c == last;
        last = c;
        still
    }, || "still delivering".into()).await;
    let mut lane = r.lane;
    tokio::spawn(async move {
        let _ = lane.write_all(&vec![1u8; 16 << 20]).await;
    });
    match tokio::time::timeout(LIMIT, r.conn.closed()).await.expect("not cut") {
        quinn::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(c.error_code.into_inner(), close::PROTOCOL as u64);
            assert!(String::from_utf8_lossy(&c.reason).contains("beyond limit"), "{c:?}");
        }
        other => panic!("{other:?}"),
    }
}

/// A peer that never acknowledges a Retract is cut after RetractTimeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_ignoring_retract_is_cut() {
    let env = env_with(retracting(fast_limits()));
    let (sink, _count) = counting_sink().await;
    let mut r = raw_session(&env, sink, 1 << 20).await;
    let mut sent = 0u64;
    r.send_within_credit(&mut sent, 512 << 10).await;
    let _ = r.wait_retract().await; // and never answer
    match tokio::time::timeout(LIMIT, r.conn.closed()).await.expect("not cut") {
        quinn::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(c.error_code.into_inner(), close::PROTOCOL as u64);
            assert!(String::from_utf8_lossy(&c.reason).contains("not acknowledged"), "{c:?}");
        }
        other => panic!("{other:?}"),
    }
    assert!(env.server.stats().retract_timeouts >= 1);
}

/// Sender side (the server sends): after acknowledging Retract seq 1 it must
/// ignore a stale grant of seq 0, and honour a seq-1 grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_seq_grant_after_retract_is_ignored() {
    let env = env_with(retracting(fast_limits()));
    let src = endless_source().await;
    let mut r = raw_session(&env, src, 64 << 10).await;
    let mut got = 0u64;
    let mut buf = vec![0u8; 65536];
    while got < 64 << 10 {
        let n = tokio::time::timeout(LIMIT, r.lane_in.read(&mut buf)).await.unwrap().unwrap().unwrap();
        got += n as u64;
    }
    assert_eq!(got, 64 << 10, "server sent beyond its 64 KiB grant");
    frame::write_message(&mut r.ctl, &Message::Retract { chan_id: 2, lane: 0, seq: 1, new_limit: got }).await.unwrap();
    let sent = loop {
        match tokio::time::timeout(LIMIT, r.ctl_in.recv()).await.unwrap().unwrap() {
            Message::RetractAck { chan_id: 2, lane: 0, seq: 1, sent } => break sent,
            _ => continue,
        }
    };
    assert_eq!(sent, got);
    // Stale grant (seq 0): must not move the server.
    frame::write_message(&mut r.ctl, &Message::LaneAck { chan_id: 2, lane: 0, accepted: got, limit: 10 << 20, seq: 0 }).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(300), r.lane_in.read(&mut buf)).await.is_err(), "bytes arrived on a stale grant");
    // Current fence (seq 1): honoured.
    frame::write_message(&mut r.ctl, &Message::LaneAck { chan_id: 2, lane: 0, accepted: got, limit: got + (32 << 10), seq: 1 }).await.unwrap();
    let mut more = 0u64;
    while more < 32 << 10 {
        let n = tokio::time::timeout(LIMIT, r.lane_in.read(&mut buf)).await.unwrap().unwrap().unwrap();
        more += n as u64;
    }
    assert_eq!(more, 32 << 10);
}

/// While detached the receiver retracts unilaterally; the resumed sender
/// sees a LOWER limit in a newer epoch, replays only up to it, and the
/// transfer still completes intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unilateral_retraction_while_detached_then_resume() {
    // The override goes outside: retracting() sets idle_timeout itself.
    let env = env_with(Limits { idle_timeout: Duration::from_millis(400), ..retracting(fast_limits()) });
    let (sink, count) = counting_sink().await;
    let (c, bh) = client_bh(&env).await;
    let fwd = forward(&c, sink).await;
    let data = Arc::new(pattern(4 << 20, 81));
    let mut s = tokio::net::TcpStream::connect(fwd).await.unwrap();
    let d = data.clone();
    let writer = tokio::spawn(async move {
        s.write_all(&d).await.unwrap();
        s.shutdown().await.unwrap();
    });
    wait_until("grant grown", LIMIT, || env.server.stats().credit_outstanding > 256 << 10, || format!("{:?}", env.server.stats())).await;
    bh.set_down(true);
    c.carrier_lost().await;
    wait_until("server detached and retracted", LIMIT, || env.server.stats().detached == 1 && env.server.stats().credit_retractions >= 1, || format!("{:?}", env.server.stats())).await;
    let st = env.server.stats();
    assert!(st.credit_outstanding <= 4 * 16384 + 2 * 16384, "credit not back to floor: {st:?}");
    c.resume(other_socket()).await.unwrap();
    writer.await.unwrap();
    wait_until("everything delivered", LIMIT, || count.load(Ordering::Relaxed) == data.len() as u64, || format!("{} of {}", count.load(Ordering::Relaxed), data.len())).await;
}

/// Demand-driven grants: lanes that burst and then go idle return to their
/// floor; the budget is free again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_lanes_return_to_floor() {
    let env = env_with(retracting(fast_limits()));
    let (sink, count) = counting_sink().await;
    let c = env.client().await;
    let fwd = forward(&c, sink).await;
    let n = 8u64;
    let mut held = Vec::new();
    for _ in 0..n {
        let mut s = tokio::net::TcpStream::connect(fwd).await.unwrap();
        s.write_all(&pattern(1 << 20, 82)).await.unwrap();
        held.push(s); // stay open, idle
    }
    wait_until("bursts delivered", LIMIT, || count.load(Ordering::Relaxed) == n << 20, || format!("{}", count.load(Ordering::Relaxed))).await;
    let floor = env.limits.lane_floor;
    wait_until("idle lanes at floor", LIMIT, || {
        let st = env.server.stats();
        st.credit_outstanding <= (n + 1) * floor && st.recv_budget_used == 0
    }, || format!("{:?}", env.server.stats())).await;
    assert!(env.server.stats().credit_retractions >= n, "{:?}", env.server.stats());
}

/// Writes `n` bytes, then closes.
async fn finite_source(n: usize) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let _ = s.write_all(&vec![3u8; n]).await;
                let _ = s.shutdown().await;
            });
        }
    });
    a
}

/// Reviewer's forced order: the peer completes the channel (ChannelDone on
/// the event log) while its final LaneAck is held back; the held-back ack,
/// now stale (accepted below what ChannelDone released), arrives while the
/// channel still exists. No close; the channel then completes and every
/// ring byte and chunk is reclaimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_done_before_stale_lane_ack() {
    let env = env_with(fast_limits());
    let n = 100_000usize;
    let src = finite_source(n).await;
    let mut r = raw_session(&env, src, 1 << 20).await;
    // The raw peer never acks the event lane, so the server keeps its few
    // event bytes for replay; channel 2's bytes are the ones under test.
    let events_only = 1024u64;
    let mut got = 0;
    let mut buf = vec![0u8; 65536];
    while got < n {
        got += tokio::time::timeout(LIMIT, r.lane_in.read(&mut buf)).await.unwrap().unwrap().unwrap();
    }
    // The server's LaneFin for its direction (the source closed).
    loop {
        if let Message::LaneFin { chan_id: 2, lane: 0, final_offset } = tokio::time::timeout(LIMIT, r.ev_in.recv()).await.unwrap().unwrap() {
            assert_eq!(final_offset as usize, n);
            break;
        }
    }
    // No LaneAck yet: the server still holds all n bytes for replay.
    assert!(env.server.stats().send_ring_bytes >= n as u64);
    // 1. ChannelDone first (event log).
    r.ev.write_all(&frame::encode(&Message::ChannelDone { chan_id: 2 })).await.unwrap();
    wait_until("ChannelDone applied (ring released)", LIMIT, || env.server.stats().send_ring_bytes < events_only, || format!("{:?}", env.server.stats())).await;
    assert_eq!(env.server.stats().channels, 1, "channel must still exist (our LaneFin is withheld)");
    // 2. The held-back, now stale ack.
    frame::write_message(&mut r.ctl, &Message::LaneAck { chan_id: 2, lane: 0, accepted: (n / 2) as u64, limit: 1 << 20, seq: 0 }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(r.conn.close_reason().is_none(), "stale ack closed the carrier: {:?}", r.conn.close_reason());
    // 3. Our direction ends: the channel completes and is reclaimed.
    r.ev.write_all(&frame::encode(&Message::LaneFin { chan_id: 2, lane: 0, final_offset: 0 })).await.unwrap();
    wait_until("channel reclaimed", LIMIT, || env.server.stats().channels == 0, || format!("{:?}", env.server.stats())).await;
    let st = env.server.stats();
    assert!(st.send_ring_bytes < events_only && st.recv_ring_bytes == 0, "{st:?}");
    assert!(r.conn.close_reason().is_none());
}
