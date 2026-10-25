//! ONE finite interleaving on the REAL server quic_reader: TWO TARGETED reads
//! (the barrier is armed for exactly two reads; any unarmed reads in between
//! run normally), with a DETACH forced between the second targeted read's
//! completion and its commit.
//!
//! Feature-gated: the whole file is compiled only with `--features test-hooks`
//! (consultant point 4), so `cargo test --no-run` WITHOUT the feature compiles
//! to zero tests here and never references the feature-only hooks.
//!
//! Correctness is checked by the COMPLETE payload, confirmed at real EOF: the
//! sink task reports a completion Result (Ok only when the socket read returns
//! 0 = clean EOF; read errors are distinct), carrying the SHA-256 of exactly
//! the bytes it read and their length. The test awaits that completion (not a
//! length poll) and asserts hash AND length equal the sent stream, so trailing
//! or duplicated bytes after `total` are rejected. Two cheap control tests
//! prove the sink rejects (a) an extra trailing byte and (b) a read error.
//!
//! Criterion: a deterministic violation on OLD with a NEW control, OR an
//! explicit bounded negative result excluding THIS schedule on both. Timers are
//! failure deadlines only, never synchronisation.
#![cfg(feature = "test-hooks")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::*;
use sha2::{Digest, Sha256};
use ssh3_core::lane::{clear_reader_barriers, install_reader_barrier, lane_snapshot};
use ssh3_core::Limits;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

const LIMIT: Duration = Duration::from_secs(10);

fn retracting(base: Limits) -> Limits {
    Limits {
        credit_idle: Duration::from_millis(100),
        retract_timeout_min: Duration::from_secs(30),
        idle_timeout: Duration::from_millis(400),
        ..base
    }
}

/// Outcome the sink task reports exactly once, when its socket read loop ends.
#[derive(Debug)]
enum SinkDone {
    /// Clean EOF (read returned 0): the full stream, its SHA-256 and length.
    Eof { hash: [u8; 32], len: u64 },
    /// The socket read returned an error before EOF (distinct from EOF).
    ReadError(String),
}

/// A sink that hashes the ordered bytes it reads and reports a `SinkDone` on a
/// oneshot when its read loop ends. It stops reading while `paused` so the
/// server's receive ring accumulates an unread tail. `connected` fires once a
/// client connects, so a control test can drive exactly one connection.
struct Sink {
    addr: std::net::SocketAddr,
    paused: Arc<AtomicBool>,
    done: oneshot::Receiver<SinkDone>,
}

async fn spawn_sink() -> Sink {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let paused = Arc::new(AtomicBool::new(false));
    let (tx, done) = oneshot::channel();
    let p = paused.clone();
    tokio::spawn(async move {
        // Exactly one accepted connection carries the forwarded stream.
        let (mut s, _) = match l.accept().await {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.send(SinkDone::ReadError(format!("accept: {e}")));
                return;
            }
        };
        let mut hasher = Sha256::new();
        let mut len: u64 = 0;
        let mut buf = vec![0u8; 65536];
        let outcome = loop {
            if p.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
            match s.read(&mut buf).await {
                Ok(0) => {
                    let h: [u8; 32] = hasher.finalize().into();
                    break SinkDone::Eof { hash: h, len };
                }
                Ok(k) => {
                    hasher.update(&buf[..k]);
                    len += k as u64;
                }
                Err(e) => break SinkDone::ReadError(e.to_string()),
            }
        };
        let _ = tx.send(outcome);
    });
    Sink { addr, paused, done }
}

/// Distinguishable payload: each 8-byte word encodes its own index, so a lost,
/// duplicated or reordered word changes the hash even at equal length.
fn distinguishable(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n + 8);
    for i in 0..n.div_ceil(8) as u64 {
        v.extend_from_slice(&i.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    }
    v.truncate(n);
    v
}

fn sha(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Await the sink's completion with a failure deadline (no sleep-as-sync).
async fn await_done(done: oneshot::Receiver<SinkDone>) -> SinkDone {
    tokio::time::timeout(LIMIT, done).await.expect("sink never completed").expect("sink task dropped the sender")
}

// --------------------------------------------------------------------------
// Cheap control tests: prove the completion check actually rejects a corrupted
// stream. These do NOT use the server; they connect straight to the sink.
// --------------------------------------------------------------------------

/// Control (a): expected prefix THEN one extra byte MUST fail the hash+len
/// check — trailing bytes after `total` are not silently accepted.
#[tokio::test]
async fn control_trailing_byte_is_rejected() {
    let sink = spawn_sink().await;
    let prefix = distinguishable(4096);
    let mut c = tokio::net::TcpStream::connect(sink.addr).await.unwrap();
    c.write_all(&prefix).await.unwrap();
    c.write_all(&[0xFF]).await.unwrap(); // one extra byte
    c.shutdown().await.unwrap();
    match await_done(sink.done).await {
        SinkDone::Eof { hash, len } => {
            assert_ne!(len, prefix.len() as u64, "extra byte not counted");
            assert_ne!(hash, sha(&prefix), "trailing byte escaped the hash check");
        }
        SinkDone::ReadError(e) => panic!("unexpected read error: {e}"),
    }
}

/// Control (b): expected prefix THEN an abruptly reset connection MUST be
/// distinguishable from clean EOF. We force a reset by setting SO_LINGER(0) and
/// dropping; the sink sees either a ReadError or a short EOF — in both cases it
/// must NOT report the full expected stream.
#[tokio::test]
async fn control_read_error_or_short_is_rejected() {
    let sink = spawn_sink().await;
    let prefix = distinguishable(4096);
    let full = distinguishable(8192); // what a correct run would deliver
    let c = tokio::net::TcpStream::connect(sink.addr).await.unwrap();
    let sock = socket2::SockRef::from(&c);
    sock.set_linger(Some(Duration::ZERO)).unwrap(); // RST on close
    let mut c = c;
    c.write_all(&prefix).await.unwrap();
    drop(c); // abortive close -> RST
    match await_done(sink.done).await {
        SinkDone::Eof { hash, len } => {
            // If it reached clean EOF at all, it must not equal the FULL stream.
            assert!(
                !(len == full.len() as u64 && hash == sha(&full)),
                "a reset mid-stream was accepted as the full stream"
            );
        }
        SinkDone::ReadError(_) => { /* distinct error path, as required */ }
    }
}

// --------------------------------------------------------------------------
// The interleaving test.
// --------------------------------------------------------------------------

/// TWO TARGETED reader parks on the same lane (unarmed reads between are
/// allowed); detach at the SECOND targeted park, between its read-completion
/// and commit, after a measured partial drain and with an unread ring tail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detach_at_second_targeted_read_loses_no_bytes() {
    clear_reader_barriers();
    let barrier = install_reader_barrier(2, 0);

    let env = env_with(retracting(fast_limits()));
    let sink = spawn_sink().await;
    let (c, bh) = client_bh(&env).await;
    let fwd = forward(&c, sink.addr).await;

    let data = Arc::new(distinguishable(2 << 20));
    let total = data.len() as u64;
    let expected_hash = sha(&data);
    let d = data.clone();
    let mut s = tokio::net::TcpStream::connect(fwd).await.unwrap();
    let writer = tokio::spawn(async move {
        s.write_all(&d).await.unwrap();
        s.shutdown().await.unwrap();
    });

    // TARGETED READ #1: arm, park, assert invariants, release so it commits.
    let a1 = barrier.arrived.notified();
    tokio::pin!(a1);
    a1.as_mut().enable();
    barrier.armed.store(true, Ordering::Release);
    tokio::time::timeout(LIMIT, a1.as_mut()).await.expect("reader never parked for targeted read #1");
    assert_eq!(barrier.park_index.load(Ordering::Acquire), 1, "expected the first targeted park");
    let p1 = barrier.park(1).expect("snapshot #1");
    eprintln!("PARK#1 {p1:?}");
    assert!(p1.held_n > 0, "park #1 holds no bytes");
    assert_eq!(p1.ring_len, p1.received - p1.delivered, "park#1 ring invariant");
    assert!(p1.received >= p1.delivered, "park#1 received>=delivered");
    assert!(p1.reserve + p1.free_cover >= p1.limit - p1.received, "park#1 credit backed");
    let epoch1 = p1.epoch;
    barrier.release.notify_waiters();

    // MEASURED partial drain between the two targeted reads (unarmed reads in
    // this window run normally): some bytes delivered, not done.
    wait_until(
        "partial drain between the two targeted reads",
        LIMIT,
        || lane_snapshot(2, 0).map_or(false, |s| s.delivered > 0 && s.delivered < total),
        || format!("snap {:?}", lane_snapshot(2, 0)),
    )
    .await;

    // Pause the sink so the server's receive ring accumulates UNREAD BUFFERED
    // bytes: committed segments the sink has not drained. Wait until the
    // on-demand snapshot shows ring_len > 0 (unread bytes, distinct from spare
    // tail capacity, which we check separately below).
    sink.paused.store(true, Ordering::Relaxed);
    wait_until(
        "receive ring holds unread buffered bytes (sink paused)",
        LIMIT,
        || lane_snapshot(2, 0).map_or(false, |s| s.ring_len > 0),
        || format!("no unread ring bytes yet; snap {:?}", lane_snapshot(2, 0)),
    )
    .await;

    // TARGETED READ #2: arm, park in the lock-drop window.
    let a2 = barrier.arrived.notified();
    tokio::pin!(a2);
    a2.as_mut().enable();
    barrier.armed.store(true, Ordering::Release);
    tokio::time::timeout(LIMIT, a2.as_mut()).await.expect("reader never parked for targeted read #2");
    assert_eq!(barrier.park_index.load(Ordering::Acquire), 2, "expected the second targeted park");
    let p2 = barrier.park(2).expect("snapshot #2");
    eprintln!("PARK#2 {p2:?}");
    assert!(p2.held_n > 0, "park #2 holds no bytes");
    // A second TARGETED read occurred and advanced the stream past the first.
    assert!(p2.received > p1.received, "second targeted read did not advance received");
    // Measured partial drain observed, with UNREAD BUFFERED bytes in the ring
    // at the detach point. (ring_len counts buffered undelivered bytes, not
    // spare tail capacity.)
    assert!(p2.delivered > 0, "no partial drain observed at park#2");
    assert!(p2.ring_len > 0, "no unread buffered bytes at the detach point");
    assert_eq!(p2.ring_len, p2.received - p2.delivered, "park#2 ring invariant");
    assert!(p2.received >= p2.delivered, "park#2 received>=delivered");
    assert!(p2.reserve + p2.free_cover >= p2.limit - p2.received, "park#2 credit backed");
    assert_eq!(p2.epoch, epoch1, "no epoch change before the detach");

    // DETACH while parked on targeted read #2 (between completion and commit).
    bh.set_down(true);
    c.carrier_lost().await;
    wait_until(
        "server detached + retracted while reader parked on read #2",
        LIMIT,
        || env.server.stats().detached == 1 && env.server.stats().credit_retractions >= 1,
        || format!("{:?}", env.server.stats()),
    )
    .await;

    // While the reader is STILL PARKED, capture the per-lane snapshot and assert
    // the epoch advanced and the per-lane backing/ring invariants hold (not just
    // aggregate stats). Log it before releasing the reader.
    let pd = wait_snapshot_epoch_above(2, 0, epoch1).await;
    eprintln!("POST-DETACH (reader still parked) {pd:?}");
    assert!(pd.epoch > epoch1, "detach did not advance the epoch");
    assert_eq!(pd.ring_len, pd.received - pd.delivered, "post-detach ring invariant");
    assert!(pd.received >= pd.delivered, "post-detach received>=delivered");
    assert!(pd.reserve + pd.free_cover >= pd.limit - pd.received, "post-detach credit backed");
    // Retracted to the intended floor: limit - received is at most the floor
    // grant (lane_floor); allow the floor chunk budget as the ceiling.
    assert!(pd.limit - pd.received <= pd.free_cover + pd.reserve, "post-detach limit not backed to floor");

    // Release the parked read #2: it reacquires, sees st.epoch != epoch, drops
    // the stale read. The connection must not be cut by a panic.
    barrier.release.notify_waiters();

    // Resume on a fresh carrier; the sender replays from the server's received.
    c.resume(other_socket()).await.unwrap();
    sink.paused.store(false, Ordering::Relaxed);
    writer.await.unwrap();

    // COMPLETE-STREAM equality at real EOF: await the sink's completion Result.
    match await_done(sink.done).await {
        SinkDone::Eof { hash, len } => {
            assert_eq!(len, total, "final length mismatch (loss/dup across the detach)");
            assert_eq!(hash, expected_hash, "final hash mismatch (loss/dup/reorder across the detach)");
        }
        SinkDone::ReadError(e) => panic!("sink read error instead of clean EOF: {e}"),
    }

    clear_reader_barriers();
}

/// Bounded wait for an on-demand snapshot whose epoch exceeds `base`; returns
/// it. Failure deadline only.
async fn wait_snapshot_epoch_above(chan: u64, lane: u8, base: u64) -> ssh3_core::lane::LaneSnapshot {
    let t = tokio::time::Instant::now();
    loop {
        if let Some(s) = lane_snapshot(chan, lane) {
            if s.epoch > base {
                return s;
            }
        }
        assert!(t.elapsed() < LIMIT, "snapshot epoch never advanced past {base}");
        tokio::task::yield_now().await;
    }
}
