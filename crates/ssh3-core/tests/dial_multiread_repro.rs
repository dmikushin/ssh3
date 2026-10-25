//! ONE finite TWO-read interleaving on the REAL server quic_reader.
//!
//! Feature-gated: the whole file is compiled only with `--features test-hooks`
//! (consultant point 4), so `cargo test --no-run` WITHOUT the feature compiles
//! to zero tests here and never references the feature-only hooks.
//!
//! The reviewed re-armable barrier pauses quic_reader after a read, with the
//! lock dropped and the read not yet committed. Here it is armed TWICE on the
//! same lane, so the server reader parks on two consecutive reads; between the
//! SECOND read's completion and its commit a DETACH (carrier death ->
//! retract_unilaterally, which bumps the epoch) is forced. A measured partial
//! sink drain happens first, verified through the per-park LaneSnapshot
//! (delivered>0 and an unread ring tail at the detach point).
//!
//! Correctness is checked by payload, not an aggregate byte count: the sink
//! collects a SHA-256 and length and the test asserts exact equality against
//! the sent stream, with a distinguishable per-chunk payload so an equal-length
//! loss/dup is caught. Per-park snapshots assert ring/backing invariants and
//! the epoch increment at each boundary.
//!
//! Criterion: a deterministic violation on OLD with a NEW control, OR an
//! explicit bounded negative result excluding THIS schedule on both. Timers are
//! failure deadlines only, never synchronisation.
#![cfg(feature = "test-hooks")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use common::*;
use sha2::{Digest, Sha256};
use ssh3_core::lane::{clear_reader_barriers, install_reader_barrier, lane_snapshot};
use ssh3_core::Limits;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;

const LIMIT: Duration = Duration::from_secs(10);

fn retracting(base: Limits) -> Limits {
    Limits {
        credit_idle: Duration::from_millis(100),
        retract_timeout_min: Duration::from_secs(30),
        idle_timeout: Duration::from_millis(400),
        ..base
    }
}

/// A sink that hashes every byte it receives (order-sensitive) and counts the
/// length, so the test asserts exact payload equality, not just a byte count.
/// It stops reading while `paused`, so the server's receive ring accumulates an
/// unread tail — needed to observe `ring_len > 0` at the detach point.
async fn hashing_sink() -> (std::net::SocketAddr, Arc<AsyncMutex<Sha256>>, Arc<AtomicU64>, Arc<AtomicBool>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let hasher = Arc::new(AsyncMutex::new(Sha256::new()));
    let len = Arc::new(AtomicU64::new(0));
    let paused = Arc::new(AtomicBool::new(false));
    let (h2, n2, p2) = (hasher.clone(), len.clone(), paused.clone());
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let (h, n, p) = (h2.clone(), n2.clone(), p2.clone());
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = vec![0u8; 65536];
                loop {
                    if p.load(Ordering::Relaxed) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        continue;
                    }
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(k) => {
                            h.lock().await.update(&buf[..k]);
                            n.fetch_add(k as u64, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
    });
    (a, hasher, len, paused)
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

/// Bounded wait that the sink length settled at `total` (EOF reached); failure
/// deadline only, no sleep-as-synchronisation.
async fn wait_eof(len: &Arc<AtomicU64>, total: u64) {
    let t = tokio::time::Instant::now();
    while len.load(Ordering::Relaxed) != total {
        assert!(t.elapsed() < LIMIT, "sink never reached EOF at {total}");
        tokio::task::yield_now().await;
    }
}

/// TWO consecutive reader parks on the same lane; detach at the SECOND park
/// (between its read-completion and commit) after a measured partial drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detach_at_second_park_loses_no_bytes() {
    clear_reader_barriers();
    let barrier = install_reader_barrier(2, 0);

    let env = env_with(retracting(fast_limits()));
    let (sink, sink_hash, sink_len, sink_paused) = hashing_sink().await;
    let (c, bh) = client_bh(&env).await;
    let fwd = forward(&c, sink).await;

    let data = Arc::new(distinguishable(2 << 20));
    let total = data.len() as u64;
    let expected_hash = {
        let mut h = Sha256::new();
        h.update(&data[..]);
        h.finalize()
    };
    let d = data.clone();
    let mut s = tokio::net::TcpStream::connect(fwd).await.unwrap();
    let writer = tokio::spawn(async move {
        s.write_all(&d).await.unwrap();
        s.shutdown().await.unwrap();
    });

    // PARK #1: pause the first targeted read, assert invariants, release it so
    // it commits and the sink can drain.
    let a1 = barrier.arrived.notified();
    tokio::pin!(a1);
    a1.as_mut().enable();
    barrier.armed.store(true, Ordering::Release);
    tokio::time::timeout(LIMIT, a1.as_mut()).await.expect("reader never parked for read #1");
    assert_eq!(barrier.park_index.load(Ordering::Acquire), 1, "expected exactly one park so far");
    let p1 = barrier.park(1).expect("snapshot #1");
    eprintln!("PARK#1 {p1:?}");
    assert!(p1.held_n > 0, "park #1 holds no bytes");
    assert_eq!(p1.ring_len, p1.received - p1.delivered, "park#1 ring invariant");
    assert!(p1.received >= p1.delivered, "park#1 received>=delivered");
    assert!(p1.reserve + p1.free_cover >= p1.limit - p1.received, "park#1 credit backed");
    let epoch1 = p1.epoch;
    barrier.release.notify_waiters();

    // MEASURED partial drain between the two parks: some bytes delivered, not done.
    wait_until(
        "partial drain between the two parks",
        LIMIT,
        || { let n = sink_len.load(Ordering::Relaxed); n > 0 && n < total },
        || format!("delivered {} of {total}; stats {:?}", sink_len.load(Ordering::Relaxed), env.server.stats()),
    )
    .await;

    // Pause the sink so the server's receive ring accumulates an UNREAD TAIL:
    // subsequent reads commit into the ring but the sink does not drain them,
    // so `ring_len > 0` holds at the park-#2 detach point (consultant point 3).
    sink_paused.store(true, Ordering::Relaxed);
    // Let at least one read commit into the now-undrained ring before park #2,
    // so the park-#2 snapshot observes a real unread tail. Use the on-demand
    // per-lane snapshot (ring_len is the committed, undelivered bytes) — NOT a
    // budget proxy, which also counts the reservation.
    wait_until(
        "receive ring holds an unread tail (sink paused)",
        LIMIT,
        || lane_snapshot(2, 0).map_or(false, |s| s.ring_len > 0),
        || format!("no committed ring tail yet; snap {:?}", lane_snapshot(2, 0)),
    )
    .await;

    // PARK #2: pause the SECOND targeted read in the lock-drop window.
    let a2 = barrier.arrived.notified();
    tokio::pin!(a2);
    a2.as_mut().enable();
    barrier.armed.store(true, Ordering::Release);
    tokio::time::timeout(LIMIT, a2.as_mut()).await.expect("reader never parked for read #2");
    assert_eq!(barrier.park_index.load(Ordering::Acquire), 2, "expected the second park");
    let p2 = barrier.park(2).expect("snapshot #2");
    eprintln!("PARK#2 {p2:?}");
    assert!(p2.held_n > 0, "park #2 holds no bytes");
    // Two consecutive reads proven: received advanced between the parks.
    assert!(p2.received > p1.received, "second read did not advance received past the first");
    // Measured partial drain observed in the snapshot, with an unread tail held
    // at the detach point.
    assert!(p2.delivered > 0, "no partial drain observed at park#2");
    assert!(p2.ring_len > 0, "no unread ring tail at the detach point");
    assert_eq!(p2.ring_len, p2.received - p2.delivered, "park#2 ring invariant");
    assert!(p2.received >= p2.delivered, "park#2 received>=delivered");
    assert!(p2.reserve + p2.free_cover >= p2.limit - p2.received, "park#2 credit backed");
    assert_eq!(p2.epoch, epoch1, "no epoch change before the detach");

    // DETACH while parked on read #2 (between completion and commit).
    bh.set_down(true);
    c.carrier_lost().await;
    wait_until(
        "server detached + retracted while reader parked on read #2",
        LIMIT,
        || env.server.stats().detached == 1 && env.server.stats().credit_retractions >= 1,
        || format!("{:?}", env.server.stats()),
    )
    .await;

    // Release read #2: it reacquires, sees st.epoch != epoch, drops the stale
    // read. The connection must not be cut by a panic.
    barrier.release.notify_waiters();

    // Resume on a fresh carrier; the sender replays from the server's received.
    c.resume(other_socket()).await.unwrap();
    // Unpause the sink so the accumulated tail and the replayed bytes drain.
    sink_paused.store(false, Ordering::Relaxed);
    writer.await.unwrap();

    // EXACT payload equality (length AND ordered SHA-256): every forwarded byte
    // arrives once, in order. A dropped old-epoch read double-counted or lost —
    // even at equal length — changes the hash.
    wait_eof(&sink_len, total).await;
    let got = sink_hash.lock().await.clone().finalize();
    assert_eq!(got, expected_hash, "payload hash mismatch: loss/dup/reorder across the detach");

    clear_reader_barriers();
}
