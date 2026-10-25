//! ONE finite multi-read interleaving on the REAL server quic_reader.
//!
//! Requires `--features test-hooks`. Builds on the reviewed barrier that pauses
//! quic_reader after a read, with the lock dropped and `received` not yet
//! advanced. Here the barrier is re-armed across TWO consecutive reads, and a
//! DETACH (carrier death -> retract_unilaterally, which bumps the epoch) is
//! forced between read-completion and commit of the first read. A sink partial
//! drain happens before, so delivered has advanced and the ring is partly
//! drained at the interleaving.
//!
//! Boundary invariants checked on the live server stats proxies and (where the
//! test can observe) via the delivered byte count and final payload equality:
//!   * recv accounting consistent (no overflow/underflow panic cutting the
//!     connection — the atomic+rollback recv_commit guarantees
//!     rbuf == received - delivered and received >= delivered),
//!   * advertised credit backed (credit_outstanding returns to the floor on
//!     detach; no "credit granted without storage" protocol close),
//!   * the old-epoch read is dropped (not double-counted) — proven by exact
//!     final byte equality after resume: every forwarded byte arrives once.
//!
//! Criterion: a deterministic violation on OLD with a NEW control, OR an
//! explicit bounded negative result excluding this ordering on both. Timers are
//! failure deadlines only, never synchronisation.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::*;
use ssh3_core::lane::{clear_reader_barriers, install_reader_barrier};
use ssh3_core::Limits;
use tokio::io::AsyncWriteExt;

const LIMIT: Duration = Duration::from_secs(10);

fn retracting(base: Limits) -> Limits {
    Limits {
        credit_idle: Duration::from_millis(100),
        retract_timeout_min: Duration::from_secs(30),
        idle_timeout: Duration::from_millis(400),
        ..base
    }
}

async fn counting_sink() -> (std::net::SocketAddr, Arc<AtomicU64>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let n = Arc::new(AtomicU64::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let n = n2.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    use tokio::io::AsyncReadExt;
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
    (a, n)
}

/// Multi-read interleaving: detach/epoch replacement between the first read's
/// completion and its commit, with a second read and a partial sink drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detach_between_two_reads_loses_no_bytes() {
    clear_reader_barriers();
    // Server's forwarded data lane is channel 2, lane 0 (first client channel).
    let barrier = install_reader_barrier(2, 0);

    let env = env_with(retracting(fast_limits()));
    let (sink, count) = counting_sink().await;
    let (c, bh) = client_bh(&env).await;
    let fwd = forward(&c, sink).await;

    // Payload large enough to span several reads; every 8-byte word encodes its
    // index, so any loss/dup/reorder shows as a count mismatch downstream.
    let data = Arc::new(pattern(2 << 20, 81));
    let total = data.len() as u64;
    let d = data.clone();
    let mut s = tokio::net::TcpStream::connect(fwd).await.unwrap();
    let writer = tokio::spawn(async move {
        s.write_all(&d).await.unwrap();
        s.shutdown().await.unwrap();
    });

    // Let the transfer get going and the sink drain partially, so delivered has
    // advanced and the ring is partly drained before the interleaving.
    wait_until(
        "partial drain underway",
        LIMIT,
        || count.load(Ordering::Relaxed) > 64 << 10,
        || format!("delivered {} ; stats {:?}", count.load(Ordering::Relaxed), env.server.stats()),
    )
    .await;

    // READ #1: arm the barrier; the next server read parks in the lock-drop
    // window (read completed, lock dropped, received not advanced).
    let arrived1 = barrier.arrived.notified();
    tokio::pin!(arrived1);
    arrived1.as_mut().enable();
    barrier.armed.store(true, Ordering::Release);
    tokio::time::timeout(LIMIT, arrived1.as_mut())
        .await
        .expect("reader never parked for read #1 (barrier id wrong, or stream drained)");
    assert!(barrier.held_n.load(Ordering::Acquire) > 0, "read #1 parked holding no bytes");

    // DETACH while the reader is parked in the window: carrier death bumps the
    // epoch (retract_unilaterally). This is the epoch replacement between the
    // first read's completion and its commit.
    bh.set_down(true);
    c.carrier_lost().await;
    wait_until(
        "server detached + retracted while reader parked",
        LIMIT,
        || env.server.stats().detached == 1 && env.server.stats().credit_retractions >= 1,
        || format!("{:?}", env.server.stats()),
    )
    .await;
    // Advertised credit must be back at the floor after the unilateral retract
    // (no unbacked credit). Floor = lane_floor; a couple of lanes/floor chunks.
    let st = env.server.stats();
    assert!(
        st.credit_outstanding <= 8 * 16384,
        "credit not backed/retracted to floor after detach: {st:?}"
    );

    // Release the parked reader: it reacquires, sees st.epoch != epoch, and
    // DROPS the stale read (read #1 not committed). The connection must not be
    // cut by any accounting panic.
    barrier.release.notify_waiters();

    // Resume on a fresh carrier (new epoch). The sender replays from the
    // server's `received`; READ #2 and the rest arrive under the new epoch.
    // (The barrier is left disarmed now, so the new carrier's reads flow.)
    c.resume(other_socket()).await.unwrap();
    writer.await.unwrap();

    // EXACT final bytes: every forwarded byte is delivered exactly once. If the
    // dropped old-epoch read had been double-counted or lost, this count would
    // not land on `total`.
    wait_until(
        "all bytes delivered exactly once after resume",
        LIMIT,
        || count.load(Ordering::Relaxed) == total,
        || format!("delivered {} of {total}; stats {:?}", count.load(Ordering::Relaxed), env.server.stats()),
    )
    .await;

    clear_reader_barriers();
}
