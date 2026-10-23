//! §1 connection-window scheduler: raise when window-limited, charge the
//! budget, lower when idle but keep charging until the old window is read.
mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use ssh3_core::transport::dual_stack_socket;
use ssh3_core::{ClientSession, Limits, udp_socket};

fn sched(base: Limits) -> Limits {
    Limits {
        idle_timeout: Duration::from_secs(10),
        window_sample_min: Duration::from_millis(20),
        window_raise_after: 2,
        ..base
    }
}

async fn client_via(env: &Env, rtt: Duration) -> ClientSession {
    let front = delay::relay(env.server_addr(), rtt).await;
    let mut opts = env.opts(&env.key);
    opts.server_addr = front;
    ClientSession::connect(opts, udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap()).await.unwrap()
}

/// A transfer limited by the 256 KiB floor at 40 ms RTT raises the window;
/// the raise is charged to the budget and never exceeds the ceiling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn window_limited_transfer_raises_the_window() {
    let env = env_with(sched(fast_limits()));
    let c = client_via(&env, Duration::from_millis(40)).await;
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let data = Arc::new(pattern(8 << 20, 61));
    assert_same(&echo_roundtrip(fwd, data.clone()).await, &data);
    let sess = env.server.session(&c.session_id()).unwrap();
    let st = env.server.stats();
    assert!(st.window_raises >= 1, "{st:?}");
    let w = sess.stats.conn_window.load(Ordering::Relaxed);
    assert!(w > env.limits.floor_window && w <= env.limits.conn_window_ceiling, "window {w}");
    assert_eq!(st.conn_window_budget_used, sess.stats.conn_window_charged.load(Ordering::Relaxed) - env.limits.floor_window, "{st:?}");
}

/// Two window-limited sessions share a small budget: the sum charged above
/// the floors never exceeds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raises_stay_within_the_budget() {
    let budget = 512 * 1024;
    let env = env_with(sched(Limits { conn_window_budget: budget, ..fast_limits() }));
    let (a, b) = (client_via(&env, Duration::from_millis(40)).await, client_via(&env, Duration::from_millis(40)).await);
    let echo = echo_server().await;
    let (fa, fb) = (forward(&a, echo).await, forward(&b, echo).await);
    let data = Arc::new(pattern(6 << 20, 62));
    let mut max_used = 0;
    let (ra, rb) = (tokio::spawn(echo_roundtrip(fa, data.clone())), tokio::spawn(echo_roundtrip(fb, data.clone())));
    while !(ra.is_finished() && rb.is_finished()) {
        max_used = max_used.max(env.server.stats().conn_window_budget_used);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_same(&ra.await.unwrap(), &data);
    assert_same(&rb.await.unwrap(), &data);
    let st = env.server.stats();
    assert!(st.window_raises >= 1, "{st:?}");
    assert!(max_used <= budget, "budget {budget} exceeded: {max_used}");
    for c in [&a, &b] {
        let s = env.server.session(&c.session_id()).unwrap();
        assert!(s.stats.conn_window.load(Ordering::Relaxed) <= env.limits.floor_window + budget);
    }
}

/// Idle → lowered to the floor, but the old window stays charged until that
/// many bytes have been received; then the charge returns to the floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lowering_keeps_the_charge_until_the_old_window_is_read() {
    let env = env_with(sched(Limits { window_lower_after: Duration::from_millis(200), ..fast_limits() }));
    let c = client_via(&env, Duration::from_millis(40)).await;
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let data = Arc::new(pattern(8 << 20, 63));
    assert_same(&echo_roundtrip(fwd, data.clone()).await, &data);
    let sess = env.server.session(&c.session_id()).unwrap();
    let raised = sess.stats.conn_window.load(Ordering::Relaxed);
    assert!(raised > env.limits.floor_window);
    wait_until("lowered while idle", Duration::from_secs(10), || sess.stats.window_lowers.load(Ordering::Relaxed) >= 1, || format!("{:?}", env.server.stats())).await;
    assert_eq!(sess.stats.conn_window.load(Ordering::Relaxed), env.limits.floor_window);
    let charged = sess.stats.conn_window_charged.load(Ordering::Relaxed);
    assert!(charged > env.limits.floor_window, "charge dropped before the old window was read: {charged}");
    // Trickle more than the old window, too slowly to be window-limited,
    // into a sink that reads everything (an unread echo would block us).
    let sink = discard_server().await;
    let fwd2 = forward(&c, sink).await;
    let mut s = tokio::net::TcpStream::connect(fwd2).await.unwrap();
    let t0 = std::time::Instant::now();
    let raises_before = sess.stats.window_raises.load(Ordering::Relaxed);
    // ~16 KiB per 20 ms ≈ 13 % of the floor window at 43 ms RTT: far below
    // the 80 % that would raise it again.
    let chunk = vec![9u8; 16 * 1024];
    let mut sent = 0u64;
    use tokio::io::AsyncWriteExt;
    while sess.stats.conn_window_charged.load(Ordering::Relaxed) > env.limits.floor_window {
        s.write_all(&chunk).await.unwrap();
        sent += chunk.len() as u64;
        assert!(sent < 8 * raised && t0.elapsed() < Duration::from_secs(60), "charge never returned after {sent} bytes in {:?} (old window {raised}, raises {})", t0.elapsed(), sess.stats.window_raises.load(Ordering::Relaxed) - raises_before);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(sess.stats.window_raises.load(Ordering::Relaxed), raises_before, "the trickle re-raised the window; the test would not isolate the debt rule");
    assert!(sent >= raised / 2, "charge returned after only {sent} bytes, old window {raised}");
    assert_eq!(env.server.stats().conn_window_budget_used, 0);
}
