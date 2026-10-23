//! Client roaming (SPEC §5.1): liveness probe + rebind, automatic resume.
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::blackhole::Blackhole;
use common::*;
use ssh3_core::transport::dual_stack_socket;
use ssh3_core::{ClientSession, Limits};

fn roaming(base: Limits) -> Limits {
    Limits {
        probe_interval: Some(Duration::from_millis(50)),
        probe_timeout_min: Duration::from_millis(150),
        resume_backoff_initial: Duration::from_millis(20),
        resume_backoff_max: Duration::from_millis(100),
        ..base
    }
}

/// A dead path is detected by the probe and fixed by a rebind to a fresh
/// socket — no resume, the carrier and its epoch survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_probe_rebinds_without_resume() {
    let env = env_with(roaming(Limits { idle_timeout: Duration::from_secs(5), ..fast_limits() }));
    let bh = Blackhole::new(dual_stack_socket("[::]:0".parse().unwrap()).unwrap());
    let c = ClientSession::connect(env.opts(&env.key), bh.clone()).await.unwrap();
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let data = Arc::new(pattern(4 << 20, 51));
    let rt = tokio::spawn(echo_roundtrip(fwd, data.clone()));
    wait_until("transfer under way", Duration::from_secs(20), || c.shared.stats.lane_bytes_sent.load(Ordering::Relaxed) > 1 << 20, || format!("{:?}", env.server.stats())).await;
    bh.set_down(true); // this socket's path is dead from now on
    let out = tokio::time::timeout(Duration::from_secs(15), rt)
        .await
        .unwrap_or_else(|_| panic!("transfer did not survive the dead path: {:?}", c.roam_stats()))
        .unwrap();
    assert_same(&out, &data);
    let r = c.roam_stats();
    assert!(r.rebinds.load(Ordering::Relaxed) >= 1, "no rebind happened");
    assert_eq!(r.resumes.load(Ordering::Relaxed), 0);
    assert_eq!(env.server.stats().resumes_accepted, 0);
    assert_eq!(env.server.session(&c.session_id()).unwrap().epoch(), 1);
}

fn network_factory(net: Arc<AtomicBool>) -> ssh3_core::client::SocketFactory {
    Arc::new(move || Ok(Blackhole::on_network(dual_stack_socket("[::]:0".parse().unwrap()).unwrap(), Some(net.clone())) as Arc<dyn quinn::AsyncUdpSocket>))
}

/// An outage longer than the idle timeout kills the carrier; when the
/// network returns the client resumes by itself and the transfer finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_outage_is_recovered_by_automatic_resume() {
    let env = env_with(roaming(Limits { idle_timeout: Duration::from_millis(300), auto_resume: true, ..fast_limits() }));
    let net = Arc::new(AtomicBool::new(false));
    let mut opts = env.opts(&env.key);
    opts.sockets = network_factory(net.clone());
    let c = ClientSession::connect(opts.clone(), (opts.sockets)().unwrap()).await.unwrap();
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let data = Arc::new(pattern(4 << 20, 52));
    let rt = tokio::spawn(echo_roundtrip(fwd, data.clone()));
    wait_until("transfer under way", Duration::from_secs(20), || c.shared.stats.lane_bytes_sent.load(Ordering::Relaxed) > 1 << 20, || format!("{:?}", env.server.stats())).await;
    net.store(true, Ordering::SeqCst);
    c.carrier_lost().await;
    wait_until("server detached", Duration::from_secs(10), || env.server.stats().detached == 1, || format!("{:?}", env.server.stats())).await;
    let attempts_while_down = c.roam_stats().resume_attempts.load(Ordering::Relaxed);
    net.store(false, Ordering::SeqCst);
    let out = rt.await.unwrap();
    assert_same(&out, &data);
    let r = c.roam_stats();
    assert!(r.resumes.load(Ordering::Relaxed) >= 1);
    assert!(r.resume_attempts.load(Ordering::Relaxed) > attempts_while_down || attempts_while_down >= 1);
    assert!(env.server.stats().resumes_accepted >= 1);
    assert!(!r.gave_up.load(Ordering::Relaxed));
}

/// After the server expired the session, automatic resume is refused and
/// the client gives up instead of retrying forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_resume_gives_up_when_the_session_is_gone() {
    let env = env_with(roaming(Limits { idle_timeout: Duration::from_millis(300), linger: Duration::from_millis(100), auto_resume: true, ..fast_limits() }));
    let net = Arc::new(AtomicBool::new(false));
    let mut opts = env.opts(&env.key);
    opts.sockets = network_factory(net.clone());
    let c = ClientSession::connect(opts.clone(), (opts.sockets)().unwrap()).await.unwrap();
    net.store(true, Ordering::SeqCst);
    c.carrier_lost().await;
    wait_until("session expired on the server", Duration::from_secs(10), || env.server.stats().sessions == 0, || format!("{:?}", env.server.stats())).await;
    net.store(false, Ordering::SeqCst);
    // R3: an awaitable notification, no polling.
    tokio::time::timeout(Duration::from_secs(10), c.gave_up()).await.expect("gave_up() did not resolve");
    assert!(c.roam_stats().gave_up.load(Ordering::Relaxed));
    let n = c.roam_stats().resume_attempts.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(c.roam_stats().resume_attempts.load(Ordering::Relaxed), n, "kept retrying after giving up");
    assert!(!c.shared.is_attached());
}

/// R3: last contact advances while the server answers probes and stops
/// while the path is dead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_contact_tracks_the_server() {
    let env = env_with(roaming(Limits { idle_timeout: Duration::from_secs(5), ..fast_limits() }));
    let bh = Blackhole::new(dual_stack_socket("[::]:0".parse().unwrap()).unwrap());
    let mut opts = env.opts(&env.key);
    // Keep the dead socket dead: rebinds land on blackholed sockets too.
    let net = Arc::new(AtomicBool::new(false));
    opts.sockets = network_factory(net.clone());
    let c = ClientSession::connect(opts, bh.clone()).await.unwrap();
    let t0 = c.last_contact();
    wait_until("contact advances", Duration::from_secs(5), || c.last_contact() > t0, || "no contact".into()).await;
    bh.set_down(true);
    net.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let frozen = c.last_contact();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(c.last_contact(), frozen, "contact advanced over a dead path");
    assert!(frozen.elapsed() >= Duration::from_millis(400));
}
