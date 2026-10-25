//! Client roaming (SPEC §5.1): liveness probe + rebind, automatic resume.
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;
use std::net::SocketAddr;
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

/// Board R6: a resume attempt is bounded by the remaining linger, not by the
/// QUIC idle timeout — with the network gone for good, the client gives up
/// about when the server's linger ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_attempts_are_bounded_by_the_linger() {
    // An unbounded attempt would last the handshake's idle timeout (2.5 s);
    // bounded, the client gives up when the 1 s linger is over.
    let env = env_with(roaming(Limits { idle_timeout: Duration::from_millis(2500), linger: Duration::from_secs(1), auto_resume: true, ..fast_limits() }));
    let net = Arc::new(AtomicBool::new(false));
    let mut opts = env.opts(&env.key);
    opts.sockets = network_factory(net.clone());
    let c = ClientSession::connect(opts.clone(), (opts.sockets)().unwrap()).await.unwrap();
    net.store(true, Ordering::SeqCst); // for good
    c.carrier_lost().await;
    let lost = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(4), c.gave_up()).await.expect("never gave up");
    assert!(lost.elapsed() < Duration::from_secs(2), "gave up only after {:?}: an attempt outlived the linger", lost.elapsed());
}

/// What the test resolver answers: addresses, or "name does not resolve".
type Answer = Arc<Mutex<Option<Vec<SocketAddr>>>>;

fn test_resolver(answer: Answer) -> ssh3_core::client::Resolver {
    Arc::new(move || {
        let a = answer.lock().unwrap().clone();
        Box::pin(async move { a.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "test resolver: name does not resolve")) })
    })
}

/// A name-resolution failure during automatic resume is transient: retried
/// with the backoff, never fatal. And the name is re-resolved on every
/// attempt: when it finally resolves to a NEW address (the old one is dead),
/// the session resumes there and the transfer completes intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_re_resolves_and_survives_an_unresolvable_name() {
    let env = env_with(roaming(Limits { idle_timeout: Duration::from_millis(300), auto_resume: true, ..fast_limits() }));
    let (old_addr, old_route) = common::delay::switchable_relay(env.server_addr()).await;
    let net = Arc::new(AtomicBool::new(false));
    let answer: Answer = Arc::new(Mutex::new(Some(vec![old_addr])));
    let mut opts = env.opts(&env.key);
    opts.server_addrs = vec![old_addr];
    opts.resolve = Some(test_resolver(answer.clone()));
    opts.sockets = network_factory(net.clone());
    let c = ClientSession::connect(opts.clone(), (opts.sockets)().unwrap()).await.unwrap();
    let echo = echo_server().await;
    let fwd = forward(&c, echo).await;
    let data = Arc::new(pattern(4 << 20, 53));
    let rt = tokio::spawn(echo_roundtrip(fwd, data.clone()));
    wait_until("transfer under way", Duration::from_secs(20), || c.shared.stats.lane_bytes_sent.load(Ordering::Relaxed) > 1 << 20, || format!("{:?}", env.server.stats())).await;
    net.store(true, Ordering::SeqCst);
    c.carrier_lost().await;
    wait_until("server detached", Duration::from_secs(10), || env.server.stats().detached == 1, || format!("{:?}", env.server.stats())).await;
    // The network is back, but the name does not resolve and the old
    // address is dead.
    *answer.lock().unwrap() = None;
    *old_route.lock().unwrap() = None;
    net.store(false, Ordering::SeqCst);
    wait_until("resolution failures retried", Duration::from_secs(10), || c.roam_stats().resolve_failures.load(Ordering::Relaxed) >= 3, || format!("{:?}", c.roam_stats())).await;
    assert!(!c.roam_stats().gave_up.load(Ordering::Relaxed), "a resolution failure ended the session");
    assert_eq!(c.roam_stats().resumes.load(Ordering::Relaxed), 0);
    // The name resolves again — to the server's new address.
    *answer.lock().unwrap() = Some(vec![env.server_addr()]);
    let out = tokio::time::timeout(Duration::from_secs(15), rt)
        .await
        .unwrap_or_else(|_| panic!("transfer did not resume at the new address: {:?}", c.roam_stats()))
        .unwrap();
    assert_same(&out, &data);
    assert_eq!(c.server_addr(), env.server_addr(), "the session did not move to the re-resolved address");
    assert!(c.roam_stats().resumes.load(Ordering::Relaxed) >= 1);
    assert_eq!(env.server.stats().resumes_accepted, c.roam_stats().resumes.load(Ordering::Relaxed));
}

fn erroring_factory(errno: Arc<AtomicI32>) -> ssh3_core::client::SocketFactory {
    Arc::new(move || Ok(Blackhole::on_network_err(dual_stack_socket("[::]:0".parse().unwrap()).unwrap(), None, Some(errno.clone())) as Arc<dyn quinn::AsyncUdpSocket>))
}

/// A laptop whose network is down answers sends with ENETUNREACH /
/// EHOSTUNREACH, a refusing path with ECONNREFUSED: every one of them is a
/// transient resume failure, retried until the network is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_retries_through_send_errors() {
    for (name, errno) in [("ENETUNREACH", libc::ENETUNREACH), ("EHOSTUNREACH", libc::EHOSTUNREACH), ("ECONNREFUSED", libc::ECONNREFUSED)] {
        let env = env_with(roaming(Limits { idle_timeout: Duration::from_millis(300), auto_resume: true, ..fast_limits() }));
        let err = Arc::new(AtomicI32::new(0));
        let mut opts = env.opts(&env.key);
        opts.sockets = erroring_factory(err.clone());
        let c = ClientSession::connect(opts.clone(), (opts.sockets)().unwrap()).await.unwrap();
        let echo = echo_server().await;
        let fwd = forward(&c, echo).await;
        let data = Arc::new(pattern(1 << 20, 54));
        err.store(errno, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), c.carrier_lost())
            .await
            .unwrap_or_else(|_| panic!("{name}: carrier not declared lost while every send fails: {:?}", c.roam_stats()));
        wait_until(&format!("{name}: attempts fail and are retried"), Duration::from_secs(10), || c.roam_stats().resume_attempts.load(Ordering::Relaxed) >= 3, || format!("{:?}", c.roam_stats())).await;
        assert!(!c.roam_stats().gave_up.load(Ordering::Relaxed), "{name} ended the session");
        assert_eq!(c.roam_stats().resumes.load(Ordering::Relaxed), 0, "{name}: resumed while every send failed");
        err.store(0, Ordering::SeqCst);
        let out = tokio::time::timeout(Duration::from_secs(15), echo_roundtrip(fwd, data.clone()))
            .await
            .unwrap_or_else(|_| panic!("{name}: no resume after the network came back: {:?}", c.roam_stats()));
        assert_same(&out, &data);
        assert!(c.roam_stats().resumes.load(Ordering::Relaxed) >= 1, "{name}");
    }
}
