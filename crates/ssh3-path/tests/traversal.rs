//! NAT traversal over the simulated network (SPEC §7, objective O3).
mod common;

use std::net::IpAddr;

use common::*;
use ssh3_path::{PathMode, RoundOutcome};

fn is_direct(s: &ssh3_path::PeerStatus) -> bool {
    matches!(s.mode, PathMode::Direct(_))
}

/// Both sides end on a direct path, inner traffic uses it, and a transfer that started on the
/// relay completes intact across the switch.
async fn goes_direct(kind_a: &str, kind_b: &str) {
    let w = World::new(kind_a, kind_b);
    let p = w.connect(true, cfg()).await;
    let t = start_transfer(&p, 1 << 20).await;
    let sa = until_w(&w, &p.pa, &p.pb, "A direct", is_direct).await;
    let sb = until_w(&w, &p.pb, &p.pa, "B direct", is_direct).await;
    t.finish().await;
    // The direct path really carries the inner connection now.
    let relay_before = p.link_a.sent();
    let t = start_transfer(&p, 512 << 10).await;
    t.finish().await;
    let ssa = w.a.mgr.socket_stats();
    let ssb = w.b.mgr.socket_stats();
    assert!(ssa.direct_out > 100 && ssb.rx_rewritten > 100, "direct path unused: A {ssa:?} B {ssb:?}");
    assert!(p.link_a.sent() - relay_before < 20, "transfer went over the relay: {} packets", p.link_a.sent() - relay_before);
    eprintln!("{kind_a} <-> {kind_b}: direct (A sends to {:?}, B to {:?}), gen {}", sa.mode, sb.mode, sa.generation);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_cone_both() {
    goes_direct("full-cone", "full-cone").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restricted_and_port_restricted() {
    goes_direct("restricted-cone", "port-restricted-cone").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn port_restricted_both_simultaneous_open() {
    goes_direct("port-restricted-cone", "port-restricted-cone").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_and_port_restricted() {
    goes_direct("public", "port-restricted-cone").await;
}

/// Endpoint-dependent mapping on one side is traversable when the other side's filtering lets
/// the unknown (peer-reflexive) mapping in: learned from the inbound punch and checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symmetric_and_full_cone_via_peer_reflexive() {
    goes_direct("symmetric", "full-cone").await;
}

/// The controlling role on the QUIC-server side works too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_side_controls() {
    let w = World::new("port-restricted-cone", "full-cone");
    let p = w.connect(false, cfg()).await;
    until(&p.pa, "A direct", is_direct).await;
    until(&p.pb, "B direct", is_direct).await;
    start_transfer(&p, 256 << 10).await.finish().await;
}

/// No direct path exists: the peers stay on the relay, report why, and traffic flows.
async fn stays_relay(kind_a: &str, kind_b: &str) {
    let w = World::new(kind_a, kind_b);
    let p = w.connect(true, cfg()).await;
    let s = until(&p.pa, "a finished round", |s| s.last_outcome != RoundOutcome::None).await;
    assert_eq!(s.mode, PathMode::Relay);
    match s.last_outcome {
        RoundOutcome::NoValidatedPair { punches_sent, responses, .. } => {
            assert!(punches_sent > 0 && responses == 0, "{s:?}");
        }
        other => panic!("{kind_a} <-> {kind_b}: unexpected outcome {other:?}"),
    }
    assert!(!is_direct(&p.pb.status()));
    start_transfer(&p, 256 << 10).await.finish().await;
    eprintln!("{kind_a} <-> {kind_b}: relay, outcome {:?}", s.last_outcome);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symmetric_both_stays_relay() {
    stays_relay("symmetric", "symmetric").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symmetric_and_port_restricted_stays_relay() {
    stays_relay("symmetric", "port-restricted-cone").await;
}

/// Direct path dies → both fall back to the relay without breaking the inner connection; when
/// it comes back a new round upgrades again. A transfer spans all of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_loss_falls_back_and_recovers() {
    let w = World::new("port-restricted-cone", "port-restricted-cone");
    let p = w.connect(true, cfg()).await;
    let s1 = until(&p.pa, "A direct", is_direct).await;
    until(&p.pb, "B direct", is_direct).await;
    let t = start_transfer(&p, 4 << 20).await;
    w.net.block(IpAddr::V4(NAT_A), IpAddr::V4(NAT_B), true);
    until(&p.pa, "A fallback", |s| s.mode == PathMode::Relay && s.fallbacks >= 1).await;
    until(&p.pb, "B fallback", |s| s.mode == PathMode::Relay && s.fallbacks >= 1).await;
    w.net.block(IpAddr::V4(NAT_A), IpAddr::V4(NAT_B), false);
    let s2 = until(&p.pa, "A direct again", |s| is_direct(s) && s.generation > s1.generation).await;
    until(&p.pb, "B direct again", |s| is_direct(s) && s.generation == s2.generation).await;
    t.finish().await;
    assert!(s2.epoch > s1.epoch);
}

/// Rebind (new socket, new NAT mapping) while a round is in progress: completions of the old
/// round are stale, a new round upgrades on the new mapping, the transfer survives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rebind_during_upgrade() {
    let w = World::new("port-restricted-cone", "full-cone");
    // A long round so the rebind certainly lands inside it.
    let mut c = cfg();
    c.punch_interval = std::time::Duration::from_millis(40);
    let p = w.connect(true, c).await;
    let t = start_transfer(&p, 1 << 20).await;
    until(&p.pa, "round 1 started", |s| s.generation >= 1).await;
    let epoch0 = w.a.mgr.epoch();
    let new_sock = w.net.bind("10.0.1.2:5001".parse().unwrap(), w.a.nat);
    w.a.mgr.rebind(new_sock).unwrap();
    assert_eq!(w.a.mgr.epoch(), epoch0 + 1);
    let s = until(&p.pa, "A direct after rebind", |s| is_direct(s) && s.generation >= 2).await;
    until(&p.pb, "B direct after rebind", |x| is_direct(x) && x.generation == s.generation).await;
    t.finish().await;
}

/// Carrier replacement while falling back: the fallback lands on the new relay link, not the
/// old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn carrier_replacement_during_fallback() {
    let w = World::new("full-cone", "full-cone");
    let p = w.connect(true, cfg()).await;
    until(&p.pa, "A direct", is_direct).await;
    until(&p.pb, "B direct", is_direct).await;
    let new_link = CountingLink::new(ssh3_path::sim::SimRelayLink {
        mgr: w.a.mgr.clone(),
        gateway: GW.parse().unwrap(),
        to: b"B".to_vec(),
    });
    w.net.block(IpAddr::V4(NAT_A), IpAddr::V4(NAT_B), true);
    p.pa.set_relay(new_link.clone());
    until(&p.pa, "A fallback", |s| s.mode == PathMode::Relay).await;
    let old = p.link_a.sent();
    start_transfer(&p, 256 << 10).await.finish().await;
    assert!(new_link.sent() > 50, "new carrier unused: {}", new_link.sent());
    assert_eq!(p.link_a.sent(), old, "old carrier still used after replacement");
}
