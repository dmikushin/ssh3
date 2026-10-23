//! X9 (SPEC §7.3): resetting quinn's path state on a switch below an unchanged virtual peer
//! address. Relay path: narrow (gateway MTU 1300 → inner ≤ 1297) and long; direct path: 1472.
//! With `path_changed` (vendored quinn) the client climbs to the direct MTU right after the
//! switch; without it quinn keeps the relay MTU until its next MTUD interval (600 s default).
mod common;

use std::net::IpAddr;
use std::time::Duration;

use common::*;
use ssh3_path::PathMode;

#[derive(Debug)]
#[allow(dead_code)] // fields are reported through Debug
struct Run {
    relay_mtu: u16,
    direct_mtu: u16,
    direct_rtt: Duration,
    fallback_mtu: u16,
    fallback_lost: u64,
}

async fn run(reset: bool) -> Run {
    let w = World::new("full-cone", "full-cone");
    w.net.set_mtu(GW.parse::<std::net::SocketAddr>().unwrap().ip(), 1300);
    // Hold the direct path closed until the relay MTU has settled.
    w.net.block(IpAddr::V4(NAT_A), IpAddr::V4(NAT_B), true);
    let mut c = cfg();
    c.reset_on_switch = reset;
    let p = w.connect(true, c).await;
    let load = start_transfer(&p, 64 << 20).await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let relay_mtu = p.ca.stats().path.current_mtu;

    w.net.block(IpAddr::V4(NAT_A), IpAddr::V4(NAT_B), false);
    until(&p.pa, "A direct", |s| matches!(s.mode, PathMode::Direct(_))).await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let direct_mtu = p.ca.stats().path.current_mtu;
    let direct_rtt = p.ca.rtt();

    let lost0 = p.ca.stats().path.lost_packets;
    w.net.block(IpAddr::V4(NAT_A), IpAddr::V4(NAT_B), true);
    until(&p.pa, "A fallback", |s| s.mode == PathMode::Relay && s.fallbacks >= 1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let fallback_mtu = p.ca.stats().path.current_mtu;
    let fallback_lost = p.ca.stats().path.lost_packets - lost0;
    drop(load);
    Run { relay_mtu, direct_mtu, direct_rtt, fallback_mtu, fallback_lost }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_changed_resets_mtu_on_switch() {
    let (with, without) = tokio::join!(run(true), run(false));
    eprintln!("X9 with path_changed:    {with:?}");
    eprintln!("X9 without path_changed: {without:?}");
    assert!(with.relay_mtu <= 1297 && without.relay_mtu <= 1297, "relay MTU not bounded: {with:?} {without:?}");
    assert!(with.direct_mtu >= 1400, "direct MTU not regained after the switch: {with:?}");
    assert!(without.direct_mtu <= 1297, "control run regained MTU without the reset: {without:?}");
    assert!(with.fallback_mtu <= 1297 && without.fallback_mtu <= 1297);
}
