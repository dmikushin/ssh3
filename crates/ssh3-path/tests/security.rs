//! Punch authentication (SPEC §7.3 step 3): forged, stale, replayed and unsolicited side-channel
//! packets are rejected and change nothing.
mod common;

use std::time::Duration;

use common::*;
use ssh3_path::wire::{self, KIND_CHECK, Punch, PunchKey, ROLE_CONTROLLING, Resp};
use ssh3_path::PathMode;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_stale_replayed_and_unsolicited_are_rejected() {
    let w = World::new("full-cone", "full-cone");
    let p = w.connect(true, cfg()).await;
    let sa = until(&p.pa, "A direct", |s| matches!(s.mode, PathMode::Direct(_))).await;
    let sb = until(&p.pb, "B direct", |s| matches!(s.mode, PathMode::Direct(_))).await;
    let PathMode::Direct(b_addr) = sa.mode else { unreachable!() };
    let g = sb.generation;
    let key = PunchKey::new(&p.secret);
    let attacker = w.net.bind("203.0.113.66:7777".parse().unwrap(), None);
    let c0 = snapshot(&p.pb);

    // Forged: right tag (so it is dispatched to B's path), wrong key.
    let forger = PunchKey::new(&[0x55; 32]);
    let mut forged = wire::encode_punch(&forger, &Punch { tag: key.tag(), generation: g, nonce: [1; 16], role: ROLE_CONTROLLING, kind: KIND_CHECK });
    attacker.send_to(b_addr, &forged);
    // Tampered copy of a genuinely keyed punch.
    let mut tampered = wire::encode_punch(&key, &Punch { tag: key.tag(), generation: g, nonce: [2; 16], role: ROLE_CONTROLLING, kind: KIND_CHECK });
    let n = tampered.len();
    tampered[n - 20] ^= 0x80;
    attacker.send_to(b_addr, &tampered);
    forged.truncate(10);
    attacker.send_to(b_addr, &forged); // too short: malformed
    // Stale generation, correctly keyed: punch and response.
    let stale = wire::encode_punch(&key, &Punch { tag: key.tag(), generation: g - 1, nonce: [3; 16], role: ROLE_CONTROLLING, kind: KIND_CHECK });
    attacker.send_to(b_addr, &stale);
    let stale_resp = wire::encode_resp(&key, &Resp { tag: key.tag(), generation: g - 1, nonce: [4; 16], role: ROLE_CONTROLLING, observed: b_addr });
    attacker.send_to(b_addr, &stale_resp);
    // Current generation, correctly keyed, but a nonce B never sent: unsolicited response.
    let unsolicited = wire::encode_resp(&key, &Resp { tag: key.tag(), generation: g, nonce: [5; 16], role: ROLE_CONTROLLING, observed: b_addr });
    attacker.send_to(b_addr, &unsolicited);
    // A valid punch replayed: the second copy is rejected.
    let valid = wire::encode_punch(&key, &Punch { tag: key.tag(), generation: g, nonce: [6; 16], role: ROLE_CONTROLLING, kind: KIND_CHECK });
    attacker.send_to(b_addr, &valid);
    attacker.send_to(b_addr, &valid);

    let want = |c: &Counts| {
        c.bad_mac >= c0.bad_mac + 2
            && c.malformed > c0.malformed
            && c.stale_generation >= c0.stale_generation + 2
            && c.unsolicited > c0.unsolicited
            && c.replayed > c0.replayed
    };
    let deadline = tokio::time::Instant::now() + BOUND;
    loop {
        let c = snapshot(&p.pb);
        if want(&c) {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "rejections not counted: before {c0:?} after {c:?}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Nothing moved: same direct pairs, same generation, no extra switch.
    let a2 = p.pa.status();
    let b2 = p.pb.status();
    assert_eq!((a2.mode, a2.generation, a2.switches_direct), (sa.mode, sa.generation, 1));
    assert_eq!((b2.mode, b2.generation, b2.switches_direct), (sb.mode, sb.generation, 1));
    start_transfer(&p, 256 << 10).await.finish().await;
}

#[derive(Debug, Clone, Copy)]
struct Counts {
    bad_mac: u64,
    malformed: u64,
    stale_generation: u64,
    unsolicited: u64,
    replayed: u64,
}

fn snapshot(p: &ssh3_path::PeerPath) -> Counts {
    use std::sync::atomic::Ordering::Relaxed;
    let c = &p.counters;
    Counts {
        bad_mac: c.bad_mac.load(Relaxed),
        malformed: c.malformed.load(Relaxed),
        stale_generation: c.stale_generation.load(Relaxed),
        unsolicited: c.unsolicited.load(Relaxed),
        replayed: c.replayed.load(Relaxed),
    }
}
