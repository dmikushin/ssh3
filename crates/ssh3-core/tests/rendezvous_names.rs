//! Rendezvous name ownership and namespace (SPEC §7.1): a registered peer
//! name belongs to the (user, key) that registered it while that
//! registration lives; other owners are refused; names live in their own
//! namespace (`<name>.peer`) and never capture jumps to DNS hosts.
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use ssh3_core::auth::Signer;
use ssh3_core::error::Error;
use ssh3_core::msg::FailReason;
use ssh3_core::path::{PathConfig, PathManager};
use ssh3_core::transport::dual_stack_socket;
use ssh3_core::{ClientOptions, ClientSession, Limits, Server};

const BOUND: Duration = Duration::from_secs(10);

fn path_cfg() -> PathConfig {
    PathConfig {
        punch_interval: Duration::from_millis(20),
        round_timeout: Duration::from_millis(800),
        retry_interval: Duration::from_millis(300),
        keepalive_interval: Duration::from_millis(80),
        direct_timeout: Duration::from_millis(400),
        reset_on_switch: true,
    }
}

/// A peer server on a real loopback socket with a path manager, so it can
/// register at a gateway.
fn peer() -> Env {
    let mgr = PathManager::new(ssh3_core::udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap());
    env_bind(fast_limits(), ssh3_core::ServerSessionEnv::new(ssh3_session::SessionConfig::default()), |o| Server::bind_path(o, mgr).unwrap())
}

fn gw_opts(gw: &Env, key: &Arc<TestKey>, user: &str) -> ClientOptions {
    ClientOptions { user: user.into(), ..gw.opts(key) }
}

async fn register(p: &Env, gw: &Env, key: &Arc<TestKey>, user: &str, name: &str) -> ssh3_core::Result<ClientSession> {
    tokio::time::timeout(BOUND, p.server.register_at(gw_opts(gw, key, user), name, path_cfg())).await.expect("register timed out")
}

fn bind_failed(r: ssh3_core::Result<ClientSession>, want: &str) {
    match r {
        Err(Error::Refused(FailReason::BindFailed(m))) => assert!(m.contains(want), "refusal {m:?} does not mention {want:?}"),
        Err(e) => panic!("expected BindFailed mentioning {want:?}, got {e}"),
        Ok(_) => panic!("expected BindFailed mentioning {want:?}, registration succeeded"),
    }
}

fn gateway(limits: Limits) -> (Env, Arc<TestKey>, Arc<TestKey>) {
    let gw = env_with(limits);
    let ka = user_key(31);
    let kb = user_key(32);
    gw.authorize_also(&ka);
    gw.authorize_also(&kb);
    (gw, ka, kb)
}

#[tokio::test(flavor = "multi_thread")]
async fn another_user_cannot_take_a_live_name() {
    let (gw, ka, kb) = gateway(fast_limits());
    let (a, b) = (peer(), peer());
    let _reg_a = register(&a, &gw, &ka, &current_user(), "box").await.unwrap();
    bind_failed(register(&b, &gw, &kb, "other-user", "box").await, "box");
    // Case-insensitive names: BOX is the same name.
    bind_failed(register(&b, &gw, &kb, "other-user", "BOX").await, "box");
    assert_eq!(gw.server.stats().peers_registered, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn same_user_other_key_cannot_take_a_live_name() {
    let (gw, ka, kb) = gateway(fast_limits());
    let (a, b) = (peer(), peer());
    let _reg_a = register(&a, &gw, &ka, &current_user(), "box").await.unwrap();
    bind_failed(register(&b, &gw, &kb, &current_user(), "box").await, "box");
}

#[tokio::test(flavor = "multi_thread")]
async fn same_owner_replaces_its_registration() {
    let (gw, ka, _) = gateway(fast_limits());
    let (a1, a2) = (peer(), peer());
    let _r1 = register(&a1, &gw, &ka, &current_user(), "box").await.unwrap();
    // A restarted peer (new session, same user and key) takes its name back.
    let _r2 = register(&a2, &gw, &ka, &current_user(), "box").await.unwrap();
    assert_eq!(gw.server.stats().peers_registered, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn name_is_freed_when_the_owner_session_ends() {
    let (gw, ka, kb) = gateway(fast_limits());
    let (a, b) = (peer(), peer());
    let reg_a = register(&a, &gw, &ka, &current_user(), "box").await.unwrap();
    assert!(reg_a.end(BOUND).await, "server confirmed the end");
    wait_until("registration freed", BOUND, || gw.server.stats().peers_registered == 0, || format!("{:?}", gw.server.stats().peers_registered)).await;
    let _reg_b = register(&b, &gw, &kb, "other-user", "box").await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_names_are_refused() {
    let (gw, ka, _) = gateway(fast_limits());
    let p = peer();
    for bad in ["", "-box", "box-", "b_x", "bøx", "box.peer", "a.b", &"x".repeat(64)] {
        bind_failed(register(&p, &gw, &ka, &current_user(), bad).await, "invalid peer name");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn registrations_are_capped_per_session() {
    let mut limits = fast_limits();
    limits.max_listeners = 2;
    let (gw, ka, _) = gateway(limits);
    let p = peer();
    let reg = register(&p, &gw, &ka, &current_user(), "one").await.unwrap();
    reg.register_name("two").await.unwrap();
    match reg.register_name("three").await {
        Err(Error::Refused(FailReason::ResourceLimit)) => {}
        r => panic!("expected ResourceLimit, got {r:?}"),
    }
    assert_eq!(gw.server.stats().peers_registered, 2);
}

/// A registration named like a DNS host must never capture a jump to that
/// host: `-J gw echo-host` (a real address) reaches the real target, and only
/// `<name>.peer` reaches the registered peer.
#[tokio::test(flavor = "multi_thread")]
async fn registrations_do_not_shadow_dns_names() {
    let (gw, ka, _) = gateway(fast_limits());
    let p = peer();
    // A plain DNS name: "localhost". Registering it is allowed (it is a valid
    // peer label) but a jump to `localhost` must still go to DNS.
    let _reg = register(&p, &gw, &ka, &current_user(), "localhost").await.unwrap();
    let target = env_with(fast_limits());
    let c = gw.client().await;
    let path = c.jump("localhost", target.server.local_addr().port()).await.unwrap();
    // The inner connection must reach the real `target`, verified by its key.
    let mut o = target.opts(&target.key);
    o.server_addr = path.virt;
    let inner = tokio::time::timeout(BOUND, ClientSession::connect(path.inner_opts(o), path.socket())).await.expect("inner connect timed out");
    let _inner = inner.expect("inner connect over the jump");
    // Every test env shares one host key, so the key check cannot tell the
    // two servers apart here: which server holds the session can.
    assert_eq!(target.server.stats().sessions, 1, "jump to the DNS name must reach the real target");
    assert_eq!(p.server.stats().sessions, 0, "the registered peer captured a jump to a DNS name");
    // And the peer is reachable only through its own namespace.
    let path = c.jump("LocalHost.Peer", 22).await.unwrap();
    let mut o = p.opts(&p.key);
    o.server_addr = path.virt;
    let _inner = tokio::time::timeout(BOUND, ClientSession::connect(path.inner_opts(o), path.socket())).await.expect("inner connect timed out").expect("inner connect to the peer");
    assert_eq!(p.server.stats().sessions, 1, "`localhost.peer` must reach the registered peer");
}

/// A `.peer` name nobody registered fails explicitly; it is never resolved.
#[tokio::test(flavor = "multi_thread")]
async fn unregistered_peer_names_fail_without_dns() {
    let (gw, _, _) = gateway(fast_limits());
    let c = gw.client().await;
    match c.jump("localhost.peer", 22).await {
        Err(e) => assert!(e.to_string().contains("no peer registered as localhost"), "{e}"),
        Ok(_) => panic!("jump to an unregistered .peer name succeeded"),
    }
}

/// Registering is permitted like `permitlisten="<label>.peer:0"`.
#[tokio::test(flavor = "multi_thread")]
async fn registration_is_permitted_per_name() {
    let (gw, ka, _) = gateway(fast_limits());
    gw.authorize_only(&ka, "permitlisten=\"box.peer:0\"");
    let p = peer();
    let reg = register(&p, &gw, &ka, &current_user(), "box").await.unwrap();
    match reg.register_name("other").await {
        Err(Error::Refused(FailReason::Prohibited)) => {}
        r => panic!("expected Prohibited, got {r:?}"),
    }
}

/// The gateway's total of names is capped (`max_sessions`).
#[tokio::test(flavor = "multi_thread")]
async fn registrations_are_capped_in_total() {
    let mut limits = fast_limits();
    limits.max_sessions = 3;
    let (gw, ka, _) = gateway(limits);
    let p = peer();
    let reg = register(&p, &gw, &ka, &current_user(), "n1").await.unwrap();
    reg.register_name("n2").await.unwrap();
    reg.register_name("n3").await.unwrap();
    match reg.register_name("n4").await {
        Err(Error::Refused(FailReason::ResourceLimit)) => {}
        r => panic!("expected ResourceLimit, got {r:?}"),
    }
    // Re-registering a held name is not a new entry.
    reg.register_name("n3").await.unwrap();
    assert_eq!(gw.server.stats().peers_registered, 3);
}

/// Connecting to a registered peer is permitted by exactly one rule,
/// `permitopen="<label>.peer:0"`, whatever port the client names (it names
/// its ssh_config Port, e.g. 443): one check, not two with different ports.
#[tokio::test(flavor = "multi_thread")]
async fn peer_connection_is_permitted_by_label_peer_port_0() {
    let (gw, ka, _) = gateway(fast_limits());
    let p = peer();
    let _reg = register(&p, &gw, &ka, &current_user(), "box").await.unwrap();
    // The jumping client's key may open only box.peer.
    let kc = user_key(33);
    let ak = std::fs::read_to_string(&gw.authorized_keys).unwrap();
    std::fs::write(&gw.authorized_keys, format!("{ak}permitopen=\"box.peer:0\" {}\n", kc.public_key().to_openssh().unwrap())).unwrap();
    let c = ClientSession::connect(gw.opts(&kc), ssh3_core::udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap()).await.unwrap();
    let path = c.jump("box.peer", 443).await.expect("permitopen=\"box.peer:0\" allows a jump to box.peer with Port 443");
    let mut o = p.opts(&p.key);
    o.server_addr = path.virt;
    let _inner = tokio::time::timeout(BOUND, ClientSession::connect(path.inner_opts(o), path.socket())).await.expect("inner connect timed out").expect("inner connect to the peer");
    // Any other target stays refused: another peer, a real host.
    for (h, port) in [("other.peer", 443), ("localhost", 443)] {
        match c.jump(h, port).await {
            Err(Error::Refused(FailReason::Prohibited)) => {}
            r => panic!("jump to {h}:{port} should be Prohibited, got {:?}", r.map(|_| ())),
        }
    }
}
