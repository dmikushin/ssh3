//! Jump through a gateway (SPEC §7.2): the inner connection to the target
//! runs end to end over a UDP channel of the gateway session.
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use ssh3_core::client::HostCheck;
use ssh3_core::{ClientOptions, ClientSession, Error};

/// Inner options: the target's own known_hosts and authorized_keys, dialled
/// at the jump path's virtual address.
fn inner_opts(target: &Env, path: &ssh3_core::jump::JumpPath) -> ClientOptions {
    ClientOptions { server_addr: path.virt, sockets: path.socket_factory(), ..target.opts(&target.key) }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_carries_an_end_to_end_session() {
    let gw = env_with(fast_limits());
    let target = env_with(fast_limits());
    let c = gw.client().await;
    let path = c.jump("127.0.0.1", target.server.local_addr().port()).await.unwrap();
    let inner = ClientSession::connect(inner_opts(&target, &path), path.socket()).await.unwrap();
    // The target, not the gateway, holds the inner session.
    assert_eq!(target.server.stats().sessions, 1);
    assert_eq!(gw.server.stats().sessions, 1);
    let echo = echo_server().await;
    let l = forward(&inner, echo).await;
    let data = Arc::new(pattern(4 << 20, 71));
    let out = echo_roundtrip(l, data.clone()).await;
    assert_same(&out, &data);
    // It really went through the gateway's relay route.
    assert!(path.relayed() > 100, "only {} packets on the relay route", path.relayed());
    let gs = gw.server.stats();
    assert!(gs.datagrams_received > 100, "gateway saw only {} datagrams: {gs:?}", gs.datagrams_received);
}

/// The inner connection verifies the TARGET's host key: a trusted gateway
/// does not make a wrong target key acceptable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_refuses_a_wrong_target_host_key() {
    let gw = env_with(fast_limits());
    let target = env_with(fast_limits());
    // known_hosts for the target names a different key.
    let wrong = target.dir.join("known_hosts.wrong");
    let other = ssh3_keys::host::HostIdentity::from_private_key(&ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[201; 32]))).unwrap();
    ssh3_keys::known_hosts::append(&wrong, "127.0.0.1", target.server.local_addr().port(), other.public_key(), false).unwrap();
    let c = gw.client().await;
    let path = c.jump("127.0.0.1", target.server.local_addr().port()).await.unwrap();
    let opts = ClientOptions { host: HostCheck { files: vec![wrong], ..target.host_check() }, ..inner_opts(&target, &path) };
    match tokio::time::timeout(Duration::from_secs(10), ClientSession::connect(opts, path.socket())).await {
        Ok(Err(Error::HostKey(_))) => {}
        Ok(Err(e)) => panic!("expected a host-key refusal, got {e}"),
        Ok(Ok(_)) => panic!("connected to a target whose key is not in known_hosts"),
        Err(_) => panic!("inner connect did not finish"),
    }
    assert_eq!(target.server.stats().sessions, 0);
}

/// A jump to a target the authorized_keys options forbid is refused by the
/// gateway (permitopen applies, as to direct-tcp).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_respects_permitopen() {
    let gw = env_with(fast_limits());
    gw.authorize_only(&gw.key, "permitopen=\"127.0.0.1:1\"");
    let c = gw.client().await;
    match c.jump("127.0.0.1", 9).await {
        Err(Error::Refused(_)) => {}
        Err(e) => panic!("expected a refusal, got {e}"),
        Ok(_) => panic!("gateway opened a jump permitopen forbids"),
    }
}

/// Two hops: client → gw1 → gw2 → target, each inner connection end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jump_two_hops() {
    let gw1 = env_with(fast_limits());
    let gw2 = env_with(fast_limits());
    let target = env_with(fast_limits());
    let c1 = gw1.client().await;
    let p1 = c1.jump("127.0.0.1", gw2.server.local_addr().port()).await.unwrap();
    let c2 = ClientSession::connect(inner_opts(&gw2, &p1), p1.socket()).await.unwrap();
    let p2 = c2.jump("127.0.0.1", target.server.local_addr().port()).await.unwrap();
    let c3 = ClientSession::connect(inner_opts(&target, &p2), p2.socket()).await.unwrap();
    let echo = echo_server().await;
    let l = forward(&c3, echo).await;
    let data = Arc::new(pattern(1 << 20, 72));
    assert_same(&echo_roundtrip(l, data.clone()).await, &data);
    assert!(p1.relayed() > 0 && p2.relayed() > 0);
    assert_eq!(target.server.stats().sessions, 1);
}
