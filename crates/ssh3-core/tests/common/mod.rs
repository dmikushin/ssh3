//! Shared test harness: pinned TLS, ed25519 test keys, servers, TCP helpers.
#![allow(dead_code)]

pub mod blackhole;
pub mod delay;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtOrd};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use ssh_key::PrivateKey;
use ssh_key::private::Ed25519Keypair;
use ssh3_core::auth::{AuthorizedKeysAuthenticator, Signer};
use ssh3_core::client::HostCheck;
use ssh3_core::transport::{EndpointKeys, dual_stack_socket};
use ssh3_core::{ClientOptions, ClientSession, Limits, Server, ServerOptions, udp_socket};
use ssh3_keys::host::HostIdentity;
use ssh3_keys::signer::FileSigner;
use ssh3_keys::verifier::StrictHostKeyChecking;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub fn init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

// ----------------------------------------------------------------- keys

pub type TestKey = FileSigner;

fn ed25519(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

/// A user key (OpenSSH ed25519) from a fixed seed.
pub fn user_key(seed: u8) -> Arc<TestKey> {
    Arc::new(FileSigner::from_key(ed25519(seed)))
}

// --------------------------------------------------------------- setups

pub fn fast_limits() -> Limits {
    Limits {
        idle_timeout: Duration::from_millis(600),
        keep_alive: Duration::from_millis(100),
        ack_interval: Duration::from_millis(50),
        login_grace: Duration::from_secs(5),
        linger: Duration::from_secs(30),
        // Roaming off by default: outage tests need a deterministic carrier
        // death and resume by hand; roaming tests opt in.
        probe_interval: None,
        auto_resume: false,
        ..Limits::default()
    }
}

/// A server with a real host identity, a real authorized_keys file and a
/// real known_hosts file, in a private directory under ~/scratch.
pub struct Env {
    pub dir: PathBuf,
    pub host: HostIdentity,
    pub key: Arc<TestKey>,
    pub authorized_keys: PathBuf,
    pub known_hosts: PathBuf,
    pub server: Server,
    pub limits: Limits,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

static DIRS: AtomicU64 = AtomicU64::new(0);

pub fn env_with(limits: Limits) -> Env {
    env_with_session(limits, ssh3_core::ServerSessionEnv::new(ssh3_session::SessionConfig::default()))
}

/// Test sessions run /bin/sh with HOME inside the test directory: the
/// developer's real login shell and dotfiles must not run (fish config was
/// being executed and resets SSH_AUTH_SOCK).
fn isolate_user(session: &mut ssh3_core::ServerSessionEnv, home: PathBuf) {
    session.users = Arc::new(move |name| {
        let mut u = ssh3_session::UserRecord::lookup(name).map_err(|e| e.to_string())?;
        u.shell = PathBuf::from("/bin/sh");
        u.home = home.clone();
        Ok(u)
    });
}

/// The account the tests run as (session processes need a real user).
pub fn current_user() -> String {
    std::env::var("USER").expect("USER is set")
}

pub fn env_with_session(limits: Limits, session: ssh3_core::ServerSessionEnv) -> Env {
    env_bind(limits, session, |o| Server::bind(o, dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap())
}

/// As `env_with_session`, with the server made by `bind` (e.g. on a path
/// manager over a simulated network).
pub fn env_bind(limits: Limits, mut session: ssh3_core::ServerSessionEnv, bind: impl FnOnce(ServerOptions) -> Server) -> Env {
    init();
    let dir = PathBuf::from(std::env::var("HOME").unwrap())
        .join("scratch/ssh-udp/core-tests")
        .join(format!("{}-{}", std::process::id(), DIRS.fetch_add(1, AtOrd::Relaxed)));
    std::fs::create_dir_all(dir.join("home")).unwrap();
    isolate_user(&mut session, dir.join("home"));
    let host = HostIdentity::from_private_key(&ed25519(200)).unwrap();
    let key = user_key(7);
    let authorized_keys = dir.join("authorized_keys");
    std::fs::write(&authorized_keys, format!("{}\n", key.public_key().to_openssh().unwrap())).unwrap();
    let ak = authorized_keys.clone();
    let server = bind(
        ServerOptions {
            tls: ssh3_core::transport::server_tls(&host).unwrap(),
            // Every account uses the same file: one key may serve several
            // users, which the user-binding test relies on.
            authenticator: Arc::new(AuthorizedKeysAuthenticator::new(move |_user| Some(ak.clone()))),
            limits: limits.clone(),
            keys: EndpointKeys::random(),
            session: Some(session),
            rendezvous: true,
        },
    );
    let known_hosts = dir.join("known_hosts");
    ssh3_keys::known_hosts::append(&known_hosts, "127.0.0.1", server.local_addr().port(), host.public_key(), false).unwrap();
    Env { dir, host, key, authorized_keys, known_hosts, server, limits }
}

impl Env {
    /// The server as clients address it: 127.0.0.1 (v4-mapped on the
    /// clients' dual-stack sockets), so a resume can come from 127.0.0.2.
    pub fn server_addr(&self) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse().unwrap(), self.server.local_addr().port())
    }
    pub fn host_check(&self) -> HostCheck {
        HostCheck {
            name: "127.0.0.1".into(),
            port: self.server.local_addr().port(),
            files: vec![self.known_hosts.clone()],
            mode: StrictHostKeyChecking::Yes,
            hash_known_hosts: false,
            prompt: None,
        }
    }
    /// Replace authorized_keys with `key` under `options` (OpenSSH syntax).
    pub fn authorize_only(&self, key: &TestKey, options: &str) {
        let sep = if options.is_empty() { "" } else { " " };
        std::fs::write(&self.authorized_keys, format!("{options}{sep}{}\n", key.public_key().to_openssh().unwrap())).unwrap();
    }
    /// Add `key` to authorized_keys.
    pub fn authorize_also(&self, key: &TestKey) {
        let mut t = std::fs::read_to_string(&self.authorized_keys).unwrap();
        t.push_str(&format!("{}\n", key.public_key().to_openssh().unwrap()));
        std::fs::write(&self.authorized_keys, t).unwrap();
    }
    pub fn opts(&self, key: &Arc<TestKey>) -> ClientOptions {
        ClientOptions {
            server_addr: self.server_addr(),
            host: self.host_check(),
            signers: vec![key.clone() as Arc<dyn ssh3_core::auth::Signer>],
            user: "tester".into(),
            limits: self.limits.clone(),
            sockets: ssh3_core::client::dual_stack_factory(),
            path: None,
        }
    }
    pub async fn client(&self) -> ClientSession {
        ClientSession::connect(self.opts(&self.key), udp_socket(dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap())
            .await
            .unwrap()
    }
}

/// A client whose socket can be blackholed (simulated outage).
pub async fn client_bh(env: &Env) -> (ClientSession, Arc<blackhole::Blackhole>) {
    let bh = blackhole::Blackhole::new(dual_stack_socket("[::]:0".parse().unwrap()).unwrap());
    let c = ClientSession::connect(env.opts(&env.key), bh.clone()).await.unwrap();
    (c, bh)
}

/// A fresh socket on another local address (127.0.0.2).
pub fn other_socket() -> Arc<dyn quinn::AsyncUdpSocket> {
    udp_socket(dual_stack_socket("[::ffff:127.0.0.2]:0".parse().unwrap()).unwrap()).unwrap()
}

/// Raw QUIC connection to the server (for protocol-level tests), verified
/// against the env's known_hosts.
pub async fn raw_conn(env: &Env) -> quinn::Connection {
    let sock = dual_stack_socket("[::]:0".parse().unwrap()).unwrap();
    let mut ep = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, sock, Arc::new(quinn::TokioRuntime)).unwrap();
    let v = Arc::new(ssh3_keys::verifier::KnownHostsVerifier::new("127.0.0.1", env.server.local_addr().port(), vec![env.known_hosts.clone()], StrictHostKeyChecking::Yes));
    ep.set_default_client_config(ssh3_core::transport::client_config(ssh3_core::transport::client_tls(v).unwrap(), &env.limits).unwrap());
    ep.connect(ssh3_core::transport::to_v6(env.server_addr()), "ssh3-test").unwrap().await.unwrap()
}

/// Authenticate a raw connection as "tester" with `key` and `intent`.
pub async fn raw_auth(conn: &quinn::Connection, key: &Arc<TestKey>, intent: ssh3_core::msg::Intent) -> (quinn::SendStream, quinn::RecvStream, ssh3_core::msg::Message) {
    raw_auth_as(conn, key, "tester", intent).await
}

pub async fn raw_auth_as(conn: &quinn::Connection, key: &Arc<TestKey>, user: &str, intent: ssh3_core::msg::Intent) -> (quinn::SendStream, quinn::RecvStream, ssh3_core::msg::Message) {
    use ssh3_core::{auth, frame, msg::Message};
    let (mut s, mut r) = conn.open_bi().await.unwrap();
    let mut exp = [0u8; 32];
    conn.export_keying_material(&mut exp, auth::EXPORTER_LABEL, b"").unwrap();
    let pubkey = auth::pubkey_blob(key.public_key()).unwrap();
    let sig = auth::sign_auth(&**key, &exp, user, auth::keys_intent(intent)).unwrap();
    frame::write_message(&mut s, &Message::Auth { user: user.into(), pubkey, sig, intent }).await.unwrap();
    let m = frame::read_message(&mut r, 65536).await.unwrap().unwrap();
    (s, r, m)
}

/// Poll `f` until true; panics with `dump()` after `limit` so a stuck test
/// reports its state instead of hanging.
pub async fn wait_until(what: &str, limit: Duration, mut f: impl FnMut() -> bool, dump: impl Fn() -> String) {
    let t = Instant::now();
    while !f() {
        if t.elapsed() > limit {
            panic!("waited {limit:?} for {what}; state: {}", dump());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ------------------------------------------------------------------ TCP

pub async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    a
}

/// Accepts and never reads; returns the accepted sockets so the test can
/// start reading later.
/// `small_rcvbuf`: shrink the accepted socket's receive buffer so a stall
/// reaches the lane quickly (but the socket then drains slowly: with delayed
/// ACKs a 4 KiB window gives ~40 KB/s on loopback, measured).
pub async fn stalled_server(small_rcvbuf: bool) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<TcpStream>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            if small_rcvbuf {
                let _ = socket2::SockRef::from(&s).set_recv_buffer_size(4096);
            }
            if tx.send(s).is_err() {
                return;
            }
        }
    });
    (a, rx)
}

/// Reads and discards everything.
pub async fn discard_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut sink = tokio::io::sink();
                let _ = tokio::io::copy(&mut s, &mut sink).await;
            });
        }
    });
    a
}

/// Reads until EOF, then answers with the byte count and SHA-256, closes.
pub async fn count_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut h = Sha256::new();
                let mut n = 0u64;
                let mut buf = vec![0u8; 65536];
                loop {
                    let k = s.read(&mut buf).await.unwrap();
                    if k == 0 {
                        break;
                    }
                    n += k as u64;
                    h.update(&buf[..k]);
                }
                let reply = format!("{n} {:x}", h.finalize());
                s.write_all(reply.as_bytes()).await.unwrap();
                s.shutdown().await.unwrap();
            });
        }
    });
    a
}

/// A local `-L` listener through `c` to `target`.
pub async fn forward(c: &ClientSession, target: SocketAddr) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    c.forward_local(l, target.ip().to_string(), target.port());
    a
}

/// Test payload: every 8-byte word is a hash of its own index and `seed`,
/// so any lost, duplicated or misplaced word shows. Generated per word
/// (a per-byte generator dominated debug-build test time).
pub fn pattern(n: usize, seed: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(n + 8);
    for i in 0..n.div_ceil(8) as u64 {
        v.extend_from_slice(&((i ^ seed.rotate_left(32)).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ seed).to_le_bytes());
    }
    v.truncate(n);
    v
}

/// Byte-exact comparison that reports where the streams diverge (memcmp
/// speed; hashing every byte in a debug build was a large part of test time).
#[track_caller]
pub fn assert_same(got: &[u8], want: &[u8]) {
    if got != want {
        let at = got.iter().zip(want).position(|(a, b)| a != b).unwrap_or(got.len().min(want.len()));
        panic!("streams differ: got {} bytes, want {}; first difference at offset {at}", got.len(), want.len());
    }
}

pub fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

/// Send `data` through `addr` and read the echo; returns the echoed bytes.
pub async fn echo_roundtrip(addr: SocketAddr, data: Arc<Vec<u8>>) -> Vec<u8> {
    let s = TcpStream::connect(addr).await.unwrap();
    let (mut r, mut w) = s.into_split();
    let d = data.clone();
    let wt = tokio::spawn(async move {
        w.write_all(&d).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut out = Vec::with_capacity(data.len());
    r.read_to_end(&mut out).await.unwrap();
    wt.await.unwrap();
    out
}
