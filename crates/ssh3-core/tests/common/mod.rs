//! Shared test harness: pinned TLS, ed25519 test keys, servers, TCP helpers.
#![allow(dead_code)]

pub mod blackhole;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier, VerifyingKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use ssh3_core::auth::{Authenticator, Authz, Signer};
use ssh3_core::transport::{EndpointKeys, dual_stack_socket};
use ssh3_core::{ClientOptions, ClientSession, Limits, Server, ServerOptions, udp_socket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

// ------------------------------------------------------------------ TLS

pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivatePkcs8KeyDer<'static>,
}

pub fn identity() -> Identity {
    let ck = rcgen::generate_simple_self_signed(vec!["ssh3-test".into()]).unwrap();
    Identity { cert: ck.cert.der().clone(), key: PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()) }
}

/// Accepts exactly one certificate (stand-in for the known_hosts verifier).
#[derive(Debug)]
struct Pinned(CertificateDer<'static>);

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, ee: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        if ee.as_ref() == self.0.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate is not the pinned one".into()))
        }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

pub fn server_tls(id: &Identity) -> rustls::ServerConfig {
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![id.cert.clone()], PrivateKeyDer::Pkcs8(id.key.clone_key()))
        .unwrap()
}

pub fn client_tls(id: &Identity) -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned(id.cert.clone())))
        .with_no_client_auth()
}

// ----------------------------------------------------------------- keys

/// Test key: public blob = "ed25519-test" || 32 raw bytes.
pub struct TestKey(pub SigningKey);

impl TestKey {
    pub fn new(seed: u8) -> Arc<Self> {
        Arc::new(Self(SigningKey::from_bytes(&[seed; 32])))
    }
}

pub fn blob_of(vk: &VerifyingKey) -> Vec<u8> {
    let mut b = b"ed25519-test".to_vec();
    b.extend_from_slice(vk.as_bytes());
    b
}

impl Signer for TestKey {
    fn public_key_blob(&self) -> Vec<u8> {
        blob_of(&self.0.verifying_key())
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.0.sign(data).to_bytes().to_vec())
    }
}

#[derive(Default)]
pub struct TestAuth {
    pub allowed: Mutex<HashSet<Vec<u8>>>,
    pub authz: Mutex<Option<Authz>>,
}

impl TestAuth {
    pub fn allowing(keys: &[&Arc<TestKey>]) -> Arc<Self> {
        let a = Self::default();
        for k in keys {
            a.allowed.lock().unwrap().insert(k.public_key_blob());
        }
        Arc::new(a)
    }
}

impl Authenticator for TestAuth {
    fn verify(&self, _user: &str, pubkey: &[u8], blob: &[u8], sig: &[u8]) -> Result<Authz, String> {
        if !self.allowed.lock().unwrap().contains(pubkey) {
            return Err("key not authorized".into());
        }
        let raw: [u8; 32] = pubkey[12..].try_into().map_err(|_| "bad key length")?;
        let vk = VerifyingKey::from_bytes(&raw).map_err(|e| e.to_string())?;
        let sig = Signature::from_slice(sig).map_err(|e| e.to_string())?;
        vk.verify(blob, &sig).map_err(|e| format!("bad signature: {e}"))?;
        Ok(self.authz.lock().unwrap().clone().unwrap_or_else(Authz::unrestricted))
    }
}

// --------------------------------------------------------------- setups

pub fn fast_limits() -> Limits {
    Limits {
        idle_timeout: Duration::from_millis(600),
        keep_alive: Duration::from_millis(100),
        ack_interval: Duration::from_millis(50),
        login_grace: Duration::from_secs(5),
        linger: Duration::from_secs(30),
        ..Limits::default()
    }
}

pub struct Env {
    pub id: Identity,
    pub key: Arc<TestKey>,
    pub auth: Arc<TestAuth>,
    pub server: Server,
    pub limits: Limits,
}

pub fn env_with(limits: Limits) -> Env {
    init();
    let id = identity();
    let key = TestKey::new(7);
    let auth = TestAuth::allowing(&[&key]);
    let server = Server::bind(
        ServerOptions { tls: server_tls(&id), authenticator: auth.clone(), limits: limits.clone(), keys: EndpointKeys::random() },
        dual_stack_socket("[::]:0".parse().unwrap()).unwrap(),
    )
    .unwrap();
    Env { id, key, auth, server, limits }
}

impl Env {
    /// The server as clients address it: 127.0.0.1 (v4-mapped on the
    /// clients' dual-stack sockets), so a resume can come from 127.0.0.2.
    pub fn server_addr(&self) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse().unwrap(), self.server.local_addr().port())
    }
    pub fn opts(&self, key: &Arc<TestKey>) -> ClientOptions {
        ClientOptions {
            server_addr: self.server_addr(),
            server_name: "ssh3-test".into(),
            tls: client_tls(&self.id),
            signer: key.clone(),
            user: "tester".into(),
            limits: self.limits.clone(),
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

/// Raw QUIC connection to the server (for protocol-level tests).
pub async fn raw_conn(env: &Env) -> quinn::Connection {
    let sock = dual_stack_socket("[::]:0".parse().unwrap()).unwrap();
    let mut ep = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, sock, Arc::new(quinn::TokioRuntime)).unwrap();
    ep.set_default_client_config(ssh3_core::transport::client_config(client_tls(&env.id), &env.limits).unwrap());
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
    let pubkey = Signer::public_key_blob(&**key);
    let blob = auth::auth_blob(&exp, user, &pubkey, intent);
    let sig = Signer::sign(&**key, &blob).unwrap();
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

pub fn pattern(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
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
