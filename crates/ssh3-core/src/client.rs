//! Client: connect, authenticate, resume (SPEC §2.2, §5).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::{AsyncUdpSocket, Connection, Endpoint, RecvStream, SendStream, TokioRuntime};
use tokio::net::TcpListener;

use ssh3_keys::verifier::{KnownHostsVerifier, Prompt, StrictHostKeyChecking};

use crate::auth::{Authz, EXPORTER_LABEL, EXPORTER_LEN, PublicKey, Signer, keys_intent, pubkey_blob, sign_auth};
use crate::error::{Error, Result, close};
use crate::frame::{self, MAX_FRAME};
use crate::limits::Limits;
use crate::msg::{Intent, Message, SessionId};
use crate::session::{Budgets, Role, SessionShared};
use crate::transport::{self, EndpointKeys};

/// How the server's host key is checked (SPEC §2.1): a fresh
/// `KnownHostsVerifier` is built from this for every dial — first connect
/// and every resume — so no pending state is ever reused.
#[derive(Clone)]
pub struct HostCheck {
    /// known_hosts lookup name: HostKeyAlias, else HostName.
    pub name: String,
    pub port: u16,
    /// UserKnownHostsFile entries, then global files; new keys go to the first.
    pub files: Vec<PathBuf>,
    pub mode: StrictHostKeyChecking,
    pub hash_known_hosts: bool,
    pub prompt: Option<Arc<Prompt>>,
}

impl HostCheck {
    fn verifier(&self) -> Arc<KnownHostsVerifier> {
        let mut v = KnownHostsVerifier::new(&self.name, self.port, self.files.clone(), self.mode).hash_known_hosts(self.hash_known_hosts);
        if let Some(p) = &self.prompt {
            v = v.with_prompt(p.clone());
        }
        Arc::new(v)
    }
}

/// Re-resolves the server's name: called before every automatic resume
/// attempt, so a server reached by name is found again after its address
/// changed (dynamic DNS, a restarted container). A failure is transient — the
/// attempt is retried with the resume backoff — because during a network
/// change name resolution fails as often as connecting does.
pub type Resolver = Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> + Send + Sync>;

/// Makes a fresh UDP socket for a rebind or a resume.
pub type SocketFactory = Arc<dyn Fn() -> std::io::Result<Arc<dyn AsyncUdpSocket>> + Send + Sync>;

/// Dual-stack `[::]:0` sockets (SPEC §5.1).
pub fn dual_stack_factory() -> SocketFactory {
    Arc::new(|| udp_socket(transport::dual_stack_socket(transport::unspecified_dual()).map_err(std::io::Error::other)?).map_err(std::io::Error::other))
}

/// Delegates to the known_hosts verifier and remembers why it rejected the
/// server's key: a rejection inside the handshake otherwise surfaces only as
/// a generic connection error, and the caller must be able to say "Host key
/// verification failed" (board request R1).
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<KnownHostsVerifier>,
    rejected: Mutex<Option<String>>,
}

impl rustls::client::danger::ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let r = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp, now);
        if let Err(e) = &r {
            *self.rejected.lock().unwrap() = Some(match e {
                rustls::Error::General(m) => m.clone(),
                other => other.to_string(),
            });
        }
        r
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Clone)]
pub struct ClientOptions {
    /// Every address the server's name resolved to (or one literal / jump
    /// path virtual address). A dial races them RFC 8305 style
    /// (`connect_attempt_delay` apart, families interleaved, IPv6 first):
    /// the first completed handshake wins, the others are closed before any
    /// authentication.
    pub server_addrs: Vec<SocketAddr>,
    /// Where automatic resumes find the server again; None = always
    /// `server_addrs` (literal addresses, or a jump path's virtual address,
    /// which never changes).
    pub resolve: Option<Resolver>,
    pub host: HostCheck,
    /// Keys offered in order on one connection until one is accepted or the
    /// server stops (MaxAuthTries), as OpenSSH (board R4).
    pub signers: Vec<Arc<dyn Signer>>,
    pub user: String,
    pub limits: Limits,
    /// Sockets for rebinds and automatic resumes (unused with `path`).
    pub sockets: SocketFactory,
    /// Run on this path manager's one endpoint instead of an own one (SPEC
    /// §7): every connection of the node shares its UDP socket — the NAT
    /// mapping the gateway observes is the one punches reuse — and rebinds
    /// go through the manager (the single route owner).
    pub path: Option<Arc<ssh3_path::PathManager>>,
}

/// Roaming counters (SPEC §8 I6).
#[derive(Default, Debug)]
pub struct RoamStats {
    pub probes_lost: AtomicU64,
    pub rebinds: AtomicU64,
    pub resume_attempts: AtomicU64,
    pub resumes: AtomicU64,
    /// Resume attempts whose name resolution failed (retried, not fatal).
    pub resolve_failures: AtomicU64,
    /// Set when automatic resume gave up (session refused or linger over).
    pub gave_up: AtomicBool,
}

struct ClientInner {
    shared: Arc<SessionShared>,
    opts: ClientOptions,
    endpoint: Mutex<Option<Endpoint>>,
    /// The server address the current (or last) carrier went to.
    addr: Mutex<SocketAddr>,
    /// The verified host key of the first connect: the session's target
    /// identity. A resume must present the same key.
    host_key: PublicKey,
    /// The key that created the session: resumes authenticate with it only
    /// (the session belongs to that exact key, SPEC §5).
    auth_signer: Arc<dyn Signer>,
    /// The server's SessionLinger: automatic resume stops after it.
    linger: Duration,
    roam: RoamStats,
    /// true once automatic resume gave up.
    gave_up: tokio::sync::watch::Sender<bool>,
    /// Direct-path machinery to restart after every resume (inner session
    /// through a jump to a registered peer).
    direct: Mutex<Option<crate::jump::DirectParams>>,
}

pub struct ClientSession {
    pub shared: Arc<SessionShared>,
    inner: Arc<ClientInner>,
    roamer: tokio::task::JoinHandle<()>,
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        self.roamer.abort();
        self.shared.teardown();
    }
}

/// Wrap a std socket for quinn. Use `transport::dual_stack_socket` to make it
/// (SPEC §5.1).
pub fn udp_socket(s: std::net::UdpSocket) -> Result<Arc<dyn AsyncUdpSocket>> {
    use quinn::Runtime;
    Ok(TokioRuntime.wrap_udp_socket(s)?)
}

/// The server's close reason if the connection is closed, else `e`.
fn explain(conn: &Connection, e: Error) -> Error {
    match conn.close_reason() {
        Some(r) => Error::Connection(r),
        None => e,
    }
}

struct Dialed {
    ep: Endpoint,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    info: Option<crate::msg::SessionInfo>,
    host_key: PublicKey,
    /// The key the server accepted.
    signer: Arc<dyn Signer>,
}

/// One QUIC handshake to `addr`, host key verified (not yet committed).
struct Handshaken {
    ep: Endpoint,
    conn: Connection,
    verifier: Arc<KnownHostsVerifier>,
}

async fn handshake(opts: &ClientOptions, addr: SocketAddr, socket: Option<Arc<dyn AsyncUdpSocket>>) -> Result<Handshaken> {
    // A fresh verifier per attempt: no pending state is shared between racers.
    let verifier = opts.host.verifier();
    let recording = Arc::new(RecordingVerifier { inner: verifier.clone(), rejected: Mutex::new(None) });
    let cc = transport::client_config(transport::client_tls(recording.clone())?, &opts.limits)?;
    let ep = match &opts.path {
        Some(mgr) => mgr.endpoint_or_init(|sock| Endpoint::new_with_abstract_socket(transport::endpoint_config(&EndpointKeys::random()), None, sock, Arc::new(TokioRuntime)))?,
        None => {
            let socket = match socket {
                Some(s) => s,
                None => (opts.sockets)()?,
            };
            Endpoint::new_with_abstract_socket(transport::endpoint_config(&EndpointKeys::random()), None, socket, Arc::new(TokioRuntime))?
        }
    };
    match ep.connect_with(cc, transport::to_v6(addr), "ssh3-rs")?.await {
        Ok(conn) => Ok(Handshaken { ep, conn, verifier }),
        // A handshake that failed because known_hosts refused the key is a
        // host-key failure, not a network one.
        Err(e) => match recording.rejected.lock().unwrap().take() {
            Some(why) => Err(Error::HostKey(why)),
            None => Err(e.into()),
        },
    }
}

/// RFC 8305 §4 order: duplicates removed, address families interleaved,
/// IPv6 first (an IPv4-mapped address counts as IPv4).
pub fn attempt_order(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut seen = Vec::new();
    for a in addrs {
        if !seen.contains(a) {
            seen.push(*a);
        }
    }
    let is_v6 = |a: &SocketAddr| matches!(a, SocketAddr::V6(v) if v.ip().to_ipv4_mapped().is_none());
    let (v6, v4): (Vec<SocketAddr>, Vec<SocketAddr>) = seen.into_iter().partition(is_v6);
    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let (mut a, mut b) = (v6.into_iter(), v4.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => return out,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
}

/// Race handshakes to `addrs` (RFC 8305 "Happy Eyeballs" connection
/// attempts): the next address is tried `connect_attempt_delay` after the
/// previous one started, or at once when it failed; the first completed
/// handshake wins and every other attempt is aborted (closed before any
/// authentication, so the server never sees a second session). Each
/// attempt's outcome is logged; the error names every address tried.
async fn race_handshake(opts: &ClientOptions, addrs: &[SocketAddr], socket: Arc<dyn AsyncUdpSocket>) -> Result<(Handshaken, SocketAddr)> {
    let order = attempt_order(addrs);
    if order.is_empty() {
        return Err(Error::Io(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no address to connect to")));
    }
    let mut set: tokio::task::JoinSet<(SocketAddr, Result<Handshaken>)> = tokio::task::JoinSet::new();
    let mut first = Some(socket);
    let mut next = 0usize;
    let mut tried: Vec<String> = Vec::new();
    let delay = opts.limits.connect_attempt_delay;
    let start = |set: &mut tokio::task::JoinSet<_>, i: usize, first: &mut Option<Arc<dyn AsyncUdpSocket>>| {
        let (addr, opts, sock) = (order[i], opts.clone(), first.take());
        tracing::debug!("connecting to {addr}");
        set.spawn(async move { (addr, handshake(&opts, addr, sock).await) });
    };
    start(&mut set, 0, &mut first);
    next += 1;
    let tick = tokio::time::sleep(delay);
    tokio::pin!(tick);
    loop {
        tokio::select! {
            Some(j) = set.join_next() => {
                let (addr, r) = j.map_err(|e| Error::Io(std::io::Error::other(format!("connection attempt task: {e}"))))?;
                match r {
                    Ok(h) => {
                        set.abort_all();
                        if !tried.is_empty() {
                            tracing::info!("connected to {addr} after: {}", tried.join("; "));
                        }
                        return Ok((h, addr));
                    }
                    // A host-key verdict is about the server, not the path:
                    // trying other addresses of the same name cannot fix it.
                    Err(Error::HostKey(why)) => {
                        set.abort_all();
                        return Err(Error::HostKey(why));
                    }
                    Err(e) => {
                        tracing::info!("tried {addr}: {e}");
                        tried.push(format!("tried {addr}: {e}"));
                        if next < order.len() {
                            start(&mut set, next, &mut first);
                            next += 1;
                            tick.as_mut().reset(tokio::time::Instant::now() + delay);
                        } else if set.is_empty() {
                            return Err(Error::Unreachable(tried.join("; ")));
                        }
                    }
                }
            }
            _ = &mut tick, if next < order.len() => {
                start(&mut set, next, &mut first);
                next += 1;
                tick.as_mut().reset(tokio::time::Instant::now() + delay);
            }
        }
    }
}

async fn connect_and_auth(opts: &ClientOptions, addrs: &[SocketAddr], signers: &[Arc<dyn Signer>], socket: Arc<dyn AsyncUdpSocket>, intent: Intent) -> Result<(Dialed, SocketAddr)> {
    if signers.is_empty() {
        return Err(Error::Auth("no identities to offer".into()));
    }
    let (Handshaken { ep, conn, verifier }, addr) = race_handshake(opts, addrs, socket).await?;
    // The handshake is confirmed (proof of possession done): only now may
    // the host key be committed — and before we sign anything for this host.
    let host_key = match verifier.commit() {
        Ok(k) => k.key().clone(),
        Err(e) => {
            conn.close(close::SHUTDOWN.into(), b"host key not accepted");
            return Err(Error::HostKey(e));
        }
    };
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|_| Error::Tls("TLS exporter unavailable".into()))?;
    let mut refusals = Vec::new();
    for signer in signers {
        let pubkey = pubkey_blob(signer.public_key()).map_err(|e| Error::Auth(e.to_string()))?;
        // Agent signing is blocking socket I/O.
        let (s, user) = (signer.clone(), opts.user.clone());
        let sig = match tokio::task::spawn_blocking(move || sign_auth(&*s, &exporter, &user, keys_intent(intent))).await {
            Ok(Ok(sig)) => sig,
            Ok(Err(e)) => {
                // This key cannot sign (agent refused, ...): try the next.
                refusals.push(format!("{}: {e}", signer.public_key().fingerprint(ssh_key::HashAlg::Sha256)));
                continue;
            }
            Err(e) => return Err(Error::Auth(format!("signing task failed: {e}"))),
        };
        // A failed write (like a failed read below) means the server stopped
        // taking attempts after its last AuthFail (MaxAuthTries).
        if frame::write_message(&mut send, &Message::Auth { user: opts.user.clone(), pubkey, sig, intent }).await.is_err() {
            break;
        }
        match frame::read_message(&mut recv, MAX_FRAME).await {
            Ok(Some(Message::AuthOk { session: info })) => return Ok((Dialed { ep, conn, send, recv, info, host_key, signer: signer.clone() }, addr)),
            Ok(Some(Message::AuthFail { reason })) => refusals.push(format!("{}: {reason}", signer.public_key().fingerprint(ssh_key::HashAlg::Sha256))),
            Ok(Some(m)) => return Err(Error::Protocol(format!("expected AuthOk/AuthFail, got {m:?}"))),
            // The server stopped taking attempts (MaxAuthTries).
            Ok(None) | Err(_) => break,
        }
    }
    conn.close(close::SHUTDOWN.into(), b"authentication refused");
    Err(Error::Auth(if refusals.is_empty() { "authentication refused".into() } else { refusals.join("; ") }))
}

impl ClientSession {
    pub async fn connect(opts: ClientOptions, socket: Arc<dyn AsyncUdpSocket>) -> Result<Self> {
        opts.limits.validate().map_err(Error::Config)?;
        let (Dialed { ep, conn, send, recv, info, host_key, signer }, addr) = connect_and_auth(&opts, &opts.server_addrs, &opts.signers, socket, Intent::New).await?;
        let info = info.ok_or_else(|| Error::Protocol("AuthOk for a new session carries no session info".into()))?;
        let shared = SessionShared::new(
            info.session_id,
            Role::Client,
            opts.user.clone(),
            pubkey_blob(signer.public_key()).map_err(|e| Error::Auth(e.to_string()))?,
            Authz::unrestricted(),
            opts.limits.clone(),
            Budgets::new(&opts.limits),
            None,
            None,
        );
        {
            let _g = shared.attach_lock.lock().await;
            shared.install_carrier(conn, send, recv, |_| None);
            shared.reopen_lanes().await?;
        }
        let inner = Arc::new(ClientInner {
            shared: shared.clone(),
            addr: Mutex::new(addr),
            opts,
            endpoint: Mutex::new(Some(ep)),
            host_key,
            auth_signer: signer,
            linger: Duration::from_secs(info.linger_secs),
            roam: RoamStats::default(),
            gave_up: tokio::sync::watch::channel(false).0,
            direct: Mutex::new(None),
        });
        let roamer = tokio::spawn(roam(Arc::downgrade(&inner)));
        Ok(Self { shared, inner, roamer })
    }

    pub(crate) fn set_direct(&self, d: crate::jump::DirectParams) {
        *self.inner.direct.lock().unwrap() = Some(d);
    }

    /// The path manager this session's endpoint runs on, if any.
    pub fn path(&self) -> Option<Arc<ssh3_path::PathManager>> {
        self.inner.opts.path.clone()
    }

    pub fn session_id(&self) -> SessionId {
        self.shared.id
    }

    pub async fn carrier_lost(&self) {
        self.shared.carrier_lost().await
    }

    pub fn roam_stats(&self) -> &RoamStats {
        &self.inner.roam
    }

    /// When the server was last heard (acks, probe replies): drives a
    /// "Last contact N s ago" indicator (board request R3).
    pub fn last_contact(&self) -> Instant {
        self.shared.last_contact()
    }

    /// Register this session at the gateway as the peer `label` (SPEC
    /// §7.1), in addition to any name it already holds. Refused if another
    /// (user, key) holds the name, if the label is invalid, or past the
    /// gateway's per-session cap (`max_listeners`). The name lives as long
    /// as this session.
    pub async fn register_name(&self, label: &str) -> Result<()> {
        self.shared.register(label.to_string()).await
    }

    /// End the session on purpose (SPEC §5 "Deliberate end"): no linger on
    /// the server. Sends SessionEnd on the event log, waits at most `bound`
    /// for the server to confirm by closing with SESSION_END, then closes
    /// with SESSION_END itself — which ends the session even if the event
    /// was lost. Returns true if the server confirmed within `bound`.
    pub async fn end(&self, bound: Duration) -> bool {
        self.roamer.abort();
        let confirmed = match self.shared.current_conn() {
            Some((conn, _)) => {
                let _ = self.shared.send_event(crate::msg::Message::SessionEnd).await;
                let ok = matches!(
                    tokio::time::timeout(bound, conn.closed()).await,
                    Ok(quinn::ConnectionError::ApplicationClosed(c)) if c.error_code.into_inner() == close::SESSION_END as u64
                );
                conn.close(close::SESSION_END.into(), b"session ended");
                ok
            }
            None => false,
        };
        self.shared.teardown();
        confirmed
    }

    /// Resolves once automatic resume has given up (the session is gone).
    pub async fn gave_up(&self) {
        let mut rx = self.inner.gave_up.subscribe();
        let _ = rx.wait_for(|g| *g).await;
    }

    /// Reattach the session over a new connection from `socket` (any local
    /// address or family). SPEC §5 "Resume".
    pub async fn resume(&self, socket: Arc<dyn AsyncUdpSocket>) -> Result<u64> {
        let addrs = self.inner.with_current_first(self.inner.opts.server_addrs.clone());
        self.inner.resume(socket, &addrs).await
    }

    /// The server address the current (or last) carrier went to.
    pub fn server_addr(&self) -> SocketAddr {
        *self.inner.addr.lock().unwrap()
    }

    /// The server's verified host key (the session's target identity).
    pub fn host_key(&self) -> &PublicKey {
        &self.inner.host_key
    }

    pub fn budgets(&self) -> &Budgets {
        &self.shared.budgets
    }

    /// Open a session channel (shell / exec / subsystem, optional pty).
    pub async fn open_session(&self, spec: crate::sesschan::SessionSpec) -> Result<crate::sesschan::SessionChannel> {
        self.shared.open_session(spec).await
    }

    /// `-W host:port`: a direct-tcp channel whose local ends are a reader
    /// and a writer (stdin/stdout). Resolves once the channel is open; the
    /// writer is shut down and dropped when the server's side ends.
    pub async fn open_direct_stream<W>(&self, r: Box<dyn tokio::io::AsyncRead + Send + Unpin>, w: W, host: &str, port: u16) -> Result<u64>
    where
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        self.shared.open_direct_stream(r, w, host.to_string(), port).await
    }

    pub async fn open_direct_tcp(&self, tcp: tokio::net::TcpStream, host: &str, port: u16) -> Result<u64> {
        self.shared.open_direct_tcp(tcp, host.to_string(), port).await
    }

    /// `-R`: the server listens on `bind_host:bind_port` (0 = any) and each
    /// connection is forwarded to `target_host:target_port` from here.
    /// Returns the port the server bound.
    pub async fn forward_remote(&self, bind_host: &str, bind_port: u16, target_host: &str, target_port: u16) -> Result<u16> {
        self.shared.forward_remote(bind_host.to_string(), bind_port, (target_host.to_string(), target_port)).await
    }

    /// `-R` UDP: the server listens on UDP `bind_host:bind_port`; each source
    /// becomes a flow forwarded to `target_host:target_port` from here.
    pub async fn forward_remote_udp(&self, bind_host: &str, bind_port: u16, target_host: &str, target_port: u16) -> Result<u16> {
        self.shared.forward_remote_udp(bind_host.to_string(), bind_port, (target_host.to_string(), target_port)).await
    }

    /// `-L` UDP: each source address sending to `sock` becomes a flow the
    /// server forwards to `host:port` (bounded flow table, SPEC §6).
    pub fn forward_local_udp(&self, sock: tokio::net::UdpSocket, host: String, port: u16) -> tokio::task::JoinHandle<()> {
        self.shared.run_udp_listener(sock, move |_| crate::msg::ChannelKind::DirectUdp { host: host.clone(), port })
    }

    /// `-D`: SOCKS5 (CONNECT and UDP ASSOCIATE) on `listener`.
    pub fn forward_dynamic(&self, listener: TcpListener) -> tokio::task::JoinHandle<()> {
        self.shared.forward_dynamic(listener)
    }

    /// `-L`: accept on `listener`, open a direct-tcp channel per connection.
    pub fn forward_local(&self, listener: TcpListener, host: String, port: u16) -> tokio::task::JoinHandle<()> {
        let shared = Arc::downgrade(&self.shared);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = listener.accept().await else { return };
                let Some(s) = shared.upgrade() else { return };
                let host = host.clone();
                tokio::spawn(async move {
                    if let Err(e) = s.open_direct_tcp(tcp, host.clone(), port).await {
                        tracing::warn!(%peer, "forward to {host}:{port} failed: {e}");
                    }
                });
            }
        })
    }
}

impl ClientInner {
    async fn resume(&self, socket: Arc<dyn AsyncUdpSocket>, addrs: &[SocketAddr]) -> Result<u64> {
        let _g = self.shared.attach_lock.lock().await;
        self.shared.detach(close::SUPERSEDED, b"client resuming");
        let ours = self.shared.snapshot_lanes();
        let (Dialed { ep, conn, mut send, mut recv, host_key, .. }, addr) = connect_and_auth(&self.opts, addrs, std::slice::from_ref(&self.auth_signer), socket, Intent::Resume).await?;
        if !ssh3_keys::spki::same_key(&host_key, &self.host_key) {
            conn.close(close::SHUTDOWN.into(), b"host key changed");
            return Err(Error::HostKey(format!(
                "resume reached a server with key {} but the session belongs to {}",
                host_key.fingerprint(ssh_key::HashAlg::Sha256),
                self.host_key.fingerprint(ssh_key::HashAlg::Sha256)
            )));
        }
        frame::write_message(&mut send, &Message::Resume { session_id: self.shared.id, lanes: ours }).await?;
        let (theirs, epoch) = match frame::read_message(&mut recv, MAX_FRAME).await.map_err(|e| explain(&conn, e))? {
            Some(Message::Resumed { lanes, epoch }) => (lanes, epoch),
            Some(Message::Fail { reason }) => {
                conn.close(close::SHUTDOWN.into(), b"resume refused");
                return Err(Error::Refused(reason));
            }
            Some(m) => return Err(Error::Protocol(format!("expected Resumed, got {m:?}"))),
            None => return Err(Error::Protocol("server closed the control stream during resume".into())),
        };
        self.shared.reconcile(&theirs)?;
        self.shared.install_carrier(conn, send, recv, |_| None);
        let old = self.endpoint.lock().unwrap().replace(ep);
        drop(old);
        self.shared.reopen_lanes().await?;
        // The direct-path machinery was bound to the old connection.
        if let Some(d) = self.direct.lock().unwrap().as_ref()
            && let Err(e) = d.start(&self.shared)
        {
            tracing::info!("direct path not restarted after resume: {e}");
        }
        *self.addr.lock().unwrap() = addr;
        self.roam.resumes.fetch_add(1, Ordering::Relaxed);
        Ok(epoch)
    }

    /// `addrs` with the current carrier's address moved to the front (it
    /// worked last; RFC 8305 still races the rest behind it).
    fn with_current_first(&self, mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let current = *self.addr.lock().unwrap();
        if let Some(i) = addrs.iter().position(|a| *a == current) {
            addrs.remove(i);
            addrs.insert(0, current);
        }
        addrs
    }

    /// Where the next resume attempt goes: what the name resolves to now, or
    /// `server_addrs` when there is no resolver; the current address first
    /// if it is still among them. A resolution failure is an attempt failure.
    async fn resume_targets(&self) -> Result<Vec<SocketAddr>> {
        let Some(resolve) = &self.opts.resolve else { return Ok(self.with_current_first(self.opts.server_addrs.clone())) };
        match resolve().await {
            Ok(addrs) if addrs.is_empty() => Err(Error::Io(std::io::Error::other("the server's name resolves to no address"))),
            Ok(addrs) => Ok(self.with_current_first(addrs)),
            Err(e) => {
                self.roam.resolve_failures.fetch_add(1, Ordering::Relaxed);
                Err(Error::Io(std::io::Error::new(e.kind(), format!("resolving the server's name: {e}"))))
            }
        }
    }

    /// One liveness probe: Ping, then wait for its Pong for
    /// max(3·RTT, probe_timeout_min). False = lost.
    async fn probe(&self, n: u64) -> bool {
        let deadline = (self.shared.rtt().unwrap_or_default() * 3).max(self.shared.limits.probe_timeout_min);
        let mut rx = self.shared.last_pong.subscribe();
        if !self.shared.send_ctrl(Message::Ping { n }) {
            return true; // detached or congested: not a path verdict
        }
        tokio::time::timeout(deadline, rx.wait_for(|v| *v >= n)).await.is_ok()
    }

    /// Move the carrier to a fresh socket (QUIC migration, SPEC §5.1).
    fn rebind(&self) -> std::io::Result<()> {
        if let Some(mgr) = &self.opts.path {
            // The path manager owns the socket: it moves the shared endpoint
            // and restarts every peer path (SPEC §7.2 "One route owner").
            let io = udp_socket(transport::dual_stack_socket(transport::unspecified_dual()).map_err(std::io::Error::other)?).map_err(std::io::Error::other)?;
            return mgr.rebind(io);
        }
        let sock = (self.opts.sockets)()?;
        match self.endpoint.lock().unwrap().as_ref() {
            Some(ep) => ep.rebind_abstract(sock),
            None => Ok(()),
        }
    }
}

/// Client roaming (SPEC §5.1): probe the path while attached and rebind when
/// a probe is lost; after a carrier death, resume with exponential backoff
/// until the server's linger has passed or it refuses the session.
async fn roam(inner: std::sync::Weak<ClientInner>) {
    let mut n = 0u64;
    loop {
        let Some(c) = inner.upgrade() else { return };
        let l = c.shared.limits.clone();
        if c.shared.is_attached() {
            let Some(period) = l.probe_interval else {
                drop(c);
                // No probing: just wait for a carrier death.
                let Some(c) = inner.upgrade() else { return };
                let shared = c.shared.clone();
                drop(c);
                shared.carrier_lost().await;
                continue;
            };
            drop(c);
            tokio::time::sleep(period).await;
            let Some(c) = inner.upgrade() else { return };
            n += 1;
            if !c.probe(n).await && c.shared.is_attached() {
                c.roam.probes_lost.fetch_add(1, Ordering::Relaxed);
                match c.rebind() {
                    Ok(()) => {
                        c.roam.rebinds.fetch_add(1, Ordering::Relaxed);
                        tracing::info!(session = %crate::session::hex(&c.shared.id), "liveness probe lost; rebound to a fresh socket");
                    }
                    Err(e) => tracing::warn!("liveness probe lost; rebind failed: {e}"),
                }
            }
            continue;
        }
        if !l.auto_resume {
            let shared = c.shared.clone();
            drop(c);
            // Manual resume only: wait until someone attaches again.
            let mut rx = shared.carrier_state_rx();
            let _ = rx.wait_for(|g| *g != 0).await;
            continue;
        }
        // Detached: resume with backoff until linger has passed.
        let lost_at = Instant::now();
        let mut wait = l.resume_backoff_initial;
        loop {
            if lost_at.elapsed() > c.linger {
                c.roam.gave_up.store(true, Ordering::Relaxed);
                c.gave_up.send_replace(true);
                tracing::warn!("session not resumed within the server's linger {:?}; giving up", c.linger);
                c.shared.teardown();
                return;
            }
            c.roam.resume_attempts.fetch_add(1, Ordering::Relaxed);
            // Each attempt is bounded by what is left of the linger (board
            // R6): an unreachable server must not hold one attempt for the
            // whole QUIC idle timeout past the session's end.
            let remaining = c.linger.saturating_sub(lost_at.elapsed());
            // Resolution, socket and handshake are all part of the attempt:
            // any of them failing (name not resolvable, no route, ECONNREFUSED
            // during a network change) is retried; only the server's refusal
            // of the session ends the loop.
            let attempt = async {
                let addrs = c.resume_targets().await?;
                let sock = (c.opts.sockets)().map_err(Error::Io)?;
                c.resume(sock, &addrs).await
            };
            let r = match tokio::time::timeout(remaining, attempt).await {
                Ok(r) => r,
                Err(_) => Err(Error::Deadline(format!("resume attempt outlived the remaining linger {remaining:?}"))),
            };
            match r {
                Ok(epoch) => {
                    tracing::info!(session = %crate::session::hex(&c.shared.id), epoch, "session resumed automatically");
                    break;
                }
                Err(Error::Refused(reason)) => {
                    // The server will never take this session back.
                    c.roam.gave_up.store(true, Ordering::Relaxed);
                    c.gave_up.send_replace(true);
                    tracing::warn!("resume refused ({reason}); giving up");
                    c.shared.teardown();
                    return;
                }
                Err(e) => tracing::debug!("resume attempt failed: {e}; retrying in {wait:?}"),
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(l.resume_backoff_max);
        }
    }
}
