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

/// Makes a fresh UDP socket for a rebind or a resume.
pub type SocketFactory = Arc<dyn Fn() -> std::io::Result<Arc<dyn AsyncUdpSocket>> + Send + Sync>;

/// Dual-stack `[::]:0` sockets (SPEC §5.1).
pub fn dual_stack_factory() -> SocketFactory {
    Arc::new(|| udp_socket(transport::dual_stack_socket(transport::unspecified_dual()).map_err(std::io::Error::other)?).map_err(std::io::Error::other))
}

#[derive(Clone)]
pub struct ClientOptions {
    pub server_addr: SocketAddr,
    pub host: HostCheck,
    pub signer: Arc<dyn Signer>,
    pub user: String,
    pub limits: Limits,
    /// Sockets for rebinds and automatic resumes.
    pub sockets: SocketFactory,
}

/// Roaming counters (SPEC §8 I6).
#[derive(Default, Debug)]
pub struct RoamStats {
    pub probes_lost: AtomicU64,
    pub rebinds: AtomicU64,
    pub resume_attempts: AtomicU64,
    pub resumes: AtomicU64,
    /// Set when automatic resume gave up (session refused or linger over).
    pub gave_up: AtomicBool,
}

struct ClientInner {
    shared: Arc<SessionShared>,
    opts: ClientOptions,
    endpoint: Mutex<Option<Endpoint>>,
    /// The verified host key of the first connect: the session's target
    /// identity. A resume must present the same key.
    host_key: PublicKey,
    /// The server's SessionLinger: automatic resume stops after it.
    linger: Duration,
    roam: RoamStats,
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
}

async fn connect_and_auth(opts: &ClientOptions, socket: Arc<dyn AsyncUdpSocket>, intent: Intent) -> Result<Dialed> {
    let verifier = opts.host.verifier();
    let cc = transport::client_config(transport::client_tls(verifier.clone())?, &opts.limits)?;
    let mut ep = Endpoint::new_with_abstract_socket(transport::endpoint_config(&EndpointKeys::random()), None, socket, Arc::new(TokioRuntime))?;
    ep.set_default_client_config(cc);
    let conn = ep.connect(transport::to_v6(opts.server_addr), "ssh3-rs")?.await?;
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
    let pubkey = pubkey_blob(opts.signer.public_key()).map_err(|e| Error::Auth(e.to_string()))?;
    // Agent signing is blocking socket I/O.
    let (signer, user) = (opts.signer.clone(), opts.user.clone());
    let sig = tokio::task::spawn_blocking(move || sign_auth(&*signer, &exporter, &user, keys_intent(intent)))
        .await
        .map_err(|e| Error::Auth(format!("signing task failed: {e}")))?
        .map_err(|e| Error::Auth(e.to_string()))?;
    frame::write_message(&mut send, &Message::Auth { user: opts.user.clone(), pubkey, sig, intent }).await?;
    match frame::read_message(&mut recv, MAX_FRAME).await.map_err(|e| explain(&conn, e))? {
        Some(Message::AuthOk { session: info }) => Ok(Dialed { ep, conn, send, recv, info, host_key }),
        Some(Message::AuthFail { reason }) => {
            conn.close(close::SHUTDOWN.into(), b"authentication refused");
            Err(Error::Auth(reason))
        }
        Some(m) => Err(Error::Protocol(format!("expected AuthOk/AuthFail, got {m:?}"))),
        None => Err(Error::Protocol("server closed the control stream during authentication".into())),
    }
}

impl ClientSession {
    pub async fn connect(opts: ClientOptions, socket: Arc<dyn AsyncUdpSocket>) -> Result<Self> {
        opts.limits.validate().map_err(Error::Config)?;
        let Dialed { ep, conn, send, recv, info, host_key } = connect_and_auth(&opts, socket, Intent::New).await?;
        let info = info.ok_or_else(|| Error::Protocol("AuthOk for a new session carries no session info".into()))?;
        let shared = SessionShared::new(
            info.session_id,
            Role::Client,
            opts.user.clone(),
            pubkey_blob(opts.signer.public_key()).map_err(|e| Error::Auth(e.to_string()))?,
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
            opts,
            endpoint: Mutex::new(Some(ep)),
            host_key,
            linger: Duration::from_secs(info.linger_secs),
            roam: RoamStats::default(),
        });
        let roamer = tokio::spawn(roam(Arc::downgrade(&inner)));
        Ok(Self { shared, inner, roamer })
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

    /// Reattach the session over a new connection from `socket` (any local
    /// address or family). SPEC §5 "Resume".
    pub async fn resume(&self, socket: Arc<dyn AsyncUdpSocket>) -> Result<u64> {
        self.inner.resume(socket).await
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

    pub async fn open_direct_tcp(&self, tcp: tokio::net::TcpStream, host: &str, port: u16) -> Result<u64> {
        self.shared.open_direct_tcp(tcp, host.to_string(), port).await
    }

    /// `-R`: the server listens on `bind_host:bind_port` (0 = any) and each
    /// connection is forwarded to `target_host:target_port` from here.
    /// Returns the port the server bound.
    pub async fn forward_remote(&self, bind_host: &str, bind_port: u16, target_host: &str, target_port: u16) -> Result<u16> {
        self.shared.forward_remote(bind_host.to_string(), bind_port, (target_host.to_string(), target_port)).await
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
    async fn resume(&self, socket: Arc<dyn AsyncUdpSocket>) -> Result<u64> {
        let _g = self.shared.attach_lock.lock().await;
        self.shared.detach(close::SUPERSEDED, b"client resuming");
        let ours = self.shared.snapshot_lanes();
        let Dialed { ep, conn, mut send, mut recv, host_key, .. } = connect_and_auth(&self.opts, socket, Intent::Resume).await?;
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
        self.roam.resumes.fetch_add(1, Ordering::Relaxed);
        Ok(epoch)
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
                tracing::warn!("session not resumed within the server's linger {:?}; giving up", c.linger);
                c.shared.teardown();
                return;
            }
            c.roam.resume_attempts.fetch_add(1, Ordering::Relaxed);
            let r = match (c.opts.sockets)() {
                Ok(sock) => c.resume(sock).await,
                Err(e) => Err(Error::Io(e)),
            };
            match r {
                Ok(epoch) => {
                    tracing::info!(session = %crate::session::hex(&c.shared.id), epoch, "session resumed automatically");
                    break;
                }
                Err(Error::Refused(reason)) => {
                    // The server will never take this session back.
                    c.roam.gave_up.store(true, Ordering::Relaxed);
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
