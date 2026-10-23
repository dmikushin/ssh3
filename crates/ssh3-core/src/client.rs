//! Client: connect, authenticate, resume (SPEC §2.2, §5).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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

#[derive(Clone)]
pub struct ClientOptions {
    pub server_addr: SocketAddr,
    pub host: HostCheck,
    pub signer: Arc<dyn Signer>,
    pub user: String,
    pub limits: Limits,
}

pub struct ClientSession {
    pub shared: Arc<SessionShared>,
    opts: ClientOptions,
    endpoint: Mutex<Option<Endpoint>>,
    /// The verified host key of the first connect: the session's target
    /// identity. A resume must present the same key.
    host_key: PublicKey,
}

impl Drop for ClientSession {
    fn drop(&mut self) {
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
        );
        {
            let _g = shared.attach_lock.lock().await;
            shared.install_carrier(conn, send, recv, |_| None);
            shared.reopen_lanes().await?;
        }
        Ok(Self { shared, opts, endpoint: Mutex::new(Some(ep)), host_key })
    }

    pub fn session_id(&self) -> SessionId {
        self.shared.id
    }

    pub async fn carrier_lost(&self) {
        self.shared.carrier_lost().await
    }

    /// Reattach the session over a new connection from `socket` (any local
    /// address or family). SPEC §5 "Resume".
    pub async fn resume(&self, socket: Arc<dyn AsyncUdpSocket>) -> Result<u64> {
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
        Ok(epoch)
    }

    /// The server's verified host key (the session's target identity).
    pub fn host_key(&self) -> &PublicKey {
        &self.host_key
    }

    pub fn budgets(&self) -> &Budgets {
        &self.shared.budgets
    }

    pub async fn open_direct_tcp(&self, tcp: tokio::net::TcpStream, host: &str, port: u16) -> Result<u64> {
        self.shared.open_direct_tcp(tcp, host.to_string(), port).await
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
