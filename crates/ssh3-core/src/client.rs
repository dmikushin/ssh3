//! Client: connect, authenticate, resume (SPEC §2.2, §5).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use quinn::{AsyncUdpSocket, Connection, Endpoint, RecvStream, SendStream, TokioRuntime};
use tokio::net::TcpListener;

use crate::auth::{Authz, EXPORTER_LABEL, EXPORTER_LEN, Signer, auth_blob};
use crate::error::{Error, Result, close};
use crate::frame::{self, MAX_FRAME};
use crate::limits::Limits;
use crate::msg::{Intent, Message, SessionId};
use crate::session::{Budgets, Role, SessionShared};
use crate::transport::{self, EndpointKeys};

#[derive(Clone)]
pub struct ClientOptions {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub tls: rustls::ClientConfig,
    pub signer: Arc<dyn Signer>,
    pub user: String,
    pub limits: Limits,
}

pub struct ClientSession {
    pub shared: Arc<SessionShared>,
    opts: ClientOptions,
    endpoint: Mutex<Option<Endpoint>>,
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

async fn connect_and_auth(opts: &ClientOptions, socket: Arc<dyn AsyncUdpSocket>, intent: Intent) -> Result<(Endpoint, Connection, SendStream, RecvStream, Option<crate::msg::SessionInfo>)> {
    let cc = transport::client_config(opts.tls.clone(), &opts.limits)?;
    let mut ep = Endpoint::new_with_abstract_socket(transport::endpoint_config(&EndpointKeys::random()), None, socket, Arc::new(TokioRuntime))?;
    ep.set_default_client_config(cc);
    let conn = ep.connect(transport::to_v6(opts.server_addr), &opts.server_name)?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    // Handshake is complete once `connect` resolved: the exporter is final.
    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|_| Error::Tls("TLS exporter unavailable".into()))?;
    let pubkey = opts.signer.public_key_blob();
    let blob = auth_blob(&exporter, &opts.user, &pubkey, intent);
    let sig = opts.signer.sign(&blob).map_err(Error::Auth)?;
    frame::write_message(&mut send, &Message::Auth { user: opts.user.clone(), pubkey, sig, intent }).await?;
    match frame::read_message(&mut recv, MAX_FRAME).await? {
        Some(Message::AuthOk { session }) => Ok((ep, conn, send, recv, session)),
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
        let (ep, conn, send, recv, info) = connect_and_auth(&opts, socket, Intent::New).await?;
        let info = info.ok_or_else(|| Error::Protocol("AuthOk for a new session carries no session info".into()))?;
        let shared = SessionShared::new(
            info.session_id,
            Role::Client,
            opts.user.clone(),
            opts.signer.public_key_blob(),
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
        Ok(Self { shared, opts, endpoint: Mutex::new(Some(ep)) })
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
        let (ep, conn, mut send, mut recv, _) = connect_and_auth(&self.opts, socket, Intent::Resume).await?;
        frame::write_message(&mut send, &Message::Resume { session_id: self.shared.id, lanes: ours }).await?;
        let (theirs, epoch) = match frame::read_message(&mut recv, MAX_FRAME).await? {
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
