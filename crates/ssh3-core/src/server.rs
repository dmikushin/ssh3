//! Server: accept loop, pre-auth phase, session registry (SPEC §2, §5, §8).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use quinn::{Connection, Endpoint, RecvStream, SendStream, TokioRuntime};
use rand::RngCore;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::auth::{Authenticator, Authz, EXPORTER_LABEL, EXPORTER_LEN, keys_intent, pubkey_blob, verify_auth};
use crate::error::{Error, Result, close};
use crate::frame::{self, MAX_FRAME, MAX_FRAME_PRE_AUTH};
use crate::limits::Limits;
use crate::msg::{FailReason, Intent, LanePos, Message, SessionId, SessionInfo};
use crate::session::{Budgets, Registry, Role, SessionShared, hex};
use crate::transport::{self, EndpointKeys};

pub struct ServerOptions {
    pub tls: rustls::ServerConfig,
    pub authenticator: Arc<dyn Authenticator>,
    pub limits: Limits,
    pub keys: EndpointKeys,
    /// Session channels (shell/exec/subsystem); None refuses them.
    pub session: Option<crate::sesschan::ServerSessionEnv>,
    /// Act as a rendezvous gateway (SPEC §7.1): clients may register as
    /// peers (permitted like a listen on `name:0`) and others may jump to
    /// them (permitted like direct-tcp to `name:0`).
    pub rendezvous: bool,
}

#[derive(Default)]
struct Counters {
    conns_accepted: AtomicU64,
    conns_active: AtomicU64,
    auth_failures: AtomicU64,
    resumes_accepted: AtomicU64,
    resumes_rejected: AtomicU64,
    protocol_closes: AtomicU64,
    refused_unauth_cap: AtomicU64,
}

struct ServerShared {
    authenticator: Arc<dyn Authenticator>,
    limits: Limits,
    registry: Arc<Registry>,
    unauth: Arc<Semaphore>,
    budgets: Arc<Budgets>,
    counters: Counters,
    session_env: Option<Arc<crate::sesschan::ServerSessionEnv>>,
    rendezvous: Option<Arc<crate::rendezvous::Rendezvous>>,
    /// Set once this server has registered at a gateway.
    hub: Mutex<Option<Arc<crate::rendezvous::PeerHub>>>,
    path: Option<Arc<ssh3_path::PathManager>>,
}

pub struct Server {
    endpoint: Endpoint,
    shared: Arc<ServerShared>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Snapshot of every counter a test or operator waits on (SPEC §8 I6).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ServerStats {
    /// QUIC connections: accepted for a handshake (cumulative), currently
    /// open (handshaking, authenticating or attached), and refused at accept
    /// because `max_unauthenticated` handshakes were in progress
    /// (`refused_unauth_cap`, cumulative). Auth refusals: `auth_failures`.
    pub conns_accepted: u64,
    pub conns_active: u64,
    pub sessions: usize,
    pub attached: usize,
    pub detached: usize,
    /// Channels other than the event log.
    pub channels: u64,
    /// OCCUPANCY: payload bytes currently held in send / receive rings
    /// (all lanes, all sessions). Always ≤ the chunk storage below.
    pub send_ring_bytes: u64,
    pub recv_ring_bytes: u64,
    /// Σ (limit − delivered): receive credit granted and not yet consumed.
    pub credit_outstanding: u64,
    /// ALLOCATION: 16 KiB chunks charged to LaneCreditBudget (receive rings
    /// plus reservations backing granted credit) and to LaneSendBudget —
    /// EXCLUDING floor chunks, which are charged to the separate, unlimited
    /// floor pool reported in `floor_chunks_bytes` (≤ 2 receive + 1 send
    /// chunk per lane). Budget beyond the floor is therefore read directly
    /// from these two fields; total chunk storage is their sum plus
    /// `floor_chunks_bytes`. Chunks stay charged until fully drained, so
    /// allocation ≥ occupancy.
    pub recv_budget_used: u64,
    pub send_budget_used: u64,
    pub floor_chunks_bytes: u64,
    /// Auth attempts refused (each AuthFail), plus connections that did not
    /// authenticate within LoginGraceTime (cumulative).
    pub auth_failures: u64,
    pub resumes_accepted: u64,
    pub resumes_rejected: u64,
    pub protocol_closes: u64,
    pub refused_unauth_cap: u64,
    /// -R listeners open, and connections they closed while detached.
    pub listeners: u64,
    pub refused_detached: u64,
    /// §1 scheduler: ConnWindowBudget in use, raises and lowers so far.
    pub conn_window_budget_used: u64,
    pub window_raises: u64,
    pub window_lowers: u64,
    /// §6: live UDP flows (all flow tables), datagrams dropped (full queue,
    /// detached, oversize, malformed), reassembly storage in use and groups
    /// evicted, LRU flow evictions.
    pub udp_flows: u64,
    /// Datagrams sent and received on live sessions (relay activity, §7.2).
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub datagrams_dropped: u64,
    pub reassembly_bytes: u64,
    pub reassembly_evicted: u64,
    pub udp_evicted: u64,
    /// §4 fenced credit retraction: completed retractions (acked or
    /// unilateral while detached) and carriers cut for an unacked Retract.
    pub credit_retractions: u64,
    pub retract_timeouts: u64,
    /// §5 pty lanes: bytes consumed in screen mode (emulator only — lost
    /// except for their effect on the screen) and redraws appended.
    pub pty_screen_bytes: u64,
    pub pty_redraws: u64,
    /// §7: peers registered at this gateway; relayed inner connections
    /// routed to this registered server.
    pub peers_registered: u64,
    pub relay_routes: u64,
}

impl Server {
    pub fn bind(opts: ServerOptions, socket: std::net::UdpSocket) -> Result<Self> {
        opts.limits.validate().map_err(Error::Config)?;
        let sc = transport::server_config(opts.tls.clone(), &opts.limits)?;
        let endpoint = Endpoint::new(transport::endpoint_config(&opts.keys), Some(sc), socket, Arc::new(TokioRuntime))?;
        Self::on_endpoint(opts, endpoint, None)
    }

    /// Serve on a path manager's endpoint (SPEC §7): the node's gateway
    /// registration and every relayed or direct inner connection share its
    /// one UDP socket.
    pub fn bind_path(opts: ServerOptions, mgr: Arc<ssh3_path::PathManager>) -> Result<Self> {
        opts.limits.validate().map_err(Error::Config)?;
        let sc = transport::server_config(opts.tls.clone(), &opts.limits)?;
        let keys = opts.keys.clone();
        let endpoint = mgr.endpoint_or_init(|sock| Endpoint::new_with_abstract_socket(transport::endpoint_config(&keys), Some(sc), sock, Arc::new(TokioRuntime)))?;
        Self::on_endpoint(opts, endpoint, Some(mgr))
    }

    fn on_endpoint(opts: ServerOptions, endpoint: Endpoint, path: Option<Arc<ssh3_path::PathManager>>) -> Result<Self> {
        let rendezvous = opts.rendezvous.then(|| crate::rendezvous::Rendezvous::new(opts.limits.max_sessions, opts.limits.max_listeners));
        let local_port = endpoint.local_addr()?.port();
        let session_env = opts.session.map(|mut e| {
            e.local_port = local_port;
            Arc::new(e)
        });
        let shared = Arc::new(ServerShared {
            authenticator: opts.authenticator,
            unauth: Arc::new(Semaphore::new(opts.limits.max_unauthenticated)),
            budgets: Budgets::new(&opts.limits),
            limits: opts.limits,
            registry: Arc::new(Mutex::new(HashMap::new())),
            counters: Counters::default(),
            session_env,
            rendezvous,
            hub: Mutex::new(None),
            path,
        });
        let accept_task = tokio::spawn(accept_loop(endpoint.clone(), shared.clone()));
        Ok(Self { endpoint, shared, accept_task })
    }

    /// SPEC I5: tear down every session now — carriers closed with a
    /// reason, -R listeners released — without waiting for drop.
    pub fn shutdown(&self) {
        self.accept_task.abort();
        let all: Vec<_> = self.shared.registry.lock().unwrap().values().cloned().collect();
        for s in all {
            s.teardown();
        }
        self.endpoint.close(close::SHUTDOWN.into(), b"server shutting down");
    }

    /// shutdown(), then wait (at most `bound`) until every connection's
    /// CONNECTION_CLOSE has been sent, so clients learn the reason (board
    /// request R2). False if `bound` elapsed first.
    pub async fn shutdown_and_wait(&self, bound: std::time::Duration) -> bool {
        self.shutdown();
        tokio::time::timeout(bound, self.endpoint.wait_idle()).await.is_ok()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr().expect("bound endpoint has an address")
    }

    pub fn session(&self, id: &SessionId) -> Option<Arc<SessionShared>> {
        self.shared.registry.lock().unwrap().get(id).cloned()
    }

    /// Register this server (built with `bind_path`) at a gateway as the
    /// peer `name` (SPEC §7.1), over a client session on the same endpoint.
    /// Relayed clients then reach this server through the gateway and both
    /// ends upgrade to a direct path with `cfg` when the NATs allow. Keep the
    /// returned session alive: dropping it ends the registration.
    pub async fn register_at(&self, opts: crate::ClientOptions, name: &str, cfg: ssh3_path::PathConfig) -> Result<crate::ClientSession> {
        let mgr = self.shared.path.clone().ok_or_else(|| Error::Config("register_at needs a server made with bind_path".into()))?;
        let hub = crate::rendezvous::PeerHub::new(mgr.clone(), cfg);
        let sess = crate::ClientSession::connect(crate::ClientOptions { path: Some(mgr.clone()), ..opts }, mgr.socket()).await?;
        hub.set_gateway(&sess.shared);
        *sess.shared.hub.lock().unwrap() = Some(hub.clone());
        sess.shared.register(name.to_string()).await?;
        *self.shared.hub.lock().unwrap() = Some(hub);
        Ok(sess)
    }

    pub fn stats(&self) -> ServerStats {
        let all: Vec<_> = self.shared.registry.lock().unwrap().values().cloned().collect();
        let c = &self.shared.counters;
        let b = &self.shared.budgets;
        let mut t = ServerStats {
            conns_accepted: c.conns_accepted.load(Ordering::Relaxed),
            conns_active: c.conns_active.load(Ordering::Relaxed),
            sessions: all.len(),
            recv_budget_used: b.recv.used(),
            send_budget_used: b.send.used(),
            floor_chunks_bytes: b.floor.used(),
            conn_window_budget_used: b.conn.used(),
            reassembly_bytes: b.reasm.used(),
            auth_failures: c.auth_failures.load(Ordering::Relaxed),
            resumes_accepted: c.resumes_accepted.load(Ordering::Relaxed),
            resumes_rejected: c.resumes_rejected.load(Ordering::Relaxed),
            protocol_closes: c.protocol_closes.load(Ordering::Relaxed),
            refused_unauth_cap: c.refused_unauth_cap.load(Ordering::Relaxed),
            peers_registered: self.shared.rendezvous.as_ref().map_or(0, |r| r.len() as u64),
            relay_routes: self.shared.hub.lock().unwrap().as_ref().map_or(0, |h| h.routes() as u64),
            ..Default::default()
        };
        for s in all {
            if s.is_attached() {
                t.attached += 1;
            } else {
                t.detached += 1;
            }
            t.channels += s.channel_count() as u64;
            t.listeners += s.listener_count() as u64;
            t.window_raises += s.stats.window_raises.load(Ordering::Relaxed);
            t.window_lowers += s.stats.window_lowers.load(Ordering::Relaxed);
            t.udp_flows += s.stats.udp_flows.load(Ordering::Relaxed);
            t.datagrams_sent += s.stats.dgrams_sent.load(Ordering::Relaxed);
            t.datagrams_received += s.stats.dgrams_received.load(Ordering::Relaxed);
            t.datagrams_dropped += s.stats.dgrams_dropped.load(Ordering::Relaxed);
            t.reassembly_evicted += s.stats.reasm_evicted.load(Ordering::Relaxed);
            t.udp_evicted += s.stats.udp_evicted.load(Ordering::Relaxed);
            t.credit_retractions += s.stats.credit_retractions.load(Ordering::Relaxed);
            t.retract_timeouts += s.stats.retract_timeouts.load(Ordering::Relaxed);
            t.pty_screen_bytes += s.stats.pty_screen_bytes.load(Ordering::Relaxed);
            t.pty_redraws += s.stats.pty_redraws.load(Ordering::Relaxed);
            t.refused_detached += s.refused_detached.load(Ordering::Relaxed);
            t.send_ring_bytes += s.stats.send_ring_bytes.load(Ordering::Relaxed);
            t.recv_ring_bytes += s.stats.recv_ring_bytes.load(Ordering::Relaxed);
            t.credit_outstanding += s.stats.credit_outstanding.load(Ordering::Relaxed);
        }
        t
    }
}

/// SPEC §8 I3: the accept loop awaits nothing per connection.
async fn accept_loop(endpoint: Endpoint, shared: Arc<ServerShared>) {
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = shared.unauth.clone().try_acquire_owned() else {
            shared.counters.refused_unauth_cap.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(peer = %incoming.remote_address(), "refusing connection: {} unauthenticated connections in progress", shared.limits.max_unauthenticated);
            incoming.refuse();
            continue;
        };
        let shared = shared.clone();
        shared.counters.conns_accepted.fetch_add(1, Ordering::Relaxed);
        shared.counters.conns_active.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let peer = incoming.remote_address();
            let counters = shared.clone();
            // Active until the QUIC connection is closed, however it ends.
            match incoming.accept() {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => {
                        if let Err(e) = handle(conn.clone(), shared, permit).await {
                            tracing::info!(%peer, "connection ended: {e}");
                        }
                        conn.closed().await;
                    }
                    Err(e) => tracing::info!(%peer, "handshake failed: {e}"),
                },
                Err(e) => tracing::info!(%peer, "connection not accepted: {e}"),
            }
            counters.counters.conns_active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

enum Authed {
    New { user: String, key: Vec<u8>, authz: Authz },
    Resume { user: String, key: Vec<u8>, authz: Authz, session_id: SessionId, lanes: Vec<LanePos> },
}

async fn handle(conn: Connection, shared: Arc<ServerShared>, permit: OwnedSemaphorePermit) -> Result<()> {
    let grace = shared.limits.login_grace;
    let pre = tokio::time::timeout(grace, pre_auth(&conn, &shared)).await;
    drop(permit);
    let (send, recv, authed) = match pre {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let code = match &e {
                Error::Auth(_) => {
                    shared.counters.auth_failures.fetch_add(1, Ordering::Relaxed);
                    close::AUTH_FAILED
                }
                _ => {
                    shared.counters.protocol_closes.fetch_add(1, Ordering::Relaxed);
                    close::PROTOCOL
                }
            };
            conn.close(code.into(), e.to_string().as_bytes());
            return Err(e);
        }
        Err(_) => {
            shared.counters.auth_failures.fetch_add(1, Ordering::Relaxed);
            conn.close(close::AUTH_FAILED.into(), b"authentication not completed within LoginGraceTime");
            return Err(Error::Deadline(format!("authentication not completed within {grace:?}")));
        }
    };
    match authed {
        Authed::New { user, key, authz } => {
            let mut id = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut id);
            let session = SessionShared::new(
                id,
                Role::Server,
                user,
                key,
                authz,
                shared.limits.clone(),
                shared.budgets.clone(),
                Some(Arc::downgrade(&shared.registry)),
                shared.session_env.clone(),
            );
            *session.rendezvous.lock().unwrap() = shared.rendezvous.clone();
            {
                let mut reg = shared.registry.lock().unwrap();
                if reg.len() >= shared.limits.max_sessions {
                    drop(reg);
                    session.teardown();
                    conn.close(close::RESOURCE_LIMIT.into(), b"too many sessions");
                    return Err(Error::Refused(FailReason::ResourceLimit));
                }
                reg.insert(id, session.clone());
            }
            let info = SessionInfo { session_id: id, linger_secs: shared.limits.linger.as_secs() };
            tracing::info!(session = %hex(&id), user = %session.user, "session created");
            let _g = session.attach_lock.lock().await;
            session.install_carrier(conn.clone(), send, recv, |_| Some(Message::AuthOk { session: Some(info) }));
            after_attach(&shared, &session, &conn);
            Ok(())
        }
        Authed::Resume { user, key, authz, session_id, lanes } => {
            let session = shared.registry.lock().unwrap().get(&session_id).cloned();
            let Some(session) = session else {
                shared.counters.resumes_rejected.fetch_add(1, Ordering::Relaxed);
                return refuse(&conn, send, FailReason::Protocol("unknown or expired session".into()), shared.limits.login_grace).await;
            };
            if session.owner_key != key || session.user != user {
                // SPEC §5: a session belongs to the user AND the exact key
                // that created it (one key may serve several accounts).
                shared.counters.resumes_rejected.fetch_add(1, Ordering::Relaxed);
                return refuse(&conn, send, FailReason::Prohibited, shared.limits.login_grace).await;
            }
            // SPEC §5: attach is serialized per session; the newer attach
            // closes the older carrier. The whole Resume is validated first,
            // so a malformed one cannot detach a working carrier.
            let _g = session.attach_lock.lock().await;
            if let Err(e) = session.validate_resume(&lanes) {
                shared.counters.resumes_rejected.fetch_add(1, Ordering::Relaxed);
                shared.counters.protocol_closes.fetch_add(1, Ordering::Relaxed);
                conn.close(close::PROTOCOL.into(), e.to_string().as_bytes());
                return Err(e);
            }
            session.detach(close::SUPERSEDED, b"superseded by resume");
            // Re-checked after detach: acks of the old carrier may have moved
            // the send side between validation and detach.
            if let Err(e) = session.reconcile(&lanes) {
                shared.counters.resumes_rejected.fetch_add(1, Ordering::Relaxed);
                shared.counters.protocol_closes.fetch_add(1, Ordering::Relaxed);
                conn.close(close::PROTOCOL.into(), e.to_string().as_bytes());
                return Err(e);
            }
            session.set_authz(authz);
            let ours = session.snapshot_lanes();
            let n = ours.len();
            // Counted before Resumed is sent: Resumed confirms it.
            shared.counters.resumes_accepted.fetch_add(1, Ordering::Relaxed);
            let epoch = session.install_carrier(conn.clone(), send, recv, move |epoch| Some(Message::Resumed { lanes: ours, epoch }));
            after_attach(&shared, &session, &conn);
            tracing::info!(session = %hex(&session_id), lanes = n, epoch, "session resumed");
            Ok(())
        }
    }
}

/// Every attach: tell the client where we see it (its server-reflexive
/// candidate, SPEC §7.3), and start the direct-path machinery of a relayed
/// inner connection.
fn after_attach(shared: &ServerShared, session: &Arc<SessionShared>, conn: &Connection) {
    let addr = ssh3_path::socket::canonical(conn.remote_address());
    if !ssh3_path::is_virtual(addr.ip()) {
        let _ = session.send_ctrl(Message::Observed { addr: addr.to_string() });
    }
    if let Some(h) = shared.hub.lock().unwrap().clone() {
        h.on_inner_attach(session, conn);
    }
}

/// Tell the client why, then close. A QUIC close discards undelivered stream
/// data, so wait until the `Fail` frame is acknowledged (or the client gives
/// up the stream) — bounded by LoginGraceTime — before closing.
async fn refuse(conn: &Connection, mut send: SendStream, reason: FailReason, grace: std::time::Duration) -> Result<()> {
    let _ = frame::write_message(&mut send, &Message::Fail { reason: reason.clone() }).await;
    deliver(&mut send, grace).await;
    conn.close(close::AUTH_FAILED.into(), reason.to_string().as_bytes());
    Err(Error::Refused(reason))
}

/// Everything before the session is attached. Any stream other than the
/// control stream, or any datagram, closes the connection (SPEC §2.3).
async fn pre_auth(conn: &Connection, shared: &ServerShared) -> Result<(SendStream, RecvStream, Authed)> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let authed = tokio::select! {
        r = auth_phase(conn, shared, &mut send, &mut recv) => r?,
        s = conn.accept_bi() => {
            s?;
            return Err(Error::Protocol("stream opened before authentication completed".into()));
        }
        d = conn.read_datagram() => {
            d?;
            return Err(Error::Protocol("datagram sent before authentication completed".into()));
        }
    };
    Ok((send, recv, authed))
}

async fn auth_phase(conn: &Connection, shared: &ServerShared, send: &mut SendStream, recv: &mut RecvStream) -> Result<Authed> {
    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|_| Error::Tls("TLS exporter unavailable".into()))?;
    for _ in 0..shared.limits.max_auth_tries {
        let m = frame::read_message(recv, MAX_FRAME_PRE_AUTH)
            .await?
            .ok_or_else(|| Error::Protocol("control stream closed during authentication".into()))?;
        let Message::Auth { user, pubkey, sig, intent } = m else {
            return Err(Error::Protocol(format!("expected Auth, got {m:?}")));
        };
        // Signature first (ssh3-keys owns the blob), then authorized_keys.
        let checked = verify_auth(&exporter, &user, &pubkey, keys_intent(intent), &sig)
            .map_err(|e| e.to_string())
            .and_then(|key| {
                let authz = shared.authenticator.authorize(&user, &key, conn.remote_address().ip())?;
                let blob = pubkey_blob(&key).map_err(|e| e.to_string())?;
                Ok((blob, authz))
            });
        match checked {
            Ok((pubkey, authz)) => {
                return match intent {
                    Intent::New => Ok(Authed::New { user, key: pubkey, authz }),
                    Intent::Resume => {
                        frame::write_message(send, &Message::AuthOk { session: None }).await?;
                        let m = frame::read_message(recv, MAX_FRAME)
                            .await?
                            .ok_or_else(|| Error::Protocol("control stream closed before Resume".into()))?;
                        let Message::Resume { session_id, lanes } = m else {
                            return Err(Error::Protocol(format!("expected Resume, got {m:?}")));
                        };
                        Ok(Authed::Resume { user, key: pubkey, authz, session_id, lanes })
                    }
                };
            }
            Err(reason) => {
                shared.counters.auth_failures.fetch_add(1, Ordering::Relaxed);
                tracing::info!(%user, "authentication refused: {reason}");
                frame::write_message(send, &Message::AuthFail { reason }).await?;
            }
        }
    }
    // The last AuthFail must reach the client before handle() closes.
    deliver(send, shared.limits.login_grace).await;
    Err(Error::Auth(format!("{} failed attempts", shared.limits.max_auth_tries)))
}

/// Every path that sends a final reply and then closes goes through here:
/// a QUIC close discards stream data not yet delivered, so finish the stream
/// and wait until the peer has acknowledged all of it (or stopped it), at
/// most `grace`.
async fn deliver(send: &mut SendStream, grace: std::time::Duration) {
    let t = std::time::Instant::now();
    let f = send.finish();
    let r = tokio::time::timeout(grace, send.stopped()).await;
    tracing::debug!("deliver: finish={f:?} stopped={r:?} after {:?}", t.elapsed());
}
