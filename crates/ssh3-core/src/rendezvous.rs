//! Rendezvous and direct-path upgrade (SPEC §7.1, §7.3).
//!
//! * A gateway server keeps a [`Rendezvous`]: peers (servers behind NAT)
//!   register a name over their own client session to the gateway.
//! * A client jumps to a registered peer with a `JumpPeer` channel; the
//!   gateway opens a `PeerRelay` channel on the peer's session and copies
//!   datagrams between the two — inner QUIC packets, opaque to it.
//! * The registered peer routes each `PeerRelay` channel into its path
//!   manager ([`PeerHub`]); the inner connection then arrives at its server
//!   endpoint from a virtual address and is authenticated like any other.
//! * On both ends of an inner connection the ssh3-path machinery
//!   ([`ssh3_path::PeerPath`]) exchanges candidates over the inner
//!   connection's control stream (`PathSignal`) and upgrades to a direct
//!   path when the NATs allow it; the relay stays as fallback.
//!
//! Every table here is bounded: names by `max_sessions` in total and by
//! `max_listeners` per registering session, routes by the registered
//! session's channel cap, queues by `udp_queue`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};

use bytes::Bytes;
use ssh3_path::{PathConfig, PathManager, PeerPath, PeerSetup, RelayLink, RouteId, wire};
use tokio::sync::{mpsc, watch};

use crate::error::{Error, Result};
use crate::jump::ChannelLink;
use crate::msg::{ChannelKind, FailReason, Message};
use crate::session::{Completion, Role, SessionShared};
use crate::udp::UdpExt;

/// Suffix that puts a host name in the registered-peer namespace: a client
/// reaches the peer registered as `box` with `-J gw box.peer`. A name without
/// it is always a DNS name (or address) and never reaches a registration, so
/// a peer registering `github` or `localhost` cannot capture jumps to those
/// hosts (SPEC §7.1).
pub const PEER_SUFFIX: &str = ".peer";

/// Longest peer label (one DNS label).
pub const MAX_PEER_LABEL: usize = 63;

/// A registered peer name: one DNS-style label, ASCII letters, digits and
/// inner hyphens, at most 63 characters; matched case-insensitively. Returns
/// the canonical (lower-case) label or why the name is refused.
pub fn peer_label(name: &str) -> std::result::Result<String, String> {
    let ok = !name.is_empty()
        && name.len() <= MAX_PEER_LABEL
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if ok {
        Ok(name.to_ascii_lowercase())
    } else {
        Err(format!(
            "invalid peer name {name:?}: one label of 1-{MAX_PEER_LABEL} ASCII letters, digits and inner hyphens \
             (no dots, no `{PEER_SUFFIX}` suffix when registering)"
        ))
    }
}

/// The peer label a client host name addresses, if it is in the peer
/// namespace (`<label>.peer`, any case); `Err` when it has the suffix but an
/// invalid label.
pub fn peer_target(host: &str) -> Option<std::result::Result<String, String>> {
    let n = host.len().checked_sub(PEER_SUFFIX.len())?;
    let (label, suffix) = host.split_at_checked(n)?;
    suffix.eq_ignore_ascii_case(PEER_SUFFIX).then(|| peer_label(label))
}

/// SHA-256 fingerprint of an OpenSSH public key blob, for logs.
pub(crate) fn key_fingerprint(blob: &[u8]) -> String {
    match ssh_key::PublicKey::from_bytes(blob) {
        Ok(k) => k.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        Err(_) => "<unparseable key>".into(),
    }
}

/// Who registered a name: the authenticated user and the exact key.
#[derive(Clone, PartialEq, Eq)]
struct Owner {
    user: String,
    key: Vec<u8>,
}

struct Registration {
    owner: Owner,
    session: Weak<SessionShared>,
}

/// Gateway: peer label → registration. A name belongs to the (user, key)
/// that registered it for as long as that registration's session lives
/// (attached or lingering); the same owner may replace it (a restarted peer
/// takes its name back), any other owner is refused. Bounded: `max` names in
/// total, `per_session` names per registering session.
pub struct Rendezvous {
    peers: Mutex<HashMap<String, Registration>>,
    max: usize,
    per_session: usize,
}

impl Rendezvous {
    pub fn new(max: usize, per_session: usize) -> Arc<Self> {
        Arc::new(Self { peers: Mutex::new(HashMap::new()), max, per_session })
    }

    fn register(&self, label: String, s: &Arc<SessionShared>) -> std::result::Result<(), FailReason> {
        let owner = Owner { user: s.user.clone(), key: s.owner_key.clone() };
        let mut p = self.peers.lock().unwrap();
        p.retain(|_, r| r.session.strong_count() > 0);
        if let Some(r) = p.get(&label) {
            if r.owner != owner {
                return Err(FailReason::BindFailed(format!("peer name {label} is registered by another owner")));
            }
        } else {
            if p.len() >= self.max {
                return Err(FailReason::ResourceLimit);
            }
            let mine = p.values().filter(|r| std::ptr::eq(r.session.as_ptr(), Arc::as_ptr(s))).count();
            if mine >= self.per_session {
                return Err(FailReason::ResourceLimit);
            }
        }
        p.insert(label, Registration { owner, session: Arc::downgrade(s) });
        Ok(())
    }

    fn lookup(&self, label: &str) -> Option<Arc<SessionShared>> {
        self.peers.lock().unwrap().get(label).and_then(|r| r.session.upgrade())
    }

    /// Live registrations.
    pub fn len(&self) -> usize {
        self.peers.lock().unwrap().values().filter(|r| r.session.strong_count() > 0).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

struct HubRoute {
    route: RouteId,
    link: Arc<ChannelLink>,
}

/// Registered peer: the path manager its server endpoint runs on, and the
/// relay route of every inner connection relayed to it, by virtual address.
pub struct PeerHub {
    pub(crate) mgr: Arc<PathManager>,
    routes: Mutex<HashMap<SocketAddr, HubRoute>>,
    pub(crate) cfg: PathConfig,
    /// The registration session (to the gateway): its observed address is
    /// our server-reflexive candidate.
    gateway: Mutex<Weak<SessionShared>>,
}

impl PeerHub {
    pub(crate) fn new(mgr: Arc<PathManager>, cfg: PathConfig) -> Arc<Self> {
        Arc::new(Self { mgr, routes: Mutex::new(HashMap::new()), cfg, gateway: Mutex::new(Weak::new()) })
    }

    pub(crate) fn set_gateway(&self, s: &Arc<SessionShared>) {
        *self.gateway.lock().unwrap() = Arc::downgrade(s);
    }

    fn route_for(&self, virt: SocketAddr) -> Option<(RouteId, Arc<ChannelLink>)> {
        self.routes.lock().unwrap().get(&virt).map(|r| (r.route, r.link.clone()))
    }

    /// Relayed inner connections currently routed.
    pub fn routes(&self) -> usize {
        self.routes.lock().unwrap().len()
    }

    /// An inner connection attached to a session of this peer's server: if it
    /// came over a relay route, start its direct-path machinery (controlled
    /// side: the dialing client controls, SPEC §7.3).
    pub(crate) fn on_inner_attach(&self, session: &Arc<SessionShared>, conn: &quinn::Connection) {
        // Relayed inner connections come from their route's virtual address.
        let Some((route, link)) = self.route_for(conn.remote_address()) else { return };
        let observed = self.gateway.lock().unwrap().upgrade().map(|g| g.observed.subscribe());
        start_path(&self.mgr, route, link, conn, session, false, observed, self.cfg.clone());
    }
}

/// Removes a relay route when its channel ends.
struct RouteGuard {
    hub: Weak<PeerHub>,
    route: RouteId,
    virt: SocketAddr,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Some(h) = self.hub.upgrade() {
            h.routes.lock().unwrap().remove(&self.virt);
            h.mgr.shared().remove_route(self.route);
        }
    }
}

/// Ends the other half of a gateway relay when this half's task ends.
struct OtherHalf {
    session: Weak<SessionShared>,
    chan_id: u64,
}

impl Drop for OtherHalf {
    fn drop(&mut self) {
        if let Some(s) = self.session.upgrade() {
            let chan_id = self.chan_id;
            tokio::spawn(async move { s.abort_channel(chan_id, "relay partner gone".into()).await });
        }
    }
}

/// Start the direct-path machinery of one inner connection; its signals
/// travel on the connection's control stream (`PathSignal`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_path(
    mgr: &Arc<PathManager>,
    route: RouteId,
    link: Arc<ChannelLink>,
    conn: &quinn::Connection,
    session: &Arc<SessionShared>,
    controlling: bool,
    observed: Option<watch::Receiver<Option<SocketAddr>>>,
    cfg: PathConfig,
) -> Option<Arc<PeerPath>> {
    let mut secret = [0u8; 32];
    if conn.export_keying_material(&mut secret, wire::EXPORTER_LABEL, b"").is_err() {
        tracing::warn!("inner connection has no TLS exporter; staying on the relay");
        return None;
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let reflexive = observed.as_ref().and_then(|o| *o.borrow());
    let relay: Arc<dyn RelayLink> = link;
    let peer = Arc::new(mgr.start_peer(PeerSetup { route, relay, conn: conn.clone(), secret, controlling, signals: tx, reflexive, cfg }));
    let w = Arc::downgrade(session);
    // Ends when the PeerPath (holder of the sender) is dropped.
    tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            let Some(s) = w.upgrade() else { return };
            if !s.send_ctrl(Message::PathSignal { bytes }) {
                tracing::debug!("path signal dropped (detached or control queue full)");
            }
        }
    });
    if let Some(mut o) = observed {
        let wp = Arc::downgrade(&peer);
        tokio::spawn(async move {
            while o.changed().await.is_ok() {
                let Some(p) = wp.upgrade() else { return };
                if let Some(a) = *o.borrow() {
                    p.set_reflexive(a);
                }
            }
        });
    }
    *session.path_peer.lock().unwrap() = Some(peer.clone());
    Some(peer)
}

impl SessionShared {
    /// Client: register this session at the gateway as `name` (SPEC §7.1).
    pub(crate) async fn register(self: &Arc<Self>, name: String) -> Result<()> {
        let req_id = self.next_req_id();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.register_pending_insert(req_id, tx);
        self.send_event(Message::Register { req_id, name }).await?;
        match rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(r)) => Err(Error::Refused(r)),
            Err(_) => Err(Error::CarrierLost),
        }
    }

    /// Gateway: a Register. Permitted like a listen on `<label>.peer:0`
    /// (the registration is the peer's listener at the gateway).
    pub(crate) fn on_register(self: &Arc<Self>, req_id: u64, name: String) -> Result<()> {
        if self.role != Role::Server {
            return Err(Error::Protocol("Register sent to a client".into()));
        }
        let label = match peer_label(&name) {
            Ok(l) => l,
            Err(m) => return self.reply_ev(Message::ListenFail { req_id, reason: FailReason::BindFailed(m) }),
        };
        if !self.authz().allows_listen(&format!("{label}{PEER_SUFFIX}"), 0) {
            tracing::warn!(user = %self.user, key = %key_fingerprint(&self.owner_key), peer = %label, "peer registration refused: not permitted (needs permitlisten=\"{label}{PEER_SUFFIX}:0\")");
            return self.reply_ev(Message::ListenFail { req_id, reason: FailReason::Prohibited });
        }
        let Some(rv) = self.rendezvous.lock().unwrap().clone() else {
            return self.reply_ev(Message::ListenFail { req_id, reason: FailReason::Prohibited });
        };
        match rv.register(label.clone(), self) {
            Ok(()) => {
                tracing::info!(peer = %label, user = %self.user, "peer registered");
                self.reply_ev(Message::ListenOk { req_id, port: 0 })
            }
            Err(reason) => {
                tracing::info!(peer = %label, user = %self.user, %reason, "peer registration refused");
                self.reply_ev(Message::ListenFail { req_id, reason })
            }
        }
    }

    /// Gateway: a client jumps to the registered peer `name`. Opens the
    /// peer's half and copies datagrams both ways; either half ending ends
    /// the other.
    /// `name` is a peer label, bare or with the `.peer` suffix; permitted
    /// like a direct connection to `<label>.peer:0`.
    pub(crate) fn accept_jump_peer(self: &Arc<Self>, chan_id: u64, name: String) -> Result<()> {
        let label = match peer_target(&name).unwrap_or_else(|| peer_label(&name)) {
            Ok(l) => l,
            Err(m) => return self.reply_ev(Message::ChannelFail { chan_id, reason: FailReason::ConnectFailed(m) }),
        };
        let name = format!("{label}{PEER_SUFFIX}");
        if !self.authz().allows_direct_tcp(&name, 0) {
            tracing::warn!(user = %self.user, key = %key_fingerprint(&self.owner_key), target = %name, "peer connection refused: not permitted (needs permitopen=\"{name}:0\")");
            return self.reply_ev(Message::ChannelFail { chan_id, reason: FailReason::Prohibited });
        }
        let rv = self.rendezvous.lock().unwrap().clone();
        let Some(peer) = rv.and_then(|r| r.lookup(&label)) else {
            return self.reply_ev(Message::ChannelFail { chan_id, reason: FailReason::ConnectFailed(format!("no peer registered as {name}")) });
        };
        let (tx_c, mut rx_c) = mpsc::channel::<Bytes>(self.limits.udp_queue);
        let ch = match self.new_channel(chan_id, 0, Completion::Manual) {
            Ok(ch) => ch,
            Err(FailReason::Protocol(m)) => return Err(Error::Protocol(m)),
            Err(reason) => return self.reply_ev(Message::ChannelFail { chan_id, reason }),
        };
        *ch.ext.lock().unwrap() = Some(crate::sesschan::ChanExt::Udp(UdpExt::new(tx_c, self.stats.clone())));
        let from = self.conn_addrs().map(|(a, _)| ssh3_path::socket::canonical(a).to_string()).unwrap_or_default();
        let me = Arc::downgrade(self);
        ch.spawn(async move {
            let (tx_p, mut rx_p) = mpsc::channel::<Bytes>(peer.limits.udp_queue);
            let ext = crate::sesschan::ChanExt::Udp(UdpExt::new(tx_p, peer.stats.clone()));
            let pch = match peer.open_channel(ChannelKind::PeerRelay { from }, 0, Completion::Manual, Some(ext)).await {
                Ok(c) => c,
                Err(e) => {
                    if let Some(s) = me.upgrade() {
                        drop(s.drop_channel(chan_id));
                        let _ = s.send_event(Message::ChannelFail { chan_id, reason: FailReason::ConnectFailed(format!("peer {name}: {e}")) }).await;
                    }
                    return;
                }
            };
            let peer_chan = pch.chan_id;
            let Some(s) = me.upgrade() else { return };
            let _ = s.send_event(Message::ChannelOk { chan_id, limit: 0 }).await;
            drop(s);
            let me2 = me.clone();
            let back = OtherHalf { session: me.clone(), chan_id };
            pch.spawn(async move {
                let _back = back;
                while let Some(d) = rx_p.recv().await {
                    let Some(s) = me2.upgrade() else { return };
                    s.send_datagram(chan_id, &d);
                }
            });
            drop(pch);
            let wpeer = Arc::downgrade(&peer);
            drop(peer);
            let _fwd = OtherHalf { session: wpeer.clone(), chan_id: peer_chan };
            while let Some(d) = rx_c.recv().await {
                let Some(p) = wpeer.upgrade() else { return };
                p.send_datagram(peer_chan, &d);
            }
        });
        Ok(())
    }

    /// Registered peer: the gateway relays a jumping client to us. Route the
    /// channel's datagrams into the path manager as a new relay route; the
    /// client's inner connection arrives at our server endpoint from its
    /// virtual address.
    pub(crate) fn accept_peer_relay(self: &Arc<Self>, chan_id: u64, from: String) -> Result<()> {
        let Some(hub) = self.hub.lock().unwrap().clone() else {
            return self.reply_ev(Message::ChannelFail { chan_id, reason: FailReason::Prohibited });
        };
        let (tx, mut rx) = mpsc::channel::<Bytes>(self.limits.udp_queue);
        let ch = match self.new_channel(chan_id, 0, Completion::Manual) {
            Ok(ch) => ch,
            Err(FailReason::Protocol(m)) => return Err(Error::Protocol(m)),
            Err(reason) => return self.reply_ev(Message::ChannelFail { chan_id, reason }),
        };
        *ch.ext.lock().unwrap() = Some(crate::sesschan::ChanExt::Udp(UdpExt::new(tx, self.stats.clone())));
        let link = Arc::new(ChannelLink::new(Arc::downgrade(self), chan_id));
        let (route, virt) = hub.mgr.add_relay_route(link.clone());
        hub.routes.lock().unwrap().insert(virt, HubRoute { route, link });
        tracing::info!(%from, %virt, "relayed client routed");
        let guard = RouteGuard { hub: Arc::downgrade(&hub), route, virt };
        let mgr = hub.mgr.clone();
        drop(hub);
        ch.spawn(async move {
            let _g = guard;
            while let Some(d) = rx.recv().await {
                mgr.relay_input(route, d);
            }
        });
        self.reply_ev(Message::ChannelOk { chan_id, limit: 0 })
    }
}
