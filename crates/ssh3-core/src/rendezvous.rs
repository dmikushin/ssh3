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
//! Every table here is bounded: peers by `max_sessions`, routes by the
//! registered session's channel cap, queues by `udp_queue`.

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

/// Gateway: name → registered peer session. A newer registration of a name
/// replaces the older (a restarted peer takes its name back).
pub struct Rendezvous {
    peers: Mutex<HashMap<String, Weak<SessionShared>>>,
    max: usize,
}

impl Rendezvous {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self { peers: Mutex::new(HashMap::new()), max })
    }

    // Names are host names to clients (`ssh3 -J gw NAME`, which ssh_config
    // lower-cases): matched case-insensitively.
    fn register(&self, name: String, s: &Arc<SessionShared>) -> std::result::Result<(), FailReason> {
        let name = name.to_ascii_lowercase();
        let mut p = self.peers.lock().unwrap();
        p.retain(|_, w| w.strong_count() > 0);
        if !p.contains_key(&name) && p.len() >= self.max {
            return Err(FailReason::ResourceLimit);
        }
        p.insert(name, Arc::downgrade(s));
        Ok(())
    }

    fn lookup(&self, name: &str) -> Option<Arc<SessionShared>> {
        self.peers.lock().unwrap().get(&name.to_ascii_lowercase()).and_then(Weak::upgrade)
    }

    pub fn has(&self, name: &str) -> bool {
        self.lookup(name).is_some()
    }

    /// Live registrations.
    pub fn len(&self) -> usize {
        self.peers.lock().unwrap().values().filter(|w| w.strong_count() > 0).count()
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

    /// Gateway: a Register. Permitted like a listen on `name:0` (the
    /// registration is the peer's listener at the gateway).
    pub(crate) fn on_register(self: &Arc<Self>, req_id: u64, name: String) -> Result<()> {
        if self.role != Role::Server {
            return Err(Error::Protocol("Register sent to a client".into()));
        }
        if !self.authz().allows_listen(&name, 0) {
            return self.reply_ev(Message::ListenFail { req_id, reason: FailReason::Prohibited });
        }
        let Some(rv) = self.rendezvous.lock().unwrap().clone() else {
            return self.reply_ev(Message::ListenFail { req_id, reason: FailReason::Prohibited });
        };
        match rv.register(name.clone(), self) {
            Ok(()) => {
                tracing::info!(peer = %name, "peer registered");
                self.reply_ev(Message::ListenOk { req_id, port: 0 })
            }
            Err(reason) => self.reply_ev(Message::ListenFail { req_id, reason }),
        }
    }

    /// Gateway: a client jumps to the registered peer `name`. Opens the
    /// peer's half and copies datagrams both ways; either half ending ends
    /// the other.
    pub(crate) fn accept_jump_peer(self: &Arc<Self>, chan_id: u64, name: String) -> Result<()> {
        if !self.authz().allows_direct_tcp(&name, 0) {
            return self.reply_ev(Message::ChannelFail { chan_id, reason: FailReason::Prohibited });
        }
        let rv = self.rendezvous.lock().unwrap().clone();
        let Some(peer) = rv.and_then(|r| r.lookup(&name)) else {
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
