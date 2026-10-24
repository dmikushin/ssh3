//! Jump through a gateway (SPEC §7.2): the inner connection to the target is
//! an ordinary end-to-end QUIC connection whose packets travel as §6
//! datagrams of a UDP channel on the gateway session. The gateway forwards
//! them to `target:port` like `direct-udp` and sees only inner ciphertext;
//! the inner connection verifies the TARGET's host key and authenticates to
//! the target itself.
//!
//! The inner endpoint runs on an `ssh3_path` path socket: quinn talks to a
//! constant virtual peer address whose real path is the relay route (the
//! UDP channel). Fragmentation of inner packets that exceed the outer
//! datagram limit is end-to-end (§6 frag_hdr, done by `send_datagram`); the
//! gateway's UDP socket sends whole reassembled packets to the target.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use bytes::Bytes;
use quinn::AsyncUdpSocket;
use ssh3_path::{PathConfig, PathManager, PeerPath, RelayLink, RouteId};
use tokio::sync::mpsc;

use crate::client::{ClientOptions, ClientSession, udp_socket};
use crate::error::{Error, Result};
use crate::msg::ChannelKind;
use crate::session::{Completion, SessionShared};
use crate::transport;
use crate::udp::UdpExt;

/// Relay real path of an inner connection: one UDP channel of the gateway
/// session. Never blocks; a packet that cannot be sent is dropped (QUIC
/// recovers) and counted by the session's datagram counters.
/// The relay carrier can be replaced under a live route (a new gateway
/// session after the old one is gone, SPEC §7.2 "carrier replacement"):
/// the route and the inner connection's virtual address stay.
pub struct ChannelLink {
    target: std::sync::Mutex<(Weak<SessionShared>, u64)>,
    pub sent: AtomicU64,
}

impl ChannelLink {
    pub(crate) fn new(shared: Weak<SessionShared>, chan_id: u64) -> Self {
        Self { target: std::sync::Mutex::new((shared, chan_id)), sent: AtomicU64::new(0) }
    }

    fn retarget(&self, shared: Weak<SessionShared>, chan_id: u64) {
        *self.target.lock().unwrap() = (shared, chan_id);
    }
}

impl RelayLink for ChannelLink {
    fn send(&self, packet: &[u8]) {
        let (w, chan_id) = self.target.lock().unwrap().clone();
        if let Some(s) = w.upgrade() {
            self.sent.fetch_add(1, Ordering::Relaxed);
            s.send_datagram(chan_id, packet);
        }
    }
}

/// An inner path through a gateway session: the path manager whose socket
/// the inner endpoint runs on, the route and the virtual peer address to
/// dial. Keep it alive as long as the inner session.
pub struct JumpPath {
    pub mgr: Arc<PathManager>,
    pub route: RouteId,
    /// The address the inner connection dials (`ClientOptions::server_addr`).
    pub virt: SocketAddr,
    pub link: Arc<ChannelLink>,
    pub chan_id: u64,
    /// The gateway session (for its observed address, our reflexive
    /// candidate); replaced with the relay carrier.
    gateway: std::sync::Mutex<Weak<SessionShared>>,
}

impl JumpPath {
    /// The socket for the inner connection (a new incarnation of the path
    /// socket; with `inner_opts` the shared endpoint is used anyway).
    pub fn socket(&self) -> Arc<dyn AsyncUdpSocket> {
        self.mgr.socket()
    }

    /// Options for the inner session: `base` (the target's host check, keys,
    /// user, limits) dialled at the virtual address on the path manager's
    /// endpoint.
    pub fn inner_opts(&self, base: ClientOptions) -> ClientOptions {
        ClientOptions { server_addr: self.virt, path: Some(self.mgr.clone()), ..base }
    }

    /// Packets sent over the relay route so far.
    pub fn relayed(&self) -> u64 {
        self.link.sent.load(Ordering::Relaxed)
    }

    /// Start the direct-path upgrade (SPEC §7.3) for `inner`, the session
    /// dialled over this path. Only meaningful for a jump to a registered
    /// peer (both ends run the machinery); the dialing side controls.
    pub fn start_direct_path(&self, inner: &ClientSession, cfg: PathConfig) -> Result<Arc<PeerPath>> {
        let (conn, _) = inner.shared.current_conn().ok_or(Error::CarrierLost)?;
        let observed = self.gateway.lock().unwrap().upgrade().map(|g| g.observed.subscribe());
        crate::rendezvous::start_path(&self.mgr, self.route, self.link.clone(), &conn, &inner.shared, true, observed, cfg)
            .ok_or_else(|| Error::Tls("inner connection has no TLS exporter".into()))
    }
}

impl ClientSession {
    /// The path manager this session runs on, or a new one (on a fresh
    /// dual-stack socket) for an inner connection through it.
    fn path_manager(&self) -> Result<Arc<PathManager>> {
        if let Some(m) = self.path() {
            return Ok(m);
        }
        let io = udp_socket(transport::dual_stack_socket(transport::unspecified_dual())?)?;
        Ok(PathManager::new(io))
    }

    async fn relay_channel(&self, kind: ChannelKind) -> Result<JumpPath> {
        let mgr = self.path_manager()?;
        let s = &self.shared;
        let (tx, rx) = mpsc::channel::<Bytes>(s.limits.udp_queue);
        let ext = crate::sesschan::ChanExt::Udp(UdpExt::new(tx, s.stats.clone()));
        let ch = s.open_channel(kind, 0, Completion::Manual, Some(ext)).await?;
        let link = Arc::new(ChannelLink::new(Arc::downgrade(s), ch.chan_id));
        let (route, virt) = mgr.add_relay_route(link.clone());
        pump(&ch, rx, &mgr, route);
        Ok(JumpPath { mgr, route, virt, link, chan_id: ch.chan_id, gateway: std::sync::Mutex::new(Arc::downgrade(s)) })
    }

    /// Carrier replacement (SPEC §7.2): this session is a NEW gateway
    /// session (the old one is gone, e.g. the gateway restarted); open a
    /// relay to the same peer through it and move `path`'s route onto it.
    /// The inner connection keeps its virtual address; resume it (or let it
    /// recover) over the new relay.
    pub async fn rejump_peer(&self, path: &JumpPath, name: &str) -> Result<()> {
        self.rejump(path, ChannelKind::JumpPeer { name: name.to_string() }).await
    }

    /// As `rejump_peer`, for a jump to `host:port`.
    pub async fn rejump(&self, path: &JumpPath, kind: ChannelKind) -> Result<()> {
        let s = &self.shared;
        let (tx, rx) = mpsc::channel::<Bytes>(s.limits.udp_queue);
        let ext = crate::sesschan::ChanExt::Udp(UdpExt::new(tx, s.stats.clone()));
        let ch = s.open_channel(kind, 0, Completion::Manual, Some(ext)).await?;
        path.link.retarget(Arc::downgrade(s), ch.chan_id);
        *path.gateway.lock().unwrap() = Arc::downgrade(s);
        pump(&ch, rx, &path.mgr, path.route);
        Ok(())
    }

    /// Open a relay route to `host:port` through this session (the gateway):
    /// a UDP channel the gateway forwards to the target. The returned path
    /// carries an inner QUIC connection; dial it with `inner_opts`.
    pub async fn jump(&self, host: &str, port: u16) -> Result<JumpPath> {
        self.relay_channel(ChannelKind::DirectUdp { host: host.to_string(), port }).await
    }

    /// Relay to the peer registered at this gateway as `name` (SPEC §7.1):
    /// the inner connection reaches that peer's server; both ends can then
    /// upgrade to a direct path (`JumpPath::start_direct_path`).
    pub async fn jump_peer(&self, name: &str) -> Result<JumpPath> {
        self.relay_channel(ChannelKind::JumpPeer { name: name.to_string() }).await
    }

    /// Our address as the server observes it (after the first attach).
    pub fn observed(&self) -> Option<SocketAddr> {
        *self.shared.observed.borrow()
    }

    /// Direct-path status of this (inner) session, if it has the machinery.
    pub fn path_status(&self) -> Option<ssh3_path::PeerStatus> {
        self.shared.path_peer.lock().unwrap().as_ref().map(|p| p.status())
    }
}

/// Relay channel → route, owned by the channel. The route itself belongs
/// to the `JumpPath` (it outlives a gateway session that dies: carrier
/// replacement moves it onto a new channel), and ends when the path is
/// dropped.
fn pump(ch: &Arc<crate::session::Channel>, mut rx: mpsc::Receiver<Bytes>, mgr: &Arc<PathManager>, route: RouteId) {
    let m2 = Arc::downgrade(mgr);
    ch.spawn(async move {
        while let Some(d) = rx.recv().await {
            let Some(m) = m2.upgrade() else { return };
            m.relay_input(route, d);
        }
    });
}

impl Drop for JumpPath {
    fn drop(&mut self) {
        self.mgr.shared().remove_route(self.route);
    }
}
