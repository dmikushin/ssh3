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
use ssh3_path::{PathManager, RelayLink, RouteId};
use tokio::sync::mpsc;

use crate::client::{ClientSession, SocketFactory, udp_socket};
use crate::error::Result;
use crate::msg::ChannelKind;
use crate::session::{Completion, SessionShared};
use crate::transport;
use crate::udp::UdpExt;

/// Relay real path of an inner connection: one UDP channel of the gateway
/// session. Never blocks; a packet that cannot be sent is dropped (QUIC
/// recovers) and counted by the session's datagram counters.
pub struct ChannelLink {
    shared: Weak<SessionShared>,
    chan_id: u64,
    pub sent: AtomicU64,
}

impl RelayLink for ChannelLink {
    fn send(&self, packet: &[u8]) {
        if let Some(s) = self.shared.upgrade() {
            self.sent.fetch_add(1, Ordering::Relaxed);
            s.send_datagram(self.chan_id, packet);
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
}

impl JumpPath {
    /// The socket for the inner endpoint.
    pub fn socket(&self) -> Arc<dyn AsyncUdpSocket> {
        self.mgr.socket()
    }

    /// Socket factory for the inner session's rebinds and resumes: a new
    /// incarnation of the same path socket (the real path is the relay and
    /// is replaced through the path manager, never around it).
    pub fn socket_factory(&self) -> SocketFactory {
        let mgr = self.mgr.clone();
        Arc::new(move || Ok(mgr.socket() as Arc<dyn AsyncUdpSocket>))
    }

    /// Packets sent over the relay route so far.
    pub fn relayed(&self) -> u64 {
        self.link.sent.load(Ordering::Relaxed)
    }
}

impl ClientSession {
    /// Open a relay route to `host:port` through this session (the gateway):
    /// a UDP channel the gateway forwards to the target. The returned path
    /// carries an inner QUIC connection; dial `virt` on `socket()`.
    pub async fn jump(&self, host: &str, port: u16) -> Result<JumpPath> {
        let s = &self.shared;
        let (tx, mut rx) = mpsc::channel::<Bytes>(s.limits.udp_queue);
        let ext = crate::sesschan::ChanExt::Udp(UdpExt::new(tx, s.stats.clone()));
        let ch = s
            .open_channel(ChannelKind::DirectUdp { host: host.to_string(), port }, 0, Completion::Manual, Some(ext))
            .await?;
        let io = udp_socket(transport::dual_stack_socket(transport::unspecified_dual())?)?;
        let mgr = PathManager::new(io);
        let link = Arc::new(ChannelLink { shared: Arc::downgrade(s), chan_id: ch.chan_id, sent: AtomicU64::new(0) });
        let (route, virt) = mgr.add_relay_route(link.clone());
        let m2 = mgr.clone();
        // Owned by the channel: it ends when the channel does.
        ch.spawn(async move {
            while let Some(d) = rx.recv().await {
                m2.relay_input(route, d);
            }
        });
        Ok(JumpPath { mgr, route, virt, link, chan_id: ch.chan_id })
    }
}
