//! A socket wrapper that can silently drop all traffic in both directions (network outage /
//! laptop suspend simulation) while the endpoint keeps running.
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};

pub struct Blackhole {
    inner: Arc<dyn AsyncUdpSocket>,
    pub down: AtomicBool,
    /// Shared by every socket of one simulated network.
    net: Option<Arc<AtomicBool>>,
    pub dropped_tx: AtomicU64,
    pub dropped_rx: AtomicU64,
}

impl fmt::Debug for Blackhole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Blackhole").finish_non_exhaustive()
    }
}

impl Blackhole {
    pub fn new(sock: UdpSocket) -> Arc<Self> {
        Self::on_network(sock, None)
    }
    pub fn on_network(sock: UdpSocket, net: Option<Arc<AtomicBool>>) -> Arc<Self> {
        Arc::new(Self {
            inner: TokioRuntime.wrap_udp_socket(sock).unwrap(),
            down: AtomicBool::new(false),
            net,
            dropped_tx: AtomicU64::new(0),
            dropped_rx: AtomicU64::new(0),
        })
    }
    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }
    fn is_down(&self) -> bool {
        self.down.load(Ordering::SeqCst) || self.net.as_ref().is_some_and(|n| n.load(Ordering::SeqCst))
    }
}

impl AsyncUdpSocket for Blackhole {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if self.is_down() {
            self.dropped_tx.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) if self.is_down() => {
                    self.dropped_rx.fetch_add(n as u64, Ordering::Relaxed);
                }
                other => return other,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
