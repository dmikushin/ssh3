//! A socket wrapper that can silently drop all traffic in both directions (network outage /
//! laptop suspend simulation) while the endpoint keeps running.
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};

pub struct Blackhole {
    inner: Arc<dyn AsyncUdpSocket>,
    pub down: AtomicBool,
    /// Shared by every socket of one simulated network.
    net: Option<Arc<AtomicBool>>,
    /// Non-zero: every send fails with this errno (ENETUNREACH, EHOSTUNREACH,
    /// ECONNREFUSED: a laptop whose network is gone or refuses), handled as a
    /// real quinn socket handles it: quinn-udp's `UdpSocketState::send` logs a
    /// send error and reports success (quinn-udp 0.5.16 src/unix.rs:207-219),
    /// so the packet is lost and QUIC's timers decide. Returning the error
    /// instead would end quinn's ConnectionDriver without closing the
    /// connection (vendor/quinn connection.rs:267, `drive_transmit(cx)?`):
    /// `closed()` would never resolve and the session would never detach.
    errno: Option<Arc<AtomicI32>>,
    pub send_errors: AtomicU64,
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
        Self::on_network_err(sock, net, None)
    }
    pub fn on_network_err(sock: UdpSocket, net: Option<Arc<AtomicBool>>, errno: Option<Arc<AtomicI32>>) -> Arc<Self> {
        Arc::new(Self {
            inner: TokioRuntime.wrap_udp_socket(sock).unwrap(),
            down: AtomicBool::new(false),
            net,
            errno,
            send_errors: AtomicU64::new(0),
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
        if let Some(e) = &self.errno {
            let e = e.load(Ordering::SeqCst);
            if e != 0 {
                self.send_errors.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("test socket: sendmsg failed: {}", io::Error::from_raw_os_error(e));
                return Ok(());
            }
        }
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
