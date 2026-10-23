//! UDP relay with a constant one-way delay (copied from quic-probe X2's
//! `pipe`, loss removed): gives tests a real RTT on loopback.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

fn pipe(from: Arc<UdpSocket>, to_sock: Arc<UdpSocket>, dest: Arc<Mutex<Option<SocketAddr>>>, learn: Option<Arc<Mutex<Option<SocketAddr>>>>, delay: Duration) {
    let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, src)) = from.recv_from(&mut buf).await {
            if let Some(l) = &learn {
                *l.lock().unwrap() = Some(src);
            }
            if tx.send((Instant::now() + delay, buf[..n].to_vec())).is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Some((at, pkt)) = rx.recv().await {
            tokio::time::sleep_until(at).await;
            let d = *dest.lock().unwrap();
            if let Some(d) = d {
                let _ = to_sock.send_to(&pkt, d).await;
            }
        }
    });
}

/// Start a relay to `server`; clients connect to the returned address.
pub async fn relay(server: SocketAddr, rtt: Duration) -> SocketAddr {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let srv = Arc::new(Mutex::new(Some(server)));
    let cli = Arc::new(Mutex::new(None));
    pipe(front.clone(), back.clone(), srv, Some(cli.clone()), rtt / 2);
    pipe(back, front.clone(), cli, None, rtt / 2);
    front.local_addr().unwrap()
}
