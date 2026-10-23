//! -D SOCKS5: CONNECT (IP and domain), refusal codes, UDP ASSOCIATE.
mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const LIMIT: Duration = Duration::from_secs(10);

async fn socks_server(c: &ssh3_core::ClientSession) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    c.forward_dynamic(l);
    a
}

/// Greeting + request; returns the stream and the reply code.
async fn request(socks: SocketAddr, cmd: u8, addr: &[u8]) -> (TcpStream, u8, Vec<u8>) {
    let mut s = TcpStream::connect(socks).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    let mut req = vec![5, cmd, 0];
    req.extend_from_slice(addr);
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 4];
    tokio::time::timeout(LIMIT, s.read_exact(&mut rep)).await.expect("no SOCKS reply").unwrap();
    let rest = match rep[3] {
        1 => 6,
        4 => 18,
        a => panic!("unexpected bound ATYP {a}"),
    };
    let mut bound = vec![0u8; rest];
    s.read_exact(&mut bound).await.unwrap();
    (s, rep[1], bound)
}

fn v4(a: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(a) = a else { panic!("v4 expected") };
    let mut v = vec![1];
    v.extend_from_slice(&a.ip().octets());
    v.extend_from_slice(&a.port().to_be_bytes());
    v
}

fn name(h: &str, port: u16) -> Vec<u8> {
    let mut v = vec![3, h.len() as u8];
    v.extend_from_slice(h.as_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_by_ip_and_by_name() {
    let env = env_with(fast_limits());
    let c = env.client().await;
    let socks = socks_server(&c).await;
    let echo = echo_server().await;
    for addr in [v4(echo), name("localhost", echo.port())] {
        let (mut s, rep, _) = request(socks, 1, &addr).await;
        assert_eq!(rep, 0);
        s.write_all(b"through socks").await.unwrap();
        let mut b = [0u8; 13];
        tokio::time::timeout(LIMIT, s.read_exact(&mut b)).await.unwrap().unwrap();
        assert_eq!(&b, b"through socks");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_refused_and_unsupported_command() {
    let env = env_with(fast_limits());
    let c = env.client().await;
    let socks = socks_server(&c).await;
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let (_s, rep, _) = request(socks, 1, &v4(dead)).await;
    assert_eq!(rep, 5, "connection refused");
    let (_s, rep, _) = request(socks, 2, &v4(dead)).await;
    assert_eq!(rep, 7, "BIND is not supported");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_associate_relays_and_ends_with_the_control_connection() {
    let env = env_with(fast_limits());
    let c = env.client().await;
    let socks = socks_server(&c).await;
    let echo = {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = s.recv_from(&mut buf).await {
                let _ = s.send_to(&buf[..n], from).await;
            }
        });
        a
    };
    let (ctl, rep, bound) = request(socks, 3, &v4("0.0.0.0:0".parse().unwrap())).await;
    assert_eq!(rep, 0);
    let relay = SocketAddr::new(std::net::Ipv4Addr::new(bound[0], bound[1], bound[2], bound[3]).into(), u16::from_be_bytes([bound[4], bound[5]]));
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut dgram = vec![0, 0, 0];
    dgram.extend_from_slice(&v4(echo));
    dgram.extend_from_slice(b"udp via socks");
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Instant::now() + LIMIT;
    let n = loop {
        app.send_to(&dgram, relay).await.unwrap();
        if let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_millis(200), app.recv_from(&mut buf)).await {
            break n;
        }
        assert!(tokio::time::Instant::now() < deadline, "no UDP reply through SOCKS");
    };
    // Reply carries the SOCKS UDP header naming the echo as its source.
    assert_eq!(&buf[..3], &[0, 0, 0]);
    assert_eq!(&buf[3..10], &v4(echo)[..]);
    assert_eq!(&buf[10..n], b"udp via socks");
    assert_eq!(env.server.stats().udp_flows, 1);
    drop(ctl);
    wait_until("association ended", LIMIT, || env.server.stats().udp_flows == 0, || format!("{:?}", env.server.stats())).await;
}
