//! `-D`: a SOCKS5 server on the client (RFC 1928, no authentication).
//! CONNECT becomes a direct-tcp channel; UDP ASSOCIATE relays each
//! destination as a direct-udp flow (bounded like every UDP flow table,
//! SPEC §6) for as long as its TCP control connection stays open.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::error::Error;
use crate::msg::{ChannelKind, FailReason};
use crate::session::{Completion, SessionShared};
use crate::udp::{MAX_UDP_PAYLOAD, UdpExt};

const VER: u8 = 5;
const REP_OK: u8 = 0;
const REP_FAIL: u8 = 1;
const REP_NOT_ALLOWED: u8 = 2;
const REP_REFUSED: u8 = 5;
const REP_CMD: u8 = 7;
const REP_ATYP: u8 = 8;

/// A SOCKS address: an IP or a domain name, with a port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Target {
    Ip(SocketAddr),
    Name(String, u16),
}

impl Target {
    fn host_port(&self) -> (String, u16) {
        match self {
            Target::Ip(a) => (a.ip().to_string(), a.port()),
            Target::Name(h, p) => (h.clone(), *p),
        }
    }
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Target::Ip(SocketAddr::V4(a)) => {
                out.push(1);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            Target::Ip(SocketAddr::V6(a)) => {
                out.push(4);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            Target::Name(h, p) => {
                out.push(3);
                out.push(h.len() as u8);
                out.extend_from_slice(h.as_bytes());
                out.extend_from_slice(&p.to_be_bytes());
            }
        }
    }
}

/// Parse ATYP + address + port from `b`; returns the target and its length.
fn parse_target(b: &[u8]) -> Option<(Target, usize)> {
    let port = |i: usize| b.get(i..i + 2).map(|p| u16::from_be_bytes([p[0], p[1]]));
    match *b.first()? {
        1 => {
            let ip: [u8; 4] = b.get(1..5)?.try_into().ok()?;
            Some((Target::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port(5)?)), 7))
        }
        4 => {
            let ip: [u8; 16] = b.get(1..17)?.try_into().ok()?;
            Some((Target::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port(17)?)), 19))
        }
        3 => {
            let n = *b.get(1)? as usize;
            let name = std::str::from_utf8(b.get(2..2 + n)?).ok()?.to_string();
            Some((Target::Name(name, port(2 + n)?), 4 + n))
        }
        _ => None,
    }
}

async fn reply(tcp: &mut TcpStream, rep: u8, bound: SocketAddr) -> std::io::Result<()> {
    let mut out = vec![VER, rep, 0];
    Target::Ip(bound).encode(&mut out);
    tcp.write_all(&out).await
}

fn rep_for(e: &Error) -> u8 {
    match e {
        Error::Refused(FailReason::ConnectFailed(_)) => REP_REFUSED,
        Error::Refused(FailReason::Prohibited) => REP_NOT_ALLOWED,
        _ => REP_FAIL,
    }
}

impl SessionShared {
    /// `-D`: serve SOCKS5 on `listener`.
    pub fn forward_dynamic(self: &Arc<Self>, listener: TcpListener) -> tokio::task::JoinHandle<()> {
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = listener.accept().await {
                let me = me.clone();
                tokio::spawn(async move {
                    if let Err(e) = socks_conn(me, tcp).await {
                        tracing::debug!(%peer, "socks: {e}");
                    }
                });
            }
        })
    }
}

async fn socks_conn(me: Weak<SessionShared>, mut tcp: TcpStream) -> std::io::Result<()> {
    let unspecified: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut head = [0u8; 2];
    tcp.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(std::io::Error::other(format!("not SOCKS5 (version {})", head[0])));
    }
    let mut methods = vec![0u8; head[1] as usize];
    tcp.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        tcp.write_all(&[VER, 0xff]).await?;
        return Ok(());
    }
    tcp.write_all(&[VER, 0]).await?;
    // VER CMD RSV, then the address: read the fixed part, then the rest by ATYP.
    let mut req = [0u8; 4];
    tcp.read_exact(&mut req).await?;
    let mut addr = vec![req[3]];
    match req[3] {
        1 => addr.resize(1 + 6, 0),
        4 => addr.resize(1 + 18, 0),
        3 => {
            let mut n = [0u8; 1];
            tcp.read_exact(&mut n).await?;
            addr.push(n[0]);
            addr.resize(2 + n[0] as usize + 2, 0);
        }
        _ => return reply(&mut tcp, REP_ATYP, unspecified).await,
    }
    let start = if req[3] == 3 { 2 } else { 1 };
    tcp.read_exact(&mut addr[start..]).await?;
    let (target, _) = parse_target(&addr).ok_or_else(|| std::io::Error::other("bad SOCKS address"))?;
    let Some(s) = me.upgrade() else { return Ok(()) };
    match req[1] {
        1 => {
            // CONNECT: answer once the server has dialed, then bridge.
            let (host, port) = target.host_port();
            match s.open_channel(ChannelKind::DirectTcp { host, port }, 1, Completion::AllLanes, None).await {
                Ok(ch) => {
                    reply(&mut tcp, REP_OK, unspecified).await?;
                    s.start_tcp(&ch, tcp);
                    if let Err(e) = s.open_lane(&ch.lanes[0]).await {
                        tracing::debug!(chan = ch.chan_id, "lane not opened now ({e}); the next resume will");
                    }
                    Ok(())
                }
                Err(e) => reply(&mut tcp, rep_for(&e), unspecified).await,
            }
        }
        3 => udp_associate(s, tcp).await,
        _ => reply(&mut tcp, REP_CMD, unspecified).await,
    }
}

struct Assoc {
    chan: Option<u64>,
    last: Instant,
}

/// UDP ASSOCIATE: relay on the control connection's local IP; one
/// direct-udp flow per destination, bounded (count/LRU/idle); ends with the
/// TCP control connection.
async fn udp_associate(s: Arc<SessionShared>, mut tcp: TcpStream) -> std::io::Result<()> {
    let local_ip = tcp.local_addr()?.ip();
    let peer_ip = tcp.peer_addr()?.ip();
    let relay = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    reply(&mut tcp, REP_OK, relay.local_addr()?).await?;
    let (cap, idle) = (s.limits.udp_flows_max, s.limits.udp_flow_idle);
    let flows: Arc<Mutex<HashMap<Target, Assoc>>> = Arc::new(Mutex::new(HashMap::new()));
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let me = Arc::downgrade(&s);
    drop(s);
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
    let mut eof = [0u8; 1];
    let mut sweep = tokio::time::interval(idle / 4);
    let mut channels: Vec<u64> = Vec::new();
    let result = loop {
        tokio::select! {
            // The association lives as long as the TCP control connection.
            r = tcp.read(&mut eof) => match r {
                Ok(0) | Err(_) => break Ok(()),
                Ok(_) => continue,
            },
            _ = sweep.tick() => {
                let expired: Vec<u64> = {
                    let mut f = flows.lock().unwrap();
                    let gone: Vec<Target> = f.iter().filter(|(_, a)| a.last.elapsed() > idle).map(|(t, _)| t.clone()).collect();
                    gone.into_iter().filter_map(|t| f.remove(&t).and_then(|a| a.chan)).collect()
                };
                if let Some(s) = me.upgrade() {
                    for c in expired {
                        s.abort_channel(c, "socks udp flow idle".into()).await;
                    }
                }
            }
            r = relay.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { break Ok(()) };
                // Only the TCP client's host may use the relay (RFC 1928 §7).
                if from.ip() != peer_ip {
                    continue;
                }
                *client.lock().unwrap() = Some(from);
                let d = &buf[..n];
                // RSV RSV FRAG ATYP ...; fragmentation is not supported: drop.
                if d.len() < 4 || d[2] != 0 {
                    continue;
                }
                let Some((target, len)) = parse_target(&d[3..]) else { continue };
                let payload = d[3 + len..].to_vec();
                let Some(s) = me.upgrade() else { break Ok(()) };
                let known = flows.lock().unwrap().get_mut(&target).map(|a| { a.last = Instant::now(); a.chan });
                match known {
                    Some(Some(c)) => {
                        s.send_datagram(c, &payload);
                    }
                    Some(None) => {
                        s.stats.dgrams_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    None => {
                        let evict = {
                            let mut f = flows.lock().unwrap();
                            let mut ev = None;
                            if f.len() >= cap && let Some(t) = f.iter().min_by_key(|(_, a)| a.last).map(|(t, _)| t.clone()) {
                                ev = f.remove(&t).and_then(|a| a.chan);
                                s.stats.udp_evicted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            f.insert(target.clone(), Assoc { chan: None, last: Instant::now() });
                            ev
                        };
                        if let Some(c) = evict {
                            s.abort_channel(c, "socks udp flow evicted (LRU)".into()).await;
                        }
                        let (relay2, client2, flows2) = (relay.clone(), client.clone(), flows.clone());
                        let (tx, mut rx) = mpsc::channel::<Bytes>(s.limits.udp_queue);
                        let (host, port) = target.host_port();
                        let ext = crate::sesschan::ChanExt::Udp(UdpExt::new(tx, s.stats.clone()));
                        match s.open_channel(ChannelKind::DirectUdp { host, port }, 0, Completion::Manual, Some(ext)).await {
                            Ok(ch) => {
                                let c = ch.chan_id;
                                channels.push(c);
                                if let Some(a) = flows2.lock().unwrap().get_mut(&target) {
                                    a.chan = Some(c);
                                }
                                s.send_datagram(c, &payload);
                                let mut head = vec![0, 0, 0];
                                target.encode(&mut head);
                                ch.spawn(async move {
                                    while let Some(d) = rx.recv().await {
                                        let Some(to) = *client2.lock().unwrap() else { continue };
                                        let mut out = head.clone();
                                        out.extend_from_slice(&d);
                                        let _ = relay2.send_to(&out, to).await;
                                    }
                                });
                            }
                            Err(e) => {
                                flows.lock().unwrap().remove(&target);
                                tracing::debug!("socks udp flow not opened: {e}");
                            }
                        }
                    }
                }
            }
        }
    };
    // Control connection gone: end every flow of this association.
    if let Some(s) = me.upgrade() {
        for c in channels {
            s.abort_channel(c, "socks udp association ended".into()).await;
        }
    }
    result
}
