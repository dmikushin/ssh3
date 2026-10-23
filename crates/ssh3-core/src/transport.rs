//! QUIC transport setup (SPEC §1, §5.1).

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::path::Path;
use std::sync::Arc;

use quinn::congestion::BbrConfig;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{EndpointConfig, IdleTimeout, TransportConfig, VarInt};
use quinn_proto::HashedConnectionIdGenerator;
use rand::RngCore;

use crate::error::{Error, Result};
use crate::limits::Limits;

pub const ALPN: &[u8] = b"ssh3-rs/0";

pub fn transport_config(l: &Limits) -> TransportConfig {
    let mut tc = TransportConfig::default();
    tc.congestion_controller_factory(Arc::new(BbrConfig::default()));
    tc.receive_window(VarInt::from_u64(l.floor_window).expect("floor window fits a varint"));
    tc.send_window(l.floor_window);
    tc.stream_receive_window(VarInt::from_u64(l.stream_receive_window).expect("stream window fits a varint"));
    tc.max_concurrent_bidi_streams(VarInt::from_u32(l.max_bidi_streams));
    tc.max_concurrent_uni_streams(VarInt::from_u32(0));
    tc.datagram_receive_buffer_size(Some(l.datagram_buffer));
    tc.datagram_send_buffer_size(l.datagram_buffer);
    tc.max_idle_timeout(Some(IdleTimeout::try_from(l.idle_timeout).expect("idle timeout within QUIC range")));
    tc.keep_alive_interval(Some(l.keep_alive));
    tc
}

/// Endpoint secrets that must survive restarts so clients learn of a server
/// restart by stateless reset instead of waiting for idle timeout (SPEC §1,
/// X5: 1.35 ms with persisted keys).
#[derive(Clone)]
pub struct EndpointKeys {
    pub reset_key: [u8; 32],
    pub cid_key: u64,
}

impl EndpointKeys {
    pub fn random() -> Self {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        Self { reset_key: k, cid_key: rand::thread_rng().next_u64() }
    }

    /// 40-byte file: reset key then cid key (LE). Created with mode 0600.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(b) if b.len() == 40 => {
                let mut reset_key = [0u8; 32];
                reset_key.copy_from_slice(&b[..32]);
                let cid_key = u64::from_le_bytes(b[32..].try_into().unwrap());
                Ok(Self { reset_key, cid_key })
            }
            Ok(b) => Err(Error::Protocol(format!(
                "endpoint key file {} has {} bytes, expected 40",
                path.display(),
                b.len()
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let k = Self::random();
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
                f.write_all(&k.reset_key)?;
                f.write_all(&k.cid_key.to_le_bytes())?;
                Ok(k)
            }
            Err(e) => Err(e.into()),
        }
    }
}

pub fn endpoint_config(keys: &EndpointKeys) -> EndpointConfig {
    let reset = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &keys.reset_key);
    let mut cfg = EndpointConfig::new(Arc::new(reset));
    let cid_key = keys.cid_key;
    cfg.cid_generator(move || Box::new(HashedConnectionIdGenerator::from_key(cid_key)));
    // Required for fixed-bit demultiplexing of punch packets (SPEC §1, E3c).
    cfg.grease_quic_bit(false);
    cfg
}

fn with_alpn_server(mut c: rustls::ServerConfig) -> rustls::ServerConfig {
    c.alpn_protocols = vec![ALPN.to_vec()];
    c
}

fn with_alpn_client(mut c: rustls::ClientConfig) -> rustls::ClientConfig {
    c.alpn_protocols = vec![ALPN.to_vec()];
    c
}

pub fn server_config(tls: rustls::ServerConfig, l: &Limits) -> Result<quinn::ServerConfig> {
    let q = QuicServerConfig::try_from(with_alpn_server(tls)).map_err(|e| Error::Tls(e.to_string()))?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(q));
    sc.transport_config(Arc::new(transport_config(l)));
    Ok(sc)
}

pub fn client_config(tls: rustls::ClientConfig, l: &Limits) -> Result<quinn::ClientConfig> {
    let q = QuicClientConfig::try_from(with_alpn_client(tls)).map_err(|e| Error::Tls(e.to_string()))?;
    let mut cc = quinn::ClientConfig::new(Arc::new(q));
    cc.transport_config(Arc::new(transport_config(l)));
    Ok(cc)
}

/// A dual-stack UDP socket (`IPV6_V6ONLY=0`). SPEC §5.1 / X1: every client
/// socket must be dual-stack, at connect and at every rebind, because quinn
/// compares peer addresses literally.
pub fn dual_stack_socket(bind: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(false)?;
    s.bind(&to_v6(bind).into())?;
    Ok(s.into())
}

/// Map a v4 address to its v4-mapped v6 form, leave v6 as is.
pub fn to_v6(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V4(v4) => SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0)),
        v6 => v6,
    }
}

pub fn unspecified_dual() -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
}
