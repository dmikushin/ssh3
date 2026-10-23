//! Wire formats of the path layer.
//!
//! Two kinds of messages exist:
//!
//! * **Side-channel datagrams** travel on the same UDP socket as QUIC (SPEC §7.3 step 2). Their
//!   first byte has the QUIC fixed bit (0x40) clear, which is how the path socket tells them apart
//!   from QUIC packets (E3c; requires `EndpointConfig::grease_quic_bit(false)` on every endpoint
//!   sharing the socket). Punch checks and responses are authenticated with a truncated
//!   HMAC-SHA256 keyed from the inner connection's TLS exporter.
//! * **Signals** (candidate exchange, nomination) travel reliably over the authenticated inner
//!   connection; the caller ships the encoded bytes and feeds received ones back in.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ring::hmac;

/// Side-channel type: connectivity check (punch).
pub const T_PUNCH: u8 = 0x01;
/// Side-channel type: response to a punch.
pub const T_RESP: u8 = 0x02;
/// Lowest side-channel type reserved for users of the socket other than the path manager
/// (e.g. a test relay). Everything from here up to 0x3f is handed to the extra side sink.
pub const T_EXTRA_MIN: u8 = 0x10;

pub const TAG_LEN: usize = 8;
pub const NONCE_LEN: usize = 16;
pub const MAC_LEN: usize = 16;
const MAC_LABEL: &[u8] = b"ssh3-path punch v0";

/// True for datagrams that are not QUIC packets (fixed bit clear).
pub fn is_side_channel(first: u8) -> bool {
    first & 0x40 == 0
}

/// Per-inner-connection punch key. Both peers derive the same 32 bytes from the inner
/// connection's TLS exporter (label [`EXPORTER_LABEL`]), so a key binds punches to one session
/// and one pair of authenticated peers.
#[derive(Clone)]
pub struct PunchKey {
    key: hmac::Key,
    tag: [u8; TAG_LEN],
}

/// TLS exporter label the caller uses to derive [`PunchKey`] material.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-ssh3-rs-path-punch";

impl PunchKey {
    pub fn new(secret: &[u8; 32]) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        let t = hmac::sign(&key, b"ssh3-path tag");
        let mut tag = [0; TAG_LEN];
        tag.copy_from_slice(&t.as_ref()[..TAG_LEN]);
        Self { key, tag }
    }
    /// Demultiplexing tag carried in every punch datagram of this connection.
    pub fn tag(&self) -> [u8; TAG_LEN] {
        self.tag
    }
    fn mac(&self, body: &[u8]) -> [u8; MAC_LEN] {
        let mut ctx = hmac::Context::with_key(&self.key);
        ctx.update(MAC_LABEL);
        ctx.update(body);
        let t = ctx.sign();
        let mut m = [0; MAC_LEN];
        m.copy_from_slice(&t.as_ref()[..MAC_LEN]);
        m
    }
    fn verify(&self, body: &[u8], mac: &[u8]) -> bool {
        let mut ctx = hmac::Context::with_key(&self.key);
        ctx.update(MAC_LABEL);
        ctx.update(body);
        let full = ctx.sign();
        mac.len() == MAC_LEN && full.as_ref()[..MAC_LEN].iter().zip(mac).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }
}

/// Role byte: the controlling peer nominates (SPEC §7.3 step 3).
pub const ROLE_CONTROLLED: u8 = 0;
pub const ROLE_CONTROLLING: u8 = 1;

/// Purpose of a punch.
pub const KIND_CHECK: u8 = 0;
pub const KIND_KEEPALIVE: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Punch {
    pub tag: [u8; TAG_LEN],
    pub generation: u32,
    pub nonce: [u8; NONCE_LEN],
    pub role: u8,
    pub kind: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resp {
    pub tag: [u8; TAG_LEN],
    pub generation: u32,
    /// Echo of the punch nonce this answers.
    pub nonce: [u8; NONCE_LEN],
    pub role: u8,
    /// The source address the responder saw the punch come from (peer-reflexive address of the
    /// requester).
    pub observed: SocketAddr,
}

/// Length of an encoded punch.
pub const PUNCH_LEN: usize = 1 + TAG_LEN + 4 + NONCE_LEN + 1 + 1 + MAC_LEN;

pub fn encode_punch(k: &PunchKey, p: &Punch) -> Vec<u8> {
    let mut b = Vec::with_capacity(PUNCH_LEN);
    b.push(T_PUNCH);
    b.extend_from_slice(&p.tag);
    b.extend_from_slice(&p.generation.to_be_bytes());
    b.extend_from_slice(&p.nonce);
    b.push(p.role);
    b.push(p.kind);
    let m = k.mac(&b);
    b.extend_from_slice(&m);
    b
}

pub fn encode_resp(k: &PunchKey, r: &Resp) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.push(T_RESP);
    b.extend_from_slice(&r.tag);
    b.extend_from_slice(&r.generation.to_be_bytes());
    b.extend_from_slice(&r.nonce);
    b.push(r.role);
    put_addr(&mut b, r.observed);
    let m = k.mac(&b);
    b.extend_from_slice(&m);
    b
}

/// Extract the demultiplexing tag of a punch/resp datagram without authenticating it.
pub fn peek_tag(d: &[u8]) -> Option<[u8; TAG_LEN]> {
    if d.len() < 1 + TAG_LEN || !(d[0] == T_PUNCH || d[0] == T_RESP) {
        return None;
    }
    let mut t = [0; TAG_LEN];
    t.copy_from_slice(&d[1..1 + TAG_LEN]);
    Some(t)
}

#[derive(Debug, PartialEq, Eq)]
pub enum SideMsg {
    Punch(Punch),
    Resp(Resp),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DecodeError {
    Malformed,
    BadMac,
}

pub fn decode_side(k: &PunchKey, d: &[u8]) -> Result<SideMsg, DecodeError> {
    if d.len() < 1 + TAG_LEN + 4 + NONCE_LEN + 1 + MAC_LEN {
        return Err(DecodeError::Malformed);
    }
    let (body, mac) = d.split_at(d.len() - MAC_LEN);
    let mut r = Reader { b: body, i: 1 };
    let mut tag = [0; TAG_LEN];
    tag.copy_from_slice(r.take(TAG_LEN)?);
    let generation = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
    let mut nonce = [0; NONCE_LEN];
    nonce.copy_from_slice(r.take(NONCE_LEN)?);
    let role = r.u8()?;
    let msg = match body[0] {
        T_PUNCH => {
            let kind = r.u8()?;
            SideMsg::Punch(Punch { tag, generation, nonce, role, kind })
        }
        T_RESP => {
            let observed = r.addr()?;
            SideMsg::Resp(Resp { tag, generation, nonce, role, observed })
        }
        _ => return Err(DecodeError::Malformed),
    };
    if r.i != body.len() {
        return Err(DecodeError::Malformed);
    }
    if !k.verify(body, mac) {
        return Err(DecodeError::BadMac);
    }
    Ok(msg)
}

/// Signals exchanged over the inner connection (reliable, ordered).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// Start (controlling → controlled) or answer (controlled → controlling) punch round
    /// `generation` with the sender's candidates (≤ `MAX_CANDIDATES`).
    Candidates { generation: u32, candidates: Vec<SocketAddr> },
    /// Controlling peer nominates the pair: it will send to `you_are_at`; the controlled peer
    /// must have validated `i_am_at` (its view of the controlling peer) before acknowledging.
    Nominate { generation: u32, you_are_at: SocketAddr, i_am_at: SocketAddr },
    NominateAck { generation: u32 },
    /// Controlled peer has not (yet) validated the nominated pair.
    NominateNak { generation: u32 },
    /// Controlled peer asks for a new round (its socket or relay changed).
    Restart,
}

/// At most this many candidates per peer (SPEC §7.1 `MaxCandidates`).
pub const MAX_CANDIDATES: usize = 8;
/// Upper bound of an encoded signal, checked before decoding (SPEC I1).
pub const MAX_SIGNAL_LEN: usize = 1 + 4 + 1 + MAX_CANDIDATES * 19 + 64;

pub fn encode_signal(s: &Signal) -> Vec<u8> {
    let mut b = Vec::new();
    match s {
        Signal::Candidates { generation, candidates } => {
            b.push(1);
            b.extend_from_slice(&generation.to_be_bytes());
            let n = candidates.len().min(MAX_CANDIDATES);
            b.push(n as u8);
            for c in &candidates[..n] {
                put_addr(&mut b, *c);
            }
        }
        Signal::Nominate { generation, you_are_at, i_am_at } => {
            b.push(2);
            b.extend_from_slice(&generation.to_be_bytes());
            put_addr(&mut b, *you_are_at);
            put_addr(&mut b, *i_am_at);
        }
        Signal::NominateAck { generation } => {
            b.push(3);
            b.extend_from_slice(&generation.to_be_bytes());
        }
        Signal::NominateNak { generation } => {
            b.push(4);
            b.extend_from_slice(&generation.to_be_bytes());
        }
        Signal::Restart => b.push(5),
    }
    b
}

pub fn decode_signal(d: &[u8]) -> Result<Signal, DecodeError> {
    if d.is_empty() || d.len() > MAX_SIGNAL_LEN {
        return Err(DecodeError::Malformed);
    }
    let mut r = Reader { b: d, i: 1 };
    let s = match d[0] {
        1 => {
            let generation = r.u32()?;
            let n = r.u8()? as usize;
            if n > MAX_CANDIDATES {
                return Err(DecodeError::Malformed);
            }
            let mut candidates = Vec::with_capacity(n);
            for _ in 0..n {
                candidates.push(r.addr()?);
            }
            Signal::Candidates { generation, candidates }
        }
        2 => Signal::Nominate { generation: r.u32()?, you_are_at: r.addr()?, i_am_at: r.addr()? },
        3 => Signal::NominateAck { generation: r.u32()? },
        4 => Signal::NominateNak { generation: r.u32()? },
        5 => Signal::Restart,
        _ => return Err(DecodeError::Malformed),
    };
    if r.i != d.len() {
        return Err(DecodeError::Malformed);
    }
    Ok(s)
}

fn put_addr(b: &mut Vec<u8>, a: SocketAddr) {
    match a.ip() {
        IpAddr::V4(v4) => {
            b.push(4);
            b.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            b.push(6);
            b.extend_from_slice(&v6.octets());
        }
    }
    b.extend_from_slice(&a.port().to_be_bytes());
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let s = self.b.get(self.i..self.i + n).ok_or(DecodeError::Malformed)?;
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn addr(&mut self) -> Result<SocketAddr, DecodeError> {
        let ip = match self.u8()? {
            4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(self.take(4)?).unwrap())),
            6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(self.take(16)?).unwrap())),
            _ => return Err(DecodeError::Malformed),
        };
        let port = u16::from_be_bytes(self.take(2)?.try_into().unwrap());
        Ok(SocketAddr::new(ip, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punch_roundtrip_and_tamper() {
        let k = PunchKey::new(&[7; 32]);
        let p = Punch { tag: k.tag(), generation: 9, nonce: [3; 16], role: 1, kind: KIND_CHECK };
        let mut d = encode_punch(&k, &p);
        assert_eq!(d.len(), PUNCH_LEN);
        assert!(is_side_channel(d[0]));
        assert_eq!(decode_side(&k, &d), Ok(SideMsg::Punch(p)));
        let other = PunchKey::new(&[8; 32]);
        assert_eq!(decode_side(&other, &d), Err(DecodeError::BadMac));
        d[10] ^= 1;
        assert_eq!(decode_side(&k, &d), Err(DecodeError::BadMac));
    }

    #[test]
    fn resp_and_signals_roundtrip() {
        let k = PunchKey::new(&[1; 32]);
        let r = Resp {
            tag: k.tag(),
            generation: 2,
            nonce: [5; 16],
            role: 0,
            observed: "198.51.100.7:4000".parse().unwrap(),
        };
        assert_eq!(decode_side(&k, &encode_resp(&k, &r)), Ok(SideMsg::Resp(r)));
        for s in [
            Signal::Candidates {
                generation: 4,
                candidates: vec!["10.0.0.1:5".parse().unwrap(), "[2001:db8::1]:7".parse().unwrap()],
            },
            Signal::Nominate {
                generation: 4,
                you_are_at: "1.2.3.4:5".parse().unwrap(),
                i_am_at: "5.6.7.8:9".parse().unwrap(),
            },
            Signal::NominateAck { generation: 4 },
            Signal::NominateNak { generation: 4 },
            Signal::Restart,
        ] {
            assert_eq!(decode_signal(&encode_signal(&s)), Ok(s));
        }
        assert_eq!(decode_signal(&[1, 0, 0, 0, 1, 9]), Err(DecodeError::Malformed));
    }
}
