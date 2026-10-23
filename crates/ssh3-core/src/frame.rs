//! Length-prefixed postcard frames (SPEC §3).
//!
//! The length is a LEB128 varint of at most 4 bytes and is checked against
//! the caller's cap **before** any buffer is allocated (SPEC §8 I1; Go ssh3
//! bug class 1: peer-sized allocation before auth).

use quinn::SendStream;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt};
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::msg::{MESSAGE_TYPES, Message};

/// Pre-auth control frames (SPEC §2.3).
pub const MAX_FRAME_PRE_AUTH: usize = 16 * 1024;
/// Control frames after auth (SPEC §3).
pub const MAX_FRAME: usize = 64 * 1024;
/// Lane headers are tiny.
pub const MAX_LANE_HEADER: usize = 64;

pub fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    let body = postcard::to_allocvec(v).expect("postcard encoding of an owned value cannot fail");
    let mut out = Vec::with_capacity(body.len() + 4);
    let mut n = body.len() as u32;
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
    out.extend_from_slice(&body);
    out
}

/// Read one frame body. `Ok(None)` on clean end of stream before a frame.
pub async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R, max: usize) -> Result<Option<Vec<u8>>> {
    let mut len: u64 = 0;
    for i in 0..4 {
        let mut b = [0u8; 1];
        match recv.read_exact(&mut b).await {
            Ok(_) => {}
            Err(e) if i == 0 && e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::Stream(format!("reading frame length: {e}"))),
        }
        len |= ((b[0] & 0x7f) as u64) << (7 * i);
        if b[0] & 0x80 == 0 {
            if len as usize > max {
                return Err(Error::Protocol(format!(
                    "frame length {len} exceeds cap {max}; refused before allocation"
                )));
            }
            let mut body = vec![0u8; len as usize];
            recv.read_exact(&mut body)
                .await
                .map_err(|e| Error::Stream(format!("reading frame body of {len} bytes: {e}")))?;
            return Ok(Some(body));
        }
    }
    Err(Error::Protocol("frame length varint longer than 4 bytes".into()))
}

pub fn decode_message(body: &[u8]) -> Result<Message> {
    // postcard encodes the enum discriminant as a varint u32 first.
    let mut ty: u32 = 0;
    for (i, b) in body.iter().take(5).enumerate() {
        ty |= ((b & 0x7f) as u32) << (7 * i);
        if b & 0x80 == 0 {
            break;
        }
    }
    if ty >= MESSAGE_TYPES {
        return Err(Error::Protocol(format!("unknown control message type {ty}")));
    }
    postcard::from_bytes(body)
        .map_err(|e| Error::Protocol(format!("malformed control message of type {ty}: {e}")))
}

pub fn decode<T: DeserializeOwned>(body: &[u8], what: &str) -> Result<T> {
    postcard::from_bytes(body).map_err(|e| Error::Protocol(format!("malformed {what}: {e}")))
}

pub async fn read_message<R: AsyncRead + Unpin>(recv: &mut R, max: usize) -> Result<Option<Message>> {
    match read_frame(recv, max).await? {
        None => Ok(None),
        Some(b) => decode_message(&b).map(Some),
    }
}

pub async fn write_message(send: &mut SendStream, m: &Message) -> Result<()> {
    send.write_all(&encode(m))
        .await
        .map_err(|e| Error::Stream(format!("writing control message: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_type_is_named() {
        // varint 200 = 0xc8 0x01
        let err = decode_message(&[0xc8, 0x01, 0, 0]).unwrap_err();
        assert!(err.to_string().contains("unknown control message type 200"), "{err}");
    }

    #[test]
    fn roundtrip() {
        let m = Message::LaneAck { chan_id: 7, lane: 1, accepted: 1 << 40, limit: 1 << 41, seq: 3 };
        let f = encode(&m);
        // strip the length prefix
        let mut i = 0;
        while f[i] & 0x80 != 0 {
            i += 1;
        }
        assert_eq!(decode_message(&f[i + 1..]).unwrap(), m);
    }
}
