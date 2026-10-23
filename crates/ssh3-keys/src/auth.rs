//! The user-authentication signature of SPEC §2.2.
//!
//! ```text
//! blob = "ssh3-rs auth v0" || exporter(32) || str(user) || str(pubkey_blob) || str(intent)
//! str(x) = u32 big-endian length || x
//! ```
//! `pubkey_blob` is the OpenSSH wire encoding of the public key. Both sides
//! build the blob from their own TLS exporter; only `user`, the key and
//! `intent` come from the client.

use signature::Verifier;
use ssh_encoding::Encode;
use ssh_key::{PublicKey, Signature};

use crate::signer::Signer;
use crate::{Error, Result};

pub const AUTH_CONTEXT: &[u8] = b"ssh3-rs auth v0";
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-ssh3-rs-auth";
pub const EXPORTER_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    New,
    Resume,
}

impl Intent {
    pub fn as_str(self) -> &'static str {
        match self {
            Intent::New => "new",
            Intent::Resume => "resume",
        }
    }
}

fn put_str(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// The OpenSSH wire encoding of a public key (string type || key fields).
pub fn pubkey_blob(key: &PublicKey) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    key.key_data().encode(&mut v)?;
    Ok(v)
}

pub fn auth_blob(exporter: &[u8; EXPORTER_LEN], user: &str, key: &PublicKey, intent: Intent) -> Result<Vec<u8>> {
    let pk = pubkey_blob(key)?;
    let mut out = Vec::with_capacity(AUTH_CONTEXT.len() + EXPORTER_LEN + 12 + user.len() + pk.len() + 6);
    out.extend_from_slice(AUTH_CONTEXT);
    out.extend_from_slice(exporter);
    put_str(&mut out, user.as_bytes());
    put_str(&mut out, &pk);
    put_str(&mut out, intent.as_str().as_bytes());
    Ok(out)
}

/// Client side: sign the blob. Returns the signature in SSH wire encoding.
pub fn sign_auth(signer: &dyn Signer, exporter: &[u8; EXPORTER_LEN], user: &str, intent: Intent) -> Result<Vec<u8>> {
    let blob = auth_blob(exporter, user, signer.public_key(), intent)?;
    let sig = signer.sign(&blob)?;
    let mut out = Vec::new();
    sig.encode(&mut out)?;
    Ok(out)
}

/// Server side: parse the client's key, rebuild the blob from the server's
/// own exporter, verify. Returns the verified key (authorization against
/// authorized_keys is the caller's next step).
pub fn verify_auth(
    exporter: &[u8; EXPORTER_LEN],
    user: &str,
    pubkey_blob: &[u8],
    intent: Intent,
    signature: &[u8],
) -> Result<PublicKey> {
    let key = PublicKey::from_bytes(pubkey_blob).map_err(|e| Error::AuthVerify(format!("public key: {e}")))?;
    use ssh_encoding::Decode;
    let sig = Signature::decode(&mut &signature[..]).map_err(|e| Error::AuthVerify(format!("signature encoding: {e}")))?;
    let blob = auth_blob(exporter, user, &key, intent)?;
    Verifier::verify(&key, &blob, &sig)
        .map_err(|e| Error::AuthVerify(format!("{} signature does not verify: {e}", sig.algorithm())))?;
    Ok(key)
}
