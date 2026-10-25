//! User keys (SPEC §2.2): sign from an OpenSSH private key file or through
//! ssh-agent.
//!
//! The agent client is hand-written: ssh3-rs needs exactly two requests of
//! the agent protocol (draft-miller-ssh-agent §4.4 REQUEST_IDENTITIES,
//! §4.5 SIGN_REQUEST), synchronously, over a Unix socket. That is ~100 lines
//! with no async runtime or extra dependency; the available crates bring a
//! full agent server framework for it.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use signature::Signer as _;
use ssh_encoding::{Decode, Encode};
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};

use crate::spki::{rsa_private_key, same_key};
use crate::{Error, Result};

pub trait Signer: Send + Sync {
    fn public_key(&self) -> &PublicKey;
    fn sign(&self, message: &[u8]) -> Result<Signature>;
}

/// An unencrypted OpenSSH private key file. RSA signs as rsa-sha2-512.
pub struct FileSigner {
    key: PrivateKey,
    public: PublicKey,
}

impl FileSigner {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let key = parse_private_key(path, &text)?;
        if key.is_encrypted() {
            return Err(Error::EncryptedKey { path: path.into() });
        }
        Ok(Self::from_key(key))
    }

    pub fn from_key(key: PrivateKey) -> Self {
        let public = key.public_key().clone();
        Self { key, public }
    }
}

/// Parse an unencrypted private-key file in any of the formats a user may hand
/// to `ssh3 -i`: OpenSSH, PEM PKCS#1 RSA (`BEGIN RSA PRIVATE KEY`) and PEM
/// PKCS#8 (`BEGIN PRIVATE KEY`). Encrypted PEM is rejected explicitly with
/// `Error::EncryptedKey` — the same policy as encrypted OpenSSH keys — rather
/// than attempting a passphrase prompt.
///
/// Classification is by PEM header (not guesswork): ssh-key parses the OpenSSH
/// armor; for the two RSA PEM encodings the `rsa` crate decodes the key and
/// `spki::rsa_to_keypair` rebuilds the OpenSSH keypair from its components,
/// avoiding ssh-key's broken RSA conversion. Only RSA is defined for the PKCS#1
/// `RSA PRIVATE KEY` label; PKCS#8 here accepts the RSA case (the format the
/// migration needs), and a PKCS#8 of another algorithm is reported as such.
fn parse_private_key(path: &Path, text: &str) -> Result<PrivateKey> {
    use pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;

    let label = pem_label(text);
    match label.as_deref() {
        Some("OPENSSH PRIVATE KEY") => PrivateKey::from_openssh(text).map_err(|source| Error::KeyParse {
            path: path.into(),
            source,
        }),
        // PKCS#1 unencrypted RSA. (Legacy OpenSSL `Proc-Type: 4,ENCRYPTED`
        // headers are caught by the encrypted check below.)
        Some("RSA PRIVATE KEY") => {
            reject_if_encrypted(path, text)?;
            let sk = RsaPrivateKey::from_pkcs1_pem(text)
                .map_err(|e| Error::Pkcs8(format!("{}: PKCS#1 RSA PEM: {e}", path.display())))?;
            let kp = crate::spki::rsa_to_keypair(&sk)?;
            PrivateKey::new(kp, "").map_err(|source| Error::KeyParse {
                path: path.into(),
                source,
            })
        }
        // Unencrypted PKCS#8. The migration needs RSA; decode as RSA.
        Some("PRIVATE KEY") => {
            let sk = RsaPrivateKey::from_pkcs8_pem(text)
                .map_err(|e| Error::Pkcs8(format!("{}: PKCS#8 PEM (RSA): {e}", path.display())))?;
            let kp = crate::spki::rsa_to_keypair(&sk)?;
            PrivateKey::new(kp, "").map_err(|source| Error::KeyParse {
                path: path.into(),
                source,
            })
        }
        // Encrypted PKCS#8 — rejected like any passphrase-protected key.
        Some("ENCRYPTED PRIVATE KEY") => Err(Error::EncryptedKey { path: path.into() }),
        _ => {
            // No recognised PEM label: fall back to OpenSSH so its own error
            // (and any future format it learns) surfaces with the usual path.
            PrivateKey::from_openssh(text).map_err(|source| Error::KeyParse {
                path: path.into(),
                source,
            })
        }
    }
}

/// First PEM label on a `-----BEGIN <label>-----` line, if any.
fn pem_label(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                return Some(label.trim().to_string());
            }
        }
    }
    None
}

/// Reject a PKCS#1 PEM carrying the legacy OpenSSL encryption headers
/// (`Proc-Type: 4,ENCRYPTED` / `DEK-Info`). `rsa`'s PKCS#1 decoder would
/// otherwise fail with an opaque Base64 error; we want the same clear
/// "passphrase-protected" message as for other encrypted keys.
fn reject_if_encrypted(path: &Path, text: &str) -> Result<()> {
    // RFC 1421 header is `Proc-Type: 4,ENCRYPTED`, but tolerate whitespace
    // around the colon/comma: split on the first ':', compare the trimmed key
    // case-insensitively, then look for the ENCRYPTED token in the value.
    let encrypted = text.lines().any(|l| match l.trim().split_once(':') {
        Some((key, val)) => {
            key.trim().eq_ignore_ascii_case("Proc-Type") && val.to_ascii_uppercase().contains("ENCRYPTED")
        }
        None => false,
    });
    if encrypted {
        return Err(Error::EncryptedKey { path: path.into() });
    }
    Ok(())
}

impl Signer for FileSigner {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> Result<Signature> {
        match self.key.key_data() {
            // ssh-key's own RSA signer goes through its broken RSA
            // conversion (see `spki::rsa_private_key`); sign with the `rsa`
            // crate directly, as rsa-sha2-512.
            KeypairData::Rsa(k) => {
                let sk = rsa_private_key(k)?;
                let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(sk);
                let sig = signer.try_sign(message).map_err(|e| Error::Sign(e.to_string()))?;
                use signature::SignatureEncoding;
                Signature::new(Algorithm::Rsa { hash: Some(HashAlg::Sha512) }, sig.to_vec())
                    .map_err(|e| Error::Sign(e.to_string()))
            }
            _ => self.key.try_sign(message).map_err(|e| Error::Sign(e.to_string())),
        }
    }
}

const SSH_AGENT_FAILURE: u8 = 5;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;
/// Agent replies larger than this are refused before allocation.
const MAX_AGENT_MSG: usize = 256 * 1024;

/// Minimal synchronous ssh-agent client; one connection per request.
#[derive(Clone, Debug)]
pub struct AgentClient {
    sock: PathBuf,
}

impl AgentClient {
    pub fn new(sock: impl Into<PathBuf>) -> Self {
        Self { sock: sock.into() }
    }

    /// From `SSH_AUTH_SOCK`.
    pub fn from_env() -> Result<Self> {
        std::env::var_os("SSH_AUTH_SOCK")
            .filter(|s| !s.is_empty())
            .map(Self::new)
            .ok_or(Error::NoAgent)
    }

    pub fn socket(&self) -> &Path {
        &self.sock
    }

    fn err(&self, msg: impl Into<String>) -> Error {
        Error::Agent {
            sock: self.sock.clone(),
            msg: msg.into(),
        }
    }

    fn request(&self, msg_type: u8, payload: &[u8]) -> Result<(u8, Vec<u8>)> {
        let mut s = UnixStream::connect(&self.sock).map_err(|e| self.err(format!("connect: {e}")))?;
        let len = u32::try_from(payload.len() + 1).map_err(|_| self.err("request too large"))?;
        let mut req = Vec::with_capacity(payload.len() + 5);
        req.extend_from_slice(&len.to_be_bytes());
        req.push(msg_type);
        req.extend_from_slice(payload);
        s.write_all(&req).map_err(|e| self.err(format!("write: {e}")))?;
        let mut lenb = [0u8; 4];
        s.read_exact(&mut lenb).map_err(|e| self.err(format!("read length: {e}")))?;
        let n = u32::from_be_bytes(lenb) as usize;
        if n == 0 || n > MAX_AGENT_MSG {
            return Err(self.err(format!("reply length {n} out of range 1..={MAX_AGENT_MSG}")));
        }
        let mut body = vec![0u8; n];
        s.read_exact(&mut body).map_err(|e| self.err(format!("read body: {e}")))?;
        let t = body[0];
        body.remove(0);
        Ok((t, body))
    }

    pub fn identities(&self) -> Result<Vec<PublicKey>> {
        let (t, body) = self.request(SSH2_AGENTC_REQUEST_IDENTITIES, &[])?;
        if t != SSH2_AGENT_IDENTITIES_ANSWER {
            return Err(self.err(format!("REQUEST_IDENTITIES answered with type {t}")));
        }
        let r = &mut body.as_slice();
        let n = u32::decode(r)?;
        let mut keys = Vec::new();
        for _ in 0..n {
            let blob = Vec::<u8>::decode(r)?;
            let comment = String::decode(r)?;
            // Keys the ssh-key crate cannot parse (e.g. certificates,
            // sk-keys) are skipped: they cannot be used by ssh3-rs anyway.
            if let Ok(mut k) = PublicKey::from_bytes(&blob) {
                k.set_comment(comment);
                keys.push(k);
            }
        }
        Ok(keys)
    }

    pub fn sign(&self, key: &PublicKey, data: &[u8], rsa_hash: HashAlg) -> Result<Signature> {
        let mut p = Vec::new();
        key.key_data().encode_prefixed(&mut p)?;
        data.encode(&mut p)?;
        let flags = match (key.algorithm(), rsa_hash) {
            (Algorithm::Rsa { .. }, HashAlg::Sha256) => SSH_AGENT_RSA_SHA2_256,
            (Algorithm::Rsa { .. }, _) => SSH_AGENT_RSA_SHA2_512,
            _ => 0,
        };
        flags.encode(&mut p)?;
        let (t, body) = self.request(SSH2_AGENTC_SIGN_REQUEST, &p)?;
        match t {
            SSH2_AGENT_SIGN_RESPONSE => {
                let r = &mut body.as_slice();
                let sig_blob = Vec::<u8>::decode(r)?;
                Signature::decode(&mut sig_blob.as_slice()).map_err(|e| self.err(format!("signature encoding: {e}")))
            }
            SSH_AGENT_FAILURE => Err(self.err(format!(
                "agent refused to sign with {} (SSH_AGENT_FAILURE)",
                key.fingerprint(HashAlg::Sha256)
            ))),
            other => Err(self.err(format!("SIGN_REQUEST answered with type {other}"))),
        }
    }
}

/// A key held by ssh-agent.
pub struct AgentSigner {
    agent: AgentClient,
    key: PublicKey,
    rsa_hash: HashAlg,
}

impl AgentSigner {
    pub fn new(agent: AgentClient, key: PublicKey) -> Self {
        Self {
            agent,
            key,
            rsa_hash: HashAlg::Sha512,
        }
    }

    /// RSA keys: rsa-sha2-512 (default) or rsa-sha2-256.
    pub fn rsa_hash(mut self, h: HashAlg) -> Self {
        self.rsa_hash = h;
        self
    }

    /// Select the agent key equal to the public key in `pub_path`.
    pub fn for_pub_file(agent: AgentClient, pub_path: &Path) -> Result<Self> {
        let wanted = read_public_key(pub_path)?;
        let held = agent.identities()?;
        match held.into_iter().find(|k| same_key(k, &wanted)) {
            Some(k) => Ok(Self::new(agent, k)),
            None => Err(Error::AgentKeyMissing {
                sock: agent.sock.clone(),
                pub_path: pub_path.into(),
                fingerprint: wanted.fingerprint(HashAlg::Sha256).to_string(),
            }),
        }
    }
}

impl Signer for AgentSigner {
    fn public_key(&self) -> &PublicKey {
        &self.key
    }

    fn sign(&self, message: &[u8]) -> Result<Signature> {
        self.agent.sign(&self.key, message, self.rsa_hash)
    }
}

pub fn read_public_key(path: &Path) -> Result<PublicKey> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    PublicKey::from_openssh(text.trim()).map_err(|source| Error::KeyParse {
        path: path.into(),
        source,
    })
}

/// Resolve one `IdentityFile` the way OpenSSH does:
/// - the public half is `path` itself if it names a `.pub` (intentional:
///   it selects the agent key without trying every agent key), else
///   `path.pub` if present;
/// - if the agent holds that key, sign through the agent;
/// - otherwise load the private key from `path` (not possible for a `.pub`).
pub fn resolve_identity(path: &Path, agent: Option<&AgentClient>) -> Result<Box<dyn Signer>> {
    let is_pub = path.extension().is_some_and(|e| e == "pub");
    let pub_path = if is_pub {
        Some(path.to_path_buf())
    } else {
        let mut p = path.as_os_str().to_owned();
        p.push(".pub");
        let p = PathBuf::from(p);
        p.exists().then_some(p)
    };
    if let (Some(agent), Some(pp)) = (agent, &pub_path) {
        match AgentSigner::for_pub_file(agent.clone(), pp) {
            Ok(s) => return Ok(Box::new(s)),
            Err(e) if is_pub => return Err(e),
            Err(_) => {}
        }
    }
    if is_pub {
        let pp = pub_path.expect("is_pub implies pub_path");
        return Err(match agent {
            None => Error::NoAgent,
            Some(a) => Error::AgentKeyMissing {
                sock: a.sock.clone(),
                fingerprint: read_public_key(&pp)?.fingerprint(HashAlg::Sha256).to_string(),
                pub_path: pp,
            },
        });
    }
    Ok(Box::new(FileSigner::load(path)?))
}
