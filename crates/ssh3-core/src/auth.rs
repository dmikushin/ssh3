//! Authentication boundary (SPEC §2.2). Key formats, agents and
//! authorized_keys live in `ssh3-keys`; core only needs these two traits and
//! the exact signed blob.

use crate::msg::Intent;

/// Exporter label and length (SPEC §2.2).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-ssh3-rs-auth";
pub const EXPORTER_LEN: usize = 32;
const AUTH_MAGIC: &[u8] = b"ssh3-rs auth v0";

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// `"ssh3-rs auth v0" || exporter || str(user) || str(pubkey_blob) || str(intent)`.
pub fn auth_blob(exporter: &[u8; EXPORTER_LEN], user: &str, pubkey_blob: &[u8], intent: Intent) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTH_MAGIC.len() + EXPORTER_LEN + 12 + user.len() + pubkey_blob.len() + 6);
    out.extend_from_slice(AUTH_MAGIC);
    out.extend_from_slice(exporter);
    put_str(&mut out, user.as_bytes());
    put_str(&mut out, pubkey_blob);
    put_str(&mut out, intent.as_str().as_bytes());
    out
}

/// Client side: holds one user key (file or agent).
pub trait Signer: Send + Sync {
    /// OpenSSH wire encoding of the public key.
    fn public_key_blob(&self) -> Vec<u8>;
    /// Signature over `data` in the key's wire signature encoding.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String>;
}

/// What an authenticated key may do (from authorized_keys options).
/// Immutable once built: the session holds it behind an `Arc` and there are
/// no setters, so a policy cannot change under a running session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authz {
    port_forwarding: bool,
    permit_open: PermitList,
    permit_listen: PermitList,
    pty: bool,
    forced_command: Option<String>,
}

/// `permitopen=` / `permitlisten=` semantics: `Any` when the option is
/// absent; otherwise only the listed `host:port` pairs (`None` port = `*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermitList {
    Any,
    Only(Vec<(String, Option<u16>)>),
}

impl PermitList {
    fn allows(&self, host: &str, port: u16) -> bool {
        match self {
            PermitList::Any => true,
            PermitList::Only(v) => v.iter().any(|(h, p)| (h == "*" || h.eq_ignore_ascii_case(host)) && p.is_none_or(|p| p == port)),
        }
    }
}

impl Authz {
    pub fn new(port_forwarding: bool, permit_open: PermitList, permit_listen: PermitList, pty: bool, forced_command: Option<String>) -> Self {
        Self { port_forwarding, permit_open, permit_listen, pty, forced_command }
    }
    /// No restrictions (a plain authorized_keys line).
    pub fn unrestricted() -> Self {
        Self::new(true, PermitList::Any, PermitList::Any, true, None)
    }
    pub fn allows_direct_tcp(&self, host: &str, port: u16) -> bool {
        self.port_forwarding && self.permit_open.allows(host, port)
    }
    pub fn allows_listen(&self, host: &str, port: u16) -> bool {
        self.port_forwarding && self.permit_listen.allows(host, port)
    }
    pub fn allows_pty(&self) -> bool {
        self.pty
    }
    pub fn forced_command(&self) -> Option<&str> {
        self.forced_command.as_deref()
    }
}

/// Server side: decides whether `pubkey_blob` may log in as `user`, checks
/// the signature over `blob`, and returns the key's policy. Returns a
/// human-readable reason on refusal.
pub trait Authenticator: Send + Sync {
    fn verify(&self, user: &str, pubkey_blob: &[u8], blob: &[u8], sig: &[u8]) -> Result<Authz, String>;
}
