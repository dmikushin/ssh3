//! Authentication and authorization (SPEC §2.2). The signed blob, key
//! formats, the agent and authorized_keys parsing are `ssh3-keys`; there is
//! exactly one implementation of the blob, there. This module adapts it:
//! the wire `Intent`, the `Authz` policy and the server's authorizer.

use std::net::IpAddr;
use std::path::PathBuf;

pub use ssh3_keys::PublicKey;
pub use ssh3_keys::auth::{EXPORTER_LABEL, EXPORTER_LEN, pubkey_blob, sign_auth, verify_auth};
use ssh3_keys::authorized_keys::{AuthorizedKeys, KeyOptions};
pub use ssh3_keys::signer::Signer;

use crate::msg::Intent;

/// The wire intent as ssh3-keys' blob builder names it.
pub fn keys_intent(i: Intent) -> ssh3_keys::auth::Intent {
    match i {
        Intent::New => ssh3_keys::auth::Intent::New,
        Intent::Resume => ssh3_keys::auth::Intent::Resume,
    }
}

/// What an authenticated key may do (from authorized_keys options).
/// Immutable once built; the session swaps in a fresh value at each attach
/// (the policy is re-evaluated on resume), never mutates one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authz {
    port_forwarding: bool,
    permit_open: PermitList,
    permit_listen: PermitList,
    pty: bool,
    agent_forwarding: bool,
    forced_command: Option<String>,
}

/// `permitopen=` / `permitlisten=` semantics: `Any` when the option is
/// absent; otherwise only the listed pairs. Host `*` or a `None` port is a
/// wildcard.
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

    /// OpenSSH `permitopen="host:port"` values (`[v6]:port`, port `*`).
    /// For `permitlisten`, a bare `port` means `localhost:port`.
    fn parse(values: &[String], listen: bool) -> Result<Self, String> {
        if values.is_empty() {
            return Ok(PermitList::Any);
        }
        let mut out = Vec::new();
        for list in values {
            for v in list.split(',') {
                let v = v.trim();
                let (host, port) = if let Some(rest) = v.strip_prefix('[') {
                    let (h, p) = rest.split_once("]:").ok_or_else(|| format!("bad permit entry {v:?}"))?;
                    (h.to_string(), p)
                } else if let Some((h, p)) = v.rsplit_once(':') {
                    (h.to_string(), p)
                } else if listen {
                    ("localhost".to_string(), v)
                } else {
                    return Err(format!("permit entry {v:?} has no port"));
                };
                let port = if port == "*" { None } else { Some(port.parse::<u16>().map_err(|_| format!("bad port in permit entry {v:?}"))?) };
                out.push((host, port));
            }
        }
        Ok(PermitList::Only(out))
    }
}

impl Authz {
    pub fn new(port_forwarding: bool, permit_open: PermitList, permit_listen: PermitList, pty: bool, agent_forwarding: bool, forced_command: Option<String>) -> Self {
        Self { port_forwarding, permit_open, permit_listen, pty, agent_forwarding, forced_command }
    }
    /// No restrictions (a plain authorized_keys line).
    pub fn unrestricted() -> Self {
        Self::new(true, PermitList::Any, PermitList::Any, true, true, None)
    }
    /// From the options of the authorized_keys line that admitted the key.
    pub fn from_key_options(o: &KeyOptions) -> Result<Self, String> {
        Ok(Self::new(
            o.port_forwarding_allowed(),
            PermitList::parse(&o.permitopen, false)?,
            PermitList::parse(&o.permitlisten, true)?,
            o.pty_allowed(),
            o.agent_forwarding_allowed(),
            o.command.clone(),
        ))
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
    pub fn allows_agent_forwarding(&self) -> bool {
        self.agent_forwarding
    }
    pub fn forced_command(&self) -> Option<&str> {
        self.forced_command.as_deref()
    }
}

/// Server side: may `key` — whose signature core has already verified with
/// ssh3-keys — log in as `user` from `peer`? Returns the key's policy or a
/// human-readable refusal.
pub trait Authenticator: Send + Sync {
    fn authorize(&self, user: &str, key: &PublicKey, peer: IpAddr) -> Result<Authz, String>;
}

/// Maps a user name to its authorized_keys file (None: no such user).
pub type KeysPathFn = Box<dyn Fn(&str) -> Option<PathBuf> + Send + Sync>;

/// OpenSSH semantics: `~user/.ssh/authorized_keys`, re-read on every attempt.
pub struct AuthorizedKeysAuthenticator {
    path_for: KeysPathFn,
}

impl AuthorizedKeysAuthenticator {
    /// `path_for(user)` names the user's authorized_keys file, or None if the
    /// user does not exist.
    pub fn new(path_for: impl Fn(&str) -> Option<PathBuf> + Send + Sync + 'static) -> Self {
        Self { path_for: Box::new(path_for) }
    }

    /// Home directories from /etc/passwd.
    pub fn from_passwd() -> Self {
        Self::new(|user| {
            let text = std::fs::read_to_string("/etc/passwd").ok()?;
            text.lines()
                .map(|l| l.split(':').collect::<Vec<_>>())
                .find(|f| f.len() >= 6 && f[0] == user)
                .map(|f| PathBuf::from(f[5]).join(".ssh/authorized_keys"))
        })
    }
}

impl Authenticator for AuthorizedKeysAuthenticator {
    fn authorize(&self, user: &str, key: &PublicKey, peer: IpAddr) -> Result<Authz, String> {
        let path = (self.path_for)(user).ok_or_else(|| format!("no such user {user:?}"))?;
        let ak = AuthorizedKeys::load(&path).map_err(|e| e.to_string())?;
        let line = ak.authorize(key, peer).map_err(|e| format!("{}: {e}", path.display()))?;
        Authz::from_key_options(&line.options).map_err(|e| format!("{}: {e}", line.location()))
    }
}
