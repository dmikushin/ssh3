//! OpenSSH `authorized_keys` (SPEC §2.2), server side.
//!
//! Line format: `[options] keytype base64 [comment]`. Options are a comma
//! list of `name` or `name="value"` (value may contain commas and `\"`).
//!
//! Enforced options (exposed as typed fields): `from=`,
//! `no-port-forwarding`/`port-forwarding`, `permitopen=`, `permitlisten=`,
//! `command=`, `restrict`, `no-pty`/`pty`, `no-agent-forwarding`/
//! `agent-forwarding`. Every other option is kept in
//! [`KeyOptions::unsupported`]; [`AuthorizedKeys::authorize`] refuses such a
//! line (fail closed), because an option ssh3-rs does not implement — e.g.
//! `expiry-time=`, `cert-authority`, `principals=`, `environment=` — would
//! otherwise silently grant more than the administrator wrote.
//!
//! Lines are tried in file order; a line whose key matches but whose
//! options refuse the client is skipped and the next line is tried
//! (OpenSSH `auth2-pubkeyfile.c`).

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ssh_key::PublicKey;

use crate::known_hosts::wildcard_match;
use crate::spki::same_key;
use crate::{Error, Result};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyOptions {
    pub from: Vec<String>,
    pub restrict: bool,
    pub no_port_forwarding: bool,
    pub port_forwarding: bool,
    pub permitopen: Vec<String>,
    pub permitlisten: Vec<String>,
    pub command: Option<String>,
    pub no_pty: bool,
    pub pty: bool,
    pub no_agent_forwarding: bool,
    pub agent_forwarding: bool,
    /// Options present in the file that ssh3-rs does not implement.
    pub unsupported: Vec<(String, Option<String>)>,
}

impl KeyOptions {
    pub fn port_forwarding_allowed(&self) -> bool {
        !(self.no_port_forwarding || (self.restrict && !self.port_forwarding))
    }

    pub fn pty_allowed(&self) -> bool {
        !(self.no_pty || (self.restrict && !self.pty))
    }

    pub fn agent_forwarding_allowed(&self) -> bool {
        !(self.no_agent_forwarding || (self.restrict && !self.agent_forwarding))
    }

    /// `from=` check against the client address. Hostname patterns are not
    /// resolved (as OpenSSH with `UseDNS no`): patterns match the textual IP
    /// with `*`/`?`, CIDR `addr/len`, and `!` negation.
    pub fn from_allows(&self, ip: IpAddr) -> bool {
        if self.from.is_empty() {
            return true;
        }
        let ip = canonical(ip);
        let text = ip.to_string();
        let mut matched = false;
        for list in &self.from {
            for p in list.split(',') {
                let (neg, p) = match p.strip_prefix('!') {
                    Some(r) => (true, r),
                    None => (false, p),
                };
                let hit = if p.contains('/') {
                    cidr_match(ip, p)
                } else {
                    wildcard_match(&text, &p.to_ascii_lowercase())
                };
                if hit && neg {
                    return false;
                }
                matched |= hit;
            }
        }
        matched
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn cidr_match(ip: IpAddr, cidr: &str) -> bool {
    let Some((addr, len)) = cidr.split_once('/') else { return false };
    let (Ok(net), Ok(len)) = (addr.parse::<IpAddr>(), len.parse::<u32>()) else {
        return false;
    };
    match (canonical(net), ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) if len <= 32 => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) if len <= 128 => {
            let mask = if len == 0 { 0 } else { u128::MAX << (128 - len) };
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

#[derive(Clone, Debug)]
pub struct AuthorizedKey {
    pub file: PathBuf,
    pub line: usize,
    pub options: KeyOptions,
    pub key: PublicKey,
}

impl AuthorizedKey {
    pub fn location(&self) -> String {
        format!("{}:{}", self.file.display(), self.line)
    }
}

#[derive(Clone, Debug, Default)]
pub struct AuthorizedKeys {
    pub keys: Vec<AuthorizedKey>,
    /// Lines that did not parse: (file, line, reason).
    pub bad_lines: Vec<(PathBuf, usize, String)>,
}

const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

fn is_key_type(t: &str) -> bool {
    KEY_TYPES.contains(&t) || t.ends_with("-cert-v01@openssh.com")
}

impl AuthorizedKeys {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        Ok(Self::parse(path, &text))
    }

    pub fn parse(file: &Path, text: &str) -> Self {
        let mut ak = AuthorizedKeys::default();
        for (i, raw) in text.lines().enumerate() {
            let s = raw.trim();
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            match parse_line(s) {
                Ok((options, key)) => ak.keys.push(AuthorizedKey {
                    file: file.to_path_buf(),
                    line: i + 1,
                    options,
                    key,
                }),
                Err(reason) => ak.bad_lines.push((file.to_path_buf(), i + 1, reason)),
            }
        }
        ak
    }

    /// Every line carrying `key`, in file order.
    pub fn lookup(&self, key: &PublicKey) -> Vec<&AuthorizedKey> {
        self.keys.iter().filter(|k| same_key(&k.key, key)).collect()
    }

    /// The first line for `key` whose options admit a client at `ip`. On
    /// refusal the error lists every matching line and why it was refused.
    pub fn authorize(&self, key: &PublicKey, ip: IpAddr) -> std::result::Result<&AuthorizedKey, String> {
        let mut reasons = Vec::new();
        for k in self.lookup(key) {
            if !k.options.unsupported.is_empty() {
                let names: Vec<&str> = k.options.unsupported.iter().map(|(n, _)| n.as_str()).collect();
                reasons.push(format!("{}: options not implemented by ssh3-rs: {}", k.location(), names.join(",")));
                continue;
            }
            if !k.options.from_allows(ip) {
                reasons.push(format!("{}: from=\"{}\" does not admit {ip}", k.location(), k.options.from.join(",")));
                continue;
            }
            return Ok(k);
        }
        if reasons.is_empty() {
            Err("key not present in authorized_keys".into())
        } else {
            Err(reasons.join("; "))
        }
    }
}

fn parse_line(s: &str) -> std::result::Result<(KeyOptions, PublicKey), String> {
    let first = s.split_whitespace().next().unwrap_or("");
    let (options, rest) = if is_key_type(first) {
        (KeyOptions::default(), s)
    } else {
        let (opts, rest) = split_options(s)?;
        (parse_options(&opts)?, rest.trim_start())
    };
    let key = PublicKey::from_openssh(rest).map_err(|e| format!("public key: {e}"))?;
    Ok((options, key))
}

type RawOptions = Vec<(String, Option<String>)>;

/// Split the leading option list from the rest at the first unquoted blank.
fn split_options(s: &str) -> std::result::Result<(RawOptions, &str), String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut opts = Vec::new();
    loop {
        let start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b',' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let name = s[start..i].to_string();
        if name.is_empty() {
            return Err("empty option name".into());
        }
        let mut value = None;
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            if i >= bytes.len() || bytes[i] != b'"' {
                return Err(format!("option {name}= value must be double-quoted"));
            }
            i += 1;
            let mut v = String::new();
            loop {
                if i >= bytes.len() {
                    return Err(format!("unterminated quoted value for {name}"));
                }
                match bytes[i] {
                    b'\\' if i + 1 < bytes.len() && bytes[i + 1] == b'"' => {
                        v.push('"');
                        i += 2;
                    }
                    b'"' => {
                        i += 1;
                        break;
                    }
                    _ => {
                        let ch = s[i..].chars().next().unwrap();
                        v.push(ch);
                        i += ch.len_utf8();
                    }
                }
            }
            value = Some(v);
        }
        opts.push((name, value));
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
            continue;
        }
        if i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            return Err(format!("unexpected character {:?} in options", bytes[i] as char));
        }
        return Ok((opts, &s[i..]));
    }
}

fn parse_options(opts: &[(String, Option<String>)]) -> std::result::Result<KeyOptions, String> {
    let mut o = KeyOptions::default();
    for (name, value) in opts {
        let lname = name.to_ascii_lowercase();
        let need = |v: &Option<String>| v.clone().ok_or_else(|| format!("option {name} requires a value"));
        match lname.as_str() {
            "from" => o.from.push(need(value)?),
            "restrict" => o.restrict = true,
            "no-port-forwarding" => o.no_port_forwarding = true,
            "port-forwarding" => o.port_forwarding = true,
            "permitopen" => o.permitopen.push(need(value)?),
            "permitlisten" => o.permitlisten.push(need(value)?),
            "command" => o.command = Some(need(value)?),
            "no-pty" => o.no_pty = true,
            "pty" => o.pty = true,
            "no-agent-forwarding" => o.no_agent_forwarding = true,
            "agent-forwarding" => o.agent_forwarding = true,
            _ => o.unsupported.push((name.clone(), value.clone())),
        }
    }
    Ok(o)
}
