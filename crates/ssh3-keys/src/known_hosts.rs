//! OpenSSH `known_hosts` (SPEC §2.1): parse, look up, append.
//!
//! Semantics follow OpenSSH `hostfile.c`/`match.c`:
//! - the lookup name is `host` for port 22 and `[host]:port` otherwise;
//! - a line's host field is either one hashed entry `|1|salt|hmac` (HMAC-SHA1
//!   of the lookup name keyed by the salt) or a comma list of patterns with
//!   `*`/`?` wildcards and `!` negation, matched case-insensitively; a matching
//!   negated pattern excludes the line;
//! - markers `@revoked` and `@cert-authority` are reported as such.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use ssh_key::PublicKey;

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marker {
    None,
    Revoked,
    CertAuthority,
}

#[derive(Clone, Debug)]
pub enum HostField {
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
    Patterns(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub file: PathBuf,
    pub line: usize,
    pub marker: Marker,
    pub hosts: HostField,
    pub key: PublicKey,
}

impl Entry {
    pub fn location(&self) -> String {
        format!("{}:{}", self.file.display(), self.line)
    }

    pub fn matches(&self, lookup_name: &str) -> bool {
        match &self.hosts {
            HostField::Hashed { salt, hash } => hash_host(salt, lookup_name) == *hash,
            HostField::Patterns(p) => match_pattern_list(lookup_name, p),
        }
    }
}

/// A line that could not be parsed. OpenSSH skips such lines; we keep them so
/// callers can report them instead of silently ignoring them.
#[derive(Clone, Debug)]
pub struct BadLine {
    pub file: PathBuf,
    pub line: usize,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct KnownHosts {
    pub entries: Vec<Entry>,
    pub bad_lines: Vec<BadLine>,
}

/// The name OpenSSH looks up: `host` for port 22, `[host]:port` otherwise.
pub fn lookup_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

pub fn hash_host(salt: &[u8], name: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(name.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// `|1|base64(salt)|base64(hmac)` with a fresh 20-byte salt.
pub fn hashed_host_field(name: &str) -> String {
    let mut salt = [0u8; 20];
    getrandom::getrandom(&mut salt).expect("OS RNG available");
    format!("|1|{}|{}", B64.encode(salt), B64.encode(hash_host(&salt, name)))
}

impl KnownHosts {
    /// Load several files (UserKnownHostsFile list, then global files).
    /// A missing file is not an error (OpenSSH behaves the same).
    pub fn load(files: &[PathBuf]) -> Result<Self> {
        let mut kh = KnownHosts::default();
        for f in files {
            match std::fs::read_to_string(f) {
                Ok(text) => kh.parse_into(f, &text),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::io(f, e)),
            }
        }
        Ok(kh)
    }

    pub fn parse(file: &Path, text: &str) -> Self {
        let mut kh = KnownHosts::default();
        kh.parse_into(file, text);
        kh
    }

    fn parse_into(&mut self, file: &Path, text: &str) {
        for (i, raw) in text.lines().enumerate() {
            let line = i + 1;
            let s = raw.trim();
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            match parse_line(s) {
                Ok((marker, hosts, key)) => self.entries.push(Entry {
                    file: file.to_path_buf(),
                    line,
                    marker,
                    hosts,
                    key,
                }),
                Err(reason) => self.bad_lines.push(BadLine {
                    file: file.to_path_buf(),
                    line,
                    reason,
                }),
            }
        }
    }

    /// All entries whose host field matches `host:port`.
    pub fn lookup(&self, host: &str, port: u16) -> Vec<&Entry> {
        let name = lookup_name(host, port).to_ascii_lowercase();
        self.entries.iter().filter(|e| e.matches(&name)).collect()
    }
}

fn parse_line(s: &str) -> std::result::Result<(Marker, HostField, PublicKey), String> {
    let mut fields = s.split_whitespace();
    let mut first = fields.next().ok_or("empty line")?;
    let marker = match first {
        "@revoked" => Marker::Revoked,
        "@cert-authority" => Marker::CertAuthority,
        m if m.starts_with('@') => return Err(format!("unknown marker {m}")),
        _ => Marker::None,
    };
    if marker != Marker::None {
        first = fields.next().ok_or("marker without host field")?;
    }
    let hosts = if let Some(rest) = first.strip_prefix("|1|") {
        let (salt, hash) = rest.split_once('|').ok_or("malformed hashed host")?;
        HostField::Hashed {
            salt: B64.decode(salt).map_err(|e| format!("hashed host salt: {e}"))?,
            hash: B64.decode(hash).map_err(|e| format!("hashed host hash: {e}"))?,
        }
    } else if first.starts_with('|') {
        return Err(format!("unsupported hashed host format {first}"));
    } else {
        HostField::Patterns(first.split(',').map(|p| p.to_ascii_lowercase()).collect())
    };
    let rest: Vec<&str> = fields.collect();
    if rest.len() < 2 {
        return Err("missing key type or key data".into());
    }
    let key = PublicKey::from_openssh(&rest.join(" ")).map_err(|e| format!("public key: {e}"))?;
    Ok((marker, hosts, key))
}

/// OpenSSH `match_hostname`: negation wins, otherwise any positive match.
pub fn match_pattern_list(name: &str, patterns: &[String]) -> bool {
    let mut matched = false;
    for p in patterns {
        if let Some(neg) = p.strip_prefix('!') {
            if wildcard_match(name, neg) {
                return false;
            }
        } else if wildcard_match(name, p) {
            matched = true;
        }
    }
    matched
}

/// `*` and `?` glob, as OpenSSH `match_pattern`.
pub fn wildcard_match(s: &str, p: &str) -> bool {
    let (s, p) = (s.as_bytes(), p.as_bytes());
    let (mut si, mut pi) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Append `host:port key` to `file`, hashed if `hash` is set. Creates the
/// file (0600) and its directory (0700) if missing.
pub fn append(file: &Path, host: &str, port: u16, key: &PublicKey, hash: bool) -> Result<String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(dir) = file.parent()
        && !dir.as_os_str().is_empty()
        && !dir.exists()
    {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Error::io(dir, e))?;
    }
    let name = lookup_name(host, port);
    let host_field = if hash { hashed_host_field(&name) } else { name };
    let mut key = key.clone();
    key.set_comment("");
    let key_text = key.to_openssh().map_err(|e| Error::Sign(e.to_string()))?;
    let line = format!("{host_field} {}\n", key_text.trim_end());

    let needs_newline = match std::fs::read(file) {
        Ok(b) => !b.is_empty() && !b.ends_with(b"\n"),
        Err(_) => false,
    };
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(file)
        .map_err(|e| Error::io(file, e))?;
    if needs_newline {
        f.write_all(b"\n").map_err(|e| Error::io(file, e))?;
    }
    f.write_all(line.as_bytes()).map_err(|e| Error::io(file, e))?;
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_and_negation() {
        let pats: Vec<String> = ["*.example.com", "!bad.example.com"].iter().map(|s| s.to_string()).collect();
        assert!(match_pattern_list("a.example.com", &pats));
        assert!(!match_pattern_list("bad.example.com", &pats));
        assert!(!match_pattern_list("example.org", &pats));
        assert!(wildcard_match("host1", "host?"));
        assert!(!wildcard_match("host12", "host?"));
        assert!(wildcard_match("[h]:2222", "[h]:2222"));
    }
}
