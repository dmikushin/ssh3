//! Destinations and ProxyJump hops, ported from OpenSSH 10.5p1 `misc.c`
//! (`hpdelim2`, `cleanhostname`, `parse_user_host_port`, `parse_uri`,
//! `valid_domain`) and `readconf.c` (`parse_jump`, `ssh_valid_hostname`,
//! `ssh_valid_ruser`).

use crate::forward::a2port;

/// One `[user@]host[:port]` hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

/// Port of `hpdelim2()`: split off a host (possibly `[bracketed]`) at the
/// next `:` or `/`. Returns (host, delimiter, rest).
fn hpdelim2(s: &str) -> Option<(&str, Option<char>, Option<&str>)> {
    let end = if s.starts_with('[') {
        s.find(']')? + 1
    } else {
        s.find([':', '/']).unwrap_or(s.len())
    };
    match s[end..].chars().next() {
        None => Some((&s[..end], None, None)),
        Some(d @ (':' | '/')) => Some((&s[..end], Some(d), Some(&s[end + 1..]))),
        Some(_) => None,
    }
}

/// `hpdelim()`: like `hpdelim2` but only `:` is accepted as a delimiter.
fn hpdelim(s: &str) -> Option<(&str, Option<&str>)> {
    let (h, d, rest) = hpdelim2(s)?;
    if d == Some('/') {
        return None;
    }
    Some((h, rest))
}

/// `hpdelim()` for callers outside this module: (host, optional port).
pub(crate) fn hpdelim_colon(s: &str) -> Option<(&str, Option<&str>)> {
    hpdelim(s)
}

/// `cleanhostname()`: strip one pair of enclosing brackets.
pub fn cleanhostname(h: &str) -> &str {
    if h.len() >= 2 && h.starts_with('[') && h.ends_with(']') {
        &h[1..h.len() - 1]
    } else {
        h
    }
}

/// Port of `parse_user_host_port()`.
pub fn parse_user_host_port(s: &str) -> Option<Hop> {
    let (user, rest) = match s.rfind('@') {
        Some(at) => {
            if at == 0 {
                return None;
            }
            (Some(s[..at].to_string()), &s[at + 1..])
        }
        None => (None, s),
    };
    let (h, port_s) = hpdelim(rest)?;
    if h.is_empty() {
        return None;
    }
    let host = cleanhostname(h).to_string();
    let port = match port_s {
        Some(p) if !p.is_empty() => match a2port(p) {
            Some(v) if v > 0 => Some(v),
            _ => return None,
        },
        _ => None,
    };
    Some(Hop { user, host, port })
}

fn urldecode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                let v = u8::from_str_radix(hex, 16).ok()?;
                if v == 0 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return None;
                }
                out.push(v);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Port of `valid_domain(name, 0, ...)` (no lowercasing). Note that the C
/// function strips one trailing dot in place; callers here only test.
pub fn valid_domain(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() {
        return false;
    }
    if !(b[0].is_ascii_alphanumeric() || b[0] == b'_') {
        return false;
    }
    let mut last = 0u8;
    for &c in b {
        let c = c.to_ascii_lowercase();
        if last == b'.' && c == b'.' {
            return false;
        }
        if c != b'.' && c != b'-' && !c.is_ascii_alphanumeric() && c != b'_' {
            return false;
        }
        last = c;
    }
    true
}

/// Result of [`parse_ssh_uri`], mirroring the C return codes.
pub enum Uri {
    /// Not an `ssh://` URI (C returns 1).
    NotUri,
    /// Malformed URI (C returns -1).
    Invalid,
    Ok(Hop),
}

/// Port of `parse_ssh_uri()` (`parse_uri("ssh", ...)` with no path allowed).
pub fn parse_ssh_uri(uri: &str) -> Uri {
    let Some(rest) = uri.strip_prefix("ssh://") else {
        return Uri::NotUri;
    };
    let (user, rest) = match rest.find('@') {
        Some(at) => {
            let mut info = &rest[..at];
            if let Some(semi) = info.find(';') {
                info = &info[..semi]; // connection params are ignored
            }
            if info.is_empty() {
                return Uri::Invalid;
            }
            match urldecode(info) {
                Some(u) => (Some(u), &rest[at + 1..]),
                None => return Uri::Invalid,
            }
        }
        None => (None, rest),
    };
    let Some((h, delim, tail)) = hpdelim2(rest) else {
        return Uri::Invalid;
    };
    if h.is_empty() {
        return Uri::Invalid;
    }
    let host = cleanhostname(h).to_string();
    if !valid_domain(&host) {
        return Uri::Invalid;
    }
    let mut port = None;
    let mut path_tail = tail;
    if let Some(t) = tail.filter(|t| !t.is_empty()) {
        if delim == Some(':') {
            let (p, after) = match t.find('/') {
                Some(slash) => (&t[..slash], Some(&t[slash + 1..])),
                None => (t, None),
            };
            match a2port(p) {
                Some(v) if v > 0 => port = Some(v),
                _ => return Uri::Invalid,
            }
            path_tail = after;
        }
        if let Some(pt) = path_tail.filter(|pt| !pt.is_empty()) {
            // A path is not allowed in an ssh:// destination.
            let _ = urldecode(pt);
            return Uri::Invalid;
        }
    }
    Uri::Ok(Hop { user, host, port })
}

/// Port of `ssh_valid_hostname()`.
pub fn valid_hostname(s: &str) -> bool {
    if s.starts_with('-') {
        return false;
    }
    !s.bytes().any(|c| {
        b"'`\"$\\;&<>|(){},".contains(&c) || c.is_ascii_whitespace() || c.is_ascii_control()
    })
}

/// Port of `ssh_valid_ruser()`.
pub fn valid_ruser(s: &str) -> bool {
    let b = s.as_bytes();
    if b.first() == Some(&b'-') {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        if c.is_ascii_control() || b"'`\";&<>|(){}".contains(&c) {
            return false;
        }
        if c.is_ascii_whitespace() && b.get(i + 1) == Some(&b'-') {
            return false;
        }
        if c == b'\\' && i + 1 == b.len() {
            return false;
        }
    }
    true
}

/// A parsed `ProxyJump` / `-J` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyJump {
    /// `ProxyJump none`.
    None,
    /// Hops in connection order (first hop first).
    Hops {
        hops: Vec<Hop>,
        /// The text before the last comma, as written (OpenSSH
        /// `jump_extra`); kept for `ssh -G`-identical output.
        extra_raw: Option<String>,
    },
}

/// Port of `parse_jump()`: returns the parsed value or an error message.
/// `strict` additionally validates host and user characters (command line).
pub fn parse_jump(s: &str, strict: bool) -> Result<ProxyJump, String> {
    if s.eq_ignore_ascii_case("none") {
        return Ok(ProxyJump::None);
    }
    let orig = match s.find('#') {
        Some(i) => &s[..i],
        None => s,
    };
    let orig = orig.trim_end_matches([' ', '\t', '\r', '\n']);
    let mut hops = Vec::new();
    for part in orig.split(',') {
        let hop = match parse_ssh_uri(part) {
            Uri::Invalid => return Err(format!("invalid ProxyJump hop \"{part}\"")),
            Uri::Ok(h) => h,
            Uri::NotUri => parse_user_host_port(part)
                .ok_or_else(|| format!("invalid ProxyJump hop \"{part}\""))?,
        };
        if strict {
            if !valid_hostname(&hop.host) {
                return Err(format!("parse_jump: invalid hostname \"{}\"", hop.host));
            }
            if let Some(u) = &hop.user
                && !valid_ruser(u)
            {
                return Err(format!("parse_jump: invalid username \"{u}\""));
            }
        }
        hops.push(hop);
    }
    let extra_raw = orig.rfind(',').map(|i| orig[..i].to_string());
    Ok(ProxyJump::Hops { hops, extra_raw })
}

impl ProxyJump {
    /// The last hop (the one the final destination is reached through).
    pub fn last(&self) -> Option<&Hop> {
        match self {
            ProxyJump::None => None,
            ProxyJump::Hops { hops, .. } => hops.last(),
        }
    }

    /// Format as `ssh -G` prints `proxyjump` (from `dump_client_config`).
    pub fn dump(&self) -> Option<String> {
        let ProxyJump::Hops { hops, extra_raw } = self else {
            // jump_host "none" prints as a bare hostname "none".
            return Some("none".into());
        };
        let h = hops.last()?;
        let numeric =
            h.host.contains(':') || h.host.bytes().all(|c| c.is_ascii_digit() || c == b'.');
        let mut s = String::new();
        if let Some(e) = extra_raw {
            s.push_str(e);
            s.push(',');
        }
        if let Some(u) = &h.user {
            s.push_str(u);
            s.push('@');
        }
        if numeric {
            s.push('[');
        }
        s.push_str(&h.host);
        if numeric {
            s.push(']');
        }
        if let Some(p) = h.port {
            s.push(':');
            s.push_str(&p.to_string());
        }
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_host_port() {
        let h = parse_user_host_port("bob@gw2:2200").unwrap();
        assert_eq!(
            (h.user.as_deref(), h.host.as_str(), h.port),
            (Some("bob"), "gw2", Some(2200))
        );
        let h = parse_user_host_port("[::1]:22").unwrap();
        assert_eq!((h.host.as_str(), h.port), ("::1", Some(22)));
        assert!(parse_user_host_port("@h").is_none());
        assert!(parse_user_host_port("h:0").is_none());
        assert!(parse_user_host_port("h/x").is_none());
    }

    #[test]
    fn uri() {
        assert!(matches!(parse_ssh_uri("host"), Uri::NotUri));
        assert!(matches!(parse_ssh_uri("ssh://[fe80::1]:22"), Uri::Invalid));
        match parse_ssh_uri("ssh://u%40x;p=1@Host.Example:2222") {
            Uri::Ok(h) => {
                assert_eq!(h.user.as_deref(), Some("u@x"));
                assert_eq!(h.host, "Host.Example");
                assert_eq!(h.port, Some(2222));
            }
            _ => panic!(),
        }
        assert!(matches!(parse_ssh_uri("ssh://h/path"), Uri::Invalid));
    }

    #[test]
    fn jump() {
        let j = parse_jump("gw1,bob@gw2:2200", false).unwrap();
        assert_eq!(j.dump().unwrap(), "gw1,bob@gw2:2200");
        assert_eq!(j.last().unwrap().host, "gw2");
        let j = parse_jump("10.0.0.1:2222", false).unwrap();
        assert_eq!(j.dump().unwrap(), "[10.0.0.1]:2222");
        assert_eq!(parse_jump("None", false).unwrap(), ProxyJump::None);
        assert!(parse_jump("a,,b", false).is_err());
    }
}
