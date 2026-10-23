//! Forwarding specifications, ported from OpenSSH 10.5p1 `readconf.c`
//! (`parse_fwd_field`, `parse_forward`, `dump_cfg_forwards`) and `misc.c`
//! (`a2port`).

use std::fmt;

use crate::expand;

/// Where a forward listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listen {
    /// TCP/UDP port; `host` is the bind address (`None` = default bind).
    /// Port 0 is only valid for remote forwards (server allocates).
    Port { host: Option<String>, port: u16 },
    /// Unix-domain socket path.
    Path(String),
}

/// Where a forward connects to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connect {
    HostPort {
        host: String,
        port: u16,
    },
    /// Unix-domain socket path.
    Path(String),
    /// Dynamic (SOCKS) forward: `-D`, or `-R [bind:]port` without a target.
    Socks,
}

/// One forwarding specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    pub listen: Listen,
    pub connect: Connect,
}

impl Forward {
    pub fn is_dynamic(&self) -> bool {
        self.connect == Connect::Socks
    }
}

/// Formats as `ssh -G` prints a forward: `listen` then (unless dynamic
/// local) the target.
impl fmt::Display for Listen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Listen::Path(p) => write!(f, "{p}"),
            Listen::Port { host: None, port } => write!(f, "{port}"),
            Listen::Port {
                host: Some(h),
                port,
            } => write!(f, "[{h}]:{port}"),
        }
    }
}

impl fmt::Display for Connect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Connect::Path(p) => write!(f, "{p}"),
            Connect::HostPort { host, port } => write!(f, "[{host}]:{port}"),
            // OpenSSH stores dynamic forwards as connect_host "socks", port 0.
            Connect::Socks => write!(f, "[socks]:0"),
        }
    }
}

/// Port of `a2port()`: decimal 0..=65535, else a TCP service name from the
/// services database. `None` = invalid (C returns -1).
pub fn a2port(s: &str) -> Option<u16> {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let digits = t.strip_prefix('+').unwrap_or(t);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        return digits
            .parse::<u32>()
            .ok()
            .filter(|&v| v <= 65535)
            .map(|v| v as u16);
    }
    service_port(s)
}

fn service_port(name: &str) -> Option<u16> {
    let cname = std::ffi::CString::new(name).ok()?;
    let proto = c"tcp";
    // SAFETY: getservbyname reads two NUL-terminated strings and returns a
    // pointer to static storage or NULL; we copy the port out immediately.
    // ssh3-config is not called concurrently with other getservbyname users
    // in this process during resolution.
    unsafe {
        let se = libc::getservbyname(cname.as_ptr(), proto.as_ptr());
        if se.is_null() {
            None
        } else {
            Some(u16::from_be((*se).s_port as u16))
        }
    }
}

struct Field {
    arg: String,
    ispath: bool,
}

/// Port of `parse_fwd_field()`. Returns the field and the remainder
/// (`None` at end of string); `Err(())` on a malformed field.
fn parse_fwd_field(p: &str) -> Result<(Field, Option<&str>), ()> {
    if p.is_empty() {
        return Err(());
    }
    if let Some(inner) = p.strip_prefix('[') {
        let end = inner.find(']').ok_or(())?;
        let after = &inner[end + 1..];
        if !(after.is_empty() || after.starts_with(':')) {
            return Err(());
        }
        let arg = &inner[..end];
        let rest = if after.is_empty() { "" } else { &after[1..] };
        return Ok((
            Field {
                arg: arg.to_string(),
                ispath: arg.contains('/'),
            },
            Some(rest),
        ));
    }
    let b = p.as_bytes();
    let mut arg = Vec::new();
    let mut ispath = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                // The escaped character is taken literally (and an escaped
                // '/' does not make the field a path).
                i += 1;
                if i >= b.len() {
                    return Err(());
                }
                arg.push(b[i]);
            }
            b'/' => {
                ispath = true;
                arg.push(b'/');
            }
            b':' => {
                return Ok((
                    Field {
                        arg: String::from_utf8_lossy(&arg).into_owned(),
                        ispath,
                    },
                    Some(&p[i + 1..]),
                ));
            }
            c => arg.push(c),
        }
        i += 1;
    }
    Ok((
        Field {
            arg: String::from_utf8_lossy(&arg).into_owned(),
            ispath,
        },
        None,
    ))
}

/// Port of `parse_forward()`.
///
/// `dynamic`: `[listenhost:]listenport` (SOCKS). Otherwise
/// `[listenhost:]listenport|listenpath:connecthost:connectport|connectpath`
/// or `listenpath:connectpath`. `remote` allows listen port 0.
pub fn parse_forward(spec: &str, dynamic: bool, remote: bool) -> Option<Forward> {
    let expanded = expand::dollar(spec).ok()?;
    let mut cp: Option<&str> = Some(expanded.trim_start_matches(|c: char| c.is_ascii_whitespace()));
    let mut fields: Vec<Field> = Vec::with_capacity(4);
    while fields.len() < 4 {
        let Some(s) = cp else { break };
        match parse_fwd_field(s) {
            Ok((f, rest)) => {
                fields.push(f);
                cp = rest;
            }
            Err(()) => {
                // C: on error the field parser leaves *p unchanged unless at
                // end of string (then *p = NULL); either way the loop stops.
                if s.is_empty() {
                    cp = None;
                }
                break;
            }
        }
    }
    // Trailing garbage → failure.
    if matches!(cp, Some(rest) if !rest.is_empty()) {
        return None;
    }

    let n = fields.len();
    let port = |f: &Field| a2port(&f.arg);
    // a2port failures are -1 in C and rejected below; model as Option.
    let (listen, connect): (Option<Listen>, Option<Connect>) = match n {
        1 => {
            let l = if fields[0].ispath {
                Some(Listen::Path(fields[0].arg.clone()))
            } else {
                port(&fields[0]).map(|p| Listen::Port {
                    host: None,
                    port: p,
                })
            };
            (l, Some(Connect::Socks))
        }
        2 => {
            if fields[0].ispath && fields[1].ispath {
                (
                    Some(Listen::Path(fields[0].arg.clone())),
                    Some(Connect::Path(fields[1].arg.clone())),
                )
            } else if fields[1].ispath {
                (
                    port(&fields[0]).map(|p| Listen::Port {
                        host: None,
                        port: p,
                    }),
                    Some(Connect::Path(fields[1].arg.clone())),
                )
            } else {
                (
                    port(&fields[1]).map(|p| Listen::Port {
                        host: Some(fields[0].arg.clone()),
                        port: p,
                    }),
                    Some(Connect::Socks),
                )
            }
        }
        3 => {
            if fields[0].ispath {
                (
                    Some(Listen::Path(fields[0].arg.clone())),
                    port(&fields[2]).map(|p| Connect::HostPort {
                        host: fields[1].arg.clone(),
                        port: p,
                    }),
                )
            } else if fields[2].ispath {
                (
                    port(&fields[1]).map(|p| Listen::Port {
                        host: Some(fields[0].arg.clone()),
                        port: p,
                    }),
                    Some(Connect::Path(fields[2].arg.clone())),
                )
            } else {
                (
                    port(&fields[0]).map(|p| Listen::Port {
                        host: None,
                        port: p,
                    }),
                    port(&fields[2]).map(|p| Connect::HostPort {
                        host: fields[1].arg.clone(),
                        port: p,
                    }),
                )
            }
        }
        4 => (
            port(&fields[1]).map(|p| Listen::Port {
                host: Some(fields[0].arg.clone()),
                port: p,
            }),
            port(&fields[3]).map(|p| Connect::HostPort {
                host: fields[2].arg.clone(),
                port: p,
            }),
        ),
        _ => return None,
    };

    if dynamic {
        // OpenSSH also accepts `port:path` / `path:path` here, producing a
        // "dynamic" forward with a connect path that has no meaning; ssh3
        // rejects those.
        if !(n == 1 || n == 2) || connect != Some(Connect::Socks) {
            return None;
        }
    } else {
        let has_path =
            matches!(listen, Some(Listen::Path(_))) || matches!(connect, Some(Connect::Path(_)));
        if !(n == 3 || n == 4 || has_path) {
            return None;
        }
        // connect_port <= 0 without a connect path fails.
        match &connect {
            Some(Connect::HostPort { port, .. }) if *port == 0 => return None,
            Some(Connect::Socks) | None => return None,
            _ => {}
        }
    }
    let listen = listen?;
    let connect = connect?;
    if let Listen::Port { port: 0, .. } = listen
        && !remote
    {
        return None;
    }
    // NI_MAXHOST (1025) and sun_path (108) length limits.
    let too_long = |s: &str, max: usize| s.len() >= max;
    match &listen {
        Listen::Port { host: Some(h), .. } if too_long(h, 1025) => return None,
        Listen::Path(p) if too_long(p, 108) => return None,
        _ => {}
    }
    match &connect {
        Connect::HostPort { host, .. } if too_long(host, 1025) => return None,
        Connect::Path(p) if too_long(p, 108) => return None,
        _ => {}
    }
    Some(Forward { listen, connect })
}

/// Parse a UDP forward (ssh3 extension, `-U`/`-u`, `LocalUDPForward`,
/// `RemoteUDPForward`): same grammar as a TCP `-L`/`-R` forward, but only
/// host/port endpoints — UDP over Unix sockets and dynamic UDP are rejected.
pub fn parse_udp_forward(spec: &str, remote: bool) -> Option<Forward> {
    let f = parse_forward(spec, false, remote)?;
    match (&f.listen, &f.connect) {
        (Listen::Port { .. }, Connect::HostPort { .. }) => Some(f),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lf(s: &str) -> String {
        let f = parse_forward(s, false, false).unwrap();
        format!("{} {}", f.listen, f.connect)
    }

    #[test]
    fn local_forms() {
        assert_eq!(lf("8080:localhost:80"), "8080 [localhost]:80");
        assert_eq!(
            lf("127.0.0.1:8080:localhost:80"),
            "[127.0.0.1]:8080 [localhost]:80"
        );
        assert_eq!(lf("[::1]:8080:[fe80::1]:80"), "[::1]:8080 [fe80::1]:80");
        assert_eq!(lf("/tmp/l.sock:remote:80"), "/tmp/l.sock [remote]:80");
        assert_eq!(lf("8080:/run/x.sock"), "8080 /run/x.sock");
        assert_eq!(lf("/a/l:/b/c"), "/a/l /b/c");
        assert!(parse_forward("0:h:80", false, false).is_none());
        assert!(parse_forward("80:h:0", false, false).is_none());
        assert!(parse_forward("80:h", false, false).is_none());
        assert!(parse_forward("1:2:3:4:5", false, false).is_none());
    }

    #[test]
    fn dynamic_and_remote() {
        let d = parse_forward("1080", true, false).unwrap();
        assert_eq!(
            d.listen,
            Listen::Port {
                host: None,
                port: 1080
            }
        );
        assert!(d.is_dynamic());
        let d = parse_forward("[::1]:1080", true, false).unwrap();
        assert_eq!(
            d.listen,
            Listen::Port {
                host: Some("::1".into()),
                port: 1080
            }
        );
        let r = parse_forward("0:localhost:22", false, true).unwrap();
        assert_eq!(
            r.listen,
            Listen::Port {
                host: None,
                port: 0
            }
        );
        assert!(parse_forward("9001", false, true).is_none());
        assert!(parse_forward("9001", true, true).is_some());
    }

    #[test]
    fn service_names() {
        assert_eq!(a2port("ssh"), Some(22));
        assert_eq!(a2port("65536"), None);
        assert_eq!(a2port("nonexistent-service-xyz"), None);
    }

    #[test]
    fn udp() {
        assert!(parse_udp_forward("5353:10.0.0.1:53", false).is_some());
        assert!(parse_udp_forward("/tmp/s:10.0.0.1:53", false).is_none());
        assert!(parse_udp_forward("5353", false).is_none());
    }
}
