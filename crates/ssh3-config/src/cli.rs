//! Client command line, ported from OpenSSH 10.5p1 `ssh.c` `main()`
//! (option loop and destination parsing).
//!
//! The option letters are OpenSSH's, so `getopt` consumes arguments exactly
//! as `ssh` does. ssh3 adds two letters OpenSSH leaves unused:
//!
//! * `-U [bind:]port:host:hostport` — local UDP forward (like `-L`);
//! * `-u [bind:]port:host:hostport` — remote UDP forward (like `-R`).
//!
//! The matching config keywords are `LocalUDPForward` / `RemoteUDPForward`
//! (OpenSSH rejects them; guard them with `IgnoreUnknown` in a config that
//! OpenSSH also reads).

use crate::dest::{self, Uri};
use crate::env::LocalEnv;
use crate::expand;
use crate::forward::{self, Connect, Listen};
use crate::options::{Ctx, Flags, IdentitySource, LineError, Options, RequestTty, SessionType};

/// OpenSSH's optstring plus ssh3's `U:` and `u:`.
const OPTSTRING: &str =
    "1246ACGKMNTVXYZafgknqstvxyB:D:E:F:I:J:L:O:P:Q:R:S:W:b:c:e:i:l:m:o:p:w:U:u:";

/// The parsed command line, before any configuration file is read.
#[derive(Debug, Clone)]
pub struct CommandLine {
    /// Destination host exactly as given (`host_arg`, `%n`).
    pub host: String,
    /// Remote command words (joined with single spaces when sent).
    pub command: Vec<String>,
    /// `-F` value.
    pub config_file: Option<String>,
    /// Number of `-v` (log level above INFO).
    pub verbose: u8,
    /// `-q`.
    pub quiet: bool,
    /// `-G`: print the resolved configuration and exit.
    pub config_test: bool,
    /// `-n` (or `-f`).
    pub stdin_null: bool,
    /// `-f`.
    pub fork_after_authentication: bool,
    /// `-g`.
    pub gateway_ports: bool,
    /// OpenSSH options ssh3 parses but does not implement, as written
    /// (e.g. `-X`, `-c aes128-ctr`). The caller decides how to report them.
    pub unsupported: Vec<String>,
    pub(crate) user_on_commandline: bool,
    pub(crate) opts: Options,
}

impl CommandLine {
    pub fn command_string(&self) -> String {
        self.command.join(" ")
    }
}

fn takes_arg(c: char) -> Option<bool> {
    let i = OPTSTRING.find(c)?;
    Some(OPTSTRING[i + c.len_utf8()..].starts_with(':'))
}

fn usage() -> String {
    "usage: ssh3 [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address]\n\
     \x20          [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n\
     \x20          [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]\n\
     \x20          [-J destination] [-L address] [-l login_name] [-m mac_spec]\n\
     \x20          [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]\n\
     \x20          [-S ctl_path] [-U udp_address] [-u udp_address] [-W host:port]\n\
     \x20          [-w local_tun[:remote_tun]] destination [command [argument ...]]"
        .to_string()
}

/// Parse `ssh3` arguments (without `argv[0]`).
///
/// Mirrors OpenSSH: options stop at the first non-option (BSD `getopt`), the
/// destination is taken, and option parsing restarts after it, so options
/// may follow the destination; `--` ends options.
pub fn parse_args<S: AsRef<str>>(args: &[S], env: &LocalEnv) -> Result<CommandLine, String> {
    let argv: Vec<String> = args.iter().map(|a| a.as_ref().to_string()).collect();
    let mut cl = CommandLine {
        host: String::new(),
        command: Vec::new(),
        config_file: None,
        verbose: 0,
        quiet: false,
        config_test: false,
        stdin_null: false,
        fork_after_authentication: false,
        gateway_ports: false,
        unsupported: Vec::new(),
        user_on_commandline: false,
        opts: Options::default(),
    };
    let mut host: Option<String> = None;
    let mut pos = 0usize;
    loop {
        // One getopt() round starting at argv[pos].
        let mut opt_terminated = false;
        while pos < argv.len() {
            let a = &argv[pos];
            if a == "--" {
                pos += 1;
                opt_terminated = true;
                break;
            }
            if !a.starts_with('-') || a == "-" {
                break;
            }
            pos += 1;
            let cluster: Vec<char> = a[1..].chars().collect();
            let mut ci = 0;
            while ci < cluster.len() {
                let c = cluster[ci];
                ci += 1;
                let Some(needs) = takes_arg(c) else {
                    return Err(format!("ssh3: unknown option -- {c}\n{}", usage()));
                };
                let optarg = if needs {
                    let rest: String = cluster[ci..].iter().collect();
                    ci = cluster.len();
                    if !rest.is_empty() {
                        Some(rest)
                    } else if pos < argv.len() {
                        pos += 1;
                        Some(argv[pos - 1].clone())
                    } else {
                        return Err(format!(
                            "ssh3: option requires an argument -- {c}\n{}",
                            usage()
                        ));
                    }
                } else {
                    None
                };
                apply_flag(&mut cl, c, optarg, host.as_deref(), env)?;
            }
        }
        if host.is_none() && pos < argv.len() {
            let a = &argv[pos];
            match dest::parse_ssh_uri(a) {
                Uri::Invalid => return Err(usage()),
                Uri::Ok(hop) => {
                    // ssh.c sets user_on_commandline even when the URI has
                    // no user, which suppresses %-expansion of a configured
                    // User.
                    if cl.opts.user.is_none() {
                        cl.opts.user = hop.user;
                        cl.user_on_commandline = true;
                    }
                    if cl.opts.port.is_none() {
                        cl.opts.port = hop.port;
                    }
                    host = Some(hop.host);
                }
                Uri::NotUri => match a.rfind('@') {
                    Some(0) => return Err(usage()),
                    Some(at) => {
                        if cl.opts.user.is_none() {
                            cl.opts.user = Some(a[..at].to_string());
                            cl.user_on_commandline = true;
                        }
                        host = Some(a[at + 1..].to_string());
                    }
                    None => host = Some(a.clone()),
                },
            }
            pos += 1;
            if argv.len() - pos > 0 && !opt_terminated {
                // ssh.c: optind = optreset = 1; goto again.
                continue;
            }
        }
        break;
    }
    cl.command = argv[pos..].to_vec();
    let host = host.ok_or_else(usage)?;
    if let Some(u) = &cl.opts.user
        && !dest::valid_ruser(u)
    {
        return Err("remote username contains invalid characters".into());
    }
    if !dest::valid_hostname(&host) {
        return Err("hostname contains invalid characters".into());
    }
    if cl.command.is_empty() && cl.opts.session_type == Some(SessionType::Subsystem) {
        return Err(format!(
            "You must specify a subsystem to invoke.\n{}",
            usage()
        ));
    }
    cl.host = host;
    Ok(cl)
}

fn apply_flag(
    cl: &mut CommandLine,
    c: char,
    optarg: Option<String>,
    host: Option<&str>,
    env: &LocalEnv,
) -> Result<(), String> {
    let o = &mut cl.opts;
    let arg = optarg.clone().unwrap_or_default();
    match c {
        '1' => return Err("SSH protocol v.1 is no longer supported".into()),
        '2' => {}
        'n' => cl.stdin_null = true,
        'f' => {
            cl.fork_after_authentication = true;
            cl.stdin_null = true;
        }
        'G' => cl.config_test = true,
        'g' => cl.gateway_ports = true,
        'P' => {
            if o.tag.is_none() {
                o.tag = Some(arg);
            }
        }
        'a' => o.forward_agent = Some(false),
        'A' => o.forward_agent = Some(true),
        'i' => {
            let p = expand::tilde(&arg, env)?;
            if let Err(e) = std::fs::metadata(&p) {
                o.warnings
                    .push(format!("Warning: Identity file {p} not accessible: {e}."));
            } else {
                o.add_identity_file(p, IdentitySource::CommandLine)?;
            }
        }
        'J' => {
            if o.jump.is_some() {
                return Err("Only a single -J option is permitted (use commas to separate multiple jump hops)".into());
            }
            if o.proxy_command.is_some() {
                return Err("Cannot specify -J with ProxyCommand".into());
            }
            match dest::parse_jump(&arg, true) {
                Ok(dest::ProxyJump::None) => o.jump = Some(dest::ProxyJump::None),
                Ok(j) => {
                    o.jump = Some(j);
                    o.proxy_command = Some("none".into());
                }
                Err(e) => return Err(format!("Invalid -J argument: {e}")),
            }
        }
        't' => {
            o.request_tty = Some(if o.request_tty == Some(RequestTty::Yes) {
                RequestTty::Force
            } else {
                RequestTty::Yes
            })
        }
        'v' => cl.verbose = (cl.verbose + 1).min(3),
        'q' => cl.quiet = true,
        'W' => {
            if o.stdio_forward.is_some() {
                return Err("stdio forward already specified".into());
            }
            match forward::parse_forward(&arg, true, false) {
                Some(f) => match f.listen {
                    Listen::Port {
                        host: Some(h),
                        port,
                    } => o.stdio_forward = Some((h, port)),
                    // `-W port` or `-W path` parse as a forward but carry no
                    // host; OpenSSH would then dial a NULL host.
                    _ => return Err(format!("Bad stdio forwarding specification '{arg}'")),
                },
                None => return Err(format!("Bad stdio forwarding specification '{arg}'")),
            }
            o.request_tty = Some(RequestTty::No);
            o.session_type = Some(SessionType::None);
        }
        'p' => {
            if o.port.is_none() {
                match forward::a2port(&arg) {
                    Some(p) if p > 0 => o.port = Some(p),
                    _ => return Err(format!("Bad port '{arg}'")),
                }
            }
        }
        'l' => {
            if o.user.is_none() {
                o.user = Some(arg);
                cl.user_on_commandline = true;
            }
        }
        'L' | 'U' => {
            let f = if c == 'L' {
                forward::parse_forward(&arg, false, false)
            } else {
                forward::parse_udp_forward(&arg, false)
            };
            let Some(f) = f else {
                return Err(format!("Bad local forwarding specification '{arg}'"));
            };
            let list = if c == 'L' {
                &mut o.local_forwards
            } else {
                &mut o.local_udp_forwards
            };
            Options::add_forward(list, f);
        }
        'R' | 'u' => {
            let f = if c == 'R' {
                forward::parse_forward(&arg, false, true)
                    .or_else(|| forward::parse_forward(&arg, true, true))
            } else {
                forward::parse_udp_forward(&arg, true)
            };
            let Some(f) = f else {
                return Err(format!("Bad remote forwarding specification '{arg}'"));
            };
            let list = if c == 'R' {
                &mut o.remote_forwards
            } else {
                &mut o.remote_udp_forwards
            };
            Options::add_forward(list, f);
        }
        'D' => match forward::parse_forward(&arg, true, false) {
            Some(f) => {
                debug_assert_eq!(f.connect, Connect::Socks);
                Options::add_forward(&mut o.local_forwards, f);
            }
            None => return Err(format!("Bad dynamic forwarding specification '{arg}'")),
        },
        'N' => {
            if o.session_type.is_some() && o.session_type != Some(SessionType::None) {
                return Err("Cannot specify -N with -s/SessionType".into());
            }
            o.session_type = Some(SessionType::None);
            o.request_tty = Some(RequestTty::No);
        }
        'T' => o.request_tty = Some(RequestTty::No),
        's' => {
            if o.session_type.is_some() && o.session_type != Some(SessionType::Subsystem) {
                return Err("Cannot specify -s with -N/SessionType".into());
            }
            o.session_type = Some(SessionType::Subsystem);
        }
        'o' => {
            let h = host.unwrap_or("");
            let mut ctx = Ctx {
                env,
                host: h,
                original_host: h,
                remote_command: "",
                want_final_pass: false,
            };
            let flags = Flags {
                userconf: true,
                ..Flags::default()
            };
            match o.process_line(&mut ctx, &arg, "command-line", 0, None, flags, 0) {
                Ok(()) => {}
                Err(LineError::Bad(m)) | Err(LineError::Fatal(m)) => return Err(m),
            }
        }
        'F' => cl.config_file = Some(arg),
        // Parsed for argument compatibility with OpenSSH, not implemented.
        _ => cl.unsupported.push(match optarg {
            Some(a) => format!("-{c} {a}"),
            None => format!("-{c}"),
        }),
    }
    Ok(())
}
