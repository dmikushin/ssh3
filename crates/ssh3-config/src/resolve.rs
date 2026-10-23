//! Resolution of a command line plus configuration files into a
//! [`ClientConfig`], ported from OpenSSH 10.5p1 `ssh.c` `main()`
//! (`process_config_files`, host name handling, the final pass, token
//! expansion) and `readconf.c` `fill_default_options`.

use std::fmt::Write as _;

use sha1::{Digest, Sha1};

use crate::cli::CommandLine;
use crate::dest::{self, Hop, ProxyJump};
use crate::env::LocalEnv;
use crate::expand;
use crate::forward::{Connect, Forward};
use crate::options::{
    Canonicalize, Ctx, Flags, IdentitySource, LineError, Options, RawOption, RequestTty,
    SYSTEM_CONFIG, SessionType, StrictHostKeyChecking,
};

/// An identity file as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityFile {
    /// As written (after `~` expansion for `-i`), as `ssh -G` prints it.
    pub raw: String,
    /// `~` and `%`/`${}` expanded path; `None` for `IdentityFile none`.
    /// A `.pub` path is kept as given: it selects the agent key.
    pub path: Option<String>,
    pub source: IdentitySource,
}

/// `ForwardAgent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardAgent {
    No,
    Yes,
    /// Forward this agent socket (expanded path).
    Socket(String),
}

/// The fully resolved client configuration for one destination.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Destination as given on the command line (`host`, `%n`).
    pub host_arg: String,
    /// Host to connect to: `HostName` with `%h` expanded, lower-cased
    /// unless it is an address.
    pub hostname: String,
    pub user: String,
    pub port: u16,
    pub identity_files: Vec<IdentityFile>,
    pub identities_only: bool,
    /// Expanded `IdentityAgent` (may be `none` or `SSH_AUTH_SOCK`).
    pub identity_agent: Option<String>,
    /// `ProxyJump` hops in connection order; empty = direct.
    pub proxy_jump: Vec<Hop>,
    /// `ProxyCommand` (ssh3 does not run proxy commands; exposed so the
    /// caller can refuse it explicitly).
    pub proxy_command: Option<String>,
    pub local_forwards: Vec<Forward>,
    pub dynamic_forwards: Vec<Forward>,
    pub remote_forwards: Vec<Forward>,
    pub local_udp_forwards: Vec<Forward>,
    pub remote_udp_forwards: Vec<Forward>,
    /// `-W host:port`.
    pub stdio_forward: Option<(String, u16)>,
    pub server_alive_interval: u32,
    pub server_alive_count_max: u32,
    pub strict_host_key_checking: StrictHostKeyChecking,
    /// Expanded; empty for `UserKnownHostsFile none`.
    pub user_known_hosts_files: Vec<String>,
    pub hash_known_hosts: bool,
    pub forward_agent: ForwardAgent,
    pub request_tty: RequestTty,
    pub session_type: SessionType,
    pub send_env: Vec<String>,
    /// `SetEnv` entries `NAME=value`, value expanded.
    pub set_env: Vec<String>,
    /// Seconds; `None` = system default.
    pub connect_timeout: Option<u32>,
    pub exit_on_forward_failure: bool,
    /// Command line command, or expanded `RemoteCommand`.
    pub remote_command: Option<String>,
    /// Expanded `RemoteCommand` only (for `ssh -G` output).
    pub config_remote_command: Option<String>,
    pub host_key_alias: Option<String>,
    pub tag: Option<String>,
    pub verbose: u8,
    pub quiet: bool,
    pub config_test: bool,
    pub stdin_null: bool,
    pub fork_after_authentication: bool,
    pub gateway_ports: bool,
    pub unsupported_flags: Vec<String>,
    /// Known OpenSSH keywords ssh3 does not interpret, as written.
    pub other: Vec<RawOption>,
    /// Unknown keywords (ssh3 keeps them instead of failing).
    pub unknown: Vec<RawOption>,
    pub warnings: Vec<String>,
    /// `ProxyJump` exactly as OpenSSH stores it, for `ssh -G` output.
    jump_dump: Option<String>,
    /// Local and dynamic forwards in their original combined order, for
    /// `ssh -G` output.
    local_all: Vec<Forward>,
}

/// `ssh_connection_hash()`: SHA-1 of thishost, host, port, user, jumphost.
pub fn connection_hash(thishost: &str, host: &str, port: &str, user: &str, jump: &str) -> String {
    let mut h = Sha1::new();
    for part in [thishost, host, port, user, jump] {
        h.update(part.as_bytes());
    }
    h.finalize()
        .iter()
        .fold(String::with_capacity(40), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// `is_addr()`: a single numeric address (contains `%` or `:`, is
/// all digits and dots, or parses as an IP address).
fn is_addr(name: &str) -> bool {
    name.contains('%')
        || name.contains(':')
        || name.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        || name.parse::<std::net::IpAddr>().is_ok()
}

fn line_err(e: LineError) -> String {
    match e {
        LineError::Bad(m) | LineError::Fatal(m) => m,
    }
}

/// Parse the command line and resolve the configuration, as `ssh` does
/// before connecting. `args` excludes `argv[0]`.
pub fn resolve_args<S: AsRef<str>>(args: &[S], env: &LocalEnv) -> Result<ClientConfig, String> {
    let cl = crate::cli::parse_args(args, env)?;
    resolve(cl, env)
}

fn process_config_files(
    opts: &mut Options,
    cl: &CommandLine,
    env: &LocalEnv,
    host: &str,
    final_pass: bool,
) -> Result<bool, String> {
    let command = cl.command_string();
    let mut ctx = Ctx {
        env,
        host,
        original_host: &cl.host,
        remote_command: &command,
        want_final_pass: false,
    };
    let mut active = true;
    match cl.config_file.as_deref() {
        Some(f) if f.eq_ignore_ascii_case("none") => {}
        Some(f) => {
            let flags = Flags {
                userconf: true,
                final_pass,
                ..Flags::default()
            };
            let found = opts
                .read_file_depth(&mut ctx, f, &mut active, flags, 0)
                .map_err(line_err)?;
            if !found {
                return Err(format!(
                    "Can't open user config file {f}: No such file or directory"
                ));
            }
        }
        None => {
            let user_conf = format!("{}/.ssh/config", env.home);
            let flags = Flags {
                checkperm: true,
                userconf: true,
                final_pass,
                ..Flags::default()
            };
            opts.read_file_depth(&mut ctx, &user_conf, &mut active, flags, 0)
                .map_err(line_err)?;
            let mut active = true;
            let flags = Flags {
                final_pass,
                ..Flags::default()
            };
            opts.read_file_depth(&mut ctx, SYSTEM_CONFIG, &mut active, flags, 0)
                .map_err(line_err)?;
        }
    }
    Ok(ctx.want_final_pass)
}

/// Resolve a parsed command line.
pub fn resolve(mut cl: CommandLine, env: &LocalEnv) -> Result<ClientConfig, String> {
    let mut o = std::mem::take(&mut cl.opts);
    let host_arg = cl.host.clone();

    let mut want_final = process_config_files(&mut o, &cl, env, &host_arg, false)?;

    // HostName with %h expanded becomes the host.
    let mut host = host_arg.clone();
    if let Some(hn) = &o.hostname {
        host = expand::percent(hn, &[('h', &host)]).map_err(|e| format!("HostName: {e}"))?;
        o.hostname = Some(host.clone());
    }
    if !is_addr(&host) {
        host = host.to_ascii_lowercase();
    }
    // ssh3 performs no DNS canonicalisation, but CanonicalizeHostname still
    // requests the re-parse, as in OpenSSH.
    if matches!(
        o.canonicalize_hostname,
        Some(Canonicalize::Yes | Canonicalize::Always)
    ) {
        want_final = true;
        o.warnings
            .push("CanonicalizeHostname: ssh3 does not canonicalize host names".into());
    }
    if want_final {
        o.hostname = Some(host.clone());
        process_config_files(&mut o, &cl, env, &host, true)?;
    }

    // fill_default_options()
    let stdio = o.stdio_forward.is_some();
    let exit_on_forward_failure = o.exit_on_forward_failure.unwrap_or(stdio);
    if o.clear_all_forwardings.unwrap_or(stdio) {
        o.local_forwards.clear();
        o.remote_forwards.clear();
        o.local_udp_forwards.clear();
        o.remote_udp_forwards.clear();
    }
    if o.identity_files.is_empty() {
        for f in [
            "id_rsa",
            "id_ecdsa",
            "id_ecdsa_sk",
            "id_ed25519",
            "id_ed25519_sk",
            "id_mldsa44_ed25519",
        ] {
            o.identity_files
                .push((format!("~/.ssh/{f}"), IdentitySource::Default));
        }
    }
    if o.user_known_hosts_files.is_empty() {
        o.user_known_hosts_files = vec!["~/.ssh/known_hosts".into(), "~/.ssh/known_hosts2".into()];
    }
    if o.proxy_command
        .as_deref()
        .is_some_and(|p| p.eq_ignore_ascii_case("none"))
    {
        o.proxy_command = None;
    }
    if o.remote_command
        .as_deref()
        .is_some_and(|p| p.eq_ignore_ascii_case("none"))
    {
        o.remote_command = None;
    }
    if o.jump == Some(ProxyJump::None) {
        o.jump = None;
    }

    let user_was_default = o.user.is_none();
    let mut user = o.user.clone().unwrap_or_else(|| env.user.clone());

    let port = match o.port {
        Some(p) if p > 0 => p,
        _ => env.default_port,
    };
    if let Some(ProxyJump::Hops { hops, .. }) = &o.jump {
        let last = hops.last().expect("parse_jump yields at least one hop");
        let jport = last.port.unwrap_or(env.default_port);
        let juser = last.user.as_deref().unwrap_or(&user);
        if last.host == host && port == jport && user == juser {
            return Err(format!("jumphost loop via {}", last.host));
        }
        if o.proxy_command.is_some() {
            return Err("inconsistent options: ProxyCommand+ProxyJump".into());
        }
    }
    let host_key_alias = o.host_key_alias.as_ref().map(|a| a.to_ascii_lowercase());
    let command = cl.command_string();
    if !command.is_empty() && o.remote_command.is_some() {
        return Err("Cannot execute command-line and remote command.".into());
    }
    if cl.fork_after_authentication
        && command.is_empty()
        && o.remote_command.is_none()
        && o.session_type != Some(SessionType::None)
    {
        return Err("Cannot fork into background without a command to execute.".into());
    }

    // Token values (struct ssh_conn_info).
    let portstr = port.to_string();
    let uidstr = env.uid.to_string();
    let keyalias = host_key_alias.clone().unwrap_or_else(|| host_arg.clone());
    let jmphost = match &o.jump {
        Some(ProxyJump::Hops { hops, .. }) => {
            hops.last().map(|h| h.host.clone()).unwrap_or_default()
        }
        _ => String::new(),
    };
    let nouser: Vec<(char, &str)> = vec![
        ('L', env.short_hostname()),
        ('i', &uidstr),
        ('k', &keyalias),
        ('l', &env.hostname),
        ('n', &host_arg),
        ('p', &portstr),
        ('d', &env.home),
        ('h', &host),
        ('u', &env.user),
        ('j', &jmphost),
    ];
    if !cl.user_on_commandline && !user_was_default {
        let expanded = expand::percent_dollar(&user, &nouser)
            .map_err(|_| "invalid environment variable expansion".to_string())?;
        let changed = expanded != user;
        user = expanded;
        if changed && !dest::valid_ruser(&user) {
            return Err("remote username contains invalid characters".into());
        }
    }
    let conn_hash = connection_hash(&env.hostname, &host, &portstr, &user, &jmphost);
    let mut tokens = nouser.clone();
    tokens.push(('C', &conn_hash));
    tokens.push(('r', &user));
    let pexp = |s: &str| expand::percent(s, &tokens).map_err(|e| e.to_string());
    let pdexp = |s: &str| {
        expand::percent_dollar(s, &tokens)
            .map_err(|_| "invalid environment variable expansion".to_string())
    };
    let tilde_pd = |s: &str| -> Result<String, String> { pdexp(&expand::tilde(s, env)?) };

    let config_remote_command = o.remote_command.as_deref().map(pexp).transpose()?;
    let identity_agent = o.identity_agent.as_deref().map(tilde_pd).transpose()?;
    let forward_agent = match (&o.forward_agent_sock_path, o.forward_agent.unwrap_or(false)) {
        (Some(p), _) => ForwardAgent::Socket(tilde_pd(p)?),
        (None, true) => ForwardAgent::Yes,
        (None, false) => ForwardAgent::No,
    };
    let user_known_hosts_files = if o.user_known_hosts_files[0].eq_ignore_ascii_case("none") {
        Vec::new()
    } else {
        o.user_known_hosts_files
            .iter()
            .map(|f| tilde_pd(f))
            .collect::<Result<_, _>>()?
    };
    let set_env = o
        .set_env
        .iter()
        .map(|kv| {
            let (k, v) = kv.split_once('=').expect("SetEnv entries contain '='");
            Ok(format!("{k}={}", pdexp(v)?))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let expand_fwd = |f: &Forward| -> Result<Forward, String> {
        use crate::forward::Listen;
        let listen = match &f.listen {
            Listen::Path(p) => Listen::Path(pexp(p)?),
            l => l.clone(),
        };
        let connect = match &f.connect {
            Connect::Path(p) => Connect::Path(pexp(p)?),
            c => c.clone(),
        };
        Ok(Forward { listen, connect })
    };
    let local_all = o
        .local_forwards
        .iter()
        .map(expand_fwd)
        .collect::<Result<Vec<_>, _>>()?;
    let remote_forwards = o
        .remote_forwards
        .iter()
        .map(expand_fwd)
        .collect::<Result<Vec<_>, _>>()?;
    let (dynamic_forwards, local_forwards): (Vec<_>, Vec<_>) =
        local_all.iter().cloned().partition(Forward::is_dynamic);
    let identity_files = o
        .identity_files
        .iter()
        .map(|(raw, source)| {
            let path = if raw.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(tilde_pd(raw)?)
            };
            Ok(IdentityFile {
                raw: raw.clone(),
                path,
                source: *source,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let jump_dump = o.jump.as_ref().and_then(ProxyJump::dump);
    let proxy_jump = match o.jump {
        Some(ProxyJump::Hops { hops, .. }) => hops,
        _ => Vec::new(),
    };
    let session_type = o.session_type.unwrap_or(SessionType::Default);
    let remote_command = if command.is_empty() {
        config_remote_command.clone()
    } else {
        Some(command)
    };

    Ok(ClientConfig {
        host_arg,
        hostname: host,
        user,
        port,
        identity_files,
        identities_only: o.identities_only.unwrap_or(false),
        identity_agent,
        proxy_jump,
        proxy_command: o.proxy_command,
        local_forwards,
        dynamic_forwards,
        remote_forwards,
        local_udp_forwards: o.local_udp_forwards,
        remote_udp_forwards: o.remote_udp_forwards,
        stdio_forward: o.stdio_forward,
        server_alive_interval: o.server_alive_interval.unwrap_or(0),
        server_alive_count_max: o.server_alive_count_max.unwrap_or(3),
        strict_host_key_checking: o
            .strict_host_key_checking
            .unwrap_or(StrictHostKeyChecking::Ask),
        user_known_hosts_files,
        hash_known_hosts: o.hash_known_hosts.unwrap_or(false),
        forward_agent,
        request_tty: o.request_tty.unwrap_or(RequestTty::Auto),
        session_type,
        send_env: o.send_env,
        set_env,
        connect_timeout: o.connect_timeout,
        exit_on_forward_failure,
        remote_command,
        config_remote_command,
        host_key_alias,
        tag: o.tag,
        verbose: cl.verbose,
        quiet: cl.quiet,
        config_test: cl.config_test,
        stdin_null: cl.stdin_null,
        fork_after_authentication: cl.fork_after_authentication,
        gateway_ports: cl.gateway_ports,
        unsupported_flags: cl.unsupported,
        other: o.other,
        unknown: o.unknown,
        warnings: o.warnings,
        jump_dump,
        local_all,
    })
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

impl ClientConfig {
    /// Whether a pty should be requested (ssh.c tty_flag logic).
    pub fn wants_tty(&self, stdin_is_tty: bool) -> bool {
        let mut tty = matches!(self.request_tty, RequestTty::Yes | RequestTty::Force);
        if self.remote_command.is_none() {
            tty = self.request_tty != RequestTty::No;
        }
        if self.request_tty == RequestTty::No || self.session_type == SessionType::None {
            tty = false;
        }
        if (!stdin_is_tty || self.stdin_null) && self.request_tty != RequestTty::Force {
            tty = false;
        }
        tty
    }

    /// The keywords ssh3-config resolves, formatted exactly as `ssh -G`
    /// prints them (same names, value spellings and per-keyword order).
    pub fn dump(&self) -> String {
        let mut s = String::new();
        let mut line = |k: &str, v: &str| {
            s.push_str(k);
            s.push(' ');
            s.push_str(v);
            s.push('\n');
        };
        line("host", &self.host_arg);
        line("user", &self.user);
        line("hostname", &self.hostname);
        line("port", &self.port.to_string());
        line("exitonforwardfailure", yes_no(self.exit_on_forward_failure));
        line("hashknownhosts", yes_no(self.hash_known_hosts));
        line("identitiesonly", yes_no(self.identities_only));
        line("requesttty", self.request_tty.dump());
        line(
            "stricthostkeychecking",
            self.strict_host_key_checking.dump(),
        );
        line(
            "serveralivecountmax",
            &self.server_alive_count_max.to_string(),
        );
        line(
            "serveraliveinterval",
            &self.server_alive_interval.to_string(),
        );
        if let Some(a) = &self.identity_agent {
            line("identityagent", a);
        }
        if let Some(c) = &self.config_remote_command {
            line("remotecommand", c);
        }
        if let Some(t) = &self.tag {
            line("tag", t);
        }
        // dump_cfg_forwards() selects dynamic forwards as "connect host is
        // NULL or socks", so OpenSSH also lists forwards to a Unix socket
        // under dynamicforward. That is a display quirk of `ssh -G`, kept
        // here for identical output; `dynamic_forwards` holds only real
        // dynamic forwards.
        for f in &self.local_all {
            if matches!(f.connect, Connect::Socks | Connect::Path(_)) {
                line("dynamicforward", &f.listen.to_string());
            }
        }
        for f in &self.local_all {
            if !f.is_dynamic() {
                line("localforward", &format!("{} {}", f.listen, f.connect));
            }
        }
        for f in &self.remote_forwards {
            line("remoteforward", &format!("{} {}", f.listen, f.connect));
        }
        for f in &self.identity_files {
            line("identityfile", &f.raw);
        }
        if self.user_known_hosts_files.is_empty() {
            line("userknownhostsfile", "none");
        } else {
            line("userknownhostsfile", &self.user_known_hosts_files.join(" "));
        }
        for e in &self.send_env {
            line("sendenv", e);
        }
        for e in &self.set_env {
            line("setenv", e);
        }
        match &self.forward_agent {
            ForwardAgent::No => line("forwardagent", "no"),
            ForwardAgent::Yes => line("forwardagent", "yes"),
            ForwardAgent::Socket(p) => line("forwardagent", p),
        }
        match self.connect_timeout {
            None => line("connecttimeout", "none"),
            Some(t) => line("connecttimeout", &t.to_string()),
        }
        if let Some(j) = &self.jump_dump {
            line("proxyjump", j);
        } else if let Some(p) = &self.proxy_command {
            line("proxycommand", p);
        }
        s
    }
}
