//! `ssh3`: the client program. OpenSSH command line and ~/.ssh/config
//! (ssh3-config), default port 443.
//!
//! Authenticates (agent / `.pub`-selected agent key / key file, OpenSSH
//! order), verifies the host key against known_hosts with a fresh verifier
//! per dial, then runs the session (shell, exec, subsystem; pty with raw
//! local terminal) and the forwards (-L, -R, -D, UDP -U/-u) with roaming and
//! automatic resume. `-J` / ProxyJump (SPEC §7.2): each hop is resolved
//! through its own ssh_config (as ssh(1) does for its jump hosts), and every
//! connection — to each hop and to the target — is end to end: it verifies
//! that host's key against known_hosts and authenticates to that host; a
//! gateway only relays inner ciphertext. Exit status: the remote command's, 128+n for a remote
//! signal n, 255 for ssh3's own failures — as ssh(1).
//!
//! ssh3 extensions in ssh_config: `ContactWarn <duration>` (default 6500ms):
//! after this long without hearing the server, a terminal shows "Last
//! contact N s ago" (SPEC §5). `DirectPath yes|no` (default yes): for a host
//! reached through a jump, try the direct-path upgrade (SPEC §7.3); `no`
//! keeps the connection on the gateway's relay.
//!
//! What it refuses, by name, instead of silently ignoring (a missing
//! feature must never look like a working one): Unix-socket forwards,
//! dynamic -R, ProxyCommand, -f, and configuration
//! options whose enforcement the user may rely on for security but which
//! ssh3 would not apply (`SECURITY_OPTIONS`).

use std::io::{IsTerminal, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ssh3_config::{ClientConfig, Connect, Forward, ForwardAgent, IdentitySource, Listen, LocalEnv, LogLevel, SessionType};
use ssh3_core::{Command, ExitInfo, PtySpec, SessionChannel, SessionSpec};

use crate::tty::{self, RawMode, StatusLine};
use ssh3_core::auth::{PublicKey, Signer};
use ssh3_core::client::{HostCheck, SocketFactory, dual_stack_factory};
use ssh3_core::{ClientOptions, ClientSession, Error, Limits};
use ssh3_keys::signer::{AgentClient, AgentSigner, resolve_identity};
use ssh3_keys::verifier::{StrictHostKeyChecking, UnknownHost};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::signal::unix::{SignalKind, signal};

use crate::predict::{Display, PredictionEngine, Preference};

/// ssh(1) exits 255 for its own errors.
const FAIL: u8 = 255;

/// The client shows "Last contact" after this long without hearing the
/// server (SPEC §5 ContactWarn, mosh terminaloverlay.h:159).
const CONTACT_WARN: Duration = Duration::from_millis(6500);

/// `ContactWarn` from ssh_config (an ssh3 keyword, kept by ssh3-config in
/// `unknown`), else the default.
fn contact_warn(c: &ClientConfig) -> Result<Duration, String> {
    match c.unknown.iter().find(|o| o.keyword == "contactwarn") {
        Some(o) => crate::duration::parse(o.args.first().map_or("", String::as_str)).map_err(|e| format!("{}:{}: ContactWarn: {e}", o.file, o.line)),
        None => Ok(CONTACT_WARN),
    }
}

/// `PredictiveEcho` from ssh_config (an ssh3 keyword, SPEC §5.2): mosh's
/// `--predict` modes, default adaptive.
fn predictive_echo(c: &ClientConfig) -> Result<Preference, String> {
    match c.unknown.iter().find(|o| o.keyword == "predictiveecho") {
        Some(o) => match o.args.first().map(|a| a.to_ascii_lowercase()).as_deref() {
            Some("adaptive") => Ok(Preference::Adaptive),
            Some("always") => Ok(Preference::Always),
            Some("never") => Ok(Preference::Never),
            _ => Err(format!("{}:{}: PredictiveEcho: expected adaptive, always or never", o.file, o.line)),
        },
        None => Ok(Preference::Adaptive),
    }
}

/// `DirectPath` from ssh_config (an ssh3 keyword), default yes.
fn direct_path(c: &ClientConfig) -> Result<bool, String> {
    match c.unknown.iter().find(|o| o.keyword == "directpath") {
        Some(o) => match o.args.first().map(|a| a.to_ascii_lowercase()).as_deref() {
            Some("yes") => Ok(true),
            Some("no") => Ok(false),
            _ => Err(format!("{}:{}: DirectPath: expected yes or no", o.file, o.line)),
        },
        None => Ok(true),
    }
}

/// `other` options that ask for a security property ssh3 would not
/// enforce, with the values that do so. Refused rather than ignored.
/// Does this option value ask for something ssh3 would not enforce?
type Refuses = fn(&[String]) -> bool;

const SECURITY_OPTIONS: &[(&str, Refuses)] = &[
    ("revokedhostkeys", |a| a.first().is_some_and(|v| v != "none")),
    ("checkhostip", |a| a.first().is_some_and(|v| v.eq_ignore_ascii_case("yes"))),
    ("pubkeyauthentication", |a| a.first().is_some_and(|v| v.eq_ignore_ascii_case("no"))),
    ("hostkeyalgorithms", |_| true),
    ("pubkeyacceptedalgorithms", |_| true),
    ("pubkeyacceptedkeytypes", |_| true),
    ("casignaturealgorithms", |_| true),
    ("requiredrsasize", |_| true),
    ("forwardx11", |a| a.first().is_some_and(|v| v.eq_ignore_ascii_case("yes"))),
    ("forwardx11trusted", |a| a.first().is_some_and(|v| v.eq_ignore_ascii_case("yes"))),
    ("tunnel", |a| a.first().is_some_and(|v| !v.eq_ignore_ascii_case("no"))),
];

pub fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let env = match LocalEnv::from_system(443) {
        Ok(e) => e,
        Err(e) => return fail(&e),
    };
    let cl = match ssh3_config::parse_args(&argv, &env) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    // Jump hosts are resolved with the same -F as the destination (ssh(1)
    // passes -F to its jump connections).
    let config_file = cl.config_file.clone();
    let cfg = match ssh3_config::resolve(cl, &env) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    if cfg.config_test {
        print!("{}", cfg.dump());
        return ExitCode::SUCCESS;
    }
    init_logging(cfg.log_level);
    if cfg.log_level >= LogLevel::Verbose {
        for w in &cfg.warnings {
            eprintln!("ssh3: {w}");
        }
    }
    if let Err(e) = refusals(&cfg) {
        return fail(&e);
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => return fail(&format!("tokio runtime: {e}")),
    };
    let code = rt.block_on(run(cfg, Jumps { config_file, env }));
    // The stdin reader is a plain thread blocked in read(2); nothing of the
    // runtime is left that must finish.
    rt.shutdown_background();
    code
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("ssh3: {msg}");
    ExitCode::from(FAIL)
}

fn init_logging(l: LogLevel) {
    let level = match l {
        LogLevel::Quiet | LogLevel::Fatal | LogLevel::Error => "error",
        LogLevel::Info => "warn",
        LogLevel::Verbose => "info",
        LogLevel::Debug1 => "debug",
        LogLevel::Debug2 | LogLevel::Debug3 => "trace",
    };
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| level.into());
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new(filter)).with_writer(std::io::stderr).init();
}

/// Everything the configuration asks for that this client cannot do.
pub fn refusals(c: &ClientConfig) -> Result<(), String> {
    let mut why = Vec::new();
    if !c.unsupported_flags.is_empty() {
        why.push(format!("unsupported option(s): {}", c.unsupported_flags.join(" ")));
    }
    if c.proxy_command.is_some() {
        why.push("ProxyCommand is not supported by ssh3 (it never runs proxy commands)".into());
    }
    if c.fork_after_authentication {
        why.push("-f is not implemented yet".into());
    }
    for f in c.local_forwards.iter().chain(&c.remote_forwards).chain(&c.dynamic_forwards).chain(&c.local_udp_forwards).chain(&c.remote_udp_forwards) {
        if matches!(f.listen, Listen::Path(_)) || matches!(f.connect, Connect::Path(_)) {
            why.push(format!("Unix-socket forward {}:{} is not implemented yet", f.listen, f.connect));
        }
    }
    for f in &c.remote_forwards {
        if f.is_dynamic() {
            why.push(format!("dynamic remote forward {} is not implemented yet", f.listen));
        }
    }
    for o in &c.other {
        if let Some((_, refused)) = SECURITY_OPTIONS.iter().find(|(k, _)| *k == o.keyword)
            && refused(&o.args)
        {
            why.push(format!("{}:{}: {} {} is not enforced by ssh3; remove it or use ssh", o.file, o.line, o.keyword, o.args.join(" ")));
        }
    }
    predictive_echo(c)?;
    if let (Ok(warn), Some(probe)) = (contact_warn(c), client_limits(c).probe_interval)
        && warn < probe * 2
    {
        // On a healthy idle link the server is heard about once per probe
        // interval: a shorter warning would show "Last contact" every
        // second for nothing.
        return Err(format!(
            "ContactWarn {warn:?} is shorter than twice the liveness probe interval {probe:?} (ServerAliveInterval, default 1 s): it would show on a healthy link"
        ));
    }
    if let Err(e) = contact_warn(c) {
        why.push(e);
    }
    if let Err(e) = direct_path(c) {
        why.push(e);
    }
    if why.is_empty() { Ok(()) } else { Err(why.join("\nssh3: ")) }
}

fn host_check(c: &ClientConfig) -> HostCheck {
    let files = c.user_known_hosts_files.iter().chain(&c.global_known_hosts_files).map(PathBuf::from).collect();
    let mode = match c.strict_host_key_checking {
        ssh3_config::StrictHostKeyChecking::Off => StrictHostKeyChecking::No,
        ssh3_config::StrictHostKeyChecking::AcceptNew => StrictHostKeyChecking::AcceptNew,
        ssh3_config::StrictHostKeyChecking::Yes => StrictHostKeyChecking::Yes,
        // BatchMode: no prompt, so an unknown host is refused (as ssh(1)).
        ssh3_config::StrictHostKeyChecking::Ask if c.batch_mode => StrictHostKeyChecking::Yes,
        ssh3_config::StrictHostKeyChecking::Ask => StrictHostKeyChecking::Ask,
    };
    HostCheck {
        name: c.host_key_alias.clone().unwrap_or_else(|| c.hostname.clone()),
        port: c.port,
        files,
        mode,
        hash_known_hosts: c.hash_known_hosts,
        prompt: Some(Arc::new(ask_tty)),
    }
}

/// ssh(1)'s unknown-host question, on the controlling terminal.
fn ask_tty(u: &UnknownHost) -> bool {
    use std::io::BufRead;
    let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") else { return false };
    let mut w = &tty;
    let host = if u.port == 22 { u.host.clone() } else { format!("[{}]:{}", u.host, u.port) };
    let _ = write!(
        w,
        "The authenticity of host '{host}' can't be established.\n{} key fingerprint is {}.\nAre you sure you want to continue connecting (yes/no)? ",
        u.key.algorithm(),
        u.fingerprint
    );
    let mut line = String::new();
    loop {
        line.clear();
        if std::io::BufReader::new(&tty).read_line(&mut line).unwrap_or(0) == 0 {
            return false;
        }
        match line.trim() {
            "yes" => return true,
            "no" => return false,
            _ => {
                let _ = write!(w, "Please type 'yes' or 'no': ");
            }
        }
    }
}

fn agent(c: &ClientConfig) -> Option<AgentClient> {
    match c.identity_agent.as_deref() {
        Some("none") => None,
        None | Some("SSH_AUTH_SOCK") => AgentClient::from_env().ok(),
        Some(p) => Some(AgentClient::new(p)),
    }
}

/// The agent socket `-A` forwards: ForwardAgent's own socket, else the
/// agent ssh3 uses (IdentityAgent / SSH_AUTH_SOCK) — as ssh(1), where
/// `IdentityAgent none` also leaves nothing to forward.
fn forwarded_agent(c: &ClientConfig) -> Option<PathBuf> {
    match &c.forward_agent {
        ForwardAgent::No => None,
        ForwardAgent::Socket(p) => Some(PathBuf::from(p)),
        ForwardAgent::Yes => agent(c).map(|a| a.socket().to_path_buf()),
    }
}

/// Signers in the order they are offered: IdentityFile entries (through the
/// agent when it holds the key), then the agent's other keys unless
/// IdentitiesOnly. Missing default identities are skipped silently, as
/// ssh(1) does; problems with explicitly configured ones are reported.
fn signers(c: &ClientConfig) -> Vec<Arc<dyn Signer>> {
    let agent = agent(c);
    let mut out: Vec<Arc<dyn Signer>> = Vec::new();
    let mut seen: Vec<PublicKey> = Vec::new();
    for id in &c.identity_files {
        let Some(p) = &id.path else { continue };
        let path = Path::new(p);
        if id.source == IdentitySource::Default && !path.exists() {
            continue;
        }
        match resolve_identity(path, agent.as_ref()) {
            Ok(s) => {
                let s: Arc<dyn Signer> = Arc::from(s);
                seen.push(s.public_key().clone());
                out.push(s);
            }
            Err(e) => eprintln!("ssh3: identity {}: {e}", id.raw),
        }
    }
    if !c.identities_only
        && let Some(a) = &agent
    {
        match a.identities() {
            Ok(keys) => {
                for k in keys {
                    if !seen.iter().any(|s| ssh3_keys::spki::same_key(s, &k)) {
                        out.push(Arc::new(AgentSigner::new(a.clone(), k)));
                    }
                }
            }
            Err(e) => tracing::info!("agent {}: {e}", a.socket().display()),
        }
    }
    out
}

async fn resolve_addrs(c: &ClientConfig) -> Result<Vec<SocketAddr>, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((c.hostname.as_str(), c.port))
        .await
        .map_err(|e| format!("Could not resolve hostname {}: {e}", c.hostname))?
        .filter(|a| match c.address_family {
            ssh3_config::AddressFamily::Any => true,
            ssh3_config::AddressFamily::Inet => a.is_ipv4(),
            ssh3_config::AddressFamily::Inet6 => a.is_ipv6(),
        })
        .collect();
    if addrs.is_empty() {
        return Err(format!("Could not resolve hostname {}: no address of the requested family", c.hostname));
    }
    Ok(addrs)
}

/// The destination's name, re-resolved before every automatic resume
/// attempt (its address may have changed while we were away).
fn resolver(c: &ClientConfig) -> ssh3_core::client::Resolver {
    let c = c.clone();
    Arc::new(move || {
        let c = c.clone();
        Box::pin(async move { resolve_addrs(&c).await.map_err(std::io::Error::other) })
    })
}

/// ServerAliveInterval / ServerAliveCountMax mean what they mean in ssh(1):
/// the server is declared dead after interval × count of silence. Here that
/// is the liveness probe period and the QUIC idle timeout (which also bounds
/// each resume attempt's handshake).
fn client_limits(c: &ClientConfig) -> Limits {
    let mut l = Limits::default();
    if c.server_alive_interval > 0 {
        let i = Duration::from_secs(c.server_alive_interval.into());
        l.probe_interval = Some(i);
        l.idle_timeout = i * c.server_alive_count_max.max(1);
        l.keep_alive = l.keep_alive.min(i);
    }
    l
}

async fn dial(c: &ClientConfig, addrs: Vec<SocketAddr>, resolve: Option<ssh3_core::client::Resolver>, host: &HostCheck, signers: &[Arc<dyn Signer>], sockets: SocketFactory, path: Option<Arc<ssh3_core::path::PathManager>>) -> Result<ClientSession, Error> {
    let opts = ClientOptions { server_addrs: addrs, resolve, host: host.clone(), signers: signers.to_vec(), user: c.user.clone(), limits: client_limits(c), sockets, path };
    let sock = (opts.sockets)().map_err(Error::Io)?;
    let fut = ClientSession::connect(opts, sock);
    match c.connect_timeout {
        Some(s) => tokio::time::timeout(Duration::from_secs(s.into()), fut)
            .await
            .map_err(|_| Error::Deadline(format!("ConnectTimeout {s} s")))?,
        None => fut.await,
    }
}

/// What jump hosts are resolved with: the destination's -F and the local
/// environment.
pub struct Jumps {
    pub config_file: Option<String>,
    pub env: LocalEnv,
}

/// ssh(1) bounds the depth of jump hosts that have jump hosts of their own.
const MAX_JUMP_DEPTH: usize = 8;

/// The connection chain to the destination. The hops (gateway sessions and
/// the relay paths through them) must live as long as the destination's
/// session; they are ended after it, innermost first.
struct Chain {
    hops: Vec<Arc<Hop>>,
    sess: ClientSession,
    /// One per hop: replaces the hop's gateway session when it is lost.
    supervisors: Vec<tokio::task::JoinHandle<()>>,
}

/// One jump hop: its configuration, its current session (replaced when the
/// gateway loses it), the relay path through it to the next host, and where
/// the hop itself is dialled (direct, or the previous hop's path).
struct Hop {
    cfg: ClientConfig,
    sess: std::sync::Mutex<Arc<ClientSession>>,
    path: ssh3_core::jump::JumpPath,
    via: Option<SocketAddr>,
    mgr: Arc<ssh3_core::path::PathManager>,
}

impl Hop {
    fn current(&self) -> Arc<ClientSession> {
        self.sess.lock().unwrap().clone()
    }
}

impl Chain {
    async fn end(self, gave_up: bool) {
        for t in &self.supervisors {
            t.abort();
        }
        // Every way out except a given-up resume is a deliberate end
        // (SPEC §5): the server destroys the session instead of lingering.
        if !gave_up {
            self.sess.end(END_BOUND).await;
        }
        drop(self.sess);
        for hop in self.hops.into_iter().rev() {
            hop.current().end(END_BOUND).await;
        }
    }
}

const REJUMP_RETRY_MIN: Duration = Duration::from_millis(250);
const REJUMP_RETRY_MAX: Duration = Duration::from_secs(10);

/// Keep hop `i` alive: when its gateway session is lost for good (resume
/// refused — the gateway restarted — or its linger passed), dial the gateway
/// again and move the relay path to the next host onto the new session
/// (carrier replacement, SPEC §7.2). The next session then resumes over the
/// same path by itself; no user action.
async fn supervise_hop(hops: Vec<Arc<Hop>>, i: usize) {
    loop {
        let cur = hops[i].current();
        cur.gave_up().await;
        drop(cur);
        let hop = &hops[i];
        tracing::warn!("lost the session to jump host {}; reconnecting", hop.cfg.hostname);
        let mut wait = REJUMP_RETRY_MIN;
        loop {
            let addrs = match hop.via {
                Some(v) => Ok(vec![v]),
                None => resolve_addrs(&hop.cfg).await,
            };
            let r = match addrs {
                Ok(a) => dial_one(&hop.cfg, a, hop.via.is_none(), dual_stack_factory(), Some(hop.mgr.clone())).await,
                Err(e) => Err(e),
            };
            match r {
                Ok(s) => match s.rejump(&hop.path).await {
                    Ok(()) => {
                        tracing::info!("jump host {} reconnected; relay moved onto the new session", hop.cfg.hostname);
                        *hop.sess.lock().unwrap() = Arc::new(s);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("jump host {}: relay not reopened: {e}", hop.cfg.hostname);
                        s.end(END_BOUND).await;
                    }
                },
                Err(e) => tracing::warn!("jump host {}: {e}", hop.cfg.hostname),
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(REJUMP_RETRY_MAX);
        }
    }
}

/// The ssh_config of one jump hop: resolved like a destination of its own
/// (`-l`/`-p` from the hop spec, the same -F), as ssh(1) does.
fn hop_config(hop: &ssh3_config::Hop, jumps: &Jumps) -> Result<ClientConfig, String> {
    let mut args: Vec<String> = Vec::new();
    if let Some(f) = &jumps.config_file {
        args.extend(["-F".into(), f.clone()]);
    }
    if let Some(u) = &hop.user {
        args.extend(["-l".into(), u.clone()]);
    }
    if let Some(p) = hop.port {
        args.extend(["-p".into(), p.to_string()]);
    }
    args.push(hop.host.clone());
    let c = ssh3_config::resolve_args(&args, &jumps.env).map_err(|e| format!("jump host {}: {e}", hop.host))?;
    refusals(&c).map_err(|e| format!("jump host {}: {e}", hop.host))?;
    Ok(c)
}

/// The hops before `c`, in connection order: a hop's own ProxyJump comes
/// before it, recursively (bounded).
fn hop_configs(c: &ClientConfig, jumps: &Jumps, depth: usize) -> Result<Vec<ClientConfig>, String> {
    if c.proxy_jump.is_empty() {
        return Ok(Vec::new());
    }
    if depth >= MAX_JUMP_DEPTH {
        return Err(format!("more than {MAX_JUMP_DEPTH} nested jump hosts"));
    }
    let mut out = Vec::new();
    for (i, h) in c.proxy_jump.iter().enumerate() {
        let hc = hop_config(h, jumps)?;
        // Only the first hop's own ProxyJump applies; later hops are reached
        // through the previous one (ssh -J a,b: b is reached via a).
        if i == 0 {
            out.extend(hop_configs(&hc, jumps, depth + 1)?);
        }
        out.push(hc);
    }
    Ok(out)
}

/// One authenticated connection to `c` at `addr` over `sockets`, every key
/// offered in order on it (core stops at MaxAuthTries), with ssh(1)'s
/// messages for the two refusals the user must be able to tell apart.
/// `by_name`: `c.hostname` is what was resolved to `addrs` (re-resolved on
/// automatic resumes); false for a jump path's fixed virtual address.
async fn dial_one(c: &ClientConfig, addrs: Vec<SocketAddr>, by_name: bool, sockets: SocketFactory, path: Option<Arc<ssh3_core::path::PathManager>>) -> Result<ClientSession, String> {
    let host = host_check(c);
    let signers = signers(c);
    let denied = format!("{}@{}: Permission denied (publickey).", c.user, c.hostname);
    if signers.is_empty() {
        return Err(denied);
    }
    // One dial: core races every address (RFC 8305) and names each one it
    // tried in the error.
    let resolve = by_name.then(|| resolver(c));
    match dial(c, addrs, resolve, &host, &signers, sockets, path).await {
        Ok(sess) => Ok(sess),
        Err(Error::Auth(why)) => {
            tracing::info!("authentication refused: {why}");
            Err(denied)
        }
        Err(Error::HostKey(why)) => Err(format!("{why}\nHost key verification failed.")),
        Err(e) => Err(format!("ssh3: connect to host {} port {}: {e}", c.hostname, c.port)),
    }
}

/// Connect to the destination: directly, or through every jump hop in turn,
/// each next connection carried end to end over a relay path through the
/// previous session (SPEC §7.2).
async fn connect(c: &ClientConfig, jumps: &Jumps) -> Result<Chain, String> {
    let cfgs = hop_configs(c, jumps, 0)?;
    let Some(first) = cfgs.first() else {
        let sess = dial_one(c, resolve_addrs(c).await?, true, dual_stack_factory(), None).await?;
        return Ok(Chain { hops: Vec::new(), sess, supervisors: Vec::new() });
    };
    // One path manager (one UDP socket) for the whole chain: the first hop
    // observes the NAT mapping the direct-path punches then reuse (§7.3).
    let io = dual_stack_factory()().map_err(|e| format!("ssh3: socket: {e}"))?;
    let mgr = ssh3_core::path::PathManager::new(io);
    let mut prev = dial_one(first, resolve_addrs(first).await?, true, dual_stack_factory(), Some(mgr.clone())).await?;
    let mut prev_cfg = first.clone();
    let mut via = None;
    let mut hops: Vec<Arc<Hop>> = Vec::new();
    let fail = |hops: Vec<Arc<Hop>>, last: ClientSession, e: String| async move {
        Chain { hops, sess: last, supervisors: Vec::new() }.end(false).await;
        Err(e)
    };
    for next in cfgs[1..].iter().chain(std::iter::once(c)) {
        // The gateway resolves the next host itself (as `ssh -W %h:%p`).
        let path = match prev.jump(&next.hostname, next.port).await {
            Ok(p) => p,
            Err(e) => return fail(hops, prev, format!("ssh3: jump to {} port {}: {e}", next.hostname, next.port)).await,
        };
        let virt = path.virt;
        match dial_one(next, vec![virt], false, dual_stack_factory(), Some(mgr.clone())).await {
            Ok(s) => {
                // If `next` is a peer registered at `prev` (SPEC §7.1), both
                // ends upgrade to a direct path when the NATs allow; a plain
                // server ignores the path signals and the relay stays.
                if direct_path(next).expect("validated by refusals()")
                    && let Err(e) = path.start_direct_path(&s, ssh3_core::path::PathConfig::default())
                {
                    tracing::info!("no direct-path upgrade to {}: {e}", next.hostname);
                }
                hops.push(Arc::new(Hop { cfg: prev_cfg, sess: std::sync::Mutex::new(Arc::new(prev)), path, via, mgr: mgr.clone() }));
                prev = s;
                prev_cfg = next.clone();
                via = Some(virt);
            }
            Err(e) => {
                drop(path);
                return fail(hops, prev, e).await;
            }
        }
    }
    let supervisors = (0..hops.len()).map(|i| tokio::spawn(supervise_hop(hops.clone(), i))).collect();
    Ok(Chain { hops, sess: prev, supervisors })
}

/// Where a local listener binds, as ssh(1): loopback unless GatewayPorts or
/// an explicit address; `*` / empty = every address.
fn local_bind_hosts(listen_host: Option<&str>, gateway_ports: bool) -> Vec<String> {
    match listen_host {
        None if gateway_ports => vec!["::".into()],
        None | Some("localhost") => vec!["127.0.0.1".into(), "::1".into()],
        Some("") | Some("*") => vec!["::".into()],
        Some(h) => vec![h.trim_start_matches('[').trim_end_matches(']').to_string()],
    }
}

fn tcp_target(f: &Forward) -> (Option<&str>, u16, &str, u16) {
    match (&f.listen, &f.connect) {
        (Listen::Port { host, port }, Connect::HostPort { host: th, port: tp }) => (host.as_deref(), *port, th, *tp),
        _ => unreachable!("refusals() rejects Unix-socket and dynamic forwards here"),
    }
}

fn listen_port(f: &Forward) -> (Option<&str>, u16) {
    match &f.listen {
        Listen::Port { host, port } => (host.as_deref(), *port),
        Listen::Path(_) => unreachable!("refusals() rejects Unix-socket listeners"),
    }
}

/// Bind every address of a local listener; at least one must succeed.
async fn bind_all<T, F, Fut>(host: Option<&str>, port: u16, gateway_ports: bool, bind: F) -> Result<Vec<T>, String>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let mut ok = Vec::new();
    let mut errors = Vec::new();
    for h in local_bind_hosts(host, gateway_ports) {
        match bind(h.clone()).await {
            Ok(l) => ok.push(l),
            Err(e) => errors.push(format!("bind [{h}]:{port}: {e}")),
        }
    }
    if ok.is_empty() { Err(errors.join("; ")) } else { Ok(ok) }
}

type Tasks = Vec<tokio::task::JoinHandle<()>>;

async fn start_forwards(c: &ClientConfig, sess: &ClientSession) -> Result<Tasks, String> {
    let mut tasks = Vec::new();
    let gp = c.gateway_ports;
    // A failed forward is fatal with ExitOnForwardFailure, else a warning.
    let problem = |e: String| -> Result<(), String> {
        if c.exit_on_forward_failure {
            return Err(e);
        }
        eprintln!("ssh3: {e}");
        Ok(())
    };
    for f in &c.local_forwards {
        let (h, p, th, tp) = tcp_target(f);
        match bind_all(h, p, gp, |a| TcpListener::bind((a, p))).await {
            Ok(ls) => tasks.extend(ls.into_iter().map(|l| sess.forward_local(l, th.to_string(), tp))),
            Err(e) => problem(format!("{e}: Could not request local forwarding."))?,
        }
    }
    for f in &c.dynamic_forwards {
        let (h, p) = listen_port(f);
        match bind_all(h, p, gp, |a| TcpListener::bind((a, p))).await {
            Ok(ls) => tasks.extend(ls.into_iter().map(|l| sess.forward_dynamic(l))),
            Err(e) => problem(format!("{e}: Could not request dynamic forwarding."))?,
        }
    }
    for f in &c.local_udp_forwards {
        let (h, p, th, tp) = tcp_target(f);
        match bind_all(h, p, gp, |a| UdpSocket::bind((a, p))).await {
            Ok(ss) => tasks.extend(ss.into_iter().map(|s| sess.forward_local_udp(s, th.to_string(), tp))),
            Err(e) => problem(format!("{e}: Could not request local UDP forwarding."))?,
        }
    }
    for f in &c.remote_forwards {
        let (h, p, th, tp) = tcp_target(f);
        match sess.forward_remote(h.unwrap_or(""), p, th, tp).await {
            Ok(bound) if p == 0 => eprintln!("Allocated port {bound} for remote forward to {th}:{tp}"),
            Ok(_) => {}
            Err(e) => problem(format!("remote port forwarding failed for listen port {p}: {e}"))?,
        }
    }
    for f in &c.remote_udp_forwards {
        let (h, p, th, tp) = tcp_target(f);
        match sess.forward_remote_udp(h.unwrap_or(""), p, th, tp).await {
            Ok(bound) if p == 0 => eprintln!("Allocated UDP port {bound} for remote forward to {th}:{tp}"),
            Ok(_) => {}
            Err(e) => problem(format!("remote UDP port forwarding failed for listen port {p}: {e}"))?,
        }
    }
    Ok(tasks)
}

async fn run(c: ClientConfig, jumps: Jumps) -> ExitCode {
    let chain = match connect(&c, &jumps).await {
        Ok(ch) => ch,
        Err(m) => {
            eprintln!("{m}");
            return ExitCode::from(FAIL);
        }
    };
    let sess = &chain.sess;
    let tasks = match start_forwards(&c, sess).await {
        Ok(t) => t,
        Err(e) => {
            chain.end(false).await;
            return fail(&e);
        }
    };
    let code = match &c.stdio_forward {
        Some((h, p)) => stdio_forward(&c, sess, h, *p).await,
        None if c.session_type == SessionType::None => forward_only(&c, sess).await,
        None => session(&c, sess).await,
    };
    for t in tasks {
        t.abort();
    }
    let gave_up = sess.roam_stats().gave_up.load(std::sync::atomic::Ordering::Relaxed);
    chain.end(gave_up).await;
    code
}

/// How long the local terminal gets to report its cursor position before
/// predictive echo is left off.
const CURSOR_QUERY: Duration = Duration::from_secs(1);

/// How long a deliberate end waits for the server's confirmation; the
/// SESSION_END close that follows ends the session even without it.
const END_BOUND: std::time::Duration = std::time::Duration::from_secs(2);

/// The "Last contact" watcher for this run, if stderr is a terminal.
fn status_watch(c: &ClientConfig, sess: &ClientSession, line: StatusLine) -> Option<tokio::task::JoinHandle<()>> {
    if !std::io::stderr().is_terminal() || c.log_level <= LogLevel::Quiet {
        return None;
    }
    let warn = contact_warn(c).expect("validated by refusals()");
    let shared = sess.shared.clone();
    Some(tokio::spawn(tty::contact_watch(move || shared.last_contact(), warn, move |s| match s {
        Some(d) => line.show(d),
        None => line.clear(),
    })))
}

/// The "Last contact" watcher of a pty session whose terminal belongs to
/// the display task: the line goes through it, so clearing it restores the
/// bottom row from the mirror.
fn status_watch_display(c: &ClientConfig, sess: &ClientSession, tx: tokio::sync::mpsc::Sender<Ev>) -> Option<tokio::task::JoinHandle<()>> {
    if !std::io::stderr().is_terminal() || c.log_level <= LogLevel::Quiet {
        return None;
    }
    let warn = contact_warn(c).expect("validated by refusals()");
    let shared = sess.shared.clone();
    Some(tokio::spawn(tty::contact_watch(move || shared.last_contact(), warn, move |s| {
        let _ = tx.try_send(Ev::Status(s));
    })))
}

fn gave_up_message(c: &ClientConfig) -> String {
    format!("connection to {} lost and the session could not be resumed", c.hostname)
}

/// stdout for `-W`: says when it is dropped — the channel's sink ends when
/// the far side closes (or the channel is torn down).
struct DoneOnDrop {
    inner: tokio::io::Stdout,
    tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for DoneOnDrop {
    fn drop(&mut self) {
        if let Some(t) = self.tx.take() {
            let _ = t.send(());
        }
    }
}

impl tokio::io::AsyncWrite for DoneOnDrop {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, b: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `-W host:port` (stdio forwarding, as ssh(1) for ProxyCommand chains):
/// stdin and stdout are bridged to a direct-tcp channel to `host:port`; it
/// ends when the far side closes, on a signal, or when resume gives up.
async fn stdio_forward(c: &ClientConfig, sess: &ClientSession, host: &str, port: u16) -> ExitCode {
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt()), signal(SignalKind::hangup())) else {
        return fail("cannot install signal handlers");
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let out = DoneOnDrop { inner: tokio::io::stdout(), tx: Some(tx) };
    if let Err(e) = sess.open_direct_stream(Box::new(tokio::io::stdin()), out, host, port).await {
        return fail(&format!("stdio forwarding to {host}:{port} failed: {e}"));
    }
    tokio::select! {
        _ = rx => ExitCode::SUCCESS,
        _ = term.recv() => ExitCode::SUCCESS,
        _ = int.recv() => ExitCode::SUCCESS,
        _ = hup.recv() => ExitCode::SUCCESS,
        _ = sess.gave_up() => fail(&gave_up_message(c)),
    }
}

/// `-N`: until a signal, or until automatic resume gives up.
async fn forward_only(c: &ClientConfig, sess: &ClientSession) -> ExitCode {
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt()), signal(SignalKind::hangup())) else {
        return fail("cannot install signal handlers");
    };
    let watch = status_watch(c, sess, StatusLine::Cooked);
    let code = tokio::select! {
        _ = term.recv() => ExitCode::SUCCESS,
        _ = int.recv() => ExitCode::SUCCESS,
        _ = hup.recv() => ExitCode::SUCCESS,
        _ = sess.gave_up() => {
            eprintln!();
            fail(&gave_up_message(c))
        }
    };
    if let Some(w) = watch {
        w.abort();
        StatusLine::Cooked.clear();
    }
    code
}

/// Environment sent with the session: SendEnv patterns over the local
/// environment, then SetEnv (as ssh(1): SetEnv wins).
fn session_env(c: &ClientConfig) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = std::env::vars().filter(|(k, _)| c.send_env.iter().any(|p| ssh3_session::match_pattern(k, p))).collect();
    for kv in &c.set_env {
        if let Some((k, v)) = kv.split_once('=') {
            env.retain(|(ek, _)| ek != k);
            env.push((k.into(), v.into()));
        }
    }
    env
}

fn exit_code(e: Option<ExitInfo>) -> (ExitCode, Option<String>) {
    match e {
        Some(ExitInfo::Status(n)) => (ExitCode::from(n.min(255) as u8), None),
        Some(ExitInfo::Signal { name, core_dumped }) => {
            let n = ssh3_session::name_to_signal(&name).unwrap_or(0);
            let core = if core_dumped { " (core dumped)" } else { "" };
            (ExitCode::from((128 + n).min(255) as u8), Some(format!("remote command killed by signal {name}{core}")))
        }
        None => (ExitCode::from(FAIL), Some("session ended without an exit status".into())),
    }
}

/// Copy local stdin into the channel. A plain thread, not tokio's stdin:
/// a blocking read(2) on a terminal cannot be cancelled, and process exit
/// simply abandons this thread.
/// Keystrokes also go to the predictive echo (`tee`); `typeahead` was read
/// before the pump started (while asking the terminal for its cursor).
fn pump_stdin(mut to: tokio::io::DuplexStream, tee: Option<tokio::sync::mpsc::Sender<Ev>>, typeahead: Vec<u8>) -> tokio::task::JoinHandle<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
    if !typeahead.is_empty() {
        let _ = tx.try_send(typeahead);
    }
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if n <= 0 || tx.blocking_send(buf[..n as usize].to_vec()).is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(b) = rx.recv().await {
            if to.write_all(&b).await.is_err() {
                return;
            }
            if let Some(t) = &tee {
                let _ = t.send(Ev::In(b)).await;
            }
        }
        let _ = to.shutdown().await;
    })
}

/// What the terminal-owning task of a session with predictive echo gets.
enum Ev {
    /// Server pty output.
    Out(Vec<u8>),
    /// The server's output ended.
    Eof,
    /// Keystrokes, already sent to the server.
    In(Vec<u8>),
    /// The local window size changed.
    Resize(u16, u16),
    /// A prediction timer (internal to the display task).
    Tick,
    /// "Last contact": show after this much silence, or clear (None).
    Status(Option<Duration>),
}

/// Asks the local terminal where its cursor is (DSR 6) and waits at most
/// `within` for the report: the mirror must start where the terminal is,
/// or it would scroll at other times. Keystrokes read meanwhile are
/// returned for the server.
fn query_cursor(within: Duration) -> (Option<(u16, u16)>, Vec<u8>) {
    let q = b"\x1b[6n";
    if unsafe { libc::write(libc::STDOUT_FILENO, q.as_ptr().cast(), q.len()) } != q.len() as isize {
        return (None, Vec::new());
    }
    let end = std::time::Instant::now() + within;
    let mut buf = Vec::new();
    loop {
        if let Some((pos, at, len)) = cursor_report(&buf) {
            buf.drain(at..at + len);
            return (Some(pos), buf);
        }
        let left = end.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return (None, buf);
        }
        let mut p = libc::pollfd { fd: libc::STDIN_FILENO, events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut p, 1, left.as_millis().max(1) as i32) } <= 0 {
            continue;
        }
        let mut b = [0u8; 256];
        let n = unsafe { libc::read(libc::STDIN_FILENO, b.as_mut_ptr().cast(), b.len()) };
        if n <= 0 {
            return (None, buf);
        }
        buf.extend_from_slice(&b[..n as usize]);
    }
}

/// `ESC [ row ; col R` in `b`: the 0-based position, where it starts, its
/// length.
fn cursor_report(b: &[u8]) -> Option<((u16, u16), usize, usize)> {
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == 0x1b && b[i + 1] == b'[' {
            let rest = &b[i + 2..];
            let end = rest.iter().position(|&x| !(x.is_ascii_digit() || x == b';'))?;
            if rest[end] == b'R'
                && let Some((r, c)) = std::str::from_utf8(&rest[..end]).ok().and_then(|t| t.split_once(';'))
                && let (Ok(r), Ok(c)) = (r.parse::<u16>(), c.parse::<u16>())
            {
                return Some(((r.saturating_sub(1), c.saturating_sub(1)), i, end + 3));
            }
        }
        i += 1;
    }
    None
}

/// The task that owns the terminal when predictive echo is on: every byte
/// for it goes through [`Display`], so the overlay can be removed before
/// server output lands and drawn again after.
fn display_task(mut d: Display, link: impl Fn() -> (Option<Duration>, std::time::Instant) + Send + 'static, mut rx: tokio::sync::mpsc::Receiver<Ev>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        loop {
            let (rtt, heard) = link();
            if let Some(r) = rtt {
                d.engine.set_srtt(r);
            }
            d.engine.set_heard(heard);
            let wait = d.engine.wait_time().unwrap_or(Duration::from_secs(3600));
            let ev = tokio::select! {
                e = rx.recv() => e,
                _ = tokio::time::sleep(wait) => Some(Ev::Tick),
            };
            let now = std::time::Instant::now();
            let bytes = match ev {
                None | Some(Ev::Eof) => break,
                Some(Ev::Out(b)) => d.output(&b, now),
                Some(Ev::In(b)) => d.input(&b, now),
                Some(Ev::Tick) => d.tick(now),
                Some(Ev::Status(Some(silent))) => {
                    d.status_show(&StatusLine::message(silent)).unwrap_or_else(|| StatusLine::BottomRow.show_bytes(silent).into_bytes())
                },
                Some(Ev::Status(None)) => d.status_clear().unwrap_or_else(|| StatusLine::BottomRow.clear_bytes().into_bytes()),
                Some(Ev::Resize(c, r)) => d.resize(c, r),
            };
            if !bytes.is_empty() && (stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err()) {
                return;
            }
        }
        let bytes = d.finish();
        let _ = stdout.write_all(&bytes).await;
        let _ = stdout.flush().await;
    })
}

/// Server pty output into the display task.
fn pump_display(mut from: tokio::io::DuplexStream, tx: tokio::sync::mpsc::Sender<Ev>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(Ev::Out(buf[..n].to_vec())).await.is_err() {
                        return;
                    }
                },
            }
        }
        let _ = tx.send(Ev::Eof).await;
    })
}

fn pump_out(mut from: tokio::io::DuplexStream, mut to: impl tokio::io::AsyncWrite + Unpin + Send + 'static) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to.write_all(&buf[..n]).await.is_err() || to.flush().await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

fn take(d: &mut tokio::io::DuplexStream) -> tokio::io::DuplexStream {
    std::mem::replace(d, tokio::io::duplex(1).0)
}

/// Shell, exec or subsystem, with a pty when ssh(1) would allocate one.
async fn session(c: &ClientConfig, sess: &ClientSession) -> ExitCode {
    let stdin_tty = std::io::stdin().is_terminal();
    let want_pty = c.wants_tty(stdin_tty);
    if c.request_tty == ssh3_config::RequestTty::Yes && !want_pty && !stdin_tty && c.log_level >= LogLevel::Info {
        eprintln!("Pseudo-terminal will not be allocated because stdin is not a terminal.");
    }
    let pty = want_pty.then(|| {
        let s = tty::size(libc::STDIN_FILENO).unwrap_or(tty::Size { cols: 80, rows: 24, xpixel: 0, ypixel: 0 });
        PtySpec { term: std::env::var("TERM").unwrap_or_default(), cols: s.cols, rows: s.rows, xpixel: s.xpixel, ypixel: s.ypixel, modes: tty::modes(libc::STDIN_FILENO) }
    });
    let command = match (&c.session_type, &c.remote_command) {
        (SessionType::Subsystem, Some(name)) => Command::Subsystem(name.clone()),
        (_, Some(cmd)) => Command::Exec(cmd.clone()),
        (_, None) => Command::Shell,
    };
    let spec_command = command.clone();
    let forward_agent = forwarded_agent(c);
    if c.forward_agent != ForwardAgent::No && forward_agent.is_none() {
        eprintln!("ssh3: no agent to forward (IdentityAgent none or SSH_AUTH_SOCK unset)");
    }
    let spec = SessionSpec { pty, env: session_env(c), command, forward_agent };
    let mut ch: SessionChannel = match sess.open_session(spec).await {
        Ok(ch) => ch,
        Err(e) => return fail(&format!("session refused: {e}")),
    };
    // Raw local terminal only for a pty session on a terminal; restored by
    // Drop on every way out of this function.
    let raw = match (want_pty && stdin_tty).then(|| RawMode::enter(libc::STDIN_FILENO)).transpose() {
        Ok(r) => r,
        Err(e) => return fail(&format!("cannot put the terminal in raw mode: {e}")),
    };
    // Predictive echo (SPEC §5.2): on a raw local terminal; adaptive mode
    // only for interactive shells, `always` for any pty session.
    // The mirror also serves the "Last contact" line (restored from it when
    // cleared), so it exists for every raw pty session unless
    // `PredictiveEcho never`; predictions themselves are on per `pref`.
    let pref = predictive_echo(c).expect("validated by refusals()");
    let interactive = matches!(spec_command, Command::Shell);
    let echo = raw.is_some() && std::io::stdout().is_terminal() && !c.stdin_null && pref != Preference::Never;
    let pref = if pref == Preference::Adaptive && !interactive { Preference::Never } else { pref };
    let (display, typeahead) = if echo {
        let size = tty::size(libc::STDIN_FILENO).unwrap_or(tty::Size { cols: 80, rows: 24, xpixel: 0, ypixel: 0 });
        match query_cursor(CURSOR_QUERY) {
            (Some((row, col)), typeahead) => {
                let mut mirror = ssh3_term::Screen::new(size.cols as u16, size.rows as u16);
                mirror.feed(format!("\x1b[{};{}H", row + 1, col + 1).as_bytes());
                (Some(Display::new(mirror, PredictionEngine::new(pref))), typeahead)
            },
            (None, typeahead) => {
                tracing::info!("predictive echo off: the terminal did not report its cursor within {CURSOR_QUERY:?}");
                (None, typeahead)
            },
        }
    } else {
        (None, Vec::new())
    };
    let (ev_tx, show) = match display {
        Some(d) => {
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            let shared = sess.shared.clone();
            (Some(tx), Some(display_task(d, move || (shared.rtt(), shared.last_contact()), rx)))
        },
        None => (None, None),
    };
    let stdin_task = if c.stdin_null {
        let mut s = take(&mut ch.stdin);
        let _ = s.shutdown().await;
        None
    } else {
        Some(pump_stdin(take(&mut ch.stdin), ev_tx.clone(), typeahead))
    };
    let out = match (&ev_tx, show) {
        (Some(tx), Some(show)) => {
            let pump = pump_display(take(&mut ch.stdout), tx.clone());
            tokio::spawn(async move {
                let _ = pump.await;
                let _ = show.await;
            })
        },
        _ => pump_out(take(&mut ch.stdout), tokio::io::stdout()),
    };
    let err = pump_out(take(&mut ch.stderr), tokio::io::stderr());
    let watch = match &ev_tx {
        Some(tx) => status_watch_display(c, sess, tx.clone()),
        None => status_watch(c, sess, if raw.is_some() { StatusLine::BottomRow } else { StatusLine::Cooked }),
    };
    let (Ok(mut term), Ok(mut int), Ok(mut hup), Ok(mut winch)) =
        (signal(SignalKind::terminate()), signal(SignalKind::interrupt()), signal(SignalKind::hangup()), signal(SignalKind::window_change()))
    else {
        return fail("cannot install signal handlers");
    };
    enum End {
        Exit(Option<ExitInfo>),
        Killed(i32),
        GaveUp,
    }
    // Every iteration that does not end the session is a SIGWINCH.
    let end = loop {
        tokio::select! {
            e = ch.exit() => break End::Exit(e),
            _ = term.recv() => break End::Killed(libc::SIGTERM),
            _ = int.recv() => break End::Killed(libc::SIGINT),
            _ = hup.recv() => break End::Killed(libc::SIGHUP),
            _ = sess.gave_up() => break End::GaveUp,
            _ = winch.recv() => {}
        }
        if want_pty && let Some(s) = tty::size(libc::STDIN_FILENO) {
            if let Some(tx) = &ev_tx {
                let _ = tx.send(Ev::Resize(s.cols as u16, s.rows as u16)).await;
            }
            if let Err(e) = ch.resize(s.cols, s.rows, s.xpixel, s.ypixel).await {
                tracing::info!("window-change: {e}");
            }
        }
    };
    if let Some(w) = watch {
        w.abort();
    }
    let (code, msg) = match end {
        End::Exit(e) => {
            // Everything the remote wrote before it exited reaches us first.
            let _ = out.await;
            let _ = err.await;
            exit_code(e)
        }
        End::Killed(sig) => (ExitCode::from(FAIL), Some(format!("Killed by signal {sig}."))),
        End::GaveUp => (ExitCode::from(FAIL), Some(gave_up_message(c))),
    };
    if let Some(t) = stdin_task {
        t.abort();
    }
    let had_raw = raw.is_some();
    drop(raw);
    if let Some(m) = msg {
        eprintln!("ssh3: {m}");
    }
    if had_raw && c.log_level >= LogLevel::Info {
        eprintln!("Connection to {} closed.", c.hostname);
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str], conf: &str) -> ClientConfig {
        let dir = PathBuf::from(std::env::var("HOME").unwrap()).join("scratch/ssh-udp/bins-unit");
        std::fs::create_dir_all(&dir).unwrap();
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let f = dir.join(format!("cfg-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        std::fs::write(&f, conf).unwrap();
        let mut a = vec!["-F".to_string(), f.to_string_lossy().into_owned()];
        a.extend(args.iter().map(|s| s.to_string()));
        let c = ssh3_config::resolve_args(&a, &LocalEnv::from_system(443).unwrap()).unwrap();
        let _ = std::fs::remove_file(&f);
        c
    }

    #[test]
    fn forwarding_only_is_accepted() {
        refusals(&cfg(&["-N", "-L", "1234:localhost:80", "-R", "0:localhost:22", "h"], "")).unwrap();
    }

    #[test]
    fn sessions_and_new_forwards_are_accepted() {
        refusals(&cfg(&["-A", "-D", "1080", "-U", "5353:127.0.0.1:53", "-u", "0:127.0.0.1:53", "h", "echo", "hi"], "")).unwrap();
    }

    #[test]
    fn predictive_echo_keyword() {
        assert_eq!(predictive_echo(&cfg(&["-N", "h"], "")).unwrap(), Preference::Adaptive);
        assert_eq!(predictive_echo(&cfg(&["-N", "h"], "PredictiveEcho never\n")).unwrap(), Preference::Never);
        assert_eq!(predictive_echo(&cfg(&["-o", "PredictiveEcho=Always", "-N", "h"], "")).unwrap(), Preference::Always);
        let e = refusals(&cfg(&["-N", "h"], "PredictiveEcho sometimes\n")).unwrap_err();
        assert!(e.contains("PredictiveEcho: expected adaptive, always or never"), "{e}");
    }

    #[test]
    fn cursor_reports_are_found_among_keystrokes() {
        assert_eq!(cursor_report(b"ab\x1b[12;40Rcd"), Some(((11, 39), 2, 8)));
        assert_eq!(cursor_report(b"\x1b[A\x1b[3;1R"), Some(((2, 0), 3, 6)));
        assert_eq!(cursor_report(b"\x1b[12;40"), None);
    }

    #[test]
    fn contact_warn_keyword() {
        assert_eq!(contact_warn(&cfg(&["-N", "h"], "")).unwrap(), CONTACT_WARN);
        assert_eq!(contact_warn(&cfg(&["-N", "h"], "ContactWarn 2500ms\n")).unwrap(), Duration::from_millis(2500));
        // Below twice the probe interval it would fire on a healthy link.
        let e = refusals(&cfg(&["-N", "h"], "ContactWarn 500ms\n")).unwrap_err();
        assert!(e.contains("ContactWarn 500ms is shorter than twice the liveness probe interval 1s"), "{e}");
        let e = refusals(&cfg(&["-o", "ServerAliveInterval=3", "-N", "h"], "ContactWarn 5s\n")).unwrap_err();
        assert!(e.contains("3s"), "{e}");
        assert!(refusals(&cfg(&["-o", "ServerAliveInterval=3", "-N", "h"], "ContactWarn 6s\n")).is_ok());
        let e = refusals(&cfg(&["-N", "h"], "ContactWarn 5\n")).unwrap_err();
        assert!(e.contains("ContactWarn"), "{e}");
    }

    #[test]
    fn remote_exit_codes() {
        assert_eq!(exit_code(Some(ExitInfo::Status(3))).0, ExitCode::from(3));
        let (c, m) = exit_code(Some(ExitInfo::Signal { name: "TERM".into(), core_dumped: false }));
        assert_eq!(c, ExitCode::from(143));
        assert!(m.unwrap().contains("TERM"));
        assert_eq!(exit_code(None).0, ExitCode::from(255));
    }

    #[test]
    fn unimplemented_features_are_refused_by_name() {
        let e = refusals(&cfg(&["-N", "-J", "j", "-R", "1080", "h"], "")).unwrap_err();
        assert!(e.contains("dynamic remote forward"), "{e}");
        assert!(!e.contains("ProxyJump"), "ProxyJump is implemented: {e}");
        assert!(refusals(&cfg(&["-W", "a:1", "h"], "")).is_ok(), "-W is implemented");
        let e = refusals(&cfg(&["-N", "h"], "ProxyCommand nc %h %p\n")).unwrap_err();
        assert!(e.contains("ProxyCommand"), "{e}");
    }

    #[test]
    fn security_options_are_refused_not_ignored() {
        let e = refusals(&cfg(&["-N", "h"], "HostKeyAlgorithms ssh-ed25519\nRevokedHostKeys /etc/ssh/revoked\n")).unwrap_err();
        assert!(e.contains("hostkeyalgorithms") && e.contains("revokedhostkeys"), "{e}");
        refusals(&cfg(&["-N", "h"], "CheckHostIP no\nForwardX11 no\n")).unwrap();
    }

    #[test]
    fn known_hosts_name_is_alias_then_hostname() {
        let c = cfg(&["-N", "h"], "Host h\n  HostName 10.0.0.1\n  HostKeyAlias box\n");
        assert_eq!(host_check(&c).name, "box");
        let c = cfg(&["-N", "h"], "Host h\n  HostName 10.0.0.1\n");
        assert_eq!(host_check(&c).name, "10.0.0.1");
    }

    #[test]
    fn local_bind_rules() {
        assert_eq!(local_bind_hosts(None, false), vec!["127.0.0.1", "::1"]);
        assert_eq!(local_bind_hosts(None, true), vec!["::"]);
        assert_eq!(local_bind_hosts(Some("*"), false), vec!["::"]);
        assert_eq!(local_bind_hosts(Some("[::1]"), false), vec!["::1"]);
    }
}
