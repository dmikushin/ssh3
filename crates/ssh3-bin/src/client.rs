//! `ssh3`: the client program. OpenSSH command line and ~/.ssh/config
//! (ssh3-config), default port 443.
//!
//! What it does today: authenticate (agent / `.pub`-selected agent key /
//! key file, OpenSSH order), verify the host key against known_hosts with a
//! fresh verifier per dial, then run -L and -R forwards with roaming and
//! automatic resume on (ssh3-core defaults). Exit status 255 on any
//! connection, authentication or host-key failure, as ssh(1).
//!
//! What it refuses, by name, instead of silently ignoring (a missing
//! feature must never look like a working one):
//! - interactive and exec sessions — ssh3-core has no session channel yet;
//!   use `-N`;
//! - -D, -W, UDP forwards, Unix-socket forwards, dynamic -R, ProxyJump,
//!   ProxyCommand, ForwardAgent, -f — not implemented by ssh3-core yet or
//!   not part of ssh3's design (ProxyCommand);
//! - configuration options whose enforcement the user may rely on for
//!   security but which ssh3 would not apply (`SECURITY_OPTIONS`).

use std::io::{IsTerminal, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use ssh3_config::{ClientConfig, Connect, Forward, ForwardAgent, IdentitySource, Listen, LocalEnv, LogLevel, SessionType};
use ssh3_core::auth::{PublicKey, Signer};
use ssh3_core::client::{HostCheck, dual_stack_factory};
use ssh3_core::{ClientOptions, ClientSession, Error, Limits};
use ssh3_keys::signer::{AgentClient, AgentSigner, resolve_identity};
use ssh3_keys::verifier::{StrictHostKeyChecking, UnknownHost};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

/// ssh(1) exits 255 for its own errors.
const FAIL: u8 = 255;

/// The client shows "Last contact" after this long without a carrier
/// (SPEC §5 ContactWarn, mosh terminaloverlay.h:159).
const CONTACT_WARN: Duration = Duration::from_millis(6500);

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
    let cfg = match ssh3_config::resolve_args(&argv, &env) {
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
    rt.block_on(run(cfg))
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
    if !c.proxy_jump.is_empty() {
        why.push("ProxyJump is not implemented yet (SPEC §7)".into());
    }
    if !c.dynamic_forwards.is_empty() {
        why.push("-D / DynamicForward is not implemented yet".into());
    }
    if !c.local_udp_forwards.is_empty() || !c.remote_udp_forwards.is_empty() {
        why.push("UDP forwards are not implemented yet (SPEC §6)".into());
    }
    if c.stdio_forward.is_some() {
        why.push("-W is not implemented yet".into());
    }
    if c.forward_agent != ForwardAgent::No {
        why.push("ForwardAgent is not implemented yet".into());
    }
    if c.fork_after_authentication {
        why.push("-f is not implemented yet".into());
    }
    if c.session_type != SessionType::None {
        why.push("interactive and exec sessions are not available yet (ssh3-core has no session channel); use -N for forwarding only".into());
    }
    for f in c.local_forwards.iter().chain(&c.remote_forwards) {
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

async fn dial(c: &ClientConfig, addr: SocketAddr, host: &HostCheck, signer: Arc<dyn Signer>) -> Result<ClientSession, Error> {
    let opts = ClientOptions { server_addr: addr, host: host.clone(), signer, user: c.user.clone(), limits: Limits::default(), sockets: dual_stack_factory() };
    let sock = (opts.sockets)().map_err(Error::Io)?;
    let fut = ClientSession::connect(opts, sock);
    match c.connect_timeout {
        Some(s) => tokio::time::timeout(Duration::from_secs(s.into()), fut)
            .await
            .map_err(|_| Error::Deadline(format!("ConnectTimeout {s} s")))?,
        None => fut.await,
    }
}

enum Outcome {
    Connected(ClientSession),
    Fatal(String),
}

/// Try every address until one answers, then every key on it.
async fn connect(c: &ClientConfig) -> Outcome {
    let addrs = match resolve_addrs(c).await {
        Ok(a) => a,
        Err(e) => return Outcome::Fatal(e),
    };
    let host = host_check(c);
    let signers = signers(c);
    let denied = format!("{}@{}: Permission denied (publickey).", c.user, c.hostname);
    if signers.is_empty() {
        return Outcome::Fatal(denied);
    }
    let mut last = String::new();
    'addr: for addr in addrs {
        for s in &signers {
            match dial(c, addr, &host, s.clone()).await {
                Ok(sess) => return Outcome::Connected(sess),
                Err(Error::Auth(why)) => {
                    tracing::info!("key {} refused: {why}", s.public_key().fingerprint(Default::default()));
                }
                Err(Error::HostKey(why)) => return Outcome::Fatal(format!("{why}\nHost key verification failed.")),
                Err(e) => {
                    last = format!("ssh3: connect to host {} port {}: {e}", c.hostname, c.port);
                    continue 'addr;
                }
            }
        }
        return Outcome::Fatal(denied);
    }
    Outcome::Fatal(last)
}

/// Where a local forward listens, as ssh(1): loopback unless GatewayPorts
/// or an explicit address; `*` / empty = every address.
fn local_bind_hosts(listen_host: Option<&str>, gateway_ports: bool) -> Vec<String> {
    match listen_host {
        None if gateway_ports => vec!["::".into()],
        None | Some("localhost") => vec!["127.0.0.1".into(), "::1".into()],
        Some("") | Some("*") => vec!["::".into()],
        Some(h) => vec![h.trim_start_matches('[').trim_end_matches(']').to_string()],
    }
}

async fn start_local(sess: &ClientSession, f: &Forward, gateway_ports: bool) -> Result<Vec<tokio::task::JoinHandle<()>>, String> {
    let (Listen::Port { host, port }, Connect::HostPort { host: th, port: tp }) = (&f.listen, &f.connect) else {
        unreachable!("refusals() rejects non-TCP local forwards")
    };
    let mut handles = Vec::new();
    let mut errors = Vec::new();
    for h in local_bind_hosts(host.as_deref(), gateway_ports) {
        match TcpListener::bind((h.as_str(), *port)).await {
            Ok(l) => handles.push(sess.forward_local(l, th.clone(), *tp)),
            Err(e) => errors.push(format!("bind [{h}]:{port}: {e}")),
        }
    }
    if handles.is_empty() { Err(errors.join("; ")) } else { Ok(handles) }
}

async fn start_remote(sess: &ClientSession, f: &Forward) -> Result<(), String> {
    let (Listen::Port { host, port }, Connect::HostPort { host: th, port: tp }) = (&f.listen, &f.connect) else {
        unreachable!("refusals() rejects non-TCP remote forwards")
    };
    let bound = sess.forward_remote(host.as_deref().unwrap_or(""), *port, th, *tp).await.map_err(|e| e.to_string())?;
    if *port == 0 {
        eprintln!("Allocated port {bound} for remote forward to {th}:{tp}");
    }
    Ok(())
}

async fn run(c: ClientConfig) -> ExitCode {
    let sess = match connect(&c).await {
        Outcome::Connected(s) => s,
        Outcome::Fatal(m) => {
            eprintln!("{m}");
            return ExitCode::from(FAIL);
        }
    };
    let mut handles = Vec::new();
    for f in &c.local_forwards {
        match start_local(&sess, f, c.gateway_ports).await {
            Ok(h) => handles.extend(h),
            Err(e) if c.exit_on_forward_failure => return fail(&format!("{e}\nssh3: Could not request local forwarding.")),
            Err(e) => eprintln!("ssh3: {e}\nssh3: Could not request local forwarding."),
        }
    }
    for f in &c.remote_forwards {
        if let Err(e) = start_remote(&sess, f).await {
            let port = match &f.listen {
                Listen::Port { port, .. } => *port,
                Listen::Path(_) => 0,
            };
            if c.exit_on_forward_failure {
                return fail(&format!("Error: remote port forwarding failed for listen port {port}: {e}"));
            }
            eprintln!("Warning: remote port forwarding failed for listen port {port}: {e}");
        }
    }
    let code = wait(&c, &sess).await;
    for h in handles {
        h.abort();
    }
    code
}

/// Until a signal, or until automatic resume gives up. While the carrier is
/// down the client says so on a terminal ("Last contact N s ago").
async fn wait(c: &ClientConfig, sess: &ClientSession) -> ExitCode {
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt()), signal(SignalKind::hangup())) else {
        return fail("cannot install signal handlers");
    };
    let show_status = std::io::stderr().is_terminal() && c.log_level > LogLevel::Quiet;
    let mut detached_since: Option<Instant> = None;
    let mut shown = false;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            _ = term.recv() => return ExitCode::SUCCESS,
            _ = int.recv() => return ExitCode::SUCCESS,
            _ = hup.recv() => return ExitCode::SUCCESS,
            _ = tick.tick() => {
                if sess.roam_stats().gave_up.load(Ordering::Acquire) {
                    if shown {
                        eprintln!();
                    }
                    return fail(&format!("connection to {} lost and the session could not be resumed", c.hostname));
                }
                if sess.shared.is_attached() {
                    if shown {
                        eprint!("\r\x1b[K");
                        shown = false;
                    }
                    detached_since = None;
                } else {
                    let since = *detached_since.get_or_insert_with(Instant::now);
                    if show_status && since.elapsed() >= CONTACT_WARN {
                        eprint!("\r\x1b[Kssh3: Last contact {} s ago", since.elapsed().as_secs());
                        let _ = std::io::stderr().flush();
                        shown = true;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str], conf: &str) -> ClientConfig {
        let dir = PathBuf::from(std::env::var("HOME").unwrap()).join("scratch/ssh-udp/bins-unit");
        std::fs::create_dir_all(&dir).unwrap();
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let f = dir.join(format!("cfg-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
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
    fn sessions_are_refused_until_core_has_them() {
        let e = refusals(&cfg(&["h", "echo", "hi"], "")).unwrap_err();
        assert!(e.contains("session channel"), "{e}");
    }

    #[test]
    fn unimplemented_features_are_refused_by_name() {
        let e = refusals(&cfg(&["-N", "-D", "1080", "-J", "j", "h"], "")).unwrap_err();
        for w in ["-D", "ProxyJump"] {
            assert!(e.contains(w), "{w} missing in {e}");
        }
        let e = refusals(&cfg(&["-W", "a:1", "h"], "")).unwrap_err();
        assert!(e.contains("-W"), "{e}");
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
