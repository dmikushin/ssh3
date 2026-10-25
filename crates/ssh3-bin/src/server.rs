//! `ssh3-server`.
//!
//! Usage: `ssh3-server [-f config] [-t] [-d]`
//!   -f  configuration file (default /etc/ssh3/ssh3-server.toml, see
//!       `server_config` for the format)
//!   -t  check the configuration and the host key, then exit
//!   -d  debug logging (RUST_LOG overrides)
//!
//! Privilege model: started as root it serves every account in the passwd
//! database; started as any other user it serves only that user and refuses
//! the rest by name. Session processes (when core gains session channels)
//! are spawned through ssh3-session, which drops privileges per session.
//!
//! `rendezvous = true` makes it a gateway for registered peers; a
//! `[register]` section makes it such a peer (SPEC §7.1): it serves on a
//! path-managed endpoint, keeps a client session to the gateway from the same
//! UDP socket, and relayed clients upgrade to a direct path when the NATs
//! allow (§7.3).
//!
//! Observability (SPEC §8 I6): SIGUSR1 prints one JSON line of server
//! counters on stdout; `stats_socket` serves the same JSON to each client
//! that connects. SIGTERM/SIGINT: every session is torn down (carriers
//! closed with a reason, -R listeners released at once — I5) and the process
//! exits 0.

use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ssh3_core::auth::{Authenticator, AuthorizedKeysAuthenticator, Authz, PublicKey};
use ssh3_core::transport::{EndpointKeys, dual_stack_socket, server_tls};
use ssh3_core::{Server, ServerOptions};
use ssh3_keys::host::HostIdentity;
use ssh3_session::UserRecord;
use tokio::io::AsyncWriteExt;
use tokio::signal::unix::{SignalKind, signal};

use crate::server_config::ServerConfig;
use crate::stats;

const DEFAULT_CONFIG: &str = "/etc/ssh3/ssh3-server.toml";

/// Upper bound on waiting for the endpoint to go idle after shutdown (the
/// CONNECTION_CLOSE frames reach the clients, so they learn of the shutdown
/// at once instead of by idle timeout).
const CLOSE_BOUND: Duration = Duration::from_secs(1);

struct Args {
    config: PathBuf,
    test_only: bool,
    debug: bool,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args { config: DEFAULT_CONFIG.into(), test_only: false, debug: false };
    let mut it = argv.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "-f" => a.config = it.next().ok_or("-f needs a file")?.into(),
            "-t" => a.test_only = true,
            "-d" => a.debug = true,
            o => return Err(format!("unknown argument {o:?}; usage: ssh3-server [-f config] [-t] [-d]")),
        }
    }
    Ok(a)
}

/// authorized_keys lookup with the server's privilege model applied.
struct Authorizer {
    cfg: Arc<ServerConfig>,
    /// Set when not running as root: the only account served.
    only_user: Option<String>,
}

impl Authenticator for Authorizer {
    fn authorize(&self, user: &str, key: &PublicKey, peer: IpAddr) -> Result<Authz, String> {
        if let Some(me) = &self.only_user
            && me != user
        {
            return Err(format!("ssh3-server runs as {me:?} without root and serves only that account, not {user:?}"));
        }
        let rec = UserRecord::lookup(user).map_err(|e| format!("user {user:?}: {e}"))?;
        let path = self.cfg.authorized_keys_for(user, &rec.home)?;
        AuthorizedKeysAuthenticator::new(move |_| Some(path.clone())).authorize(user, key, peer)
    }
}

pub fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ssh3-server: {e}");
            return ExitCode::from(2);
        }
    };
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| if args.debug { "debug".into() } else { "info".into() });
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new(filter)).with_writer(std::io::stderr).init();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ssh3-server: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    let cfg = Arc::new(ServerConfig::load(&args.config)?);
    let limits = cfg.limits();
    let host = HostIdentity::load(&cfg.host_key).map_err(|e| format!("host key {}: {e}", cfg.host_key.display()))?;
    let tls = server_tls(&host).map_err(|e| e.to_string())?;
    if args.test_only {
        println!("ssh3-server: configuration {} OK; host key {}", args.config.display(), host.public_key().fingerprint(Default::default()));
        return Ok(());
    }
    let keys = match &cfg.endpoint_keys {
        Some(p) => EndpointKeys::load_or_create(p).map_err(|e| e.to_string())?,
        None => {
            tracing::warn!("no endpoint_keys file configured: clients will not learn of a restart by stateless reset (SPEC §1)");
            EndpointKeys::random()
        }
    };
    let only_user = if unsafe { libc::geteuid() } == 0 {
        None
    } else {
        Some(ssh3_config::LocalEnv::from_system(443)?.user)
    };
    let authenticator = Arc::new(Authorizer { cfg: cfg.clone(), only_user });
    // A fixed worker count, not one per CPU: per-thread allocator state made
    // idle RSS grow with the core count (531 MB on 88 CPUs).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.worker_threads)
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(async move {
        let socket = dual_stack_socket(cfg.listen).map_err(|e| format!("listen {}: {e}", cfg.listen))?;
        let session = Some(ssh3_core::ServerSessionEnv::new(cfg.session()));
        let rendezvous = cfg.rendezvous;
        // Every server runs on a path manager: the one UDP socket carries its
        // own connections, a gateway registration and direct-path punches.
        let mgr = ssh3_core::path::PathManager::new(ssh3_core::udp_socket(socket).map_err(|e| e.to_string())?);
        let server = Server::bind_path(ServerOptions { tls, authenticator, limits, keys, session, rendezvous }, mgr).map_err(|e| e.to_string())?;
        println!("ssh3-server: listening on {}", server.local_addr());
        let _ = std::io::stdout().flush();
        let server = Arc::new(server);
        let register_task = cfg.register.as_ref().map(|r| tokio::spawn(keep_registered(server.clone(), r.clone_spec())));
        let stats_task = match &cfg.stats_socket {
            Some(p) => Some(serve_stats(p, server.clone())?),
            None => None,
        };
        let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
        let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
        let mut usr1 = signal(SignalKind::user_defined1()).map_err(|e| e.to_string())?;
        loop {
            tokio::select! {
                _ = term.recv() => break,
                _ = int.recv() => break,
                _ = usr1.recv() => {
                    println!("{}", stats::to_json(&server.stats()));
                    let _ = std::io::stdout().flush();
                }
            }
        }
        tracing::info!("shutting down");
        if !server.shutdown_and_wait(CLOSE_BOUND).await {
            tracing::warn!("endpoint not idle within {CLOSE_BOUND:?} after shutdown; exiting anyway");
        }
        if let Some(t) = stats_task {
            t.abort();
        }
        if let Some(t) = register_task {
            t.abort();
        }
        if let Some(p) = &cfg.stats_socket {
            let _ = std::fs::remove_file(p);
        }
        Ok(())
    })
}

/// What a registration needs, owned by the supervisor task.
pub struct RegisterSpec {
    gateway: String,
    name: String,
    user: String,
    identity: PathBuf,
    known_hosts: PathBuf,
    alias: Option<String>,
    family: crate::server_config::AddressFamily,
}

impl crate::server_config::Register {
    fn clone_spec(&self) -> RegisterSpec {
        RegisterSpec { gateway: self.gateway.clone(), name: self.name.clone(), user: self.user.clone(), identity: self.identity.clone(), known_hosts: self.known_hosts.clone(), alias: self.host_key_alias.clone(), family: self.address_family }
    }
}

const REGISTER_RETRY_MIN: Duration = Duration::from_secs(1);
const REGISTER_RETRY_MAX: Duration = Duration::from_secs(60);

/// Register at the gateway and stay registered: when the registration
/// session gives up (the gateway refused the resume, e.g. it restarted),
/// register again, with exponential backoff on failures.
async fn keep_registered(server: Arc<Server>, r: RegisterSpec) {
    let mut wait = REGISTER_RETRY_MIN;
    loop {
        match register_once(&server, &r).await {
            Ok(sess) => {
                tracing::info!(gateway = %r.gateway, name = %r.name, "registered at the gateway");
                wait = REGISTER_RETRY_MIN;
                sess.gave_up().await;
                tracing::warn!(gateway = %r.gateway, "registration session lost; registering again");
            }
            Err(e) => {
                tracing::warn!(gateway = %r.gateway, "registration failed: {e}; retrying in {wait:?}");
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(REGISTER_RETRY_MAX);
            }
        }
    }
}

async fn register_once(server: &Server, r: &RegisterSpec) -> Result<ssh3_core::ClientSession, String> {
    let (host, port) = match r.gateway.rsplit_once(':') {
        Some((h, p)) => (h.trim_start_matches('[').trim_end_matches(']').to_string(), p.parse::<u16>().map_err(|e| format!("gateway {:?}: port: {e}", r.gateway))?),
        None => (r.gateway.clone(), 443),
    };
    let family = r.family;
    let lookup = move |h: String| async move {
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((h.as_str(), port)).await?.filter(|a| family.admits(a)).collect();
        if addrs.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("{h}: no address of address family {family:?}")));
        }
        Ok(addrs)
    };
    let addrs = lookup(host.clone()).await.map_err(|e| format!("resolve {host}: {e}"))?;
    let signer: Arc<dyn ssh3_core::auth::Signer> = Arc::new(ssh3_keys::signer::FileSigner::load(&r.identity).map_err(|e| format!("identity {}: {e}", r.identity.display()))?);
    let name = host.clone();
    let resolve: ssh3_core::client::Resolver = Arc::new(move || Box::pin(lookup(name.clone())));
    let opts = ssh3_core::ClientOptions {
        server_addrs: addrs,
        resolve: Some(resolve),
        host: ssh3_core::client::HostCheck {
            name: r.alias.clone().unwrap_or(host),
            port,
            files: vec![r.known_hosts.clone()],
            mode: ssh3_keys::verifier::StrictHostKeyChecking::Yes,
            hash_known_hosts: false,
            prompt: None,
        },
        signers: vec![signer],
        user: r.user.clone(),
        limits: ssh3_core::Limits::default(),
        sockets: ssh3_core::client::dual_stack_factory(),
        path: None,
    };
    server.register_at(opts, &r.name, ssh3_core::path::PathConfig::default()).await.map_err(|e| e.to_string())
}

/// One JSON object per connection on a Unix socket.
fn serve_stats(path: &Path, server: Arc<Server>) -> Result<tokio::task::JoinHandle<()>, String> {
    // Remove a stale socket left by a previous run, but never another kind
    // of file at that path.
    if let Ok(m) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        if !m.file_type().is_socket() {
            return Err(format!("stats_socket {} exists and is not a socket", path.display()));
        }
        std::fs::remove_file(path).map_err(|e| format!("stats_socket {}: {e}", path.display()))?;
    }
    let l = tokio::net::UnixListener::bind(path).map_err(|e| format!("stats_socket {}: {e}", path.display()))?;
    Ok(tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let body = format!("{}\n", stats::to_json(&server.stats()));
            tokio::spawn(async move {
                let _ = s.write_all(body.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    }))
}
