//! Server-side process layer of an ssh3 session channel.
//!
//! [`spawn`] starts the user's shell, command or subsystem the way OpenSSH
//! `sshd` does (session.c `do_exec*`, `do_child`, `do_setup_env`,
//! `do_setusercontext`), and hands back a [`SessionProcess`] with byte-stream
//! halves, window-change / signal control, and the exit outcome. It knows
//! nothing about the transport; ssh3-core connects these streams to lanes.
//!
//! Session end follows sshd exactly: dropping a [`SessionProcess`] signals
//! nothing. With a pty, closing the master hangs up the terminal and the
//! kernel delivers SIGHUP; without one, the pipes close. `nohup cmd &`
//! survives in both modes. The leader is reaped when it exits (no zombies),
//! and Drop never blocks.

mod env;
mod process;
mod pty;
mod user;

use std::collections::HashMap;
use std::path::PathBuf;

pub use env::match_pattern;
pub use process::{Exit, SessionProcess};
pub use pty::{PtyReader, PtyWriter};
pub use user::UserRecord;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}: {1}")]
    Os(String, #[source] std::io::Error),
    #[error("user database: {0}")]
    User(String),
    #[error("privilege: {0}")]
    Privilege(String),
    #[error("subsystem {0:?} is not configured")]
    UnknownSubsystem(String),
    #[error("signal {0:?} is not supported (RFC 4254 §6.9 subset: HUP INT KILL QUIT TERM USR1 USR2)")]
    UnknownSignal(String),
    #[error("refusing to send a signal to a {0} session")]
    SignalRefused(&'static str),
    #[error("session has no pty")]
    NoPty,
    #[error("protocol: {0}")]
    Protocol(String),
}

/// Terminal size in characters and pixels (RFC 4254 §6.2 / §6.7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowSize {
    pub cols: u32,
    pub rows: u32,
    pub xpixel: u32,
    pub ypixel: u32,
}

/// `pty-req` (RFC 4254 §6.2).
#[derive(Clone, Debug, Default)]
pub struct PtyRequest {
    /// TERM; empty means "do not set TERM" (OpenSSH).
    pub term: String,
    pub size: WindowSize,
    /// Encoded terminal modes (RFC 4254 §8).
    pub modes: Vec<u8>,
}

/// What to run.
#[derive(Clone, Debug)]
pub enum Kind {
    /// Login shell (`argv[0]` prefixed with `-`).
    Shell,
    /// `shell -c command`.
    Exec(String),
    /// Named subsystem from [`SessionConfig::subsystems`].
    Subsystem(String),
}

/// Endpoint addresses for SSH_CLIENT / SSH_CONNECTION.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_ip: String,
    pub local_port: u16,
}

#[derive(Clone, Debug)]
pub struct SessionRequest {
    pub user: UserRecord,
    pub kind: Kind,
    pub pty: Option<PtyRequest>,
    /// Variables sent with `env` requests, in arrival order; filtered by
    /// [`SessionConfig::accept_env`].
    pub env: Vec<(String, String)>,
    /// Forced command (`command=` in authorized_keys or the server config);
    /// replaces what the client asked for and sets SSH_ORIGINAL_COMMAND.
    pub forced_command: Option<String>,
    pub connection: Option<ConnectionInfo>,
    pub auth_sock: Option<PathBuf>,
}

/// Server policy for sessions (sshd_config analogues).
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// AcceptEnv patterns (`*`, `?` wildcards).
    pub accept_env: Vec<String>,
    /// At most this many client variables are accepted (OpenSSH: 128).
    pub max_client_env: usize,
    /// SetEnv: applied after the login variables.
    pub set_env: Vec<(String, String)>,
    /// Subsystem name → command line run with `shell -c`.
    pub subsystems: HashMap<String, String>,
    /// PATH for non-root users (OpenSSH `_PATH_STDPATH` default).
    pub default_path: String,
    /// PATH for root (OpenSSH `SUPERUSER_PATH` default).
    pub superuser_path: String,
    /// MAIL is `<mail_dir>/<user>`.
    pub mail_dir: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            accept_env: Vec::new(),
            max_client_env: 128,
            set_env: Vec::new(),
            subsystems: HashMap::new(),
            default_path: "/usr/bin:/bin:/usr/sbin:/sbin".into(),
            superuser_path: "/usr/bin:/bin:/usr/sbin:/sbin".into(),
            mail_dir: "/var/mail".into(),
        }
    }
}

impl SessionConfig {
    /// Whether an `env` request for `name` is accepted (the reply to the
    /// client's request); [`spawn`] applies the same filter.
    pub fn accepts_env(&self, name: &str) -> bool {
        self.accept_env.iter().any(|p| match_pattern(name, p))
    }
}

/// RFC 4254 §6.9 signal names accepted in `signal` requests (OpenSSH
/// `name2sig`).
pub fn name_to_signal(name: &str) -> Option<libc::c_int> {
    Some(match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "KILL" => libc::SIGKILL,
        "QUIT" => libc::SIGQUIT,
        "TERM" => libc::SIGTERM,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        _ => return None,
    })
}

/// Name used in `exit-signal` (OpenSSH `sig2name`).
pub fn signal_name(sig: libc::c_int) -> &'static str {
    match sig {
        libc::SIGABRT => "ABRT",
        libc::SIGALRM => "ALRM",
        libc::SIGFPE => "FPE",
        libc::SIGHUP => "HUP",
        libc::SIGILL => "ILL",
        libc::SIGINT => "INT",
        libc::SIGKILL => "KILL",
        libc::SIGPIPE => "PIPE",
        libc::SIGQUIT => "QUIT",
        libc::SIGSEGV => "SEGV",
        libc::SIGTERM => "TERM",
        libc::SIGUSR1 => "USR1",
        libc::SIGUSR2 => "USR2",
        _ => "SIG@openssh.com",
    }
}

/// Start the session's process. Must be called inside a tokio runtime.
pub fn spawn(cfg: &SessionConfig, req: &SessionRequest) -> Result<SessionProcess, Error> {
    process::spawn(cfg, req)
}
