//! OpenSSH-compatible client command line and `ssh_config` resolution for
//! ssh3-rs (SPEC.md §9).
//!
//! The parsing and resolution logic is a port of OpenSSH 10.5p1 (`ssh.c`,
//! `readconf.c`, `misc.c`, `match.c`), checked by differential tests against
//! the real `ssh -G` (`tests/ssh_g.rs`).
//!
//! ```no_run
//! let env = ssh3_config::LocalEnv::from_system(443).unwrap();
//! let args = ["-L", "8080:localhost:80", "user@host"];
//! let cfg = ssh3_config::resolve_args(&args, &env).unwrap();
//! assert_eq!(cfg.user, "user");
//! ```
//!
//! # ssh3 extensions
//!
//! * `-U [bind:]port:host:hostport` / `LocalUDPForward port host:hostport`
//!   — local UDP forward; `-u` / `RemoteUDPForward` — remote UDP forward.
//!   Same grammar as `-L`/`-R`, host/port endpoints only.
//! * The default port comes from [`LocalEnv::default_port`] (ssh3: 443).
//!
//! # Deviations from OpenSSH 10.5p1
//!
//! * Unknown keywords are kept in [`ClientConfig::unknown`] with a warning
//!   instead of failing the file.
//! * No DNS canonicalisation: `CanonicalizeHostname` only triggers the final
//!   configuration pass (`Match canonical` then matches in that pass).
//! * `Match localnetwork` and `Match version` are rejected as unsupported.
//! * Values of OpenSSH keywords ssh3 does not implement at all (cipher and
//!   MAC lists, X11, GSSAPI, connection multiplexing, tunnels, ...) are kept
//!   in [`ClientConfig::other`] unvalidated. Every keyword whose value ssh3
//!   acts on has a typed field and is compared against `ssh -G` in
//!   `tests/ssh_g.rs` (`COMPARED`).
//! * `-D`/`DynamicForward` with a Unix-socket target and `-W port` (no host)
//!   are rejected; OpenSSH accepts them with no useful meaning.
//! * OpenSSH options that ssh3 does not implement (`-X`, `-c`, `-M`, ...)
//!   are consumed with their arguments and listed in
//!   [`ClientConfig::unsupported_flags`].

pub mod cli;
pub mod dest;
pub mod env;
pub mod expand;
pub mod forward;
mod lex;
pub mod options;
pub mod pattern;
pub mod resolve;

pub use cli::{CommandLine, parse_args};
pub use dest::{Hop, ProxyJump};
pub use env::LocalEnv;
pub use forward::{Connect, Forward, Listen};
pub use options::{
    AddressFamily, EscapeChar, IdentitySource, LogLevel, RawOption, RequestTty, SessionType,
    StrictHostKeyChecking,
};
pub use resolve::{ClientConfig, ForwardAgent, IdentityFile, resolve, resolve_args};
