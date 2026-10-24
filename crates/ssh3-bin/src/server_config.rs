//! `ssh3-server` configuration file (TOML).
//!
//! TOML rather than an sshd_config subset: the server's settings are mostly
//! ssh3-specific caps and timers (SPEC §1–§5) with no sshd equivalent, and a
//! subset of sshd_config would invite operators to paste sshd options that
//! ssh3 would then have to either silently ignore or reject one by one.
//! Unknown keys are an error (`deny_unknown_fields`), so a typo never turns
//! into a silently ignored limit.
//!
//! ```toml
//! listen = "[::]:443"                       # a v6 or v4-mapped address; [::] is dual-stack
//! host_key = "/etc/ssh/ssh_host_ed25519_key"
//! endpoint_keys = "/var/lib/ssh3/endpoint-keys"   # persisted reset/CID keys (SPEC §1)
//! authorized_keys = "%h/.ssh/authorized_keys"      # %h home, %u user, %% percent;
//!                                                  # relative paths are relative to %h
//! stats_socket = "/run/ssh3/stats.sock"     # optional; one JSON object per connection
//! rendezvous = false                        # act as a gateway for registered peers (SPEC §7.1)
//!
//! [register]                                # optional: be reachable as a peer at a gateway
//! gateway = "gw.example.org:443"            # the gateway's ssh3-server
//! name = "home"                             # clients reach us as `ssh3 -J gw home`
//! user = "peer"                             # account at the gateway
//! identity = "/etc/ssh3/peer_ed25519"       # private key (OpenSSH format)
//! known_hosts = "/etc/ssh3/gateway_known_hosts"   # the gateway's host key
//!
//! [session]                                 # sshd_config analogues, all optional
//! accept_env = ["LANG", "LC_*"]             # AcceptEnv
//! set_env = { EDITOR = "vi" }               # SetEnv
//! subsystems = { sftp = "/usr/lib/ssh/sftp-server" }
//!
//! [limits]                                  # every field of ssh3_core::Limits, optional
//! idle_timeout = "30s"
//! linger = "12h"
//! probe_interval = "off"
//! lane_buffer = 8388608
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use ssh3_core::Limits;

use crate::duration::{Dur, OptDur};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub host_key: PathBuf,
    /// Without it the keys are random per start, and clients learn of a
    /// restart only by idle timeout instead of stateless reset (SPEC §1).
    pub endpoint_keys: Option<PathBuf>,
    #[serde(default = "default_authorized_keys")]
    pub authorized_keys: String,
    pub stats_socket: Option<PathBuf>,
    #[serde(default)]
    pub session: SessionOverrides,
    #[serde(default)]
    pub limits: LimitsOverrides,
    #[serde(default)]
    pub rendezvous: bool,
    pub register: Option<Register>,
}

/// Registration at a gateway (SPEC §7.1): the server keeps a client session
/// to the gateway from its own UDP socket and re-registers whenever that
/// session is lost for good (e.g. the gateway restarted).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub gateway: String,
    pub name: String,
    pub user: String,
    pub identity: PathBuf,
    pub known_hosts: PathBuf,
    /// known_hosts lookup name; default: the gateway host as written.
    pub host_key_alias: Option<String>,
}

fn default_authorized_keys() -> String {
    "%h/.ssh/authorized_keys".into()
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let c: ServerConfig = toml::from_str(text).map_err(|e| e.to_string())?;
        c.limits().validate()?;
        Ok(c)
    }

    pub fn limits(&self) -> Limits {
        self.limits.apply(Limits::default())
    }

    pub fn session(&self) -> ssh3_session::SessionConfig {
        self.session.apply(ssh3_session::SessionConfig::default())
    }

    /// The authorized_keys path for a user, sshd-style: `%h`, `%u`, `%%`;
    /// a relative result is taken relative to the home directory.
    pub fn authorized_keys_for(&self, user: &str, home: &Path) -> Result<PathBuf, String> {
        let mut out = String::new();
        let mut it = self.authorized_keys.chars();
        while let Some(c) = it.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            match it.next() {
                Some('h') => out.push_str(&home.to_string_lossy()),
                Some('u') => out.push_str(user),
                Some('%') => out.push('%'),
                Some(t) => return Err(format!("authorized_keys {:?}: unknown token %{t}", self.authorized_keys)),
                None => return Err(format!("authorized_keys {:?}: trailing %", self.authorized_keys)),
            }
        }
        let p = PathBuf::from(out);
        Ok(if p.is_absolute() { p } else { home.join(p) })
    }
}

/// Every field of [`ssh3_session::SessionConfig`], each optional; built
/// exhaustively like [`LimitsOverrides`].
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionOverrides {
    accept_env: Option<Vec<String>>,
    max_client_env: Option<usize>,
    set_env: Option<std::collections::BTreeMap<String, String>>,
    subsystems: Option<std::collections::HashMap<String, String>>,
    default_path: Option<String>,
    superuser_path: Option<String>,
    mail_dir: Option<String>,
}

impl SessionOverrides {
    pub fn apply(&self, d: ssh3_session::SessionConfig) -> ssh3_session::SessionConfig {
        let ssh3_session::SessionConfig { accept_env, max_client_env, set_env, subsystems, default_path, superuser_path, mail_dir } = d;
        ssh3_session::SessionConfig {
            accept_env: self.accept_env.clone().unwrap_or(accept_env),
            max_client_env: self.max_client_env.unwrap_or(max_client_env),
            set_env: self.set_env.as_ref().map_or(set_env, |m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
            subsystems: self.subsystems.clone().unwrap_or(subsystems),
            default_path: self.default_path.clone().unwrap_or(default_path),
            superuser_path: self.superuser_path.clone().unwrap_or(superuser_path),
            mail_dir: self.mail_dir.clone().unwrap_or(mail_dir),
        }
    }
}

/// Every field of [`Limits`], each optional. `apply` constructs `Limits`
/// exhaustively, so a field added to `Limits` fails to compile here until it
/// is made configurable (QA requirement: every timer and cap settable).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsOverrides {
    floor_window: Option<u64>,
    conn_window_ceiling: Option<u64>,
    conn_window_budget: Option<u64>,
    window_sample_min: Option<Dur>,
    window_raise_after: Option<u32>,
    window_lower_after: Option<Dur>,
    window_lower_util_pct: Option<u8>,
    stream_receive_window: Option<u64>,
    max_bidi_streams: Option<u32>,
    datagram_buffer: Option<usize>,
    idle_timeout: Option<Dur>,
    keep_alive: Option<Dur>,
    login_grace: Option<Dur>,
    max_auth_tries: Option<u32>,
    max_unauthenticated: Option<usize>,
    max_channels: Option<usize>,
    connect_timeout: Option<Dur>,
    max_listeners: Option<usize>,
    detached_accept_max: Option<usize>,
    lane_buffer: Option<usize>,
    pty_lane_buffer: Option<usize>,
    pty_max_cols: Option<u16>,
    pty_max_rows: Option<u16>,
    lane_floor: Option<u64>,
    lane_ack_bytes: Option<u64>,
    credit_idle: Option<Dur>,
    retract_timeout_min: Option<Dur>,
    lane_credit_budget: Option<u64>,
    lane_send_budget: Option<u64>,
    event_queue: Option<usize>,
    ack_interval: Option<Dur>,
    linger: Option<Dur>,
    pty_linger: Option<OptDur>,
    probe_interval: Option<OptDur>,
    probe_timeout_min: Option<Dur>,
    auto_resume: Option<bool>,
    resume_backoff_initial: Option<Dur>,
    resume_backoff_max: Option<Dur>,
    max_sessions: Option<usize>,
    tcp_socket_buffer: Option<usize>,
    udp_flows_max: Option<usize>,
    udp_flow_idle: Option<Dur>,
    udp_queue: Option<usize>,
    reassembly_budget: Option<u64>,
    reassembly_max_age: Option<Dur>,
}

impl LimitsOverrides {
    pub fn apply(&self, d: Limits) -> Limits {
        let Limits {
            floor_window,
            conn_window_ceiling,
            conn_window_budget,
            window_sample_min,
            window_raise_after,
            window_lower_after,
            window_lower_util_pct,
            stream_receive_window,
            max_bidi_streams,
            datagram_buffer,
            idle_timeout,
            keep_alive,
            login_grace,
            max_auth_tries,
            max_unauthenticated,
            max_channels,
            connect_timeout,
            max_listeners,
            detached_accept_max,
            lane_buffer,
            pty_lane_buffer,
            pty_max_cols,
            pty_max_rows,
            lane_floor,
            lane_ack_bytes,
            credit_idle,
            retract_timeout_min,
            lane_credit_budget,
            lane_send_budget,
            event_queue,
            ack_interval,
            linger,
            pty_linger,
            probe_interval,
            probe_timeout_min,
            auto_resume,
            resume_backoff_initial,
            resume_backoff_max,
            max_sessions,
            tcp_socket_buffer,
            udp_flows_max,
            udp_flow_idle,
            udp_queue,
            reassembly_budget,
            reassembly_max_age,
        } = d;
        let dur = |o: Option<Dur>, v| o.map_or(v, |d| d.0);
        Limits {
            floor_window: self.floor_window.unwrap_or(floor_window),
            conn_window_ceiling: self.conn_window_ceiling.unwrap_or(conn_window_ceiling),
            conn_window_budget: self.conn_window_budget.unwrap_or(conn_window_budget),
            window_sample_min: dur(self.window_sample_min, window_sample_min),
            window_raise_after: self.window_raise_after.unwrap_or(window_raise_after),
            window_lower_after: dur(self.window_lower_after, window_lower_after),
            window_lower_util_pct: self.window_lower_util_pct.unwrap_or(window_lower_util_pct),
            stream_receive_window: self.stream_receive_window.unwrap_or(stream_receive_window),
            max_bidi_streams: self.max_bidi_streams.unwrap_or(max_bidi_streams),
            datagram_buffer: self.datagram_buffer.unwrap_or(datagram_buffer),
            idle_timeout: dur(self.idle_timeout, idle_timeout),
            keep_alive: dur(self.keep_alive, keep_alive),
            login_grace: dur(self.login_grace, login_grace),
            max_auth_tries: self.max_auth_tries.unwrap_or(max_auth_tries),
            max_unauthenticated: self.max_unauthenticated.unwrap_or(max_unauthenticated),
            max_channels: self.max_channels.unwrap_or(max_channels),
            connect_timeout: dur(self.connect_timeout, connect_timeout),
            max_listeners: self.max_listeners.unwrap_or(max_listeners),
            detached_accept_max: self.detached_accept_max.unwrap_or(detached_accept_max),
            lane_buffer: self.lane_buffer.unwrap_or(lane_buffer),
            pty_lane_buffer: self.pty_lane_buffer.unwrap_or(pty_lane_buffer),
            pty_max_cols: self.pty_max_cols.unwrap_or(pty_max_cols),
            pty_max_rows: self.pty_max_rows.unwrap_or(pty_max_rows),
            lane_floor: self.lane_floor.unwrap_or(lane_floor),
            lane_ack_bytes: self.lane_ack_bytes.unwrap_or(lane_ack_bytes),
            credit_idle: dur(self.credit_idle, credit_idle),
            retract_timeout_min: dur(self.retract_timeout_min, retract_timeout_min),
            lane_credit_budget: self.lane_credit_budget.unwrap_or(lane_credit_budget),
            lane_send_budget: self.lane_send_budget.unwrap_or(lane_send_budget),
            event_queue: self.event_queue.unwrap_or(event_queue),
            ack_interval: dur(self.ack_interval, ack_interval),
            linger: dur(self.linger, linger),
            pty_linger: self.pty_linger.map_or(pty_linger, |p| p.0),
            probe_interval: self.probe_interval.map_or(probe_interval, |p| p.0),
            probe_timeout_min: dur(self.probe_timeout_min, probe_timeout_min),
            auto_resume: self.auto_resume.unwrap_or(auto_resume),
            resume_backoff_initial: dur(self.resume_backoff_initial, resume_backoff_initial),
            resume_backoff_max: dur(self.resume_backoff_max, resume_backoff_max),
            max_sessions: self.max_sessions.unwrap_or(max_sessions),
            tcp_socket_buffer: self.tcp_socket_buffer.unwrap_or(tcp_socket_buffer),
            udp_flows_max: self.udp_flows_max.unwrap_or(udp_flows_max),
            udp_flow_idle: dur(self.udp_flow_idle, udp_flow_idle),
            udp_queue: self.udp_queue.unwrap_or(udp_queue),
            reassembly_budget: self.reassembly_budget.unwrap_or(reassembly_budget),
            reassembly_max_age: dur(self.reassembly_max_age, reassembly_max_age),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const MIN: &str = "listen = \"[::]:443\"\nhost_key = \"/k\"\n";

    #[test]
    fn minimal_uses_defaults() {
        let c = ServerConfig::parse(MIN).unwrap();
        assert_eq!(c.authorized_keys, "%h/.ssh/authorized_keys");
        assert_eq!(c.limits().idle_timeout, Limits::default().idle_timeout);
    }

    #[test]
    fn overrides_apply() {
        let c = ServerConfig::parse(&format!("{MIN}[limits]\nidle_timeout = \"300ms\"\nlinger = \"0\"\nprobe_interval = \"off\"\nmax_channels = 7\n")).unwrap();
        let l = c.limits();
        assert_eq!(l.idle_timeout, Duration::from_millis(300));
        assert_eq!(l.linger, Duration::ZERO);
        assert_eq!(l.probe_interval, None);
        assert_eq!(l.max_channels, 7);
    }

    #[test]
    fn session_section() {
        let c = ServerConfig::parse(&format!("{MIN}[session]\naccept_env = [\"LANG\", \"LC_*\"]\nset_env = {{ EDITOR = \"vi\" }}\nsubsystems = {{ sftp = \"/usr/lib/ssh/sftp-server\" }}\n")).unwrap();
        let s = c.session();
        assert!(s.accepts_env("LC_ALL") && !s.accepts_env("PATH"));
        assert_eq!(s.set_env, vec![("EDITOR".to_string(), "vi".to_string())]);
        assert_eq!(s.subsystems["sftp"], "/usr/lib/ssh/sftp-server");
    }

    #[test]
    fn unknown_key_is_an_error() {
        let e = ServerConfig::parse(&format!("{MIN}[limits]\nidle_timout = \"1s\"\n")).unwrap_err();
        assert!(e.contains("idle_timout"), "{e}");
        let e = ServerConfig::parse(&format!("{MIN}lisen = 1\n")).unwrap_err();
        assert!(e.contains("lisen"), "{e}");
    }

    #[test]
    fn invalid_limits_are_rejected_with_the_field_named() {
        let e = ServerConfig::parse(&format!("{MIN}[limits]\nlane_floor = 4096\n")).unwrap_err();
        assert!(e.contains("lane_floor"), "{e}");
    }

    #[test]
    fn authorized_keys_tokens() {
        let mut c = ServerConfig::parse(MIN).unwrap();
        let home = Path::new("/home/u");
        assert_eq!(c.authorized_keys_for("u", home).unwrap(), PathBuf::from("/home/u/.ssh/authorized_keys"));
        c.authorized_keys = "/etc/ssh3/keys/%u".into();
        assert_eq!(c.authorized_keys_for("bob", home).unwrap(), PathBuf::from("/etc/ssh3/keys/bob"));
        c.authorized_keys = ".ssh/ak3".into();
        assert_eq!(c.authorized_keys_for("u", home).unwrap(), PathBuf::from("/home/u/.ssh/ak3"));
        c.authorized_keys = "%x".into();
        assert!(c.authorized_keys_for("u", home).is_err());
    }
}
