//! ssh_config line processing, ported from OpenSSH 10.5p1 `readconf.c`
//! (`process_config_line_depth`, `match_cfg_line`, `read_config_file_depth`).
//!
//! Semantics kept from OpenSSH: for scalar options the first obtained value
//! wins; `Host`/`Match` gate the following lines; `Include` files inherit
//! the gate; `-o` lines are processed before any file.
//!
//! Deliberate deviation: an unknown keyword is kept (in
//! [`ClientConfig::unknown`](crate::ClientConfig::unknown)) with a warning instead of making the whole file
//! fatal, so ssh3-specific and future keywords do not break shared configs.

use std::fs;
use std::os::unix::fs::MetadataExt;

use crate::dest::{self, ProxyJump};
use crate::env::LocalEnv;
use crate::expand;
use crate::forward::{self, Forward, a2port};
use crate::lex::{WHITESPACE, argv_split, strdelim};
use crate::pattern::{ListMatch, match_hostname, match_pattern, match_pattern_list};

pub(crate) const MAX_IDENTITY_FILES: usize = 100;
const MAX_HOSTS_FILES: usize = 32;
const MAX_INCLUDE_DEPTH: usize = 16;
pub(crate) const SYSTEM_CONFIG: &str = "/etc/ssh/ssh_config";

/// `StrictHostKeyChecking`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictHostKeyChecking {
    Off,
    AcceptNew,
    Yes,
    Ask,
}

impl StrictHostKeyChecking {
    /// The `ssh -G` spelling (first key of `multistate_strict_hostkey`).
    pub fn dump(self) -> &'static str {
        match self {
            Self::Yes => "true",
            Self::Off => "false",
            Self::Ask => "ask",
            Self::AcceptNew => "accept-new",
        }
    }
}

/// `RequestTTY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestTty {
    Auto,
    No,
    Yes,
    Force,
}

impl RequestTty {
    pub fn dump(self) -> &'static str {
        match self {
            Self::Yes => "true",
            Self::No => "false",
            Self::Force => "force",
            Self::Auto => "auto",
        }
    }
}

/// `SessionType` / `-N` / `-s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    None,
    Subsystem,
    Default,
}

/// `CanonicalizeHostname`. ssh3 does not perform DNS canonicalisation; a
/// non-`No` value only triggers the second ("final") configuration pass, as
/// it does in OpenSSH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canonicalize {
    No,
    Yes,
    Always,
}

/// `AddressFamily` / `-4` / `-6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Any,
    Inet,
    Inet6,
}

impl AddressFamily {
    pub fn dump(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Inet => "inet",
            Self::Inet6 => "inet6",
        }
    }
}

/// `LogLevel` / `-q` / `-v` (log.c `log_levels[]`, in severity order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Quiet,
    Fatal,
    Error,
    Info,
    Verbose,
    Debug1,
    Debug2,
    Debug3,
}

impl LogLevel {
    /// `log_level_name()`: the first name in the table, so DEBUG1 prints
    /// as `DEBUG`.
    pub fn dump(self) -> &'static str {
        match self {
            Self::Quiet => "QUIET",
            Self::Fatal => "FATAL",
            Self::Error => "ERROR",
            Self::Info => "INFO",
            Self::Verbose => "VERBOSE",
            Self::Debug1 => "DEBUG",
            Self::Debug2 => "DEBUG2",
            Self::Debug3 => "DEBUG3",
        }
    }

    /// `log_level_number()`, case-insensitive; `DEBUG` = `DEBUG1`.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().as_str() {
            "QUIET" => Self::Quiet,
            "FATAL" => Self::Fatal,
            "ERROR" => Self::Error,
            "INFO" => Self::Info,
            "VERBOSE" => Self::Verbose,
            "DEBUG" | "DEBUG1" => Self::Debug1,
            "DEBUG2" => Self::Debug2,
            "DEBUG3" => Self::Debug3,
            _ => return None,
        })
    }

    pub(crate) fn next(self) -> Self {
        match self {
            Self::Quiet => Self::Fatal,
            Self::Fatal => Self::Error,
            Self::Error => Self::Info,
            Self::Info => Self::Verbose,
            Self::Verbose => Self::Debug1,
            Self::Debug1 => Self::Debug2,
            Self::Debug2 | Self::Debug3 => Self::Debug3,
        }
    }
}

/// `EscapeChar` / `-e`: a byte, or `none`.
pub type EscapeChar = Option<u8>;

/// Parse an `EscapeChar` value as readconf.c does: `none`, one character,
/// or `^X` with X in 64..128.
pub(crate) fn parse_escape_keyword(arg: &str) -> Option<EscapeChar> {
    let b = arg.as_bytes();
    if arg == "none" {
        Some(None)
    } else if b.len() == 1 {
        Some(Some(b[0]))
    } else if b.len() == 2 && b[0] == b'^' && (64..128).contains(&b[1]) {
        Some(Some(b[1] & 31))
    } else {
        None
    }
}

/// `vis(buf, c, VIS_WHITE, 0)` as `ssh -G` prints the escape character.
pub fn dump_escape_char(c: EscapeChar) -> String {
    match c {
        None => "none".into(),
        Some(b'\\') => "\\\\".into(),
        Some(b' ') => "\\040".into(),
        Some(c) if c < 0x20 => format!("\\^{}", (c + 64) as char),
        Some(0x7f) => "\\^?".into(),
        Some(c) => (c as char).to_string(),
    }
}

/// Which source added an identity file. OpenSSH de-duplicates identity
/// files only within the same source class (`identity_file_userprovided`:
/// 0 = system config/default, 1 = `-i`, 2 = user config/`-o`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    Default,
    CommandLine,
    UserConfig,
}

/// A configuration line kept verbatim: either a known OpenSSH keyword ssh3
/// does not interpret, or an unknown keyword.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawOption {
    /// Lower-cased keyword.
    pub keyword: String,
    pub args: Vec<String>,
    pub file: String,
    pub line: usize,
}

/// Option state during resolution (`Options` in readconf.h). `None` means
/// "not yet set" (`-1`/`NULL` in OpenSSH).
#[derive(Debug, Clone, Default)]
pub(crate) struct Options {
    pub hostname: Option<String>,
    pub host_key_alias: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<(String, IdentitySource)>,
    pub identities_only: Option<bool>,
    pub identity_agent: Option<String>,
    pub proxy_command: Option<String>,
    pub jump: Option<ProxyJump>,
    /// Local and dynamic forwards, in OpenSSH order (one list, as in C).
    pub local_forwards: Vec<Forward>,
    pub remote_forwards: Vec<Forward>,
    pub local_udp_forwards: Vec<Forward>,
    pub remote_udp_forwards: Vec<Forward>,
    pub clear_all_forwardings: Option<bool>,
    pub server_alive_interval: Option<u32>,
    pub server_alive_count_max: Option<u32>,
    pub strict_host_key_checking: Option<StrictHostKeyChecking>,
    pub user_known_hosts_files: Vec<String>,
    pub hash_known_hosts: Option<bool>,
    pub forward_agent: Option<bool>,
    pub forward_agent_sock_path: Option<String>,
    pub request_tty: Option<RequestTty>,
    pub session_type: Option<SessionType>,
    pub send_env: Vec<String>,
    pub set_env: Vec<String>,
    pub connect_timeout: Option<u32>,
    pub exit_on_forward_failure: Option<bool>,
    pub canonicalize_hostname: Option<Canonicalize>,
    pub ignore_unknown: Option<String>,
    pub tag: Option<String>,
    pub remote_command: Option<String>,
    /// `-W host:port`.
    pub stdio_forward: Option<(String, u16)>,
    pub gateway_ports: Option<bool>,
    pub address_family: Option<AddressFamily>,
    pub bind_address: Option<String>,
    pub bind_interface: Option<String>,
    pub streamlocal_bind_unlink: Option<bool>,
    pub streamlocal_bind_mask: Option<u32>,
    /// `PermitRemoteOpen` entries as written (`None` = unset = any).
    pub permit_remote_open: Option<Vec<String>>,
    pub connection_attempts: Option<u32>,
    pub batch_mode: Option<bool>,
    pub log_level: Option<LogLevel>,
    pub escape_char: Option<EscapeChar>,
    pub global_known_hosts_files: Vec<String>,
    pub stdin_null: Option<bool>,
    pub fork_after_authentication: Option<bool>,
    pub other: Vec<RawOption>,
    pub unknown: Vec<RawOption>,
    pub warnings: Vec<String>,
}

/// Flags of `read_config_file_depth` (`SSHCONF_*`).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Flags {
    pub checkperm: bool,
    pub userconf: bool,
    pub final_pass: bool,
    pub nevermatch: bool,
}

/// What OpenSSH does with a failed line.
#[derive(Debug)]
pub(crate) enum LineError {
    /// `goto out` → counted; the file fails after all lines are read.
    Bad(String),
    /// `fatal()` → stops immediately.
    Fatal(String),
}

/// Inputs to line processing that are not option state.
pub(crate) struct Ctx<'a> {
    pub env: &'a LocalEnv,
    /// The host the Host/Match lines are evaluated against (`host`).
    pub host: &'a str,
    /// The host as given on the command line (`original_host`, `%n`).
    pub original_host: &'a str,
    /// The remote command from the command line (`Match command`).
    pub remote_command: &'a str,
    /// Set when a `Match final` is seen (`want_final_pass`).
    pub want_final_pass: bool,
}

/// Classification of a keyword (`parse_token`).
enum Kw {
    Known(&'static str),
    Other,
    Ignore,
    Deprecated,
    Unsupported,
    IgnoredUnknown,
    Unknown,
}

/// Keywords handled by ssh3-config (canonical lower-case names, plus
/// OpenSSH aliases mapped to their canonical name).
const HANDLED: &[(&str, &str)] = &[
    ("hostname", "hostname"),
    ("hostkeyalias", "hostkeyalias"),
    ("user", "user"),
    ("port", "port"),
    ("identityfile", "identityfile"),
    ("identityfile2", "identityfile"),
    ("identitiesonly", "identitiesonly"),
    ("identityagent", "identityagent"),
    ("proxycommand", "proxycommand"),
    ("proxyjump", "proxyjump"),
    ("localforward", "localforward"),
    ("remoteforward", "remoteforward"),
    ("dynamicforward", "dynamicforward"),
    ("clearallforwardings", "clearallforwardings"),
    ("serveraliveinterval", "serveraliveinterval"),
    ("serveralivecountmax", "serveralivecountmax"),
    ("stricthostkeychecking", "stricthostkeychecking"),
    ("userknownhostsfile", "userknownhostsfile"),
    ("hashknownhosts", "hashknownhosts"),
    ("forwardagent", "forwardagent"),
    ("requesttty", "requesttty"),
    ("sessiontype", "sessiontype"),
    ("sendenv", "sendenv"),
    ("setenv", "setenv"),
    ("connecttimeout", "connecttimeout"),
    ("exitonforwardfailure", "exitonforwardfailure"),
    ("canonicalizehostname", "canonicalizehostname"),
    ("ignoreunknown", "ignoreunknown"),
    ("tag", "tag"),
    ("remotecommand", "remotecommand"),
    ("host", "host"),
    ("match", "match"),
    ("include", "include"),
    ("gatewayports", "gatewayports"),
    ("addressfamily", "addressfamily"),
    ("bindaddress", "bindaddress"),
    ("bindinterface", "bindinterface"),
    ("streamlocalbindunlink", "streamlocalbindunlink"),
    ("streamlocalbindmask", "streamlocalbindmask"),
    ("permitremoteopen", "permitremoteopen"),
    ("connectionattempts", "connectionattempts"),
    ("batchmode", "batchmode"),
    ("loglevel", "loglevel"),
    ("escapechar", "escapechar"),
    ("globalknownhostsfile", "globalknownhostsfile"),
    ("stdinnull", "stdinnull"),
    ("forkafterauthentication", "forkafterauthentication"),
    // ssh3 extensions (UDP forwarding).
    ("localudpforward", "localudpforward"),
    ("remoteudpforward", "remoteudpforward"),
];

/// Remaining OpenSSH 10.5p1 client keywords (readconf.c `keywords[]`) that
/// ssh3 accepts without interpreting.
const OTHER: &[&str] = &[
    "gssapiauthentication",
    "gssapidelegatecredentials",
    "pkcs11provider",
    "smartcarddevice",
    "forwardx11",
    "forwardx11trusted",
    "forwardx11timeout",
    "xauthlocation",
    "passwordauthentication",
    "kbdinteractiveauthentication",
    "kbdinteractivedevices",
    "challengeresponseauthentication",
    "skeyauthentication",
    "tisauthentication",
    "pubkeyauthentication",
    "dsaauthentication",
    "hostbasedauthentication",
    "certificatefile",
    "addkeystoagent",
    "ciphers",
    "macs",
    "checkhostip",
    "compression",
    "tcpkeepalive",
    "keepalive",
    "numberofpasswordprompts",
    "syslogfacility",
    "logverbose",
    "preferredauthentications",
    "hostkeyalgorithms",
    "casignaturealgorithms",
    "enablesshkeysign",
    "verifyhostkeydns",
    "nohostauthenticationforlocalhost",
    "rekeylimit",
    "controlpath",
    "controlmaster",
    "controlpersist",
    "tunnel",
    "tunneldevice",
    "localcommand",
    "permitlocalcommand",
    "visualhostkey",
    "kexalgorithms",
    "ipqos",
    "proxyusefdpass",
    "canonicaldomains",
    "canonicalizefallbacklocal",
    "canonicalizemaxdots",
    "canonicalizepermittedcnames",
    "revokedhostkeys",
    "fingerprinthash",
    "updatehostkeys",
    "hostbasedacceptedalgorithms",
    "hostbasedkeytypes",
    "pubkeyacceptedalgorithms",
    "pubkeyacceptedkeytypes",
    "securitykeyprovider",
    "knownhostscommand",
    "requiredrsasize",
    "enableescapecommandline",
    "obscurekeystroketiming",
    "channeltimeout",
    "versionaddendum",
    "refuseconnection",
    "warnweakcrypto",
];

const DEPRECATED: &[&str] = &[
    "cipher",
    "fallbacktorsh",
    "globalknownhostsfile2",
    "rhostsauthentication",
    "userknownhostsfile2",
    "useroaming",
    "usersh",
    "useprivilegedport",
];

const UNSUPPORTED: &[&str] = &[
    "afstokenpassing",
    "kerberosauthentication",
    "kerberostgtpassing",
    "rsaauthentication",
    "rhostsrsaauthentication",
    "compressionlevel",
];

fn classify(keyword: &str, ignore_unknown: Option<&str>) -> Kw {
    if let Some((_, canon)) = HANDLED.iter().find(|(k, _)| *k == keyword) {
        return Kw::Known(canon);
    }
    if keyword == "protocol" {
        return Kw::Ignore;
    }
    if OTHER.contains(&keyword) {
        return Kw::Other;
    }
    if DEPRECATED.contains(&keyword) {
        return Kw::Deprecated;
    }
    if UNSUPPORTED.contains(&keyword) {
        return Kw::Unsupported;
    }
    if let Some(list) = ignore_unknown
        && match_pattern_list(keyword, list, true) == ListMatch::Positive
    {
        return Kw::IgnoredUnknown;
    }
    Kw::Unknown
}

fn flag_value(arg: &str) -> Option<bool> {
    match arg.to_ascii_lowercase().as_str() {
        "true" | "yes" => Some(true),
        "false" | "no" => Some(false),
        _ => None,
    }
}

fn strict_value(arg: &str) -> Option<StrictHostKeyChecking> {
    use StrictHostKeyChecking::*;
    match arg.to_ascii_lowercase().as_str() {
        "true" | "yes" => Some(Yes),
        "false" | "no" | "off" => Some(Off),
        "ask" => Some(Ask),
        "accept-new" => Some(AcceptNew),
        _ => None,
    }
}

fn tty_value(arg: &str) -> Option<RequestTty> {
    use RequestTty::*;
    match arg.to_ascii_lowercase().as_str() {
        "true" | "yes" => Some(Yes),
        "false" | "no" => Some(No),
        "force" => Some(Force),
        "auto" => Some(Auto),
        _ => None,
    }
}

fn session_value(arg: &str) -> Option<SessionType> {
    match arg.to_ascii_lowercase().as_str() {
        "none" => Some(SessionType::None),
        "subsystem" => Some(SessionType::Subsystem),
        "default" => Some(SessionType::Default),
        _ => None,
    }
}

fn canon_value(arg: &str) -> Option<Canonicalize> {
    match arg.to_ascii_lowercase().as_str() {
        "true" | "yes" => Some(Canonicalize::Yes),
        "false" | "no" => Some(Canonicalize::No),
        "always" => Some(Canonicalize::Always),
        _ => None,
    }
}

/// Port of `convtime()`: `90`, `1h30m`, `1.5s`, `2d`, `1w`. Fractions
/// are allowed only for seconds and are truncated.
pub(crate) fn convtime(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let b = s.as_bytes();
    let mut total = 0f64;
    let mut seen_seconds = false;
    let mut i = 0;
    while i < b.len() {
        if !(b[i].is_ascii_digit() || b[i] == b'.') {
            return None;
        }
        let start = i;
        while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
            i += 1;
        }
        let num = &s[start..i];
        let val: f64 = num.parse().ok()?;
        let mult = match b.get(i) {
            None | Some(b's') | Some(b'S') => {
                if seen_seconds {
                    return None;
                }
                seen_seconds = true;
                1.0
            }
            Some(b'm') | Some(b'M') => 60.0,
            Some(b'h') | Some(b'H') => 3600.0,
            Some(b'd') | Some(b'D') => 86400.0,
            Some(b'w') | Some(b'W') => 604800.0,
            Some(_) => return None,
        };
        if num.contains('.') && (mult > 1.0 || num.ends_with('.')) {
            return None;
        }
        total += val * mult;
        if i < b.len() {
            i += 1;
        }
    }
    if total > i32::MAX as f64 {
        return None;
    }
    Some(total as u32)
}

/// Port of `atoi_err()`: decimal 0..=INT_MAX.
fn atoi_err(s: Option<&str>) -> Result<u32, &'static str> {
    let s = s.filter(|s| !s.is_empty()).ok_or("missing")?;
    let t = s.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err("invalid");
    }
    if neg {
        return Err("too small");
    }
    match digits.parse::<u64>() {
        Ok(v) if v <= i32::MAX as u64 => Ok(v as u32),
        _ => Err("too large"),
    }
}

fn valid_env_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Shift the next argument (`argv_next`).
fn next(args: &mut std::collections::VecDeque<String>) -> Option<String> {
    args.pop_front()
}

impl Options {
    /// Port of `add_identity_file()` (dir = NULL case).
    pub fn add_identity_file(&mut self, path: String, src: IdentitySource) -> Result<(), String> {
        if self.identity_files.len() >= MAX_IDENTITY_FILES {
            return Err(format!(
                "Too many identity files specified (max {MAX_IDENTITY_FILES})"
            ));
        }
        if self
            .identity_files
            .iter()
            .any(|(p, s)| *s == src && *p == path)
        {
            return Ok(());
        }
        self.identity_files.push((path, src));
        Ok(())
    }

    /// `add_local_forward()` / `add_remote_forward()`: ignore duplicates.
    pub fn add_forward(list: &mut Vec<Forward>, f: Forward) {
        if !list.contains(&f) {
            list.push(f);
        }
    }

    /// Port of `process_config_line_depth()`. `active` is `None` for a
    /// command-line (`-o`) line.
    #[allow(clippy::too_many_arguments)]
    pub fn process_line(
        &mut self,
        ctx: &mut Ctx<'_>,
        raw_line: &str,
        filename: &str,
        linenum: usize,
        active: Option<&mut bool>,
        flags: Flags,
        depth: usize,
    ) -> Result<(), LineError> {
        let mut cmdline_active = true;
        let cmdline = active.is_none();
        let active: &mut bool = match active {
            Some(a) => a,
            None => &mut cmdline_active,
        };
        let bad = |m: String| Err(LineError::Bad(format!("{filename} line {linenum}: {m}")));

        // Strip trailing whitespace (and \f), never the first character.
        let mut line = raw_line.to_string();
        while line.len() > 1 && line.ends_with([' ', '\t', '\r', '\n', '\x0c']) {
            line.pop();
        }
        if line.is_empty() {
            return Ok(());
        }
        let Some((mut keyword, mut rest)) = strdelim(&line) else {
            return Ok(());
        };
        if keyword.is_empty() {
            let Some(r) = rest.as_deref() else {
                return Ok(());
            };
            let Some((k, r2)) = strdelim(r) else {
                return Ok(());
            };
            keyword = k;
            rest = r2;
        }
        if keyword.is_empty() || keyword.starts_with('\n') || keyword.starts_with('#') {
            return Ok(());
        }
        let keyword = keyword.to_ascii_lowercase();
        let str_rest: String = match rest {
            Some(r) => r.trim_start_matches(WHITESPACE).to_string(),
            None => String::new(),
        };
        if str_rest.is_empty() {
            return bad(format!("no argument after keyword \"{keyword}\""));
        }
        let kw = classify(&keyword, self.ignore_unknown.as_deref());
        if matches!(kw, Kw::Unknown) {
            // OpenSSH: error("Bad configuration option") and the file fails.
            // ssh3: keep and warn (see module docs).
            let args = argv_split(&str_rest, true).unwrap_or_default();
            self.warnings.push(format!(
                "{filename}: line {linenum}: unknown configuration option \"{keyword}\" kept but not interpreted"
            ));
            if *active {
                self.unknown.push(RawOption {
                    keyword,
                    args,
                    file: filename.into(),
                    line: linenum,
                });
            }
            return Ok(());
        }
        let Some(argv) = argv_split(&str_rest, true) else {
            return bad("invalid quotes".into());
        };
        let mut args: std::collections::VecDeque<String> = argv.into();

        let canon = match kw {
            Kw::Known(c) => c,
            Kw::Ignore | Kw::Deprecated | Kw::IgnoredUnknown => {
                if matches!(kw, Kw::IgnoredUnknown) && *active {
                    self.unknown.push(RawOption {
                        keyword,
                        args: args.into(),
                        file: filename.into(),
                        line: linenum,
                    });
                }
                return Ok(());
            }
            Kw::Unsupported => {
                self.warnings.push(format!(
                    "{filename} line {linenum}: Unsupported option \"{keyword}\""
                ));
                return Ok(());
            }
            Kw::Other => {
                if *active {
                    self.other.push(RawOption {
                        keyword,
                        args: args.into(),
                        file: filename.into(),
                        line: linenum,
                    });
                }
                return Ok(());
            }
            Kw::Unknown => unreachable!(),
        };

        macro_rules! set_if_unset {
            ($field:expr, $val:expr) => {
                if *active && $field.is_none() {
                    $field = Some($val);
                }
            };
        }

        match canon {
            "connecttimeout" | "serveraliveinterval" => {
                let Some(arg) = next(&mut args).filter(|a| !a.is_empty()) else {
                    return bad("missing time value.".into());
                };
                let value = if arg == "none" {
                    None
                } else {
                    match convtime(&arg) {
                        Some(v) => Some(v),
                        None => return bad("invalid time value.".into()),
                    }
                };
                // "none" is the unset marker (-1) in OpenSSH: setting it
                // leaves the option unset for later lines.
                if let Some(v) = value {
                    if canon == "connecttimeout" {
                        set_if_unset!(self.connect_timeout, v);
                    } else {
                        set_if_unset!(self.server_alive_interval, v);
                    }
                }
            }
            "forwardagent" => {
                let Some(arg) = next(&mut args).filter(|a| !a.is_empty()) else {
                    return bad("missing argument.".into());
                };
                match flag_value(&arg) {
                    Some(v) => set_if_unset!(self.forward_agent, v),
                    None => {
                        set_if_unset!(self.forward_agent, true);
                        self.agent_path(&arg, *active, true).or_else(&bad)?;
                    }
                }
            }
            "addressfamily" => {
                let arg = next(&mut args);
                let v = match arg.as_deref().map(str::to_ascii_lowercase).as_deref() {
                    Some("inet") => AddressFamily::Inet,
                    Some("inet6") => AddressFamily::Inet6,
                    Some("any") => AddressFamily::Any,
                    _ => {
                        return bad(format!(
                            "unsupported option \"{}\".",
                            arg.unwrap_or_default()
                        ));
                    }
                };
                set_if_unset!(self.address_family, v);
            }
            "loglevel" => {
                let arg = next(&mut args);
                let Some(v) = arg.as_deref().and_then(LogLevel::parse) else {
                    return bad(format!(
                        "unsupported log level '{}'",
                        arg.unwrap_or_else(|| "<NONE>".into())
                    ));
                };
                set_if_unset!(self.log_level, v);
            }
            "escapechar" => {
                let Some(arg) = next(&mut args).filter(|a| !a.is_empty()) else {
                    return bad("Missing argument.".into());
                };
                let Some(v) = parse_escape_keyword(&arg) else {
                    return bad("Bad escape character.".into());
                };
                set_if_unset!(self.escape_char, v);
            }
            "connectionattempts" => {
                let arg = next(&mut args);
                match atoi_err(arg.as_deref()) {
                    Ok(v) => set_if_unset!(self.connection_attempts, v),
                    Err(e) => return bad(format!("integer value {e}.")),
                }
            }
            "streamlocalbindmask" => {
                let Some(arg) = next(&mut args).filter(|a| !a.is_empty()) else {
                    return bad("Missing StreamLocalBindMask argument.".into());
                };
                // strtol(arg, &end, 8): leading octal digits; the rest of the
                // string is ignored, as in readconf.c.
                let t = arg.trim_start_matches(|c: char| c.is_ascii_whitespace());
                let (neg, t) = match t.as_bytes().first() {
                    Some(b'-') => (true, &t[1..]),
                    Some(b'+') => (false, &t[1..]),
                    _ => (false, t),
                };
                let digits: String = t.chars().take_while(|c| ('0'..='7').contains(c)).collect();
                let value = if digits.is_empty() {
                    None
                } else {
                    u64::from_str_radix(&digits, 8)
                        .ok()
                        .filter(|v| !neg && *v <= 0o777)
                };
                let Some(v) = value else {
                    return bad("Bad mask.".into());
                };
                // readconf.c assigns unconditionally: no first-value-wins
                // and no Host/Match gating for this keyword.
                self.streamlocal_bind_mask = Some(v as u32);
            }
            "permitremoteopen" => {
                let found = self.permit_remote_open.is_none();
                let mut strs: Vec<String> = Vec::new();
                while let Some(arg) = next(&mut args) {
                    if arg.eq_ignore_ascii_case("none") || arg.eq_ignore_ascii_case("any") {
                        if !strs.is_empty() || !args.is_empty() {
                            return bad(format!(
                                "keyword {keyword} \"{arg}\" argument must appear alone."
                            ));
                        }
                    } else {
                        // hpdelim(): host (possibly [bracketed]) then ':' port.
                        let Some((_host, port)) = dest::hpdelim_colon(&arg) else {
                            return Err(LineError::Fatal(format!(
                                "{filename} line {linenum}: missing host in permitremoteopen"
                            )));
                        };
                        let ok = match port {
                            Some("*") => true,
                            Some(p) => a2port(p).is_some_and(|v| v > 0),
                            None => false,
                        };
                        if !ok {
                            return Err(LineError::Fatal(format!(
                                "{filename} line {linenum}: bad port number in permitremoteopen"
                            )));
                        }
                    }
                    strs.push(arg);
                }
                if strs.is_empty() {
                    return Err(LineError::Fatal(format!(
                        "{filename} line {linenum}: missing permitremoteopen specification"
                    )));
                }
                if found && *active {
                    self.permit_remote_open = Some(strs);
                }
            }
            "exitonforwardfailure"
            | "identitiesonly"
            | "hashknownhosts"
            | "clearallforwardings"
            | "gatewayports"
            | "streamlocalbindunlink"
            | "batchmode"
            | "stdinnull"
            | "forkafterauthentication" => {
                let arg = next(&mut args);
                let Some(v) = arg.as_deref().and_then(flag_value) else {
                    return bad(format!(
                        "unsupported option \"{}\".",
                        arg.unwrap_or_default()
                    ));
                };
                match canon {
                    "exitonforwardfailure" => set_if_unset!(self.exit_on_forward_failure, v),
                    "identitiesonly" => set_if_unset!(self.identities_only, v),
                    "hashknownhosts" => set_if_unset!(self.hash_known_hosts, v),
                    "gatewayports" => set_if_unset!(self.gateway_ports, v),
                    "streamlocalbindunlink" => set_if_unset!(self.streamlocal_bind_unlink, v),
                    "batchmode" => set_if_unset!(self.batch_mode, v),
                    "stdinnull" => set_if_unset!(self.stdin_null, v),
                    "forkafterauthentication" => set_if_unset!(self.fork_after_authentication, v),
                    _ => set_if_unset!(self.clear_all_forwardings, v),
                }
            }
            "stricthostkeychecking" => {
                let arg = next(&mut args);
                let Some(v) = arg.as_deref().and_then(strict_value) else {
                    return bad(format!(
                        "unsupported option \"{}\".",
                        arg.unwrap_or_default()
                    ));
                };
                set_if_unset!(self.strict_host_key_checking, v);
            }
            "requesttty" => {
                let arg = next(&mut args);
                let Some(v) = arg.as_deref().and_then(tty_value) else {
                    return bad(format!(
                        "unsupported option \"{}\".",
                        arg.unwrap_or_default()
                    ));
                };
                set_if_unset!(self.request_tty, v);
            }
            "sessiontype" => {
                let arg = next(&mut args);
                let Some(v) = arg.as_deref().and_then(session_value) else {
                    return bad(format!(
                        "unsupported option \"{}\".",
                        arg.unwrap_or_default()
                    ));
                };
                set_if_unset!(self.session_type, v);
            }
            "canonicalizehostname" => {
                let arg = next(&mut args);
                let Some(v) = arg.as_deref().and_then(canon_value) else {
                    return bad(format!(
                        "unsupported option \"{}\".",
                        arg.unwrap_or_default()
                    ));
                };
                set_if_unset!(self.canonicalize_hostname, v);
            }
            "identityfile" => {
                let Some(arg) = next(&mut args).filter(|a| !a.is_empty()) else {
                    return bad("Missing argument.".into());
                };
                if *active {
                    let src = if flags.userconf {
                        IdentitySource::UserConfig
                    } else {
                        IdentitySource::Default
                    };
                    self.add_identity_file(arg, src).or_else(&bad)?;
                }
            }
            "user" | "hostname" | "hostkeyalias" | "tag" | "ignoreunknown" | "bindaddress"
            | "bindinterface" => {
                let Some(arg) = next(&mut args).filter(|a| !a.is_empty()) else {
                    return bad("Missing argument.".into());
                };
                match canon {
                    "user" => set_if_unset!(self.user, arg),
                    "hostname" => set_if_unset!(self.hostname, arg),
                    "hostkeyalias" => set_if_unset!(self.host_key_alias, arg),
                    "tag" => set_if_unset!(self.tag, arg),
                    "bindaddress" => set_if_unset!(self.bind_address, arg),
                    "bindinterface" => set_if_unset!(self.bind_interface, arg),
                    _ => set_if_unset!(self.ignore_unknown, arg),
                }
            }
            "userknownhostsfile" | "globalknownhostsfile" => {
                let list = if canon == "userknownhostsfile" {
                    &mut self.user_known_hosts_files
                } else {
                    &mut self.global_known_hosts_files
                };
                let was_empty = list.is_empty();
                let mut i = 0;
                while let Some(arg) = next(&mut args) {
                    if arg.is_empty() {
                        return bad(format!("keyword {keyword} empty argument"));
                    }
                    if arg.eq_ignore_ascii_case("none") && (i > 0 || !args.is_empty()) {
                        return bad(format!(
                            "keyword {keyword} \"none\" argument must appear alone."
                        ));
                    }
                    i += 1;
                    if *active && was_empty {
                        if list.len() >= MAX_HOSTS_FILES {
                            return bad(format!("too many {keyword} entries."));
                        }
                        list.push(arg);
                    }
                }
            }
            "proxycommand" | "remotecommand" => {
                let cmd = str_rest
                    .trim_start_matches([' ', '\t', '\r', '\n', '='])
                    .to_string();
                if canon == "proxycommand" {
                    set_if_unset!(self.proxy_command, cmd);
                } else {
                    set_if_unset!(self.remote_command, cmd);
                }
                args.clear();
            }
            "proxyjump" => {
                let spec = str_rest.trim_start_matches([' ', '\t', '\r', '\n', '=']);
                match dest::parse_jump(spec, cmdline) {
                    Ok(ProxyJump::None) => {
                        if *active && self.jump.is_none() {
                            self.jump = Some(ProxyJump::None);
                        }
                    }
                    Ok(j) => {
                        if *active && self.proxy_command.is_none() && self.jump.is_none() {
                            self.jump = Some(j);
                            self.proxy_command = Some("none".into());
                        }
                    }
                    Err(e) => return bad(format!("Invalid ProxyJump \"{spec}\": {e}")),
                }
                args.clear();
            }
            "port" => {
                let Some(arg) = next(&mut args).filter(|a| !a.is_empty()) else {
                    return bad("Missing argument.".into());
                };
                match a2port(&arg) {
                    Some(p) if p > 0 => set_if_unset!(self.port, p),
                    _ => return bad(format!("Bad port '{arg}'.")),
                }
            }
            "serveralivecountmax" => {
                let arg = next(&mut args);
                match atoi_err(arg.as_deref()) {
                    Ok(v) => set_if_unset!(self.server_alive_count_max, v),
                    Err(e) => return bad(format!("integer value {e}.")),
                }
            }
            "localforward" | "remoteforward" | "dynamicforward" | "localudpforward"
            | "remoteudpforward" => {
                let Some(arg) = next(&mut args).filter(|a| !a.is_empty()) else {
                    return bad("Missing argument.".into());
                };
                let remote = canon == "remoteforward" || canon == "remoteudpforward";
                let udp = canon.ends_with("udpforward");
                let mut dynamic = canon == "dynamicforward";
                let mut spec = arg.clone();
                if !dynamic {
                    match next(&mut args).filter(|a| !a.is_empty()) {
                        Some(arg2) => spec = format!("{arg}:{arg2}"),
                        None if remote && !udp => dynamic = true,
                        None => return bad("Missing target argument.".into()),
                    }
                }
                let parsed = if udp {
                    forward::parse_udp_forward(&spec, remote)
                } else {
                    forward::parse_forward(&spec, dynamic, remote)
                };
                let Some(fwd) = parsed else {
                    return bad("Bad forwarding specification.".into());
                };
                if *active {
                    let list = match canon {
                        "remoteforward" => &mut self.remote_forwards,
                        "localudpforward" => &mut self.local_udp_forwards,
                        "remoteudpforward" => &mut self.remote_udp_forwards,
                        _ => &mut self.local_forwards,
                    };
                    Options::add_forward(list, fwd);
                }
            }
            "host" => {
                if cmdline {
                    return bad("Host directive not supported as a command-line option".into());
                }
                *active = false;
                while let Some(arg) = next(&mut args) {
                    if arg.is_empty() {
                        return bad(format!("keyword {keyword} empty argument"));
                    }
                    if flags.nevermatch {
                        args.clear();
                        break;
                    }
                    let (negated, pat) = match arg.strip_prefix('!') {
                        Some(p) => (true, p),
                        None => (false, arg.as_str()),
                    };
                    if match_pattern(ctx.host, pat) {
                        if negated {
                            *active = false;
                            args.clear();
                            break;
                        }
                        *active = true;
                    }
                }
            }
            "match" => {
                if cmdline {
                    return bad("Match directive not supported as a command-line option".into());
                }
                let value =
                    self.match_cfg_line(ctx, &mut args, flags.final_pass, filename, linenum)?;
                *active = if flags.nevermatch { false } else { value };
            }
            "sendenv" => {
                let mut found = false;
                while let Some(arg) = next(&mut args) {
                    if arg.is_empty() || arg.contains('=') {
                        return bad("Invalid environment name.".into());
                    }
                    found = true;
                    if !*active {
                        continue;
                    }
                    if let Some(pat) = arg.strip_prefix('-') {
                        self.send_env.retain(|e| !match_pattern(e, pat));
                        continue;
                    }
                    self.send_env.push(arg);
                }
                if !found {
                    return Err(LineError::Fatal(format!(
                        "{filename} line {linenum}: no {keyword} specified"
                    )));
                }
            }
            "setenv" => {
                let found = self.set_env.is_empty();
                let mut strs: Vec<String> = Vec::new();
                while let Some(arg) = next(&mut args) {
                    let Some(eq) = arg.find('=') else {
                        return bad("Invalid SetEnv.".into());
                    };
                    let name = &arg[..eq];
                    if strs.iter().any(|s| s.split('=').next() == Some(name)) {
                        continue;
                    }
                    strs.push(arg);
                }
                if strs.is_empty() {
                    return Err(LineError::Fatal(format!(
                        "{filename} line {linenum}: no {keyword} specified"
                    )));
                }
                if found && *active {
                    self.set_env = strs;
                }
            }
            "identityagent" => {
                let Some(arg) = next(&mut args).filter(|a| !a.is_empty()) else {
                    return bad("Missing argument.".into());
                };
                self.agent_path(&arg, *active, false).or_else(&bad)?;
            }
            "include" => {
                if cmdline {
                    return bad("Include directive not supported as a command-line option".into());
                }
                self.include(ctx, &mut args, filename, linenum, active, flags, depth)?;
            }
            _ => unreachable!("unhandled keyword {canon}"),
        }

        if !args.is_empty() {
            return bad(format!("keyword {keyword} extra arguments at end of line"));
        }
        Ok(())
    }

    /// `parse_agent_path` (shared by IdentityAgent and ForwardAgent).
    fn agent_path(&mut self, arg: &str, active: bool, forward: bool) -> Result<(), String> {
        if expand::dollar(arg).is_err() {
            return Err(format!("Invalid environment expansion {arg}."));
        }
        if let Some(name) = arg.strip_prefix('$')
            && !name.starts_with('{')
            && !valid_env_name(name)
        {
            return Err(format!("Invalid environment name {arg}."));
        }
        let field = if forward {
            &mut self.forward_agent_sock_path
        } else {
            &mut self.identity_agent
        };
        if active && field.is_none() {
            *field = Some(arg.to_string());
        }
        Ok(())
    }

    /// Port of `expand_match_exec_or_include_path()`.
    fn expand_exec_or_include(
        &self,
        ctx: &Ctx<'_>,
        path: &str,
        final_pass: bool,
        is_include: bool,
    ) -> Result<String, expand::ExpandError> {
        let env = ctx.env;
        let port = self.port.unwrap_or(env.default_port).to_string();
        let ruser = self.user.clone().unwrap_or_else(|| env.user.clone());
        let host = self.match_host(ctx, final_pass);
        let jmphost = match &self.jump {
            Some(ProxyJump::Hops { hops, .. }) => {
                hops.last().map(|h| h.host.clone()).unwrap_or_default()
            }
            _ => String::new(),
        };
        let conn_hash =
            crate::resolve::connection_hash(&env.hostname, &host, &port, &ruser, &jmphost);
        let keyalias = self.host_key_alias.clone().unwrap_or_else(|| host.clone());
        let uid = env.uid.to_string();
        let tokens: [(char, &str); 12] = [
            ('C', &conn_hash),
            ('L', env.short_hostname()),
            ('d', &env.home),
            ('h', &host),
            ('k', &keyalias),
            ('l', &env.hostname),
            ('n', ctx.original_host),
            ('p', &port),
            ('r', &ruser),
            ('u', &env.user),
            ('i', &uid),
            ('j', &jmphost),
        ];
        if is_include {
            expand::percent_dollar(path, &tokens)
        } else {
            expand::percent(path, &tokens)
        }
    }

    /// The host `Match host` and `%h` see: the configured HostName with
    /// `%h` expanded, or the command-line host (final pass: HostName as is).
    fn match_host(&self, ctx: &Ctx<'_>, final_pass: bool) -> String {
        match &self.hostname {
            Some(h) if final_pass => h.clone(),
            Some(h) => expand::percent(h, &[('h', ctx.host)]).unwrap_or_else(|_| h.clone()),
            None => ctx.host.to_string(),
        }
    }

    /// Port of `match_cfg_line()`. Returns whether the block is active.
    fn match_cfg_line(
        &self,
        ctx: &mut Ctx<'_>,
        args: &mut std::collections::VecDeque<String>,
        final_pass: bool,
        filename: &str,
        linenum: usize,
    ) -> Result<bool, LineError> {
        let bad = |m: String| LineError::Bad(format!("{filename} line {linenum}: {m}"));
        let ruser = self.user.clone().unwrap_or_else(|| ctx.env.user.clone());
        let host = self.match_host(ctx, final_pass);
        let mut result = true;
        let mut attributes = 0;
        while let Some(oattrib) = args.pop_front() {
            if oattrib.starts_with('#') {
                args.clear();
                break;
            }
            let (negate, attrib) = match oattrib.strip_prefix('!') {
                Some(a) => (true, a.to_string()),
                None => (false, oattrib.clone()),
            };
            let lower = attrib.to_ascii_lowercase();
            if lower == "all" {
                let more = args.pop_front();
                if attributes > 1
                    || matches!(more.as_deref(), Some(a) if !a.is_empty() && !a.starts_with('#'))
                {
                    return Err(bad(format!(
                        "'{oattrib}' cannot be combined with other Match attributes"
                    )));
                }
                if more.as_deref().is_some_and(|a| a.starts_with('#')) {
                    args.clear();
                }
                if result {
                    result = !negate;
                }
                return Ok(result);
            }
            attributes += 1;
            if lower == "canonical" || lower == "final" {
                if lower == "final" {
                    ctx.want_final_pass |= !negate;
                }
                if final_pass == negate {
                    result = false;
                }
                continue;
            }
            const EQ_FORMS: &[&str] = &[
                "host",
                "originalhost",
                "user",
                "localuser",
                "localnetwork",
                "version",
                "tagged",
                "command",
                "exec",
            ];
            let (name, arg) = match attrib.find('=') {
                Some(eq) if EQ_FORMS.contains(&attrib[..eq].to_ascii_lowercase().as_str()) => (
                    attrib[..eq].to_ascii_lowercase(),
                    Some(attrib[eq + 1..].to_string()),
                ),
                _ => match args.pop_front() {
                    Some(a) => (lower.clone(), Some(a)),
                    None => return Err(bad(format!("missing argument for Match '{oattrib}'"))),
                },
            };
            let arg = arg.filter(|a| !a.is_empty() || name == "tagged" || name == "command");
            let Some(arg) = arg.filter(|a| !a.starts_with('#')) else {
                return Err(bad(format!("Missing Match criteria for {attrib}")));
            };
            let r = match name.as_str() {
                "host" => match_hostname(&host, &arg) == ListMatch::Positive,
                "originalhost" => match_hostname(ctx.original_host, &arg) == ListMatch::Positive,
                "user" => match_pattern_list(&ruser, &arg, false) == ListMatch::Positive,
                "localuser" => {
                    match_pattern_list(&ctx.env.user, &arg, false) == ListMatch::Positive
                }
                "tagged" => {
                    let criteria = self.tag.as_deref().unwrap_or("");
                    if criteria.is_empty() {
                        arg.is_empty()
                    } else {
                        match_pattern_list(criteria, &arg, false) == ListMatch::Positive
                    }
                }
                "command" => {
                    if ctx.remote_command.is_empty() {
                        arg.is_empty()
                    } else {
                        match_pattern_list(ctx.remote_command, &arg, false) == ListMatch::Positive
                    }
                }
                "sessiontype" => {
                    let criteria = match self.session_type {
                        Some(SessionType::Subsystem) => "subsystem",
                        Some(SessionType::None) => "none",
                        _ if !ctx.remote_command.is_empty() => "exec",
                        _ => "shell",
                    };
                    match_pattern_list(criteria, &arg, false) == ListMatch::Positive
                }
                "exec" => {
                    let cmd = self
                        .expand_exec_or_include(ctx, &arg, final_pass, false)
                        .map_err(|e| {
                            LineError::Fatal(format!(
                                "{filename} line {linenum}: failed to expand match exec '{arg}': {e}"
                            ))
                        })?;
                    if !result {
                        // Skip execution if a prior predicate failed.
                        continue;
                    }
                    match run_shell(&ctx.env.shell, &cmd) {
                        Ok(code) => code == 0,
                        Err(e) => {
                            return Err(LineError::Fatal(format!(
                                "{filename} line {linenum}: match exec '{cmd}' error: {e}"
                            )));
                        }
                    }
                }
                // localnetwork needs interface enumeration and version
                // compares against the OpenSSH release string; neither is
                // meaningful for ssh3 yet.
                _ => return Err(bad(format!("Unsupported Match attribute {attrib}"))),
            };
            if r == negate {
                result = false;
            }
        }
        if attributes == 0 {
            return Err(bad("One or more attributes required for Match".into()));
        }
        Ok(result)
    }

    /// The `Include` keyword.
    #[allow(clippy::too_many_arguments)]
    fn include(
        &mut self,
        ctx: &mut Ctx<'_>,
        args: &mut std::collections::VecDeque<String>,
        filename: &str,
        linenum: usize,
        active: &mut bool,
        flags: Flags,
        depth: usize,
    ) -> Result<(), LineError> {
        while let Some(arg) = args.pop_front() {
            if arg.is_empty() {
                return Err(LineError::Bad(format!(
                    "{filename} line {linenum}: keyword include empty argument"
                )));
            }
            let p = match self.expand_exec_or_include(ctx, &arg, flags.final_pass, true) {
                Ok(p) => p,
                Err(expand::ExpandError::MissingVar(_)) => {
                    self.warnings.push(format!(
                        "{filename} line {linenum}: Unable to expand user config file '{arg}'"
                    ));
                    continue;
                }
                Err(e) => return Err(LineError::Fatal(format!("{filename} line {linenum}: {e}"))),
            };
            if p.starts_with('~') && !flags.userconf {
                return Err(LineError::Bad(format!(
                    "{filename} line {linenum}: bad include path {p}."
                )));
            }
            let anchored = if !p.starts_with('/') && !p.starts_with('~') {
                if flags.userconf {
                    format!("~/.ssh/{p}")
                } else {
                    format!("/etc/ssh/{p}")
                }
            } else {
                p
            };
            // readconf.c: glob(arg2, GLOB_TILDE, NULL, &gl). POSIX glob(3)
            // does its own `~` expansion and has no recursive `**` and no
            // brace expansion, so the C library is called directly.
            let paths = match posix_glob_tilde(&anchored) {
                Ok(p) => p,
                Err(e) => {
                    return Err(LineError::Bad(format!(
                        "{filename} line {linenum}: glob failed for {anchored}: {e}"
                    )));
                }
            };
            let oactive = *active;
            for path in paths {
                let sub = Flags {
                    checkperm: true,
                    nevermatch: flags.nevermatch || !oactive,
                    ..flags
                };
                // A file that vanished between glob and open (ENOENT) is
                // skipped, as in OpenSSH.
                self.read_file_depth(ctx, &path, active, sub, depth + 1)?;
                // Match blocks inside an included file do not leak out.
                *active = oactive;
            }
        }
        Ok(())
    }

    /// Port of `read_config_file_depth()`. `Ok(false)` = file absent.
    pub fn read_file_depth(
        &mut self,
        ctx: &mut Ctx<'_>,
        filename: &str,
        active: &mut bool,
        flags: Flags,
        depth: usize,
    ) -> Result<bool, LineError> {
        if depth > MAX_INCLUDE_DEPTH {
            return Err(LineError::Fatal(
                "Too many recursive configuration includes".into(),
            ));
        }
        let data = match fs::read(filename) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(LineError::Fatal(format!(
                    "Can't open user config file {filename}: {e}"
                )));
            }
        };
        if flags.checkperm {
            let md = fs::metadata(filename)
                .map_err(|e| LineError::Fatal(format!("fstat {filename}: {e}")))?;
            if (md.uid() != 0 && md.uid() != ctx.env.uid) || (md.mode() & 0o022) != 0 {
                return Err(LineError::Fatal(format!(
                    "Bad owner or permissions on {filename}"
                )));
            }
        }
        let text = String::from_utf8_lossy(&data);
        let mut bad = Vec::new();
        for (i, line) in text.split_inclusive('\n').enumerate() {
            match self.process_line(ctx, line, filename, i + 1, Some(active), flags, depth) {
                Ok(()) => {}
                Err(LineError::Bad(m)) => bad.push(m),
                Err(f @ LineError::Fatal(_)) => return Err(f),
            }
        }
        if !bad.is_empty() {
            return Err(LineError::Fatal(format!(
                "{}\n{filename}: terminating, {} bad configuration options",
                bad.join("\n"),
                bad.len()
            )));
        }
        Ok(true)
    }
}

/// `GLOB_TILDE`, defined locally because the libc crate exports it only for
/// glibc targets. Same value in both C libraries this crate is built for:
/// glibc `/usr/include/glob.h:53` `(1 << 12)` and musl
/// `/usr/lib/musl/include/glob.h:34` `0x1000`; musl's glob() implements it.
const GLOB_TILDE: libc::c_int = 0x1000;

/// `glob(pattern, GLOB_TILDE, NULL, &gl)` from the C library, as
/// readconf.c calls it. Returns the sorted matches; no match is an empty
/// list (GLOB_NOMATCH).
fn posix_glob_tilde(pattern: &str) -> Result<Vec<String>, String> {
    let cpat = std::ffi::CString::new(pattern).map_err(|_| "pattern contains NUL".to_string())?;
    // SAFETY: glob_t is plain data that glob() initialises; we pass a valid
    // NUL-terminated pattern and no error callback, read gl_pathv only for
    // gl_pathc entries, and always release it with globfree().
    unsafe {
        let mut gl: libc::glob_t = std::mem::zeroed();
        let r = libc::glob(cpat.as_ptr(), GLOB_TILDE, None, &mut gl);
        let result = match r {
            0 => {
                let mut v = Vec::with_capacity(gl.gl_pathc);
                for i in 0..gl.gl_pathc {
                    let p = *gl.gl_pathv.add(i);
                    v.push(std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned());
                }
                Ok(v)
            }
            libc::GLOB_NOMATCH => Ok(Vec::new()),
            other => Err(format!("glob() returned {other}")),
        };
        libc::globfree(&mut gl);
        result
    }
}

/// Port of `execute_in_shell()`: `$SHELL -c cmd` with stdin and stdout on
/// /dev/null. Returns the exit status; abnormal exit is an error.
fn run_shell(shell: &str, cmd: &str) -> Result<i32, String> {
    use std::process::{Command, Stdio};
    let status = Command::new(shell)
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("Unable to execute '{cmd}' with {shell}: {e}"))?;
    status
        .code()
        .ok_or_else(|| format!("command '{cmd}' exited abnormally"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(convtime("90"), Some(90));
        assert_eq!(convtime("1h30m"), Some(5400));
        assert_eq!(convtime("1.5s"), Some(1));
        assert_eq!(convtime("1.5m"), None);
        assert_eq!(convtime("5s5s"), None);
        assert_eq!(convtime("1w"), Some(604800));
        assert_eq!(convtime("x"), None);
    }
}
