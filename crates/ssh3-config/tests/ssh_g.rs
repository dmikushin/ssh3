//! Differential tests: ssh3-config resolution vs. the real OpenSSH `ssh -G`.
//!
//! Each case writes a config file (and optional extra files) into a fresh
//! directory under `~/scratch/ssh-udp/config-test/`, runs
//! `ssh -G -F <config> <args>` and `ssh3_config::resolve_args` with the same
//! arguments, and compares, keyword by keyword, the lines both print for the
//! keywords ssh3-config resolves. When `ssh -G` fails, resolution must fail
//! too. The user's real `~/.ssh/config` is never read (`-F` is always given).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

use ssh3_config::{LocalEnv, resolve_args};

/// Every keyword ssh3 acts on must be listed here: a keyword that is acted
/// on but not compared is invisible to this suite.
const COMPARED: &[&str] = &[
    "host",
    "user",
    "hostname",
    "port",
    "exitonforwardfailure",
    "hashknownhosts",
    "identitiesonly",
    "requesttty",
    "stricthostkeychecking",
    "serveralivecountmax",
    "serveraliveinterval",
    "identityagent",
    "remotecommand",
    "tag",
    "dynamicforward",
    "localforward",
    "remoteforward",
    "identityfile",
    "userknownhostsfile",
    "sendenv",
    "setenv",
    "forwardagent",
    "connecttimeout",
    "proxyjump",
    "proxycommand",
    "hostkeyalias",
    "addressfamily",
    "batchmode",
    "clearallforwardings",
    "gatewayports",
    "sessiontype",
    "stdinnull",
    "forkafterauthentication",
    "streamlocalbindunlink",
    "streamlocalbindmask",
    "connectionattempts",
    "loglevel",
    "bindaddress",
    "bindinterface",
    "globalknownhostsfile",
    "permitremoteopen",
    "escapechar",
];

/// Cases where `ssh -G` must fail. Every other case must succeed, so a
/// typo in a test config cannot turn a positive case into a vacuous
/// "both failed" pass.
const EXPECT_FAIL: &[&str] = &[
    "tk-af-bad",
    "tk-loglevel-bad",
    "tk-esc-bad",
    "tk-attempts-zero",
    "tk-mask-bad",
    "tk-pro-mixed",
    "tk-pro-badport",
    "tk-gkh-none-mixed",
    "tk-e-bad",
    "tk-f-nocmd",
    "agent-bad-env",
    "agent-unset-env",
    "alive-bad",
    "bad-hostname",
    "bad-quotes",
    "bad-user",
    "count-bad",
    "extra-args",
    "fw-cfg-missing-target",
    "fw-D-bad",
    "fw-L-bad",
    "fw-L-zero",
    "inc-bad-file",
    "kh-none-mixed",
    "m-all-combined",
    "missing-host",
    "m-missing-arg",
    "m-unsupported",
    "no-arg",
    "o-bad",
    "o-host-rejected",
    "pj-bad",
    "pj-J-twice",
    "pj-loop",
    "port-bad",
    "port-uri-v6-invalid",
    "remotecommand-and-cmd",
    "sendenv-bad",
    "setenv-bad",
    "strict-bad",
    "tty-bad",
    "unknown-cli-opt",
];

struct Case {
    name: &'static str,
    config: &'static str,
    /// Extra files: (relative path, content). `@DIR@` in any text is replaced
    /// with the case directory.
    files: &'static [(&'static str, &'static str)],
    args: &'static [&'static str],
}

fn scratch_root() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME");
    PathBuf::from(home).join("scratch/ssh-udp/config-test/cases")
}

fn setup_env() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: set once before any case reads the environment; the
        // variables are private to this test binary and its `ssh` children.
        unsafe {
            std::env::set_var("SSH3_CFG_T_SOCK", "/run/agent.sock");
            std::env::set_var("SSH3_CFG_T_PORT", "4022");
            std::env::remove_var("SSH3_CFG_T_UNSET");
        }
    });
}

fn by_keyword(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once(' ').unwrap_or((line, ""));
        if COMPARED.contains(&k) {
            m.entry(k.to_string()).or_default().push(v.to_string());
        }
    }
    m
}

fn prepare(case: &Case) -> (PathBuf, Vec<String>) {
    let dir = scratch_root().join(case.name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_string_lossy().into_owned();
    let cfg = dir.join("config");
    let user = std::env::var("USER").unwrap_or_default();
    std::fs::write(
        &cfg,
        case.config.replace("@DIR@", &d).replace("@USER@", &user),
    )
    .unwrap();
    for (rel, content) in case.files {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content.replace("@DIR@", &d)).unwrap();
    }
    // Config files must not be group/world-writable for CHECKPERM includes.
    set_mode_tree(&dir);
    let mut args = vec!["-F".to_string(), cfg.to_string_lossy().into_owned()];
    args.extend(case.args.iter().map(|a| a.replace("@DIR@", &d)));
    (dir, args)
}

fn set_mode_tree(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        if p.is_dir() {
            set_mode_tree(&p);
        } else {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

/// Run one case; returns a description of the mismatch, if any.
fn run_case(case: &Case, env: &LocalEnv) -> Option<String> {
    let (dir, args) = prepare(case);
    let out = Command::new("ssh")
        .arg("-G")
        .args(&args)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run ssh -G");
    let ssh_ok = out.status.success();
    if ssh_ok == EXPECT_FAIL.contains(&case.name) {
        return Some(format!(
            "{}: test expectation wrong: ssh -G {} (stderr: {})",
            case.name,
            if ssh_ok { "succeeded" } else { "failed" },
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let ssh_text = String::from_utf8_lossy(&out.stdout).into_owned();
    let ssh_err = String::from_utf8_lossy(&out.stderr).into_owned();
    std::fs::write(dir.join("ssh-G.out"), &ssh_text).unwrap();
    std::fs::write(dir.join("ssh-G.err"), &ssh_err).unwrap();

    let ours = resolve_args(&args, env);
    match (&ours, ssh_ok) {
        (Ok(cfg), true) => {
            let dump = cfg.dump();
            std::fs::write(dir.join("ssh3.out"), &dump).unwrap();
            let a = by_keyword(&ssh_text);
            let b = by_keyword(&dump);
            if a != b {
                let mut diff = String::new();
                for k in COMPARED {
                    let (x, y) = (a.get(*k), b.get(*k));
                    if x != y {
                        diff.push_str(&format!("  {k}: ssh={x:?} ssh3={y:?}\n"));
                    }
                }
                return Some(format!("{}: output differs\n{diff}", case.name));
            }
            None
        }
        (Err(_), false) => None,
        (Ok(_), false) => Some(format!(
            "{}: ssh -G failed but ssh3 resolved; ssh stderr: {}",
            case.name,
            ssh_err.trim()
        )),
        (Err(e), true) => Some(format!(
            "{}: ssh3 failed but ssh -G succeeded: {e}",
            case.name
        )),
    }
}

fn check(cases: &[Case]) {
    assert!(!cases.is_empty(), "an empty case list would pass vacuously");
    setup_env();
    let env = LocalEnv::from_system(22).unwrap();
    let failures: Vec<String> = cases.iter().filter_map(|c| run_case(c, &env)).collect();
    assert!(
        failures.is_empty(),
        "{} of {} cases differ from ssh -G:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

macro_rules! case {
    ($name:expr, $config:expr, [$($arg:expr),* $(,)?]) => {
        Case { name: $name, config: $config, files: &[], args: &[$($arg),*] }
    };
    ($name:expr, $config:expr, files: $files:expr, [$($arg:expr),* $(,)?]) => {
        Case { name: $name, config: $config, files: $files, args: &[$($arg),*] }
    };
}

const BASIC_CFG: &str = "\
Host foo
  HostName bar.example
  Port 2222
  User alice
  IdentityFile ~/.ssh/id_x.pub
  LocalForward 8080 localhost:80
  RemoteForward [::1]:9000 /tmp/sock
  DynamicForward 1080
";

#[test]
fn basics() {
    check(&[
        case!("empty", "", ["somehost"]),
        case!("basic", BASIC_CFG, ["foo"]),
        case!("basic-other-host", BASIC_CFG, ["other"]),
        case!("first-wins", "Port 1\nPort 2\nUser a\nUser b\n", ["h"]),
        case!(
            "equals-forms",
            "Port=2200\nUser = bob\nHostName =x.example\n",
            ["h"]
        ),
        case!("quoted-keyword", "\"User\" quoted\n", ["h"]),
        case!(
            "leading-ws-comments",
            "   # comment\n\tPort 33 # trailing\n\n",
            ["h"]
        ),
        case!("case-insensitive-kw", "PORT 44\nuSeR Upper\n", ["h"]),
        case!("hostname-token", "Host *\n  HostName %h.lan\n", ["Box"]),
        case!("hostname-lower", "", ["MiXeD.Example"]),
        case!("hostname-addr-v4", "", ["10.0.0.1"]),
        case!("hostname-addr-v6", "", ["FE80::1"]),
        case!("hostname-bracket", "", ["[::1]"]),
        case!("user-at", "", ["bob@h"]),
        case!("user-l", "", ["-l", "carol", "h"]),
        case!("user-l-and-at", "", ["-l", "carol", "bob@h"]),
        case!("user-cfg-token", "User u-%h-%p\n", ["h"]),
        case!("user-cfg-token-l-wins", "User u-%h\n", ["-l", "x", "h"]),
        case!("port-p", "Port 99\n", ["-p", "2022", "h"]),
        case!("port-service", "Port ssh\n", ["h"]),
        case!("port-bad", "Port 0\n", ["h"]),
        case!("port-uri", "", ["ssh://u@Host.Example:2222"]),
        case!("port-uri-v6-invalid", "", ["ssh://u@[fe80::1]:2222"]),
        case!(
            "uri-no-user-cfg-token",
            "User u-%h\n",
            ["ssh://Host.Example"]
        ),
        case!(
            "uri-user-cfg-port",
            "Port 77\nUser cfg\n",
            ["ssh://uri@h:2200"]
        ),
        case!("opts-after-host", "", ["h", "-p", "2023", "-l", "late"]),
        case!("double-dash", "", ["-p", "2024", "--", "h", "-p", "7"]),
        case!("command-words", "", ["h", "echo", "a", "b"]),
        case!("unknown-cli-opt", "", ["-H", "h"]),
        case!("missing-host", "", []),
        case!("bad-hostname", "", ["a;b"]),
        case!("bad-user", "", ["-l", "-x", "h"]),
    ]);
}

#[test]
fn host_patterns() {
    let cfg = "\
Host *.example !bad.example
  User ex
Host a? b*
  Port 1001
Host Foo*
  Port 1002
Host *
  Port 1999
  User star
";
    check(&[
        case!("hp-good", cfg, ["good.example"]),
        case!("hp-bad", cfg, ["bad.example"]),
        case!("hp-q", cfg, ["ax"]),
        case!("hp-q-long", cfg, ["axx"]),
        case!("hp-b", cfg, ["bzz"]),
        case!("hp-case", cfg, ["FooBar"]),
        case!("hp-case-lower", cfg, ["foobar"]),
        case!("hp-star", cfg, ["zzz"]),
        case!("hp-commas-literal", "Host a,b\n  Port 7\n", ["a"]),
        case!("hp-neg-only", "Host !x\n  Port 8\n", ["y"]),
        case!(
            "hp-uses-arg-not-hostname",
            "Host real\n  Port 9\nHost alias\n  HostName real\n",
            ["alias"]
        ),
    ]);
}

#[test]
fn match_blocks() {
    check(&[
        case!(
            "m-host",
            "Match host bar.example\n  Port 3001\nHost foo\n  HostName bar.example\n",
            ["foo"]
        ),
        case!(
            "m-host-after",
            "Host foo\n  HostName bar.example\nMatch host bar.example\n  Port 3002\n",
            ["foo"]
        ),
        case!(
            "m-originalhost",
            "Host foo\n  HostName bar.example\nMatch originalhost foo\n  Port 3003\n",
            ["foo"]
        ),
        case!("m-user", "Match user bob\n  Port 3004\n", ["bob@h"]),
        case!("m-user-neg", "Match !user bob\n  Port 3005\n", ["bob@h"]),
        case!("m-localuser", "Match localuser *\n  Port 3006\n", ["h"]),
        case!("m-all", "Match all\n  Port 3007\n", ["h"]),
        case!("m-all-combined", "Match all host x\n  Port 3008\n", ["h"]),
        case!("m-exec-true", "Match exec true\n  Port 3009\n", ["h"]),
        case!("m-exec-false", "Match exec false\n  Port 3010\n", ["h"]),
        case!(
            "m-exec-token",
            "Match exec \"test %h = h && test %p = 22 && test %n = h\"\n  Port 3011\n",
            ["h"]
        ),
        case!(
            "m-exec-skip",
            "Match host nomatch exec \"exit 1\"\n  Port 3012\nPort 3013\n",
            ["h"]
        ),
        case!("m-host-eq", "Match host=h\n  Port 3014\n", ["h"]),
        case!("m-final", "Match final\n  Port 3015\nPort 3016\n", ["h"]),
        case!(
            "m-final-hostname",
            "HostName real.example\nMatch final host real.example\n  User fin\n",
            ["h"]
        ),
        case!("m-canonical", "Match canonical\n  Port 3017\n", ["h"]),
        case!(
            "m-canonical-final",
            "Match final\n  User f\nMatch canonical\n  Port 3018\n",
            ["h"]
        ),
        case!(
            "m-tagged",
            "Match tagged t1\n  Port 3019\n",
            ["-P", "t1", "h"]
        ),
        case!("m-tagged-empty", "Match tagged \"\"\n  Port 3020\n", ["h"]),
        case!(
            "m-command",
            "Match command \"echo*\"\n  Port 3021\n",
            ["h", "echo", "hi"]
        ),
        case!(
            "m-sessiontype",
            "Match sessiontype none\n  Port 3022\n",
            ["-N", "h"]
        ),
        case!(
            "m-sessiontype-exec",
            "Match sessiontype exec\n  Port 3023\n",
            ["h", "ls"]
        ),
        case!("m-missing-arg", "Match host\n  Port 3024\n", ["h"]),
        case!("m-unsupported", "Match bogus x\n  Port 3025\n", ["h"]),
        case!("m-comment", "Match host h # comment\n  Port 3026\n", ["h"]),
        case!("m-case", "Match HOST H\n  Port 3027\n", ["h"]),
        case!(
            "m-user-from-cfg",
            "User zed\nMatch user zed\n  Port 3028\n",
            ["h"]
        ),
    ]);
}

#[test]
fn forwards() {
    check(&[
        case!("fw-L", "", ["-L", "8080:localhost:80", "h"]),
        case!("fw-L-bind", "", ["-L", "127.0.0.1:8080:localhost:80", "h"]),
        case!("fw-L-v6", "", ["-L", "[::1]:8080:[fe80::1]:80", "h"]),
        case!("fw-L-path", "", ["-L", "/tmp/l.sock:remote:80", "h"]),
        case!("fw-L-to-path", "", ["-L", "8080:/run/x.sock", "h"]),
        case!("fw-L-path-path", "", ["-L", "/a/l:/b/c", "h"]),
        case!("fw-L-bad", "", ["-L", "8080", "h"]),
        case!("fw-L-zero", "", ["-L", "0:h:80", "h"]),
        case!("fw-L-dup", "", ["-L", "1:h:2", "-L", "1:h:2", "h"]),
        case!("fw-L-escape", "", ["-L", "8080:host\\:x:80", "h"]),
        case!("fw-L-env", "", ["-L", "${SSH3_CFG_T_PORT}:h:80", "h"]),
        case!("fw-R", "", ["-R", "9000:localhost:22", "h"]),
        case!("fw-R-zero", "", ["-R", "0:localhost:22", "h"]),
        case!("fw-R-dynamic", "", ["-R", "9001", "h"]),
        case!("fw-R-dynamic-bind", "", ["-R", "127.0.0.1:9002", "h"]),
        case!("fw-D", "", ["-D", "1080", "h"]),
        case!("fw-D-bind", "", ["-D", "[::1]:1081", "h"]),
        case!("fw-D-bad", "", ["-D", "a:b:c", "h"]),
        case!(
            "fw-cfg",
            "LocalForward 8081 [::1]:81\nRemoteForward 9003\nRemoteForward 9004 h:4\nDynamicForward 127.0.0.1:1082\n",
            ["h"]
        ),
        case!("fw-cfg-missing-target", "LocalForward 8082\n", ["h"]),
        case!(
            "fw-cfg-and-cli",
            "LocalForward 1 a:1\n",
            ["-L", "2:b:2", "h"]
        ),
        case!(
            "fw-clear",
            "ClearAllForwardings yes\nLocalForward 1 a:1\n",
            ["-L", "2:b:2", "-R", "3:c:3", "h"]
        ),
        case!("fw-W", "LocalForward 1 a:1\n", ["-W", "dst:22", "h"]),
        case!(
            "fw-W-clear-no",
            "ClearAllForwardings no\nLocalForward 1 a:1\nExitOnForwardFailure no\n",
            ["-W", "dst:22", "h"]
        ),
        case!(
            "fw-path-token",
            "LocalForward /tmp/%h.sock remote:80\n",
            ["h"]
        ),
        case!(
            "fw-remote-path-token",
            "RemoteForward /tmp/r-%r.sock /tmp/l-%u.sock\n",
            ["h"]
        ),
    ]);
}

#[test]
fn identities_and_agent() {
    check(&[
        case!("id-default", "", ["h"]),
        case!(
            "id-cfg",
            "IdentityFile ~/.ssh/a\nIdentityFile %d/b-%h\nIdentityFile ~/.ssh/a\n",
            ["h"]
        ),
        case!("id-pub", "IdentityFile ~/.ssh/id_ed25519.pub\n", ["h"]),
        case!("id-i", "", files: &[("k1", "x")], ["-i", "@DIR@/k1", "h"]),
        case!("id-i-missing", "", ["-i", "@DIR@/nope", "h"]),
        case!("id-i-and-cfg-same", "IdentityFile @DIR@/k1\n", files: &[("k1", "x")], ["-i", "@DIR@/k1", "-o", "IdentityFile @DIR@/k1", "h"]),
        case!("id-only", "IdentitiesOnly yes\n", ["h"]),
        case!("id-none", "IdentityFile none\n", ["h"]),
        case!("agent-path", "IdentityAgent ~/agent.sock\n", ["h"]),
        case!("agent-env", "IdentityAgent ${SSH3_CFG_T_SOCK}\n", ["h"]),
        case!("agent-legacy-env", "IdentityAgent $SSH_AUTH_SOCK\n", ["h"]),
        case!("agent-bad-env", "IdentityAgent $BAD-NAME\n", ["h"]),
        case!(
            "agent-unset-env",
            "IdentityAgent ${SSH3_CFG_T_UNSET}\n",
            ["h"]
        ),
        case!("agent-token", "IdentityAgent /run/%u/%h.sock\n", ["h"]),
        case!("agent-none", "IdentityAgent none\n", ["h"]),
        case!("fwdagent-yes", "ForwardAgent yes\n", ["h"]),
        case!("fwdagent-A", "ForwardAgent no\n", ["-A", "h"]),
        case!("fwdagent-a", "ForwardAgent yes\n", ["-a", "h"]),
        case!("fwdagent-path", "ForwardAgent /tmp/fwd-%u.sock\n", ["h"]),
        case!("fwdagent-bad", "ForwardAgent maybe\n", ["h"]),
    ]);
}

#[test]
fn misc_keywords() {
    check(&[
        case!("strict-yes", "StrictHostKeyChecking yes\n", ["h"]),
        case!("strict-no", "StrictHostKeyChecking no\n", ["h"]),
        case!("strict-off", "StrictHostKeyChecking off\n", ["h"]),
        case!("strict-new", "StrictHostKeyChecking accept-new\n", ["h"]),
        case!("strict-bad", "StrictHostKeyChecking sometimes\n", ["h"]),
        case!(
            "strict-o",
            "StrictHostKeyChecking yes\n",
            ["-o", "StrictHostKeyChecking=no", "h"]
        ),
        case!("kh-files", "UserKnownHostsFile ~/kh1 %d/kh2 /x/%h\n", ["h"]),
        case!("kh-none", "UserKnownHostsFile none\n", ["h"]),
        case!("kh-none-mixed", "UserKnownHostsFile none /x\n", ["h"]),
        case!(
            "kh-first-line",
            "UserKnownHostsFile /a\nUserKnownHostsFile /b\n",
            ["h"]
        ),
        case!("hashkh", "HashKnownHosts yes\n", ["h"]),
        case!(
            "alive",
            "ServerAliveInterval 1m30s\nServerAliveCountMax 7\n",
            ["h"]
        ),
        case!(
            "alive-none",
            "ServerAliveInterval none\nServerAliveInterval 15\n",
            ["h"]
        ),
        case!("alive-bad", "ServerAliveInterval soon\n", ["h"]),
        case!("count-bad", "ServerAliveCountMax -1\n", ["h"]),
        case!("timeout", "ConnectTimeout 5\n", ["h"]),
        case!(
            "timeout-none",
            "ConnectTimeout none\nConnectTimeout 9\n",
            ["h"]
        ),
        case!("tty-force", "RequestTTY force\n", ["h"]),
        case!("tty-t", "", ["-t", "h"]),
        case!("tty-tt", "", ["-tt", "h"]),
        case!("tty-T", "RequestTTY yes\n", ["-T", "h"]),
        case!("tty-N", "", ["-N", "h"]),
        case!("tty-bad", "RequestTTY sometimes\n", ["h"]),
        case!(
            "sendenv",
            "SendEnv LANG LC_*\nSendEnv FOO\nSendEnv -LC_*\n",
            ["h"]
        ),
        case!("sendenv-bad", "SendEnv A=B\n", ["h"]),
        case!(
            "setenv",
            "SetEnv FOO=bar \"BAZ=q x\" FOO=dup\nSetEnv LATER=no\n",
            ["h"]
        ),
        case!("setenv-token", "SetEnv WHO=%u@%h\n", ["h"]),
        case!("setenv-bad", "SetEnv NOEQ\n", ["h"]),
        case!("exitfwd", "ExitOnForwardFailure yes\n", ["h"]),
        case!("remotecommand", "RemoteCommand echo %h %%\n", ["h"]),
        case!(
            "remotecommand-and-cmd",
            "RemoteCommand echo x\n",
            ["h", "ls"]
        ),
        case!("remotecommand-none", "RemoteCommand none\n", ["h"]),
        case!("tag", "Tag t2\n", ["h"]),
        case!("extra-args", "Port 22 23\n", ["h"]),
        case!("no-arg", "Port\n", ["h"]),
        case!("bad-quotes", "User \"open\n", ["h"]),
        case!("deprecated", "UseRoaming no\nPort 55\n", ["h"]),
        case!(
            "other-keywords",
            "Compression yes\nCiphers aes128-ctr\nLogLevel DEBUG\nPort 56\n",
            ["h"]
        ),
        case!(
            "ignore-unknown",
            "IgnoreUnknown Foo*\nFooBar 1\nPort 57\n",
            ["h"]
        ),
        case!("identityfile2", "IdentityFile2 ~/.ssh/legacy\n", ["h"]),
        case!("o-host-rejected", "", ["-o", "Host x", "h"]),
        case!("o-bad", "", ["-o", "Port nope", "h"]),
        case!("o-first", "Port 1\n", ["-o", "Port=2", "h"]),
    ]);
}

#[test]
fn proxy_jump() {
    check(&[
        case!("pj-cfg", "ProxyJump gw1,bob@gw2:2200\n", ["h"]),
        case!("pj-J", "", ["-J", "u@gw:2200", "h"]),
        case!("pj-J-multi", "", ["-J", "a,b@c,ssh://d@e:3", "h"]),
        case!("pj-J-numeric", "", ["-J", "10.1.1.1:22", "h"]),
        case!("pj-J-v6", "", ["-J", "[fe80::1]:22", "h"]),
        case!("pj-none", "ProxyJump none\nProxyJump gw\n", ["h"]),
        case!("pj-J-twice", "", ["-J", "a", "-J", "b", "h"]),
        case!("pj-J-over-cfg", "ProxyJump cfg\n", ["-J", "cli", "h"]),
        case!(
            "pj-after-proxycommand",
            "ProxyCommand nc %h %p\nProxyJump gw\n",
            ["h"]
        ),
        case!("pj-loop", "ProxyJump h\n", ["h"]),
        case!("pj-bad", "ProxyJump a,,b\n", ["h"]),
        case!("pj-comment", "ProxyJump gw # comment\n", ["h"]),
        case!(
            "pj-token-hostname",
            "ProxyJump gw\nHostName %h.inner\n",
            ["h"]
        ),
    ]);
}

#[test]
fn includes() {
    check(&[
        case!("inc-abs", "Include @DIR@/inc1\nPort 4001\n", files: &[("inc1", "User incuser\n")], ["h"]),
        case!("inc-glob", "Include @DIR@/conf.d/*.conf\n", files: &[("conf.d/b.conf", "User b\n"), ("conf.d/a.conf", "User a\n")], ["h"]),
        case!("inc-missing", "Include @DIR@/nope\nPort 4002\n", ["h"]),
        case!("inc-in-host", "Host other\n  Include @DIR@/inc2\nHost *\n  Port 4003\n", files: &[("inc2", "User shouldnot\n")], ["h"]),
        case!("inc-match-scope", "Include @DIR@/inc3\nUser outer\n", files: &[("inc3", "Match host nomatch\n  Port 4004\n")], ["h"]),
        case!("inc-host-inside", "Include @DIR@/inc4\n", files: &[("inc4", "Host h\n  Port 4005\nHost *\n  User x\n")], ["h"]),
        case!("inc-nested", "Include @DIR@/n1\n", files: &[("n1", "Include @DIR@/n2\n"), ("n2", "Port 4006\n")], ["h"]),
        case!("inc-token", "Include @DIR@/inc-%h\n", files: &[("inc-h", "Port 4007\n")], ["h"]),
        case!("inc-env", "Include @DIR@/${SSH3_CFG_T_PORT}.conf\n", files: &[("4022.conf", "Port 4008\n")], ["h"]),
        // `~` in Include paths: glob(3) GLOB_TILDE, and the ~/.ssh anchor
        // for relative paths. The fixtures live under the real home
        // directory (tests/ssh_g.rs writes them into ~/scratch/...).
        case!("inc-tilde", "Include ~/scratch/ssh-udp/config-test/cases/inc-tilde/t.conf\n", files: &[("t.conf", "Port 4012\n")], ["h"]),
        case!("inc-tilde-glob", "Include ~/scratch/ssh-udp/config-test/cases/inc-tilde-glob/*.conf\n", files: &[("x.conf", "Port 4013\n")], ["h"]),
        case!("inc-tilde-user", "Include ~@USER@/scratch/ssh-udp/config-test/cases/inc-tilde-user/u.conf\n", files: &[("u.conf", "Port 4014\n")], ["h"]),
        case!(
            "inc-tilde-missing",
            "Include ~/scratch/ssh-udp/config-test/cases/inc-tilde-missing/none.conf\nPort 4015\n",
            ["h"]
        ),
        case!(
            "inc-relative-ssh-dir",
            "Include ssh3-config-test-nonexistent-*.conf\nPort 4016\n",
            ["h"]
        ),
        case!("inc-double-star", "Include @DIR@/conf/**/extra.conf\n", files: &[("conf/a/b/extra.conf", "Port 4009\n"), ("conf/a/extra.conf", "User onelevel\n")], ["h"]),
        case!("inc-brace", "Include @DIR@/{a,b}.conf\n", files: &[("a.conf", "Port 4010\n"), ("{a,b}.conf", "User literal\n")], ["h"]),
        case!("inc-bracket-class", "Include @DIR@/c[12].conf\n", files: &[("c2.conf", "Port 4011\n")], ["h"]),
        case!("inc-bad-file", "Include @DIR@/badinc\n", files: &[("badinc", "Port nope\n")], ["h"]),
    ]);
}

/// Generated corpus: pairs of Host/Match blocks over a set of destination
/// names, to exercise first-match-wins and pattern semantics broadly.
#[test]
fn generated_blocks() {
    let patterns = ["*", "a*", "!b*", "?x", "*.lan", "A*"];
    let hosts = ["ax", "bx", "AX", "q.lan", "zz"];
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    let mut cases = Vec::new();
    for (i, p1) in patterns.iter().enumerate() {
        for (j, p2) in patterns.iter().enumerate() {
            let block2 = if j % 2 == 0 {
                format!(
                    "Match host \"{}\"\n  User m{j}\n  HostName %h.m{j}\n",
                    p2.replace('!', "")
                )
            } else {
                format!("Host {p2} other\n  User h{j}\n  Port {}\n", 2000 + j)
            };
            let config = leak(format!(
                "Host {p1} never\n  Port {}\n  IdentityFile ~/.ssh/k{i}\n  LocalForward {} t{i}:1\n{block2}Host *\n  User fallback\n  IdentityFile ~/.ssh/k{j}\n",
                1000 + i,
                7000 + i
            ));
            for (k, h) in hosts.iter().enumerate() {
                cases.push(Case {
                    name: leak(format!("gen-{i}-{j}-{k}")),
                    config,
                    files: &[],
                    args: Box::leak(vec![*h].into_boxed_slice()),
                });
            }
        }
    }
    check(&cases);
}

/// Keywords ssh3 acts on, beyond the first set: typed fields, first value
/// wins, command-line flags and `-o` take precedence.
#[test]
fn typed_keywords() {
    check(&[
        case!("tk-gw", "GatewayPorts yes\n", ["h"]),
        case!("tk-gw-g", "GatewayPorts no\n", ["-g", "h"]),
        case!(
            "tk-gw-o",
            "GatewayPorts yes\n",
            ["-o", "GatewayPorts=no", "h"]
        ),
        case!("tk-gw-first", "GatewayPorts no\nGatewayPorts yes\n", ["h"]),
        case!("tk-gw-host", "Host other\n  GatewayPorts yes\n", ["h"]),
        case!("tk-af", "AddressFamily inet6\n", ["h"]),
        case!("tk-af-4", "AddressFamily inet6\n", ["-4", "h"]),
        case!("tk-af-6", "", ["-6", "h"]),
        case!("tk-af-bad", "AddressFamily ipx\n", ["h"]),
        case!(
            "tk-bind",
            "BindAddress 192.0.2.1\nBindInterface eth9\n",
            ["h"]
        ),
        case!(
            "tk-bind-cli",
            "BindAddress 192.0.2.1\n",
            ["-b", "10.0.0.1", "-B", "wg0", "h"]
        ),
        case!("tk-unlink", "StreamLocalBindUnlink yes\n", ["h"]),
        case!("tk-mask", "StreamLocalBindMask 0077\n", ["h"]),
        case!(
            "tk-mask-last-wins",
            "StreamLocalBindMask 0077\nStreamLocalBindMask 0007\n",
            ["h"]
        ),
        case!(
            "tk-mask-inactive",
            "Host other\n  StreamLocalBindMask 0111\n",
            ["h"]
        ),
        case!("tk-mask-trailing", "StreamLocalBindMask 07x\n", ["h"]),
        case!("tk-mask-bad", "StreamLocalBindMask 01000\n", ["h"]),
        case!("tk-pro", "PermitRemoteOpen host:22 [::1]:80 *.x:*\n", ["h"]),
        case!(
            "tk-pro-any",
            "PermitRemoteOpen any\nPermitRemoteOpen a:1\n",
            ["h"]
        ),
        case!("tk-pro-mixed", "PermitRemoteOpen any a:1\n", ["h"]),
        case!("tk-pro-badport", "PermitRemoteOpen a:0\n", ["h"]),
        case!("tk-attempts", "ConnectionAttempts 3\n", ["h"]),
        case!("tk-attempts-zero", "ConnectionAttempts 0\n", ["h"]),
        case!("tk-batch", "BatchMode yes\n", ["h"]),
        case!("tk-loglevel", "LogLevel debug\n", ["h"]),
        case!("tk-loglevel-verbose", "LogLevel VERBOSE\n", ["h"]),
        case!("tk-loglevel-bad", "LogLevel loud\n", ["h"]),
        case!("tk-v", "LogLevel ERROR\n", ["-v", "h"]),
        case!("tk-vvv", "", ["-vvvv", "h"]),
        case!("tk-q", "LogLevel DEBUG3\n", ["-q", "h"]),
        case!("tk-qv", "", ["-q", "-v", "-v", "h"]),
        case!("tk-vq", "", ["-v", "-q", "h"]),
        case!("tk-esc", "EscapeChar %\n", ["h"]),
        case!("tk-esc-ctrl", "EscapeChar ^]\n", ["h"]),
        case!("tk-esc-none", "EscapeChar none\n", ["h"]),
        case!("tk-esc-space", "EscapeChar \" \"\n", ["h"]),
        case!("tk-esc-backslash", "EscapeChar \\\\\n", ["h"]),
        case!("tk-esc-bad", "EscapeChar ab\n", ["h"]),
        case!("tk-e", "EscapeChar %\n", ["-e", "^A", "h"]),
        case!("tk-e-none", "", ["-e", "none", "h"]),
        case!("tk-e-bad", "", ["-e", "xy", "h"]),
        case!("tk-gkh", "GlobalKnownHostsFile ~/gk1 /etc/gk2\n", ["h"]),
        case!("tk-gkh-none", "GlobalKnownHostsFile none\n", ["h"]),
        case!("tk-gkh-none-mixed", "GlobalKnownHostsFile none /x\n", ["h"]),
        case!("tk-stdinnull", "StdinNull yes\n", ["h"]),
        case!("tk-n", "", ["-n", "h"]),
        case!("tk-f", "", ["-f", "h", "true"]),
        case!("tk-f-nocmd", "", ["-f", "h"]),
        case!("tk-f-N", "", ["-f", "-N", "h"]),
        case!(
            "tk-fork-kw",
            "ForkAfterAuthentication yes\nSessionType none\n",
            ["h"]
        ),
        case!("tk-sessiontype", "SessionType subsystem\n", ["h", "sftp"]),
        case!("tk-s", "", ["-s", "h", "sftp"]),
        case!("tk-hka", "HostKeyAlias MyAlias\n", ["h"]),
        case!("tk-proxycommand", "ProxyCommand nc %h %p\n", ["h"]),
        case!("tk-proxycommand-none", "ProxyCommand none\n", ["h"]),
        case!("tk-clear", "ClearAllForwardings yes\n", ["h"]),
    ]);
}
