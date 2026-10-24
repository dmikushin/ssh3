//! Behavioural tests of the session process layer, run as the current user.
//! The root (privilege-drop) path runs inside an unprivileged user namespace
//! (`unshare --map-root-user --map-auto`), see `root_path_*`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use ssh3_session::{
    ConnectionInfo, Error, Exit, Kind, PtyRequest, SessionConfig, SessionProcess, SessionRequest, UserRecord,
    WindowSize, spawn,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

fn me() -> UserRecord {
    let name = std::env::var("USER").expect("USER set");
    let mut u = UserRecord::lookup(&name).expect("lookup current user");
    // Deterministic shell for the tests; the real login shell is exercised
    // by `real_login_shell_runs_exec`.
    u.shell = PathBuf::from("/bin/sh");
    u
}

fn req(kind: Kind) -> SessionRequest {
    SessionRequest {
        user: me(),
        kind,
        pty: None,
        env: Vec::new(),
        forced_command: None,
        connection: Some(ConnectionInfo {
            remote_ip: "192.0.2.1".into(),
            remote_port: 40000,
            local_ip: "192.0.2.2".into(),
            local_port: 443,
        }),
        auth_sock: None,
    }
}

fn exec(cmd: &str) -> SessionRequest {
    req(Kind::Exec(cmd.into()))
}

fn pty(cols: u32, rows: u32, modes: Vec<u8>) -> Option<PtyRequest> {
    Some(PtyRequest { term: "xterm-256color".into(), size: WindowSize { cols, rows, xpixel: 0, ypixel: 0 }, modes })
}

/// Hard limit for every wait in this file: a test that would block fails
/// with a message instead.
const LIMIT: Duration = Duration::from_secs(10);

async fn bounded<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(LIMIT, f).await {
        Ok(v) => v,
        Err(_) => panic!("{what}: no result within {LIMIT:?}"),
    }
}

async fn read_all(r: &mut (dyn AsyncRead + Send + Unpin)) -> String {
    let mut out = Vec::new();
    bounded("read to EOF", r.read_to_end(&mut out)).await.expect("read");
    String::from_utf8_lossy(&out).into_owned()
}

/// Read until `needle` has appeared; returns everything read so far.
async fn read_until(r: &mut (dyn AsyncRead + Send + Unpin), acc: &mut String, needle: &str) {
    let mut buf = [0u8; 4096];
    while !acc.contains(needle) {
        let n = bounded(&format!("read until {needle:?} (have {acc:?})"), r.read(&mut buf)).await.expect("read");
        assert!(n > 0, "EOF before {needle:?}; got {acc:?}");
        acc.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
}

async fn wait_exit(p: &mut SessionProcess) -> Exit {
    let pid = p.pid();
    bounded(&format!("exit of session leader {pid}"), p.wait()).await.expect("wait")
}

/// Poll (2 ms) until /proc/<pid> is gone, i.e. the process was reaped;
/// fails after LIMIT naming the pid. There is no event for "reaped by
/// someone else".
fn reaped_within(pid: u32) {
    let deadline = std::time::Instant::now() + LIMIT;
    while std::path::Path::new(&format!("/proc/{pid}")).exists() {
        assert!(std::time::Instant::now() < deadline, "process {pid} not reaped within {LIMIT:?}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Poll (2 ms) until `pid` is `nohup`'s target, i.e. has exec'd past nohup
/// (comm no longer "nohup"/"sh") with SIGHUP ignored — nohup sets SIG_IGN
/// before exec and exec preserves it. Fails after LIMIT naming the state.
fn nohup_in_place_within(pid: i32) {
    let deadline = std::time::Instant::now() + LIMIT;
    loop {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let field = |k: &str| s.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_string()).unwrap_or_default();
        let comm = field("Name:");
        let hup_ignored = u64::from_str_radix(&field("SigIgn:"), 16).is_ok_and(|m| m & 1 == 1);
        if hup_ignored && comm != "nohup" && comm != "sh" {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "nohup child {pid} not in place within {LIMIT:?}: comm={comm:?} SIGHUP ignored={hup_ignored}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

async fn run(cfg: &SessionConfig, r: &SessionRequest) -> (String, String, Exit) {
    let mut p = spawn(cfg, r).expect("spawn");
    drop(p.take_stdin());
    let mut out = p.take_stdout().unwrap();
    let mut err = p.take_stderr().unwrap();
    let (o, e) = tokio::join!(read_all(&mut *out), read_all(&mut *err));
    let exit = wait_exit(&mut p).await;
    (o, e, exit)
}

#[tokio::test]
async fn exec_echo_exit_zero() {
    let (o, e, x) = run(&SessionConfig::default(), &exec("echo hello")).await;
    assert_eq!((o.as_str(), e.as_str(), x), ("hello\n", "", Exit::Status(0)));
}

#[tokio::test]
async fn exit_code_propagates() {
    let (_, _, x) = run(&SessionConfig::default(), &exec("exit 7")).await;
    assert_eq!(x, Exit::Status(7));
}

#[tokio::test]
async fn stderr_is_separate_without_pty() {
    let (o, e, x) = run(&SessionConfig::default(), &exec("echo out; echo err >&2")).await;
    assert_eq!((o.as_str(), e.as_str(), x), ("out\n", "err\n", Exit::Status(0)));
}

#[tokio::test]
async fn exit_signal_reports_name() {
    // Only signals whose default action does not dump core: a core-dumping
    // signal (SEGV, QUIT, ABRT) hands the process to the host's core_pattern
    // pipe handler (systemd-coredump here), which wrote a real dump of `sh` to
    // /var/lib/systemd/coredump on every run (81 found) and, under load, kept
    // the pipe open past this file's 10 s limit — a failure seen at 050b115.
    let (_, _, x) = run(&SessionConfig::default(), &exec("kill -HUP $$")).await;
    assert_eq!(x, Exit::Signal { name: "HUP", core_dumped: false });
    let (_, _, x) = run(&SessionConfig::default(), &exec("kill -USR1 $$")).await;
    assert_eq!(x, Exit::Signal { name: "USR1", core_dumped: false });
}

#[tokio::test]
async fn real_login_shell_runs_exec() {
    let mut r = exec("echo via-login-shell");
    r.user = UserRecord::lookup(&std::env::var("USER").unwrap()).unwrap();
    let (o, _, x) = run(&SessionConfig::default(), &r).await;
    assert_eq!((o.as_str(), x), ("via-login-shell\n", Exit::Status(0)));
}

#[tokio::test]
async fn shell_is_a_login_shell() {
    let mut p = spawn(&SessionConfig::default(), &req(Kind::Shell)).expect("spawn");
    let mut stdin = p.take_stdin().unwrap();
    stdin.write_all(b"echo \"argv0=$0\"; exit 3\n").await.unwrap();
    drop(stdin);
    let o = read_all(&mut *p.take_stdout().unwrap()).await;
    assert_eq!(o, "argv0=-sh\n");
    assert_eq!(wait_exit(&mut p).await, Exit::Status(3));
}

#[tokio::test]
async fn stdin_eof_reaches_cat_without_pty() {
    let mut p = spawn(&SessionConfig::default(), &exec("cat")).expect("spawn");
    let mut stdin = p.take_stdin().unwrap();
    stdin.write_all(b"abc").await.unwrap();
    stdin.shutdown().await.unwrap();
    drop(stdin);
    assert_eq!(read_all(&mut *p.take_stdout().unwrap()).await, "abc");
    assert_eq!(wait_exit(&mut p).await, Exit::Status(0));
}

#[tokio::test]
async fn environment_follows_openssh_order_and_allowlist() {
    let cfg = SessionConfig {
        accept_env: vec!["LC_*".into(), "LANG".into()],
        set_env: vec![("ADMIN_VAR".into(), "set".into())],
        ..Default::default()
    };
    let mut r = exec("env");
    r.env = vec![
        ("LC_FOO".into(), "1".into()),
        ("EVIL".into(), "2".into()),
        ("USER".into(), "spoofed".into()),
        ("LANG".into(), "C".into()),
    ];
    r.auth_sock = Some("/run/agent.sock".into());
    let (o, _, x) = run(&cfg, &r).await;
    assert_eq!(x, Exit::Status(0));
    let env: HashMap<_, _> = o.lines().filter_map(|l| l.split_once('=')).collect();
    let u = me();
    assert_eq!(env.get("LC_FOO"), Some(&"1"));
    assert_eq!(env.get("LANG"), Some(&"C"));
    assert_eq!(env.get("EVIL"), None, "not in AcceptEnv");
    assert_eq!(env.get("USER"), Some(&u.name.as_str()), "login variables override client env");
    assert_eq!(env.get("LOGNAME"), Some(&u.name.as_str()));
    assert_eq!(env.get("HOME").map(PathBuf::from), Some(u.home.clone()));
    assert_eq!(env.get("SHELL"), Some(&"/bin/sh"));
    assert_eq!(env.get("PATH"), Some(&"/usr/bin:/bin:/usr/sbin:/sbin"));
    assert_eq!(env.get("MAIL").copied(), Some(format!("/var/mail/{}", u.name).as_str()));
    assert_eq!(env.get("SSH_CONNECTION"), Some(&"192.0.2.1 40000 192.0.2.2 443"));
    assert_eq!(env.get("SSH_CLIENT"), Some(&"192.0.2.1 40000 443"));
    assert_eq!(env.get("SSH_AUTH_SOCK"), Some(&"/run/agent.sock"));
    assert_eq!(env.get("ADMIN_VAR"), Some(&"set"));
    assert_eq!(env.get("SSH_TTY"), None);
    assert_eq!(env.get("TERM"), None);
}

#[tokio::test]
async fn client_env_count_is_capped() {
    let cfg = SessionConfig { accept_env: vec!["V*".into()], max_client_env: 2, ..Default::default() };
    let mut r = exec("env");
    r.env = (0..5).map(|i| (format!("V{i}"), "x".into())).collect();
    let (o, _, _) = run(&cfg, &r).await;
    let vs: Vec<_> = o.lines().filter(|l| l.starts_with('V')).collect();
    assert_eq!(vs.len(), 2, "{vs:?}");
}

#[tokio::test]
async fn working_directory_is_home_and_missing_home_is_reported() {
    let dir = std::env::temp_dir().canonicalize().unwrap();
    let mut r = exec("pwd");
    r.user.home = dir.clone();
    let (o, _, _) = run(&SessionConfig::default(), &r).await;
    assert_eq!(o.trim_end(), dir.to_str().unwrap());

    let mut r = exec("echo still-runs");
    r.user.home = PathBuf::from("/nonexistent/ssh3-session-test");
    let (o, e, x) = run(&SessionConfig::default(), &r).await;
    assert_eq!((o.as_str(), x), ("still-runs\n", Exit::Status(0)));
    assert_eq!(e, "Could not chdir to home directory /nonexistent/ssh3-session-test\n");
}

#[tokio::test]
async fn subsystem_runs_configured_command_and_refuses_signals() {
    let mut cfg = SessionConfig::default();
    cfg.subsystems.insert("demo".into(), "echo subsystem-ran; cat >/dev/null".into());
    let mut p = spawn(&cfg, &req(Kind::Subsystem("demo".into()))).expect("spawn");
    let mut out = p.take_stdout().unwrap();
    let mut acc = String::new();
    read_until(&mut *out, &mut acc, "subsystem-ran\n").await;
    assert!(matches!(p.signal("TERM"), Err(Error::SignalRefused("subsystem"))));
    drop(p.take_stdin());
    assert_eq!(wait_exit(&mut p).await, Exit::Status(0));

    assert!(matches!(
        spawn(&cfg, &req(Kind::Subsystem("missing".into()))),
        Err(Error::UnknownSubsystem(n)) if n == "missing"
    ));
}

#[tokio::test]
async fn forced_command_replaces_request_and_exports_original() {
    let mut r = exec("what-the-client-asked");
    r.forced_command = Some("echo \"forced:$SSH_ORIGINAL_COMMAND\"".into());
    let (o, _, _) = run(&SessionConfig::default(), &r).await;
    assert_eq!(o, "forced:what-the-client-asked\n");
}

#[tokio::test]
async fn signal_term_gives_exit_signal_term() {
    let mut p = spawn(&SessionConfig::default(), &exec("echo ready; sleep 100")).expect("spawn");
    let mut out = p.take_stdout().unwrap();
    let mut acc = String::new();
    read_until(&mut *out, &mut acc, "ready\n").await;
    assert!(matches!(p.signal("BOGUS"), Err(Error::UnknownSignal(_))));
    p.signal("TERM").expect("signal");
    assert_eq!(wait_exit(&mut p).await, Exit::Signal { name: "TERM", core_dumped: false });
}

#[tokio::test]
async fn pty_is_a_controlling_terminal_with_requested_size() {
    let mut r = exec("tty; stty size; echo TERM=$TERM SSH_TTY=$SSH_TTY");
    r.pty = pty(80, 24, Vec::new());
    let mut p = spawn(&SessionConfig::default(), &r).expect("spawn");
    assert!(p.take_stderr().is_none(), "pty merges stderr");
    let tty = p.tty().unwrap().to_owned();
    assert!(tty.starts_with("/dev/pts/"), "{tty}");
    let o = read_all(&mut *p.take_stdout().unwrap()).await;
    assert_eq!(o, format!("{tty}\r\n24 80\r\nTERM=xterm-256color SSH_TTY={tty}\r\n"));
    assert_eq!(wait_exit(&mut p).await, Exit::Status(0));
}

/// tty_nr and tpgid of /proc/self/stat, read by the child about itself.
/// The "shell" is python3 (it accepts `-c`): bash would mask a missing
/// TIOCSCTTY by opening ttyname(stdin) without O_NOCTTY at startup, which
/// makes a session leader acquire the terminal (seen with strace).
#[tokio::test]
async fn pty_is_the_controlling_terminal_of_a_new_session() {
    let mut r = exec("print(open('/proc/self/stat').read(), end='')");
    r.user.shell = PathBuf::from("/usr/bin/python3");
    r.pty = pty(80, 24, Vec::new());
    let mut p = spawn(&SessionConfig::default(), &r).expect("spawn");
    let pid = p.pid();
    let o = read_all(&mut *p.take_stdout().unwrap()).await;
    let rest = &o[o.rfind(')').unwrap() + 2..];
    let f: Vec<&str> = rest.split(' ').collect();
    // state ppid pgrp session tty_nr tpgid
    let (pgrp, session, tty_nr, tpgid): (u32, u32, i64, i64) =
        (f[2].parse().unwrap(), f[3].parse().unwrap(), f[4].parse().unwrap(), f[5].parse().unwrap());
    assert_eq!((pgrp, session), (pid, pid), "new session and process group led by the child");
    assert_ne!(tty_nr, 0, "no controlling terminal: {o}");
    assert_eq!(tpgid, pid as i64, "the child's group is the terminal's foreground group: {o}");
}

#[tokio::test]
async fn window_change_resizes_and_delivers_sigwinch() {
    let mut r = exec("trap 'stty size; exit 0' WINCH; echo ready; while :; do sleep 0.01; done");
    r.pty = pty(80, 24, Vec::new());
    let mut p = spawn(&SessionConfig::default(), &r).expect("spawn");
    let mut out = p.take_stdout().unwrap();
    let mut acc = String::new();
    read_until(&mut *out, &mut acc, "ready\r\n").await;
    p.resize(WindowSize { cols: 132, rows: 50, xpixel: 0, ypixel: 0 }).expect("resize");
    read_until(&mut *out, &mut acc, "50 132\r\n").await;
    assert_eq!(wait_exit(&mut p).await, Exit::Status(0));
}

/// RFC 4254 §8 encoding: opcode byte + u32 argument.
fn mode(op: u8, v: u32) -> Vec<u8> {
    let mut m = vec![op];
    m.extend_from_slice(&v.to_be_bytes());
    m
}

#[tokio::test]
async fn pty_modes_are_applied() {
    let mut modes = Vec::new();
    modes.extend(mode(53, 0)); // ECHO off
    modes.extend(mode(1, 7)); // VINTR = ^G
    modes.extend(mode(128, 9600)); // ISPEED
    modes.extend(mode(129, 9600)); // OSPEED
    modes.push(0); // TTY_OP_END
    let mut r = exec("stty -a");
    r.pty = pty(80, 24, modes);
    let mut p = spawn(&SessionConfig::default(), &r).expect("spawn");
    let o = read_all(&mut *p.take_stdout().unwrap()).await;
    assert!(o.contains("-echo "), "{o}");
    assert!(o.contains("intr = ^G"), "{o}");
    assert!(o.contains("speed 9600 baud"), "{o}");

    let mut r = exec("true");
    r.pty = pty(80, 24, vec![53, 0, 0]); // truncated argument
    assert!(matches!(spawn(&SessionConfig::default(), &r), Err(Error::Protocol(_))));
}

#[tokio::test]
async fn pty_stdin_shutdown_does_not_end_input() {
    let mut r = exec("cat");
    r.pty = pty(80, 24, Vec::new());
    let mut p = spawn(&SessionConfig::default(), &r).expect("spawn");
    let mut stdin = p.take_stdin().unwrap();
    let mut out = p.take_stdout().unwrap();
    let mut acc = String::new();
    stdin.write_all(b"one\n").await.unwrap();
    stdin.shutdown().await.unwrap();
    read_until(&mut *out, &mut acc, "one\r\none\r\n").await;
    // The terminal is still open and cat still running: more input flows.
    stdin.write_all(b"two\n").await.unwrap();
    read_until(&mut *out, &mut acc, "two\r\ntwo\r\n").await;
    p.signal("HUP").unwrap();
    assert_eq!(wait_exit(&mut p).await, Exit::Signal { name: "HUP", core_dumped: false });
}

#[tokio::test]
async fn cannot_start_session_for_another_user_without_privileges() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let mut r = exec("true");
    r.user.uid += 1;
    assert!(matches!(spawn(&SessionConfig::default(), &r), Err(Error::Privilege(_))));
}


/// A background process the test itself started (pid printed by the
/// child as `$!`); killed by that pid when the test ends, pass or fail.
struct Leftover(i32);

impl Drop for Leftover {
    fn drop(&mut self) {
        unsafe { libc::kill(self.0, libc::SIGKILL) };
    }
}

fn running(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => &stat[stat.rfind(')').unwrap() + 2..stat.rfind(')').unwrap() + 3] != "Z",
        Err(_) => false,
    }
}

/// Value of `key=<pid>` in the child's output.
fn pid_of(out: &str, key: &str) -> i32 {
    let tag = format!("{key}=");
    let line = out.lines().find(|l| l.trim_end_matches('\r').starts_with(&tag)).unwrap_or_else(|| panic!("no {tag} in {out:?}"));
    line.trim_end_matches('\r')[tag.len()..].parse().unwrap()
}

/// Per-test marker file in the target's scratch dir (not /tmp).
fn marker(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ssh3-session-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// Poll (2 ms) for `path` to contain a line; fails after LIMIT naming it.
fn file_within(path: &std::path::Path) -> String {
    let deadline = std::time::Instant::now() + LIMIT;
    loop {
        if let Ok(s) = std::fs::read_to_string(path)
            && s.ends_with('\n')
        {
            return s;
        }
        assert!(std::time::Instant::now() < deadline, "{} not written within {LIMIT:?}", path.display());
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// End the session as the channel layer does: drop the process and all of
/// its stream halves.
fn end_session(p: SessionProcess, halves: Vec<Box<dyn std::any::Any>>) {
    drop(halves);
    drop(p);
}

#[tokio::test]
async fn without_pty_session_end_signals_nothing_and_children_survive() {
    let mut p = spawn(
        &SessionConfig::default(),
        &exec("nohup sleep 1000 >/dev/null 2>&1 & echo nohup=$!; sleep 1000 >/dev/null 2>&1 & echo plain=$!; echo ready; cat"),
    )
    .expect("spawn");
    let leader = p.pid();
    let mut out = p.take_stdout().unwrap();
    let mut acc = String::new();
    read_until(&mut *out, &mut acc, "ready\n").await;
    let (nohup, plain) = (Leftover(pid_of(&acc, "nohup")), Leftover(pid_of(&acc, "plain")));
    let halves: Vec<Box<dyn std::any::Any>> = vec![Box::new(out), Box::new(p.take_stdin()), Box::new(p.take_stderr())];
    end_session(p, halves);
    // stdin closed → cat sees EOF → the shell exits and is reaped.
    reaped_within(leader);
    assert!(running(nohup.0), "nohup child {} was killed at session end", nohup.0);
    assert!(running(plain.0), "background child {} was killed at session end (sshd signals nothing without a pty)", plain.0);
}

#[tokio::test]
async fn without_pty_closed_stdin_is_eof_for_the_child() {
    let f = marker("eof");
    let mut p = spawn(&SessionConfig::default(), &exec(&format!("cat >/dev/null; echo eof-seen > {}", f.display()))).expect("spawn");
    let leader = p.pid();
    let halves: Vec<Box<dyn std::any::Any>> = vec![Box::new(p.take_stdin()), Box::new(p.take_stdout()), Box::new(p.take_stderr())];
    end_session(p, halves);
    assert_eq!(file_within(&f), "eof-seen\n");
    reaped_within(leader);
}

#[tokio::test]
async fn pty_session_end_hangs_up_the_terminal_and_nohup_survives() {
    let leader_hup = marker("leader-hup");
    let child_hup = marker("child-hup");
    let child_ready = marker("child-ready");
    // The leader's "ready" says nothing about its background children: under
    // load the hangup used to arrive before `nohup` had set SIG_IGN or before
    // the child had installed its trap (46/300 failures at 84 busy threads,
    // every failure with a disposition still missing at "ready"). The child
    // reports its own readiness after `trap`; nohup's is observed below.
    let script = format!(
        "trap 'echo leader-hup > {lh}; exit 0' HUP; \
         nohup sleep 1000 >/dev/null 2>&1 & echo nohup=$!; \
         sh -c 'trap \"echo child-hup > {ch}; exit 0\" HUP; echo ok > {cr}; while :; do sleep 0.01; done' & echo child=$!; \
         echo ready; while :; do sleep 0.01; done",
        lh = leader_hup.display(),
        ch = child_hup.display(),
        cr = child_ready.display()
    );
    let mut r = exec(&script);
    r.pty = pty(80, 24, Vec::new());
    let mut p = spawn(&SessionConfig::default(), &r).expect("spawn");
    let leader = p.pid();
    let mut out = p.take_stdout().unwrap();
    let mut acc = String::new();
    read_until(&mut *out, &mut acc, "ready\r\n").await;
    let nohup = Leftover(pid_of(&acc, "nohup"));
    let child = Leftover(pid_of(&acc, "child"));
    file_within(&child_ready);
    nohup_in_place_within(nohup.0);
    let halves: Vec<Box<dyn std::any::Any>> = vec![Box::new(out), Box::new(p.take_stdin())];
    end_session(p, halves); // last reference to the master: hangup
    assert_eq!(file_within(&leader_hup), "leader-hup\n", "session leader not hung up");
    assert_eq!(file_within(&child_hup), "child-hup\n", "interactive child {} not hung up", child.0);
    reaped_within(leader);
    assert!(running(nohup.0), "nohup child {} did not survive the hangup", nohup.0);
}

#[tokio::test]
async fn drop_while_running_does_not_block_and_leader_is_reaped_later() {
    let mut p = spawn(&SessionConfig::default(), &exec("echo ready; read x")).expect("spawn");
    let leader = p.pid();
    let mut out = p.take_stdout().unwrap();
    let mut acc = String::new();
    read_until(&mut *out, &mut acc, "ready\n").await;
    let mut stdin = p.take_stdin().unwrap();
    let t = std::time::Instant::now();
    drop(p); // leader still blocked in `read`
    assert!(t.elapsed() < Duration::from_millis(100), "drop blocked for {:?}", t.elapsed());
    assert!(running(leader as i32), "drop must not signal the leader");
    stdin.write_all(b"go\n").await.unwrap(); // let it finish on its own
    reaped_within(leader);
}

// ---- root path, inside an unprivileged user namespace ----------------------

/// Runs the `#[ignore]`d inner test as namespace root. `--map-auto` maps the
/// user's subordinate id range, so uid/gid 65534 exist inside and setgroups
/// is permitted (newuidmap/newgidmap). A private devpts instance is mounted
/// so that new ptys carry ids mapped in the namespace: on the host devpts the
/// slave's group (host `tty`) is unmapped and namespace root may not chown it.
#[test]
fn root_path_in_user_namespace() {
    let exe = std::env::current_exe().unwrap();
    let script = "mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts /dev/pts \
        && mount --bind /dev/pts/ptmx /dev/ptmx \
        && exec \"$0\" --exact root_path_inner --ignored --nocapture --test-threads=1";
    let log = marker("userns.log");
    let mut child = std::process::Command::new("unshare")
        .args(["--map-root-user", "--map-auto", "--mount", "sh", "-c", script])
        .arg(&exe)
        .stdout(std::fs::File::create(&log).unwrap())
        .stderr(std::process::Stdio::from(std::fs::OpenOptions::new().append(true).open(&log).unwrap()))
        .spawn()
        .expect("run unshare");
    let deadline = std::time::Instant::now() + LIMIT * 2;
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if std::time::Instant::now() >= deadline {
            let pid = child.id();
            let _ = child.kill(); // our own direct child, by pid
            let _ = child.wait();
            panic!("user-namespace run (pid {pid}) did not finish within {:?}: {}", LIMIT * 2, std::fs::read_to_string(&log).unwrap_or_default());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_file(&log);
    assert!(status.success(), "{text}");
    assert!(text.contains("1 passed"), "{text}");
}

#[tokio::test]
#[ignore = "runs only as root; driven by root_path_in_user_namespace"]
async fn root_path_inner() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "must run as (namespace) root");
    let nobody = UserRecord {
        name: "nobody".into(),
        uid: 65534,
        gid: 65534,
        home: PathBuf::from("/"),
        shell: PathBuf::from("/bin/sh"),
    };
    let mut r = exec("id -u; id -g; id -G; cat /proc/self/status | grep -E '^(Uid|Gid|Groups):'");
    r.user = nobody.clone();
    let (o, e, x) = run(&SessionConfig::default(), &r).await;
    assert_eq!(x, Exit::Status(0), "stderr: {e}");
    let mut lines = o.lines();
    assert_eq!(lines.next(), Some("65534"));
    assert_eq!(lines.next(), Some("65534"));
    // Supplementary groups replaced by initgroups(nobody): root's groups
    // (0, 65534, 1000 in this namespace) must not survive.
    assert_eq!(lines.next(), Some("65534"));
    println!("{o}");
    let status: String = o.lines().filter(|l| l.starts_with("Uid:") || l.starts_with("Gid:")).collect::<Vec<_>>().join("|");
    assert_eq!(status, "Uid:\t65534\t65534\t65534\t65534|Gid:\t65534\t65534\t65534\t65534", "real/effective/saved/fs ids");

    // pty as root: the slave is chowned to the user.
    let mut r = exec("stat -c '%u' $(tty)");
    r.user = nobody;
    r.pty = pty(80, 24, Vec::new());
    match spawn(&SessionConfig::default(), &r) {
        Ok(mut p) => {
            let o = read_all(&mut *p.take_stdout().unwrap()).await;
            println!("pty-as-root: {o:?} exit {:?}", wait_exit(&mut p).await);
            assert_eq!(o, "65534\r\n");
        }
        Err(e) => panic!("pty as namespace root failed: {e}"),
    }
}
