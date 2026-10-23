//! End to end with the real executables on loopback: ssh3-server with a temp
//! config and host key, ssh3 with `-F` (the user's ~/.ssh/config is never
//! read). Every wait has a deadline and fails naming what did not happen.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const DEADLINE: Duration = Duration::from_secs(10);

static N: AtomicU32 = AtomicU32::new(0);

/// A child killed (by its own PID) when the test ends, pass or fail.
struct Proc {
    child: Child,
    name: &'static str,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proc {
    fn wait_exit(&mut self, within: Duration) -> ExitStatus {
        let end = Instant::now() + within;
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(Instant::now() < end, "{} (pid {}) did not exit within {within:?}", self.name, self.child.id());
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Lines of a child's pipe, delivered through a channel so reads can have
/// deadlines.
fn lines(r: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for l in BufReader::new(r).lines() {
            let Ok(l) = l else { return };
            if tx.send(l).is_err() {
                return;
            }
        }
    });
    rx
}

fn expect_line(rx: &mpsc::Receiver<String>, what: &str, pred: impl Fn(&str) -> bool) -> String {
    let end = Instant::now() + DEADLINE;
    let mut seen = Vec::new();
    loop {
        let left = end.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(l) if pred(&l) => return l,
            Ok(l) => seen.push(l),
            Err(_) => panic!("no line {what} within {DEADLINE:?}; saw: {seen:#?}"),
        }
    }
}

fn keygen(path: &Path) {
    let st = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f"]).arg(path).status().unwrap();
    assert!(st.success(), "ssh-keygen {} failed", path.display());
}

fn me() -> String {
    ssh3_config::LocalEnv::from_system(443).unwrap().user
}

struct Env {
    dir: PathBuf,
    server: Proc,
    port: u16,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Env {
    fn new() -> Self {
        Self::with_limits("")
    }

    /// `limits`: extra lines for the server's `[limits]` section.
    fn with_limits(limits: &str) -> Self {
        let dir = PathBuf::from(std::env::var("HOME").unwrap())
            .join("scratch/ssh-udp/bins-tests")
            .join(format!("{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for k in ["host_key", "user_key", "other_key"] {
            keygen(&dir.join(k));
        }
        std::fs::copy(dir.join("user_key.pub"), dir.join("authorized_keys")).unwrap();
        // Sessions run the account's real login shell; HOME and
        // XDG_CONFIG_HOME point into the test directory so its startup files
        // (e.g. a fish config that relinks ~/.ssh/ssh_auth_sock) never run
        // against the real home.
        let conf = dir.join("server.toml");
        std::fs::write(
            &conf,
            format!(
                "listen = \"[::]:0\"\nhost_key = \"{d}/host_key\"\nendpoint_keys = \"{d}/endpoint-keys\"\nauthorized_keys = \"{d}/authorized_keys\"\nstats_socket = \"{d}/stats.sock\"\n[session]\nset_env = {{ HOME = \"{d}\", XDG_CONFIG_HOME = \"{d}/.config\" }}\n[limits]\nlogin_grace = \"5s\"\n{limits}",
                d = dir.display()
            ),
        )
        .unwrap();
        let log = std::fs::File::create(dir.join("server.log")).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_ssh3-server"))
            .arg("-f")
            .arg(&conf)
            .stdout(Stdio::piped())
            .stderr(log)
            .spawn()
            .unwrap();
        let out = lines(child.stdout.take().unwrap());
        let server = Proc { child, name: "ssh3-server" };
        let l = expect_line(&out, "'listening on'", |l| l.contains("listening on"));
        let port: u16 = l.rsplit(':').next().unwrap().parse().unwrap();
        let host_pub = std::fs::read_to_string(dir.join("host_key.pub")).unwrap();
        std::fs::write(dir.join("known_hosts"), format!("[127.0.0.1]:{port} {host_pub}")).unwrap();
        let env = Env { dir, server, port };
        env.client_config("user_key");
        env
    }

    fn client_config(&self, identity: &str) -> PathBuf {
        let p = self.dir.join(format!("ssh_config.{identity}"));
        std::fs::write(
            &p,
            format!(
                "Host t\n  HostName 127.0.0.1\n  Port {port}\n  User {user}\n  IdentityFile {d}/{identity}\n  IdentitiesOnly yes\n  IdentityAgent none\n  UserKnownHostsFile {d}/known_hosts\n  GlobalKnownHostsFile none\n  StrictHostKeyChecking yes\n  ExitOnForwardFailure yes\n",
                port = self.port,
                user = me(),
                d = self.dir.display()
            ),
        )
        .unwrap();
        p
    }

    fn cmd(&self, identity: &str, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ssh3"));
        c.arg("-F").arg(self.client_config(identity)).args(args);
        c
    }

    fn ssh3(&self, identity: &str, args: &[&str]) -> (Proc, mpsc::Receiver<String>) {
        let mut child = self
            .cmd(identity, args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let err = lines(child.stderr.take().unwrap());
        (Proc { child, name: "ssh3" }, err)
    }

    fn stats(&self) -> serde_json::Value {
        let mut s = std::os::unix::net::UnixStream::connect(self.dir.join("stats.sock")).unwrap();
        let mut body = String::new();
        s.read_to_string(&mut body).unwrap();
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("stats {body:?}: {e}"))
    }
}

fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut r = s.try_clone().unwrap();
                let _ = std::io::copy(&mut r, &mut s);
            });
        }
    });
    port
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn connect_within(port: u16, what: &str) -> TcpStream {
    let end = Instant::now() + DEADLINE;
    loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            return s;
        }
        assert!(Instant::now() < end, "{what} on port {port} not accepting within {DEADLINE:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Send `n` pseudo-random bytes through `s`, read the echo, compare SHA-256.
fn echo_check(s: TcpStream, n: usize) {
    let data: Vec<u8> = (0..n as u64).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let want = Sha256::digest(&data);
    s.set_read_timeout(Some(DEADLINE)).unwrap();
    let mut w = s.try_clone().unwrap();
    let writer = std::thread::spawn(move || {
        w.write_all(&data).unwrap();
        w.shutdown(std::net::Shutdown::Write).unwrap();
    });
    let mut got = Vec::with_capacity(n);
    (&s).read_to_end(&mut got).unwrap_or_else(|e| panic!("echo read after {} of {n} bytes: {e}", got.len()));
    writer.join().unwrap();
    assert_eq!(got.len(), n, "echo length");
    assert_eq!(Sha256::digest(&got), want, "echo content");
}

#[test]
fn local_forward_echo() {
    let env = Env::new();
    let echo = echo_server();
    let lport = free_port();
    let (_c, _err) = env.ssh3("user_key", &["-N", "-L", &format!("{lport}:127.0.0.1:{echo}"), "t"]);
    echo_check(connect_within(lport, "-L listener"), 4 << 20);
    let st = env.stats();
    assert_eq!(st["sessions"], 1, "{st}");
    assert_eq!(st["attached"], 1, "{st}");
}

#[test]
fn remote_forward_echo() {
    let env = Env::new();
    let echo = echo_server();
    let (_c, err) = env.ssh3("user_key", &["-N", "-R", &format!("0:127.0.0.1:{echo}"), "t"]);
    let l = expect_line(&err, "'Allocated port'", |l| l.starts_with("Allocated port"));
    let rport: u16 = l.split_whitespace().nth(2).unwrap().parse().unwrap();
    echo_check(connect_within(rport, "-R listener"), 4 << 20);
}

#[test]
fn wrong_key_is_permission_denied() {
    let env = Env::new();
    let (mut c, err) = env.ssh3("other_key", &["-N", "t"]);
    let st = c.wait_exit(DEADLINE);
    assert_eq!(st.code(), Some(255));
    let l = expect_line(&err, "'Permission denied'", |l| l.contains("Permission denied"));
    assert_eq!(l, format!("{}@127.0.0.1: Permission denied (publickey).", me()));
}

fn changed_host_key(env: &Env) -> (Proc, mpsc::Receiver<String>, String) {
    let other_pub = std::fs::read_to_string(env.dir.join("other_key.pub")).unwrap();
    let kh = format!("[127.0.0.1]:{} {other_pub}", env.port);
    std::fs::write(env.dir.join("known_hosts"), &kh).unwrap();
    let (c, err) = env.ssh3("user_key", &["-N", "t"]);
    (c, err, kh)
}

/// The mismatch is detected and named with file:line, the client exits 255
/// and known_hosts is untouched.
#[test]
fn changed_host_key_is_refused() {
    let env = Env::new();
    let (mut c, err, kh) = changed_host_key(&env);
    assert_eq!(c.wait_exit(DEADLINE).code(), Some(255));
    expect_line(&err, "'HOST KEY MISMATCH ... known_hosts:1'", |l| l.contains("HOST KEY MISMATCH") && l.contains("known_hosts:1"));
    assert_eq!(std::fs::read_to_string(env.dir.join("known_hosts")).unwrap(), kh, "known_hosts must not change");
}

/// ssh(1)'s final line (ssh3-core reports the rejection as Error::HostKey).
#[test]
fn changed_host_key_prints_verification_failed() {
    let env = Env::new();
    let (mut c, err, _) = changed_host_key(&env);
    assert_eq!(c.wait_exit(DEADLINE).code(), Some(255));
    expect_line(&err, "'Host key verification failed.'", |l| l == "Host key verification failed.");
}

#[test]
fn sigterm_releases_remote_port() {
    let mut env = Env::new();
    let echo = echo_server();
    let (_c, err) = env.ssh3("user_key", &["-N", "-R", &format!("0:127.0.0.1:{echo}"), "t"]);
    let l = expect_line(&err, "'Allocated port'", |l| l.starts_with("Allocated port"));
    let rport: u16 = l.split_whitespace().nth(2).unwrap().parse().unwrap();
    assert!(TcpListener::bind(("127.0.0.1", rport)).is_err(), "-R port {rport} should be held by the server");
    let t0 = Instant::now();
    assert_eq!(unsafe { libc::kill(env.server.child.id() as i32, libc::SIGTERM) }, 0);
    let st = env.server.wait_exit(Duration::from_secs(3));
    assert!(st.success(), "ssh3-server exit on SIGTERM: {st}");
    // The port is free once the server has exited; I5 asks for it at once.
    TcpListener::bind(("127.0.0.1", rport)).unwrap_or_else(|e| panic!("-R port {rport} still held after SIGTERM: {e}"));
    assert!(t0.elapsed() < Duration::from_secs(1), "shutdown took {:?}", t0.elapsed());
}

#[test]
fn server_config_check() {
    let env = Env::new();
    let out = Command::new(env!("CARGO_BIN_EXE_ssh3-server")).arg("-t").arg("-f").arg(env.dir.join("server.toml")).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("OK"));
    std::fs::write(env.dir.join("bad.toml"), "listen = \"[::]:0\"\nhost_key = \"/nonexistent\"\n[limits]\nidle_timout = \"1s\"\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ssh3-server")).arg("-t").arg("-f").arg(env.dir.join("bad.toml")).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("idle_timout"));
}

// ------------------------------------------------------------- sessions

struct Output {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

/// Run to completion with `input` on stdin (then EOF), bounded.
fn run(mut cmd: Command, input: &[u8]) -> Output {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = so.read_to_end(&mut v);
        v
    });
    let err = std::thread::spawn(move || {
        let mut v = String::new();
        let _ = se.read_to_string(&mut v);
        v
    });
    let mut p = Proc { child, name: "ssh3" };
    let st = p.wait_exit(DEADLINE);
    Output { code: st.code(), stdout: out.join().unwrap(), stderr: err.join().unwrap() }
}

#[test]
fn exec_streams_and_exit_status() {
    let env = Env::new();
    let o = run(env.cmd("user_key", &["t", "echo out; echo err >&2; exit 3"]), b"");
    assert_eq!(o.code, Some(3), "stderr: {}", o.stderr);
    assert_eq!(o.stdout, b"out\n");
    assert!(o.stderr.contains("err"), "{}", o.stderr);
    assert!(!String::from_utf8_lossy(&o.stdout).contains("err"), "stderr must not reach stdout without a pty");
}

#[test]
fn exit_signal_is_128_plus_n() {
    let env = Env::new();
    // `exec`: the session process itself must die by the signal; a shell
    // that merely ran a killed child would exit with status 143 instead.
    let o = run(env.cmd("user_key", &["t", "exec sh -c 'kill -TERM $$'"]), b"");
    assert_eq!(o.code, Some(128 + 15), "stderr: {}", o.stderr);
    assert!(o.stderr.contains("TERM"), "{}", o.stderr);
}

#[test]
fn stdin_eof_reaches_remote() {
    let env = Env::new();
    let data: Vec<u8> = (0..1u32 << 20).map(|i| (i.wrapping_mul(2654435761) >> 11) as u8).collect();
    let o = run(env.cmd("user_key", &["t", "cat"]), &data);
    assert_eq!(o.code, Some(0), "stderr: {}", o.stderr);
    assert_eq!(o.stdout.len(), data.len());
    assert_eq!(Sha256::digest(&o.stdout), Sha256::digest(&data));
}

#[test]
fn tty_request_rules() {
    let env = Env::new();
    // -t without a terminal on stdin: no pty, with ssh(1)'s notice.
    let o = run(env.cmd("user_key", &["-t", "t", "tty"]), b"");
    assert!(o.stderr.contains("Pseudo-terminal will not be allocated because stdin is not a terminal."), "{}", o.stderr);
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "not a tty");
    // -tt forces one.
    let o = run(env.cmd("user_key", &["-tt", "t", "tty"]), b"");
    assert!(String::from_utf8_lossy(&o.stdout).trim().starts_with("/dev/pts/"), "stdout {:?} stderr {}", String::from_utf8_lossy(&o.stdout), o.stderr);
    // -T with a command: none.
    let o = run(env.cmd("user_key", &["-T", "t", "tty"]), b"");
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "not a tty");
}

// ------------------------------------------------------------ real pty

struct Pty {
    master: std::fs::File,
    slave: std::os::fd::OwnedFd,
}

fn openpty(rows: u16, cols: u16) -> Pty {
    use std::os::fd::FromRawFd;
    let (mut m, mut s) = (0, 0);
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    assert_eq!(unsafe { libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), &ws) }, 0);
    unsafe { Pty { master: std::fs::File::from_raw_fd(m), slave: std::os::fd::OwnedFd::from_raw_fd(s) } }
}

fn termios(fd: &impl std::os::fd::AsRawFd) -> libc::termios {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut t) }, 0);
    t
}

fn same_termios(a: &libc::termios, b: &libc::termios) -> bool {
    a.c_iflag == b.c_iflag && a.c_oflag == b.c_oflag && a.c_cflag == b.c_cflag && a.c_lflag == b.c_lflag && a.c_cc == b.c_cc
}

/// Spawn with the pty slave as stdin/stdout/stderr and controlling
/// terminal (so the kernel sends it SIGWINCH).
fn spawn_on_pty(mut cmd: Command, pty: &Pty, name: &'static str) -> Proc {
    use std::os::unix::process::CommandExt;
    let io = || Stdio::from(pty.slave.try_clone().unwrap());
    unsafe {
        cmd.stdin(io()).stdout(io()).stderr(io()).pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Proc { child: cmd.spawn().unwrap(), name }
}

/// Everything the master side has produced so far, read by a thread.
struct Screen {
    rx: mpsc::Receiver<Vec<u8>>,
    text: String,
}

impl Screen {
    fn new(master: &std::fs::File) -> Self {
        let mut m = master.try_clone().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut b = [0u8; 4096];
            while let Ok(n) = m.read(&mut b) {
                if n == 0 || tx.send(b[..n].to_vec()).is_err() {
                    return;
                }
            }
        });
        Screen { rx, text: String::new() }
    }
    fn wait_for(&mut self, what: &str, within: Duration) {
        let end = Instant::now() + within;
        while !self.text.contains(what) {
            let left = end.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(b) => self.text.push_str(&String::from_utf8_lossy(&b)),
                Err(_) => panic!("terminal never showed {what:?} within {within:?}; screen: {:?}", self.text),
            }
        }
    }
}

fn set_winsize(f: &std::fs::File, rows: u16, cols: u16) {
    use std::os::fd::AsRawFd;
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    assert_eq!(unsafe { libc::ioctl(f.as_raw_fd(), libc::TIOCSWINSZ, &ws) }, 0);
}

#[test]
fn pty_session_raw_mode_resize_exit() {
    let env = Env::new();
    let mut pty = openpty(24, 80);
    let before = termios(&pty.slave);
    let mut screen = Screen::new(&pty.master);
    let mut c = spawn_on_pty(env.cmd("user_key", &["-t", "t", "sh -c 'stty size; while read x; do stty size; done; exit 5'"]), &pty, "ssh3");
    screen.wait_for("24 80", DEADLINE);
    // The local terminal is raw while the session runs.
    let during = termios(&pty.slave);
    assert_eq!(during.c_lflag & (libc::ICANON | libc::ECHO), 0, "local terminal not in raw mode");
    // SIGWINCH -> window-change; the remote sees the new size on its next
    // `stty size` (resend the line until it does: resize and input travel on
    // different streams, so their order is not defined).
    set_winsize(&pty.master, 50, 132);
    let end = Instant::now() + DEADLINE;
    while !screen.text.contains("50 132") {
        assert!(Instant::now() < end, "remote never saw 50x132; screen: {:?}", screen.text);
        pty.master.write_all(b"\r").unwrap();
        let _ = screen.rx.recv_timeout(Duration::from_millis(100)).map(|b| screen.text.push_str(&String::from_utf8_lossy(&b)));
    }
    // ^D: EOF to the remote `read` through the remote pty's line discipline.
    pty.master.write_all(&[4]).unwrap();
    let st = c.wait_exit(DEADLINE);
    assert_eq!(st.code(), Some(5), "screen: {:?}", screen.text);
    screen.wait_for("Connection to 127.0.0.1 closed.", DEADLINE);
    assert!(same_termios(&before, &termios(&pty.slave)), "terminal settings not restored after exit");
}

#[test]
fn pty_terminal_restored_when_killed() {
    let env = Env::new();
    let pty = openpty(24, 80);
    let before = termios(&pty.slave);
    let mut screen = Screen::new(&pty.master);
    let mut c = spawn_on_pty(env.cmd("user_key", &["-t", "t", "echo ready; sleep 30"]), &pty, "ssh3");
    screen.wait_for("ready", DEADLINE);
    assert_eq!(termios(&pty.slave).c_lflag & libc::ICANON, 0);
    assert_eq!(unsafe { libc::kill(c.child.id() as i32, libc::SIGTERM) }, 0);
    assert_eq!(c.wait_exit(DEADLINE).code(), Some(255));
    assert!(same_termios(&before, &termios(&pty.slave)), "terminal settings not restored after SIGTERM");
}

#[test]
fn last_contact_line_follows_server_silence() {
    let mut env = Env::new();
    let pty = openpty(24, 80);
    let mut screen = Screen::new(&pty.master);
    std::fs::OpenOptions::new().append(true).open(env.client_config("user_key")).unwrap();
    let cfg = env.dir.join("ssh_config.contact");
    std::fs::write(&cfg, format!("{}  ContactWarn 300ms\n", std::fs::read_to_string(env.client_config("user_key")).unwrap())).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ssh3"));
    cmd.arg("-F").arg(&cfg).args(["-N", "-L", &format!("{}:127.0.0.1:9", free_port()), "t"]);
    let _c = spawn_on_pty(cmd, &pty, "ssh3");
    // Wait for the session (stats), then silence the server.
    let end = Instant::now() + DEADLINE;
    while env.stats()["attached"] != 1 {
        assert!(Instant::now() < end, "client never attached");
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = env.server.child.id() as i32;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
    screen.wait_for("Last contact", Duration::from_secs(5));
    assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
    // Contact returns: the line is cleared (erase-line after the message).
    let shown_at = screen.text.rfind("Last contact").unwrap();
    let end = Instant::now() + DEADLINE;
    while !screen.text[shown_at..].contains("\r\x1b[K\x1b") && !screen.text[shown_at..].ends_with("\r\x1b[K") {
        assert!(Instant::now() < end, "status line never cleared; screen: {:?}", &screen.text[shown_at..]);
        if let Ok(b) = screen.rx.recv_timeout(Duration::from_millis(100)) {
            screen.text.push_str(&String::from_utf8_lossy(&b));
        }
    }
    env.server.child.kill().unwrap();
}

#[test]
fn gave_up_exits_255() {
    // Dead after 2 s of silence (ServerAliveInterval × CountMax) and a
    // server linger of 1 s: once the server is gone, resume gives up.
    let mut env = Env::with_limits("linger = \"1s\"\n");
    let (mut c, err) = env.ssh3("user_key", &["-N", "-o", "ServerAliveInterval=1", "-o", "ServerAliveCountMax=2", "t"]);
    let end = Instant::now() + DEADLINE;
    while env.stats()["attached"] != 1 {
        assert!(Instant::now() < end, "client never attached");
        std::thread::sleep(Duration::from_millis(20));
    }
    env.server.child.kill().unwrap();
    let st = c.wait_exit(Duration::from_secs(20));
    assert_eq!(st.code(), Some(255));
    expect_line(&err, "give-up message", |l| l.contains("could not be resumed"));
}

// -------------------------------------------------------- forwards (new)

fn udp_echo() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut b = [0u8; 65536];
        while let Ok((n, from)) = s.recv_from(&mut b) {
            let _ = s.send_to(&b[..n], from);
        }
    });
    port
}

/// Send datagrams to `to` until one echo comes back (UDP: the first may be
/// sent before the forward's flow exists), bounded.
fn udp_roundtrip(to: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let end = Instant::now() + DEADLINE;
    let mut b = [0u8; 65536];
    loop {
        s.send_to(payload, to).unwrap();
        if let Ok((n, _)) = s.recv_from(&mut b) {
            return b[..n].to_vec();
        }
        assert!(Instant::now() < end, "no UDP echo via {to} within {DEADLINE:?}");
    }
}

#[test]
fn udp_local_and_remote_forwards() {
    let env = Env::new();
    let echo = udp_echo();
    let lport = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    let (_c, err) = env.ssh3("user_key", &["-N", "-U", &format!("{lport}:127.0.0.1:{echo}"), "-u", &format!("0:127.0.0.1:{echo}"), "t"]);
    let l = expect_line(&err, "'Allocated UDP port'", |l| l.starts_with("Allocated UDP port"));
    let rport: u16 = l.split_whitespace().nth(3).unwrap().parse().unwrap();
    let big: Vec<u8> = (0..1400u32).map(|i| i as u8).collect();
    assert_eq!(udp_roundtrip(([127, 0, 0, 1], lport).into(), &big), big, "-U echo");
    assert_eq!(udp_roundtrip(([127, 0, 0, 1], rport).into(), b"remote"), b"remote", "-u echo");
}

fn socks_hello(s: &mut TcpStream) {
    s.write_all(&[5, 1, 0]).unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).unwrap();
    assert_eq!(r, [5, 0], "SOCKS5 method selection");
}

/// Reply: VER REP RSV ATYP(1) ADDR(4) PORT(2).
fn socks_reply(s: &mut TcpStream) -> std::net::SocketAddr {
    let mut r = [0u8; 10];
    s.read_exact(&mut r).unwrap();
    assert_eq!((r[0], r[1], r[3]), (5, 0, 1), "SOCKS5 reply {r:?}");
    (std::net::Ipv4Addr::new(r[4], r[5], r[6], r[7]), u16::from_be_bytes([r[8], r[9]])).into()
}

#[test]
fn socks5_connect_and_udp_associate() {
    let env = Env::new();
    let echo = echo_server();
    let uecho = udp_echo();
    let dport = free_port();
    let (_c, _err) = env.ssh3("user_key", &["-N", "-D", &dport.to_string(), "t"]);
    // CONNECT 127.0.0.1:echo
    let mut s = connect_within(dport, "-D listener");
    s.set_read_timeout(Some(DEADLINE)).unwrap();
    socks_hello(&mut s);
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend_from_slice(&echo.to_be_bytes());
    s.write_all(&req).unwrap();
    socks_reply(&mut s);
    echo_check(s, 1 << 20);
    // UDP ASSOCIATE, then one datagram through the relay to the UDP echo.
    let mut ctl = connect_within(dport, "-D listener");
    ctl.set_read_timeout(Some(DEADLINE)).unwrap();
    socks_hello(&mut ctl);
    ctl.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut relay = socks_reply(&mut ctl);
    if relay.ip().is_unspecified() {
        relay.set_ip([127, 0, 0, 1].into());
    }
    let mut dgram = vec![0, 0, 0, 1, 127, 0, 0, 1];
    dgram.extend_from_slice(&uecho.to_be_bytes());
    dgram.extend_from_slice(b"via socks");
    let back = udp_roundtrip(relay, &dgram);
    assert_eq!(&back[10..], b"via socks", "UDP ASSOCIATE echo {back:?}");
}

#[test]
fn agent_forwarding() {
    let env = Env::new();
    let sock = env.dir.join("agent.sock");
    let agent = Command::new("ssh-agent").arg("-D").arg("-a").arg(&sock).stdout(Stdio::null()).spawn().unwrap();
    let _agent = Proc { child: agent, name: "ssh-agent" };
    let end = Instant::now() + DEADLINE;
    while !sock.exists() {
        assert!(Instant::now() < end, "ssh-agent socket never appeared");
        std::thread::sleep(Duration::from_millis(10));
    }
    let st = Command::new("ssh-add").arg("-q").arg(env.dir.join("user_key")).env("SSH_AUTH_SOCK", &sock).status().unwrap();
    assert!(st.success());
    let fp = String::from_utf8(Command::new("ssh-keygen").arg("-lf").arg(env.dir.join("user_key.pub")).output().unwrap().stdout).unwrap();
    let fp = fp.split_whitespace().nth(1).unwrap().to_string();
    let agent_opt = format!("IdentityAgent={}", sock.display());
    let o = run(env.cmd("user_key", &["-A", "-o", &agent_opt, "t", "ssh-add -l"]), b"");
    assert_eq!(o.code, Some(0), "stderr {}", o.stderr);
    let listed = String::from_utf8_lossy(&o.stdout);
    assert_eq!(listed.lines().count(), 1, "remote must see exactly the forwarded agent's one key; it listed {} keys", listed.lines().count());
    assert!(listed.contains(&fp), "remote ssh-add -l does not show {fp}");
    // Without -A the remote has no agent.
    let o = run(env.cmd("user_key", &["-o", &agent_opt, "t", "ssh-add -l"]), b"");
    assert_ne!(o.code, Some(0), "remote reached an agent without -A");
}

// -------------------------------------------------------- multi-key auth

/// UDP relay in front of the server that counts client 4-tuples: every dial
/// uses a fresh socket, so the count is the number of connections the
/// client made.
fn counting_relay(server_port: u16) -> (u16, std::sync::Arc<std::sync::Mutex<std::collections::HashSet<std::net::SocketAddr>>>) {
    use std::collections::HashMap;
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};
    let front = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = front.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        let mut ups: HashMap<std::net::SocketAddr, Arc<UdpSocket>> = HashMap::new();
        let mut b = [0u8; 65536];
        while let Ok((n, from)) = front.recv_from(&mut b) {
            let up = ups.entry(from).or_insert_with(|| {
                seen2.lock().unwrap().insert(from);
                let up = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
                up.connect(("127.0.0.1", server_port)).unwrap();
                let (up2, front2) = (up.clone(), front.try_clone().unwrap());
                std::thread::spawn(move || {
                    let mut b = [0u8; 65536];
                    while let Ok(n) = up2.recv(&mut b) {
                        let _ = front2.send_to(&b[..n], from);
                    }
                });
                up
            });
            let _ = up.send(&b[..n]);
        }
    });
    (port, seen)
}

#[test]
fn several_keys_on_one_connection() {
    let env = Env::new();
    let (rport, seen) = counting_relay(env.port);
    let host_pub = std::fs::read_to_string(env.dir.join("host_key.pub")).unwrap();
    std::fs::write(env.dir.join("known_hosts.relay"), format!("[127.0.0.1]:{rport} {host_pub}")).unwrap();
    let cfg = env.dir.join("ssh_config.two_keys");
    // Only the second identity is in authorized_keys.
    std::fs::write(
        &cfg,
        format!(
            "Host t\n  HostName 127.0.0.1\n  Port {rport}\n  User {user}\n  IdentityFile {d}/other_key\n  IdentityFile {d}/user_key\n  IdentitiesOnly yes\n  IdentityAgent none\n  UserKnownHostsFile {d}/known_hosts.relay\n  GlobalKnownHostsFile none\n",
            user = me(),
            d = env.dir.display()
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ssh3"));
    cmd.arg("-F").arg(&cfg).args(["t", "echo ok"]);
    let o = run(cmd, b"");
    assert_eq!(o.code, Some(0), "stderr: {}", o.stderr);
    assert_eq!(o.stdout, b"ok\n");
    assert_eq!(seen.lock().unwrap().len(), 1, "client connections through the relay");
    assert_eq!(env.stats()["auth_failures"], 1, "the first key must have been offered and refused");
}
