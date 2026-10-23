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
        let dir = PathBuf::from(std::env::var("HOME").unwrap())
            .join("scratch/ssh-udp/bins-tests")
            .join(format!("{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for k in ["host_key", "user_key", "other_key"] {
            keygen(&dir.join(k));
        }
        std::fs::copy(dir.join("user_key.pub"), dir.join("authorized_keys")).unwrap();
        let conf = dir.join("server.toml");
        std::fs::write(
            &conf,
            format!(
                "listen = \"[::]:0\"\nhost_key = \"{d}/host_key\"\nendpoint_keys = \"{d}/endpoint-keys\"\nauthorized_keys = \"{d}/authorized_keys\"\nstats_socket = \"{d}/stats.sock\"\n[limits]\nlogin_grace = \"5s\"\n",
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

    fn ssh3(&self, identity: &str, args: &[&str]) -> (Proc, mpsc::Receiver<String>) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ssh3"))
            .arg("-F")
            .arg(self.client_config(identity))
            .args(args)
            .stdin(Stdio::null())
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

/// What holds today: the mismatch is detected, named with file:line, the
/// client exits 255 and known_hosts is untouched.
#[test]
fn changed_host_key_is_refused() {
    let env = Env::new();
    let (mut c, err, kh) = changed_host_key(&env);
    assert_eq!(c.wait_exit(DEADLINE).code(), Some(255));
    expect_line(&err, "'HOST KEY MISMATCH ... known_hosts:1'", |l| l.contains("HOST KEY MISMATCH") && l.contains("known_hosts:1"));
    assert_eq!(std::fs::read_to_string(env.dir.join("known_hosts")).unwrap(), kh, "known_hosts must not change");
}

/// ssh(1)'s final line. ssh3-core reports a verifier rejection inside the
/// TLS handshake as a generic connection error, so the client cannot tell it
/// from a network failure without matching error text (requested on the
/// board: core maps it to Error::HostKey).
#[test]
#[ignore = "needs ssh3-core: TLS-handshake host-key rejection -> Error::HostKey (board, Requests to core)"]
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
fn sessions_are_refused_explicitly() {
    let env = Env::new();
    let (mut c, err) = env.ssh3("user_key", &["t", "echo", "hi"]);
    assert_eq!(c.wait_exit(DEADLINE).code(), Some(255));
    expect_line(&err, "session refusal", |l| l.contains("no session channel"));
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
