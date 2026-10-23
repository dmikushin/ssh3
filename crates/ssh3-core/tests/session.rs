//! Session channels: exec/shell/pty, env, window-change, signal, exit status
//! (also across a resume), pty hangup on close, the PtyOverflow hook.
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::*;
use ssh3_core::{Command, ExitInfo, Limits, PtyOverflow, PtySpec, ServerSessionEnv, SessionChannel, SessionSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: Duration = Duration::from_secs(10);

async fn client_as_me(env: &Env) -> ssh3_core::ClientSession {
    let mut o = env.opts(&env.key);
    o.user = current_user();
    ssh3_core::ClientSession::connect(o, ssh3_core::udp_socket(ssh3_core::transport::dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap()).await.unwrap()
}

/// Sessions run `<login shell> -c command` (sshd); the login shell may be
/// fish, so test scripts are POSIX sh wrapped in `sh -c '…'`.
fn sh(script: &str) -> String {
    assert!(!script.contains('\''), "keep single quotes out of test scripts");
    format!("sh -c '{script}'")
}

fn exec(script: &str) -> SessionSpec {
    SessionSpec { pty: None, env: vec![], command: Command::Exec(sh(script)), forward_agent: None }
}

fn exec_pty(script: &str, rows: u32, cols: u32) -> SessionSpec {
    SessionSpec { pty: Some(PtySpec { term: "xterm".into(), cols, rows, ..Default::default() }), env: vec![], command: Command::Exec(sh(script)), forward_agent: None }
}

async fn read_all(r: &mut tokio::io::DuplexStream) -> String {
    let mut s = String::new();
    tokio::time::timeout(LIMIT, r.read_to_string(&mut s)).await.expect("output did not end").unwrap();
    s
}

async fn exit_of(ch: &mut SessionChannel) -> ExitInfo {
    tokio::time::timeout(LIMIT, ch.exit()).await.expect("no exit status").expect("session ended without exit")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_output_and_exit_status() {
    let env = env_with(fast_limits());
    let c = client_as_me(&env).await;
    let mut ch = c.open_session(exec("echo hello; echo oops >&2; exit 3")).await.unwrap();
    assert_eq!(read_all(&mut ch.stdout).await, "hello\n");
    assert_eq!(read_all(&mut ch.stderr).await, "oops\n");
    assert_eq!(exit_of(&mut ch).await, ExitInfo::Status(3));
    wait_until("channel gone on both sides", LIMIT, || env.server.stats().channels == 0 && c.shared.channel_count() == 0, || format!("{:?}", env.server.stats())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_eof_reaches_the_command() {
    let env = env_with(fast_limits());
    let c = client_as_me(&env).await;
    let mut ch = c.open_session(exec("cat")).await.unwrap();
    ch.stdin.write_all(b"through cat").await.unwrap();
    ch.stdin.shutdown().await.unwrap();
    assert_eq!(read_all(&mut ch.stdout).await, "through cat");
    assert_eq!(exit_of(&mut ch).await, ExitInfo::Status(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_env_filters_variables() {
    let cfg = ssh3_session::SessionConfig { accept_env: vec!["LC_*".into()], ..Default::default() };
    let env = env_with_session(fast_limits(), ServerSessionEnv::new(cfg));
    let c = client_as_me(&env).await;
    let spec = SessionSpec { env: vec![("LC_TEST".into(), "a".into()), ("FOO".into(), "b".into())], ..exec("echo \"$LC_TEST,$FOO\"") };
    let mut ch = c.open_session(spec).await.unwrap();
    assert_eq!(read_all(&mut ch.stdout).await, "a,\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pty_size_and_window_change() {
    let env = env_with(fast_limits());
    let c = client_as_me(&env).await;
    let mut ch = c.open_session(exec_pty("stty size; read x; stty size", 30, 100)).await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(LIMIT, ch.stdout.read(&mut buf)).await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("30 100"), "{:?}", String::from_utf8_lossy(&buf[..n]));
    ch.resize(120, 40, 0, 0).await.unwrap();
    ch.stdin.write_all(b"\n").await.unwrap();
    let out = read_all(&mut ch.stdout).await;
    assert!(out.contains("40 120"), "{out:?}");
    assert_eq!(exit_of(&mut ch).await, ExitInfo::Status(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signal_ends_the_process_with_exit_signal() {
    let env = env_with(fast_limits());
    let c = client_as_me(&env).await;
    let mut ch = c.open_session(exec("echo up; exec sleep 30")).await.unwrap();
    let mut buf = [0u8; 3];
    tokio::time::timeout(LIMIT, ch.stdout.read_exact(&mut buf)).await.unwrap().unwrap();
    ch.signal("TERM").await.unwrap();
    assert_eq!(exit_of(&mut ch).await, ExitInfo::Signal { name: "TERM".into(), core_dumped: false });
}

/// The exit status is an event: produced while detached, delivered after the
/// resume, with the output intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exit_status_is_replayed_after_resume() {
    let env = env_with(Limits { idle_timeout: Duration::from_millis(500), ..fast_limits() });
    let bh = blackhole::Blackhole::new(ssh3_core::transport::dual_stack_socket("[::]:0".parse().unwrap()).unwrap());
    let mut o = env.opts(&env.key);
    o.user = current_user();
    let c = ssh3_core::ClientSession::connect(o, bh.clone()).await.unwrap();
    let mut ch = c.open_session(exec("read x; echo done; exit 7")).await.unwrap();
    ch.stdin.write_all(b"go\n").await.unwrap();
    // Cut the path right away: the output and the exit happen while detached.
    bh.set_down(true);
    c.carrier_lost().await;
    wait_until("server detached", LIMIT, || env.server.stats().detached == 1, || format!("{:?}", env.server.stats())).await;
    c.resume(other_socket()).await.unwrap();
    assert_eq!(read_all(&mut ch.stdout).await, "done\n");
    assert_eq!(exit_of(&mut ch).await, ExitInfo::Status(7));
}

/// Closing a pty session drops every pty half on the server: the master
/// closes and the shell gets SIGHUP (sshd semantics).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_hangs_up_the_pty() {
    let env = env_with(fast_limits());
    let mark = env.dir.join("hup");
    let c = client_as_me(&env).await;
    let script = format!("trap \"touch {}; exit 0\" HUP; echo ready; while :; do sleep 0.05; done", mark.display());
    let mut ch = c.open_session(exec_pty(&script, 24, 80)).await.unwrap();
    let mut buf = vec![0u8; 64];
    let mut got = String::new();
    while !got.contains("ready") {
        let n = tokio::time::timeout(LIMIT, ch.stdout.read(&mut buf)).await.unwrap().unwrap();
        assert!(n > 0);
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    ch.close().await;
    wait_until("SIGHUP delivered (pty master closed)", LIMIT, || mark.exists(), || format!("{:?}", env.server.stats())).await;
    wait_until("server channel gone", LIMIT, || env.server.stats().channels == 0, || format!("{:?}", env.server.stats())).await;
}

#[derive(Default)]
struct Recording {
    full: AtomicU64,
}

impl PtyOverflow for Recording {
    fn ring_full(&self) -> bool {
        self.full.fetch_add(1, Ordering::Relaxed);
        false // stream mode: block, like the stub
    }
    fn feed(&self, _bytes: &[u8]) {}
}

/// SPEC §5 hybrid pty lanes: the overflow hook is invoked once the pty
/// output lane is full (the client stops reading).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pty_overflow_hook_is_invoked_when_the_lane_is_full() {
    let rec = Arc::new(Recording::default());
    let r2 = rec.clone();
    let mut senv = ServerSessionEnv::new(ssh3_session::SessionConfig::default());
    senv.overflow = Arc::new(move || r2.clone() as Arc<dyn PtyOverflow>);
    let env = env_with_session(fast_limits(), senv);
    let c = client_as_me(&env).await;
    // Never read: the client pipe, then its ring, then the credit fill up.
    let _ch = c.open_session(exec_pty("yes", 24, 80)).await.unwrap();
    wait_until("overflow hook invoked", LIMIT, || rec.full.load(Ordering::Relaxed) > 0, || format!("{:?}", env.server.stats())).await;
}

/// A real ssh-agent for the test, killed through its own child handle.
struct Agent {
    child: std::process::Child,
    sock: std::path::PathBuf,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn agent_with_key(dir: &std::path::Path) -> Agent {
    let sock = dir.join("agent.sock");
    let child = std::process::Command::new("ssh-agent").arg("-D").arg("-a").arg(&sock).stdout(std::process::Stdio::null()).spawn().unwrap();
    let agent = Agent { child, sock };
    wait_until("agent socket", LIMIT, || agent.sock.exists(), || "no socket".into()).await;
    let key = dir.join("agent_key");
    assert!(std::process::Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap().success());
    assert!(std::process::Command::new("ssh-add").arg("-q").arg(&key).env("SSH_AUTH_SOCK", &agent.sock).status().unwrap().success());
    agent
}

/// Agent forwarding: through the session's forwarded socket, `ssh-add -l`
/// lists exactly what the local agent holds. The remote command names the
/// socket explicitly: a login shell's own config may reset SSH_AUTH_SOCK (the
/// developer's fish config does), which sshd would not prevent either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_forwarding_reaches_the_local_agent() {
    let env = env_with(Limits { linger: Duration::from_millis(100), idle_timeout: Duration::from_millis(300), ..fast_limits() });
    let agent = agent_with_key(&env.dir).await;
    let local = std::process::Command::new("ssh-add").arg("-l").env("SSH_AUTH_SOCK", &agent.sock).output().unwrap();
    let local = String::from_utf8(local.stdout).unwrap();
    assert!(local.contains("ED25519") && local.lines().count() == 1, "{local}");
    let c = client_as_me(&env).await;
    // Enable forwarding with a first session, then use its socket.
    let spec = SessionSpec { forward_agent: Some(agent.sock.clone()), ..exec("true") };
    let mut first = c.open_session(spec).await.unwrap();
    assert_eq!(exit_of(&mut first).await, ExitInfo::Status(0));
    let fwd = env.server.session(&c.session_id()).unwrap().agent_socket().expect("forwarded agent socket");
    let meta = std::fs::metadata(fwd.parent().unwrap()).unwrap();
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777, 0o700);
    let mut ch = c.open_session(exec(&format!("SSH_AUTH_SOCK={} ssh-add -l", fwd.display()))).await.unwrap();
    assert_eq!(read_all(&mut ch.stdout).await, local);
    assert_eq!(exit_of(&mut ch).await, ExitInfo::Status(0));
    // The socket and its directory live as long as the session.
    drop(c);
    wait_until("session expired", LIMIT, || env.server.stats().sessions == 0, || format!("{:?}", env.server.stats())).await;
    assert!(!fwd.exists() && !fwd.parent().unwrap().exists(), "{} left behind", fwd.display());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_forwarding_refused_by_authorized_keys() {
    let env = env_with(fast_limits());
    env.authorize_only(&env.key, "no-agent-forwarding");
    let agent = agent_with_key(&env.dir).await;
    let c = client_as_me(&env).await;
    let spec = SessionSpec { forward_agent: Some(agent.sock.clone()), ..exec("true") };
    match c.open_session(spec).await {
        Err(e) => assert!(e.to_string().contains("no-agent-forwarding"), "{e}"),
        Ok(_) => panic!("agent forwarding was not refused"),
    }
}
