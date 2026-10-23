//! SPEC §5 hybrid pty lanes: a program never blocks on its terminal; output
//! beyond the client's credit goes to the server's emulator only, and a
//! redraw brings the client's terminal to the same state.
mod common;

use std::time::{Duration, Instant};

use common::*;
use ssh3_core::{Command, ExitInfo, Limits, PtySpec, SessionChannel, SessionSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: Duration = Duration::from_secs(20);
const COLS: u16 = 80;
const ROWS: u16 = 24;

async fn client_as_me(env: &Env, bh: Option<&std::sync::Arc<blackhole::Blackhole>>) -> ssh3_core::ClientSession {
    let mut o = env.opts(&env.key);
    o.user = current_user();
    let sock: std::sync::Arc<dyn quinn::AsyncUdpSocket> = match bh {
        Some(b) => b.clone(),
        None => ssh3_core::udp_socket(ssh3_core::transport::dual_stack_socket("[::]:0".parse().unwrap()).unwrap()).unwrap(),
    };
    ssh3_core::ClientSession::connect(o, sock).await.unwrap()
}

fn pty_exec(script: &str) -> SessionSpec {
    SessionSpec { pty: Some(PtySpec { term: "xterm".into(), cols: COLS as u32, rows: ROWS as u32, ..Default::default() }), env: vec![], command: Command::Exec(script.into()), forward_agent: None }
}

/// Wait for the program's exit while NOT reading its output (measures that
/// it never blocks), then until the server's pty reached EOF, and return
/// the server's final screen.
async fn exit_unread(env: &Env, c: &ssh3_core::ClientSession, ch: &mut SessionChannel) -> (ExitInfo, Duration, ssh3_term::Snapshot) {
    let t = Instant::now();
    let exit = tokio::time::timeout(LIMIT, ch.exit()).await.expect("the program blocked: no exit while the client stalled").expect("no exit");
    let took = t.elapsed();
    let srv = env.server.session(&c.session_id()).unwrap();
    let mut snap = None;
    wait_until("server pty at EOF", LIMIT, || match srv.pty_screen(ch.chan_id) {
        Some((s, true)) => {
            snap = Some(s);
            true
        }
        _ => false,
    }, || format!("{:?}", env.server.stats())).await;
    (exit, took, snap.unwrap())
}

/// Drain the client's output into a client-side terminal model.
async fn client_screen(ch: &mut SessionChannel) -> (ssh3_term::Screen, Vec<u8>) {
    let mut screen = ssh3_term::Screen::new(COLS, ROWS);
    let mut all = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = tokio::time::timeout(LIMIT, ch.stdout.read(&mut buf)).await.expect("output did not end").unwrap();
        if n == 0 {
            break;
        }
        screen.feed(&buf[..n]);
        all.extend_from_slice(&buf[..n]);
    }
    (screen, all)
}

fn assert_same_screen(client: &ssh3_term::Screen, server: &ssh3_term::Snapshot) {
    let diff = client.snapshot().diff(server);
    assert!(diff.is_empty(), "client terminal differs from the server's screen:\n{}", diff.join("\n"));
}

/// (a) A flood while the client's sink is stalled: the program finishes
/// without blocking; after the drain the client's terminal equals the
/// server's screen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flood_with_stalled_client_never_blocks_and_converges() {
    let env = env_with(fast_limits());
    let c = client_as_me(&env, None).await;
    let mut ch = c.open_session(pty_exec("printf '\\033[1;31mstart\\033[0m\\n'; seq 1 400000; printf 'END'")).await.unwrap();
    let (exit, took, server) = exit_unread(&env, &c, &mut ch).await;
    assert_eq!(exit, ExitInfo::Status(0));
    let st = env.server.stats();
    assert!(st.pty_screen_bytes > 1 << 20, "screen mode was not used: {st:?}");
    eprintln!("program finished in {took:?} with the client stalled; {} bytes screen-only", st.pty_screen_bytes);
    let (client, _) = client_screen(&mut ch).await;
    assert_same_screen(&client, &server);
    assert!(env.server.stats().pty_redraws >= 1);
}

/// (b) The same across a detach and a resume: the program finishes while
/// the client is away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flood_while_detached_converges_after_resume() {
    let env = env_with(Limits { idle_timeout: Duration::from_millis(500), ..fast_limits() });
    let bh = blackhole::Blackhole::new(ssh3_core::transport::dual_stack_socket("[::]:0".parse().unwrap()).unwrap());
    let c = client_as_me(&env, Some(&bh)).await;
    let mut ch = c.open_session(pty_exec("read x; seq 1 400000; printf '\\033[7mdone\\033[0m'")).await.unwrap();
    ch.stdin.write_all(b"go\n").await.unwrap();
    // Let the carrier carry the "go" before cutting it.
    tokio::time::sleep(Duration::from_millis(100)).await;
    bh.set_down(true);
    c.carrier_lost().await;
    wait_until("server detached", LIMIT, || env.server.stats().detached == 1, || format!("{:?}", env.server.stats())).await;
    let srv = env.server.session(&c.session_id()).unwrap();
    wait_until("program finished while detached", LIMIT, || matches!(srv.pty_screen(ch.chan_id), Some((_, true))), || format!("{:?}", env.server.stats())).await;
    let (server, _) = srv.pty_screen(ch.chan_id).unwrap();
    assert!(env.server.stats().pty_screen_bytes > 1 << 20, "{:?}", env.server.stats());
    c.resume(other_socket()).await.unwrap();
    assert_eq!(tokio::time::timeout(LIMIT, ch.exit()).await.unwrap(), Some(ExitInfo::Status(0)));
    let (client, _) = client_screen(&mut ch).await;
    assert_same_screen(&client, &server);
}

/// (c) The client's parser is inside an unterminated OSC when the redraw
/// arrives: the redraw's CAN/ST prefix resynchronises it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redraw_resynchronises_a_client_inside_an_unterminated_osc() {
    let env = env_with(fast_limits());
    let c = client_as_me(&env, None).await;
    // Stream mode delivers "hello" and the start of a title OSC; the rest
    // (including its BEL terminator) is screen-only.
    let mut ch = c.open_session(pty_exec("printf 'hello\\033]0;tit'; seq 1 400000; printf '\\007after'")).await.unwrap();
    let (_, _, server) = exit_unread(&env, &c, &mut ch).await;
    assert!(env.server.stats().pty_screen_bytes > 1 << 20, "{:?}", env.server.stats());
    let (client, bytes) = client_screen(&mut ch).await;
    let osc = bytes.windows(4).position(|w| w == b"\x1b]0;").expect("OSC start delivered");
    assert!(bytes[osc..].contains(&0x18), "no CAN after the unterminated OSC: the redraw did not resynchronise");
    assert_same_screen(&client, &server);
}

/// (d) Small output never fills the ring: byte-exact, no redraw.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn small_output_is_byte_exact() {
    let env = env_with(fast_limits());
    let c = client_as_me(&env, None).await;
    let mut ch = c.open_session(pty_exec("printf 'abc\\033[1mdef\\033[0m'")).await.unwrap();
    let (_, bytes) = client_screen(&mut ch).await;
    assert_eq!(bytes, b"abc\x1b[1mdef\x1b[0m");
    let st = env.server.stats();
    assert_eq!((st.pty_redraws, st.pty_screen_bytes), (0, 0), "{st:?}");
}

/// A pty larger than the configured maximum is clamped (the redraw bound
/// holds), and an undersized pty LaneBuffer is rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pty_size_is_clamped_and_lane_buffer_validated() {
    let env = env_with(Limits { pty_max_cols: 100, pty_max_rows: 30, ..fast_limits() });
    let c = client_as_me(&env, None).await;
    let spec = SessionSpec { pty: Some(PtySpec { term: "xterm".into(), cols: 500, rows: 200, ..Default::default() }), ..pty_exec("stty size") };
    let mut ch = c.open_session(spec).await.unwrap();
    let (_, bytes) = client_screen(&mut ch).await;
    assert_eq!(String::from_utf8_lossy(&bytes).trim(), "30 100");
    let e = Limits { pty_lane_buffer: 1 << 20, ..Limits::default() }.validate().unwrap_err();
    assert!(e.contains("pty_lane_buffer"), "{e}");
}
