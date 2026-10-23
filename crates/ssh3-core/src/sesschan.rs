//! Session channels (SPEC §4 channel kind `session`, RFC 4254 §6).
//!
//! Lane 0 carries stdin (client→server) and stdout (server→client), lane 1
//! stderr. Requests, replies and the exit status are session events, so they
//! are replayed after a resume. The server runs processes through
//! `ssh3-session`; this module only connects its streams to lanes.

use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{DuplexStream, unix::AsyncFd};
use tokio::sync::{Notify, oneshot, watch};

use crate::error::{Error, Result};
use crate::lane::{BlockingOverflow, PtyOverflow};
use crate::msg::{ChannelKind, FailReason, Message, SessReq};
use crate::session::{Completion, SessionShared};

/// Makes the overflow policy of each pty output lane (the terminal crate
/// supplies screen mode; the default blocks).
pub type OverflowFactory = Arc<dyn Fn() -> Arc<dyn PtyOverflow> + Send + Sync>;

/// Server-wide settings for session channels.
pub struct ServerSessionEnv {
    pub config: ssh3_session::SessionConfig,
    pub overflow: OverflowFactory,
    /// The server's UDP port (SSH_CONNECTION).
    pub(crate) local_port: u16,
}

impl ServerSessionEnv {
    pub fn new(config: ssh3_session::SessionConfig) -> Self {
        Self { config, overflow: Arc::new(|| Arc::new(BlockingOverflow) as Arc<dyn PtyOverflow>), local_port: 0 }
    }
}

/// Set once when the session's process has exited and its exit was sent.
#[derive(Default)]
pub(crate) struct ExitFlag {
    done: AtomicBool,
    notify: Notify,
}

impl ExitFlag {
    pub(crate) async fn wait(&self) {
        loop {
            let fut = self.notify.notified();
            tokio::pin!(fut);
            fut.as_mut().enable();
            if self.done.load(Ordering::Acquire) {
                return;
            }
            fut.await;
        }
    }
    fn set(&self) {
        self.done.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

/// How the remote process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitInfo {
    Status(u32),
    Signal { name: String, core_dumped: bool },
}

pub(crate) struct ServerSess {
    pty: Mutex<Option<ssh3_session::PtyRequest>>,
    env: Mutex<Vec<(String, String)>>,
    started: AtomicBool,
    process: tokio::sync::Mutex<Option<ssh3_session::SessionProcess>>,
    exited: Arc<ExitFlag>,
}

pub(crate) struct ClientSess {
    exit: watch::Sender<Option<ExitInfo>>,
}

pub(crate) enum ChanExt {
    Server(Arc<ServerSess>),
    Client(Arc<ClientSess>),
}

/// What the client asks the server to run.
#[derive(Debug, Clone)]
pub enum Command {
    Shell,
    Exec(String),
    Subsystem(String),
}

/// A pty request (RFC 4254 §6.2).
#[derive(Debug, Clone, Default)]
pub struct PtySpec {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    pub xpixel: u32,
    pub ypixel: u32,
    pub modes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionSpec {
    pub pty: Option<PtySpec>,
    pub env: Vec<(String, String)>,
    pub command: Command,
}

/// Client side of a session channel. The application reads `stdout` /
/// `stderr` and writes `stdin` (shut down `stdin` to send EOF).
pub struct SessionChannel {
    pub chan_id: u64,
    pub stdin: DuplexStream,
    pub stdout: DuplexStream,
    pub stderr: DuplexStream,
    exit: watch::Receiver<Option<ExitInfo>>,
    shared: Arc<SessionShared>,
}

/// In-memory pipes between a client session channel and the application.
const PIPE: usize = 64 * 1024;

impl SessionChannel {
    /// The process's exit (status or signal); waits until it is known.
    /// `None` if the session ended without one.
    pub async fn exit(&mut self) -> Option<ExitInfo> {
        let _ = self.exit.wait_for(|e| e.is_some()).await;
        self.exit.borrow().clone()
    }
    /// `window-change`.
    pub async fn resize(&self, cols: u32, rows: u32, xpixel: u32, ypixel: u32) -> Result<()> {
        self.shared.session_request(self.chan_id, SessReq::WindowChange { cols, rows, xpixel, ypixel }).await
    }
    /// `signal` (RFC 4254 §6.9 names, e.g. "TERM").
    pub async fn signal(&self, name: &str) -> Result<()> {
        self.shared.session_request(self.chan_id, SessReq::Signal { name: name.into() }).await
    }
    /// End the channel now (the server drops the process's streams: a pty
    /// hangs up).
    pub async fn close(self) {
        self.shared.abort_channel(self.chan_id, "closed by client".into()).await;
    }
}

/// pidfd readable = the process exited (not reaped: ssh3-session waits with
/// WNOWAIT and reaps on drop).
async fn exited(pid: u32) -> std::io::Result<()> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh pidfd owned by nothing else.
    let afd = unsafe { AsyncFd::register_with_interest(OwnedFd::from_raw_fd(fd as i32), tokio::io::Interest::READABLE) }.map_err(|e| e.into_parts().1)?;
    let _guard = afd.readable().await?;
    Ok(())
}

static REQ_IDS: AtomicU64 = AtomicU64::new(1);

impl SessionShared {
    // ------------------------------------------------------------ client

    /// Open a session channel and start `spec` on the server.
    pub async fn open_session(self: &Arc<Self>, spec: SessionSpec) -> Result<SessionChannel> {
        let (tx, rx) = watch::channel(None);
        let ext = ChanExt::Client(Arc::new(ClientSess { exit: tx }));
        let ch = self.open_channel(ChannelKind::Session, 2, Completion::AllLanes, Some(ext)).await?;
        let (stdin_app, stdin_lane) = tokio::io::duplex(PIPE);
        let (stdout_lane, stdout_app) = tokio::io::duplex(PIPE);
        let (stderr_lane, stderr_app) = tokio::io::duplex(PIPE);
        self.start_io(&ch, 0, stdin_lane, stdout_lane);
        // The client sends nothing on the stderr lane: an empty source
        // finishes that direction at once.
        self.start_io(&ch, 1, tokio::io::empty(), stderr_lane);
        for l in &ch.lanes {
            if let Err(e) = self.open_lane(l).await {
                tracing::debug!(chan = ch.chan_id, "lane not opened now ({e}); the next resume will");
            }
        }
        let chan_id = ch.chan_id;
        if let Some(p) = spec.pty {
            self.session_request(chan_id, SessReq::Pty { term: p.term, cols: p.cols, rows: p.rows, xpixel: p.xpixel, ypixel: p.ypixel, modes: p.modes })
                .await?;
        }
        for (name, value) in spec.env {
            // A refused variable is not an error (OpenSSH: want_reply 0).
            let _ = self.session_request(chan_id, SessReq::Env { name, value }).await;
        }
        let start = match spec.command {
            Command::Shell => SessReq::Shell,
            Command::Exec(command) => SessReq::Exec { command },
            Command::Subsystem(name) => SessReq::Subsystem { name },
        };
        self.session_request(chan_id, start).await?;
        Ok(SessionChannel { chan_id, stdin: stdin_app, stdout: stdout_app, stderr: stderr_app, exit: rx, shared: self.clone() })
    }

    /// Send a session request and wait for its reply.
    pub(crate) async fn session_request(&self, chan_id: u64, req: SessReq) -> Result<()> {
        let req_id = REQ_IDS.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.session_replies.lock().unwrap().insert((chan_id, req_id), tx);
        self.send_event(Message::SessionRequest { chan_id, req_id, req }).await?;
        match rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Error::Refused(FailReason::Protocol(e))),
            Err(_) => Err(Error::CarrierLost),
        }
    }

    pub(crate) fn on_session_reply(&self, chan_id: u64, req_id: u64, error: Option<String>) {
        if let Some(tx) = self.session_replies.lock().unwrap().remove(&(chan_id, req_id)) {
            let _ = tx.send(match error {
                None => Ok(()),
                Some(e) => Err(e),
            });
        }
    }

    pub(crate) fn on_exit(&self, chan_id: u64, info: ExitInfo) {
        if let Some(ch) = self.channel_by_id(chan_id)
            && let Some(ChanExt::Client(c)) = &*ch.ext.lock().unwrap()
        {
            c.exit.send_replace(Some(info));
        }
    }

    // ------------------------------------------------------------ server

    /// Peer's ChannelOpen{Session}.
    pub(crate) fn accept_session(self: &Arc<Self>, chan_id: u64, peer_limit: u64) -> Result<()> {
        if self.server_env.is_none() {
            return self.reply_ev(Message::ChannelFail { chan_id, reason: FailReason::Prohibited });
        }
        let exited = Arc::new(ExitFlag::default());
        let ch = match self.new_channel(chan_id, 2, Completion::AfterExit(exited.clone())) {
            Ok(ch) => ch,
            Err(FailReason::Protocol(m)) => return Err(Error::Protocol(m)),
            Err(reason) => return self.reply_ev(Message::ChannelFail { chan_id, reason }),
        };
        for l in &ch.lanes {
            l.set_peer_limit(peer_limit);
        }
        let st = ServerSess { pty: Mutex::new(None), env: Mutex::new(Vec::new()), started: AtomicBool::new(false), process: tokio::sync::Mutex::new(None), exited };
        *ch.ext.lock().unwrap() = Some(ChanExt::Server(Arc::new(st)));
        let limit = ch.lanes[0].initial_limit();
        self.reply_ev(Message::ChannelOk { chan_id, limit })
    }

    pub(crate) async fn on_session_request(self: &Arc<Self>, chan_id: u64, req_id: u64, req: SessReq) -> Result<()> {
        let reply = |e: Option<String>| Message::SessionReply { chan_id, req_id, error: e };
        if self.server_env.is_none() {
            return Err(Error::Protocol("session request sent to a client".into()));
        }
        let Some(ch) = self.channel_by_id(chan_id) else {
            // Closed meanwhile; its close event is in the log.
            return self.reply_ev(reply(Some("no such channel".into())));
        };
        let sess = match &*ch.ext.lock().unwrap() {
            Some(ChanExt::Server(s)) => s.clone(),
            _ => return Err(Error::Protocol(format!("channel {chan_id} is not a session channel"))),
        };
        let result: std::result::Result<(), String> = match req {
            SessReq::Pty { term, cols, rows, xpixel, ypixel, modes } => {
                if !self.authz().allows_pty() {
                    Err("pty allocation refused by authorized_keys (no-pty/restrict)".into())
                } else if sess.started.load(Ordering::Acquire) {
                    Err("pty-req after the session started".into())
                } else {
                    *sess.pty.lock().unwrap() = Some(ssh3_session::PtyRequest { term, size: ssh3_session::WindowSize { cols, rows, xpixel, ypixel }, modes });
                    Ok(())
                }
            }
            SessReq::Env { name, value } => {
                let env = self.server_env.as_ref().unwrap();
                if env.config.accepts_env(&name) {
                    sess.env.lock().unwrap().push((name, value));
                    Ok(())
                } else {
                    Err(format!("environment variable {name} not accepted (AcceptEnv)"))
                }
            }
            SessReq::Shell => self.start_process(&ch, &sess, ssh3_session::Kind::Shell).await,
            SessReq::Exec { command } => self.start_process(&ch, &sess, ssh3_session::Kind::Exec(command)).await,
            SessReq::Subsystem { name } => self.start_process(&ch, &sess, ssh3_session::Kind::Subsystem(name)).await,
            SessReq::WindowChange { cols, rows, xpixel, ypixel } => {
                let size = ssh3_session::WindowSize { cols, rows, xpixel, ypixel };
                match &*sess.process.lock().await {
                    Some(p) => p.resize(size).map_err(|e| e.to_string()),
                    None => match &mut *sess.pty.lock().unwrap() {
                        Some(p) => {
                            p.size = size;
                            Ok(())
                        }
                        None => Err("window-change without a pty".into()),
                    },
                }
            }
            SessReq::Signal { name } => match &*sess.process.lock().await {
                Some(p) => p.signal(&name).map_err(|e| e.to_string()),
                None => Err("no process yet".into()),
            },
        };
        self.reply_ev(reply(result.err()))
    }

    async fn start_process(self: &Arc<Self>, ch: &Arc<crate::session::Channel>, sess: &Arc<ServerSess>, kind: ssh3_session::Kind) -> std::result::Result<(), String> {
        if sess.started.swap(true, Ordering::AcqRel) {
            return Err("the session already runs a process".into());
        }
        let env = self.server_env.clone().expect("checked by the caller");
        let user = ssh3_session::UserRecord::lookup(&self.user).map_err(|e| e.to_string())?;
        let connection = self.conn_addrs().map(|(remote, local_ip)| ssh3_session::ConnectionInfo {
            remote_ip: remote.ip().to_canonical().to_string(),
            remote_port: remote.port(),
            local_ip: local_ip.map(|i| i.to_canonical().to_string()).unwrap_or_default(),
            local_port: env.local_port,
        });
        let pty = sess.pty.lock().unwrap().clone();
        let has_pty = pty.is_some();
        let req = ssh3_session::SessionRequest {
            user,
            kind,
            pty,
            env: std::mem::take(&mut *sess.env.lock().unwrap()),
            forced_command: self.authz().forced_command().map(str::to_owned),
            connection,
            auth_sock: self.agent_socket_path(),
        };
        let mut p = ssh3_session::spawn(&env.config, &req).map_err(|e| e.to_string())?;
        let stdin = p.take_stdin().ok_or("process has no stdin")?;
        let stdout = p.take_stdout().ok_or("process has no stdout")?;
        let stderr = p.take_stderr();
        if has_pty {
            ch.lanes[0].set_overflow((env.overflow)());
            self.note_pty();
        }
        self.start_io(ch, 0, stdout, stdin);
        match stderr {
            Some(e) => self.start_io(ch, 1, e, tokio::io::sink()),
            None => self.start_io(ch, 1, tokio::io::empty(), tokio::io::sink()),
        }
        let pid = p.pid();
        *sess.process.lock().await = Some(p);
        // Exit watcher: exit-status/exit-signal as an event, then let the
        // supervisor finish the channel once the output is delivered.
        let me = Arc::downgrade(self);
        let sess = sess.clone();
        let chan_id = ch.chan_id;
        ch.spawn(async move {
            if let Err(e) = exited(pid).await {
                tracing::warn!(pid, "cannot watch the session process: {e}");
                return;
            }
            let exit = match sess.process.lock().await.as_mut() {
                Some(p) => p.wait().await,
                None => return,
            };
            let Some(s) = me.upgrade() else { return };
            let m = match exit {
                Ok(ssh3_session::Exit::Status(status)) => Message::ExitStatus { chan_id, status },
                Ok(ssh3_session::Exit::Signal { name, core_dumped }) => Message::ExitSignal { chan_id, signal: name.to_string(), core_dumped },
                Err(e) => {
                    tracing::warn!(pid, "waiting for the session process: {e}");
                    return;
                }
            };
            let _ = s.send_event(m).await;
            sess.exited.set();
        });
        Ok(())
    }
}
