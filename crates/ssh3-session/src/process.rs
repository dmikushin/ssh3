//! Fork/exec of the session process and its owned lifetime.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::pty::{self, Master, PtyReader, PtyWriter};
use crate::{Error, Kind, SessionConfig, SessionRequest, WindowSize, env, signal_name, name_to_signal, user};

/// How the session's leader process ended (RFC 4254 §6.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    /// `exit-status`.
    Status(u32),
    /// `exit-signal`: signal name without "SIG", core dump flag.
    Signal { name: &'static str, core_dumped: bool },
}

type Writer = Box<dyn AsyncWrite + Send + Unpin>;
type Reader = Box<dyn AsyncRead + Send + Unpin>;

/// A running session process. Dropping it hangs up and kills the process
/// group and reaps the leader.
pub struct SessionProcess {
    pid: libc::pid_t,
    pidfd: Option<AsyncFd<OwnedFd>>,
    exit: Option<Exit>,
    master: Option<Arc<Master>>,
    tty: Option<String>,
    stdin: Option<Writer>,
    stdout: Option<Reader>,
    stderr: Option<Reader>,
    /// Why signals are refused (forced command / subsystem), as OpenSSH.
    signal_refusal: Option<&'static str>,
    drop_grace: Duration,
}

/// Values the child needs between fork and exec, prepared in the parent so
/// that the child performs only async-signal-safe system calls.
struct ChildSetup {
    pty: bool,
    /// `Some` when running as root: switch to these credentials.
    creds: Option<(libc::uid_t, libc::gid_t, Vec<libc::gid_t>)>,
    home: CString,
    chdir_failed_msg: Vec<u8>,
}

fn os(what: &str) -> impl FnOnce(io::Error) -> Error + '_ {
    move |e| Error::Os(what.to_owned(), e)
}

fn child_setup(s: &ChildSetup) -> io::Result<()> {
    unsafe {
        // New session and process group (OpenSSH: "setsid() since the 4.4BSD
        // setlogin() affects the entire process group").
        if libc::setsid() == -1 {
            return Err(io::Error::last_os_error());
        }
        if s.pty && libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
            return Err(io::Error::last_os_error());
        }
        if let Some((uid, gid, groups)) = &s.creds {
            // OpenSSH do_setusercontext order: setgid, initgroups, then
            // permanently_set_uid. setgroups needs CAP_SETGID, so it runs
            // before setuid; the group list was resolved in the parent.
            if libc::setgid(*gid) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgroups(groups.len(), groups.as_ptr()) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::setuid(*uid) == -1 {
                return Err(io::Error::last_os_error());
            }
            // permanently_set_uid: verify the switch and that it is not
            // reversible.
            if libc::getuid() != *uid || libc::geteuid() != *uid || libc::getgid() != *gid || libc::getegid() != *gid {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            if *uid != 0 && libc::setuid(0) != -1 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
        }
        // Change to the home directory as the user; failure is reported to
        // the session's stderr and is not fatal (OpenSSH do_child).
        if libc::chdir(s.home.as_ptr()) == -1 {
            libc::write(2, s.chdir_failed_msg.as_ptr().cast(), s.chdir_failed_msg.len());
        }
        // Inherited descriptors above stderr must not reach the user's
        // program (OpenSSH closefrom). Mark them close-on-exec rather than
        // closing them, so std's exec-error pipe keeps working.
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
        libc::syscall(libc::SYS_close_range, 3 as libc::c_uint, libc::c_uint::MAX, CLOSE_RANGE_CLOEXEC);
    }
    Ok(())
}

pub(crate) fn spawn(cfg: &SessionConfig, req: &SessionRequest) -> Result<SessionProcess, Error> {
    let user = &req.user;
    let (command, original_command, refusal): (Option<String>, Option<&str>, Option<&'static str>) =
        match (&req.forced_command, &req.kind) {
            (Some(forced), kind) => {
                let orig = match kind {
                    Kind::Exec(c) => Some(c.as_str()),
                    _ => None,
                };
                (Some(forced.clone()), orig, Some("forced-command"))
            }
            (None, Kind::Shell) => (None, None, None),
            (None, Kind::Exec(c)) => (Some(c.clone()), None, None),
            (None, Kind::Subsystem(name)) => {
                let cmd = cfg.subsystems.get(name).ok_or_else(|| Error::UnknownSubsystem(name.clone()))?;
                (Some(cmd.clone()), None, Some("subsystem"))
            }
        };

    // Credentials: as root, switch to the target account; otherwise the
    // target must be the current user (OpenSSH fatal "Failed to set uids").
    let euid = unsafe { libc::geteuid() };
    let creds = if euid == 0 {
        Some((user.uid, user.gid, user.group_list()?))
    } else {
        let uid = unsafe { libc::getuid() };
        if uid != user.uid || euid != user.uid {
            return Err(Error::Privilege(format!(
                "running as uid {uid}/euid {euid} without privileges, cannot start a session as {} (uid {})",
                user.name, user.uid
            )));
        }
        None
    };

    let shell = user.login_shell();
    let shell_str = shell.to_string_lossy().into_owned();
    let shell0 = shell.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| shell_str.clone());

    let pty = match &req.pty {
        Some(p) => {
            let pty = pty::allocate()?;
            if euid == 0 {
                // pty_setowner: owner = user, group tty with 0620, else the
                // user's group with 0600.
                let (gid, mode) = match user::tty_group() {
                    Some(g) => (g, 0o620),
                    None => (user.gid, 0o600),
                };
                let path = CString::new(pty.path.as_str()).expect("pts path has no NUL");
                if unsafe { libc::chown(path.as_ptr(), user.uid, gid) } == -1 {
                    return Err(Error::Os(format!("chown({}, {}, {gid})", pty.path, user.uid), io::Error::last_os_error()));
                }
                if unsafe { libc::chmod(path.as_ptr(), mode) } == -1 {
                    return Err(Error::Os(format!("chmod({}, {mode:o})", pty.path), io::Error::last_os_error()));
                }
            }
            pty::apply_modes(pty.slave.as_raw_fd(), &p.modes)?;
            pty::set_window_size(pty.master.as_raw_fd(), p.size)?;
            Some(pty)
        }
        None => None,
    };

    let env = env::build(cfg, req, &shell_str, pty.as_ref().map(|p| p.path.as_str()), original_command);

    let mut cmd = Command::new(&shell);
    match &command {
        None => {
            cmd.arg0(format!("-{shell0}"));
        }
        Some(c) => {
            cmd.arg0(&shell0).arg("-c").arg(c);
        }
    }
    cmd.env_clear().envs(env.into_vec());
    match &pty {
        Some(p) => {
            let dup = |what| p.slave.try_clone().map_err(os(what));
            cmd.stdin(Stdio::from(dup("dup pty slave")?))
                .stdout(Stdio::from(dup("dup pty slave")?))
                .stderr(Stdio::from(dup("dup pty slave")?));
        }
        None => {
            cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        }
    }
    let home = CString::new(user.home.as_os_str().as_bytes())
        .map_err(|_| Error::User(format!("home of {} contains NUL", user.name)))?;
    let setup = ChildSetup {
        pty: pty.is_some(),
        creds,
        chdir_failed_msg: format!("Could not chdir to home directory {}\n", user.home.display()).into_bytes(),
        home,
    };
    unsafe {
        cmd.pre_exec(move || child_setup(&setup));
    }
    let mut child = cmd.spawn().map_err(|e| Error::Os(format!("spawn {shell_str}"), e))?;
    drop(cmd); // closes the parent's copies of the pty slave
    let pid = child.id() as libc::pid_t;

    // The leader stays unreaped until drop, so `pid` keeps naming this
    // process (and its process group) for our whole lifetime.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if pidfd == -1 {
        let e = io::Error::last_os_error();
        unsafe { libc::kill(pid, libc::SIGKILL) };
        return Err(Error::Os("pidfd_open".into(), e));
    }
    // SAFETY: an OwnedFd keeps its descriptor open and unchanged for the
    // AsyncFd's lifetime.
    let pidfd = unsafe {
        AsyncFd::register_with_interest(OwnedFd::from_raw_fd(pidfd as i32), tokio::io::Interest::READABLE)
    }
    .map_err(|e| Error::Os("register pidfd".into(), e.into_parts().1))?;

    let mut proc = SessionProcess {
        pid,
        pidfd: Some(pidfd),
        exit: None,
        master: None,
        tty: None,
        stdin: None,
        stdout: None,
        stderr: None,
        signal_refusal: refusal,
        drop_grace: cfg.drop_grace,
    };
    match pty {
        Some(p) => {
            drop(p.slave);
            let master = Master::new(p.master)?;
            proc.stdin = Some(Box::new(PtyWriter(master.clone())));
            proc.stdout = Some(Box::new(PtyReader(master.clone())));
            proc.master = Some(master);
            proc.tty = Some(p.path);
        }
        None => {
            let stdin = tokio::process::ChildStdin::from_std(child.stdin.take().expect("piped")).map_err(os("stdin"))?;
            let stdout = tokio::process::ChildStdout::from_std(child.stdout.take().expect("piped")).map_err(os("stdout"))?;
            let stderr = tokio::process::ChildStderr::from_std(child.stderr.take().expect("piped")).map_err(os("stderr"))?;
            proc.stdin = Some(Box::new(stdin));
            proc.stdout = Some(Box::new(stdout));
            proc.stderr = Some(Box::new(stderr));
        }
    }
    // std's Child neither kills nor reaps on drop; the pidfd owns the
    // lifetime from here on.
    drop(child);
    Ok(proc)
}

/// Non-blocking (`WNOHANG`) or blocking observation of the leader's exit.
/// `WNOWAIT` leaves it a zombie (not reaped).
fn waitid(pid: libc::pid_t, flags: libc::c_int) -> io::Result<Option<Exit>> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | flags) };
        if rc == -1 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        break;
    }
    if unsafe { info.si_pid() } == 0 {
        return Ok(None);
    }
    let status = unsafe { info.si_status() };
    Ok(Some(match info.si_code {
        libc::CLD_EXITED => Exit::Status(status as u32),
        libc::CLD_DUMPED => Exit::Signal { name: signal_name(status), core_dumped: true },
        _ => Exit::Signal { name: signal_name(status), core_dumped: false },
    }))
}

impl SessionProcess {
    /// Process id of the leader (also its process-group id).
    pub fn pid(&self) -> u32 {
        self.pid as u32
    }

    /// Slave path when a pty was allocated.
    pub fn tty(&self) -> Option<&str> {
        self.tty.as_deref()
    }

    /// Child input. With a pty, shutting it down does not deliver EOF to the
    /// child (as OpenSSH); without, it closes the child's stdin pipe.
    pub fn take_stdin(&mut self) -> Option<Box<dyn AsyncWrite + Send + Unpin>> {
        self.stdin.take()
    }

    /// Child output; with a pty, stdout and stderr merged by the terminal.
    pub fn take_stdout(&mut self) -> Option<Box<dyn AsyncRead + Send + Unpin>> {
        self.stdout.take()
    }

    /// Child stderr; `None` with a pty.
    pub fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Send + Unpin>> {
        self.stderr.take()
    }

    /// `window-change`.
    pub fn resize(&self, size: WindowSize) -> Result<(), Error> {
        let m = self.master.as_ref().ok_or(Error::NoPty)?;
        pty::set_window_size(m.raw(), size)
    }

    /// `signal`: deliver to the session's process group (OpenSSH killpg).
    pub fn signal(&self, name: &str) -> Result<(), Error> {
        if let Some(kind) = self.signal_refusal {
            return Err(Error::SignalRefused(kind));
        }
        let sig = name_to_signal(name).ok_or_else(|| Error::UnknownSignal(name.to_owned()))?;
        if unsafe { libc::killpg(self.pid, sig) } == -1 {
            return Err(Error::Os(format!("killpg({}, {name})", self.pid), io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Wait for the leader to exit. Output may still be pending in the
    /// readers (and other group members may keep the streams open), exactly
    /// as with OpenSSH, which sends exit-status before the channel's EOF.
    pub async fn wait(&mut self) -> Result<Exit, Error> {
        if let Some(e) = &self.exit {
            return Ok(e.clone());
        }
        let pidfd = self.pidfd.as_ref().expect("pidfd present until drop");
        loop {
            let mut guard = pidfd.readable().await.map_err(os("wait for pidfd"))?;
            if let Some(exit) = waitid(self.pid, libc::WNOHANG | libc::WNOWAIT).map_err(os("waitid"))? {
                self.exit = Some(exit.clone());
                return Ok(exit);
            }
            guard.clear_ready();
        }
    }
}

/// SIGKILL the process group and the leader itself, then reap the leader on
/// a short-lived thread. Never blocks the caller: Drop and runtime shutdown
/// stay non-blocking. The leader is killed directly as well, so its death —
/// and therefore the reap — does not depend on it still leading the group.
fn kill_and_reap(pid: libc::pid_t) {
    unsafe {
        libc::killpg(pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = std::thread::Builder::new().name(format!("ssh3-reap-{pid}")).spawn(move || {
        let _ = waitid(pid, 0);
    });
}

/// Escalates to [`kill_and_reap`] when dropped: at the end of the grace
/// period, or when the grace task is cancelled (runtime shutdown).
struct Escalate(libc::pid_t);

impl Drop for Escalate {
    fn drop(&mut self) {
        kill_and_reap(self.0);
    }
}

impl Drop for SessionProcess {
    fn drop(&mut self) {
        let pid = self.pid;
        if self.pidfd.take().is_none() {
            return;
        }
        // The leader is not reaped yet, so the process group id cannot have
        // been reused: signalling it reaches only this session's processes.
        // The leader is reaped only after SIGKILL has been sent.
        unsafe { libc::killpg(pid, libc::SIGHUP) };
        let escalate = Escalate(pid);
        let leader_exited = self.exit.is_some() || matches!(waitid(pid, libc::WNOHANG | libc::WNOWAIT), Ok(Some(_)));
        if leader_exited {
            // The session is over: no grace for leftover group members.
            return; // `escalate` drops here
        }
        let grace = self.drop_grace;
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn(async move {
                let _escalate = escalate;
                tokio::time::sleep(grace).await;
            });
        }
        // Without a runtime `escalate` drops here: immediate SIGKILL.
    }
}
