//! Pseudo-terminal allocation, RFC 4254 §8 terminal modes (as OpenSSH
//! `ssh_tty_parse_modes`), window size, and an async master.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Error, WindowSize};

pub(crate) struct Pty {
    pub master: OwnedFd,
    pub slave: OwnedFd,
    pub path: String,
}

fn cvt(rc: libc::c_int, what: &str) -> Result<libc::c_int, Error> {
    if rc == -1 { Err(Error::Os(what.to_owned(), io::Error::last_os_error())) } else { Ok(rc) }
}

pub(crate) fn allocate() -> Result<Pty, Error> {
    let m = cvt(unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) }, "posix_openpt")?;
    let master = unsafe { OwnedFd::from_raw_fd(m) };
    cvt(unsafe { libc::grantpt(m) }, "grantpt")?;
    cvt(unsafe { libc::unlockpt(m) }, "unlockpt")?;
    let mut name = [0 as libc::c_char; 128];
    let rc = unsafe { libc::ptsname_r(m, name.as_mut_ptr(), name.len()) };
    if rc != 0 {
        return Err(Error::Os("ptsname_r".into(), io::Error::from_raw_os_error(rc)));
    }
    let path = unsafe { CStr::from_ptr(name.as_ptr()) }.to_string_lossy().into_owned();
    let s = cvt(unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) }, "open pty slave")?;
    let slave = unsafe { OwnedFd::from_raw_fd(s) };
    Ok(Pty { master, slave, path })
}

/// `TIOCSWINSZ` on the master; the kernel delivers SIGWINCH to the
/// foreground process group of the terminal.
pub(crate) fn set_window_size(fd: RawFd, ws: WindowSize) -> Result<(), Error> {
    let w = libc::winsize { ws_row: clamp16(ws.rows), ws_col: clamp16(ws.cols), ws_xpixel: clamp16(ws.xpixel), ws_ypixel: clamp16(ws.ypixel) };
    cvt(unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &w) }, "ioctl(TIOCSWINSZ)")?;
    Ok(())
}

fn clamp16(v: u32) -> u16 {
    v.min(u16::MAX as u32) as u16
}

const TTY_OP_END: u8 = 0;
const TTY_OP_ISPEED: u8 = 128;
const TTY_OP_OSPEED: u8 = 129;

enum Field {
    I,
    L,
    O,
    C,
}

/// Opcode table of OpenSSH ttymodes.h restricted to what Linux defines.
fn char_index(op: u8) -> Option<usize> {
    Some(match op {
        1 => libc::VINTR,
        2 => libc::VQUIT,
        3 => libc::VERASE,
        4 => libc::VKILL,
        5 => libc::VEOF,
        6 => libc::VEOL,
        7 => libc::VEOL2,
        8 => libc::VSTART,
        9 => libc::VSTOP,
        10 => libc::VSUSP,
        12 => libc::VREPRINT,
        13 => libc::VWERASE,
        14 => libc::VLNEXT,
        18 => libc::VDISCARD,
        _ => return None,
    })
}

fn mode_flag(op: u8) -> Option<(Field, libc::tcflag_t)> {
    use Field::*;
    Some(match op {
        30 => (I, libc::IGNPAR),
        31 => (I, libc::PARMRK),
        32 => (I, libc::INPCK),
        33 => (I, libc::ISTRIP),
        34 => (I, libc::INLCR),
        35 => (I, libc::IGNCR),
        36 => (I, libc::ICRNL),
        37 => (I, libc::IUCLC),
        38 => (I, libc::IXON),
        39 => (I, libc::IXANY),
        40 => (I, libc::IXOFF),
        41 => (I, libc::IMAXBEL),
        42 => (I, libc::IUTF8),
        50 => (L, libc::ISIG),
        51 => (L, libc::ICANON),
        52 => (L, libc::XCASE),
        53 => (L, libc::ECHO),
        54 => (L, libc::ECHOE),
        55 => (L, libc::ECHOK),
        56 => (L, libc::ECHONL),
        57 => (L, libc::NOFLSH),
        58 => (L, libc::TOSTOP),
        59 => (L, libc::IEXTEN),
        60 => (L, libc::ECHOCTL),
        61 => (L, libc::ECHOKE),
        62 => (L, libc::PENDIN),
        70 => (O, libc::OPOST),
        71 => (O, libc::OLCUC),
        72 => (O, libc::ONLCR),
        73 => (O, libc::OCRNL),
        74 => (O, libc::ONOCR),
        75 => (O, libc::ONLRET),
        90 => (C, libc::CS7),
        91 => (C, libc::CS8),
        92 => (C, libc::PARENB),
        93 => (C, libc::PARODD),
        _ => return None,
    })
}

fn baud_to_speed(baud: u32) -> Option<libc::speed_t> {
    Some(match baud {
        0 => libc::B0,
        50 => libc::B50,
        75 => libc::B75,
        110 => libc::B110,
        134 => libc::B134,
        150 => libc::B150,
        200 => libc::B200,
        300 => libc::B300,
        600 => libc::B600,
        1200 => libc::B1200,
        1800 => libc::B1800,
        2400 => libc::B2400,
        4800 => libc::B4800,
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115200 => libc::B115200,
        230400 => libc::B230400,
        _ => return None,
    })
}

/// Apply an encoded terminal-modes string to `fd`, with OpenSSH's parsing
/// rules: opcodes 1..159 carry a u32, 160..255 stop parsing, `TTY_OP_END`
/// ends the list; unknown opcodes in 1..159 are skipped. Malformed input
/// (truncated argument) leaves the terminal unchanged.
pub(crate) fn apply_modes(fd: RawFd, modes: &[u8]) -> Result<(), Error> {
    if modes.is_empty() {
        return Ok(());
    }
    let mut tio: libc::termios = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::tcgetattr(fd, &mut tio) }, "tcgetattr")?;
    let mut i = 0;
    let arg = |i: usize| -> Result<u32, Error> {
        modes
            .get(i..i + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| Error::Protocol("truncated terminal mode argument".into()))
    };
    while i < modes.len() {
        let op = modes[i];
        i += 1;
        match op {
            // OpenSSH stops at END or at an opcode >= 160 and applies the
            // modes only if nothing follows (`len > 0` → "bytes left",
            // modes discarded).
            TTY_OP_END | 160..=255 if i < modes.len() => return Ok(()),
            TTY_OP_END => break,
            TTY_OP_ISPEED | TTY_OP_OSPEED => {
                let baud = arg(i)?;
                i += 4;
                if let Some(sp) = baud_to_speed(baud) {
                    unsafe {
                        if op == TTY_OP_ISPEED { libc::cfsetispeed(&mut tio, sp) } else { libc::cfsetospeed(&mut tio, sp) };
                    }
                }
            }
            1..=159 => {
                let v = arg(i)?;
                i += 4;
                if let Some(idx) = char_index(op) {
                    // special_char_decode: 255 means "disabled".
                    tio.c_cc[idx] = if v == 255 { 0 } else { v as libc::cc_t };
                } else if let Some((field, flag)) = mode_flag(op) {
                    let f = match field {
                        Field::I => &mut tio.c_iflag,
                        Field::L => &mut tio.c_lflag,
                        Field::O => &mut tio.c_oflag,
                        Field::C => &mut tio.c_cflag,
                    };
                    if v != 0 { *f |= flag } else { *f &= !flag }
                }
            }
            _ => break,
        }
    }
    cvt(unsafe { libc::tcsetattr(fd, libc::TCSANOW, &tio) }, "tcsetattr")?;
    Ok(())
}

/// Async view of the pty master shared by the reader and writer halves.
pub(crate) struct Master(AsyncFd<OwnedFd>);

impl Master {
    pub(crate) fn new(fd: OwnedFd) -> Result<Arc<Self>, Error> {
        let raw = fd.as_raw_fd();
        let fl = cvt(unsafe { libc::fcntl(raw, libc::F_GETFL) }, "fcntl(F_GETFL)")?;
        cvt(unsafe { libc::fcntl(raw, libc::F_SETFL, fl | libc::O_NONBLOCK) }, "fcntl(F_SETFL)")?;
        // SAFETY: an OwnedFd keeps its descriptor open and unchanged for the
        // AsyncFd's lifetime.
        let afd = unsafe { AsyncFd::register(fd) }.map_err(|e| Error::Os("register pty master".into(), e.into_parts().1))?;
        Ok(Arc::new(Master(afd)))
    }
    pub(crate) fn raw(&self) -> RawFd {
        self.0.get_ref().as_raw_fd()
    }
}

/// Output of the terminal (child stdout and stderr merged by the tty).
pub struct PtyReader(pub(crate) Arc<Master>);
/// Input of the terminal.
pub struct PtyWriter(pub(crate) Arc<Master>);

impl AsyncRead for PtyReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.0.poll_read_ready(cx))?;
            let dst = buf.initialize_unfilled();
            let n = unsafe { libc::read(guard.get_inner().as_raw_fd(), dst.as_mut_ptr().cast(), dst.len()) };
            if n >= 0 {
                buf.advance(n as usize);
                return Poll::Ready(Ok(()));
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                // Linux reports EIO on the master once no process holds the
                // slave open any more: that is end of output.
                Some(libc::EIO) => return Poll::Ready(Ok(())),
                Some(libc::EAGAIN) => guard.clear_ready(),
                Some(libc::EINTR) => {}
                _ => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for PtyWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.0.poll_write_ready(cx))?;
            let n = unsafe { libc::write(guard.get_inner().as_raw_fd(), data.as_ptr().cast(), data.len()) };
            if n >= 0 {
                return Poll::Ready(Ok(n as usize));
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EAGAIN) => guard.clear_ready(),
                Some(libc::EINTR) => {}
                _ => return Poll::Ready(Err(e)),
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    /// End of input on a pty does not reach the child: OpenSSH closes only
    /// its own duplicate of the master (`chan_shutdown_write`), and the
    /// terminal stays open through the reader's descriptor. The client sends
    /// the EOF character itself when it wants the child to see one.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
