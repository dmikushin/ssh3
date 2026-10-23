//! The client's local terminal: raw mode (restored on drop, so on every
//! return and unwind), window size, RFC 4254 terminal modes, and the
//! "Last contact" status line.

use std::io::Write as _;
use std::os::fd::RawFd;
use std::time::Duration;

/// The terminal in raw mode while this lives; the saved settings are put
/// back by `Drop`, which runs on every return path and on panic unwind
/// (release profile is `panic = "unwind"`).
pub struct RawMode {
    fd: RawFd,
    saved: libc::termios,
}

impl RawMode {
    pub fn enter(fd: RawFd) -> std::io::Result<Self> {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let saved = t;
        unsafe { libc::cfmakeraw(&mut t) };
        if unsafe { libc::tcsetattr(fd, libc::TCSADRAIN, &t) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { fd, saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSADRAIN, &self.saved) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub cols: u32,
    pub rows: u32,
    pub xpixel: u32,
    pub ypixel: u32,
}

pub fn size(fd: RawFd) -> Option<Size> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } != 0 || ws.ws_col == 0 {
        return None;
    }
    Some(Size { cols: ws.ws_col.into(), rows: ws.ws_row.into(), xpixel: ws.ws_xpixel.into(), ypixel: ws.ws_ypixel.into() })
}

/// The terminal modes of `fd` encoded as RFC 4254 §8 (opcode, u32 value),
/// the subset OpenSSH's ttymodes.h sends that the receiving side
/// (ssh3-session) applies. Empty if `fd` is not a terminal.
pub fn modes(fd: RawFd) -> Vec<u8> {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut put = |op: u8, v: u32| {
        out.push(op);
        out.extend_from_slice(&v.to_be_bytes());
    };
    for (op, idx) in [
        (1, libc::VINTR),
        (2, libc::VQUIT),
        (3, libc::VERASE),
        (4, libc::VKILL),
        (5, libc::VEOF),
        (6, libc::VEOL),
        (7, libc::VEOL2),
        (8, libc::VSTART),
        (9, libc::VSTOP),
        (10, libc::VSUSP),
        (12, libc::VREPRINT),
        (13, libc::VWERASE),
        (14, libc::VLNEXT),
    ] {
        put(op, t.c_cc[idx].into());
    }
    let flag = |set: libc::tcflag_t, bit: libc::tcflag_t| u32::from(set & bit != 0);
    for (op, set, bit) in [
        (30, t.c_iflag, libc::IGNPAR),
        (31, t.c_iflag, libc::PARMRK),
        (32, t.c_iflag, libc::INPCK),
        (33, t.c_iflag, libc::ISTRIP),
        (34, t.c_iflag, libc::INLCR),
        (35, t.c_iflag, libc::IGNCR),
        (36, t.c_iflag, libc::ICRNL),
        (38, t.c_iflag, libc::IXON),
        (39, t.c_iflag, libc::IXANY),
        (40, t.c_iflag, libc::IXOFF),
        (41, t.c_iflag, libc::IMAXBEL),
        (42, t.c_iflag, libc::IUTF8),
        (50, t.c_lflag, libc::ISIG),
        (51, t.c_lflag, libc::ICANON),
        (53, t.c_lflag, libc::ECHO),
        (54, t.c_lflag, libc::ECHOE),
        (55, t.c_lflag, libc::ECHOK),
        (56, t.c_lflag, libc::ECHONL),
        (57, t.c_lflag, libc::NOFLSH),
        (58, t.c_lflag, libc::TOSTOP),
        (59, t.c_lflag, libc::IEXTEN),
        (60, t.c_lflag, libc::ECHOCTL),
        (61, t.c_lflag, libc::ECHOKE),
        (62, t.c_lflag, libc::PENDIN),
        (70, t.c_oflag, libc::OPOST),
        (72, t.c_oflag, libc::ONLCR),
        (73, t.c_oflag, libc::OCRNL),
        (74, t.c_oflag, libc::ONOCR),
        (75, t.c_oflag, libc::ONLRET),
        (90, t.c_cflag, libc::CS7),
        (91, t.c_cflag, libc::CS8),
        (92, t.c_cflag, libc::PARENB),
        (93, t.c_cflag, libc::PARODD),
    ] {
        put(op, flag(set, bit));
    }
    put(128, unsafe { libc::cfgetispeed(&t) });
    put(129, unsafe { libc::cfgetospeed(&t) });
    out.push(0);
    out
}

/// Where the "Last contact" line is drawn.
#[derive(Clone, Copy)]
pub enum StatusLine {
    /// stderr is a terminal in cooked mode: a line of its own, rewritten
    /// in place.
    Cooked,
    /// A raw-mode pty session: drawn in reverse video on the bottom row
    /// with the cursor saved and restored, so the remote screen keeps its
    /// cursor. Clearing it leaves that row blank until the remote redraws.
    BottomRow,
}

impl StatusLine {
    pub fn show(self, silent_for: Duration) {
        let msg = format!("ssh3: Last contact {} s ago", silent_for.as_secs());
        let s = match self {
            StatusLine::Cooked => format!("\r\x1b[K{msg}"),
            StatusLine::BottomRow => {
                let rows = size(libc::STDERR_FILENO).map_or(24, |s| s.rows);
                format!("\x1b7\x1b[{rows};1H\x1b[7m {msg} \x1b[0m\x1b[K\x1b8")
            }
        };
        let mut e = std::io::stderr();
        let _ = e.write_all(s.as_bytes());
        let _ = e.flush();
    }

    pub fn clear(self) {
        let s = match self {
            StatusLine::Cooked => "\r\x1b[K".to_string(),
            StatusLine::BottomRow => {
                let rows = size(libc::STDERR_FILENO).map_or(24, |s| s.rows);
                format!("\x1b7\x1b[{rows};1H\x1b[K\x1b8")
            }
        };
        let mut e = std::io::stderr();
        let _ = e.write_all(s.as_bytes());
        let _ = e.flush();
    }
}

/// Shows the status line while the server has been silent for at least
/// `warn`, refreshing once a second while shown, and clears it when contact
/// returns. Sleeps until the next deadline in between — no polling.
pub async fn contact_watch(last_contact: impl Fn() -> std::time::Instant, warn: Duration, line: StatusLine) {
    let mut shown = false;
    loop {
        let silent = last_contact().elapsed();
        if silent < warn {
            if shown {
                line.clear();
                shown = false;
            }
            tokio::time::sleep(warn - silent).await;
            continue;
        }
        line.show(silent);
        shown = true;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_of_a_non_tty_are_empty() {
        let (r, _w) = std::io::pipe().unwrap();
        use std::os::fd::AsRawFd;
        assert!(modes(r.as_raw_fd()).is_empty());
    }
}
