//! Account records (`getpwnam_r`) and the supplementary group list
//! (`getgrouplist`), resolved in the parent so that the child between fork
//! and exec only performs async-signal-safe system calls.

use std::ffi::{CStr, CString};
use std::path::PathBuf;

use crate::Error;

/// The target account of a session, as `struct passwd` describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    /// Login shell; empty means `/bin/sh` (OpenSSH `_PATH_BSHELL`).
    pub shell: PathBuf,
}

impl UserRecord {
    /// Look the account up in the system user database.
    pub fn lookup(name: &str) -> Result<Self, Error> {
        let cname = CString::new(name).map_err(|_| Error::User(format!("user name {name:?} contains NUL")))?;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
            let mut out: *mut libc::passwd = std::ptr::null_mut();
            let rc = unsafe {
                libc::getpwnam_r(cname.as_ptr(), &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut out)
            };
            if rc == libc::ERANGE && buf.len() < 1 << 20 {
                buf.resize(buf.len() * 2, 0);
                continue;
            }
            if rc != 0 {
                return Err(Error::User(format!(
                    "getpwnam_r({name}) failed: {}",
                    std::io::Error::from_raw_os_error(rc)
                )));
            }
            if out.is_null() {
                return Err(Error::User(format!("no such user {name:?}")));
            }
            let s = |p: *const libc::c_char| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
            return Ok(UserRecord {
                name: s(pw.pw_name),
                uid: pw.pw_uid,
                gid: pw.pw_gid,
                home: PathBuf::from(s(pw.pw_dir)),
                shell: PathBuf::from(s(pw.pw_shell)),
            });
        }
    }

    /// The shell to execute: the passwd shell, or `/bin/sh` when empty.
    pub fn login_shell(&self) -> PathBuf {
        if self.shell.as_os_str().is_empty() { PathBuf::from("/bin/sh") } else { self.shell.clone() }
    }

    /// Supplementary groups as `initgroups(3)` would set them: the primary
    /// gid plus every group listing the user as a member.
    pub fn group_list(&self) -> Result<Vec<libc::gid_t>, Error> {
        let cname = CString::new(self.name.as_str())
            .map_err(|_| Error::User(format!("user name {:?} contains NUL", self.name)))?;
        let mut n: libc::c_int = 32;
        loop {
            let mut groups = vec![0 as libc::gid_t; n as usize];
            let mut count = n;
            let rc = unsafe { libc::getgrouplist(cname.as_ptr(), self.gid, groups.as_mut_ptr(), &mut count) };
            if rc >= 0 {
                groups.truncate(count as usize);
                return Ok(groups);
            }
            if count <= n {
                // glibc reports the needed size in `count`; grow geometrically
                // if it did not.
                n = n.saturating_mul(2);
            } else {
                n = count;
            }
            if n > 1 << 16 {
                return Err(Error::User(format!("getgrouplist({}) did not converge", self.name)));
            }
        }
    }
}

/// gid of the `tty` group, used as the pty group (OpenSSH `pty_setowner`).
pub(crate) fn tty_group() -> Option<libc::gid_t> {
    let mut buf = vec![0u8; 16 * 1024];
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe { libc::getgrnam_r(c"tty".as_ptr(), &mut gr, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() { None } else { Some(gr.gr_gid) }
}
