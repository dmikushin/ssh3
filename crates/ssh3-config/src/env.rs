//! The local facts OpenSSH reads from the system while resolving a
//! configuration: the invoking user, its home directory, the host name.

use nix::unistd::{Uid, User};

#[derive(Debug, Clone)]
pub struct LocalEnv {
    /// `pw->pw_name` of the invoking uid (`%u`, default remote user).
    pub user: String,
    /// `pw->pw_uid` (`%i`).
    pub uid: u32,
    /// `pw->pw_dir` (`%d`, `~`).
    pub home: String,
    /// `gethostname()` (`%l`; `%L` is the part before the first dot).
    pub hostname: String,
    /// `$SHELL` or `/bin/sh`, used for `Match exec`.
    pub shell: String,
    /// Port used when neither the command line nor the config sets one.
    /// OpenSSH uses 22 (`default_ssh_port()`); ssh3 uses its own default.
    pub default_port: u16,
}

impl LocalEnv {
    /// Read the facts from the running system, as `ssh` does at startup.
    pub fn from_system(default_port: u16) -> Result<Self, String> {
        let uid = Uid::current();
        let pw = User::from_uid(uid)
            .map_err(|e| format!("getpwuid({uid}): {e}"))?
            .ok_or_else(|| format!("No user exists for uid {uid}"))?;
        let hostname = nix::unistd::gethostname()
            .map_err(|e| format!("gethostname: {e}"))?
            .to_string_lossy()
            .into_owned();
        Ok(LocalEnv {
            user: pw.name,
            uid: uid.as_raw(),
            home: pw.dir.to_string_lossy().into_owned(),
            hostname,
            shell: std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()),
            default_port,
        })
    }

    /// Home directory of another local user (`~user`).
    pub fn home_of(&self, user: &str) -> Option<String> {
        if user == self.user {
            return Some(self.home.clone());
        }
        User::from_name(user)
            .ok()
            .flatten()
            .map(|u| u.dir.to_string_lossy().into_owned())
    }

    /// `%L`: host name up to the first dot.
    pub fn short_hostname(&self) -> &str {
        self.hostname.split('.').next().unwrap_or("")
    }

    #[cfg(test)]
    pub(crate) fn for_tests(home: &str) -> Self {
        LocalEnv {
            user: "t".into(),
            uid: 1000,
            home: home.into(),
            hostname: "box.example".into(),
            shell: "/bin/sh".into(),
            default_port: 22,
        }
    }
}
