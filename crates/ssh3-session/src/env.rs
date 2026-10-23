//! Child environment, built in the order of OpenSSH `do_setup_env`
//! (session.c): accepted client variables first, then the login variables,
//! which therefore override anything the client sent under the same name.

use crate::{ConnectionInfo, SessionConfig, SessionRequest};

/// OpenSSH `match_pattern`: `*` matches any run, `?` one character.
pub fn match_pattern(s: &str, pattern: &str) -> bool {
    fn m(s: &[u8], p: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => (0..=s.len()).any(|i| m(&s[i..], rest)),
            Some((b'?', rest)) => !s.is_empty() && m(&s[1..], rest),
            Some((c, rest)) => s.first() == Some(c) && m(&s[1..], rest),
        }
    }
    m(s.as_bytes(), pattern.as_bytes())
}

#[derive(Default)]
pub(crate) struct Env(Vec<(String, String)>);

impl Env {
    fn set(&mut self, name: &str, value: &str) {
        if let Some(e) = self.0.iter_mut().find(|(n, _)| n == name) {
            e.1 = value.to_owned();
        } else {
            self.0.push((name.to_owned(), value.to_owned()));
        }
    }
    pub(crate) fn into_vec(self) -> Vec<(String, String)> {
        self.0
    }
}

fn connection_vars(env: &mut Env, c: &ConnectionInfo) {
    env.set("SSH_CLIENT", &format!("{} {} {}", c.remote_ip, c.remote_port, c.local_port));
    env.set("SSH_CONNECTION", &format!("{} {} {} {}", c.remote_ip, c.remote_port, c.local_ip, c.local_port));
}

/// Build the child's environment. `tty` is the slave path when a pty was
/// allocated; `original_command` is set when a forced command replaced the
/// client's request.
pub(crate) fn build(
    cfg: &SessionConfig,
    req: &SessionRequest,
    shell: &str,
    tty: Option<&str>,
    original_command: Option<&str>,
) -> Env {
    let mut env = Env::default();
    let user = &req.user;
    let mut accepted = 0usize;
    for (name, value) in &req.env {
        if accepted >= cfg.max_client_env {
            break;
        }
        if cfg.accepts_env(name) {
            env.set(name, value);
            accepted += 1;
        }
    }
    env.set("USER", &user.name);
    env.set("LOGNAME", &user.name);
    env.set("HOME", &user.home.to_string_lossy());
    env.set("PATH", if user.uid == 0 { &cfg.superuser_path } else { &cfg.default_path });
    env.set("MAIL", &format!("{}/{}", cfg.mail_dir, user.name));
    env.set("SHELL", shell);
    if let Ok(tz) = std::env::var("TZ") {
        env.set("TZ", &tz);
    }
    if let Some(pty) = req.pty.as_ref().filter(|p| !p.term.is_empty()) {
        env.set("TERM", &pty.term);
    }
    if let Some(sock) = &req.auth_sock {
        env.set("SSH_AUTH_SOCK", &sock.to_string_lossy());
    }
    for (name, value) in &cfg.set_env {
        env.set(name, value);
    }
    if let Some(c) = &req.connection {
        connection_vars(&mut env, c);
    }
    if let Some(tty) = tty {
        env.set("SSH_TTY", tty);
    }
    if let Some(cmd) = original_command {
        env.set("SSH_ORIGINAL_COMMAND", cmd);
    }
    env
}

#[cfg(test)]
mod tests {
    use super::match_pattern;

    #[test]
    fn patterns() {
        assert!(match_pattern("LANG", "LANG"));
        assert!(match_pattern("LC_ALL", "LC_*"));
        assert!(match_pattern("LC_", "LC_*"));
        assert!(!match_pattern("XLC_ALL", "LC_*"));
        assert!(match_pattern("AB", "A?"));
        assert!(!match_pattern("A", "A?"));
        assert!(match_pattern("anything", "*"));
    }
}
