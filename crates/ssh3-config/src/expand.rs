//! `~`, `%token` and `${ENV}` expansion, ported from OpenSSH 10.5p1 `misc.c`
//! (`tilde_expand`, `vdollar_percent_expand`).

use crate::env::LocalEnv;

/// Why an expansion failed. OpenSSH treats `Syntax` as fatal and
/// `MissingVar` as "expansion produced nothing" (callers decide).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandError {
    /// Unknown `%x` token, `%` at end of string, `${` without `}`, `${}`.
    Syntax(String),
    /// `${VAR}` named an unset environment variable.
    MissingVar(String),
}

impl std::fmt::Display for ExpandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpandError::Syntax(m) => write!(f, "{m}"),
            ExpandError::MissingVar(v) => write!(f, "env var ${{{v}}} has no value"),
        }
    }
}

/// `%x` → replacement table. Keys are single characters.
pub type Tokens<'a> = &'a [(char, &'a str)];

/// Port of `vdollar_percent_expand()`.
pub fn expand(s: &str, dollar: bool, tokens: Option<Tokens<'_>>) -> Result<String, ExpandError> {
    let mut out = String::with_capacity(s.len());
    let mut missing: Option<String> = None;
    let mut chars = s.char_indices().peekable();
    while let Some((idx, c)) = chars.next() {
        if dollar && c == '$' && s[idx + 1..].starts_with('{') {
            let body = &s[idx + 2..];
            let Some(end) = body.find('}') else {
                return Err(ExpandError::Syntax(format!(
                    "environment variable '{body}' missing closing '}}'"
                )));
            };
            if end == 0 {
                return Err(ExpandError::Syntax(
                    "zero-length environment variable".into(),
                ));
            }
            let var = &body[..end];
            match std::env::var(var) {
                Ok(v) => out.push_str(&v),
                Err(_) => missing = Some(var.to_string()),
            }
            // Skip "{", the name and "}".
            let skip_to = idx + 2 + end + 1;
            while let Some(&(j, _)) = chars.peek() {
                if j >= skip_to {
                    break;
                }
                chars.next();
            }
            continue;
        }
        let Some(tokens) = tokens else {
            out.push(c);
            continue;
        };
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            None => return Err(ExpandError::Syntax("invalid format".into())),
            Some((_, '%')) => out.push('%'),
            Some((_, k)) => match tokens.iter().find(|(key, _)| *key == k) {
                Some((_, repl)) => out.push_str(repl),
                None => return Err(ExpandError::Syntax(format!("unknown key %{k}"))),
            },
        }
    }
    match missing {
        Some(v) => Err(ExpandError::MissingVar(v)),
        None => Ok(out),
    }
}

/// `percent_expand()`.
pub fn percent(s: &str, tokens: Tokens<'_>) -> Result<String, ExpandError> {
    expand(s, false, Some(tokens))
}

/// `percent_dollar_expand()`.
pub fn percent_dollar(s: &str, tokens: Tokens<'_>) -> Result<String, ExpandError> {
    expand(s, true, Some(tokens))
}

/// `dollar_expand()`.
pub fn dollar(s: &str) -> Result<String, ExpandError> {
    expand(s, true, None)
}

/// Port of `tilde_expand()`: `~`, `~/path`, `~user`, `~user/path`.
pub fn tilde(filename: &str, env: &LocalEnv) -> Result<String, String> {
    let Some(rest) = filename.strip_prefix('~') else {
        return Ok(filename.to_string());
    };
    let (user, path): (Option<&str>, Option<&str>) = if rest.is_empty() {
        (None, None)
    } else if rest.starts_with('/') {
        let p = rest.trim_start_matches('/');
        (None, if p.is_empty() { None } else { Some(p) })
    } else {
        match rest.find('/') {
            Some(slash) => {
                let p = rest[slash + 1..].trim_start_matches('/');
                (
                    Some(&rest[..slash]),
                    if p.is_empty() { None } else { Some(p) },
                )
            }
            None => (Some(rest), None),
        }
    };
    let dir = match user {
        Some(u) => env
            .home_of(u)
            .ok_or_else(|| format!("tilde_expand: No such user {u}"))?,
        None => env.home.clone(),
    };
    let slash = dir.is_empty() || !dir.ends_with('/');
    Ok(format!(
        "{dir}{}{}",
        if slash { "/" } else { "" },
        path.unwrap_or("")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_tokens() {
        let t = [('h', "host"), ('p', "22")];
        assert_eq!(percent("%h:%p %%", &t).unwrap(), "host:22 %");
        assert!(matches!(percent("%x", &t), Err(ExpandError::Syntax(_))));
        assert!(matches!(percent("a%", &t), Err(ExpandError::Syntax(_))));
        // percent-only expansion leaves ${} alone
        assert_eq!(percent("${HOME}", &t).unwrap(), "${HOME}");
    }

    #[test]
    fn dollar_vars() {
        // SAFETY: test-local variable name, no concurrent readers of it.
        unsafe { std::env::set_var("SSH3_CONFIG_TEST_VAR", "v") };
        assert_eq!(dollar("a${SSH3_CONFIG_TEST_VAR}b").unwrap(), "avb");
        assert!(matches!(
            dollar("${SSH3_CONFIG_TEST_UNSET_VAR}"),
            Err(ExpandError::MissingVar(_))
        ));
        assert!(matches!(dollar("${}"), Err(ExpandError::Syntax(_))));
        assert!(matches!(dollar("${X"), Err(ExpandError::Syntax(_))));
    }

    #[test]
    fn tilde_forms() {
        let env = LocalEnv::for_tests("/home/t");
        assert_eq!(tilde("~", &env).unwrap(), "/home/t/");
        assert_eq!(tilde("~/", &env).unwrap(), "/home/t/");
        assert_eq!(tilde("~//a/b", &env).unwrap(), "/home/t/a/b");
        assert_eq!(tilde("/abs", &env).unwrap(), "/abs");
    }
}
