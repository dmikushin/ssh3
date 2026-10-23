//! Tokenisers for ssh_config lines, ported from OpenSSH 10.5p1 `misc.c`
//! (`strdelim_internal`, `argv_split`).

pub(crate) const WHITESPACE: &[char] = &[' ', '\t', '\r', '\n'];

/// Port of `strdelim()` (split on whitespace, a double quote, or one `=`).
///
/// Returns `None` when the token has an unmatched quote (OpenSSH returns
/// NULL). Otherwise returns the token and the remainder; the remainder is
/// `None` when the input was exhausted (C: `*s = NULL`).
pub(crate) fn strdelim(s: &str) -> Option<(String, Option<String>)> {
    let bytes = s.as_bytes();
    let Some(pos) = bytes
        .iter()
        .position(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'='))
    else {
        return Some((s.to_string(), None));
    };

    if bytes[pos] == b'"' {
        // memmove removes the opening quote; then find the closing quote.
        let after = &s[pos + 1..];
        let close = after.find('"')?;
        let mut token = String::with_capacity(pos + close);
        token.push_str(&s[..pos]);
        token.push_str(&after[..close]);
        let rest = &after[close + 1..];
        let rest = rest.trim_start_matches(WHITESPACE);
        return Some((token, Some(rest.to_string())));
    }

    let wspace = bytes[pos] == b'=';
    let token = s[..pos].to_string();
    let mut rest = s[pos + 1..].trim_start_matches(WHITESPACE);
    if !wspace && rest.starts_with('=') {
        rest = rest[1..].trim_start_matches(WHITESPACE);
    }
    Some((token, Some(rest.to_string())))
}

/// Port of `argv_split()`: quoting with `"`/`'`, escapes `\\`, `\"`, `\'`
/// and (outside quotes) `\ `. With `terminate_on_comment`, a `#` at the start
/// of a token ends the line. Returns `None` on an unterminated quote.
pub(crate) fn argv_split(s: &str, terminate_on_comment: bool) -> Option<Vec<String>> {
    let b = s.as_bytes();
    let mut argv = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b' ' || b[i] == b'\t' {
            i += 1;
            continue;
        }
        if terminate_on_comment && b[i] == b'#' {
            break;
        }
        let mut quote = 0u8;
        let mut arg: Vec<u8> = Vec::new();
        while i < b.len() {
            let c = b[i];
            if c == b'\\' {
                let n = b.get(i + 1).copied();
                if matches!(n, Some(b'\'') | Some(b'"') | Some(b'\\'))
                    || (quote == 0 && n == Some(b' '))
                {
                    i += 1;
                    arg.push(b[i]);
                } else {
                    arg.push(c);
                }
            } else if quote == 0 && (c == b' ' || c == b'\t') {
                break;
            } else if quote == 0 && (c == b'"' || c == b'\'') {
                quote = c;
            } else if quote != 0 && c == quote {
                quote = 0;
            } else {
                arg.push(c);
            }
            i += 1;
        }
        argv.push(String::from_utf8_lossy(&arg).into_owned());
        if i >= b.len() {
            if quote != 0 {
                return None;
            }
            break;
        }
        i += 1;
    }
    Some(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strdelim_forms() {
        assert_eq!(
            strdelim("Port 22"),
            Some(("Port".into(), Some("22".into())))
        );
        assert_eq!(
            strdelim("Port=22"),
            Some(("Port".into(), Some("22".into())))
        );
        assert_eq!(
            strdelim("Port = 22"),
            Some(("Port".into(), Some("22".into())))
        );
        assert_eq!(strdelim("Port"), Some(("Port".into(), None)));
        assert_eq!(
            strdelim("  Port 1"),
            Some(("".into(), Some("Port 1".into())))
        );
        assert_eq!(
            strdelim("\"Po rt\" 1"),
            Some(("Po rt".into(), Some("1".into())))
        );
        assert_eq!(strdelim("\"Port 1"), None);
    }

    #[test]
    fn argv_split_forms() {
        assert_eq!(argv_split("a b  c", true).unwrap(), ["a", "b", "c"]);
        assert_eq!(argv_split("\"a b\" 'c d'", true).unwrap(), ["a b", "c d"]);
        assert_eq!(argv_split("a\\ b c", true).unwrap(), ["a b", "c"]);
        assert_eq!(argv_split("a #c d", true).unwrap(), ["a"]);
        assert_eq!(argv_split("a#c d", true).unwrap(), ["a#c", "d"]);
        assert_eq!(argv_split("BAZ=\"q x\"", true).unwrap(), ["BAZ=q x"]);
        assert!(argv_split("\"open", true).is_none());
    }
}
