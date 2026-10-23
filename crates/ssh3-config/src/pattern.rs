//! Wildcard matching, ported from OpenSSH 10.5p1 `match.c`.

/// `match_pattern()`: `*` matches any sequence, `?` any single byte; the
/// whole string must match. Case-sensitive.
pub fn match_pattern(s: &str, pattern: &str) -> bool {
    let s = s.as_bytes();
    let p = pattern.as_bytes();
    // Iterative wildcard match with single backtrack point (equivalent to the
    // NFA in match.c for patterns over '*' and '?').
    let (mut si, mut pi) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) && p[pi] != b'*' {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, si));
            pi += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Result of [`match_pattern_list`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListMatch {
    Negative,
    None,
    Positive,
}

/// `match_pattern_list()`: comma-separated sub-patterns, each optionally
/// negated with `!`. A negated match wins over everything.
pub fn match_pattern_list(string: &str, pattern: &str, dolower: bool) -> ListMatch {
    let p = pattern.as_bytes();
    let len = p.len();
    let mut got_positive = false;
    let mut i = 0;
    // Same scan as match.c: the loop runs only while input remains, so an
    // empty pattern or a trailing comma yields no empty sub-pattern.
    while i < len {
        let negated = p[i] == b'!';
        if negated {
            i += 1;
        }
        let start = i;
        while i < len && p[i] != b',' {
            i += 1;
        }
        // match.c copies into a 1024-byte buffer; longer sub-patterns fail.
        if i - start >= 1023 {
            return ListMatch::None;
        }
        let sub = &pattern[start..i];
        if i < len && p[i] == b',' {
            i += 1;
        }
        let sub = if dolower {
            sub.to_ascii_lowercase()
        } else {
            sub.to_string()
        };
        if match_pattern(string, &sub) {
            if negated {
                return ListMatch::Negative;
            }
            got_positive = true;
        }
    }
    if got_positive {
        ListMatch::Positive
    } else {
        ListMatch::None
    }
}

/// `match_hostname()`: lowercase host, case-insensitive pattern list.
pub fn match_hostname(host: &str, pattern: &str) -> ListMatch {
    match_pattern_list(&host.to_ascii_lowercase(), pattern, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard() {
        assert!(match_pattern("foobar", "foo*"));
        assert!(match_pattern("foobar", "*bar"));
        assert!(match_pattern("foobar", "f?o*r"));
        assert!(!match_pattern("foobar", "foo"));
        assert!(match_pattern("", ""));
        assert!(match_pattern("", "*"));
        assert!(!match_pattern("a", ""));
        assert!(match_pattern("abcabc", "*abc"));
        assert!(match_pattern("aXbXc", "a*b*c"));
        assert!(!match_pattern("FooBar", "foo*"));
    }

    #[test]
    fn lists() {
        assert_eq!(
            match_pattern_list("a.example", "*.example,!b.example", false),
            ListMatch::Positive
        );
        assert_eq!(
            match_pattern_list("b.example", "*.example,!b.example", false),
            ListMatch::Negative
        );
        assert_eq!(
            match_pattern_list("c.other", "*.example", false),
            ListMatch::None
        );
        assert_eq!(match_hostname("Foo.Example", "FOO.*"), ListMatch::Positive);
    }
}
