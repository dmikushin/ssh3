//! Durations in configuration files: an integer with a unit, `250ms`, `30s`,
//! `5m`, `12h`, `2d`, or `0`. A bare number other than 0 is rejected: in an
//! operator-facing file "30" is ambiguous (sshd reads seconds, systemd reads
//! microseconds in places), and a wrong guess is a silent misconfiguration.

use std::time::Duration;

pub fn parse(s: &str) -> Result<Duration, String> {
    let t = s.trim();
    if t == "0" {
        return Ok(Duration::ZERO);
    }
    let split = t.find(|c: char| !c.is_ascii_digit()).ok_or_else(|| {
        format!("duration {s:?} has no unit; write e.g. \"{t}s\" or \"{t}ms\"")
    })?;
    let (num, unit) = t.split_at(split);
    let n: u64 = num.parse().map_err(|_| format!("duration {s:?}: {num:?} is not a number"))?;
    let ms = match unit {
        "ms" => n,
        "s" => n * 1000,
        "m" => n * 60_000,
        "h" => n * 3_600_000,
        "d" => n * 86_400_000,
        u => return Err(format!("duration {s:?}: unknown unit {u:?} (use ms, s, m, h or d)")),
    };
    Ok(Duration::from_millis(ms))
}

/// serde adapter for a `Duration` written as a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dur(pub Duration);

impl<'de> serde::Deserialize<'de> for Dur {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse(&s).map(Dur).map_err(serde::de::Error::custom)
    }
}

/// A duration that may be switched off with `"off"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptDur(pub Option<Duration>);

impl<'de> serde::Deserialize<'de> for OptDur {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.trim() == "off" {
            return Ok(OptDur(None));
        }
        parse(&s).map(|d| OptDur(Some(d))).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(parse("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse("12h").unwrap(), Duration::from_secs(12 * 3600));
        assert_eq!(parse("2d").unwrap(), Duration::from_secs(2 * 86400));
        assert_eq!(parse("0").unwrap(), Duration::ZERO);
    }

    #[test]
    fn rejects_ambiguous() {
        assert!(parse("30").unwrap_err().contains("no unit"));
        assert!(parse("3x").unwrap_err().contains("unknown unit"));
        assert!(parse("s").unwrap_err().contains("not a number"));
    }
}
