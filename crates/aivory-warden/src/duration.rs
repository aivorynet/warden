//! Parse durations such as `30d`, `12h`, `5m`, `2s`, `2w`.

use std::time::Duration;
use warden_core::{Result, WardenError};

/// Parse `<number><unit>` with unit `s`, `m`, `h`, `d` or `w`.
pub fn parse(s: &str) -> Result<Duration> {
    let bad = || WardenError::Config(format!("bad duration `{s}` (use for example 30d, 12h, 5m)"));
    let s = s.trim();
    let unit = s.chars().last().ok_or_else(bad)?;
    let num: u64 = s[..s.len() - unit.len_utf8()].parse().map_err(|_| bad())?;
    let mul = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        'w' => 604_800,
        _ => return Err(bad()),
    };
    num.checked_mul(mul)
        .map(Duration::from_secs)
        .ok_or_else(bad)
}

/// Format a duration with the largest whole unit.
pub fn format(d: Duration) -> String {
    let s = d.as_secs();
    for (unit, n) in [('w', 604_800), ('d', 86_400), ('h', 3600), ('m', 60)] {
        if s >= n && s.is_multiple_of(n) {
            return format!("{}{unit}", s / n);
        }
    }
    format!("{s}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse("14d").unwrap(), Duration::from_secs(14 * 86_400));
        assert_eq!(parse("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse("1m").unwrap(), Duration::from_secs(60));
        assert!(parse("").is_err());
        assert!(parse("d").is_err());
        assert!(parse("10x").is_err());
    }

    #[test]
    fn formats_units() {
        assert_eq!(format(Duration::from_secs(14 * 86_400)), "2w");
        assert_eq!(format(Duration::from_secs(90)), "90s");
        assert_eq!(format(Duration::from_secs(3 * 86_400)), "3d");
    }
}
