//! The one duration syntax shared by device configs and the tools that describe networks.
//!
//! A duration is a non-negative integer followed by a unit: `ns`, `us`, `ms` or `s`
//! (`250us`, `20ms`, `3s`). A bare integer means nanoseconds. There are no fractions and no
//! spaces, so every value maps to exactly one `u64` of virtual nanoseconds and back.

use alloc::format;
use alloc::string::String;

/// Units from largest to smallest, with their size in nanoseconds.
const UNITS: [(&str, u64); 4] = [
    ("s", 1_000_000_000),
    ("ms", 1_000_000),
    ("us", 1_000),
    ("ns", 1),
];

/// Parses a duration into nanoseconds. Returns `None` for anything malformed or out of range.
pub fn parse_duration(text: &str) -> Option<u64> {
    let digits_end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, unit) = text.split_at(digits_end);
    if digits.is_empty() {
        return None;
    }
    let value: u64 = digits.parse().ok()?;
    let scale = match unit {
        "" => 1,
        unit => UNITS.iter().find(|(name, _)| *name == unit)?.1,
    };
    value.checked_mul(scale)
}

/// Formats nanoseconds with the largest unit that divides them exactly (`1500000` → `1500us`).
/// [`parse_duration`] reads the result back to the same value.
pub fn format_duration(ns: u64) -> String {
    let (unit, scale) = UNITS
        .iter()
        .find(|(_, scale)| ns.is_multiple_of(*scale) && ns != 0)
        .copied()
        .unwrap_or(("ns", 1));
    format!("{}{unit}", ns / scale)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_unit_and_bare_nanoseconds() {
        assert_eq!(parse_duration("250us"), Some(250_000));
        assert_eq!(parse_duration("20ms"), Some(20_000_000));
        assert_eq!(parse_duration("3s"), Some(3_000_000_000));
        assert_eq!(parse_duration("7ns"), Some(7));
        assert_eq!(parse_duration("42"), Some(42));
        assert_eq!(parse_duration("0ms"), Some(0));
    }

    #[test]
    fn rejects_malformed_and_overflowing_input() {
        for bad in [
            "",
            "ms",
            "1.5ms",
            "-1ms",
            "10 ms",
            "10m",
            "10mss",
            "1h",
            "99999999999s",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn formats_with_the_largest_exact_unit_and_round_trips() {
        assert_eq!(format_duration(0), "0ns");
        assert_eq!(format_duration(1_500_000), "1500us");
        assert_eq!(format_duration(20_000_000), "20ms");
        assert_eq!(format_duration(2_000_000_000), "2s");
        for ns in [0, 1, 999, 1_000, 1_234_000, 5_000_000_000, u64::MAX] {
            assert_eq!(parse_duration(&format_duration(ns)), Some(ns));
        }
    }
}
