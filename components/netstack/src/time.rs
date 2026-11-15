//! Virtual time conversions between the host's `u64` nanoseconds and smoltcp's `i64`
//! microseconds (smoltcp issues #13 and #17 in `docs/upstream/smoltcp.md`).
//!
//! * Into smoltcp: nanoseconds are truncated to whole microseconds. Sub-µs link latencies
//!   therefore collapse into the same smoltcp instant (the exact ns are kept for our own
//!   timestamps, such as ping RTTs).
//! * Out of smoltcp: a deadline is clamped to `now`. `poll_at` returns `Instant::ZERO` to mean
//!   "now", and a deadline inside the current microsecond lies before `now` in ns. Negative
//!   instants clamp to `now` too, and the far future saturates instead of overflowing.

use smoltcp::time::Instant;

/// `now` (virtual ns) as a smoltcp instant (µs, truncated). Never fails: `u64::MAX` ns is
/// about 1.8e16 µs, well inside `i64`.
pub fn to_smol(ns: u64) -> Instant {
    Instant::from_micros((ns / 1_000) as i64)
}

/// A smoltcp deadline as virtual ns, clamped to `now_ns` (never in the past).
pub fn deadline_ns(at: Instant, now_ns: u64) -> u64 {
    let us = at.total_micros();
    if us <= 0 {
        return now_ns;
    }
    (us as u64).saturating_mul(1_000).max(now_ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ns_truncate_to_microseconds() {
        assert_eq!(to_smol(0), Instant::ZERO);
        assert_eq!(to_smol(1_999), Instant::from_micros(1));
        assert_eq!(to_smol(250_000), Instant::from_micros(250));
        assert_eq!(to_smol(u64::MAX).total_micros(), (u64::MAX / 1_000) as i64);
    }

    #[test]
    fn deadlines_clamp_to_now_and_saturate() {
        // Instant::ZERO means "now" (smoltcp issue #13).
        assert_eq!(deadline_ns(Instant::ZERO, 5_000_000), 5_000_000);
        assert_eq!(deadline_ns(Instant::from_micros(-3), 7), 7);
        // Inside the current microsecond: now.
        assert_eq!(
            deadline_ns(Instant::from_micros(1_000), 1_000_500),
            1_000_500
        );
        assert_eq!(
            deadline_ns(Instant::from_micros(1_001), 1_000_500),
            1_001_000
        );
        assert_eq!(deadline_ns(Instant::from_micros(i64::MAX), 0), u64::MAX);
        // Round trip for whole microseconds.
        for ns in [0, 1_000, 250_000, 10_000_000_000] {
            assert_eq!(deadline_ns(to_smol(ns), 0).max(ns), ns);
        }
    }
}
