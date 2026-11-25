//! A device's linear memory as every backend accounts for it: measured for its cost report
//! ([`crate::DeviceCost::memory`], `peak_memory`) and, with [`crate::DeviceOptions::memory`],
//! bounded. The decision and its error text live here; a backend only reports what it sees.
//!
//! * A backend that sees each growth before it happens (wasmtime's resource limiter) calls
//!   [`MemoryBudget::growing`], which refuses the growth that would pass the limit: the device
//!   traps at the growing instruction, the same on every run.
//! * A backend that can only read its memories' sizes afterwards (a browser, where jco grows
//!   memories itself) calls [`MemoryBudget::observe`] with their total after each call into
//!   the device: the growth that passed the limit is found there, with the same error text,
//!   and the device faults at that point instead.

use crate::device::CostMeter;

/// A device's linear memories, all of them together.
pub struct MemoryBudget {
    /// `None`: measured only.
    limit: Option<u64>,
    used: u64,
    /// The last growth allowed (taken back if the growth then failed).
    last: u64,
    /// Where the device's cost report sees it.
    meter: CostMeter,
}

impl MemoryBudget {
    pub fn new(limit: Option<u64>, meter: CostMeter) -> Self {
        Self {
            limit,
            used: 0,
            last: 0,
            meter,
        }
    }

    /// The bytes counted now.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// A memory is about to grow by `grow` bytes: `Ok` (counted), or the device's fault when
    /// the growth would take it past its limit (nothing counted).
    pub fn growing(&mut self, grow: u64) -> Result<(), String> {
        let after = self.used.saturating_add(grow);
        self.check(grow, after)?;
        self.used = after;
        self.last = grow;
        self.meter.set_memory(after);
        Ok(())
    }

    /// The growth [`growing`](Self::growing) allowed last did not happen: uncount it.
    pub fn grow_failed(&mut self) {
        self.used = self.used.saturating_sub(self.last);
        self.meter.set_memory(self.used);
    }

    /// The device's memories total `total` bytes now (a backend that reads sizes after the
    /// fact): counted, and the device's fault if that is past its limit, worded as if the
    /// growth had been refused.
    pub fn observe(&mut self, total: u64) -> Result<(), String> {
        let grow = total.saturating_sub(self.used);
        self.used = total;
        self.meter.set_memory(total);
        self.check(grow, total)
    }

    fn check(&self, grow: u64, after: u64) -> Result<(), String> {
        match self.limit {
            Some(limit) if after > limit => Err(format!(
                "memory limit: growing a linear memory by {grow} bytes would take the device to \
                 {after} bytes, past its {limit} bytes"
            )),
            _ => Ok(()),
        }
    }
}

impl Drop for MemoryBudget {
    /// The device's instance is gone (it stopped): it holds no memory any more.
    fn drop(&mut self) {
        self.meter.set_memory(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_is_counted_and_bounded_the_same_either_way() {
        let meter = CostMeter::default();
        let mut b = MemoryBudget::new(Some(100), meter.clone());
        assert!(b.growing(60).is_ok());
        let refused = b.growing(50).unwrap_err();
        assert_eq!(
            refused,
            "memory limit: growing a linear memory by 50 bytes would take the device to 110 \
             bytes, past its 100 bytes"
        );
        assert_eq!(b.used(), 60);
        let mut seen = MemoryBudget::new(Some(100), CostMeter::default());
        assert!(seen.observe(60).is_ok());
        assert_eq!(seen.observe(110), Err(refused));
        let mut unbounded = MemoryBudget::new(None, CostMeter::default());
        assert!(unbounded.observe(1 << 40).is_ok());
        drop(b);
        let _ = meter;
    }
}
