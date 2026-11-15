//! The netstack's own multicast deadline (smoltcp issue #3 in `docs/upstream/smoltcp.md`).
//!
//! smoltcp's `poll_at` only looks at sockets: it ignores pending IGMP/MLD reports, both the
//! unsolicited ones after a join (or after addresses change, which joins the IPv6
//! solicited-node groups) and the delayed answers to a querier. Without help those reports
//! would only go out whenever something else happens to poll the interface.
//!
//! So the driver keeps this extra deadline:
//! * after a control-plane change (addresses set, group joined or left) the stack must be
//!   polled **now**;
//! * after an IGMP/MLD query arrives, smoltcp schedules its reports at a delay inside the query's
//!   maximum response time that we cannot read. The deadline then steps through that window
//!   every [`QUERY_STEP_NS`] (1 ms, the granularity of smoltcp's own report delays, counted
//!   from the query) until it has passed. A report is therefore sent on time for MLD and at most
//!   1 ms late for IGMP.
//!
//! An upstream `poll_at` that covers multicast would make the window unnecessary.

/// Polling step inside a query's response window.
pub const QUERY_STEP_NS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MulticastDeadline {
    /// Poll at this instant (a control-plane change).
    due: Option<u64>,
    /// `(query time, window end)`: poll every step after the query, up to the end.
    window: Option<(u64, u64)>,
}

impl MulticastDeadline {
    /// Addresses or group memberships changed at `now`: poll now.
    pub fn control_changed(&mut self, now: u64) {
        self.due = Some(self.due.map_or(now, |d| d.min(now)));
    }

    /// A query with `max_resp_ns` arrived at `now`.
    pub fn query(&mut self, now: u64, max_resp_ns: u64) {
        let end = now
            .saturating_add(max_resp_ns)
            .saturating_add(QUERY_STEP_NS);
        self.window = Some(match self.window {
            Some((_, old_end)) if old_end > end => (now, old_end),
            _ => (now, end),
        });
    }

    /// The stack was polled at `now`: everything due by now has been served.
    pub fn polled(&mut self, now: u64) {
        if self.due.is_some_and(|d| d <= now) {
            self.due = None;
        }
        if self.window.is_some_and(|(_, end)| end <= now) {
            self.window = None;
        }
    }

    /// Its state, for a snapshot: the due instant and the query window.
    pub fn parts(&self) -> (Option<u64>, Option<(u64, u64)>) {
        (self.due, self.window)
    }

    /// The deadline [`parts`](Self::parts) described.
    pub fn from_parts(due: Option<u64>, window: Option<(u64, u64)>) -> Self {
        Self { due, window }
    }

    /// The next instant the stack should be polled for multicast work, if any.
    pub fn next(&self, now: u64) -> Option<u64> {
        let step = self.window.and_then(|(from, end)| {
            let k = now.saturating_sub(from) / QUERY_STEP_NS + 1;
            let at = from.saturating_add(k.saturating_mul(QUERY_STEP_NS));
            (at <= end).then_some(at)
        });
        match (self.due, step) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_change_is_due_until_polled() {
        let mut m = MulticastDeadline::default();
        assert_eq!(m.next(0), None);
        m.control_changed(5);
        assert_eq!(m.next(5), Some(5));
        m.polled(5);
        assert_eq!(m.next(5), None);
    }

    #[test]
    fn a_query_window_steps_from_the_query() {
        let mut m = MulticastDeadline::default();
        m.query(10_500_000, 3 * QUERY_STEP_NS);
        let mut now = 10_500_000;
        let mut steps = Vec::new();
        while let Some(t) = m.next(now) {
            now = t;
            m.polled(now);
            steps.push(now);
        }
        assert_eq!(steps, [11_500_000, 12_500_000, 13_500_000, 14_500_000]);
        // An earlier control change wins.
        m.query(20_000_000, 10 * QUERY_STEP_NS);
        m.control_changed(20_000_000);
        assert_eq!(m.next(20_000_000), Some(20_000_000));
    }
}
