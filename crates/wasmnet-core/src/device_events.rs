//! The events a controller reads of the devices it created (`wasmnet:infra/events`): what each
//! device journalled through `wasmnet:link/log.event`, kept in a bounded ring per device, with a
//! cursor that numbers them. The device table ([`crate::Infra`]) owns the rings; this module is
//! the ring, the cursor arithmetic and the kind filters
//! (`docs/design/topology-and-infra.md`, "Events of the devices a controller created").

use std::collections::VecDeque;

use crate::clock::Nanos;
use crate::infra::InfraError;

/// The most events kept per device; older ones are dropped first.
pub const EVENTS_KEPT: usize = 256;

/// The most bytes of events kept per device (kinds, field names and values, and
/// [`EVENT_OVERHEAD`] per event); older events are dropped first, but the newest is always
/// kept.
pub const EVENT_BYTES_KEPT: usize = 256 << 10;

/// What one event counts towards [`EVENT_BYTES_KEPT`] besides its text.
pub const EVENT_OVERHEAD: usize = 32;

/// The most kind patterns one filter takes.
pub const MAX_KINDS: usize = 16;

/// The longest kind pattern.
pub const MAX_KIND: usize = 128;

/// The most devices one `wait` or `arm` follows.
pub const MAX_FOLLOWS: usize = 64;

/// One event a device journalled (`wasmnet:infra/events.event`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceEvent {
    /// Its number among the events of the device's name: 1 for the first, one more for each
    /// next. The cursor a reader resumes from.
    pub seq: u64,
    /// When it was journalled.
    pub at: Nanos,
    pub kind: String,
    /// In the order the device gave them.
    pub fields: Vec<(String, String)>,
}

/// What a read found (`wasmnet:infra/events.page`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct EventPage {
    /// The events after the cursor that match the filter, oldest first.
    pub events: Vec<DeviceEvent>,
    /// The cursor to read from next: everything up to it was looked at.
    pub next: u64,
    /// How many events after the cursor were dropped from the ring before they were read, of
    /// any kind (the ring keeps every kind).
    pub missed: u64,
}

/// One device a wait follows (`wasmnet:infra/events.follow`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Follow {
    pub name: String,
    /// Kind patterns: a kind, or a prefix and `*` (`tunnel-*`); none: every kind.
    pub kinds: Vec<String>,
    /// The cursor: events up to it were seen.
    pub since: u64,
}

impl Follow {
    /// Follows `name`'s events of `kinds` after `since`.
    pub fn new(name: impl Into<String>, kinds: Vec<String>, since: u64) -> Self {
        Self {
            name: name.into(),
            kinds,
            since,
        }
    }
}

/// The table part of a wait (`wasmnet:infra/events.table-since`): a change after `since` to a
/// device matching `selector`, as `changes.wait` takes them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TableSince {
    pub selector: Vec<(String, String)>,
    pub since: u64,
}

impl TableSince {
    /// Changes after `since` to devices whose labels include all of `selector`.
    pub fn new(selector: Vec<(String, String)>, since: u64) -> Self {
        Self { selector, since }
    }
}

/// Why a wait returned (`wasmnet:infra/events.ready`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ready {
    /// The latest resource version of the caller's view.
    pub rv: u64,
    /// The table has a change it waited for.
    pub changed: bool,
    /// The followed devices that have an event it waited for, a gap, or are gone, in the order
    /// they were given.
    pub devices: Vec<String>,
}

impl Ready {
    /// Whether anything is ready (a deadline returns a `Ready` with nothing).
    pub fn any(&self) -> bool {
        self.changed || !self.devices.is_empty()
    }
}

/// Checks a filter's kind patterns.
pub(crate) fn check_kinds(kinds: &[String]) -> Result<(), InfraError> {
    if kinds.len() > MAX_KINDS {
        return Err(InfraError::Invalid(format!(
            "at most {MAX_KINDS} kind patterns"
        )));
    }
    for k in kinds {
        let body = k.strip_suffix('*').unwrap_or(k);
        if k.is_empty()
            || k.len() > MAX_KIND
            || body.contains('*')
            || k.chars().any(char::is_whitespace)
        {
            return Err(InfraError::Invalid(format!(
                "kind pattern `{k}`: 1-{MAX_KIND} bytes without spaces, a kind or a prefix and `*`"
            )));
        }
    }
    Ok(())
}

/// Whether `kind` matches one of `kinds` (none: every kind).
pub(crate) fn matches_kind(kinds: &[String], kind: &str) -> bool {
    kinds.is_empty()
        || kinds.iter().any(|k| match k.strip_suffix('*') {
            Some(prefix) => kind.starts_with(prefix),
            None => kind == k,
        })
}

fn size(kind: &str, fields: &[(String, String)]) -> usize {
    EVENT_OVERHEAD + kind.len() + fields.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
}

/// One device's ring. Events are numbered per device name, across the name's incarnations, so
/// a cursor never goes back; `base` is the last number before this incarnation's first event.
#[derive(Clone, Debug)]
pub(crate) struct Ring {
    base: u64,
    /// The highest number dropped from the ring (`base` when none was).
    dropped: u64,
    events: VecDeque<DeviceEvent>,
    bytes: usize,
}

impl Ring {
    /// A ring whose first event will be number `base + 1`.
    pub(crate) fn new(base: u64) -> Self {
        Self {
            base,
            dropped: base,
            events: VecDeque::new(),
            bytes: 0,
        }
    }

    /// Keeps event `seq`, dropping the oldest past the bounds.
    pub(crate) fn push(
        &mut self,
        seq: u64,
        at: Nanos,
        kind: String,
        fields: Vec<(String, String)>,
    ) {
        self.bytes += size(&kind, &fields);
        self.events.push_back(DeviceEvent {
            seq,
            at,
            kind,
            fields,
        });
        while self.events.len() > EVENTS_KEPT
            || (self.bytes > EVENT_BYTES_KEPT && self.events.len() > 1)
        {
            let Some(old) = self.events.pop_front() else {
                break;
            };
            self.bytes -= size(&old.kind, &old.fields);
            self.dropped = old.seq;
        }
    }

    /// How many events after `since` were dropped.
    pub(crate) fn missed(&self, since: u64) -> u64 {
        self.dropped.saturating_sub(since.max(self.base))
    }

    /// The events after `since` matching `kinds`, at most `max` (at least 1).
    pub(crate) fn read(&self, kinds: &[String], since: u64, max: u32) -> EventPage {
        let max = max.max(1) as usize;
        let mut events = Vec::new();
        let mut next = since;
        for e in self.events.iter().filter(|e| e.seq > since) {
            if matches_kind(kinds, &e.kind) {
                if events.len() == max {
                    return EventPage {
                        events,
                        next,
                        missed: self.missed(since),
                    };
                }
                events.push(e.clone());
            }
            next = e.seq;
        }
        EventPage {
            events,
            next: next.max(self.dropped),
            missed: self.missed(since),
        }
    }

    /// Whether a reader at `since` filtering `kinds` has something to read: a matching event
    /// or a gap.
    pub(crate) fn ready(&self, kinds: &[String], since: u64) -> bool {
        self.missed(since) > 0
            || self
                .events
                .iter()
                .rev()
                .take_while(|e| e.seq > since)
                .any(|e| matches_kind(kinds, &e.kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(k: &[&str]) -> Vec<String> {
        k.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn filters_take_kinds_and_prefixes() {
        assert!(matches_kind(&[], "anything"));
        let f = kinds(&["tunnel-*", "route-added"]);
        assert!(matches_kind(&f, "tunnel-up"));
        assert!(matches_kind(&f, "route-added"));
        assert!(!matches_kind(&f, "route-removed"));
        assert!(check_kinds(&f).is_ok());
        assert!(check_kinds(&kinds(&["*"])).is_ok(), "every kind");
        for bad in ["", "a*b", "a b", "**"] {
            assert!(check_kinds(&kinds(&[bad])).is_err(), "{bad:?}");
        }
        assert!(check_kinds(&vec!["k".to_owned(); MAX_KINDS + 1]).is_err());
    }

    #[test]
    fn a_ring_reads_each_event_once_and_reports_what_it_dropped() {
        let mut r = Ring::new(0);
        for seq in 1..=3 {
            r.push(seq, 7, format!("k{seq}"), Vec::new());
        }
        // Three events at one instant, one at a time: each exactly once.
        let mut since = 0;
        let mut seen = Vec::new();
        loop {
            let p = r.read(&[], since, 1);
            if p.events.is_empty() {
                assert_eq!(p.next, since);
                break;
            }
            seen.extend(p.events.iter().map(|e| e.seq));
            since = p.next;
        }
        assert_eq!(seen, [1, 2, 3]);
        // A filter skips what it does not want, and the cursor moves past it.
        let p = r.read(&kinds(&["k2"]), 0, 10);
        assert_eq!((p.events.len(), p.next, p.missed), (1, 3, 0));
        assert!(r.ready(&kinds(&["k3"]), 2));
        assert!(!r.ready(&kinds(&["k1"]), 1));
        // Overflow: a reader at 0 missed what was dropped, and only that.
        for seq in 4..=(EVENTS_KEPT as u64 + 10) {
            r.push(seq, 8, "n".into(), Vec::new());
        }
        let p = r.read(&[], 0, u32::MAX);
        assert_eq!(p.missed, 10);
        assert_eq!(p.events.len(), EVENTS_KEPT);
        assert_eq!(p.events[0].seq, 11);
        assert!(
            r.ready(&kinds(&["nothing"]), 0),
            "a gap is something to read"
        );
        assert_eq!(r.read(&[], 10, 1).missed, 0);
        assert_eq!(r.read(&[], 5, 1).missed, 5);
    }

    #[test]
    fn a_ring_is_bounded_in_bytes_but_keeps_the_newest() {
        let mut r = Ring::new(4);
        let big = "x".repeat(EVENT_BYTES_KEPT / 2);
        for seq in 5..=7 {
            r.push(seq, 0, "big".into(), vec![("v".into(), big.clone())]);
        }
        let p = r.read(&[], 0, 10);
        assert_eq!(p.events.iter().map(|e| e.seq).collect::<Vec<_>>(), [7]);
        assert_eq!(
            p.missed, 2,
            "events of an earlier incarnation are not missed"
        );
        r.push(
            8,
            0,
            "huge".into(),
            vec![("v".into(), "x".repeat(EVENT_BYTES_KEPT))],
        );
        assert_eq!(r.read(&[], 0, 10).events.len(), 1, "the newest stays");
    }
}
