//! The network journal: every `wasmnet:link/log` record, stamped with virtual time and device name.
//!
//! Devices call the sync `log.log`/`log.event` imports, and the host appends one [`JournalEntry`]
//! per call, in call order. Because calls happen in causal-key order on one thread
//! (`docs/design/event-order.md`), the journal is deterministic like everything else. It is bounded: past [`MAX_ENTRIES`] records the host
//! keeps only a count of what it dropped.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::clock::{Nanos, Tag, VirtualClock};

/// The journal keeps at most this many records per network.
pub const MAX_ENTRIES: usize = 1 << 20;
/// Longer log messages and field values are truncated to this many bytes (at a char boundary).
pub const MAX_TEXT: usize = 16 << 10;

/// Severity of a log line (mirrors `wasmnet:link/log.level`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    /// Lowercase name: `trace`, `debug`, `info`, `warn` or `error`.
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

/// What a device recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Record {
    /// A human-readable line from `log.log`.
    Log { level: Level, message: String },
    /// A structured event from `log.event`, fields in the order the device gave them.
    Event {
        kind: String,
        fields: Vec<(String, String)>,
    },
    /// One line the device wrote to stdout or stderr (without its line ending), stamped when
    /// the line was completed. Only for devices that asked for it
    /// ([`crate::DeviceOptions::journal_stdio`]); a last line without a newline is not
    /// journalled ([`crate::Network::stdout`] has every byte).
    Output { stream: Stream, line: String },
}

/// A standard output stream of a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stream {
    Stdout,
    Stderr,
}

impl Stream {
    /// `stdout` or `stderr`.
    pub fn as_str(self) -> &'static str {
        match self {
            Stream::Stdout => "stdout",
            Stream::Stderr => "stderr",
        }
    }

    /// The stream called `stdout` or `stderr`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "stdout" => Some(Stream::Stdout),
            "stderr" => Some(Stream::Stderr),
            _ => None,
        }
    }
}

/// One journal record, stamped by the host.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct JournalEntry {
    /// Virtual time of the call.
    pub at: Nanos,
    /// The device's name in the network.
    pub device: String,
    pub record: Record,
}

impl JournalEntry {
    /// `record`, made by `device` at virtual time `at`.
    pub fn new(at: Nanos, device: impl Into<String>, record: Record) -> Self {
        Self {
            at,
            device: device.into(),
            record,
        }
    }
}

/// Shared, append-only journal of one network. With a clock, every record is also stamped with the
/// processing context it was made in ([`Tag`]), for merging the journals of a multi-site network.
#[derive(Clone, Default)]
pub(crate) struct Journal {
    inner: Arc<Mutex<JournalState>>,
    clock: Option<VirtualClock>,
}

/// Sees every record the journal keeps, as it is appended, in the appending context.
pub(crate) type Observer = Arc<dyn Fn(&JournalEntry) + Send + Sync>;

/// Sees every `wasmnet:link/log.event` call of a device, in the device's processing context,
/// whether or not the journal still keeps records.
pub(crate) type EventSink = Arc<dyn Fn(&JournalEntry) + Send + Sync>;

#[derive(Default)]
struct JournalState {
    entries: Vec<JournalEntry>,
    tags: Vec<Tag>,
    dropped: u64,
    observer: Option<Observer>,
    events: Option<EventSink>,
}

impl Journal {
    /// A journal whose records are tagged with `clock`'s processing context.
    pub(crate) fn new(clock: VirtualClock) -> Self {
        Self {
            inner: Arc::default(),
            clock: Some(clock),
        }
    }

    fn state(&self) -> MutexGuard<'_, JournalState> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Calls `observer` with every record kept from now on, right before it is appended (the
    /// journal is not locked meanwhile, so the observer may read it).
    pub(crate) fn set_observer(&self, observer: Observer) {
        self.state().observer = Some(observer);
    }

    /// Calls `sink` with every event a device journals through `wasmnet:link/log.event` from
    /// now on ([`JournalEnd::event`]), before it is appended, kept or not.
    pub(crate) fn set_event_sink(&self, sink: EventSink) {
        self.state().events = Some(sink);
    }

    pub(crate) fn push(&self, entry: JournalEntry) {
        let tag = self.clock.as_ref().map(VirtualClock::tag);
        let (kept, observer) = {
            let s = self.state();
            (s.entries.len() < MAX_ENTRIES, s.observer.clone())
        };
        if let Some(observe) = observer.filter(|_| kept) {
            observe(&entry);
        }
        let mut s = self.state();
        if kept {
            s.entries.push(entry);
            s.tags.extend(tag);
        } else {
            s.dropped += 1;
        }
    }

    pub(crate) fn entries(&self) -> Vec<JournalEntry> {
        self.state().entries.clone()
    }

    /// Entries `from..` (a live view's increment).
    pub(crate) fn entries_from(&self, from: usize) -> Vec<JournalEntry> {
        let s = self.state();
        s.entries.get(from..).map(<[_]>::to_vec).unwrap_or_default()
    }

    /// The tag of every entry (empty for a journal without a clock).
    pub(crate) fn tags(&self) -> Vec<Tag> {
        self.state().tags.clone()
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.state().dropped
    }

    pub(crate) fn len(&self) -> usize {
        self.state().entries.len()
    }

    /// Entries `from..` with their tags.
    pub(crate) fn tagged_entries_from(&self, from: usize) -> Vec<(JournalEntry, Option<Tag>)> {
        let s = self.state();
        s.entries
            .iter()
            .enumerate()
            .skip(from)
            .map(|(i, e)| (e.clone(), s.tags.get(i).cloned()))
            .collect()
    }
}

/// Where a device's log records go: the network journal, under the device's name.
#[derive(Clone)]
pub struct JournalEnd {
    pub(crate) journal: Journal,
    pub(crate) device: String,
}

pub fn truncate(mut s: String) -> String {
    if s.len() > MAX_TEXT {
        let mut end = MAX_TEXT;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

impl JournalEnd {
    /// Appends a host-made record (for example `app-exit`) under the device's name.
    pub fn push(&self, at: Nanos, record: Record) {
        self.journal.push(JournalEntry {
            at,
            device: self.device.clone(),
            record,
        });
    }
}

impl JournalEnd {
    /// A `wasmnet:link/log.log` call at `at` (the message is truncated to [`MAX_TEXT`]).
    pub fn log(&self, at: Nanos, level: Level, message: String) {
        self.push(
            at,
            Record::Log {
                level,
                message: truncate(message),
            },
        );
    }

    /// A `wasmnet:link/log.event` call at `at` (kind, keys and values truncated to
    /// [`MAX_TEXT`]).
    pub fn event(&self, at: Nanos, kind: String, fields: Vec<(String, String)>) {
        let fields = fields
            .into_iter()
            .map(|(k, v)| (truncate(k), truncate(v)))
            .collect();
        let entry = JournalEntry {
            at,
            device: self.device.clone(),
            record: Record::Event {
                kind: truncate(kind),
                fields,
            },
        };
        // Not locked while the sink runs: it may wake controllers, which may read the journal.
        let sink = self.journal.state().events.clone();
        if let Some(sink) = sink {
            sink(&entry);
        }
        self.journal.push(entry);
    }

    /// The device's name in the network.
    pub fn device(&self) -> &str {
        &self.device
    }

    /// A composed node's app `app` returned from its `run` at `at` (`ok`: it returned `ok`):
    /// the log line `app <app> exited: ok|error` and the event `app-exit {app, status}`, as
    /// every backend journals it.
    pub fn app_exit(&self, at: Nanos, app: &str, ok: bool) {
        let status = if ok { "ok" } else { "error" };
        self.push(
            at,
            Record::Log {
                level: Level::Info,
                message: format!("app {app} exited: {status}"),
            },
        );
        self.push(
            at,
            Record::Event {
                kind: "app-exit".to_owned(),
                fields: vec![
                    ("app".to_owned(), app.to_owned()),
                    ("status".to_owned(), status.to_owned()),
                ],
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_at_a_char_boundary() {
        let s = "é".repeat(MAX_TEXT); // 2 bytes each
        let t = truncate(s);
        assert!(t.len() <= MAX_TEXT && t.len() >= MAX_TEXT - 1);
        assert!(t.chars().all(|c| c == 'é'));
        assert_eq!(truncate("short".to_owned()), "short");
    }

    #[test]
    fn journal_is_bounded() {
        let j = Journal::default();
        let entry = JournalEntry {
            at: 0,
            device: "d".to_owned(),
            record: Record::Log {
                level: Level::Info,
                message: String::new(),
            },
        };
        j.push(entry.clone());
        assert_eq!(j.entries(), std::slice::from_ref(&entry));
        assert_eq!(j.dropped(), 0);
        // Up to the bound, then only counted.
        for _ in 1..MAX_ENTRIES + 3 {
            j.push(entry.clone());
        }
        assert_eq!(j.entries().len(), MAX_ENTRIES);
        assert_eq!(j.dropped(), 3);
    }
}
