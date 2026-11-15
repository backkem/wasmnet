//! Captured stdout and stderr of one device, optionally journalled line by line.
//!
//! [`OutputCapture`] keeps every byte a guest writes (up to [`CAPTURE_LIMIT`]). When it has a
//! [`JournalEnd`], each completed line also becomes a [`Record::Output`] in the network journal,
//! stamped with the virtual time at which its newline was written. A runtime backend feeds it
//! from the guest's stdio streams inside the device's event loop, so the stamps are as
//! deterministic as everything else.
//!
//! Guest stdout is the natural channel for unmodified programs: with the journal, a test can
//! assert on, say, `wget -O -` output with virtual timestamps.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::clock::VirtualClock;
use crate::journal::{JournalEnd, MAX_TEXT, Record, Stream, truncate};

/// Max bytes captured per stream; a guest writing more gets a stream error (p2) or a short
/// write (p3), like wasmtime-wasi's `MemoryOutputPipe`.
pub const CAPTURE_LIMIT: usize = 16 << 20;

/// Where completed lines go.
struct Lines {
    journal: JournalEnd,
    clock: VirtualClock,
    stream: Stream,
    /// The current line so far (bounded: a longer line is cut at [`MAX_TEXT`]).
    partial: Vec<u8>,
}

#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    lines: Option<Lines>,
}

/// One captured output stream. Cloning gives another handle to the same buffer.
#[derive(Clone, Default)]
pub struct OutputCapture {
    state: Arc<Mutex<State>>,
}

impl OutputCapture {
    /// A pipe that only captures.
    pub fn new() -> Self {
        Self::default()
    }

    /// A pipe that also journals each completed line as `stream`.
    pub fn journalled(journal: JournalEnd, clock: VirtualClock, stream: Stream) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                bytes: Vec::new(),
                lines: Some(Lines {
                    journal,
                    clock,
                    stream,
                    partial: Vec::new(),
                }),
            })),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Everything written so far.
    pub fn contents(&self) -> Vec<u8> {
        self.state().bytes.clone()
    }

    /// How many more bytes fit before the capture limit.
    pub fn remaining(&self) -> usize {
        CAPTURE_LIMIT - self.state().bytes.len()
    }

    /// Appends as much of `data` as fits; returns how many bytes were taken (a backend turns a
    /// short write into the stream error its WASI flavour expects).
    /// [`Self::remaining`] says how much still fits.
    pub fn append(&self, data: &[u8]) -> usize {
        let mut s = self.state();
        let n = data.len().min(CAPTURE_LIMIT - s.bytes.len());
        let data = &data[..n];
        s.bytes.extend_from_slice(data);
        if let Some(lines) = &mut s.lines {
            for &b in data {
                if b == b'\n' {
                    lines.complete();
                } else if lines.partial.len() < MAX_TEXT {
                    lines.partial.push(b);
                }
            }
        }
        n
    }
}

impl Lines {
    fn complete(&mut self) {
        let mut raw = std::mem::take(&mut self.partial);
        if raw.last() == Some(&b'\r') {
            raw.pop();
        }
        let line = truncate(String::from_utf8_lossy(&raw).into_owned());
        self.journal.push(
            self.clock.now(),
            Record::Output {
                stream: self.stream,
                line,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Journal;

    #[test]
    fn lines_are_journalled_when_complete_and_bytes_kept() {
        let journal = Journal::default();
        let clock = VirtualClock::new(std::time::Duration::ZERO);
        let end = JournalEnd {
            journal: journal.clone(),
            device: "d".to_owned(),
        };
        let pipe = OutputCapture::journalled(end, clock.clone(), Stream::Stdout);
        assert_eq!(pipe.append(b"hel"), 3);
        clock.advance_to(5);
        pipe.append(b"lo\r\nwor");
        clock.advance_to(9);
        pipe.append(b"ld\n\npartial");
        let lines: Vec<(u64, String)> = journal
            .entries()
            .into_iter()
            .map(|e| match e.record {
                Record::Output { stream, line } => {
                    assert_eq!(stream, Stream::Stdout);
                    (e.at, line)
                }
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            lines,
            [
                (5, "hello".to_owned()),
                (9, "world".to_owned()),
                (9, String::new())
            ]
        );
        assert_eq!(pipe.contents(), b"hello\r\nworld\n\npartial");
        assert!(journal.entries().iter().all(|e| e.device == "d"));
        // A plain pipe journals nothing.
        let plain = OutputCapture::new();
        plain.append(b"x\n");
        assert_eq!(plain.contents(), b"x\n");
    }
}
