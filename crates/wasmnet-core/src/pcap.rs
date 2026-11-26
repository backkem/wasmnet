//! Captures: the pcap-ng reader, and the limits on a link's capture notes.
//!
//! The reader ([`parse`], [`parse_header`], [`Capture`], [`LinkEnd`], ...) lives in
//! `wasmnet-wire` beside the encoder ([`wasmnet_wire::pcap`]) and is re-exported here, so
//! `wasmnet_core::pcap::parse` keeps working. What is the core's own is the rule for the notes
//! a link's capture carries ([`check_notes`]), which [`crate::Network::set_capture_notes`]
//! enforces.

pub use wasmnet_wire::pcap::*;

/// The most notes a link's capture holds ([`crate::Network::set_capture_notes`]).
pub const MAX_NOTES: usize = 16;
/// The longest note, in bytes of UTF-8.
pub const MAX_NOTE_BYTES: usize = 1024;

/// Checks a link's capture notes: at most [`MAX_NOTES`], none empty, none longer than
/// [`MAX_NOTE_BYTES`]. The error says which rule a note breaks.
///
/// ```
/// # use wasmnet_core::pcap::check_notes;
/// assert!(check_notes(&["UDP 6081: Geneve with STUN checks"]).is_ok());
/// assert!(check_notes(&[""]).is_err());
/// assert!(check_notes(&["x".repeat(1025)]).is_err());
/// ```
pub fn check_notes<S: AsRef<str>>(notes: &[S]) -> Result<(), String> {
    if notes.len() > MAX_NOTES {
        return Err(format!(
            "{} capture notes, at most {MAX_NOTES} allowed",
            notes.len()
        ));
    }
    for (i, note) in notes.iter().enumerate() {
        let len = note.as_ref().len();
        if len == 0 {
            return Err(format!("capture note {i} is empty"));
        }
        if len > MAX_NOTE_BYTES {
            return Err(format!(
                "capture note {i} has {len} bytes, at most {MAX_NOTE_BYTES} allowed"
            ));
        }
    }
    Ok(())
}
