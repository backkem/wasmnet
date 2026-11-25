//! pad-probe: a stepped fabric device with no ports that keeps notes through a portable
//! extension's interface, `wasmnet-test:pad/notes` (`crates/wasmnet-pad`), which no host serves
//! by default. The tests of portable extensions run it on both backends.
//!
//! On its first poll it counts its boots in the note `boot` (found with `note.find`, one byte
//! appended per boot), journals `pad-boot {boots, notes, bytes}`, and with `big` in its config
//! (bytes) appends that many bytes to the note `big` and reads the last 16 back
//! (`pad-big {size, tail, state}`), then journals the device's note names (`pad-names`). Then
//! every `period` (default 10ms) it appends 64 bytes to the note `log`: `pad-append {size}`, or
//! `pad-error {error}`.

// Native builds (a `cargo test --workspace`) compile it without the export, so nothing is used.
#![cfg_attr(not(target_family = "wasm"), allow(dead_code))]
// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::{Cell, RefCell};

wit_bindgen::generate!({
    inline: r#"
        package wasmnet-test:pad-probe@0.1.0;

        world pad-probe {
            include wasmnet:link/stepped-device@0.1.0;
            include wasmnet-test:pad/user@0.1.0;
        }
    "#,
    path: ["../../wit/deps/config", "../../wit/link", "../../wit/test-pad"],
    world: "wasmnet-test:pad-probe/pad-probe",
    generate_all,
});

use exports::wasmnet::link::device::Guest;
use wasi::config::store;
use wasmnet::link::log;
use wasmnet::link::types::PortInfo;
use wasmnet_test::pad::notes::{self, Note};

thread_local! {
    static NEXT: Cell<Option<u64>> = const { Cell::new(None) };
    static LOG: RefCell<Option<Note>> = const { RefCell::new(None) };
}

fn number(key: &str, default: u64) -> u64 {
    let text = store::get(key).ok().flatten().unwrap_or_default();
    let (digits, scale) = match text.strip_suffix("ms") {
        Some(ms) => (ms, 1_000_000),
        None => (text.as_str(), 1),
    };
    digits.parse::<u64>().map_or(default, |n| n * scale)
}

fn event(kind: &str, fields: &[(&str, String)]) {
    let fields: Vec<(String, String)> = fields
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    log::event(kind, &fields);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn boot() {
    let boots = Note::find("boot").map_or(0, |n| n.info().size);
    let (count, bytes) = notes::totals();
    event(
        "pad-boot",
        &[
            ("boots", boots.to_string()),
            ("notes", count.to_string()),
            ("bytes", bytes.to_string()),
        ],
    );
    if let Err(e) = Note::new("boot").append(&[1]) {
        event("pad-error", &[("error", format!("{e:?}"))]);
    }
    let big = number("big", 0);
    if big > 0 {
        let note = Note::new("big");
        let value: Vec<u8> = (0..big).map(|i| (i % 251) as u8).collect();
        match note.append(&value) {
            Ok(size) => {
                let tail = note.read(size.saturating_sub(16), 16);
                let state = format!("{:?}", note.info().state);
                event(
                    "pad-big",
                    &[
                        ("size", size.to_string()),
                        ("tail", hex(&tail)),
                        ("state", state),
                    ],
                );
            }
            Err(e) => event("pad-error", &[("error", format!("{e:?}"))]),
        }
    }
    event("pad-names", &[("names", notes::names().join(","))]);
    LOG.with_borrow_mut(|l| *l = Some(Note::new("log")));
}

fn tick() {
    LOG.with_borrow(|l| {
        if let Some(note) = l {
            match note.append(&[7; 64]) {
                Ok(size) => event("pad-append", &[("size", size.to_string())]),
                Err(e) => event("pad-error", &[("error", format!("{e:?}"))]),
            }
        }
    });
}

struct Component;

impl Guest for Component {
    fn ports() -> Vec<PortInfo> {
        Vec::new()
    }

    fn receive(_now: u64, _port: u32, _frame: Vec<u8>) {}

    fn poll(now: u64) -> Option<u64> {
        let period = number("period", 10_000_000).max(1);
        match NEXT.get() {
            None => {
                boot();
                NEXT.set(Some(now + period));
            }
            Some(next) if now >= next => {
                tick();
                NEXT.set(Some(next + period));
            }
            Some(_) => {}
        }
        NEXT.get()
    }

    fn link_state(_now: u64, _port: u32, _up: bool) {}
}

#[cfg(target_family = "wasm")]
export!(Component);
