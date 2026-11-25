//! disk-device: a stepped fabric device with no ports that imports a test-only host capability,
//! `wasmnet-test:disk/disk`, which no host serves by default.
//! `crates/wasmnet-host/tests/faults.rs` serves it through a host extension that keeps one disk
//! per device, outside the device's store.
//!
//! On its first poll the device reads block 0 (how many times it booted on this disk), journals
//! `disk-boot {count}` and writes the count plus one back. Then every `period` (config, a
//! duration, default 10ms) it writes block 1 and journals `disk-write {n}`.

// Native builds (a `cargo test --workspace`) compile it without the export, so nothing is used.
#![cfg_attr(not(target_family = "wasm"), allow(dead_code))]
// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::Cell;

wit_bindgen::generate!({
    inline: r#"
        package wasmnet-test:disk@0.1.0;

        /// A block store the host keeps for this device.
        interface disk {
            /// Block `block`, if it was ever written.
            read: func(block: u32) -> option<list<u8>>;
            /// Writes block `block`. The host may trap here (a failing disk).
            write: func(block: u32, data: list<u8>);
        }

        world disk-device {
            include wasmnet:link/stepped-device@0.1.0;
            import disk;
        }
    "#,
    path: ["../../wit/deps/config", "../../wit/link"],
    world: "wasmnet-test:disk/disk-device",
    generate_all,
});

use exports::wasmnet::link::device::Guest;
use wasi::config::store;
use wasmnet::link::log;
use wasmnet::link::types::PortInfo;
use wasmnet_test::disk::disk;

thread_local! {
    /// The next write's instant (`None` before the first poll) and the writes so far.
    static NEXT: Cell<Option<u64>> = const { Cell::new(None) };
    static WRITES: Cell<u64> = const { Cell::new(0) };
}

/// `period` from the config: a number with `ms` or `us`, or nanoseconds.
fn period() -> u64 {
    let text = store::get("period").ok().flatten().unwrap_or_default();
    let (digits, scale) = if let Some(ms) = text.strip_suffix("ms") {
        (ms, 1_000_000)
    } else if let Some(us) = text.strip_suffix("us") {
        (us, 1_000)
    } else {
        (text.as_str(), 1)
    };
    digits
        .parse::<u64>()
        .map_or(10_000_000, |n| n * scale)
        .max(1)
}

struct Component;

impl Guest for Component {
    fn ports() -> Vec<PortInfo> {
        Vec::new()
    }

    fn receive(_now: u64, _port: u32, _frame: Vec<u8>) {}

    fn poll(now: u64) -> Option<u64> {
        let period = period();
        match NEXT.get() {
            None => {
                let count = disk::read(0)
                    .and_then(|b| <[u8; 4]>::try_from(b.as_slice()).ok())
                    .map_or(0, u32::from_le_bytes);
                log::event("disk-boot", &[("count".into(), count.to_string())]);
                disk::write(0, &(count + 1).to_le_bytes());
                NEXT.set(Some(now + period));
            }
            Some(next) if now >= next => {
                let n = WRITES.get() + 1;
                WRITES.set(n);
                disk::write(1, &n.to_le_bytes());
                log::event("disk-write", &[("n".into(), n.to_string())]);
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
