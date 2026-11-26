//! store-probe: a stepped fabric device with no ports that keeps its data through a contract of
//! its own, `wasmnet-test:bytes-store` (`wit/test-store`: records under byte keys, objects by
//! hash), which the adapter component `components/store-adapter` serves over its disks once the
//! two are composed (`wac plug`). The adapter tests run it on wasmtime.
//!
//! On its first poll it reads its boot count (record `boots`), journals `store-boot {boots}`,
//! writes it back plus one, writes records under binary keys and scans the prefix `01`
//! (`store-scan {keys}`, hex), keeps two objects (1 KiB, and `big` bytes, default 64 KiB), reads
//! the last 8 bytes of the second, lists them, removes the first and lists again
//! (`store-objects {held, tail, after}`). With `reps` in its config it then writes `reps`
//! objects of `size` bytes (default 64), through the adapter or, with `via = direct`, straight
//! to the disk `objects` under hex keys, and journals `store-bench {via, reps, size}`: what the
//! adapter costs is the difference in wall time.

// Native builds (a `cargo test --workspace`) compile it without the export, so nothing is used.
#![cfg_attr(not(target_family = "wasm"), allow(dead_code))]
// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::Cell;

wit_bindgen::generate!({
    inline: r#"
        package wasmnet-test:store-probe@0.1.0;

        world store-probe {
            include wasmnet:link/stepped-device@0.1.0;
            include wasmnet-test:bytes-store/user@0.1.0;
            import wasi:keyvalue/store@0.2.0-draft2;
            import wasmnet:keyvalue-ext/ordered@0.1.0;
        }
    "#,
    path: [
        "../../wit/deps/config",
        "../../wit/link",
        "../../wit/deps/keyvalue",
        "../../wit/keyvalue-ext",
        "../../wit/test-store",
    ],
    world: "wasmnet-test:store-probe/store-probe",
    generate_all,
});

use exports::wasmnet::link::device::Guest;
use wasi::config::store as config;
use wasi::keyvalue::store;
use wasmnet::keyvalue_ext::ordered;
use wasmnet::link::log;
use wasmnet::link::types::PortInfo;
use wasmnet_test::bytes_store::{objects, state};

thread_local! {
    static BOOTED: Cell<bool> = const { Cell::new(false) };
}

fn number(key: &str, default: u64) -> u64 {
    config::get(key)
        .ok()
        .flatten()
        .and_then(|t| t.parse().ok())
        .unwrap_or(default)
}

fn event(kind: &str, fields: &[(&str, String)]) {
    let fields: Vec<(String, String)> = fields
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    log::event(kind, &fields);
}

fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 * b.len());
    for x in b {
        s.push(char::from(D[usize::from(x >> 4)]));
        s.push(char::from(D[usize::from(x & 15)]));
    }
    s
}

fn fail(what: &str, e: impl std::fmt::Debug) {
    event(
        "store-error",
        &[("what", what.to_owned()), ("error", format!("{e:?}"))],
    );
}

fn boot() {
    let boots = match state::get(b"boots") {
        Ok(v) => v
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map_or(0, u64::from_le_bytes),
        Err(e) => return fail("get boots", e),
    };
    event("store-boot", &[("boots", boots.to_string())]);
    let changes = vec![
        state::Change::Set((b"boots".to_vec(), (boots + 1).to_le_bytes().to_vec())),
        state::Change::Set((vec![0x00], b"zero".to_vec())),
        state::Change::Set((vec![0x01, 0x02], b"a".to_vec())),
        state::Change::Set((vec![0x01, 0xff], b"b".to_vec())),
        state::Change::Set((vec![0x01], b"c".to_vec())),
        state::Change::Set((vec![0xff, 0x00], b"d".to_vec())),
    ];
    if let Err(e) = state::write(&changes) {
        return fail("write", e);
    }
    match state::scan(&[0x01], None, 10) {
        Ok(es) => {
            let keys: Vec<String> = es.iter().map(|e| hex(&e.key)).collect();
            event("store-scan", &[("keys", keys.join(","))]);
        }
        Err(e) => return fail("scan", e),
    }
    let (h1, h2) = ([0x11u8; 32], [0xeeu8; 32]);
    let big = number("big", 64 << 10) as usize;
    let value: Vec<u8> = (0..big).map(|i| (i % 251) as u8).collect();
    for (h, v) in [(&h1, vec![1u8; 1024]), (&h2, value)] {
        if let Err(e) = objects::keep(h, &v) {
            return fail("keep", e);
        }
    }
    let tail = match objects::read(&h2, big.saturating_sub(8) as u64, 8) {
        Ok(Some(t)) => hex(&t),
        other => return fail("read", other),
    };
    let held = |what| match objects::held(None, 10) {
        Ok(h) => h
            .iter()
            .map(|o| format!("{}:{}", &hex(&o.hash)[..4], o.size))
            .collect::<Vec<_>>()
            .join(","),
        Err(e) => {
            fail(what, e);
            String::new()
        }
    };
    let before = held("held");
    if let Err(e) = objects::remove(&h1) {
        return fail("remove", e);
    }
    let after = held("held after");
    event(
        "store-objects",
        &[("held", before), ("tail", tail), ("after", after)],
    );
    bench();
}

fn bench() {
    let reps = number("reps", 0);
    if reps == 0 {
        return;
    }
    let size = number("size", 64) as usize;
    let direct = config::get("via").ok().flatten().as_deref() == Some("direct");
    let value = vec![7u8; size];
    let bucket = if direct {
        match store::open("objects") {
            Ok(b) => Some(b),
            Err(e) => return fail("open objects", e),
        }
    } else {
        None
    };
    for i in 0..reps {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&i.to_be_bytes());
        let r = match &bucket {
            Some(b) => ordered::write(b, &[ordered::Change::Set((hex(&hash), value.clone()))])
                .map_err(|e| format!("{e:?}")),
            None => objects::keep(&hash, &value).map_err(|e| format!("{e:?}")),
        };
        if let Err(e) = r {
            return fail("bench", e);
        }
    }
    let via = if direct { "direct" } else { "adapter" };
    event(
        "store-bench",
        &[
            ("via", via.to_owned()),
            ("reps", reps.to_string()),
            ("size", size.to_string()),
        ],
    );
}

struct Component;

impl Guest for Component {
    fn ports() -> Vec<PortInfo> {
        Vec::new()
    }

    fn receive(_now: u64, _port: u32, _frame: Vec<u8>) {}

    fn poll(_now: u64) -> Option<u64> {
        if !BOOTED.get() {
            BOOTED.set(true);
            boot();
        }
        None
    }

    fn link_state(_now: u64, _port: u32, _up: bool) {}
}

#[cfg(target_family = "wasm")]
export!(Component);
