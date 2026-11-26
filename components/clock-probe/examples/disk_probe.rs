//! disk-probe: a stepped fabric device with no ports that keeps its state on two disks through
//! `wasi:keyvalue` and `wasmnet:keyvalue-ext` (`crates/wasmnet-disk`): `state`, every call
//! durable, and `log`, durable at `sync`. The disk tests run it on both backends.
//!
//! On its first poll it reads `boots` from `state` and scans `log` (`e/` entries), journals
//! `kv-boot {boots, entries, last, mode}` and writes `boots + 1`; then it checks the standard
//! functions (`exists`, `list-keys`, `get-many`, `set-many`, `delete-many`) and journals
//! `kv-check {keys, many}`. With `big` (bytes) in its config it sets a value of that size `reps`
//! times (default once) and reads its last 16 bytes back with `get-range` (`kv-big {size,
//! tail}`); with `fill` (bytes) it writes one value of that size and journals the answer
//! (`kv-fill {answer}`, a quota hit when it is too big). Then every `period` (default 10ms),
//! write `n` puts `e/<n>` (64 bytes) and `last` = n in one atomic write to `log`, syncs every
//! third write (`sync`, default 3; 0 never), and journals `kv-write {n}`, or `kv-error {what,
//! error}`.

// Native builds (a `cargo test --workspace`) compile it without the export, so nothing is used.
#![cfg_attr(not(target_family = "wasm"), allow(dead_code))]
// Generated bindings and `export!` need unsafe (raw ABI glue); our own code here does not.
#![allow(unsafe_code)]

use std::cell::Cell;

wit_bindgen::generate!({
    inline: r#"
        package wasmnet-test:disk-probe@0.1.0;

        world disk-probe {
            include wasmnet:link/stepped-device@0.1.0;
            include wasmnet:keyvalue-ext/disk-user@0.1.0;
        }
    "#,
    path: [
        "../../wit/deps/config",
        "../../wit/link",
        "../../wit/deps/keyvalue",
        "../../wit/keyvalue-ext",
    ],
    world: "wasmnet-test:disk-probe/disk-probe",
    generate_all,
});

use exports::wasmnet::link::device::Guest;
use wasi::config::store as config;
use wasi::keyvalue::{batch, store};
use wasmnet::keyvalue_ext::{durable, ordered};
use wasmnet::link::log;
use wasmnet::link::types::PortInfo;

thread_local! {
    static NEXT: Cell<Option<u64>> = const { Cell::new(None) };
    static N: Cell<u64> = const { Cell::new(0) };
}

fn number(key: &str, default: u64) -> u64 {
    let text = config::get(key).ok().flatten().unwrap_or_default();
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

fn fail(what: &str, e: impl std::fmt::Debug) {
    event(
        "kv-error",
        &[("what", what.to_owned()), ("error", format!("{e:?}"))],
    );
}

fn u64_of(v: Option<Vec<u8>>) -> u64 {
    v.and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map_or(0, u64::from_le_bytes)
}

fn boot() {
    let state = match store::open("state") {
        Ok(b) => b,
        Err(e) => return fail("open state", e),
    };
    let boots = u64_of(state.get("boots").ok().flatten());
    let (mut entries, mut after, mut last, mut mode) = (0u64, None::<String>, 0, String::new());
    if let Ok(lb) = store::open("log") {
        mode = format!("{:?}", durable::mode(&lb));
        loop {
            match ordered::scan(&lb, "e/", after.as_deref(), 1000, false) {
                Ok(page) if !page.is_empty() => {
                    entries += page.len() as u64;
                    after = page.last().map(|e| e.key.clone());
                }
                Ok(_) => break,
                Err(e) => {
                    fail("scan", e);
                    break;
                }
            }
        }
        last = u64_of(lb.get("last").ok().flatten());
    }
    N.set(last);
    event(
        "kv-boot",
        &[
            ("boots", boots.to_string()),
            ("entries", entries.to_string()),
            ("last", last.to_string()),
            ("mode", mode),
        ],
    );
    if let Err(e) = state.set("boots", &(boots + 1).to_le_bytes()) {
        fail("set boots", e);
    }
    check(&state);
    let big = number("big", 0);
    if big > 0 {
        let reps = number("reps", 1).max(1);
        let value: Vec<u8> = (0..big).map(|i| (i % 251) as u8).collect();
        let mut tail = Vec::new();
        for _ in 0..reps {
            if let Err(e) = state.set("big", &value) {
                return fail("set big", e);
            }
            match ordered::get_range(&state, "big", big.saturating_sub(16), 16) {
                Ok(Some(t)) => tail = t,
                other => return fail("get-range", other),
            }
        }
        let tail: String = tail.iter().map(|b| format!("{b:02x}")).collect();
        event("kv-big", &[("size", big.to_string()), ("tail", tail)]);
    }
    let fill = number("fill", 0);
    if fill > 0 {
        let answer = ordered::write(
            &state,
            &[ordered::Change::Set((
                "fill".to_owned(),
                vec![7; fill as usize],
            ))],
        );
        event("kv-fill", &[("answer", format!("{answer:?}"))]);
    }
}

/// The standard functions, on keys of their own.
fn check(state: &store::Bucket) {
    let pairs = vec![
        ("m/a".to_owned(), b"1".to_vec()),
        ("m/b".to_owned(), b"22".to_vec()),
    ];
    let many = batch::set_many(state, &pairs)
        .and_then(|()| batch::get_many(state, &["m/a".to_owned(), "m/z".to_owned()]))
        .map(|got| {
            got.iter()
                .map(|(k, v)| format!("{k}={}", v.as_ref().map_or(0, Vec::len)))
                .collect::<Vec<_>>()
                .join(",")
        });
    let exists = state.exists("m/b");
    let _ = batch::delete_many(state, &["m/b".to_owned()]);
    let keys = state
        .list_keys(None)
        .map(|r| r.keys.join(","))
        .unwrap_or_default();
    event(
        "kv-check",
        &[
            ("keys", keys),
            ("many", format!("{many:?}")),
            ("exists", format!("{exists:?}")),
        ],
    );
}

fn tick() {
    let lb = match store::open("log") {
        Ok(b) => b,
        Err(e) => return fail("open log", e),
    };
    let n = N.get() + 1;
    N.set(n);
    let changes = vec![
        ordered::Change::Set((format!("e/{n:08}"), vec![(n % 256) as u8; 64])),
        ordered::Change::Set(("last".to_owned(), n.to_le_bytes().to_vec())),
    ];
    if let Err(e) = ordered::write(&lb, &changes) {
        return fail("write", e);
    }
    let every = number("sync", 3);
    if every > 0
        && n.is_multiple_of(every)
        && let Err(e) = durable::sync(&lb)
    {
        fail("sync", e);
    }
    event("kv-write", &[("n", n.to_string())]);
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
