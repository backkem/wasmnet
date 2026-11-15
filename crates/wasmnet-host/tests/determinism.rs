//! Acceptance test: the clock-probe guests produce byte-identical output for the same seed,
//! different entropy for a different seed, and only ever see virtual time.
//!
//! The guests are built by shelling out to
//! `cargo build --release --target wasm32-wasip2 -p wasmnet-clock-probe --bins --example async-probe`
//! once per test binary (`guests()`), so `cargo test -p wasmnet-host` needs nothing else.
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use wasmnet_host::{DEFAULT_WALL_EPOCH, Host, SimConfig};
use wasmtime::component::Component;

/// Must match `SLEEP` in components/clock-probe/src/main.rs.
const PROBE_SLEEP: Duration = Duration::from_millis(1500);

struct Guests {
    host: Host,
    /// Plain std wasm32-wasip2 command (`wasi:cli/run@0.2`).
    std_probe: Component,
    /// wit-bindgen async command (`wasi:cli/run@0.3`).
    async_probe: Component,
}

fn guests() -> &'static Guests {
    static GUESTS: OnceLock<Guests> = OnceLock::new();
    GUESTS.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let status = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args(["build", "--release", "--target", "wasm32-wasip2"])
            .args([
                "-p",
                "wasmnet-clock-probe",
                "--bins",
                "--example",
                "async-probe",
            ])
            .status()
            .expect("spawn cargo to build clock-probe");
        assert!(status.success(), "building clock-probe failed");

        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target"));
        let out = target.join("wasm32-wasip2/release");
        let host = Host::new().expect("host");
        let std_probe = host.load(out.join("clock-probe.wasm")).expect("load");
        let async_probe = host
            .load(out.join("examples/async_probe.wasm"))
            .expect("load");
        Guests {
            host,
            std_probe,
            async_probe,
        }
    })
}

fn run(component: &Component, seed: u64) -> (String, Duration) {
    let g = guests();
    let sim = g.host.sim(SimConfig::seeded(seed));
    let started = Instant::now();
    let out = sim
        .run_command("probe", component, &[])
        .unwrap_or_else(|e| panic!("seed={seed}: {e}"));
    let real = started.elapsed();
    assert!(
        out.success,
        "seed={seed}: guest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty(), "seed={seed}: unexpected stderr");
    (String::from_utf8(out.stdout).expect("utf-8 stdout"), real)
}

/// Values of `key=` in the probe's output, in order.
fn values<'a>(out: &'a str, key: &str) -> Vec<&'a str> {
    out.lines()
        .filter_map(|l| l.trim().strip_prefix(key)?.strip_prefix('='))
        .collect()
}

#[test]
fn same_seed_is_byte_identical() {
    let g = guests();
    for component in [&g.std_probe, &g.async_probe] {
        let (a, _) = run(component, 42);
        let (b, _) = run(component, 42);
        assert_eq!(a, b, "seed=42 replay diverged");
        println!("{a}");
    }
}

#[test]
fn different_seed_changes_entropy_not_time() {
    let g = guests();
    let (a, _) = run(&g.std_probe, 42);
    let (b, _) = run(&g.std_probe, 43);
    for key in ["random_u64", "insecure_u64", "insecure_seed", "std_hash"] {
        let (va, vb) = (values(&a, key), values(&b, key));
        assert_eq!(va.len(), 2, "{key} missing from:\n{a}");
        assert!(
            va.iter().zip(&vb).all(|(x, y)| x != y),
            "{key}: {va:?} vs {vb:?}"
        );
    }
    // Two draws in one run differ too (the PRNG advances).
    let r = values(&a, "random_u64");
    assert_ne!(r[0], r[1]);
    for key in ["monotonic_ns", "wall", "systemtime_ns"] {
        assert_eq!(
            values(&a, key),
            values(&b, key),
            "{key} must not depend on seed"
        );
    }
}

#[test]
fn clocks_are_virtual_and_sleep_advances_them_instantly() {
    let (out, real) = run(&guests().std_probe, 42);
    let sleep_ns = PROBE_SLEEP.as_nanos().to_string();
    let epoch = DEFAULT_WALL_EPOCH;
    let after = epoch + PROBE_SLEEP;

    assert_eq!(values(&out, "monotonic_ns"), ["0", sleep_ns.as_str()]);
    assert_eq!(values(&out, "instant_elapsed_ns"), ["0", sleep_ns.as_str()]);
    assert_eq!(
        values(&out, "wall"),
        [
            format!("{}.{:09}", epoch.as_secs(), epoch.subsec_nanos()),
            format!("{}.{:09}", after.as_secs(), after.subsec_nanos()),
        ]
    );
    assert_eq!(
        values(&out, "systemtime_ns"),
        [epoch.as_nanos().to_string(), after.as_nanos().to_string()]
    );
    // A real sleep would take at least PROBE_SLEEP of wall time.
    assert!(
        real < PROBE_SLEEP,
        "run took {real:?}: sleep used real time"
    );
}

#[test]
fn p3_waits_fire_at_virtual_deadlines_in_order() {
    let (out, real) = run(&guests().async_probe, 42);
    assert!(out.contains("p3 t0=0 wall=1767225600.000000000\n"), "{out}");
    assert!(
        out.contains("p3 fast_done=+100000000 slow_done=+300000000\n"),
        "{out}"
    );
    assert!(out.contains("p3 after_wait_until=+1000000000\n"), "{out}");
    assert!(real < Duration::from_secs(1), "run took {real:?}");
}

#[test]
fn std_guest_imports_have_no_ambient_authority() {
    let g = guests();
    let imports = g.host.imports(&g.std_probe);
    println!("clock-probe imports:\n  {}", imports.join("\n  "));
    for name in &imports {
        assert!(
            !name.starts_with("wasi:sockets/") && !name.starts_with("wasi:filesystem/"),
            "unexpected ambient import {name}"
        );
    }
    assert!(
        imports
            .iter()
            .any(|i| i.starts_with("wasi:clocks/monotonic-clock@0.2"))
    );
    assert!(
        g.host
            .imports(&g.async_probe)
            .iter()
            .any(|i| i.starts_with("wasi:clocks/monotonic-clock@0.3"))
    );
}
