//! Portable exports on wasmtime: a device's export functions called by name with `Value`s
//! (`Network::invoke`, an operator event's `ExportRequest`), through the typed adapter
//! `portable_adapter!` generates for a world that exports the interface (`wasmnet-test:pad/keeper`)
//! and through the host's dynamic path (a host whose adapter only links the imports,
//! `wasmnet-test:pad/user`). Both answer alike and journal alike.
//!
//! Also: a bad argument faults the device on both paths; a served call costs its device no fuel
//! for its size; an embedder drives the run instant by instant and reads the device between
//! instants, with the journal of one run. `export_cost` (ignored; run it with `--ignored
//! --nocapture`) prints what a 4 MiB and a 16 MiB argument cost each way.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

use support::{built, config, transcript};
use wasmnet_host::sim::export::{Answered, ExportRequest};
use wasmnet_host::sim::value::Value;
use wasmnet_host::sim::{Invocation, Op, Placement};
use wasmnet_host::wasmtime::component::Component;
use wasmnet_host::{DeviceId, DeviceOptions, Host, Nanos, Network};
use wasmnet_pad::Pad;

const MS: Nanos = 1_000_000;

wasmnet_host::portable_adapter!({
    name: PadUser,
    path: "../../wit/test-pad",
    world: "wasmnet-test:pad/user",
});

wasmnet_host::portable_adapter!({
    name: PadKeeper,
    path: "../../wit/test-pad",
    world: "wasmnet-test:pad/keeper",
});

/// A host and the probe loaded on it.
struct World {
    host: Host,
    probe: Component,
}

fn probe_path() -> std::path::PathBuf {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let ok = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args(["build", "--release", "--target", "wasm32-wasip2"])
            .args(["-p", "wasmnet-clock-probe", "--example", "pad-probe"])
            .status()
            .expect("spawn cargo")
            .success();
        assert!(ok, "building pad-probe failed");
    });
    built()
        .target
        .join("wasm32-wasip2/release/examples/pad_probe.wasm")
}

/// The typed host (`true`: the keeper's adapter) or the dynamic one.
fn world(typed: bool) -> &'static World {
    static TYPED: OnceLock<World> = OnceLock::new();
    static DYNAMIC: OnceLock<World> = OnceLock::new();
    let make = || {
        let host = if typed {
            Host::builder().extension(PadKeeper).build()
        } else {
            Host::builder().extension(PadUser).build()
        }
        .expect("host");
        let probe = host.load(probe_path()).expect("pad-probe");
        World { host, probe }
    };
    if typed {
        TYPED.get_or_init(make)
    } else {
        DYNAMIC.get_or_init(make)
    }
}

fn network(typed: bool, seed: u64) -> (Network<'static>, DeviceId) {
    let w = world(typed);
    let mut net = Network::new(&w.host, seed);
    net.add_extension(Pad::default());
    let p = net
        .device_with_options(
            "p",
            &w.probe,
            config(&[("period", "10ms")]),
            DeviceOptions::default(),
        )
        .expect("probe");
    (net, p)
}

fn inspect(function: &str, args: Vec<Value>) -> Invocation {
    Invocation::new("wasmnet-test:pad/inspect", function, args)
}

fn invoke(net: &mut Network<'_>, p: DeviceId, inv: Invocation) -> Option<Result<Answered, String>> {
    net.invoke(p, inv).expect("invoke")
}

/// The answers and the journal of one run.
fn scenario(typed: bool, seed: u64) -> (Vec<String>, String) {
    let (mut net, p) = network(typed, seed);
    net.run_until(MS).expect("run");
    let mut answers = vec![net.device_exports(p).join(",")];
    let mut call = |net: &mut Network<'_>, inv| answers.push(format!("{:?}", invoke(net, p, inv)));
    call(
        &mut net,
        inspect(
            "write",
            vec![Value::str("ext"), Value::Bytes(b"hello".to_vec())],
        ),
    );
    net.add_op(
        Op::control(
            p,
            ExportRequest::new(inspect(
                "write",
                vec![Value::str("ext"), Value::Bytes(vec![7; 1 << 20])],
            ))
            .into_control(),
        ),
        Placement::StartOf(5 * MS),
    )
    .expect("op");
    net.run_until(30 * MS).expect("run");
    call(&mut net, inspect("size", vec![Value::str("ext")]));
    call(&mut net, inspect("size", vec![Value::str("none")]));
    call(
        &mut net,
        inspect(
            "read",
            vec![Value::str("ext"), Value::U64(0), Value::U32(8)],
        ),
    );
    call(&mut net, inspect("missing", Vec::new()));
    call(
        &mut net,
        Invocation::new("wasmnet-test:pad/nope", "x", Vec::new()),
    );
    let states = format!("{:?}", net.op_states());
    answers.push(states);
    (answers, transcript(&net.journal()))
}

#[test]
fn typed_and_dynamic_exports_answer_alike() {
    for seed in [42, 7] {
        let (typed, typed_journal) = scenario(true, seed);
        let (dynamic, dynamic_journal) = scenario(false, seed);
        assert_eq!(typed, dynamic, "seed {seed}");
        assert_eq!(typed_journal, dynamic_journal, "seed {seed}");
        assert!(typed[0].contains("wasmnet-test:pad/inspect"), "{typed:?}");
        assert!(typed[0].contains("wasmnet:link/device"), "{typed:?}");
        assert_eq!(typed[1], "Some(Ok(Ok(U64(5))))");
        assert_eq!(typed[2], format!("Some(Ok(Ok(U64({}))))", 5 + (1 << 20)));
        assert_eq!(typed[3], "Some(Ok(Ok(None)))");
        assert_eq!(
            typed[4],
            format!("Some(Ok(Ok(Bytes({:?}))))", b"hello\x07\x07\x07")
        );
        assert!(typed[5].starts_with("Some(Err("), "{typed:?}");
        assert_eq!(typed[6], "None");
        assert!(typed_journal.contains("pad-written"), "{typed_journal}");
        // A rerun is byte-identical.
        assert_eq!(scenario(true, seed).1, typed_journal);
    }
}

#[test]
fn a_bad_argument_faults_the_device() {
    for typed in [true, false] {
        let (mut net, p) = network(typed, 1);
        net.run_until(MS).expect("run");
        let err = net
            .invoke(p, inspect("size", vec![Value::U32(3)]))
            .expect_err("a trap");
        assert!(err.to_string().contains("size"), "{err}");
    }
}

#[test]
#[ignore = "a measurement: run with --ignored --nocapture"]
fn export_cost() {
    for mib in [4usize, 16] {
        for typed in [true, false] {
            let (mut net, p) = network(typed, 1);
            net.run_until(MS).expect("run");
            let bytes = vec![3u8; mib << 20];
            let mut best = f64::MAX;
            for _ in 0..5 {
                let inv = inspect("write", vec![Value::str("x"), Value::Bytes(bytes.clone())]);
                let t = Instant::now();
                let answer = invoke(&mut net, p, inv);
                best = best.min(t.elapsed().as_secs_f64() * 1e3);
                assert!(matches!(answer, Some(Ok(Ok(_)))), "{answer:?}");
            }
            let way = if typed { "typed" } else { "dynamic" };
            println!("export write {mib} MiB, {way}: {best:.2} ms");
        }
    }
}

/// The fuel a device spends on a call is its own code's: what the host does for it (copying the
/// argument in, the extension's server copying the bytes out of the device's memory) costs none,
/// so a 16 MiB write costs about what a 16-byte one does.
#[test]
fn a_served_call_costs_its_device_no_fuel_for_its_size() {
    let fuel = |len: usize| {
        let (mut net, p) = network(true, 1);
        net.run_until(MS).expect("run");
        let before = net.cost_of("p").fuel;
        let inv = inspect("write", vec![Value::str("x"), Value::Bytes(vec![1; len])]);
        assert!(matches!(invoke(&mut net, p, inv), Some(Ok(Ok(_)))));
        net.cost_of("p").fuel - before
    };
    let (small, big) = (fuel(16), fuel(16 << 20));
    println!("fuel of a write: 16 B {small}, 16 MiB {big}");
    assert!(small > 0, "fuel is metered");
    assert!(big < small * 2, "16 B: {small}, 16 MiB: {big}");
}

/// An embedder's own run loop: one instant at a time (`next_event_time`, then `run_until` it),
/// reading the device through its export between instants. The journal is the one a single
/// run gives: a call that does not reschedule leaves the device's schedule alone.
#[test]
fn an_embedder_drives_the_run_instant_by_instant() {
    let deadline = 60 * MS;
    let (mut whole, _) = network(true, 3);
    whole.run_until(deadline).expect("run");
    let (mut net, p) = network(true, 3);
    let mut sizes = Vec::new();
    while let Some(t) = net.next_event_time().filter(|t| *t <= deadline) {
        net.run_until(t).expect("run");
        let size = invoke(&mut net, p, inspect("size", vec![Value::str("log")]));
        sizes.push(format!("{t}: {size:?}"));
    }
    net.run_until(deadline).expect("run");
    assert_eq!(transcript(&net.journal()), transcript(&whole.journal()));
    // The log note grows by 64 bytes every 10 ms (the first append at 10 ms).
    assert!(
        sizes.iter().any(|s| s.ends_with("Some(Ok(Ok(U64(320))))")),
        "{sizes:?}"
    );
}
