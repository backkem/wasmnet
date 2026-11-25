//! Portable extensions on wasmtime, end to end, with the fixture `wasmnet-pad` (a device's notes,
//! `wasmnet-test:pad/notes`) and its probe device (`components/clock-probe/examples/pad_probe.rs`):
//!
//! - the adapter `portable_adapter!` generates from the WIT links the interface, typed; the
//!   extension serves it from `Value`s (a resource with a constructor, methods and a static
//!   function, a record, an enum, a variant, an option, a tuple, a list, 16 MiB of bytes);
//! - the extension's server faults a device inside a call, and the crash is journalled with its
//!   message;
//! - the extension hears the device's life: notes survive a stop and a start, a crash clears
//!   them, a controller's recreation keeps them (`DeviceLife::replaced`), a removal drops them;
//! - two seeds, and a rerun is byte-identical.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use support::{built, config, events, field, transcript};
use wasmnet_det_cbor::Value as Cbor;
use wasmnet_host::sim::{Op, Placement};
use wasmnet_host::wasmtime::component::Component;
use wasmnet_host::{DeviceOptions, Host, JournalEntry, Nanos, Network, Record, sim};
use wasmnet_pad::{Pad, PadOptions};

const MS: Nanos = 1_000_000;

wasmnet_host::portable_adapter!({
    name: PadAdapter,
    path: "../../wit/test-pad",
    world: "wasmnet-test:pad/user",
});

/// A host with the pad's adapter, and the probe on it.
struct World {
    host: Host,
    probe: Component,
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let ok = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args(["build", "--release", "--target", "wasm32-wasip2"])
            .args(["-p", "wasmnet-clock-probe", "--example", "pad-probe"])
            .status()
            .expect("spawn cargo")
            .success();
        assert!(ok, "building pad-probe failed");
        let host = Host::builder().extension(PadAdapter).build().expect("host");
        let probe = host
            .load(
                built()
                    .target
                    .join("wasm32-wasip2/release/examples/pad_probe.wasm"),
            )
            .expect("pad-probe");
        World { host, probe }
    })
}

fn spec(period: &str) -> String {
    let bytes = Cbor::Map(vec![
        (Cbor::text("component"), Cbor::text("pad")),
        (
            Cbor::text("config"),
            Cbor::Map(vec![(Cbor::text("period"), Cbor::text(period))]),
        ),
    ])
    .encode();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn network(seed: u64) -> Network<'static> {
    let w = world();
    let mut net = Network::new(&w.host, seed);
    net.add_extension(Pad::default());
    net.set_component_resolver(Box::new(move |name, instantiate| match name {
        "pad" => instantiate(&w.probe),
        other => Err(sim::Error::Refused(format!("no component {other}"))),
    }));
    net.set_infra_catalog(vec!["pad".to_owned()]);
    // `p`: 16 MiB through the interface, then stopped, started, crashed and started.
    net.device_with_options(
        "p",
        &w.probe,
        config(&[("period", "10ms"), ("big", "16777216")]),
        DeviceOptions::default()
            .crash_alone(true)
            .fuel_per_instant(4_000_000_000),
    )
    .unwrap();
    // `q`: its third append faults it.
    let mut faulty = DeviceOptions::default().crash_alone(true);
    faulty.ext.set(PadOptions::default().fault_at(3));
    net.device_with_options("q", &w.probe, config(&[("period", "10ms")]), faulty)
        .unwrap();
    // `r`: a controller's device, recreated, removed and created again.
    let steps = [
        format!("0ms apply r {}", spec("10ms")),
        format!("45ms apply r {}", spec("20ms")),
        "70ms remove r".to_owned(),
        format!("80ms apply r {}", spec("10ms")),
    ];
    let cfg: Vec<(String, String)> = steps
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("step.{n}"), s.clone()))
        .collect();
    let cfg: Vec<(&str, &str)> = cfg.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let ctl = w.host.load(built().path("infra_script")).unwrap();
    net.device_with_options(
        "ctl",
        &ctl,
        config(&cfg),
        DeviceOptions::default().infra(true),
    )
    .unwrap();
    for (at, op) in [
        (55, Op::stop_device("p")),
        (60, Op::start_device("p")),
        (85, Op::crash_device("p", "operator crash")),
        (90, Op::start_device("p")),
    ] {
        net.add_op(op, Placement::StartOf(at * MS)).unwrap();
    }
    net
}

fn lines(j: &[JournalEntry]) -> String {
    j.iter()
        .filter_map(|e| match &e.record {
            Record::Event { kind, fields }
                if kind.starts_with("pad-") || kind.starts_with("device-") =>
            {
                let f: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
                Some(format!("{} {} {} {}", e.at, e.device, kind, f.join(" ")))
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_adapter_links_what_the_extension_declares() {
    assert_eq!(PadAdapter::interfaces(), Pad::interfaces());
}

#[test]
fn a_portable_extension_serves_hears_and_faults_alike_at_two_seeds() {
    for seed in [42, 7] {
        let mut runs = Vec::new();
        for _ in 0..2 {
            let mut net = network(seed);
            net.run_until(120 * MS)
                .unwrap_or_else(|e| panic!("{e}\n{}", transcript(&net.journal())));
            let j = net.journal();
            let ctx = format!("seed {seed}\n{}", lines(&j));
            let boots = |dev: &str| -> Vec<String> {
                events(&j, dev, "pad-boot")
                    .iter()
                    .map(|f| field(f, "boots").to_owned())
                    .collect()
            };
            // p: 16 MiB through the interface and read back; notes kept over a stop, cleared
            // by a crash.
            let big = events(&j, "p", "pad-big");
            assert_eq!(field(&big[0], "size"), "16777216", "{ctx}");
            assert_eq!(
                field(&big[0], "tail"),
                "6d6e6f707172737475767778797a7b7c",
                "{ctx}"
            );
            assert_eq!(field(&big[0], "state"), "State::Written", "{ctx}");
            assert_eq!(boots("p"), ["0", "1", "0"], "{ctx}");
            assert_eq!(events(&j, "p", "pad-cleared").len(), 1, "{ctx}");
            assert_eq!(
                field(&events(&j, "p", "pad-names")[0], "names"),
                "big,boot",
                "{ctx}"
            );
            // q: its third append faults it, with the extension's message.
            let crashed = events(&j, "q", "device-crashed");
            assert_eq!(
                field(&crashed[0], "message"),
                "pad: append 3 failed",
                "{ctx}"
            );
            assert_eq!(events(&j, "q", "pad-fault").len(), 1, "{ctx}");
            // r: a recreation keeps the notes, a removal drops them.
            assert_eq!(boots("r"), ["0", "1", "0"], "{ctx}");
            assert_eq!(events(&j, "r", "pad-dropped").len(), 1, "{ctx}");
            runs.push((j, net.frames()));
        }
        assert!(runs[0] == runs[1], "seed {seed}: the rerun differs");
    }
}

/// The page test's portable-extension scenario, natively: `p` (1 MiB through the interface,
/// stopped, started, crashed, started), `q` (its third append faults it, armed by the
/// extension's name rule, as the page's installer arms it), and `r`, a controller's device
/// recreated, removed and created again. Writes the lines the page must match to
/// `target/pad-native.txt` (the page test reads it with `NATIVE_PAD`).
#[test]
fn page_scenario_native() {
    let w = world();
    let mut net = Network::new(&w.host, 42);
    net.add_extension(Pad::default().fault_at("q", 3));
    net.set_component_resolver(Box::new(move |name, instantiate| match name {
        "pad_probe" => instantiate(&w.probe),
        other => Err(sim::Error::Refused(format!("no component {other}"))),
    }));
    net.set_infra_catalog(vec!["pad_probe".to_owned()]);
    let alone = DeviceOptions::default().crash_alone(true);
    net.device_with_options(
        "p",
        &w.probe,
        config(&[("period", "10ms"), ("big", "1048576")]),
        alone.clone(),
    )
    .unwrap();
    net.device_with_options("q", &w.probe, config(&[("period", "10ms")]), alone)
        .unwrap();
    let spec = |period: &str| {
        let bytes = Cbor::Map(vec![
            (Cbor::text("component"), Cbor::text("pad_probe")),
            (
                Cbor::text("config"),
                Cbor::Map(vec![(Cbor::text("period"), Cbor::text(period))]),
            ),
        ])
        .encode();
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let steps = [
        ("step.0", format!("0ms apply r {}", spec("10ms"))),
        ("step.1", format!("45ms apply r {}", spec("20ms"))),
        ("step.2", "70ms remove r".to_owned()),
        ("step.3", format!("80ms apply r {}", spec("10ms"))),
    ];
    let cfg: Vec<(&str, &str)> = steps.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let ctl = w.host.load(built().path("infra_script")).unwrap();
    net.device_with_options(
        "ctl",
        &ctl,
        config(&cfg),
        DeviceOptions::default().infra(true),
    )
    .unwrap();
    for (at, op) in [
        (55, Op::stop_device("p")),
        (60, Op::start_device("p")),
        (85, Op::crash_device("p", "operator crash")),
        (90, Op::start_device("p")),
    ] {
        net.add_op(op, Placement::StartOf(at * MS)).unwrap();
    }
    net.run_until(120 * MS)
        .unwrap_or_else(|e| panic!("{e}\n{}", transcript(&net.journal())));
    let text = lines(&net.journal()) + "\n";
    let out = built().target.join("pad-native.txt");
    std::fs::write(&out, &text).unwrap();
    assert!(
        text.contains("q device-crashed message=pad: append 3 failed"),
        "{text}"
    );
}
