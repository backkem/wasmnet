//! What an extension needs around its calls, end to end on wasmtime with the fixture
//! `wasmnet-pad`:
//!
//! - a device option of the extension's, set from a generic value (`Network::set_option`) and
//!   from a controller's spec (a key of the extension's own), checked before the device is
//!   created (`NetworkExtension::check_options`);
//! - an operator event of the extension's timed at a device (`Op::ExtensionAt`), built from a
//!   generic value (`Network::parse_op`), and accepted in a split network;
//! - a cable kind registered twice is refused.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, OnceLock};

use support::{built, config, events, field, transcript};
use wasmnet_det_cbor::Value as Cbor;
use wasmnet_host::sim::ext::{CableModel, CableSend, Carry};
use wasmnet_host::sim::infra::Phase;
use wasmnet_host::sim::value::Value;
use wasmnet_host::sim::{CableKind, Op, Placement};
use wasmnet_host::wasmtime::component::Component;
use wasmnet_host::{DeviceOptions, Host, Nanos, Network, sim};
use wasmnet_pad::Pad;

const MS: Nanos = 1_000_000;

wasmnet_host::portable_adapter!({
    name: PadAdapter,
    path: "../../wit/test-pad",
    world: "wasmnet-test:pad/user",
});

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

fn network(seed: u64) -> Network<'static> {
    let w = world();
    let mut net = Network::new(&w.host, seed);
    net.add_extension(Pad::default());
    net.set_component_resolver(Box::new(move |name, instantiate| match name {
        "pad" => instantiate(&w.probe),
        other => Err(sim::Error::Refused(format!("no component {other}"))),
    }));
    net.set_infra_catalog(vec!["pad".to_owned()]);
    net
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn spec(extra: Vec<(&str, Cbor)>) -> String {
    let mut m = vec![
        (Cbor::text("component"), Cbor::text("pad")),
        (
            Cbor::text("config"),
            Cbor::Map(vec![(Cbor::text("period"), Cbor::text("10ms"))]),
        ),
    ];
    m.extend(extra.into_iter().map(|(k, v)| (Cbor::text(k), v)));
    hex(&Cbor::Map(m).encode())
}

#[test]
fn options_from_rust_and_from_a_spec_ops_at_a_device_alike_at_two_seeds() {
    for seed in [42, 7] {
        let mut runs = Vec::new();
        for _ in 0..2 {
            let w = world();
            let mut net = network(seed);
            // From Rust, through the extension's own parser.
            let mut options = DeviceOptions::default().crash_alone(true);
            net.set_option(&mut options, "pad.fault-at", &Value::U32(2))
                .unwrap();
            net.device_with_options("a", &w.probe, config(&[("period", "10ms")]), options)
                .unwrap();
            let b = net
                .device_with_options(
                    "b",
                    &w.probe,
                    config(&[("period", "10ms")]),
                    DeviceOptions::default(),
                )
                .unwrap();
            // From a controller's spec: its own key, its refusal, a key nobody reads.
            let steps = [
                format!(
                    "0ms apply c {}",
                    spec(vec![("pad.fault-at", Cbor::Uint(2))])
                ),
                format!(
                    "0ms apply z {}",
                    spec(vec![("pad.fault-at", Cbor::Uint(0))])
                ),
                format!("0ms apply u {}", spec(vec![("pad.nope", Cbor::Uint(1))])),
            ];
            let cfg: Vec<(String, String)> = steps
                .iter()
                .enumerate()
                .map(|(n, s)| (format!("step.{n}"), s.clone()))
                .collect();
            let cfg: Vec<(&str, &str)> =
                cfg.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let ctl = w.host.load(built().path("infra_script")).unwrap();
            net.device_with_options(
                "ctl",
                &ctl,
                config(&cfg),
                DeviceOptions::default().infra(true),
            )
            .unwrap();
            // An extension's op timed at `b`, built from a generic value.
            let clear = net.parse_op("pad.clear", &Value::None).unwrap();
            net.add_op(Op::extension_at(b, clear), Placement::StartOf(25 * MS))
                .unwrap();
            net.run_until(40 * MS)
                .unwrap_or_else(|e| panic!("{e}\n{}", transcript(&net.journal())));
            let j = net.journal();
            let ctx = format!("seed {seed}\n{}", transcript(&j));
            for dev in ["a", "c"] {
                let crashed = events(&j, dev, "device-crashed");
                assert_eq!(
                    field(&crashed[0], "message"),
                    "pad: append 2 failed",
                    "{dev}: {ctx}"
                );
            }
            let cleared = events(&j, "b", "pad-cleared");
            assert_eq!(field(&cleared[0], "by"), "operator", "{ctx}");
            // The spec keeps the extension's key as given.
            let c = net.infra().get("c").unwrap();
            assert!(
                c.spec.windows(12).any(|w| w == b"pad.fault-at"),
                "{:?}",
                c.spec
            );
            let z = net.infra().get("z").unwrap();
            assert_eq!(z.phase, Phase::Failed, "{ctx}");
            assert!(
                z.message
                    .as_deref()
                    .unwrap_or("")
                    .contains("pad.fault-at counts appends from 1"),
                "{z:?}"
            );
            let refused: Vec<String> = events(&j, "ctl", "infra-script")
                .iter()
                .map(|f| field(f, "result").to_owned())
                .collect();
            assert!(
                refused.iter().any(|r| r.contains("unknown key `pad.nope`")),
                "{refused:?}"
            );
            runs.push((j, net.frames()));
        }
        assert!(runs[0] == runs[1], "seed {seed}: the rerun differs");
    }
}

#[test]
fn the_builder_checks_an_extensions_options() {
    let w = world();
    let mut net = network(1);
    let mut options = DeviceOptions::default();
    net.set_option(&mut options, "pad.fault-at", &Value::U32(0))
        .unwrap();
    let err = net
        .device_with_options("a", &w.probe, config(&[]), options)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("pad.fault-at counts appends from 1"),
        "{err}"
    );
    assert!(net.parse_option("pad.nope", &Value::U32(1)).is_err());
    assert_eq!(net.option_keys(), ["pad.fault-at"]);
}

#[test]
fn an_extension_op_at_a_device_is_accepted_in_a_split_network() {
    let w = world();
    let mut net = network(1);
    let here = net
        .device_with_options("here", &w.probe, config(&[]), DeviceOptions::default())
        .unwrap();
    let far = net.remote_device("far").unwrap();
    let clear = || sim::ExtensionOp::new(wasmnet_pad::PadOp::Clear);
    net.add_op(Op::extension_at(here, clear()), Placement::StartOf(MS))
        .unwrap();
    net.add_op(Op::extension_at(far, clear()), Placement::StartOf(MS))
        .unwrap();
    assert!(
        net.add_op(Op::Extension(clear()), Placement::StartOf(MS))
            .is_err(),
        "an op not timed at a device is refused in a split network"
    );
}

struct Echo;
impl CableModel for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn carry(&self, _: &CableSend<'_>, _: Option<&mut (dyn std::any::Any + Send)>) -> Carry {
        Carry::Forward
    }
}

#[test]
fn a_cable_kind_has_one_model() {
    let mut net = network(1);
    let kind = CableKind::new(7);
    net.register_cable(kind, Arc::new(Echo)).unwrap();
    let again = net.register_cable(kind, Arc::new(Echo)).unwrap_err();
    assert!(
        again.to_string().contains("already has a model (echo)"),
        "{again}"
    );
}
