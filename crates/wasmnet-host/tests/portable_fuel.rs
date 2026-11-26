//! A device's fuel span on wasmtime (`FuelSpan`, `DeviceExt::fuel_span`): a stretch of one
//! instant in which the device's work costs it no fuel, for a server that lets a controller work
//! on a stopped device. With the pad's probe (`components/clock-probe/examples/pad_probe.rs`) and
//! a test extension, added after the pad, that puts a server in front of the pad's to open and
//! close spans at chosen calls, and keeps each device's handle for the test's actions:
//!
//! - the device code between a span's begin and end in one call costs it nothing, and its run is
//!   otherwise the same;
//! - export calls a controller makes into the device during a span leave it with the fuel it
//!   had: the run with them and the run without have one journal and one cost, and with a budget
//!   the calls would exhaust, the spanned run goes on where the unspanned one runs out;
//! - a second begin changes nothing; a span left open ends with its instant, and the device's
//!   later work is metered as before;
//! - a device's stop, crash or removal closes its span for good, and a restarted device has a
//!   new one.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use support::{built, config, events, transcript};
use wasmnet_host::sim::export::ExportRequest;
use wasmnet_host::sim::ext::DeviceSetup;
use wasmnet_host::sim::value::Value;
use wasmnet_host::sim::{
    DeviceCost, DeviceExt, FuelSpan, ImportServer, Invocation, NetworkExtension, Op, Placement,
    Served,
};
use wasmnet_host::wasmtime::component::Component;
use wasmnet_host::{DeviceOptions, Host, Nanos, Network};
use wasmnet_pad::{NOTES, Pad};

const MS: Nanos = 1_000_000;

wasmnet_host::portable_adapter!({
    name: PadKeeper,
    path: "../../wit/test-pad",
    world: "wasmnet-test:pad/keeper",
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
        let host = Host::builder().extension(PadKeeper).build().expect("host");
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

/// Where a device's server opens and closes its span: after every call of these functions.
#[derive(Clone, Default)]
struct Plan {
    begin: Vec<&'static str>,
    end: Vec<&'static str>,
}

/// What the test sees: each device's latest span handle, and what every begin and end answered.
#[derive(Clone, Default)]
struct Seen {
    spans: Arc<Mutex<BTreeMap<String, FuelSpan>>>,
    log: Arc<Mutex<Vec<String>>>,
}

impl Seen {
    fn span(&self, device: &str) -> FuelSpan {
        self.spans.lock().unwrap()[device].clone()
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

/// The test extension (added after the pad).
struct Spans {
    plans: BTreeMap<&'static str, Plan>,
    seen: Seen,
}

impl NetworkExtension for Spans {
    fn device_setup(&mut self, setup: &DeviceSetup<'_>, ext: &mut DeviceExt) {
        let span = ext.fuel_span().clone();
        self.seen
            .spans
            .lock()
            .unwrap()
            .insert(setup.name.to_owned(), span.clone());
        if let Some(plan) = self.plans.get(setup.name) {
            let inner = ext.server(NOTES).expect("the pad's server").clone();
            ext.serve(
                NOTES,
                Arc::new(Spanning {
                    inner,
                    span,
                    plan: plan.clone(),
                    log: self.seen.log.clone(),
                }),
            );
        }
    }
}

/// The pad's server, then the span's begin or end the plan puts after the call.
struct Spanning {
    inner: Arc<dyn ImportServer>,
    span: FuelSpan,
    plan: Plan,
    log: Arc<Mutex<Vec<String>>>,
}

impl ImportServer for Spanning {
    fn call(&self, interface: &str, function: &str, args: Vec<Value>) -> Served {
        let served = self.inner.call(interface, function, args);
        if self.plan.begin.contains(&function) {
            let r = self.span.begin();
            self.log
                .lock()
                .unwrap()
                .push(format!("{function} begin {r}"));
        }
        if self.plan.end.contains(&function) {
            let r = self.span.end();
            self.log.lock().unwrap().push(format!("{function} end {r}"));
        }
        served
    }

    fn drop_resource(&self, interface: &str, resource: &str, handle: u32) {
        self.inner.drop_resource(interface, resource, handle);
    }
}

/// A network with the pad and the test extension; the action `span` begins (argument `begin`)
/// or ends (`end`) the span of the device it names.
fn network(plans: &[(&'static str, Plan)]) -> (Network<'static>, Seen) {
    let w = world();
    let mut net = Network::new(&w.host, 5);
    net.add_extension(Pad::default());
    let seen = Seen::default();
    net.add_extension(Spans {
        plans: plans.iter().cloned().collect(),
        seen: seen.clone(),
    });
    let s = seen.clone();
    net.register_action("span", move |_ctx, call| {
        let span = s.span(call.device);
        let r = match call.argument {
            "begin" => span.begin(),
            _ => span.end(),
        };
        s.log
            .lock()
            .unwrap()
            .push(format!("{} {} {r}", call.device, call.argument));
        Ok(())
    });
    (net, seen)
}

fn probe(net: &mut Network<'static>, name: &str, cfg: &[(&str, &str)], options: DeviceOptions) {
    net.device_with_options(name, &world().probe, config(cfg), options)
        .unwrap();
}

fn fuel(cost: &DeviceCost) -> (u64, u64, Nanos) {
    (cost.fuel, cost.peak_fuel, cost.peak_fuel_at)
}

/// The device code between a span's begin and end inside one of its calls (here most of the
/// probe's boot: building a 256 KiB value and appending it) costs it nothing; everything else
/// of the run is the same.
#[test]
fn work_between_a_spans_begin_and_end_costs_nothing() {
    let run = |spanned: bool| {
        let plan = Plan {
            begin: vec!["[static]note.find"],
            end: vec!["names"],
        };
        let plans = if spanned { vec![("p", plan)] } else { vec![] };
        let (mut net, seen) = network(&plans);
        let cfg = [("period", "10ms"), ("big", "262144")];
        probe(&mut net, "p", &cfg, DeviceOptions::default());
        net.run_until(35 * MS).unwrap();
        let tick = net.cost_of("p").fuel;
        net.run_until(65 * MS).unwrap();
        let cost = net.cost_of("p");
        (
            transcript(&net.journal()),
            fuel(&cost),
            cost.fuel - tick,
            seen.log(),
        )
    };
    let (plain, spanned) = (run(false), run(true));
    assert!(plain.0 == spanned.0, "the journals differ");
    assert_eq!(
        spanned.3,
        ["[static]note.find begin true", "names end true"],
        "{:?}",
        spanned.3
    );
    // The boot (instant 0) is the peak of both; with the span, most of it is not counted.
    let ((pf, pp, pat), (sf, sp, sat)) = (plain.1, spanned.1);
    assert_eq!((pat, sat), (0, 0));
    assert!(sp * 4 < pp, "peak: plain {pp}, spanned {sp}");
    assert_eq!(pf - sf, pp - sp, "only the boot's spanned work is missing");
    // The later ticks cost the same.
    assert_eq!(plain.2, spanned.2);
    println!("boot fuel: plain {pp}, spanned {sp}");
}

/// The determinism bar: a controller's export calls made into the device during a span (50
/// reads, at 10 ms, between the actions that begin and end it) leave the device as it was. The
/// run with them and the run without them have one journal and one cost; the device's own work
/// at that instant (its tick, after the reads) runs on the fuel it had. With a budget the reads
/// would exhaust, the run without a span runs out of fuel, the spanned one does not change.
#[test]
fn export_calls_during_a_span_leave_the_device_as_it_was() {
    const READS: usize = 50;
    let run = |span: bool, reads: bool, budget: Option<u64>| {
        let (mut net, seen) = network(&[]);
        let mut options = DeviceOptions::default().crash_alone(true);
        if let Some(b) = budget {
            options = options.fuel_per_instant(b);
        }
        probe(&mut net, "p", &[("period", "10ms")], options);
        let p = net.live_device("p").unwrap();
        let at = || Placement::StartOf(10 * MS);
        if span {
            net.add_op(Op::action("span", "p", "begin"), at()).unwrap();
        }
        if reads {
            for _ in 0..READS {
                let read = Invocation::new(
                    "wasmnet-test:pad/inspect",
                    "read",
                    vec![Value::str("boot"), Value::U64(0), Value::U32(1)],
                );
                net.add_op(
                    Op::control(p, ExportRequest::new(read).into_control()),
                    at(),
                )
                .unwrap();
            }
        }
        if span {
            net.add_op(Op::action("span", "p", "end"), at()).unwrap();
        }
        net.run_until(45 * MS).unwrap();
        let cost = net.cost_of("p");
        (transcript(&net.journal()), fuel(&cost), seen.log())
    };
    let with = run(true, true, None);
    let without = run(true, false, None);
    let unspanned = run(false, true, None);
    assert!(with.0 == without.0, "the journals differ");
    assert_eq!(with.1, without.1, "the costs differ");
    assert_eq!(with.2, ["p begin true", "p end true"]);
    // Without a span the reads cost the device, at that instant.
    let (peak, read_peak) = (without.1.1, unspanned.1.1);
    assert!(unspanned.1.0 > without.1.0);
    assert_eq!(unspanned.1.2, 10 * MS, "{:?}", unspanned.1);
    assert!(read_peak > peak * 2, "{peak} {read_peak}");
    // A budget between the two: the spanned run is the one it was, the other runs out.
    let budget = peak + (read_peak - peak) / 2;
    let tight = run(true, true, Some(budget));
    assert!(
        tight.0 == without.0,
        "the spanned run changed under a tight budget"
    );
    let starved = run(false, true, Some(budget));
    let crashed = starved.0.contains("device-crashed") && starved.0.contains("fuel");
    assert!(crashed, "{}", starved.0);
    println!("fuel at 10 ms: tick {peak}, tick and {READS} reads {read_peak}");
}

/// A second begin changes nothing; a span never ended closes with its instant, and the device's
/// later work is metered as it was without one.
#[test]
fn a_span_left_open_ends_with_its_instant() {
    let run = |spanned: bool| {
        let plan = Plan {
            begin: vec!["[static]note.find", "totals"],
            end: vec![],
        };
        let plans = if spanned { vec![("p", plan)] } else { vec![] };
        let (mut net, seen) = network(&plans);
        probe(
            &mut net,
            "p",
            &[("period", "10ms")],
            DeviceOptions::default(),
        );
        net.run_until(15 * MS).unwrap();
        let early = net.cost_of("p").fuel;
        net.run_until(45 * MS).unwrap();
        let cost = net.cost_of("p");
        let open = seen.span("p").is_open();
        (
            transcript(&net.journal()),
            cost.fuel - early,
            open,
            seen.log(),
        )
    };
    let (plain, spanned) = (run(false), run(true));
    assert!(plain.0 == spanned.0, "the journals differ");
    assert_eq!(
        spanned.3,
        ["[static]note.find begin true", "totals begin false"]
    );
    assert!(!spanned.2, "closed with its instant");
    assert_eq!(plain.1, spanned.1, "the ticks after it are metered alike");
    assert!(plain.1 > 0);
}

/// A device's stop, crash or removal closes its span for good (before the extensions hear of
/// it); a device started again has a new span.
#[test]
fn a_span_ends_with_its_device() {
    let (mut net, seen) = network(&[]);
    for name in ["s", "c", "r"] {
        let options = DeviceOptions::default().crash_alone(true);
        probe(&mut net, name, &[("period", "10ms")], options);
    }
    let at = || Placement::StartOf(10 * MS);
    for (name, op) in [
        ("s", Op::stop_device("s")),
        ("c", Op::crash_device("c", "operator crash")),
        ("r", Op::remove_device("r")),
    ] {
        net.add_op(Op::action("span", name, "begin"), at()).unwrap();
        net.add_op(op, at()).unwrap();
    }
    net.run_until(10 * MS).unwrap();
    let old: Vec<FuelSpan> = ["s", "c", "r"].iter().map(|n| seen.span(n)).collect();
    for span in &old {
        assert!(!span.is_open());
        assert!(!span.begin(), "a span of a gone incarnation never opens");
    }
    assert_eq!(seen.log(), ["s begin true", "c begin true", "r begin true"]);
    net.add_op(Op::start_device("s"), Placement::StartOf(20 * MS))
        .unwrap();
    net.add_op(Op::action("span", "s", "begin"), Placement::EndOf(20 * MS))
        .unwrap();
    net.run_until(30 * MS).unwrap();
    assert_eq!(seen.log().last().unwrap(), "s begin true");
    assert!(!old[0].begin());
    assert!(net.cost_of("s").fuel > 0);
    let started = events(&net.journal(), "s", "device-started");
    assert_eq!(started.len(), 1);
}
