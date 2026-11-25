//! What a controller can still change while its devices run, and the limits it runs under, end
//! to end with real composed nodes:
//!
//! - cables plugged and unplugged while the network runs (`devices.wire`, `devices.unwire`),
//!   with impairments, also on operator events' cables;
//! - a device taking a new config in place (`wasmnet:reconfigure`: the switch), and recreated
//!   where it cannot;
//! - limits: how many devices a controller may have, and how much memory a device may use;
//! - a crash told apart from a stop.
//!
//! Every network runs at two seeds, and a rerun is byte-identical.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config, events, field, transcript};
use wasmnet_det_cbor::Value;
use wasmnet_host::sim::infra::Phase;
use wasmnet_host::sim::{Impairments, LinkInfo, Op, Placement};
use wasmnet_host::{
    DeviceConfig, DeviceOptions, FrameRecord, JournalEntry, Nanos, Network, Record, sim,
};

const MS: Nanos = 1_000_000;
const US: Nanos = 1_000;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn text_map(pairs: &[(&str, &str)]) -> Value {
    Value::Map(
        pairs
            .iter()
            .map(|(k, v)| (Value::text(*k), Value::text(*v)))
            .collect(),
    )
}

/// A cable to `to` from `port`, 100 µs, with any further keys.
fn cable(port: u64, to: &str, extra: Vec<(&str, Value)>) -> Value {
    let mut m = vec![
        (Value::text("port"), Value::Uint(port)),
        (Value::text("to"), Value::text(to)),
        (Value::text("latency"), Value::Uint(100 * US)),
    ];
    m.extend(extra.into_iter().map(|(k, v)| (Value::text(k), v)));
    Value::Map(m)
}

/// A device spec: component, config, cables, further keys.
fn spec(
    component: &str,
    cfg: &[(&str, &str)],
    wire: Vec<Value>,
    extra: Vec<(&str, Value)>,
) -> Vec<u8> {
    let mut m = vec![
        (Value::text("component"), Value::text(component)),
        (Value::text("config"), text_map(cfg)),
    ];
    if !wire.is_empty() {
        m.push((Value::text("wire"), Value::Array(wire)));
    }
    m.extend(extra.into_iter().map(|(k, v)| (Value::text(k), v)));
    Value::Map(m).encode()
}

fn script(steps: &[String]) -> DeviceConfig {
    steps
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("step.{n}"), s.clone()))
        .collect()
}

fn controller() -> DeviceOptions {
    DeviceOptions::default().infra(true)
}

/// A network with the catalog controllers create from.
fn network(seed: u64) -> Network<'static> {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    network.set_component_resolver(Box::new(move |name, instantiate| {
        let file = match name {
            "switch" => "switch",
            "node:http-server" => "node-http-server",
            "node:http-get" => "node-http-get",
            other => return Err(sim::Error::Refused(format!("no component {other}"))),
        };
        instantiate(&b.load(file))
    }));
    network.set_infra_catalog(
        ["switch", "node:http-server", "node:http-get"]
            .map(String::from)
            .to_vec(),
    );
    network
}

#[derive(Debug, PartialEq)]
struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
}

fn timed(
    journal: &[JournalEntry],
    device: &str,
    kind: &str,
) -> Vec<(Nanos, Vec<(String, String)>)> {
    journal
        .iter()
        .filter(|e| e.device == device)
        .filter_map(|e| match &e.record {
            Record::Event { kind: k, fields } if k == kind => Some((e.at, fields.clone())),
            _ => None,
        })
        .collect()
}

/// The `infra-script` results of `ctl`, by step number.
fn step(journal: &[JournalEntry], n: u32) -> Vec<(String, String)> {
    events(journal, "ctl", "infra-script")
        .into_iter()
        .find(|f| field(f, "step") == n.to_string())
        .unwrap_or_else(|| panic!("step {n}:\n{}", transcript(journal)))
}

/// Runs `build(seed)` to `deadline` at two seeds, twice each: checks each run and that the
/// rerun is byte-identical.
fn at_two_seeds(
    deadline: Nanos,
    build: impl Fn(u64) -> Network<'static>,
    check: impl Fn(&Network, u64),
) {
    for seed in [42, 7] {
        let mut runs = Vec::new();
        for _ in 0..2 {
            let mut network = build(seed);
            network
                .run_until(deadline)
                .unwrap_or_else(|e| panic!("seed {seed}: {e}\n{}", transcript(&network.journal())));
            check(&network, seed);
            runs.push(Run {
                journal: network.journal(),
                frames: network.frames(),
            });
        }
        assert_eq!(runs[0], runs[1], "seed {seed}: the rerun is byte-identical");
    }
}

fn node(n: u8) -> DeviceConfig {
    config(&[
        ("mac", &format!("02:00:00:00:00:{n:02x}")),
        ("ipv4", &format!("10.0.0.{n}/24")),
    ])
}

// ---- cables plugged and unplugged while the network runs ----

/// `ctl` creates `web` with no cable, then plugs it into `sw` at 10 ms with a 20 Mbit/s rate
/// toward the client, and unplugs it at 900 ms. A client fetches 200 kB at 50 ms (it crosses
/// the shaped cable: at least 80 ms) and again at 1 s (nothing there any more). A second
/// cable from the same port is refused when it applies. An operator's cable carries its
/// impairments from its first frame too.
fn cabling_network(seed: u64) -> Network<'static> {
    let b = built();
    let mut network = network(seed);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "4")]))
        .unwrap();
    let mut client = node(20);
    client.extend(config(&[
        ("app.http-get.url", "http://10.0.0.10/big?n=200000"),
        ("app.http-get.start", "50ms"),
        ("app.http-get.interval", "950ms"),
        ("app.http-get.repeat", "2"),
    ]));
    let client = network
        .device_with_config("client", &b.load("node-http-get"), client)
        .unwrap();
    network
        .link(client.port(0), sw.port(0))
        .unwrap()
        .latency(100 * US);
    let web = spec(
        "node:http-server",
        &[("mac", "02:00:00:00:00:10"), ("ipv4", "10.0.0.10/24")],
        Vec::new(),
        Vec::new(),
    );
    let shaped = cable(
        0,
        "sw",
        vec![(
            "impair",
            Value::Map(vec![(Value::text("rate"), Value::Uint(20_000_000))]),
        )],
    );
    network
        .device_with_options(
            "ctl",
            &b.load("infra_script"),
            script(&[
                format!("0ms apply web {}", hex(&web)),
                format!("10ms wire web {}", hex(&shaped.encode())),
                format!(
                    "20ms wire web {}",
                    hex(&cable(0, "sw", Vec::new()).encode())
                ),
                "900ms unwire web 0".to_owned(),
            ]),
            controller(),
        )
        .unwrap();
    // An operator's cable between two spare ports, impaired from its first frame.
    network
        .device_with_config("spare", &b.load("switch"), config(&[("ports", "2")]))
        .unwrap();
    let lossy = Impairments::default().loss_ppm(100_000);
    network
        .add_op(
            Op::wire(("spare", 0), ("sw", 3))
                .with_latency(50 * US)
                .with_impairments([lossy, Impairments::default()]),
            Placement::StartOf(5 * MS),
        )
        .unwrap();
    network
}

fn link_called(network: &Network, name: &str) -> LinkInfo {
    network
        .links()
        .into_iter()
        .map(|l| network.link_info(l))
        .find(|i| i.name == name)
        .unwrap_or_else(|| panic!("no link `{name}`"))
}

#[test]
fn a_controller_plugs_and_unplugs_cables() {
    at_two_seeds(3_000 * MS, cabling_network, |network, seed| {
        let journal = network.journal();
        let log = transcript(&journal);
        assert_eq!(field(&step(&journal, 1), "result"), "ok", "{log}");
        let added = timed(&journal, "web", "link-added");
        assert_eq!(added.len(), 1, "seed {seed}:\n{log}");
        assert_eq!(added[0].0, 10 * MS);
        let name = field(&added[0].1, "link").to_owned();
        assert_eq!(name, "web.0-sw.1");
        // The second cable from the same port: refused when it applied.
        let failed = events(&journal, "ctl", "infra-failed");
        assert!(
            failed.iter().any(|f| field(f, "verb") == "wire"),
            "{failed:?}\n{log}"
        );
        // Its impairments were there from its first frame: 200 kB at 20 Mbit/s.
        let info = link_called(network, &name);
        assert!(info.removed, "unplugged; it stays in the records");
        assert_eq!(info.impairments[0].rate, 20_000_000);
        let done = events(&journal, "client", "http-get-done");
        assert_eq!(done.len(), 1, "only the first fetch is answered:\n{log}");
        assert_eq!(field(&done[0], "body-bytes"), "200000");
        let ns: u64 = field(&done[0], "done-ns").parse().unwrap();
        assert!(ns >= 80 * MS, "the shaped cable carried it: {ns} ns");
        assert_eq!(timed(&journal, "web", "link-removed")[0].0, 900 * MS);
        // The operator's cable.
        let op = link_called(network, "spare.0-sw.3");
        assert_eq!(op.impairments[0].loss_ppm, 100_000);
    });
}

// ---- a new config in place ----

/// `ctl` creates the switch `lan` between a client and a server and, while the client fetches
/// 2 MB through it, applies new specs: a longer aging time (taken in place: the switch keeps
/// its table, its links and their captures), a config the switch refuses (it keeps the old
/// one) and, with `restart`, more ports (which needs a restart: recreated).
fn reconfiguring_network(seed: u64, restart: bool) -> Network<'static> {
    let b = built();
    let mut network = network(seed);
    network
        .device_with_config("server", &b.load("node-http-server"), node(10))
        .unwrap();
    let mut client = node(20);
    client.extend(config(&[
        ("app.http-get.url", "http://10.0.0.10/big?n=2000000"),
        ("app.http-get.start", "10ms"),
    ]));
    network
        .device_with_config("client", &b.load("node-http-get"), client)
        .unwrap();
    let lan = |cfg: &[(&str, &str)]| {
        spec(
            "switch",
            cfg,
            vec![
                cable(0, "server", Vec::new()),
                cable(1, "client", Vec::new()),
            ],
            Vec::new(),
        )
    };
    let mut steps = vec![
        format!("0ms apply lan {}", hex(&lan(&[("ports", "3")]))),
        format!(
            "30ms apply lan {}",
            hex(&lan(&[("ports", "3"), ("aging", "60s")]))
        ),
        format!(
            "40ms apply lan {}",
            hex(&lan(&[("ports", "3"), ("aging", "never")]))
        ),
    ];
    if restart {
        steps.push(format!(
            "50ms apply lan {}",
            hex(&lan(&[("ports", "4"), ("aging", "60s")]))
        ));
    }
    network
        .device_with_options("ctl", &b.load("infra_script"), script(&steps), controller())
        .unwrap();
    network
}

#[test]
fn a_switch_takes_a_new_config_in_place() {
    for restart in [false, true] {
        at_two_seeds(
            3_000 * MS,
            |seed| reconfiguring_network(seed, restart),
            |network, seed| {
                let journal = network.journal();
                let log = transcript(&journal);
                // 30 ms: in place.
                let re = timed(&journal, "lan", "reconfigured");
                assert_eq!(re.len(), 1, "seed {seed}:\n{log}");
                assert_eq!(re[0].0, 30 * MS);
                assert_eq!(field(&re[0].1, "aging"), "60s");
                assert_eq!(timed(&journal, "lan", "device-reconfigured")[0].0, 30 * MS);
                // 40 ms: refused, the old config stays.
                let failed = events(&journal, "ctl", "infra-failed");
                assert!(
                    failed
                        .iter()
                        .any(|f| field(f, "verb") == "apply"
                            && field(f, "message").contains("aging")),
                    "{failed:?}\n{log}"
                );
                let removed = timed(&journal, "lan", "device-removed");
                let view = network.infra().get("lan").unwrap();
                if restart {
                    // 50 ms: more ports need a restart: recreated, its cables renamed.
                    assert_eq!(removed.len(), 1, "{log}");
                    assert_eq!(removed[0].0, 50 * MS);
                    link_called(network, "lan.0-server.0-2");
                    assert_eq!(view.generation, 3);
                } else {
                    assert!(removed.is_empty(), "never recreated:\n{log}");
                    // The transfer went through the change undisturbed.
                    let done = events(&journal, "client", "http-get-done");
                    assert_eq!(done.len(), 1, "{log}");
                    assert_eq!(field(&done[0], "body-bytes"), "2000000");
                    assert_eq!(view.generation, 2);
                    let spec = wasmnet_det_cbor::decode(&view.spec).unwrap();
                    assert_eq!(
                        spec.get("config").and_then(|c| c.get("aging")),
                        Some(&Value::text("60s")),
                        "the table shows the config the switch runs with"
                    );
                }
            },
        );
    }
}

// ---- limits, and a crash told apart from a stop ----

/// `ctl` may have two devices. It creates `hog` (an HTTP client limited to 3 MiB of memory,
/// whose 1 MiB read buffer cannot fit), `fit` (the same with 8 MiB), and asks for a third,
/// which is refused. An operator stops `fit` at 500 ms.
fn limited_network(seed: u64) -> Network<'static> {
    let b = built();
    let mut network = network(seed);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "4")]))
        .unwrap();
    let server = network
        .device_with_config("server", &b.load("node-http-server"), node(10))
        .unwrap();
    network
        .link(server.port(0), sw.port(0))
        .unwrap()
        .latency(100 * US);
    let client = |n: u8, memory: u64| {
        spec(
            "node:http-get",
            &[
                ("mac", &format!("02:00:00:00:00:{n:02x}")),
                ("ipv4", &format!("10.0.0.{n}/24")),
                ("app.http-get.url", "http://10.0.0.10/big?n=100000"),
                ("app.http-get.start", "50ms"),
                ("app.http-get.read-size", "1048576"),
            ],
            vec![cable(0, "sw", Vec::new())],
            vec![("memory", Value::Uint(memory))],
        )
    };
    network
        .device_with_options(
            "ctl",
            &b.load("infra_script"),
            script(&[
                format!("0ms apply hog {}", hex(&client(31, 3 << 20))),
                format!("0ms apply fit {}", hex(&client(32, 8 << 20))),
                format!("0ms apply more {}", hex(&client(33, 8 << 20))),
            ]),
            controller().infra_max_devices(2),
        )
        .unwrap();
    network
        .add_op(Op::stop_device("fit"), Placement::StartOf(500 * MS))
        .unwrap();
    network
}

#[test]
fn limits_hold_and_a_crash_is_not_a_stop() {
    at_two_seeds(1_000 * MS, limited_network, |network, seed| {
        let journal = network.journal();
        let log = transcript(&journal);
        // The third device: refused at the call, nothing queued, nothing journalled for it.
        let third = field(&step(&journal, 2), "result").to_owned();
        assert!(third.contains("at most 2 devices"), "{third}");
        assert!(network.infra().get("more").is_err());
        assert!(
            timed(&journal, "ctl", "infra-apply")
                .iter()
                .all(|(_, f)| field(f, "name") != "more")
        );
        // `hog` outgrew its memory when it read: it crashed alone, deterministically.
        let crashed = timed(&journal, "hog", "device-crashed");
        assert_eq!(crashed.len(), 1, "seed {seed}:\n{log}");
        assert!(
            field(&crashed[0].1, "message").contains("memory limit"),
            "{:?}",
            crashed[0]
        );
        let hog = network.infra().get("hog").unwrap();
        assert_eq!(hog.phase, Phase::Crashed);
        assert!(
            hog.message
                .as_deref()
                .is_some_and(|m| m.contains("memory limit"))
        );
        // `fit` read its body, then an operator stopped it: `stopped`, with no fault.
        assert_eq!(events(&journal, "fit", "http-get-done").len(), 1, "{log}");
        let fit = network.infra().get("fit").unwrap();
        assert_eq!((fit.phase, fit.message.as_deref()), (Phase::Stopped, None));
        // The controller's view tells them apart too.
        let (_, changes) = network.infra().watch_for("ctl", &[], 0, u32::MAX);
        let last = |name: &str| {
            changes
                .iter()
                .rev()
                .find(|c| c.device.name == name)
                .map(|c| c.device.phase)
        };
        assert_eq!(
            (last("hog"), last("fit")),
            (Some(Phase::Crashed), Some(Phase::Stopped))
        );
        // Memory, measured: the server (a netstack and an app, one linear memory each, both
        // counted) holds what it grew to; `fit` held its 1 MiB read buffer at its peak, and
        // nothing once it stopped.
        let server = network.cost_of("server");
        assert!(server.memory >= 2 << 20, "{server:?}");
        assert_eq!(server.peak_memory, server.memory, "memory never shrinks");
        let fit = network.cost_of("fit");
        assert_eq!(fit.memory, 0, "stopped: {fit:?}");
        assert!(fit.peak_memory > (3 << 20), "{fit:?}");
        assert!(network.cost_of("hog").peak_memory <= 3 << 20);
    });
}

/// Memory is measured whether a device has a limit or not, during a run and after it, and the
/// same in every run.
#[test]
fn memory_is_measured_the_same_every_run() {
    let measure = |seed| {
        let mut network = limited_network(seed);
        network.run_until(100 * MS).unwrap();
        let early = network.cost_of("fit");
        network.run_until(1_000 * MS).unwrap();
        let costs: Vec<(String, u64, u64)> = network
            .costs()
            .into_iter()
            .map(|(n, c)| (n, c.memory, c.peak_memory))
            .collect();
        (early.memory, costs)
    };
    let (early, costs) = measure(42);
    assert!(early > (3 << 20), "during the run: {early}");
    assert_eq!(measure(42), (early, costs));
}
