//! What a controller (and the embedder) can give and get from the devices it runs, end to end
//! with real composed nodes:
//!
//! - arguments and environment variables for a device (`DeviceOptions::args`/`env`, and the
//!   spec keys `args` and `env` of `wasmnet:infra`), served by `wasi:cli/environment`;
//! - a created device's output for its controller (`devices.logs`, with the spec's `stdio`);
//! - the devices a controller created stopping or going with it (`DeviceOptions::infra_cascade`);
//! - a controller woken by a change instead of its timer (`wasmnet:infra/changes.wait`);
//! - a device the embedder built directly starting again after a stop, without a resolver.
//!
//! Every network runs at two seeds, and a rerun is byte-identical.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config, events, field, transcript};
use wasmnet_det_cbor::Value;
use wasmnet_host::sim::infra::Phase;
use wasmnet_host::sim::{Cascade, Op, OpState, Placement};
use wasmnet_host::{
    DeviceConfig, DeviceOptions, FrameRecord, JournalEntry, Nanos, Network, Record, sim,
};

const MS: Nanos = 1_000_000;
const US: Nanos = 1_000;

/// FNV-1a 64, as the HTTP apps journal a body's (`body-fnv`).
fn fnv(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A device spec for `devices.apply`: a component, its config, its cables (to the far
/// device's first free port, 100 µs) and any further keys.
fn spec(
    component: &str,
    cfg: &[(&str, &str)],
    wire: &[&str],
    extra: Vec<(&str, Value)>,
) -> Vec<u8> {
    let config = cfg
        .iter()
        .map(|(k, v)| (Value::text(*k), Value::text(*v)))
        .collect();
    let cables = wire
        .iter()
        .enumerate()
        .map(|(port, to)| {
            Value::Map(vec![
                (Value::text("port"), Value::Uint(port as u64)),
                (Value::text("to"), Value::text(*to)),
                (Value::text("latency"), Value::Uint(100 * US)),
            ])
        })
        .collect();
    let mut m = vec![
        (Value::text("component"), Value::text(component)),
        (Value::text("config"), Value::Map(config)),
        (Value::text("wire"), Value::Array(cables)),
    ];
    m.extend(extra.into_iter().map(|(k, v)| (Value::text(k), v)));
    Value::Map(m).encode()
}

/// An `infra-script` controller's config: one step per line.
fn script(steps: &[String]) -> DeviceConfig {
    steps
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("step.{n}"), s.clone()))
        .collect()
}

fn controller(cascade: Cascade) -> DeviceOptions {
    DeviceOptions {
        infra: true,
        infra_cascade: cascade,
        ..DeviceOptions::default()
    }
}

/// A network with the catalog controllers create from.
fn network(seed: u64) -> Network<'static> {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    network.set_component_resolver(Box::new(move |name, instantiate| {
        let file = match name {
            "router" => "router",
            "node:http-server" => "node-http-server",
            "node:http-get" => "node-http-get",
            other => return Err(sim::Error::Refused(format!("no component {other}"))),
        };
        instantiate(&b.load(file))
    }));
    network.set_infra_catalog(
        ["router", "node:http-server", "node:http-get"]
            .map(String::from)
            .to_vec(),
    );
    network
}

/// What a rerun must reproduce byte for byte.
#[derive(Debug, PartialEq)]
struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
}

fn record(network: &Network) -> Run {
    Run {
        journal: network.journal(),
        frames: network.frames(),
    }
}

/// Every `kind` event of `device` with its time.
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

/// Runs `build(seed)` to `deadline` at two seeds, twice each: checks each run with `check` and
/// that the rerun is byte-identical.
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
            runs.push(record(&network));
        }
        assert_eq!(runs[0], runs[1], "seed {seed}: the rerun is byte-identical");
    }
}

// ---- arguments and environment ----

/// `web-a` (built by the embedder with arguments and environment variables) and `web-b` (made
/// by a controller from a spec that has them) answer `GET /` with a body made of their own
/// arguments and `GREETING`; a client fetches both.
#[test]
fn a_device_gets_its_arguments_and_environment() {
    let body = [
        ("app.http-server.route.e.path", "/"),
        ("app.http-server.route.e.body", "{args}|{env:GREETING}"),
    ];
    let web_b = spec(
        "node:http-server",
        &[
            &[("mac", "02:00:00:00:00:11"), ("ipv4", "10.0.0.11/24")][..],
            &body[..],
        ]
        .concat(),
        &["sw"],
        vec![
            ("args", Value::Array(vec![Value::text("b")])),
            (
                "env",
                Value::Map(vec![(Value::text("GREETING"), Value::text("bonjour"))]),
            ),
        ],
    );
    let build = |seed| {
        let b = built();
        let mut network = network(seed);
        let sw = network
            .device_with_config("sw", &b.load("switch"), config(&[("ports", "4")]))
            .unwrap();
        let mut web_config = config(&[("mac", "02:00:00:00:00:10"), ("ipv4", "10.0.0.10/24")]);
        web_config.extend(config(&body));
        let web_a = network
            .device_with_options(
                "web-a",
                &b.load("node-http-server"),
                web_config,
                DeviceOptions {
                    args: vec!["-v".to_owned(), "two words".to_owned()],
                    env: vec![
                        ("GREETING".to_owned(), "hello".to_owned()),
                        ("UNUSED".to_owned(), "x".to_owned()),
                    ],
                    ..DeviceOptions::default()
                },
            )
            .unwrap();
        network
            .device_with_options(
                "ctl",
                &b.load("infra_script"),
                script(&[format!("0ms apply web-b {}", hex(&web_b))]),
                controller(Cascade::Keep),
            )
            .unwrap();
        let client = network
            .device_with_config(
                "client",
                &b.load("node-http-get"),
                config(&[
                    ("mac", "02:00:00:00:00:20"),
                    ("ipv4", "10.0.0.20/24"),
                    ("app.http-get.urls", "http://10.0.0.10/,http://10.0.0.11/"),
                    ("app.http-get.start", "100ms"),
                ]),
            )
            .unwrap();
        network
            .link(web_a.port(0), sw.port(0))
            .unwrap()
            .latency(100 * US);
        network
            .link(client.port(0), sw.port(1))
            .unwrap()
            .latency(100 * US);
        network
    };
    at_two_seeds(2_000 * MS, build, |network, seed| {
        let journal = network.journal();
        let log = transcript(&journal);
        for (device, text) in [("web-a", "-v two words|hello"), ("web-b", "b|bonjour")] {
            let responses = events(&journal, device, "http-response");
            assert_eq!(responses.len(), 1, "seed {seed}, {device}:\n{log}");
            assert_eq!(
                field(&responses[0], "body-fnv"),
                fnv(text.as_bytes()),
                "{device}"
            );
        }
        let done = events(&journal, "client", "http-get-done");
        assert_eq!(done.len(), 2, "seed {seed}:\n{log}");
        // The table shows them in the spec, in their canonical form.
        let spec = network.infra().get("web-b").unwrap().spec;
        let v = wasmnet_det_cbor::decode(&spec).unwrap();
        assert_eq!(v.get("args"), Some(&Value::Array(vec![Value::text("b")])));
    });
}

// ---- a device's output, for its controller ----

/// A controller creates a router whose configuration is broken, with its output journalled
/// (`"stdio": "journal"`): the creation fails, and the controller reads why from the router's
/// own last lines on stderr. The network's own devices' logs are not its to read.
#[test]
fn a_controller_reads_why_its_device_failed() {
    let bad = spec(
        "router",
        &[
            ("mac", "02:00:00:00:fe:01"),
            ("port0.ipv4", "10.0.0.1/24"),
            ("routes", "nowhere"),
        ],
        &["sw"],
        vec![("stdio", Value::text("journal"))],
    );
    let build = |seed| {
        let b = built();
        let mut network = network(seed);
        network
            .device_with_config("sw", &b.load("switch"), config(&[("ports", "2")]))
            .unwrap();
        network
            .device_with_options(
                "ctl",
                &b.load("infra_script"),
                script(&[
                    format!("0ms apply r1 {}", hex(&bad)),
                    "10ms logs r1 stderr 5".to_owned(),
                    "10ms logs sw".to_owned(),
                ]),
                controller(Cascade::Keep),
            )
            .unwrap();
        network
    };
    at_two_seeds(100 * MS, build, |network, seed| {
        let journal = network.journal();
        let log = transcript(&journal);
        let failed = events(&journal, "ctl", "infra-failed");
        assert_eq!(failed.len(), 1, "seed {seed}:\n{log}");
        assert_eq!(network.infra().get("r1").unwrap().phase, Phase::Failed);
        let steps = events(&journal, "ctl", "infra-script");
        let logs = steps
            .iter()
            .find(|f| field(f, "verb") == "logs" && field(f, "name") == "r1")
            .expect("the logs step");
        assert_eq!(field(logs, "result"), "ok", "{log}");
        assert!(field(logs, "lines").parse::<u32>().unwrap() >= 1, "{log}");
        assert!(
            field(logs, "text").contains("router: config routes"),
            "the router's own words: {}",
            field(logs, "text")
        );
        let sw = steps
            .iter()
            .find(|f| field(f, "verb") == "logs" && field(f, "name") == "sw")
            .expect("the second logs step");
        assert!(field(sw, "result").contains("Denied"), "{sw:?}");
    });
}

// ---- owned devices with their owner ----

/// `ctl` creates `web-1` and `web-2`; a client fetches from `web-1` every 200 ms from 100 ms.
/// At 400 ms an operator stops (or removes) `ctl`: with `Cascade::Stop` its devices stop with
/// it, with `Cascade::Remove` they go with it, and with the default they keep running.
fn cascade_network(seed: u64, cascade: Cascade, remove: bool) -> Network<'static> {
    let b = built();
    let mut network = network(seed);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "4")]))
        .unwrap();
    let web = |n: u8| {
        spec(
            "node:http-server",
            &[
                ("mac", &format!("02:00:00:00:00:1{n}")),
                ("ipv4", &format!("10.0.0.1{n}/24")),
            ],
            &["sw"],
            Vec::new(),
        )
    };
    network
        .device_with_options(
            "ctl",
            &b.load("infra_script"),
            script(&[
                format!("0ms apply web-1 {}", hex(&web(1))),
                format!("0ms apply web-2 {}", hex(&web(2))),
            ]),
            controller(cascade),
        )
        .unwrap();
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:00:20"),
                ("ipv4", "10.0.0.20/24"),
                ("app.http-get.url", "http://10.0.0.11/"),
                ("app.http-get.start", "100ms"),
                ("app.http-get.interval", "200ms"),
                ("app.http-get.repeat", "4"),
            ]),
        )
        .unwrap();
    network
        .link(client.port(0), sw.port(0))
        .unwrap()
        .latency(100 * US);
    let op = if remove {
        Op::RemoveDevice {
            device: "ctl".to_owned(),
        }
    } else {
        Op::StopDevice {
            device: "ctl".to_owned(),
        }
    };
    network.add_op(op, Placement::StartOf(400 * MS)).unwrap();
    network
}

#[test]
fn owned_devices_stop_or_go_with_their_controller() {
    for (cascade, remove) in [
        (Cascade::Stop, false),
        (Cascade::Remove, true),
        (Cascade::Keep, false),
    ] {
        let label = format!("{cascade:?}");
        at_two_seeds(
            3_000 * MS,
            |seed| cascade_network(seed, cascade, remove),
            |network, seed| {
                let journal = network.journal();
                let log = transcript(&journal);
                let kind = if remove {
                    "device-removed"
                } else {
                    "device-stopped"
                };
                assert_eq!(timed(&journal, "ctl", kind).len(), 1, "{label}:\n{log}");
                for web in ["web-1", "web-2"] {
                    let gone = timed(&journal, web, kind);
                    match cascade {
                        Cascade::Keep => {
                            assert!(gone.is_empty(), "{label}: {web} keeps running:\n{log}");
                            assert_eq!(network.infra().get(web).unwrap().phase, Phase::Running);
                        }
                        _ => {
                            assert_eq!(gone.len(), 1, "{label}, seed {seed}: {web}:\n{log}");
                            assert_eq!(gone[0].0, 400 * MS, "{label}: at the owner's stop");
                            assert_eq!(field(&gone[0].1, "with-owner"), "ctl");
                        }
                    }
                }
                match cascade {
                    Cascade::Stop => {
                        assert_eq!(network.infra().get("web-1").unwrap().phase, Phase::Stopped)
                    }
                    Cascade::Remove => assert!(network.infra().get("web-1").is_err()),
                    Cascade::Keep => {}
                }
                // The client's fetches at 100 and 300 ms are answered; after 400 ms only
                // while `web-1` still runs.
                let answered = events(&journal, "client", "http-get-done")
                    .iter()
                    .filter(|f| field(f, "status") == "200")
                    .count();
                let expected = if cascade == Cascade::Keep { 4 } else { 2 };
                assert_eq!(answered, expected, "{label}:\n{log}");
            },
        );
    }
}

// ---- a controller woken by a change ----

/// `replicas` keeps one `web` instance running with a 1 s period. An operator stops `web-1`
/// at 1.5 s: a controller that waits on `changes.wait` (`wake = true`) starts it again at
/// once; one that only polls starts it at its next pass, at 2 s.
fn waking_network(seed: u64, wake: bool) -> Network<'static> {
    let b = built();
    let mut network = network(seed);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "4")]))
        .unwrap();
    let ctl = network
        .device_with_options(
            "ctl",
            &b.load("node-replicas"),
            config(&[
                ("mac", "02:00:00:00:01:05"),
                ("ipv4", "10.0.1.5/24"),
                ("app.replicas.replicas", "1"),
                ("app.replicas.period", "1s"),
                ("app.replicas.wake", if wake { "true" } else { "false" }),
                ("app.replicas.template.component", "node:http-server"),
                ("app.replicas.template.config.mac", "02:00:00:00:01:{n+10}"),
                ("app.replicas.template.config.ipv4", "10.0.1.{n+10}/24"),
                ("app.replicas.template.wire.0.port", "0"),
                ("app.replicas.template.wire.0.to", "sw"),
            ]),
            controller(Cascade::Keep),
        )
        .unwrap();
    network
        .link(ctl.port(0), sw.port(0))
        .unwrap()
        .latency(100 * US);
    network
        .add_op(
            Op::StopDevice {
                device: "web-1".to_owned(),
            },
            Placement::StartOf(1_500 * MS),
        )
        .unwrap();
    network
}

#[test]
fn a_waiting_controller_is_woken_by_a_change() {
    for wake in [true, false] {
        at_two_seeds(
            3_000 * MS,
            |seed| waking_network(seed, wake),
            |network, seed| {
                let journal = network.journal();
                let log = transcript(&journal);
                assert_eq!(timed(&journal, "web-1", "device-stopped").len(), 1, "{log}");
                let starts: Vec<Nanos> = timed(&journal, "ctl", "infra-start")
                    .into_iter()
                    .filter(|(_, f)| field(f, "name") == "web-1")
                    .map(|(at, _)| at)
                    .collect();
                let expected = if wake { 1_500 * MS } else { 2_000 * MS };
                assert_eq!(starts, [expected], "wake={wake}, seed {seed}:\n{log}");
                assert_eq!(network.infra().get("web-1").unwrap().phase, Phase::Running);
            },
        );
    }
}

// ---- a device built directly starts again ----

/// A network without a component resolver: the embedder stops `web` at 250 ms and starts it
/// again at 450 ms, and it serves the client's later fetches.
#[test]
fn a_device_built_directly_starts_again_without_a_resolver() {
    let build = |seed| {
        let b = built();
        let mut network = Network::new(&b.host, seed);
        let sw = network
            .device_with_config("sw", &b.load("switch"), config(&[("ports", "2")]))
            .unwrap();
        let web = network
            .device_with_config(
                "web",
                &b.load("node-http-server"),
                config(&[("mac", "02:00:00:00:00:10"), ("ipv4", "10.0.0.10/24")]),
            )
            .unwrap();
        let client = network
            .device_with_config(
                "client",
                &b.load("node-http-get"),
                config(&[
                    ("mac", "02:00:00:00:00:20"),
                    ("ipv4", "10.0.0.20/24"),
                    ("app.http-get.url", "http://10.0.0.10/"),
                    ("app.http-get.start", "100ms"),
                    ("app.http-get.interval", "200ms"),
                    ("app.http-get.repeat", "5"),
                ]),
            )
            .unwrap();
        network
            .link(web.port(0), sw.port(0))
            .unwrap()
            .latency(100 * US);
        network
            .link(client.port(0), sw.port(1))
            .unwrap()
            .latency(100 * US);
        for (at, op) in [
            (
                250 * MS,
                Op::StopDevice {
                    device: "web".to_owned(),
                },
            ),
            (
                450 * MS,
                Op::StartDevice {
                    device: "web".to_owned(),
                },
            ),
        ] {
            network.add_op(op, Placement::StartOf(at)).unwrap();
        }
        network
    };
    at_two_seeds(3_000 * MS, build, |network, seed| {
        let journal = network.journal();
        let log = transcript(&journal);
        assert!(
            network
                .op_states()
                .iter()
                .all(|s| matches!(s, OpState::Applied { .. })),
            "seed {seed}: {:?}\n{log}",
            network.op_states()
        );
        let started = timed(&journal, "web", "device-started");
        assert_eq!(started.len(), 1, "{log}");
        assert_eq!(started[0].0, 450 * MS);
        let later = timed(&journal, "web", "http-accepted")
            .into_iter()
            .filter(|(at, _)| *at > 450 * MS)
            .count();
        assert!(
            later >= 2,
            "the restarted web serves the later fetches:\n{log}"
        );
    });
}

// ---- a command's answer, for its controller ----

/// `ctl` creates the router `r1` between the client's network (10.0.1.0/24, on `lan`) and the
/// transit network (10.0.2.0/24, on `wan`), behind which `gw` leads to the server's network
/// (10.0.3.0/24). It sends `r1` the command `routes` with a request id, reads the answer, and
/// adds the route to 10.0.3.0/24 only if the answer lacks it; then reads `routes` again. When
/// `r1` was created with that route already, the conditional step is skipped. Either way the
/// client's fetch from the server succeeds.
fn answering_network(seed: u64, with_route: bool) -> Network<'static> {
    let b = built();
    let mut network = network(seed);
    let router = b.load("router");
    let lan = network
        .device_with_config("lan", &b.load("switch"), config(&[("ports", "3")]))
        .unwrap();
    let wan = network
        .device_with_config("wan", &b.load("switch"), config(&[("ports", "3")]))
        .unwrap();
    let gw = network
        .device_with_config(
            "gw",
            &router,
            config(&[
                ("mac", "02:00:00:00:fe:20"),
                ("port0.ipv4", "10.0.2.2/24"),
                ("port1.ipv4", "10.0.3.1/24"),
                ("routes", "10.0.1.0/24 via 10.0.2.1"),
            ]),
        )
        .unwrap();
    let server = network
        .device_with_config(
            "server",
            &b.load("node-http-server"),
            config(&[
                ("mac", "02:00:00:00:03:10"),
                ("ipv4", "10.0.3.10/24"),
                ("ipv4-gateway", "10.0.3.1"),
            ]),
        )
        .unwrap();
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:01:20"),
                ("ipv4", "10.0.1.20/24"),
                ("ipv4-gateway", "10.0.1.1"),
                ("app.http-get.url", "http://10.0.3.10/"),
                ("app.http-get.start", "50ms"),
            ]),
        )
        .unwrap();
    let mut r1 = vec![
        ("mac", "02:00:00:00:fe:10"),
        ("port0.ipv4", "10.0.1.1/24"),
        ("port1.ipv4", "10.0.2.1/24"),
    ];
    if with_route {
        r1.push(("routes", "10.0.3.0/24 via 10.0.2.2"));
    }
    let r1 = spec("router", &r1, &["lan", "wan"], Vec::new());
    network
        .device_with_options(
            "ctl",
            &b.load("infra_script"),
            script(&[
                format!("0ms apply r1 {}", hex(&r1)),
                "1ms id=q control r1 routes".to_owned(),
                "1ms answer q".to_owned(),
                "2ms answer q".to_owned(),
                "2ms id=add when=q!10.0.3.0/24 control r1 route-add 10.0.3.0/24 via 10.0.2.2"
                    .to_owned(),
                "3ms id=q2 control r1 routes".to_owned(),
                "4ms answer q2".to_owned(),
                "4ms answer nope".to_owned(),
            ]),
            controller(Cascade::Keep),
        )
        .unwrap();
    for (a, b) in [
        (client.port(0), lan.port(0)),
        (gw.port(0), wan.port(0)),
        (server.port(0), gw.port(1)),
    ] {
        network.link(a, b).unwrap().latency(100 * US);
    }
    network
}

#[test]
fn a_controller_reads_a_commands_answer_and_acts_on_it() {
    for with_route in [false, true] {
        at_two_seeds(
            1_000 * MS,
            |seed| answering_network(seed, with_route),
            |network, seed| {
                let journal = network.journal();
                let log = transcript(&journal);
                let steps = events(&journal, "ctl", "infra-script");
                let step = |n: u32| {
                    steps
                        .iter()
                        .find(|f| field(f, "step") == n.to_string())
                        .unwrap_or_else(|| panic!("step {n}:\n{log}"))
                };
                // Asked in the same poll the command was sent in: not answered yet.
                assert_eq!(field(step(2), "result"), "pending", "{log}");
                // A millisecond later: `r1`'s table, as the router wrote it, at 1 ms.
                let first = step(3);
                assert_eq!(field(first, "result"), "ok", "{log}");
                assert_eq!(field(first, "at"), MS.to_string());
                assert!(field(first, "text").contains("10.0.1.0/24"), "{first:?}");
                assert_eq!(
                    field(first, "text").contains("10.0.3.0/24"),
                    with_route,
                    "{first:?}"
                );
                // The route is added only when the answer lacked it.
                let added = field(step(4), "result");
                assert_eq!(added, if with_route { "skipped" } else { "ok" }, "{log}");
                assert_eq!(
                    events(&journal, "r1", "route-added").len(),
                    usize::from(!with_route),
                    "{log}"
                );
                assert!(field(step(6), "text").contains("10.0.3.0/24 via 10.0.2.2"));
                assert!(field(step(7), "result").contains("NotFound"), "{log}");
                // Either way the client reaches the server through it.
                let done = events(&journal, "client", "http-get-done");
                assert_eq!(
                    done.len(),
                    1,
                    "with_route={with_route}, seed {seed}:\n{log}"
                );
                assert_eq!(field(&done[0], "status"), "200");
            },
        );
    }
}
