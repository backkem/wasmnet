//! End to end: a router's routes change while a transfer crosses it, and no frame is lost.
//!
//! ```text
//! server ── r1 ── wan ─┬─ r2 ─┬─ lan ── client
//! 10.0.1.10            └─ r3 ─┘         10.0.3.10
//! ```
//!
//! The client fetches a large body from the server. Its requests and acknowledgements go out
//! through `r3`, its gateway. The server's data comes back through `r1`, whose configured route
//! to 10.0.3.0/24 leads to `r2`. While the data flows, `r1` gets
//! `route-add 10.0.3.10/32 via 10.0.2.3` (the data moves over to `r3`) and later
//! `route-replace 10.0.3.10/32 via 10.0.2.2` (back to `r2`). Both next hops are neighbours `r1`
//! already knows (it learned `r3` from `r3`'s own ARP request for 10.0.2.1, when the client's
//! first segment came through), so neither change sends an ARP request. The data flows from
//! about 8 ms to 70 ms; the changes are at 25 ms and 50 ms. A third command, which `r1` refuses
//! (a route for a connected prefix), changes nothing.
//!
//! The changes come once from operator events, and once from a controller (the `infra-script`
//! fixture) that created `r1` through `wasmnet:infra` and changes it with `devices.control`,
//! including a retry by request id. Each runs at two seeds, twice: the reruns are
//! byte-identical.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config, ethertype, events, field, transcript};
use wasmnet_det_cbor::Value;
use wasmnet_host::sim::{DeviceCommand, Op, OpState, Placement};
use wasmnet_host::{DeviceId, DeviceOptions, FrameFate, FrameRecord, JournalEntry, Network, sim};

const US: u64 = 1_000;
const MS: u64 = 1_000_000;

/// The body the client fetches.
const BODY: u64 = 4_000_000;
/// When `r1` gets the host route via `r3`, and when that route is replaced (back to `r2`).
const T_ADD: u64 = 25 * MS;
const T_REPLACE: u64 = 50 * MS;
const ADD: &str = "10.0.3.10/32 via 10.0.2.3";
const REPLACE: &str = "10.0.3.10/32 via 10.0.2.2";
/// A command `r1` refuses: 10.0.1.0/24 is connected to its port 0.
const REFUSED: &str = "10.0.1.0/24 via 10.0.2.2";

const R1_MAC: &str = "02:00:00:00:fe:00";
const R2_MAC: [u8; 6] = [2, 0, 0, 0, 0xfe, 0x20];
const R3_MAC: [u8; 6] = [2, 0, 0, 0, 0xfe, 0x30];

#[derive(Clone, Copy, Debug)]
enum How {
    /// The embedder's operator events.
    Operator,
    /// A controller device through `wasmnet:infra`.
    Controller,
}

struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
    links: Vec<String>,
    op_states: Vec<OpState>,
    r1: DeviceId,
    r1_counters: Vec<(String, u64)>,
    r1_routes: String,
    /// Frames dropped after the first millisecond (the setup).
    dropped: u64,
}

fn r1_config() -> Vec<(&'static str, &'static str)> {
    vec![
        ("mac", R1_MAC),
        ("port0.ipv4", "10.0.1.1/24"),
        ("port1.ipv4", "10.0.2.1/24"),
        ("routes", "10.0.3.0/24 via 10.0.2.2"),
    ]
}

/// `r1`'s spec for the controller: the router, its config and its two cables.
fn r1_spec() -> Vec<u8> {
    let config = r1_config()
        .into_iter()
        .map(|(k, v)| (Value::text(k), Value::text(v)))
        .collect();
    let cable = |port: u64, to: &str| {
        Value::Map(vec![
            (Value::text("port"), Value::Uint(port)),
            (Value::text("to"), Value::text(to)),
            (Value::text("latency"), Value::Uint(100 * US)),
        ])
    };
    Value::Map(vec![
        (Value::text("component"), Value::text("router")),
        (Value::text("config"), Value::Map(config)),
        (
            Value::text("wire"),
            Value::Array(vec![cable(0, "server:0"), cable(1, "wan:0")]),
        ),
    ])
    .encode()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ms(ns: u64) -> String {
    format!("{}ms", ns / MS)
}

fn run(seed: u64, how: How) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let router = b.load("router");
    let resolver_router = router.clone();
    network.set_component_resolver(Box::new(move |name, instantiate| match name {
        "router" => instantiate(&resolver_router),
        other => Err(sim::Error::Refused(format!("no component {other}"))),
    }));
    network.set_infra_catalog(vec!["router".to_owned()]);

    let server = network
        .device_with_config(
            "server",
            &b.load("node-http-server"),
            config(&[
                ("mac", "02:00:00:00:01:10"),
                ("ipv4", "10.0.1.10/24"),
                ("ipv4-gateway", "10.0.1.1"),
            ]),
        )
        .unwrap();
    let wan = network
        .device_with_config("wan", &b.load("switch"), config(&[("ports", "3")]))
        .unwrap();
    let r2 = network
        .device_with_config(
            "r2",
            &router,
            config(&[
                ("port0.mac", "02:00:00:00:fe:20"),
                ("port1.mac", "02:00:00:00:fe:21"),
                ("port0.ipv4", "10.0.2.2/24"),
                ("port1.ipv4", "10.0.3.1/24"),
                ("routes", "10.0.1.0/24 via 10.0.2.1"),
            ]),
        )
        .unwrap();
    let r3 = network
        .device_with_config(
            "r3",
            &router,
            config(&[
                ("port0.mac", "02:00:00:00:fe:30"),
                ("port1.mac", "02:00:00:00:fe:31"),
                ("port0.ipv4", "10.0.2.3/24"),
                ("port1.ipv4", "10.0.3.2/24"),
                ("routes", "10.0.1.0/24 via 10.0.2.1"),
            ]),
        )
        .unwrap();
    let lan = network
        .device_with_config("lan", &b.load("switch"), config(&[("ports", "3")]))
        .unwrap();
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:03:10"),
                ("ipv4", "10.0.3.10/24"),
                ("ipv4-gateway", "10.0.3.2"),
                (
                    "app.http-get.url",
                    &format!("http://10.0.1.10/big?n={BODY}"),
                ),
                ("app.http-get.start", "5ms"),
            ]),
        )
        .unwrap();
    let link = |network: &mut Network, a, b| {
        network.link(a, b).unwrap().latency(100 * US);
    };
    link(&mut network, r2.port(0), wan.port(1));
    link(&mut network, r3.port(0), wan.port(2));
    link(&mut network, r2.port(1), lan.port(0));
    link(&mut network, r3.port(1), lan.port(1));
    link(&mut network, client.port(0), lan.port(2));

    match how {
        How::Operator => {
            let r1 = network
                .device_with_config("r1", &router, config(&r1_config()))
                .unwrap();
            link(&mut network, server.port(0), r1.port(0));
            link(&mut network, r1.port(1), wan.port(0));
            for (at, command, argument) in [
                (T_ADD, "route-add", ADD),
                (T_ADD, "route-add", REFUSED),
                (T_REPLACE, "route-replace", REPLACE),
            ] {
                network
                    .add_op(
                        Op::Control {
                            device: r1,
                            call: DeviceCommand::new(command, argument).into_control(),
                        },
                        Placement::StartOf(at),
                    )
                    .unwrap();
            }
        }
        How::Controller => {
            let steps = [
                format!("0ms apply r1 {}", hex(&r1_spec())),
                format!("{} control r1 route-add {ADD}", ms(T_ADD)),
                format!("{} control r1 route-add {REFUSED}", ms(T_ADD)),
                // A retry of step 1 by its request id: answered from the record, not sent again.
                format!("{} id=step-1 control r1 route-add {ADD}", ms(T_ADD + MS)),
                format!("{} control r1 route-replace {REPLACE}", ms(T_REPLACE)),
            ];
            let keys: Vec<String> = (0..steps.len()).map(|n| format!("step.{n}")).collect();
            let pairs: Vec<(&str, &str)> = keys
                .iter()
                .zip(&steps)
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            network
                .device_with_options(
                    "ctl",
                    &b.load("infra_script"),
                    config(&pairs),
                    DeviceOptions {
                        infra: true,
                        ..DeviceOptions::default()
                    },
                )
                .unwrap();
        }
    }

    let all = |network: &Network| -> Vec<DeviceId> {
        ["server", "wan", "r1", "r2", "r3", "lan", "client"]
            .iter()
            .filter_map(|n| network.live_device(n))
            .collect()
    };
    // The first millisecond: `r1` exists (the controller creates it at 0) and the client has
    // not started. What the server sent before its cable to `r1` was plugged in is dropped on
    // its unwired port; that is the only drop the setup may cause.
    network.run_until(MS).unwrap_or_else(|e| {
        panic!(
            "seed={seed} {how:?}: {e}\n{}",
            transcript(&network.journal())
        )
    });
    assert!(network.live_device("r1").is_some(), "{how:?}: r1 by 1 ms");
    let setup_drops = support::dropped(&network, &all(&network));
    network.run_until_quiescent().unwrap_or_else(|e| {
        panic!(
            "seed={seed} {how:?}: {e}\n{}",
            transcript(&network.journal())
        )
    });
    let r1 = network.live_device("r1").expect("r1 exists");
    let r1_counters = network.counters(r1).unwrap().expect("r1 has counters");
    let r1_routes = network
        .command(r1, "routes", "")
        .unwrap()
        .expect("r1 takes commands")
        .expect("routes answers");
    let devices = all(&network);
    assert_eq!(devices.len(), 7);
    Run {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        links: network
            .links()
            .into_iter()
            .map(|l| network.link_info(l).name)
            .collect(),
        op_states: network.op_states(),
        r1,
        r1_counters,
        r1_routes,
        dropped: support::dropped(&network, &devices) - setup_drops,
    }
}

fn counter(run: &Run, name: &str) -> u64 {
    run.r1_counters
        .iter()
        .find(|(k, _)| k == name)
        .map_or(0, |(_, v)| *v)
}

/// What every run must show, whoever changed the routes.
fn check(run: &Run, label: &str) {
    let log = transcript(&run.journal);

    // The transfer completed.
    let done = events(&run.journal, "client", "http-get-done");
    assert_eq!(done.len(), 1, "{label}: one fetch\n{log}");
    assert_eq!(field(&done[0], "status"), "200", "{label}");
    assert_eq!(field(&done[0], "body-bytes"), BODY.to_string(), "{label}");

    // Nothing was lost: every frame arrived, no router dropped a packet.
    assert_eq!(run.dropped, 0, "{label}: frames dropped after the setup");
    let undelivered: Vec<_> = run
        .frames
        .iter()
        .filter(|f| !matches!(f.fate, FrameFate::Delivered { .. }))
        .collect();
    assert!(undelivered.is_empty(), "{label}: {undelivered:?}");
    for device in ["r1", "r2", "r3"] {
        assert!(
            events(&run.journal, device, "forward-drop").is_empty(),
            "{label}: {device} dropped a packet\n{log}"
        );
    }
    for name in [
        "no-route",
        "neighbor-drops",
        "queue-overflow",
        "port-down-drops",
    ] {
        assert_eq!(counter(run, name), 0, "{label}: r1 {name}");
    }

    // The changes took effect: r1 sent the data to r2, then r3, then r2 again.
    let r1_out = run.r1.port(1);
    let data_to = |from: u64, to: u64, mac: [u8; 6]| {
        run.frames
            .iter()
            .filter(|f| f.from == r1_out && (from..to).contains(&f.sent_at))
            .filter(|f| f.bytes[..6] == mac)
            .filter(|f| support::segment(&f.bytes).is_some_and(|s| !s.payload.is_empty()))
            .count()
    };
    let end = u64::MAX;
    assert!(
        data_to(0, T_ADD, R2_MAC) > 0,
        "{label}: data via r2 before the add"
    );
    assert_eq!(data_to(0, T_ADD, R3_MAC), 0, "{label}");
    assert!(
        data_to(T_ADD, T_REPLACE, R3_MAC) > 0,
        "{label}: via r3 after the add"
    );
    // (A frame sent in the instant of a change may precede it: a derived change applies
    // at its own position in that instant.)
    assert_eq!(data_to(T_ADD + 1, T_REPLACE, R2_MAC), 0, "{label}");
    assert!(
        data_to(T_REPLACE, end, R2_MAC) > 0,
        "{label}: via r2 after the replace"
    );
    assert_eq!(data_to(T_REPLACE + 1, end, R3_MAC), 0, "{label}");

    // No new ARP exchange: every neighbour was already known when the routes changed.
    let late_arp: Vec<_> = run
        .frames
        .iter()
        .filter(|f| f.sent_at >= T_ADD && ethertype(&f.bytes) == Some(0x0806))
        .collect();
    assert!(
        late_arp.is_empty(),
        "{label}: ARP after the change: {late_arp:?}"
    );

    // The router journalled each change once, and kept the refused one out.
    let added = events(&run.journal, "r1", "route-added");
    let removed = events(&run.journal, "r1", "route-removed");
    let prefixes = |list: &[Vec<(String, String)>]| -> Vec<(String, String)> {
        list.iter()
            .map(|e| (field(e, "prefix").to_owned(), field(e, "via").to_owned()))
            .collect()
    };
    assert_eq!(
        prefixes(&added),
        [
            ("10.0.3.10/32".to_owned(), "10.0.2.3".to_owned()),
            ("10.0.3.10/32".to_owned(), "10.0.2.2".to_owned()),
        ],
        "{label}\n{log}"
    );
    assert_eq!(
        prefixes(&removed),
        [("10.0.3.10/32".to_owned(), "10.0.2.3".to_owned())],
        "{label}"
    );
    assert_eq!(counter(run, "routes-added"), 2, "{label}");
    assert_eq!(counter(run, "routes-removed"), 1, "{label}");
    assert!(
        run.r1_routes
            .lines()
            .any(|l| l == "10.0.3.10/32 via 10.0.2.2 port 1 (static)"),
        "{label}: {}",
        run.r1_routes
    );

    // The router's links kept their names: two links, one capture each, never rewired.
    let r1_links: Vec<&String> = run.links.iter().filter(|l| l.contains("r1.")).collect();
    assert_eq!(r1_links.len(), 2, "{label}: {:?}", run.links);
    assert!(
        r1_links.iter().all(|l| !l.ends_with("-2")),
        "{label}: {r1_links:?}"
    );
    assert_eq!(run.pcaps.len(), run.links.len());
    assert_eq!(run.links.len(), 7, "{label}: {:?}", run.links);
}

#[test]
fn an_operator_changes_a_routers_routes_without_losing_a_frame() {
    for seed in [1, 2] {
        let label = format!("operator, seed={seed}");
        let a = run(seed, How::Operator);
        check(&a, &label);
        // The refused command is the op's state; the others applied.
        assert!(matches!(a.op_states[0], OpState::Applied { .. }), "{label}");
        match &a.op_states[1] {
            OpState::Failed { message, .. } => {
                assert!(message.contains("connected"), "{label}: {message}")
            }
            other => panic!("{label}: the refused command is {other:?}"),
        }
        assert!(matches!(a.op_states[2], OpState::Applied { .. }), "{label}");
        let b = run(seed, How::Operator);
        assert_eq!(a.journal, b.journal, "{label}: journal");
        assert_eq!(a.frames, b.frames, "{label}: frames");
        assert_eq!(a.pcaps, b.pcaps, "{label}: pcaps");
    }
}

#[test]
fn a_controller_changes_the_routes_of_a_router_it_created() {
    for seed in [1, 2] {
        let label = format!("controller, seed={seed}");
        let a = run(seed, How::Controller);
        check(&a, &label);
        let log = transcript(&a.journal);
        // r1 is the controller's; every step was taken, the retry was answered from the record
        // (two `control` requests and the refused one were queued, not four).
        let steps = events(&a.journal, "ctl", "infra-script");
        assert_eq!(steps.len(), 5, "{label}\n{log}");
        assert!(
            steps.iter().all(|s| field(s, "result") == "ok"),
            "{label}: {steps:?}"
        );
        assert_eq!(
            events(&a.journal, "ctl", "infra-control").len(),
            3,
            "{label}\n{log}"
        );
        // The router refused one command: journalled on the controller.
        let failed = events(&a.journal, "ctl", "infra-failed");
        assert_eq!(failed.len(), 1, "{label}: {failed:?}");
        assert_eq!(field(&failed[0], "verb"), "control");
        assert_eq!(field(&failed[0], "name"), "r1");
        assert!(
            field(&failed[0], "message").contains("connected"),
            "{failed:?}"
        );
        let b = run(seed, How::Controller);
        assert_eq!(a.journal, b.journal, "{label}: journal");
        assert_eq!(a.frames, b.frames, "{label}: frames");
        assert_eq!(a.pcaps, b.pcaps, "{label}: pcaps");
    }
}
