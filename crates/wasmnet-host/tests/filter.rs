//! End to end: a router's packet filter, for IPv4 and IPv6, and a rule added by a command while
//! the network runs.
//!
//! ```text
//!  web 10.0.1.10, fd00:1::10 ─┐                          ┌─ browser 10.0.2.10, fd00:2::10
//!  caller 10.0.1.20           ├─ lan ── fw ── wan ───────┤  echo 10.0.2.20
//!  echo 10.0.1.30             ┘                          └─ prober 10.0.2.30
//! ```
//!
//! `fw` allows only TCP port 80 to `web` from the outside (`port1.allow`). The outside browser
//! fetches from `web` over IPv4 and IPv6; the inside caller's echoes to the outside come back
//! (return traffic); the outside prober's echoes to the inside echo server are dropped, until a
//! command adds `udp to 10.0.1.30/32 dport 7` (in the second variant), after which they pass.
//! Each runs at two seeds, twice, byte for byte.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config, events, field, transcript};
use wasmnet_host::sim::{DeviceCommand, Op, Placement};
use wasmnet_host::{FrameRecord, JournalEntry, Network};

const US: u64 = 1_000;
const MS: u64 = 1_000_000;

/// When the command allows the prober's echoes.
const T_ALLOW: u64 = 250 * MS;

struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
    counters: Vec<(String, u64)>,
    rules: String,
}

fn run(seed: u64, command: bool) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let node = |network: &mut Network, name: &str, component: &str, pairs: &[(&str, &str)]| {
        network
            .device_with_config(name, &b.load(component), config(pairs))
            .unwrap()
    };
    let lan = node(&mut network, "lan", "switch", &[("ports", "4")]);
    let wan = node(&mut network, "wan", "switch", &[("ports", "4")]);
    let fw = node(
        &mut network,
        "fw",
        "router",
        &[
            ("mac", "02:00:00:00:fe:00"),
            ("port0.ipv4", "10.0.1.1/24"),
            ("port0.ipv6", "fd00:1::1/64"),
            ("port1.ipv4", "10.0.2.1/24"),
            ("port1.ipv6", "fd00:2::1/64"),
            (
                "port1.allow",
                "tcp to 10.0.1.10/32 dport 80, tcp to fd00:1::10/128 dport 80",
            ),
        ],
    );
    let web = node(
        &mut network,
        "web",
        "node-http-server",
        &[
            ("mac", "02:00:00:00:01:10"),
            ("ipv4", "10.0.1.10/24"),
            ("ipv4-gateway", "10.0.1.1"),
            ("ipv6", "fd00:1::10/64"),
            ("ipv6-gateway", "fd00:1::1"),
            ("app.http-server.listen", "0.0.0.0:80,[::]:80"),
        ],
    );
    let echo_client = |target: &str, start: &str| {
        vec![
            ("app.udp-echo-client.target".to_owned(), target.to_owned()),
            ("app.udp-echo-client.count".to_owned(), "5".to_owned()),
            (
                "app.udp-echo-client.interval".to_owned(),
                "100ms".to_owned(),
            ),
            ("app.udp-echo-client.timeout".to_owned(), "50ms".to_owned()),
            ("app.udp-echo-client.start".to_owned(), start.to_owned()),
        ]
    };
    let with = |base: &[(&str, &str)], extra: Vec<(String, String)>| {
        let mut c = config(base);
        c.extend(extra);
        c
    };
    let caller = network
        .device_with_config(
            "caller",
            &b.load("node-udp-echo-client"),
            with(
                &[
                    ("mac", "02:00:00:00:01:20"),
                    ("ipv4", "10.0.1.20/24"),
                    ("ipv4-gateway", "10.0.1.1"),
                ],
                echo_client("10.0.2.20", "5ms"),
            ),
        )
        .unwrap();
    let inside_echo = node(
        &mut network,
        "inside-echo",
        "node-udp-echo-server",
        &[
            ("mac", "02:00:00:00:01:30"),
            ("ipv4", "10.0.1.30/24"),
            ("ipv4-gateway", "10.0.1.1"),
        ],
    );
    let browser = node(
        &mut network,
        "browser",
        "node-http-get",
        &[
            ("mac", "02:00:00:00:02:10"),
            ("ipv4", "10.0.2.10/24"),
            ("ipv4-gateway", "10.0.2.1"),
            ("ipv6", "fd00:2::10/64"),
            ("ipv6-gateway", "fd00:2::1"),
            ("app.http-get.url", "http://10.0.1.10/big?n=3000"),
            ("app.http-get.urls", "http://[fd00:1::10]/big?n=2000"),
            ("app.http-get.start", "5ms"),
        ],
    );
    let outside_echo = node(
        &mut network,
        "outside-echo",
        "node-udp-echo-server",
        &[
            ("mac", "02:00:00:00:02:20"),
            ("ipv4", "10.0.2.20/24"),
            ("ipv4-gateway", "10.0.2.1"),
        ],
    );
    let prober = network
        .device_with_config(
            "prober",
            &b.load("node-udp-echo-client"),
            with(
                &[
                    ("mac", "02:00:00:00:02:30"),
                    ("ipv4", "10.0.2.30/24"),
                    ("ipv4-gateway", "10.0.2.1"),
                ],
                echo_client("10.0.1.30", "10ms"),
            ),
        )
        .unwrap();
    let link = |network: &mut Network, a, b| {
        network.link(a, b).unwrap().latency(100 * US);
    };
    link(&mut network, fw.port(0), lan.port(0));
    link(&mut network, web.port(0), lan.port(1));
    link(&mut network, caller.port(0), lan.port(2));
    link(&mut network, inside_echo.port(0), lan.port(3));
    link(&mut network, fw.port(1), wan.port(0));
    link(&mut network, browser.port(0), wan.port(1));
    link(&mut network, outside_echo.port(0), wan.port(2));
    link(&mut network, prober.port(0), wan.port(3));
    if command {
        network
            .add_op(
                Op::control(
                    fw,
                    DeviceCommand::new("allow-add", "1 udp to 10.0.1.30/32 dport 7").into_control(),
                ),
                Placement::StartOf(T_ALLOW),
            )
            .unwrap();
    }
    network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    let counters = network.counters(fw).unwrap().expect("counters");
    let rules = network
        .command(fw, "rules", "")
        .unwrap()
        .expect("fw takes commands")
        .expect("rules answers");
    Run {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        counters,
        rules,
    }
}

fn counter(run: &Run, name: &str) -> u64 {
    run.counters
        .iter()
        .find(|(k, _)| k == name)
        .map_or_else(|| panic!("no counter {name}"), |(_, v)| *v)
}

/// The sequence numbers of the echoes `device` got back.
fn replies(run: &Run, device: &str) -> Vec<String> {
    events(&run.journal, device, "udp-echo-reply")
        .iter()
        .map(|e| field(e, "seq").to_owned())
        .collect()
}

#[test]
fn the_filter_allows_by_rule_and_lets_answers_back() {
    for command in [false, true] {
        for seed in [1, 2] {
            let label = format!("command={command}, seed={seed}");
            let a = run(seed, command);
            let log = transcript(&a.journal);
            // The allowed service, over both families.
            let done = events(&a.journal, "browser", "http-get-done");
            assert_eq!(done.len(), 2, "{label}\n{log}");
            assert!(done.iter().all(|d| field(d, "status") == "200"), "{label}");
            // Return traffic of the inside caller's flow.
            assert_eq!(
                replies(&a, "caller"),
                ["1", "2", "3", "4", "5"],
                "{label}\n{log}"
            );
            // The prober: blocked, or blocked until the command at 250 ms (seq 3 leaves at
            // 210 ms and times out; seq 4 leaves at 310 ms).
            let prober = replies(&a, "prober");
            let drops = events(&a.journal, "fw", "filter-drop");
            if command {
                assert_eq!(prober, ["4", "5"], "{label}\n{log}");
                let added = events(&a.journal, "fw", "allow-added");
                assert_eq!(added.len(), 1, "{label}");
                assert_eq!(field(&added[0], "rule"), "udp to 10.0.1.30/32 dport 7");
                assert_eq!(
                    a.rules,
                    "1 tcp to 10.0.1.10/32 dport 80\n1 tcp to fd00:1::10/128 dport 80\n\
                     1 udp to 10.0.1.30/32 dport 7"
                );
                assert_eq!(counter(&a, "filter-dropped"), 3, "{label}");
            } else {
                assert!(prober.is_empty(), "{label}");
                assert_eq!(counter(&a, "filter-dropped"), 5, "{label}");
            }
            // One `filter-drop` per flow (the prober's datagrams share one).
            assert_eq!(drops.len(), 1, "{label}: {drops:?}");
            assert_eq!(field(&drops[0], "dst"), "10.0.1.30:7");
            assert_eq!(field(&drops[0], "port"), "1");
            assert!(events(&a.journal, "inside-echo", "udp-echoed").len() == prober.len());
            let b = run(seed, command);
            assert_eq!(a.journal, b.journal, "{label}: journal");
            assert_eq!(a.frames, b.frames, "{label}: frames");
            assert_eq!(a.pcaps, b.pcaps, "{label}: pcaps");
        }
    }
}
