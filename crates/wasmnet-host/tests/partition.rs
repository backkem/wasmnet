//! End to end: a switch cut into groups by command, healed, and then slowed between two ports.
//!
//! Three nodes on one switch: `n0` (port 0) pings `n1` (port 1) and `n2` (port 2) every 100 ms,
//! and `n2` pings `n1`. At 1 s the switch is partitioned into ports 0 and 1 against port 2; at
//! 2 s it heals; at 2.5 s the pair 0-1 gets a 20 ms delay each way. The test asserts on the
//! pings' replies and timeouts and on the decoded frames the switch sent, at two seeds, each
//! byte-identical on a rerun.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config, events, field, transcript};
use wasmnet_host::{DeviceId, FrameRecord, JournalEntry, Network, Record};

const US: u64 = 1_000;
const MS: u64 = 1_000_000;
const S: u64 = 1_000_000_000;

const MACS: [[u8; 6]; 3] = [
    [2, 0, 0, 0, 0, 0x10],
    [2, 0, 0, 0, 0, 0x11],
    [2, 0, 0, 0, 0, 0x12],
];

struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
    switch: DeviceId,
    counters: Vec<(String, u64)>,
}

fn command(network: &mut Network, d: DeviceId, c: &str, a: &str) -> String {
    match network.command(d, c, a).unwrap() {
        Some(Ok(s)) => s,
        other => panic!("{c} {a}: {other:?}"),
    }
}

fn run(seed: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "3")]))
        .unwrap();
    let ping = b.load("node-ping");
    let mac = |n: usize| {
        MACS[n]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let session = |name: &str, target: &str| {
        vec![
            (format!("app.ping.{name}.target"), target.to_owned()),
            (format!("app.ping.{name}.count"), "30".to_owned()),
            (format!("app.ping.{name}.interval"), "100ms".to_owned()),
            (format!("app.ping.{name}.start"), "100ms".to_owned()),
            (format!("app.ping.{name}.timeout"), "90ms".to_owned()),
        ]
    };
    for n in 0..3 {
        let mut cfg = vec![
            ("mac".to_owned(), mac(n)),
            ("ipv4".to_owned(), format!("10.0.0.{}/24", n + 1)),
        ];
        match n {
            0 => {
                cfg.extend(session("n1", "10.0.0.2"));
                cfg.extend(session("n2", "10.0.0.3"));
            }
            2 => cfg.extend(session("n1", "10.0.0.2")),
            _ => {}
        }
        let pairs: Vec<(&str, &str)> = cfg.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let node = network
            .device_with_config(&format!("n{n}"), &ping, config(&pairs))
            .unwrap();
        network
            .link(node.port(0), sw.port(n as u32))
            .unwrap()
            .latency(100 * US);
    }
    for (at, c, a, want) in [
        (S, "partition", "0+1 2", "partitioned"),
        (2 * S, "heal", "", "healed"),
        (2500 * MS, "delay", "0 1 20ms", "delayed"),
    ] {
        network.run_until(at).unwrap();
        assert_eq!(command(&mut network, sw, c, a), want);
    }
    network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    let counters = network.counters(sw).unwrap().unwrap();
    Run {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        switch: sw,
        counters,
    }
}

/// The sequence numbers of `session` on `node` that got a reply, with their round trip, and
/// those that timed out.
fn outcome(journal: &[JournalEntry], node: &str, session: &str) -> (Vec<(u64, u64)>, Vec<u64>) {
    let replies = events(journal, node, "ping-reply")
        .iter()
        .filter(|f| field(f, "session") == session)
        .map(|f| {
            (
                field(f, "seq").parse().unwrap(),
                field(f, "rtt-ns").parse().unwrap(),
            )
        })
        .collect();
    let timeouts = events(journal, node, "ping-timeout")
        .iter()
        .filter(|f| field(f, "session") == session)
        .map(|f| field(f, "seq").parse().unwrap())
        .collect();
    (replies, timeouts)
}

#[test]
fn a_switch_partitions_three_nodes_heals_and_slows_a_pair() {
    for seed in [1, 2] {
        let label = format!("seed={seed}");
        let r = run(seed);
        let log = transcript(&r.journal);
        // Request k leaves at k * 100 ms. Requests 10 to 19 meet the partition: request 10 leaves
        // at the instant of the cut and reaches the switch after it; request 20 leaves at the
        // instant of the heal and gets through.
        let inside = 10..=19u64;
        let (to_n2, lost) = outcome(&r.journal, "n0", "n2");
        assert_eq!(
            lost,
            inside.clone().collect::<Vec<_>>(),
            "{label}: n0 -> n2\n{log}"
        );
        assert!(to_n2.iter().all(|(s, _)| !inside.contains(s)));
        assert_eq!(
            to_n2.len(),
            30 - 10,
            "{label}: every other request answered"
        );
        let (from_n2, lost) = outcome(&r.journal, "n2", "n1");
        assert_eq!(
            lost,
            inside.clone().collect::<Vec<_>>(),
            "{label}: n2 -> n1"
        );
        assert_eq!(from_n2.len(), 20);
        // Inside one group nothing changed, until the delay: 20 ms each way from 2.5 s on
        // (request 25 leaves at that instant and is held).
        let (to_n1, lost) = outcome(&r.journal, "n0", "n1");
        assert!(lost.is_empty(), "{label}: n0 -> n1 never lost one");
        assert_eq!(to_n1.len(), 30);
        for (seq, rtt) in &to_n1 {
            if *seq >= 25 {
                assert!(
                    *rtt >= 40 * MS && *rtt < 41 * MS,
                    "{label}: seq {seq} took {rtt}"
                );
            } else {
                assert!(*rtt < MS, "{label}: seq {seq} took {rtt}");
            }
        }
        // On the wire: while partitioned, the switch sent nothing across the cut.
        let src = |f: &FrameRecord| -> [u8; 6] { f.bytes[6..12].try_into().unwrap() };
        let mut within = 0;
        for f in r.frames.iter().filter(|f| f.from.device == r.switch) {
            let across = match f.from.port {
                2 => src(f) == MACS[0] || src(f) == MACS[1],
                _ => src(f) == MACS[2],
            };
            if (S..2 * S).contains(&f.sent_at) {
                assert!(!across, "{label}: a frame across the cut at {}", f.sent_at);
                within += 1;
            }
        }
        assert!(within > 10, "{label}: traffic inside the groups went on");
        // The switch said so, and counted it.
        let kinds: Vec<String> = r
            .journal
            .iter()
            .filter(|e| e.device == "sw")
            .filter_map(|e| match &e.record {
                Record::Event { kind, .. } if kind.starts_with("ports-") => Some(kind.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, ["ports-blocked", "ports-healed", "ports-delayed"]);
        let blocked = events(&r.journal, "sw", "ports-blocked");
        assert_eq!(
            (
                field(&blocked[0], "from"),
                field(&blocked[0], "to"),
                field(&blocked[0], "pairs")
            ),
            ("0+1", "2", "2")
        );
        let get = |k: &str| r.counters.iter().find(|(n, _)| n == k).map(|(_, v)| *v);
        // Ten requests each way into the cut, from n0 (port 0) and from n2 (port 2).
        assert_eq!(
            (get("p0-blocked"), get("p2-blocked")),
            (Some(10), Some(10)),
            "{label}: {:?}",
            r.counters
        );
        assert_eq!(get("blocked-pairs"), Some(0), "healed");
        assert_eq!(get("delayed-pairs"), Some(1));
        assert_eq!(get("held"), Some(0));
        assert!(get("p0-delayed").unwrap() >= 5 && get("p1-delayed").unwrap() >= 5);
        let again = run(seed);
        assert_eq!(r.journal, again.journal, "{label}: journal");
        assert_eq!(r.frames, again.frames, "{label}: frames");
        assert_eq!(r.pcaps, again.pcaps, "{label}: pcaps");
    }
}
