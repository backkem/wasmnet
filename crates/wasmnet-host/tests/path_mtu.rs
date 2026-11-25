//! Path MTU discovery end to end (`docs/design/netstack.md`): real composed nodes fetch 200 KB
//! across two routers whose link between them carries IP packets of at most 1280 bytes, while
//! both hosts have an MTU of 1500 and agree on 1460-byte segments.
//!
//! The router before the narrow link answers every full-size segment with an ICMP
//! "fragmentation needed" (IPv4) or "packet too big" (IPv6). The sender must lower its segment
//! size for that connection and send the lost data again, or the transfer stalls after the
//! handshake. Both directions (the server on either side), both families, two seeds, each
//! rerun byte for byte.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`). Replay a failure with
//! `cargo test -p wasmnet-host --test path_mtu -- --nocapture`.

mod support;

use support::{built, config, events, field, transcript};
use wasmnet_host::{FrameRecord, JournalEntry, Nanos, Network, Record};

const US: Nanos = 1_000;
const MS: Nanos = 1_000_000;

/// The body `GET /big?n=` asks for.
const BODY: u64 = 200_000;
/// The narrow link's IP MTU.
const NARROW: u16 = 1280;
/// How long a fetch may take: the transfer needs well under a second; a stalled one keeps
/// retransmitting the same segment with a back-off up to 60 s and never finishes.
const DEADLINE: Nanos = 30_000 * MS;

/// Which side the server is on.
#[derive(Clone, Copy, Debug)]
enum Server {
    Left,
    Right,
}

struct Fetch {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
}

/// `left` (10.0.1.10, fd00:1::10) - `r1` - narrow link - `r2` - `right` (10.0.3.10,
/// fd00:3::10). The client fetches `/big?n=BODY` from the server over `v6` or IPv4.
fn fetch(seed: u64, server: Server, v6: bool) -> Fetch {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let narrow = NARROW.to_string();
    let r1 = network
        .device_with_config(
            "r1",
            &b.load("router"),
            config(&[
                ("mac", "02:00:00:00:fe:01"),
                ("port0.ipv4", "10.0.1.1/24"),
                ("port0.ipv6", "fd00:1::1/64"),
                ("port1.ipv4", "10.0.2.1/24"),
                ("port1.ipv6", "fd00:2::1/64"),
                ("port1.mtu", &narrow),
                (
                    "routes",
                    "10.0.3.0/24 via 10.0.2.2,fd00:3::/64 via fd00:2::2",
                ),
            ]),
        )
        .unwrap();
    let r2 = network
        .device_with_config(
            "r2",
            &b.load("router"),
            config(&[
                ("mac", "02:00:00:00:fe:02"),
                ("port0.ipv4", "10.0.2.2/24"),
                ("port0.ipv6", "fd00:2::2/64"),
                ("port0.mtu", &narrow),
                ("port1.ipv4", "10.0.3.1/24"),
                ("port1.ipv6", "fd00:3::1/64"),
                (
                    "routes",
                    "10.0.1.0/24 via 10.0.2.1,fd00:1::/64 via fd00:2::1",
                ),
            ]),
        )
        .unwrap();
    let host = |side: usize| {
        let n = if side == 0 { 1 } else { 3 };
        vec![
            ("mac".to_owned(), format!("02:00:00:00:0{n}:10")),
            ("ipv4".to_owned(), format!("10.0.{n}.10/24")),
            ("ipv4-gateway".to_owned(), format!("10.0.{n}.1")),
            ("ipv6".to_owned(), format!("fd00:{n}::10/64")),
            ("ipv6-gateway".to_owned(), format!("fd00:{n}::1")),
        ]
    };
    let (server_side, client_side) = match server {
        Server::Left => (0, 1),
        Server::Right => (1, 0),
    };
    let target = match (server_side, v6) {
        (0, false) => "10.0.1.10".to_owned(),
        (0, true) => "[fd00:1::10]".to_owned(),
        (_, false) => "10.0.3.10".to_owned(),
        (_, true) => "[fd00:3::10]".to_owned(),
    };
    let mut server_cfg = host(server_side);
    server_cfg.push((
        "app.http-server.listen".to_owned(),
        "0.0.0.0:80,[::]:80".to_owned(),
    ));
    let mut client_cfg = host(client_side);
    client_cfg.push((
        "app.http-get.url".to_owned(),
        format!("http://{target}/big?n={BODY}"),
    ));
    client_cfg.push(("app.http-get.start".to_owned(), "1ms".to_owned()));
    let cfg = |pairs: &[(String, String)]| {
        let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (&k[..], &v[..])).collect();
        config(&refs)
    };
    let server_dev = network
        .device_with_config("server", &b.load("node-http-server"), cfg(&server_cfg))
        .unwrap();
    let client_dev = network
        .device_with_config("client", &b.load("node-http-get"), cfg(&client_cfg))
        .unwrap();
    let (left, right) = match server {
        Server::Left => (server_dev, client_dev),
        Server::Right => (client_dev, server_dev),
    };
    network
        .link(left.port(0), r1.port(0))
        .unwrap()
        .latency(100 * US);
    network
        .link(r1.port(1), r2.port(0))
        .unwrap()
        .latency(300 * US);
    network
        .link(r2.port(1), right.port(0))
        .unwrap()
        .latency(100 * US);
    network
        .run_until(DEADLINE)
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    Fetch {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
    }
}

/// Runs each case twice at two seeds: it completes, and each seed replays byte for byte.
fn completes(server: Server, v6: bool) {
    for seed in [1, 2] {
        let a = fetch(seed, server, v6);
        let log = transcript(&a.journal);
        let done = events(&a.journal, "client", "http-get-done");
        assert_eq!(
            done.len(),
            1,
            "{server:?} v6={v6} seed={seed}: the fetch did not finish\n{}",
            tail(&log)
        );
        assert_eq!(field(&done[0], "status"), "200");
        assert_eq!(field(&done[0], "body-bytes"), BODY.to_string());
        let sent = events(&a.journal, "server", "http-response");
        assert_eq!(field(&done[0], "body-fnv"), field(&sent[0], "body-fnv"));
        // The sender learned the path MTU from the router before the narrow link.
        let learned = events(&a.journal, "server", "path-mtu-lowered");
        assert_eq!(
            learned.len(),
            1,
            "{server:?} v6={v6} seed={seed}\n{}",
            tail(&log)
        );
        assert_eq!(field(&learned[0], "mtu"), NARROW.to_string());
        let mss = if v6 { NARROW - 60 } else { NARROW - 40 };
        assert_eq!(field(&learned[0], "mss"), mss.to_string());
        let at = a
            .journal
            .iter()
            .find(|e| matches!(&e.record, Record::Event { kind, .. } if kind == "http-get-done"))
            .map_or(0, |e| e.at);
        println!(
            "{server:?} v6={v6} seed={seed}: done at {} ns, {} frames",
            at,
            a.frames.len()
        );
        let b = fetch(seed, server, v6);
        assert!(a.pcaps == b.pcaps, "seed={seed}: the captures differ");
        assert!(a.journal == b.journal, "seed={seed}: the journals differ");
    }
}

/// The end of a long transcript.
fn tail(log: &str) -> String {
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

#[test]
fn a_fetch_from_the_left_learns_the_path_mtu_over_ipv4() {
    completes(Server::Left, false);
}

#[test]
fn a_fetch_from_the_right_learns_the_path_mtu_over_ipv4() {
    completes(Server::Right, false);
}

#[test]
fn a_fetch_from_the_left_learns_the_path_mtu_over_ipv6() {
    completes(Server::Left, true);
}

#[test]
fn a_fetch_from_the_right_learns_the_path_mtu_over_ipv6() {
    completes(Server::Right, true);
}
