//! End to end: a multi-homed host. `web` (the netstack with the http-server and http-get apps)
//! is on a LAN by its port 0 and on a second segment by its port 1:
//!
//! ```text
//!   LAN 10.0.1.0/24 (sw1)              segment 10.0.2.0/24 (sw2)
//!   dhcp 10.0.1.2   c1 10.0.1.20       c2 10.0.2.20
//!   r1 10.0.1.254 ── 10.0.9.0/24 ── inet 10.0.9.10
//!   web eth0: DHCP (reserved 10.0.1.10) web eth1: 10.0.2.5/24
//!                                      r2 10.0.2.254 ── 10.0.3.0/24 ── far 10.0.3.10
//! ```
//!
//! `web` leases its LAN address, and with it its default route via `r1`, the home router; its
//! second segment is static, with `routes = "10.0.3.0/24 via 10.0.2.254"`. It serves `c1` and
//! `c2` on their own segments, and fetches `far` through `r2` by the static route and `inet`
//! through `r1` by the lease's default route. A host never forwards: `c1`, whose gateway is
//! `web`, cannot reach `c2` through it.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use std::net::Ipv4Addr;

use support::{built, config, events, field, segment, transcript};
use wasmnet_host::{DeviceId, FrameRecord, JournalEntry, Network, PortRef};

const US: u64 = 1_000;
const MS: u64 = 1_000_000;

struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
    web: DeviceId,
    /// Web's counters at the end.
    counters: Vec<(String, u64)>,
}

/// One IPv4 TCP segment: from the frame, its destination MAC, addresses and SYN flag.
struct Tcp4 {
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    syn: bool,
}

fn tcp4(frame: &[u8]) -> Option<Tcp4> {
    if frame.get(12..14)? != [8, 0] || *frame.get(23)? != 6 {
        return None;
    }
    let ip = |at: usize| Ipv4Addr::new(frame[at], frame[at + 1], frame[at + 2], frame[at + 3]);
    let seg = segment(frame)?;
    Some(Tcp4 {
        dst_mac: frame[..6].try_into().ok()?,
        src: ip(26),
        dst: ip(30),
        syn: seg.syn && !seg.ack,
    })
}

fn tcp_from(frames: &[FrameRecord], port: PortRef) -> Vec<Tcp4> {
    frames
        .iter()
        .filter(|f| f.from == port)
        .filter_map(|f| tcp4(&f.bytes))
        .collect()
}

fn lab(seed: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let switch = |network: &mut Network, name: &str| {
        network
            .device_with_config(name, &b.load("switch"), config(&[("ports", "4")]))
            .unwrap()
    };
    let (sw1, sw2) = (switch(&mut network, "sw1"), switch(&mut network, "sw2"));
    let r1 = network
        .device_with_config(
            "r1",
            &b.load("router"),
            config(&[
                ("port0.mac", "02:00:00:00:01:fe"),
                ("port0.ipv4", "10.0.1.254/24"),
                ("port1.ipv4", "10.0.9.254/24"),
            ]),
        )
        .unwrap();
    let r2 = network
        .device_with_config(
            "r2",
            &b.load("router"),
            config(&[
                ("port0.mac", "02:00:00:00:02:fe"),
                ("port0.ipv4", "10.0.2.254/24"),
                ("port1.ipv4", "10.0.3.254/24"),
            ]),
        )
        .unwrap();
    let dhcp = network
        .device_with_config(
            "dhcp",
            &b.load("node-dhcp-dns"),
            config(&[
                ("mac", "02:00:00:00:01:02"),
                ("ipv4", "10.0.1.2/24"),
                ("app.dhcp-server.server-id", "10.0.1.2"),
                ("app.dhcp-server.pool.a.subnet", "10.0.1.0/24"),
                ("app.dhcp-server.pool.a.range", "10.0.1.100-10.0.1.199"),
                ("app.dhcp-server.pool.a.router", "10.0.1.254"),
                ("app.dhcp-server.pool.a.dns", "10.0.1.2"),
                ("app.dhcp-server.pool.a.lease", "60s"),
                (
                    "app.dhcp-server.pool.a.reserve",
                    "02:00:00:00:01:05=10.0.1.10",
                ),
                ("app.dns-server.zone", "home"),
                ("app.dns-server.records.web", "10.0.1.10"),
            ]),
        )
        .unwrap();
    let web = network
        .device_with_config(
            "web",
            &b.load("node-web-get"),
            config(&[
                ("mac", "02:00:00:00:01:05"),
                ("ipv4", "dhcp"),
                ("hostname", "web"),
                ("port1.mac", "02:00:00:00:02:05"),
                ("port1.ipv4", "10.0.2.5/24"),
                ("routes", "10.0.3.0/24 via 10.0.2.254"),
                ("app.http-server.listen", "0.0.0.0:80"),
                ("app.http-server.route.index.path", "/"),
                ("app.http-server.route.index.body", "hello from web\n"),
                ("app.http-get.urls", "http://10.0.3.10/,http://10.0.9.10/"),
                ("app.http-get.start", "300ms"),
            ]),
        )
        .unwrap();
    let server = |network: &mut Network, name: &str, mac: &str, ip: &str, gw: &str, body: &str| {
        network
            .device_with_config(
                name,
                &b.load("node-http-server"),
                config(&[
                    ("mac", mac),
                    ("ipv4", ip),
                    ("ipv4-gateway", gw),
                    ("app.http-server.listen", "0.0.0.0:80"),
                    ("app.http-server.route.index.path", "/"),
                    ("app.http-server.route.index.body", body),
                ]),
            )
            .unwrap()
    };
    let far = server(
        &mut network,
        "far",
        "02:00:00:00:03:10",
        "10.0.3.10/24",
        "10.0.3.254",
        "far away\n",
    );
    let inet = server(
        &mut network,
        "inet",
        "02:00:00:00:09:10",
        "10.0.9.10/24",
        "10.0.9.254",
        "the internet\n",
    );
    let client = |network: &mut Network, name: &str, mac: &str, ip: &str, gw: &str, urls: &str| {
        network
            .device_with_config(
                name,
                &b.load("node-http-get"),
                config(&[
                    ("mac", mac),
                    ("ipv4", ip),
                    ("ipv4-gateway", gw),
                    ("app.http-get.urls", urls),
                    ("app.http-get.start", "400ms"),
                ]),
            )
            .unwrap()
    };
    // c1's gateway is web: its fetch from c2 must go nowhere (a host forwards nothing).
    let c1 = client(
        &mut network,
        "c1",
        "02:00:00:00:01:20",
        "10.0.1.20/24",
        "10.0.1.10",
        "http://10.0.1.10/,http://10.0.2.20/",
    );
    let c2 = client(
        &mut network,
        "c2",
        "02:00:00:00:02:20",
        "10.0.2.20/24",
        "10.0.2.254",
        "http://10.0.2.5/",
    );
    let cable = |network: &mut Network, a: PortRef, b: PortRef| {
        network.link(a, b).unwrap().latency(50 * US);
    };
    for (n, end) in [dhcp.port(0), c1.port(0), r1.port(0), web.port(0)]
        .into_iter()
        .enumerate()
    {
        cable(&mut network, end, sw1.port(n as u32));
    }
    for (n, end) in [c2.port(0), r2.port(0), web.port(1)]
        .into_iter()
        .enumerate()
    {
        cable(&mut network, end, sw2.port(n as u32));
    }
    cable(&mut network, r1.port(1), inet.port(0));
    cable(&mut network, r2.port(1), far.port(0));
    network
        .run_until(5_000 * MS)
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    let counters = network.counters(web).unwrap().unwrap_or_default();
    Run {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        web,
        counters,
    }
}

#[test]
fn a_host_on_two_segments_serves_both_and_fetches_by_its_routes() {
    let run = lab(42);
    let log = transcript(&run.journal);
    let web0 = run.web.port(0);
    let web1 = run.web.port(1);

    // The LAN port leased its address (and the default route) while eth1 stayed static.
    let bound = events(&run.journal, "web", "dhcp-bound");
    assert_eq!(bound.len(), 1, "{log}");
    assert_eq!(field(&bound[0], "ip"), "10.0.1.10/24", "{log}");
    assert_eq!(field(&bound[0], "router"), "10.0.1.254", "{log}");
    assert_eq!(field(&bound[0], "port"), "eth0", "{log}");

    // Both clients were served by web, each on its own segment.
    for (client, url) in [("c1", "http://10.0.1.10/"), ("c2", "http://10.0.2.5/")] {
        let done = events(&run.journal, client, "http-get-done");
        let ok = done
            .iter()
            .find(|d| field(d, "url") == url)
            .unwrap_or_else(|| panic!("{client} fetched {url}\n{log}"));
        assert_eq!(field(ok, "status"), "200", "{log}");
        assert_eq!(field(ok, "body-bytes"), "15", "{log}");
    }
    // Web answered c1 from eth0 with its leased address and c2 from eth1 with its static one.
    let to = |port: PortRef, peer: [u8; 4]| -> Vec<Ipv4Addr> {
        tcp_from(&run.frames, port)
            .into_iter()
            .filter(|t| t.dst == Ipv4Addr::from(peer))
            .map(|t| t.src)
            .collect()
    };
    let c1_seen = to(web0, [10, 0, 1, 20]);
    assert!(!c1_seen.is_empty() && c1_seen.iter().all(|a| *a == Ipv4Addr::new(10, 0, 1, 10)));
    let c2_seen = to(web1, [10, 0, 2, 20]);
    assert!(!c2_seen.is_empty() && c2_seen.iter().all(|a| *a == Ipv4Addr::new(10, 0, 2, 5)));
    assert!(to(web0, [10, 0, 2, 20]).is_empty() && to(web1, [10, 0, 1, 20]).is_empty());

    // Its own fetches: far through r2 by the static route (eth1), inet through r1 by the
    // lease's default route (eth0), each from that port's address.
    let done = events(&run.journal, "web", "http-get-done");
    let status = |url: &str| {
        done.iter()
            .find(|d| field(d, "url") == url)
            .map(|d| field(d, "status").to_owned())
    };
    assert_eq!(status("http://10.0.3.10/").as_deref(), Some("200"), "{log}");
    assert_eq!(status("http://10.0.9.10/").as_deref(), Some("200"), "{log}");
    let syns = |port: PortRef, dst: [u8; 4]| -> Vec<([u8; 6], Ipv4Addr)> {
        tcp_from(&run.frames, port)
            .into_iter()
            .filter(|t| t.syn && t.dst == Ipv4Addr::from(dst))
            .map(|t| (t.dst_mac, t.src))
            .collect()
    };
    let r2_mac = [2, 0, 0, 0, 2, 0xfe];
    let r1_mac = [2, 0, 0, 0, 1, 0xfe];
    assert_eq!(
        syns(web1, [10, 0, 3, 10]),
        [(r2_mac, Ipv4Addr::new(10, 0, 2, 5))],
        "{log}"
    );
    assert_eq!(
        syns(web0, [10, 0, 9, 10]),
        [(r1_mac, Ipv4Addr::new(10, 0, 1, 10))],
        "{log}"
    );
    assert!(syns(web0, [10, 0, 3, 10]).is_empty() && syns(web1, [10, 0, 9, 10]).is_empty());

    // No forwarding: c1 sent its SYNs for c2 to web, and web never passed them on.
    let c1_to_c2 = run
        .frames
        .iter()
        .filter(|f| f.to == web0)
        .filter_map(|f| tcp4(&f.bytes))
        .filter(|t| t.dst == Ipv4Addr::new(10, 0, 2, 20))
        .count();
    assert!(c1_to_c2 > 0, "{log}");
    let passed_on = run
        .frames
        .iter()
        .filter(|f| f.from == web0 || f.from == web1)
        .filter_map(|f| tcp4(&f.bytes))
        .filter(|t| t.src == Ipv4Addr::new(10, 0, 1, 20))
        .count();
    assert_eq!(passed_on, 0, "web sent none of c1's packets on\n{log}");
    assert!(
        !events(&run.journal, "c1", "http-get-done")
            .iter()
            .any(|d| field(d, "url") == "http://10.0.2.20/"),
        "{log}"
    );

    // Each port's own counters follow the totals on a node with several ports.
    let counters: std::collections::BTreeMap<String, u64> = run.counters.into_iter().collect();
    assert_eq!(
        counters["eth0.rx-frames"] + counters["eth1.rx-frames"],
        counters["rx-frames"]
    );
    assert_eq!(counters["eth0.dhcp-bound"], 1);
    assert_eq!(counters["eth1.dhcp-bound"], 0);
    assert_eq!(counters["driver-late-wakes"], 0);
}

#[test]
fn the_multi_homed_lab_is_deterministic() {
    let (a, b) = (lab(42), lab(42));
    assert_eq!(
        a.pcaps, b.pcaps,
        "seed=42: the captures differ between runs"
    );
    assert_eq!(a.journal, b.journal, "seed=42: the journals differ");
    let other = lab(7);
    let done = events(&other.journal, "web", "http-get-done");
    assert_eq!(done.len(), 2, "seed=7\n{}", transcript(&other.journal));
    let (c, d) = (lab(7), other);
    assert_eq!(c.pcaps, d.pcaps, "seed=7: the captures differ between runs");
}
