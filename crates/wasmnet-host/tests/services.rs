//! End to end: the services a network needs before an application can say `http://web/`.
//!
//! * **Zero configuration.** A client with no address broadcasts a DHCP DISCOVER, is offered and
//!   handed the address (OFFER, REQUEST, ACK), learns its DNS server from the lease, asks that
//!   server for `web.home`, and fetches the page from the address the answer names. The web server
//!   itself got its address by DHCP too, from a reservation.
//! * **mDNS.** A responder claims `alice.local` on the link (probes, then announces); a client
//!   resolves the name with a multicast query and fetches from the address it learns.
//! * The same seed gives the same bytes on every link.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{
    DnsMessage, built, config, dhcp_types_from, dns_messages_from, events, field, transcript,
};
use wasmnet_host::{FrameRecord, JournalEntry, Network, PortRef};

const US: u64 = 1_000;
const MS: u64 = 1_000_000;

struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
    /// The DHCP server's port and the fetching client's port (zero configuration only).
    infra: PortRef,
    client: PortRef,
}

fn finish(mut network: Network, deadline: Option<u64>, seed: u64, ports: [PortRef; 2]) -> Run {
    let outcome = match deadline {
        Some(d) => network.run_until(d),
        None => network.run_until_quiescent(),
    };
    outcome.unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    Run {
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        infra: ports[0],
        client: ports[1],
    }
}

/// `infra` (DHCP and DNS servers), `web` and `client` on one switch; `web` and `client` boot
/// with `ipv4 = dhcp`. Stops at 1 s: the servers and the lease timers never go quiet.
fn zero_config(seed: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "4")]))
        .unwrap();
    let infra = network
        .device_with_config(
            "infra",
            &b.load("node-dhcp-dns"),
            config(&[
                ("mac", "02:00:00:00:01:02"),
                ("ipv4", "10.0.1.2/24"),
                ("app.dhcp-server.server-id", "10.0.1.2"),
                ("app.dhcp-server.pool.a.subnet", "10.0.1.0/24"),
                ("app.dhcp-server.pool.a.range", "10.0.1.100-10.0.1.199"),
                ("app.dhcp-server.pool.a.router", "10.0.1.1"),
                ("app.dhcp-server.pool.a.dns", "10.0.1.2"),
                ("app.dhcp-server.pool.a.domain", "home"),
                ("app.dhcp-server.pool.a.lease", "10s"),
                (
                    "app.dhcp-server.pool.a.reserve",
                    "02:00:00:00:01:10=10.0.1.10",
                ),
                ("app.dns-server.zone", "home"),
                ("app.dns-server.records.web", "10.0.1.10"),
                ("app.dns-server.records.infra", "10.0.1.2"),
            ]),
        )
        .unwrap();
    let web = network
        .device_with_config(
            "web",
            &b.load("node-http-server"),
            config(&[
                ("mac", "02:00:00:00:01:10"),
                ("ipv4", "dhcp"),
                ("hostname", "web"),
                ("app.http-server.listen", "0.0.0.0:80"),
                ("app.http-server.route.index.path", "/"),
                ("app.http-server.route.index.body", "hello from web.home\n"),
            ]),
        )
        .unwrap();
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:02:10"),
                ("ipv4", "dhcp"),
                ("hostname", "client"),
                ("app.http-get.url", "http://web.home/"),
                ("app.http-get.start", "10ms"),
            ]),
        )
        .unwrap();
    for (dev, port) in [(infra, 1), (web, 2), (client, 3)] {
        network
            .link(dev.port(0), sw.port(port))
            .unwrap()
            .latency(50 * US);
    }
    let ports = [infra.port(0), client.port(0)];
    finish(network, Some(1_000 * MS), seed, ports)
}

#[test]
fn a_client_boots_with_no_configuration_and_fetches_by_name() {
    let run = zero_config(42);
    let log = transcript(&run.journal);

    // The lease: DISCOVER, OFFER, REQUEST, ACK for each of the two clients, in that order per
    // client (the messages of the two exchanges may interleave).
    // Seen from the client's port: DISCOVER, then REQUEST. From the server's: an OFFER and an
    // ACK for each of the two clients (web and the client).
    let sent = dhcp_types_from(&run.frames, run.client);
    assert_eq!(sent, [1, 3], "DISCOVER, REQUEST\n{log}");
    let served = dhcp_types_from(&run.frames, run.infra);
    assert_eq!(served, [2, 2, 5, 5], "two OFFERs, then two ACKs\n{log}");

    let offers = events(&run.journal, "infra", "dhcp-offer");
    assert!(
        offers
            .iter()
            .any(|o| field(o, "ip") == "10.0.1.10" && field(o, "hostname") == "web"),
        "web is offered its reservation\n{log}"
    );
    let bound = events(&run.journal, "client", "dhcp-bound");
    assert_eq!(bound.len(), 1, "{log}");
    assert_eq!(
        field(&bound[0], "dns"),
        "10.0.1.2",
        "the lease names the DNS server"
    );
    assert_eq!(field(&bound[0], "domain"), "home");
    assert!(field(&bound[0], "ip").starts_with("10.0.1."), "{log}");
    let web = events(&run.journal, "web", "dhcp-bound");
    assert_eq!(field(&web[0], "ip"), "10.0.1.10/24", "{log}");

    // DNS: the client sends one query, the server one authoritative answer (no IPv6, so no AAAA).
    let asked = dns_messages_from(&run.frames, run.client);
    let answered = dns_messages_from(&run.frames, run.infra);
    let make = |response| DnsMessage {
        response,
        rcode: 0,
        name: "web.home".into(),
    };
    assert_eq!(asked, [make(false)], "{log}");
    assert_eq!(answered, [make(true)], "{log}");
    let served = events(&run.journal, "infra", "dns-served");
    assert_eq!(field(&served[0], "name"), "web.home");
    assert_eq!(field(&served[0], "answers"), "10.0.1.10");
    let resolved = events(&run.journal, "client", "name-resolved");
    assert_eq!(field(&resolved[0], "name"), "web.home");
    assert_eq!(field(&resolved[0], "addresses"), "10.0.1.10");

    // Then the fetch.
    let done = events(&run.journal, "client", "http-get-done");
    assert_eq!(done.len(), 1, "{log}");
    assert_eq!(field(&done[0], "status"), "200", "{log}");
    assert_eq!(field(&done[0], "body-bytes"), "20", "{log}");
    let exit = events(&run.journal, "client", "app-exit");
    assert_eq!(field(&exit[0], "status"), "ok", "{log}");
}

#[test]
fn zero_config_is_deterministic() {
    let (a, b) = (zero_config(42), zero_config(42));
    assert_eq!(
        a.pcaps, b.pcaps,
        "seed=42: the captures differ between runs"
    );
    assert_eq!(a.journal, b.journal, "seed=42: the journals differ");
    let other = zero_config(7);
    assert_eq!(events(&other.journal, "client", "http-get-done").len(), 1);
}

/// `alice` (an HTTP server that claims `alice.local`) and `bob`, who fetches `alice.local`.
fn mdns(seed: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let sw = network
        .device_with_config(
            "sw",
            &b.load("switch"),
            config(&[("ports", "4"), ("aging", "10s")]),
        )
        .unwrap();
    let alice = network
        .device_with_config(
            "alice",
            &b.load("node-mdns-web"),
            config(&[
                ("mac", "02:00:00:00:00:10"),
                ("ipv4", "10.0.0.10/24"),
                ("ipv6", "fd00::10/64"),
                ("app.http-server.listen", "10.0.0.10:80,[fd00::10]:80"),
                ("app.http-server.route.index.path", "/"),
                ("app.http-server.route.index.body", "hello"),
                ("app.mdns-responder.hostname", "alice"),
            ]),
        )
        .unwrap();
    let bob = network
        .device_with_config(
            "bob",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:00:20"),
                ("ipv4", "10.0.0.20/24"),
                ("ipv6", "fd00::20/64"),
                (
                    "app.http-get.urls",
                    "http://alice.local/,http://nobody.local/",
                ),
                ("app.http-get.start", "3500ms"),
            ]),
        )
        .unwrap();
    for (dev, port) in [(alice, 1), (bob, 2)] {
        network
            .link(dev.port(0), sw.port(port))
            .unwrap()
            .latency(50 * US);
    }
    let ports = [alice.port(0), bob.port(0)];
    finish(network, None, seed, ports)
}

#[test]
fn a_name_is_claimed_and_resolved_with_multicast_dns() {
    let run = mdns(42);
    let log = transcript(&run.journal);

    // Nobody objected to the probes, so the name is announced.
    let announced = events(&run.journal, "alice", "mdns-announced");
    assert_eq!(announced.len(), 1, "{log}");
    assert_eq!(field(&announced[0], "name"), "alice.local");
    assert!(field(&announced[0], "addresses").contains("10.0.0.10"));

    // Bob's one-shot query is answered, and he fetches from the address in the answer.
    let answered = events(&run.journal, "alice", "mdns-answered");
    assert!(
        answered
            .iter()
            .any(|a| field(a, "mode") == "legacy-unicast"),
        "a querier on an ephemeral port gets a unicast answer\n{log}"
    );
    let resolved = events(&run.journal, "bob", "name-resolved");
    assert_eq!(resolved.len(), 1, "{log}");
    assert_eq!(field(&resolved[0], "name"), "alice.local");
    assert!(
        field(&resolved[0], "addresses").contains("10.0.0.10"),
        "{log}"
    );

    let done = events(&run.journal, "bob", "http-get-done");
    assert_eq!(done.len(), 1, "only alice.local was fetched\n{log}");
    assert_eq!(field(&done[0], "url"), "http://alice.local/");
    assert_eq!(field(&done[0], "status"), "200", "{log}");
    assert_eq!(field(&done[0], "body-bytes"), "5", "{log}");

    // A name nobody claims never resolves: mDNS has no negative answer.
    let failed = events(&run.journal, "bob", "name-lookup-failed");
    assert_eq!(failed.len(), 1, "{log}");
    assert_eq!(field(&failed[0], "name"), "nobody.local");
    let exit = events(&run.journal, "bob", "app-exit");
    assert_eq!(field(&exit[0], "status"), "error", "{log}");
}

#[test]
fn mdns_is_deterministic() {
    let (a, b) = (mdns(42), mdns(42));
    assert_eq!(
        a.pcaps, b.pcaps,
        "seed=42: the captures differ between runs"
    );
    assert_eq!(a.journal, b.journal, "seed=42: the journals differ");
}

/// `a` and `b`, two hosts whose responders both claim `alice` and start probing at the same
/// instant (the probe delay follows the name). Stops at 10 s.
fn same_name(seed: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "4")]))
        .unwrap();
    let mut host = |name: &str, n: u8| {
        network
            .device_with_config(
                name,
                &b.load("node-mdns-responder"),
                config(&[
                    ("mac", &format!("02:00:00:00:00:{n:02x}")),
                    ("ipv4", &format!("10.0.0.{n}/24")),
                    ("app.mdns-responder.hostname", "alice"),
                ]),
            )
            .unwrap()
    };
    let (a, h) = (host("a", 10), host("b", 20));
    for (dev, port) in [(a, 1), (h, 2)] {
        network
            .link(dev.port(0), sw.port(port))
            .unwrap()
            .latency(50 * US);
    }
    finish(network, Some(10_000 * MS), seed, [a.port(0), h.port(0)])
}

#[test]
fn two_hosts_probing_for_one_name_end_up_with_two_names() {
    // RFC 6762 §8.2: the simultaneous probes are a tiebreak. `a`'s address (10.0.0.10) sorts
    // before `b`'s, so `a` loses, waits, meets `b`'s announcement and renames once.
    let run = same_name(42);
    let log = transcript(&run.journal);
    let announced = |dev: &str| -> Vec<String> {
        events(&run.journal, dev, "mdns-announced")
            .iter()
            .map(|e| field(e, "name").to_owned())
            .collect()
    };
    assert_eq!(announced("b"), ["alice.local"], "{log}");
    assert_eq!(announced("a"), ["alice-2.local"], "{log}");
    assert!(
        !events(&run.journal, "a", "mdns-probe-lost").is_empty(),
        "{log}"
    );
    assert!(
        events(&run.journal, "b", "mdns-probe-lost").is_empty(),
        "{log}"
    );
    assert_eq!(events(&run.journal, "a", "mdns-renamed").len(), 1, "{log}");
    assert!(
        events(&run.journal, "b", "mdns-conflict").is_empty(),
        "{log}"
    );
}
