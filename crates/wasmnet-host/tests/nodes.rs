//! End to end: real nodes, a real switch, a real router, real TCP.
//!
//! `http-get` → `wasi:sockets` → netstack (smoltcp) → switch or router → netstack →
//! `http-server`, and back. The nodes are the composed components `cargo xtask build` makes
//! from `compositions/http-get.wac` and `compositions/http-server.wac`; the apps never learn
//! that the network is simulated.
//!
//! * A GET crosses a switch as ARP, a three-way handshake, `GET /` and `200 OK`.
//! * The same seed gives the same bytes on every link; another seed still works.
//! * A GET crosses a router between two subnets, and the hop costs one TTL.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`). Replay a failure with
//! `cargo test -p wasmnet-host --test nodes`; every message carries the journal.

mod support;

use support::{built, config, events, field, segments_from, transcript};
use wasmnet_host::{FrameRecord, JournalEntry, Network, Outcome, PortRef};

const US: u64 = 1_000;
/// What `http-server` answers on `/` when it has no routes.
const HELLO: &str = "hello from wasmnet\n";

struct Run {
    outcome: Outcome,
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcaps: Vec<Vec<u8>>,
    /// The client's and the server's own ports.
    client: PortRef,
    server: PortRef,
    dropped: u64,
}

/// `client` and `server` on one switch; the client fetches `http://web/` at t = 1 ms.
fn switched(seed: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "4")]))
        .unwrap();
    let server = network
        .device_with_config(
            "server",
            &b.load("node-http-server"),
            config(&[
                ("mac", "02:00:00:00:00:01"),
                ("ipv4", "10.0.0.1/24"),
                ("app.http-server.listen", "0.0.0.0:80"),
            ]),
        )
        .unwrap();
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:00:02"),
                ("ipv4", "10.0.0.2/24"),
                ("hosts.web", "10.0.0.1"),
                ("app.http-get.url", "http://web/"),
                ("app.http-get.start", "1ms"),
            ]),
        )
        .unwrap();
    network
        .link(server.port(0), sw.port(1))
        .unwrap()
        .latency(150 * US);
    network
        .link(client.port(0), sw.port(2))
        .unwrap()
        .latency(100 * US);
    let outcome = network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    Run {
        outcome,
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        client: client.port(0),
        server: server.port(0),
        dropped: support::dropped(&network, &[sw, server, client]),
    }
}

/// The one fetch the client made: it must have ended with `200` and the whole body.
fn assert_fetched(run: &Run, body: &str, ctx: &str) {
    let log = transcript(&run.journal);
    let done = events(&run.journal, "client", "http-get-done");
    assert_eq!(done.len(), 1, "{ctx}: one fetch\n{log}");
    assert_eq!(field(&done[0], "status"), "200", "{ctx}\n{log}");
    assert_eq!(
        field(&done[0], "body-bytes"),
        body.len().to_string(),
        "{ctx}\n{log}"
    );
    let exit = events(&run.journal, "client", "app-exit");
    assert_eq!(exit.len(), 1, "{ctx}: the client app returned\n{log}");
    assert_eq!(field(&exit[0], "app"), "http-get", "{ctx}");
    assert_eq!(field(&exit[0], "status"), "ok", "{ctx}\n{log}");
}

#[test]
fn a_get_crosses_the_switch_as_real_tcp() {
    let run = switched(42);
    assert_fetched(&run, HELLO, "seed=42");
    assert_eq!(run.dropped, 0, "a clean run drops nothing");

    // The server never returns: it is reported as a daemon, never as a deadlock.
    let Outcome::Quiescent { daemons, .. } = &run.outcome else {
        panic!("expected quiescence, got {:?}", run.outcome);
    };
    assert!(
        daemons.iter().any(|d| d.contains("app-http-server")),
        "{daemons:?}"
    );
    assert_eq!(events(&run.journal, "server", "http-listening").len(), 1);

    // On the wire, from the client: an ARP request, then exactly one SYN, then the request.
    let sent = support::sent_by(&run.frames, run.client);
    let arp = sent
        .iter()
        .position(|f| support::ethertype(&f.bytes) == Some(0x0806))
        .expect("the client asks for the server's MAC");
    let syn = sent
        .iter()
        .position(|f| support::segment(&f.bytes).is_some_and(|s| s.syn))
        .expect("the client sends a SYN");
    assert!(
        arp < syn,
        "ARP resolves the server before the SYN can leave"
    );
    let out = segments_from(&run.frames, run.client);
    assert_eq!(out.iter().filter(|s| s.syn && !s.ack).count(), 1);
    assert_eq!(
        out.iter()
            .filter(|s| s.payload.starts_with(b"GET / HTTP/1.1\r\n"))
            .count(),
        1
    );
    assert_eq!(out.iter().filter(|s| s.rst).count(), 0);

    // And back from the server: one SYN-ACK, the response, and a FIN.
    let back = segments_from(&run.frames, run.server);
    assert_eq!(back.iter().filter(|s| s.syn && s.ack).count(), 1);
    assert_eq!(
        back.iter()
            .filter(|s| s.payload.starts_with(b"HTTP/1.1 200 "))
            .count(),
        1
    );
    let body: Vec<u8> = back.iter().flat_map(|s| s.payload.clone()).collect();
    assert!(body.ends_with(HELLO.as_bytes()), "the body is on the wire");
    assert!(back.iter().any(|s| s.fin));
}

/// SHA-256 of each link's capture of [`switched`] at seed 42, in link order.
const PINNED_SEED42: [&str; 2] = [
    "958a7b85516ff0956aece478045837a318c8fa02d2a9582f9e0d9bace09bde74",
    "9448538a93988aeb8d6ec365ca87ba0e92053048b4d004d6a3a8f1fffb085ca6",
];

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn the_same_seed_gives_the_same_bytes() {
    let (a, b) = (switched(42), switched(42));
    assert_eq!(
        a.pcaps, b.pcaps,
        "seed=42: the captures differ between runs"
    );
    assert_eq!(a.journal, b.journal, "seed=42: the journals differ");
    assert_eq!(a.outcome, b.outcome);

    // The same bytes on every machine, not only twice here: the captures of a real GET through
    // the netstack are pinned, and CI runs this on more than one operating system.
    let hashes: Vec<String> = a.pcaps.iter().map(|p| sha256_hex(p)).collect();
    println!("seed=42 capture hashes: {hashes:?}");
    assert_eq!(
        hashes, PINNED_SEED42,
        "seed=42: the pinned capture hashes changed (a behaviour change on the wire: \n         update them only when that is intended)"
    );

    // Another seed moves what the seed feeds (initial sequence numbers, ephemeral ports),
    // never the result.
    let other = switched(7);
    assert_fetched(&other, HELLO, "seed=7");
    assert_ne!(a.pcaps, other.pcaps, "the seed reaches the wire");
}

#[test]
fn a_get_crosses_a_router_between_two_subnets() {
    let b = built();
    let mut network = Network::new(&b.host, 42);
    let router = network
        .device_with_config(
            "router",
            &b.load("router"),
            config(&[
                ("mac", "02:00:00:00:fe:00"),
                ("port0.ipv4", "10.0.1.1/24"),
                ("port1.ipv4", "10.0.2.1/24"),
            ]),
        )
        .unwrap();
    let server = network
        .device_with_config(
            "server",
            &b.load("node-http-server"),
            config(&[
                ("mac", "02:00:00:00:01:10"),
                ("ipv4", "10.0.1.10/24"),
                ("ipv4-gateway", "10.0.1.1"),
                ("app.http-server.route.index.path", "/"),
                ("app.http-server.route.index.body", "hello from subnet A\n"),
            ]),
        )
        .unwrap();
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:02:10"),
                ("ipv4", "10.0.2.10/24"),
                ("ipv4-gateway", "10.0.2.1"),
                ("app.http-get.url", "http://10.0.1.10/"),
                ("app.http-get.start", "1ms"),
            ]),
        )
        .unwrap();
    network
        .link(server.port(0), router.port(0))
        .unwrap()
        .latency(150 * US);
    network
        .link(client.port(0), router.port(1))
        .unwrap()
        .latency(100 * US);
    let outcome = network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("{e}\n{}", transcript(&network.journal())));
    let run = Run {
        outcome,
        journal: network.journal(),
        frames: network.frames(),
        pcaps: support::pcaps(&network),
        client: client.port(0),
        server: server.port(0),
        dropped: support::dropped(&network, &[router, server, client]),
    };
    assert_fetched(&run, "hello from subnet A\n", "routed");
    assert_eq!(run.dropped, 0);

    // The client's SYN leaves with the default TTL and reaches the server's subnet one lower.
    let syn = |port| {
        segments_from(&run.frames, port)
            .into_iter()
            .find(|s| s.syn && !s.ack)
            .expect("a SYN")
    };
    assert_eq!(syn(run.client).hop_limit, 64);
    assert_eq!(syn(router.port(0)).hop_limit, 63, "the router decrements");
}
