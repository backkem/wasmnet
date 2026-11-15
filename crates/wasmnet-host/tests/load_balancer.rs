//! End to end: an HTTP load balancer in front of two backends.
//!
//! `http-get` (a client making a steady stream of requests) → `http-lb` → one of two
//! `http-server` backends, each answering with its own name in `X-Instance`. The balancer checks
//! every backend with a real `GET /healthz` and proxies each request over a new TCP connection.
//!
//! * With both backends healthy, round-robin spreads the requests evenly: they alternate.
//! * A backend whose health route still answers `503` is skipped, and every request goes to the
//!   other; once the route answers `200` the next health check puts it in rotation, and the
//!   requests spread again.
//! * The same seed gives the same bytes on every link.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config, events, field, transcript};
use wasmnet_host::{JournalEntry, Network, Record};

const US: u64 = 1_000;
const MS: u64 = 1_000_000;
const SECOND: u64 = 1_000 * MS;

struct Run {
    journal: Vec<JournalEntry>,
    pcaps: Vec<Vec<u8>>,
}

/// One switch with `lb` (10.0.1.2), `client` (10.0.1.3), `web-1` (10.0.1.11) and `web-2`
/// (10.0.1.12, ready after `web2_ready_after`). The client fetches `http://10.0.1.2/` 15 times,
/// 200 ms apart, from 500 ms; the run stops at `deadline` (health checks never go quiet).
fn balanced(seed: u64, web2_ready_after: &str, deadline: u64) -> Run {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "6")]))
        .unwrap();
    let lb = network
        .device_with_config(
            "lb",
            &b.load("node-http-lb"),
            config(&[
                ("mac", "02:00:00:00:01:02"),
                ("ipv4", "10.0.1.2/24"),
                ("app.http-lb.listen", "0.0.0.0:80"),
                ("app.http-lb.policy", "round-robin"),
                ("app.http-lb.health.path", "/healthz"),
                ("app.http-lb.health.interval", "1s"),
                ("app.http-lb.backend.web-1", "10.0.1.11:80"),
                ("app.http-lb.backend.web-2", "10.0.1.12:80"),
            ]),
        )
        .unwrap();
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:01:03"),
                ("ipv4", "10.0.1.3/24"),
                ("app.http-get.url", "http://10.0.1.2/"),
                ("app.http-get.start", "500ms"),
                ("app.http-get.interval", "200ms"),
                ("app.http-get.repeat", "15"),
                ("app.http-get.quiet", "true"),
            ]),
        )
        .unwrap();
    let mut backend = |name: &str, mac: &str, ip: &str, ready: &str| {
        network
            .device_with_config(
                name,
                &b.load("node-http-server"),
                config(&[
                    ("mac", mac),
                    ("ipv4", ip),
                    ("app.http-server.instance", name),
                    ("app.http-server.health", "/healthz"),
                    ("app.http-server.ready-after", ready),
                ]),
            )
            .unwrap()
    };
    let web1 = backend("web-1", "02:00:00:00:01:11", "10.0.1.11/24", "0");
    let web2 = backend(
        "web-2",
        "02:00:00:00:01:12",
        "10.0.1.12/24",
        web2_ready_after,
    );
    for (i, dev) in [lb, client, web1, web2].into_iter().enumerate() {
        network
            .link(dev.port(0), sw.port(i as u32))
            .unwrap()
            .latency(50 * US);
    }
    network
        .run_until(deadline)
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    Run {
        journal: network.journal(),
        pcaps: support::pcaps(&network),
    }
}

/// The backend each request was proxied to, with the virtual time it was forwarded, in order.
fn forwards(journal: &[JournalEntry]) -> Vec<(u64, String)> {
    journal
        .iter()
        .filter(|e| e.device == "lb")
        .filter_map(|e| match &e.record {
            Record::Event { kind, fields } if kind == "lb-forward" => {
                assert_eq!(field(fields, "result"), "ok", "a proxied request failed");
                assert_eq!(field(fields, "status"), "200");
                Some((e.at, field(fields, "backend").to_owned()))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn requests_alternate_between_healthy_backends() {
    let run = balanced(42, "0", 4 * SECOND);
    let log = transcript(&run.journal);

    let sent = forwards(&run.journal);
    assert_eq!(sent.len(), 15, "every request was proxied\n{log}");
    let backends: Vec<&str> = sent.iter().map(|(_, b)| b.as_str()).collect();
    let first = backends[0];
    for (i, b) in backends.iter().enumerate() {
        let expected = if i % 2 == 0 { first } else { other(first) };
        assert_eq!(*b, expected, "round-robin alternates (request {i})\n{log}");
    }

    // What the client saw agrees: each answer names the instance that served it.
    let done = events(&run.journal, "client", "http-get-done");
    assert_eq!(done.len(), 15, "{log}");
    assert!(done.iter().all(|d| field(d, "status") == "200"));
    for name in ["web-1", "web-2"] {
        let n = done.iter().filter(|d| field(d, "instance") == name).count();
        assert!((7..=8).contains(&n), "{name} served {n} of 15\n{log}");
    }
}

fn other(name: &str) -> &'static str {
    if name == "web-1" { "web-2" } else { "web-1" }
}

#[test]
fn a_backend_that_is_not_ready_is_skipped_until_it_is() {
    // web-2's health route answers 503 until 3 s; the requests run from 500 ms to 3.3 s.
    let run = balanced(42, "3s", 6 * SECOND);
    let log = transcript(&run.journal);

    let health: Vec<_> = run
        .journal
        .iter()
        .filter(|e| e.device == "lb")
        .filter_map(|e| match &e.record {
            Record::Event { kind, fields } if kind == "lb-health" => Some((
                e.at,
                field(fields, "backend").to_owned(),
                field(fields, "state").to_owned(),
            )),
            _ => None,
        })
        .collect();
    let up = |name: &str| {
        health
            .iter()
            .find(|(_, b, s)| b == name && s == "up")
            .map(|(at, ..)| *at)
    };
    assert!(
        up("web-1").unwrap() < 500 * MS,
        "web-1 is up at once\n{log}"
    );
    let web2_up = up("web-2").unwrap_or_else(|| panic!("web-2 never came up\n{log}"));
    assert!(
        web2_up >= 3 * SECOND,
        "web-2 is not in rotation before it is ready: {web2_up}\n{log}"
    );

    let sent = forwards(&run.journal);
    assert_eq!(sent.len(), 15, "{log}");
    let (before, after): (Vec<_>, Vec<_>) = sent.iter().partition(|(at, _)| *at < web2_up);
    assert!(
        !before.is_empty(),
        "requests ran while web-2 was not ready\n{log}"
    );
    assert!(
        before.iter().all(|(_, b)| b == "web-1"),
        "an unready backend got traffic: {before:?}\n{log}"
    );
    assert!(
        after.iter().any(|(_, b)| b == "web-2"),
        "web-2 serves again once it is up: {after:?}\n{log}"
    );
}

#[test]
fn the_same_seed_gives_the_same_bytes() {
    let (a, b) = (
        balanced(42, "3s", 6 * SECOND),
        balanced(42, "3s", 6 * SECOND),
    );
    assert_eq!(
        a.pcaps, b.pcaps,
        "seed=42: the captures differ between runs"
    );
    assert_eq!(a.journal, b.journal, "seed=42: the journals differ");
}
