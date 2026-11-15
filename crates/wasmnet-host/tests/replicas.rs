//! End to end: a replica controller keeps instances running and registered with a load balancer.
//!
//! `ctl` (`node-replicas`, granted `wasmnet:infra`) holds `replicas = 3`: it creates
//! `web-1` .. `web-3` from `node-http-server` through `wasmnet:infra`, cabled to the switch, and
//! registers each with `lb` (`node-http-lb`) over TCP with its **default** admin requests. A
//! client's requests through the load balancer then reach all three instances.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use support::{built, config, events, field, transcript};
use wasmnet_host::{DeviceOptions, JournalEntry, Network, sim};

const US: u64 = 1_000;
const MS: u64 = 1_000_000;
const SECOND: u64 = 1_000 * MS;

/// One switch: `lb` (10.0.1.2) on port 0, `client` (10.0.1.3) on 1, `ctl` (10.0.1.5) on 2, and
/// `web-<n>` (10.0.1.<n+10>) on port n + 2. The client fetches `http://10.0.1.2/` 12 times,
/// 100 ms apart, from 1.5 s.
fn controlled(seed: u64) -> Vec<JournalEntry> {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    // What a controller may create, and how the network finds it.
    let web = b.load("node-http-server");
    network.set_component_resolver(Box::new(move |name, instantiate| match name {
        "node:http-server" => instantiate(&web),
        other => Err(sim::Error::Refused(format!("no component {other}"))),
    }));
    network.set_infra_catalog(vec!["node:http-server".to_owned()]);

    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "8")]))
        .unwrap();
    let lb = network
        .device_with_config(
            "lb",
            &b.load("node-http-lb"),
            config(&[
                ("mac", "02:00:00:00:01:02"),
                ("ipv4", "10.0.1.2/24"),
                ("app.http-lb.listen", "0.0.0.0:80"),
                ("app.http-lb.admin", "0.0.0.0:8080"),
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
                ("app.http-get.start", "1500ms"),
                ("app.http-get.interval", "100ms"),
                ("app.http-get.repeat", "12"),
                ("app.http-get.quiet", "true"),
            ]),
        )
        .unwrap();
    let ctl = network
        .device_with_options(
            "ctl",
            &b.load("node-replicas"),
            config(&[
                ("mac", "02:00:00:00:01:05"),
                ("ipv4", "10.0.1.5/24"),
                ("app.replicas.replicas", "3"),
                ("app.replicas.period", "250ms"),
                ("app.replicas.template.component", "node:http-server"),
                ("app.replicas.template.config.mac", "02:00:00:00:01:{n+10}"),
                ("app.replicas.template.config.ipv4", "10.0.1.{n+10}/24"),
                (
                    "app.replicas.template.config.app.http-server.instance",
                    "{name}",
                ),
                (
                    "app.replicas.template.config.app.http-server.health",
                    "/healthz",
                ),
                ("app.replicas.template.wire.0.port", "0"),
                ("app.replicas.template.wire.0.to", "sw:{n+2}"),
                ("app.replicas.template.wire.0.latency", "50us"),
                // Registration with the defaults: no `register`, `register-body` or
                // `deregister`.
                ("app.replicas.lb", "10.0.1.2:8080"),
                ("app.replicas.backend", "10.0.1.{n+10}:80"),
            ]),
            DeviceOptions {
                infra: true,
                ..DeviceOptions::default()
            },
        )
        .unwrap();
    for (i, dev) in [lb, client, ctl].into_iter().enumerate() {
        network
            .link(dev.port(0), sw.port(i as u32))
            .unwrap()
            .latency(50 * US);
    }
    network
        .run_until(4 * SECOND)
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    network.journal()
}

#[test]
fn a_controller_keeps_its_instances_registered_with_the_load_balancer() {
    let journal = controlled(42);
    let log = transcript(&journal);

    // The controller registered each instance, and the load balancer said `201 Created`.
    let registered = events(&journal, "ctl", "replicas-registered");
    let mut names: Vec<&str> = registered.iter().map(|e| field(e, "name")).collect();
    names.sort_unstable();
    assert_eq!(names, ["web-1", "web-2", "web-3"], "{log}");
    assert!(
        registered.iter().all(|e| field(e, "status") == "201"),
        "every registration was accepted: {registered:?}\n{log}"
    );
    assert!(
        events(&journal, "ctl", "replicas-error").is_empty(),
        "{log}"
    );

    // The load balancer took them through its admin API, at their addresses.
    let lb: Vec<(String, String)> = events(&journal, "lb", "lb-registered")
        .iter()
        .map(|e| {
            assert_eq!(field(e, "via"), "admin");
            (field(e, "backend").to_owned(), field(e, "addr").to_owned())
        })
        .collect();
    let mut lb = lb;
    lb.sort();
    assert_eq!(
        lb,
        [
            ("web-1".to_owned(), "10.0.1.11:80".to_owned()),
            ("web-2".to_owned(), "10.0.1.12:80".to_owned()),
            ("web-3".to_owned(), "10.0.1.13:80".to_owned()),
        ],
        "{log}"
    );

    // Every request was proxied, and each instance served some of them.
    let done = events(&journal, "client", "http-get-done");
    assert_eq!(done.len(), 12, "{log}");
    assert!(done.iter().all(|d| field(d, "status") == "200"), "{log}");
    for name in ["web-1", "web-2", "web-3"] {
        let n = done.iter().filter(|d| field(d, "instance") == name).count();
        assert_eq!(
            n, 4,
            "round-robin over three: {name} served {n} of 12\n{log}"
        );
    }
}
