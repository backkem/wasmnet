//! End to end: a controller .any(|f| field(f, "message").contains("does not link")),etches a component over the network, supplies its bytes and runs
//! devices made from its digest (`docs/design/topology-and-infra.md`, "Components a controller
//! supplies").
//!
//! `store` (`node-http-server`) serves the bytes of built components as route bodies
//! (`body-base64`). `ctl` (`node-replicas`, granted `wasmnet:infra` and `infra_supply`) fetches
//! one with `template.fetch`, supplies it, and keeps two instances made from its digest. A client
//! then fetches from both. The `replicas` app is the controller because fetching needs a TCP
//! client in a node (the `infra-script` fixture is a stepped device with no ports), and two
//! replicas give the second device from the same digest for free.
//!
//! ```text
//!   store 10.0.0.9 ──┐
//!   ctl   10.0.0.5 ──┤
//!   cli   10.0.0.3 ──┼── sw
//!   web-1 10.0.0.11 ─┤        (made from sha256:<node-http-server>)
//!   web-2 10.0.0.12 ─┘
//! ```
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use sha2::{Digest as _, Sha256};
use support::{base64, built, config, events, field, transcript};
use wasmnet_host::sim::SupplyLimits;
use wasmnet_host::sim::infra::Phase;
use wasmnet_host::{DeviceConfig, DeviceOptions, ImportPolicy, JournalEntry, Network};

const US: u64 = 1_000;
const MS: u64 = 1_000_000;

/// `sha256:<hex>` of `bytes`.
fn reference(bytes: &[u8]) -> String {
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// The bytes of `<name>.wasm`, as `cargo xtask build` wrote it.
fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(built().path(name)).expect("a built component")
}

/// One way to run the network.
struct Case {
    /// The route `ctl` fetches (`/web.wasm`, `/infra.wasm`, `/app.wasm`).
    path: &'static str,
    /// What `ctl` states as the digest (`None`: the right one).
    digest: Option<String>,
    /// `ctl`'s grant to supply components.
    grant: bool,
    /// The admission's import policy.
    policy: ImportPolicy,
}

impl Case {
    fn good() -> Self {
        Self {
            path: "/web.wasm",
            digest: None,
            grant: true,
            policy: ImportPolicy::devices(),
        }
    }
}

/// A device in the table: its phase and message.
type Row = (Phase, Option<String>);

/// What a run gives.
struct Run {
    journal: Vec<JournalEntry>,
    /// Every link's capture.
    pcaps: Vec<Vec<u8>>,
    compiles: u64,
    /// `web-1` and `web-2` in the table: phase, component in the spec, message.
    table: Vec<(String, Option<Row>)>,
}

fn run(case: &Case, seed: u64) -> Run {
    let b = built();
    let web = bytes("node-http-server");
    let mut network = Network::new(&b.host, seed);
    network.set_supply_admission(case.policy.clone().admission());

    let sw = network
        .device_with_config("sw", &b.load("switch"), config(&[("ports", "8")]))
        .unwrap();
    // Decoding megabytes of base64 config costs more than the default fuel of one instant.
    let heavy = DeviceOptions {
        fuel_per_instant: Some(4_000_000_000),
        ..DeviceOptions::default()
    };
    let store = network
        .device_with_options(
            "store",
            &b.load("node-http-server"),
            [
                ("mac", "02:00:00:00:01:09".to_owned()),
                ("ipv4", "10.0.0.9/24".to_owned()),
                ("app.http-server.route.web.path", "/web.wasm".to_owned()),
                ("app.http-server.route.web.body-base64", base64(&web)),
                (
                    "app.http-server.route.web.type",
                    "application/wasm".to_owned(),
                ),
                ("app.http-server.route.infra.path", "/infra.wasm".to_owned()),
                (
                    "app.http-server.route.infra.body-base64",
                    base64(&bytes("node-replicas")),
                ),
                ("app.http-server.route.app.path", "/app.wasm".to_owned()),
                (
                    "app.http-server.route.app.body-base64",
                    base64(&bytes("http_server")),
                ),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<DeviceConfig>(),
            heavy,
        )
        .unwrap();
    let digest = case.digest.clone().unwrap_or_else(|| reference(&web));
    let options = DeviceOptions {
        infra: true,
        infra_supply: case.grant.then(SupplyLimits::default),
        ..DeviceOptions::default()
    };
    let ctl = network
        .device_with_options(
            "ctl",
            &b.load("node-replicas"),
            config(&[
                ("mac", "02:00:00:00:01:05"),
                ("ipv4", "10.0.0.5/24"),
                ("app.replicas.replicas", "2"),
                ("app.replicas.period", "200ms"),
                ("app.replicas.start", "10ms"),
                (
                    "app.replicas.template.fetch",
                    &format!("http://10.0.0.9{}", case.path),
                ),
                ("app.replicas.template.digest", &digest),
                ("app.replicas.template.config.mac", "02:00:00:00:01:{n+10}"),
                ("app.replicas.template.config.ipv4", "10.0.0.{n+10}/24"),
                (
                    "app.replicas.template.config.app.http-server.instance",
                    "{name}",
                ),
                ("app.replicas.template.wire.0.port", "0"),
                ("app.replicas.template.wire.0.to", "sw"),
                ("app.replicas.template.wire.0.latency", "100us"),
            ]),
            options,
        )
        .unwrap();
    let cli = network
        .device_with_config(
            "cli",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:01:03"),
                ("ipv4", "10.0.0.3/24"),
                ("app.http-get.urls", "http://10.0.0.11/,http://10.0.0.12/"),
                ("app.http-get.start", "1s"),
            ]),
        )
        .unwrap();
    for (port, d) in [(1, store), (2, ctl), (3, cli)] {
        network
            .link(d.port(0), sw.port(port))
            .unwrap()
            .latency(100 * US);
    }
    network.run_until(2_000 * MS).unwrap();
    let table = ["web-1", "web-2"]
        .into_iter()
        .map(|name| {
            let row = network.infra().get(name).ok().map(|d| {
                let spec = wasmnet_det_cbor::decode(&d.spec).expect("spec");
                let component = match spec {
                    wasmnet_det_cbor::Value::Map(m) => m
                        .into_iter()
                        .find(|(k, _)| k.as_text() == Some("component"))
                        .and_then(|(_, v)| v.as_text().map(str::to_owned)),
                    _ => None,
                };
                assert_eq!(component.as_deref(), Some(digest.as_str()), "{name}");
                (d.phase, d.message)
            });
            (name.to_owned(), row)
        })
        .collect();
    Run {
        journal: network.journal(),
        pcaps: support::pcaps(&network),
        compiles: network.supplied_compiles(),
        table,
    }
}

/// The `what`/`error` of every `replicas-error` of `ctl`.
fn errors(journal: &[JournalEntry]) -> Vec<String> {
    events(journal, "ctl", "replicas-error")
        .iter()
        .map(|f| format!("{}: {}", field(f, "what"), field(f, "error")))
        .collect()
}

#[test]
fn a_controller_runs_a_component_it_fetched_by_digest() {
    let web = bytes("node-http-server");
    let digest = reference(&web);
    for seed in [1, 2] {
        let r = run(&Case::good(), seed);
        let j = &r.journal;
        let t = || transcript(j);
        // Fetched over the network, supplied once, journalled by digest and size only.
        let supplied = events(j, "ctl", "infra-supply");
        assert_eq!(supplied.len(), 1, "{}", t());
        assert_eq!(field(&supplied[0], "digest"), digest);
        assert_eq!(field(&supplied[0], "size"), web.len().to_string());
        assert_eq!(events(j, "ctl", "replicas-supplied").len(), 1, "{}", t());
        assert!(errors(j).is_empty(), "{:?}", errors(j));
        // Two devices from one digest, compiled once.
        assert_eq!(r.compiles, 1);
        for (name, row) in &r.table {
            assert_eq!(row, &Some((Phase::Running, None)), "{name}\n{}", t());
            let added = events(j, name, "device-added");
            assert_eq!(field(&added[0], "component"), digest);
        }
        // Both serve traffic.
        let done = events(j, "cli", "http-get-done");
        assert_eq!(done.len(), 2, "{}", t());
        for (d, instance) in done.iter().zip(["web-1", "web-2"]) {
            assert_eq!(field(d, "status"), "200");
            assert_eq!(field(d, "instance"), instance);
        }
        // The bytes are never journalled (a line can hold no 1.4 MB).
        assert!(j.iter().all(|e| format!("{:?}", e.record).len() < 4096));
        // Byte-identical on rerun.
        let again = run(&Case::good(), seed);
        assert_eq!(transcript(&again.journal), transcript(j));
        assert_eq!(again.pcaps, r.pcaps);
    }
}

#[test]
fn a_wrong_digest_is_refused() {
    let r = run(
        &Case {
            digest: Some(reference(b"other bytes")),
            ..Case::good()
        },
        1,
    );
    let errors = errors(&r.journal);
    assert!(
        errors.iter().any(|e| e.contains("digest mismatch")),
        "{errors:?}"
    );
    assert!(events(&r.journal, "ctl", "infra-supply").is_empty());
    assert!(r.table.iter().all(|(_, row)| row.is_none()));
    assert_eq!(r.compiles, 0);
}

#[test]
fn the_admission_refuses_what_its_policy_does_not_allow() {
    // The controller node itself imports `wasmnet:infra`: not on the devices' list.
    let r = run(
        &Case {
            path: "/infra.wasm",
            digest: Some(reference(&bytes("node-replicas"))),
            ..Case::good()
        },
        1,
    );
    let errors = errors(&r.journal);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("Denied") && e.contains("wasmnet:infra/")),
        "{errors:?}"
    );
    assert!(events(&r.journal, "ctl", "infra-supply").is_empty());
    assert!(r.table.iter().all(|(_, row)| row.is_none()));
}

#[test]
fn a_controller_without_the_grant_is_denied() {
    let r = run(
        &Case {
            grant: false,
            ..Case::good()
        },
        1,
    );
    let errors = errors(&r.journal);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("Denied") && e.contains("infra_supply")),
        "{errors:?}"
    );
    assert!(r.table.iter().all(|(_, row)| row.is_none()));
}

#[test]
fn a_component_that_imports_what_the_host_does_not_serve_fails_its_creation() {
    // A bare app imports `wasi:sockets` and `wasmnet:sockets-ext`, which only a netstack serves;
    // a policy that lets them through leaves the host's own check, when it compiles the
    // component.
    let app = bytes("http_server");
    let r = run(
        &Case {
            path: "/app.wasm",
            digest: Some(reference(&app)),
            policy: ImportPolicy::devices().and(["wasi:sockets/*", "wasmnet:sockets-ext/*"]),
            ..Case::good()
        },
        1,
    );
    let j = &r.journal;
    assert_eq!(
        events(j, "ctl", "infra-supply").len(),
        1,
        "{}",
        transcript(j)
    );
    for (name, row) in &r.table {
        let (phase, message) = row.clone().expect("in the table");
        assert_eq!(phase, Phase::Failed, "{name}");
        let message = message.expect("why");
        assert!(message.contains("does not link"), "{message}");
        assert!(message.contains("sockets"), "{message}");
    }
    assert!(
        events(j, "ctl", "infra-failed")
            .iter()
            .any(|f| field(f, "message").contains("wasi:sockets")),
        "{}",
        transcript(j)
    );
    // The failed compile is kept with the bytes: two creations, one compile.
    assert_eq!(r.compiles, 1);
}
