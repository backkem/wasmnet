//! The `async-device` path inside a network: a stepped blaster talks to an async reflector
//! whose `start()` spawns a task that echoes each frame after a virtual `wasi:clocks@0.3`
//! `wait-for`. Guest timers, frame deliveries and poll deadlines share one event queue, so
//! every echo arrives at exactly `send + 2L + delay`.
//!
//! The async reflector is the `reflector` crate built with `--features async-device` into its
//! own target dir (`target/async-device`), so it never clobbers the stepped-device build.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use wasmnet_host::pcap;
use wasmnet_host::{DeviceConfig, Guard, Host, Network, Outcome, Record, SimConfig};
use wasmnet_wire::{Direction, MacAddr};
use wasmtime::component::Component;

/// Must match `COUNT`/`INTERVAL_NS` (blaster) and `ASYNC_DELAY_NS` (reflector).
const COUNT: u64 = 8;
const INTERVAL: u64 = 1_000_000;
const DELAY: u64 = 50_000;
const LATENCY: u64 = 250_000;

struct Guests {
    host: Host,
    blaster: Component,
    async_reflector: Component,
}

fn cargo_build(root: &Path, args: &[&str]) {
    let status = Command::new(env!("CARGO"))
        .current_dir(root)
        .args(["build", "--release", "--target", "wasm32-wasip2"])
        .args(args)
        .status()
        .expect("spawn cargo");
    assert!(status.success(), "cargo build {args:?} failed");
}

fn guests() -> &'static Guests {
    static GUESTS: OnceLock<Guests> = OnceLock::new();
    GUESTS.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target"));
        let async_dir = target.join("async-device");
        cargo_build(&root, &["-p", "wasmnet-blaster"]);
        let async_dir_arg = async_dir.to_str().expect("UTF-8 target dir");
        cargo_build(
            &root,
            &[
                "-p",
                "wasmnet-reflector",
                "--features",
                "async-device",
                "--target-dir",
                async_dir_arg,
            ],
        );
        let host = Host::new().expect("host");
        let blaster = host
            .load(target.join("wasm32-wasip2/release/blaster.wasm"))
            .expect("blaster.wasm");
        let async_reflector = host
            .load(async_dir.join("wasm32-wasip2/release/reflector.wasm"))
            .expect("async reflector.wasm");
        Guests {
            host,
            blaster,
            async_reflector,
        }
    })
}

#[test]
fn async_reflector_echoes_after_a_virtual_wait() {
    let g = guests();
    let mut runs = Vec::new();
    for _ in 0..2 {
        let guard = Guard::default().paranoid(true);
        let mut network = Network::with_config(&g.host, SimConfig::seeded(42), guard);
        let a = network.device("blaster", &g.blaster).unwrap();
        let b = network.device("reflector", &g.async_reflector).unwrap();
        let link = network
            .link(a.port(0), b.port(0))
            .unwrap()
            .latency(LATENCY)
            .id();
        let outcome = network
            .run_until_quiescent()
            .expect("seed=42 async network");
        // The echo task is still parked waiting for frames; nothing the host awaits is owed.
        assert_eq!(
            outcome,
            Outcome::quiescent(
                (COUNT - 1) * INTERVAL + 2 * LATENCY + DELAY,
                vec!["reflector".to_owned()],
                vec![]
            )
        );
        let log: String = network
            .journal()
            .into_iter()
            .filter(|e| e.device == "blaster")
            .filter_map(|e| match e.record {
                Record::Log { message, .. } => Some(format!(
                    "t={} {message}
",
                    e.at
                )),
                _ => None,
            })
            .collect();
        for i in 0..COUNT {
            let rtt = 2 * LATENCY + DELAY;
            let line = format!("t={} echo seq={i} rtt={rtt}ns", i * INTERVAL + rtt);
            assert!(log.contains(&line), "missing `{line}` in\n{log}");
        }
        let cap = pcap::parse(&network.pcap(link)).unwrap();
        // At the reflector's NIC, each echo leaves exactly DELAY after its probe arrived.
        for p in cap.packets.iter().filter(|p| p.interface == 1) {
            let seq = u64::from(u32::from_be_bytes(p.data[22..26].try_into().unwrap()));
            let expected = seq * INTERVAL
                + LATENCY
                + if p.direction == Some(Direction::Outbound) {
                    DELAY
                } else {
                    0
                };
            assert_eq!(p.timestamp, expected, "{p:?}");
        }
        println!("{outcome:?} {:?}\n{log}", network.stats());
        runs.push(network.pcap(link));
    }
    assert_eq!(runs[0], runs[1], "seed=42: async replay diverged");
}

#[test]
fn async_reflector_uses_its_configured_mac() {
    let g = guests();
    let mut network = Network::new(&g.host, 42);
    let config = DeviceConfig::from([("mac".to_owned(), "02:00:00:00:00:2a".to_owned())]);
    let b = network
        .device_with_config("reflector", &g.async_reflector, config)
        .unwrap();
    assert_eq!(
        network.ports(b)[0].mac,
        Some(MacAddr::new([2, 0, 0, 0, 0, 0x2a]))
    );
}
