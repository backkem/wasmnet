//! "Keep your own WIT, put an adapter in front": a device that keeps its data through a contract
//! of its own (`wit/test-store`: records under byte keys, objects by a 32-byte hash), composed
//! with the adapter component (`components/store-adapter`) that serves that contract over its
//! disks. The device never names the disk; the composed device runs as any other, at two seeds,
//! with byte-identical reruns, and its keys keep their byte order on the disk.
//!
//! `adapter_cost` (ignored; `--ignored --nocapture`) prints what a write costs through the adapter
//! against the same write straight to the disk, by value size.
//!
//! Needs `wac` on `PATH`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

use wasmnet_disk::{DiskOptions, DiskSpec, Disks};
use wasmnet_host::sim::{Op, Placement};
use wasmnet_host::wasmtime::component::Component;
use wasmnet_host::{DeviceConfig, DeviceOptions, Host, JournalEntry, Nanos, Network, Record};

#[cfg(feature = "wasmtime")]
use wasmnet_disk::DiskAdapter;
#[cfg(not(feature = "wasmtime"))]
wasmnet_host::portable_adapter!({
    name: DiskAdapter,
    path: ["../../wit/deps/keyvalue", "../../wit/keyvalue-ext"],
    world: "wasmnet:keyvalue-ext/disk-user",
});

const MS: Nanos = 1_000_000;

fn target() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from)
}

struct World {
    host: Host,
    device: Component,
}

/// The probe and the adapter, built and composed once.
fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let ok = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args(["build", "--release", "--target", "wasm32-wasip2"])
            .args(["-p", "wasmnet-clock-probe", "--example", "store-probe"])
            .args(["-p", "wasmnet-store-adapter"])
            .status()
            .expect("spawn cargo")
            .success();
        assert!(ok, "building the probe and the adapter failed");
        let dir = target().join("wasm32-wasip2/release");
        let out = dir.join("store_probe_composed.wasm");
        let ok = Command::new("wac")
            .arg("plug")
            .arg(dir.join("examples/store_probe.wasm"))
            .arg("--plug")
            .arg(dir.join("store_adapter.wasm"))
            .arg("-o")
            .arg(&out)
            .status()
            .expect("spawn wac (it must be on PATH)")
            .success();
        assert!(ok, "wac plug failed");
        let host = Host::builder()
            .extension(DiskAdapter)
            .build()
            .expect("host");
        let device = host.load(&out).expect("the composed device");
        World { host, device }
    })
}

fn config(pairs: &[(&str, &str)]) -> DeviceConfig {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn options() -> DeviceOptions {
    let mut o = DeviceOptions::default()
        .crash_alone(true)
        .fuel_per_instant(40_000_000_000);
    o.ext.set(DiskOptions::new(vec![
        DiskSpec::new("state"),
        DiskSpec::new("objects").quota(512 << 20),
    ]));
    o
}

fn events(j: &[JournalEntry], kind: &str) -> Vec<Vec<(String, String)>> {
    j.iter()
        .filter_map(|e| match &e.record {
            Record::Event { kind: k, fields } if k == kind => Some(fields.clone()),
            _ => None,
        })
        .collect()
}

fn field(fields: &[(String, String)], name: &str) -> String {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| panic!("no `{name}` in {fields:?}"))
}

fn run(seed: u64) -> (Vec<JournalEntry>, Vec<u8>, Vec<String>) {
    let w = world();
    let mut net = Network::new(&w.host, seed);
    net.add_extension(Disks::default());
    net.device_with_options("s", &w.device, config(&[]), options())
        .unwrap();
    net.add_op(Op::stop_device("s"), Placement::StartOf(5 * MS))
        .unwrap();
    net.add_op(Op::start_device("s"), Placement::StartOf(6 * MS))
        .unwrap();
    net.run_until(10 * MS).unwrap();
    let d = net.extension::<Disks>().unwrap();
    let image = d.export_vec("s", "state").unwrap();
    let keys = d
        .read("s", "state", |r| {
            r.iter("").map(|(k, _)| k.to_owned()).collect()
        })
        .unwrap();
    (net.journal(), image, keys)
}

#[test]
fn a_device_keeps_its_own_contract_through_the_adapter() {
    for seed in [42, 7] {
        let (j, image, keys) = run(seed);
        let boots: Vec<String> = events(&j, "store-boot")
            .iter()
            .map(|f| field(f, "boots"))
            .collect();
        assert_eq!(boots, ["0", "1"], "{j:?}");
        assert!(events(&j, "store-error").is_empty(), "{j:?}");
        // Byte order on the disk: the prefix 01 scans 01, 0102, 01ff.
        let scan = &events(&j, "store-scan")[0];
        assert_eq!(field(scan, "keys"), "01,0102,01ff");
        let objects = &events(&j, "store-objects")[0];
        assert_eq!(field(objects, "held"), "1111:1024,eeee:65536");
        assert_eq!(field(objects, "after"), "eeee:65536");
        assert_eq!(field(objects, "tail"), "1112131415161718");
        // The disk's string keys sort as the device's byte keys do.
        let bytes: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| k.chars().map(|c| u8::try_from(c).unwrap()).collect())
            .collect();
        let mut sorted = bytes.clone();
        sorted.sort();
        assert_eq!(bytes, sorted);
        let (j2, image2, _) = run(seed);
        assert!(j == j2 && image == image2, "seed {seed}: the rerun differs");
    }
}

/// Wall time per write, through the adapter and straight to the disk, by value size.
#[test]
#[ignore = "a measurement: --ignored --nocapture"]
fn adapter_cost() {
    let w = world();
    for (size, reps) in [
        (64usize, 2000u64),
        (4096, 2000),
        (1 << 20, 40),
        (16 << 20, 8),
    ] {
        let mut per = Vec::new();
        for via in ["adapter", "direct"] {
            let mut best = f64::MAX;
            for _ in 0..3 {
                let mut net = Network::new(&w.host, 1);
                net.add_extension(Disks::default().total(1 << 30));
                let cfg = config(&[
                    ("big", "8"),
                    ("reps", &reps.to_string()),
                    ("size", &size.to_string()),
                    ("via", via),
                ]);
                let mut opts = options();
                opts.ext.set(DiskOptions::new(vec![
                    DiskSpec::new("state"),
                    DiskSpec::new("objects").quota(1 << 30),
                ]));
                net.device_with_options("s", &w.device, cfg, opts).unwrap();
                let t = Instant::now();
                net.run_until(MS).unwrap();
                best = best.min(t.elapsed().as_secs_f64() * 1e6 / reps as f64);
                let j = net.journal();
                assert_eq!(events(&j, "store-bench").len(), 1, "{j:?}");
            }
            per.push(best);
        }
        println!(
            "a write of {size} bytes: through the adapter {:.1} us, straight to the disk {:.1} us",
            per[0], per[1]
        );
    }
}
