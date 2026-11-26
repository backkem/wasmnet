//! The disks on wasmtime, end to end, with the probe device
//! (`components/clock-probe/examples/disk_probe.rs`) and the typed adapter:
//!
//! - `p` keeps its state over stops and starts; an `on-sync` disk loses its unsynced tail at a
//!   stop, and an armed power loss keeps a seeded prefix and tears the next write; a crash inside
//!   a write keeps what the fault says; failed calls, corrupted values and a quota cut are seen
//!   by the device; a 16 MiB value goes through and back;
//! - `q` starts from images (one in its options, one loaded before the run) and hits its quota;
//! - `r` is a controller's device whose spec declares its disks: a recreation keeps them, a
//!   removal drops them, the device made again starts empty;
//! - `s` loses a disk;
//! - two seeds, and a rerun is byte-identical (journal and every disk's image); an exported
//!   image loads into another network to the same digest; a split network applies a device's
//!   faults on its own site and merges into the unsplit run.
//!
//! The probe and the controller fixture are built here (`cargo build --target wasm32-wasip2`).

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use wasmnet_det_cbor::Value as Cbor;
use wasmnet_disk::{DiskFault, DiskOp, DiskOptions, DiskSpec, Disks, Durability, Keep, image};
use wasmnet_host::sim::{ExtensionOp, Op, Placement};
use wasmnet_host::wasmtime::component::Component;
use wasmnet_host::{
    DeviceConfig, DeviceId, DeviceOptions, Host, JournalEntry, Nanos, Network, Record, sim,
};
use wasmnet_sites::{self as sites, Msg, SiteRecords, SiteSync, Step};

#[cfg(feature = "wasmtime")]
use wasmnet_disk::DiskAdapter;
#[cfg(not(feature = "wasmtime"))]
wasmnet_host::portable_adapter!({
    name: DiskAdapter,
    path: ["../../wit/deps/keyvalue", "../../wit/keyvalue-ext"],
    world: "wasmnet:keyvalue-ext/disk-user",
});

const MS: Nanos = 1_000_000;

struct World {
    host: Host,
    probe: Component,
    ctl: Component,
}

fn target() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from)
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let ok = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args(["build", "--release", "--target", "wasm32-wasip2"])
            .args(["-p", "wasmnet-clock-probe", "--example", "disk-probe"])
            .args(["-p", "wasmnet-infra-script"])
            .status()
            .expect("spawn cargo")
            .success();
        assert!(ok, "building the probe failed");
        let host = Host::builder()
            .extension(DiskAdapter)
            .build()
            .expect("host");
        let dir = target().join("wasm32-wasip2/release");
        let probe = host
            .load(dir.join("examples/disk_probe.wasm"))
            .expect("probe");
        let ctl = host
            .load(dir.join("infra_script.wasm"))
            .expect("infra-script");
        World { host, probe, ctl }
    })
}

fn config(pairs: &[(&str, &str)]) -> DeviceConfig {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn two_disks() -> DiskOptions {
    DiskOptions::new(vec![
        DiskSpec::new("state"),
        DiskSpec::new("log").durability(Durability::OnSync),
    ])
}

fn with_disks(d: DiskOptions) -> DeviceOptions {
    let mut o = DeviceOptions::default()
        .crash_alone(true)
        .fuel_per_instant(4_000_000_000);
    o.ext.set(d);
    o
}

fn u64_image(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let owned: Vec<(String, Vec<u8>)> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    image::of(&owned)
}

/// A controller's spec for the probe with its two disks, as CBOR hex.
fn spec(period: &str) -> String {
    let disk = |name: &str, durability: Option<&str>| {
        let mut m = vec![(Cbor::text("name"), Cbor::text(name))];
        if let Some(d) = durability {
            m.push((Cbor::text("durability"), Cbor::text(d)));
        }
        Cbor::Map(m)
    };
    Cbor::Map(vec![
        (Cbor::text("component"), Cbor::text("probe")),
        (
            Cbor::text("config"),
            Cbor::Map(vec![(Cbor::text("period"), Cbor::text(period))]),
        ),
        (
            Cbor::text("disk.specs"),
            Cbor::Array(vec![disk("state", None), disk("log", Some("on-sync"))]),
        ),
    ])
    .encode()
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect()
}

fn fault(net: &mut Network<'static>, at: Nanos, device: DeviceId, disk: &str, f: DiskFault) {
    net.add_op(
        Op::extension_at(device, ExtensionOp::new(DiskOp::new(disk, f))),
        Placement::StartOf(at),
    )
    .unwrap();
}

/// The scenario's network, before its run.
fn network(seed: u64) -> Network<'static> {
    let w = world();
    let mut net = Network::new(&w.host, seed);
    net.add_extension(Disks::default());
    net.set_component_resolver(Box::new(move |name, instantiate| match name {
        "probe" => instantiate(&w.probe),
        other => Err(sim::Error::Refused(format!("no component {other}"))),
    }));
    net.set_infra_catalog(vec!["probe".to_owned()]);

    let p = net
        .device_with_options(
            "p",
            &w.probe,
            config(&[("period", "10ms"), ("big", "16777216")]),
            with_disks(two_disks()),
        )
        .unwrap();
    for (at, op) in [
        (25, Op::stop_device("p")),
        (30, Op::start_device("p")),
        (75, Op::crash_device("p", "operator crash")),
        (78, Op::start_device("p")),
        (82, Op::start_device("p")),
        (106, Op::stop_device("p")),
        (107, Op::start_device("p")),
    ] {
        net.add_op(op, Placement::StartOf(at * MS)).unwrap();
    }
    fault(
        &mut net,
        35 * MS,
        p,
        "log",
        DiskFault::PowerLoss {
            keep: Keep::Prefix,
            tear: true,
        },
    );
    fault(
        &mut net,
        76 * MS,
        p,
        "state",
        DiskFault::CrashAt {
            call: 1,
            keep: Keep::All,
        },
    );
    fault(&mut net, 80 * MS, p, "state", DiskFault::Lose);
    fault(
        &mut net,
        95 * MS,
        p,
        "log",
        DiskFault::FailCalls {
            count: 1,
            text: "a bad sector".to_owned(),
        },
    );
    fault(
        &mut net,
        105 * MS,
        p,
        "state",
        DiskFault::Corrupt {
            prefix: "boots".to_owned(),
            how: wasmnet_disk::Corruption::FlipFirstByte,
        },
    );
    fault(&mut net, 110 * MS, p, "log", DiskFault::Quota(10));
    // The crash-at armed at 76 fires in the boot after the start at 78 (keeping its write); the
    // loss at 80 empties the state before the start at 82.

    // q: from images, and over its quota.
    let initial = u64_image(&[("boots", 41u64.to_le_bytes().to_vec())]);
    net.device_with_options(
        "q",
        &w.probe,
        config(&[("period", "1000ms"), ("fill", "8192")]),
        with_disks(DiskOptions::new(vec![
            DiskSpec::new("state").quota(4096).initial(initial),
            DiskSpec::new("log").durability(Durability::OnSync),
        ])),
    )
    .unwrap();
    let log = u64_image(&[
        ("e/00000001", vec![1; 64]),
        ("e/00000002", vec![2; 64]),
        ("last", 2u64.to_le_bytes().to_vec()),
    ]);
    net.extension::<Disks>()
        .unwrap()
        .load("q", "log", &log)
        .unwrap();

    // r: a controller's device whose spec declares its disks.
    let steps = [
        format!("0ms apply r {}", spec("10ms")),
        format!("45ms apply r {}", spec("20ms")),
        "70ms remove r".to_owned(),
        format!("80ms apply r {}", spec("10ms")),
    ];
    let cfg: Vec<(String, String)> = steps
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("step.{n}"), s.clone()))
        .collect();
    let cfg: Vec<(&str, &str)> = cfg.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    net.device_with_options(
        "ctl",
        &w.ctl,
        config(&cfg),
        DeviceOptions::default().infra(true),
    )
    .unwrap();

    // s: loses its state disk.
    let s = net
        .device_with_options(
            "s",
            &w.probe,
            config(&[("period", "10ms")]),
            with_disks(DiskOptions::new(vec![DiskSpec::new("state")])),
        )
        .unwrap();
    fault(&mut net, 15 * MS, s, "state", DiskFault::Lose);
    net.add_op(Op::stop_device("s"), Placement::StartOf(20 * MS))
        .unwrap();
    net.add_op(Op::start_device("s"), Placement::StartOf(21 * MS))
        .unwrap();
    net
}

fn lines(j: &[JournalEntry]) -> String {
    j.iter()
        .filter_map(|e| match &e.record {
            Record::Event { kind, fields }
                if kind.starts_with("disk-")
                    || kind.starts_with("kv-")
                    || kind.starts_with("device-") =>
            {
                let f: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
                Some(format!("{} {} {} {}", e.at, e.device, kind, f.join(" ")))
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn events(j: &[JournalEntry], device: &str, kind: &str) -> Vec<Vec<(String, String)>> {
    j.iter()
        .filter(|e| e.device == device)
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
        .unwrap_or_else(|| panic!("no field `{name}` in {fields:?}"))
}

/// Every disk's image, by device and name.
fn images(net: &Network<'_>) -> Vec<(String, String, Vec<u8>)> {
    let d = net.extension::<Disks>().unwrap();
    d.devices()
        .into_iter()
        .flat_map(|dev| {
            d.names(&dev)
                .into_iter()
                .map(move |n| (dev.clone(), n))
                .collect::<Vec<_>>()
        })
        .map(|(dev, n)| {
            let img = d.export_vec(&dev, &n).unwrap();
            (dev, n, img)
        })
        .collect()
}

const DEADLINE: Nanos = 130 * MS;

#[test]
fn disks_live_fault_and_replay_alike_at_two_seeds() {
    for seed in [42, 7] {
        let mut runs = Vec::new();
        for _ in 0..2 {
            let mut net = network(seed);
            net.run_until(DEADLINE)
                .unwrap_or_else(|e| panic!("{e}\n{}", lines(&net.journal())));
            let j = net.journal();
            let ctx = format!("seed {seed}\n{}", lines(&j));
            let boots = |dev: &str| -> Vec<String> {
                events(&j, dev, "kv-boot")
                    .iter()
                    .map(|f| field(f, "boots"))
                    .collect()
            };
            // p: its state over stops and starts, the crash inside a write keeping all of it,
            // the loss, then the corrupted count (1 XOR 0x5a).
            assert_eq!(boots("p"), ["0", "1", "2", "0", "91"], "{ctx}");
            let big = events(&j, "p", "kv-big");
            assert_eq!(field(&big[0], "size"), "16777216", "{ctx}");
            assert_eq!(
                field(&big[0], "tail"),
                "6d6e6f707172737475767778797a7b7c",
                "{ctx}"
            );
            // The log lost its two unsynced writes at the stop.
            let losses = events(&j, "p", "disk-power-loss");
            assert_eq!(field(&losses[0], "disk"), "log", "{ctx}");
            assert_eq!(field(&losses[0], "lost"), "2", "{ctx}");
            let first = events(&j, "p", "kv-boot");
            assert_eq!(field(&first[1], "entries"), "0", "{ctx}");
            assert_eq!(field(&first[1], "mode"), "Durability::OnSync", "{ctx}");
            // The crash inside a write, with the disk's own message.
            assert_eq!(events(&j, "p", "disk-crash").len(), 1, "{ctx}");
            let crashed: Vec<String> = events(&j, "p", "device-crashed")
                .iter()
                .map(|f| field(f, "message"))
                .collect();
            assert_eq!(
                crashed,
                ["operator crash", "disk `state` failed inside write 9"],
                "{ctx}"
            );
            // The failed call, and the quota cut.
            let errors: Vec<String> = events(&j, "p", "kv-error")
                .iter()
                .map(|f| field(f, "error"))
                .collect();
            assert!(errors.iter().any(|e| e.contains("a bad sector")), "{ctx}");
            assert!(errors.iter().any(|e| e.contains("Full")), "{ctx}");
            assert_eq!(events(&j, "p", "disk-corrupted").len(), 1, "{ctx}");
            // The standard functions.
            let check = &events(&j, "p", "kv-check")[0];
            assert_eq!(field(check, "keys"), "boots,m/a", "{ctx}");
            assert_eq!(field(check, "many"), "Ok(\"m/a=1,m/z=0\")", "{ctx}");
            assert_eq!(field(check, "exists"), "Ok(true)", "{ctx}");

            // q: from its images; its quota refuses the fill.
            assert_eq!(boots("q"), ["41"], "{ctx}");
            let qb = &events(&j, "q", "kv-boot")[0];
            assert_eq!(
                (field(qb, "entries"), field(qb, "last")),
                ("2".into(), "2".into()),
                "{ctx}"
            );
            let fill = field(&events(&j, "q", "kv-fill")[0], "answer");
            assert!(fill.starts_with("Err(Error::Full("), "{fill}\n{ctx}");
            assert_eq!(events(&j, "q", "disk-loaded").len(), 1, "{ctx}");

            // r: a recreation keeps its disks, a removal drops them.
            assert_eq!(boots("r"), ["0", "1", "0"], "{ctx}");
            assert_eq!(events(&j, "r", "disk-dropped").len(), 2, "{ctx}");
            assert_eq!(events(&j, "r", "disk-created").len(), 4, "{ctx}");

            // s: the loss.
            assert_eq!(boots("s"), ["0", "0"], "{ctx}");
            assert_eq!(events(&j, "s", "disk-lost").len(), 1, "{ctx}");

            runs.push((j, images(&net)));
        }
        assert!(runs[0] == runs[1], "seed {seed}: the rerun differs");
        // The power loss's seeded prefix and tear are journalled.
        let armed = events(&runs[0].0, "p", "disk-power-loss");
        assert!(armed.len() >= 2, "{}", lines(&runs[0].0));
    }
}

#[test]
fn an_exported_image_loads_into_another_network_alike() {
    let mut net = network(3);
    net.run_until(DEADLINE).unwrap();
    let disks = net.extension::<Disks>().unwrap();
    let img = disks.export_vec("p", "log").unwrap();
    let digest = disks.digest("p", "log").unwrap();
    assert_eq!(digest, sha2_digest(&img));
    let w = world();
    let mut other = Network::new(&w.host, 9);
    other.add_extension(Disks::default());
    other
        .device_with_options("x", &w.probe, config(&[]), with_disks(two_disks()))
        .unwrap();
    let d = other.extension::<Disks>().unwrap();
    d.load("x", "log", &img).unwrap();
    assert_eq!(d.digest("x", "log"), Some(digest));
    // A disk not declared, a bad image, one past the quota.
    assert!(d.load("x", "nope", &img).is_err());
    assert!(d.load("x", "log", b"wasmnet-disk/1\n").is_err());
    let mut small = Network::new(&w.host, 9);
    small.add_extension(Disks::default());
    small
        .device_with_options(
            "y",
            &w.probe,
            config(&[]),
            with_disks(DiskOptions::new(vec![DiskSpec::new("log").quota(100)])),
        )
        .unwrap();
    let err = small
        .extension::<Disks>()
        .unwrap()
        .load("y", "log", &img)
        .unwrap_err();
    assert!(err.contains("does not fit"), "{err}");
}

fn sha2_digest(b: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(b).into()
}

#[test]
fn declarations_are_checked() {
    let w = world();
    let mut net = Network::new(&w.host, 1);
    net.add_extension(Disks::default());
    let twice = DiskOptions::new(vec![DiskSpec::new("a"), DiskSpec::new("a")]);
    let e = net
        .device_with_options("x", &w.probe, config(&[]), with_disks(twice))
        .unwrap_err();
    assert!(e.to_string().contains("declared twice"), "{e}");
    let huge = DiskOptions::new(vec![DiskSpec::new("a").quota(u64::MAX)]);
    assert!(
        net.device_with_options("x", &w.probe, config(&[]), with_disks(huge))
            .is_err()
    );
    let bad = DiskOptions::new(vec![DiskSpec::new("a").initial(b"junk".to_vec())]);
    assert!(
        net.device_with_options("x", &w.probe, config(&[]), with_disks(bad))
            .is_err()
    );
    // From a generic value, as a spec or a page gives it.
    let v = sim::value::Value::List(vec![sim::value::Value::record(vec![
        ("name", sim::value::Value::str("a")),
        ("quota", sim::value::Value::U32(1 << 20)),
        ("durability", sim::value::Value::str("on-sync")),
    ])]);
    let mut options = DeviceOptions::default();
    net.set_option(&mut options, "disk.specs", &v).unwrap();
    assert_eq!(
        options.ext.get::<DiskOptions>(),
        Some(&DiskOptions::new(vec![
            DiskSpec::new("a")
                .quota(1 << 20)
                .durability(Durability::OnSync)
        ]))
    );
    assert!(
        net.parse_op(
            "disk.lose",
            &sim::value::Value::record(vec![("disk", sim::value::Value::str("a"))])
        )
        .is_ok()
    );
    assert!(net.parse_op("disk.lose", &sim::value::Value::None).is_err());
}

// ---- a split network ------------------------------------------------------------------------

const WAN: Nanos = MS;

/// `a` on site 0 and `b` on site 1, each with disks and faults of its own (the whole network
/// when `site` is `None`).
fn split_network(seed: u64, site: Option<usize>) -> Network<'static> {
    let w = world();
    let mut net = Network::new(&w.host, seed);
    net.add_extension(Disks::default());
    let mut ids = Vec::new();
    for (i, name) in ["a", "b"].into_iter().enumerate() {
        let options = with_disks(two_disks());
        let cfg = config(&[("period", "10ms")]);
        let id = if site.is_none_or(|s| s == i) {
            net.device_with_options(name, &w.probe, cfg, options)
                .unwrap()
        } else {
            net.remote_device_with(name, cfg, options).unwrap()
        };
        ids.push(id);
    }
    // A split network takes no stop or start: each device's disk crashes it instead, inside its
    // second or third write to the log, after an armed power loss; its state is lost first.
    for (i, id) in ids.iter().enumerate() {
        fault(&mut net, 5 * MS, *id, "state", DiskFault::Lose);
        let loss = DiskFault::PowerLoss {
            keep: Keep::Prefix,
            tear: true,
        };
        fault(&mut net, 15 * MS, *id, "log", loss);
        let crash = DiskFault::CrashAt {
            call: 2 + i as u64,
            keep: Keep::Prefix,
        };
        fault(&mut net, 16 * MS, *id, "log", crash);
    }
    net
}

fn carry(m: Msg) -> Msg {
    Msg::decode(&m.encode()).expect("a message decodes")
}

#[test]
fn a_split_network_applies_disk_faults_on_the_devices_site() {
    let deadline = 60 * MS;
    let mut whole = split_network(5, None);
    whole.run_until(deadline).unwrap();
    let mut nets: Vec<Network<'static>> = (0..2).map(|s| split_network(5, Some(s))).collect();
    let hellos: Vec<Msg> = nets.iter().map(|n| carry(sites::hello(n))).collect();
    for (s, n) in nets.iter_mut().enumerate() {
        sites::apply_hello(n, &hellos[1 - s]).unwrap();
    }
    let mut sync = [
        SiteSync::new(WAN, Some(deadline)),
        SiteSync::new(WAN, Some(deadline)),
    ];
    let mut inbox: [VecDeque<Msg>; 2] = Default::default();
    let (mut window, mut done) = ([true, true], [false, false]);
    while !(done[0] && done[1]) {
        let mut progress = false;
        for i in 0..2 {
            if done[i] {
                continue;
            }
            if window[i] {
                for m in sync[i].window(&mut nets[i]).unwrap() {
                    inbox[1 - i].push_back(carry(m));
                }
                window[i] = false;
                progress = true;
            }
            while let Some(m) = inbox[i].pop_front() {
                progress = true;
                match sync[i].handle(&mut nets[i], m).unwrap() {
                    Step::Wait => {}
                    Step::Window => {
                        window[i] = true;
                        break;
                    }
                    Step::Done { send_done } => {
                        if send_done {
                            inbox[1 - i].push_back(Msg::Done);
                        }
                        done[i] = true;
                        break;
                    }
                }
            }
        }
        assert!(progress, "the sites wait for each other");
    }
    let mut records = Vec::new();
    for i in 0..2 {
        let outcome = sync[i].finish(&mut nets[i]).unwrap();
        records.push(SiteRecords::collect(&nets[i], Ok(outcome)));
    }
    let merged = sites::merge(
        [&records[0], &records[1]],
        &["a".to_owned(), "b".to_owned()],
        Some(deadline),
    )
    .expect("the records merge");
    assert_eq!(lines(&merged.journal), lines(&whole.journal()));
    assert!(
        merged.journal == whole.journal(),
        "the merged journal differs"
    );
    assert!(lines(&merged.journal).contains("disk-power-loss"));
    // Each disk lives on its device's site, with the unsplit run's contents.
    for (i, dev) in ["a", "b"].into_iter().enumerate() {
        for disk in ["state", "log"] {
            let here = nets[i].extension::<Disks>().unwrap().digest(dev, disk);
            assert_eq!(
                here,
                whole.extension::<Disks>().unwrap().digest(dev, disk),
                "{dev} {disk}"
            );
            assert!(
                nets[1 - i]
                    .extension::<Disks>()
                    .unwrap()
                    .digest(dev, disk)
                    .is_none()
            );
        }
    }
}

#[test]
fn a_device_without_disks_is_told_no_such_store() {
    let w = world();
    let mut net = Network::new(&w.host, 1);
    net.add_extension(Disks::default());
    net.device_with_options(
        "x",
        &w.probe,
        config(&[]),
        DeviceOptions::default().crash_alone(true),
    )
    .unwrap();
    net.run_until(MS).unwrap();
    let j = net.journal();
    let errors = events(&j, "x", "kv-error");
    assert_eq!(field(&errors[0], "what"), "open state", "{}", lines(&j));
    assert_eq!(
        field(&errors[0], "error"),
        "Error::NoSuchStore",
        "{}",
        lines(&j)
    );
    assert!(
        events(&j, "x", "device-crashed").is_empty(),
        "{}",
        lines(&j)
    );
}

#[test]
fn supplied_components_with_disks_are_admitted_by_the_disk_patterns() {
    world();
    let bytes =
        std::fs::read(target().join("wasm32-wasip2/release/examples/disk_probe.wasm")).unwrap();
    let plain = sim::ImportPolicy::devices();
    let refused = plain.check(&bytes).unwrap_err();
    assert!(refused.contains("wasi:keyvalue/store"), "{refused}");
    plain.and(wasmnet_disk::IMPORTS).check(&bytes).unwrap();
}

// ---- the page test's scenario ---------------------------------------------------------------

/// The page test's disk scenario (`web/src/worker.ts`, `disks`), natively and in the same
/// generic forms the page uses (options and ops from values, a controller's spec, an image
/// loaded before the run): `p` through stops, starts, a crash and every fault, `q` from images
/// and over its quota, `r` a controller's device recreated, removed and made again. Writes the
/// lines and digests the page must match to `target/disk-native.txt` (the page test reads it
/// with `NATIVE_DISK`).
#[test]
fn page_scenario_native() {
    use sim::value::Value as V;
    let w = world();
    let mut net = Network::new(&w.host, 42);
    net.add_extension(Disks::default());
    net.set_component_resolver(Box::new(move |name, instantiate| match name {
        "disk_probe" => instantiate(&w.probe),
        other => Err(sim::Error::Refused(format!("no component {other}"))),
    }));
    net.set_infra_catalog(vec!["disk_probe".to_owned()]);
    let disk = |name: &str, extra: Vec<(&str, V)>| {
        let mut f = vec![("name", V::str(name))];
        f.extend(extra);
        V::record(f)
    };
    let options = |disks: Vec<V>| {
        let mut o = DeviceOptions::default().crash_alone(true);
        net.set_option(&mut o, "disk.specs", &V::List(disks))
            .unwrap();
        o
    };
    let two = options(vec![
        disk("state", vec![]),
        disk("log", vec![("durability", V::str("on-sync"))]),
    ]);
    let boots = u64_image(&[("boots", 41u64.to_le_bytes().to_vec())]);
    let small = options(vec![
        disk(
            "state",
            vec![("quota", V::U32(2048)), ("initial", V::Bytes(boots))],
        ),
        disk("log", vec![]),
    ]);
    let p = net
        .device_with_options(
            "p",
            &w.probe,
            config(&[("period", "10ms"), ("big", "1048576")]),
            two,
        )
        .unwrap();
    net.device_with_options(
        "q",
        &w.probe,
        config(&[("period", "1000ms"), ("fill", "4096")]),
        small,
    )
    .unwrap();
    let spec = |period: &str| {
        let disk = |name: &str, d: Option<&str>| {
            let mut m = vec![(Cbor::text("name"), Cbor::text(name))];
            if let Some(d) = d {
                m.push((Cbor::text("durability"), Cbor::text(d)));
            }
            Cbor::Map(m)
        };
        let bytes = Cbor::Map(vec![
            (Cbor::text("component"), Cbor::text("disk_probe")),
            (
                Cbor::text("config"),
                Cbor::Map(vec![(Cbor::text("period"), Cbor::text(period))]),
            ),
            (
                Cbor::text("disk.specs"),
                Cbor::Array(vec![disk("state", None), disk("log", Some("on-sync"))]),
            ),
        ])
        .encode();
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let steps = [
        ("step.0", format!("0ms apply r {}", spec("10ms"))),
        ("step.1", format!("45ms apply r {}", spec("20ms"))),
        ("step.2", "70ms remove r".to_owned()),
        ("step.3", format!("80ms apply r {}", spec("10ms"))),
    ];
    let cfg: Vec<(&str, &str)> = steps.iter().map(|(k, v)| (*k, v.as_str())).collect();
    net.device_with_options(
        "ctl",
        &w.ctl,
        config(&cfg),
        DeviceOptions::default().infra(true),
    )
    .unwrap();
    for (at, op) in [
        (25, Op::stop_device("p")),
        (30, Op::start_device("p")),
        (55, Op::crash_device("p", "operator crash")),
        (58, Op::start_device("p")),
        (62, Op::start_device("p")),
        (86, Op::stop_device("p")),
        (87, Op::start_device("p")),
    ] {
        net.add_op(op, Placement::StartOf(at * MS)).unwrap();
    }
    #[allow(clippy::type_complexity)]
    let faults: [(Nanos, &str, Vec<(&str, V)>); 6] = [
        (
            35,
            "disk.power-loss",
            vec![
                ("disk", V::str("log")),
                ("keep", V::str("prefix")),
                ("tear", V::Bool(true)),
            ],
        ),
        (
            56,
            "disk.crash-at",
            vec![
                ("disk", V::str("state")),
                ("call", V::U32(1)),
                ("keep", V::str("prefix")),
            ],
        ),
        (60, "disk.lose", vec![("disk", V::str("log"))]),
        (
            70,
            "disk.fail",
            vec![
                ("disk", V::str("log")),
                ("count", V::U32(1)),
                ("text", V::str("a bad sector")),
            ],
        ),
        (
            85,
            "disk.corrupt",
            vec![
                ("disk", V::str("state")),
                ("prefix", V::str("boots")),
                ("how", V::str("garbage")),
            ],
        ),
        (
            90,
            "disk.quota",
            vec![("disk", V::str("log")), ("bytes", V::U32(10))],
        ),
    ];
    for (at, kind, value) in faults {
        let op = net.parse_op(kind, &V::record(value)).unwrap();
        net.add_op(Op::extension_at(p, op), Placement::StartOf(at * MS))
            .unwrap();
    }
    let log = u64_image(&[
        ("e/00000001", vec![1; 64]),
        ("e/00000002", vec![2; 64]),
        ("last", 2u64.to_le_bytes().to_vec()),
    ]);
    net.extension::<Disks>()
        .unwrap()
        .load("q", "log", &log)
        .unwrap();
    net.run_until(100 * MS)
        .unwrap_or_else(|e| panic!("{e}\n{}", lines(&net.journal())));
    let mut text = lines(&net.journal());
    let d = net.extension::<Disks>().unwrap();
    for (dev, name) in [
        ("p", "state"),
        ("p", "log"),
        ("q", "state"),
        ("q", "log"),
        ("r", "state"),
        ("r", "log"),
    ] {
        let digest = d.digest(dev, name).map(|h| wasmnet_disk::digest_hex(&h));
        text.push_str(&format!(
            "\ndigest {dev} {name} {}",
            digest.unwrap_or_default()
        ));
    }
    text.push('\n');
    std::fs::write(target().join("disk-native.txt"), &text).unwrap();
    assert!(text.contains("p disk-crash"), "{text}");
    assert!(text.contains("q kv-fill answer=Err(Error::Full("), "{text}");
    assert!(text.contains("r disk-dropped"), "{text}");
}

/// What one `set` plus a 16-byte `get-range` costs on wasmtime through the typed adapter, by value
/// size: a boot with `reps` of them less a boot with one, over `reps - 1`. `--ignored --nocapture`.
#[test]
#[ignore = "a measurement"]
fn call_cost() {
    let w = world();
    let time = |size: usize, reps: u64| {
        let mut best = f64::MAX;
        for _ in 0..3 {
            let mut net = Network::new(&w.host, 1);
            net.add_extension(Disks::default());
            let cfg = config(&[
                ("period", "1000ms"),
                ("big", &size.to_string()),
                ("reps", &reps.to_string()),
            ]);
            let mut o = with_disks(DiskOptions::new(vec![
                DiskSpec::new("state").quota(1 << 30),
            ]));
            o = o.fuel_per_instant(400_000_000_000);
            net.device_with_options("p", &w.probe, cfg, o).unwrap();
            let t = std::time::Instant::now();
            net.run_until(MS).unwrap();
            best = best.min(t.elapsed().as_secs_f64());
        }
        best
    };
    for (size, reps) in [
        (64usize, 2001u64),
        (4096, 2001),
        (1 << 20, 41),
        (16 << 20, 9),
    ] {
        let per = (time(size, reps) - time(size, 1)) / (reps - 1) as f64;
        println!("set + get-range of {size} bytes: {:.1} us", per * 1e6);
    }
}
