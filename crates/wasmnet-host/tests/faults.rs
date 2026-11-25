//! Faults an embedder can inject, end to end with real components:
//!
//! - a node paused in the middle of a TCP transfer: the peer retransmits into silence, the node
//!   wakes with its clocks jumped and its timers overdue, and the transfer completes;
//! - a crash at a chosen import call: a host extension (`Disks`, below) traps the n-th disk
//!   write of a device, which crashes alone when it may (a device a controller created, or one
//!   with `crash_alone`) and fails the network otherwise;
//! - an operator's crash told apart from an operator's stop, as the controller sees them;
//! - a network extension hearing a device's life (stop, start, crash, remove, pause, resume)
//!   right after the network's journal records;
//! - an embedder action that wipes a device's disk at an exact place among an instant's events.
//!
//! `Disks` is also the worked example of the extension points
//! (`docs/design/runtime-and-extensions.md`): a host extension serves a test-only
//! `wasmnet-test:disk/disk` import, and a network extension keeps one disk per device name,
//! outside the device's store, so a disk outlives a stop or a crash and goes with a removal.
//! `disk-device` (`components/clock-probe/examples/disk_device.rs`) is the device that uses it.
//!
//! Every network runs at two seeds, and a rerun is byte-identical.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use support::{built, config, events, field, transcript};
use wasmnet_det_cbor::Value;
use wasmnet_host::sim::ext::{DeviceExt, DeviceLife, DeviceSetup, LifeEvent, NetworkExtension};
use wasmnet_host::sim::infra::Phase;
use wasmnet_host::sim::{DeviceContext, DevicePhase, Op, OpState, Placement};
use wasmnet_host::wasmtime::component::{Component, HasData, Linker};
use wasmnet_host::{
    DeviceConfig, DeviceOptions, Error, FrameRecord, Host, HostExtension, HostState, JournalEntry,
    Nanos, Network, Record, sim,
};

const MS: Nanos = 1_000_000;
const US: Nanos = 1_000;

// ---- the disk extension ------------------------------------------------------------------

mod bindings {
    wasmnet_host::wasmtime::component::bindgen!({
        inline: r#"
            package wasmnet-test:disk@0.1.0;
            interface disk {
                read: func(block: u32) -> option<list<u8>>;
                write: func(block: u32, data: list<u8>);
            }
            world disk-host {
                import disk;
            }
        "#,
        world: "wasmnet-test:disk/disk-host",
        imports: { default: trappable },
    });
}

use bindings::wasmnet_test::disk::disk;

/// One device's disk: its blocks, and how many writes it took.
#[derive(Debug, Default)]
struct Disk {
    blocks: BTreeMap<u32, Vec<u8>>,
    writes: u64,
    /// The write that traps (a failing disk), counted from the disk's creation.
    fail_at: Option<u64>,
}

/// The handle a device's store holds: the disk lives in the network extension, so it outlives
/// the store (a stop, a crash) and goes when the network says the device is gone.
#[derive(Clone, Debug, Default)]
struct DiskHandle(Arc<Mutex<Disk>>);

/// The network extension: one disk per device name, the writes that fail, and what it heard.
#[derive(Default)]
struct Disks {
    disks: BTreeMap<String, DiskHandle>,
    /// Device name -> the write of its disk that traps.
    fail: BTreeMap<String, u64>,
    heard: Vec<String>,
}

impl Disks {
    /// Empties the disk of `name` (an embedder action's work).
    fn wipe(&mut self, name: &str) -> bool {
        match self.disks.get(name) {
            Some(d) => {
                d.0.lock().unwrap().blocks.clear();
                true
            }
            None => false,
        }
    }
}

impl NetworkExtension for Disks {
    /// Every device gets the disk of its name, a new one the first time.
    fn device_setup(&mut self, setup: &DeviceSetup<'_>, ext: &mut DeviceExt) {
        let disk = self.disks.entry(setup.name.to_owned()).or_default();
        disk.0.lock().unwrap().fail_at = self.fail.get(setup.name).copied();
        ext.insert(disk.clone());
    }

    /// A removal is the end of the device: its disk goes. Everything is journalled after the
    /// network's own record.
    fn device_life(&mut self, life: &DeviceLife<'_>) {
        let what = match life.event {
            LifeEvent::Paused => "paused",
            LifeEvent::Resumed => "resumed",
            LifeEvent::Stopped => "stopped",
            LifeEvent::Started => "started",
            LifeEvent::Crashed { .. } => "crashed",
            LifeEvent::Removed => {
                self.disks.remove(life.name);
                "removed"
            }
            _ => "other",
        };
        life.journal.push(
            life.at,
            Record::Event {
                kind: "disk-life".into(),
                fields: vec![("event".into(), what.into())],
            },
        );
        self.heard
            .push(format!("{}@{} {what}", life.name, life.at / MS));
    }
}

/// What the store's host functions reach: the device's disk, if the network gave it one.
#[derive(Default)]
struct DiskSlot(Option<DiskHandle>);

impl DiskSlot {
    fn disk(&self) -> wasmnet_host::wasmtime::Result<&DiskHandle> {
        self.0
            .as_ref()
            .ok_or_else(|| wasmnet_host::wasmtime::format_err!("no disk for this device"))
    }
}

impl disk::Host for DiskSlot {
    fn read(&mut self, block: u32) -> wasmnet_host::wasmtime::Result<Option<Vec<u8>>> {
        Ok(self.disk()?.0.lock().unwrap().blocks.get(&block).cloned())
    }

    /// Traps on the disk's `fail_at`-th write: the device crashes inside this import call.
    fn write(&mut self, block: u32, data: Vec<u8>) -> wasmnet_host::wasmtime::Result<()> {
        let mut d = self.disk()?.0.lock().unwrap();
        d.writes += 1;
        if d.fail_at == Some(d.writes) {
            return Err(wasmnet_host::wasmtime::format_err!(
                "disk write {} failed",
                d.writes
            ));
        }
        d.blocks.insert(block, data);
        Ok(())
    }
}

struct DiskData;

impl HasData for DiskData {
    type Data<'a> = &'a mut DiskSlot;
}

/// The host extension: links the import, gives each store its slot, copies the network
/// extension's handle into it, and registers the network extension on every network.
struct DiskHost;

impl HostExtension for DiskHost {
    fn name(&self) -> &str {
        "wasmnet-test:disk/disk"
    }

    fn add_to_linker(&self, linker: &mut Linker<HostState>) -> wasmnet_host::wasmtime::Result<()> {
        disk::add_to_linker::<HostState, DiskData>(linker, |s| {
            s.extension_mut::<DiskSlot>()
                .expect("DiskHost::init_store ran for this store")
        })
    }

    fn init_store(&self, state: &mut HostState) -> wasmnet_host::wasmtime::Result<()> {
        state.insert_extension(DiskSlot::default());
        Ok(())
    }

    fn init_device(
        &self,
        state: &mut HostState,
        device: &DeviceContext,
    ) -> wasmnet_host::wasmtime::Result<()> {
        if let Some(disk) = device.ext.get::<DiskHandle>() {
            state.insert_extension(DiskSlot(Some(disk.clone())));
        }
        Ok(())
    }

    fn install(&self, network: &mut Network<'_>) {
        network.add_extension(Disks::default());
    }
}

/// A host with the disk extension, and the disk device loaded on it.
struct DiskWorld {
    host: Host,
    device: Component,
}

fn disk_world() -> &'static DiskWorld {
    static WORLD: OnceLock<DiskWorld> = OnceLock::new();
    WORLD.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let status = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args(["build", "--release", "--target", "wasm32-wasip2"])
            .args(["-p", "wasmnet-clock-probe", "--example", "disk-device"])
            .status()
            .expect("spawn cargo to build disk-device");
        assert!(status.success(), "building disk-device failed");
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target"));
        let host = Host::new()
            .expect("host")
            .with_extension(DiskHost)
            .expect("link the disk");
        let device = host
            .load(target.join("wasm32-wasip2/release/examples/disk_device.wasm"))
            .expect("disk-device");
        DiskWorld { host, device }
    })
}

/// A network on the disk host whose writes fail as `fail` says, with `disk` in its catalog
/// (for operator events and controllers).
fn disk_network(seed: u64, fail: &[(&str, u64)]) -> Network<'static> {
    let w = disk_world();
    let mut network = Network::new(&w.host, seed);
    network.extension_mut::<Disks>().expect("installed").fail = fail
        .iter()
        .map(|(name, n)| ((*name).to_owned(), *n))
        .collect();
    network.set_component_resolver(Box::new(move |name, instantiate| match name {
        "disk" => instantiate(&w.device),
        other => Err(sim::Error::Refused(format!("no component {other}"))),
    }));
    network.set_infra_catalog(vec!["disk".to_owned()]);
    network
}

fn disk_device(network: &mut Network<'_>, name: &str, crash_alone: bool) {
    network
        .device_with_options(
            name,
            &disk_world().device,
            config(&[("period", "10ms")]),
            DeviceOptions::default().crash_alone(crash_alone),
        )
        .unwrap();
    network.set_device_component(network.live_device(name).unwrap(), "disk");
}

// ---- helpers -------------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
struct Run {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
}

/// Runs `build(seed)` to `deadline` at two seeds, twice each: checks each run and that the
/// rerun is byte-identical.
fn at_two_seeds(
    deadline: Nanos,
    build: impl Fn(u64) -> Network<'static>,
    check: impl Fn(&Network, u64),
) {
    for seed in [42, 7] {
        let mut runs = Vec::new();
        for _ in 0..2 {
            let mut network = build(seed);
            network
                .run_until(deadline)
                .unwrap_or_else(|e| panic!("seed {seed}: {e}\n{}", transcript(&network.journal())));
            check(&network, seed);
            runs.push(Run {
                journal: network.journal(),
                frames: network.frames(),
            });
        }
        assert_eq!(runs[0], runs[1], "seed {seed}: the rerun is byte-identical");
    }
}

/// `kind` events of `device` with their instants in ms.
fn timed(
    journal: &[JournalEntry],
    device: &str,
    kind: &str,
) -> Vec<(Nanos, Vec<(String, String)>)> {
    journal
        .iter()
        .filter(|e| e.device == device)
        .filter_map(|e| match &e.record {
            Record::Event { kind: k, fields } if k == kind => Some((e.at, fields.clone())),
            _ => None,
        })
        .collect()
}

/// `device`'s journal events among `kinds`, as `at-ms kind [first field value]`.
fn story(journal: &[JournalEntry], device: &str, kinds: &[&str]) -> Vec<String> {
    journal
        .iter()
        .filter(|e| e.device == device)
        .filter_map(|e| match &e.record {
            Record::Event { kind, fields } if kinds.contains(&kind.as_str()) => {
                let first = fields
                    .first()
                    .map(|(_, v)| format!(" {v}"))
                    .unwrap_or_default();
                Some(format!("{} {kind}{first}", e.at / MS))
            }
            _ => None,
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The spec of a disk device a controller creates.
fn disk_spec() -> String {
    hex(&Value::Map(vec![
        (Value::text("component"), Value::text("disk")),
        (
            Value::text("config"),
            Value::Map(vec![(Value::text("period"), Value::text("10ms"))]),
        ),
    ])
    .encode())
}

/// An `infra-script` controller with these steps.
fn controller(network: &mut Network<'_>, steps: &[String]) {
    let script: DeviceConfig = steps
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("step.{n}"), s.clone()))
        .collect();
    network
        .device_with_options(
            "ctl",
            &disk_world()
                .host
                .load(built().path("infra_script"))
                .expect("infra_script"),
            script,
            DeviceOptions::default().infra(true),
        )
        .unwrap();
}

// ---- a crash at a chosen import call ------------------------------------------------------

/// `a` (crashes alone) and `b` write every 10 ms; `a`'s third disk write (at 20 ms: the boot
/// write, then n=1, then n=2) traps in the extension. `ctl` creates `c`, whose second write (at
/// 10 ms) traps.
fn failing_disks(seed: u64, a_alone: bool) -> Network<'static> {
    let mut network = disk_network(seed, &[("a", 3), ("c", 2)]);
    disk_device(&mut network, "a", a_alone);
    disk_device(&mut network, "b", false);
    controller(&mut network, &[format!("0ms apply c {}", disk_spec())]);
    network
}

#[test]
fn an_extension_trap_at_a_chosen_call_crashes_that_device_alone() {
    at_two_seeds(
        100 * MS,
        |seed| failing_disks(seed, true),
        |network, seed| {
            let journal = network.journal();
            let log = transcript(&journal);
            for (device, at, n) in [("a", 20, 3), ("c", 10, 2)] {
                let crashed = timed(&journal, device, "device-crashed");
                assert_eq!(crashed.len(), 1, "seed {seed} {device}:\n{log}");
                assert_eq!(crashed[0].0, at * MS, "{device}");
                assert!(
                    field(&crashed[0].1, "message").contains(&format!("disk write {n} failed")),
                    "{crashed:?}"
                );
                assert_eq!(network.infra().get(device).unwrap().phase, Phase::Crashed);
                let id = network.live_device(device).unwrap();
                assert_eq!(network.device_phase(id), DevicePhase::Stopped);
            }
            // The failed write never reached the disk; the rest of the network carries on.
            assert_eq!(events(&journal, "a", "disk-write").len(), 1, "{log}");
            assert_eq!(events(&journal, "b", "disk-write").len(), 10, "{log}");
            let heard = &network.extension::<Disks>().unwrap().heard;
            assert_eq!(heard, &["c@10 crashed", "a@20 crashed"]);
        },
    );
}

#[test]
fn without_crash_alone_an_extension_trap_fails_the_network() {
    let mut network = failing_disks(42, false);
    match network.run_until(100 * MS) {
        Err(Error::Trap {
            device,
            at,
            message,
            ..
        }) => {
            assert_eq!((device.as_str(), at), ("a", 20 * MS));
            assert!(message.contains("disk write 3 failed"), "{message}");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(network.run_until(200 * MS), Err(Error::Halted)));
}

// ---- an operator's crash and an operator's stop, as the controller sees them ---------------

#[test]
fn an_operator_crash_is_a_crash_and_an_operator_stop_is_a_stop() {
    let build = |seed| {
        let mut network = disk_network(seed, &[]);
        let spec = disk_spec();
        controller(
            &mut network,
            &[
                format!("0ms apply c1 {spec}"),
                format!("0ms apply c2 {spec}"),
            ],
        );
        network
            .add_op(
                Op::crash_device("c1", "power supply failed"),
                Placement::StartOf(25 * MS),
            )
            .unwrap();
        network
            .add_op(Op::stop_device("c2"), Placement::StartOf(25 * MS))
            .unwrap();
        network
    };
    at_two_seeds(50 * MS, build, |network, seed| {
        let journal = network.journal();
        let log = transcript(&journal);
        let crashed = timed(&journal, "c1", "device-crashed");
        assert_eq!(crashed.len(), 1, "seed {seed}:\n{log}");
        assert_eq!(field(&crashed[0].1, "message"), "power supply failed");
        assert!(timed(&journal, "c2", "device-crashed").is_empty());
        assert_eq!(timed(&journal, "c2", "device-stopped").len(), 1);
        let (c1, c2) = (
            network.infra().get("c1").unwrap(),
            network.infra().get("c2").unwrap(),
        );
        assert_eq!(
            (c1.phase, c1.message.as_deref()),
            (Phase::Crashed, Some("power supply failed"))
        );
        assert_eq!((c2.phase, c2.message.as_deref()), (Phase::Stopped, None));
        // The controller's own view tells them apart.
        let (_, changes) = network.infra().watch_for("ctl", &[], 0, u32::MAX);
        let last = |name: &str| {
            changes
                .iter()
                .rev()
                .find(|c| c.device.name == name)
                .map(|c| c.device.phase)
        };
        assert_eq!(
            (last("c1"), last("c2")),
            (Some(Phase::Crashed), Some(Phase::Stopped))
        );
        // Neither wrote after 25 ms.
        for d in ["c1", "c2"] {
            assert!(
                timed(&journal, d, "disk-write")
                    .iter()
                    .all(|(at, _)| *at < 25 * MS)
            );
        }
    });
}

// ---- a device's life, heard by a network extension ----------------------------------------

/// `a` boots on its disk, then: paused 100-150 ms, stopped at 200, started at 250, crashed at
/// 300, started at 350, removed at 400, added again at 450 (a new device, a new disk).
fn living(seed: u64) -> Network<'static> {
    let mut network = disk_network(seed, &[]);
    disk_device(&mut network, "a", true);
    let ops = [
        (Op::pause_device("a"), 100),
        (Op::resume_device("a"), 150),
        (Op::stop_device("a"), 200),
        (Op::start_device("a"), 250),
        (Op::crash_device("a", "kernel panic"), 300),
        (Op::start_device("a"), 350),
        (Op::remove_device("a"), 400),
        (
            Op::add_device("a", "disk").with_config(config(&[("period", "10ms")])),
            450,
        ),
    ];
    for (op, at) in ops {
        network.add_op(op, Placement::StartOf(at * MS)).unwrap();
    }
    network
}

#[test]
fn extensions_hear_a_devices_life_right_after_the_network_records_it() {
    at_two_seeds(480 * MS, living, |network, seed| {
        let journal = network.journal();
        let log = transcript(&journal);
        let kinds = [
            "device-paused",
            "device-resumed",
            "device-stopped",
            "device-started",
            "device-crashed",
            "device-removed",
            "device-added",
            "disk-life",
            "disk-boot",
        ];
        // Each record of the network is followed at once by what the extension heard; the disk
        // survives a stop and a crash (the boot count goes on) and goes with the removal.
        assert_eq!(
            story(&journal, "a", &kinds),
            [
                "0 disk-boot 0",
                "100 device-paused up",
                "100 disk-life paused",
                "150 device-resumed 1",
                "150 disk-life resumed",
                "200 device-stopped",
                "200 disk-life stopped",
                "250 device-started",
                "250 disk-life started",
                "250 disk-boot 1",
                "300 device-crashed kernel panic",
                "300 disk-life crashed",
                "350 device-started",
                "350 disk-life started",
                "350 disk-boot 2",
                "400 device-removed",
                "400 disk-life removed",
                "450 device-added disk",
                "450 disk-boot 0",
            ],
            "seed {seed}:\n{log}"
        );
        // Paused, `a` wrote nothing; its overdue poll deadline fired at the resume, and it
        // caught up from there.
        let writes: Vec<Nanos> = timed(&journal, "a", "disk-write")
            .into_iter()
            .map(|(at, _)| at / MS)
            .filter(|at| (90..=160).contains(at))
            .collect();
        assert_eq!(writes.first(), Some(&90));
        assert!(
            !writes.iter().any(|at| (91..150).contains(at)),
            "{writes:?}"
        );
        assert!(writes.contains(&150), "{writes:?}");
        assert_eq!(
            network.extension::<Disks>().unwrap().heard,
            [
                "a@100 paused",
                "a@150 resumed",
                "a@200 stopped",
                "a@250 started",
                "a@300 crashed",
                "a@350 started",
                "a@400 removed",
            ]
        );
    });
}

// ---- an embedder action at an exact place ----------------------------------------------------

/// `a` and `b` boot on their disks. At 30 ms both are stopped (start of the instant), a `wipe`
/// action empties `a`'s disk at the end of the instant, and then both start again (two more
/// operator events at the end of the instant, placed after the action).
fn wiping(seed: u64) -> Network<'static> {
    let mut network = disk_network(seed, &[]);
    disk_device(&mut network, "a", false);
    disk_device(&mut network, "b", false);
    network.register_action("wipe", |ctx, call| {
        let wiped = ctx
            .extension_mut::<Disks>()
            .ok_or("no disks")?
            .wipe(call.device);
        if !wiped {
            return Err(format!("`{}` has no disk", call.device).into());
        }
        ctx.journal_event(call.device, "disk-wiped", Vec::new());
        Ok(())
    });
    let at = 30 * MS;
    for d in ["a", "b"] {
        network
            .add_op(Op::stop_device(d), Placement::StartOf(at))
            .unwrap();
    }
    network
        .add_op(Op::action("wipe", "a", String::new()), Placement::EndOf(at))
        .unwrap();
    for d in ["a", "b"] {
        network
            .add_op(Op::start_device(d), Placement::EndOf(at))
            .unwrap();
    }
    network
}

#[test]
fn an_embedder_action_wipes_a_disk_at_its_place_among_the_instants_events() {
    at_two_seeds(50 * MS, wiping, |network, seed| {
        let journal = network.journal();
        let log = transcript(&journal);
        let kinds = [
            "device-stopped",
            "device-started",
            "action",
            "disk-wiped",
            "disk-boot",
        ];
        assert_eq!(
            story(&journal, "a", &kinds),
            [
                "0 disk-boot 0",
                "30 device-stopped",
                "30 action wipe",
                "30 disk-wiped",
                "30 device-started",
                "30 disk-boot 0",
            ],
            "seed {seed}:\n{log}"
        );
        // `b`'s disk was not wiped: it boots for the second time.
        assert_eq!(
            story(&journal, "b", &kinds),
            [
                "0 disk-boot 0",
                "30 device-stopped",
                "30 device-started",
                "30 disk-boot 1"
            ]
        );
        assert!(
            network
                .op_states()
                .iter()
                .all(|s| matches!(s, OpState::Applied { at, .. } if *at == 30 * MS)),
            "{:?}",
            network.op_states()
        );
    });
}

// ---- a node paused in the middle of a TCP transfer -----------------------------------------

/// The pause.
const PAUSE: Nanos = 4 * MS;
const RESUME: Nanos = 3_004 * MS;
/// The body the client fetches.
const BODY: usize = 200_000;

/// `client` fetches 200 kB from `server` through a switch from 1 ms; `sleeper` sleeps from 4 ms
/// to 3.004 s, its links down or not.
fn paused_transfer(seed: u64, sleeper: &str, link_down: bool) -> Network<'static> {
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
                ("app.http-get.url", &format!("http://10.0.0.1/big?n={BODY}")),
                ("app.http-get.start", "1ms"),
            ]),
        )
        .unwrap();
    network
        .link(server.port(0), sw.port(1))
        .unwrap()
        .latency(100 * US);
    network
        .link(client.port(0), sw.port(2))
        .unwrap()
        .latency(100 * US);
    let device = sleeper.to_owned();
    network
        .add_op(
            Op::pause_device(device.clone()).with_link_down(link_down),
            Placement::StartOf(PAUSE),
        )
        .unwrap();
    network
        .add_op(Op::resume_device(device), Placement::StartOf(RESUME))
        .unwrap();
    network
}

/// Data segments `port` sent in `[from, to)`.
fn data_sent(frames: &[FrameRecord], port: sim::PortRef, from: Nanos, to: Nanos) -> usize {
    frames
        .iter()
        .filter(|f| f.from == port && f.sent_at >= from && f.sent_at < to)
        .filter_map(|f| support::segment(&f.bytes))
        .filter(|s| !s.payload.is_empty())
        .count()
}

/// What every paused transfer shows: the sleeper sent nothing while it slept, the fetch
/// completed after the resume with every byte, and the resume was journalled.
fn check_transfer(network: &Network, seed: u64, sleeper: &str) -> Vec<(String, String)> {
    let journal = network.journal();
    let log = transcript(&journal);
    let frames = network.frames();
    let port = network.live_device(sleeper).unwrap().port(0);
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.from == port && f.sent_at >= PAUSE && f.sent_at < RESUME)
            .count(),
        0,
        "seed {seed}: a sleeping node sends nothing"
    );
    let server = network.live_device("server").unwrap().port(0);
    assert!(
        data_sent(&frames, server, 0, PAUSE) > 0,
        "seed {seed}: paused in the middle of the transfer\n{log}"
    );
    assert!(
        data_sent(&frames, server, RESUME, Nanos::MAX) > 0,
        "seed {seed}:\n{log}"
    );
    let done = timed(&journal, "client", "http-get-done");
    assert_eq!(done.len(), 1, "seed {seed}:\n{log}");
    assert!(done[0].0 > RESUME, "{done:?}");
    assert_eq!(field(&done[0].1, "status"), "200");
    assert_eq!(field(&done[0].1, "body-bytes"), BODY.to_string());
    let resumed = timed(&journal, sleeper, "device-resumed");
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].0, RESUME);
    resumed[0].1.clone()
}

/// The client sleeps with its carrier up: the server keeps retransmitting into the silence,
/// every one dropped at the sleeping port; at the resume the client's overdue timers fire and
/// it acknowledges, and the transfer completes.
#[test]
fn a_receiver_paused_mid_transfer_misses_retransmissions_and_finishes_it() {
    at_two_seeds(
        20_000 * MS,
        |seed| paused_transfer(seed, "client", false),
        |network, seed| {
            let resumed = check_transfer(network, seed, "client");
            let frames = network.frames();
            let server = network.live_device("server").unwrap().port(0);
            // The peer's view: its retransmission timer fired while the client slept, more
            // than once (it backs off), and nothing answered.
            let retransmitted: Vec<Nanos> = frames
                .iter()
                .filter(|f| f.from == server && f.sent_at >= PAUSE + 100 * MS)
                .filter(|f| f.sent_at < RESUME)
                .filter(|f| support::segment(&f.bytes).is_some_and(|s| !s.payload.is_empty()))
                .map(|f| f.sent_at)
                .collect();
            assert!(retransmitted.len() >= 2, "seed {seed}: {retransmitted:?}");
            let dropped: usize = field(&resumed, "dropped").parse().unwrap();
            assert!(
                dropped >= retransmitted.len(),
                "{resumed:?} {retransmitted:?}"
            );
            // The client spoke first at the resume instant: its overdue timers fired there.
            let client = network.live_device("client").unwrap().port(0);
            let first = frames
                .iter()
                .find(|f| f.from == client && f.sent_at >= RESUME)
                .map(|f| f.sent_at);
            assert_eq!(first, Some(RESUME), "seed {seed}");
        },
    );
}

/// The server sleeps with its links down: the switch sees the carrier drop, and the client's
/// frames to it never reach it; at the resume its link comes back, its overdue retransmission
/// fires at that instant, and the transfer completes.
#[test]
fn a_sender_paused_with_its_link_down_resumes_the_transfer() {
    at_two_seeds(
        20_000 * MS,
        |seed| paused_transfer(seed, "server", true),
        |network, seed| {
            let resumed = check_transfer(network, seed, "server");
            assert_eq!(
                field(&resumed, "dropped"),
                "0",
                "the link was down, not the port"
            );
            let frames = network.frames();
            let server = network.live_device("server").unwrap().port(0);
            assert_eq!(
                frames
                    .iter()
                    .find(|f| f.from == server && f.sent_at >= RESUME)
                    .map(|f| f.sent_at),
                Some(RESUME),
                "seed {seed}: its overdue timer fired at the resume"
            );
            let link = network.link_at(server).unwrap();
            let transitions: Vec<(Nanos, bool)> = network
                .link_transitions()
                .into_iter()
                .filter(|t| t.link == link)
                .map(|t| (t.at, t.up))
                .collect();
            assert!(
                transitions.ends_with(&[(PAUSE, false), (RESUME, true)]),
                "{transitions:?}"
            );
        },
    );
}
