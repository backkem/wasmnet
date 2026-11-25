//! Acceptance test: blaster ↔ reflector over one point-to-point link.
//!
//! * Every echo reaches the blaster exactly `send + 2L` after its probe left (`L` = latency).
//! * The same seed gives byte-identical pcaps, pinned by a SHA-256.
//! * Changing the latency shifts exactly the timestamps it should.
//! * The pcap is structurally valid (strict reader; `capinfos`/`tshark` too if on PATH).
//!
//! The components are built once per test binary with
//! `cargo build --release --target wasm32-wasip2 -p wasmnet-blaster -p wasmnet-reflector`.
//! Replay any failure with `cargo test -p wasmnet-host --test echo`; every message names
//! the seed and latency.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use wasmnet_host::pcap::{self, Capture, Direction};
use wasmnet_host::{Guard, Host, Network, Outcome, Record, SimConfig};
use wasmnet_wire::{EthernetFrame, MacAddr};
use wasmtime::component::Component;

/// Must match `COUNT` and `INTERVAL_NS` in components/blaster/src/lib.rs.
const COUNT: u64 = 8;
const INTERVAL: u64 = 1_000_000;
const US: u64 = 1_000;
/// `sha256(pcap)` for seed 42, latency 250 µs. Any change to the WIT, host scheduling, pcap
/// encoding, MAC derivation or the components' behaviour changes this on purpose.
const PINNED_SEED42_L250US: &str =
    "a9aec6a9bcb527254d0f4e8459c09fcd34120d300f744917fb566faeb6dbfee7";

struct Guests {
    host: Host,
    blaster: Component,
    reflector: Component,
}

fn guests() -> &'static Guests {
    static GUESTS: OnceLock<Guests> = OnceLock::new();
    GUESTS.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let status = Command::new(env!("CARGO"))
            .current_dir(&root)
            .args(["build", "--release", "--target", "wasm32-wasip2"])
            .args(["-p", "wasmnet-blaster", "-p", "wasmnet-reflector"])
            .status()
            .expect("spawn cargo to build the components");
        assert!(status.success(), "building blaster/reflector failed");
        let out = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target"))
            .join("wasm32-wasip2/release");
        let host = Host::new().expect("host");
        let blaster = host.load(out.join("blaster.wasm")).expect("blaster.wasm");
        let reflector = host
            .load(out.join("reflector.wasm"))
            .expect("reflector.wasm");
        Guests {
            host,
            blaster,
            reflector,
        }
    })
}

struct Run {
    outcome: Outcome,
    pcap: Vec<u8>,
    blaster_log: String,
}

/// The echo network: blaster:0 <-latency-> reflector:0, run to quiescence.
fn run_echo(seed: u64, latency: u64) -> Run {
    let g = guests();
    let guard = Guard {
        paranoid: true,
        ..Guard::default()
    };
    let mut network = Network::with_config(&g.host, SimConfig::seeded(seed), guard);
    let a = network.device("blaster", &g.blaster).unwrap();
    let b = network.device("reflector", &g.reflector).unwrap();
    let link = network
        .link(a.port(0), b.port(0))
        .unwrap()
        .latency(latency)
        .id();
    let outcome = network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed} latency={latency}: {e}"));
    let stats = network.link_stats(link);
    assert_eq!(
        stats.frames,
        [COUNT, COUNT],
        "seed={seed} latency={latency}"
    );
    assert_eq!((network.dropped(a), network.dropped(b)), (0, 0));
    Run {
        outcome,
        pcap: network.pcap(link),
        blaster_log: log_lines(&network, "blaster"),
    }
}

/// The device's `wasmnet:link/log` lines as `t=<virtual ns> <message>`, one per line.
fn log_lines(network: &Network, device: &str) -> String {
    network
        .journal()
        .into_iter()
        .filter(|e| e.device == device)
        .filter_map(|e| match e.record {
            Record::Log { message, .. } => Some(format!(
                "t={} {message}
",
                e.at
            )),
            _ => None,
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `(interface, direction, timestamp, probe seq)` for every packet, in file order.
fn timeline(cap: &Capture) -> Vec<(u32, Direction, u64, u32)> {
    cap.packets
        .iter()
        .map(|p| {
            let seq = u32::from_be_bytes(p.data[22..26].try_into().unwrap());
            (p.interface, p.direction.unwrap(), p.timestamp, seq)
        })
        .collect()
}

/// Asserts the exact timeline: probe i leaves the blaster at i·INTERVAL, reaches the reflector
/// at +L, is echoed at once, and the echo reaches the blaster at +2L.
fn assert_exact_timing(cap: &Capture, latency: u64, ctx: &str) {
    let mut expected = Vec::new();
    for i in 0..COUNT {
        let t = i * INTERVAL;
        let seq = i as u32;
        expected.push((t, 0, Direction::Outbound, seq));
        expected.push((t + latency, 1, Direction::Inbound, seq));
        expected.push((t + latency, 1, Direction::Outbound, seq));
        expected.push((t + 2 * latency, 0, Direction::Inbound, seq));
    }
    // The file is in event order; compare as a set ordered by (time, ...), and check that the
    // file itself never goes back in time.
    expected.sort();
    let mut got: Vec<_> = timeline(cap)
        .into_iter()
        .map(|(i, d, t, s)| (t, i, d, s))
        .collect();
    let file_times: Vec<u64> = got.iter().map(|g| g.0).collect();
    assert!(file_times.is_sorted(), "{ctx}: timestamps go backwards");
    got.sort();
    assert_eq!(got, expected, "{ctx}");
}

#[test]
fn echoes_arrive_exactly_two_latencies_after_each_probe() {
    for seed in [1, 42] {
        let latency = 250 * US;
        let ctx = format!("seed={seed} latency={latency}");
        let run = run_echo(seed, latency);
        // Quiescent once the last echo has arrived and been polled: nothing parked, nothing owed.
        assert_eq!(
            run.outcome,
            Outcome::Quiescent {
                at: (COUNT - 1) * INTERVAL + 2 * latency,
                parked: vec![],
                daemons: vec![],
            },
            "{ctx}"
        );
        let cap = pcap::parse(&run.pcap).unwrap();
        assert_exact_timing(&cap, latency, &ctx);
        // The blaster saw the same thing from inside: every RTT is exactly 2L.
        for i in 0..COUNT {
            let line = format!(
                "t={} echo seq={i} rtt={}ns",
                i * INTERVAL + 2 * latency,
                2 * latency
            );
            assert!(
                run.blaster_log.contains(&line),
                "{ctx}: missing `{line}` in\n{}",
                run.blaster_log
            );
        }
        println!("{ctx}: {:?}\n{}", run.outcome, run.blaster_log);
    }
}

#[test]
fn same_seed_gives_byte_identical_pcaps_matching_the_pinned_hash() {
    let a = run_echo(42, 250 * US);
    let b = run_echo(42, 250 * US);
    assert_eq!(a.pcap, b.pcap, "seed=42: replay diverged");
    let hash = sha256_hex(&a.pcap);
    println!(
        "seed=42 latency=250us: {} bytes, sha256 {hash}",
        a.pcap.len()
    );
    assert_eq!(
        hash, PINNED_SEED42_L250US,
        "seed=42 latency=250us: pinned pcap hash changed"
    );

    // Another seed changes the bytes (seeded MACs) but not the timing or the sizes.
    let c = run_echo(43, 250 * US);
    assert_ne!(a.pcap, c.pcap, "seed=43 must differ from seed=42");
    let (ca, cc) = (pcap::parse(&a.pcap).unwrap(), pcap::parse(&c.pcap).unwrap());
    let shape = |cap: &Capture| -> Vec<_> {
        cap.packets
            .iter()
            .map(|p| (p.interface, p.direction, p.timestamp, p.data.len()))
            .collect()
    };
    assert_eq!(shape(&ca), shape(&cc));
}

#[test]
fn changing_the_latency_shifts_the_timestamps() {
    let base = 250 * US;
    let reference = pcap::parse(&run_echo(42, base).pcap).unwrap();
    // Shorter, longer, and longer than the probe interval (echoes overlap later probes).
    for latency in [0, 10 * US, 1_500 * US] {
        let ctx = format!("seed=42 latency={latency}");
        let cap = pcap::parse(&run_echo(42, latency).pcap).unwrap();
        assert_exact_timing(&cap, latency, &ctx);
        // Packet by packet (matched by interface, direction and seq), the shift is exactly
        // 0 for probes leaving the blaster, ΔL at the reflector and 2ΔL for echoes arriving back.
        let key = |cap: &Capture| {
            let mut v: Vec<_> = timeline(cap)
                .into_iter()
                .map(|(i, d, t, s)| ((i, d == Direction::Inbound, s), t))
                .collect();
            v.sort();
            v
        };
        for ((k, t_ref), (k2, t)) in key(&reference).into_iter().zip(key(&cap)) {
            assert_eq!(k, k2, "{ctx}");
            let hops = match k {
                (0, false, _) => 0, // probe leaves the blaster
                (1, _, _) => 1,     // at the reflector, in and out
                (0, true, _) => 2,  // echo back at the blaster
                _ => unreachable!(),
            };
            let shift = t as i128 - t_ref as i128;
            assert_eq!(
                shift,
                hops * (latency as i128 - base as i128),
                "{ctx} {k:?}"
            );
        }
    }
}

#[test]
fn the_pcap_is_structurally_valid() {
    let run = run_echo(42, 250 * US);
    let cap = pcap::parse(&run.pcap).expect("strict pcap-ng parse");
    assert_eq!(cap.user_appl.as_deref(), Some("wasmnet"));
    let names: Vec<_> = cap.interfaces.iter().map(|i| i.name.as_deref()).collect();
    assert_eq!(names, [Some("blaster:0"), Some("reflector:0")]);
    for iface in &cap.interfaces {
        assert_eq!((iface.linktype, iface.tsresol, iface.snaplen), (1, 9, 0));
    }
    assert_eq!(cap.packets.len() as u64, 4 * COUNT);
    let (mut blaster_mac, mut reflector_mac) = (None, None);
    for p in &cap.packets {
        assert_eq!(p.original_len as usize, p.data.len());
        let eth = EthernetFrame::new_checked(&p.data[..]).expect("every packet is Ethernet");
        assert_eq!(eth.ethertype().0, 0x88b5);
        assert_eq!(&eth.payload()[..8], b"wasmnet1");
        if eth.dst() == MacAddr::BROADCAST {
            // A probe: from the blaster's seeded, locally administered unicast MAC.
            assert!(eth.src().is_locally_administered() && eth.src().is_unicast());
            assert_eq!(*blaster_mac.get_or_insert(eth.src()), eth.src());
        } else {
            // An echo: addressed back to the blaster, from the reflector's own MAC.
            assert_eq!(Some(eth.dst()), blaster_mac);
            assert!(eth.src().is_locally_administered() && eth.src().is_unicast());
            assert_eq!(*reflector_mac.get_or_insert(eth.src()), eth.src());
        }
    }
    assert_ne!(blaster_mac, reflector_mac);
    validate_with_wireshark_tools_if_present(&run.pcap);
}

/// Runs `capinfos` and `tshark` on the capture when they are on PATH. Nothing is installed.
fn validate_with_wireshark_tools_if_present(bytes: &[u8]) {
    let present = |bin: &str| Command::new(bin).arg("-v").output().is_ok();
    let (capinfos, tshark) = (present("capinfos"), present("tshark"));
    if !capinfos && !tshark {
        println!("capinfos/tshark not on PATH: skipping external validation");
        return;
    }
    let dir = std::env::temp_dir().join(format!("wasmnet-echo-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("echo.pcapng");
    std::fs::write(&file, bytes).unwrap();
    for (bin, args) in [("capinfos", vec!["-c"]), ("tshark", vec!["-r"])] {
        if !present(bin) {
            continue;
        }
        let out = Command::new(bin).args(&args).arg(&file).output().unwrap();
        assert!(
            out.status.success(),
            "{bin} rejected the capture: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        println!("{bin}: {}", String::from_utf8_lossy(&out.stdout));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stopping_at_a_deadline_and_resuming_gives_the_same_pcap() {
    let g = guests();
    let whole = run_echo(42, 250 * US).pcap;
    let mut network = Network::new(&g.host, 42);
    let a = network.device("blaster", &g.blaster).unwrap();
    let b = network.device("reflector", &g.reflector).unwrap();
    let link = network
        .link(a.port(0), b.port(0))
        .unwrap()
        .latency(250 * US)
        .id();
    let mid = network.run_until(3_100 * US).unwrap();
    assert!(
        matches!(
            mid,
            Outcome::Deadline {
                at: 3_100_000,
                pending_events: 1..
            }
        ),
        "{mid:?}"
    );
    assert_eq!(network.now(), 3_100 * US);
    assert!(matches!(
        network.run_until_quiescent().unwrap(),
        Outcome::Quiescent { .. }
    ));
    assert_eq!(network.pcap(link), whole);
}

#[test]
fn ports_are_validated_when_linking() {
    let g = guests();
    let mut network = Network::new(&g.host, 42);
    let a = network.device("blaster", &g.blaster).unwrap();
    let b = network.device("reflector", &g.reflector).unwrap();
    let ports = network.ports(b);
    assert_eq!(ports.len(), 1);
    assert_eq!(
        (ports[0].id, ports[0].name.as_str(), ports[0].mtu),
        (0, "eth0", 1500)
    );
    let err = network
        .link(a.port(0), b.port(1))
        .err()
        .expect("port 1 is undeclared");
    assert!(
        matches!(&err, wasmnet_host::Error::UnknownPort { device, port: 1, declared } if device == "reflector" && declared == &[0]),
        "{err}"
    );
    network.link(a.port(0), b.port(0)).unwrap();
    assert!(
        matches!(
            network.link(a.port(0), b.port(0)),
            Err(wasmnet_host::Error::PortInUse { .. })
        ),
        "port reuse must fail"
    );
    assert!(matches!(
        network.run_until_quiescent(),
        Ok(Outcome::Quiescent { .. })
    ));
}

#[test]
fn device_imports_are_link_plus_deterministic_wasi_only() {
    let g = guests();
    for c in [&g.blaster, &g.reflector] {
        let imports = g.host.imports(c);
        for name in &imports {
            assert!(
                [
                    "wasmnet:link/",
                    "wasi:cli/",
                    "wasi:io/",
                    "wasi:clocks/",
                    "wasi:random/",
                    "wasi:config/store@",
                ]
                .iter()
                .any(|p| name.starts_with(p)),
                "unexpected import {name}"
            );
        }
        assert!(
            imports
                .iter()
                .any(|i| i.starts_with("wasmnet:link/wire@0.1.0"))
        );
        assert!(
            g.host
                .exports(c)
                .iter()
                .any(|e| e.starts_with("wasmnet:link/device@0.1.0"))
        );
    }
}

#[test]
fn a_scripted_link_outage_drops_and_loses_frames() {
    let g = guests();
    let mut network = Network::new(&g.host, 42);
    let a = network.device("blaster", &g.blaster).unwrap();
    let b = network.device("reflector", &g.reflector).unwrap();
    let link = network
        .link(a.port(0), b.port(0))
        .unwrap()
        .latency(250 * US)
        .id();
    // Probe 2 (t=2ms) is in flight at 2.1ms: lost. Probe 3 (t=3ms) meets a down link: dropped.
    network.schedule_link_state(link, 2_100 * US, false);
    network.schedule_link_state(link, 3_500 * US, true);
    network.run_until_quiescent().unwrap();

    let stats = network.link_stats(link);
    assert_eq!(stats.frames, [COUNT - 1, COUNT - 2]);
    assert_eq!(stats.lost, [1, 0]);
    assert_eq!(stats.dropped_down, [1, 0]);
    let fates: Vec<_> = network
        .frames()
        .iter()
        .filter(|f| f.from.device == a)
        .map(|f| f.fate)
        .collect();
    assert_eq!(fates[2], wasmnet_host::FrameFate::Lost);
    assert_eq!(
        fates[3],
        wasmnet_host::FrameFate::Dropped(wasmnet_host::DropReason::LinkDown)
    );
    assert_eq!(
        fates[4],
        wasmnet_host::FrameFate::Delivered { at: 4_250 * US }
    );
    let transitions: Vec<_> = network
        .link_transitions()
        .iter()
        .map(|t| (t.at, t.up))
        .collect();
    assert_eq!(transitions, [(2_100 * US, false), (3_500 * US, true)]);
    let log = log_lines(&network, "blaster");
    assert!(
        !log.contains("echo seq=2 ") && !log.contains("echo seq=3 "),
        "{log}"
    );
    assert!(log.contains("echo seq=4 "), "{log}");
}

#[test]
fn frames_over_the_link_mtu_are_dropped() {
    let g = guests();
    let mut network = Network::new(&g.host, 42);
    let a = network.device("blaster", &g.blaster).unwrap();
    let b = network.device("reflector", &g.reflector).unwrap();
    // Probes carry a 46-byte payload.
    let link = network.link(a.port(0), b.port(0)).unwrap().mtu(45).id();
    assert_eq!(network.link_info(link).mtu, 45);
    network.run_until_quiescent().unwrap();
    let stats = network.link_stats(link);
    assert_eq!((stats.frames, stats.oversize), ([0, 0], [COUNT, 0]));
    assert!(pcap::parse(&network.pcap(link)).unwrap().packets.is_empty());
}

#[test]
fn a_device_can_have_its_own_fuel_budget() {
    // `DeviceOptions::fuel_per_instant` overrides the network's guard for one device, in both
    // directions, and stays a deterministic guard.
    use wasmnet_host::{DeviceConfig, DeviceOptions, Error};
    let g = guests();
    let run = |guard_fuel: u64, blaster_fuel: Option<u64>| {
        let guard = Guard {
            fuel_per_instant: guard_fuel,
            ..Guard::default()
        };
        let mut network = Network::with_config(&g.host, SimConfig::seeded(42), guard);
        let options = DeviceOptions {
            fuel_per_instant: blaster_fuel,
            ..DeviceOptions::default()
        };
        let a = network.device_with_options("blaster", &g.blaster, DeviceConfig::new(), options)?;
        let b = network.device_with_options(
            "reflector",
            &g.reflector,
            DeviceConfig::new(),
            DeviceOptions {
                fuel_per_instant: Some(Guard::default().fuel_per_instant),
                ..DeviceOptions::default()
            },
        )?;
        network.link(a.port(0), b.port(0))?.latency(250 * US);
        network.run_until_quiescent()
    };
    // A starved blaster runs out of fuel (here already while it is being created), the same
    // way every time.
    for _ in 0..2 {
        match run(Guard::default().fuel_per_instant, Some(1_000)) {
            Err(e @ Error::Runtime { .. }) => assert_eq!(
                wasmnet_host::wasmtime_trap(&e),
                Some(wasmtime::Trap::OutOfFuel),
                "{e:?}"
            ),
            other => panic!("expected an out-of-fuel trap, got {other:?}"),
        }
    }
    // A network whose guard would starve everyone runs when each device brings its own budget.
    let outcome = run(1_000, Some(Guard::default().fuel_per_instant)).expect("run");
    assert!(matches!(outcome, Outcome::Quiescent { .. }), "{outcome:?}");
}
