//! The public types an embedder builds, built the way `docs/stability.md` says to: through
//! `Default`, a constructor and chainable setters, never a struct literal. Most of them are
//! `#[non_exhaustive]`, so this file only compiles while each keeps the constructor it lists;
//! a field added to any of them later must not break it.

use std::time::Duration;

use wasmnet_host::sim::infra::{Follow, TableSince};
use wasmnet_host::sim::{
    Cable, CaptureOptions, Control, DeclaredPort, DeviceCommand, DeviceCost, DeviceInstance,
    ExtOptions, Fault, Impairments, LinkKind, Op, SeriesOptions, SupplyLimits,
};
use wasmnet_host::{
    DeviceConfig, DeviceId, DeviceOptions, Guard, JournalEntry, Level, LinkId, LinkStats, Outcome,
    Record, SimConfig,
};

#[test]
fn every_listed_type_has_a_constructor_outside_its_crate() {
    let impaired = Impairments::default()
        .rate(1_000_000)
        .queue(10)
        .loss_ppm(1_000)
        .jitter(5);
    let capture = CaptureOptions::default()
        .record(true)
        .snap_len(128)
        .name_ends(true);
    let series = SeriesOptions::new(1_000, 16);
    let limits = SupplyLimits::default()
        .max_bytes(1 << 20)
        .max_components(2)
        .max_total(2 << 20);
    let options = DeviceOptions::default()
        .fuel_per_instant(1_000)
        .journal_stdio(true)
        .infra(true)
        .infra_prefix("p-")
        .infra_cascade(Default::default())
        .infra_max_devices(4)
        .infra_supply(limits)
        .memory(64 << 20)
        .crash_alone(true)
        .args(["-v"])
        .env([("K", "v")])
        .ext(ExtOptions::default());
    let cable = Cable::new(0, "sw", 1)
        .latency(100)
        .mtu(1400)
        .impairments([impaired, Impairments::default()]);
    let guard = Guard::default()
        .fuel_per_instant(1_000)
        .max_polls_per_instant(10)
        .paranoid(true);
    let config = SimConfig::seeded(7).wall_epoch(Duration::from_secs(1));
    let fault = Fault::new("trap");
    let instance = DeviceInstance::new(
        vec![DeclaredPort {
            id: 0,
            name: "eth0".to_owned(),
            mac: None,
            mtu: 1500,
        }],
        Box::pin(async { Ok(()) }),
    )
    .has_counters(true)
    .exports(Vec::new())
    .apps(vec!["app".to_owned()]);
    let entry = JournalEntry::new(
        1,
        "sw",
        Record::Log {
            level: Level::Info,
            message: "hello".to_owned(),
        },
    );
    let outcomes = [
        Outcome::quiescent(1, Vec::new(), Vec::new()),
        Outcome::deadline(2, 3),
    ];
    let follow = Follow::new("r1", vec!["tunnel-*".to_owned()], 7);
    let table = TableSince::new(vec![("app".to_owned(), "web".to_owned())], 3);
    assert_eq!((follow.since, table.since), (7, 3));
    let call = || -> Control { DeviceCommand::new("routes", "").into_control() };
    let (link, device) = (LinkId::from_index(0), DeviceId::from_index(0));
    let ops = [
        Op::link_state(link, false),
        Op::latency(link, 10),
        Op::impair(link, impaired).with_from(0),
        Op::inject(device.port(0), vec![0u8; 14]),
        Op::stdin(device, b"x".to_vec()),
        Op::control(device, call()),
        Op::add_device("d", "switch")
            .with_config(DeviceConfig::new())
            .with_options(options.clone())
            .with_cable(cable.clone()),
        Op::stop_device("d"),
        Op::pause_device("d").with_link_down(true),
        Op::resume_device("d"),
        Op::crash_device("d", "boom"),
        Op::action("wipe", "d", ""),
        Op::start_device("d"),
        Op::remove_device("d"),
        Op::wire(("a", 0), ("b", 1))
            .with_latency(10)
            .with_mtu(1400)
            .with_kind(LinkKind::Ethernet)
            .with_impairments([impaired, impaired]),
        Op::unwire("a.0-b.1"),
        Op::set_link("a.0-b.1").with_up(true).with_latency(5),
        Op::impair_named("a.0-b.1", impaired).with_from(1),
        Op::stdin_named("d", b"x".to_vec()),
        Op::control_named("d", call()),
    ];

    // Fields stay public: what was set reads back.
    assert_eq!(
        (impaired.rate, capture.snap_len, series.keep),
        (1_000_000, 128, 16)
    );
    assert_eq!(
        (options.infra_max_devices, options.args.len()),
        (Some(4), 1)
    );
    assert_eq!((cable.to_device.as_str(), cable.mtu), ("sw", Some(1400)));
    assert_eq!((guard.max_polls_per_instant, config.seed), (10, 7));
    assert_eq!((fault.message.as_str(), instance.apps.len()), ("trap", 1));
    assert_eq!(entry.device, "sw");
    assert!(matches!(outcomes[1], Outcome::Deadline { at: 2, .. }));
    assert!(matches!(
        &ops[14],
        Op::Wire {
            mtu: Some(1400),
            ..
        }
    ));
    assert_eq!(LinkStats::default().frames, [0, 0]);
    assert_eq!(DeviceCost::default().fuel, 0);
}

/// Portable extensions: what an extension builds to declare and answer an interface.
#[test]
fn portable_extensions() {
    use wasmnet_host::sim::value::Value;
    use wasmnet_host::sim::{Interface, Served};
    let i = Interface::new("example:pad/notes@0.1.0")
        .function("[constructor]note")
        .function("names")
        .resource("note");
    assert_eq!(i.name, "example:pad/notes@0.1.0");
    assert_eq!(i.functions, ["[constructor]note", "names"]);
    assert_eq!(i.resources, ["note"]);
    let answers = [
        Served::Ok(Value::resource("note", 3)),
        Served::Err(Value::case("full", Value::U64(1))),
        Served::Fault("pad: append 3 failed".to_owned()),
    ];
    // Closed on purpose: a backend handles every case.
    for a in answers {
        match a {
            Served::Ok(_) | Served::Err(_) | Served::Fault(_) => {}
        }
    }
    assert_eq!(Value::option(None).into_option(), None);
}
