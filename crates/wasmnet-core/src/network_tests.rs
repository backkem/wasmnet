//! Operator events that pause, resume and crash devices, embedder actions and the life hooks of
//! network extensions, on a fake runtime whose devices are plain Rust futures.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use super::*;
use crate::clock::Sleep;
use crate::ext::{DeviceLife, LifeEvent, NetworkExtension};
use crate::{Fault, Record};

type Log = Arc<Mutex<Vec<String>>>;

/// A runtime whose component is a spec: `tick=10,15` (a timer per period, rearmed after each
/// tick), `tx` (each tick transmits a frame on port 0), `trap=N` (the N-th tick traps). Every
/// device has ports 0 and 1, answers `counters` and takes device commands (refusing them).
struct Fake {
    log: Log,
}

impl Fake {
    fn new() -> Self {
        Self {
            log: Log::default(),
        }
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl Runtime for Fake {
    type Component = str;

    fn instantiate(&self, ctx: DeviceContext, component: &str) -> Result<DeviceInstance> {
        let mut periods = Vec::new();
        let (mut tx, mut trap) = (false, None);
        for part in component.split(';').filter(|p| !p.is_empty()) {
            match part.split_once('=') {
                Some(("tick", ps)) => periods = ps.split(',').map(|p| p.parse().unwrap()).collect(),
                Some(("trap", n)) => trap = Some(n.parse::<u32>().unwrap()),
                None if part == "tx" => tx = true,
                _ => panic!("bad spec {part}"),
            }
        }
        let log = self.log.clone();
        let DeviceContext {
            index,
            name,
            clock,
            wire,
            inbox,
            ..
        } = ctx;
        let mut sleeps: Vec<(Nanos, Option<Pin<Box<Sleep>>>)> =
            periods.into_iter().map(|p| (p, None)).collect();
        let mut ticks = 0;
        let actor = Box::pin(poll_fn(move |cx| {
            let now = clock.now();
            let say = |what: String| log.lock().unwrap().push(format!("{name}@{now} {what}"));
            while let Some(command) = inbox.poll_pop(cx) {
                match command {
                    Command::Receive { port, .. } => say(format!("rx p{port}")),
                    Command::LinkState { port, up } => say(format!("link p{port} {up}")),
                    Command::Poll => clock.set_poll(index, None),
                    Command::Counters(reply) => *reply.lock().unwrap() = Some(Vec::new()),
                    Command::Control(call) => call.unsupported(),
                    Command::Stdin(bytes) => {
                        say(format!("stdin {}", String::from_utf8_lossy(&bytes)))
                    }
                }
            }
            for (period, sleep) in &mut sleeps {
                loop {
                    let s = sleep.get_or_insert_with(|| Box::pin(clock.sleep_for(*period)));
                    if s.as_mut().poll(cx).is_pending() {
                        break;
                    }
                    *sleep = None;
                    say(format!("tick {period}"));
                    if tx {
                        wire.transmit(0, vec![0; 60]);
                    }
                    ticks += 1;
                    if trap == Some(ticks) {
                        return Poll::Ready(Err(Fault::new("boom\nat tick")));
                    }
                }
            }
            Poll::Pending
        }));
        let port = |id| DeclaredPort {
            id,
            name: format!("p{id}"),
            mac: None,
            mtu: 1500,
        };
        Ok(DeviceInstance {
            ports: vec![port(0), port(1)],
            actor,
            has_counters: true,
            exports: vec![crate::COMMANDS_EXPORT.to_owned()],
            apps: Vec::new(),
        })
    }
}

/// The network's own records about devices' lives, in journal order.
fn lives(network: &Network<'_, Fake>) -> Vec<String> {
    network
        .journal()
        .into_iter()
        .filter_map(|e| match e.record {
            Record::Event { kind, fields }
                if kind.starts_with("device-") || kind == "action" || kind == "heard" =>
            {
                let fields: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
                Some(
                    format!("{}@{} {kind} {}", e.device, e.at, fields.join(" "))
                        .trim_end()
                        .to_owned(),
                )
            }
            _ => None,
        })
        .collect()
}

fn add(network: &mut Network<'_, Fake>, op: Op, placement: Placement) -> usize {
    network.add_op(op, placement).unwrap()
}

fn named(device: &str) -> String {
    device.to_owned()
}

#[test]
fn a_paused_device_misses_time_and_its_overdue_timers_fire_first_in_order() {
    let run = || {
        let fake = Fake::new();
        let mut network = Network::new(&fake, 1);
        network.device("a", "tick=10,15").unwrap();
        network.device("b", "tick=25").unwrap();
        add(
            &mut network,
            Op::PauseDevice {
                device: named("a"),
                link_down: false,
            },
            Placement::StartOf(12),
        );
        add(
            &mut network,
            Op::ResumeDevice { device: named("a") },
            Placement::StartOf(50),
        );
        network.run_until(66).unwrap();
        (fake.log(), lives(&network), network.journal())
    };
    let (log, lives, journal) = run();
    assert_eq!(
        log,
        [
            "a@10 tick 10",
            // Paused from 12 to 50: its 15 and 20 timers are held, b runs on.
            "b@25 tick 25",
            // Resumed at the start of 50: its overdue timers fire first, in the order they
            // came due, then b's event at 50.
            "a@50 tick 15",
            "a@50 tick 10",
            "b@50 tick 25",
            "a@60 tick 10",
            "a@65 tick 15",
        ]
    );
    assert_eq!(
        lives,
        [
            "a@12 device-paused carrier=up",
            "a@50 device-resumed overdue=2 dropped=0",
        ]
    );
    assert_eq!(run().2, journal, "a rerun is the same");
}

#[test]
fn a_paused_device_drops_frames_and_hears_link_changes_when_it_resumes() {
    for link_down in [false, true] {
        let fake = Fake::new();
        let mut network = Network::new(&fake, 1);
        let tx = network.device("tx", "tick=10;tx").unwrap();
        let rx = network.device("rx", "").unwrap();
        let link = network
            .link(tx.port(0), rx.port(0))
            .unwrap()
            .latency(1)
            .id();
        add(
            &mut network,
            Op::PauseDevice {
                device: named("rx"),
                link_down,
            },
            Placement::StartOf(15),
        );
        add(
            &mut network,
            Op::ResumeDevice {
                device: named("rx"),
            },
            Placement::StartOf(45),
        );
        network.run_until(55).unwrap();
        let rx_log: Vec<String> = fake
            .log()
            .into_iter()
            .filter(|l| l.starts_with("rx@") && !l.contains("@0 "))
            .collect();
        let stats = network.link_stats(link);
        if link_down {
            // Its link went down at 15 and up at 45: the frames of 20, 30 and 40 never entered
            // the wire, and the sleeper hears both changes when it wakes.
            assert_eq!(
                rx_log,
                [
                    "rx@11 rx p0",
                    "rx@45 link p0 false",
                    "rx@45 link p0 true",
                    "rx@51 rx p0"
                ]
            );
            assert_eq!(stats.dropped_down[0], 3, "{stats:?}");
            assert_eq!(
                lives(&network)[1],
                "rx@45 device-resumed overdue=0 dropped=0"
            );
            let tx_log: Vec<String> = fake
                .log()
                .into_iter()
                .filter(|l| l.starts_with("tx@") && l.contains("link") && !l.contains("@0 "))
                .collect();
            assert_eq!(tx_log, ["tx@15 link p0 false", "tx@45 link p0 true"]);
        } else {
            // The link stayed up: the frames of 20, 30 and 40 crossed it and were dropped at
            // the sleeping port.
            assert_eq!(rx_log, ["rx@11 rx p0", "rx@51 rx p0"]);
            assert_eq!(stats.dropped_down, [0, 0], "{stats:?}");
            assert_eq!(stats.frames[0], 5, "10, 20, 30, 40 and 50");
            assert_eq!(
                lives(&network)[1],
                "rx@45 device-resumed overdue=0 dropped=3"
            );
        }
    }
}

#[test]
fn a_paused_device_takes_no_control_call_and_keeps_its_stdin() {
    let fake = Fake::new();
    let mut network = Network::new(&fake, 1);
    let a = network.device("a", "").unwrap();
    let pause = |n: &mut Network<'_, Fake>, at| {
        add(
            n,
            Op::PauseDevice {
                device: named("a"),
                link_down: false,
            },
            Placement::StartOf(at),
        )
    };
    let resume_running = add(
        &mut network,
        Op::ResumeDevice { device: named("a") },
        Placement::StartOf(5),
    );
    pause(&mut network, 10);
    let twice = pause(&mut network, 11);
    let command = add(
        &mut network,
        Op::ControlNamed {
            device: named("a"),
            call: crate::DeviceCommand::new("x", "").into_control(),
        },
        Placement::StartOf(12),
    );
    let crash_stopped = add(
        &mut network,
        Op::CrashDevice {
            device: named("nobody"),
            message: "x".into(),
        },
        Placement::StartOf(12),
    );
    add(
        &mut network,
        Op::StdinNamed {
            device: named("a"),
            bytes: b"hi".to_vec(),
        },
        Placement::StartOf(13),
    );
    network.run_until(20).unwrap();
    assert_eq!(network.device_phase(a), DevicePhase::Paused);
    // Between runs: refused, and the network goes on.
    assert!(matches!(network.counters(a), Err(Error::Refused(_))));
    assert!(matches!(
        network.command(a, "x", ""),
        Err(Error::Refused(_))
    ));
    let states = network.op_states();
    let failed = |i: usize| match &states[i] {
        OpState::Failed { message, .. } => message.clone(),
        other => panic!("op {i}: {other:?}"),
    };
    assert_eq!(failed(resume_running), "`a` is not paused");
    assert_eq!(failed(twice), "`a` is paused");
    assert_eq!(failed(command), "`a` is paused");
    assert_eq!(failed(crash_stopped), "no device `nobody`");
    add(
        &mut network,
        Op::ResumeDevice { device: named("a") },
        Placement::StartOf(30),
    );
    network.run_until(40).unwrap();
    assert!(
        fake.log().contains(&"a@30 stdin hi".to_owned()),
        "{:?}",
        fake.log()
    );
    assert_eq!(network.counters(a).unwrap(), Some(Vec::new()));
}

#[test]
fn a_split_network_refuses_pauses_crashes_and_actions() {
    let fake = Fake::new();
    let mut network = Network::new(&fake, 1);
    network.device("a", "").unwrap();
    network.remote_device("far").unwrap();
    network.register_action("noop", |_, _| Ok(()));
    for op in [
        Op::PauseDevice {
            device: named("a"),
            link_down: false,
        },
        Op::ResumeDevice { device: named("a") },
        Op::CrashDevice {
            device: named("a"),
            message: "x".into(),
        },
        Op::Action {
            name: "noop".into(),
            device: named("a"),
            argument: String::new(),
        },
    ] {
        assert!(matches!(
            network.add_op(op, Placement::StartOf(5)),
            Err(Error::Refused(_))
        ));
    }
}

#[test]
fn a_crash_follows_the_one_rule_whatever_raised_it() {
    let fake = Fake::new();
    let mut network = Network::new(&fake, 1);
    let alone = DeviceOptions {
        crash_alone: true,
        ..DeviceOptions::default()
    };
    let a = network
        .device_with_options("a", "tick=10", DeviceConfig::new(), alone.clone())
        .unwrap();
    let peer = network.device("peer", "").unwrap();
    network.link(a.port(0), peer.port(0)).unwrap();
    // A guest trap of a device that crashes alone (its 2nd tick, at 20)...
    network
        .device_with_options("g", "tick=10;trap=2", DeviceConfig::new(), alone)
        .unwrap();
    // ... and an operator's crash of one at 15: both stop alone.
    add(
        &mut network,
        Op::CrashDevice {
            device: named("a"),
            message: "power cut\nsecond line".into(),
        },
        Placement::StartOf(15),
    );
    add(
        &mut network,
        Op::StartDevice { device: named("a") },
        Placement::StartOf(30),
    );
    network.run_until(35).unwrap();
    assert_eq!(
        lives(&network),
        [
            "a@15 device-crashed message=power cut",
            "g@20 device-crashed message=boom",
            "a@30 device-started",
        ]
    );
    assert_eq!(
        network.infra().get("g").unwrap().phase,
        crate::infra::Phase::Crashed
    );
    assert!(fake.log().contains(&"peer@15 link p0 false".to_owned()));
    assert!(fake.log().contains(&"peer@30 link p0 true".to_owned()));
    // An operator's crash of a device that does not crash alone fails the network, as its
    // guest's trap would.
    add(
        &mut network,
        Op::CrashDevice {
            device: named("peer"),
            message: "power cut".into(),
        },
        Placement::EndOf(40),
    );
    match network.run_until(50) {
        Err(Error::Trap {
            device,
            at,
            message,
            ..
        }) => assert_eq!(
            (device.as_str(), at, message.as_str()),
            ("peer", 40, "power cut")
        ),
        other => panic!("{other:?}"),
    }
}

/// Records every life event, journals `heard` on the device, and counts wipes.
#[derive(Default)]
struct Recorder {
    heard: Vec<String>,
    wipes: u32,
}

impl NetworkExtension for Recorder {
    fn device_life(&mut self, life: &DeviceLife<'_>) {
        let what = match life.event {
            LifeEvent::Crashed { message } => format!("crashed {message}"),
            other => format!("{other:?}").to_lowercase(),
        };
        life.journal.push(
            life.at,
            Record::Event {
                kind: "heard".into(),
                fields: vec![("what".into(), what.clone())],
            },
        );
        self.heard.push(format!("{}@{} {what}", life.name, life.at));
    }
}

#[test]
fn extensions_hear_a_devices_life_right_after_its_record() {
    let fake = Fake::new();
    let mut network = Network::new(&fake, 1);
    network.add_extension(Recorder::default());
    network
        .device_with_options(
            "a",
            "",
            DeviceConfig::new(),
            DeviceOptions {
                crash_alone: true,
                ..DeviceOptions::default()
            },
        )
        .unwrap();
    let ops = [
        (
            Op::PauseDevice {
                device: named("a"),
                link_down: true,
            },
            10,
        ),
        (Op::ResumeDevice { device: named("a") }, 20),
        (Op::StopDevice { device: named("a") }, 30),
        (Op::StartDevice { device: named("a") }, 40),
        (
            Op::CrashDevice {
                device: named("a"),
                message: "x".into(),
            },
            50,
        ),
        (Op::StartDevice { device: named("a") }, 60),
        (Op::RemoveDevice { device: named("a") }, 70),
    ];
    for (op, at) in ops {
        add(&mut network, op, Placement::StartOf(at));
    }
    network.run_until(80).unwrap();
    assert_eq!(
        lives(&network),
        [
            "a@10 device-paused carrier=down",
            "a@10 heard what=paused",
            "a@20 device-resumed overdue=0 dropped=0",
            "a@20 heard what=resumed",
            "a@30 device-stopped",
            "a@30 heard what=stopped",
            "a@40 device-started",
            "a@40 heard what=started",
            "a@50 device-crashed message=x",
            "a@50 heard what=crashed x",
            "a@60 device-started",
            "a@60 heard what=started",
            "a@70 device-removed",
            "a@70 heard what=removed",
        ]
    );
    assert_eq!(network.extension::<Recorder>().unwrap().heard.len(), 7);
}

#[test]
fn an_action_runs_at_its_place_changes_extensions_and_places_ops() {
    let fake = Fake::new();
    let mut network = Network::new(&fake, 1);
    network.add_extension(Recorder::default());
    network.device("a", "").unwrap();
    let seen: Log = Log::default();
    let s = seen.clone();
    network.register_action("wipe", move |ctx, call| {
        s.lock().unwrap().push(format!(
            "{} {} {} @{}",
            call.name,
            call.device,
            call.argument,
            ctx.at()
        ));
        ctx.extension_mut::<Recorder>().unwrap().wipes += 1;
        // Stops the device right after, at this instant.
        ctx.add_op(
            Op::StopDevice {
                device: call.device.to_owned(),
            },
            Placement::EndOf(ctx.at()),
        )?;
        Ok(())
    });
    network.register_action("refuse", |_, _| Err("not today".into()));
    assert!(matches!(
        network.add_op(
            Op::Action {
                name: "unknown".into(),
                device: named("a"),
                argument: String::new(),
            },
            Placement::StartOf(1),
        ),
        Err(Error::Refused(_))
    ));
    // At 20: stdin at the start of the instant, the action at its end (it stops `a` then).
    let wipe = add(
        &mut network,
        Op::Action {
            name: "wipe".into(),
            device: named("a"),
            argument: "disk0".into(),
        },
        Placement::EndOf(20),
    );
    add(
        &mut network,
        Op::StdinNamed {
            device: named("a"),
            bytes: b"x".to_vec(),
        },
        Placement::StartOf(20),
    );
    let refused = add(
        &mut network,
        Op::Action {
            name: "refuse".into(),
            device: named("a"),
            argument: String::new(),
        },
        Placement::StartOf(30),
    );
    network.run_until(40).unwrap();
    assert_eq!(*seen.lock().unwrap(), ["wipe a disk0 @20"]);
    assert!(fake.log().contains(&"a@20 stdin x".to_owned()));
    assert_eq!(network.extension::<Recorder>().unwrap().wipes, 1);
    assert_eq!(
        lives(&network),
        [
            "a@20 action name=wipe argument=disk0",
            "a@20 device-stopped",
            "a@20 heard what=stopped",
            "a@30 action name=refuse argument=",
        ]
    );
    let states = network.op_states();
    assert!(matches!(states[wipe], OpState::Applied { at: 20, .. }));
    assert!(matches!(&states[refused], OpState::Failed { message, .. } if message == "not today"));
    // The stop the action placed is an op of its own, applied right after it.
    assert!(matches!(
        states[states.len() - 1],
        OpState::Applied { at: 20, .. }
    ));
}
