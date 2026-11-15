//! The JavaScript backend against a fake JavaScript side written in Rust: sync devices that
//! transmit from inside a host call (re-entrancy), and an async node whose `start`, app `run`
//! and timers complete "later", the way jco completes them between the driver's steps.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use wasmnet_core::{DeclaredPort, DeviceConfig, DeviceId, Level, Nanos, Outcome, Record, pcap};
use wasmnet_web::{CallEnd, Entropy, Instance, JsHost, Network, Registry, RunOutcome, codec};
use wasmnet_wire::Direction;

/// Work the fake JavaScript event loop runs when the driver lets it settle.
type Job = Box<dyn FnOnce(&Registry)>;

#[derive(Clone, Default)]
struct FakeJs {
    registry: Rc<RefCell<Option<Registry>>>,
    later: Rc<RefCell<VecDeque<Job>>>,
    /// Components by device index, from `instantiate`.
    kinds: Rc<RefCell<Vec<String>>>,
    /// Timer id -> (device, app call).
    timers: Rc<RefCell<Vec<(u32, u32, u32)>>>,
    /// Every async export call started, in order.
    calls: Rc<RefCell<Vec<String>>>,
}

impl FakeJs {
    fn registry(&self) -> Registry {
        self.registry.borrow().clone().expect("registry set")
    }

    fn later(&self, job: impl FnOnce(&Registry) + 'static) {
        self.later.borrow_mut().push_back(Box::new(job));
    }

    /// The JavaScript event loop: runs queued jobs until none are left.
    fn settle(&self) {
        loop {
            let job = self.later.borrow_mut().pop_front();
            match job {
                Some(job) => job(&self.registry()),
                None => return,
            }
        }
    }

    fn kind(&self, dev: u32) -> String {
        self.kinds.borrow()[dev as usize].clone()
    }
}

fn port(id: u32) -> DeclaredPort {
    DeclaredPort {
        id,
        name: format!("p{id}"),
        mac: None,
        mtu: 1500,
    }
}

/// A 60-byte Ethernet frame: broadcast, from 02:00:00:00:00:01, a local-experimental
/// EtherType, and eight bytes of the device's seeded entropy.
fn probe(random: u64) -> Vec<u8> {
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    f.extend_from_slice(&[0x88, 0xb5]);
    f.extend_from_slice(&random.to_le_bytes());
    f.resize(60, 0);
    f
}

impl JsHost for FakeJs {
    fn instantiate(
        &self,
        dev: u32,
        _: &str,
        component: &str,
        _: &DeviceConfig,
    ) -> Result<Instance, String> {
        let instance = match component {
            "pinger" | "echo" | "crasher" => Instance {
                ports: vec![port(0)],
                ..Instance::default()
            },
            "napper" => Instance {
                ports: vec![port(0)],
                apps: vec!["nap".to_owned()],
                counters: true,
                lifecycle: true,
            },
            other => return Err(format!("no component {other}")),
        };
        // What JavaScript answers crosses the boundary in the codec's encoding.
        let instance = codec::decode_instance(&codec::encode_instance(&instance))
            .map_err(|e| e.to_string())?;
        let mut kinds = self.kinds.borrow_mut();
        kinds.truncate(dev as usize);
        kinds.push(component.to_owned());
        Ok(instance)
    }

    fn receive(&self, dev: u32, port: u32, _: Nanos, frame: &[u8]) -> Result<(), String> {
        let r = self.registry();
        match self.kind(dev).as_str() {
            // Re-entrant: the actor is mid-poll while the "guest" transmits.
            "echo" => r.transmit(dev, port, frame.to_vec()),
            "crasher" => return Err("boom".to_owned()),
            _ => {
                r.log(dev, Level::Info, format!("got {} bytes", frame.len()));
                r.event(
                    dev,
                    "pong".to_owned(),
                    vec![("len".to_owned(), frame.len().to_string())],
                );
            }
        }
        Ok(())
    }

    fn link_state(&self, _: u32, _: u32, _: bool, _: Nanos) -> Result<(), String> {
        Ok(())
    }

    fn poll(&self, dev: u32, now: Nanos) -> Result<Option<Nanos>, String> {
        if self.kind(dev) == "pinger" && now == 0 {
            let r = self.registry();
            let random = r.random_u64(dev, Entropy::Secure);
            r.transmit(dev, 0, probe(random));
        }
        Ok(None)
    }

    fn counters(&self, _: u32) -> Result<Vec<(String, u64)>, String> {
        Ok(vec![("naps".to_owned(), 1)])
    }

    fn start(&self, dev: u32, call: u32) -> Result<(), String> {
        self.calls.borrow_mut().push(format!("start {dev}"));
        self.later(move |r| r.call_done(dev, call, CallEnd::Ok));
        Ok(())
    }

    fn run_app(&self, dev: u32, app: u32, call: u32) -> Result<(), String> {
        self.calls.borrow_mut().push(format!("run {dev} {app}"));
        let timers = self.timers.clone();
        // The app asks for a 5 ms sleep (a microtask after it was called).
        self.later(move |r| {
            let id = r.timer(dev, 5_000_000);
            timers.borrow_mut().push((id, dev, call));
        });
        Ok(())
    }

    fn timer_fire(&self, timer: u32) {
        let entry = self
            .timers
            .borrow()
            .iter()
            .find(|(t, _, _)| *t == timer)
            .copied();
        if let Some((_, dev, call)) = entry {
            let trap = self.kind(dev) == "napper-trap";
            // The app wakes, reports and returns, a little later (a microtask).
            self.later(move |r| {
                r.event(dev, "napped".to_owned(), vec![]);
                let end = if trap {
                    CallEnd::Trap("unreachable".to_owned())
                } else {
                    CallEnd::Ok
                };
                r.call_done(dev, call, end);
            });
        }
    }
}

fn network(seed: u64) -> (FakeJs, Network<FakeJs>) {
    let js = FakeJs::default();
    let net = Network::new(js.clone(), seed);
    *js.registry.borrow_mut() = Some(net.registry().clone());
    (js, net)
}

/// The JavaScript driver loop of the crate docs.
fn drive(js: &FakeJs, net: &mut Network<FakeJs>, deadline: Option<Nanos>) -> RunOutcome {
    if net.step(net.now()) {
        loop {
            js.settle();
            if net.take_dirty() {
                if !net.step(net.now()) {
                    break;
                }
                continue;
            }
            match net.next_event_time() {
                None => break,
                Some(t) if deadline.is_some_and(|d| t > d) => break,
                Some(t) => {
                    if !net.step(t) {
                        break;
                    }
                }
            }
        }
    }
    net.finish(deadline)
}

/// A pinger and an echo on a 1 ms link.
fn ping_echo(seed: u64) -> (FakeJs, Network<FakeJs>, RunOutcome) {
    let (js, mut net) = network(seed);
    let a = net.device("a", "pinger", DeviceConfig::new()).unwrap();
    let b = net.device("b", "echo", DeviceConfig::new()).unwrap();
    net.link(a.port(0), b.port(0), 1_000_000).unwrap();
    let outcome = drive(&js, &mut net, None);
    (js, net, outcome)
}

fn events(net: &Network<FakeJs>, kind: &str) -> Vec<(Nanos, String)> {
    net.journal()
        .into_iter()
        .filter_map(|e| match e.record {
            Record::Event { kind: k, .. } if k == kind => Some((e.at, e.device)),
            _ => None,
        })
        .collect()
}

#[test]
fn an_echo_over_a_link_has_exact_virtual_timing() {
    let (_, net, outcome) = ping_echo(42);
    assert!(
        matches!(
            outcome,
            RunOutcome::Finished(Outcome::Quiescent { at: 2_000_000, .. })
        ),
        "{outcome:?}"
    );
    let frames = net.frames();
    assert_eq!(frames.len(), 2, "the probe and its echo");
    assert_eq!(frames[0].sent_at, 0);
    assert_eq!(frames[0].from, DeviceId::from_index(0).port(0));
    assert_eq!(
        frames[1].sent_at, 1_000_000,
        "echoed at the instant it arrived"
    );
    assert_eq!(frames[1].from, DeviceId::from_index(1).port(0));
    assert_eq!(frames[0].bytes, frames[1].bytes);
    // The pong reaches the pinger one more latency later.
    assert_eq!(events(&net, "pong"), [(2_000_000, "a".to_owned())]);
    let log = net.journal().into_iter().find_map(|e| match e.record {
        Record::Log { message, .. } => Some((e.at, message)),
        _ => None,
    });
    assert_eq!(log, Some((2_000_000, "got 60 bytes".to_owned())));
    assert_eq!(net.registry().orphans(), 0);
}

#[test]
fn a_links_capture_is_valid_pcapng() {
    let (_, net, _) = ping_echo(42);
    let links = net.links();
    assert_eq!(links.len(), 1);
    assert_eq!(net.link_name(links[0]), "a.0-b.0");
    let capture = pcap::parse(&net.pcap(links[0])).expect("valid pcap-ng");
    assert_eq!(capture.interfaces.len(), 2, "one per end");
    let packets: Vec<_> = capture
        .packets
        .iter()
        .map(|p| (p.interface, p.timestamp, p.data.len(), p.direction))
        .collect();
    // Each end's interface sees a frame leave and arrive, stamped in virtual nanoseconds.
    assert_eq!(
        packets,
        [
            (0, 0, 60, Some(Direction::Outbound)),
            (1, 1_000_000, 60, Some(Direction::Inbound)),
            (1, 1_000_000, 60, Some(Direction::Outbound)),
            (0, 2_000_000, 60, Some(Direction::Inbound)),
        ]
    );
}

#[test]
fn the_same_seed_gives_the_same_bytes() {
    let run = |seed| {
        let (_, net, outcome) = ping_echo(seed);
        let pcap = net.pcap(net.links()[0]);
        (pcap, codec::encode_journal(&net.journal()), outcome)
    };
    let first = run(7);
    assert_eq!(first, run(7));
    // The probe carries the pinger's seeded entropy, so another seed gives other bytes.
    assert_ne!(first.0, run(8).0);
}

#[test]
fn the_journal_comes_out_in_increments() {
    let (js, mut net) = network(1);
    let a = net.device("a", "pinger", DeviceConfig::new()).unwrap();
    let b = net.device("b", "echo", DeviceConfig::new()).unwrap();
    net.link(a.port(0), b.port(0), 1_000_000).unwrap();
    let mut taken = Vec::new();
    let mut next = 0;
    assert!(net.step(0));
    js.settle();
    while let Some(t) = net.next_event_time() {
        assert!(net.step(t));
        js.settle();
        let rows = net.journal_from(next);
        next += rows.len();
        taken.extend(rows);
    }
    assert!(!taken.is_empty());
    assert_eq!(taken, net.journal());
}

#[test]
fn an_async_nodes_calls_complete_later() {
    let (js, mut net) = network(3);
    let n = net
        .device(
            "n",
            "napper",
            DeviceConfig::from([("app.nap.for".to_owned(), "5ms".to_owned())]),
        )
        .unwrap();
    // The config is served to the device's imports.
    let r = net.registry().clone();
    assert_eq!(r.config_get(0, "app.nap.for").as_deref(), Some("5ms"));
    assert_eq!(r.config_get(0, "missing"), None);

    // The first round starts `start()` only; the app runs once JavaScript reported its end.
    assert!(net.step(0));
    assert_eq!(*js.calls.borrow(), ["start 0"]);
    js.settle();
    assert!(net.take_dirty(), "the completion woke the node");
    assert!(net.step(net.now()));
    assert_eq!(*js.calls.borrow(), ["start 0", "run 0 0"]);

    // Run to a deadline before the app's timer: the run is resumable.
    let early = drive(&js, &mut net, Some(3_000_000));
    assert_eq!(
        early,
        RunOutcome::Finished(Outcome::Deadline {
            at: 3_000_000,
            pending_events: 1
        })
    );
    assert!(events(&net, "app-exit").is_empty());

    let outcome = drive(&js, &mut net, None);
    let RunOutcome::Finished(Outcome::Quiescent { at, daemons, .. }) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(at, 5_000_000);
    assert!(daemons.is_empty(), "the app returned: {daemons:?}");
    assert_eq!(events(&net, "napped"), [(5_000_000, "n".to_owned())]);
    assert_eq!(events(&net, "app-exit"), [(5_000_000, "n".to_owned())]);
    let exit = net.journal().into_iter().find_map(|e| match e.record {
        Record::Event { kind, fields } if kind == "app-exit" => Some(fields),
        _ => None,
    });
    assert_eq!(
        exit,
        Some(vec![
            ("app".to_owned(), "nap".to_owned()),
            ("status".to_owned(), "ok".to_owned())
        ])
    );
    assert_eq!(net.counters(n), Ok(Some(vec![("naps".to_owned(), 1)])));
    assert_eq!(net.registry().orphans(), 0);
}

#[test]
fn a_device_that_fails_to_instantiate_is_refused_and_the_network_goes_on() {
    let (js, mut net) = network(5);
    let err = net
        .device("x", "nonesuch", DeviceConfig::new())
        .unwrap_err();
    assert!(err.contains("nonesuch") && err.contains("`x`"), "{err}");
    assert!(net.devices().is_empty());
    // Nothing of it is left behind: its index is the next device's.
    let a = net.device("a", "pinger", DeviceConfig::new()).unwrap();
    assert_eq!(a.index(), 0);
    let b = net.device("b", "echo", DeviceConfig::new()).unwrap();
    assert!(
        net.link(a.port(0), b.port(7), 0).is_err(),
        "an undeclared port"
    );
    assert!(
        net.link(a.port(0), DeviceId::from_index(9).port(0), 0)
            .is_err(),
        "a device that does not exist"
    );
    net.link(a.port(0), b.port(0), 1_000).unwrap();
    let outcome = drive(&js, &mut net, None);
    assert!(matches!(
        outcome,
        RunOutcome::Finished(Outcome::Quiescent { .. })
    ));
    assert_eq!(net.frames().len(), 2);
}

#[test]
fn a_trap_fails_the_network_at_its_instant() {
    let (js, mut net) = network(5);
    let a = net.device("a", "pinger", DeviceConfig::new()).unwrap();
    let c = net.device("c", "crasher", DeviceConfig::new()).unwrap();
    net.link(a.port(0), c.port(0), 1_000_000).unwrap();
    let outcome = drive(&js, &mut net, None);
    let RunOutcome::Failed { at, message } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(at, 1_000_000);
    assert!(
        message.contains("boom") && message.contains("`c`"),
        "{message}"
    );
    assert!(!net.step(2_000_000), "a failed network stays failed");
    assert!(net.counters(a).is_err());
}

#[test]
fn an_async_trap_reported_later_fails_the_network() {
    let (js, mut net) = network(5);
    // The same node, but its app traps when it wakes.
    net.device("n", "napper", DeviceConfig::new()).unwrap();
    js.kinds.borrow_mut()[0] = "napper-trap".to_owned();
    let outcome = drive(&js, &mut net, None);
    let RunOutcome::Failed { at, message } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(at, 5_000_000);
    assert!(message.contains("unreachable"), "{message}");
}
