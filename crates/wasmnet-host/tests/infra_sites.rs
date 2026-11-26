//! In-world controllers (`wasmnet:infra`) in a network split over two sites.
//!
//! A controller creates, commands, stops, removes and re-creates devices on its own site while
//! the network runs; traffic reaches them across the WAN link. The split run, driven in
//! lockstep on this thread with every message through the site-sync wire format, must merge
//! into exactly the unsplit run: journal, frame log, link transitions, every link's name,
//! counters and capture, the outcome, every device's counters, the operator events' states,
//! and each controller's whole view of the device table (`list` and the full `watch` feed).
//!
//! The controllers are the `infra-script` fixture (a controller with a script of calls at set
//! virtual times).
//!
//! ```text
//! one controller:                site 0                  |            site 1
//!   ctl ~> r1 (router) ── sw-a ═══════ 1 ms WAN ═══════ sw-b ── gw (router) ── client
//!          └── web (http-server)                         |
//!
//! two controllers:   ctl-a ~> a-web, a-get ── sw-a ═══ WAN ═══ sw-b ── b-web, b-get <~ ctl-b
//! ```
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`).

mod support;

use std::collections::VecDeque;

use sha2::{Digest as _, Sha256};
use support::{built, config, events, field, transcript};
use wasmnet_det_cbor::Value;
use wasmnet_host::sim::infra::{Change, DeviceView};
use wasmnet_host::sim::{CREATOR_RANGE, DeviceCommand, Op, OpState, Placement, SupplyLimits};
use wasmnet_host::{
    DeviceConfig, DeviceId, DeviceOptions, FrameRecord, ImportPolicy, JournalEntry, LinkTransition,
    Nanos, Network, sim,
};
use wasmnet_sites::{self as sites, Msg, SiteRecords, SiteSync, Step};

const US: Nanos = 1_000;
const MS: Nanos = 1_000_000;
/// The WAN link's latency: the lookahead.
const WAN: Nanos = MS;

/// One device of the network's description.
struct Dev {
    name: &'static str,
    /// The file `cargo xtask build` wrote (`node-http-get`), and the catalog name it has.
    file: &'static str,
    component: &'static str,
    config: DeviceConfig,
    options: DeviceOptions,
    site: usize,
}

/// A setup link: `((device, port), (device, port), latency)`, by device index.
type SetupLink = ((usize, u32), (usize, u32), Nanos);

/// A network: devices (built in this order on every site), setup links, timed operator
/// events, and the deadline.
struct Plan {
    devices: Vec<Dev>,
    links: Vec<SetupLink>,
    ops: Vec<(Nanos, usize, DeviceCommand)>,
    deadline: Nanos,
}

/// Everything the equivalence compares.
#[derive(Debug, PartialEq)]
struct Run {
    outcome: String,
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    transitions: Vec<LinkTransition>,
    /// Per link: name, counters, capture digest.
    links: Vec<String>,
    /// Per device that reports counters, by name.
    counters: Vec<(String, Vec<(String, u64)>)>,
    /// The operator events' states (on the site of the device each one names), without the
    /// boundary ordinal (`events`), which counts only the events of that site.
    op_states: Vec<OpState>,
    /// Each controller's view: `list` of everything, then the whole `watch` feed.
    tables: Vec<(String, String)>,
    /// Every device's number in event keys, by name (the devices that run on each site).
    numbers: Vec<(String, u32)>,
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn infra(prefix: Option<&str>) -> DeviceOptions {
    let mut options = DeviceOptions::default().infra(true);
    options.infra_prefix = prefix.map(str::to_owned);
    options
}

/// A device spec for `devices.apply`: a component, its config and its cables.
fn spec(component: &str, cfg: &[(&str, &str)], wire: &[(u64, &str)]) -> Vec<u8> {
    let config = cfg
        .iter()
        .map(|(k, v)| (Value::text(*k), Value::text(*v)))
        .collect();
    let cables = wire
        .iter()
        .map(|(port, to)| {
            Value::Map(vec![
                (Value::text("port"), Value::Uint(*port)),
                (Value::text("to"), Value::text(*to)),
                (Value::text("latency"), Value::Uint(100 * US)),
            ])
        })
        .collect();
    Value::Map(vec![
        (Value::text("component"), Value::text(component)),
        (Value::text("config"), Value::Map(config)),
        (Value::text("wire"), Value::Array(cables)),
    ])
    .encode()
}

/// An `infra-script` controller's config: one step per line.
fn script(steps: &[String]) -> DeviceConfig {
    steps
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("step.{n}"), s.clone()))
        .collect()
}

fn controller(name: &'static str, prefix: Option<&str>, steps: &[String], site: usize) -> Dev {
    Dev {
        name,
        file: "infra_script",
        component: "infra-script",
        config: script(steps),
        options: infra(prefix),
        site,
    }
}

fn switch(name: &'static str, ports: &str, site: usize) -> Dev {
    Dev {
        name,
        file: "switch",
        component: "switch",
        config: config(&[("ports", ports)]),
        options: DeviceOptions::default(),
        site,
    }
}

// ---- the networks ----

/// One controller, on site 0. `ctl` creates the router `r1` (to `sw-a`) and the web server
/// `web` behind it, gives `r1` the route back to the client's network (without it no answer
/// gets back), then stops, removes and re-creates `web` while the client on site 1 fetches
/// from it five times through `gw` and the WAN link. An operator event adds a host route to
/// `gw` on site 1 meanwhile. `wire_web_to` is where `web`'s cable goes (`r1:1`; the refusal
/// test sends it to another site).
fn one_controller(wire_web_to: &str) -> Plan {
    let r1 = spec(
        "router",
        &[
            ("mac", "02:00:00:00:fe:10"),
            ("port0.ipv4", "10.0.2.1/24"),
            ("port1.ipv4", "10.0.1.1/24"),
        ],
        &[(0, "sw-a")],
    );
    let web = spec(
        "node:http-server",
        &[
            ("mac", "02:00:00:00:01:10"),
            ("ipv4", "10.0.1.10/24"),
            ("ipv4-gateway", "10.0.1.1"),
        ],
        &[(0, wire_web_to)],
    );
    let steps = [
        format!("0ms apply r1 {}", hex(&r1)),
        format!("0ms apply web {}", hex(&web)),
        "100ms control r1 route-add 10.0.3.0/24 via 10.0.2.2".to_owned(),
        "700ms stop web".to_owned(),
        "800ms remove web".to_owned(),
        format!("900ms apply web {}", hex(&web)),
    ];
    Plan {
        devices: vec![
            switch("sw-a", "4", 0),
            controller("ctl", None, &steps, 0),
            switch("sw-b", "3", 1),
            Dev {
                name: "gw",
                file: "router",
                component: "router",
                config: config(&[
                    ("mac", "02:00:00:00:fe:20"),
                    ("port0.ipv4", "10.0.2.2/24"),
                    ("port1.ipv4", "10.0.3.1/24"),
                    ("routes", "10.0.1.0/24 via 10.0.2.1"),
                ]),
                options: DeviceOptions::default(),
                site: 1,
            },
            Dev {
                name: "client",
                file: "node-http-get",
                component: "node:http-get",
                config: config(&[
                    ("mac", "02:00:00:00:03:10"),
                    ("ipv4", "10.0.3.10/24"),
                    ("ipv4-gateway", "10.0.3.1"),
                    ("app.http-get.url", "http://10.0.1.10/"),
                    ("app.http-get.start", "200ms"),
                    ("app.http-get.interval", "300ms"),
                    ("app.http-get.repeat", "5"),
                ]),
                options: DeviceOptions::default(),
                site: 1,
            },
        ],
        links: vec![
            ((0, 0), (2, 0), WAN),
            ((3, 0), (2, 1), 100 * US),
            ((4, 0), (3, 1), 100 * US),
        ],
        ops: vec![(
            1_200 * MS,
            3,
            DeviceCommand::new("route-add", "10.0.1.10/32 via 10.0.2.1"),
        )],
        deadline: 4_000 * MS,
    }
}

/// A controller on each site, each with a name prefix. Each creates a web server and a client
/// of the other site's server: `b-get` fetches from `a-web`, `a-get` from `b-web`, across the
/// WAN link. `ctl-b` stops, removes and re-creates `b-web` while `a-get` fetches from it. The
/// creations interleave between the creators (a-web, b-web, b-get, a-get, b-web again), so
/// the merge must put them back into the unsplit order. `extra` adds a step to `ctl-a` and to
/// `ctl-b` (the refusal tests); `prefixes` turns the prefixes off (refused when split).
fn two_controllers(extra: [Option<String>; 2], prefixes: bool) -> Plan {
    let [extra_a, extra_b] = extra;
    let web = |mac: &str, ip: &str, to: &str| {
        spec(
            "node:http-server",
            &[("mac", mac), ("ipv4", ip)],
            &[(0, to)],
        )
    };
    let get = |mac: &str, ip: &str, url: &str, to: &str| {
        spec(
            "node:http-get",
            &[
                ("mac", mac),
                ("ipv4", ip),
                ("app.http-get.url", url),
                ("app.http-get.start", "100ms"),
                ("app.http-get.interval", "250ms"),
                ("app.http-get.repeat", "6"),
            ],
            &[(0, to)],
        )
    };
    let a_web = web("02:00:00:00:0a:10", "10.0.0.10/24", "sw-a");
    let a_get = get(
        "02:00:00:00:0a:11",
        "10.0.0.11/24",
        "http://10.0.0.20/",
        "sw-a",
    );
    let b_web = web("02:00:00:00:0b:20", "10.0.0.20/24", "sw-b");
    let b_get = get(
        "02:00:00:00:0b:21",
        "10.0.0.21/24",
        "http://10.0.0.10/",
        "sw-b",
    );
    let mut a = vec![
        format!("0ms apply a-web {}", hex(&a_web)),
        format!("300ms apply a-get {}", hex(&a_get)),
    ];
    a.extend(extra_a);
    let mut b = vec![
        format!("0ms apply b-web {}", hex(&b_web)),
        format!("100ms apply b-get {}", hex(&b_get)),
        "700ms stop b-web".to_owned(),
        "800ms remove b-web".to_owned(),
        format!("900ms apply b-web {}", hex(&b_web)),
    ];
    b.extend(extra_b);
    let prefix = |p| prefixes.then_some(p);
    Plan {
        devices: vec![
            switch("sw-a", "6", 0),
            controller("ctl-a", prefix("a-"), &a, 0),
            switch("sw-b", "6", 1),
            controller("ctl-b", prefix("b-"), &b, 1),
        ],
        links: vec![((0, 0), (2, 0), WAN)],
        ops: Vec::new(),
        deadline: 3_000 * MS,
    }
}

/// A `replicas` controller on site 0 that waits on `changes.wait` (`wake`): it keeps two
/// `node:http-get` instances, each fetching twice from `server` on site 1 across the WAN link
/// and then exiting. Its own creations and the instances' exits wake it.
fn waking_controller() -> Plan {
    Plan {
        devices: vec![
            switch("sw-a", "6", 0),
            Dev {
                name: "ctl",
                file: "node-replicas",
                component: "node:replicas",
                config: config(&[
                    ("mac", "02:00:00:00:01:05"),
                    ("ipv4", "10.0.0.5/24"),
                    ("app.replicas.replicas", "2"),
                    ("app.replicas.period", "1s"),
                    ("app.replicas.wake", "true"),
                    ("app.replicas.prefix", "get"),
                    ("app.replicas.template.component", "node:http-get"),
                    ("app.replicas.template.config.mac", "02:00:00:00:01:{n+10}"),
                    ("app.replicas.template.config.ipv4", "10.0.0.{n+10}/24"),
                    (
                        "app.replicas.template.config.app.http-get.url",
                        "http://10.0.0.50/",
                    ),
                    ("app.replicas.template.config.app.http-get.start", "50ms"),
                    (
                        "app.replicas.template.config.app.http-get.interval",
                        "100ms",
                    ),
                    ("app.replicas.template.config.app.http-get.repeat", "2"),
                    ("app.replicas.template.wire.0.port", "0"),
                    ("app.replicas.template.wire.0.to", "sw-a"),
                ]),
                options: infra(None),
                site: 0,
            },
            switch("sw-b", "4", 1),
            Dev {
                name: "server",
                file: "node-http-server",
                component: "node:http-server",
                config: config(&[("mac", "02:00:00:00:02:50"), ("ipv4", "10.0.0.50/24")]),
                options: DeviceOptions::default(),
                site: 1,
            },
        ],
        links: vec![
            ((0, 0), (2, 0), WAN),
            ((1, 0), (0, 1), 100 * US),
            ((3, 0), (2, 1), 100 * US),
        ],
        ops: Vec::new(),
        deadline: 3_000 * MS,
    }
}

/// A `replicas` controller on site 0 that fetches its instances' component from `store` on site
/// 1 across the WAN link (`template.fetch`), supplies its bytes and keeps two `web-<n>` made
/// from its digest on its own site; `client` on site 1 fetches from both across the WAN link.
fn supplying_controller() -> Plan {
    let web = std::fs::read(built().path("node-http-server")).expect("a built node");
    let mut store = config(&[("mac", "02:00:00:00:02:09"), ("ipv4", "10.0.0.9/24")]);
    store.insert(
        "app.http-server.route.web.path".to_owned(),
        "/web.wasm".to_owned(),
    );
    store.insert(
        "app.http-server.route.web.body-base64".to_owned(),
        support::base64(&web),
    );
    Plan {
        devices: vec![
            switch("sw-a", "6", 0),
            Dev {
                name: "ctl",
                file: "node-replicas",
                component: "node:replicas",
                config: config(&[
                    ("mac", "02:00:00:00:01:05"),
                    ("ipv4", "10.0.0.5/24"),
                    ("app.replicas.replicas", "2"),
                    ("app.replicas.period", "200ms"),
                    ("app.replicas.template.fetch", "http://10.0.0.9/web.wasm"),
                    (
                        "app.replicas.template.digest",
                        &format!("sha256:{}", sha(&web)),
                    ),
                    ("app.replicas.template.config.mac", "02:00:00:00:01:{n+10}"),
                    ("app.replicas.template.config.ipv4", "10.0.0.{n+10}/24"),
                    ("app.replicas.template.wire.0.port", "0"),
                    ("app.replicas.template.wire.0.to", "sw-a"),
                ]),
                options: infra(None).infra_supply(SupplyLimits::default()),
                site: 0,
            },
            switch("sw-b", "4", 1),
            Dev {
                name: "store",
                file: "node-http-server",
                component: "node:http-server",
                config: store,
                // Decoding the base64 body costs more than an instant's default fuel.
                options: DeviceOptions::default().fuel_per_instant(4_000_000_000),
                site: 1,
            },
            Dev {
                name: "client",
                file: "node-http-get",
                component: "node:http-get",
                config: config(&[
                    ("mac", "02:00:00:00:02:03"),
                    ("ipv4", "10.0.0.3/24"),
                    ("app.http-get.urls", "http://10.0.0.11/,http://10.0.0.12/"),
                    ("app.http-get.start", "1s"),
                ]),
                options: DeviceOptions::default(),
                site: 1,
            },
        ],
        links: vec![
            ((0, 0), (2, 0), WAN),
            ((1, 0), (0, 1), 100 * US),
            ((3, 0), (2, 1), 100 * US),
            ((4, 0), (2, 2), 100 * US),
        ],
        ops: Vec::new(),
        deadline: 1_500 * MS,
    }
}

// ---- running a plan ----

/// The devices of `plan` as site `site` builds them (`None`: the unsplit network): its own,
/// and the others as placeholders with their description. [`wire`] adds the rest.
fn build(plan: &Plan, seed: u64, site: Option<usize>) -> (Network<'static>, Vec<DeviceId>) {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    network.set_component_resolver(Box::new(move |name, instantiate| {
        let file = match name {
            "router" => "router",
            "node:http-server" => "node-http-server",
            "node:http-get" => "node-http-get",
            other => return Err(sim::Error::Refused(format!("no component {other}"))),
        };
        instantiate(&b.load(file))
    }));
    network.set_infra_catalog(
        ["router", "node:http-server", "node:http-get"]
            .map(String::from)
            .to_vec(),
    );
    // Only `supplying_controller`'s `ctl` is granted to supply components.
    network.set_supply_admission(ImportPolicy::devices().admission());
    let mut ids = Vec::new();
    for d in &plan.devices {
        let id = if site.is_none_or(|s| s == d.site) {
            network
                .device_with_options(d.name, &b.load(d.file), d.config.clone(), d.options.clone())
                .unwrap_or_else(|e| panic!("{}: {e}", d.name))
        } else {
            network
                .remote_device_with(d.name, d.config.clone(), d.options.clone())
                .unwrap_or_else(|e| panic!("{}: {e}", d.name))
        };
        network.set_device_component(id, d.component);
        ids.push(id);
    }
    (network, ids)
}

/// Wires `plan`'s links and places its operator events (every site places them all).
fn wire(plan: &Plan, network: &mut Network<'static>, ids: &[DeviceId]) {
    for ((a, pa), (b, pb), latency) in &plan.links {
        network
            .link(ids[*a].port(*pa), ids[*b].port(*pb))
            .unwrap()
            .latency(*latency);
    }
    for (at, device, command) in &plan.ops {
        network
            .add_op(
                Op::control(ids[*device], command.clone().into_control()),
                Placement::StartOf(*at),
            )
            .unwrap();
    }
}

/// Controller `name`'s view of the table as text: `list`, then the whole `watch` feed.
fn table(network: &Network, name: &str) -> String {
    let line = |d: &DeviceView| {
        format!(
            "{} uid={} gen={} rv={} labels={:?} owner={:?} phase={:?} target={:?} since={} \
             apps={:?} message={:?} spec={}",
            d.name,
            d.uid,
            d.generation,
            d.rv,
            d.labels,
            d.owner,
            d.phase,
            d.target,
            d.since,
            d.apps,
            d.message,
            sha(&d.spec)
        )
    };
    let (rv, items) = network.infra().list_for(name, &[]);
    let mut out = format!("list rv={rv}\n");
    for d in &items {
        out += &format!("  {}\n", line(d));
    }
    let (rv, changes) = network.infra().watch_for(name, &[], 0, u32::MAX);
    out += &format!("watch rv={rv}\n");
    for Change { kind, device, .. } in &changes {
        out += &format!("  {kind:?} {}\n", line(device));
    }
    out
}

/// The numbers of the devices of `network` that run here.
fn numbers(network: &Network) -> Vec<(String, u32)> {
    network
        .devices()
        .into_iter()
        .filter(|&d| !network.is_remote(d))
        .map(|d| (network.device_name(d).to_owned(), network.device_number(d)))
        .collect()
}

/// What the devices of `network` that run here report: their counters, by name.
fn counters(network: &mut Network) -> Vec<(String, Vec<(String, u64)>)> {
    let mut out = Vec::new();
    for d in network.devices() {
        if network.is_remote(d) || network.device_phase(d) != sim::DevicePhase::Running {
            continue;
        }
        if let Some(c) = network.counters(d).unwrap() {
            out.push((network.device_name(d).to_owned(), c));
        }
    }
    out
}

fn controllers(plan: &Plan) -> Vec<&'static str> {
    plan.devices
        .iter()
        .filter(|d| d.options.infra)
        .map(|d| d.name)
        .collect()
}

/// The unsplit run.
fn run_whole(plan: &Plan, seed: u64) -> Run {
    let (mut network, ids) = build(plan, seed, None);
    wire(plan, &mut network, &ids);
    let outcome = network.run_until(plan.deadline);
    let journal = network.journal();
    let outcome = format!("{:?}", outcome.map_err(|e| e.to_string()));
    let links = network
        .links()
        .into_iter()
        .map(|l| {
            format!(
                "{} {:?} {}",
                network.link_name(l),
                network.link_stats(l),
                sha(&network.pcap(l))
            )
        })
        .collect();
    let mut counters = counters(&mut network);
    counters.sort();
    let mut numbers = numbers(&network);
    numbers.sort();
    Run {
        outcome,
        frames: network.frames(),
        transitions: network.link_transitions(),
        links,
        counters,
        op_states: network
            .op_states()
            .into_iter()
            .map(without_ordinal)
            .collect(),
        tables: controllers(plan)
            .into_iter()
            .map(|c| (c.to_owned(), table(&network, c)))
            .collect(),
        numbers,
        journal,
    }
}

/// An operator event's state without its boundary ordinal: a site counts only its own
/// events.
fn without_ordinal(state: OpState) -> OpState {
    match state {
        OpState::Applied { at, .. } => OpState::Applied { at, events: 0 },
        OpState::Failed { at, message, .. } => OpState::Failed {
            at,
            events: 0,
            message,
        },
        other => other,
    }
}

/// Through the wire format, as a carrier would move it.
fn carry(m: Msg) -> Msg {
    Msg::decode(&m.encode()).expect("a message decodes")
}

/// The split run: both sites on this thread in lockstep, every message through the wire
/// format, RECORDS too. `Err((site, now, message))` if a site's run failed.
fn run_split(plan: &Plan, seed: u64) -> Result<Run, (usize, Nanos, String)> {
    let (mut nets, ids): (Vec<Network<'static>>, Vec<Vec<DeviceId>>) =
        (0..2).map(|s| build(plan, seed, Some(s))).unzip();
    // Each site's HELLO before the links are wired.
    let hellos: Vec<Msg> = nets.iter().map(|n| carry(sites::hello(n))).collect();
    for (s, network) in nets.iter_mut().enumerate() {
        sites::apply_hello(network, &hellos[1 - s]).unwrap();
        wire(plan, network, &ids[s]);
    }
    let mut sync = [
        SiteSync::new(WAN, Some(plan.deadline)),
        SiteSync::new(WAN, Some(plan.deadline)),
    ];
    let mut inbox: [VecDeque<Msg>; 2] = Default::default();
    let mut window = [true, true];
    let mut done = [false, false];
    while !(done[0] && done[1]) {
        let mut progress = false;
        for i in 0..2 {
            if done[i] {
                continue;
            }
            if window[i] {
                let out = sync[i]
                    .window(&mut nets[i])
                    .map_err(|e| (i, nets[i].now(), e.to_string()))?;
                for m in out {
                    inbox[1 - i].push_back(carry(m));
                }
                window[i] = false;
                progress = true;
            }
            while let Some(m) = inbox[i].pop_front() {
                progress = true;
                match sync[i]
                    .handle(&mut nets[i], m)
                    .map_err(|e| (i, nets[i].now(), e.to_string()))?
                {
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
        let outcome = sync[i]
            .finish(&mut nets[i])
            .map_err(|e| (i, nets[i].now(), e.to_string()))?;
        let r = SiteRecords::collect(&nets[i], Ok(outcome));
        match carry(Msg::Records(Box::new(r))) {
            Msg::Records(r) => records.push(*r),
            other => panic!("{other:?}"),
        }
    }
    let names: Vec<String> = plan.devices.iter().map(|d| d.name.to_owned()).collect();
    let merged = sites::merge([&records[0], &records[1]], &names, Some(plan.deadline))
        .expect("the records merge");
    let links = merged
        .link_infos
        .iter()
        .zip(&merged.links)
        .map(|(info, (stats, pcap))| format!("{} {stats:?} {}", info.name, sha(pcap)))
        .collect();
    let mut counters: Vec<_> = nets.iter_mut().flat_map(counters).collect();
    counters.sort();
    let mut numbers: Vec<_> = nets.iter().flat_map(numbers).collect();
    numbers.sort();
    // Each operator event from the site of the device it names.
    let site_of = |device: usize| plan.devices[device].site;
    let op_states = plan
        .ops
        .iter()
        .enumerate()
        .map(|(i, (_, device, _))| without_ordinal(nets[site_of(*device)].op_states()[i].clone()))
        .collect();
    let tables = plan
        .devices
        .iter()
        .filter(|d| d.options.infra)
        .map(|d| (d.name.to_owned(), table(&nets[d.site], d.name)))
        .collect();
    Ok(Run {
        outcome: format!("{:?}", merged.outcome.map_err(|(_, m)| m)),
        journal: merged.journal,
        frames: merged.frames,
        transitions: merged.transitions,
        links,
        counters,
        op_states,
        tables,
        numbers,
    })
}

/// Compares two runs field by field, so a failure names what differs.
fn assert_same(whole: &Run, split: &Run, label: &str) {
    assert_eq!(whole.outcome, split.outcome, "{label}: outcome");
    if whole.journal != split.journal {
        let at = whole
            .journal
            .iter()
            .zip(&split.journal)
            .position(|(a, b)| a != b)
            .unwrap_or(whole.journal.len().min(split.journal.len()));
        panic!(
            "{label}: journals differ at entry {at} ({} vs {} entries)\nunsplit:\n{}\nsplit:\n{}",
            whole.journal.len(),
            split.journal.len(),
            transcript(&whole.journal[at.saturating_sub(3)..(at + 3).min(whole.journal.len())]),
            transcript(&split.journal[at.saturating_sub(3)..(at + 3).min(split.journal.len())]),
        );
    }
    if whole.frames != split.frames {
        let at = whole
            .frames
            .iter()
            .zip(&split.frames)
            .position(|(a, b)| a != b);
        panic!(
            "{label}: frame logs differ ({} vs {} frames), first at {at:?}: {:?} vs {:?}",
            whole.frames.len(),
            split.frames.len(),
            at.map(|i| &whole.frames[i]),
            at.map(|i| &split.frames[i]),
        );
    }
    assert_eq!(whole.transitions, split.transitions, "{label}: transitions");
    assert_eq!(whole.links, split.links, "{label}: links");
    assert_eq!(whole.counters, split.counters, "{label}: counters");
    assert_eq!(whole.op_states, split.op_states, "{label}: operator events");
    assert_eq!(whole.numbers, split.numbers, "{label}: device numbers");
    for ((name, a), (_, b)) in whole.tables.iter().zip(&split.tables) {
        assert_eq!(a, b, "{label}: {name}'s view of the device table");
    }
    assert_eq!(whole, split, "{label}");
}

// ---- the tests ----

#[test]
fn one_controller_on_one_site_matches_the_unsplit_run() {
    let plan = one_controller("r1:1");
    for seed in [42, 7] {
        let whole = run_whole(&plan, seed);
        let log = transcript(&whole.journal);
        // The run did what the story says: five fetches, all answered but the one made
        // while `web` was away; the route command applied (without it nothing comes back);
        // `web` created twice; the operator's route on `gw`.
        let summary = events(&whole.journal, "client", "http-get-summary");
        assert_eq!(summary.len(), 1, "seed {seed}:\n{log}");
        assert_eq!(
            (field(&summary[0], "ok"), field(&summary[0], "failed")),
            ("4", "1"),
            "seed {seed}:\n{log}"
        );
        assert_eq!(
            events(&whole.journal, "r1", "route-added").len(),
            1,
            "{log}"
        );
        assert_eq!(
            events(&whole.journal, "gw", "route-added").len(),
            1,
            "{log}"
        );
        assert_eq!(
            events(&whole.journal, "web", "device-added").len(),
            2,
            "{log}"
        );
        assert_eq!(
            events(&whole.journal, "web", "device-stopped").len(),
            1,
            "{log}"
        );
        assert_eq!(
            events(&whole.journal, "web", "device-removed").len(),
            1,
            "{log}"
        );
        assert!(
            whole.links.iter().any(|l| l.starts_with("web.0-r1.1-2 ")),
            "the re-created web's cable has a fresh name: {:?}",
            whole.links
        );
        assert!(matches!(whole.op_states[0], OpState::Applied { .. }));
        // One creator: the created devices' numbers are their indices, as before.
        let created: Vec<_> = whole.numbers.iter().filter(|(_, k)| *k >= 5).collect();
        assert_eq!(
            created,
            [
                &("r1".to_owned(), 5),
                &("web".to_owned(), 6),
                &("web".to_owned(), 7)
            ]
        );

        let split = run_split(&plan, seed).unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        assert_same(&whole, &split, &format!("seed {seed}"));
        let again = run_split(&plan, seed).unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        assert_eq!(
            split, again,
            "seed {seed}: the split rerun is byte-identical"
        );
    }
}

#[test]
fn a_controller_on_each_site_matches_the_unsplit_run() {
    let plan = two_controllers([None, None], true);
    for seed in [42, 7] {
        let whole = run_whole(&plan, seed);
        let log = transcript(&whole.journal);
        for client in ["a-get", "b-get"] {
            let done = events(&whole.journal, client, "http-get-done");
            assert_eq!(done.len(), 6, "seed {seed}, {client}:\n{log}");
        }
        // Numbers follow the creator: `ctl-b`'s first device is number 4 + CREATOR_RANGE
        // although it was the network's sixth device; the re-created `b-web` is its third.
        let number = |name: &str| {
            whole
                .numbers
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, k)| *k)
                .collect::<Vec<_>>()
        };
        assert_eq!(number("a-web"), [4]);
        assert_eq!(number("a-get"), [5]);
        assert_eq!(number("b-web"), [4 + CREATOR_RANGE, 6 + CREATOR_RANGE]);
        assert_eq!(number("b-get"), [5 + CREATOR_RANGE]);
        // Each controller sees the network's own devices and its own.
        let b_view = &whole.tables[1].1;
        assert!(b_view.contains("b-get uid=") && !b_view.contains("a-web uid="));

        let split = run_split(&plan, seed).unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        assert_same(&whole, &split, &format!("seed {seed}"));
        let again = run_split(&plan, seed).unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        assert_eq!(
            split, again,
            "seed {seed}: the split rerun is byte-identical"
        );
    }
}

/// A cable to a device the network was built with on another site cannot be wired on the
/// controller's site: the split run fails at the request's event, with the same site, instant
/// and message every time, where the unsplit run wires it. A cable to another controller's
/// device is refused by the rule of cables, the same split and unsplit.
#[test]
fn a_cable_to_another_site_fails_the_split_run_deterministically() {
    // `web`'s cable to `sw-b`, a device the network was built with, on site 1.
    let plan = one_controller("sw-b");
    let whole = run_whole(&plan, 42);
    assert!(
        events(&whole.journal, "web", "link-added")
            .iter()
            .any(|f| field(f, "link") == "web.0-sw-b.2"),
        "the unsplit network wires it"
    );
    let failure = |plan: &Plan| match run_split(plan, 42) {
        Ok(_) => panic!("the split run should fail"),
        Err(e) => e,
    };
    let (site, at, message) = failure(&plan);
    assert_eq!((site, at), (0, 0), "{message}");
    assert!(
        message
            .contains("`ctl` asked for a cable from `web` to `sw-b`, which runs on another site"),
        "{message}"
    );
    assert_eq!(failure(&plan), (site, at, message));

    // `a-x`'s cable to `b-r`, a router `ctl-b` created on site 1 (its prefix says so).
    let b_r = spec(
        "router",
        &[
            ("mac", "02:00:00:00:0b:f0"),
            ("port0.ipv4", "10.0.9.1/24"),
            ("port1.ipv4", "10.0.8.1/24"),
        ],
        &[(0, "sw-b")],
    );
    let to_b = spec(
        "node:http-server",
        &[("mac", "02:00:00:00:0a:30"), ("ipv4", "10.0.9.30/24")],
        &[(0, "b-r")],
    );
    let plan = two_controllers(
        [
            Some(format!("500ms apply a-x {}", hex(&to_b))),
            Some(format!("200ms apply b-r {}", hex(&b_r))),
        ],
        true,
    );
    // That is another controller's device: the rule of cables refuses it, the same split or
    // not (on site 0, where `b-r` does not exist, by `ctl-b`'s prefix), so the runs agree.
    let whole = run_whole(&plan, 42);
    let failed = events(&whole.journal, "ctl-a", "infra-failed");
    assert!(
        failed.iter().any(|f| field(f, "name") == "a-x"
            && field(f, "message").contains("`b-r` belongs to `ctl-b`")),
        "{failed:?}\n{}",
        transcript(&whole.journal)
    );
    assert!(events(&whole.journal, "a-x", "device-added").is_empty());
    let split = run_split(&plan, 42).unwrap_or_else(|e| panic!("{e:?}"));
    assert_same(&whole, &split, "a cable to another controller's device");
}

/// Controllers on both sites need disjoint name prefixes; a controller creates only names
/// under its own, split or not.
#[test]
fn controllers_on_two_sites_need_name_prefixes() {
    let plan = two_controllers([None, None], false);
    let b = built();
    let mut network = Network::new(&b.host, 1);
    network
        .device_with_options(
            "ctl-a",
            &b.load("infra_script"),
            DeviceConfig::new(),
            infra(None),
        )
        .unwrap();
    let refused = network
        .remote_device_with("ctl-b", DeviceConfig::new(), infra(None))
        .expect_err("a second site's controller without prefixes");
    assert!(refused.to_string().contains("infra_prefix"), "{refused}");
    // Unsplit, the same network is fine.
    let whole = run_whole(&plan, 42);
    assert!(
        whole.outcome.starts_with("Ok(Deadline"),
        "{}",
        whole.outcome
    );
    // Overlapping prefixes are refused everywhere.
    let mut network = Network::new(&b.host, 1);
    network
        .device_with_options(
            "ctl-a",
            &b.load("infra_script"),
            DeviceConfig::new(),
            infra(Some("web")),
        )
        .unwrap();
    let overlap = network
        .device_with_options(
            "ctl-b",
            &b.load("infra_script"),
            DeviceConfig::new(),
            infra(Some("web-a")),
        )
        .expect_err("overlapping prefixes");
    assert!(overlap.to_string().contains("overlaps"), "{overlap}");
    // A name outside the prefix is denied, in the journal of the unsplit run too.
    let outside = spec("node:http-server", &[], &[(0, "sw-a")]);
    let plan = two_controllers(
        [Some(format!("500ms apply web {}", hex(&outside))), None],
        true,
    );
    let whole = run_whole(&plan, 42);
    let results: Vec<_> = events(&whole.journal, "ctl-a", "infra-script")
        .into_iter()
        .filter(|f| field(f, "name") == "web")
        .collect();
    assert_eq!(results.len(), 1);
    assert!(
        field(&results[0], "result").contains("outside this controller's names"),
        "{results:?}"
    );
}

/// A controller woken by `changes.wait` (its own creations, its instances' exits) wakes at the
/// same positions split and unsplit.
#[test]
fn a_waking_controller_matches_the_unsplit_run() {
    let plan = waking_controller();
    for seed in [42, 7] {
        let whole = run_whole(&plan, seed);
        let log = transcript(&whole.journal);
        for get in ["get-1", "get-2"] {
            let exits = events(&whole.journal, get, "app-exit");
            assert_eq!(exits.len(), 1, "seed {seed}, {get}:\n{log}");
        }
        // Each exit is observed at once, not at the next period: in the same instant.
        let exit_at: Vec<Nanos> = whole
            .journal
            .iter()
            .filter(|e| matches!(&e.record, wasmnet_host::Record::Event { kind, .. } if kind == "app-exit"))
            .map(|e| e.at)
            .collect();
        for at in &exit_at {
            assert!(
                whole.journal.iter().any(|e| e.at == *at
                    && e.device == "ctl"
                    && matches!(&e.record, wasmnet_host::Record::Event { kind, fields }
                        if kind == "replicas-observed"
                            && fields.iter().any(|(k, v)| k == "change" && v == "modified"))),
                "seed {seed}: an exit at {at} is observed then:\n{log}"
            );
        }
        let split = run_split(&plan, seed).unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        assert_same(&whole, &split, &format!("seed {seed}"));
        let again = run_split(&plan, seed).unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        assert_eq!(
            split, again,
            "seed {seed}: the split rerun is byte-identical"
        );
    }
}

/// A controller that fetches a component from another site, supplies it and runs devices made
/// from its digest on its own site: the split run merges into the unsplit one, its journal of
/// digests and sizes and its view of the table included.
#[test]
fn a_supplying_controller_matches_the_unsplit_run() {
    let plan = supplying_controller();
    let seed = 42;
    let whole = run_whole(&plan, seed);
    let log = transcript(&whole.journal);
    assert_eq!(
        events(&whole.journal, "ctl", "infra-supply").len(),
        1,
        "{log}"
    );
    let done = events(&whole.journal, "client", "http-get-done");
    assert_eq!(done.len(), 2, "{log}");
    assert!(done.iter().all(|d| field(d, "status") == "200"), "{log}");
    let split = run_split(&plan, seed).unwrap_or_else(|e| panic!("{e:?}"));
    assert_same(&whole, &split, "supplied");
}

/// `devices.wire` follows the rule of a creation's cables: a far end on another site fails the
/// split run at that event, the same every time, where the unsplit network wires it. The
/// `unwire` before it stays on the controller's site and is fine.
#[test]
fn a_wire_to_another_site_fails_the_split_run_deterministically() {
    let mut plan = one_controller("r1:1");
    let to_b = Value::Map(vec![
        (Value::text("port"), Value::Uint(1)),
        (Value::text("to"), Value::text("sw-b")),
        (Value::text("latency"), Value::Uint(50 * US)),
    ])
    .encode();
    let ctl = &mut plan.devices[1].config;
    ctl.insert("step.20".to_owned(), "150ms unwire r1 1".to_owned());
    ctl.insert(
        "step.21".to_owned(),
        format!("200ms wire r1 {}", hex(&to_b)),
    );
    let whole = run_whole(&plan, 42);
    assert_eq!(
        events(&whole.journal, "r1", "link-removed").len(),
        1,
        "{}",
        transcript(&whole.journal)
    );
    assert!(
        events(&whole.journal, "r1", "link-added")
            .iter()
            .any(|f| field(f, "link") == "r1.1-sw-b.2"),
        "the unsplit network wires it:\n{}",
        transcript(&whole.journal)
    );
    let failure = || match run_split(&plan, 42) {
        Ok(_) => panic!("the split run should fail"),
        Err(e) => e,
    };
    let (site, at, message) = failure();
    assert_eq!((site, at), (0, 200 * MS), "{message}");
    assert!(
        message.contains("asked for a cable from `r1` to `sw-b`"),
        "{message}"
    );
    assert_eq!(failure(), (site, at, message));
}

/// When each `kind` event of `device` was journalled.
fn times(journal: &[JournalEntry], device: &str, kind: &str) -> Vec<Nanos> {
    journal
        .iter()
        .filter(|e| e.device == device)
        .filter(|e| matches!(&e.record, wasmnet_host::Record::Event { kind: k, .. } if k == kind))
        .map(|e| e.at)
        .collect()
}

/// The one-controller network, with `ctl` following the events of the router it created
/// (`wasmnet:infra/events`, armed by the `infra-script` fixture): every `route-lookup` of `r1`,
/// which the client's traffic from site 1 sets off, makes it send `r1` a `routes` command.
fn following_controller() -> Plan {
    let mut plan = one_controller("r1:1");
    let ctl = plan
        .devices
        .iter_mut()
        .find(|d| d.name == "ctl")
        .expect("ctl");
    ctl.config.insert(
        "on.0".to_owned(),
        "r1 route-lookup : control r1 routes".to_owned(),
    );
    plan
}

/// A controller woken by the events of a device it created, which traffic from the other site
/// causes: it reacts in the instant of each event, and the split run merges into the unsplit
/// one (the controller's journal, its commands and their answers, and its view included).
#[test]
fn a_controller_following_events_matches_the_unsplit_run() {
    let plan = following_controller();
    for seed in [42, 7] {
        let whole = run_whole(&plan, seed);
        let log = transcript(&whole.journal);
        let lookups = times(&whole.journal, "r1", "route-lookup");
        assert!(!lookups.is_empty(), "seed {seed}:\n{log}");
        let reactions: Vec<Nanos> = whole
            .journal
            .iter()
            .filter(|e| e.device == "ctl")
            .filter(|e| {
                matches!(&e.record, wasmnet_host::Record::Event { kind, fields }
                if kind == "infra-script"
                    && fields.iter().any(|(k, v)| k == "step" && v == "on.0"))
            })
            .map(|e| e.at)
            .collect();
        assert_eq!(
            reactions, lookups,
            "seed {seed}: one reaction per event, at its instant"
        );
        let results: Vec<String> = events(&whole.journal, "ctl", "infra-script")
            .iter()
            .filter(|f| field(f, "step") == "on.0")
            .map(|f| field(f, "result").to_owned())
            .collect();
        assert!(
            results.iter().all(|r| r == "ok"),
            "seed {seed}: {results:?}"
        );
        let split = run_split(&plan, seed).unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        assert_same(&whole, &split, &format!("seed {seed}"));
        let again = run_split(&plan, seed).unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        assert_eq!(
            split, again,
            "seed {seed}: the split rerun is byte-identical"
        );
    }
}
