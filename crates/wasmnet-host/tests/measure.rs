//! What an embedder measures in a run (`docs/design/links.md`, "Counters" and "What a link
//! records"; `docs/design/runtime-and-extensions.md`, "Costs"), end to end with real nodes:
//!
//! * a snap length bounds a megabyte transfer's capture and frame log and changes nothing
//!   else (journal, outcome, counters, costs), and recording off keeps only the headers;
//! * the counters read between runs, and a link's series, give exactly the traffic its
//!   capture shows in each window;
//! * a device's peak fuel per instant is the instant the workload puts it at, and equals what
//!   reading the total fuel at every instant gives;
//! * the captures of a device removed and added again are joined by their headers;
//! * split over two sites, the merged records keep exactly what the unsplit captures keep.
//!
//! Every run is repeated: the same seed gives the same bytes. Needs `wac` and `wasm-tools` on
//! `PATH` (see `support`). Replay a failure with `cargo test -p wasmnet-host --test measure`.

mod support;

use std::collections::{BTreeMap, VecDeque};

use support::{built, config, events, field, transcript};
use wasmnet_host::pcap::{self, Direction, LinkEnd};
use wasmnet_host::sim::{
    CaptureOptions, DeviceCost, Impairments, LinkStats, Op, Placement, SeriesOptions,
    sites::{self, Msg, SiteRecords, SiteSync, Step},
};
use wasmnet_host::{DeviceOptions, FrameRecord, JournalEntry, LinkId, Nanos, Network, Outcome};

const US: Nanos = 1_000;
const MS: Nanos = 1_000_000;

/// The body the fetch asks for: a megabyte.
const BULK: u64 = 1_000_000;
/// What the snapped run keeps of each frame: Ethernet, IP and TCP headers and some payload.
const SNAP: u32 = 128;
/// The series' bucket width.
const BUCKET: Nanos = 50 * MS;
/// The windowed reads' link rate, so the transfer spreads over most of a second.
const RATE: u64 = 10_000_000;

/// One fetch of `/big?n=bulk`, server and client on one link of 100 µs at `rate` bits per
/// second (0: unlimited), every link recording with `capture` and keeping a series.
struct Fetch {
    outcome: String,
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    pcap: Vec<u8>,
    /// The link's counters after `run_until(stop)`, for each stop.
    at_stops: Vec<LinkStats>,
    stats: LinkStats,
    series: Vec<(Nanos, LinkStats)>,
    costs: Vec<(String, DeviceCost)>,
}

fn fetch(seed: u64, bulk: u64, rate: u64, capture: CaptureOptions, stops: &[Nanos]) -> Fetch {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    network.set_capture_defaults(capture);
    network.set_series_defaults(Some(SeriesOptions {
        width: BUCKET,
        keep: 1_000,
    }));
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
    let url = format!("http://web/big?n={bulk}");
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:00:02"),
                ("ipv4", "10.0.0.2/24"),
                ("hosts.web", "10.0.0.1"),
                ("app.http-get.url", &url),
                ("app.http-get.start", "1ms"),
            ]),
        )
        .unwrap();
    let link = network
        .link(server.port(0), client.port(0))
        .unwrap()
        .latency(100 * US)
        .impair(Impairments::default().rate(rate))
        .id();
    let mut at_stops = Vec::new();
    for &stop in stops {
        network.run_until(stop).unwrap();
        at_stops.push(network.link_stats(link));
    }
    let outcome = network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    assert!(matches!(outcome, Outcome::Quiescent { .. }), "{outcome:?}");
    let journal = network.journal();
    let done = events(&journal, "client", "http-get-done");
    assert_eq!(done.len(), 1, "seed={seed}: one fetch");
    assert_eq!(field(&done[0], "body-bytes"), bulk.to_string());
    Fetch {
        outcome: format!("{outcome:?}"),
        frames: network.frames(),
        pcap: network.pcap(link),
        at_stops,
        stats: network.link_stats(link),
        series: network.link_series(link),
        costs: network.costs(),
        journal,
    }
}

/// A frame record without its bytes.
fn meta(f: &FrameRecord) -> String {
    format!(
        "{:?} {:?} {:?} {} {:?} {}",
        f.link, f.from, f.to, f.sent_at, f.fate, f.len
    )
}

#[test]
fn a_snap_length_bounds_a_megabyte_capture_and_changes_nothing_else() {
    let whole = fetch(1, BULK, 0, CaptureOptions::default(), &[]);
    let snapped = fetch(1, BULK, 0, CaptureOptions::default().snap_len(SNAP), &[]);
    let off = fetch(1, BULK, 0, CaptureOptions::default().record(false), &[]);
    for (label, run) in [("snapped", &snapped), ("off", &off)] {
        assert_eq!(run.outcome, whole.outcome, "{label}: outcome");
        assert!(run.journal == whole.journal, "{label}: the journals differ");
        assert_eq!(run.stats, whole.stats, "{label}: counters");
        assert_eq!(run.costs, whole.costs, "{label}: costs");
        let (a, b): (Vec<_>, Vec<_>) = (
            run.frames.iter().map(meta).collect(),
            whole.frames.iter().map(meta).collect(),
        );
        assert!(a == b, "{label}: the frame records differ");
    }
    // The snapped frame log and capture keep the first SNAP bytes of each frame, and its
    // original length.
    for (s, w) in snapped.frames.iter().zip(&whole.frames) {
        assert_eq!(s.bytes, w.bytes[..w.len.min(SNAP as usize)]);
    }
    let (ws, ss) = (
        pcap::parse(&whole.pcap).unwrap(),
        pcap::parse(&snapped.pcap).unwrap(),
    );
    assert_eq!(ws.packets.len(), ss.packets.len());
    for (w, s) in ws.packets.iter().zip(&ss.packets) {
        assert_eq!(s.original_len as usize, w.data.len());
        assert_eq!((s.timestamp, s.direction), (w.timestamp, w.direction));
        assert_eq!(s.data, w.data[..w.data.len().min(SNAP as usize)]);
    }
    // Bounded: per packet at most 32 bytes of block, SNAP of data and 12 of options.
    let header = pcap_header_len(&snapped.pcap);
    let bound = header + ss.packets.len() * (32 + SNAP as usize + 12);
    assert!(
        snapped.pcap.len() <= bound && snapped.pcap.len() * 5 < whole.pcap.len(),
        "snapped capture {} bytes (bound {bound}), whole {}",
        snapped.pcap.len(),
        whole.pcap.len()
    );
    let kept: usize = snapped.frames.iter().map(|f| f.bytes.len()).sum();
    assert!(kept <= snapped.frames.len() * SNAP as usize);
    assert!(
        whole.stats.bytes.iter().sum::<u64>() > 2 * BULK / 2,
        "a megabyte crossed"
    );
    // Recording off: the header, and records without bytes.
    let oc = pcap::parse(&off.pcap).unwrap();
    assert_eq!((oc.interfaces.len(), oc.packets.len()), (2, 0));
    assert_eq!(off.pcap, whole.pcap[..header]);
    assert!(off.frames.iter().all(|f| f.bytes.is_empty()));

    let again = fetch(1, BULK, 0, CaptureOptions::default().snap_len(SNAP), &[]);
    assert_eq!(
        again.pcap, snapped.pcap,
        "the same seed gives the same capture"
    );
    assert!(again.frames == snapped.frames && again.journal == snapped.journal);
}

/// The bytes before the first Enhanced Packet Block.
fn pcap_header_len(bytes: &[u8]) -> usize {
    let mut at = 0;
    while at + 8 <= bytes.len() {
        let block = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        if block == 6 {
            break;
        }
        at += u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
    }
    at
}

/// Outbound packets per sending end in `(from, to]`, from the capture: `(frames, bytes)`.
fn captured(cap: &pcap::Capture, from: Option<Nanos>, to: Nanos) -> ([u64; 2], [u64; 2]) {
    let (mut frames, mut bytes) = ([0; 2], [0; 2]);
    for p in &cap.packets {
        let inside = from.is_none_or(|f| p.timestamp > f) && p.timestamp <= to;
        if p.direction == Some(Direction::Outbound) && inside {
            frames[p.interface as usize] += 1;
            bytes[p.interface as usize] += u64::from(p.original_len);
        }
    }
    (frames, bytes)
}

#[test]
fn counters_in_a_window_match_the_capture() {
    let plain = fetch(2, BULK, RATE, CaptureOptions::default(), &[]);
    // Stops at the start, at four points across the transfer (from the first frame to the
    // last full-size frame, as the plain run shows them) and after it.
    let data: Vec<_> = plain.frames.iter().filter(|f| f.len > 1_000).collect();
    let (first, last) = (data[0].sent_at, data.last().unwrap().sent_at);
    let stops: Vec<Nanos> = [0, 1, 2, 3, 4]
        .map(|k| first + (last - first) * k / 4)
        .into_iter()
        .chain([last + 10 * MS])
        .collect();
    let run = fetch(2, BULK, RATE, CaptureOptions::default(), &stops);
    assert_eq!(run.pcap, plain.pcap, "reading the counters changes nothing");
    let cap = pcap::parse(&run.pcap).unwrap();
    // Reads between runs, subtracted.
    let mut previous: Option<(Nanos, LinkStats)> = None;
    let mut busy = Vec::new();
    for (&stop, stats) in stops.iter().zip(&run.at_stops) {
        let window = match previous {
            Some((_, before)) => stats.since(&before),
            None => *stats,
        };
        let (frames, bytes) = captured(&cap, previous.map(|(t, _)| t), stop);
        assert_eq!(
            (window.frames, window.bytes),
            (frames, bytes),
            "window up to {stop}"
        );
        busy.push(frames);
        previous = Some((stop, *stats));
    }
    assert!(
        busy.iter().filter(|f| f[0] > 10).count() >= 3,
        "the transfer spans several windows: {busy:?}"
    );
    // The series: every bucket against the capture, and the buckets add up to the totals.
    let mut sum = LinkStats::default();
    for (start, stats) in &run.series {
        let (frames, bytes) = captured(&cap, start.checked_sub(1), start + BUCKET - 1);
        assert_eq!(
            (stats.frames, stats.bytes),
            (frames, bytes),
            "bucket at {start}"
        );
        sum.add(stats);
    }
    assert!(run.series.len() > 3, "{} buckets", run.series.len());
    assert_eq!(sum, run.stats);
    assert_eq!(run.series, plain.series);
}

/// Each device's most fuel in one instant and the first instant it happened at, found by
/// running to every instant in turn and reading its total fuel after each.
fn stepped_peaks(network: &mut Network) -> BTreeMap<String, (u64, Nanos)> {
    let mut last: BTreeMap<String, u64> = BTreeMap::new();
    let mut peaks: BTreeMap<String, (u64, Nanos)> = BTreeMap::new();
    while let Some(t) = network.next_event_time() {
        network.run_until(t).unwrap();
        for (name, cost) in network.costs() {
            let before = last.insert(name.clone(), cost.fuel).unwrap_or(0);
            let used = cost.fuel - before;
            let peak = peaks.entry(name).or_default();
            if used > peak.0 {
                *peak = (used, t);
            }
        }
    }
    peaks
}

fn peaks(network: &Network) -> BTreeMap<String, (u64, Nanos)> {
    network
        .costs()
        .into_iter()
        .map(|(name, c)| (name, (c.peak_fuel, c.peak_fuel_at)))
        .collect()
}

#[test]
fn peak_fuel_is_the_busiest_instant() {
    const LATENCY: Nanos = 100 * US;
    // The blaster sends one probe at 0 and 1 ms, fifty at 5 ms and one at 9 ms; the reflector
    // echoes each, so its busiest instant is the fifty arriving at 5 ms + latency.
    let schedule = ["0ms", "1ms"]
        .into_iter()
        .chain(std::iter::repeat_n("5ms", 50))
        .chain(["9ms"])
        .collect::<Vec<_>>()
        .join(",");
    let echo = |step: bool| {
        let b = built();
        let mut network = Network::new(&b.host, 7);
        let blaster = network
            .device_with_config(
                "blaster",
                &b.load("blaster"),
                config(&[("schedule", &schedule)]),
            )
            .unwrap();
        let reflector = network.device("reflector", &b.load("reflector")).unwrap();
        network
            .link(blaster.port(0), reflector.port(0))
            .unwrap()
            .latency(LATENCY);
        let stepped = step.then(|| stepped_peaks(&mut network));
        network.run_until_quiescent().unwrap();
        (
            peaks(&network),
            stepped,
            network.pcap(LinkId::from_index(0)),
        )
    };
    let (reported, _, pcap) = echo(false);
    let (again, stepped, stepped_pcap) = echo(true);
    assert_eq!(reported, again, "stepping changes nothing");
    assert_eq!(pcap, stepped_pcap);
    assert_eq!(
        Some(reported.clone()),
        stepped,
        "the peaks equal the stepped totals"
    );
    let (fuel, at) = reported["reflector"];
    assert_eq!(at, 5 * MS + LATENCY, "the reflector's busiest instant");
    assert!(fuel > 0);
    let (blaster, _) = reported["blaster"];
    assert!(blaster > 0);

    // Real nodes: a 100 kB fetch, stepped through every instant.
    let b = built();
    let mut network = Network::new(&b.host, 3);
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
                ("hosts.web", "10.0.0.1"),
                ("app.http-get.url", "http://web/big?n=100000"),
                ("app.http-get.start", "1ms"),
            ]),
        )
        .unwrap();
    network
        .link(server.port(0), client.port(0))
        .unwrap()
        .latency(LATENCY);
    let stepped = stepped_peaks(&mut network);
    let reported = peaks(&network);
    assert_eq!(
        reported, stepped,
        "nodes: the peaks equal the stepped totals"
    );
    for (name, (fuel, at)) in &reported {
        assert!(*fuel > 0 && *at > 0, "{name}: {fuel} at {at}");
    }
    let total = network.cost_of("server");
    assert!(total.peak_fuel < total.fuel);
}

#[test]
fn a_recreated_device_is_followed_by_its_capture_headers() {
    let run = || {
        let b = built();
        let mut network = Network::new(&b.host, 5);
        network.set_capture_defaults(CaptureOptions::default().name_ends(true));
        network.set_component_resolver(Box::new(move |name, instantiate| match name {
            "node:http-server" => instantiate(&b.load("node-http-server")),
            other => Err(wasmnet_host::Error::Refused(format!(
                "no component {other}"
            ))),
        }));
        let sw = network
            .device_with_config("sw", &b.load("switch"), config(&[("ports", "2")]))
            .unwrap();
        let web_config = config(&[
            ("mac", "02:00:00:00:00:10"),
            ("ipv4", "10.0.0.10/24"),
            ("app.http-server.listen", "0.0.0.0:80"),
        ]);
        let web = network
            .device_with_config("web", &b.load("node-http-server"), web_config.clone())
            .unwrap();
        let client = network
            .device_with_config(
                "client",
                &b.load("node-http-get"),
                config(&[
                    ("mac", "02:00:00:00:00:20"),
                    ("ipv4", "10.0.0.20/24"),
                    ("app.http-get.url", "http://10.0.0.10/"),
                    ("app.http-get.start", "10ms"),
                    ("app.http-get.interval", "200ms"),
                    ("app.http-get.repeat", "3"),
                ]),
            )
            .unwrap();
        network
            .link(web.port(0), sw.port(1))
            .unwrap()
            .latency(100 * US);
        network
            .link(client.port(0), sw.port(0))
            .unwrap()
            .latency(100 * US);
        network
            .add_op(
                Op::RemoveDevice {
                    device: "web".to_owned(),
                },
                Placement::StartOf(100 * MS),
            )
            .unwrap();
        network
            .add_op(
                Op::AddDevice {
                    name: "web".to_owned(),
                    component: "node:http-server".to_owned(),
                    config: web_config,
                    options: DeviceOptions::default(),
                    wire: vec![wasmnet_host::sim::Cable {
                        port: 0,
                        to_device: "sw".to_owned(),
                        to_port: 1,
                        latency: 100 * US,
                        mtu: None,
                    }],
                },
                Placement::StartOf(150 * MS),
            )
            .unwrap();
        network.run_until(800 * MS).unwrap();
        let journal = network.journal();
        let pcaps: Vec<Vec<u8>> = network
            .links()
            .into_iter()
            .map(|l| network.pcap(l))
            .collect();
        (pcaps, journal)
    };
    let (pcaps, journal) = run();
    let done = events(&journal, "client", "http-get-done");
    assert!(done.len() >= 2, "{}", transcript(&journal));

    // A tool that knows nothing of the run: every capture whose header names `web`, in the
    // order the links were created.
    let mut web: Vec<(LinkEnd, usize)> = Vec::new();
    for bytes in &pcaps {
        let cap = pcap::parse(bytes).unwrap();
        for iface in &cap.interfaces {
            let end = LinkEnd::parse(iface.description.as_deref().unwrap()).unwrap();
            if end.device == "web" {
                web.push((end, cap.packets.len()));
            }
        }
    }
    web.sort_by_key(|(end, _)| end.created_at);
    let names: Vec<_> = web
        .iter()
        .map(|(e, _)| {
            (
                e.link.as_str(),
                e.port,
                e.peer_device.as_str(),
                e.peer_port,
                e.created_at,
            )
        })
        .collect();
    assert_eq!(
        names,
        [
            ("web.0-sw.1", 0, "sw", 1, 0),
            ("web.0-sw.1-2", 0, "sw", 1, 150 * MS),
        ]
    );
    assert!(
        web.iter().all(|(_, packets)| *packets > 0),
        "both carried traffic"
    );

    let (again, journal_again) = run();
    assert_eq!(again, pcaps, "the same seed gives the same captures");
    assert!(journal_again == journal);
}

// ---- split over two sites (docs/design/sites.md) ----

/// `client` -L- `sw` -L- `server`, the client fetching 200 kB; devices in this order on every
/// site.
const NAMES: [&str; 3] = ["sw", "server", "client"];
const L: Nanos = 200 * US;

/// The network on one site: `local` names the devices it runs, the others are placeholders;
/// every link records with `capture`.
fn site(local: &[&str], capture: CaptureOptions) -> Network<'static> {
    let b = built();
    let mut network = Network::new(&b.host, 11);
    network.set_capture_defaults(capture);
    for name in NAMES {
        if !local.contains(&name) {
            network.remote_device(name).unwrap();
            continue;
        }
        let (component, cfg) = match name {
            "sw" => ("switch", config(&[("ports", "2")])),
            "server" => (
                "node-http-server",
                config(&[
                    ("mac", "02:00:00:00:00:01"),
                    ("ipv4", "10.0.0.1/24"),
                    ("app.http-server.listen", "0.0.0.0:80"),
                ]),
            ),
            _ => (
                "node-http-get",
                config(&[
                    ("mac", "02:00:00:00:00:02"),
                    ("ipv4", "10.0.0.2/24"),
                    ("hosts.web", "10.0.0.1"),
                    ("app.http-get.url", "http://web/big?n=200000"),
                    ("app.http-get.start", "1ms"),
                ]),
            ),
        };
        network
            .device_with_config(name, &b.load(component), cfg)
            .unwrap();
    }
    network
}

fn wire(network: &mut Network<'static>) {
    let [sw, server, client] = [0, 1, 2].map(wasmnet_host::DeviceId::from_index);
    network.link(client.port(0), sw.port(0)).unwrap().latency(L);
    network.link(sw.port(1), server.port(0)).unwrap().latency(L);
}

/// Through the wire format, as a carrier would move it.
fn carry(m: Msg) -> Msg {
    Msg::decode(&m.encode()).expect("a message decodes")
}

/// The network split into `split[0]` and `split[1]`, run in lockstep on this thread, merged.
fn run_split(split: [&[&str]; 2], capture: CaptureOptions) -> sites::Merged {
    let mut nets = split.map(|local| site(local, capture));
    let hellos = [sites::hello(&nets[0]), sites::hello(&nets[1])];
    for (i, hello) in hellos.into_iter().enumerate() {
        sites::apply_hello(&mut nets[1 - i], &carry(hello)).unwrap();
    }
    for n in &mut nets {
        wire(n);
    }
    let mut sync = [SiteSync::new(L, None), SiteSync::new(L, None)];
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
    let records: Vec<SiteRecords> = (0..2)
        .map(|i| {
            let outcome = sync[i].finish(&mut nets[i]).map_err(|e| (0, e.to_string()));
            match carry(Msg::Records(Box::new(SiteRecords::collect(
                &nets[i], outcome,
            )))) {
                Msg::Records(r) => *r,
                other => panic!("{other:?}"),
            }
        })
        .collect();
    let names: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
    sites::merge([&records[0], &records[1]], &names, None).unwrap()
}

#[test]
fn split_over_two_sites_keeps_what_the_captures_keep() {
    for capture in [
        CaptureOptions::default().snap_len(64).name_ends(true),
        CaptureOptions::default().record(false),
    ] {
        let mut whole = site(&NAMES, capture);
        wire(&mut whole);
        let outcome = whole.run_until_quiescent().unwrap();
        let journal = whole.journal();
        assert_eq!(events(&journal, "client", "http-get-done").len(), 1);
        for split in [
            [&["client"][..], &["sw", "server"][..]],
            [&["client", "sw"][..], &["server"][..]],
        ] {
            let merged = run_split(split, capture);
            let what = format!("{capture:?}, split {split:?}");
            assert_eq!(merged.outcome, Ok(outcome.clone()), "{what}");
            assert!(merged.journal == journal, "{what}: journal");
            assert!(merged.frames == whole.frames(), "{what}: frame log");
            for (l, (s, pcap)) in whole.links().into_iter().zip(&merged.links) {
                assert_eq!(*s, whole.link_stats(l), "{what}: link {l:?} counters");
                assert!(*pcap == whole.pcap(l), "{what}: link {l:?} capture");
            }
        }
    }
}
