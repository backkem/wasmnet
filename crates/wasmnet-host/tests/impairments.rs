//! Link impairments end to end (`docs/design/links.md`): a rate with a bounded transmit queue,
//! seeded loss and jitter, under real nodes and real TCP.
//!
//! * A bulk transfer over a rated link takes exactly its serialisation time plus the latency
//!   once the window is open, and a small queue drops frames without stopping TCP.
//! * Seeded loss and jitter replay byte for byte, another seed differs, and the bounds hold.
//! * A link whose impairments are all off is the plain link, byte for byte.
//! * Operator events change them while the network runs, by link id or by name.
//! * Split over two sites, an impaired network (the impaired link crossing the sites, or local
//!   to one) gives exactly the records of the unsplit one.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`). Replay a failure with
//! `cargo test -p wasmnet-host --test impairments`.

mod support;

use std::collections::VecDeque;

use support::{built, config, events, field, segment, transcript};
use wasmnet_host::sim::sites::{self, Msg, SiteRecords, SiteSync, Step};
use wasmnet_host::sim::{FrameFate, Impairments, Op, OpState, Placement};
use wasmnet_host::{DeviceId, LinkId, Nanos, Network, Outcome, PortRef, Record};

const US: Nanos = 1_000;

/// The body `GET /big?n=` asks for in the bulk transfers.
const BULK: u64 = 1_000_000;

/// The server's and the client's device configs: `server` 10.0.0.1, `client` 10.0.0.2
/// fetching `url` at t = 1 ms.
fn server_config() -> wasmnet_host::DeviceConfig {
    config(&[
        ("mac", "02:00:00:00:00:01"),
        ("ipv4", "10.0.0.1/24"),
        ("app.http-server.listen", "0.0.0.0:80"),
    ])
}

fn client_config(url: &str) -> wasmnet_host::DeviceConfig {
    config(&[
        ("mac", "02:00:00:00:00:02"),
        ("ipv4", "10.0.0.2/24"),
        ("hosts.web", "10.0.0.1"),
        ("app.http-get.url", url),
        ("app.http-get.start", "1ms"),
    ])
}

/// A finished run of a two-node network.
struct Bulk {
    journal: Vec<wasmnet_host::JournalEntry>,
    frames: Vec<wasmnet_host::FrameRecord>,
    stats: wasmnet_host::LinkStats,
    server: PortRef,
    /// When the client journalled `http-get-done`.
    done: Nanos,
}

/// `server` and `client` on one link of `latency`, each direction with `imp`; the client
/// fetches `/big?n=BULK`.
fn bulk(seed: u64, latency: Nanos, imp: Impairments) -> Bulk {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let server = network
        .device_with_config("server", &b.load("node-http-server"), server_config())
        .unwrap();
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            client_config(&format!("http://web/big?n={BULK}")),
        )
        .unwrap();
    let link = network
        .link(server.port(0), client.port(0))
        .unwrap()
        .latency(latency)
        .impair(imp)
        .id();
    let outcome = network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    assert!(matches!(outcome, Outcome::Quiescent { .. }), "{outcome:?}");
    let journal = network.journal();
    let log = transcript(&journal);
    let done = events(&journal, "client", "http-get-done");
    assert_eq!(done.len(), 1, "one fetch\n{log}");
    assert_eq!(field(&done[0], "status"), "200", "{log}");
    assert_eq!(field(&done[0], "body-bytes"), BULK.to_string(), "{log}");
    let sent = events(&journal, "server", "http-response");
    assert_eq!(
        field(&done[0], "body-fnv"),
        field(&sent[0], "body-fnv"),
        "the body arrived intact"
    );
    let done = journal
        .iter()
        .find(|e| matches!(&e.record, Record::Event { kind, .. } if kind == "http-get-done"))
        .map_or(0, |e| e.at);
    Bulk {
        stats: network.link_stats(link),
        frames: network.frames(),
        journal,
        server: server.port(0),
        done,
    }
}

#[test]
fn a_bulk_transfer_takes_its_serialisation_time() {
    const RATE: u64 = 10_000_000;
    const LATENCY: Nanos = 100 * US;
    let imp = Impairments::default().rate(RATE);
    let run = bulk(1, LATENCY, imp);
    assert_eq!(
        run.stats.dropped_queue,
        [0, 0],
        "the default queue holds the window"
    );

    // The response's data segments, server -> client: from the first one handed to the link
    // to the arrival of the last one.
    let data: Vec<_> = run
        .frames
        .iter()
        .filter(|f| f.from == run.server)
        .filter(|f| segment(&f.bytes).is_some_and(|s| !s.payload.is_empty()))
        .collect();
    let first = data.first().unwrap().sent_at;
    let last = data.last().unwrap();
    let FrameFate::Delivered { at: arrived } = last.fate else {
        panic!("the last segment was not delivered: {:?}", last.fate);
    };
    // Everything the server's transmitter serialised in between, headers and all.
    let busy: Nanos = run
        .frames
        .iter()
        .filter(|f| f.from == run.server && f.sent_at >= first && f.sent_at <= last.sent_at)
        .map(|f| imp.serialisation(f.bytes.len()))
        .sum();
    let elapsed = arrived - first;
    // The link cannot be faster than its rate: the lower bound is exact.
    assert!(
        elapsed >= busy + LATENCY,
        "elapsed {elapsed} < busy {busy} + latency"
    );
    // The receive window is far larger than the bandwidth-delay product (about 2.5 kB), so
    // the transmitter idles only while TCP's slow start opens the congestion window: the
    // initial window (2048 bytes: a full segment and 588 bytes) is less than two full
    // segments, so the receiver holds its ACK for its delayed-ACK time (10 ms); the next
    // window already exceeds the bandwidth-delay product, and from then on the transmitter
    // never idles. Allow that delay and one full frame's time.
    let idle = elapsed - busy - LATENCY;
    assert!(
        idle <= 10_000 * US + imp.serialisation(1514),
        "the transmitter idled {idle} ns"
    );
    // Against size / rate: the payload alone, plus the Ethernet, IP and TCP headers (54 of
    // every 1514 bytes, 3.7 %), the HTTP head and the slow start (1.3 %).
    let ideal = BULK * 8 * 1_000_000_000 / RATE;
    let ratio = elapsed as f64 / ideal as f64;
    assert!(
        (1.0..1.06).contains(&ratio),
        "elapsed {elapsed} ns for size / rate {ideal} ns: ratio {ratio:.4}"
    );
    println!(
        "bulk: {BULK} B at {RATE} bit/s: elapsed {elapsed} ns, busy {busy} ns, idle {idle} ns, \
         size/rate {ideal} ns, ratio {ratio:.4}, fetch done t={}",
        run.done
    );
}

#[test]
fn a_small_queue_drops_frames_and_tcp_still_completes() {
    let imp = Impairments::default().rate(10_000_000).queue(4);
    let run = bulk(1, 100 * US, imp);
    let full = run
        .frames
        .iter()
        .filter(|f| f.fate == FrameFate::Dropped(wasmnet_host::DropReason::QueueFull))
        .count() as u64;
    assert!(
        run.stats.dropped_queue[0] > 0,
        "the server's bursts overflow 4 frames"
    );
    assert_eq!(
        full,
        run.stats.dropped_queue[0] + run.stats.dropped_queue[1]
    );
    println!(
        "queue 4: dropped {:?}, retransmitted, fetch done t={}",
        run.stats.dropped_queue, run.done
    );
    // And it replays.
    let again = bulk(1, 100 * US, imp);
    assert_eq!(again.frames, run.frames);
    assert_eq!(again.journal, run.journal);
}

/// blaster <-> reflector: `count` probes 10 µs apart, both directions impaired with `imp`.
fn blast(seed: u64, count: u32, imp: Option<Impairments>) -> (Vec<u8>, Network<'static>, LinkId) {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let cfg = config(&[("count", &count.to_string()), ("interval", "10us")]);
    let a = network
        .device_with_config("blaster", &b.load("blaster"), cfg)
        .unwrap();
    let r = network.device("reflector", &b.load("reflector")).unwrap();
    let mut link = network.link(a.port(0), r.port(0)).unwrap().latency(50 * US);
    if let Some(imp) = imp {
        link = link.impair(imp);
    }
    let link = link.id();
    network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}"));
    (network.pcap(link), network, link)
}

#[test]
fn seeded_loss_and_jitter_replay_and_stay_in_bounds() {
    const COUNT: u32 = 2_000;
    const JITTER: Nanos = 30 * US;
    // 20 % loss each way, up to 30 µs of jitter.
    let imp = Impairments::default().loss_ppm(200_000).jitter(JITTER);
    let (pcap, network, link) = blast(7, COUNT, Some(imp));
    let stats = network.link_stats(link);
    assert_eq!(stats.frames[0], u64::from(COUNT));
    // Binomial bounds at about 5 sigma: 2000 x 0.2 = 400 +- 89; the echoes are the probes
    // that arrived, and lose 20 % again.
    let lost = stats.lost_random;
    assert!((311..=489).contains(&lost[0]), "probes lost: {lost:?}");
    let echoed = stats.frames[1];
    assert_eq!(echoed, u64::from(COUNT) - lost[0], "every arrival echoed");
    assert!(
        lost[1] * 1000 / echoed > 120 && lost[1] * 1000 / echoed < 280,
        "{lost:?}"
    );

    // Every arrival is within [latency, latency + jitter] of its transmit, in order per
    // direction.
    let frames = network.frames();
    for from in [0, 1] {
        let mut last = 0;
        for f in frames
            .iter()
            .filter(|f| f.from == network.link_info(link).ends[from])
        {
            match f.fate {
                FrameFate::Delivered { at } => {
                    let extra = at - f.sent_at - 50 * US;
                    assert!(at >= f.sent_at + 50 * US && extra <= JITTER, "{f:?}");
                    assert!(at >= last, "reordered: {f:?}");
                    last = at;
                }
                FrameFate::Lost => {}
                other => panic!("unexpected fate {other:?}"),
            }
        }
    }

    let (again, ..) = blast(7, COUNT, Some(imp));
    assert_eq!(again, pcap, "the same seed replays byte for byte");
    let (other, ..) = blast(8, COUNT, Some(imp));
    assert_ne!(other, pcap, "another seed loses other frames");

    // Probability 1 on the way back: no echo arrives, and the blaster's probes all do.
    let b = built();
    let mut network = Network::new(&b.host, 7);
    let cfg = config(&[("count", "50"), ("interval", "10us")]);
    let a = network
        .device_with_config("blaster", &b.load("blaster"), cfg)
        .unwrap();
    let r = network.device("reflector", &b.load("reflector")).unwrap();
    let link = network
        .link(a.port(0), r.port(0))
        .unwrap()
        .latency(50 * US)
        .impair_from(r.port(0), Impairments::default().loss_ppm(1_000_000))
        .id();
    network.run_until_quiescent().unwrap();
    let stats = network.link_stats(link);
    assert_eq!(stats.frames, [50, 50]);
    assert_eq!(stats.lost_random, [0, 50]);
}

#[test]
fn impairments_that_are_off_change_nothing() {
    let (plain, plain_net, _) = blast(3, 200, None);
    let off = Impairments::default().queue(0);
    let (with_off, off_net, _) = blast(3, 200, Some(off));
    assert_eq!(with_off, plain);
    assert_eq!(off_net.frames(), plain_net.frames());
    assert_eq!(off_net.journal(), plain_net.journal());
}

// ---- split over two sites (docs/design/sites.md) ----

/// The split network: `client` -L1- `sw` -L2- `server`, both links impaired, the client
/// fetching `/big?n=200000`. Devices in this order on every site: sw, server, client.
const NAMES: [&str; 3] = ["sw", "server", "client"];
const L1: Nanos = 200 * US;
const L2: Nanos = 150 * US;

fn impaired() -> Impairments {
    Impairments::default()
        .rate(20_000_000)
        .queue(16)
        .loss_ppm(10_000)
        .jitter(30 * US)
}

/// Builds the network on one site: `local` names the devices this site runs (all three for
/// the unsplit network); the others are placeholders. Returns the network before its links.
fn devices(local: &[&str]) -> Network<'static> {
    let b = built();
    let mut network = Network::new(&b.host, 11);
    for name in NAMES {
        if !local.contains(&name) {
            network.remote_device(name).unwrap();
            continue;
        }
        let (component, cfg) = match name {
            "sw" => ("switch", config(&[("ports", "2")])),
            "server" => ("node-http-server", server_config()),
            _ => ("node-http-get", client_config("http://web/big?n=200000")),
        };
        network
            .device_with_config(name, &b.load(component), cfg)
            .unwrap();
    }
    network
}

/// Wires the two links, the same on every site.
fn links(network: &mut Network<'static>) {
    let [sw, server, client] = [0, 1, 2].map(DeviceId::from_index);
    network
        .link(client.port(0), sw.port(0))
        .unwrap()
        .latency(L1)
        .impair(impaired());
    network
        .link(sw.port(1), server.port(0))
        .unwrap()
        .latency(L2)
        .impair(impaired())
        .impair_from(server.port(0), impaired().loss_ppm(30_000));
}

/// Through the wire format, as a carrier would move it.
fn carry(m: Msg) -> Msg {
    Msg::decode(&m.encode()).expect("a message decodes")
}

/// Runs the network split into the sites `split[0]` and `split[1]` on this thread, in
/// lockstep, and merges their records.
fn run_split(split: [&[&str]; 2], lookahead: Nanos) -> sites::Merged {
    let mut nets = split.map(devices);
    let hellos = [sites::hello(&nets[0]), sites::hello(&nets[1])];
    for (i, hello) in hellos.into_iter().enumerate() {
        sites::apply_hello(&mut nets[1 - i], &carry(hello)).unwrap();
    }
    for n in &mut nets {
        links(n);
    }
    let mut sync = [
        SiteSync::new(lookahead, None),
        SiteSync::new(lookahead, None),
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
            let r = SiteRecords::collect(&nets[i], outcome);
            // RECORDS crosses the wire too.
            match carry(Msg::Records(Box::new(r))) {
                Msg::Records(r) => *r,
                other => panic!("{other:?}"),
            }
        })
        .collect();
    let names: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
    sites::merge([&records[0], &records[1]], &names, None).unwrap()
}

#[test]
fn an_impaired_network_split_over_two_sites_matches_the_unsplit_one() {
    let mut whole = devices(&NAMES);
    links(&mut whole);
    let outcome = whole
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("{e}\n{}", transcript(&whole.journal())));
    let journal = whole.journal();
    let done = events(&journal, "client", "http-get-done");
    assert_eq!(done.len(), 1, "{}", transcript(&journal));
    assert_eq!(field(&done[0], "body-bytes"), "200000");
    let stats: Vec<_> = whole
        .links()
        .into_iter()
        .map(|l| whole.link_stats(l))
        .collect();
    assert!(
        stats.iter().all(|s| s.lost_random.iter().sum::<u64>() > 0),
        "both links lose frames: {stats:?}"
    );
    println!("unsplit: {outcome:?}, links {stats:?}");

    // Split at L1 (the impaired WAN link is L1, L2 is local to the server's site), then at L2.
    for (split, lookahead) in [
        ([&["client"][..], &["sw", "server"][..]], L1),
        ([&["client", "sw"][..], &["server"][..]], L2),
    ] {
        let merged = run_split(split, lookahead);
        let what = format!("split {split:?}");
        assert_eq!(merged.outcome, Ok(outcome.clone()), "{what}");
        assert_eq!(merged.journal, journal, "{what}: journal");
        assert_eq!(merged.frames, whole.frames(), "{what}: frame log");
        for (l, (s, pcap)) in whole.links().into_iter().zip(&merged.links) {
            assert_eq!(*s, whole.link_stats(l), "{what}: link {l:?} counters");
            assert!(*pcap == whole.pcap(l), "{what}: link {l:?} capture");
        }
    }
}

#[test]
fn operator_events_change_impairments_while_the_network_runs() {
    let b = built();
    let mut network = Network::new(&b.host, 5);
    let cfg = config(&[("count", "50"), ("interval", "10us")]);
    let a = network
        .device_with_config("blaster", &b.load("blaster"), cfg)
        .unwrap();
    let r = network.device("reflector", &b.load("reflector")).unwrap();
    let link = network
        .link(a.port(0), r.port(0))
        .unwrap()
        .latency(50 * US)
        .id();
    let all = Impairments::default().loss_ppm(1_000_000);
    // Probe k leaves at 10k µs and is echoed at 10k + 50 µs. From 255 µs the reflector's
    // direction loses everything; from 400 µs, by name, both directions are plain again.
    network
        .add_op(
            Op::impair(link, all).with_from(1),
            Placement::StartOf(255 * US),
        )
        .unwrap();
    network
        .add_op(
            Op::impair_named("blaster.0-reflector.0", Impairments::default()),
            Placement::StartOf(400 * US),
        )
        .unwrap();
    let bad = Op::impair(link, all).with_from(2);
    assert!(network.add_op(bad, Placement::StartOf(US)).is_err());
    let missing = Op::impair_named("no-such-link", all);
    let missing = network.add_op(missing, Placement::StartOf(US)).unwrap();
    network.run_until_quiescent().unwrap();

    let stats = network.link_stats(link);
    assert_eq!(stats.frames, [50, 50]);
    // Echoes 21 ..= 34 (sent at 260 .. 390 µs) were lost.
    assert_eq!(stats.lost_random, [0, 14]);
    assert_eq!(
        network.link_info(link).impairments,
        [Impairments::default(); 2]
    );
    let states = network.op_states();
    assert!(
        matches!(states[missing], OpState::Failed { .. }),
        "{:?}",
        states[missing]
    );
    let changed = events(&network.journal(), "blaster", "link-changed");
    assert_eq!(changed.len(), 1, "the named op is journalled");
    assert_eq!(field(&changed[0], "loss-ppm"), "0");
}
