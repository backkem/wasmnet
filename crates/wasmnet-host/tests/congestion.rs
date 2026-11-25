//! TCP congestion control and retransmission timeouts end to end
//! (`docs/design/netstack.md`): real composed nodes fetch 1 MB over a rated link with a small
//! transmit queue, over a lossy one, and over a long one.
//!
//! * With the netstack's default controller (Reno) each fetch finishes within a bound derived
//!   below (through the small queue: its serialisation time plus one timeout), and replays
//!   byte for byte at two seeds.
//! * `tcp.congestion = "none"` with `tcp.rto-min = "1s"` keeps a pinned timing close to the one
//!   from before the netstack had congestion control (see that test for what changed it since).
//! * Over a path of 300 ms each way nothing is retransmitted although the least timeout is
//!   200 ms: Linux's rule keeps the timeout at least 200 ms above the smoothed round trip.
//! * `fetch_times` (ignored: run it by name) prints the fetch times at seeds 1 to 8 for the
//!   least timeouts of 1 s and 200 ms.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (see `support`). Replay a failure with
//! `cargo test -p wasmnet-host --test congestion -- --nocapture`.

mod support;

use etherparse::{SlicedPacket, TransportSlice};
use support::{built, config, events, field, transcript};
use wasmnet_host::sim::Impairments;
use wasmnet_host::{FrameRecord, JournalEntry, LinkStats, Nanos, Network, Outcome, PortRef};

const US: Nanos = 1_000;
const MS: Nanos = 1_000_000;

/// The body `GET /big?n=` asks for.
const BULK: u64 = 1_000_000;
const RATE: u64 = 10_000_000;
const LATENCY: Nanos = 100 * US;
/// When the client starts its fetch (`app.http-get.start`).
const START: Nanos = MS;

/// A full data frame: 1460 bytes of payload behind the Ethernet, IPv4 and TCP headers.
const FRAME: u64 = 1514;
const PAYLOAD: u64 = 1460;
/// The longest retransmission timeout once the round trip is measured, as long as no timeout
/// backed it off: the netstack's `tcp.rto-min` (200 ms by default) is a margin over the
/// smoothed round trip (Linux's rule), and the round trip here, a delayed ACK and four queued
/// frames included, stays under 20 ms.
const MIN_RTO: Nanos = 220 * MS;
/// The retransmission timeout before the round trip is measured (RFC 6298's 1 s): what a lost
/// SYN or SYN-ACK costs.
const INITIAL_RTO: Nanos = 1_000 * MS;

/// The time the server's transmitter needs for the body alone: every full data frame
/// serialised back to back. Nothing can be faster than this (about 0.83 s; size / rate alone
/// is 0.8 s).
fn serialisation() -> Nanos {
    BULK.div_ceil(PAYLOAD)
        * Impairments::default()
            .rate(RATE)
            .serialisation(FRAME as usize)
}

/// One finished fetch.
struct Fetch {
    journal: Vec<JournalEntry>,
    frames: Vec<FrameRecord>,
    stats: LinkStats,
    server: PortRef,
    /// From the fetch's start to `http-get-done`.
    took: Nanos,
}

impl Fetch {
    /// Data segments the server sent again (a sequence range it had sent before).
    fn retransmissions(&self) -> usize {
        let mut highest: Option<u32> = None;
        let mut again = 0;
        for f in self.frames.iter().filter(|f| f.from == self.server) {
            let Ok(packet) = SlicedPacket::from_ethernet(&f.bytes) else {
                continue;
            };
            let Some(TransportSlice::Tcp(tcp)) = packet.transport else {
                continue;
            };
            if tcp.payload().is_empty() {
                continue;
            }
            let end = tcp
                .sequence_number()
                .wrapping_add(tcp.payload().len() as u32);
            match highest {
                Some(h) if end.wrapping_sub(h) as i32 <= 0 => again += 1,
                _ => highest = Some(end),
            }
        }
        again
    }
}

/// How the two nodes are set up: both nodes get `tcp` (`tcp.*` keys), the link `latency` and,
/// each direction, `imp`.
#[derive(Clone, Copy)]
struct Setup<'a> {
    tcp: &'a [(&'a str, &'a str)],
    latency: Nanos,
    imp: Impairments,
}

impl<'a> Setup<'a> {
    fn new(tcp: &'a [(&'a str, &'a str)], imp: Impairments) -> Self {
        Self {
            tcp,
            latency: LATENCY,
            imp,
        }
    }
}

/// `server` and `client` on one link as `setup` says; the client fetches `/big?n=BULK`.
fn fetch(seed: u64, setup: Setup) -> Fetch {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let mut server_config = vec![
        ("mac", "02:00:00:00:00:01"),
        ("ipv4", "10.0.0.1/24"),
        ("app.http-server.listen", "0.0.0.0:80"),
    ];
    server_config.extend_from_slice(setup.tcp);
    let server = network
        .device_with_config(
            "server",
            &b.load("node-http-server"),
            config(&server_config),
        )
        .unwrap();
    let url = format!("http://web/big?n={BULK}");
    let mut client_config = vec![
        ("mac", "02:00:00:00:00:02"),
        ("ipv4", "10.0.0.2/24"),
        ("hosts.web", "10.0.0.1"),
        ("app.http-get.url", &url),
        ("app.http-get.start", "1ms"),
    ];
    client_config.extend_from_slice(setup.tcp);
    let client = network
        .device_with_config("client", &b.load("node-http-get"), config(&client_config))
        .unwrap();
    let link = network
        .link(server.port(0), client.port(0))
        .unwrap()
        .latency(setup.latency)
        .impair(setup.imp)
        .id();
    let outcome = network
        .run_until_quiescent()
        .unwrap_or_else(|e| panic!("seed={seed}: {e}\n{}", transcript(&network.journal())));
    assert!(matches!(outcome, Outcome::Quiescent { .. }), "{outcome:?}");
    let journal = network.journal();
    let log = transcript(&journal);
    let done = events(&journal, "client", "http-get-done");
    assert_eq!(done.len(), 1, "seed={seed}: one fetch\n{log}");
    assert_eq!(field(&done[0], "status"), "200", "{log}");
    assert_eq!(field(&done[0], "body-bytes"), BULK.to_string(), "{log}");
    let sent = events(&journal, "server", "http-response");
    assert_eq!(
        field(&done[0], "body-fnv"),
        field(&sent[0], "body-fnv"),
        "seed={seed}: the body arrived intact"
    );
    let at = journal
        .iter()
        .find(|e| {
            matches!(&e.record, wasmnet_host::Record::Event { kind, .. } if kind == "http-get-done")
        })
        .map(|e| e.at)
        .expect("http-get-done");
    Fetch {
        stats: network.link_stats(link),
        frames: network.frames(),
        journal,
        server: server.port(0),
        took: at - START,
    }
}

/// One line about a fetch, for `--nocapture`.
fn describe(label: &str, seed: u64, run: &Fetch) -> String {
    format!(
        "{label} seed={seed}: took {} ns ({:.3} x serialisation), {} retransmitted, dropped by \
         the queue {:?}, lost {:?}",
        run.took,
        run.took as f64 / serialisation() as f64,
        run.retransmissions(),
        run.stats.dropped_queue,
        run.stats.lost_random,
    )
}

/// Runs `fetch` twice at each of two seeds: each seed replays byte for byte. Returns the
/// first seed's run.
fn replayed(label: &str, setup: Setup) -> Fetch {
    let mut first = None;
    for seed in [1, 2] {
        let a = fetch(seed, setup);
        let b = fetch(seed, setup);
        assert!(a.frames == b.frames, "seed={seed}: the frames differ");
        assert!(a.journal == b.journal, "seed={seed}: the journals differ");
        println!("{}", describe(label, seed, &a));
        first.get_or_insert(a);
    }
    first.unwrap()
}

/// 1 MB at 10 Mbit/s through a transmit queue of 4 frames.
///
/// The bound: the round trip without queueing is 2 x 100 us plus one frame's 1.2 ms on the
/// wire, so the bandwidth-delay product is about 1.2 frames, and the queue holds 4 more.
/// Reno's window saws between the pipe's 5 to 6 frames and half of that, which is still more
/// than the bandwidth-delay product, so the link stays busy while Reno probes and halves.
/// Each time the window outgrows the pipe the queue drops a frame or a few; while new data
/// follows, duplicate ACKs and partial ACKs (NewReno) repair every hole within a few round
/// trips. Only the transfer's last window cannot be repaired that way: too few segments follow
/// a drop there to bring three duplicate ACKs, so the fetch may end in one retransmission
/// timeout, at most [`MIN_RTO`]. The fetch must therefore finish within the serialisation time
/// plus 10 % (the handshake, the request, slow start, the repairs) plus one timeout: about
/// 1.1 s, against 54 virtual minutes without congestion control.
#[test]
fn a_bulk_fetch_through_a_small_queue_takes_close_to_its_serialisation_time() {
    let imp = Impairments::default().rate(RATE).queue(4);
    let run = replayed("reno", Setup::new(&[], imp));
    let bound = serialisation() + serialisation() / 10 + MIN_RTO;
    assert!(
        run.took >= serialisation(),
        "faster than the link: {} ns",
        run.took
    );
    assert!(
        run.took <= bound,
        "took {} ns, bound {bound} ns (serialisation {} ns)",
        run.took,
        serialisation()
    );
    assert!(
        run.stats.dropped_queue[0] > 0,
        "Reno probes until the queue overflows"
    );
}

/// 1 MB at 10 Mbit/s with 1 % of the frames lost each way (the default queue of 1000 frames
/// never fills: the receive window is 64 KiB, 45 frames).
///
/// The bound: with a window of tens of segments, three duplicate ACKs follow a lost segment
/// within a round trip, and fast retransmit and NewReno repair it, and any further hole in
/// the same window, in a few round trips (1.4 ms each) while the link keeps sending. What
/// duplicate ACKs cannot repair costs one retransmission timeout: a loss while the window is
/// under four segments (the first round trips, or right after a timeout), a loss among the
/// last three segments, a lost retransmission, a lost request. A timeout costs the timeout in
/// force (at most [`MIN_RTO`], doubled for each further timeout of the same segment) plus
/// resending the window (at most 45 frames, 55 ms). Counting every lost frame, in either
/// direction, as two such timeouts covers all of that unless one segment is lost three times
/// in a row (probability about one in a million per segment); a SYN or SYN-ACK lost before the
/// round trip was measured costs RFC 6298's initial second instead, counted once. The fetch
/// must finish within the serialisation time plus 10 % plus that. Measured at seeds 1 to 8
/// (`fetch_times`) it took 0.85 s to 2.07 s with a least timeout of 200 ms, against 0.85 s to
/// 5.83 s with 1 s, with 8 to 16 frames lost.
#[test]
fn a_bulk_fetch_over_a_lossy_link_finishes_within_its_loss_bound() {
    let imp = Impairments::default().rate(RATE).loss_ppm(10_000);
    let run = replayed("reno", Setup::new(&[], imp));
    let lost = run.stats.lost_random[0] + run.stats.lost_random[1];
    let bound = serialisation() + serialisation() / 10 + INITIAL_RTO + lost * 2 * MIN_RTO;
    assert!(lost > 0, "frames were lost");
    assert!(run.retransmissions() > 0, "and sent again");
    assert!(
        run.took <= bound,
        "took {} ns with {lost} frames lost, bound {bound} ns (serialisation {} ns)",
        run.took,
        serialisation()
    );
}

/// 1 MB at 10 Mbit/s over a path of 300 ms each way, nothing lost: no segment is sent twice.
/// The round trip (600 ms, plus up to 55 ms of a window's serialisation and the 10 ms delayed
/// ACK) is far above the least timeout of 200 ms, and on a steady path RFC 6298's variation
/// term decays to a few milliseconds; Linux's rule keeps the timeout at least 200 ms above the
/// smoothed round trip, so the round trips that are longer than usual (the last segments of a
/// window, a delayed ACK) do not trip it.
#[test]
fn a_long_path_has_no_spurious_retransmission() {
    let imp = Impairments::default().rate(RATE);
    let setup = Setup {
        latency: 300 * MS,
        ..Setup::new(&[], imp)
    };
    let run = replayed("reno 300ms", setup);
    assert_eq!(run.retransmissions(), 0, "spurious retransmissions");
    // At most one 64 KiB window per round trip: 16 round trips and the handshake.
    assert!(run.took > 16 * 600 * MS, "took {} ns", run.took);
}

/// Without congestion control the netstack sends its whole window at once and recovers each
/// loss on its own three duplicate ACKs: the small-queue fetch takes about 54 virtual
/// minutes, mostly in retransmission timeouts.
///
/// Pinned with `tcp.rto-min = 1s`. Before the netstack had congestion control this fetch's
/// `http-get-done` came at 3 246 882 938 200 ns; with `tcp.rto-min` a measured timeout is the
/// smoothed round trip (a few milliseconds here) plus 1 s instead of exactly 1 s, which moves it
/// 504 ms later over the run. Everything else about the timing is as it was.
#[test]
fn none_keeps_the_timing_from_before_congestion_control() {
    /// `http-get-done` of this fetch at seed 1.
    const BEFORE: Nanos = 3_247_386_938_200;
    let tcp = [("tcp.congestion", "none"), ("tcp.rto-min", "1s")];
    let run = fetch(
        1,
        Setup::new(&tcp, Impairments::default().rate(RATE).queue(4)),
    );
    println!(
        "none seed=1: took {} ns, {} retransmitted, dropped by the queue {:?}",
        run.took,
        run.retransmissions(),
        run.stats.dropped_queue
    );
    assert_eq!(run.took + START, BEFORE);
}

/// Prints the fetch times through the small queue and over the lossy link at seeds 1 to 8,
/// with the least retransmission timeout at 1 s (the netstack before `tcp.rto-min`) and at its
/// default, 200 ms. A measurement, not a check:
/// `cargo test -p wasmnet-host --test congestion -- --ignored fetch_times --nocapture`.
#[test]
#[ignore = "a measurement: run it by name"]
fn fetch_times() {
    let queue = Impairments::default().rate(RATE).queue(4);
    let lossy = Impairments::default().rate(RATE).loss_ppm(10_000);
    for (name, imp) in [("small queue", queue), ("lossy", lossy)] {
        for rto in ["1s", "200ms"] {
            let tcp = [("tcp.rto-min", rto)];
            let mut took = Vec::new();
            for seed in 1..=8 {
                let run = fetch(seed, Setup::new(&tcp, imp));
                println!("{}", describe(&format!("{name} rto-min={rto}"), seed, &run));
                took.push(run.took);
            }
            let min = took.iter().min().unwrap();
            let max = took.iter().max().unwrap();
            println!(
                "{name} rto-min={rto}: {:.2} s to {:.2} s",
                *min as f64 / 1e9,
                *max as f64 / 1e9
            );
        }
    }
}
