//! TCP congestion control end to end (`docs/design/netstack.md`): real composed nodes fetch
//! 1 MB over a rated link with a small transmit queue, and over a lossy one.
//!
//! * With the netstack's default controller (Reno) each fetch finishes within a bound derived
//!   below (through the small queue: its serialisation time plus one timeout), and replays
//!   byte for byte at two seeds.
//! * `tcp.congestion = "none"` gives exactly the timing the netstack had before it had
//!   congestion control.
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
/// smoltcp's smallest retransmission timeout (RFC 6298's 1 s).
const MIN_RTO: Nanos = 1_000 * MS;

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

/// `server` and `client` on one link of [`LATENCY`], each direction with `imp`, both nodes
/// with `tcp.congestion = congestion`; the client fetches `/big?n=BULK`.
fn fetch(seed: u64, congestion: &str, imp: Impairments) -> Fetch {
    let b = built();
    let mut network = Network::new(&b.host, seed);
    let server = network
        .device_with_config(
            "server",
            &b.load("node-http-server"),
            config(&[
                ("mac", "02:00:00:00:00:01"),
                ("ipv4", "10.0.0.1/24"),
                ("tcp.congestion", congestion),
                ("app.http-server.listen", "0.0.0.0:80"),
            ]),
        )
        .unwrap();
    let url = format!("http://web/big?n={BULK}");
    let client = network
        .device_with_config(
            "client",
            &b.load("node-http-get"),
            config(&[
                ("mac", "02:00:00:00:00:02"),
                ("ipv4", "10.0.0.2/24"),
                ("hosts.web", "10.0.0.1"),
                ("tcp.congestion", congestion),
                ("app.http-get.url", &url),
                ("app.http-get.start", "1ms"),
            ]),
        )
        .unwrap();
    let link = network
        .link(server.port(0), client.port(0))
        .unwrap()
        .latency(LATENCY)
        .impair(imp)
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

/// Runs `fetch` twice at each of two seeds: each seed replays byte for byte. Returns the
/// first seed's run.
fn replayed(congestion: &str, imp: Impairments) -> Fetch {
    let mut first = None;
    for seed in [1, 2] {
        let a = fetch(seed, congestion, imp);
        let b = fetch(seed, congestion, imp);
        assert!(a.frames == b.frames, "seed={seed}: the frames differ");
        assert!(a.journal == b.journal, "seed={seed}: the journals differ");
        println!(
            "{congestion} seed={seed}: took {} ns ({:.3} x serialisation), {} retransmitted, \
             dropped by the queue {:?}, lost {:?}",
            a.took,
            a.took as f64 / serialisation() as f64,
            a.retransmissions(),
            a.stats.dropped_queue,
            a.stats.lost_random,
        );
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
/// timeout, at least 1 s. The fetch must therefore finish within the serialisation time plus
/// 10 % (the handshake, the request, slow start, the repairs) plus one minimum RTO: about
/// 1.9 s, against 54 virtual minutes without congestion control.
#[test]
fn a_bulk_fetch_through_a_small_queue_takes_close_to_its_serialisation_time() {
    let imp = Impairments::default().rate(RATE).queue(4);
    let run = replayed("reno", imp);
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
/// last three segments, a lost retransmission, a lost SYN or request. A timeout costs the
/// RTO in force (1 s, doubled for each further timeout of the same segment) plus resending the
/// window (at most 45 frames, 55 ms). Counting every lost frame, in either direction, as two
/// minimum RTOs covers all of that unless one segment is lost three times in a row
/// (probability about one in a million per segment): the fetch must finish within the
/// serialisation time plus 10 % plus 2 s per lost frame. Measured at seeds 1 to 8 it took
/// 0.85 s to 5.8 s, with 8 to 16 frames lost.
#[test]
fn a_bulk_fetch_over_a_lossy_link_finishes_within_its_loss_bound() {
    let imp = Impairments::default().rate(RATE).loss_ppm(10_000);
    let run = replayed("reno", imp);
    let lost = run.stats.lost_random[0] + run.stats.lost_random[1];
    let bound = serialisation() + serialisation() / 10 + lost * 2 * MIN_RTO;
    assert!(lost > 0, "frames were lost");
    assert!(run.retransmissions() > 0, "and sent again");
    assert!(
        run.took <= bound,
        "took {} ns with {lost} frames lost, bound {bound} ns (serialisation {} ns)",
        run.took,
        serialisation()
    );
}

/// Without congestion control the netstack sends its whole window at once and recovers each
/// loss on its own three duplicate ACKs, as it did before: the small-queue fetch takes exactly
/// as long as it did then, about 54 virtual minutes, mostly in retransmission timeouts.
#[test]
fn none_keeps_the_timing_from_before_congestion_control() {
    /// `http-get-done` of this fetch at seed 1, measured before the netstack had congestion
    /// control.
    const BEFORE: Nanos = 3_246_882_938_200;
    let run = fetch(1, "none", Impairments::default().rate(RATE).queue(4));
    println!(
        "none seed=1: took {} ns, {} retransmitted, dropped by the queue {:?}",
        run.took,
        run.retransmissions(),
        run.stats.dropped_queue
    );
    assert_eq!(run.took + START, BEFORE);
}
