//! The patch panel: point-to-point links between device ports, with latency, carrier (up/down),
//! an MTU, per-direction impairments (a rate with a bounded transmit queue, seeded loss and
//! jitter), pcap taps and a frame log.
//!
//! `wire.transmit` lands here. It never calls into a device. A frame on an unwired port, on a
//! down link, with a payload over the link MTU or that finds its direction's transmit queue full
//! is dropped and counted. Otherwise it is tapped as *outbound* on the sender's end and, unless
//! the direction's seeded loss takes it, a delivery is queued at its arrival time (`now +
//! latency` without impairments). When the executor fires that delivery, the frame is tapped as
//! *inbound* on the receiver's end and goes to the receiver's inbox, unless the link went down in
//! the meantime (then it is lost). The model is described in `docs/design/links.md`.
//!
//! Each link has one pcap-ng capture with one interface per end (`<device>:<port>`), so a link's
//! file shows what each NIC saw and when, with direction flags and virtual-ns timestamps. The
//! frame log keeps every transmission with its fate, for run records and assertions.
//!
//! The only frame parsing here is the L2 header length (for the MTU), which is link-model
//! behaviour like a PHY's maximum frame size, not networking logic.

use std::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use wasmnet_wire::{Direction, EthernetFrame, InterfaceId, MacAddr, PcapNgEncoder};

use crate::clock::{Delivery, DeviceIdx, EventKey, Nanos, Tag, VirtualClock};
use crate::digest::{self, Digest};
use crate::ext::{CableKind, CableModel, CableSend, Carry, ExtValue};
use crate::journal::{Journal, JournalEntry};
use crate::network::{DeviceId, LinkId, PortRef};
use crate::rng::{SimRng, derive_seed};

/// `shb_userappl` in every capture.
const PCAP_USER_APPL: &str = "wasmnet";

/// The frame-log index of a delivery that carries a cable's message: such messages are not in
/// the frame log.
const CABLE_MESSAGE: usize = usize::MAX;

/// One port, as the device declared it in `ports()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortInfo {
    pub id: u32,
    pub name: String,
    pub mac: Option<MacAddr>,
    /// Largest payload after the Ethernet header.
    pub mtu: u32,
}

/// Counters for one link. Each array is indexed by the *sending* end (0 = `a`, 1 = `b`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkStats {
    /// Frames that entered the wire (tapped outbound).
    pub frames: [u64; 2],
    /// Bytes that entered the wire.
    pub bytes: [u64; 2],
    /// Frames transmitted while the link was down (never on the wire).
    pub dropped_down: [u64; 2],
    /// Frames whose payload exceeded the link MTU (never on the wire).
    pub oversize: [u64; 2],
    /// Frames that were in flight when the link went down (tapped outbound, never delivered).
    pub lost: [u64; 2],
    /// Frames that found the direction's transmit queue full (never on the wire).
    pub dropped_queue: [u64; 2],
    /// Frames the direction's seeded loss took (tapped outbound, never delivered).
    pub lost_random: [u64; 2],
}

impl LinkStats {
    /// What was counted after `earlier`, a read of the same link's counters
    /// ([`Network::link_stats`](crate::Network::link_stats)) taken before this one: the
    /// traffic of the interval between the two reads. Saturating, so a read that is not
    /// earlier gives zeros rather than wrapping.
    ///
    /// ```
    /// # use wasmnet_core::LinkStats;
    /// let mut before = LinkStats::default();
    /// before.frames = [3, 1];
    /// let mut after = before;
    /// after.frames = [10, 4];
    /// after.bytes = [600, 180];
    /// let window = after.since(&before);
    /// assert_eq!((window.frames, window.bytes), ([7, 3], [600, 180]));
    /// ```
    pub fn since(&self, earlier: &LinkStats) -> LinkStats {
        let mut out = *self;
        out.zip_with(earlier, u64::saturating_sub);
        out
    }

    /// Adds `other`'s counters to these (saturating): two sites' halves of a link, or the
    /// buckets of a series.
    pub fn add(&mut self, other: &LinkStats) {
        self.zip_with(other, u64::saturating_add);
    }

    fn zip_with(&mut self, other: &LinkStats, f: fn(u64, u64) -> u64) {
        for (mine, theirs) in [
            (&mut self.frames, other.frames),
            (&mut self.bytes, other.bytes),
            (&mut self.dropped_down, other.dropped_down),
            (&mut self.oversize, other.oversize),
            (&mut self.lost, other.lost),
            (&mut self.dropped_queue, other.dropped_queue),
            (&mut self.lost_random, other.lost_random),
        ] {
            for end in 0..2 {
                mine[end] = f(mine[end], theirs[end]);
            }
        }
    }
}

/// What a link's capture and frame log keep (`docs/design/links.md`, "What a link records").
/// The default keeps everything and names nothing, exactly as a link without the option.
///
/// ```
/// # use wasmnet_core::CaptureOptions;
/// // Headers only: the first 128 bytes of each frame, and the capture names its ends.
/// let headers = CaptureOptions::default().snap_len(128).name_ends(true);
/// assert!(headers.record);
/// assert_eq!(CaptureOptions::default().record(false).kept(1514), 0);
/// assert_eq!(headers.kept(1514), 128);
/// assert_eq!(headers.kept(60), 60);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CaptureOptions {
    /// Keep frame bytes at all. Off, the capture holds its header and no packet, and the frame
    /// log keeps each transmission's record (link, ends, time, fate, length) without its
    /// bytes. Default on.
    pub record: bool,
    /// Keep at most this many bytes of each frame, in the capture (the `snaplen` of both
    /// interfaces; each packet records its original length) and in the frame log
    /// ([`FrameRecord::len`] is the original length). 0: whole frames (the default).
    pub snap_len: u32,
    /// Name the link's two ends in the capture header: each interface's `if_description` is a
    /// [`LinkEnd`](crate::pcap::LinkEnd). Default off (no description, as before the option).
    pub name_ends: bool,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            record: true,
            snap_len: 0,
            name_ends: false,
        }
    }
}

impl CaptureOptions {
    /// Keeping frame bytes, or not.
    pub const fn record(mut self, on: bool) -> Self {
        self.record = on;
        self
    }

    /// Keeping at most `bytes` of each frame (0: whole frames).
    pub const fn snap_len(mut self, bytes: u32) -> Self {
        self.snap_len = bytes;
        self
    }

    /// Naming the link's ends in the capture header, or not.
    pub const fn name_ends(mut self, on: bool) -> Self {
        self.name_ends = on;
        self
    }

    /// How many bytes of a frame of `len` bytes are kept.
    pub const fn kept(&self, len: usize) -> usize {
        if !self.record {
            0
        } else if self.snap_len == 0 || len <= self.snap_len as usize {
            len
        } else {
            self.snap_len as usize
        }
    }
}

/// A link's counters per interval of virtual time (`docs/design/links.md`, "Counters"):
/// buckets of `width` ns, the last `keep` of those in which a counter changed. A link keeps
/// at most `keep` [`LinkStats`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SeriesOptions {
    /// The bucket width in ns (0 counts as 1).
    pub width: Nanos,
    /// How many buckets to keep (0 counts as 1): the oldest goes when one more starts.
    pub keep: u32,
}

impl SeriesOptions {
    /// Buckets of `width` ns, the last `keep` kept.
    pub const fn new(width: Nanos, keep: u32) -> Self {
        Self { width, keep }
    }
}

/// One link's bucketed counters.
struct Series {
    options: SeriesOptions,
    /// `(bucket index, counters)`, oldest first: only buckets in which something counted.
    buckets: VecDeque<(u64, LinkStats)>,
}

impl Series {
    fn new(options: SeriesOptions) -> Self {
        Self {
            options,
            buckets: VecDeque::new(),
        }
    }

    /// The bucket of instant `at` (instants come in order).
    fn bucket(&mut self, at: Nanos) -> &mut LinkStats {
        let index = at / self.options.width.max(1);
        if self.buckets.back().is_none_or(|&(i, _)| i != index) {
            if self.buckets.len() >= self.options.keep.max(1) as usize {
                self.buckets.pop_front();
            }
            self.buckets.push_back((index, LinkStats::default()));
        }
        &mut self.buckets.back_mut().expect("just pushed").1
    }

    /// `(bucket start, counters)`, oldest first.
    fn read(&self) -> Vec<(Nanos, LinkStats)> {
        let width = self.options.width.max(1);
        self.buckets
            .iter()
            .map(|&(i, s)| (i.saturating_mul(width), s))
            .collect()
    }
}

/// [`Impairments::queue`] unless set: Linux's default `txqueuelen`.
pub const DEFAULT_QUEUE: u32 = 1000;

/// One million: the [`Impairments::loss_ppm`] of a direction that loses every frame.
pub const PPM: u32 = 1_000_000;

/// How one direction of a link carries frames beyond its latency (`docs/design/links.md`). The
/// default changes nothing: no rate, no loss, no jitter, and no random numbers drawn.
///
/// ```
/// # use wasmnet_core::Impairments;
/// // 10 Mbit/s, at most 64 frames waiting, 1 % loss, up to 50 µs of jitter.
/// let slow = Impairments::default()
///     .rate(10_000_000)
///     .queue(64)
///     .loss_ppm(10_000)
///     .jitter(50_000);
/// assert!(!slow.is_off());
/// assert!(Impairments::default().is_off());
/// // A 1514-byte frame takes 1211.2 µs at 10 Mbit/s, rounded up to the nanosecond.
/// assert_eq!(slow.serialisation(1514), 1_211_200);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Impairments {
    /// Bits per second; 0: unlimited (no serialisation delay, so no queue either). A frame of
    /// `n` bytes (as transmitted: header and payload, no preamble or FCS) occupies the
    /// transmitter for `ceil(n * 8 * 10^9 / rate)` ns.
    pub rate: u64,
    /// Frames that may wait behind the one being serialised; one more is dropped (tail drop).
    /// A frame that finds the transmitter idle is never dropped. Default [`DEFAULT_QUEUE`].
    pub queue: u32,
    /// The probability that a frame is lost on the wire, in parts per million (values above
    /// [`PPM`] count as [`PPM`]). 0 and [`PPM`] draw no random numbers.
    pub loss_ppm: u32,
    /// The largest extra delay in ns: each frame waits a uniform draw from `[0, jitter]` on top
    /// of the latency, and never arrives before the frame transmitted before it.
    pub jitter: Nanos,
}

impl Default for Impairments {
    fn default() -> Self {
        Self {
            rate: 0,
            queue: DEFAULT_QUEUE,
            loss_ppm: 0,
            jitter: 0,
        }
    }
}

impl Impairments {
    /// With a rate in bits per second (0: unlimited).
    pub const fn rate(mut self, bits_per_second: u64) -> Self {
        self.rate = bits_per_second;
        self
    }

    /// With a transmit queue of `frames` (waiting behind the one being serialised).
    pub const fn queue(mut self, frames: u32) -> Self {
        self.queue = frames;
        self
    }

    /// With a loss probability in parts per million (`10_000` is 1 %).
    pub const fn loss_ppm(mut self, ppm: u32) -> Self {
        self.loss_ppm = ppm;
        self
    }

    /// With up to `ns` of jitter.
    pub const fn jitter(mut self, ns: Nanos) -> Self {
        self.jitter = ns;
        self
    }

    /// No rate, no loss and no jitter: the direction behaves as a plain link (the queue bound
    /// alone changes nothing).
    pub const fn is_off(&self) -> bool {
        self.rate == 0 && self.loss_ppm == 0 && self.jitter == 0
    }

    /// How long a frame of `len` bytes occupies the transmitter, in ns (0 without a rate).
    pub const fn serialisation(&self, len: usize) -> Nanos {
        if self.rate == 0 {
            return 0;
        }
        let bits = len as u128 * 8 * 1_000_000_000;
        let ns = bits.div_ceil(self.rate as u128);
        if ns > Nanos::MAX as u128 {
            Nanos::MAX
        } else {
            ns as Nanos
        }
    }
}

/// Static and current properties of a link.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkInfo {
    /// File-name safe: `<device>.<port>-<device>.<port>`.
    pub name: String,
    pub ends: [PortRef; 2],
    /// One-way latency in virtual ns (the same both ways).
    pub latency: Nanos,
    /// Largest payload after the Ethernet header (802.1Q tag excluded).
    pub mtu: u32,
    /// Current carrier state.
    pub up: bool,
    /// Unwired by an operator event: its ports are free again; it stays in the
    /// records with its capture.
    pub removed: bool,
    /// What it carries: Ethernet frames, or a cable's messages.
    pub kind: LinkKind,
    /// Each direction's impairments, indexed by the sending end (0 = `a`, 1 = `b`). Cables
    /// ignore them.
    pub impairments: [Impairments; 2],
    /// What its capture and frame log keep.
    pub capture: CaptureOptions,
    /// The notes its capture carries as section comments
    /// ([`Network::set_capture_notes`](crate::Network::set_capture_notes)).
    pub capture_notes: Vec<String>,
}

/// What a link carries. A cable kind is a registered [`CableModel`] that names its
/// payload, its timing and its tap; a cable has no pcap and no frame log and never crosses
/// sites.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinkKind {
    /// Ethernet frames: the pcap and the frame log.
    #[default]
    Ethernet,
    /// A registered cable kind.
    Cable(CableKind),
}

impl LinkKind {
    /// A cable: no pcap, no frame log.
    pub fn is_cable(self) -> bool {
        self != LinkKind::Ethernet
    }

    /// The kind's stable code: 0 for Ethernet, the cable kind's code otherwise.
    pub fn code(self) -> u8 {
        match self {
            LinkKind::Ethernet => 0,
            LinkKind::Cable(kind) => kind.code(),
        }
    }

    /// The kind with code `code` ([`code`](Self::code)).
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => LinkKind::Ethernet,
            c => LinkKind::Cable(CableKind::new(c)),
        }
    }
}

/// Why a frame never entered the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DropReason {
    /// The link was down at transmit time.
    LinkDown,
    /// The payload exceeded the link MTU.
    Oversize,
    /// An operator dropped it: a frame rule, or a [`TransmitHook`]'s verdict.
    Operator,
    /// Its direction's transmit queue was full ([`Impairments::queue`]).
    QueueFull,
}

impl DropReason {
    /// `link-down`, `oversize`, `operator` or `queue-full`.
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::LinkDown => "link-down",
            DropReason::Oversize => "oversize",
            DropReason::Operator => "operator",
            DropReason::QueueFull => "queue-full",
        }
    }
}

/// What an operator does to one transmission, at `wire.transmit`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameAction {
    /// It never enters the wire (fate `dropped`, reason `operator`).
    Drop,
    /// These bytes enter the wire instead (and are what the pcap and frame log show).
    Replace(Vec<u8>),
    /// It arrives this much later than the link's latency.
    Delay(Nanos),
}

/// A transmission on a wired port, as a [`TransmitHook`] sees it before it enters the wire.
#[non_exhaustive]
pub struct Transmit<'a> {
    /// The tag its frame record will get, and that tag's causal digest (`fr:`).
    pub tag: &'a Tag,
    pub digest: Digest,
    pub link: LinkId,
    pub from: PortRef,
    pub to: PortRef,
    pub at: Nanos,
    pub bytes: &'a [u8],
    /// The frame rule for this transmission, if one matched (it applies regardless).
    pub rule: Option<&'a FrameAction>,
}

/// Called on the simulation's thread for every transmission on a wired port while installed (an
/// embedder's monitor or breakpoint). It may block: the simulation waits. Its verdict applies only when no
/// frame rule matched. It must be deterministic for a run to replay; a caller that records every
/// verdict that changed a frame as a frame rule replays without a hook.
pub type TransmitHook = Arc<dyn Fn(&Transmit<'_>) -> Option<FrameAction> + Send + Sync>;

/// What happened to a transmitted frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameFate {
    /// On the wire, not yet arrived (the run stopped at a deadline first).
    InFlight,
    /// Arrived at the peer at this instant.
    Delivered { at: Nanos },
    /// It entered the wire but never arrived: the link went down while it was in flight, or
    /// its direction's seeded loss took it.
    Lost,
    /// Never entered the wire.
    Dropped(DropReason),
}

/// One `wire.transmit` on a wired port, in transmit order.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FrameRecord {
    pub link: LinkId,
    pub from: PortRef,
    pub to: PortRef,
    /// Virtual time of the transmit call.
    pub sent_at: Nanos,
    pub fate: FrameFate,
    /// The frame's length as transmitted.
    pub len: usize,
    /// The frame's bytes as the link's [`CaptureOptions`] keep them: all `len` of them by
    /// default, the first `snap_len`, or none with recording off.
    pub bytes: Vec<u8>,
}

/// A frame leaving this site over a WAN link (a link whose other end is on another site). The
/// receiving site queues its delivery under `key`, which the sender computed exactly as a
/// local delivery would get it (`docs/design/sites.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteFrame {
    pub key: EventKey,
    pub link: LinkId,
    /// The receiving end of the link (0 or 1).
    pub to_end: usize,
    /// The link's generation at transmit time (bumped by every carrier loss).
    pub generation: u64,
    /// Index of the frame in the sending site's frame log.
    pub frame_id: usize,
    pub device: DeviceId,
    pub port: u32,
    pub bytes: Vec<u8>,
}

/// One pcap record of a WAN link, as one site saw it (its own end only). Merging both sites'
/// records by `tag` rebuilds the single-site capture.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Tap {
    pub tag: Tag,
    pub link: LinkId,
    /// The end whose interface recorded it.
    pub end: usize,
    pub at: Nanos,
    pub inbound: bool,
    /// The frame's length on the wire.
    pub len: usize,
    /// Its bytes as the link's capture keeps them (the first `snap_len`). A link that records
    /// nothing has no taps.
    pub bytes: Vec<u8>,
}

/// What became of a frame that another site sent to this one (its record is in the sender's
/// frame log, at `frame_id`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RemoteArrival {
    pub frame_id: usize,
    pub fate: FrameFate,
}

/// A carrier change of a whole link, as it happened (scripted; creating a link is not one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkTransition {
    pub at: Nanos,
    pub link: LinkId,
    pub up: bool,
}

/// Why two ports could not be wired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConnectError {
    /// The port is already on a link (or both ends are the same port).
    InUse(DeviceIdx, u32),
    /// The device did not declare the port in `ports()`.
    Unknown(DeviceIdx, u32),
}

/// Shared handle to the panel state (devices, links, captures, frame log).
#[derive(Clone, Default)]
pub(crate) struct Panel {
    inner: Arc<Mutex<PanelState>>,
    /// The transmit hook, apart from the state so it runs without the panel locked.
    hook: Arc<Mutex<Option<TransmitHook>>>,
    /// The registered cable kinds, by code.
    cables: Arc<Mutex<BTreeMap<u8, Arc<dyn CableModel>>>>,
    /// Where cables journal their events: the network journal.
    journal: Option<Journal>,
}

#[derive(Default)]
struct PanelState {
    devices: Vec<DeviceEntry>,
    links: Vec<Link>,
    /// `(device, port) -> (link, end)`.
    ends: BTreeMap<(DeviceIdx, u32), (usize, usize)>,
    frames: Vec<FrameRecord>,
    transitions: Vec<LinkTransition>,
    /// The tag of each frame-log record and of each transition (multi-site merging).
    frame_tags: Vec<Tag>,
    transition_tags: Vec<Tag>,
    /// Multi-site: frames for devices on another site, not yet sent.
    outbox: Vec<RemoteFrame>,
    /// Multi-site: this site's pcap records of WAN links (links with a remote end).
    taps: Vec<Tap>,
    /// Multi-site: fates of frames that came from another site.
    arrivals: Vec<RemoteArrival>,
    /// Operator frame rules by transmission digest.
    rules: BTreeMap<Digest, FrameAction>,
    /// The network's seed: the links' loss and jitter streams derive from it.
    seed: u64,
    /// What new links' captures keep, and their series (the network's defaults).
    capture: CaptureOptions,
    series: Option<SeriesOptions>,
}

struct DeviceEntry {
    name: String,
    ports: Vec<PortInfo>,
    /// The device runs on another site (a placeholder here).
    remote: bool,
    /// Frames transmitted on an unwired port.
    dropped: u64,
}

struct Link {
    name: String,
    ends: [(DeviceIdx, u32); 2],
    latency: Nanos,
    mtu: u32,
    up: bool,
    /// Bumped every time the link goes down, so frames in flight across a down edge are lost.
    generation: u64,
    pcap: PcapNgEncoder,
    ifaces: [InterfaceId; 2],
    stats: LinkStats,
    /// Unwired.
    removed: bool,
    /// What it carries.
    kind: LinkKind,
    /// A cable's state, kept for its model ([`CableModel::new_link`]).
    cable: Option<Box<dyn Any + Send>>,
    /// Each direction's impairments and their state, by sending end.
    lanes: [Lane; 2],
    /// What its capture and frame log keep (the snap length is the capture header's).
    capture: CaptureOptions,
    /// The notes its capture carries: section comments, added when the capture is read.
    notes: Vec<String>,
    /// A packet was written to its capture (its header is fixed from then on).
    recorded: bool,
    /// The instant it was created.
    created_at: Nanos,
    /// Its counters per interval, if asked for.
    series: Option<Series>,
}

impl Link {
    fn port_ref(&self, end: usize) -> PortRef {
        let (device, port) = self.ends[end];
        DeviceId(device).port(port)
    }

    /// Counts at instant `at`: in the totals and in the series' bucket of `at`.
    fn count(&mut self, at: Nanos, f: impl Fn(&mut LinkStats)) {
        f(&mut self.stats);
        if let Some(series) = &mut self.series {
            f(series.bucket(at));
        }
    }

    /// Writes one packet to the capture, unless the link records nothing (the encoder keeps
    /// the snap length of the header).
    fn tap(&mut self, end: usize, at: Nanos, frame: &[u8], direction: Direction) {
        if !self.capture.record {
            return;
        }
        // Only a > 4 GiB frame could fail to encode; such a frame is still delivered.
        let _ = self
            .pcap
            .write_packet_directed(self.ifaces[end], at, frame, direction);
        self.recorded = true;
    }

    /// The bytes of `frame` its frame log and taps keep.
    fn kept(&self, frame: &[u8]) -> Vec<u8> {
        frame[..self.capture.kept(frame.len())].to_vec()
    }
}

/// `capture` (a link's, whose Section Header Block is the encoder's for [`PCAP_USER_APPL`])
/// with that block written again to carry `notes` as `opt_comment`s, and the rest unchanged;
/// `capture` itself without notes. Notes are checked when set ([`crate::pcap::check_notes`]),
/// so they always fit a pcap-ng option.
fn with_notes(capture: &[u8], notes: &[String]) -> Vec<u8> {
    let notes: Vec<&str> = notes.iter().map(String::as_str).collect();
    let header = match PcapNgEncoder::with_comments(PCAP_USER_APPL, &notes) {
        Ok(header) if !notes.is_empty() => header.into_bytes(),
        _ => return capture.to_vec(),
    };
    let section = capture
        .get(4..8)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .filter(|&len| len <= capture.len())
        .unwrap_or(capture.len());
    let mut out = header;
    out.extend_from_slice(&capture[section..]);
    out
}

/// A link's capture header: one interface per end, `<device>:<port>`, with the snap length
/// and (with `name_ends`) a [`LinkEnd`](crate::pcap::LinkEnd) description each. `names` are
/// the ends' `(device, port)`.
fn capture_header(
    link: &str,
    names: [(&str, u32); 2],
    created_at: Nanos,
    capture: CaptureOptions,
) -> (PcapNgEncoder, [InterfaceId; 2]) {
    // Building a capture header cannot fail for names this short; fall back to no names.
    let mut pcap = PcapNgEncoder::new(PCAP_USER_APPL).expect("static SHB fits");
    let snap = capture.snap_len;
    let mut iface = |end: usize| {
        let (device, port) = names[end];
        let (peer_device, peer_port) = names[1 - end];
        let description = if capture.name_ends {
            crate::pcap::LinkEnd::new(link, end, device, port, peer_device, peer_port, created_at)
                .to_string()
        } else {
            String::new()
        };
        pcap.add_described_interface(&format!("{device}:{port}"), snap, &description)
            .or_else(|_| pcap.add_ethernet_interface("", snap))
            .expect("IDB without options fits")
    };
    let ifaces = [iface(0), iface(1)];
    (pcap, ifaces)
}

/// One direction of a link: its impairments, its transmitter and its random streams.
#[derive(Default)]
struct Lane {
    imp: Impairments,
    /// When the transmitter finishes the last frame it accepted.
    busy_until: Nanos,
    /// When each accepted frame that had to wait reaches the transmitter, in order: those
    /// after `now` are the queue.
    waiting: VecDeque<Nanos>,
    /// The arrival time of the last frame queued for delivery.
    last_arrival: Nanos,
    /// The loss and jitter streams, created on their first draw.
    loss: Option<SimRng>,
    jitter: Option<SimRng>,
}

/// What a direction's impairments do to one frame.
enum Shaped {
    /// The transmit queue was full: never on the wire.
    QueueFull,
    /// On the wire, then lost.
    Lost,
    /// On the wire, arriving at this instant (before an operator delay).
    Arrive(Nanos),
}

/// A uniform draw from `0..n` (`n > 0`): the high half of a 64 x 64-bit product.
fn below(rng: &mut SimRng, n: u64) -> u64 {
    ((u128::from(rng.next_u64()) * u128::from(n)) >> 64) as u64
}

impl Lane {
    /// The queue, serialisation, loss and jitter for a frame of `len` bytes handed to this
    /// direction at `now`, on a link of `latency`. The streams derive from the network seed,
    /// the link's name and the sending end.
    fn shape(
        &mut self,
        now: Nanos,
        len: usize,
        latency: Nanos,
        (seed, link, end): (u64, &str, usize),
    ) -> Shaped {
        // Frames wait only while the transmitter is busy.
        if self.busy_until > now {
            while self.waiting.front().is_some_and(|&start| start <= now) {
                self.waiting.pop_front();
            }
            if self.waiting.len() >= self.imp.queue as usize {
                return Shaped::QueueFull;
            }
        }
        let start = now.max(self.busy_until);
        if start > now {
            self.waiting.push_back(start);
        }
        let finish = start.saturating_add(self.imp.serialisation(len));
        self.busy_until = finish;
        let stream =
            |what: &str| SimRng::from_seed(derive_seed(seed, link, &format!("link-{what}-{end}")));
        // Every frame on the wire draws its jitter, lost or not, so the loss never shifts it.
        let jitter = match self.imp.jitter {
            0 => None,
            j => {
                let rng = self.jitter.get_or_insert_with(|| stream("jitter"));
                Some(below(rng, j.saturating_add(1)))
            }
        };
        let lost = match self.imp.loss_ppm.min(PPM) {
            0 => false,
            PPM => true,
            p => {
                let rng = self.loss.get_or_insert_with(|| stream("loss"));
                below(rng, u64::from(PPM)) < u64::from(p)
            }
        };
        if lost {
            return Shaped::Lost;
        }
        let mut at = finish.saturating_add(latency);
        if let Some(j) = jitter {
            // Jitter never reorders: no earlier than the frame before.
            at = at.saturating_add(j).max(self.last_arrival);
        }
        self.last_arrival = at;
        Shaped::Arrive(at)
    }

    /// The link went down at `at`: what waited is lost, and the transmitter is idle.
    fn flush(&mut self, at: Nanos) {
        self.busy_until = self.busy_until.min(at);
        self.waiting.clear();
    }
}

/// Payload length after the Ethernet header (and an 802.1Q tag, if present).
fn payload_len(frame: &[u8]) -> usize {
    EthernetFrame::new_checked(frame).map_or(0, |f| f.payload().len())
}

impl Panel {
    fn state(&self) -> MutexGuard<'_, PanelState> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn add_device(&self, name: &str, ports: Vec<PortInfo>, remote: bool) -> DeviceIdx {
        let mut s = self.state();
        s.devices.push(DeviceEntry {
            name: name.to_owned(),
            ports,
            remote,
            dropped: 0,
        });
        s.devices.len() - 1
    }

    /// A panel whose links' loss and jitter streams derive from `seed`.
    pub(crate) fn with_seed(self, seed: u64) -> Self {
        self.state().seed = seed;
        self
    }

    pub(crate) fn ports(&self, device: DeviceIdx) -> Vec<PortInfo> {
        self.state().devices[device].ports.clone()
    }

    /// Wires `a` to `b` with the given latency, at instant `at`. The link starts up, its MTU is
    /// the smaller of the two ports' MTUs, and its capture and series follow the panel's
    /// defaults.
    pub(crate) fn connect(
        &self,
        a: (DeviceIdx, u32),
        b: (DeviceIdx, u32),
        latency: Nanos,
        at: Nanos,
    ) -> Result<usize, ConnectError> {
        let mut s = self.state();
        let mut mtu = u32::MAX;
        for end @ (device, port) in [a, b] {
            let declared = s.devices[device].ports.iter().find(|p| p.id == port);
            let Some(info) = declared else {
                return Err(ConnectError::Unknown(device, port));
            };
            mtu = mtu.min(info.mtu);
            if s.ends.contains_key(&end) || a == b {
                return Err(ConnectError::InUse(device, port));
            }
        }
        let end_name =
            |s: &PanelState, (d, p): (DeviceIdx, u32)| format!("{}:{p}", s.devices[d].name);
        let (na, nb) = (end_name(&s, a), end_name(&s, b));
        let id = s.links.len();
        // File-name safe: `blaster.0-reflector.0`. The same two ports wired again after an
        // unwire get `-2`, `-3`, ...: link names (and pcap files) stay unique.
        let base = format!("{na}-{nb}").replace(':', ".");
        let mut name = base.clone();
        let mut n = 1;
        while s.links.iter().any(|l| l.name == name) {
            n += 1;
            name = format!("{base}-{n}");
        }
        let capture = s.capture;
        let names = [
            (s.devices[a.0].name.as_str(), a.1),
            (s.devices[b.0].name.as_str(), b.1),
        ];
        let (pcap, ifaces) = capture_header(&name, names, at, capture);
        let series = s.series.map(Series::new);
        s.links.push(Link {
            name,
            ends: [a, b],
            latency,
            mtu,
            up: true,
            generation: 0,
            removed: false,
            kind: LinkKind::Ethernet,
            cable: None,
            pcap,
            ifaces,
            stats: LinkStats::default(),
            lanes: Default::default(),
            capture,
            recorded: false,
            notes: Vec::new(),
            created_at: at,
            series,
        });
        s.ends.insert(a, (id, 0));
        s.ends.insert(b, (id, 1));
        Ok(id)
    }

    /// A panel whose cables journal their events into `journal`.
    pub(crate) fn with_journal(mut self, journal: Journal) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Registers the model of cable kind `kind`; `false` (nothing changed) if the kind has one.
    pub(crate) fn register_cable(&self, kind: CableKind, model: Arc<dyn CableModel>) -> bool {
        let mut cables = self.cables.lock().unwrap_or_else(PoisonError::into_inner);
        if cables.contains_key(&kind.code()) {
            return false;
        }
        cables.insert(kind.code(), model);
        true
    }

    fn cable_model(&self, kind: LinkKind) -> Option<Arc<dyn CableModel>> {
        let LinkKind::Cable(kind) = kind else {
            return None;
        };
        self.cables
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&kind.code())
            .cloned()
    }

    /// `ethernet`, or the cable model's name (`cable` without a registered model).
    pub(crate) fn kind_name(&self, kind: LinkKind) -> &'static str {
        match kind {
            LinkKind::Ethernet => "ethernet",
            LinkKind::Cable(_) => self.cable_model(kind).map_or("cable", |m| m.name()),
        }
    }

    /// Sets what `link` carries; before its first transmission. A cable gets the
    /// state its model keeps for a new link.
    pub(crate) fn set_kind(&self, link: usize, kind: LinkKind) {
        let model = self.cable_model(kind);
        let mut s = self.state();
        let l = &mut s.links[link];
        l.kind = kind;
        l.cable = model.and_then(|m| m.new_link(&l.name));
    }

    /// Configures a cable's state with a setup value; before its first message.
    pub(crate) fn configure_cable(&self, link: usize, setup: &ExtValue) {
        let kind = self.state().links[link].kind;
        let Some(model) = self.cable_model(kind) else {
            return;
        };
        if let Some(state) = self.state().links[link].cable.as_deref_mut() {
            model.configure(state, setup);
        }
    }

    /// Reads a cable's state, if it is a `T` (`None` for other links).
    pub(crate) fn with_cable<T: Any, U>(&self, link: usize, f: impl FnOnce(&T) -> U) -> Option<U> {
        let s = self.state();
        let state = s.links[link].cable.as_deref()?;
        (state as &dyn Any).downcast_ref::<T>().map(f)
    }

    pub(crate) fn set_latency(&self, link: usize, latency: Nanos) {
        self.state().links[link].latency = latency;
    }

    pub(crate) fn set_mtu(&self, link: usize, mtu: u32) {
        self.state().links[link].mtu = mtu;
    }

    /// Sets the impairments of the direction sent from end `from` (`None`: both directions),
    /// for frames transmitted from now on. Frames already queued keep their schedule.
    pub(crate) fn set_impairments(&self, link: usize, from: Option<usize>, imp: Impairments) {
        let mut s = self.state();
        for (end, lane) in s.links[link].lanes.iter_mut().enumerate() {
            if from.is_none_or(|f| f == end) {
                lane.imp = imp;
            }
        }
    }

    /// What links created from now on record, and their series.
    pub(crate) fn set_defaults(&self, capture: CaptureOptions, series: Option<SeriesOptions>) {
        let mut s = self.state();
        s.capture = capture;
        s.series = series;
    }

    pub(crate) fn defaults(&self) -> (CaptureOptions, Option<SeriesOptions>) {
        let s = self.state();
        (s.capture, s.series)
    }

    /// Sets what `link` records. Before its first packet the capture header is written again
    /// (snap length, names); after it, only `record` changes.
    pub(crate) fn set_capture(&self, link: usize, capture: CaptureOptions) {
        let mut s = self.state();
        let names = s.links[link]
            .ends
            .map(|(d, p)| (s.devices[d].name.clone(), p));
        let l = &mut s.links[link];
        if l.recorded {
            l.capture.record = capture.record;
            return;
        }
        let names = [
            (names[0].0.as_str(), names[0].1),
            (names[1].0.as_str(), names[1].1),
        ];
        (l.pcap, l.ifaces) = capture_header(&l.name, names, l.created_at, capture);
        l.capture = capture;
    }

    /// Starts (or with `None` ends) `link`'s series; a new one starts empty.
    pub(crate) fn set_series(&self, link: usize, series: Option<SeriesOptions>) {
        self.state().links[link].series = series.map(Series::new);
    }

    /// `link`'s series: `(bucket start, counters)`, oldest first; empty without one.
    pub(crate) fn link_series(&self, link: usize) -> Vec<(Nanos, LinkStats)> {
        self.state().links[link]
            .series
            .as_ref()
            .map_or_else(Vec::new, Series::read)
    }

    /// Adds (or replaces) the operator rule for the transmission with this digest.
    pub(crate) fn set_rule(&self, digest: Digest, action: FrameAction) {
        self.state().rules.insert(digest, action);
    }

    /// Installs (or removes) the transmit hook.
    pub(crate) fn set_hook(&self, hook: Option<TransmitHook>) {
        *self.hook.lock().unwrap_or_else(PoisonError::into_inner) = hook;
    }

    /// Sets the carrier of `link` at `at`. Returns both ends if the state actually changed (then
    /// each end gets a `link-state` call), or `None` if it already was in that state.
    pub(crate) fn set_up(
        &self,
        clock: &VirtualClock,
        at: Nanos,
        link: usize,
        up: bool,
    ) -> Option<[(DeviceIdx, u32); 2]> {
        let mut s = self.state();
        let l = &mut s.links[link];
        if l.up == up {
            return None;
        }
        l.up = up;
        if !up {
            l.generation += 1;
            for lane in &mut l.lanes {
                lane.flush(at);
            }
        }
        let ends = l.ends;
        s.transition_tags.push(clock.tag());
        s.transitions.push(LinkTransition {
            at,
            link: LinkId(link),
            up,
        });
        Some(ends)
    }

    pub(crate) fn transitions(&self) -> Vec<LinkTransition> {
        self.state().transitions.clone()
    }

    pub(crate) fn transition_tags(&self) -> Vec<Tag> {
        self.state().transition_tags.clone()
    }

    pub(crate) fn frame_tags(&self) -> Vec<Tag> {
        self.state().frame_tags.clone()
    }

    /// Sets a remote device's ports (learned from its site in the join handshake).
    pub(crate) fn set_ports(&self, device: DeviceIdx, ports: Vec<PortInfo>) {
        self.state().devices[device].ports = ports;
    }

    pub(crate) fn is_remote(&self, device: DeviceIdx) -> bool {
        self.state().devices[device].remote
    }

    /// Takes the frames waiting for other sites, in transmit order.
    pub(crate) fn take_outbox(&self) -> Vec<RemoteFrame> {
        std::mem::take(&mut self.state().outbox)
    }

    pub(crate) fn taps(&self) -> Vec<Tap> {
        self.state().taps.clone()
    }

    pub(crate) fn arrivals(&self) -> Vec<RemoteArrival> {
        self.state().arrivals.clone()
    }

    /// A frame from another site: queue its delivery under the sender's key.
    pub(crate) fn receive_remote(&self, clock: &VirtualClock, f: RemoteFrame) {
        clock.schedule_remote_delivery(
            f.key,
            Delivery {
                link: f.link.0,
                to_end: f.to_end,
                generation: f.generation,
                frame_id: f.frame_id,
                remote: true,
                device: f.device.0,
                port: f.port,
                frame: f.bytes,
            },
        );
    }

    pub(crate) fn link_count(&self) -> usize {
        self.state().links.len()
    }

    pub(crate) fn link_info(&self, link: usize) -> LinkInfo {
        let s = self.state();
        let l = &s.links[link];
        LinkInfo {
            name: l.name.clone(),
            ends: [l.port_ref(0), l.port_ref(1)],
            latency: l.latency,
            mtu: l.mtu,
            up: l.up,
            removed: l.removed,
            kind: l.kind,
            impairments: [l.lanes[0].imp, l.lanes[1].imp],
            capture: l.capture,
            capture_notes: l.notes.clone(),
        }
    }

    /// Unwires `link`: it goes down at `at` (frames in flight are lost) and its
    /// ports are free for new links. Returns the ends that saw the carrier drop (`None` if it
    /// was down already).
    pub(crate) fn disconnect(
        &self,
        clock: &VirtualClock,
        at: Nanos,
        link: usize,
    ) -> Option<[(DeviceIdx, u32); 2]> {
        let dropped = self.set_up(clock, at, link, false);
        let mut s = self.state();
        let ends = s.links[link].ends;
        s.links[link].removed = true;
        for end in ends {
            if s.ends.get(&end).is_some_and(|&(l, _)| l == link) {
                s.ends.remove(&end);
            }
        }
        dropped
    }

    /// The links attached to `device` (not removed), in creation order.
    pub(crate) fn links_of(&self, device: DeviceIdx) -> Vec<usize> {
        let s = self.state();
        s.links
            .iter()
            .enumerate()
            .filter(|(_, l)| !l.removed && l.ends.iter().any(|&(d, _)| d == device))
            .map(|(i, _)| i)
            .collect()
    }

    /// Whether the device's declared ports equal `ports` (a restarted device declares them
    /// again).
    pub(crate) fn device_ports_match(&self, device: DeviceIdx, ports: &[PortInfo]) -> bool {
        self.state().devices[device].ports == ports
    }

    pub(crate) fn link_stats(&self, link: usize) -> LinkStats {
        self.state().links[link].stats
    }

    /// The link's capture so far (a complete, valid pcap-ng file), with its notes as section
    /// comments: without notes, exactly the encoder's bytes.
    pub(crate) fn pcap(&self, link: usize) -> Vec<u8> {
        let s = self.state();
        let l = &s.links[link];
        with_notes(l.pcap.bytes(), &l.notes)
    }

    /// Sets the notes `link`'s capture carries (checked by [`crate::pcap::check_notes`]).
    pub(crate) fn set_notes(&self, link: usize, notes: Vec<String>) {
        self.state().links[link].notes = notes;
    }

    pub(crate) fn frames(&self) -> Vec<FrameRecord> {
        self.state().frames.clone()
    }

    pub(crate) fn frames_len(&self) -> usize {
        self.state().frames.len()
    }

    /// Frame records `from..` with their tags.
    pub(crate) fn frames_from(&self, from: usize) -> Vec<(FrameRecord, Tag)> {
        let s = self.state();
        s.frames
            .iter()
            .zip(&s.frame_tags)
            .skip(from)
            .map(|(f, t)| (f.clone(), t.clone()))
            .collect()
    }

    pub(crate) fn device_name(&self, device: DeviceIdx) -> String {
        self.state().devices[device].name.clone()
    }

    pub(crate) fn dropped(&self, device: DeviceIdx) -> u64 {
        self.state().devices[device].dropped
    }

    /// `wire.transmit`: drop, or tap outbound and queue the delivery. Never re-entrant. A frame
    /// for a device on another site goes to the outbox instead, keyed exactly as its delivery
    /// would be queued here.
    pub(crate) fn transmit(
        &self,
        clock: &VirtualClock,
        device: DeviceIdx,
        port: u32,
        mut frame: Vec<u8>,
    ) {
        let now = clock.now();
        let hook = self
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        // Operator rules and the hook see the transmission before it enters the
        // wire, with the panel unlocked (a hook may block while a controller reads it).
        let mut action = None;
        {
            let s = self.state();
            let Some(&(link_id, end)) = s.ends.get(&(device, port)) else {
                drop(s);
                self.state().devices[device].dropped += 1;
                return;
            };
            if !s.rules.is_empty() || hook.is_some() {
                let tag = clock.peek_tag();
                let digest = digest::record(&tag);
                let rule = s.rules.get(&digest).cloned();
                let (from, to) = (
                    s.links[link_id].port_ref(end),
                    s.links[link_id].port_ref(1 - end),
                );
                drop(s);
                let verdict = hook.as_ref().and_then(|h| {
                    h(&Transmit {
                        tag: &tag,
                        digest,
                        link: LinkId(link_id),
                        from,
                        to,
                        at: now,
                        bytes: &frame,
                        rule: rule.as_ref(),
                    })
                });
                action = rule.or(verdict);
            }
        }
        let mut delay = 0;
        let dropped = action == Some(FrameAction::Drop);
        match action {
            Some(FrameAction::Replace(bytes)) => frame = bytes,
            Some(FrameAction::Delay(d)) => delay = d,
            Some(FrameAction::Drop) | None => {}
        }
        let mut s = self.state();
        let Some(&(link_id, end)) = s.ends.get(&(device, port)) else {
            s.devices[device].dropped += 1;
            return;
        };
        let frame_id = s.frames.len();
        let to_end = 1 - end;
        let peer_remote = s.devices[s.links[link_id].ends[to_end].0].remote;
        if s.links[link_id].kind.is_cable() {
            // A cable: no frame log, no pcap, no MTU; its model says what the
            // message does (with the panel locked), its tap records it (unlocked), and what it
            // delivers arrives `latency` later. Cables stay within a site (a split refuses networks
            // with them, and latency 0 gives a split no lookahead anyway).
            let model = self.cable_model(s.links[link_id].kind);
            let link = &mut s.links[link_id];
            if !model.as_ref().is_none_or(|m| m.well_formed(&frame)) {
                // A malformed message: dropped and counted, never a trap.
                link.count(now, |c| c.oversize[end] += 1);
                return;
            }
            if dropped || !link.up || peer_remote {
                link.count(now, |c| c.dropped_down[end] += 1);
                return;
            }
            let len = frame.len() as u64;
            link.count(now, |c| {
                c.frames[end] += 1;
                c.bytes[end] += len;
            });
            let at = now.saturating_add(link.latency).saturating_add(delay);
            let generation = link.generation;
            let ends = link.ends;
            let link_name = link.name.clone();
            let device_name = s.devices[device].name.clone();
            let port_name = s.devices[device]
                .ports
                .iter()
                .find(|p| p.id == port)
                .map_or_else(|| port.to_string(), |p| p.name.clone());
            let send = CableSend {
                at: now,
                end,
                device,
                device_name: &device_name,
                port,
                port_name: &port_name,
                link: &link_name,
                message: &frame,
            };
            let carry = match &model {
                Some(m) => m.carry(&send, s.links[link_id].cable.as_deref_mut()),
                None => Carry::Forward,
            };
            drop(s);
            let to = match carry {
                Carry::Nothing => return,
                Carry::Forward => {
                    if let Some(m) = &model {
                        m.tap(&send);
                    }
                    vec![(to_end, frame)]
                }
                Carry::Deliver { to, events } => {
                    if let Some(m) = &model {
                        m.tap(&send);
                    }
                    if let Some(journal) = &self.journal {
                        for record in events {
                            journal.push(JournalEntry {
                                at: now,
                                device: device_name.clone(),
                                record,
                            });
                        }
                    }
                    to
                }
            };
            for (to_end, message) in to {
                let (peer, peer_port) = ends[to_end];
                clock.schedule_delivery(
                    at,
                    Delivery {
                        link: link_id,
                        to_end,
                        generation,
                        frame_id: CABLE_MESSAGE,
                        remote: false,
                        device: peer,
                        port: peer_port,
                        frame: message,
                    },
                );
            }
            return;
        }
        let tag = clock.tag();
        let seed = s.seed;
        let link = &mut s.links[link_id];
        let mut shaped = Shaped::Arrive(now.saturating_add(link.latency));
        let drop_reason = if dropped {
            Some(DropReason::Operator)
        } else if !link.up {
            link.count(now, |c| c.dropped_down[end] += 1);
            Some(DropReason::LinkDown)
        } else if payload_len(&frame) > link.mtu as usize {
            link.count(now, |c| c.oversize[end] += 1);
            Some(DropReason::Oversize)
        } else {
            // The direction's queue, rate, loss and jitter. A plain direction (never shaped,
            // so never busy) keeps `now + latency` and draws nothing.
            let lane = &mut link.lanes[end];
            if !lane.imp.is_off() || lane.busy_until > now {
                shaped = lane.shape(now, frame.len(), link.latency, (seed, &link.name, end));
            }
            if matches!(shaped, Shaped::QueueFull) {
                link.count(now, |c| c.dropped_queue[end] += 1);
                Some(DropReason::QueueFull)
            } else {
                None
            }
        };
        let lost = matches!(shaped, Shaped::Lost);
        let record = FrameRecord {
            link: LinkId(link_id),
            from: link.port_ref(end),
            to: link.port_ref(to_end),
            sent_at: now,
            fate: match drop_reason {
                Some(reason) => FrameFate::Dropped(reason),
                None if lost => FrameFate::Lost,
                None => FrameFate::InFlight,
            },
            len: frame.len(),
            bytes: link.kept(&frame),
        };
        if drop_reason.is_some() {
            s.frames.push(record);
            s.frame_tags.push(tag);
            return;
        }
        link.tap(end, now, &frame, Direction::Outbound);
        let len = frame.len() as u64;
        link.count(now, |c| {
            c.frames[end] += 1;
            c.bytes[end] += len;
            c.lost_random[end] += u64::from(lost);
        });
        let record_taps = link.capture.record;
        let (peer, peer_port) = link.ends[to_end];
        let at = match shaped {
            Shaped::Arrive(at) => at.saturating_add(delay),
            Shaped::Lost | Shaped::QueueFull => now,
        };
        let generation = link.generation;
        let tap_bytes = (peer_remote && record_taps).then(|| record.bytes.clone());
        s.frames.push(record);
        s.frame_tags.push(tag.clone());
        if peer_remote {
            // A WAN link: record this site's half of the capture (as the link keeps it) and
            // hand the frame to site sync, keyed exactly as a local delivery would be.
            if let Some(bytes) = tap_bytes {
                s.taps.push(Tap {
                    tag,
                    link: LinkId(link_id),
                    end,
                    at: now,
                    inbound: false,
                    len: frame.len(),
                    bytes,
                });
            }
            if lost {
                // Lost on the wire: this site's half of the capture has it, the peer gets
                // nothing.
                return;
            }
            let key = clock.remote_key(at);
            s.outbox.push(RemoteFrame {
                key,
                link: LinkId(link_id),
                to_end,
                generation,
                frame_id,
                device: DeviceId(peer),
                port: peer_port,
                bytes: frame,
            });
            return;
        }
        drop(s);
        if lost {
            return;
        }
        clock.schedule_delivery(
            at,
            Delivery {
                link: link_id,
                to_end,
                generation,
                frame_id,
                remote: false,
                device: peer,
                port: peer_port,
                frame,
            },
        );
    }

    /// A delivery's event fired at `at`. Returns whether the frame reaches the receiver: if the
    /// link went down since it was sent, it is lost. Otherwise it is tapped inbound.
    pub(crate) fn arrive(&self, clock: &VirtualClock, at: Nanos, d: &Delivery) -> bool {
        let mut s = self.state();
        let link = &mut s.links[d.link];
        let delivered = link.generation == d.generation;
        if d.frame_id == CABLE_MESSAGE {
            // A cable's message: nothing to tap on arrival.
            if !delivered {
                link.count(at, |c| c.lost[1 - d.to_end] += 1);
            }
            return delivered;
        }
        if delivered {
            link.tap(d.to_end, at, &d.frame, Direction::Inbound);
        } else {
            link.count(at, |c| c.lost[1 - d.to_end] += 1);
        }
        let tap_bytes = (d.remote && delivered && link.capture.record).then(|| link.kept(&d.frame));
        let fate = if delivered {
            FrameFate::Delivered { at }
        } else {
            FrameFate::Lost
        };
        if d.remote {
            if delivered {
                // The tag is taken whether or not the link records, as it always was.
                let tag = clock.tag();
                if let Some(bytes) = tap_bytes {
                    s.taps.push(Tap {
                        tag,
                        link: LinkId(d.link),
                        end: d.to_end,
                        at,
                        inbound: true,
                        len: d.frame.len(),
                        bytes,
                    });
                }
            }
            s.arrivals.push(RemoteArrival {
                frame_id: d.frame_id,
                fate,
            });
        } else {
            s.frames[d.frame_id].fate = fate;
        }
        delivered
    }
}

/// A device's end of the patch panel: what a runtime backend calls for `wasmnet:link/wire`'s
/// `transmit`. It only enqueues (the peer gets the frame at `now + latency`), never re-enters a
/// device, and knows which device is sending.
#[derive(Clone)]
pub struct Wire {
    pub(crate) device: DeviceIdx,
    pub(crate) panel: Panel,
    pub(crate) clock: VirtualClock,
}

impl Wire {
    /// `wire.transmit(port, frame)` from this device, at the current virtual instant.
    pub fn transmit(&self, port: u32, frame: Vec<u8>) {
        self.panel.transmit(&self.clock, self.device, port, frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::clock::Event;

    fn port(id: u32, mtu: u32) -> PortInfo {
        PortInfo {
            id,
            name: format!("p{id}"),
            mac: None,
            mtu,
        }
    }

    /// Two devices with ports 0 and 1 (MTUs 1500 and 100), wired a:0 <-> b:1, latency 10.
    fn panel() -> (VirtualClock, Panel, usize) {
        let clock = VirtualClock::new(Duration::ZERO);
        let panel = Panel::default();
        let a = panel.add_device("a", vec![port(0, 1500), port(1, 1500)], false);
        let b = panel.add_device("b", vec![port(0, 1500), port(1, 100)], false);
        let link = panel.connect((a, 0), (b, 1), 10, 0).unwrap();
        (clock, panel, link)
    }

    fn frame(payload: usize) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x88, 0xb5];
        f.resize(14 + payload, 0);
        f
    }

    fn next_delivery(clock: &VirtualClock) -> Option<(Nanos, Delivery)> {
        match clock.pop(None)? {
            (key, Event::Deliver(d)) => Some((key.at(), d)),
            _ => None,
        }
    }

    #[test]
    fn connect_validates_ports_and_takes_the_smaller_mtu() {
        let (_, panel, link) = panel();
        assert_eq!(panel.link_info(link).mtu, 100);
        assert_eq!(panel.link_info(link).name, "a.0-b.1");
        assert_eq!(
            panel.connect((0, 7), (1, 0), 0, 0),
            Err(ConnectError::Unknown(0, 7))
        );
        assert_eq!(
            panel.connect((0, 0), (1, 0), 0, 0),
            Err(ConnectError::InUse(0, 0))
        );
        assert_eq!(
            panel.connect((0, 1), (0, 1), 0, 0),
            Err(ConnectError::InUse(0, 1))
        );
    }

    #[test]
    fn oversize_and_down_frames_never_enter_the_wire() {
        let (clock, panel, link) = panel();
        panel.transmit(&clock, 0, 0, frame(100));
        panel.transmit(&clock, 0, 0, frame(101));
        assert!(panel.set_up(&clock, 0, link, false).is_some());
        assert!(
            panel.set_up(&clock, 0, link, false).is_none(),
            "no change, no event"
        );
        panel.transmit(&clock, 1, 1, frame(10));
        panel.transmit(&clock, 0, 5, frame(10)); // unwired

        let stats = panel.link_stats(link);
        assert_eq!(stats.frames, [1, 0]);
        assert_eq!(stats.oversize, [1, 0]);
        assert_eq!(stats.dropped_down, [0, 1]);
        assert_eq!(panel.dropped(0), 1);
        let fates: Vec<_> = panel.frames().iter().map(|f| f.fate).collect();
        assert_eq!(
            fates,
            [
                FrameFate::InFlight,
                FrameFate::Dropped(DropReason::Oversize),
                FrameFate::Dropped(DropReason::LinkDown),
            ]
        );
        // The in-flight frame was sent before the link went down, so it is lost on arrival.
        let (at, d) = next_delivery(&clock).unwrap();
        assert_eq!(at, 10);
        assert!(!panel.arrive(&clock, at, &d));
        assert_eq!(panel.frames()[0].fate, FrameFate::Lost);
        assert_eq!(panel.link_stats(link).lost, [1, 0]);
        assert!(next_delivery(&clock).is_none());
    }

    #[test]
    fn frames_sent_after_the_link_comes_back_are_delivered() {
        let (clock, panel, link) = panel();
        panel.set_up(&clock, 0, link, false);
        panel.set_up(&clock, 0, link, true);
        panel.transmit(&clock, 1, 1, frame(0));
        let (at, d) = next_delivery(&clock).unwrap();
        assert!(panel.arrive(&clock, at, &d));
        let f = &panel.frames()[0];
        assert_eq!(f.fate, FrameFate::Delivered { at: 10 });
        assert_eq!((f.from, f.to), (DeviceId(1).port(1), DeviceId(0).port(0)));
        let cap = crate::pcap::parse(&panel.pcap(link)).unwrap();
        assert_eq!(cap.packets.len(), 2);
    }

    // ---- impairments (docs/design/links.md) ----

    /// Every delivery left in the queue, in pop order: `(arrival, frame-log index)`.
    fn drain(clock: &VirtualClock) -> Vec<(Nanos, usize)> {
        std::iter::from_fn(|| next_delivery(clock))
            .map(|(at, d)| (at, d.frame_id))
            .collect()
    }

    /// Whether the direction sent from `end` has created a random stream.
    fn drew(panel: &Panel, link: usize, end: usize) -> bool {
        let s = panel.state();
        let lane = &s.links[link].lanes[end];
        lane.loss.is_some() || lane.jitter.is_some()
    }

    #[test]
    fn a_rate_serialises_frames_and_a_full_queue_drops_at_the_tail() {
        let (clock, panel, link) = panel();
        // 8 Mbit/s: one byte per µs. A 100-byte frame occupies the transmitter for 100 µs.
        let imp = Impairments::default().rate(8_000_000).queue(2);
        assert_eq!(imp.serialisation(100), 100_000);
        panel.set_impairments(link, Some(0), imp);
        for _ in 0..5 {
            panel.transmit(&clock, 0, 0, frame(86));
        }
        // b -> a is not impaired: it arrives after the latency alone.
        panel.transmit(&clock, 1, 1, frame(86));
        let fates: Vec<_> = panel.frames().iter().map(|f| f.fate).collect();
        let full = FrameFate::Dropped(DropReason::QueueFull);
        assert_eq!(fates[3..5], [full, full], "one on the wire, two waiting");
        let stats = panel.link_stats(link);
        assert_eq!(stats.frames, [3, 1]);
        assert_eq!(stats.dropped_queue, [2, 0]);
        assert!(!drew(&panel, link, 0), "a rate alone draws nothing");

        // Each frame arrives at (its turn at the transmitter) + 100 µs + latency.
        let first = next_delivery(&clock).unwrap();
        assert_eq!((first.0, first.1.frame_id), (10, 5));
        let second = next_delivery(&clock).unwrap();
        assert_eq!((second.0, second.1.frame_id), (100_010, 0));
        // At 100.01 µs frame 1 is on the transmitter and frame 2 waits: room for one more,
        // which waits for frame 2 to finish at 300 µs; the next one is dropped.
        panel.transmit(&clock, 0, 0, frame(86));
        panel.transmit(&clock, 0, 0, frame(86));
        assert_eq!(
            drain(&clock),
            [(200_010, 1), (300_010, 2), (400_010, 6)],
            "FIFO, back to back"
        );
        assert_eq!(panel.frames()[7].fate, full);
        // Dropped frames never entered the wire: 5 outbound records (4 a -> b, 1 b -> a).
        let cap = crate::pcap::parse(&panel.pcap(link)).unwrap();
        assert_eq!(cap.packets.len(), 5);
    }

    #[test]
    fn a_link_going_down_empties_the_queue() {
        let (clock, panel, link) = panel();
        let imp = Impairments::default().rate(8_000_000).queue(1);
        panel.set_impairments(link, None, imp);
        panel.transmit(&clock, 0, 0, frame(86));
        panel.transmit(&clock, 0, 0, frame(86));
        panel.set_up(&clock, 0, link, false);
        panel.set_up(&clock, 0, link, true);
        // The transmitter is idle again: no queue drop, and this frame goes first.
        panel.transmit(&clock, 0, 0, frame(86));
        assert_eq!(panel.link_stats(link).dropped_queue, [0, 0]);
        let mut arrivals = drain(&clock);
        arrivals.sort();
        assert_eq!(arrivals, [(100_010, 0), (100_010, 2), (200_010, 1)]);
    }

    /// The fates of `n` frames a -> b at t = 0 with `imp`, in a network seeded with `seed`,
    /// after `extra` unrelated links were wired first.
    fn fates(seed: u64, imp: Impairments, n: usize, extra: usize) -> (Vec<FrameFate>, LinkStats) {
        let clock = VirtualClock::new(Duration::ZERO);
        let panel = Panel::default().with_seed(seed);
        for i in 0..extra {
            let ports = vec![port(0, 1500), port(1, 1500)];
            let d = panel.add_device(&format!("x{i}"), ports, false);
            panel.connect((d, 0), (d, 1), 5, 0).unwrap();
        }
        let a = panel.add_device("a", vec![port(0, 1500)], false);
        let b = panel.add_device("b", vec![port(1, 1500)], false);
        let link = panel.connect((a, 0), (b, 1), 10, 0).unwrap();
        panel.set_impairments(link, Some(0), imp);
        for _ in 0..n {
            panel.transmit(&clock, a, 0, frame(46));
        }
        let delivered = drain(&clock).len();
        let stats = panel.link_stats(link);
        assert_eq!(delivered as u64 + stats.lost_random[0], n as u64);
        (panel.frames().iter().map(|f| f.fate).collect(), stats)
    }

    #[test]
    fn loss_replays_by_seed_and_is_exact_at_zero_and_one() {
        const N: usize = 10_000;
        let ten_percent = Impairments::default().loss_ppm(100_000);
        let (run, stats) = fates(42, ten_percent, N, 0);
        let lost = stats.lost_random[0];
        // Binomial(10 000, 0.1): mean 1000, sigma 30; this bound is 5 sigma.
        assert!((850..=1150).contains(&lost), "lost {lost} of {N}");
        assert_eq!(stats.frames[0], N as u64, "lost frames entered the wire");
        let marked = run.iter().filter(|&&f| f == FrameFate::Lost).count() as u64;
        assert_eq!(marked, lost);
        assert_eq!(fates(42, ten_percent, N, 0).0, run, "the same seed replays");
        assert_eq!(
            fates(42, ten_percent, N, 3).0,
            run,
            "links wired before it do not shift its stream"
        );
        assert_ne!(fates(43, ten_percent, N, 0).0, run, "another seed differs");

        let (none, stats) = fates(42, Impairments::default().loss_ppm(0), N, 0);
        assert!(none.iter().all(|&f| f == FrameFate::InFlight));
        assert_eq!(stats.lost_random[0], 0);
        let (all, stats) = fates(42, Impairments::default().loss_ppm(PPM), N, 0);
        assert!(all.iter().all(|&f| f == FrameFate::Lost));
        assert_eq!(stats.lost_random[0], N as u64);
        let (_, stats) = fates(42, Impairments::default().loss_ppm(u32::MAX), 10, 0);
        assert_eq!(
            stats.lost_random[0], 10,
            "above one million counts as one million"
        );
    }

    #[test]
    fn zero_and_full_loss_draw_no_random_numbers() {
        for ppm in [0, PPM] {
            let (clock, panel, link) = panel();
            panel.set_impairments(link, None, Impairments::default().loss_ppm(ppm));
            panel.transmit(&clock, 0, 0, frame(10));
            assert!(!drew(&panel, link, 0), "loss {ppm} ppm");
        }
        let (clock, panel, link) = panel();
        panel.set_impairments(link, Some(0), Impairments::default().loss_ppm(1));
        panel.transmit(&clock, 0, 0, frame(10));
        panel.transmit(&clock, 1, 1, frame(10));
        assert!(drew(&panel, link, 0));
        assert!(!drew(&panel, link, 1), "the plain direction draws nothing");
    }

    #[test]
    fn jitter_stays_in_bounds_and_never_reorders() {
        const N: u64 = 2_000;
        const LATENCY: Nanos = 10;
        const JITTER: Nanos = 1_000;
        let (clock, panel, link) = panel();
        panel.set_impairments(link, Some(0), Impairments::default().jitter(JITTER));
        // One frame every 100 ns: ten times closer than the jitter, so independent draws
        // would reorder them.
        for i in 0..N {
            clock.advance_to(i * 100);
            panel.transmit(&clock, 0, 0, frame(10));
        }
        let arrivals = drain(&clock);
        assert_eq!(arrivals.len(), N as usize);
        let frames = panel.frames();
        let mut extra = Vec::new();
        for (k, &(at, id)) in arrivals.iter().enumerate() {
            assert_eq!(id, k, "in transmit order");
            let sent = frames[id].sent_at;
            assert!(at >= sent + LATENCY, "frame {id} early: {at}");
            assert!(at <= sent + LATENCY + JITTER, "frame {id} late: {at}");
            extra.push(at - sent - LATENCY);
        }
        assert!(arrivals.windows(2).all(|w| w[0].0 <= w[1].0));
        let (min, max) = (extra.iter().min().unwrap(), extra.iter().max().unwrap());
        // Keeping the order lifts small draws (the frame before, 100 ns earlier, is often
        // later), but the delays still span the range.
        assert!(
            *min < 250 && *max > 900,
            "the delays cover the range: {min}..{max}"
        );
    }

    #[test]
    fn jitter_with_a_rate_comes_after_the_queue() {
        let (clock, panel, link) = panel();
        let imp = Impairments::default().rate(8_000_000).jitter(50_000);
        panel.set_impairments(link, Some(0), imp);
        for _ in 0..50 {
            panel.transmit(&clock, 0, 0, frame(86));
        }
        for (k, &(at, id)) in drain(&clock).iter().enumerate() {
            assert_eq!(id, k);
            // Frame k finishes serialising at (k + 1) * 100 µs.
            let base = (k as u64 + 1) * 100_000 + 10;
            assert!((base..=base + 50_000).contains(&at), "frame {k} at {at}");
        }
    }

    #[test]
    fn a_plain_link_is_unchanged() {
        let (clock, panel, link) = panel();
        panel.set_impairments(link, None, Impairments::default().queue(0));
        for _ in 0..3 {
            panel.transmit(&clock, 0, 0, frame(10));
        }
        assert_eq!(drain(&clock), [(10, 0), (10, 1), (10, 2)]);
        assert!(!drew(&panel, link, 0));
        assert_eq!(panel.link_info(link).impairments[1].queue, 0);
    }

    // ---- what a link records (docs/design/links.md) ----

    /// [`panel`] with `capture` for every link, wired at instant 5.
    fn recording_panel(capture: CaptureOptions) -> (VirtualClock, Panel, usize) {
        let clock = VirtualClock::new(Duration::ZERO);
        let panel = Panel::default();
        panel.set_defaults(capture, None);
        let a = panel.add_device("a", vec![port(0, 1500)], false);
        let b = panel.add_device("b", vec![port(1, 1500)], false);
        let link = panel.connect((a, 0), (b, 1), 10, 5).unwrap();
        (clock, panel, link)
    }

    /// Sends a 100-byte frame a -> b and a 60-byte one b -> a, and delivers both.
    fn exchange(clock: &VirtualClock, panel: &Panel) -> Vec<Delivery> {
        panel.transmit(clock, 0, 0, frame(86));
        panel.transmit(clock, 1, 1, frame(46));
        std::iter::from_fn(|| next_delivery(clock))
            .map(|(at, d)| {
                assert!(panel.arrive(clock, at, &d));
                d
            })
            .collect()
    }

    #[test]
    fn the_default_capture_header_is_the_one_links_always_had() {
        let (_, panel, link) = panel();
        let mut old = PcapNgEncoder::new(PCAP_USER_APPL).unwrap();
        old.add_ethernet_interface("a:0", 0).unwrap();
        old.add_ethernet_interface("b:1", 0).unwrap();
        assert_eq!(panel.pcap(link), old.bytes());
        assert_eq!(panel.link_info(link).capture, CaptureOptions::default());
    }

    #[test]
    fn a_snap_length_cuts_the_capture_and_the_frame_log_but_not_the_delivery() {
        let (clock, panel, link) = recording_panel(CaptureOptions::default().snap_len(20));
        let delivered = exchange(&clock, &panel);
        assert_eq!(
            delivered.iter().map(|d| d.frame.len()).collect::<Vec<_>>(),
            [100, 60],
            "the far end gets whole frames"
        );
        let cap = crate::pcap::parse(&panel.pcap(link)).unwrap();
        assert!(cap.interfaces.iter().all(|i| i.snaplen == 20));
        let lens: Vec<_> = cap
            .packets
            .iter()
            .map(|p| (p.data.len(), p.original_len))
            .collect();
        assert_eq!(lens, [(20, 100), (20, 60), (20, 100), (20, 60)]);
        assert_eq!(cap.packets[0].data, frame(86)[..20]);
        let log: Vec<_> = panel
            .frames()
            .iter()
            .map(|f| (f.bytes.len(), f.len))
            .collect();
        assert_eq!(log, [(20, 100), (20, 60)]);
        assert_eq!(
            panel.link_stats(link).bytes,
            [100, 60],
            "counters count whole frames"
        );
    }

    #[test]
    fn recording_off_keeps_the_header_the_records_and_the_counters() {
        let (clock, panel, link) = recording_panel(CaptureOptions::default().record(false));
        exchange(&clock, &panel);
        let cap = crate::pcap::parse(&panel.pcap(link)).unwrap();
        assert_eq!((cap.interfaces.len(), cap.packets.len()), (2, 0));
        let frames = panel.frames();
        assert!(frames.iter().all(|f| f.bytes.is_empty()));
        assert_eq!(frames.iter().map(|f| f.len).collect::<Vec<_>>(), [100, 60]);
        assert_eq!(frames[0].fate, FrameFate::Delivered { at: 10 });
        let stats = panel.link_stats(link);
        assert_eq!((stats.frames, stats.bytes), ([1, 1], [100, 60]));
    }

    #[test]
    fn a_capture_can_name_its_ends() {
        let (clock, panel, link) = recording_panel(CaptureOptions::default().name_ends(true));
        exchange(&clock, &panel);
        let cap = crate::pcap::parse(&panel.pcap(link)).unwrap();
        let ends: Vec<_> = cap
            .interfaces
            .iter()
            .map(|i| crate::pcap::LinkEnd::parse(i.description.as_deref().unwrap()).unwrap())
            .collect();
        let want = |end, device: &str, port, peer: &str, peer_port| {
            crate::pcap::LinkEnd::new("a.0-b.1", end, device, port, peer, peer_port, 5)
        };
        assert_eq!(ends, [want(0, "a", 0, "b", 1), want(1, "b", 1, "a", 0)]);
        assert_eq!(cap.interfaces[0].name.as_deref(), Some("a:0"));
        assert_eq!(cap.packets.len(), 4);
    }

    #[test]
    fn capture_options_rewrite_the_header_until_the_first_packet() {
        let (clock, panel, link) = panel();
        panel.set_capture(link, CaptureOptions::default().snap_len(16).name_ends(true));
        let cap = crate::pcap::parse(&panel.pcap(link)).unwrap();
        assert_eq!(cap.interfaces[0].snaplen, 16);
        assert!(cap.interfaces[0].description.is_some());
        panel.transmit(&clock, 0, 0, frame(10));
        // After a packet only `record` changes: the header and its snap length stay.
        panel.set_capture(link, CaptureOptions::default().record(false));
        panel.transmit(&clock, 0, 0, frame(10));
        let info = panel.link_info(link).capture;
        assert_eq!(
            (info.record, info.snap_len, info.name_ends),
            (false, 16, true)
        );
        let cap = crate::pcap::parse(&panel.pcap(link)).unwrap();
        assert_eq!(cap.packets.len(), 1);
        assert_eq!(cap.interfaces[0].snaplen, 16);
    }

    #[test]
    fn notes_are_section_comments_at_any_time_and_none_change_nothing() {
        let (clock, panel, link) = panel();
        let plain = || {
            let mut enc = PcapNgEncoder::new(PCAP_USER_APPL).unwrap();
            let a = enc.add_ethernet_interface("a:0", 0).unwrap();
            enc.add_ethernet_interface("b:1", 0).unwrap();
            (enc, a)
        };
        panel.set_notes(link, vec!["UDP 6081: Geneve".into(), "TCP 80: HTTP".into()]);
        let cap = crate::pcap::parse(&panel.pcap(link)).unwrap();
        assert_eq!(cap.comments, ["UDP 6081: Geneve", "TCP 80: HTTP"]);
        assert_eq!(cap.user_appl.as_deref(), Some(PCAP_USER_APPL));
        assert_eq!(cap.interfaces.len(), 2);
        // After packets: the same packets, with the notes in force when it is read.
        panel.transmit(&clock, 0, 0, frame(10));
        panel.set_notes(link, vec!["changed".into()]);
        let noted = panel.pcap(link);
        let cap = crate::pcap::parse(&noted).unwrap();
        assert_eq!(cap.comments, ["changed"]);
        assert_eq!(cap.packets.len(), 1);
        assert_eq!(panel.link_info(link).capture_notes, ["changed"]);
        // Without notes, exactly the capture the encoder wrote.
        panel.set_notes(link, Vec::new());
        let (mut enc, a) = plain();
        enc.write_packet_directed(a, 0, &frame(10), Direction::Outbound)
            .unwrap();
        assert_eq!(panel.pcap(link), enc.bytes());
        assert_eq!(
            crate::pcap::parse(&panel.pcap(link)).unwrap().packets,
            cap.packets
        );
    }

    #[test]
    fn a_series_counts_per_bucket_and_keeps_the_last_ones() {
        let (clock, panel, link) = panel();
        panel.set_series(link, Some(SeriesOptions::new(100, 3)));
        // One frame a -> b at 0, 50, 150, 420 and 430; one b -> a oversize at 420 (MTU 100).
        for t in [0, 50, 150, 420, 430] {
            clock.advance_to(t);
            panel.transmit(&clock, 0, 0, frame(10));
        }
        clock.advance_to(430);
        panel.transmit(&clock, 1, 1, frame(101));
        // Delivered frames count nothing on arrival.
        assert_eq!(drain_arrivals(&clock, &panel), 5);
        let series = panel.link_series(link);
        let frames: Vec<_> = series.iter().map(|(at, s)| (*at, s.frames[0])).collect();
        assert_eq!(
            frames,
            [(0, 2), (100, 1), (400, 2)],
            "empty buckets are absent"
        );
        assert_eq!(series[2].1.oversize, [0, 1]);
        let mut sum = LinkStats::default();
        for (_, s) in &series {
            sum.add(s);
        }
        assert_eq!(
            sum,
            panel.link_stats(link),
            "the buckets add up to the totals"
        );
        // A fourth bucket pushes out the first.
        clock.advance_to(1_000);
        panel.transmit(&clock, 0, 0, frame(10));
        let starts: Vec<_> = panel.link_series(link).iter().map(|(at, _)| *at).collect();
        assert_eq!(starts, [100, 400, 1_000]);
        // Lost frames count at the instant they would have arrived.
        panel.set_up(&clock, 1_000, link, false);
        let _ = drain_arrivals(&clock, &panel);
        let last = *panel.link_series(link).last().unwrap();
        assert_eq!(last.0, 1_000);
        assert_eq!(last.1.lost[0], 1);
        assert_eq!(panel.link_series(link).len(), 3);
    }

    /// Fires every delivery left, as the executor would.
    fn drain_arrivals(clock: &VirtualClock, panel: &Panel) -> usize {
        let mut n = 0;
        while let Some((at, d)) = next_delivery(clock) {
            panel.arrive(clock, at, &d);
            n += 1;
        }
        n
    }
}
