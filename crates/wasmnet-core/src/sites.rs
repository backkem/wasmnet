//! Multi-site networks: site sync, its wire format, and merging the sites' records.
//!
//! A network can be split into **sites** (instances that each run some of its devices). A link
//! whose ends are on different sites is a **WAN link**. Every site builds the whole network in
//! the same order, with the other sites' devices as placeholders ([`Network::remote_device`]),
//! so indices and event keys are global. Frames crossing a WAN link travel as [`RemoteFrame`]s,
//! each carrying the causal key its delivery gets ([`crate::EventKey`]). The sites stay in
//! lockstep with conservative PDES ([`SiteSync`]): the WAN links' smallest latency is the
//! lookahead, null messages ([`Sync`]) promise lower bounds, and a next-event fixpoint skips
//! idle stretches. Merging the sites' tagged records ([`merge`]) gives byte for byte what the
//! network produces on one site (**multi-site equivalence**).
//!
//! The algorithm and the wire format are described in `docs/design/sites.md`. Two sites for
//! now.
//!
//! The driver is sans-IO: it never touches a real network. A **carrier** moves the encoded
//! messages between the sites (an in-process channel in tests, or a carrier component), and the
//! only thing it must provide is one reliable, ordered byte-message channel per peer site.
//!
//! Embedder surface, unstable: the driver, the messages and the wire format may change between
//! versions without notice (the format carries [`VERSION`]).

use std::collections::BTreeMap;

use wasmnet_wire::{Direction, PcapNgEncoder};

use crate::clock::{Ctx, EventKey, KeyLevel, Nanos, Origin, Tag};
use crate::journal::{JournalEntry, Level, Record, Stream};
use crate::link::{
    CaptureOptions, DropReason, FrameFate, FrameRecord, Impairments, LinkInfo, LinkKind, LinkStats,
    LinkTransition, PortInfo, RemoteArrival, RemoteFrame, Tap,
};
use crate::network::{DeviceId, LinkId, Network, PortRef, Runtime};
use crate::{Outcome, Result};

// ---- messages and their wire format (docs/design/sites.md) ----------------------------------

/// The null message: no frame the sender sends from now on is due before `promise`. `next` is
/// the sender's earliest queued event that it will still process (`None`: none), valid for the
/// moment when it had sent `sent` frames and received `recv` frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sync {
    pub promise: Nanos,
    pub next: Option<Nanos>,
    pub sent: u64,
    pub recv: u64,
}

/// One site-sync message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    /// The join handshake: the sender's devices' `ports()` answers, by global device index.
    Hello { ports: Vec<(usize, Vec<PortInfo>)> },
    /// Frames for the receiver's devices, in transmit order.
    Frames(Vec<RemoteFrame>),
    /// A null message.
    Sync(Sync),
    /// The sender saw the whole network finish (quiescent, or nothing left before the deadline).
    Done,
    /// After the network finished: everything the sender recorded, so the receiver can merge
    /// both sites' records (a site that runs on a thread or worker of its own ships them).
    Records(Box<SiteRecords>),
}

/// The first bytes of every message, then the format version.
pub const MAGIC: [u8; 3] = *b"WNS";
/// The wire format version this implementation speaks.
pub const VERSION: u8 = 3;

/// A message that could not be decoded, or a handshake that does not fit this site.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    /// The bytes do not start with [`MAGIC`] and a version.
    #[error("site-sync message: not a site-sync message")]
    NotSiteSync,
    /// A format version this implementation does not speak.
    #[error("site-sync message: unsupported version {0}")]
    Version(u8),
    #[error("site-sync message: unknown message type {0}")]
    UnknownType(u8),
    /// The message is cut short or a field holds a value it cannot hold.
    #[error("site-sync message: {what} at byte {at}")]
    Malformed { what: &'static str, at: usize },
    /// [`apply_hello`] got another kind of message.
    #[error("site-sync message: expected Hello, got {0}")]
    NotHello(&'static str),
    /// A Hello names a device that is not one of the peer's.
    #[error("site-sync message: Hello for device {0}, not one of the peer's")]
    NotPeerDevice(usize),
}

/// A peer site that broke the lockstep protocol ([`SiteSync::handle`]). Nothing of the
/// offending message was queued.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// A frame on a link this network does not have.
    #[error("site sync: a WAN frame on link {link}, of {links}")]
    NoSuchLink { link: usize, links: usize },
    /// A frame for a link end other than 0 or 1.
    #[error("site sync: a WAN frame for link end {0}")]
    NoSuchEnd(usize),
    /// A frame whose destination is not a WAN link's end on this site.
    #[error(
        "site sync: a WAN frame for {device}:{port} on link {link}, not a WAN link's end on this site"
    )]
    NotWanEnd {
        device: usize,
        port: u32,
        link: usize,
    },
    /// A frame without a causal key.
    #[error("site sync: a WAN frame without a key")]
    NoKey,
    /// A frame due before this site's current time: the sites are out of lockstep.
    #[error("site sync: lockstep violation: a frame due at t={due} arrived at t={now}")]
    Overdue { due: Nanos, now: Nanos },
    /// A Hello or Records message while the sites run in lockstep.
    #[error("site sync: a {0} message during lockstep")]
    UnexpectedMessage(&'static str),
}

/// Two sites' records that cannot be merged ([`merge`]): records from a peer must name what
/// exists and be in processing order.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MergeError {
    #[error("a site's records are out of processing order")]
    OutOfOrder,
    /// The sites disagree on how many links the network was built with.
    #[error("the sites saw {0} and {1} setup links")]
    LinkCount(usize, usize),
    /// The sites disagree on how many devices the network was built with.
    #[error("the sites saw {0} and {1} setup devices")]
    SetupDevices(usize, usize),
    /// The sites disagree on a setup link.
    #[error("the sites' setup links differ: `{0}` and `{1}`")]
    SetupLink(String, String),
    #[error("unknown device {0}")]
    UnknownDevice(usize),
    #[error("unknown link {0}")]
    UnknownLink(usize),
    #[error("link {0} has an end on no site")]
    NoSite(String),
    #[error("a tap on link end {0}")]
    BadTapEnd(usize),
    #[error("arrival of unknown frame {0}")]
    UnknownFrame(usize),
    #[error("frame {0} arrived twice")]
    ArrivedTwice(usize),
    /// Writing a WAN link's merged capture failed.
    #[error(transparent)]
    Pcap(#[from] wasmnet_wire::PcapNgError),
}

impl Msg {
    /// The message's kind, as errors name it.
    fn kind(&self) -> &'static str {
        match self {
            Msg::Hello { .. } => "Hello",
            Msg::Frames(_) => "Frames",
            Msg::Sync(_) => "Sync",
            Msg::Done => "Done",
            Msg::Records(_) => "Records",
        }
    }
}

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    /// Unsigned LEB128.
    fn uv(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.0.push(b);
                return;
            }
            self.0.push(b | 0x80);
        }
    }

    fn bytes(&mut self, b: &[u8]) {
        self.uv(b.len() as u64);
        self.0.extend_from_slice(b);
    }

    fn key(&mut self, k: &EventKey) {
        self.uv(k.levels.len() as u64);
        let mut prev: Option<Nanos> = None;
        for l in &k.levels {
            // Causes are never later than their effects: deltas going back are non-negative.
            match prev {
                None => self.uv(l.at),
                Some(p) => self.uv(p - l.at),
            }
            prev = Some(l.at);
            self.u8(l.origin.code());
            self.uv(l.slot);
            self.uv(u64::from(l.round));
            self.uv(u64::from(l.device));
            self.uv(u64::from(l.idx));
            self.uv(l.counter);
        }
    }
}

struct Reader<'b> {
    buf: &'b [u8],
    pos: usize,
}

impl<'b> Reader<'b> {
    fn err(&self, what: &'static str) -> WireError {
        WireError::Malformed { what, at: self.pos }
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| self.err("truncated"))?;
        self.pos += 1;
        Ok(b)
    }

    fn uv(&mut self) -> Result<u64, WireError> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(self.err("varint too long"))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        u32::try_from(self.uv()?).map_err(|_| self.err("value out of range"))
    }

    fn usize(&mut self) -> Result<usize, WireError> {
        usize::try_from(self.uv()?).map_err(|_| self.err("value out of range"))
    }

    fn bytes(&mut self) -> Result<&'b [u8], WireError> {
        let n = self.usize()?;
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len());
        let end = end.ok_or_else(|| self.err("truncated"))?;
        let b = &self.buf[self.pos..end];
        self.pos = end;
        Ok(b)
    }

    fn string(&mut self) -> Result<String, WireError> {
        let b = self.bytes()?;
        String::from_utf8(b.to_vec()).map_err(|_| self.err("invalid UTF-8"))
    }

    fn key(&mut self) -> Result<EventKey, WireError> {
        let n = self.usize()?;
        if n == 0 || n > crate::clock::KEY_DEPTH {
            return Err(self.err("bad key depth"));
        }
        let mut levels = Vec::with_capacity(n);
        let mut prev: Option<Nanos> = None;
        for _ in 0..n {
            let v = self.uv()?;
            let at = match prev {
                None => v,
                Some(p) => p.checked_sub(v).ok_or_else(|| self.err("bad key time"))?,
            };
            prev = Some(at);
            let origin = Origin::from_code(self.u8()?).ok_or_else(|| self.err("bad origin"))?;
            levels.push(KeyLevel {
                at,
                origin,
                slot: self.uv()?,
                round: self.u32()?,
                device: self.u32()?,
                idx: self.u32()?,
                counter: self.uv()?,
                // Operator events never cross sites: the wire has no pre bit.
                pre: 0,
            });
        }
        Ok(EventKey { levels })
    }
}

// ---- RECORDS (type 5): a site's final records -------------------------------------------------

impl Writer {
    fn flag(&mut self, b: bool) {
        self.u8(u8::from(b));
    }

    fn string(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    fn strings(&mut self, list: &[String]) {
        self.uv(list.len() as u64);
        for s in list {
            self.string(s);
        }
    }

    /// A key with each level's *pre* number after it (records only; frames never carry one).
    fn full_key(&mut self, k: &EventKey) {
        self.key(k);
        for l in &k.levels {
            self.uv(u64::from(l.pre));
        }
    }

    fn tag(&mut self, t: &Tag) {
        self.u8(t.ctx.origin.code());
        match &t.ctx.cause {
            None => self.u8(0),
            Some(k) => {
                self.u8(1);
                self.full_key(k);
            }
        }
        self.uv(t.ctx.slot);
        self.uv(u64::from(t.ctx.round));
        self.uv(u64::from(t.ctx.device));
        self.uv(t.n);
    }

    fn port_ref(&mut self, p: PortRef) {
        self.uv(p.device.index() as u64);
        self.uv(u64::from(p.port));
    }

    fn fate(&mut self, f: &FrameFate) {
        match f {
            FrameFate::InFlight => self.u8(0),
            FrameFate::Delivered { at } => {
                self.u8(1);
                self.uv(*at);
            }
            FrameFate::Lost => self.u8(2),
            FrameFate::Dropped(r) => {
                self.u8(3);
                self.u8(match r {
                    DropReason::LinkDown => 0,
                    DropReason::Oversize => 1,
                    DropReason::Operator => 2,
                    DropReason::QueueFull => 3,
                });
            }
        }
    }

    fn records(&mut self, r: &SiteRecords) {
        match &r.outcome {
            Ok(Outcome::Quiescent {
                at,
                parked,
                daemons,
            }) => {
                self.u8(0);
                self.uv(*at);
                self.strings(parked);
                self.strings(daemons);
            }
            Ok(Outcome::Deadline { at, pending_events }) => {
                self.u8(1);
                self.uv(*at);
                self.uv(*pending_events as u64);
            }
            Err((at, message)) => {
                self.u8(2);
                self.uv(*at);
                self.string(message);
            }
        }
        self.uv(r.now);
        self.uv(r.devices.len() as u64);
        for &d in &r.devices {
            self.uv(d as u64);
        }
        self.uv(r.setup_devices as u64);
        self.uv(r.created_devices.len() as u64);
        for (d, name, t) in &r.created_devices {
            self.uv(*d as u64);
            self.string(name);
            self.tag(t);
        }
        self.uv(r.created_links.len() as u64);
        for (l, t) in &r.created_links {
            self.uv(*l as u64);
            self.tag(t);
        }
        self.uv(r.journal.len() as u64);
        for (t, e) in &r.journal {
            self.tag(t);
            self.uv(e.at);
            self.string(&e.device);
            match &e.record {
                Record::Log { level, message } => {
                    self.u8(0);
                    self.u8(match level {
                        Level::Trace => 0,
                        Level::Debug => 1,
                        Level::Info => 2,
                        Level::Warn => 3,
                        Level::Error => 4,
                    });
                    self.string(message);
                }
                Record::Event { kind, fields } => {
                    self.u8(1);
                    self.string(kind);
                    self.uv(fields.len() as u64);
                    for (k, v) in fields {
                        self.string(k);
                        self.string(v);
                    }
                }
                Record::Output { stream, line } => {
                    self.u8(2);
                    self.flag(*stream == Stream::Stderr);
                    self.string(line);
                }
            }
        }
        self.uv(r.journal_dropped);
        self.uv(r.frames.len() as u64);
        for (t, f) in &r.frames {
            self.tag(t);
            self.uv(f.link.index() as u64);
            self.port_ref(f.from);
            self.port_ref(f.to);
            self.uv(f.sent_at);
            self.fate(&f.fate);
            self.uv(f.len as u64);
            self.bytes(&f.bytes);
        }
        self.uv(r.arrivals.len() as u64);
        for a in &r.arrivals {
            self.uv(a.frame_id as u64);
            self.fate(&a.fate);
        }
        self.uv(r.taps.len() as u64);
        for t in &r.taps {
            self.tag(&t.tag);
            self.uv(t.link.index() as u64);
            self.uv(t.end as u64);
            self.uv(t.at);
            self.flag(t.inbound);
            self.uv(t.len as u64);
            self.bytes(&t.bytes);
        }
        self.uv(r.transitions.len() as u64);
        for (t, tr) in &r.transitions {
            self.tag(t);
            self.uv(tr.at);
            self.uv(tr.link.index() as u64);
            self.flag(tr.up);
        }
        self.uv(r.links.len() as u64);
        for (info, stats, pcap) in &r.links {
            self.string(&info.name);
            self.port_ref(info.ends[0]);
            self.port_ref(info.ends[1]);
            self.uv(info.latency);
            self.uv(u64::from(info.mtu));
            self.flag(info.up);
            self.flag(info.removed);
            // The kind's stable code: 0 for Ethernet, a cable kind's registered code.
            self.u8(info.kind.code());
            for imp in &info.impairments {
                self.uv(imp.rate);
                self.uv(u64::from(imp.queue));
                self.uv(u64::from(imp.loss_ppm));
                self.uv(imp.jitter);
            }
            self.flag(info.capture.record);
            self.uv(u64::from(info.capture.snap_len));
            self.flag(info.capture.name_ends);
            for pair in [
                stats.frames,
                stats.bytes,
                stats.dropped_down,
                stats.oversize,
                stats.lost,
                stats.dropped_queue,
                stats.lost_random,
            ] {
                self.uv(pair[0]);
                self.uv(pair[1]);
            }
            self.bytes(pcap);
        }
    }
}

impl Reader<'_> {
    fn flag(&mut self) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(self.err("bad flag")),
        }
    }

    fn strings(&mut self) -> Result<Vec<String>, WireError> {
        let n = self.usize()?;
        (0..n).map(|_| self.string()).collect()
    }

    fn full_key(&mut self) -> Result<EventKey, WireError> {
        let mut k = self.key()?;
        for l in &mut k.levels {
            l.pre = self.u32()?;
        }
        Ok(k)
    }

    fn tag(&mut self) -> Result<Tag, WireError> {
        let origin = Origin::from_code(self.u8()?).ok_or_else(|| self.err("bad origin"))?;
        let cause = match self.u8()? {
            0 => None,
            1 => Some(self.full_key()?),
            _ => return Err(self.err("bad cause flag")),
        };
        Ok(Tag {
            ctx: Ctx {
                origin,
                cause,
                slot: self.uv()?,
                round: self.u32()?,
                device: self.u32()?,
            },
            n: self.uv()?,
        })
    }

    fn port_ref(&mut self) -> Result<PortRef, WireError> {
        Ok(PortRef {
            device: DeviceId::from_index(self.usize()?),
            port: self.u32()?,
        })
    }

    fn fate(&mut self) -> Result<FrameFate, WireError> {
        Ok(match self.u8()? {
            0 => FrameFate::InFlight,
            1 => FrameFate::Delivered { at: self.uv()? },
            2 => FrameFate::Lost,
            3 => FrameFate::Dropped(match self.u8()? {
                0 => DropReason::LinkDown,
                1 => DropReason::Oversize,
                2 => DropReason::Operator,
                3 => DropReason::QueueFull,
                _ => return Err(self.err("bad drop reason")),
            }),
            _ => return Err(self.err("bad frame fate")),
        })
    }

    fn records(&mut self) -> Result<SiteRecords, WireError> {
        let outcome = match self.u8()? {
            0 => Ok(Outcome::Quiescent {
                at: self.uv()?,
                parked: self.strings()?,
                daemons: self.strings()?,
            }),
            1 => Ok(Outcome::Deadline {
                at: self.uv()?,
                pending_events: self.usize()?,
            }),
            2 => Err((self.uv()?, self.string()?)),
            _ => return Err(self.err("bad outcome")),
        };
        let now = self.uv()?;
        let n = self.usize()?;
        let devices = (0..n).map(|_| self.usize()).collect::<Result<_, _>>()?;
        let setup_devices = self.usize()?;
        let n = self.usize()?;
        let mut created_devices = Vec::new();
        for _ in 0..n {
            created_devices.push((self.usize()?, self.string()?, self.tag()?));
        }
        let n = self.usize()?;
        let mut created_links = Vec::new();
        for _ in 0..n {
            created_links.push((self.usize()?, self.tag()?));
        }
        let n = self.usize()?;
        let mut journal = Vec::new();
        for _ in 0..n {
            let tag = self.tag()?;
            let at = self.uv()?;
            let device = self.string()?;
            let record = match self.u8()? {
                0 => {
                    let level = match self.u8()? {
                        0 => Level::Trace,
                        1 => Level::Debug,
                        2 => Level::Info,
                        3 => Level::Warn,
                        4 => Level::Error,
                        _ => return Err(self.err("bad level")),
                    };
                    Record::Log {
                        level,
                        message: self.string()?,
                    }
                }
                1 => {
                    let kind = self.string()?;
                    let k = self.usize()?;
                    let fields = (0..k)
                        .map(|_| Ok((self.string()?, self.string()?)))
                        .collect::<Result<_, WireError>>()?;
                    Record::Event { kind, fields }
                }
                2 => Record::Output {
                    stream: if self.flag()? {
                        Stream::Stderr
                    } else {
                        Stream::Stdout
                    },
                    line: self.string()?,
                },
                _ => return Err(self.err("bad journal record")),
            };
            journal.push((tag, JournalEntry { at, device, record }));
        }
        let journal_dropped = self.uv()?;
        let n = self.usize()?;
        let mut frames = Vec::new();
        for _ in 0..n {
            let tag = self.tag()?;
            frames.push((
                tag,
                FrameRecord {
                    link: LinkId::from_index(self.usize()?),
                    from: self.port_ref()?,
                    to: self.port_ref()?,
                    sent_at: self.uv()?,
                    fate: self.fate()?,
                    len: self.usize()?,
                    bytes: self.bytes()?.to_vec(),
                },
            ));
            if frames.last().is_some_and(|(_, f)| f.bytes.len() > f.len) {
                return Err(self.err("frame bytes longer than the frame"));
            }
        }
        let n = self.usize()?;
        let mut arrivals = Vec::new();
        for _ in 0..n {
            arrivals.push(RemoteArrival {
                frame_id: self.usize()?,
                fate: self.fate()?,
            });
        }
        let n = self.usize()?;
        let mut taps = Vec::new();
        for _ in 0..n {
            let tag = self.tag()?;
            let link = LinkId::from_index(self.usize()?);
            let end = self.usize()?;
            if end > 1 {
                return Err(self.err("bad link end"));
            }
            taps.push(Tap {
                tag,
                link,
                end,
                at: self.uv()?,
                inbound: self.flag()?,
                len: self.usize()?,
                bytes: self.bytes()?.to_vec(),
            });
            if taps.last().is_some_and(|t| t.bytes.len() > t.len) {
                return Err(self.err("tap bytes longer than the frame"));
            }
        }
        let n = self.usize()?;
        let mut transitions = Vec::new();
        for _ in 0..n {
            let tag = self.tag()?;
            transitions.push((
                tag,
                LinkTransition {
                    at: self.uv()?,
                    link: LinkId::from_index(self.usize()?),
                    up: self.flag()?,
                },
            ));
        }
        let n = self.usize()?;
        let mut links = Vec::new();
        for _ in 0..n {
            let mut info = LinkInfo {
                name: self.string()?,
                ends: [self.port_ref()?, self.port_ref()?],
                latency: self.uv()?,
                mtu: self.u32()?,
                up: self.flag()?,
                removed: self.flag()?,
                kind: LinkKind::from_code(self.u8()?),
                impairments: [Impairments::default(); 2],
                capture: CaptureOptions::default(),
                capture_notes: Vec::new(),
            };
            for imp in &mut info.impairments {
                *imp = Impairments {
                    rate: self.uv()?,
                    queue: self.u32()?,
                    loss_ppm: self.u32()?,
                    jitter: self.uv()?,
                };
            }
            info.capture = CaptureOptions {
                record: self.flag()?,
                snap_len: self.u32()?,
                name_ends: self.flag()?,
            };
            let mut pairs = [[0u64; 2]; 7];
            for p in &mut pairs {
                *p = [self.uv()?, self.uv()?];
            }
            let [
                frames,
                bytes,
                dropped_down,
                oversize,
                lost,
                dropped_queue,
                lost_random,
            ] = pairs;
            let stats = LinkStats {
                frames,
                bytes,
                dropped_down,
                oversize,
                lost,
                dropped_queue,
                lost_random,
            };
            let pcap = self.bytes()?.to_vec();
            // The notes travel in the capture itself, as its section comments.
            info.capture_notes = crate::pcap::parse_header(&pcap)
                .map(|c| c.comments)
                .unwrap_or_default();
            links.push((info, stats, pcap));
        }
        Ok(SiteRecords {
            outcome,
            now,
            devices,
            setup_devices,
            created_devices,
            created_links,
            journal,
            journal_dropped,
            frames,
            arrivals,
            taps,
            transitions,
            links,
        })
    }
}

impl Msg {
    /// The message in the site-sync wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        w.0.extend_from_slice(&MAGIC);
        w.u8(VERSION);
        match self {
            Msg::Hello { ports } => {
                w.u8(1);
                w.uv(ports.len() as u64);
                for (device, ports) in ports {
                    w.uv(*device as u64);
                    w.uv(ports.len() as u64);
                    for p in ports {
                        w.uv(u64::from(p.id));
                        w.bytes(p.name.as_bytes());
                        match p.mac {
                            None => w.u8(0),
                            Some(mac) => {
                                w.u8(1);
                                w.0.extend_from_slice(&mac.octets());
                            }
                        }
                        w.uv(u64::from(p.mtu));
                    }
                }
            }
            Msg::Frames(frames) => {
                w.u8(2);
                w.uv(frames.len() as u64);
                for f in frames {
                    w.key(&f.key);
                    w.uv(f.link.index() as u64);
                    w.u8(f.to_end as u8);
                    w.uv(f.generation);
                    w.uv(f.frame_id as u64);
                    w.uv(f.device.index() as u64);
                    w.uv(u64::from(f.port));
                    w.bytes(&f.bytes);
                }
            }
            Msg::Sync(s) => {
                w.u8(3);
                w.uv(s.promise);
                match s.next {
                    None => w.u8(0),
                    Some(t) => {
                        w.u8(1);
                        w.uv(t);
                    }
                }
                w.uv(s.sent);
                w.uv(s.recv);
            }
            Msg::Done => w.u8(4),
            Msg::Records(r) => {
                w.u8(5);
                w.records(r);
            }
        }
        w.0
    }

    /// Parses one message.
    pub fn decode(buf: &[u8]) -> Result<Msg, WireError> {
        let mut r = Reader { buf, pos: 0 };
        if buf.len() < 5 || buf[..3] != MAGIC {
            return Err(WireError::NotSiteSync);
        }
        if buf[3] != VERSION {
            return Err(WireError::Version(buf[3]));
        }
        r.pos = 4;
        let msg = match r.u8()? {
            1 => {
                let n = r.usize()?;
                let mut ports = Vec::new();
                for _ in 0..n {
                    let device = r.usize()?;
                    let k = r.usize()?;
                    let mut list = Vec::new();
                    for _ in 0..k {
                        let id = r.u32()?;
                        let name = r.string()?;
                        let mac = match r.u8()? {
                            0 => None,
                            1 => {
                                let mut o = [0u8; 6];
                                for b in &mut o {
                                    *b = r.u8()?;
                                }
                                Some(wasmnet_wire::MacAddr::new(o))
                            }
                            _ => return Err(r.err("bad MAC flag")),
                        };
                        let mtu = r.u32()?;
                        list.push(PortInfo { id, name, mac, mtu });
                    }
                    ports.push((device, list));
                }
                Msg::Hello { ports }
            }
            2 => {
                let n = r.usize()?;
                let mut frames = Vec::new();
                for _ in 0..n {
                    let key = r.key()?;
                    let link = LinkId::from_index(r.usize()?);
                    let to_end = usize::from(r.u8()?);
                    if to_end > 1 {
                        return Err(r.err("bad link end"));
                    }
                    frames.push(RemoteFrame {
                        key,
                        link,
                        to_end,
                        generation: r.uv()?,
                        frame_id: r.usize()?,
                        device: DeviceId::from_index(r.usize()?),
                        port: r.u32()?,
                        bytes: r.bytes()?.to_vec(),
                    });
                }
                Msg::Frames(frames)
            }
            3 => Msg::Sync(Sync {
                promise: r.uv()?,
                next: match r.u8()? {
                    0 => None,
                    1 => Some(r.uv()?),
                    _ => return Err(r.err("bad next flag")),
                },
                sent: r.uv()?,
                recv: r.uv()?,
            }),
            4 => Msg::Done,
            5 => Msg::Records(Box::new(r.records()?)),
            t => return Err(WireError::UnknownType(t)),
        };
        if r.pos != buf.len() {
            return Err(r.err("trailing bytes"));
        }
        Ok(msg)
    }
}

/// The join handshake message: this site's devices' ports.
pub fn hello<R: Runtime + ?Sized>(network: &Network<'_, R>) -> Msg {
    let ports = network
        .devices()
        .into_iter()
        .filter(|&d| !network.is_remote(d))
        .map(|d| (d.index(), network.ports(d)))
        .collect();
    Msg::Hello { ports }
}

/// Applies the peer's handshake: its devices' ports become our placeholders' ports.
pub fn apply_hello<R: Runtime + ?Sized>(
    network: &mut Network<'_, R>,
    msg: &Msg,
) -> Result<(), WireError> {
    let Msg::Hello { ports } = msg else {
        return Err(WireError::NotHello(msg.kind()));
    };
    for (device, ports) in ports {
        let id = network
            .devices()
            .get(*device)
            .copied()
            .filter(|&d| network.is_remote(d))
            .ok_or(WireError::NotPeerDevice(*device))?;
        network.set_remote_ports(id, ports.clone());
    }
    Ok(())
}

// ---- the lockstep driver ---------------------------------------------------------------------

/// What [`SiteSync::handle`] asks the caller to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Wait for the next message from the peer.
    Wait,
    /// The horizon moved: run [`SiteSync::window`] and send what it returns.
    Window,
    /// The whole network finished; send `Done` if [`SiteSync::handle`] said so, then stop.
    Done { send_done: bool },
}

/// Site-sync counters, for reports and benchmarks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyncStats {
    /// Windows run.
    pub windows: u64,
    /// Null messages sent.
    pub syncs: u64,
    /// Horizon raises from the next-event fixpoint (not from a plain promise).
    pub fixpoint_raises: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
}

/// The conservative lockstep driver of one site of a two-site network (sans-IO).
///
/// ```text
/// H := L                                   # the peer's earliest transmit is at t = 0
/// loop:
///   run every local event with at < H      # window()
///   send Frames(outbox), then Sync{promise = min(next, H) + L, next, sent, recv}
///   on Frames: queue them under their keys
///   on Sync s: H := max(H, s.promise)
///              if the counts match (nothing in flight either way):
///                done if both sites have nothing left; otherwise
///                H := max(H, min(s.next, our_next + L) + L)          # the fixpoint
/// ```
#[derive(Clone, Debug)]
pub struct SiteSync {
    lookahead: Nanos,
    horizon: Nanos,
    deadline: Option<Nanos>,
    fixpoint: bool,
    sent: u64,
    recv: u64,
    stats: SyncStats,
}

impl SiteSync {
    /// A driver for a network whose WAN links' smallest latency is `lookahead` (> 0), running until
    /// quiescent (`deadline = None`) or through `deadline`.
    pub fn new(lookahead: Nanos, deadline: Option<Nanos>) -> Self {
        assert!(
            lookahead > 0,
            "a WAN link needs a latency > 0: it is the lookahead"
        );
        Self {
            lookahead,
            horizon: lookahead,
            deadline,
            fixpoint: true,
            sent: 0,
            recv: 0,
            stats: SyncStats::default(),
        }
    }

    /// Turns the next-event fixpoint off (plain Chandy–Misra–Bryant null messages; slow, for
    /// tests and measurements).
    pub fn without_fixpoint(mut self) -> Self {
        self.fixpoint = false;
        self
    }

    pub fn stats(&self) -> SyncStats {
        self.stats
    }

    /// The earliest queued event this site will still process (`None` past the deadline).
    fn next<R: Runtime + ?Sized>(&self, network: &Network<'_, R>) -> Option<Nanos> {
        network
            .next_event_time()
            .filter(|&t| self.deadline.is_none_or(|d| t <= d))
    }

    /// One window: runs every local event before the horizon (and not after the deadline),
    /// then returns the messages for the peer: the frames transmitted towards it, and a null
    /// message.
    pub fn window<R: Runtime + ?Sized>(
        &mut self,
        network: &mut Network<'_, R>,
    ) -> Result<Vec<Msg>> {
        network.run_before(Some(self.cap()))?;
        Ok(self.close_window(network))
    }

    /// Where the current window ends: the events to run are those strictly before it. A
    /// driver that runs them itself (one in a browser, which lets JS settle between instants)
    /// calls this, runs them, then [`close_window`](Self::close_window).
    pub fn cap(&self) -> Nanos {
        self.deadline
            .map_or(self.horizon, |d| self.horizon.min(d.saturating_add(1)))
    }

    /// Ends a window whose events (those before [`cap`](Self::cap)) have run: the messages for
    /// the peer, as [`window`](Self::window) returns them.
    pub fn close_window<R: Runtime + ?Sized>(&mut self, network: &mut Network<'_, R>) -> Vec<Msg> {
        self.stats.windows += 1;
        let mut out = Vec::new();
        let frames = network.take_outbox();
        if !frames.is_empty() {
            self.sent += frames.len() as u64;
            self.stats.frames_sent += frames.len() as u64;
            out.push(Msg::Frames(frames));
        }
        let next = self.next(network);
        // Whatever we do from now on happens at or after min(next, horizon); a frame is due one
        // lookahead later.
        let promise = next
            .unwrap_or(Nanos::MAX)
            .min(self.horizon)
            .saturating_add(self.lookahead);
        out.push(Msg::Sync(Sync {
            promise,
            next,
            sent: self.sent,
            recv: self.recv,
        }));
        self.stats.syncs += 1;
        out
    }

    /// Handles one message from the peer.
    pub fn handle<R: Runtime + ?Sized>(
        &mut self,
        network: &mut Network<'_, R>,
        msg: Msg,
    ) -> Result<Step> {
        match msg {
            Msg::Frames(frames) => {
                // Peer input: every frame must be for a WAN link's end here and not overdue,
                // or the message is refused whole (nothing queued).
                for f in &frames {
                    network.check_remote(f)?;
                }
                self.recv += frames.len() as u64;
                self.stats.frames_received += frames.len() as u64;
                for f in frames {
                    network.receive_remote(f);
                }
                Ok(Step::Wait)
            }
            Msg::Sync(s) => {
                let consistent = s.recv == self.sent && self.recv == s.sent;
                let ours = self.next(network);
                if consistent && s.next.is_none() && ours.is_none() {
                    // Both queues are empty (up to the deadline) and nothing is in flight.
                    return Ok(Step::Done { send_done: true });
                }
                let old = self.horizon;
                self.horizon = self.horizon.max(s.promise);
                if self.fixpoint && consistent {
                    // Both snapshots see every frame sent so far, so the peer's next frame is
                    // due no earlier than min(its next event, ours + lookahead) + lookahead.
                    let bound = s
                        .next
                        .unwrap_or(Nanos::MAX)
                        .min(ours.unwrap_or(Nanos::MAX).saturating_add(self.lookahead))
                        .saturating_add(self.lookahead);
                    if bound > self.horizon {
                        self.horizon = bound;
                        self.stats.fixpoint_raises += 1;
                    }
                }
                Ok(if self.horizon > old {
                    Step::Window
                } else {
                    Step::Wait
                })
            }
            Msg::Done => Ok(Step::Done { send_done: false }),
            Msg::Hello { .. } | Msg::Records(_) => {
                Err(SyncError::UnexpectedMessage(msg.kind()).into())
            }
        }
    }

    /// After [`Step::Done`]: runs what is left before the deadline (nothing, normally) and
    /// returns this site's end state.
    pub fn finish<R: Runtime + ?Sized>(&self, network: &mut Network<'_, R>) -> Result<Outcome> {
        network.run_before(self.deadline.map(|d| d.saturating_add(1)))
    }
}

// ---- merging the sites' records --------------------------------------------------------------

/// Everything one site recorded, tagged for merging.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SiteRecords {
    /// The site's end state (`Err((at, message))` if it failed).
    pub outcome: std::result::Result<Outcome, (Nanos, String)>,
    /// Its virtual time at the end.
    pub now: Nanos,
    /// Indices of its devices.
    pub devices: Vec<usize>,
    /// How many devices the network was built with (the same on every site). Indices below
    /// it are the same everywhere; the devices created while the network ran have indices
    /// local to their site.
    pub setup_devices: usize,
    /// The devices this site created while the network ran: index, name, and the tag of the
    /// processing context that created it.
    pub created_devices: Vec<(usize, String, Tag)>,
    /// The links this site created while the network ran: index and creation tag. The links
    /// it did not create are the network's setup links, the same on every site.
    pub created_links: Vec<(usize, Tag)>,
    pub journal: Vec<(Tag, JournalEntry)>,
    pub journal_dropped: u64,
    pub frames: Vec<(Tag, FrameRecord)>,
    pub arrivals: Vec<RemoteArrival>,
    pub taps: Vec<Tap>,
    pub transitions: Vec<(Tag, LinkTransition)>,
    /// Every link as this site saw it: info, counters, capture.
    pub links: Vec<(LinkInfo, LinkStats, Vec<u8>)>,
}

impl SiteRecords {
    /// Collects a site's records after its run.
    pub fn collect<R: Runtime + ?Sized>(
        network: &Network<'_, R>,
        outcome: std::result::Result<Outcome, (Nanos, String)>,
    ) -> Self {
        let zip = |tags: Vec<Tag>, items| tags.into_iter().zip(items).collect();
        let created_devices: Vec<(usize, String, Tag)> = network
            .created_devices()
            .into_iter()
            .map(|(d, t)| (d.index(), network.device_name(d).to_owned(), t))
            .collect();
        Self {
            outcome,
            now: network.now(),
            devices: network
                .devices()
                .into_iter()
                .filter(|&d| !network.is_remote(d))
                .map(DeviceId::index)
                .collect(),
            setup_devices: network.devices().len() - created_devices.len(),
            created_devices,
            created_links: network
                .created_links()
                .into_iter()
                .map(|(l, t)| (l.index(), t))
                .collect(),
            journal: zip(network.journal_tags(), network.journal()),
            journal_dropped: network.journal_dropped(),
            frames: network
                .frame_tags()
                .into_iter()
                .zip(network.frames())
                .collect(),
            arrivals: network.remote_arrivals(),
            taps: network.taps(),
            transitions: network
                .transition_tags()
                .into_iter()
                .zip(network.link_transitions())
                .collect(),
            links: network
                .links()
                .into_iter()
                .map(|l| (network.link_info(l), network.link_stats(l), network.pcap(l)))
                .collect(),
        }
    }
}

/// The records of a whole multi-site network, as one site would have produced them.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Merged {
    pub outcome: std::result::Result<Outcome, (Nanos, String)>,
    pub end: Nanos,
    /// Every device's name, by index: the setup devices, then the devices created while the
    /// network ran, in the order the unsplit network created them.
    pub devices: Vec<String>,
    pub journal: Vec<JournalEntry>,
    pub journal_dropped: u64,
    pub frames: Vec<FrameRecord>,
    pub transitions: Vec<LinkTransition>,
    /// Per link: counters and capture.
    pub links: Vec<(LinkStats, Vec<u8>)>,
    /// Per link: its properties at the end, from the site that ran it (a WAN link's from
    /// site 0).
    pub link_infos: Vec<LinkInfo>,
}

/// Where each site's site-local indices go in the merged records: the setup indices stay,
/// the indices of what a site created while the network ran follow in the unsplit creation
/// order (the order of the creations' tags).
struct Renumber {
    setup_devices: usize,
    setup_links: usize,
    devices: [BTreeMap<usize, usize>; 2],
    links: [BTreeMap<usize, usize>; 2],
}

impl Renumber {
    fn new(sites: [&SiteRecords; 2]) -> std::result::Result<Self, MergeError> {
        let setup_devices = sites[0].setup_devices;
        if sites[1].setup_devices != setup_devices {
            return Err(MergeError::SetupDevices(
                setup_devices,
                sites[1].setup_devices,
            ));
        }
        let setup = |s: &SiteRecords| s.links.len().checked_sub(s.created_links.len());
        let (Some(a), Some(b)) = (setup(sites[0]), setup(sites[1])) else {
            return Err(MergeError::LinkCount(
                sites[0].links.len(),
                sites[1].links.len(),
            ));
        };
        if a != b {
            return Err(MergeError::LinkCount(a, b));
        }
        let setup_links = a;
        let mut devices: Vec<(&Tag, usize, usize)> = Vec::new();
        let mut links: Vec<(&Tag, usize, usize)> = Vec::new();
        for (k, s) in sites.iter().enumerate() {
            for (d, _, t) in &s.created_devices {
                if *d < setup_devices {
                    return Err(MergeError::UnknownDevice(*d));
                }
                devices.push((t, k, *d));
            }
            for (l, t) in &s.created_links {
                if !(setup_links..s.links.len()).contains(l) {
                    return Err(MergeError::UnknownLink(*l));
                }
                links.push((t, k, *l));
            }
        }
        // Everything one processing context creates is on one site, in its local order.
        devices.sort();
        links.sort();
        let mut out = Self {
            setup_devices,
            setup_links,
            devices: Default::default(),
            links: Default::default(),
        };
        for (n, (_, k, d)) in devices.into_iter().enumerate() {
            if out.devices[k].insert(d, setup_devices + n).is_some() {
                return Err(MergeError::UnknownDevice(d));
            }
        }
        for (n, (_, k, l)) in links.into_iter().enumerate() {
            if out.links[k].insert(l, setup_links + n).is_some() {
                return Err(MergeError::UnknownLink(l));
            }
        }
        Ok(out)
    }

    fn device(&self, site: usize, d: DeviceId) -> std::result::Result<DeviceId, MergeError> {
        let i = d.index();
        if i < self.setup_devices {
            return Ok(d);
        }
        self.devices[site]
            .get(&i)
            .map(|&m| DeviceId::from_index(m))
            .ok_or(MergeError::UnknownDevice(i))
    }

    fn port(&self, site: usize, p: PortRef) -> std::result::Result<PortRef, MergeError> {
        Ok(PortRef {
            device: self.device(site, p.device)?,
            port: p.port,
        })
    }

    fn link(&self, site: usize, l: LinkId) -> std::result::Result<LinkId, MergeError> {
        let j = l.index();
        if j < self.setup_links {
            return Ok(l);
        }
        self.links[site]
            .get(&j)
            .map(|&m| LinkId::from_index(m))
            .ok_or(MergeError::UnknownLink(j))
    }
}

/// Merges two sites' records (see `docs/design/sites.md`). `device_names` are the names of
/// the devices the network was built with, in order (the names of devices created while it
/// ran come with the records; names past the setup devices are ignored), `deadline` the run's
/// deadline if any. The devices and links a site created while the network ran are
/// renumbered into the unsplit network's order.
pub fn merge(
    sites: [&SiteRecords; 2],
    device_names: &[String],
    deadline: Option<Nanos>,
) -> std::result::Result<Merged, MergeError> {
    for s in sites {
        let ordered = |tags: Vec<&Tag>| tags.windows(2).all(|w| w[0] < w[1]);
        if !ordered(s.journal.iter().map(|(t, _)| t).collect())
            || !ordered(s.frames.iter().map(|(t, _)| t).collect())
            || !ordered(s.taps.iter().map(|t| &t.tag).collect())
        {
            return Err(MergeError::OutOfOrder);
        }
    }

    // Records can come from a peer: what they name must exist (an error, never a panic).
    let renumber = Renumber::new(sites)?;
    let setup = renumber.setup_devices;
    if device_names.len() < setup {
        return Err(MergeError::UnknownDevice(device_names.len()));
    }
    let mut names: Vec<String> = device_names[..setup].to_vec();
    names.resize(
        setup + renumber.devices.iter().map(BTreeMap::len).sum::<usize>(),
        String::new(),
    );
    for (k, s) in sites.iter().enumerate() {
        for (d, name, _) in &s.created_devices {
            let m = renumber.device(k, DeviceId::from_index(*d))?.index();
            names[m] = name.clone();
        }
    }
    let site_of = |device: usize| {
        (device < setup)
            .then(|| sites.iter().position(|s| s.devices.contains(&device)))
            .flatten()
    };
    let device_name = |e: crate::PortRef| {
        names
            .get(e.device.index())
            .map(|n| format!("{n}:{}", e.port))
            .ok_or(MergeError::UnknownDevice(e.device.index()))
    };

    // The setup links: a site-local link from its site; a WAN link from both halves.
    let mut links = Vec::new();
    let mut link_infos = Vec::new();
    for j in 0..renumber.setup_links {
        let info = &sites[0].links[j].0;
        if sites[1].links[j].0.name != info.name {
            return Err(MergeError::SetupLink(
                info.name.clone(),
                sites[1].links[j].0.name.clone(),
            ));
        }
        let [ea, eb] = info.ends;
        let (sa, sb) = (site_of(ea.device.index()), site_of(eb.device.index()));
        match (sa, sb) {
            (Some(a), Some(b)) if a == b => {
                let (info, stats, pcap) = &sites[a].links[j];
                links.push((*stats, pcap.clone()));
                link_infos.push(info.clone());
            }
            (Some(_), Some(_)) => {
                let mut stats = LinkStats::default();
                for s in sites {
                    stats.add(&s.links[j].1);
                }
                let mut taps: Vec<&Tap> = sites
                    .iter()
                    .flat_map(|s| s.taps.iter().filter(|t| t.link.index() == j))
                    .collect();
                taps.sort_by(|x, y| x.tag.cmp(&y.tag));
                // The header the first site wrote for the link (names, snap length,
                // descriptions, notes; without a readable one, the ends' names and no notes),
                // then both halves' records, each with its original length.
                let (header, notes) = crate::pcap::parse_header(&sites[0].links[j].2)
                    .map(|c| (c.interfaces, c.comments))
                    .unwrap_or_default();
                let notes: Vec<&str> = notes.iter().map(String::as_str).collect();
                let mut pcap = PcapNgEncoder::with_comments("wasmnet", &notes)?;
                let mut ifaces = Vec::new();
                for (end, port) in [ea, eb].into_iter().enumerate() {
                    let (name, snaplen, description) = match header.get(end) {
                        Some(i) => (
                            i.name.clone().unwrap_or_default(),
                            i.snaplen,
                            i.description.clone().unwrap_or_default(),
                        ),
                        None => (device_name(port)?, 0, String::new()),
                    };
                    ifaces.push(pcap.add_described_interface(&name, snaplen, &description)?);
                }
                for t in taps {
                    let dir = if t.inbound {
                        Direction::Inbound
                    } else {
                        Direction::Outbound
                    };
                    let iface = *ifaces.get(t.end).ok_or(MergeError::BadTapEnd(t.end))?;
                    pcap.write_packet_prefix(iface, t.at, &t.bytes, t.len, dir)?;
                }
                links.push((stats, pcap.bytes().to_vec()));
                link_infos.push(info.clone());
            }
            _ => return Err(MergeError::NoSite(info.name.clone())),
        }
    }
    // The links created while the network ran: each from the site that created it (both its
    // ends are there), in the unsplit creation order.
    let mut created: Vec<(usize, usize, usize)> = Vec::new();
    for (k, s) in sites.iter().enumerate() {
        for (l, _) in &s.created_links {
            created.push((renumber.link(k, LinkId::from_index(*l))?.index(), k, *l));
        }
    }
    created.sort();
    for (_, k, l) in created {
        let (info, stats, pcap) = &sites[k].links[l];
        let mut info = info.clone();
        for e in &mut info.ends {
            *e = renumber.port(k, *e)?;
        }
        links.push((*stats, pcap.clone()));
        link_infos.push(info);
    }

    // Frames: each site's log with the fates the other site saw, renumbered, merged by tag.
    let mut frames: Vec<(Tag, FrameRecord)> = Vec::new();
    for (k, s) in sites.iter().enumerate() {
        let mut log = s.frames.clone();
        for a in &sites[1 - k].arrivals {
            let (_, f) = log
                .get_mut(a.frame_id)
                .ok_or(MergeError::UnknownFrame(a.frame_id))?;
            if f.fate != FrameFate::InFlight {
                return Err(MergeError::ArrivedTwice(a.frame_id));
            }
            f.fate = a.fate;
        }
        for (_, f) in &mut log {
            f.link = renumber.link(k, f.link)?;
            f.from = renumber.port(k, f.from)?;
            f.to = renumber.port(k, f.to)?;
        }
        frames.extend(log);
    }
    frames.sort_by(|x, y| x.0.cmp(&y.0));

    let mut journal: Vec<(Tag, JournalEntry)> =
        sites.iter().flat_map(|s| s.journal.clone()).collect();
    journal.sort_by(|x, y| x.0.cmp(&y.0));
    // A scripted change of a WAN link happens on both sites, under the same tag: keep one.
    let mut transitions: BTreeMap<Tag, LinkTransition> = BTreeMap::new();
    for (k, s) in sites.iter().enumerate() {
        for (t, tr) in &s.transitions {
            let mut tr = *tr;
            tr.link = renumber.link(k, tr.link)?;
            transitions.insert(t.clone(), tr);
        }
    }

    let end = sites.iter().map(|s| s.now).max().unwrap_or(0);
    // The live device of a name is its latest one.
    let index_of = |name: &str| names.iter().rposition(|d| d == name);
    let outcome = match (&sites[0].outcome, &sites[1].outcome) {
        (Err(e), _) | (_, Err(e)) => Err(e.clone()),
        (Ok(a), Ok(b)) => {
            let parts = |o: &Outcome| match o {
                Outcome::Quiescent {
                    parked, daemons, ..
                } => (parked.clone(), daemons.clone(), 0),
                Outcome::Deadline { pending_events, .. } => {
                    (Vec::new(), Vec::new(), *pending_events)
                }
            };
            let (pa, da, na) = parts(a);
            let (pb, db, nb) = parts(b);
            if na + nb > 0 {
                Ok(Outcome::Deadline {
                    at: deadline.unwrap_or(end),
                    pending_events: na + nb,
                })
            } else {
                let mut parked: Vec<String> = pa.into_iter().chain(pb).collect();
                parked.sort_by_key(|n| index_of(n));
                let mut daemons: Vec<String> = da.into_iter().chain(db).collect();
                // `<device>: <call>`; the sort is stable, so one device's calls keep their order.
                daemons.sort_by_key(|d| index_of(d.split(": ").next().unwrap_or("")));
                Ok(Outcome::Quiescent {
                    at: end,
                    parked,
                    daemons,
                })
            }
        }
    };
    let end = match (&outcome, deadline) {
        (Ok(Outcome::Deadline { .. }), Some(d)) => d,
        _ => end,
    };
    Ok(Merged {
        outcome,
        end,
        devices: names,
        journal: journal.into_iter().map(|(_, e)| e).collect(),
        journal_dropped: sites.iter().map(|s| s.journal_dropped).sum(),
        frames: frames.into_iter().map(|(_, f)| f).collect(),
        transitions: transitions.into_values().collect(),
        links,
        link_infos,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(at: Nanos) -> EventKey {
        let level = |at, origin| KeyLevel {
            at,
            origin,
            slot: 3,
            round: 2,
            device: crate::clock::HOST_DEVICE,
            idx: 1,
            counter: 99_999,
            pre: 0,
        };
        EventKey {
            levels: vec![level(at, Origin::Popped), level(at - 5, Origin::Setup)],
        }
    }

    /// A site's records with one of every kind of row.
    fn records() -> SiteRecords {
        let mut cause = key(2_000);
        cause.levels[1].pre = 2;
        let tag = |n| Tag {
            ctx: Ctx {
                origin: Origin::Popped,
                cause: Some(cause.clone()),
                slot: 0,
                round: 1,
                device: 3,
            },
            n,
        };
        let setup = Tag {
            ctx: Ctx {
                origin: Origin::Setup,
                cause: None,
                slot: 4,
                round: 0,
                device: crate::clock::HOST_DEVICE,
            },
            n: 0,
        };
        let port = |d, port| PortRef {
            device: DeviceId::from_index(d),
            port,
        };
        let entry = |record| JournalEntry {
            at: 1_500,
            device: "alice".to_owned(),
            record,
        };
        let mut r = SiteRecords {
            outcome: Ok(Outcome::Quiescent {
                at: 9_000,
                parked: vec!["alice".to_owned()],
                daemons: vec!["web: app-http-server.run".to_owned()],
            }),
            now: 9_000,
            devices: vec![0, 3, 4],
            setup_devices: 4,
            created_devices: vec![(4, "web-1".to_owned(), tag(30))],
            created_links: vec![(1, tag(31))],
            journal: vec![
                (
                    tag(0),
                    entry(Record::Log {
                        level: Level::Warn,
                        message: "hm".to_owned(),
                    }),
                ),
                (
                    tag(1),
                    entry(Record::Event {
                        kind: "mac-learned".to_owned(),
                        fields: vec![("port".to_owned(), "1".to_owned())],
                    }),
                ),
                (
                    tag(2),
                    entry(Record::Output {
                        stream: Stream::Stderr,
                        line: "x".to_owned(),
                    }),
                ),
            ],
            journal_dropped: 1,
            frames: [
                FrameFate::InFlight,
                FrameFate::Delivered { at: 7 },
                FrameFate::Lost,
                FrameFate::Dropped(DropReason::Oversize),
                FrameFate::Dropped(DropReason::QueueFull),
            ]
            .into_iter()
            .enumerate()
            .map(|(i, fate)| {
                (
                    tag(10 + i as u64),
                    FrameRecord {
                        link: LinkId::from_index(0),
                        from: port(0, 0),
                        to: port(3, 1),
                        sent_at: 1_000,
                        fate,
                        len: 3,
                        bytes: vec![1, 2, 3],
                    },
                )
            })
            .collect(),
            arrivals: vec![RemoteArrival {
                frame_id: 5,
                fate: FrameFate::Dropped(DropReason::Operator),
            }],
            taps: vec![Tap {
                tag: tag(20),
                link: LinkId::from_index(0),
                end: 1,
                at: 1_100,
                inbound: true,
                len: 60,
                bytes: vec![9; 14],
            }],
            transitions: vec![(
                setup,
                LinkTransition {
                    at: 5_000,
                    link: LinkId::from_index(0),
                    up: false,
                },
            )],
            links: vec![(
                LinkInfo {
                    name: "alice.0-sw.1".to_owned(),
                    ends: [port(0, 0), port(3, 1)],
                    latency: 100_000,
                    mtu: 1500,
                    up: true,
                    removed: false,
                    kind: LinkKind::from_code(2),
                    impairments: [
                        Impairments::default()
                            .rate(10_000_000)
                            .queue(64)
                            .loss_ppm(10_000)
                            .jitter(50_000),
                        Impairments::default(),
                    ],
                    capture: CaptureOptions::default().snap_len(96).name_ends(true),
                    capture_notes: Vec::new(),
                },
                LinkStats {
                    frames: [1, 2],
                    bytes: [3, 4],
                    dropped_down: [5, 6],
                    oversize: [7, 8],
                    lost: [9, 10],
                    dropped_queue: [11, 12],
                    lost_random: [13, 14],
                },
                vec![0x0a, 0x0d, 0x0d, 0x0a],
            )],
        };
        // A link `web-1` was created with, to `sw`.
        let mut created = r.links[0].clone();
        created.0.name = "web-1.0-sw.2".to_owned();
        created.0.ends = [port(4, 0), port(3, 2)];
        r.links.push(created);
        r
    }

    /// Two sites' records whose sites each created devices and links while the network ran:
    /// site 0 `ctl-a`'s `a-1` (at tag 1) and `a-2` (tag 3), site 1 `ctl-b`'s `b-1` (tag 2).
    /// Both were built with devices 0 (`sw-a`, site 0) and 1 (`sw-b`, site 1) and one WAN link.
    fn created_on_both() -> [SiteRecords; 2] {
        let tag = |n: u64| Tag {
            ctx: Ctx {
                origin: Origin::Popped,
                cause: Some(key(n * 1_000)),
                slot: 0,
                round: 0,
                device: crate::clock::HOST_DEVICE,
            },
            n: 0,
        };
        let port = |d, port| PortRef {
            device: DeviceId::from_index(d),
            port,
        };
        let link = |name: &str, a, b| {
            (
                LinkInfo {
                    name: name.to_owned(),
                    ends: [a, b],
                    latency: 1_000,
                    mtu: 1500,
                    up: true,
                    removed: false,
                    kind: LinkKind::Ethernet,
                    impairments: [Impairments::default(); 2],
                    capture: CaptureOptions::default(),
                    capture_notes: Vec::new(),
                },
                LinkStats::default(),
                Vec::new(),
            )
        };
        let frame = |link, from, to| FrameRecord {
            link: LinkId::from_index(link),
            from,
            to,
            sent_at: 0,
            fate: FrameFate::Delivered { at: 1 },
            len: 1,
            bytes: vec![1],
        };
        let wan = link("sw-a.0-sw-b.0", port(0, 0), port(1, 0));
        let empty = |devices| SiteRecords {
            outcome: Ok(Outcome::Deadline {
                at: 9_000,
                pending_events: 0,
            }),
            now: 9_000,
            devices,
            setup_devices: 2,
            created_devices: Vec::new(),
            created_links: Vec::new(),
            journal: Vec::new(),
            journal_dropped: 0,
            frames: Vec::new(),
            arrivals: Vec::new(),
            taps: Vec::new(),
            transitions: Vec::new(),
            links: vec![wan.clone()],
        };
        let mut a = empty(vec![0, 2, 3]);
        a.created_devices = vec![(2, "a-1".to_owned(), tag(1)), (3, "a-2".to_owned(), tag(3))];
        a.created_links = vec![(1, tag(1)), (2, tag(3))];
        a.links.push(link("a-1.0-sw-a.1", port(2, 0), port(0, 1)));
        a.links.push(link("a-2.0-sw-a.2", port(3, 0), port(0, 2)));
        a.frames = vec![
            (tag(1), frame(1, port(2, 0), port(0, 1))),
            (tag(3), frame(2, port(3, 0), port(0, 2))),
        ];
        let mut b = empty(vec![1, 2]);
        b.created_devices = vec![(2, "b-1".to_owned(), tag(2))];
        b.created_links = vec![(1, tag(2))];
        b.links.push(link("b-1.0-sw-b.1", port(2, 0), port(1, 1)));
        b.frames = vec![(tag(2), frame(1, port(2, 0), port(1, 1)))];
        [a, b]
    }

    #[test]
    fn devices_and_links_created_on_both_sites_merge_in_creation_order() {
        let [a, b] = created_on_both();
        let names: Vec<String> = ["sw-a", "sw-b"].map(String::from).to_vec();
        let m = merge([&a, &b], &names, None).expect("merges");
        assert_eq!(m.devices, ["sw-a", "sw-b", "a-1", "b-1", "a-2"]);
        let link_names: Vec<&str> = m.link_infos.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(
            link_names,
            [
                "sw-a.0-sw-b.0",
                "a-1.0-sw-a.1",
                "b-1.0-sw-b.1",
                "a-2.0-sw-a.2"
            ]
        );
        // `b-1` is device 3 and its link is link 2 in the merged records; `a-2` device 4 on
        // link 3.
        assert_eq!(m.link_infos[2].ends[0].device.index(), 3);
        let renumbered: Vec<(usize, usize)> = m
            .frames
            .iter()
            .map(|f| (f.link.index(), f.from.device.index()))
            .collect();
        assert_eq!(renumbered, [(1, 2), (2, 3), (3, 4)]);
        // The names past the setup devices are the records' own.
        let more: Vec<String> = ["sw-a", "sw-b", "x"].map(String::from).to_vec();
        assert_eq!(merge([&a, &b], &more, None).unwrap().devices, m.devices);
        // Sites that disagree on the setup, or name what they did not create, are errors.
        let mut bad = b.clone();
        bad.setup_devices = 3;
        assert!(merge([&a, &bad], &names, None).is_err());
        let mut bad = b.clone();
        bad.created_links.clear();
        assert!(merge([&a, &bad], &names, None).is_err());
        let mut bad = b.clone();
        bad.frames[0].1.from = port_of(7);
        assert!(merge([&a, &bad], &names, None).is_err());
        let mut bad = b.clone();
        bad.links[0].0.name = "other".to_owned();
        assert!(merge([&a, &bad], &names, None).is_err());
    }

    fn port_of(device: usize) -> PortRef {
        PortRef {
            device: DeviceId::from_index(device),
            port: 0,
        }
    }

    #[test]
    fn messages_round_trip_through_the_wire_format() {
        let msgs = [
            Msg::Hello {
                ports: vec![(
                    2,
                    vec![PortInfo {
                        id: 1,
                        name: "p1".to_owned(),
                        mac: Some(wasmnet_wire::MacAddr::new([2, 0, 0, 0, 0, 1])),
                        mtu: 1500,
                    }],
                )],
            },
            Msg::Frames(vec![RemoteFrame {
                key: key(1_000_000),
                link: LinkId::from_index(3),
                to_end: 1,
                generation: 2,
                frame_id: 17,
                device: DeviceId::from_index(4),
                port: 0,
                bytes: vec![0xff; 60],
            }]),
            Msg::Sync(Sync {
                promise: 123,
                next: Some(456),
                sent: 7,
                recv: 8,
            }),
            Msg::Sync(Sync {
                promise: u64::MAX,
                next: None,
                sent: 0,
                recv: 0,
            }),
            Msg::Done,
            Msg::Records(Box::new(records())),
        ];
        for m in msgs {
            let bytes = m.encode();
            assert_eq!(Msg::decode(&bytes), Ok(m.clone()), "{m:?}");
            for cut in 0..bytes.len() {
                assert!(Msg::decode(&bytes[..cut]).is_err(), "{m:?} cut at {cut}");
            }
        }
        let mut wrong = Msg::Done.encode();
        wrong[3] = 9;
        assert!(Msg::decode(&wrong).is_err());
    }

    #[test]
    fn records_from_a_peer_that_name_nothing_are_errors_not_panics() {
        // A tap on link end 2 does not decode.
        let mut r = records();
        r.taps[0].end = 2;
        assert!(Msg::decode(&Msg::Records(Box::new(r)).encode()).is_err());
        // Two sites: device 0 on one, device 3 on the other, link 0 between them a WAN link
        // with one tap.
        let mut a = records();
        a.devices = vec![0];
        a.arrivals.clear();
        a.taps[0].link = LinkId::from_index(0);
        let mut b = records();
        b.devices = vec![3];
        b.created_devices.clear();
        b.created_links.clear();
        b.links.truncate(1);
        b.arrivals.clear();
        b.journal.clear();
        b.frames.clear();
        b.taps.clear();
        let names: Vec<String> = ["alice", "x", "y", "sw"].map(String::from).to_vec();
        assert!(merge([&a, &b], &names, None).is_ok());
        // A device the names do not know, a tap end past the two, link lists that differ.
        assert!(merge([&a, &b], &names[..2], None).is_err());
        let mut far_tap = a.clone();
        far_tap.taps[0].end = 5;
        assert!(merge([&far_tap, &b], &names, None).is_err());
        let mut fewer = b.clone();
        fewer.links.clear();
        assert!(merge([&a, &fewer], &names, None).is_err());
    }
}
