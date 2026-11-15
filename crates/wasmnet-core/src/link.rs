//! The patch panel: point-to-point links between device ports, with latency, carrier (up/down),
//! an MTU, pcap taps and a frame log.
//!
//! `wire.transmit` lands here. It never calls into a device. A frame on an unwired port, on a
//! down link or with a payload over the link MTU is dropped and counted. Otherwise it is tapped
//! as *outbound* on the sender's end and a delivery is queued at `now + latency`. When the
//! executor fires that delivery, the frame is tapped as *inbound* on the receiver's end and goes
//! to the receiver's inbox, unless the link went down in the meantime (then it is lost).
//!
//! Each link has one pcap-ng capture with one interface per end (`<device>:<port>`), so a link's
//! file shows what each NIC saw and when, with direction flags and virtual-ns timestamps. The
//! frame log keeps every transmission with its fate, for run records and assertions.
//!
//! The only frame parsing here is the L2 header length (for the MTU), which is link-model
//! behaviour like a PHY's maximum frame size, not networking logic.

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use wasmnet_wire::{Direction, EthernetFrame, InterfaceId, MacAddr, PcapNgEncoder};

use crate::clock::{Delivery, DeviceIdx, EventKey, Nanos, Tag, VirtualClock};
use crate::digest::{self, Digest};
use crate::ext::{CableKind, CableModel, CableSend, Carry, ExtValue};
use crate::journal::{Journal, JournalEntry};
use crate::network::{DeviceId, LinkId, PortRef};

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
}

/// Static and current properties of a link.
#[derive(Clone, Debug, PartialEq, Eq)]
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
}

impl DropReason {
    /// `link-down`, `oversize` or `operator`.
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::LinkDown => "link-down",
            DropReason::Oversize => "oversize",
            DropReason::Operator => "operator",
        }
    }
}

/// What an operator does to one transmission, at `wire.transmit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameAction {
    /// It never enters the wire (fate `dropped`, reason `operator`).
    Drop,
    /// These bytes enter the wire instead (and are what the pcap and frame log show).
    Replace(Vec<u8>),
    /// It arrives this much later than the link's latency.
    Delay(Nanos),
}

/// A transmission on a wired port, as a [`TransmitHook`] sees it before it enters the wire.
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
pub enum FrameFate {
    /// On the wire, not yet arrived (the run stopped at a deadline first).
    InFlight,
    /// Arrived at the peer at this instant.
    Delivered { at: Nanos },
    /// The link went down while the frame was in flight.
    Lost,
    /// Never entered the wire.
    Dropped(DropReason),
}

/// One `wire.transmit` on a wired port, in transmit order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameRecord {
    pub link: LinkId,
    pub from: PortRef,
    pub to: PortRef,
    /// Virtual time of the transmit call.
    pub sent_at: Nanos,
    pub fate: FrameFate,
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
pub struct Tap {
    pub tag: Tag,
    pub link: LinkId,
    /// The end whose interface recorded it.
    pub end: usize,
    pub at: Nanos,
    pub inbound: bool,
    pub bytes: Vec<u8>,
}

/// What became of a frame that another site sent to this one (its record is in the sender's
/// frame log, at `frame_id`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteArrival {
    pub frame_id: usize,
    pub fate: FrameFate,
}

/// A carrier change of a whole link, as it happened (scripted; creating a link is not one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

impl Link {
    fn port_ref(&self, end: usize) -> PortRef {
        let (device, port) = self.ends[end];
        DeviceId(device).port(port)
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

    pub(crate) fn ports(&self, device: DeviceIdx) -> Vec<PortInfo> {
        self.state().devices[device].ports.clone()
    }

    /// Wires `a` to `b` with the given latency. The link starts up, and its MTU is the smaller
    /// of the two ports' MTUs.
    pub(crate) fn connect(
        &self,
        a: (DeviceIdx, u32),
        b: (DeviceIdx, u32),
        latency: Nanos,
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
        // Building a capture header cannot fail for names this short; fall back to no names.
        let mut pcap = PcapNgEncoder::new(PCAP_USER_APPL).expect("static SHB fits");
        let mut iface = |name: &str| {
            pcap.add_ethernet_interface(name, 0)
                .or_else(|_| pcap.add_ethernet_interface("", 0))
                .expect("IDB without options fits")
        };
        let ifaces = [iface(&na), iface(&nb)];
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

    /// Registers the model of cable kind `kind`.
    pub(crate) fn register_cable(&self, kind: CableKind, model: Arc<dyn CableModel>) {
        self.cables
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(kind.code(), model);
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

    /// The link's capture so far (a complete, valid pcap-ng file).
    pub(crate) fn pcap(&self, link: usize) -> Vec<u8> {
        self.state().links[link].pcap.bytes().to_vec()
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
                link.stats.oversize[end] += 1;
                return;
            }
            if dropped || !link.up || peer_remote {
                link.stats.dropped_down[end] += 1;
                return;
            }
            link.stats.frames[end] += 1;
            link.stats.bytes[end] += frame.len() as u64;
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
        let link = &mut s.links[link_id];
        let drop_reason = if dropped {
            Some(DropReason::Operator)
        } else if !link.up {
            link.stats.dropped_down[end] += 1;
            Some(DropReason::LinkDown)
        } else if payload_len(&frame) > link.mtu as usize {
            link.stats.oversize[end] += 1;
            Some(DropReason::Oversize)
        } else {
            None
        };
        let record = FrameRecord {
            link: LinkId(link_id),
            from: link.port_ref(end),
            to: link.port_ref(to_end),
            sent_at: now,
            fate: drop_reason.map_or(FrameFate::InFlight, FrameFate::Dropped),
            bytes: frame.clone(),
        };
        if drop_reason.is_some() {
            s.frames.push(record);
            s.frame_tags.push(tag);
            return;
        }
        // Only a > 4 GiB frame could fail to encode; such a frame is still delivered.
        let _ = link
            .pcap
            .write_packet_directed(link.ifaces[end], now, &frame, Direction::Outbound);
        link.stats.frames[end] += 1;
        link.stats.bytes[end] += frame.len() as u64;
        let (peer, peer_port) = link.ends[to_end];
        let at = now.saturating_add(link.latency).saturating_add(delay);
        let generation = link.generation;
        s.frames.push(record);
        s.frame_tags.push(tag.clone());
        if peer_remote {
            // A WAN link: record this site's half of the capture and hand the frame to site
            // sync, keyed exactly as a local delivery would be.
            s.taps.push(Tap {
                tag,
                link: LinkId(link_id),
                end,
                at: now,
                inbound: false,
                bytes: frame.clone(),
            });
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
                link.stats.lost[1 - d.to_end] += 1;
            }
            return delivered;
        }
        if delivered {
            let _ = link.pcap.write_packet_directed(
                link.ifaces[d.to_end],
                at,
                &d.frame,
                Direction::Inbound,
            );
        } else {
            link.stats.lost[1 - d.to_end] += 1;
        }
        let fate = if delivered {
            FrameFate::Delivered { at }
        } else {
            FrameFate::Lost
        };
        if d.remote {
            if delivered {
                let tag = clock.tag();
                s.taps.push(Tap {
                    tag,
                    link: LinkId(d.link),
                    end: d.to_end,
                    at,
                    inbound: true,
                    bytes: d.frame.clone(),
                });
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
        let link = panel.connect((a, 0), (b, 1), 10).unwrap();
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
            panel.connect((0, 7), (1, 0), 0),
            Err(ConnectError::Unknown(0, 7))
        );
        assert_eq!(
            panel.connect((0, 0), (1, 0), 0),
            Err(ConnectError::InUse(0, 0))
        );
        assert_eq!(
            panel.connect((0, 1), (0, 1), 0),
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
}
