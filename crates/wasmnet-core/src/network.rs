//! The network builder: devices, links, scripted link changes and a deterministic run, over any
//! [`Runtime`] backend.
//!
//! The network owns everything deterministic: the clock and queue, the executor, the patch
//! panel, the journal and captured stdio. A backend only turns a component into a running
//! device: it instantiates it with the handles in a [`DeviceContext`], answers its `ports()`,
//! and returns one actor future that turns [`Command`]s from the device's inbox into export
//! calls (`docs/design/async-under-virtual-time.md`).

use std::any::{Any, TypeId};
use std::borrow::Borrow;
use std::sync::Arc;

use crate::clock::{DeviceIdx, EventKey, HOST_DEVICE, Nanos, Tag, VirtualClock};
use crate::config::DeviceConfig;
use crate::device::{Command, CountersReply, Inbox, Status};
use crate::digest::Digest;
use crate::exec::{ActorFuture, Boundary, CoreOp, Executor, Flow, OpState, Stats, Step};
use crate::ext::{
    Action, ActionCall, CableKind, CableModel, Control, ControlCall, DeviceExt, DeviceLife,
    DeviceSetup, ExtOptions, ExtValue, ExtensionOp, LifeEvent, NetworkExtension, OpContext,
    OpError, OpTarget, SetupOrigin,
};
use crate::infra::{Infra, InfraEnd, Phase};
use crate::journal::{Journal, JournalEnd, JournalEntry, Stream};
use crate::link::{
    CaptureOptions, FrameAction, Impairments, LinkKind, SeriesOptions, TransmitHook,
};
use crate::link::{
    ConnectError, FrameRecord, LinkInfo, LinkStats, LinkTransition, Panel, PortInfo, RemoteArrival,
    RemoteFrame, Tap, Wire,
};
use crate::output::OutputCapture;
use crate::{Error, Guard, Outcome, Result, SimConfig};
use wasmnet_wire::MacAddr;

/// A runtime backend: turns a component into a running network device.
pub trait Runtime {
    /// What a device is made from (wasmtime: a compiled `Component`). The network keeps an
    /// owned copy of each device's component, so a stopped device starts again without the
    /// component resolver.
    type Component: ?Sized + ToOwned;

    /// Instantiates `component` as the device described by `device`, calls its `ports()` at the
    /// network's current instant, and returns the answer with the device's actor: one future
    /// that owns the instance for its whole life, starts it (`start()` for async devices, then the
    /// apps' `run`s), and turns every [`Command`] from `device.inbox` into an export call,
    /// recording in-flight calls in `device.status`. After a `receive` or `link-state` it asks
    /// for a `poll` at the same instant ([`VirtualClock::poll_by`]), and after a `poll` it
    /// replaces the deadline ([`VirtualClock::set_poll`]).
    ///
    /// Nothing may be queued for the device before this returns; the network registers the
    /// device (and its first poll) afterwards.
    fn instantiate(
        &self,
        device: DeviceContext,
        component: &Self::Component,
    ) -> Result<DeviceInstance>;

    /// Called once by [`Network::with_config`] before the network is returned: a backend
    /// registers the network extensions and cable kinds it serves ([`Network::add_extension`],
    /// [`Network::register_cable`]). The default registers nothing.
    fn install(&self, network: &mut Network<'_, Self>) {
        let _ = network;
    }

    /// One line of a fault or error message this backend produced, for the records that show
    /// it: a contained crash's `device-crashed` event and a controller's device message. The
    /// default is the first line ([`crate::infra::one_line`]); a backend whose messages put
    /// the cause last picks that line instead.
    fn summarize(&self, message: &str) -> String {
        crate::infra::one_line(message)
    }

    /// Compiles a component an in-world controller supplied as bytes
    /// ([`crate::supply`], `docs/design/topology-and-infra.md`), named by its digest reference
    /// `digest` (`sha256:<hex>`). The network calls it when a creation from that digest
    /// applies and it has no result for the digest yet, after it checked the digest and the
    /// embedder admitted the bytes; it keeps the result (a refusal too) while a controller's
    /// store keeps the bytes. A refusal (`Err(why)`) fails the creation, never the network: a
    /// backend refuses bytes that are not a component, and a component that imports
    /// something it does not serve. The default refuses: a backend that cannot compile at run
    /// time.
    fn compile_supplied(
        &self,
        digest: &str,
        bytes: &[u8],
    ) -> std::result::Result<<Self::Component as ToOwned>::Owned, String> {
        let _ = bytes;
        Err(format!(
            "this runtime cannot run supplied components (`{digest}`): it compiles nothing \
             while a network runs"
        ))
    }
}

/// Everything a backend needs to run one device deterministically.
#[non_exhaustive]
pub struct DeviceContext {
    /// The device's index in the network (what [`VirtualClock::set_poll`] and friends take).
    pub index: usize,
    /// Its unique name in the network: `argv[0]`, the key of its RNG seeds and of its journal
    /// records.
    pub name: String,
    /// The network's root seed ([`crate::derive_seed`] with the name gives the device's seeds).
    pub seed: u64,
    pub clock: VirtualClock,
    /// `wasmnet:link/wire.transmit`.
    pub wire: Wire,
    /// `wasmnet:link/log`.
    pub journal: JournalEnd,
    /// Served read-only (`wasi:config/store`).
    pub config: DeviceConfig,
    /// Its arguments after `argv[0]` (the name) and its environment variables
    /// ([`DeviceOptions::args`], [`DeviceOptions::env`]), for `wasi:cli/environment`.
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    /// [`DeviceOptions::memory`], for a backend that enforces it.
    pub memory: Option<u64>,
    /// Where the guest's stdout and stderr go (journalled per [`DeviceOptions::journal_stdio`]).
    pub stdout: OutputCapture,
    pub stderr: OutputCapture,
    /// The device's commands, and what the host still awaits from it.
    pub inbox: Inbox,
    pub status: Status,
    /// Fuel per virtual instant (a backend without fuel metering ignores it).
    pub fuel_per_instant: u64,
    /// `wasmnet:infra` for a device granted it ([`DeviceOptions::infra`]). `None`: the backend
    /// must refuse the device's infra calls.
    pub infra: Option<InfraEnd>,
    /// The handles the network's extensions made for the device
    /// ([`NetworkExtension::device_setup`]).
    pub ext: DeviceExt,
}

/// One port as a device declared it (before the network checks it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredPort {
    pub id: u32,
    pub name: String,
    pub mac: Option<Vec<u8>>,
    pub mtu: u32,
}

/// A device the backend created.
#[non_exhaustive]
pub struct DeviceInstance {
    /// Its `ports()` answer.
    pub ports: Vec<DeclaredPort>,
    /// Its actor (see [`Runtime::instantiate`]).
    pub actor: ActorFuture,
    /// It exports `wasmnet:link/counters`.
    pub has_counters: bool,
    /// The optional exports the backend found and serves control calls for
    /// ([`ControlCall::export`]), by interface name.
    pub exports: Vec<String>,
    /// A composed node's apps (its `app-<name>` exports, by name, in the order they start).
    pub apps: Vec<String>,
}

impl DeviceInstance {
    /// A device with these ports and this actor, no `counters`, no optional exports and no
    /// apps.
    pub fn new(ports: Vec<DeclaredPort>, actor: ActorFuture) -> Self {
        Self {
            ports,
            actor,
            has_counters: false,
            exports: Vec::new(),
            apps: Vec::new(),
        }
    }

    /// Sets [`has_counters`](Self::has_counters).
    pub fn has_counters(mut self, on: bool) -> Self {
        self.has_counters = on;
        self
    }

    /// Sets [`exports`](Self::exports).
    pub fn exports(mut self, exports: Vec<String>) -> Self {
        self.exports = exports;
        self
    }

    /// Sets [`apps`](Self::apps).
    pub fn apps(mut self, apps: Vec<String>) -> Self {
        self.apps = apps;
        self
    }
}

/// A device in a network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub(crate) DeviceIdx);

impl DeviceId {
    /// One of the device's ports, for [`Network::link`].
    pub fn port(self, port: u32) -> PortRef {
        PortRef { device: self, port }
    }

    /// The device's index in its network (creation order).
    pub fn index(self) -> usize {
        self.0
    }

    /// The device with this index.
    pub fn from_index(index: usize) -> Self {
        Self(index)
    }
}

/// A `(device, port)` pair: one end of a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortRef {
    pub device: DeviceId,
    pub port: u32,
}

/// A point-to-point link in a network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(pub(crate) usize);

impl LinkId {
    /// The link's index in its network (creation order).
    pub fn index(self) -> usize {
        self.0
    }

    /// The link with this index.
    pub fn from_index(index: usize) -> Self {
        Self(index)
    }
}

/// A freshly created link, for setting its properties.
pub struct LinkMut<'l> {
    panel: &'l Panel,
    id: LinkId,
}

impl LinkMut<'_> {
    /// Sets the one-way latency in virtual nanoseconds (the same in both directions).
    /// It applies to frames transmitted from now on.
    pub fn latency(self, ns: Nanos) -> Self {
        self.panel.set_latency(self.id.0, ns);
        self
    }

    /// Sets the link MTU: the largest payload after the Ethernet header (and 802.1Q tag). Frames
    /// over it are dropped at transmit and counted. Default: the smaller of the two ports' MTUs.
    pub fn mtu(self, mtu: u32) -> Self {
        self.panel.set_mtu(self.id.0, mtu);
        self
    }

    /// Sets both directions' impairments (`docs/design/links.md`): a rate with a bounded
    /// transmit queue, seeded loss and jitter. They apply to frames transmitted from now on.
    pub fn impair(self, impairments: Impairments) -> Self {
        self.panel.set_impairments(self.id.0, None, impairments);
        self
    }

    /// Sets the impairments of the direction that `port`, one of the link's two ends, sends
    /// in. Panics if `port` is not an end of this link.
    pub fn impair_from(self, port: PortRef, impairments: Impairments) -> Self {
        let ends = self.panel.link_info(self.id.0).ends;
        let end = ends
            .iter()
            .position(|&e| e == port)
            .unwrap_or_else(|| panic!("{port:?} is not an end of this link ({ends:?})"));
        self.panel
            .set_impairments(self.id.0, Some(end), impairments);
        self
    }

    /// Sets what it carries: a cable kind ([`CableModel`]) has no pcap and no frame log; its
    /// model decides what each message does and records. Set it before the first transmission.
    pub fn kind(self, kind: LinkKind) -> Self {
        self.panel.set_kind(self.id.0, kind);
        self
    }

    /// Sets what its capture and frame log keep (`docs/design/links.md`): frame bytes or
    /// none, a snap length, and whether the capture header names the link's ends. Default: the
    /// network's ([`Network::set_capture_defaults`]). Set it before the first frame: the
    /// capture header is written again then; once a packet was captured only `record`
    /// changes.
    pub fn capture(self, capture: CaptureOptions) -> Self {
        self.panel.set_capture(self.id.0, capture);
        self
    }

    /// Sets the notes its capture carries, for a person who opens it (`docs/design/links.md`,
    /// "Notes in a capture"): each note becomes one `opt_comment` of the capture's Section
    /// Header Block, in order, such as `UDP 6081: Geneve tunnel data with STUN checks`. They
    /// replace the notes set before; none (the default) leaves the capture's bytes as they were.
    /// Unlike the capture options they may change at any time: a capture read later carries the
    /// notes in force then.
    ///
    /// Panics if the notes break [`pcap::check_notes`](crate::pcap::check_notes) (more than 16,
    /// an empty one, or one over 1024 bytes); [`Network::set_capture_notes`] refuses them
    /// instead.
    pub fn capture_notes<S: Into<String>>(self, notes: impl IntoIterator<Item = S>) -> Self {
        let notes: Vec<String> = notes.into_iter().map(Into::into).collect();
        if let Err(e) = crate::pcap::check_notes(&notes) {
            panic!("{e}");
        }
        self.panel.set_notes(self.id.0, notes);
        self
    }

    /// Counts its traffic per interval of virtual time as well (`docs/design/links.md`):
    /// buckets of `series.width` ns, the last `series.keep` kept
    /// ([`Network::link_series`]). It starts empty, from now on.
    pub fn series(self, series: SeriesOptions) -> Self {
        self.panel.set_series(self.id.0, Some(series));
        self
    }

    /// Configures the cable's state with a setup value its model understands
    /// ([`CableModel::configure`]); after [`kind`](Self::kind), before the first message.
    pub fn cable_setup(self, setup: &ExtValue) -> Self {
        self.panel.configure_cable(self.id.0, setup);
        self
    }

    pub fn id(&self) -> LinkId {
        self.id
    }
}

/// Per-device settings beyond its config. The defaults: the network's [`Guard`] fuel budget,
/// and stdio captured but not journalled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceOptions {
    /// This device's fuel per virtual instant instead of [`Guard::fuel_per_instant`]. A
    /// device that does heavy work in one instant (an interpreter, a large copy) needs far more
    /// than a small app. It stays a deterministic guard: a device that exceeds it traps with
    /// `OutOfFuel` at the same instant on every replay.
    pub fuel_per_instant: Option<u64>,
    /// Journal every line the device completes on stdout or stderr
    /// ([`crate::Record::Output`], stamped with virtual time). [`Network::stdout`] and
    /// [`Network::stderr`] have the raw bytes either way.
    pub journal_stdio: bool,
    /// The device may use `wasmnet:infra` (an in-world controller,
    /// `docs/design/topology-and-infra.md`): it gets an [`InfraEnd`] over the network's device
    /// table.
    pub infra: bool,
    /// With `infra`: the device may create only devices whose names start with this prefix
    /// (1-63 letters, digits, `-` or `_`). No two controllers' prefixes may overlap (one a
    /// prefix of the other). A split network whose controllers run on more than one site
    /// needs one on every controller, so that names their devices take on different sites
    /// cannot collide (`docs/design/sites.md`).
    pub infra_prefix: Option<String>,
    /// With `infra`: what becomes of the devices this controller created when it stops or is
    /// removed ([`Cascade`]; by default they keep running).
    pub infra_cascade: Cascade,
    /// With `infra`: the most devices this controller may have at once (every device it
    /// created that is in the table, whatever its phase); an `apply` of a new name beyond it
    /// is refused (`denied`) and changes nothing. `None`: no limit.
    pub infra_max_devices: Option<u32>,
    /// With `infra`: the controller may supply components as bytes and create devices from
    /// them by digest (`wasmnet:infra/components`), within these bounds; the network's
    /// admission callback judges every one ([`Network::set_supply_admission`]). `None`: the
    /// calls are `denied` and specs may name catalog components only.
    pub infra_supply: Option<crate::supply::SupplyLimits>,
    /// The most linear memory the device may use, in bytes, all its instances together. A
    /// device that grows past it traps, deterministically, at the growing instruction: a
    /// device that crashes alone (a controller's, or one with [`crash_alone`](Self::crash_alone))
    /// stops as `crashed`, any other fails the network, as when it runs out of fuel. `None`: no
    /// limit (the backend's own). Backends that cannot enforce it (the browser) ignore it.
    pub memory: Option<u64>,
    /// A fault of this device is a crash of the device alone, not the network's failure: when
    /// it traps (its own code, its fuel, its memory, a host extension's import, or
    /// [`Op::CrashDevice`]) it stops as crashed (`device-crashed`, phase `crashed`) and the
    /// network runs on, as a device an in-world controller created always does. Without it a
    /// fault of a device the embedder created fails the network ([`Error::Trap`]).
    pub crash_alone: bool,
    /// The device's arguments after `argv[0]` (its name), served by `wasi:cli/environment`.
    pub args: Vec<String>,
    /// Its environment variables, in this order, served by `wasi:cli/environment`.
    pub env: Vec<(String, String)>,
    /// Options of the network's extensions, by type: where an embedder's grant of a capability
    /// its extension serves goes (embedder surface, unstable).
    pub ext: ExtOptions,
}

/// Chainable setters, one per field, for building options that survive new fields:
/// `DeviceOptions::default().infra(true).crash_alone(true)`.
impl DeviceOptions {
    /// Sets [`fuel_per_instant`](Self::fuel_per_instant).
    pub fn fuel_per_instant(mut self, fuel: u64) -> Self {
        self.fuel_per_instant = Some(fuel);
        self
    }

    /// Sets [`journal_stdio`](Self::journal_stdio).
    pub fn journal_stdio(mut self, on: bool) -> Self {
        self.journal_stdio = on;
        self
    }

    /// Sets [`infra`](Self::infra).
    pub fn infra(mut self, on: bool) -> Self {
        self.infra = on;
        self
    }

    /// Sets [`infra_prefix`](Self::infra_prefix).
    pub fn infra_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.infra_prefix = Some(prefix.into());
        self
    }

    /// Sets [`infra_cascade`](Self::infra_cascade).
    pub fn infra_cascade(mut self, cascade: Cascade) -> Self {
        self.infra_cascade = cascade;
        self
    }

    /// Sets [`infra_max_devices`](Self::infra_max_devices).
    pub fn infra_max_devices(mut self, max: u32) -> Self {
        self.infra_max_devices = Some(max);
        self
    }

    /// Sets [`infra_supply`](Self::infra_supply).
    pub fn infra_supply(mut self, limits: crate::supply::SupplyLimits) -> Self {
        self.infra_supply = Some(limits);
        self
    }

    /// Sets [`memory`](Self::memory), in bytes.
    pub fn memory(mut self, bytes: u64) -> Self {
        self.memory = Some(bytes);
        self
    }

    /// Sets [`crash_alone`](Self::crash_alone).
    pub fn crash_alone(mut self, on: bool) -> Self {
        self.crash_alone = on;
        self
    }

    /// Sets [`args`](Self::args).
    pub fn args<S: Into<String>>(mut self, args: impl IntoIterator<Item = S>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Sets [`env`](Self::env).
    pub fn env<K: Into<String>, V: Into<String>>(
        mut self,
        env: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        self.env = env.into_iter().map(|(k, v)| (k.into(), v.into())).collect();
        self
    }

    /// Sets [`ext`](Self::ext) (embedder surface, unstable).
    pub fn ext(mut self, ext: ExtOptions) -> Self {
        self.ext = ext;
        self
    }
}

/// What becomes of the devices a controller created when the controller stops or is removed
/// ([`DeviceOptions::infra_cascade`], `docs/design/topology-and-infra.md`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cascade {
    /// They keep running (and stay its).
    #[default]
    Keep,
    /// They stop with it, at once, as on a power cut; a start of the controller does not start
    /// them again.
    Stop,
    /// They are removed with it.
    Remove,
}

struct DeviceRecord {
    name: String,
    /// Its number in event keys and record tags ([`Network::device_number`]).
    number: u32,
    /// Created while the network ran (an operator event or a controller): the tag of the
    /// processing context that created it (a split network's records are merged by it).
    created: Option<Tag>,
    inbox: Inbox,
    /// The component exports `wasmnet:link/counters`.
    has_counters: bool,
    /// The optional exports its backend serves control calls for.
    exports: Vec<String>,
    /// The node's apps (`app-<name>` exports), by name.
    apps: Vec<String>,
    stdout: OutputCapture,
    stderr: OutputCapture,
    /// A placeholder for a device that runs on another site.
    remote: bool,
    /// Its component's catalog name, when known (to start it again after a stop).
    component: Option<String>,
    config: DeviceConfig,
    options: DeviceOptions,
    phase: DevicePhase,
    /// Links its stop (or its pause with `link_down`) took down (a start or the resume brings
    /// them up again).
    downed: Vec<usize>,
    /// Paused with its links down ([`Op::PauseDevice`]'s `link_down`).
    paused_down: bool,
}

/// What a device is doing (its status under operator events).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DevicePhase {
    Running,
    /// Paused by an operator event ([`Op::PauseDevice`]): its store is kept and does not run;
    /// its name, ports and links stay.
    Paused,
    /// Stopped by an operator event, or crashed: no store, its links down, its name kept.
    Stopped,
    /// Removed by an operator event: unwired, its name free again.
    Removed,
}

/// The handles a new device's actor shares with the network.
struct Handles {
    inbox: Inbox,
    status: Status,
    stdout: OutputCapture,
    stderr: OutputCapture,
}

/// The rest of instantiating a device: called with the resolved component.
pub type Instantiate<'a, R> = dyn FnMut(&<R as Runtime>::Component) -> Result<DeviceInstance> + 'a;

/// Resolves a catalog name to a component and instantiates it (see
/// [`Network::set_component_resolver`]).
pub type ComponentResolver<'r, R> =
    Box<dyn Fn(&str, &mut Instantiate<'_, R>) -> Result<DeviceInstance> + 'r>;

/// A virtual network: devices (one runtime instance each), links between their ports, and one
/// virtual clock. Same components + same topology + same seed ⇒ byte-identical pcaps.
pub struct Network<'r, R: Runtime + ?Sized> {
    runtime: &'r R,
    config: SimConfig,
    guard: Guard,
    clock: VirtualClock,
    panel: Panel,
    journal: Journal,
    exec: Executor,
    devices: Vec<DeviceRecord>,
    /// Scripted link changes so far (their setup slots follow the devices').
    actions: u64,
    failed: bool,
    /// The network's extensions, in registration order.
    extensions: Vec<Box<dyn NetworkExtension>>,
    /// Operator events the network applies itself, by [`CoreOp::Network`] index.
    network_ops: Vec<Op>,
    /// Catalog names to components, for devices created by operator events.
    resolver: Option<ComponentResolver<'r, R>>,
    /// How many times each device name has been instantiated (its seeds follow).
    incarnations: std::collections::BTreeMap<String, u32>,
    /// The device table `wasmnet:infra` serves.
    infra: Infra,
    /// The derived request being applied (its creation adopts the pending device).
    applying: Option<usize>,
    /// Each device's component, by index, to start it again after a stop.
    components: std::collections::BTreeMap<usize, <R::Component as ToOwned>::Owned>,
    /// How devices created while the network runs are numbered; fixed at the first creation.
    numbering: Option<Numbering>,
    /// The links created while the network ran (operator events, controllers' cables), with
    /// the tag of the processing context that created each, in creation order.
    created_links: Vec<(usize, Tag)>,
    /// The embedder's actions, by name ([`Network::register_action`]).
    embedder_actions: std::collections::BTreeMap<String, Action<'r>>,
    /// Components compiled from controllers' supplied bytes (or why they could not be), by
    /// digest reference, while some controller's store keeps the bytes.
    supplied: std::collections::BTreeMap<
        String,
        std::result::Result<<R::Component as ToOwned>::Owned, String>,
    >,
    /// How many components were compiled from supplied bytes.
    supplied_compiles: u64,
    /// The extensions' option and op parsers, by key (shared with the device table).
    parsers: Arc<std::sync::Mutex<crate::ext::Parsers>>,
}

/// The size of each creator's range of device numbers: a creator can create this many devices
/// in one run (recreations included).
pub const CREATOR_RANGE: u32 = 1 << 20;

/// How devices created while a network runs are numbered (`docs/design/event-order.md`).
/// Creator `c`'s `n`-th creation gets number `setup + c * CREATOR_RANGE + n`, so a device's
/// number depends only on its creator's own history: the same on every site of a split
/// network and in the unsplit one.
struct Numbering {
    /// The devices the network had when the first device was created while it ran.
    setup: u32,
    /// Creators by rank: the devices granted `infra` among those, in order, then the embedder
    /// (`None`: operator events and devices added with the builder API from then on), then
    /// controllers added later, in the order they first create.
    creators: Vec<Option<String>>,
    /// Each creator's creations so far.
    created: Vec<u32>,
}

impl<'r, R: Runtime + ?Sized> Network<'r, R> {
    /// An empty network with `seed`, the default wall epoch and default [`Guard`]s.
    pub fn new(runtime: &'r R, seed: u64) -> Self {
        Self::with_config(runtime, SimConfig::seeded(seed), Guard::default())
    }

    pub fn with_config(runtime: &'r R, config: SimConfig, guard: Guard) -> Self {
        let clock = VirtualClock::new(config.wall_epoch);
        let journal = Journal::new(clock.clone());
        let panel = Panel::default()
            .with_journal(journal.clone())
            .with_seed(config.seed);
        let infra = Infra::new(clock.clone(), journal.clone());
        let mut network = Self {
            runtime,
            config,
            guard,
            exec: Executor::new(clock.clone(), panel.clone(), guard),
            journal,
            clock,
            panel,
            actions: 0,
            devices: Vec::new(),
            failed: false,
            extensions: Vec::new(),
            network_ops: Vec::new(),
            resolver: None,
            incarnations: std::collections::BTreeMap::new(),
            infra,
            applying: None,
            components: std::collections::BTreeMap::new(),
            numbering: None,
            created_links: Vec::new(),
            embedder_actions: std::collections::BTreeMap::new(),
            supplied: std::collections::BTreeMap::new(),
            supplied_compiles: 0,
            parsers: Arc::default(),
        };
        network.infra.set_parsers(network.parsers.clone());
        runtime.install(&mut network);
        network
    }

    /// Registers a network extension: from now on its hooks run for every device the network
    /// sets up, after those of the extensions registered before it. One extension per type: a
    /// second of the same type replaces the first in its place.
    ///
    /// Embedder surface, unstable (extension points, [`crate::ext`]).
    pub fn add_extension<T: NetworkExtension>(&mut self, extension: T) {
        let id = TypeId::of::<T>();
        match self
            .extensions
            .iter_mut()
            .find(|e| (&***e as &dyn Any).type_id() == id)
        {
            Some(slot) => *slot = Box::new(extension),
            None => self.extensions.push(Box::new(extension)),
        }
        self.refresh_parsers();
    }

    /// [`add_extension`](Self::add_extension) for an extension whose type the caller does not
    /// name (an installer that returns boxed extensions): one per type, the same rules.
    pub fn add_boxed_extension(&mut self, extension: Box<dyn NetworkExtension>) {
        let id = (&*extension as &dyn Any).type_id();
        match self
            .extensions
            .iter_mut()
            .find(|e| (&***e as &dyn Any).type_id() == id)
        {
            Some(slot) => *slot = extension,
            None => self.extensions.push(extension),
        }
        self.refresh_parsers();
    }

    /// The portable interfaces the network's extensions serve, in registration order
    /// ([`NetworkExtension::interfaces`]). A backend links these for its devices.
    pub fn interfaces(&self) -> Vec<crate::ext::Interface> {
        self.extensions
            .iter()
            .flat_map(|e| e.interfaces())
            .collect()
    }

    /// Rebuilds the parsers from the extensions, in registration order: a key two extensions
    /// declare goes to the first.
    fn refresh_parsers(&mut self) {
        let mut parsers = crate::ext::Parsers::default();
        for e in &self.extensions {
            for o in e.options() {
                parsers.options.entry(o.key().to_owned()).or_insert(o);
            }
            for p in e.ops() {
                parsers.ops.entry(p.kind().to_owned()).or_insert(p);
            }
        }
        *self
            .parsers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = parsers;
    }

    /// Parses the extension option `key` from a generic value ([`crate::ext::ExtOption`]): what
    /// a controller's spec, the page's plain objects and an embedder's own formats set.
    pub fn parse_option(
        &self,
        key: &str,
        value: &crate::value::Value,
    ) -> std::result::Result<crate::ext::ExtValue, String> {
        let parsers = self
            .parsers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match parsers.options.get(key) {
            Some(o) => o.parse(value).map_err(|e| format!("option `{key}`: {e}")),
            None => Err(format!("no extension reads an option `{key}`")),
        }
    }

    /// Sets the extension option `key` in `options`, parsed from `value` ([`parse_option`](Self::parse_option)).
    pub fn set_option(
        &self,
        options: &mut DeviceOptions,
        key: &str,
        value: &crate::value::Value,
    ) -> std::result::Result<(), String> {
        options.ext.set_value(self.parse_option(key, value)?);
        Ok(())
    }

    /// The keys of the extension options the network's extensions read, sorted.
    pub fn option_keys(&self) -> Vec<String> {
        let parsers = self
            .parsers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        parsers.options.keys().cloned().collect()
    }

    /// Builds the extension operator event `kind` from a generic value
    /// ([`crate::ext::ExtOpParser`]): what the page's plain objects ask for.
    pub fn parse_op(
        &self,
        kind: &str,
        value: &crate::value::Value,
    ) -> std::result::Result<crate::ext::ExtensionOp, String> {
        let parsers = self
            .parsers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match parsers.ops.get(kind) {
            Some(p) => p
                .parse(value)
                .map_err(|e| format!("operator event `{kind}`: {e}")),
            None => Err(format!("no extension builds an operator event `{kind}`")),
        }
    }

    /// The network's extension of type `T`, if registered.
    pub fn extension<T: NetworkExtension>(&self) -> Option<&T> {
        self.extensions
            .iter()
            .find_map(|e| (&**e as &dyn Any).downcast_ref())
    }

    /// The network's extension of type `T`, mutably.
    pub fn extension_mut<T: NetworkExtension>(&mut self) -> Option<&mut T> {
        self.extensions
            .iter_mut()
            .find_map(|e| (&mut **e as &mut dyn Any).downcast_mut())
    }

    /// Registers what links of cable kind `kind` carry ([`LinkMut::kind`]`(LinkKind::Cable)`).
    /// A kind has one model: registering a second one is refused ([`Error::Refused`], nothing
    /// changes), so two extensions cannot share a code by accident.
    ///
    /// Embedder surface, unstable (extension points, [`crate::ext`]).
    pub fn register_cable(&mut self, kind: CableKind, model: Arc<dyn CableModel>) -> Result<()> {
        if self.panel.register_cable(kind, model) {
            Ok(())
        } else {
            Err(Error::Refused(format!(
                "cable kind {} already has a model ({})",
                kind.code(),
                self.panel.kind_name(LinkKind::Cable(kind))
            )))
        }
    }

    /// The name of a link kind: `ethernet`, or its cable model's name (`cable` for a kind
    /// without one).
    pub fn kind_name(&self, kind: LinkKind) -> &'static str {
        self.panel.kind_name(kind)
    }

    /// Reads a cable's state ([`CableModel::new_link`]) if it is a `T`.
    pub fn with_cable<T: Any, U>(&self, link: LinkId, f: impl FnOnce(&T) -> U) -> Option<U> {
        self.panel.with_cable(link.0, f)
    }

    /// Makes a control call into one of the device's optional exports ([`ControlCall::export`]);
    /// `Ok(false)` (and the call dropped unanswered) if the device does not report it.
    ///
    /// Like [`counters`](Self::counters): it runs at the network's current instant, inside the
    /// device's event loop, between runs; virtual time does not move. A call that
    /// [`may_reschedule`](ControlCall::may_reschedule) is followed by a `poll` of the device at
    /// the same instant (queued, run by the next run), so a stepped device can report a new
    /// deadline. The answer is in the call's own slot.
    ///
    /// Embedder surface, unstable (extension points, [`crate::ext`]).
    pub fn control(&mut self, device: DeviceId, call: Box<dyn ControlCall>) -> Result<bool> {
        if self.failed {
            return Err(Error::Halted);
        }
        let record = &self.devices[device.0];
        if !record.exports.iter().any(|e| e == call.export()) {
            return Ok(false);
        }
        refuse_paused(record)?;
        let answer = call.answer();
        let what = call.name().to_owned();
        record.inbox.push(Command::Control(call));
        let settled = self.exec.settle(u64::from(self.devices[device.0].number));
        self.failed = settled.is_err();
        settled?;
        let out = if answer.answered() {
            Ok(true)
        } else {
            Err(Error::Deadlock {
                at: self.clock.now(),
                outstanding: vec![(record.name.clone(), what)],
            })
        };
        self.settle_crashes();
        out
    }

    /// Runs `command` with `argument` in the device's `wasmnet:control/commands` export
    /// ([`crate::commands`]) and returns its answer: `ok` text or its refusal. `Ok(None)`: the
    /// device takes no commands.
    ///
    /// A control call like [`control`](Self::control): at the network's current instant,
    /// between runs, without moving virtual time; the device's `poll` at this instant follows
    /// in the next run.
    pub fn command(
        &mut self,
        device: DeviceId,
        command: &str,
        argument: &str,
    ) -> Result<Option<std::result::Result<String, String>>> {
        let call = crate::commands::CommandCall::new(crate::commands::DeviceCommand::new(
            command, argument,
        ));
        let answer = call.answer_slot();
        if !self.control(device, Box::new(call))? {
            return Ok(None);
        }
        Ok(answer.get())
    }

    /// The optional exports the device's backend serves control calls for.
    pub fn device_exports(&self, device: DeviceId) -> &[String] {
        &self.devices[device.0].exports
    }

    /// Where records about `device` go in the network journal.
    pub fn journal_end(&self, device: &str) -> JournalEnd {
        JournalEnd {
            journal: self.journal.clone(),
            device: device.to_owned(),
        }
    }

    /// The backend.
    pub fn runtime(&self) -> &'r R {
        self.runtime
    }

    /// The network's virtual clock.
    pub fn clock(&self) -> &VirtualClock {
        &self.clock
    }

    /// Instantiates `component` as a device called `name`, with an empty configuration.
    pub fn device(&mut self, name: &str, component: &R::Component) -> Result<DeviceId> {
        self.device_with_config(name, component, DeviceConfig::new())
    }

    /// Instantiates `component` as a device called `name`, with `config`.
    ///
    /// `name` must be unique: it is the key for the device's RNG seeds, its pcap interface
    /// names and its journal records. `ports()` is called right here, at the network's current
    /// instant, so [`link`](Self::link) can validate port numbers. The rest of the start-up
    /// (`start()` if exported, `link-state` for wired ports, then `poll(now)`) happens when the
    /// network runs.
    pub fn device_with_config(
        &mut self,
        name: &str,
        component: &R::Component,
        config: DeviceConfig,
    ) -> Result<DeviceId> {
        self.device_with_options(name, component, config, DeviceOptions::default())
    }

    /// [`device_with_config`](Self::device_with_config) with per-device [`DeviceOptions`]: its
    /// own fuel budget per instant, stdout/stderr lines in the journal, grants, and the options
    /// of the network's extensions.
    pub fn device_with_options(
        &mut self,
        name: &str,
        component: &R::Component,
        config: DeviceConfig,
        options: DeviceOptions,
    ) -> Result<DeviceId> {
        if self.live_device(name).is_some() {
            return Err(Error::DuplicateDevice(name.to_owned()));
        }
        self.check_grant(name, &options, false)
            .map_err(Error::Refused)?;
        self.check_extensions(name, &options)
            .map_err(Error::Refused)?;
        let idx = self.devices.len();
        let (rank, number) = self.builder_number().map_err(Error::Refused)?;
        // Everything queued while creating the device is in the setup slot of its number (its
        // index, unless devices were created while the network ran).
        self.clock.set_setup(u64::from(number), number);
        let (context, handles) = self.context(
            idx,
            name,
            config.clone(),
            options.clone(),
            None,
            SetupOrigin::Created,
        );
        let instance = self.runtime.instantiate(context, component)?;
        let crash_alone = options.crash_alone;
        self.register(idx, number, name, config, options, instance, handles, false)?;
        self.exec.set_contain(idx, crash_alone);
        if let Some(rank) = rank {
            self.take_number(rank);
        }
        self.components.insert(idx, component.to_owned());
        self.infra_added(idx, None);
        Ok(DeviceId(idx))
    }

    /// The number of a device added with the builder API: its index, or once devices were
    /// created while the network ran, the embedder's next number (with its rank, to
    /// [`take_number`](Self::take_number) once the device exists).
    fn builder_number(&mut self) -> std::result::Result<(Option<usize>, u32), String> {
        if self.numbering.is_none() {
            let number = u32::try_from(self.devices.len())
                .ok()
                .filter(|&n| n < HOST_DEVICE)
                .ok_or_else(|| "too many devices".to_owned())?;
            return Ok((None, number));
        }
        let (rank, number) = self.peek_number(None)?;
        Ok((Some(rank), number))
    }

    /// Creator `rank` created the device [`peek_number`](Self::peek_number) numbered.
    fn take_number(&mut self, rank: usize) {
        if let Some(n) = self.numbering.as_mut() {
            n.created[rank] += 1;
        }
    }

    /// The rank of `creator` (`None`: the embedder) and the number of the next device it
    /// creates while the network runs; [`take_number`](Self::take_number) once it exists (a
    /// creation that fails takes none). The first call fixes the numbering: the devices so
    /// far are the setup devices, and the creators are the ones granted `infra` among them,
    /// then the embedder.
    fn peek_number(&mut self, creator: Option<&str>) -> std::result::Result<(usize, u32), String> {
        let devices = &self.devices;
        let numbering = self.numbering.get_or_insert_with(|| {
            let mut creators: Vec<Option<String>> = devices
                .iter()
                .filter(|d| d.options.infra)
                .map(|d| Some(d.name.clone()))
                .collect();
            creators.push(None);
            Numbering {
                setup: u32::try_from(devices.len()).unwrap_or(u32::MAX),
                created: vec![0; creators.len()],
                creators,
            }
        });
        let rank = match numbering
            .creators
            .iter()
            .position(|c| c.as_deref() == creator)
        {
            Some(rank) => rank,
            None => {
                numbering.creators.push(creator.map(str::to_owned));
                numbering.created.push(0);
                numbering.creators.len() - 1
            }
        };
        let n = numbering.created[rank];
        let who = creator.map_or("the embedder".to_owned(), |c| format!("`{c}`"));
        if n >= CREATOR_RANGE {
            return Err(format!(
                "{who} has created {CREATOR_RANGE} devices in this run: it has no device \
                 numbers left"
            ));
        }
        let number =
            u64::from(numbering.setup) + rank as u64 * u64::from(CREATOR_RANGE) + u64::from(n);
        let number = u32::try_from(number)
            .ok()
            .filter(|&n| n < HOST_DEVICE)
            .ok_or_else(|| format!("{who} has no device numbers left (too many creators)"))?;
        Ok((rank, number))
    }

    /// Refuses `options` for a new device `name` (on another site with `remote`) when its
    /// `infra_prefix` is malformed, given without `infra`, or overlaps another controller's;
    /// and a controller that puts controllers on more than one site of a split network while
    /// one of them has no prefix.
    /// The network's extensions' checks of a new device's options
    /// ([`NetworkExtension::check_options`]), in registration order.
    fn check_extensions(
        &self,
        name: &str,
        options: &DeviceOptions,
    ) -> std::result::Result<(), String> {
        for e in &self.extensions {
            e.check_options(name, options)
                .map_err(|why| format!("`{name}`: {why}"))?;
        }
        Ok(())
    }

    fn check_grant(
        &self,
        name: &str,
        options: &DeviceOptions,
        remote: bool,
    ) -> std::result::Result<(), String> {
        if !options.infra && options.infra_supply.is_some() {
            return Err(format!("`{name}`: `infra_supply` needs `infra`"));
        }
        if !options.infra {
            return match options.infra_prefix {
                Some(_) => Err(format!("`{name}`: `infra_prefix` needs `infra`")),
                None => Ok(()),
            };
        }
        let controllers = || {
            self.devices
                .iter()
                .filter(|d| d.options.infra && d.phase != DevicePhase::Removed)
        };
        if let Some(prefix) = &options.infra_prefix {
            if !crate::infra::valid_name(prefix) {
                return Err(format!(
                    "`{name}`: infra prefix `{prefix}`: 1-63 letters, digits, `-` or `_`"
                ));
            }
            if let Some((d, other)) = controllers().find_map(|d| {
                let other = d.options.infra_prefix.as_deref()?;
                (prefix.starts_with(other) || other.starts_with(prefix.as_str()))
                    .then_some((d, other))
            }) {
                return Err(format!(
                    "`{name}`: infra prefix `{prefix}` overlaps `{}`'s `{other}`",
                    d.name
                ));
            }
        }
        let (mut local, mut far) = (!remote, remote);
        let mut unprefixed = options.infra_prefix.is_none();
        for d in controllers() {
            if d.remote {
                far = true;
            } else {
                local = true;
            }
            unprefixed |= d.options.infra_prefix.is_none();
        }
        if local && far && unprefixed {
            return Err(format!(
                "`{name}`: controllers on more than one site of a split network each need an \
                 `infra_prefix`, so that the names of the devices they create cannot collide"
            ));
        }
        Ok(())
    }

    /// Tells the device table that device `idx` was created (by derived request `request`).
    fn infra_added(&self, idx: usize, request: Option<usize>) {
        let d = &self.devices[idx];
        let spec = crate::infra::spec_value(
            d.component.as_deref().unwrap_or_default(),
            &d.config,
            d.options.clone(),
            None,
        );
        self.infra.added(&d.name, spec, self.clock.now(), request);
    }

    /// The components in-world controllers may create, by catalog name (the names the
    /// [`set_component_resolver`](Self::set_component_resolver) resolves). Without a call: any
    /// component the resolver knows.
    pub fn set_infra_catalog(&mut self, components: Vec<String>) {
        self.infra.set_catalog(components);
    }

    /// Decides which components controllers granted [`DeviceOptions::infra_supply`] may supply
    /// (`docs/design/topology-and-infra.md`): `admit` sees each one's bytes, digest and
    /// controller before anything keeps, compiles or instantiates it, and answers `Ok` to keep
    /// it or `Err(reason)` to refuse it (the controller's `denied(reason)`). It is called at
    /// the controller's `supply` call, again at the same position on every rerun, so its
    /// verdict must depend only on what it is given. Without one, every supply is refused. A
    /// second call replaces the first.
    pub fn set_supply_admission(
        &mut self,
        admit: impl Fn(&crate::supply::Supplied<'_>) -> std::result::Result<(), String>
        + Send
        + Sync
        + 'static,
    ) {
        self.infra.set_admission(Arc::new(admit));
    }

    /// How many components this network compiled from controllers' supplied bytes so far: one
    /// per digest while its bytes are kept, however many devices are made from it
    /// ([`Runtime::compile_supplied`]).
    pub fn supplied_compiles(&self) -> u64 {
        self.supplied_compiles
    }

    /// The device table `wasmnet:infra` serves: every device by name, with its
    /// changes; tools read it like a controller does.
    pub fn infra(&self) -> &Infra {
        &self.infra
    }

    /// The handles of device `idx` (with `captures`: a restarted device keeps its stdout and
    /// stderr). The network's extensions set up their handles first, in registration order.
    fn context(
        &mut self,
        idx: usize,
        name: &str,
        config: DeviceConfig,
        options: DeviceOptions,
        captures: Option<(OutputCapture, OutputCapture)>,
        origin: SetupOrigin,
    ) -> (DeviceContext, Handles) {
        let journal = JournalEnd {
            journal: self.journal.clone(),
            device: name.to_owned(),
        };
        let mut ext = DeviceExt::default();
        let setup = DeviceSetup {
            index: idx,
            name,
            origin,
            options: &options,
            clock: &self.clock,
            journal: &journal,
            seed: self.config.seed,
        };
        for e in &mut self.extensions {
            e.device_setup(&setup, &mut ext);
        }
        let pipe = |stream| {
            if options.journal_stdio {
                OutputCapture::journalled(journal.clone(), self.clock.clone(), stream)
            } else {
                OutputCapture::new()
            }
        };
        let (stdout, stderr) =
            captures.unwrap_or_else(|| (pipe(Stream::Stdout), pipe(Stream::Stderr)));
        let (inbox, status) = (Inbox::default(), Status::default());
        let context = DeviceContext {
            index: idx,
            name: name.to_owned(),
            // A device instantiated again under a name (restarted, or re-added) draws fresh
            // numbers, as a rebooted host would: its seed follows its incarnation.
            seed: match self.incarnations.get(name).copied().unwrap_or(0) {
                0 => self.config.seed,
                n => crate::derive_seed(self.config.seed, name, &format!("incarnation-{n}")),
            },
            clock: self.clock.clone(),
            wire: Wire {
                device: idx,
                panel: self.panel.clone(),
                clock: self.clock.clone(),
            },
            journal,
            config,
            args: options.args.clone(),
            env: options.env.clone(),
            memory: options.memory,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            inbox: inbox.clone(),
            status: status.clone(),
            fuel_per_instant: options
                .fuel_per_instant
                .unwrap_or(self.guard.fuel_per_instant),
            infra: options.infra.then(|| {
                self.infra.end(
                    name,
                    idx,
                    options.infra_prefix.clone(),
                    options.infra_max_devices,
                    options.infra_supply,
                )
            }),
            ext,
        };
        let handles = Handles {
            inbox,
            status,
            stdout,
            stderr,
        };
        (context, handles)
    }

    /// Registers a freshly instantiated device as device `idx` with `number`: a new one (the
    /// next index), or with `restart` the stopped device `idx` started again (its ports must
    /// not change; it keeps its number).
    #[allow(clippy::too_many_arguments)]
    fn register(
        &mut self,
        idx: usize,
        number: u32,
        name: &str,
        config: DeviceConfig,
        options: DeviceOptions,
        instance: DeviceInstance,
        h: Handles,
        restart: bool,
    ) -> Result<()> {
        let ports = check_ports(name, instance.ports)?;
        *self.incarnations.entry(name.to_owned()).or_default() += 1;
        if restart {
            if !self.panel.device_ports_match(idx, &ports) {
                return Err(Error::Refused(format!(
                    "`{name}` declared other ports when started again"
                )));
            }
            self.exec
                .restart_actor(idx, h.inbox.clone(), h.status, instance.actor);
            let d = &mut self.devices[idx];
            d.inbox = h.inbox;
            d.has_counters = instance.has_counters;
            d.exports = instance.exports;
            d.apps = instance.apps;
            d.phase = DevicePhase::Running;
        } else {
            self.exec
                .add(name, number, h.inbox.clone(), h.status, instance.actor);
            let registered = self.panel.add_device(name, ports, false);
            debug_assert_eq!(registered, idx);
            self.devices.push(DeviceRecord {
                name: name.to_owned(),
                number,
                created: None,
                inbox: h.inbox,
                has_counters: instance.has_counters,
                exports: instance.exports,
                apps: instance.apps,
                stdout: h.stdout,
                stderr: h.stderr,
                remote: false,
                component: None,
                config,
                options,
                phase: DevicePhase::Running,
                downed: Vec::new(),
                paused_down: false,
            });
        }
        // The first poll, at the device's first instant (after its link-state calls).
        self.clock.set_poll(idx, Some(self.clock.now()));
        Ok(())
    }

    /// The device called `name` that is not removed (the latest, if a name was reused).
    pub fn live_device(&self, name: &str) -> Option<DeviceId> {
        self.devices
            .iter()
            .rposition(|d| d.name == name && d.phase != DevicePhase::Removed)
            .map(DeviceId)
    }

    /// The device's number in event keys and record tags (`docs/design/event-order.md`): its
    /// index for a device the network was built with; for one created while the network ran,
    /// its creator's next number (`setup + rank * CREATOR_RANGE + n`), which equals its index
    /// while only one creator creates.
    pub fn device_number(&self, device: DeviceId) -> u32 {
        self.devices[device.0].number
    }

    /// Whether the device runs, is stopped, or was removed.
    pub fn device_phase(&self, device: DeviceId) -> DevicePhase {
        self.devices[device.0].phase
    }

    /// The catalog name of the device's component, if the network knows it
    /// ([`set_device_component`](Self::set_device_component), or a dynamic device).
    pub fn device_component(&self, device: DeviceId) -> Option<&str> {
        self.devices[device.0].component.as_deref()
    }

    /// The device's config and options, as created.
    pub fn device_spec(&self, device: DeviceId) -> (&DeviceConfig, DeviceOptions) {
        let d = &self.devices[device.0];
        (&d.config, d.options.clone())
    }

    /// Records the catalog name of a device's component, so an operator event can start it
    /// again after a stop.
    pub fn set_device_component(&mut self, device: DeviceId, component: &str) {
        let d = &mut self.devices[device.0];
        d.component = Some(component.to_owned());
        let spec = crate::infra::spec_value(component, &d.config, d.options.clone(), None);
        self.infra.respec(&d.name, spec);
    }

    /// Installs how the network turns a catalog name (`node:dhcp-dns`, `switch`) into a
    /// component for devices created by operator events (`docs/design/topology-and-infra.md`):
    /// `resolve(name, instantiate)` finds the component and calls `instantiate` with it. Without
    /// one, such ops are refused.
    ///
    /// Embedder surface, unstable (operator events).
    pub fn set_component_resolver(&mut self, resolve: ComponentResolver<'r, R>) {
        self.resolver = Some(resolve);
    }

    /// Wires two ports with a point-to-point link (latency 0 until set with
    /// [`LinkMut::latency`]). Both ports must be declared by their device's `ports()`, and each
    /// port can be on one link only. The link starts up: both devices get `link-state(up)`.
    pub fn link(&mut self, a: PortRef, b: PortRef) -> Result<LinkMut<'_>> {
        let id = self.connect(a, b)?;
        Ok(LinkMut {
            panel: &self.panel,
            id,
        })
    }

    /// Wires `a` to `b`, up: both running ends get `link-state(up)`. A stopped end keeps the
    /// link down until it starts again.
    fn connect(&mut self, a: PortRef, b: PortRef) -> Result<LinkId> {
        let (ea, eb) = ((a.device.0, a.port), (b.device.0, b.port));
        let id = self
            .panel
            .connect(ea, eb, 0, self.clock.now())
            .map_err(|e| match e {
                ConnectError::InUse(d, port) => Error::PortInUse {
                    device: self.devices[d].name.clone(),
                    port,
                },
                ConnectError::Unknown(d, port) => Error::UnknownPort {
                    device: self.devices[d].name.clone(),
                    port,
                    declared: self.panel.ports(d).iter().map(|p| p.id).collect(),
                },
            })?;
        // An end without power keeps the link down: a stopped device, or one paused with its
        // links down (its resume brings the link up). A paused device that keeps its carrier
        // hears the new link when it resumes.
        let stopped = [ea, eb].into_iter().find(|&(d, _)| {
            let r = &self.devices[d];
            match r.phase {
                DevicePhase::Running => false,
                DevicePhase::Paused => r.paused_down,
                DevicePhase::Stopped | DevicePhase::Removed => true,
            }
        });
        match stopped {
            None => {
                for (device, port) in [ea, eb] {
                    self.devices[device]
                        .inbox
                        .push(Command::LinkState { port, up: true });
                }
            }
            Some((d, _)) => {
                let at = self.clock.now();
                self.carrier(id, at, false);
                self.devices[d].downed.push(id);
            }
        }
        self.exec.touched();
        Ok(LinkId(id))
    }

    /// Takes `link` down (`up = false`) or brings it back up at virtual time `at` (clamped to
    /// now). Both ends get `link-state` at that instant if the state actually changes. While a
    /// link is down, frames transmitted into it are dropped, and frames already in flight on it
    /// are lost. Several changes can be scheduled; same-instant ones apply in call order.
    pub fn schedule_link_state(&mut self, link: LinkId, at: Nanos, up: bool) {
        self.next_action_slot();
        self.clock.schedule_link_state(at, link.0, up);
    }

    /// Runs until the network is quiescent (nothing queued, no host call outstanding).
    ///
    /// A device that keeps scheduling work forever never quiesces; bound such networks with
    /// [`run_until`](Self::run_until).
    pub fn run_until_quiescent(&mut self) -> Result<Outcome> {
        self.run(None)
    }

    /// Runs every event at or before `deadline`. Returns [`Outcome::Deadline`] (with the clock at
    /// `deadline`) if work remains after it, or [`Outcome::Quiescent`] if the network went idle
    /// first. Runs can be chained: stopping at a deadline and resuming gives the same result as
    /// one run.
    pub fn run_until(&mut self, deadline: Nanos) -> Result<Outcome> {
        self.run(Some(deadline))
    }

    fn run(&mut self, until: Option<Nanos>) -> Result<Outcome> {
        if self.failed {
            return Err(Error::Halted);
        }
        let outcome = self.drive(|e| e.run(until));
        self.failed = outcome.is_err();
        outcome
    }

    /// Runs the executor, applying the operator events it returns at and going on.
    fn drive<T>(&mut self, mut f: impl FnMut(&mut Executor) -> Result<Flow<T>>) -> Result<T> {
        loop {
            match f(&mut self.exec)? {
                Flow::Done(t) => return Ok(t),
                Flow::Network { op, network } => {
                    let at = self.clock.now();
                    let change = self.network_ops[network].clone();
                    let applied = match change {
                        // A crash may fail the whole network: the one rule decides.
                        Op::CrashDevice { device, message } => {
                            self.crash_device(&device, message, at)?
                        }
                        change => self.apply_change(Some(op), change, at),
                    };
                    if let Err(message) = applied {
                        self.exec.fail_op(op, message);
                    }
                    self.prune_supplied();
                }
                Flow::Derived(n) => {
                    let at = self.clock.now();
                    self.apply_derived(n, at)?;
                    self.prune_supplied();
                }
                Flow::Crashed(i, message) => {
                    let at = self.clock.now();
                    self.crash(i, message, at);
                }
            }
        }
    }

    /// Device `idx` trapped, and its trap was contained (a device a controller created): it
    /// is stopped as crashed (its links go down, the far ends see it), journalled
    /// as `device-crashed {message}`, and the network goes on.
    fn crash(&mut self, idx: usize, message: String, at: Nanos) {
        if !matches!(
            self.devices[idx].phase,
            DevicePhase::Running | DevicePhase::Paused
        ) {
            return;
        }
        self.stop_device(idx, at);
        let name = self.devices[idx].name.clone();
        let message = self.runtime.summarize(&message);
        self.infra.crashed(&name, &message, at);
        self.journal_event(
            &name,
            at,
            "device-crashed",
            vec![("message", message.clone())],
        );
        self.life(idx, at, LifeEvent::Crashed { message: &message });
    }

    /// [`Op::CrashDevice`]: the device faults at the op's position, as if its guest trapped
    /// there, and the one rule decides: a contained device crashes alone ([`crash`](Self::crash),
    /// before the op's rounds, so the far ends see the carrier drop in them); any other fails
    /// the network ([`Error::Trap`]). The inner `Err` is the op's refusal (no such device, or
    /// not running or paused).
    fn crash_device(
        &mut self,
        device: &str,
        message: String,
        at: Nanos,
    ) -> Result<std::result::Result<(), String>> {
        let Some(id) = self.live_device(device) else {
            return Ok(Err(format!("no device `{device}`")));
        };
        if !matches!(
            self.devices[id.0].phase,
            DevicePhase::Running | DevicePhase::Paused
        ) {
            return Ok(Err(format!("`{device}` is not running")));
        }
        if self.exec.fault(id.0, crate::Fault::new(message.clone()))? {
            self.crash(id.0, message, at);
        }
        Ok(Ok(()))
    }

    /// Tells the network's extensions about device `idx`'s life (after its journal record).
    fn life(&mut self, idx: usize, at: Nanos, event: LifeEvent<'_>) {
        if self.extensions.is_empty() {
            return;
        }
        let name = self.devices[idx].name.clone();
        let journal = self.journal_end(&name);
        let life = DeviceLife {
            index: idx,
            name: &name,
            at,
            event,
            journal: &journal,
            replaced: self.infra.is_recreating(&name),
        };
        for e in &mut self.extensions {
            e.device_life(&life);
        }
    }

    /// Applies the contained traps a control call's settle met.
    fn settle_crashes(&mut self) {
        let at = self.clock.now();
        for (i, message) in self.exec.take_crashed() {
            self.crash(i, message, at);
        }
    }

    /// Applies derived request `n` of an in-world controller (`wasmnet:infra`), in the event's
    /// own processing context, like an operator event. A refusal is journalled on
    /// the controller (`infra-failed`) and shown on the device, never the network's failure.
    ///
    /// In a split network a creation whose cable reaches a device on another site fails the
    /// run instead ([`Error::Refused`]): the unsplit network would have wired it, so no answer
    /// on this site could match. It fails at this event, so at the same instant and with the
    /// same message on every rerun.
    fn apply_derived(&mut self, n: usize, at: Nanos) -> Result<()> {
        let Some(req) = self.infra.request(n) else {
            return Ok(());
        };
        // The device it was asked for may have been removed (or replaced) meanwhile.
        let current = self.infra.get(&req.name).ok().map(|d| d.uid);
        // A controller whose devices go with it: what it asked before it stopped is void.
        let caller_gone = self
            .devices
            .iter()
            .rfind(|d| d.name == req.caller)
            .is_some_and(|d| {
                d.options.infra_cascade != Cascade::Keep
                    && !matches!(d.phase, DevicePhase::Running | DevicePhase::Paused)
            });
        let result = if caller_gone {
            Err(format!(
                "`{}` stopped before this request applied",
                req.caller
            ))
        } else if current.as_deref() == Some(req.uid.as_str()) {
            if let Some(far) = self.cable_to_another_site(&req) {
                return Err(Error::Refused(format!(
                    "`{}` asked for a cable from `{}` to `{far}`, which runs on another site: \
                     a controller's devices and cables stay on its own site",
                    req.caller, req.name
                )));
            }
            self.apply_request(n, &req, at)
        } else {
            Err(format!(
                "`{}` was removed or replaced before this request applied",
                req.name
            ))
        };
        let error = result.err().map(|e| self.runtime.summarize(&e));
        self.infra.applied(n, error, at);
        Ok(())
    }

    /// The far device of a cable in creation or `wire` `req` that is a placeholder: a device
    /// the network was built with that runs on another site. (A name another site's controller
    /// may create is refused by the rule of cables, [`cables`](Self::cables), the same split
    /// or not.)
    fn cable_to_another_site(&self, req: &crate::infra::Request) -> Option<String> {
        use crate::infra::Verb;
        let wire = match &req.verb {
            Verb::Create(spec) | Verb::Recreate(spec) | Verb::Reconfigure { spec, .. } => {
                spec.wire.as_slice()
            }
            Verb::Wire(c) => std::slice::from_ref(c),
            _ => return None,
        };
        wire.iter()
            .find(|c| {
                self.live_device(&c.device)
                    .is_some_and(|d| self.devices[d.0].remote)
            })
            .map(|c| c.device.clone())
    }

    /// The controller other than `caller` whose devices `name` would be: the owner of a device
    /// in the table, or for a name not in it, the controller whose `infra_prefix` it starts with.
    fn other_owner(&self, caller: &str, name: &str) -> Option<String> {
        let owner = match self.infra.get(name) {
            Ok(view) => view.owner,
            Err(_) => self
                .devices
                .iter()
                .find(|d| {
                    d.options.infra
                        && d.phase != DevicePhase::Removed
                        && d.options
                            .infra_prefix
                            .as_deref()
                            .is_some_and(|p| name.starts_with(p))
                })
                .map(|d| d.name.clone()),
        };
        owner.filter(|o| o != caller)
    }

    fn apply_request(
        &mut self,
        n: usize,
        req: &crate::infra::Request,
        at: Nanos,
    ) -> std::result::Result<(), String> {
        use crate::infra::Verb;
        let name = req.name.clone();
        let phase = self.live_device(&name).map(|d| self.devices[d.0].phase);
        let reconfigurable = self.live_device(&name).is_some_and(|d| {
            phase == Some(DevicePhase::Running)
                && self.devices[d.0]
                    .exports
                    .iter()
                    .any(|e| e == crate::RECONFIGURE_EXPORT)
        });
        match &req.verb {
            // Only the config changed, and the device takes configs in place: ask it. Its
            // answer decides (`Infra::reconfigured`): a follow-up request records the config or
            // recreates the device.
            Verb::Reconfigure { spec, .. } if reconfigurable => {
                let id = self.live_device(&name).expect("running");
                let call =
                    crate::ReconfigureCall::derived(spec.config.clone(), self.infra.clone(), n);
                OpTarget::control(self, None, id, Box::new(call));
                Ok(())
            }
            Verb::Configured(spec) => {
                if let Some(id) = self.live_device(&name) {
                    self.devices[id.0].config = spec.config.clone();
                }
                self.infra.configured(&name);
                self.journal_event(&name, at, "device-reconfigured", Vec::new());
                Ok(())
            }
            Verb::Create(spec) | Verb::Recreate(spec) | Verb::Reconfigure { spec, .. } => {
                if !matches!(req.verb, Verb::Create(_)) && phase.is_some() {
                    self.infra.set_recreating(&name, true);
                    let removed = self.apply_change(
                        None,
                        Op::RemoveDevice {
                            device: name.clone(),
                        },
                        at,
                    );
                    if let Err(e) = removed {
                        self.infra.set_recreating(&name, false);
                        return Err(e);
                    }
                }
                let wire = self.cables(&req.caller, &spec.wire)?;
                self.applying = Some(n);
                let added = self.apply_change(
                    None,
                    Op::AddDevice {
                        name,
                        component: spec.component.clone(),
                        config: spec.config.clone(),
                        options: spec.options.clone(),
                        wire,
                    },
                    at,
                );
                self.applying = None;
                added
            }
            Verb::Start if phase == Some(DevicePhase::Stopped) => {
                self.apply_change(None, Op::StartDevice { device: name }, at)
            }
            Verb::Stop if matches!(phase, Some(DevicePhase::Running | DevicePhase::Paused)) => {
                self.apply_change(None, Op::StopDevice { device: name }, at)
            }
            Verb::Remove if phase.is_some() => {
                self.apply_change(None, Op::RemoveDevice { device: name }, at)
            }
            // Served in this event's rounds; the device's refusal reaches the table from its
            // answer (`CommandCall::finish`).
            Verb::Control(command) => {
                if phase == Some(DevicePhase::Paused) {
                    return Err(format!("`{name}` is paused"));
                }
                let id = self
                    .live_device(&name)
                    .filter(|_| phase == Some(DevicePhase::Running))
                    .ok_or_else(|| format!("`{name}` is not running"))?;
                self.require_export(id, crate::commands::COMMANDS_EXPORT)
                    .map_err(|e| e.to_string())?;
                let call =
                    crate::commands::CommandCall::derived(command.clone(), self.infra.clone(), n);
                OpTarget::control(self, None, id, Box::new(call));
                Ok(())
            }
            Verb::Wire(c) => {
                let id = self
                    .live_device(&name)
                    .ok_or_else(|| format!("no device `{name}`"))?;
                let cable = self.cables(&req.caller, std::slice::from_ref(c))?.remove(0);
                let far = self
                    .live_device(&cable.to_device)
                    .ok_or_else(|| format!("wire: no device `{}`", cable.to_device))?;
                let tag = self.clock.peek_tag();
                let link = self
                    .connect(id.port(cable.port), far.port(cable.to_port))
                    .map_err(|e| e.to_string())?;
                self.created_links.push((link.0, tag));
                self.link_options(link.0, cable.latency, cable.mtu, cable.impairments);
                let l = self.panel.link_info(link.0).name;
                self.journal_event(&name, at, "link-added", vec![("link", l)]);
                Ok(())
            }
            Verb::Unwire(port) => {
                let id = self
                    .live_device(&name)
                    .ok_or_else(|| format!("no device `{name}`"))?;
                let link = self
                    .panel
                    .links_of(id.0)
                    .into_iter()
                    .find(|&l| {
                        self.panel
                            .link_info(l)
                            .ends
                            .iter()
                            .any(|e| e.device == id && e.port == *port)
                    })
                    .ok_or_else(|| format!("unwire: no cable at `{name}:{port}`"))?;
                let info = self.panel.link_info(link);
                let far = info.ends.iter().find(|e| e.device != id || e.port != *port);
                if let Some(owner) =
                    far.and_then(|e| self.infra.owner_of(&self.devices[e.device.0].name))
                    && owner != req.caller
                {
                    return Err(format!(
                        "unwire: the cable at `{name}:{port}` leads to a device of `{owner}`"
                    ));
                }
                self.unwire(link, at);
                self.journal_event(&name, at, "link-removed", vec![("link", info.name)]);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// A controller's cables (of a creation, or `wire`), far ports resolved: a cable to a
    /// device without a port takes its first free declared port (in order; none twice in one
    /// request). The one rule for a controller's cables: the far end is a device `caller`
    /// created or one of the network's own, never another controller's.
    fn cables(
        &self,
        caller: &str,
        wire: &[crate::infra::CableReq],
    ) -> std::result::Result<Vec<Cable>, String> {
        let mut taken: Vec<(usize, u32)> = Vec::new();
        let mut out = Vec::new();
        for c in wire {
            // The rule first, so a name another site's controller owns is refused the same way
            // on this site, where it does not exist, as in the unsplit network, where it does.
            if let Some(owner) = self.other_owner(caller, &c.device) {
                return Err(format!(
                    "wire: `{}` belongs to `{owner}`: a controller's cables go to its own \
                     devices and the network's",
                    c.device
                ));
            }
            let d = self
                .live_device(&c.device)
                .ok_or_else(|| format!("wire: no device `{}`", c.device))?;
            let far = match c.far {
                Some(p) => p,
                None => {
                    let used: Vec<u32> = self
                        .panel
                        .links_of(d.0)
                        .into_iter()
                        .flat_map(|l| self.panel.link_info(l).ends)
                        .filter(|e| e.device == d)
                        .map(|e| e.port)
                        .collect();
                    self.panel
                        .ports(d.0)
                        .iter()
                        .map(|p| p.id)
                        .find(|p| !used.contains(p) && !taken.contains(&(d.0, *p)))
                        .ok_or_else(|| format!("wire: `{}` has no free port", c.device))?
                }
            };
            taken.push((d.0, far));
            out.push(Cable {
                port: c.port,
                to_device: c.device.clone(),
                to_port: far,
                latency: c.latency,
                mtu: c.mtu,
                impairments: c.impair,
            });
        }
        Ok(out)
    }

    /// A new link's latency, MTU (if given) and impairments by sending end (if given), before
    /// any frame crosses it.
    fn link_options(
        &mut self,
        link: usize,
        latency: Nanos,
        mtu: Option<u32>,
        impairments: Option<[Impairments; 2]>,
    ) {
        self.panel.set_latency(link, latency);
        if let Some(mtu) = mtu {
            self.panel.set_mtu(link, mtu);
        }
        if let Some(imp) = impairments {
            for (end, i) in imp.into_iter().enumerate() {
                self.panel.set_impairments(link, Some(end), i);
            }
        }
    }

    /// Applies a topology change or name-resolved write (the [`Op`] of operator event `op`, or
    /// a derived request's with `op = None`) in the event's own processing context: what it
    /// queues is keyed by this event, exactly as on every replay. A refusal is the op's state
    /// ([`OpState::Failed`]), never the network's.
    fn apply_change(
        &mut self,
        op: Option<usize>,
        change: Op,
        at: Nanos,
    ) -> std::result::Result<(), String> {
        let running = |l: &Self, name: &str| -> std::result::Result<DeviceId, String> {
            let id = l
                .live_device(name)
                .ok_or_else(|| format!("no device `{name}`"))?;
            match l.devices[id.0].phase {
                DevicePhase::Running => Ok(id),
                DevicePhase::Paused => Err(format!("`{name}` is paused")),
                _ => Err(format!("`{name}` is not running")),
            }
        };
        // Running or paused: it has a store.
        let alive = |l: &Self, name: &str| -> std::result::Result<DeviceId, String> {
            let id = l
                .live_device(name)
                .ok_or_else(|| format!("no device `{name}`"))?;
            match l.devices[id.0].phase {
                DevicePhase::Running | DevicePhase::Paused => Ok(id),
                _ => Err(format!("`{name}` is not running")),
            }
        };
        match change {
            Op::AddDevice {
                name,
                component,
                config,
                options,
                wire,
            } => {
                if self.live_device(&name).is_some() {
                    return Err(format!("a device `{name}` exists"));
                }
                self.check_grant(&name, &options, false)?;
                self.check_extensions(&name, &options)?;
                // The far ends must exist before anything is created.
                let mut ends = Vec::new();
                for c in &wire {
                    let d = self
                        .live_device(&c.to_device)
                        .ok_or_else(|| format!("wire: no device `{}`", c.to_device))?;
                    ends.push((c.port, d.port(c.to_port), c.latency, c.mtu, c.impairments));
                }
                // Its creator: the controller whose request this is, or the embedder.
                let creator = self
                    .applying
                    .and_then(|n| self.infra.request(n))
                    .map(|r| r.caller);
                let (rank, number) = self.peek_number(creator.as_deref())?;
                let created = self.clock.peek_tag();
                let idx = self.devices.len();
                let (context, handles) = self.context(
                    idx,
                    &name,
                    config.clone(),
                    options.clone(),
                    None,
                    SetupOrigin::Added,
                );
                let (instance, resolved) = if crate::supply::is_reference(&component) {
                    self.supplied_instantiate(&component, context)?
                } else {
                    self.resolve_instantiate(&component, context)?
                };
                self.register(
                    idx, number, &name, config, options, instance, handles, false,
                )
                .map_err(|e| e.to_string())?;
                self.take_number(rank);
                self.components.insert(idx, resolved);
                self.devices[idx].created = Some(created);
                self.devices[idx].component = Some(component.clone());
                self.infra_added(idx, self.applying);
                // A controller's device crashes alone, and so does one whose options say so: a
                // trap stops it, not the network.
                let crash_alone = self.applying.is_some() || self.devices[idx].options.crash_alone;
                self.exec.set_contain(idx, crash_alone);
                self.journal_event(&name, at, "device-added", vec![("component", component)]);
                // Its cables, before it first runs (this op's rounds come after).
                for (port, far, latency, mtu, impairments) in ends {
                    let tag = self.clock.peek_tag();
                    let link = self
                        .connect(DeviceId(idx).port(port), far)
                        .map_err(|e| format!("`{name}` was added, but: {e}"))?;
                    self.created_links.push((link.0, tag));
                    self.link_options(link.0, latency, mtu, impairments);
                    let l = self.panel.link_info(link.0).name;
                    self.journal_event(&name, at, "link-added", vec![("link", l)]);
                }
            }
            Op::StopDevice { device } => {
                let id = alive(self, &device)?;
                self.stop_device(id.0, at);
                self.infra.set_phase(&device, Phase::Stopped, at);
                self.journal_event(&device, at, "device-stopped", Vec::new());
                self.life(id.0, at, LifeEvent::Stopped);
                self.cascade(id.0, at);
            }
            Op::PauseDevice { device, link_down } => {
                let id = running(self, &device)?;
                let idx = id.0;
                self.exec.pause_actor(idx);
                self.devices[idx].phase = DevicePhase::Paused;
                self.devices[idx].paused_down = link_down;
                if link_down {
                    for l in self.panel.links_of(idx) {
                        if self.carrier(l, at, false) {
                            self.devices[idx].downed.push(l);
                        }
                    }
                }
                let carrier = if link_down { "down" } else { "up" };
                self.journal_event(
                    &device,
                    at,
                    "device-paused",
                    vec![("carrier", carrier.to_owned())],
                );
                self.life(idx, at, LifeEvent::Paused);
            }
            Op::ResumeDevice { device } => {
                let id = self
                    .live_device(&device)
                    .ok_or_else(|| format!("no device `{device}`"))?;
                let idx = id.0;
                if self.devices[idx].phase != DevicePhase::Paused {
                    return Err(format!("`{device}` is not paused"));
                }
                self.devices[idx].phase = DevicePhase::Running;
                self.devices[idx].paused_down = false;
                let (overdue, dropped) = self.exec.resume_actor(idx);
                for l in std::mem::take(&mut self.devices[idx].downed) {
                    self.carrier(l, at, true);
                }
                self.journal_event(
                    &device,
                    at,
                    "device-resumed",
                    vec![
                        ("overdue", overdue.to_string()),
                        ("dropped", dropped.to_string()),
                    ],
                );
                self.life(idx, at, LifeEvent::Resumed);
            }
            Op::Action {
                name,
                device,
                argument,
            } => {
                if self.live_device(&device).is_none() {
                    return Err(format!("no device `{device}`"));
                }
                let mut action = self
                    .embedder_actions
                    .remove(&name)
                    .ok_or_else(|| format!("no action `{name}`"))?;
                self.journal_event(
                    &device,
                    at,
                    "action",
                    vec![("name", name.clone()), ("argument", argument.clone())],
                );
                let call = ActionCall {
                    name: &name,
                    device: &device,
                    argument: &argument,
                };
                let result = action(
                    &mut OpContext {
                        at,
                        op,
                        device: None,
                        network: self,
                    },
                    &call,
                );
                self.embedder_actions.insert(name, action);
                result.map_err(|e| e.to_string())?;
            }
            Op::StartDevice { device } => {
                let id = self
                    .live_device(&device)
                    .ok_or_else(|| format!("no device `{device}`"))?;
                let idx = id.0;
                let d = &self.devices[idx];
                if d.phase != DevicePhase::Stopped {
                    return Err(format!("`{device}` is not stopped"));
                }
                // The component it ran: kept since it was created, so no resolver is needed.
                if !self.components.contains_key(&idx) {
                    return Err(format!(
                        "`{device}`'s component is not known to the network"
                    ));
                }
                let (config, options) = (d.config.clone(), d.options.clone());
                let captures = Some((d.stdout.clone(), d.stderr.clone()));
                let (context, handles) = self.context(
                    idx,
                    &device,
                    config.clone(),
                    options.clone(),
                    captures,
                    SetupOrigin::Restarted,
                );
                let component = &self.components[&idx];
                let instance = self
                    .runtime
                    .instantiate(context, component.borrow())
                    .map_err(|e| e.to_string())?;
                self.register(
                    idx,
                    self.devices[idx].number,
                    &device,
                    config,
                    options,
                    instance,
                    handles,
                    true,
                )
                .map_err(|e| e.to_string())?;
                for l in std::mem::take(&mut self.devices[idx].downed) {
                    self.carrier(l, at, true);
                }
                self.infra.set_phase(&device, Phase::Running, at);
                self.journal_event(&device, at, "device-started", Vec::new());
                self.life(idx, at, LifeEvent::Started);
            }
            Op::RemoveDevice { device } => {
                let id = self
                    .live_device(&device)
                    .ok_or_else(|| format!("no device `{device}`"))?;
                self.remove_device(id.0, at, Vec::new());
                self.cascade(id.0, at);
            }
            Op::Wire {
                a,
                b,
                latency,
                mtu,
                kind,
                cable,
                impairments,
            } => {
                let end = |l: &Self, (name, port): &(String, u32)| {
                    l.live_device(name)
                        .map(|d| d.port(*port))
                        .ok_or_else(|| format!("no device `{name}`"))
                };
                let (pa, pb) = (end(self, &a)?, end(self, &b)?);
                let tag = self.clock.peek_tag();
                let link = self.connect(pa, pb).map_err(|e| e.to_string())?;
                self.created_links.push((link.0, tag));
                self.link_options(link.0, latency, mtu, impairments);
                if kind != LinkKind::Ethernet {
                    self.panel.set_kind(link.0, kind);
                }
                if let Some(setup) = cable {
                    self.panel.configure_cable(link.0, &setup);
                }
                let name = self.panel.link_info(link.0).name;
                self.journal_event(&a.0, at, "link-added", vec![("link", name)]);
            }
            Op::SetLink { link, up, latency } => {
                let l = self.live_link(&link)?;
                let mut fields = vec![("link", link.clone())];
                if let Some(ns) = latency {
                    self.panel.set_latency(l, ns);
                    fields.push(("latency-ns", ns.to_string()));
                }
                if let Some(up) = up {
                    self.carrier(l, at, up);
                    fields.push(("up", up.to_string()));
                }
                let device = self.devices[self.panel.link_info(l).ends[0].device.0]
                    .name
                    .clone();
                self.journal_event(&device, at, "link-changed", fields);
            }
            Op::ImpairNamed {
                link,
                from,
                impairments: imp,
            } => {
                let l = self.live_link(&link)?;
                check_end(from).map_err(|e| e.to_string())?;
                self.panel.set_impairments(l, from, imp);
                let mut fields = vec![("link", link.clone())];
                if let Some(end) = from {
                    let e = self.panel.link_info(l).ends[end];
                    let name = &self.devices[e.device.0].name;
                    fields.push(("from", format!("{name}:{}", e.port)));
                }
                fields.extend([
                    ("rate-bps", imp.rate.to_string()),
                    ("queue", imp.queue.to_string()),
                    ("loss-ppm", imp.loss_ppm.to_string()),
                    ("jitter-ns", imp.jitter.to_string()),
                ]);
                let device = self.devices[self.panel.link_info(l).ends[0].device.0]
                    .name
                    .clone();
                self.journal_event(&device, at, "link-changed", fields);
            }
            Op::Unwire { link } => {
                let l = self.live_link(&link)?;
                let device = self.devices[self.panel.link_info(l).ends[0].device.0]
                    .name
                    .clone();
                self.unwire(l, at);
                self.journal_event(&device, at, "link-removed", vec![("link", link)]);
            }
            Op::StdinNamed { device, bytes } => {
                // A paused device's stdin keeps what is typed for when it resumes.
                let id = alive(self, &device)?;
                self.devices[id.0].inbox.push(Command::Stdin(bytes));
            }
            Op::Extension(ext) => {
                ext.apply(&mut OpContext {
                    at,
                    op,
                    device: None,
                    network: self,
                })
                .map_err(|e| e.to_string())?;
            }
            Op::ExtensionAt { device, op: ext } => {
                if self.devices[device.0].phase == DevicePhase::Removed {
                    return Err(format!("`{}` was removed", self.devices[device.0].name));
                }
                ext.apply(&mut OpContext {
                    at,
                    op,
                    device: Some(device),
                    network: self,
                })
                .map_err(|e| e.to_string())?;
            }
            Op::ControlNamed { device, call } => {
                let id = running(self, &device)?;
                self.require_export(id, call.export())
                    .map_err(|e| e.to_string())?;
                OpTarget::control(self, op, id, call.call());
            }
            other => return Err(format!("not a network op: {other:?}")),
        }
        Ok(())
    }

    /// The link called `name` that is still wired.
    fn live_link(&self, name: &str) -> std::result::Result<usize, String> {
        (0..self.panel.link_count())
            .find(|&l| {
                let i = self.panel.link_info(l);
                i.name == name && !i.removed
            })
            .ok_or_else(|| format!("no link `{name}`"))
    }

    /// The link called `name` that is still wired.
    pub fn link_named(&self, name: &str) -> Option<LinkId> {
        self.live_link(name).ok().map(LinkId)
    }

    /// Instantiates `component` (a catalog name) with `context`, through the resolver; with
    /// the component it resolved to.
    fn resolve_instantiate(
        &self,
        component: &str,
        context: DeviceContext,
    ) -> std::result::Result<(DeviceInstance, <R::Component as ToOwned>::Owned), String> {
        let resolver = self
            .resolver
            .as_ref()
            .ok_or("this network has no component catalog")?;
        let runtime = self.runtime;
        let mut context = Some(context);
        let mut resolved = None;
        let instance = resolver(component, &mut |c| {
            let ctx = context
                .take()
                .ok_or_else(|| Error::Refused("instantiated twice".to_owned()))?;
            resolved = Some(c.to_owned());
            runtime.instantiate(ctx, c)
        })
        .map_err(|e| e.to_string())?;
        let resolved = resolved.ok_or("the component resolver instantiated nothing")?;
        Ok((instance, resolved))
    }

    /// Instantiates the component a controller supplied under digest reference `component`
    /// with `context`, for the derived request being applied: compiled from the caller's
    /// bytes the first time (the result kept by digest), from the kept result after.
    fn supplied_instantiate(
        &mut self,
        component: &str,
        context: DeviceContext,
    ) -> std::result::Result<(DeviceInstance, <R::Component as ToOwned>::Owned), String> {
        let caller = self
            .applying
            .and_then(|n| self.infra.request(n))
            .map(|r| r.caller)
            .ok_or_else(|| {
                format!(
                    "`{component}` names a component a controller supplied: only that \
                     controller's requests create devices from it"
                )
            })?;
        let bytes = self
            .infra
            .supplied_bytes(&caller, component)
            .ok_or_else(|| format!("`{caller}`'s store keeps no component `{component}`"))?;
        // Forget the compiled components whose bytes went meanwhile.
        self.prune_supplied();
        if !self.supplied.contains_key(component) {
            self.supplied_compiles += 1;
            let compiled = self.runtime.compile_supplied(component, &bytes);
            self.supplied.insert(component.to_owned(), compiled);
        }
        let owned = match &self.supplied[component] {
            Ok(c) => {
                let c: &R::Component = c.borrow();
                c.to_owned()
            }
            Err(why) => return Err(why.clone()),
        };
        let instance = self
            .runtime
            .instantiate(context, owned.borrow())
            .map_err(|e| e.to_string())?;
        Ok((instance, owned))
    }

    /// Forgets the compiled components whose bytes no controller's store keeps any more.
    fn prune_supplied(&mut self) {
        if self.supplied.is_empty() {
            return;
        }
        let kept = self.infra.stored_digests();
        self.supplied.retain(|digest, _| kept.contains(digest));
    }

    /// Removes device `idx` at `at`: stopped if running, every link unwired, its name free;
    /// journalled as `device-removed` with `fields`.
    fn remove_device(&mut self, idx: usize, at: Nanos, fields: Vec<(&str, String)>) {
        if matches!(
            self.devices[idx].phase,
            DevicePhase::Running | DevicePhase::Paused
        ) {
            self.stop_device(idx, at);
        }
        for l in self.panel.links_of(idx) {
            self.unwire(l, at);
        }
        self.devices[idx].phase = DevicePhase::Removed;
        self.devices[idx].downed.clear();
        let name = self.devices[idx].name.clone();
        self.infra.removed(&name, at);
        self.journal_event(&name, at, "device-removed", fields);
        self.life(idx, at, LifeEvent::Removed);
    }

    /// Controller `idx` just stopped or was removed: its [`Cascade`] stops or removes the
    /// devices it created, at once and in creation order, journalled on each with
    /// `with-owner`.
    fn cascade(&mut self, idx: usize, at: Nanos) {
        let d = &self.devices[idx];
        if !d.options.infra || d.options.infra_cascade == Cascade::Keep {
            return;
        }
        let (owner, cascade) = (d.name.clone(), d.options.infra_cascade);
        let mut owned: Vec<usize> = self
            .infra
            .owned_by(&owner)
            .iter()
            .filter_map(|name| self.live_device(name).map(|d| d.0))
            .collect();
        owned.sort_unstable();
        for i in owned {
            let name = self.devices[i].name.clone();
            let fields = vec![("with-owner", owner.clone())];
            match cascade {
                Cascade::Stop
                    if matches!(
                        self.devices[i].phase,
                        DevicePhase::Running | DevicePhase::Paused
                    ) =>
                {
                    self.stop_device(i, at);
                    self.infra.stopped_with(&name, &owner, at);
                    self.journal_event(&name, at, "device-stopped", fields);
                    self.life(i, at, LifeEvent::Stopped);
                }
                Cascade::Remove => self.remove_device(i, at, fields),
                _ => {}
            }
        }
    }

    /// Stops device `idx`: its links go down (the far ends see it), its actor is dropped.
    fn stop_device(&mut self, idx: usize, at: Nanos) {
        for l in self.panel.links_of(idx) {
            if self.carrier(l, at, false) {
                self.devices[idx].downed.push(l);
            }
        }
        self.exec.stop_actor(idx);
        self.devices[idx].phase = DevicePhase::Stopped;
        self.devices[idx].paused_down = false;
    }

    /// Whether device `idx` gets `link-state` calls: a running one at once, a paused one when
    /// it resumes (they wait in its inbox).
    fn hears_links(&self, idx: usize) -> bool {
        matches!(
            self.devices[idx].phase,
            DevicePhase::Running | DevicePhase::Paused
        )
    }

    /// Sets link `l`'s carrier at `at`; running ends get `link-state`. Whether it changed.
    fn carrier(&mut self, l: usize, at: Nanos, up: bool) -> bool {
        let Some(ends) = self.panel.set_up(&self.clock, at, l, up) else {
            return false;
        };
        for (device, port) in ends {
            if self.hears_links(device) {
                self.devices[device]
                    .inbox
                    .push(Command::LinkState { port, up });
            }
        }
        self.exec.touched();
        true
    }

    /// Unwires link `l` at `at`: down for its running ends, its ports free.
    fn unwire(&mut self, l: usize, at: Nanos) {
        if let Some(ends) = self.panel.disconnect(&self.clock, at, l) {
            for (device, port) in ends {
                if self.hears_links(device) {
                    self.devices[device]
                        .inbox
                        .push(Command::LinkState { port, up: false });
                }
            }
        }
        for d in &mut self.devices {
            d.downed.retain(|&x| x != l);
        }
        self.exec.touched();
    }

    /// A journal event from the network about `device` (its topology records).
    fn journal_event(&self, device: &str, at: Nanos, kind: &str, fields: Vec<(&str, String)>) {
        JournalEnd {
            journal: self.journal.clone(),
            device: device.to_owned(),
        }
        .push(
            at,
            crate::journal::Record::Event {
                kind: kind.to_owned(),
                fields: fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
            },
        );
    }

    /// Current virtual time.
    pub fn now(&self) -> Nanos {
        self.clock.now()
    }

    /// The network's seed and wall epoch.
    pub fn config(&self) -> &SimConfig {
        &self.config
    }

    /// Every device, in creation order.
    pub fn devices(&self) -> Vec<DeviceId> {
        (0..self.devices.len()).map(DeviceId).collect()
    }

    /// The device's name.
    pub fn device_name(&self, device: DeviceId) -> &str {
        &self.devices[device.0].name
    }

    /// The apps of a composed node (its `app-<name>` exports, by name, in the order they
    /// start). Empty for a plain device.
    pub fn apps(&self, device: DeviceId) -> &[String] {
        &self.devices[device.0].apps
    }

    /// The ports the device declared, in its order.
    pub fn ports(&self, device: DeviceId) -> Vec<PortInfo> {
        self.panel.ports(device.0)
    }

    /// Every link, in creation order.
    pub fn links(&self) -> Vec<LinkId> {
        (0..self.panel.link_count()).map(LinkId).collect()
    }

    /// The link's ends, latency, MTU and current state.
    pub fn link_info(&self, link: LinkId) -> LinkInfo {
        self.panel.link_info(link.0)
    }

    /// The link's file-name-safe name, `<device>.<port>-<device>.<port>`.
    pub fn link_name(&self, link: LinkId) -> String {
        self.panel.link_info(link.0).name
    }

    /// The link attached to `port`, if any.
    pub fn link_at(&self, port: PortRef) -> Option<LinkId> {
        self.links()
            .into_iter()
            .find(|&l| self.panel.link_info(l.0).ends.contains(&port))
    }

    /// The link's pcap-ng capture so far: one interface per end (`<device>:<port>`), every frame
    /// recorded outbound on the sender's interface at transmit time and inbound on the
    /// receiver's interface at arrival time. Timestamps are virtual nanoseconds. Frames dropped
    /// at transmit (link down, oversize, a full transmit queue) are not in it; lost ones (in
    /// flight when the link went down, or taken by its seeded loss) appear outbound only. What
    /// it keeps of each frame follows the link's [`CaptureOptions`].
    pub fn pcap(&self, link: LinkId) -> Vec<u8> {
        self.panel.pcap(link.0)
    }

    /// Sets the notes `link`'s capture carries ([`LinkMut::capture_notes`]), at any time:
    /// before, during or after a run, for links the builder wired and links created while the
    /// network ran alike. A capture read later ([`pcap`](Self::pcap)) carries them; an empty
    /// list removes them. Refused ([`Error::Refused`]) for a link the network does not have and
    /// for notes that break [`pcap::check_notes`](crate::pcap::check_notes).
    pub fn set_capture_notes<S: Into<String>>(
        &mut self,
        link: LinkId,
        notes: impl IntoIterator<Item = S>,
    ) -> Result<()> {
        if link.0 >= self.panel.link_count() {
            return Err(Error::Refused(format!("no link {}", link.0)));
        }
        let notes: Vec<String> = notes.into_iter().map(Into::into).collect();
        crate::pcap::check_notes(&notes).map_err(Error::Refused)?;
        self.panel.set_notes(link.0, notes);
        Ok(())
    }

    /// Every transmission on a wired port so far, in transmit order, with its fate (its bytes
    /// as its link's [`CaptureOptions`] keep them).
    pub fn frames(&self) -> Vec<FrameRecord> {
        self.panel.frames()
    }

    /// What the captures and frame log of links created from now on keep
    /// (`docs/design/links.md`): links the builder wires and links created while the network
    /// runs (operator events, controllers' cables) alike. [`LinkMut::capture`] overrides it for
    /// one link. The default, [`CaptureOptions::default`], keeps everything and names nothing.
    pub fn set_capture_defaults(&mut self, capture: CaptureOptions) {
        let (_, series) = self.panel.defaults();
        self.panel.set_defaults(capture, series);
    }

    /// What new links' captures keep ([`set_capture_defaults`](Self::set_capture_defaults)).
    pub fn capture_defaults(&self) -> CaptureOptions {
        self.panel.defaults().0
    }

    /// Gives every link created from now on a series of its counters per interval
    /// ([`LinkMut::series`]), or none with `None` (the default).
    pub fn set_series_defaults(&mut self, series: Option<SeriesOptions>) {
        let (capture, _) = self.panel.defaults();
        self.panel.set_defaults(capture, series);
    }

    /// The link's counters per interval so far: `(bucket start, counters)`, oldest first, only
    /// buckets in which a counter changed, at most the series' `keep` (the most recent). Empty
    /// for a link without a series. Each counter is counted in the bucket of the instant it
    /// changed at, as [`link_stats`](Self::link_stats) counts it: so while no bucket was
    /// dropped, the buckets add up to `link_stats`.
    pub fn link_series(&self, link: LinkId) -> Vec<(Nanos, LinkStats)> {
        self.panel.link_series(link.0)
    }

    /// Every link up/down change so far (scripted ones; creation is not a transition).
    pub fn link_transitions(&self) -> Vec<LinkTransition> {
        self.panel.transitions()
    }

    /// The link's counters as of now: everything counted up to the network's current
    /// position. Between runs (`run_until`, `run_stoppable` stops) that is every event
    /// processed so far, so reading at two points and subtracting ([`LinkStats::since`]) gives
    /// the traffic in between, without parsing captures. Frames are counted at transmit
    /// (`frames`, `bytes` and the drops) and `lost` at the instant the frame would have
    /// arrived.
    pub fn link_stats(&self, link: LinkId) -> LinkStats {
        self.panel.link_stats(link.0)
    }

    /// Frames the device transmitted on unwired ports.
    pub fn dropped(&self, device: DeviceId) -> u64 {
        self.panel.dropped(device.0)
    }

    /// Every `wasmnet:link/log` record so far, in call order, stamped with virtual time.
    pub fn journal(&self) -> Vec<JournalEntry> {
        self.journal.entries()
    }

    /// The journal from entry `from` on: what a live monitor has not taken yet.
    pub fn journal_from(&self, from: usize) -> Vec<JournalEntry> {
        self.journal.entries_from(from)
    }

    /// Records the journal discarded because it was full ([`crate::journal::MAX_ENTRIES`]).
    pub fn journal_dropped(&self) -> u64 {
        self.journal.dropped()
    }

    /// Everything the device wrote to stdout so far. Its lines are also in the journal,
    /// time-stamped, if the device was created with [`DeviceOptions::journal_stdio`].
    pub fn stdout(&self, device: DeviceId) -> Vec<u8> {
        self.devices[device.0].stdout.contents()
    }

    /// Everything the device wrote to stderr so far (time-stamped lines only with
    /// [`DeviceOptions::journal_stdio`]; components should prefer the log import).
    pub fn stderr(&self, device: DeviceId) -> Vec<u8> {
        self.devices[device.0].stderr.contents()
    }

    /// Reads the device's counters through its `wasmnet:link/counters` export, or `None` if the
    /// device does not export it.
    ///
    /// This is a control call into the live device: it runs at the network's current instant,
    /// inside the device's event loop, between runs (call it after [`run_until`](Self::run_until)
    /// or [`run_until_quiescent`](Self::run_until_quiescent) returned). Virtual time does not
    /// move and no queued event fires. A device that traps here fails the network like a trap
    /// in a run.
    pub fn counters(&mut self, device: DeviceId) -> Result<Option<Vec<(String, u64)>>> {
        if self.failed {
            return Err(Error::Halted);
        }
        let record = &self.devices[device.0];
        if !record.has_counters {
            return Ok(None);
        }
        refuse_paused(record)?;
        let reply = CountersReply::default();
        record.inbox.push(Command::Counters(reply.clone()));
        let settled = self.exec.settle(u64::from(self.devices[device.0].number));
        self.failed = settled.is_err();
        settled?;
        let values = reply
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let out = values.map(Some).ok_or_else(|| Error::Deadlock {
            at: self.clock.now(),
            outstanding: vec![(record.name.clone(), "counters".to_owned())],
        });
        self.settle_crashes();
        out
    }

    // ---- multi-site (docs/design/sites.md) ---------------------------------------------------

    /// Enters the setup slot of the next scripted link change.
    fn next_action_slot(&mut self) {
        let slot = self.devices.len() as u64 + self.actions;
        self.actions += 1;
        self.clock.set_setup(slot, HOST_DEVICE);
    }

    /// Adds a placeholder for a device that runs on another site, so device indices (and the
    /// event keys built from them) are the same on every site. Its ports come from its own
    /// site ([`set_remote_ports`](Self::set_remote_ports)). Create devices in the same order on
    /// every site, local and remote alike.
    ///
    /// The placeholder has an empty description: a network whose controllers read the device
    /// table (`wasmnet:infra`) describes it with
    /// [`remote_device_with`](Self::remote_device_with) instead, so that every site's table
    /// lists it as its own site does.
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn remote_device(&mut self, name: &str) -> Result<DeviceId> {
        self.remote_device_with(name, DeviceConfig::new(), DeviceOptions::default())
    }

    /// [`remote_device`](Self::remote_device) with the device's description: the config and
    /// options its own site creates it with (and, with
    /// [`set_device_component`](Self::set_device_component), its component). The device
    /// table lists the placeholder with them, exactly as the unsplit network's table lists the
    /// device; its options also tell this site where the network's controllers run
    /// ([`DeviceOptions::infra_prefix`]).
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn remote_device_with(
        &mut self,
        name: &str,
        config: DeviceConfig,
        options: DeviceOptions,
    ) -> Result<DeviceId> {
        if self.devices.iter().any(|d| d.name == name) {
            return Err(Error::DuplicateDevice(name.to_owned()));
        }
        self.check_grant(name, &options, true)
            .map_err(Error::Refused)?;
        let idx = self.devices.len();
        let (rank, number) = self.builder_number().map_err(Error::Refused)?;
        if let Some(rank) = rank {
            self.take_number(rank);
        }
        let (inbox, status) = (Inbox::default(), Status::default());
        self.exec.add_remote(name, number, inbox.clone(), status);
        let registered = self.panel.add_device(name, Vec::new(), true);
        debug_assert_eq!(registered, idx);
        self.devices.push(DeviceRecord {
            name: name.to_owned(),
            number,
            created: None,
            inbox,
            has_counters: false,
            exports: Vec::new(),
            apps: Vec::new(),
            stdout: OutputCapture::new(),
            stderr: OutputCapture::new(),
            remote: true,
            component: None,
            config,
            options,
            phase: DevicePhase::Running,
            downed: Vec::new(),
            paused_down: false,
        });
        self.infra_added(idx, None);
        Ok(DeviceId(idx))
    }

    /// Sets a remote device's ports (its `ports()` answer, from its own site).
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn set_remote_ports(&mut self, device: DeviceId, ports: Vec<PortInfo>) {
        assert!(self.devices[device.0].remote, "only remote devices");
        self.panel.set_ports(device.0, ports);
    }

    /// Whether the device runs on another site.
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn is_remote(&self, device: DeviceId) -> bool {
        self.devices[device.0].remote
    }

    /// Counts a scripted link change that this site does not schedule (both ends of the link
    /// are on other sites), so setup slots stay aligned with the single-site network.
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn skip_link_state(&mut self) {
        self.next_action_slot();
    }

    /// One site-sync window: runs every event *before* `horizon` (exclusive; `None`: all of
    /// them) without moving the clock to the horizon. Resumable; frames from other sites may
    /// be queued in between ([`receive_remote`](Self::receive_remote)). While events remain it
    /// returns `Deadline { at: now, .. }`.
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn run_before(&mut self, horizon: Option<Nanos>) -> Result<Outcome> {
        if self.failed {
            return Err(Error::Halted);
        }
        let outcome = self.drive(|e| e.run_before(horizon));
        self.failed = outcome.is_err();
        outcome
    }

    /// Moves the clock to `t` without firing anything (a multi-site run that stopped at its
    /// deadline, like [`run_until`](Self::run_until) does on one site).
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn advance_to(&mut self, t: Nanos) {
        self.clock.advance_to(t);
    }

    /// The time of the earliest queued event, if any.
    pub fn next_event_time(&self) -> Option<Nanos> {
        self.clock.next_event_time()
    }

    /// Queued events.
    pub fn pending_events(&self) -> usize {
        self.clock.pending_events()
    }

    /// Frames transmitted towards devices on other sites since the last call, in transmit
    /// order.
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn take_outbox(&self) -> Vec<RemoteFrame> {
        self.panel.take_outbox()
    }

    /// Why `frame` cannot have come from a peer site in lockstep, if it cannot: its link must
    /// be a WAN link whose `to_end` is `device:port` on this site, and its key must not lie
    /// before now. [`crate::sites::SiteSync::handle`] checks every frame with it, so a malformed
    /// or out-of-step message is an error, not a panic.
    pub(crate) fn check_remote(
        &self,
        frame: &RemoteFrame,
    ) -> std::result::Result<(), crate::sites::SyncError> {
        use crate::sites::SyncError;
        let links = self.panel.link_count();
        if frame.link.0 >= links {
            return Err(SyncError::NoSuchLink {
                link: frame.link.0,
                links,
            });
        }
        if frame.to_end > 1 {
            return Err(SyncError::NoSuchEnd(frame.to_end));
        }
        let ends = self.panel.link_info(frame.link.0).ends;
        let to = PortRef {
            device: frame.device,
            port: frame.port,
        };
        if ends[frame.to_end] != to
            || self.panel.is_remote(frame.device.0)
            || !self.panel.is_remote(ends[1 - frame.to_end].device.0)
        {
            return Err(SyncError::NotWanEnd {
                device: frame.device.0,
                port: frame.port,
                link: frame.link.0,
            });
        }
        let now = self.clock.now();
        match frame.key.levels.first() {
            None => Err(SyncError::NoKey),
            Some(_) if frame.key.at() < now => Err(SyncError::Overdue {
                due: frame.key.at(),
                now,
            }),
            Some(_) => Ok(()),
        }
    }

    /// Queues a frame that another site transmitted towards one of this site's devices.
    ///
    /// # Panics
    ///
    /// If the frame is not for a WAN link's end on this site, or is due before now (the sites
    /// are out of lockstep). [`crate::sites::SiteSync::handle`] checks both first and returns
    /// an error instead.
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn receive_remote(&self, frame: RemoteFrame) {
        assert!(
            !self.panel.is_remote(frame.device.0),
            "a WAN frame for a device that is not on this site"
        );
        self.panel.receive_remote(&self.clock, frame);
    }

    /// This site's halves of the WAN links' captures, tagged for merging.
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn taps(&self) -> Vec<Tap> {
        self.panel.taps()
    }

    /// Fates of the frames other sites sent here.
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn remote_arrivals(&self) -> Vec<RemoteArrival> {
        self.panel.arrivals()
    }

    /// The tag of every journal entry ([`journal`](Self::journal) order).
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn journal_tags(&self) -> Vec<Tag> {
        self.journal.tags()
    }

    /// The tag of every frame-log record ([`frames`](Self::frames) order).
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn frame_tags(&self) -> Vec<Tag> {
        self.panel.frame_tags()
    }

    /// The devices created while the network ran (operator events, controllers), each with the
    /// tag of the processing context that created it, in creation order.
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn created_devices(&self) -> Vec<(DeviceId, Tag)> {
        self.devices
            .iter()
            .enumerate()
            .filter_map(|(i, d)| Some((DeviceId(i), d.created.clone()?)))
            .collect()
    }

    /// The links created while the network ran (operator events, controllers' cables), each
    /// with the tag of the processing context that created it, in creation order. The others
    /// are the links the network was built with.
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn created_links(&self) -> Vec<(LinkId, Tag)> {
        self.created_links
            .iter()
            .map(|(l, t)| (LinkId(*l), t.clone()))
            .collect()
    }

    /// The tag of every link transition ([`link_transitions`](Self::link_transitions) order).
    ///
    /// Embedder surface, unstable (multi-site runs, [`crate::sites`]).
    pub fn transition_tags(&self) -> Vec<Tag> {
        self.panel.transition_tags()
    }

    /// Executor counters.
    pub fn stats(&self) -> Stats {
        self.exec.stats()
    }

    /// Every device's cost so far, by device name, in device order. Reports only: nothing in a
    /// run depends on it.
    pub fn costs(&self) -> Vec<(String, crate::DeviceCost)> {
        self.exec.costs()
    }

    /// The cost of the device named `name` (zero for an unknown name).
    pub fn cost_of(&self, name: &str) -> crate::DeviceCost {
        self.exec
            .costs()
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c)
            .unwrap_or_default()
    }

    /// Gives the executor a wall clock (ns) so device costs include wall time (where the
    /// runtime has one).
    pub fn set_wall_clock(&mut self, wall: fn() -> u64) {
        self.exec.set_wall_clock(wall);
    }

    // ---- world stops and operator events (docs/design/event-order.md) -----------------------

    /// Runs like [`run_until`](Self::run_until) (`until = None`: to quiescence), but checks
    /// `stop` at every event boundary (the current one included) and returns
    /// [`Step::Stopped`] where it holds. Resumable: a run that stopped any number of times
    /// (with nothing changed at the stops) is byte-identical to one that never stopped.
    ///
    /// Embedder surface, unstable (operator events).
    pub fn run_stoppable(
        &mut self,
        until: Option<Nanos>,
        stop: &mut dyn FnMut(&Boundary) -> bool,
    ) -> Result<Step> {
        if self.failed {
            return Err(Error::Halted);
        }
        let step = self.drive(|e| e.run_stoppable(until, &mut *stop));
        self.failed = step.is_err();
        step
    }

    /// An actor was woken from outside a run (a runtime whose devices make progress between
    /// runs, such as a browser's JS event loop). The next
    /// [`run_stoppable`](Self::run_stoppable) polls before it pops, as
    /// [`run_until`](Self::run_until) always does.
    pub fn woken_outside(&mut self) {
        self.exec.woken_outside();
    }

    /// The current event boundary.
    pub fn boundary(&self) -> Boundary {
        Boundary {
            events: self.exec.stats().events,
            now: self.clock.now(),
            next: self.clock.next_key(),
        }
    }

    /// Places an operator event and returns its index.
    ///
    /// A split network takes only timed ones ([`Placement::StartOf`], [`Placement::EndOf`])
    /// at a device: [`Op::Stdin`], [`Op::Control`] and [`Op::Inject`]. Every site must add the
    /// same operator events in the same order: an op at a device of another site is counted
    /// (so indices and keys agree) but not queued here, and stays [`OpState::Pending`] on this
    /// site.
    ///
    /// Embedder surface, unstable (operator events).
    pub fn add_op(&mut self, op: Op, placement: Placement) -> Result<usize> {
        let elsewhere = if self.devices.iter().any(|d| d.remote) {
            let device = match &op {
                Op::Stdin { device, .. }
                | Op::Control { device, .. }
                | Op::ExtensionAt { device, .. } => Some(*device),
                Op::Inject { from, .. } => Some(from.device),
                _ => None,
            };
            match (device, &placement) {
                (Some(d), Placement::StartOf(_) | Placement::EndOf(_)) => self.devices[d.0].remote,
                _ => {
                    return Err(Error::Refused(
                        "a split (multi-site) network takes only timed operator events at a \
                         device (stdin, a control call, an injected frame, an extension's op at a device)"
                            .to_owned(),
                    ));
                }
            }
        } else {
            false
        };
        let core = match op {
            Op::LinkState { link, up } => CoreOp::LinkState { link: link.0, up },
            Op::Latency { link, ns } => CoreOp::Latency { link: link.0, ns },
            Op::Impair {
                link,
                from,
                impairments,
            } => {
                check_end(from)?;
                CoreOp::Impair {
                    link: link.0,
                    from,
                    impairments,
                }
            }
            Op::Inject { from, bytes } => CoreOp::Inject {
                device: from.device.0,
                port: from.port,
                bytes,
            },
            Op::Stdin { device, bytes } => CoreOp::Stdin {
                device: device.0,
                bytes,
            },
            Op::Control { device, call } => {
                // Another site's device: that site checks.
                if !elsewhere {
                    self.require_export(device, call.export())?;
                }
                CoreOp::Control {
                    device: device.0,
                    call,
                }
            }
            op => {
                debug_assert!(op.is_network_op());
                if let Op::ImpairNamed { from, .. } = op {
                    check_end(from)?;
                }
                if matches!(op, Op::AddDevice { .. }) && self.resolver.is_none() {
                    return Err(Error::Refused(
                        "this network has no component catalog: it cannot create devices"
                            .to_owned(),
                    ));
                }
                if let Op::Action { name, .. } = &op
                    && !self.embedder_actions.contains_key(name)
                {
                    return Err(Error::Refused(format!("no action `{name}` is registered")));
                }
                self.network_ops.push(op);
                CoreOp::Network(self.network_ops.len() - 1)
            }
        };
        let slot = self.exec.op_states().len() as u64;
        let (key, anchor) = match placement {
            Placement::Before(anchor) => {
                let anchor = anchor.anchor();
                let n = self.exec.ops_before(&anchor) + 1;
                (anchor.pre(n), Some(anchor))
            }
            // After the devices' and actions' setup slots, whatever their number.
            Placement::StartOf(at) => (EventKey::operator_at(at, (1 << 40) + slot), None),
            Placement::EndOf(at) => (EventKey::operator_after(at, slot), None),
        };
        if key.at() < self.clock.now() && placement_is_timed(&key) {
            return Err(Error::Refused(format!(
                "an operator event at t={} is in the past (now t={})",
                key.at(),
                self.clock.now()
            )));
        }
        let idx = self.exec.add_op(core, anchor);
        if elsewhere {
            return Ok(idx);
        }
        if !self.clock.schedule_op(key, idx) {
            return Err(Error::Refused("two operator events at one key".to_owned()));
        }
        Ok(idx)
    }

    /// Refuses a device that does not report `export` among its optional exports.
    fn require_export(&self, device: DeviceId, export: &str) -> Result<()> {
        if self.devices[device.0].exports.iter().any(|e| e == export) {
            Ok(())
        } else {
            Err(Error::Refused(format!(
                "device `{}` does not export {export}",
                self.devices[device.0].name
            )))
        }
    }

    /// Registers an embedder action under `name` (replacing an earlier one), for
    /// [`Op::Action`]: a way for an operator event to act on state outside the simulation (an
    /// extension's, through [`OpContext::extension_mut`], or the embedder's own) at an exact
    /// position among the instant's events.
    ///
    /// The action runs when its op applies, in the op's own processing context, before the
    /// op's rounds: it gets the op's instant ([`OpContext::at`]), may read device phases,
    /// journal on devices, queue control calls, change the network's extensions and place
    /// further operator events ([`OpContext::add_op`]). It cannot run guest code itself,
    /// change the topology directly (it places an op for that) or move time. It is code
    /// outside the simulation, so a rerun replays it only as far as it is deterministic: its
    /// effects must depend only on what it is given (the instant, the argument, the state it
    /// changes); one that reads anything else (a wall clock, a file) makes the network a
    /// function of that too.
    ///
    /// Embedder surface, unstable (operator events).
    pub fn register_action(
        &mut self,
        name: impl Into<String>,
        action: impl FnMut(&mut OpContext<'_>, &ActionCall<'_>) -> std::result::Result<(), OpError> + 'r,
    ) {
        self.embedder_actions.insert(name.into(), Box::new(action));
    }

    /// What became of every operator event so far, by index.
    pub fn op_states(&self) -> Vec<OpState> {
        self.exec.op_states()
    }

    /// Adds (or replaces) the operator rule for the transmission with this causal digest: it
    /// applies at `wire.transmit` whenever that transmission happens.
    ///
    /// Embedder surface, unstable (operator events).
    pub fn set_frame_rule(&mut self, digest: Digest, action: FrameAction) {
        self.panel.set_rule(digest, action);
    }

    /// Installs (or with `None` removes) the transmit hook: live monitors and import holds.
    ///
    /// Embedder surface, unstable (operator events).
    pub fn set_transmit_hook(&mut self, hook: Option<TransmitHook>) {
        self.panel.set_hook(hook);
    }
}

impl<R: Runtime + ?Sized> Network<'_, R> {
    /// A read-only handle on the network's growing records, usable while the network runs
    /// (stop conditions and monitors evaluate on it at boundaries and holds).
    pub fn records(&self) -> Records {
        Records {
            journal: self.journal.clone(),
            panel: self.panel.clone(),
        }
    }
}

/// A read-only view of a network's records that stays valid while the network runs.
#[derive(Clone)]
pub struct Records {
    journal: Journal,
    panel: Panel,
}

impl Records {
    pub fn journal_len(&self) -> usize {
        self.journal.len()
    }

    /// Journal entries `from..`, each with its tag.
    pub fn journal_from(&self, from: usize) -> Vec<(JournalEntry, Option<Tag>)> {
        self.journal.tagged_entries_from(from)
    }

    pub fn frames_len(&self) -> usize {
        self.panel.frames_len()
    }

    /// Frame records `from..`, each with its tag.
    pub fn frames_from(&self, from: usize) -> Vec<(FrameRecord, Tag)> {
        self.panel.frames_from(from)
    }

    /// The link's name.
    pub fn link_name(&self, link: LinkId) -> String {
        self.panel.link_info(link.0).name
    }

    /// A device's name.
    pub fn device_name(&self, device: DeviceId) -> String {
        self.panel.device_name(device.0)
    }
}

/// A cable of a device an operator event adds ([`Op::AddDevice`]), plugged in before the
/// device first runs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Cable {
    /// The new device's port.
    pub port: u32,
    /// The device at the far end, by name.
    pub to_device: String,
    /// Its port.
    pub to_port: u32,
    /// The link's one-way latency.
    pub latency: Nanos,
    /// The link's MTU, if not the default.
    pub mtu: Option<u32>,
    /// Its impairments by sending end (from the new device's port, then from the far end),
    /// set before any frame crosses it; `None`: unimpaired.
    pub impairments: Option<[Impairments; 2]>,
}

impl Cable {
    /// A cable from the new device's `port` to `to_device`'s `to_port`: no latency, the
    /// default MTU, unimpaired.
    pub fn new(port: u32, to_device: impl Into<String>, to_port: u32) -> Self {
        Self {
            port,
            to_device: to_device.into(),
            to_port,
            latency: 0,
            mtu: None,
            impairments: None,
        }
    }

    /// Sets [`latency`](Self::latency).
    pub fn latency(mut self, ns: Nanos) -> Self {
        self.latency = ns;
        self
    }

    /// Sets [`mtu`](Self::mtu).
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Sets [`impairments`](Self::impairments): from the new device's port, then from the far
    /// end.
    pub fn impairments(mut self, impairments: [Impairments; 2]) -> Self {
        self.impairments = Some(impairments);
        self
    }
}

/// An operator event the sim core applies (`docs/design/event-order.md`).
///
/// Build one with its constructor (`Op::wire`, `Op::stop_device`, ...) and set what it leaves
/// at its default with the `with_*` methods: every variant with fields is
/// `#[non_exhaustive]`, so a field added later is never a compile error
/// (`docs/stability.md`). A `with_*` method on an op it does not apply to panics. Match a
/// variant with `..`: `Op::Wire { a, b, .. }`.
///
/// Embedder surface, unstable (operator events).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Op {
    /// A carrier change of a whole link.
    #[non_exhaustive]
    LinkState { link: LinkId, up: bool },
    /// A link's one-way latency, for frames transmitted from then on.
    #[non_exhaustive]
    Latency { link: LinkId, ns: Nanos },
    /// A link's impairments (`docs/design/links.md`), for frames transmitted from then on: the
    /// direction sent from end `from` (0: `a`, 1: `b`, as in [`LinkInfo::ends`]), or both with
    /// `None`. Frames already queued keep their schedule.
    #[non_exhaustive]
    Impair {
        link: LinkId,
        from: Option<usize>,
        impairments: Impairments,
    },
    /// A frame transmitted from a port, as if its device had sent it.
    #[non_exhaustive]
    Inject { from: PortRef, bytes: Vec<u8> },
    /// Bytes for the device's stdin, appended at the op's instant ([`crate::InputQueue`]).
    #[non_exhaustive]
    Stdin { device: DeviceId, bytes: Vec<u8> },
    /// A control call into one of the device's optional exports, served in the op's own
    /// processing context (an extension's write, probe or the like). Refused when added if the
    /// device does not report the call's export; the device's own refusal is the op's state.
    #[non_exhaustive]
    Control { device: DeviceId, call: Control },
    // ---- dynamic topology (docs/design/topology-and-infra.md): resolved by name when applied
    /// A new device from the catalog (the network's component resolver), created in the op's
    /// own processing context: its first poll, `start` and seeds follow from there.
    #[non_exhaustive]
    AddDevice {
        name: String,
        component: String,
        config: DeviceConfig,
        options: DeviceOptions,
        /// Links wired in the same op, before the device first runs (a cable plugged in
        /// before power-on).
        wire: Vec<Cable>,
    },
    /// Stops a running (or paused) device: its store is dropped and its links go down (the
    /// far ends see the carrier drop). Its name, ports and links stay.
    #[non_exhaustive]
    StopDevice { device: String },
    /// Pauses a running device, as a laptop sleeps: its store (memory, sockets, timers) is
    /// kept but does not run, and it misses time (`docs/design/topology-and-infra.md`). Frames
    /// that reach its ports are dropped there (counted in `device-resumed`); its timers and
    /// poll deadline are held as they come due; link changes, stdin and wakes wait for it.
    /// With `link_down` its links go down for the far ends, as a sleeping NIC's carrier does,
    /// and come up at the resume; without, they stay up, as a frozen machine's do.
    #[non_exhaustive]
    PauseDevice { device: String, link_down: bool },
    /// Resumes a paused device. Its clocks read the network's time, so they jump by the pause;
    /// the timers and poll deadline that came due meanwhile fire right after this op, at this
    /// instant, one event each in the order they came due, before anything else still queued.
    #[non_exhaustive]
    ResumeDevice { device: String },
    /// The device faults at this position, as if its own code trapped there, with `message`:
    /// a device that crashes alone ([`DeviceOptions::crash_alone`], or one a controller
    /// created) is stopped as crashed (`device-crashed`, phase `crashed`); a fault of any other
    /// device fails the network ([`Error::Trap`]), as its guest's trap would.
    #[non_exhaustive]
    CrashDevice { device: String, message: String },
    /// Calls the embedder action registered as `name` ([`Network::register_action`]) with
    /// `argument`, journalled as `action {name, argument}` on `device` (which must exist; it
    /// need not run). The action's refusal is the op's state.
    #[non_exhaustive]
    Action {
        name: String,
        device: String,
        argument: String,
    },
    /// Starts a stopped device again from its component and config (a fresh instance), and
    /// brings up the links its stop took down.
    #[non_exhaustive]
    StartDevice { device: String },
    /// Removes a device: stopped if running, unwired, its name free for a new device.
    #[non_exhaustive]
    RemoveDevice { device: String },
    /// Wires two free ports (`(device, port)`) with a new link, up at once.
    #[non_exhaustive]
    Wire {
        a: (String, u32),
        b: (String, u32),
        latency: Nanos,
        mtu: Option<u32>,
        /// What it carries (Ethernet frames or a registered cable kind).
        kind: LinkKind,
        /// A cable's setup value ([`LinkMut::cable_setup`]).
        cable: Option<ExtValue>,
        /// Its impairments by sending end (from `a`, then from `b`), set before any frame
        /// crosses it; `None`: unimpaired.
        impairments: Option<[Impairments; 2]>,
    },
    /// Unwires a link by name: it goes down and its ports are free again.
    #[non_exhaustive]
    Unwire { link: String },
    /// A link by name (one that an earlier op wires): its carrier and/or latency.
    #[non_exhaustive]
    SetLink {
        link: String,
        up: Option<bool>,
        latency: Option<Nanos>,
    },
    /// [`Op::Impair`] on the link called `link` when the op applies (one that an earlier op
    /// wires); journalled as `link-changed`.
    #[non_exhaustive]
    ImpairNamed {
        link: String,
        from: Option<usize>,
        impairments: Impairments,
    },
    /// [`Op::Stdin`] into the device called `device` when the op applies (a device that an
    /// earlier op creates).
    #[non_exhaustive]
    StdinNamed { device: String, bytes: Vec<u8> },
    /// [`Op::Control`] into the device called `device` when the op applies.
    #[non_exhaustive]
    ControlNamed { device: String, call: Control },
    /// An extension's op ([`crate::ext::ExtOp`]), applied by the network in the op's own
    /// processing context.
    Extension(ExtensionOp),
    /// An extension's op that concerns one device, applied at its instant like
    /// [`Op::Extension`]: timed at a device, it is accepted in a split network, where only the
    /// device's own site applies it.
    #[non_exhaustive]
    ExtensionAt { device: DeviceId, op: ExtensionOp },
}

/// Constructors, one per variant with fields, taking what the op cannot do without; the rest
/// starts at its default and is set with the `with_*` methods below.
impl Op {
    /// [`Op::LinkState`].
    pub fn link_state(link: LinkId, up: bool) -> Self {
        Op::LinkState { link, up }
    }

    /// [`Op::Latency`].
    pub fn latency(link: LinkId, ns: Nanos) -> Self {
        Op::Latency { link, ns }
    }

    /// [`Op::Impair`], both directions (one with [`with_from`](Self::with_from)).
    pub fn impair(link: LinkId, impairments: Impairments) -> Self {
        Op::Impair {
            link,
            from: None,
            impairments,
        }
    }

    /// [`Op::Inject`].
    pub fn inject(from: PortRef, bytes: impl Into<Vec<u8>>) -> Self {
        Op::Inject {
            from,
            bytes: bytes.into(),
        }
    }

    /// [`Op::Stdin`].
    pub fn stdin(device: DeviceId, bytes: impl Into<Vec<u8>>) -> Self {
        Op::Stdin {
            device,
            bytes: bytes.into(),
        }
    }

    /// [`Op::Control`].
    pub fn control(device: DeviceId, call: Control) -> Self {
        Op::Control { device, call }
    }

    /// [`Op::AddDevice`]: an empty config, default options and no cables (set with
    /// [`with_config`](Self::with_config), [`with_options`](Self::with_options) and
    /// [`with_cable`](Self::with_cable)).
    pub fn add_device(name: impl Into<String>, component: impl Into<String>) -> Self {
        Op::AddDevice {
            name: name.into(),
            component: component.into(),
            config: DeviceConfig::new(),
            options: DeviceOptions::default(),
            wire: Vec::new(),
        }
    }

    /// [`Op::StopDevice`].
    pub fn stop_device(device: impl Into<String>) -> Self {
        Op::StopDevice {
            device: device.into(),
        }
    }

    /// [`Op::PauseDevice`], its links left up (down with
    /// [`with_link_down`](Self::with_link_down)).
    pub fn pause_device(device: impl Into<String>) -> Self {
        Op::PauseDevice {
            device: device.into(),
            link_down: false,
        }
    }

    /// [`Op::ResumeDevice`].
    pub fn resume_device(device: impl Into<String>) -> Self {
        Op::ResumeDevice {
            device: device.into(),
        }
    }

    /// [`Op::ExtensionAt`].
    pub fn extension_at(device: DeviceId, op: ExtensionOp) -> Self {
        Op::ExtensionAt { device, op }
    }

    /// [`Op::CrashDevice`].
    pub fn crash_device(device: impl Into<String>, message: impl Into<String>) -> Self {
        Op::CrashDevice {
            device: device.into(),
            message: message.into(),
        }
    }

    /// [`Op::Action`].
    pub fn action(
        name: impl Into<String>,
        device: impl Into<String>,
        argument: impl Into<String>,
    ) -> Self {
        Op::Action {
            name: name.into(),
            device: device.into(),
            argument: argument.into(),
        }
    }

    /// [`Op::StartDevice`].
    pub fn start_device(device: impl Into<String>) -> Self {
        Op::StartDevice {
            device: device.into(),
        }
    }

    /// [`Op::RemoveDevice`].
    pub fn remove_device(device: impl Into<String>) -> Self {
        Op::RemoveDevice {
            device: device.into(),
        }
    }

    /// [`Op::Wire`] between ports `a` and `b` (`(device, port)`): an Ethernet link with no
    /// latency, the default MTU, no cable setup and unimpaired (set with
    /// [`with_latency`](Self::with_latency), [`with_mtu`](Self::with_mtu),
    /// [`with_kind`](Self::with_kind), [`with_cable_setup`](Self::with_cable_setup) and
    /// [`with_impairments`](Self::with_impairments)).
    pub fn wire(a: (impl Into<String>, u32), b: (impl Into<String>, u32)) -> Self {
        Op::Wire {
            a: (a.0.into(), a.1),
            b: (b.0.into(), b.1),
            latency: 0,
            mtu: None,
            kind: LinkKind::Ethernet,
            cable: None,
            impairments: None,
        }
    }

    /// [`Op::Unwire`].
    pub fn unwire(link: impl Into<String>) -> Self {
        Op::Unwire { link: link.into() }
    }

    /// [`Op::SetLink`], changing nothing yet (set with [`with_up`](Self::with_up) and
    /// [`with_latency`](Self::with_latency)).
    pub fn set_link(link: impl Into<String>) -> Self {
        Op::SetLink {
            link: link.into(),
            up: None,
            latency: None,
        }
    }

    /// [`Op::ImpairNamed`], both directions (one with [`with_from`](Self::with_from)).
    pub fn impair_named(link: impl Into<String>, impairments: Impairments) -> Self {
        Op::ImpairNamed {
            link: link.into(),
            from: None,
            impairments,
        }
    }

    /// [`Op::StdinNamed`].
    pub fn stdin_named(device: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Op::StdinNamed {
            device: device.into(),
            bytes: bytes.into(),
        }
    }

    /// [`Op::ControlNamed`].
    pub fn control_named(device: impl Into<String>, call: Control) -> Self {
        Op::ControlNamed {
            device: device.into(),
            call,
        }
    }

    /// Sets an [`Op::Impair`]'s or [`Op::ImpairNamed`]'s sending end (0: `a`, 1: `b`).
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_from(mut self, end: usize) -> Self {
        match &mut self {
            Op::Impair { from, .. } | Op::ImpairNamed { from, .. } => *from = Some(end),
            other => not_for("with_from", other),
        }
        self
    }

    /// Sets an [`Op::AddDevice`]'s config.
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_config(mut self, config: DeviceConfig) -> Self {
        match &mut self {
            Op::AddDevice { config: c, .. } => *c = config,
            other => not_for("with_config", other),
        }
        self
    }

    /// Sets an [`Op::AddDevice`]'s options.
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_options(mut self, options: DeviceOptions) -> Self {
        match &mut self {
            Op::AddDevice { options: o, .. } => *o = options,
            other => not_for("with_options", other),
        }
        self
    }

    /// Adds a cable to an [`Op::AddDevice`] (after those added before).
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_cable(mut self, cable: Cable) -> Self {
        match &mut self {
            Op::AddDevice { wire, .. } => wire.push(cable),
            other => not_for("with_cable", other),
        }
        self
    }

    /// Sets an [`Op::PauseDevice`]'s `link_down`.
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_link_down(mut self, on: bool) -> Self {
        match &mut self {
            Op::PauseDevice { link_down, .. } => *link_down = on,
            other => not_for("with_link_down", other),
        }
        self
    }

    /// Sets an [`Op::Wire`]'s or [`Op::SetLink`]'s latency.
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_latency(mut self, ns: Nanos) -> Self {
        match &mut self {
            Op::Wire { latency, .. } => *latency = ns,
            Op::SetLink { latency, .. } => *latency = Some(ns),
            other => not_for("with_latency", other),
        }
        self
    }

    /// Sets an [`Op::SetLink`]'s carrier.
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_up(mut self, on: bool) -> Self {
        match &mut self {
            Op::SetLink { up, .. } => *up = Some(on),
            other => not_for("with_up", other),
        }
        self
    }

    /// Sets an [`Op::Wire`]'s MTU.
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_mtu(mut self, bytes: u32) -> Self {
        match &mut self {
            Op::Wire { mtu, .. } => *mtu = Some(bytes),
            other => not_for("with_mtu", other),
        }
        self
    }

    /// Sets what an [`Op::Wire`] carries.
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_kind(mut self, link_kind: LinkKind) -> Self {
        match &mut self {
            Op::Wire { kind, .. } => *kind = link_kind,
            other => not_for("with_kind", other),
        }
        self
    }

    /// Sets an [`Op::Wire`]'s cable setup value ([`LinkMut::cable_setup`]).
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_cable_setup(mut self, setup: ExtValue) -> Self {
        match &mut self {
            Op::Wire { cable, .. } => *cable = Some(setup),
            other => not_for("with_cable_setup", other),
        }
        self
    }

    /// Sets an [`Op::Wire`]'s impairments by sending end (from `a`, then from `b`).
    ///
    /// # Panics
    ///
    /// On any other op.
    pub fn with_impairments(mut self, impairments: [Impairments; 2]) -> Self {
        match &mut self {
            Op::Wire { impairments: i, .. } => *i = Some(impairments),
            other => not_for("with_impairments", other),
        }
        self
    }
}

#[track_caller]
fn not_for(method: &str, op: &Op) -> ! {
    panic!("Op::{method} does not apply to {op:?}")
}

impl Op {
    /// Whether the network (not the executor) applies it: topology and name-resolved ops.
    fn is_network_op(&self) -> bool {
        matches!(
            self,
            Op::AddDevice { .. }
                | Op::StopDevice { .. }
                | Op::PauseDevice { .. }
                | Op::ResumeDevice { .. }
                | Op::CrashDevice { .. }
                | Op::Action { .. }
                | Op::StartDevice { .. }
                | Op::RemoveDevice { .. }
                | Op::Wire { .. }
                | Op::Unwire { .. }
                | Op::SetLink { .. }
                | Op::ImpairNamed { .. }
                | Op::StdinNamed { .. }
                | Op::ControlNamed { .. }
                | Op::Extension(_)
                | Op::ExtensionAt { .. }
        )
    }
}

impl<R: Runtime + ?Sized> OpTarget for Network<'_, R> {
    fn running(&self, name: &str) -> std::result::Result<DeviceId, OpError> {
        let id = self
            .live_device(name)
            .ok_or_else(|| OpError::NoDevice(name.to_owned()))?;
        match self.devices[id.0].phase {
            DevicePhase::Running => Ok(id),
            _ => Err(OpError::NotRunning(name.to_owned())),
        }
    }

    fn phase(&self, name: &str) -> Option<DevicePhase> {
        self.live_device(name).map(|d| self.devices[d.0].phase)
    }

    fn add_op(&mut self, op: Op, placement: Placement) -> Result<usize> {
        Network::add_op(self, op, placement)
    }

    fn require_export(&self, device: DeviceId, export: &str) -> Result<()> {
        Network::require_export(self, device, export)
    }

    fn device_name(&self, device: DeviceId) -> &str {
        &self.devices[device.0].name
    }

    fn journal_event(&self, device: &str, at: Nanos, kind: &str, fields: Vec<(&str, String)>) {
        Network::journal_event(self, device, at, kind, fields);
    }

    fn control(&mut self, op: Option<usize>, device: DeviceId, call: Box<dyn ControlCall>) {
        let answer = call.answer();
        self.devices[device.0].inbox.push(Command::Control(call));
        if let Some(op) = op {
            self.exec.set_op_reply(op, answer);
        }
    }

    fn extension_any(&mut self, type_id: TypeId) -> Option<&mut dyn Any> {
        self.extensions
            .iter_mut()
            .map(|e| &mut **e as &mut dyn Any)
            .find(|e| (**e).type_id() == type_id)
    }
}

/// Where an operator event goes in the queue.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Placement {
    /// Immediately before this event (several in placement order); unreached if it never
    /// occurs.
    Before(EventKey),
    /// At the start of instant `t`, before every event at `t`.
    StartOf(Nanos),
    /// At the end of instant `t`, after every event at `t`.
    EndOf(Nanos),
}

/// A control call cannot run in a paused device: refused, and the network goes on.
fn refuse_paused(record: &DeviceRecord) -> Result<()> {
    match record.phase {
        DevicePhase::Paused => Err(Error::Refused(format!(
            "`{}` is paused: it answers no control call until it resumes",
            record.name
        ))),
        _ => Ok(()),
    }
}

fn placement_is_timed(key: &EventKey) -> bool {
    key.levels[0].pre == 0
}

/// Refuses a link end other than 0, 1 or both (`None`).
fn check_end(from: Option<usize>) -> Result<()> {
    match from {
        Some(end) if end > 1 => Err(Error::Refused(format!(
            "a link has ends 0 and 1, not {end}"
        ))),
        _ => Ok(()),
    }
}

/// Converts and checks a device's `ports()` answer: unique ids and 6-byte MACs.
fn check_ports(device: &str, ports: Vec<DeclaredPort>) -> Result<Vec<PortInfo>> {
    let bad = |reason: String| Error::BadPorts {
        device: device.to_owned(),
        reason,
    };
    let mut out: Vec<PortInfo> = Vec::with_capacity(ports.len());
    for p in ports {
        if out.iter().any(|q| q.id == p.id) {
            return Err(bad(format!("port id {} is declared twice", p.id)));
        }
        let mac = match p.mac {
            None => None,
            Some(bytes) => match <[u8; 6]>::try_from(bytes.as_slice()) {
                Ok(octets) => Some(MacAddr::new(octets)),
                Err(_) => {
                    return Err(bad(format!(
                        "port {} has a {}-byte MAC (want 6)",
                        p.id,
                        bytes.len()
                    )));
                }
            },
        };
        out.push(PortInfo {
            id: p.id,
            name: p.name,
            mac,
            mtu: p.mtu,
        });
    }
    Ok(out)
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
