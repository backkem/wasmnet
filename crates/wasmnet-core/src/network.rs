//! The network builder: devices, links, scripted link changes and a deterministic run, over any
//! [`Runtime`] backend.
//!
//! The network owns everything deterministic: the clock and queue, the executor, the patch
//! panel, the journal and captured stdio. A backend only turns a component into a running
//! device: it instantiates it with the handles in a [`DeviceContext`], answers its `ports()`,
//! and returns one actor future that turns [`Command`]s from the device's inbox into export
//! calls (`docs/design/async-under-virtual-time.md`).

use std::any::{Any, TypeId};
use std::sync::Arc;

use crate::clock::{DeviceIdx, EventKey, HOST_DEVICE, Nanos, Tag, VirtualClock};
use crate::config::DeviceConfig;
use crate::device::{Command, CountersReply, Inbox, Status};
use crate::digest::Digest;
use crate::exec::{ActorFuture, Boundary, CoreOp, Executor, Flow, OpState, Stats, Step};
use crate::ext::{
    CableKind, CableModel, Control, ControlCall, DeviceExt, DeviceSetup, ExtOptions, ExtValue,
    ExtensionOp, NetworkExtension, OpContext, OpError, OpTarget, SetupOrigin,
};
use crate::infra::{Infra, InfraEnd, Phase};
use crate::journal::{Journal, JournalEnd, JournalEntry, Stream};
use crate::link::{
    ConnectError, FrameRecord, LinkInfo, LinkStats, LinkTransition, Panel, PortInfo, RemoteArrival,
    RemoteFrame, Tap, Wire,
};
use crate::link::{FrameAction, Impairments, LinkKind, TransmitHook};
use crate::output::OutputCapture;
use crate::{Error, Guard, Outcome, Result, SimConfig};
use wasmnet_wire::MacAddr;

/// A runtime backend: turns a component into a running network device.
pub trait Runtime {
    /// What a device is made from (wasmtime: a compiled `Component`).
    type Component: ?Sized;

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
}

/// Everything a backend needs to run one device deterministically.
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
    /// Options of the network's extensions, by type: where an embedder's grant of a capability
    /// its extension serves goes (embedder surface, unstable).
    pub ext: ExtOptions,
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
    /// Links its stop took down (a start brings them up again).
    downed: Vec<usize>,
}

/// What a device is doing (its status under operator events).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevicePhase {
    Running,
    /// Stopped by an operator event: no store, its links down, its name kept.
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
    /// How devices created while the network runs are numbered; fixed at the first creation.
    numbering: Option<Numbering>,
    /// The links created while the network ran (operator events, controllers' cables), with
    /// the tag of the processing context that created each, in creation order.
    created_links: Vec<(usize, Tag)>,
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
            numbering: None,
            created_links: Vec::new(),
        };
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

    /// Registers what links of cable kind `kind` carry ([`LinkMut::kind`]`(LinkKind::Cable)`),
    /// replacing an earlier model of that kind.
    ///
    /// Embedder surface, unstable (extension points, [`crate::ext`]).
    pub fn register_cable(&mut self, kind: CableKind, model: Arc<dyn CableModel>) {
        self.panel.register_cable(kind, model);
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
        self.register(idx, number, name, config, options, instance, handles, false)?;
        if let Some(rank) = rank {
            self.take_number(rank);
        }
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
    fn check_grant(
        &self,
        name: &str,
        options: &DeviceOptions,
        remote: bool,
    ) -> std::result::Result<(), String> {
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
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            inbox: inbox.clone(),
            status: status.clone(),
            fuel_per_instant: options
                .fuel_per_instant
                .unwrap_or(self.guard.fuel_per_instant),
            infra: options
                .infra
                .then(|| self.infra.end(name, options.infra_prefix.clone())),
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
        let id = self.panel.connect(ea, eb, 0).map_err(|e| match e {
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
        let stopped = [ea, eb]
            .into_iter()
            .find(|&(d, _)| self.devices[d].phase != DevicePhase::Running);
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
                    if let Err(message) = self.apply_change(Some(op), change, at) {
                        self.exec.fail_op(op, message);
                    }
                }
                Flow::Derived(n) => {
                    let at = self.clock.now();
                    self.apply_derived(n, at)?;
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
        if self.devices[idx].phase != DevicePhase::Running {
            return;
        }
        self.stop_device(idx, at);
        let name = self.devices[idx].name.clone();
        let message = self.runtime.summarize(&message);
        self.infra.crashed(&name, &message, at);
        self.journal_event(&name, at, "device-crashed", vec![("message", message)]);
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
        let result = if current.as_deref() == Some(req.uid.as_str()) {
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

    /// The far device of a cable in creation `req` that runs on another site: a placeholder,
    /// or a name only a controller on another site may create (its `infra_prefix`).
    fn cable_to_another_site(&self, req: &crate::infra::Request) -> Option<String> {
        use crate::infra::Verb;
        let (Verb::Create(spec) | Verb::Recreate(spec)) = &req.verb else {
            return None;
        };
        spec.wire
            .iter()
            .find(|c| match self.live_device(&c.device) {
                Some(d) => self.devices[d.0].remote,
                None => self.devices.iter().any(|d| {
                    d.remote
                        && d.options.infra
                        && d.phase != DevicePhase::Removed
                        && d.options
                            .infra_prefix
                            .as_deref()
                            .is_some_and(|p| c.device.starts_with(p))
                }),
            })
            .map(|c| c.device.clone())
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
        match &req.verb {
            Verb::Create(spec) | Verb::Recreate(spec) => {
                if matches!(req.verb, Verb::Recreate(_)) && phase.is_some() {
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
                let wire = self.cables(&spec.wire)?;
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
            Verb::Stop if phase == Some(DevicePhase::Running) => {
                self.apply_change(None, Op::StopDevice { device: name }, at)
            }
            Verb::Remove if phase.is_some() => {
                self.apply_change(None, Op::RemoveDevice { device: name }, at)
            }
            // Served in this event's rounds; the device's refusal reaches the table from its
            // answer (`CommandCall::finish`).
            Verb::Control(command) => {
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
            _ => Ok(()),
        }
    }

    /// A derived creation's cables, far ports resolved: a cable to a device without a port
    /// takes its first free declared port (in order; none twice in one request).
    fn cables(&self, wire: &[crate::infra::CableReq]) -> std::result::Result<Vec<Cable>, String> {
        let mut taken: Vec<(usize, u32)> = Vec::new();
        let mut out = Vec::new();
        for c in wire {
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
            });
        }
        Ok(out)
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
                // The far ends must exist before anything is created.
                let mut ends = Vec::new();
                for c in &wire {
                    let d = self
                        .live_device(&c.to_device)
                        .ok_or_else(|| format!("wire: no device `{}`", c.to_device))?;
                    ends.push((c.port, d.port(c.to_port), c.latency, c.mtu));
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
                let instance = self.resolve_instantiate(&component, context)?;
                self.register(
                    idx, number, &name, config, options, instance, handles, false,
                )
                .map_err(|e| e.to_string())?;
                self.take_number(rank);
                self.devices[idx].created = Some(created);
                self.devices[idx].component = Some(component.clone());
                self.infra_added(idx, self.applying);
                // A controller's device crashes alone: a trap stops it, not the network.
                if self.applying.is_some() {
                    self.exec.set_contain(idx, true);
                }
                self.journal_event(&name, at, "device-added", vec![("component", component)]);
                // Its cables, before it first runs (this op's rounds come after).
                for (port, far, latency, mtu) in ends {
                    let tag = self.clock.peek_tag();
                    let link = self
                        .connect(DeviceId(idx).port(port), far)
                        .map_err(|e| format!("`{name}` was added, but: {e}"))?;
                    self.created_links.push((link.0, tag));
                    self.panel.set_latency(link.0, latency);
                    if let Some(mtu) = mtu {
                        self.panel.set_mtu(link.0, mtu);
                    }
                    let l = self.panel.link_info(link.0).name;
                    self.journal_event(&name, at, "link-added", vec![("link", l)]);
                }
            }
            Op::StopDevice { device } => {
                let id = running(self, &device)?;
                self.stop_device(id.0, at);
                self.infra.set_phase(&device, Phase::Stopped, at);
                self.journal_event(&device, at, "device-stopped", Vec::new());
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
                let component = d
                    .component
                    .clone()
                    .ok_or_else(|| format!("`{device}`'s component is not known to the network"))?;
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
                let instance = self.resolve_instantiate(&component, context)?;
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
            }
            Op::RemoveDevice { device } => {
                let id = self
                    .live_device(&device)
                    .ok_or_else(|| format!("no device `{device}`"))?;
                if self.devices[id.0].phase == DevicePhase::Running {
                    self.stop_device(id.0, at);
                }
                for l in self.panel.links_of(id.0) {
                    self.unwire(l, at);
                }
                self.devices[id.0].phase = DevicePhase::Removed;
                self.devices[id.0].downed.clear();
                self.infra.removed(&device, at);
                self.journal_event(&device, at, "device-removed", Vec::new());
            }
            Op::Wire {
                a,
                b,
                latency,
                mtu,
                kind,
                cable,
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
                self.panel.set_latency(link.0, latency);
                if let Some(mtu) = mtu {
                    self.panel.set_mtu(link.0, mtu);
                }
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
                let id = running(self, &device)?;
                self.devices[id.0].inbox.push(Command::Stdin(bytes));
            }
            Op::Extension(ext) => {
                ext.apply(&mut OpContext {
                    at,
                    op,
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

    /// Instantiates `component` (a catalog name) with `context`, through the resolver.
    fn resolve_instantiate(
        &self,
        component: &str,
        context: DeviceContext,
    ) -> std::result::Result<DeviceInstance, String> {
        let resolver = self
            .resolver
            .as_ref()
            .ok_or("this network has no component catalog")?;
        let runtime = self.runtime;
        let mut context = Some(context);
        resolver(component, &mut |c| {
            let ctx = context
                .take()
                .ok_or_else(|| Error::Refused("instantiated twice".to_owned()))?;
            runtime.instantiate(ctx, c)
        })
        .map_err(|e| e.to_string())
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
    }

    /// Sets link `l`'s carrier at `at`; running ends get `link-state`. Whether it changed.
    fn carrier(&mut self, l: usize, at: Nanos, up: bool) -> bool {
        let Some(ends) = self.panel.set_up(&self.clock, at, l, up) else {
            return false;
        };
        for (device, port) in ends {
            if self.devices[device].phase == DevicePhase::Running {
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
                if self.devices[device].phase == DevicePhase::Running {
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
    /// flight when the link went down, or taken by its seeded loss) appear outbound only.
    pub fn pcap(&self, link: LinkId) -> Vec<u8> {
        self.panel.pcap(link.0)
    }

    /// Every transmission on a wired port so far, in transmit order, with its fate.
    pub fn frames(&self) -> Vec<FrameRecord> {
        self.panel.frames()
    }

    /// Every link up/down change so far (scripted ones; creation is not a transition).
    pub fn link_transitions(&self) -> Vec<LinkTransition> {
        self.panel.transitions()
    }

    /// Frame and byte counters for the link.
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
                Op::Stdin { device, .. } | Op::Control { device, .. } => Some(*device),
                Op::Inject { from, .. } => Some(from.device),
                _ => None,
            };
            match (device, &placement) {
                (Some(d), Placement::StartOf(_) | Placement::EndOf(_)) => self.devices[d.0].remote,
                _ => {
                    return Err(Error::Refused(
                        "a split (multi-site) network takes only timed operator events at a \
                         device (stdin, a control call, an injected frame)"
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
                if matches!(op, Op::AddDevice { .. } | Op::StartDevice { .. })
                    && self.resolver.is_none()
                {
                    return Err(Error::Refused(
                        "this network has no component catalog: it cannot create devices"
                            .to_owned(),
                    ));
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
}

/// An operator event the sim core applies (`docs/design/event-order.md`).
///
/// Embedder surface, unstable (operator events).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Op {
    /// A carrier change of a whole link.
    LinkState { link: LinkId, up: bool },
    /// A link's one-way latency, for frames transmitted from then on.
    Latency { link: LinkId, ns: Nanos },
    /// A link's impairments (`docs/design/links.md`), for frames transmitted from then on: the
    /// direction sent from end `from` (0: `a`, 1: `b`, as in [`LinkInfo::ends`]), or both with
    /// `None`. Frames already queued keep their schedule.
    Impair {
        link: LinkId,
        from: Option<usize>,
        impairments: Impairments,
    },
    /// A frame transmitted from a port, as if its device had sent it.
    Inject { from: PortRef, bytes: Vec<u8> },
    /// Bytes for the device's stdin, appended at the op's instant ([`crate::InputQueue`]).
    Stdin { device: DeviceId, bytes: Vec<u8> },
    /// A control call into one of the device's optional exports, served in the op's own
    /// processing context (an extension's write, probe or the like). Refused when added if the
    /// device does not report the call's export; the device's own refusal is the op's state.
    Control { device: DeviceId, call: Control },
    // ---- dynamic topology (docs/design/topology-and-infra.md): resolved by name when applied
    /// A new device from the catalog (the network's component resolver), created in the op's
    /// own processing context: its first poll, `start` and seeds follow from there.
    AddDevice {
        name: String,
        component: String,
        config: DeviceConfig,
        options: DeviceOptions,
        /// Links wired in the same op, before the device first runs (a cable plugged in
        /// before power-on).
        wire: Vec<Cable>,
    },
    /// Stops a running device: its store is dropped and its links go down (the far ends see
    /// the carrier drop). Its name, ports and links stay.
    StopDevice { device: String },
    /// Starts a stopped device again from its component and config (a fresh instance), and
    /// brings up the links its stop took down.
    StartDevice { device: String },
    /// Removes a device: stopped if running, unwired, its name free for a new device.
    RemoveDevice { device: String },
    /// Wires two free ports (`(device, port)`) with a new link, up at once.
    Wire {
        a: (String, u32),
        b: (String, u32),
        latency: Nanos,
        mtu: Option<u32>,
        /// What it carries (Ethernet frames or a registered cable kind).
        kind: LinkKind,
        /// A cable's setup value ([`LinkMut::cable_setup`]).
        cable: Option<ExtValue>,
    },
    /// Unwires a link by name: it goes down and its ports are free again.
    Unwire { link: String },
    /// A link by name (one that an earlier op wires): its carrier and/or latency.
    SetLink {
        link: String,
        up: Option<bool>,
        latency: Option<Nanos>,
    },
    /// [`Op::Impair`] on the link called `link` when the op applies (one that an earlier op
    /// wires); journalled as `link-changed`.
    ImpairNamed {
        link: String,
        from: Option<usize>,
        impairments: Impairments,
    },
    /// [`Op::Stdin`] into the device called `device` when the op applies (a device that an
    /// earlier op creates).
    StdinNamed { device: String, bytes: Vec<u8> },
    /// [`Op::Control`] into the device called `device` when the op applies.
    ControlNamed { device: String, call: Control },
    /// An extension's op ([`crate::ext::ExtOp`]), applied by the network in the op's own
    /// processing context.
    Extension(ExtensionOp),
}

impl Op {
    /// Whether the network (not the executor) applies it: topology and name-resolved ops.
    fn is_network_op(&self) -> bool {
        matches!(
            self,
            Op::AddDevice { .. }
                | Op::StopDevice { .. }
                | Op::StartDevice { .. }
                | Op::RemoveDevice { .. }
                | Op::Wire { .. }
                | Op::Unwire { .. }
                | Op::SetLink { .. }
                | Op::ImpairNamed { .. }
                | Op::StdinNamed { .. }
                | Op::ControlNamed { .. }
                | Op::Extension(_)
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
