//! wasmnet-core: the runtime-agnostic simulation core.
//!
//! Everything that makes a network deterministic, without any Wasm runtime: the virtual clock
//! and the one event queue, the multi-actor executor, the patch panel with its link model, pcap
//! taps and frame log, the journal, captured stdio, seeded entropy and the [`Network`] builder.
//! A [`Runtime`] backend supplies the devices: it instantiates a component, answers its
//! `ports()`, and hands back one actor future that drives the device from its [`Inbox`].
//! `wasmnet-host` is the wasmtime backend and `wasmnet-web` the one for a browser's own
//! engine. This crate builds for `wasm32-unknown-unknown`.
//!
//! The design notes in `docs/design/` explain what the private modules implement; start with
//! `docs/README.md`.
//!
//! # Who uses what
//!
//! The API serves four audiences.
//!
//! **Building and running a network** (most users do this through `wasmnet-host`, whose
//! `Network` is this [`Network`] with wasmtime as its runtime):
//! [`Network`] (`device*`, `link`, `schedule_link_state`, `run_until_quiescent`, `run_until`,
//! `journal`, `pcap`, `frames`, `counters`), [`DeviceConfig`], [`DeviceOptions`], [`DeviceId`],
//! [`PortRef`], [`LinkId`], [`LinkMut`] (with a link's [`Impairments`]: rate, transmit queue,
//! seeded loss and jitter, `docs/design/links.md`), [`SimConfig`], [`Guard`], [`Outcome`],
//! [`Error`], the records ([`JournalEntry`], [`Record`], [`FrameRecord`], [`FrameFate`],
//! [`LinkStats`], [`LinkTransition`]) and [`pcap`] to read captures back. Changing a running
//! network (**operator events: embedder surface, unstable**):
//! [`Op`] and [`Placement`] through [`Network::add_op`], [`OpState`], [`Network::run_stoppable`]
//! with [`Boundary`] and [`Step`], frame rules ([`FrameAction`], [`Digest`]) and
//! [`Network::set_component_resolver`] for dynamic topology. The event order these follow,
//! including [`EventKey`], [`KeyLevel`], [`Origin`], [`Tag`] and the *pre* number, is
//! `docs/design/event-order.md`; dynamic topology and [`infra`] are
//! `docs/design/topology-and-infra.md`; the executor and its guarantees are
//! `docs/design/async-under-virtual-time.md`.
//!
//! **Writing a backend**: [`Runtime`], [`DeviceContext`], [`DeviceInstance`], [`DeclaredPort`],
//! [`ActorFuture`], [`Command`], [`Inbox`], [`Status`], [`CostMeter`], [`Fault`], [`Detail`],
//! [`Wire`], [`JournalEnd`], [`OutputCapture`], [`InputQueue`], [`InfraEnd`], [`VirtualClock`]
//! (with [`VirtualClock::poll_by`] and [`VirtualClock::set_poll`]), [`derive_seed`], [`SimRng`]
//! and [`block_on`]. The contract is `docs/design/runtime-and-extensions.md`.
//!
//! **Multi-site runs** (embedder surface, unstable): [`sites`] ([`sites::SiteSync`],
//! [`sites::Msg`], [`sites::merge`]), with
//! [`Network::remote_device`], [`Network::run_before`], [`Network::take_outbox`],
//! [`Network::receive_remote`], [`Network::skip_link_state`], [`RemoteFrame`], [`Tap`] and
//! [`RemoteArrival`]. The protocol and its wire format are `docs/design/sites.md`.
//!
//! **Extensions** (embedder surface, unstable): [`ext`] ([`NetworkExtension`],
//! [`ext::CableModel`] with [`CableKind`] and
//! [`LinkKind`], [`ext::ControlCall`] with [`Control`], [`ext::ExtOp`] with [`ExtensionOp`],
//! [`ExtOptions`], [`ExtValue`], [`DeviceExt`]), registered with [`Network::add_extension`],
//! [`Network::register_cable`] and called through [`Network::control`] or [`Op`]; plus
//! [`TransmitHook`]. Their ordering rules are `docs/design/runtime-and-extensions.md`. The
//! control-call traits have one implementation here, [`commands`]; the others none.
//!
//! **Device commands**: [`commands`] ([`DeviceCommand`], [`CommandCall`]): text commands into a
//! device's `wasmnet:control/commands` export (a router's `route-add`), between runs
//! ([`Network::command`]), as an operator event ([`Op::Control`]) or from an in-world
//! controller (`wasmnet:infra/devices.control`). See `docs/design/topology-and-infra.md`.
//!
//! **Embedder surface, unstable** marks what is public for embedders that build tooling on the
//! core (operator events, multi-site runs, extension points): it works and is tested, but it
//! may change between versions without notice. The rest is the core API.
//!
//! Module map: `clock` (virtual time + the event queue), `exec` (executors), `device` (a
//! device's command inbox and call status), `link` (patch panel), `network` (builder API and the
//! [`Runtime`] trait), `ext` (extension points: network extensions, cable kinds, control calls,
//! extension ops), `commands` (device commands), `journal` (device log records), `output` (captured stdout/stderr), `input`
//! (stdin), `config` (device configuration), `rng` (seeded PRNG), `pcap` (a small pcap-ng
//! reader), `digest` (causal digests), `infra` (`wasmnet:infra`), `sites` (multi-site runs).
//! `clock`, `exec`, `device`, `link`, `network`, `output`, `input`, `config` and `rng` are
//! private: their items are re-exported here, and where an item's docs say "see the module
//! docs" (`clock`'s [`Origin`] and [`EventKey`]), `docs/design/event-order.md` has that
//! explanation.

#![deny(unsafe_code)]

mod clock;
pub mod commands;
mod config;
mod device;
pub mod digest;
mod exec;
pub mod ext;
pub mod infra;
mod input;
pub mod journal;
mod link;
mod network;
mod output;
pub mod pcap;
mod rng;
pub mod sites;

use std::any::Any;
use std::fmt;
use std::time::Duration;

pub use clock::{
    Ctx, EventKey, HOST_DEVICE, KEY_DEPTH, KeyLevel, Nanos, Origin, Sleep, Tag, VirtualClock,
};
pub use commands::{COMMANDS_EXPORT, CommandAnswer, CommandCall, DeviceCommand};
pub use config::DeviceConfig;
pub use device::{Command, CostMeter, CountersReply, DeviceCost, Inbox, Snapshot, Status};
pub use digest::Digest;
pub use exec::{ActorFuture, Boundary, OpState, Stalled, Stats, Step, block_on};
pub use ext::{CableKind, Control, DeviceExt, ExtOptions, ExtValue, ExtensionOp, NetworkExtension};
pub use infra::{Infra, InfraEnd};
pub use input::InputQueue;
pub use journal::{JournalEnd, JournalEntry, Level, Record, Stream};
pub use link::{
    DEFAULT_QUEUE, DropReason, FrameAction, FrameFate, FrameRecord, Impairments, LinkInfo,
    LinkKind, LinkStats, LinkTransition, PPM, PortInfo, RemoteArrival, RemoteFrame, Tap, Transmit,
    TransmitHook, Wire,
};
pub use network::{
    CREATOR_RANGE, Cable, ComponentResolver, DeclaredPort, DeviceContext, DeviceId, DeviceInstance,
    DeviceOptions, DevicePhase, Instantiate, LinkId, LinkMut, Network, Op, Placement, PortRef,
    Records, Runtime,
};
pub use output::{CAPTURE_LIMIT, OutputCapture};
pub use rng::{SimRng, derive_seed};

/// Default wall-clock reading at virtual time 0: 2026-01-01T00:00:00Z.
pub const DEFAULT_WALL_EPOCH: Duration = Duration::from_secs(1_767_225_600);

/// A runtime-specific value carried through the sim untouched (a backend's error or trap
/// code), so the backend can recover it: `detail.downcast_ref::<wasmtime::Trap>()`.
pub struct Detail(Box<dyn Any + Send + Sync>);

impl Detail {
    pub fn new(value: impl Any + Send + Sync) -> Self {
        Self(Box::new(value))
    }

    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref()
    }

    /// The value, if it is a `T`; otherwise the detail back.
    pub fn downcast<T: Any>(self) -> Result<T, Self> {
        self.0.downcast().map(|b| *b).map_err(Self)
    }
}

impl fmt::Debug for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Detail(..)")
    }
}

/// Why a device's actor stopped: a guest trap or a host-detected contract violation.
#[derive(Debug)]
pub struct Fault {
    /// Human-readable, as the backend formats it (it ends up in error messages and run records).
    pub message: String,
    /// The backend's trap code, if any (e.g. `wasmtime::Trap`).
    pub detail: Option<Detail>,
}

impl Fault {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(message: impl Into<String>, detail: impl Any + Send + Sync) -> Self {
        Self {
            message: message.into(),
            detail: Some(Detail::new(detail)),
        }
    }
}

/// Errors from the simulation core and from the runtime backends built on it (`wasmnet-host`
/// returns this type too). Backend values ride along as a [`Detail`]: read them with
/// [`Error::detail`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The runtime backend failed to compile, link or instantiate a component, or a command
    /// trapped. `detail` holds the backend's own error (e.g. `wasmtime::Error`).
    #[error("{message}")]
    Runtime {
        message: String,
        detail: Option<Detail>,
    },
    /// The component exports neither `wasi:cli/run@0.2.x` nor `wasi:cli/run@0.3.x`, so it
    /// cannot run as a command.
    #[error("component `{0}` does not export wasi:cli/run")]
    NotACommand(String),
    /// The peer site of a multi-site run broke the lockstep protocol.
    #[error(transparent)]
    SiteSync(#[from] sites::SyncError),
    /// Nothing is queued and every store is idle, yet the host still awaits these calls, given as
    /// `(component, call)`. They can never finish.
    #[error(
        "deadlock at t={at}ns: nothing is queued, yet these calls can never finish: {outstanding:?}"
    )]
    Deadlock {
        at: Nanos,
        outstanding: Vec<(String, String)>,
    },
    /// A device trapped (a "device crash"), including the fuel guard. `detail` is the backend's
    /// trap code, `None` for host-detected contract violations.
    #[error("device `{device}` crashed at t={at}ns: {message}")]
    Trap {
        device: String,
        at: Nanos,
        detail: Option<Detail>,
        message: String,
    },
    /// A device was polled more than [`Guard::max_polls_per_instant`] times without virtual
    /// time advancing (a busy-yield or a device that keeps asking for `poll` at `now`).
    #[error("device `{device}` ran away at t={at}ns: more than {polls} polls in one instant")]
    Runaway {
        device: String,
        at: Nanos,
        polls: u32,
    },
    /// The paranoid round found work after the executor had decided everyone was idle.
    #[error("missed wake: device `{device}` had work at t={at}ns after the executor saw it idle")]
    MissedWake { device: String, at: Nanos },
    /// Device names key RNG seeds and pcap names, so they must be unique.
    #[error("a device named `{0}` already exists")]
    DuplicateDevice(String),
    /// Each port can be on one link only.
    #[error("port {device}:{port} is already wired")]
    PortInUse { device: String, port: u32 },
    /// The port is not among the ones the device declared in `ports()`.
    #[error("port {device}:{port} does not exist (the device declares ports {declared:?})")]
    UnknownPort {
        device: String,
        port: u32,
        declared: Vec<u32>,
    },
    /// The device's `ports()` answer is malformed (duplicate ids, a MAC that is not 6 bytes).
    #[error("device `{device}` declared invalid ports: {reason}")]
    BadPorts { device: String, reason: String },
    /// A previous run of this network failed; its state is no longer meaningful.
    #[error("the network already failed in an earlier run")]
    Halted,
    /// A request the sim core cannot honour as asked (an operator event in the past, in a
    /// split network, ...); nothing changed.
    #[error("refused: {0}")]
    Refused(String),
}

impl Error {
    /// The backend's value this error carries, if any: a [`Error::Runtime`]'s error or a
    /// [`Error::Trap`]'s trap code (`err.detail()?.downcast_ref::<wasmtime::Trap>()`).
    pub fn detail(&self) -> Option<&Detail> {
        match self {
            Error::Runtime { detail, .. } | Error::Trap { detail, .. } => detail.as_ref(),
            _ => None,
        }
    }
}

/// Result alias for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Normal end states of a network run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing is queued, every store is idle and no host call is outstanding. `parked` lists
    /// devices whose guest still has live tasks (e.g. a stack loop waiting for frames). That is
    /// fine: nothing the host awaits is pending. `daemons` lists the apps' `run` calls that are
    /// still running (`<device>: app-<name>.run`, e.g. a server waiting for requests): they
    /// never count as a deadlock.
    Quiescent {
        at: Nanos,
        parked: Vec<String>,
        daemons: Vec<String>,
    },
    /// Stopped at the requested deadline with `pending_events` still queued. Resumable.
    Deadline { at: Nanos, pending_events: usize },
}

/// Runaway guards. All of them are deterministic: they trip at the same virtual instant and
/// with the same error on every replay.
#[derive(Clone, Copy, Debug)]
pub struct Guard {
    /// Fuel each device store gets at the start of every virtual instant it runs in, unless
    /// the device has its own budget ([`DeviceOptions::fuel_per_instant`]). A backend
    /// without fuel metering ignores it.
    pub fuel_per_instant: u64,
    /// Max actor polls of one device within one virtual instant.
    pub max_polls_per_instant: u32,
    /// After each idle round, poll every device once more and fail with
    /// [`Error::MissedWake`] if that finds work (a debug check on the runtime's wakers).
    pub paranoid: bool,
}

impl Default for Guard {
    fn default() -> Self {
        Self {
            fuel_per_instant: 50_000_000,
            max_polls_per_instant: 10_000,
            paranoid: false,
        }
    }
}

/// Parameters that fully determine a simulation's nondeterminism.
#[derive(Clone, Debug)]
pub struct SimConfig {
    /// Root seed; per-component RNG seeds derive from `(seed, component name)`.
    pub seed: u64,
    /// Wall-clock reading at virtual time 0.
    pub wall_epoch: Duration,
}

impl SimConfig {
    /// A config with `seed` and the default wall epoch.
    pub fn seeded(seed: u64) -> Self {
        Self {
            seed,
            wall_epoch: DEFAULT_WALL_EPOCH,
        }
    }
}
