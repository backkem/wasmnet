//! Extension points: how capabilities the core does not know enter a network.
//!
//! The core runs networking, scheduling, the journal, stdio, sites and the infra table.
//! Anything else a network offers its devices comes in through these registration points, each
//! called at a fixed place of the core's own flow, so an extension never reorders the event
//! queue or the journal:
//!
//! * [`NetworkExtension`]s, registered on the [`crate::Network`]
//!   ([`crate::Network::add_extension`]; a [`crate::Runtime`] may register its own in
//!   [`crate::Runtime::install`]): per-device handles a backend reads by type ([`DeviceExt`]),
//!   and network-wide state reached with [`crate::Network::extension`].
//! * Per-extension device options ([`ExtOptions`] in [`crate::DeviceOptions::ext`]).
//! * Cable kinds ([`CableModel`], keyed by a [`CableKind`] code): links that carry something
//!   other than Ethernet frames. The patch panel keeps the Ethernet path (pcap, frame log, MTU)
//!   and asks the cable's model what a message does.
//! * Control calls ([`ControlCall`]): a call into a device's optional export, queued in its
//!   inbox like `counters` ([`crate::Command::Control`], [`crate::Network::control`]), and, as an
//!   operator event, [`Control`] ([`crate::Op::Control`], [`crate::Op::ControlNamed`]).
//! * Ops of an extension ([`ExtensionOp`], [`crate::Op::Extension`]): applied by the network in
//!   the op's own processing context through an [`OpContext`].
//!
//! Embedder surface, unstable: everything in this module is public for embedders, and it may
//! change between versions without notice.

use std::any::{Any, TypeId};
use std::fmt;
use std::num::NonZeroU8;
use std::sync::Arc;

use crate::clock::{Nanos, VirtualClock};
use crate::journal::{JournalEnd, Record};
use crate::network::{DeviceId, DeviceOptions};

// ---- typed values --------------------------------------------------------------------------

/// A value an extension keeps in a core data structure (a device option, a cable's setup): any
/// `'static` type that is `Debug + PartialEq + Send + Sync`.
pub trait ExtData: Any + fmt::Debug + Send + Sync {
    /// Whether `other` is a value of the same type and equal to this one.
    fn eq_data(&self, other: &dyn ExtData) -> bool;
}

impl<T: Any + fmt::Debug + PartialEq + Send + Sync> ExtData for T {
    fn eq_data(&self, other: &dyn ExtData) -> bool {
        (other as &dyn Any).downcast_ref::<T>() == Some(self)
    }
}

/// A shared, typed [`ExtData`] value.
#[derive(Clone)]
pub struct ExtValue(Arc<dyn ExtData>);

impl ExtValue {
    pub fn new(value: impl ExtData) -> Self {
        Self(Arc::new(value))
    }

    /// The value, if it is a `T`.
    pub fn get<T: Any>(&self) -> Option<&T> {
        (&*self.0 as &dyn Any).downcast_ref()
    }

    fn type_id(&self) -> TypeId {
        (&*self.0 as &dyn Any).type_id()
    }
}

impl fmt::Debug for ExtValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq for ExtValue {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_data(&*other.0)
    }
}

impl Eq for ExtValue {}

/// Device options of extensions, one value per type (an extension reads its own type), empty
/// by default.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ExtOptions(Vec<ExtValue>);

impl ExtOptions {
    /// Sets the option of `value`'s type, replacing an earlier one.
    pub fn set(&mut self, value: impl ExtData) {
        let value = ExtValue::new(value);
        let id = value.type_id();
        match self.0.binary_search_by(|v| v.type_id().cmp(&id)) {
            Ok(i) => self.0[i] = value,
            Err(i) => self.0.insert(i, value),
        }
    }

    /// With the option of `value`'s type set.
    pub fn with(mut self, value: impl ExtData) -> Self {
        self.set(value);
        self
    }

    /// The option of type `T`, if set.
    pub fn get<T: Any>(&self) -> Option<&T> {
        self.0.iter().find_map(ExtValue::get)
    }

    /// Removes the option of type `T`.
    pub fn remove<T: Any>(&mut self) {
        let id = TypeId::of::<T>();
        self.0.retain(|v| v.type_id() != id);
    }
}

impl fmt::Debug for ExtOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.0).finish()
    }
}

// ---- network extensions ------------------------------------------------------------------------

/// Why a device is being instantiated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupOrigin {
    /// Created by [`crate::Network::device_with_options`] (a device the network was built
    /// with).
    Created,
    /// Added by an operator event or an in-world controller ([`crate::Op::AddDevice`]).
    Added,
    /// A stopped device started again ([`crate::Op::StartDevice`]).
    Restarted,
}

/// The device a [`NetworkExtension::device_setup`] call is about.
pub struct DeviceSetup<'a> {
    /// Its index in the network.
    pub index: usize,
    /// Its name in the network.
    pub name: &'a str,
    pub origin: SetupOrigin,
    pub options: &'a DeviceOptions,
    pub clock: &'a VirtualClock,
    /// Its journal (records under its name).
    pub journal: &'a JournalEnd,
}

/// Per-device handles of the network's extensions, one value per type: what a backend serves
/// the device's extension imports from ([`crate::DeviceContext::ext`]).
#[derive(Default)]
pub struct DeviceExt(Vec<(TypeId, Box<dyn Any + Send + Sync>)>);

impl DeviceExt {
    /// Sets the handle of `value`'s type, replacing an earlier one.
    pub fn insert<T: Any + Send + Sync>(&mut self, value: T) {
        let id = TypeId::of::<T>();
        match self.0.iter_mut().find(|(t, _)| *t == id) {
            Some(slot) => slot.1 = Box::new(value),
            None => self.0.push((id, Box::new(value))),
        }
    }

    /// The handle of type `T`, if an extension set one.
    pub fn get<T: Any>(&self) -> Option<&T> {
        let id = TypeId::of::<T>();
        self.0
            .iter()
            .find(|(t, _)| *t == id)
            .and_then(|(_, v)| v.downcast_ref())
    }
}

/// A network extension: network-wide state plus hooks the network calls at fixed points, in
/// registration order. Reach it with [`crate::Network::extension`].
pub trait NetworkExtension: Any + Send {
    /// A device is being instantiated: put the handles its backend reads into `ext`. Called
    /// first thing when the network builds the device's context: for a created device right
    /// after it entered its setup slot, for an added or restarted one in the op's own context.
    fn device_setup(&mut self, setup: &DeviceSetup<'_>, ext: &mut DeviceExt) {
        let _ = (setup, ext);
    }
}

// ---- cables --------------------------------------------------------------------------------

/// A registered cable kind's stable code (1-255; 0 is Ethernet). It is what the site-sync wire
/// format and the cable registry key on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CableKind(NonZeroU8);

impl CableKind {
    /// The kind with code `code`. Panics on 0 (Ethernet's code).
    pub const fn new(code: u8) -> Self {
        match NonZeroU8::new(code) {
            Some(c) => Self(c),
            None => panic!("cable code 0 is Ethernet"),
        }
    }

    /// The kind's code.
    pub const fn code(self) -> u8 {
        self.0.get()
    }
}

/// One message entering a cable, as its model sees it.
pub struct CableSend<'a> {
    /// The virtual instant of the transmission.
    pub at: Nanos,
    /// The sending end of the link (0 or 1).
    pub end: usize,
    /// The sending device's index and name, and the sending port's id and name.
    pub device: usize,
    pub device_name: &'a str,
    pub port: u32,
    pub port_name: &'a str,
    /// The link's name.
    pub link: &'a str,
    pub message: &'a [u8],
}

/// What a message does to a cable.
pub enum Carry {
    /// Nothing reaches anyone (it was counted).
    Nothing,
    /// The message reaches the other end, unchanged.
    Forward,
    /// These messages reach these ends (0 or 1, in this order), and these records are journalled
    /// on the sending device first.
    Deliver {
        to: Vec<(usize, Vec<u8>)>,
        events: Vec<Record>,
    },
}

/// What a cable kind carries and records (registered with [`crate::Network::register_cable`]).
/// A cable has no pcap and no frame log, never crosses sites, and is counted in its link's
/// [`crate::LinkStats`]; its messages arrive `latency` (plus an operator delay) after they were
/// sent.
pub trait CableModel: Send + Sync + 'static {
    /// The kind's name (`serial`): what descriptions and records of a network call it.
    fn name(&self) -> &'static str;

    /// The state of a new link of this kind named `link` (kept by the patch panel; read with
    /// [`crate::Network::with_cable`]), if the kind keeps any.
    fn new_link(&self, link: &str) -> Option<Box<dyn Any + Send>> {
        let _ = link;
        None
    }

    /// Configures a link's state from a setup value ([`crate::LinkMut::cable_setup`]).
    fn configure(&self, state: &mut (dyn Any + Send), setup: &ExtValue) {
        let _ = (state, setup);
    }

    /// Whether a message is well formed. A malformed one is dropped and counted as oversize,
    /// before anything else.
    fn well_formed(&self, message: &[u8]) -> bool {
        let _ = message;
        true
    }

    /// A message entered the cable (it is counted). Called with the patch panel locked: it may
    /// only update the link's state.
    fn carry(&self, send: &CableSend<'_>, state: Option<&mut (dyn Any + Send)>) -> Carry;

    /// The cable's tap, with the panel unlocked, after a message that was not
    /// [`Carry::Nothing`] and before its deliveries are queued.
    fn tap(&self, send: &CableSend<'_>) {
        let _ = send;
    }
}

// ---- control calls -------------------------------------------------------------------------

/// Where a control call's answer is, as the core sees it.
pub trait ControlAnswer: Send + Sync {
    /// The device answered.
    fn answered(&self) -> bool;
    /// The device's refusal (an operator event's state shows it), if it refused.
    fn refusal(&self) -> Option<String>;
}

/// A control call into a device's optional export, answered into the call's own slot. It
/// travels the device's inbox ([`crate::Command::Control`]) and runs inside the device's live
/// event loop, at the current instant, like `counters`.
pub trait ControlCall: Any + Send + fmt::Debug {
    /// Its name among the device's in-flight calls.
    fn name(&self) -> &str;
    /// The export the device needs for it (only devices that report it get the call).
    fn export(&self) -> &str;
    /// The call may move a stepped device's deadline: a poll at the same instant follows it.
    fn may_reschedule(&self) -> bool;
    /// Its answer slot.
    fn answer(&self) -> Arc<dyn ControlAnswer>;
    /// No backend serves it: answer with the extension's own refusal.
    fn unsupported(self: Box<Self>);
}

/// A control call an operator event makes when it applies (each application gets a fresh call).
pub trait ControlRequest: Any + fmt::Debug + Send + Sync {
    /// The export the device needs ([`ControlCall::export`]).
    fn export(&self) -> &str;
    /// A fresh call.
    fn call(&self) -> Box<dyn ControlCall>;
    /// Whether `other` is the same request.
    fn same(&self, other: &dyn ControlRequest) -> bool;
}

/// A shared [`ControlRequest`] (what [`crate::Op::Control`] carries).
#[derive(Clone)]
pub struct Control(Arc<dyn ControlRequest>);

impl Control {
    pub fn new(request: impl ControlRequest) -> Self {
        Self(Arc::new(request))
    }

    /// The request, if it is an `R`.
    pub fn get<R: Any>(&self) -> Option<&R> {
        (&*self.0 as &dyn Any).downcast_ref()
    }

    pub fn export(&self) -> &str {
        self.0.export()
    }

    pub fn call(&self) -> Box<dyn ControlCall> {
        self.0.call()
    }
}

impl fmt::Debug for Control {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq for Control {
    fn eq(&self, other: &Self) -> bool {
        self.0.same(&*other.0)
    }
}

impl Eq for Control {}

// ---- extension ops -------------------------------------------------------------------------

/// Why an operator event was refused when it applied. Its text is what
/// [`crate::OpState::Failed`] records.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpError {
    /// No live device has this name.
    #[error("no device `{0}`")]
    NoDevice(String),
    /// The device exists but is stopped or removed.
    #[error("`{0}` is not running")]
    NotRunning(String),
    /// The network refused a step of the op.
    #[error(transparent)]
    Network(#[from] crate::Error),
    /// The extension's own reason.
    #[error("{0}")]
    Other(String),
}

impl From<String> for OpError {
    fn from(reason: String) -> Self {
        Self::Other(reason)
    }
}

impl From<&str> for OpError {
    fn from(reason: &str) -> Self {
        Self::Other(reason.to_owned())
    }
}

/// An op of an extension ([`crate::Op::Extension`]): applied by the network in the op's own
/// processing context, like a topology change.
pub trait ExtOp: Any + fmt::Debug + Send + Sync {
    /// Applies the op. An `Err` is the op's refusal ([`crate::OpState::Failed`]).
    fn apply(&self, ctx: &mut OpContext<'_>) -> Result<(), OpError>;
    /// Whether `other` is the same op.
    fn same(&self, other: &dyn ExtOp) -> bool;
}

/// A shared [`ExtOp`].
#[derive(Clone)]
pub struct ExtensionOp(Arc<dyn ExtOp>);

impl ExtensionOp {
    pub fn new(op: impl ExtOp) -> Self {
        Self(Arc::new(op))
    }

    /// The op, if it is an `O`.
    pub fn get<O: Any>(&self) -> Option<&O> {
        (&*self.0 as &dyn Any).downcast_ref()
    }

    pub(crate) fn apply(&self, ctx: &mut OpContext<'_>) -> Result<(), OpError> {
        self.0.apply(ctx)
    }
}

impl fmt::Debug for ExtensionOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq for ExtensionOp {
    fn eq(&self, other: &Self) -> bool {
        self.0.same(&*other.0)
    }
}

impl Eq for ExtensionOp {}

/// What an [`ExtOp`] may do while it applies: find running devices, journal, queue control
/// calls (answered in the op's rounds, their refusal the op's state) and reach the network's
/// extensions.
pub struct OpContext<'a> {
    pub(crate) at: Nanos,
    pub(crate) op: Option<usize>,
    pub(crate) network: &'a mut dyn OpTarget,
}

/// The network's side of an [`OpContext`] (implemented by the network for every runtime).
pub(crate) trait OpTarget {
    fn running(&self, name: &str) -> Result<DeviceId, OpError>;
    fn require_export(&self, device: DeviceId, export: &str) -> crate::Result<()>;
    fn device_name(&self, device: DeviceId) -> &str;
    fn journal_event(&self, device: &str, at: Nanos, kind: &str, fields: Vec<(&str, String)>);
    fn control(&mut self, op: Option<usize>, device: DeviceId, call: Box<dyn ControlCall>);
    fn extension_any(&mut self, type_id: TypeId) -> Option<&mut dyn Any>;
}

impl OpContext<'_> {
    /// The op's virtual instant.
    pub fn at(&self) -> Nanos {
        self.at
    }

    /// The running device called `name` (refused as [`OpError::NoDevice`] or
    /// [`OpError::NotRunning`]).
    pub fn running(&self, name: &str) -> Result<DeviceId, OpError> {
        self.network.running(name)
    }

    /// Refuses (as [`crate::Error::Refused`]) a device that does not report `export`.
    pub fn require_export(&self, device: DeviceId, export: &str) -> crate::Result<()> {
        self.network.require_export(device, export)
    }

    pub fn device_name(&self, device: DeviceId) -> &str {
        self.network.device_name(device)
    }

    /// Journals an event on `device` at the op's instant.
    pub fn journal_event(&self, device: &str, kind: &str, fields: Vec<(&str, String)>) {
        self.network.journal_event(device, self.at, kind, fields);
    }

    /// Queues a control call for `device`; its refusal becomes the op's state.
    pub fn control(&mut self, device: DeviceId, call: Box<dyn ControlCall>) {
        self.network.control(self.op, device, call);
    }

    /// The network's extension of type `T`.
    pub fn extension_mut<T: NetworkExtension>(&mut self) -> Option<&mut T> {
        self.network
            .extension_any(TypeId::of::<T>())
            .and_then(|e| e.downcast_mut())
    }
}
