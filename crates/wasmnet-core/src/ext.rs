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
//! * Embedder actions ([`Action`], [`crate::Network::register_action`], [`crate::Op::Action`]):
//!   a closure of the embedder's, called through an [`OpContext`] when its op applies.
//! * A device's life ([`NetworkExtension::device_life`]): pauses, stops, starts, crashes and
//!   removals, heard right after the network journalled them.
//!
//! Embedder surface, unstable: everything in this module is public for embedders, and it may
//! change between versions without notice.

use std::any::{Any, TypeId};
use std::fmt;
use std::num::NonZeroU8;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::clock::{Nanos, VirtualClock};
use crate::journal::{JournalEnd, Record};
use crate::network::{DeviceId, DeviceOptions};
use crate::value::Value;

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

    /// Sets an option already wrapped (what an [`ExtOption`] parsed), replacing an earlier one
    /// of its type.
    pub fn set_value(&mut self, value: ExtValue) {
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
#[non_exhaustive]
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
    /// The network's root seed: an extension derives its own streams from it
    /// ([`crate::derive_seed`] with the device's name and a stream name of its own).
    pub seed: u64,
}

/// Per-device handles of the network's extensions, one value per type: what a backend serves
/// the device's extension imports from ([`crate::DeviceContext::ext`]); and the servers of the
/// portable interfaces the device is given ([`DeviceExt::serve`]), and its fuel span
/// ([`DeviceExt::fuel_span`]).
#[derive(Default)]
pub struct DeviceExt {
    handles: Vec<(TypeId, Box<dyn Any + Send + Sync>)>,
    servers: Vec<(String, Arc<dyn ImportServer>)>,
    fuel_span: FuelSpan,
}

impl DeviceExt {
    /// The handles of a device the network is setting up, with its fuel span.
    pub(crate) fn with_fuel_span(fuel_span: FuelSpan) -> Self {
        Self {
            fuel_span,
            ..Self::default()
        }
    }

    /// The device's fuel span ([`FuelSpan`]): a server keeps a clone to open and close it.
    /// Every server of the device shares it, and it belongs to this incarnation of the device.
    /// A `DeviceExt` the network did not make (`default()`) has one that never opens.
    pub fn fuel_span(&self) -> &FuelSpan {
        &self.fuel_span
    }

    /// Sets the handle of `value`'s type, replacing an earlier one.
    pub fn insert<T: Any + Send + Sync>(&mut self, value: T) {
        let id = TypeId::of::<T>();
        match self.handles.iter_mut().find(|(t, _)| *t == id) {
            Some(slot) => slot.1 = Box::new(value),
            None => self.handles.push((id, Box::new(value))),
        }
    }

    /// The handle of type `T`, if an extension set one.
    pub fn get<T: Any>(&self) -> Option<&T> {
        let id = TypeId::of::<T>();
        self.handles
            .iter()
            .find(|(t, _)| *t == id)
            .and_then(|(_, v)| v.downcast_ref())
    }

    /// Serves the portable `interface` (its full name with its version, as the device imports
    /// it: `example:pad/notes@0.1.0`) to this device through `server`, replacing an earlier
    /// server of it. Every backend links the interface and hands each of the device's calls to
    /// the server ([`ImportServer`]); a device given no server of an interface it imports
    /// faults at its first call.
    pub fn serve(&mut self, interface: impl Into<String>, server: Arc<dyn ImportServer>) {
        let interface = interface.into();
        match self.servers.iter_mut().find(|(i, _)| *i == interface) {
            Some(slot) => slot.1 = server,
            None => self.servers.push((interface, server)),
        }
    }

    /// The server of `interface` for this device, if an extension set one.
    pub fn server(&self, interface: &str) -> Option<&Arc<dyn ImportServer>> {
        self.servers
            .iter()
            .find(|(i, _)| i == interface)
            .map(|(_, s)| s)
    }

    /// Every interface served to this device, with its server, in the order they were set.
    pub fn servers(&self) -> impl Iterator<Item = (&str, &Arc<dyn ImportServer>)> {
        self.servers.iter().map(|(i, s)| (i.as_str(), s))
    }
}

// ---- fuel spans ----------------------------------------------------------------------------

/// A device's fuel span: a stretch of one instant in which the device's work costs it no fuel,
/// for a server that lets a controller work on the device while it is stopped (a debugger's
/// hold). One per device incarnation, shared by every server of the device
/// ([`DeviceExt::fuel_span`]).
///
/// [`begin`](Self::begin) opens it, [`end`](Self::end) closes it. On a metered backend (wasmtime)
/// the device's fuel when it ends is what it was when it began, whatever device code ran in
/// between (the device's own code between two calls of a server, or export calls others made
/// into it), and that work is in none of its cost figures. While it is open the device runs on
/// an allowance of its own, its fuel per instant, set when the span opens and again at every
/// look the backend takes (every served call and every round of the device's actor). A backend
/// without metering (a page, `fuel(false)`, an unmetered component) changes nothing: the calls
/// answer the same and the span is only a state. Only fuel is spared: the commands and actor
/// polls a span's work takes still count in the device's costs and toward
/// [`crate::Guard::max_polls_per_instant`].
///
/// Rules, the same on every backend:
///
/// * A span lasts at most to the end of the instant it began in: at a later instant it is
///   closed, and the device's fuel is that instant's budget, as always.
/// * A second `begin` while one is open changes nothing (the span keeps the fuel it saved); one
///   `end` closes it, whoever opened it.
/// * The device's stop, crash or removal closes it for good: the handle of that incarnation
///   does nothing after (a device started again has a new one).
/// * Made from inside a served call, a change applies at once (when the call returns to the
///   device); made from anywhere else (an operator event, an action, between runs), it applies
///   at the device's next look, before it runs any code.
///
/// It is not a way to give a device unmetered work of its own: everything the device does while
/// a span is open (its own calls included) is free, so a server opens one only for a stop the
/// device makes to be inspected, and ends it when the stop ends.
///
/// Embedder surface, unstable.
#[derive(Clone)]
pub struct FuelSpan {
    state: Arc<Mutex<SpanState>>,
    /// `None`: a handle of no device (begins nothing).
    clock: Option<VirtualClock>,
}

#[derive(Default)]
struct SpanState {
    /// The instant of the open span.
    open_at: Option<Nanos>,
    /// The device's incarnation ended.
    retired: bool,
}

impl FuelSpan {
    pub(crate) fn new(clock: VirtualClock) -> Self {
        Self {
            state: Arc::default(),
            clock: Some(clock),
        }
    }

    fn state(&self) -> MutexGuard<'_, SpanState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a span at the current instant. `false` if one was open already (nothing changes),
    /// or the handle's device is gone.
    pub fn begin(&self) -> bool {
        let Some(clock) = &self.clock else {
            return false;
        };
        let now = clock.now();
        let mut s = self.state();
        if s.retired || s.open_at == Some(now) {
            return false;
        }
        s.open_at = Some(now);
        true
    }

    /// Closes the open span. `false` if none was open.
    pub fn end(&self) -> bool {
        let open = self.is_open();
        self.state().open_at = None;
        open
    }

    /// A span is open: begun at the current instant, not ended, and the device is still the
    /// one it was begun for.
    pub fn is_open(&self) -> bool {
        let Some(clock) = &self.clock else {
            return false;
        };
        let s = self.state();
        !s.retired && s.open_at == Some(clock.now())
    }

    /// The device's incarnation ended (its stop, crash or removal).
    pub(crate) fn retire(&self) {
        let mut s = self.state();
        s.retired = true;
        s.open_at = None;
    }
}

impl Default for FuelSpan {
    /// A handle of no device: it never opens.
    fn default() -> Self {
        Self {
            state: Arc::default(),
            clock: None,
        }
    }
}

impl fmt::Debug for FuelSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuelSpan")
            .field("open", &self.is_open())
            .finish()
    }
}

/// What happened to a device ([`NetworkExtension::device_life`]): one value per journal record
/// the network makes about the device's life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifeEvent<'a> {
    /// Paused (`device-paused`, [`crate::Op::PauseDevice`]): its store is kept and no longer
    /// runs.
    Paused,
    /// Resumed (`device-resumed`, [`crate::Op::ResumeDevice`]).
    Resumed,
    /// Stopped (`device-stopped`): by an operator event, its controller, or with its owner. Its
    /// store is gone; it may start again.
    Stopped,
    /// Started again after a stop or a crash (`device-started`), with a fresh store.
    Started,
    /// It crashed (`device-crashed`): a trap of its own, its fuel or memory, an extension's
    /// import, or [`crate::Op::CrashDevice`]. Its store is gone; it may start again.
    Crashed {
        /// The one-line message journalled with it.
        message: &'a str,
    },
    /// Removed (`device-removed`), for good: its name is free, and a later device of the same
    /// name is a new device. A controller's recreation (a new spec) is a removal and a new
    /// device.
    Removed,
}

/// The device a [`NetworkExtension::device_life`] call is about.
#[non_exhaustive]
pub struct DeviceLife<'a> {
    /// Its index in the network.
    pub index: usize,
    /// Its name in the network.
    pub name: &'a str,
    /// The instant it happened.
    pub at: Nanos,
    pub event: LifeEvent<'a>,
    /// Its journal (records under its name), after the network's own record.
    pub journal: &'a JournalEnd,
    /// The device is being replaced: this removal, and the stop before it, are part of a
    /// recreation of the device under the same name (an in-world controller applied a new
    /// spec), and the new device is set up right after (`device_setup`, origin
    /// [`SetupOrigin::Added`]). State an extension keeps for the name (a disk) may stay.
    pub replaced: bool,
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

    /// A device paused, resumed, stopped, started again, crashed or was removed. Called right
    /// after the network made the change and journalled its record, in the same processing
    /// context, before anything else (a cascade's devices, the event's rounds): an extension
    /// that journals here comes after the network's record. The device's store is already
    /// dropped for [`LifeEvent::Stopped`], [`LifeEvent::Crashed`] and [`LifeEvent::Removed`]
    /// (a backend's per-store state went with it); for [`LifeEvent::Started`] the new store
    /// exists and has not run yet.
    fn device_life(&mut self, life: &DeviceLife<'_>) {
        let _ = life;
    }

    /// The portable interfaces this extension serves to devices, on every backend. A backend
    /// links them for every device; `device_setup` hands each device the servers of those it
    /// is given ([`DeviceExt::serve`]). The default serves none.
    fn interfaces(&self) -> Vec<Interface> {
        Vec::new()
    }

    /// The device options this extension reads, each with the key it goes by outside Rust
    /// and its parser from a generic value: what a controller's spec, the page's plain objects
    /// and an embedder's own formats set ([`crate::Network::parse_option`]). The default
    /// declares none.
    fn options(&self) -> Vec<ExtOption> {
        Vec::new()
    }

    /// Checks a device's options before the device is created (by the embedder, an operator
    /// event or a controller); an `Err` refuses the creation with that reason. Not called when
    /// a stopped device starts again. The default accepts everything.
    fn check_options(&self, name: &str, options: &DeviceOptions) -> Result<(), String> {
        let _ = (name, options);
        Ok(())
    }

    /// The operator events this extension builds from generic values (the page's plain
    /// objects), by kind ([`crate::Network::parse_op`]). The default builds none.
    fn ops(&self) -> Vec<ExtOpParser> {
        Vec::new()
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
#[non_exhaustive]
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
#[non_exhaustive]
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

    /// The export function this call is a call of, by name: its interface without a version
    /// and the function's name in it, as [`Invocation`] names them. A handler checks it before
    /// it takes the call's [`invocation`](Self::invocation), and gives the call back untouched
    /// when it is not one of its functions. `None` (the default): only a backend's own handler
    /// serves it.
    fn target(&self) -> Option<(&str, &str)> {
        None
    }

    /// The call as a call of its [`target`](Self::target), with its arguments at `now`: how a
    /// backend that calls exports by name (a page, or a typed adapter on wasmtime) serves it
    /// ([`Invocation`]). The handler that serves the call takes it once, after `target`
    /// matched, then answers through [`invoked`](Self::invoked) or
    /// [`unsupported`](Self::unsupported): the call may move its arguments out (a large byte
    /// argument is not copied), so a second call may answer `None`. `None` (the default): only
    /// a backend's own handler serves it.
    fn invocation(&mut self, now: Nanos) -> Option<Invocation> {
        let _ = now;
        None
    }

    /// The device answered the [`invocation`](Self::invocation): `Ok` the function's value (a
    /// `result`'s `ok` value), `Err` a `result`'s `err` value. `config` is what the device's
    /// `wasi:config/store` serves, which a call may replace (a reconfiguration taken in place).
    /// A trap in the device is not an answer: the device faults. The default refuses.
    fn invoked(self: Box<Self>, answer: Result<Value, Value>, config: &mut crate::DeviceConfig) {
        let _ = (answer, config);
        self.unsupported();
    }
}

/// A call of one export function of a device by name: what a control call is to a backend that
/// calls exports by name ([`ControlCall::invocation`]); it owns its arguments, which a backend
/// moves on into the device's call. `interface` is the export's name without
/// a version (`wasmnet:control/commands`), as [`crate::Network::device_exports`] lists it;
/// `function` its name in the interface (`invoke`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Invocation {
    pub interface: String,
    pub function: String,
    pub args: Vec<Value>,
}

impl Invocation {
    pub fn new(
        interface: impl Into<String>,
        function: impl Into<String>,
        args: Vec<Value>,
    ) -> Self {
        Self {
            interface: interface.into(),
            function: function.into(),
            args,
        }
    }
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
    /// The device an op timed at a device concerns ([`crate::Op::ExtensionAt`]).
    pub(crate) device: Option<DeviceId>,
    pub(crate) network: &'a mut dyn OpTarget,
}

/// An embedder action being called ([`crate::Op::Action`], [`crate::Network::register_action`]).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct ActionCall<'a> {
    /// The name it was registered under.
    pub name: &'a str,
    /// The device the op names (its `action` record is journalled on it).
    pub device: &'a str,
    /// The op's argument, as given.
    pub argument: &'a str,
}

/// An embedder action ([`crate::Network::register_action`]): called when an [`crate::Op::Action`]
/// naming it applies. An `Err` is the op's refusal ([`crate::OpState::Failed`]).
pub type Action<'r> =
    Box<dyn FnMut(&mut OpContext<'_>, &ActionCall<'_>) -> Result<(), OpError> + 'r>;

/// The network's side of an [`OpContext`] (implemented by the network for every runtime).
pub(crate) trait OpTarget {
    fn running(&self, name: &str) -> Result<DeviceId, OpError>;
    fn phase(&self, name: &str) -> Option<crate::DevicePhase>;
    fn add_op(&mut self, op: crate::Op, placement: crate::Placement) -> crate::Result<usize>;
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

    /// The device an op timed at a device concerns ([`crate::Op::ExtensionAt`]); `None` for
    /// other ops.
    pub fn device(&self) -> Option<DeviceId> {
        self.device
    }

    /// The running device called `name` (refused as [`OpError::NoDevice`] or
    /// [`OpError::NotRunning`]).
    pub fn running(&self, name: &str) -> Result<DeviceId, OpError> {
        self.network.running(name)
    }

    /// The phase of the device called `name` that is not removed, if there is one.
    pub fn phase(&self, name: &str) -> Option<crate::DevicePhase> {
        self.network.phase(name)
    }

    /// Places another operator event, exactly as [`crate::Network::add_op`] does between runs
    /// (the same refusals: a timed placement before the op's instant, an op a split network
    /// does not take). One placed at the op's own instant whose key sorts before the next
    /// queued event (`EndOf(now)` from an op at the start of the instant, say) applies right
    /// after this op's rounds, before anything else still queued.
    pub fn add_op(&mut self, op: crate::Op, placement: crate::Placement) -> crate::Result<usize> {
        self.network.add_op(op, placement)
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

// ---- portable imports ----------------------------------------------------------------------

/// An interface an extension serves to devices on every backend
/// ([`NetworkExtension::interfaces`]): its full name with its version, as devices import it
/// (`example:pad/notes@0.1.0`), its functions by their component-model names (`open`,
/// `[constructor]note`, `[method]note.write`, `[static]note.count`), and its resources.
///
/// The wasmtime backend links it through an adapter generated from the interface's WIT
/// (`wasmnet_host::portable_adapter!`), the browser backend from these names alone.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Interface {
    pub name: String,
    pub functions: Vec<String>,
    pub resources: Vec<String>,
}

impl Interface {
    /// An interface called `name` (with its version), with no functions yet.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            functions: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// Adds a function, by its component-model name.
    pub fn function(mut self, name: impl Into<String>) -> Self {
        self.functions.push(name.into());
        self
    }

    /// Adds a resource, by its WIT name.
    pub fn resource(mut self, name: impl Into<String>) -> Self {
        self.resources.push(name.into());
        self
    }
}

/// How a served call ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Served {
    /// The function's value: for a `result`, its `ok` value; for a function without a result,
    /// anything (it is dropped).
    Ok(Value),
    /// A `result`'s `err` value.
    Err(Value),
    /// The device faults inside the call: its crash is journalled with this message on every
    /// backend (`device-crashed`), and the one rule for crashes applies.
    Fault(String),
}

/// One device's server of a portable interface ([`DeviceExt::serve`]).
///
/// Called by the device's backend while the device runs, synchronously, at the current virtual
/// instant and in the device's own processing context: a call never yields, so whatever the
/// server does is ordered with the device's other effects. Arguments arrive in the shapes of
/// [`Value`]; a resource argument (`borrow` or `own`) arrives as [`Value::Resource`] with the
/// handle the server gave out, and a resource the server answers is a handle it chose. The
/// server owns what it keeps; the backend owns nothing of the call once it returned.
///
/// A server that lets a controller work on a stopped device keeps the device's [`FuelSpan`]
/// ([`DeviceExt::fuel_span`]), so that the work costs the device nothing.
pub trait ImportServer: Send + Sync {
    /// Serves `function` (its component-model name) of `interface` with `args`.
    fn call(&self, interface: &str, function: &str, args: Vec<Value>) -> Served;

    /// The device dropped its handle `handle` to `resource` of `interface` (or its store went
    /// away with the handle still held: then this is not called; the device's life events say
    /// so). The default does nothing.
    fn drop_resource(&self, interface: &str, resource: &str, handle: u32) {
        let _ = (interface, resource, handle);
    }
}

// ---- options and ops from generic values -----------------------------------------------------

type ParseOption = dyn Fn(&Value) -> Result<ExtValue, String> + Send + Sync;
type ParseOp = dyn Fn(&Value) -> Result<ExtensionOp, String> + Send + Sync;

/// A device option an extension reads ([`ExtOptions`]), as it is set from outside Rust: a key
/// and a parser from a [`Value`] ([`NetworkExtension::options`]). One parser per option type:
/// a controller's spec (its CBOR read as a `Value`), the page's plain objects and an embedder's
/// own formats all go through it.
#[derive(Clone)]
pub struct ExtOption {
    key: String,
    parse: Arc<ParseOption>,
}

impl ExtOption {
    /// The option `key` (an extension's own name, say `pad.fault-at`), parsed into a `T` by
    /// `parse`.
    pub fn new<T: ExtData>(
        key: impl Into<String>,
        parse: impl Fn(&Value) -> Result<T, String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            key: key.into(),
            parse: Arc::new(move |v| parse(v).map(ExtValue::new)),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    /// Parses `value` into the option.
    pub fn parse(&self, value: &Value) -> Result<ExtValue, String> {
        (self.parse)(value)
    }
}

impl fmt::Debug for ExtOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtOption").field("key", &self.key).finish()
    }
}

/// An operator event an extension builds from a generic value, by its kind (`pad.fault`):
/// how the page's plain objects reach an extension's ops ([`NetworkExtension::ops`]).
#[derive(Clone)]
pub struct ExtOpParser {
    kind: String,
    parse: Arc<ParseOp>,
}

impl ExtOpParser {
    pub fn new(
        kind: impl Into<String>,
        parse: impl Fn(&Value) -> Result<ExtensionOp, String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind: kind.into(),
            parse: Arc::new(parse),
        }
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Builds the op from `value`.
    pub fn parse(&self, value: &Value) -> Result<ExtensionOp, String> {
        (self.parse)(value)
    }
}

impl fmt::Debug for ExtOpParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtOpParser")
            .field("kind", &self.kind)
            .finish()
    }
}

/// The options and op parsers of a network's extensions, by key: shared with the device table,
/// which reads controllers' specs.
#[derive(Clone, Default)]
pub(crate) struct Parsers {
    pub(crate) options: std::collections::BTreeMap<String, ExtOption>,
    pub(crate) ops: std::collections::BTreeMap<String, ExtOpParser>,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_fuel_span_lasts_one_instant_and_one_incarnation() {
        let clock = VirtualClock::new(Duration::ZERO);
        let span = FuelSpan::new(clock.clone());
        let other = span.clone();
        assert!(!span.is_open());
        assert!(!span.end(), "nothing to end");
        assert!(span.begin());
        // A second begin, by any holder, changes nothing; one end closes it.
        assert!(!other.begin());
        assert!(other.is_open());
        assert!(other.end());
        assert!(!span.is_open());
        assert!(!span.end());
        // Begun and not ended: closed once the instant is over.
        assert!(span.begin());
        clock.advance_to(5);
        assert!(!span.is_open());
        assert!(!span.end());
        assert!(span.begin(), "a new span at the new instant");
        // The incarnation ends: closed for good.
        span.retire();
        assert!(!other.is_open());
        assert!(!other.begin());
        // A handle of no device never opens.
        let none = FuelSpan::default();
        assert!(!none.begin());
        assert!(!none.is_open());
        assert!(!DeviceExt::default().fuel_span().begin());
    }
}
