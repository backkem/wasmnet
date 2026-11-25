//! `wasmnet:infra` in the sim core: the operational API for in-world controllers,
//! runtime-agnostic (`docs/design/topology-and-infra.md`).
//!
//! A device the network grants `infra` ([`crate::DeviceOptions::infra`]) gets an [`InfraEnd`]:
//! the backend serves the guest's `wasmnet:infra/devices` calls from it, so every runtime
//! answers every call identically.
//!
//! * **The device table** ([`Infra`]) is kept by the network as topology changes apply (the
//!   devices it was built with, operator events, derived requests): every device by name with a
//!   uid, a generation, labels, an owner, its spec (CBOR), its phase and the changes so far. A
//!   resource version is the ordinal of a change in this table.
//! * **Mutations are derived operator events.** A call validates and records what was asked
//!   (the device's `target`, a pending creation), journals `infra-<verb>` on the caller, and
//!   queues `Event::Derived` in the clock at the caller's own position: `now` in the call's
//!   processing context (a graceful stop at `now + grace`; after anything still queued for that
//!   device). The executor returns it to the network, which applies it like a topology
//!   [`crate::Op`] in that event's processing context. So the world is a deterministic function
//!   of the network's description and seed: a replay re-runs the controller, which makes the
//!   same calls.
//! * **Reads** answer from the table at the call, in the caller's view: the network's own
//!   devices and the ones the caller created, its resource versions counting only those
//!   changes. The `app-exit` events of devices controllers created are folded in from the
//!   journal as they appear. The view is the same when the network is split over sites.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Waker;

use wasmnet_det_cbor as det_cbor;

use det_cbor::Value;

use crate::clock::{Nanos, VirtualClock};
use crate::commands::DeviceCommand;
use crate::config::DeviceConfig;
use crate::journal::{Journal, JournalEnd, JournalEntry, Record, Stream};
use crate::network::DeviceOptions;

/// Answers kept per caller for request-id retries.
const ANSWERS_KEPT: usize = 256;

/// What a device is doing (`wasmnet:infra/types.phase`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Pending,
    Running,
    Stopped,
    /// It trapped (a device a controller created crashes alone): stopped, `message` the trap.
    Crashed,
    Removed,
    Failed,
}

/// How a change touched a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

/// One device as the API returns it (`wasmnet:infra/types.device`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceView {
    pub name: String,
    pub uid: String,
    pub generation: u64,
    pub rv: u64,
    pub labels: Vec<(String, String)>,
    pub owner: Option<String>,
    /// CBOR (see `wit/infra/infra.wit`).
    pub spec: Vec<u8>,
    pub phase: Phase,
    pub target: Option<Phase>,
    pub since: Nanos,
    pub apps: Vec<(String, String)>,
    pub message: Option<String>,
}

/// One watch event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub kind: ChangeKind,
    pub device: DeviceView,
}

/// The answer to a command a controller sent with a request id (`devices.control-answer`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandAnswer {
    /// The device it went to, and the command.
    pub name: String,
    pub command: String,
    /// When the answer came: the instant the command ran in the device (or was refused).
    pub at: Nanos,
    /// The device's `ok` text, or its refusal (or why the command never reached it); at most
    /// [`MAX_ANSWER`] bytes.
    pub answer: Result<String, String>,
}

/// The longest command answer kept (longer ones are cut at a character boundary).
pub const MAX_ANSWER: usize = 64 << 10;

/// A command sent with a request id, and its answer once it came.
#[derive(Clone, Debug)]
struct Sent {
    id: String,
    name: String,
    command: String,
    answer: Option<(Nanos, Result<String, String>)>,
}

fn cut(mut text: String) -> String {
    if text.len() > MAX_ANSWER {
        let mut end = MAX_ANSWER;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// One journalled output line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogLine {
    pub at: Nanos,
    pub stream: Stream,
    pub line: String,
}

/// `wasmnet:infra/types.error`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InfraError {
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("denied: {0}")]
    Denied(String),
}

/// A cable of a device a controller creates: its own port, the far device and (if given) port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CableReq {
    pub port: u32,
    pub device: String,
    pub far: Option<u32>,
    pub latency: Nanos,
    pub mtu: Option<u32>,
    /// Its impairments by sending end: from this device's port, then from the far end.
    pub impair: Option<[crate::Impairments; 2]>,
}

/// A validated device spec of a derived creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DerivedSpec {
    pub component: String,
    pub config: DeviceConfig,
    pub options: DeviceOptions,
    pub wire: Vec<CableReq>,
}

/// What a derived request asks the network to do.
#[derive(Clone, Debug)]
pub(crate) enum Verb {
    Create(DerivedSpec),
    /// Remove and add again with a new spec, in one change.
    Recreate(DerivedSpec),
    Start,
    Stop,
    Remove,
    /// A command into the device's `wasmnet:control/commands` export.
    Control(DeviceCommand),
    /// A cable from one of the device's ports.
    Wire(CableReq),
    /// Unplugs the cable at one of the device's ports.
    Unwire(u32),
    /// A new config for a running device that may take it in place
    /// ([`crate::reconfigure`]); `old` is the spec it runs with.
    Reconfigure {
        spec: DerivedSpec,
        old: Vec<u8>,
    },
    /// The device took `.0`'s config in place: the network records it.
    Configured(DerivedSpec),
}

impl Verb {
    fn name(&self) -> &'static str {
        match self {
            Verb::Create(_)
            | Verb::Recreate(_)
            | Verb::Reconfigure { .. }
            | Verb::Configured(_) => "apply",
            Verb::Start => "start",
            Verb::Stop => "stop",
            Verb::Remove => "remove",
            Verb::Control(_) => "control",
            Verb::Wire(_) => "wire",
            Verb::Unwire(_) => "unwire",
        }
    }
}

/// The longest command argument `devices.control` takes.
pub const MAX_COMMAND_ARGUMENT: usize = 64 << 10;

/// Whether `command` can name a command: 1-63 lowercase ASCII letters, digits and `-`, starting
/// with a letter (`route-add`).
pub fn valid_command(command: &str) -> bool {
    (1..=63).contains(&command.len())
        && command.starts_with(|c: char| c.is_ascii_lowercase())
        && command
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// One derived request (`Event::Derived(index)`).
#[derive(Clone, Debug)]
pub(crate) struct Request {
    pub caller: String,
    pub name: String,
    pub verb: Verb,
    /// The uid of the device it was made for (to tell it from a namesake made meanwhile).
    pub uid: String,
}

#[derive(Clone, Debug)]
struct Item {
    uid: String,
    generation: u64,
    rv: u64,
    labels: Vec<(String, String)>,
    owner: Option<String>,
    spec: Vec<u8>,
    phase: Phase,
    target: Option<Phase>,
    since: Nanos,
    apps: BTreeMap<String, String>,
    message: Option<String>,
    /// Requests queued for it and not applied yet.
    queued: u32,
    /// When its last queued request applies (later requests queue after it).
    last_at: Nanos,
    /// A recreate removed it and is about to add it again.
    recreating: bool,
}

impl Item {
    fn view(&self, name: &str) -> DeviceView {
        DeviceView {
            name: name.to_owned(),
            uid: self.uid.clone(),
            generation: self.generation,
            rv: self.rv,
            labels: self.labels.clone(),
            owner: self.owner.clone(),
            spec: self.spec.clone(),
            phase: self.phase,
            target: self.target,
            since: self.since,
            apps: self
                .apps
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            message: self.message.clone(),
        }
    }
}

/// A recorded answer, for request-id retries.
#[derive(Clone, Debug)]
enum Answer {
    Applied(Result<(DeviceView, bool), InfraError>),
    Device(Result<DeviceView, InfraError>),
    Removed(Result<bool, InfraError>),
}

struct State {
    items: BTreeMap<String, Item>,
    changes: Vec<Change>,
    requests: Vec<Request>,
    answers: BTreeMap<String, VecDeque<(String, String, Answer)>>,
    /// Who each change is visible to, by index: `None` for a device of the network's own (every
    /// controller sees it), or the controller that created the device.
    scopes: Vec<Option<String>>,
    /// Each controller's view: the indices of the changes it sees, in order.
    views: BTreeMap<String, Vec<usize>>,
    /// The tasks waiting for a change in a controller's view ([`ChangeWait`]), by controller.
    waiters: BTreeMap<String, Vec<Waker>>,
    /// The request ids of commands queued with one, by request index.
    command_ids: BTreeMap<usize, String>,
    /// The last [`ANSWERS_KEPT`] commands each controller sent with a request id, oldest
    /// first, with their answers once they came.
    sent: BTreeMap<String, VecDeque<Sent>>,
    /// The components controllers may create ([`crate::Network::set_infra_catalog`]); `None`: any.
    catalog: Option<std::collections::BTreeSet<String>>,
}

/// One network's device table and derived requests. Cloning gives another handle to the same table.
#[derive(Clone)]
pub struct Infra {
    inner: Arc<Mutex<State>>,
    clock: VirtualClock,
    journal: Journal,
}

/// The digest of `parts` as a short hex uid.
fn uid_of(parts: &[&[u8]]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
        h.update([0xff]);
    }
    h.finalize()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn matches(labels: &[(String, String)], selector: &[(String, String)]) -> bool {
    selector.iter().all(|s| labels.contains(s))
}

impl Infra {
    pub(crate) fn new(clock: VirtualClock, journal: Journal) -> Self {
        let inner = Arc::new(Mutex::new(State {
            items: BTreeMap::new(),
            changes: Vec::new(),
            requests: Vec::new(),
            answers: BTreeMap::new(),
            scopes: Vec::new(),
            views: BTreeMap::new(),
            waiters: BTreeMap::new(),
            command_ids: BTreeMap::new(),
            sent: BTreeMap::new(),
            catalog: None,
        }));
        // App exits are folded in as they are journalled, in the exiting device's own
        // processing context, so the change (and the wake it causes) is at the same place in
        // every run and on every site.
        let table = Arc::downgrade(&inner);
        journal.set_observer(Arc::new(move |e: &JournalEntry| {
            let exit = matches!(&e.record, Record::Event { kind, .. } if kind == "app-exit");
            if exit && let Some(table) = table.upgrade() {
                Self::fold(&mut table.lock().unwrap_or_else(PoisonError::into_inner), e);
            }
        }));
        Self {
            inner,
            clock,
            journal,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records a change of `name` (its item as it is now), visible to every controller if the
    /// device is the network's own, otherwise to the controller that created it.
    fn change(s: &mut State, kind: ChangeKind, name: &str) {
        let rv = s.changes.len() as u64 + 1;
        let (view, scope) = match s.items.get_mut(name) {
            Some(item) => {
                item.rv = rv;
                (item.view(name), item.owner.clone())
            }
            None => return,
        };
        let index = s.changes.len();
        s.changes.push(Change { kind, device: view });
        let mut woken = Vec::new();
        for (viewer, seen) in s.views.iter_mut() {
            if scope.as_ref().is_none_or(|o| o == viewer) {
                seen.push(index);
                woken.push(viewer.clone());
            }
        }
        s.scopes.push(scope);
        // Wakers only mark their task runnable; the executor polls it in its next round.
        for viewer in woken {
            for w in s.waiters.remove(&viewer).unwrap_or_default() {
                w.wake();
            }
        }
    }

    /// Folds a journalled `app-exit` event into the `apps` of a device a controller created.
    /// The devices the network was built with keep none: in a split network a site's journal
    /// holds only its own devices' exits, so following them would make the table differ from
    /// site to site.
    fn fold(s: &mut State, e: &JournalEntry) {
        let Record::Event { kind, fields } = &e.record else {
            return;
        };
        if kind != "app-exit" || s.items.get(&e.device).is_none_or(|i| i.owner.is_none()) {
            return;
        }
        let field = |k: &str| {
            fields
                .iter()
                .find(|(f, _)| f == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let (app, status) = (field("app"), field("status"));
        if let Some(item) = s.items.get_mut(&e.device) {
            item.apps.insert(app, status);
        }
        Self::change(s, ChangeKind::Modified, &e.device);
    }

    /// Who created device `name` (`None`: the network or an operator, or not in the table).
    pub(crate) fn owner_of(&self, name: &str) -> Option<String> {
        self.state().items.get(name).and_then(|i| i.owner.clone())
    }

    /// The names of the devices `owner` created that are in the table, by name.
    pub(crate) fn owned_by(&self, owner: &str) -> Vec<String> {
        self.state()
            .items
            .iter()
            .filter(|(_, i)| i.owner.as_deref() == Some(owner))
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Whether `viewer`'s view has a change after `since` matching `selector`; its latest
    /// resource version. Registers `waker` otherwise.
    fn changed_since(
        &self,
        viewer: &str,
        selector: &[(String, String)],
        since: u64,
        waker: Option<&Waker>,
    ) -> (bool, u64) {
        let mut s = self.state();
        let seen = s.views.get(viewer).map(Vec::as_slice).unwrap_or_default();
        let latest = seen.len() as u64;
        let from = usize::try_from(since).unwrap_or(usize::MAX);
        let changed = seen
            .iter()
            .skip(from)
            .any(|&i| matches(&s.changes[i].device.labels, selector));
        if !changed && let Some(w) = waker {
            let ws = s.waiters.entry(viewer.to_owned()).or_default();
            if !ws.iter().any(|x| x.will_wake(w)) {
                ws.push(w.clone());
            }
        }
        (changed, latest)
    }

    // ---- what the network tells the table ------------------------------------------------

    /// The components controllers may create ([`crate::Network::set_infra_catalog`]); without a
    /// call, any component the network's resolver knows.
    pub(crate) fn set_catalog(&self, components: Vec<String>) {
        self.state().catalog = Some(components.into_iter().collect());
    }

    /// The `wasmnet:infra` end of controller `device`, which may create only names starting
    /// with `prefix` (if given). Its view of the table starts here: the network's own devices
    /// and the devices it created, with resource versions counting the changes it sees.
    pub(crate) fn end(
        &self,
        device: &str,
        prefix: Option<String>,
        max_devices: Option<u32>,
    ) -> InfraEnd {
        self.add_view(device);
        InfraEnd {
            infra: self.clone(),
            device: device.to_owned(),
            prefix,
            max_devices,
        }
    }

    /// The resource version, in a view whose changes are `seen`, of global version `rv`: how
    /// many of the changes up to `rv` it sees.
    fn view_rv(seen: &[usize], rv: u64) -> u64 {
        seen.partition_point(|&i| (i as u64) < rv) as u64
    }

    /// Whether controller `viewer` sees `item` (the network's own devices and its own).
    fn sees(item: &Item, viewer: &str) -> bool {
        item.owner.as_deref().is_none_or(|o| o == viewer)
    }

    /// Device `name` was created (at setup, by an operator event, or by derived request
    /// `request`) with `spec`.
    pub(crate) fn added(&self, name: &str, spec: Vec<u8>, at: Nanos, request: Option<usize>) {
        let mut s = self.state();
        let mine = request
            .and_then(|r| s.requests.get(r))
            .map(|r| r.uid.clone());
        match s.items.get_mut(name) {
            // A derived creation (or recreation) that was asked for: it runs now.
            Some(item) if mine.as_ref() == Some(&item.uid) => {
                let recreated = item.recreating;
                item.recreating = false;
                if recreated {
                    item.generation += 1;
                }
                item.phase = Phase::Running;
                item.since = at;
                item.message = None;
                item.apps.clear();
                let kind = if recreated {
                    ChangeKind::Modified
                } else {
                    ChangeKind::Added
                };
                Self::change(&mut s, kind, name);
            }
            // Someone else's device under a name a controller had asked for: theirs wins (the
            // controller's request fails when it applies).
            _ => {
                let rv = s.changes.len() as u64 + 1;
                let uid = uid_of(&[b"device", name.as_bytes(), &rv.to_be_bytes()]);
                s.items.insert(
                    name.to_owned(),
                    Item {
                        uid,
                        generation: 1,
                        rv,
                        labels: Vec::new(),
                        owner: None,
                        spec,
                        phase: Phase::Running,
                        target: None,
                        since: at,
                        apps: BTreeMap::new(),
                        message: None,
                        queued: 0,
                        last_at: 0,
                        recreating: false,
                    },
                );
                Self::change(&mut s, ChangeKind::Added, name);
            }
        }
    }

    /// A setup device's spec, once its component is known (no change: still setup).
    pub(crate) fn respec(&self, name: &str, spec: Vec<u8>) {
        let mut s = self.state();
        let Some(item) = s.items.get_mut(name) else {
            return;
        };
        item.spec = spec.clone();
        let rv = item.rv;
        // Its `added` change is the same moment: it shows the spec too.
        if let Some(c) = rv
            .checked_sub(1)
            .and_then(|i| s.changes.get_mut(usize::try_from(i).ok()?))
            && c.device.name == name
        {
            c.device.spec = spec;
        }
    }

    /// Device `name` stopped or started again.
    pub(crate) fn set_phase(&self, name: &str, phase: Phase, at: Nanos) {
        let mut s = self.state();
        let Some(item) = s.items.get_mut(name) else {
            return;
        };
        item.phase = phase;
        item.since = at;
        if phase == Phase::Running {
            item.apps.clear();
        }
        // A stop says why only when it was its owner's ([`Self::stopped_with`]); a crash
        // is `crashed`, with the trap ([`Self::crashed`]).
        item.message = None;
        Self::change(&mut s, ChangeKind::Modified, name);
    }

    /// Device `name` stopped because its controller `owner` stopped (a cascade).
    pub(crate) fn stopped_with(&self, name: &str, owner: &str, at: Nanos) {
        let mut s = self.state();
        let Some(item) = s.items.get_mut(name) else {
            return;
        };
        item.phase = Phase::Stopped;
        item.since = at;
        item.message = Some(format!("stopped with its owner `{owner}`"));
        Self::change(&mut s, ChangeKind::Modified, name);
    }

    /// Device `name` trapped and was stopped as crashed, with the trap's `message`.
    pub(crate) fn crashed(&self, name: &str, message: &str, at: Nanos) {
        let mut s = self.state();
        let Some(item) = s.items.get_mut(name) else {
            return;
        };
        item.phase = Phase::Crashed;
        item.since = at;
        item.message = Some(message.to_owned());
        Self::change(&mut s, ChangeKind::Modified, name);
    }

    /// Device `name` was removed (unless a recreate is about to add it again).
    pub(crate) fn removed(&self, name: &str, at: Nanos) {
        let mut s = self.state();
        let Some(item) = s.items.get_mut(name) else {
            return;
        };
        if item.recreating {
            return;
        }
        item.phase = Phase::Removed;
        item.since = at;
        item.target = None;
        Self::change(&mut s, ChangeKind::Deleted, name);
        s.items.remove(name);
    }

    /// The derived request `index` (the network applies it).
    pub(crate) fn request(&self, index: usize) -> Option<Request> {
        self.state().requests.get(index).cloned()
    }

    /// Marks a recreate in progress (its removal keeps the device in the table).
    pub(crate) fn set_recreating(&self, name: &str, on: bool) {
        if let Some(item) = self.state().items.get_mut(name) {
            item.recreating = on;
        }
    }

    /// The device answered the command of derived request `index` (a `control`), at the
    /// current instant and in the device's own processing context. The answer is kept for the
    /// caller's `control-answer` (if it gave a request id) and is a `modified` change of the
    /// device; a refusal is also the device's `message` and an `infra-failed` on the caller,
    /// like a request the network refused.
    pub(crate) fn command_answered(&self, index: usize, answer: &Result<String, String>) {
        let at = self.clock.now();
        let mut s = self.state();
        let Some(req) = s.requests.get(index).cloned() else {
            return;
        };
        Self::answer(&mut s, index, &req, answer.clone(), at);
        drop(s);
        if let Err(message) = answer {
            self.journal_failed(&req, message.clone(), at);
        }
    }

    /// The device answered the reconfiguration of derived request `index`, at the current
    /// instant and in its own processing context. `ok`: a follow-up request records the new
    /// config (the network applies it right after, at this instant); `restart`: a follow-up
    /// request recreates the device with it; `invalid`: the request fails, the device keeps
    /// its config and the table its old spec.
    pub(crate) fn reconfigured(&self, index: usize, answer: &Result<(), crate::Refusal>) {
        let at = self.clock.now();
        let mut s = self.state();
        let Some(req) = s.requests.get(index).cloned() else {
            return;
        };
        let Verb::Reconfigure { spec, old } = &req.verb else {
            return;
        };
        let current = s.items.get(&req.name).is_some_and(|i| i.uid == req.uid);
        match answer {
            Ok(()) | Err(crate::Refusal::Restart(_)) if current => {
                let verb = match answer {
                    Ok(()) => Verb::Configured(spec.clone()),
                    _ => Verb::Recreate(spec.clone()),
                };
                let follow = Request {
                    verb,
                    ..req.clone()
                };
                let item = s.items.get_mut(&req.name).expect("current");
                item.queued += 1;
                item.target = Some(Phase::Running);
                let next = s.requests.len();
                s.requests.push(follow);
                self.clock.schedule_derived(at, next);
            }
            Err(crate::Refusal::Invalid(message)) => {
                if current {
                    let item = s.items.get_mut(&req.name).expect("current");
                    item.spec = old.clone();
                    item.message = Some(message.clone());
                    Self::change(&mut s, ChangeKind::Modified, &req.name);
                }
                drop(s);
                self.journal_failed(&req, message.clone(), at);
            }
            _ => {}
        }
    }

    /// Device `name` took a new config in place (generation + 1).
    pub(crate) fn configured(&self, name: &str) {
        let mut s = self.state();
        let Some(item) = s.items.get_mut(name) else {
            return;
        };
        item.generation += 1;
        item.message = None;
        Self::change(&mut s, ChangeKind::Modified, name);
    }

    /// Keeps the answer to command request `index` and records it as a change of the device
    /// (its `message` the refusal, if any), which wakes the caller's `changes.wait`.
    fn answer(
        s: &mut State,
        index: usize,
        req: &Request,
        answer: Result<String, String>,
        at: Nanos,
    ) {
        let answer = answer.map(cut).map_err(cut);
        if let Some(id) = s.command_ids.remove(&index)
            && let Some(sent) = s
                .sent
                .get_mut(&req.caller)
                .and_then(|q| q.iter_mut().rev().find(|x| x.id == id))
        {
            sent.answer = Some((at, answer.clone()));
        }
        if let Some(item) = s.items.get_mut(&req.name)
            && item.uid == req.uid
        {
            item.message = answer.err();
            Self::change(s, ChangeKind::Modified, &req.name);
        }
    }

    fn journal_failed(&self, req: &Request, message: String, at: Nanos) {
        JournalEnd {
            journal: self.journal.clone(),
            device: req.caller.clone(),
        }
        .push(
            at,
            Record::Event {
                kind: "infra-failed".to_owned(),
                fields: vec![
                    ("verb".to_owned(), req.verb.name().to_owned()),
                    ("name".to_owned(), req.name.clone()),
                    ("message".to_owned(), message),
                ],
            },
        );
    }

    /// Derived request `index` applied (`error`: refused, with why). Journals `infra-failed` on
    /// the caller for a refusal.
    pub(crate) fn applied(&self, index: usize, error: Option<String>, at: Nanos) {
        let mut s = self.state();
        let Some(req) = s.requests.get(index).cloned() else {
            return;
        };
        let mut failed_create = false;
        if let Some(item) = s.items.get_mut(&req.name)
            && item.uid == req.uid
        {
            item.queued = item.queued.saturating_sub(1);
            if item.queued == 0 {
                item.target = None;
            }
            if let Some(m) = &error {
                item.message = Some(m.clone());
                item.recreating = false;
                if item.phase == Phase::Pending {
                    item.phase = Phase::Failed;
                    item.since = at;
                    failed_create = true;
                }
            }
        }
        if failed_create {
            Self::change(&mut s, ChangeKind::Modified, &req.name);
        }
        // A command that never reached its device: that is its answer.
        if let (Verb::Control(_), Some(m)) = (&req.verb, &error) {
            Self::answer(&mut s, index, &req, Err(m.clone()), at);
        }
        drop(s);
        if let Some(message) = error {
            self.journal_failed(&req, message, at);
        }
    }

    // ---- reads (also for tools and tests) ---------------------------------------------------

    /// One device. Tools read the whole table; a controller reads its view of it
    /// ([`InfraEnd::get`]).
    pub fn get(&self, name: &str) -> Result<DeviceView, InfraError> {
        self.get_as(None, name)
    }

    /// Every device matching `selector`, by name, and the latest resource version.
    pub fn list(&self, selector: &[(String, String)]) -> (u64, Vec<DeviceView>) {
        self.list_as(None, selector)
    }

    /// Changes after `since` matching `selector`, at most `max`, and the version to resume from.
    pub fn watch(&self, selector: &[(String, String)], since: u64, max: u32) -> (u64, Vec<Change>) {
        self.watch_as(None, selector, since, max)
    }

    /// What controller `controller` reads from [`list`](Self::list): the network's own
    /// devices and the ones it created, with the resource version of its view.
    pub fn list_for(
        &self,
        controller: &str,
        selector: &[(String, String)],
    ) -> (u64, Vec<DeviceView>) {
        self.add_view(controller);
        self.list_as(Some(controller), selector)
    }

    /// What controller `controller` reads from [`watch`](Self::watch): the changes it sees,
    /// its resource versions counting them.
    pub fn watch_for(
        &self,
        controller: &str,
        selector: &[(String, String)],
        since: u64,
        max: u32,
    ) -> (u64, Vec<Change>) {
        self.add_view(controller);
        self.watch_as(Some(controller), selector, since, max)
    }

    /// Starts `controller`'s view (if it has none yet) with every change it sees so far.
    fn add_view(&self, controller: &str) {
        let mut s = self.state();
        if !s.views.contains_key(controller) {
            let seen = (0..s.changes.len())
                .filter(|&i| s.scopes[i].as_deref().is_none_or(|o| o == controller))
                .collect();
            s.views.insert(controller.to_owned(), seen);
        }
    }

    /// `view` with its resource version as `viewer` counts them (`None`: the whole table).
    fn seen_by(s: &State, viewer: Option<&str>, mut view: DeviceView) -> DeviceView {
        if let Some(seen) = viewer.and_then(|v| s.views.get(v)) {
            view.rv = Self::view_rv(seen, view.rv);
        }
        view
    }

    fn get_as(&self, viewer: Option<&str>, name: &str) -> Result<DeviceView, InfraError> {
        let s = self.state();
        let view = s
            .items
            .get(name)
            .filter(|i| viewer.is_none_or(|v| Self::sees(i, v)))
            .map(|i| i.view(name))
            .ok_or_else(|| InfraError::NotFound(format!("no device `{name}`")))?;
        Ok(Self::seen_by(&s, viewer, view))
    }

    fn list_as(
        &self,
        viewer: Option<&str>,
        selector: &[(String, String)],
    ) -> (u64, Vec<DeviceView>) {
        let s = self.state();
        let items = s
            .items
            .iter()
            .filter(|(_, i)| matches(&i.labels, selector))
            .filter(|(_, i)| viewer.is_none_or(|v| Self::sees(i, v)))
            .map(|(n, i)| Self::seen_by(&s, viewer, i.view(n)))
            .collect();
        let latest = match viewer.and_then(|v| s.views.get(v)) {
            Some(seen) => seen.len() as u64,
            None => s.changes.len() as u64,
        };
        (latest, items)
    }

    fn watch_as(
        &self,
        viewer: Option<&str>,
        selector: &[(String, String)],
        since: u64,
        max: u32,
    ) -> (u64, Vec<Change>) {
        let s = self.state();
        let all: Vec<usize>;
        let seen = match viewer.and_then(|v| s.views.get(v)) {
            Some(seen) => seen.as_slice(),
            None => {
                all = (0..s.changes.len()).collect();
                &all
            }
        };
        let mut out = Vec::new();
        let latest = seen.len() as u64;
        let from = usize::try_from(since).unwrap_or(usize::MAX);
        for (k, &i) in seen.iter().enumerate().skip(from) {
            let c = &s.changes[i];
            if !matches(&c.device.labels, selector) {
                continue;
            }
            if out.len() as u64 >= u64::from(max.max(1)) {
                let resume = out.last().map_or(since, |c: &Change| c.device.rv);
                return (resume, out);
            }
            let mut c = c.clone();
            c.device.rv = k as u64 + 1;
            out.push(c);
        }
        (latest, out)
    }

    /// The device's journalled output lines on `want` at or after `since`, the last `tail`
    /// (0: all).
    pub fn logs(
        &self,
        name: &str,
        want: Stream,
        since: Nanos,
        tail: u32,
    ) -> Result<Vec<LogLine>, InfraError> {
        if !self.state().items.contains_key(name) {
            return Err(InfraError::NotFound(format!("no device `{name}`")));
        }
        let mut lines: Vec<LogLine> = self
            .journal
            .entries_from(0)
            .into_iter()
            .filter(|e| e.device == name && e.at >= since)
            .filter_map(|e| match e.record {
                Record::Output { stream, line } if stream == want => Some(LogLine {
                    at: e.at,
                    stream,
                    line,
                }),
                _ => None,
            })
            .collect();
        if tail > 0 && lines.len() > tail as usize {
            lines.drain(..lines.len() - tail as usize);
        }
        Ok(lines)
    }
}

// ---- the device's side ----------------------------------------------------------------------

/// A granted device's `wasmnet:infra`: what its backend serves the guest's calls
/// from. Every call is sync and runs in the guest's own processing context.
#[derive(Clone)]
pub struct InfraEnd {
    pub(crate) infra: Infra,
    /// The caller's device name.
    pub(crate) device: String,
    /// The names it may create, if limited ([`crate::DeviceOptions::infra_prefix`]).
    pub(crate) prefix: Option<String>,
    /// The most devices it may have ([`crate::DeviceOptions::infra_max_devices`]).
    pub(crate) max_devices: Option<u32>,
}

impl InfraEnd {
    fn journal(&self, kind: &str, fields: Vec<(&str, String)>) {
        JournalEnd {
            journal: self.infra.journal.clone(),
            device: self.device.clone(),
        }
        .push(
            self.infra.clock.now(),
            Record::Event {
                kind: kind.to_owned(),
                fields: fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
            },
        );
    }

    /// A recorded answer for `(id, args)`, or a conflict for `id` with other arguments.
    fn recorded(&self, id: &Option<String>, args: &str) -> Option<Result<Answer, InfraError>> {
        let id = id.as_ref()?;
        let s = self.infra.state();
        let (_, a, answer) = s
            .answers
            .get(&self.device)?
            .iter()
            .find(|(i, ..)| i == id)?;
        Some(if a == args {
            Ok(answer.clone())
        } else {
            Err(InfraError::Conflict(format!(
                "request id `{id}` was used with other arguments"
            )))
        })
    }

    fn record(&self, id: &Option<String>, args: String, answer: Answer) {
        let Some(id) = id else {
            return;
        };
        let mut s = self.infra.state();
        let q = s.answers.entry(self.device.clone()).or_default();
        if q.len() == ANSWERS_KEPT {
            q.pop_front();
        }
        q.push_back((id.clone(), args, answer));
    }

    /// Refuses a mutation of `name` outside this controller's names (its `infra_prefix`).
    fn mutable(&self, name: &str) -> Result<(), InfraError> {
        match &self.prefix {
            Some(p) if !name.starts_with(p.as_str()) => Err(InfraError::Denied(format!(
                "`{name}` is outside this controller's names (`{p}...`)"
            ))),
            _ => Ok(()),
        }
    }

    /// Device `name` as this controller sees it (its resource version counted in its view).
    fn view(&self, s: &State, name: &str) -> DeviceView {
        Infra::seen_by(s, Some(&self.device), s.items[name].view(name))
    }

    /// Queues derived request `req` for `name` at `at` (or after what is queued for it).
    fn queue(&self, s: &mut State, req: Request, at: Nanos, target: Phase) {
        let item = s.items.get_mut(&req.name).expect("a device to queue for");
        let at = at.max(item.last_at);
        item.last_at = at;
        item.queued += 1;
        item.target = Some(target);
        item.message = None;
        let index = s.requests.len();
        s.requests.push(req);
        self.infra.clock.schedule_derived(at, index);
    }

    /// The device `name` for a mutation by this caller: absent, or this caller's own.
    fn own<'s>(&self, s: &'s State, name: &str) -> Result<Option<&'s Item>, InfraError> {
        if name == self.device {
            return Err(InfraError::Denied(format!("`{name}` is the caller itself")));
        }
        match s.items.get(name) {
            None => Ok(None),
            Some(i) if i.owner.as_deref() == Some(self.device.as_str()) => Ok(Some(i)),
            Some(i) => Err(InfraError::Denied(format!(
                "`{name}` belongs to {}",
                i.owner
                    .as_deref()
                    .map_or("the embedder".to_owned(), |o| format!("`{o}`"))
            ))),
        }
    }

    /// `devices.apply`.
    pub fn apply(
        &self,
        request_id: Option<String>,
        name: &str,
        labels: Vec<(String, String)>,
        spec: &[u8],
    ) -> Result<(DeviceView, bool), InfraError> {
        let args = format!("apply {name} {labels:?} {spec:?}");
        if let Some(r) = self.recorded(&request_id, &args) {
            return match r? {
                Answer::Applied(a) => a,
                _ => Err(InfraError::Conflict(
                    "request id reused by another verb".into(),
                )),
            };
        }
        let answer = self.apply_now(name, labels, spec);
        self.record(&request_id, args, Answer::Applied(answer.clone()));
        if let Ok((d, true)) = &answer {
            let mut f = vec![
                ("name", name.to_owned()),
                ("generation", d.generation.to_string()),
            ];
            if let Some(id) = request_id {
                f.push(("request", id));
            }
            self.journal("infra-apply", f);
        }
        answer
    }

    fn apply_now(
        &self,
        name: &str,
        mut labels: Vec<(String, String)>,
        spec: &[u8],
    ) -> Result<(DeviceView, bool), InfraError> {
        self.mutable(name)?;
        check_name(name)?;
        labels.sort();
        if labels.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(InfraError::Invalid("a label key is given twice".into()));
        }
        let (parsed, canonical) = parse_spec(spec)?;
        if let Some(c) = &self.infra.state().catalog
            && !c.contains(&parsed.component)
        {
            return Err(InfraError::Denied(format!(
                "component `{}` is not in the network's component catalog",
                parsed.component
            )));
        }
        let now = self.infra.clock.now();
        let mut s = self.infra.state();
        let existing = match self.own(&s, name) {
            Ok(e) => e.cloned(),
            Err(InfraError::Denied(m)) if name != self.device => {
                return Err(InfraError::Conflict(m));
            }
            Err(e) => return Err(e),
        };
        match existing {
            // A failed creation is asked for again: a fresh attempt under the same uid.
            Some(item) if item.phase == Phase::Failed => {
                let i = s.items.get_mut(name).expect("present");
                i.phase = Phase::Pending;
                i.spec = canonical;
                i.labels = labels;
                i.since = now;
                let req = Request {
                    caller: self.device.clone(),
                    name: name.to_owned(),
                    verb: Verb::Create(parsed),
                    uid: item.uid.clone(),
                };
                self.queue(&mut s, req, now, Phase::Running);
                Ok((self.view(&s, name), true))
            }
            Some(item) if item.spec == canonical => {
                if item.labels == labels {
                    return Ok((self.view(&s, name), false));
                }
                let i = s.items.get_mut(name).expect("present");
                i.labels = labels;
                Self::modified(&mut s, name);
                Ok((self.view(&s, name), true))
            }
            Some(item) => {
                let i = s.items.get_mut(name).expect("present");
                i.spec = canonical;
                i.labels = labels;
                if item.phase == Phase::Pending {
                    // Not created yet: the queued creation takes the new spec.
                    if let Some(r) = s
                        .requests
                        .iter_mut()
                        .rev()
                        .find(|r| r.uid == item.uid && matches!(r.verb, Verb::Create(_)))
                    {
                        r.verb = Verb::Create(parsed);
                    }
                    return Ok((self.view(&s, name), true));
                }
                // Only the config changed: the device may take it in place (the network
                // decides when it applies: a device without the export is recreated).
                let in_place = parse_spec(&item.spec).is_ok_and(|(old, _)| {
                    old.component == parsed.component
                        && old.options == parsed.options
                        && old.wire == parsed.wire
                });
                let verb = if in_place {
                    Verb::Reconfigure {
                        spec: parsed,
                        old: item.spec.clone(),
                    }
                } else {
                    Verb::Recreate(parsed)
                };
                let req = Request {
                    caller: self.device.clone(),
                    name: name.to_owned(),
                    verb,
                    uid: item.uid.clone(),
                };
                self.queue(&mut s, req, now, Phase::Running);
                Ok((self.view(&s, name), true))
            }
            None => {
                if let Some(max) = self.max_devices {
                    let has = s
                        .items
                        .values()
                        .filter(|i| i.owner.as_deref() == Some(self.device.as_str()))
                        .count();
                    if has >= max as usize {
                        return Err(InfraError::Denied(format!(
                            "`{}` may have at most {max} devices, and has {has}: remove one \
                             first",
                            self.device
                        )));
                    }
                }
                // The uid: the digest of the derived event that will create it.
                let key = self.infra.clock.peek_key(now);
                let uid = crate::digest::event(&key).short();
                let rv = s.changes.len() as u64;
                s.items.insert(
                    name.to_owned(),
                    Item {
                        uid: uid.clone(),
                        generation: 1,
                        rv,
                        labels,
                        owner: Some(self.device.clone()),
                        spec: canonical,
                        phase: Phase::Pending,
                        target: None,
                        since: now,
                        apps: BTreeMap::new(),
                        message: None,
                        queued: 0,
                        last_at: now,
                        recreating: false,
                    },
                );
                let req = Request {
                    caller: self.device.clone(),
                    name: name.to_owned(),
                    verb: Verb::Create(parsed),
                    uid,
                };
                self.queue(&mut s, req, now, Phase::Running);
                Ok((self.view(&s, name), true))
            }
        }
    }

    fn modified(s: &mut State, name: &str) {
        Infra::change(s, ChangeKind::Modified, name);
    }

    /// `devices.start`.
    pub fn start(&self, request_id: Option<String>, name: &str) -> Result<DeviceView, InfraError> {
        self.lifecycle(request_id, name, Verb::Start, 0)
    }

    /// `devices.stop`.
    pub fn stop(
        &self,
        request_id: Option<String>,
        name: &str,
        grace_ns: u64,
    ) -> Result<DeviceView, InfraError> {
        self.lifecycle(request_id, name, Verb::Stop, grace_ns)
    }

    fn lifecycle(
        &self,
        request_id: Option<String>,
        name: &str,
        verb: Verb,
        grace: u64,
    ) -> Result<DeviceView, InfraError> {
        let what = verb.name();
        let args = format!("{what} {name} {grace}");
        if let Some(r) = self.recorded(&request_id, &args) {
            return match r? {
                Answer::Device(a) => a,
                _ => Err(InfraError::Conflict(
                    "request id reused by another verb".into(),
                )),
            };
        }
        let (answer, queued) = self.lifecycle_now(name, verb, grace);
        self.record(&request_id, args, Answer::Device(answer.clone()));
        if queued {
            let mut f = vec![("name", name.to_owned())];
            if grace > 0 {
                f.push(("grace-ns", grace.to_string()));
            }
            if let Some(id) = request_id {
                f.push(("request", id));
            }
            self.journal(&format!("infra-{what}"), f);
        }
        answer
    }

    fn lifecycle_now(
        &self,
        name: &str,
        verb: Verb,
        grace: u64,
    ) -> (Result<DeviceView, InfraError>, bool) {
        let r = (|| {
            self.mutable(name)?;
            let now = self.infra.clock.now();
            let mut s = self.infra.state();
            let item = self
                .own(&s, name)?
                .cloned()
                .ok_or_else(|| InfraError::NotFound(format!("no device `{name}`")))?;
            // Where the device is headed once what is queued has applied.
            let heading = item.target.unwrap_or(item.phase);
            let target = match verb {
                Verb::Start if matches!(heading, Phase::Stopped | Phase::Crashed) => Phase::Running,
                Verb::Stop if matches!(heading, Phase::Running | Phase::Pending) => Phase::Stopped,
                _ => return Ok((self.view(&s, name), false)),
            };
            let req = Request {
                caller: self.device.clone(),
                name: name.to_owned(),
                verb,
                uid: item.uid.clone(),
            };
            self.queue(&mut s, req, now.saturating_add(grace), target);
            Ok((self.view(&s, name), true))
        })();
        match r {
            Ok((v, q)) => (Ok(v), q),
            Err(e) => (Err(e), false),
        }
    }

    /// `devices.remove`.
    pub fn remove(&self, request_id: Option<String>, name: &str) -> Result<bool, InfraError> {
        let args = format!("remove {name}");
        if let Some(r) = self.recorded(&request_id, &args) {
            return match r? {
                Answer::Removed(a) => a,
                _ => Err(InfraError::Conflict(
                    "request id reused by another verb".into(),
                )),
            };
        }
        let (answer, queued) = match self.remove_now(name) {
            Ok((b, q)) => (Ok(b), q),
            Err(e) => (Err(e), false),
        };
        self.record(&request_id, args, Answer::Removed(answer.clone()));
        if queued {
            let mut f = vec![("name", name.to_owned())];
            if let Some(id) = request_id {
                f.push(("request", id));
            }
            self.journal("infra-remove", f);
        }
        answer
    }

    fn remove_now(&self, name: &str) -> Result<(bool, bool), InfraError> {
        self.mutable(name)?;
        let now = self.infra.clock.now();
        let mut s = self.infra.state();
        let Some(item) = self.own(&s, name)?.cloned() else {
            return Ok((false, false));
        };
        if item.target == Some(Phase::Removed) {
            return Ok((true, false));
        }
        if item.phase == Phase::Failed && item.queued == 0 {
            // Never created: nothing to remove in the world, only the record of the attempt.
            if let Some(i) = s.items.get_mut(name) {
                i.phase = Phase::Removed;
                i.since = now;
            }
            Infra::change(&mut s, ChangeKind::Deleted, name);
            s.items.remove(name);
            return Ok((true, false));
        }
        let req = Request {
            caller: self.device.clone(),
            name: name.to_owned(),
            verb: Verb::Remove,
            uid: item.uid.clone(),
        };
        self.queue(&mut s, req, now, Phase::Removed);
        Ok((true, true))
    }

    /// `devices.wire`: queues a cable from port `cable.port` of `name`, a device this caller
    /// created, to `cable.to` (a device this caller created, or one of the network's own:
    /// the rule of creation-time cables). Not idempotent by name: a second cable from the same
    /// port is refused when it applies (the port is taken); a retry by request id is answered
    /// from the record.
    pub fn wire(
        &self,
        request_id: Option<String>,
        name: &str,
        cable: &[u8],
    ) -> Result<DeviceView, InfraError> {
        let args = format!("wire {name} {cable:?}");
        self.link_verb(request_id, args, name, || {
            let v =
                det_cbor::decode(cable).map_err(|e| invalid(format!("cable: not CBOR: {e:?}")))?;
            let c = parse_cable(&v)?;
            let far = self
                .infra
                .state()
                .items
                .get(&c.device)
                .map(|i| i.owner.clone());
            if let Some(Some(owner)) = far
                && owner != self.device
            {
                return Err(InfraError::Denied(format!(
                    "`{}` belongs to `{owner}`: a controller's cables go to its own devices \
                     and the network's",
                    c.device
                )));
            }
            let fields = vec![("port", c.port.to_string()), ("to", c.device.clone())];
            Ok((Verb::Wire(c), fields))
        })
    }

    /// `devices.unwire`: queues unplugging the cable at `port` of `name`, a device this caller
    /// created. Refused when it applies if no cable is there.
    pub fn unwire(
        &self,
        request_id: Option<String>,
        name: &str,
        port: u32,
    ) -> Result<DeviceView, InfraError> {
        let args = format!("unwire {name} {port}");
        self.link_verb(request_id, args, name, || {
            Ok((Verb::Unwire(port), vec![("port", port.to_string())]))
        })
    }

    /// `wire` and `unwire`: on a device this caller created that exists or is about to, queued
    /// after what is already queued for it; journalled as `infra-<verb>` with `fields`.
    fn link_verb(
        &self,
        request_id: Option<String>,
        args: String,
        name: &str,
        verb: impl FnOnce() -> Result<(Verb, Vec<(&'static str, String)>), InfraError>,
    ) -> Result<DeviceView, InfraError> {
        if let Some(r) = self.recorded(&request_id, &args) {
            return match r? {
                Answer::Device(a) => a,
                _ => Err(InfraError::Conflict(
                    "request id reused by another verb".into(),
                )),
            };
        }
        let mut journal = None;
        let answer = (|| {
            self.mutable(name)?;
            let (verb, fields) = verb()?;
            let what = verb.name();
            let now = self.infra.clock.now();
            let mut s = self.infra.state();
            let item = self
                .own(&s, name)?
                .cloned()
                .ok_or_else(|| InfraError::NotFound(format!("no device `{name}`")))?;
            let heading = item.target.unwrap_or(item.phase);
            if matches!(heading, Phase::Failed | Phase::Removed) {
                return Err(InfraError::Invalid(format!("`{name}` does not exist")));
            }
            let req = Request {
                caller: self.device.clone(),
                name: name.to_owned(),
                verb,
                uid: item.uid.clone(),
            };
            self.queue(&mut s, req, now, heading);
            journal = Some((what, fields));
            Ok(self.view(&s, name))
        })();
        self.record(&request_id, args, Answer::Device(answer.clone()));
        if let Some((what, fields)) = journal {
            let mut f = vec![("name", name.to_owned())];
            f.extend(fields);
            if let Some(id) = request_id {
                f.push(("request", id));
            }
            self.journal(&format!("infra-{what}"), f);
        }
        answer
    }

    /// `devices.control`: queues `command` with `argument` for the device's
    /// `wasmnet:control/commands` export (`crate::commands`). Idempotent by request id only.
    pub fn control(
        &self,
        request_id: Option<String>,
        name: &str,
        command: &str,
        argument: &str,
    ) -> Result<DeviceView, InfraError> {
        let args = format!("control {name} {command} {argument:?}");
        if let Some(r) = self.recorded(&request_id, &args) {
            return match r? {
                Answer::Device(a) => a,
                _ => Err(InfraError::Conflict(
                    "request id reused by another verb".into(),
                )),
            };
        }
        let answer = self.control_now(name, command, argument);
        self.record(&request_id, args, Answer::Device(answer.clone()));
        if answer.is_ok()
            && let Some(id) = &request_id
        {
            // Its answer is kept under the request id, for `control-answer`.
            let mut s = self.infra.state();
            let index = s.requests.len() - 1;
            s.command_ids.insert(index, id.clone());
            let q = s.sent.entry(self.device.clone()).or_default();
            if q.len() == ANSWERS_KEPT {
                q.pop_front();
            }
            q.push_back(Sent {
                id: id.clone(),
                name: name.to_owned(),
                command: command.to_owned(),
                answer: None,
            });
        }
        if answer.is_ok() {
            let mut f = vec![("name", name.to_owned()), ("command", command.to_owned())];
            if let Some(id) = request_id {
                f.push(("request", id));
            }
            self.journal("infra-control", f);
        }
        answer
    }

    fn control_now(
        &self,
        name: &str,
        command: &str,
        argument: &str,
    ) -> Result<DeviceView, InfraError> {
        self.mutable(name)?;
        if !valid_command(command) {
            return Err(InfraError::Invalid(format!(
                "command `{command}`: 1-63 lowercase letters, digits and `-`, from a letter"
            )));
        }
        if argument.len() > MAX_COMMAND_ARGUMENT {
            return Err(InfraError::Invalid(format!(
                "a command argument is at most {MAX_COMMAND_ARGUMENT} bytes"
            )));
        }
        let now = self.infra.clock.now();
        let mut s = self.infra.state();
        let item = self
            .own(&s, name)?
            .cloned()
            .ok_or_else(|| InfraError::NotFound(format!("no device `{name}`")))?;
        let heading = item.target.unwrap_or(item.phase);
        if !matches!(heading, Phase::Running | Phase::Pending) {
            return Err(InfraError::Invalid(format!(
                "`{name}` is not running (a command needs a running device)"
            )));
        }
        let req = Request {
            caller: self.device.clone(),
            name: name.to_owned(),
            verb: Verb::Control(DeviceCommand::new(command, argument)),
            uid: item.uid.clone(),
        };
        self.queue(&mut s, req, now, Phase::Running);
        Ok(self.view(&s, name))
    }

    /// `devices.control-answer`: the answer to the command this controller sent with
    /// `request_id` (`None` while the command has not run yet). `not-found` for an id it never
    /// sent a command with, or one more than 256 commands ago.
    pub fn control_answer(&self, request_id: &str) -> Result<Option<CommandAnswer>, InfraError> {
        let s = self.infra.state();
        let sent = s
            .sent
            .get(&self.device)
            .and_then(|q| q.iter().rev().find(|x| x.id == request_id))
            .ok_or_else(|| {
                InfraError::NotFound(format!(
                    "no command was sent with request id `{request_id}`"
                ))
            })?;
        Ok(sent.answer.as_ref().map(|(at, answer)| CommandAnswer {
            name: sent.name.clone(),
            command: sent.command.clone(),
            at: *at,
            answer: answer.clone(),
        }))
    }

    /// `devices.get`: a device this controller sees (the network's own, or one it created).
    pub fn get(&self, name: &str) -> Result<DeviceView, InfraError> {
        self.infra.get_as(Some(&self.device), name)
    }

    /// `devices.list`: the devices this controller sees, and the latest resource version of
    /// its view.
    pub fn list(&self, selector: &[(String, String)]) -> (u64, Vec<DeviceView>) {
        self.infra.list_as(Some(&self.device), selector)
    }

    /// `devices.watch`: the changes this controller sees, its resource versions counting them.
    pub fn watch(&self, selector: &[(String, String)], since: u64, max: u32) -> (u64, Vec<Change>) {
        self.infra
            .watch_as(Some(&self.device), selector, since, max)
    }

    /// `devices.logs`: only of a device this controller created (in a split network the
    /// others' lines may be on another site); `denied` for the network's own devices.
    pub fn logs(
        &self,
        name: &str,
        stream: Stream,
        since: Nanos,
        tail: u32,
    ) -> Result<Vec<LogLine>, InfraError> {
        let owner = self.get(name)?.owner;
        if owner.as_deref() != Some(self.device.as_str()) {
            return Err(InfraError::Denied(format!(
                "`{name}` was not created by this controller: logs are for the devices it created"
            )));
        }
        self.infra.logs(name, stream, since, tail)
    }

    /// `changes.wait`: a future that completes once this controller's view has a change after
    /// `since` to a device matching `selector` (at once if it has one), or once virtual time
    /// reaches `deadline`, with the latest resource version of its view. A change wakes the
    /// waiting task in the processing context the change is made in (a derived event, a
    /// device's app exit), so it runs in that event's next round, the same on every replay and
    /// on every site.
    pub fn wait(
        &self,
        selector: Vec<(String, String)>,
        since: u64,
        deadline: Option<Nanos>,
    ) -> ChangeWait {
        ChangeWait {
            end: self.clone(),
            selector,
            since,
            deadline,
            sleep: None,
            waker: None,
        }
    }
}

/// The future of [`InfraEnd::wait`]. Dropping it stops waiting (and cancels its deadline).
pub struct ChangeWait {
    end: InfraEnd,
    selector: Vec<(String, String)>,
    since: u64,
    deadline: Option<Nanos>,
    sleep: Option<crate::clock::Sleep>,
    /// The waker it registered last (taken out again when it is dropped).
    waker: Option<std::task::Waker>,
}

impl Drop for ChangeWait {
    fn drop(&mut self) {
        if let Some(w) = self.waker.take() {
            let mut s = self.end.infra.state();
            if let Some(ws) = s.waiters.get_mut(&self.end.device) {
                ws.retain(|x| !x.will_wake(&w));
            }
        }
    }
}

impl std::future::Future for ChangeWait {
    type Output = u64;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<u64> {
        let this = &mut *self;
        let infra = &this.end.infra;
        let (changed, latest) = infra.changed_since(
            &this.end.device,
            &this.selector,
            this.since,
            Some(cx.waker()),
        );
        if changed {
            return std::task::Poll::Ready(latest);
        }
        this.waker = Some(cx.waker().clone());
        if let Some(deadline) = this.deadline {
            let clock = infra.clock.clone();
            let sleep = this
                .sleep
                .get_or_insert_with(|| clock.sleep_until(deadline));
            if std::pin::Pin::new(sleep).poll(cx).is_ready() {
                return std::task::Poll::Ready(latest);
            }
        }
        std::task::Poll::Pending
    }
}

/// The output stream a `devices.logs` call names (`stdout` or `stderr`).
pub fn parse_stream(name: &str) -> Result<Stream, InfraError> {
    Stream::from_name(name)
        .ok_or_else(|| InfraError::Invalid(format!("stream `{name}`: stdout or stderr")))
}

/// A message's first line, without a leading `N:` numbering, at most 200 characters: what
/// [`crate::Runtime::summarize`] gives by default.
pub fn one_line(message: &str) -> String {
    let line = message.lines().next().unwrap_or_default().trim();
    let line = line
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == ':')
        .trim();
    line.chars().take(200).collect()
}

/// Whether `name` can name a device a controller creates: 1-63 letters, digits, `-` or `_`
/// (it keys seeds, pcaps and journal records).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn check_name(name: &str) -> Result<(), InfraError> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(InfraError::Invalid(format!(
            "device name `{name}`: 1-63 letters, digits, `-` or `_`"
        )))
    }
}

fn invalid(m: impl Into<String>) -> InfraError {
    InfraError::Invalid(m.into())
}

/// Flattens a config map into `config` (`prefix.key`), text, unsigned or boolean values.
fn flatten(prefix: &str, v: &Value, config: &mut DeviceConfig) -> Result<(), InfraError> {
    match v {
        Value::Map(entries) => {
            for (k, v) in entries {
                let k = k.as_text().ok_or_else(|| invalid("config keys are text"))?;
                let key = if prefix.is_empty() {
                    k.to_owned()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&key, v, config)?;
            }
            Ok(())
        }
        Value::Text(t) => {
            config.insert(prefix.to_owned(), t.clone());
            Ok(())
        }
        Value::Uint(n) => {
            config.insert(prefix.to_owned(), n.to_string());
            Ok(())
        }
        Value::Bool(b) => {
            config.insert(prefix.to_owned(), b.to_string());
            Ok(())
        }
        _ => Err(invalid(format!(
            "config `{prefix}`: text, a number or a boolean"
        ))),
    }
}

/// Validates a derived device spec; returns it parsed and in its canonical CBOR form.
pub(crate) fn parse_spec(bytes: &[u8]) -> Result<(DerivedSpec, Vec<u8>), InfraError> {
    let v = det_cbor::decode(bytes).map_err(|e| invalid(format!("spec: not CBOR: {e:?}")))?;
    let Value::Map(entries) = &v else {
        return Err(invalid("a spec is a map: {component, config?, ...}"));
    };
    let mut component = None;
    let mut config = DeviceConfig::new();
    let mut options = DeviceOptions::default();
    let mut wire = Vec::new();
    for (k, val) in entries {
        let k = k.as_text().ok_or_else(|| invalid("spec keys are text"))?;
        match k {
            "component" => {
                component = Some(
                    val.as_text()
                        .filter(|c| !c.is_empty())
                        .ok_or_else(|| invalid("component: a catalog name"))?
                        .to_owned(),
                );
            }
            "config" => {
                if !matches!(val, Value::Map(_)) {
                    return Err(invalid("config: a map"));
                }
                flatten("", val, &mut config)?;
            }
            "stdio" => match val.as_text() {
                Some("journal") => options.journal_stdio = true,
                Some("capture") => {}
                _ => return Err(invalid("stdio: \"journal\" or \"capture\"")),
            },
            "fuel_per_instant" => {
                options.fuel_per_instant = Some(
                    val.as_uint()
                        .ok_or_else(|| invalid("fuel_per_instant: uint"))?,
                );
            }
            "args" => options.args = parse_args(val)?,
            "memory" => {
                options.memory = Some(
                    val.as_uint()
                        .filter(|&m| m > 0)
                        .ok_or_else(|| invalid("memory: uint bytes, > 0"))?,
                );
            }
            "env" => options.env = parse_env(val)?,
            "wire" => {
                let Value::Array(cables) = val else {
                    return Err(invalid("wire: an array of cables"));
                };
                for c in cables {
                    wire.push(parse_cable(c)?);
                }
            }
            "infra" | "infra_prefix" | "infra_cascade" | "infra_max_devices" => {
                return Err(InfraError::Denied(format!(
                    "a controller cannot grant `{k}` (only the embedder can)"
                )));
            }
            other => return Err(invalid(format!("spec: unknown key `{other}`"))),
        }
    }
    let component = component.ok_or_else(|| invalid("spec: no component"))?;
    let spec = DerivedSpec {
        component,
        config,
        options,
        wire,
    };
    let canonical = spec_value(
        &spec.component,
        &spec.config,
        spec.options.clone(),
        Some(&spec.wire),
    );
    Ok((spec, canonical))
}

/// The most arguments, and the most environment variables, a spec gives a device.
pub const MAX_ARGS: usize = 256;

/// The longest argument, variable name or value a spec gives a device.
pub const MAX_ARG: usize = 4096;

fn check_text(what: &str, t: &str) -> Result<(), InfraError> {
    if t.len() > MAX_ARG || t.contains('\0') {
        return Err(invalid(format!("{what}: at most {MAX_ARG} bytes, no NUL")));
    }
    Ok(())
}

/// A spec's `args`: an array of text.
fn parse_args(v: &Value) -> Result<Vec<String>, InfraError> {
    let Value::Array(items) = v else {
        return Err(invalid("args: an array of text"));
    };
    if items.len() > MAX_ARGS {
        return Err(invalid(format!("args: at most {MAX_ARGS}")));
    }
    items
        .iter()
        .map(|a| {
            let a = a
                .as_text()
                .ok_or_else(|| invalid("args: an array of text"))?;
            check_text("an argument", a)?;
            Ok(a.to_owned())
        })
        .collect()
}

/// A spec's `env`: a map of text to text, names without `=`; sorted by name (its canonical
/// order).
fn parse_env(v: &Value) -> Result<Vec<(String, String)>, InfraError> {
    let Value::Map(entries) = v else {
        return Err(invalid("env: a map of text to text"));
    };
    if entries.len() > MAX_ARGS {
        return Err(invalid(format!("env: at most {MAX_ARGS} variables")));
    }
    let mut env = Vec::new();
    for (k, v) in entries {
        let (Some(k), Some(v)) = (k.as_text(), v.as_text()) else {
            return Err(invalid("env: a map of text to text"));
        };
        if k.is_empty() || k.contains('=') {
            return Err(invalid(format!("env: `{k}` is not a variable name")));
        }
        check_text("an environment variable", k)?;
        check_text("an environment variable", v)?;
        env.push((k.to_owned(), v.to_owned()));
    }
    env.sort();
    if env.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(invalid("env: a variable is given twice"));
    }
    Ok(env)
}

fn parse_cable(c: &Value) -> Result<CableReq, InfraError> {
    let port = c
        .get("port")
        .and_then(Value::as_uint)
        .and_then(|p| u32::try_from(p).ok())
        .ok_or_else(|| invalid("a cable's port: uint"))?;
    let to = c
        .get("to")
        .and_then(Value::as_text)
        .ok_or_else(|| invalid("a cable's to: \"device\" or \"device:port\""))?;
    let (device, far) = match to.split_once(':') {
        Some((d, p)) => (
            d,
            Some(
                p.parse::<u32>()
                    .map_err(|_| invalid(format!("cable to `{to}`: a port number")))?,
            ),
        ),
        None => (to, None),
    };
    check_name(device)?;
    let latency = match c.get("latency") {
        None => 0,
        Some(v) => v
            .as_uint()
            .ok_or_else(|| invalid("a cable's latency: uint ns"))?,
    };
    let mtu = match c.get("mtu") {
        None => None,
        Some(v) => Some(
            v.as_uint()
                .and_then(|m| u32::try_from(m).ok())
                .ok_or_else(|| invalid("a cable's mtu: uint"))?,
        ),
    };
    let impair = match c.get("impair") {
        None => None,
        Some(v) => Some(parse_impair(v)?),
    };
    if let Value::Map(e) = c {
        for (k, _) in e {
            match k.as_text() {
                Some("port" | "to" | "latency" | "mtu" | "impair") => {}
                _ => {
                    return Err(invalid(
                        "a cable has port, to, latency, mtu and impair only",
                    ));
                }
            }
        }
    }
    Ok(CableReq {
        port,
        device: device.to_owned(),
        far,
        latency,
        mtu,
        impair,
    })
}

/// A cable's `impair`: one map (both directions) or two (from this device's port, then from
/// the far end), each `{rate, queue, loss_ppm, jitter}` (all optional; the defaults are a
/// link's: unimpaired).
fn parse_impair(v: &Value) -> Result<[crate::Impairments; 2], InfraError> {
    let one = |m: &Value| -> Result<crate::Impairments, InfraError> {
        let Value::Map(entries) = m else {
            return Err(invalid("impair: maps of rate, queue, loss_ppm and jitter"));
        };
        let mut imp = crate::Impairments::default();
        for (k, v) in entries {
            let n = v
                .as_uint()
                .ok_or_else(|| invalid("impair: rate, queue, loss_ppm and jitter are uints"))?;
            let small = || u32::try_from(n).map_err(|_| invalid("impair: a value too large"));
            match k.as_text() {
                Some("rate") => imp.rate = n,
                Some("queue") => imp.queue = small()?,
                Some("loss_ppm") => imp.loss_ppm = small()?,
                Some("jitter") => imp.jitter = n,
                _ => return Err(invalid("impair: rate, queue, loss_ppm and jitter only")),
            }
        }
        Ok(imp)
    };
    match v {
        Value::Map(_) => {
            let i = one(v)?;
            Ok([i, i])
        }
        Value::Array(items) if items.len() == 2 => Ok([one(&items[0])?, one(&items[1])?]),
        _ => Err(invalid("impair: a map, or an array of two maps")),
    }
}

/// An impairment in its canonical CBOR form (only what differs from the default).
fn impair_value(imp: &crate::Impairments) -> Value {
    let d = crate::Impairments::default();
    let mut m = Vec::new();
    if imp.rate != d.rate {
        m.push((Value::text("rate"), Value::Uint(imp.rate)));
    }
    if imp.queue != d.queue {
        m.push((Value::text("queue"), Value::Uint(u64::from(imp.queue))));
    }
    if imp.loss_ppm != d.loss_ppm {
        m.push((
            Value::text("loss_ppm"),
            Value::Uint(u64::from(imp.loss_ppm)),
        ));
    }
    if imp.jitter != d.jitter {
        m.push((Value::text("jitter"), Value::Uint(imp.jitter)));
    }
    Value::Map(m)
}

/// A cable in its canonical CBOR form.
fn cable_value(c: &CableReq) -> Value {
    let to = match c.far {
        Some(p) => format!("{}:{p}", c.device),
        None => c.device.clone(),
    };
    let mut e = vec![
        (Value::text("port"), Value::Uint(u64::from(c.port))),
        (Value::text("to"), Value::text(to)),
    ];
    if c.latency > 0 {
        e.push((Value::text("latency"), Value::Uint(c.latency)));
    }
    if let Some(mtu) = c.mtu {
        e.push((Value::text("mtu"), Value::Uint(u64::from(mtu))));
    }
    if let Some([a, b]) = &c.impair {
        e.push((
            Value::text("impair"),
            Value::Array(vec![impair_value(a), impair_value(b)]),
        ));
    }
    Value::Map(e)
}

/// A device's spec in its canonical CBOR form (the devices a network is built with: `wire`
/// is `None`).
pub(crate) fn spec_value(
    component: &str,
    config: &DeviceConfig,
    options: DeviceOptions,
    wire: Option<&[CableReq]>,
) -> Vec<u8> {
    let mut m = vec![
        (Value::text("component"), Value::text(component)),
        (
            Value::text("config"),
            Value::Map(
                config
                    .iter()
                    .map(|(k, v)| (Value::text(k.as_str()), Value::text(v.as_str())))
                    .collect(),
            ),
        ),
    ];
    if options.journal_stdio {
        m.push((Value::text("stdio"), Value::text("journal")));
    }
    if let Some(f) = options.fuel_per_instant {
        m.push((Value::text("fuel_per_instant"), Value::Uint(f)));
    }
    if options.infra {
        m.push((Value::text("infra"), Value::Bool(true)));
    }
    if let Some(prefix) = &options.infra_prefix {
        m.push((Value::text("infra_prefix"), Value::text(prefix.as_str())));
    }
    if let Some(max) = options.infra_max_devices {
        m.push((
            Value::text("infra_max_devices"),
            Value::Uint(u64::from(max)),
        ));
    }
    if let Some(bytes) = options.memory {
        m.push((Value::text("memory"), Value::Uint(bytes)));
    }
    match options.infra_cascade {
        crate::Cascade::Keep => {}
        crate::Cascade::Stop => m.push((Value::text("infra_cascade"), Value::text("stop"))),
        crate::Cascade::Remove => m.push((Value::text("infra_cascade"), Value::text("remove"))),
    }
    if !options.args.is_empty() {
        let args = options
            .args
            .iter()
            .map(|a| Value::text(a.as_str()))
            .collect();
        m.push((Value::text("args"), Value::Array(args)));
    }
    if !options.env.is_empty() {
        let env = options
            .env
            .iter()
            .map(|(k, v)| (Value::text(k.as_str()), Value::text(v.as_str())))
            .collect();
        m.push((Value::text("env"), Value::Map(env)));
    }
    if let Some(wire) = wire.filter(|w| !w.is_empty()) {
        let cables = wire.iter().map(cable_value).collect();
        m.push((Value::text("wire"), Value::Array(cables)));
    }
    Value::Map(m).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(component: &str) -> Vec<u8> {
        Value::Map(vec![
            (Value::text("component"), Value::text(component)),
            (
                Value::text("config"),
                Value::Map(vec![(
                    Value::text("app"),
                    Value::Map(vec![(Value::text("x"), Value::Uint(3))]),
                )]),
            ),
            (
                Value::text("wire"),
                Value::Array(vec![Value::Map(vec![
                    (Value::text("port"), Value::Uint(0)),
                    (Value::text("to"), Value::text("sw")),
                ])]),
            ),
        ])
        .encode()
    }

    /// `args` and `env`: text only, names without `=`, env sorted by name in the canonical
    /// form; the controller-only options cannot be granted.
    #[test]
    fn specs_take_arguments_and_environment() {
        let with = |extra: Vec<(Value, Value)>| {
            let mut m = vec![(Value::text("component"), Value::text("node:web"))];
            m.extend(extra);
            Value::Map(m).encode()
        };
        let env = |pairs: &[(&str, &str)]| {
            Value::Map(
                pairs
                    .iter()
                    .map(|(k, v)| (Value::text(*k), Value::text(*v)))
                    .collect(),
            )
        };
        let (s, canonical) = parse_spec(&with(vec![
            (
                Value::text("args"),
                Value::Array(vec![Value::text("-v"), Value::text("x y")]),
            ),
            (Value::text("env"), env(&[("B", "2"), ("A", "1")])),
        ]))
        .expect("valid");
        assert_eq!(s.options.args, ["-v", "x y"]);
        assert_eq!(
            s.options.env,
            [
                ("A".to_owned(), "1".to_owned()),
                ("B".to_owned(), "2".to_owned())
            ]
        );
        assert_eq!(parse_spec(&canonical).unwrap().1, canonical);
        for bad in [
            vec![(Value::text("args"), Value::text("-v"))],
            vec![(Value::text("args"), Value::Array(vec![Value::Uint(1)]))],
            vec![(Value::text("env"), env(&[("A=B", "1")]))],
            vec![(Value::text("env"), env(&[("", "1")]))],
            vec![(Value::text("env"), Value::Array(Vec::new()))],
        ] {
            assert!(
                matches!(parse_spec(&with(bad.clone())), Err(InfraError::Invalid(_))),
                "{bad:?}: {:?}",
                parse_spec(&with(bad.clone()))
            );
        }
        let cascade = with(vec![(Value::text("infra_cascade"), Value::text("stop"))]);
        assert!(matches!(parse_spec(&cascade), Err(InfraError::Denied(_))));
    }

    #[test]
    fn specs_are_validated_and_canonical() {
        let (s, c) = parse_spec(&spec("node:web")).expect("valid");
        assert_eq!(s.config.get("app.x").map(String::as_str), Some("3"));
        assert_eq!(s.wire[0].far, None);
        let (_, again) = parse_spec(&c).expect("canonical parses");
        assert_eq!(again, c);
        let grant = Value::Map(vec![
            (Value::text("component"), Value::text("x")),
            (Value::text("infra"), Value::Bool(true)),
        ])
        .encode();
        assert!(matches!(parse_spec(&grant), Err(InfraError::Denied(_))));
        assert!(matches!(parse_spec(&[0xff]), Err(InfraError::Invalid(_))));
        assert!(check_name("web-1").is_ok());
        assert!(check_name("a b").is_err());
    }

    #[test]
    fn fault_messages_are_one_line() {
        assert_eq!(one_line("no free port\nmore"), "no free port");
        assert_eq!(one_line("  0: bad thing\n"), "bad thing");
        assert_eq!(one_line(&"x".repeat(300)).len(), 200);
    }

    /// The table and the request rules without a runtime: what a call records, queues and
    /// answers, and what the network's hooks turn it into.
    #[test]
    fn calls_queue_requests_and_the_table_follows_the_network() {
        let clock = VirtualClock::new(std::time::Duration::ZERO);
        let infra = Infra::new(clock.clone(), Journal::new(clock.clone()));
        let ctl = infra.end("ctl", None, None);
        let other = infra.end("other", None, None);
        infra.added(
            "ctl",
            spec_value(
                "node:replicas",
                &DeviceConfig::new(),
                DeviceOptions::default(),
                None,
            ),
            0,
            None,
        );
        let labels = vec![("app".to_owned(), "web".to_owned())];
        let (d, changed) = ctl
            .apply(
                Some("r1".into()),
                "web-1",
                labels.clone(),
                &spec("node:web"),
            )
            .expect("apply");
        assert!(changed);
        assert_eq!((d.phase, d.target), (Phase::Pending, Some(Phase::Running)));
        assert_eq!(clock.pending_events(), 1, "one derived event queued");
        // Idempotent: the same again queues nothing; a retry by id is answered from the record.
        assert!(
            !ctl.apply(None, "web-1", labels.clone(), &spec("node:web"))
                .unwrap()
                .1
        );
        assert_eq!(
            ctl.apply(
                Some("r1".into()),
                "web-1",
                labels.clone(),
                &spec("node:web")
            )
            .unwrap(),
            (d.clone(), true)
        );
        assert!(matches!(
            ctl.apply(
                Some("r1".into()),
                "web-2",
                labels.clone(),
                &spec("node:web")
            ),
            Err(InfraError::Conflict(_))
        ));
        assert_eq!(clock.pending_events(), 1);
        // Another controller may not touch it; nobody may touch the devices the network was
        // built with, or itself.
        assert!(matches!(
            other.remove(None, "web-1"),
            Err(InfraError::Denied(_))
        ));
        assert!(matches!(
            ctl.stop(None, "ctl", 0),
            Err(InfraError::Denied(_))
        ));
        assert!(matches!(
            other.apply(None, "web-1", vec![], &spec("node:web")),
            Err(InfraError::Conflict(_))
        ));
        // The network applies request 0: the device runs.
        let req = infra.request(0).expect("request 0");
        assert_eq!(req.uid, d.uid);
        infra.added("web-1", vec![], 0, Some(0));
        infra.applied(0, None, 0);
        let (rv, items) = ctl.list(&labels);
        assert_eq!(items.len(), 1);
        assert_eq!((items[0].phase, items[0].target), (Phase::Running, None));
        let (_, changes) = ctl.watch(&labels, 0, 10);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Added);
        // A graceful stop queues at now + grace; a remove after it.
        assert_eq!(
            ctl.stop(None, "web-1", 5).unwrap().target,
            Some(Phase::Stopped)
        );
        assert!(ctl.remove(None, "web-1").unwrap());
        assert_eq!(clock.pending_events(), 3);
        infra.crashed("web-1", "wasm trap: unreachable", 3);
        assert_eq!(ctl.get("web-1").unwrap().phase, Phase::Crashed);
        infra.removed("web-1", 5);
        let (rv2, changes) = ctl.watch(&labels, rv, 10);
        assert_eq!(
            changes.iter().map(|c| c.kind).collect::<Vec<_>>(),
            [ChangeKind::Modified, ChangeKind::Deleted]
        );
        assert!(rv2 > rv);
        assert!(
            !ctl.remove(None, "web-1").unwrap(),
            "removing what is gone is a no-op"
        );
    }

    /// `control`: only on the caller's own running (or about to run) devices, queued like the
    /// other mutations, answered from the record on a retry by id.
    #[test]
    fn commands_queue_for_the_callers_running_devices() {
        let clock = VirtualClock::new(std::time::Duration::ZERO);
        let infra = Infra::new(clock.clone(), Journal::new(clock.clone()));
        let end = |device: &str| infra.end(device, None, None);
        let (ctl, other) = (end("ctl"), end("other"));
        let spec_of = |c: &str| spec_value(c, &DeviceConfig::new(), DeviceOptions::default(), None);
        infra.added("ctl", spec_of("node:ctl"), 0, None);
        infra.added("sw", spec_of("switch"), 0, None);
        let d = ctl.apply(None, "r1", vec![], &spec("router")).unwrap().0;
        // A command right after the apply queues behind the creation.
        let v = ctl
            .control(
                Some("c1".into()),
                "r1",
                "route-add",
                "10.0.3.0/24 via 10.0.2.2",
            )
            .expect("queued for a pending device");
        assert_eq!(v.target, Some(Phase::Running));
        assert_eq!(clock.pending_events(), 2);
        let req = infra.request(1).expect("request 1");
        assert!(matches!(&req.verb, Verb::Control(c) if c.command == "route-add"));
        assert_eq!(req.uid, d.uid);
        // A retry by id is answered from the record; the same id with other arguments is a
        // conflict; without an id every call queues.
        assert_eq!(
            ctl.control(
                Some("c1".into()),
                "r1",
                "route-add",
                "10.0.3.0/24 via 10.0.2.2"
            ),
            Ok(v)
        );
        assert!(matches!(
            ctl.control(Some("c1".into()), "r1", "route-remove", "10.0.3.0/24"),
            Err(InfraError::Conflict(_))
        ));
        assert_eq!(clock.pending_events(), 2);
        ctl.control(None, "r1", "routes", "").unwrap();
        assert_eq!(clock.pending_events(), 3);
        // Only the caller's own devices, never itself, only well-formed commands.
        for (who, name, command, argument) in [
            (&other, "r1", "routes", ""),
            (&ctl, "sw", "routes", ""),
            (&ctl, "ctl", "routes", ""),
        ] {
            assert!(
                matches!(
                    who.control(None, name, command, argument),
                    Err(InfraError::Denied(_))
                ),
                "{name}"
            );
        }
        assert!(matches!(
            ctl.control(None, "nope", "routes", ""),
            Err(InfraError::NotFound(_))
        ));
        let long = "x".repeat(MAX_COMMAND_ARGUMENT + 1);
        for (command, argument) in [
            ("", ""),
            ("Route", ""),
            ("-x", ""),
            ("routes", long.as_str()),
        ] {
            assert!(
                matches!(
                    ctl.control(None, "r1", command, argument),
                    Err(InfraError::Invalid(_))
                ),
                "{command:?}"
            );
        }
        // The device ran, then stopped: no commands for it.
        infra.added("r1", vec![], 0, Some(0));
        for n in 0..3 {
            infra.applied(n, None, 0);
        }
        ctl.stop(None, "r1", 0).unwrap();
        assert!(matches!(
            ctl.control(None, "r1", "routes", ""),
            Err(InfraError::Invalid(_))
        ));
        // A refusal from the device: the device's message and `infra-failed` on the caller.
        infra.command_answered(1, &Err("10.0.1.0/24 is connected".into()));
        assert_eq!(
            ctl.get("r1").unwrap().message.as_deref(),
            Some("10.0.1.0/24 is connected")
        );
        let failed: Vec<_> = infra
            .journal
            .entries_from(0)
            .into_iter()
            .filter(|e| matches!(&e.record, Record::Event { kind, .. } if kind == "infra-failed"))
            .collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].device, "ctl");
        let controls = infra
            .journal
            .entries_from(0)
            .into_iter()
            .filter(|e| matches!(&e.record, Record::Event { kind, .. } if kind == "infra-control"))
            .count();
        assert_eq!(controls, 2, "the retry was not journalled again");
    }

    /// `wire` and `unwire` on the caller's own devices, toward its own or the network's, and a
    /// limit on how many devices a controller may have; a cable's `impair` in its forms.
    #[test]
    fn cables_and_limits_at_the_call() {
        let clock = VirtualClock::new(std::time::Duration::ZERO);
        let infra = Infra::new(clock.clone(), Journal::new(clock.clone()));
        let spec_of = |c: &str| spec_value(c, &DeviceConfig::new(), DeviceOptions::default(), None);
        infra.added("sw", spec_of("switch"), 0, None);
        let ctl = infra.end("ctl", None, Some(2));
        let other = infra.end("other", None, None);
        ctl.apply(None, "web", vec![], &spec("node:web")).unwrap();
        other
            .apply(None, "theirs", vec![], &spec("node:web"))
            .unwrap();
        let to = |device: &str| {
            Value::Map(vec![
                (Value::text("port"), Value::Uint(1)),
                (Value::text("to"), Value::text(device)),
            ])
            .encode()
        };
        let queued = clock.pending_events();
        ctl.wire(None, "web", &to("sw"))
            .expect("to the network's own");
        ctl.unwire(None, "web", 0).expect("its own port");
        assert_eq!(clock.pending_events(), queued + 2);
        for (who, name, cable) in [
            (&ctl, "web", to("theirs")),
            (&ctl, "sw", to("web")),
            (&other, "web", to("sw")),
        ] {
            assert!(
                matches!(who.wire(None, name, &cable), Err(InfraError::Denied(_))),
                "{name}"
            );
        }
        assert!(matches!(
            ctl.wire(None, "nope", &to("sw")),
            Err(InfraError::NotFound(_))
        ));
        assert!(matches!(
            ctl.wire(None, "web", &[0xff]),
            Err(InfraError::Invalid(_))
        ));
        // Two devices at most: the third is refused and nothing is queued for it.
        ctl.apply(None, "web-2", vec![], &spec("node:web")).unwrap();
        let queued = clock.pending_events();
        assert!(matches!(
            ctl.apply(None, "web-3", vec![], &spec("node:web")),
            Err(InfraError::Denied(m)) if m.contains("at most 2")
        ));
        assert_eq!(clock.pending_events(), queued);
        assert!(ctl.get("web-3").is_err());
        // `impair`: one map for both directions, or two by sending end.
        let imp = |v: Value| {
            parse_cable(&Value::Map(vec![
                (Value::text("port"), Value::Uint(0)),
                (Value::text("to"), Value::text("sw")),
                (Value::text("impair"), v),
            ]))
        };
        let rate = |r: u64| Value::Map(vec![(Value::text("rate"), Value::Uint(r))]);
        let both = imp(rate(5)).unwrap().impair.unwrap();
        assert_eq!((both[0].rate, both[1].rate), (5, 5));
        let two = imp(Value::Array(vec![rate(5), rate(7)])).unwrap();
        assert_eq!(two.impair.map(|i| (i[0].rate, i[1].rate)), Some((5, 7)));
        assert_eq!(parse_cable(&cable_value(&two)).unwrap(), two, "canonical");
        assert!(imp(Value::Array(vec![rate(5)])).is_err());
        assert!(imp(Value::Map(vec![(Value::text("speed"), Value::Uint(1))])).is_err());
    }

    /// A command sent with a request id has its answer kept for its caller: `None` until the
    /// device answers, then the text (cut at `MAX_ANSWER`), as a `modified` change of the
    /// device; a command that never reaches its device is answered with why.
    #[test]
    fn a_controller_reads_its_commands_answers() {
        let clock = VirtualClock::new(std::time::Duration::ZERO);
        let infra = Infra::new(clock.clone(), Journal::new(clock.clone()));
        let ctl = infra.end("ctl", None, None);
        infra.added(
            "ctl",
            spec_value("ctl", &DeviceConfig::new(), DeviceOptions::default(), None),
            0,
            None,
        );
        ctl.apply(None, "r1", vec![], &spec("router")).unwrap();
        ctl.control(Some("q".into()), "r1", "routes", "").unwrap();
        ctl.control(Some("bad".into()), "r1", "route-add", "x")
            .unwrap();
        ctl.control(None, "r1", "routes", "").unwrap();
        assert_eq!(ctl.control_answer("q"), Ok(None), "not answered yet");
        assert!(matches!(
            ctl.control_answer("nope"),
            Err(InfraError::NotFound(_))
        ));
        assert!(matches!(
            infra.end("other", None, None).control_answer("q"),
            Err(InfraError::NotFound(_))
        ));
        infra.added("r1", vec![], 0, Some(0));
        infra.applied(0, None, 0);
        let rv = ctl.list(&[]).0;
        infra.applied(1, None, 0);
        let long = "x".repeat(MAX_ANSWER + 10);
        infra.command_answered(1, &Ok(long));
        let a = ctl.control_answer("q").unwrap().expect("answered");
        assert_eq!((a.name.as_str(), a.command.as_str()), ("r1", "routes"));
        assert_eq!(a.answer.map(|t| t.len()), Ok(MAX_ANSWER));
        let (_, changes) = ctl.watch(&[], rv, 10);
        assert_eq!(changes.len(), 1, "the answer is a change of the device");
        assert_eq!(changes[0].kind, ChangeKind::Modified);
        // The device stopped before the second one reached it: that is its answer.
        infra.applied(2, Some("`r1` is not running".into()), 0);
        let b = ctl.control_answer("bad").unwrap().expect("answered");
        assert_eq!(b.answer, Err("`r1` is not running".into()));
        assert_eq!(
            ctl.get("r1").unwrap().message.as_deref(),
            Some("`r1` is not running")
        );
    }

    /// Each controller sees the network's own devices and the ones it created, with resource
    /// versions counting what it sees; only created devices follow their app exits; logs are
    /// for the caller's own devices; a prefix bounds the names a controller may create.
    #[test]
    fn controllers_see_their_own_view_of_the_table() {
        let clock = VirtualClock::new(std::time::Duration::ZERO);
        let journal = Journal::new(clock.clone());
        let infra = Infra::new(clock.clone(), journal.clone());
        let spec_of = |c: &str| spec_value(c, &DeviceConfig::new(), DeviceOptions::default(), None);
        infra.added("sw", spec_of("switch"), 0, None);
        infra.added("ctl-a", spec_of("node:ctl"), 0, None);
        infra.added("ctl-b", spec_of("node:ctl"), 0, None);
        let a = infra.end("ctl-a", Some("a-".to_owned()), None);
        let b = infra.end("ctl-b", None, None);
        b.apply(None, "b-1", vec![], &spec("node:web")).unwrap();
        a.apply(None, "a-1", vec![], &spec("node:web")).unwrap();
        infra.added("b-1", vec![], 0, Some(0));
        infra.applied(0, None, 0);
        infra.added("a-1", vec![], 0, Some(1));
        infra.applied(1, None, 0);
        // The whole table: 5 changes; `ctl-a` sees 4 of them (not `b-1`'s), `ctl-b` 4.
        assert_eq!(infra.list(&[]).0, 5);
        let (rv, items) = a.list(&[]);
        let names: Vec<&str> = items.iter().map(|d| d.name.as_str()).collect();
        assert_eq!((rv, names), (4, vec!["a-1", "ctl-a", "ctl-b", "sw"]));
        assert_eq!(a.get("a-1").unwrap().rv, 4, "its own fourth change");
        assert_eq!(infra.get("a-1").unwrap().rv, 5, "the table's fifth");
        assert!(matches!(a.get("b-1"), Err(InfraError::NotFound(_))));
        let (rv, changes) = a.watch(&[], 3, 10);
        assert_eq!(rv, 4);
        assert_eq!(changes.len(), 1);
        assert_eq!(
            (changes[0].device.name.as_str(), changes[0].device.rv),
            ("a-1", 4)
        );
        assert_eq!(infra.watch_for("ctl-b", &[], 0, 10).0, 4);
        assert_eq!(infra.list_for("ctl-a", &[]), a.list(&[]));
        // App exits: only a created device's are folded in.
        for device in ["sw", "a-1"] {
            JournalEnd {
                journal: journal.clone(),
                device: device.to_owned(),
            }
            .push(
                0,
                Record::Event {
                    kind: "app-exit".to_owned(),
                    fields: vec![
                        ("app".to_owned(), "x".to_owned()),
                        ("status".to_owned(), "ok".to_owned()),
                    ],
                },
            );
        }
        assert!(a.get("sw").unwrap().apps.is_empty());
        assert_eq!(
            a.get("a-1").unwrap().apps,
            [("x".to_owned(), "ok".to_owned())]
        );
        assert_eq!(a.list(&[]).0, 5);
        assert_eq!(b.list(&[]).0, 4, "ctl-b does not see a-1's exit");
        // Logs: the caller's own devices only.
        assert!(a.logs("a-1", Stream::Stdout, 0, 0).is_ok());
        assert!(matches!(
            a.logs("sw", Stream::Stdout, 0, 0),
            Err(InfraError::Denied(_))
        ));
        assert!(matches!(
            a.logs("b-1", Stream::Stdout, 0, 0),
            Err(InfraError::NotFound(_))
        ));
        // The prefix: `ctl-a` may change only `a-...` names.
        assert!(matches!(
            a.apply(None, "web", vec![], &spec("node:web")),
            Err(InfraError::Denied(_))
        ));
        assert!(matches!(a.stop(None, "b-1", 0), Err(InfraError::Denied(_))));
        assert!(a.stop(None, "a-1", 0).is_ok());
    }
}
