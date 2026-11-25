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

use wasmnet_det_cbor as det_cbor;

use det_cbor::Value;

use crate::clock::{Nanos, VirtualClock};
use crate::commands::DeviceCommand;
use crate::config::DeviceConfig;
use crate::journal::{Journal, JournalEnd, Record, Stream};
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
}

impl Verb {
    fn name(&self) -> &'static str {
        match self {
            Verb::Create(_) | Verb::Recreate(_) => "apply",
            Verb::Start => "start",
            Verb::Stop => "stop",
            Verb::Remove => "remove",
            Verb::Control(_) => "control",
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
    /// Journal entries already folded in (`app-exit`).
    journal_seen: usize,
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
        Self {
            inner: Arc::new(Mutex::new(State {
                items: BTreeMap::new(),
                changes: Vec::new(),
                requests: Vec::new(),
                answers: BTreeMap::new(),
                scopes: Vec::new(),
                views: BTreeMap::new(),
                journal_seen: 0,
                catalog: None,
            })),
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
        for (viewer, seen) in s.views.iter_mut() {
            if scope.as_ref().is_none_or(|o| o == viewer) {
                seen.push(index);
            }
        }
        s.scopes.push(scope);
    }

    /// Folds the journal's new `app-exit` events into the `apps` of the devices controllers
    /// created. The devices the network was built with keep none: in a split network a
    /// site's journal holds only its own devices' exits, so following them would make the
    /// table differ from site to site.
    fn refresh(&self, s: &mut State) {
        let new = self.journal.entries_from(s.journal_seen);
        s.journal_seen += new.len();
        for e in new {
            let Record::Event { kind, fields } = &e.record else {
                continue;
            };
            if kind != "app-exit" || s.items.get(&e.device).is_none_or(|i| i.owner.is_none()) {
                continue;
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
    pub(crate) fn end(&self, device: &str, prefix: Option<String>) -> InfraEnd {
        self.add_view(device);
        InfraEnd {
            infra: self.clone(),
            device: device.to_owned(),
            prefix,
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
        self.refresh(&mut s);
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
        self.refresh(&mut s);
        let Some(item) = s.items.get_mut(name) else {
            return;
        };
        item.phase = phase;
        item.since = at;
        if phase == Phase::Running {
            item.apps.clear();
            item.message = None;
        }
        Self::change(&mut s, ChangeKind::Modified, name);
    }

    /// Device `name` trapped and was stopped as crashed, with the trap's `message`.
    pub(crate) fn crashed(&self, name: &str, message: &str, at: Nanos) {
        let mut s = self.state();
        self.refresh(&mut s);
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
        self.refresh(&mut s);
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
    /// current instant and in the device's own processing context. A refusal is the device's
    /// `message` and an `infra-failed` on the caller, like a request the network refused.
    pub(crate) fn command_answered(&self, index: usize, answer: &Result<String, String>) {
        let Err(message) = answer else {
            return;
        };
        let at = self.clock.now();
        let Some(req) = self.state().requests.get(index).cloned() else {
            return;
        };
        if let Some(item) = self.state().items.get_mut(&req.name)
            && item.uid == req.uid
        {
            item.message = Some(message.clone());
        }
        self.journal_failed(&req, message.clone(), at);
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
        let mut s = self.state();
        self.refresh(&mut s);
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
        let mut s = self.state();
        self.refresh(&mut s);
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
        let mut s = self.state();
        self.refresh(&mut s);
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
        self.infra.refresh(&mut s);
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
                let verb = Verb::Recreate(parsed);
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
            self.infra.refresh(&mut s);
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
        self.infra.refresh(&mut s);
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
        self.infra.refresh(&mut s);
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
            "wire" => {
                let Value::Array(cables) = val else {
                    return Err(invalid("wire: an array of cables"));
                };
                for c in cables {
                    wire.push(parse_cable(c)?);
                }
            }
            "infra" | "infra_prefix" => {
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
    if let Value::Map(e) = c {
        for (k, _) in e {
            match k.as_text() {
                Some("port" | "to" | "latency" | "mtu") => {}
                _ => return Err(invalid("a cable has port, to, latency and mtu only")),
            }
        }
    }
    Ok(CableReq {
        port,
        device: device.to_owned(),
        far,
        latency,
        mtu,
    })
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
    if let Some(wire) = wire.filter(|w| !w.is_empty()) {
        let cables = wire
            .iter()
            .map(|c| {
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
                Value::Map(e)
            })
            .collect();
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
        let ctl = infra.end("ctl", None);
        let other = infra.end("other", None);
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
        let end = |device: &str| infra.end(device, None);
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
        let a = infra.end("ctl-a", Some("a-".to_owned()));
        let b = infra.end("ctl-b", None);
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
