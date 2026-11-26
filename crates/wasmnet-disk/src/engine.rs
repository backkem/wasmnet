//! The disks of one network: ordered maps, their durability, quotas, faults and records. Pure
//! Rust over the core's seed derivation: no backend, no WIT, no journal of its own (every
//! function that has something to journal answers it as [`Rec`]s for the caller to journal).

use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use sha2::{Digest as _, Sha256};
use wasmnet_core::{SimRng, derive_seed};

use crate::image;

/// The longest key, in bytes.
pub const MAX_KEY: usize = 4096;
/// The largest value, and the longest ranged read.
pub const MAX_VALUE: usize = 16 << 20;
/// The most changes in one write.
pub const MAX_CHANGES: usize = 4096;
/// The most bytes of keys and values in one write.
pub const MAX_WRITE_BYTES: usize = 32 << 20;
/// The most entries one scan returns.
pub const MAX_SCAN: u32 = 4096;
/// The most bytes of keys and values in one scan page (at least one entry is always returned).
pub const MAX_PAGE_BYTES: usize = 8 << 20;
/// Keys per `list-keys` page.
pub const LIST_PAGE: usize = 1024;
/// What every record costs a quota on top of its key and value bytes.
pub const RECORD_OVERHEAD: u64 = 64;
/// A disk's quota when its spec gives none.
pub const DEFAULT_QUOTA: u64 = 64 << 20;
/// The most every disk of a network holds together, by default (quota accounting).
pub const DEFAULT_TOTAL: u64 = 1 << 30;

/// When a disk's changes survive a power loss (a stop or a crash of its device).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Durability {
    /// Every call that returned `ok` is durable.
    #[default]
    EachCall,
    /// Changes are durable once `sync` returned; a power loss loses the rest.
    OnSync,
}

impl Durability {
    /// Its WIT name (`each-call`, `on-sync`).
    pub fn name(self) -> &'static str {
        match self {
            Self::EachCall => "each-call",
            Self::OnSync => "on-sync",
        }
    }
}

/// One disk a device declares (in its options, [`crate::DiskOptions`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiskSpec {
    /// Its name: the identifier the device opens it with.
    pub name: String,
    /// The most it holds, in quota bytes (key + value + [`RECORD_OVERHEAD`] per record).
    pub quota: u64,
    pub durability: Durability,
    /// What it holds when it is created: a `wasmnet-disk/1` image ([`crate::image`]).
    pub initial: Option<Arc<Vec<u8>>>,
}

impl DiskSpec {
    /// A disk called `name`, with [`DEFAULT_QUOTA`], [`Durability::EachCall`], empty.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            quota: DEFAULT_QUOTA,
            durability: Durability::EachCall,
            initial: None,
        }
    }

    /// Sets [`quota`](Self::quota).
    pub fn quota(mut self, bytes: u64) -> Self {
        self.quota = bytes;
        self
    }

    /// Sets [`durability`](Self::durability).
    pub fn durability(mut self, d: Durability) -> Self {
        self.durability = d;
        self
    }

    /// Sets [`initial`](Self::initial).
    pub fn initial(mut self, image: Vec<u8>) -> Self {
        self.initial = Some(Arc::new(image));
        self
    }
}

/// What of a call's changes, or of an unsynced tail, survives a fault.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Keep {
    /// None of it.
    #[default]
    None,
    /// All of it.
    All,
    /// A seeded prefix (fewer than all, maybe none).
    Prefix,
}

/// How values are corrupted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Corruption {
    /// The first byte of each value XOR `0x5a`.
    FlipFirstByte,
    /// `n` seeded positions of each value XOR a seeded non-zero byte.
    SeededBytes(u32),
    /// Every byte replaced by seeded bytes; the length kept.
    Garbage,
}

/// A fault an operator event puts on one disk ([`crate::DiskOp`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiskFault {
    /// Emptied, now: a drive replaced. Journalled as `disk-lost`.
    Lose,
    /// Armed for the device's next power loss: what of the unsynced tail survives it, and
    /// whether the call after the kept ones survives as a seeded prefix of its changes (`tear`).
    /// Without one, a power loss keeps none of the tail.
    PowerLoss { keep: Keep, tear: bool },
    /// The `call`-th mutating call from now (1: the next) faults the device inside the call,
    /// keeping none, all or a seeded prefix of its changes.
    CrashAt { call: u64, keep: Keep },
    /// The next `count` calls on the disk answer `failed(text)` (`other(text)` from a standard
    /// function) and change nothing.
    FailCalls { count: u64, text: String },
    /// Values whose keys start with `prefix` change.
    Corrupt { prefix: String, how: Corruption },
    /// The disk's quota becomes `bytes`. Below its use, every call that would grow it is `full`.
    Quota(u64),
}

/// Why a call did not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiskError {
    /// The device declares no disk of that name.
    NoSuchStore,
    /// Over a per-call limit.
    TooLarge(String),
    /// No room: nothing changed.
    Full(String),
    /// A failure an operator injected ([`DiskFault::FailCalls`]).
    Failed(String),
    /// The device faults inside this call ([`DiskFault::CrashAt`]): the backend traps it with
    /// this message.
    Fault(String),
}

impl DiskError {
    /// The text a standard `wasi:keyvalue` function answers as `other(...)`.
    pub fn text(&self) -> String {
        match self {
            Self::NoSuchStore => "no such store".to_owned(),
            Self::TooLarge(t) => format!("too large: {t}"),
            Self::Full(t) => format!("full: {t}"),
            Self::Failed(t) | Self::Fault(t) => t.clone(),
        }
    }
}

/// One change of a write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Set(String, Vec<u8>),
    Delete(String),
}

impl Change {
    fn key(&self) -> &str {
        match self {
            Self::Set(k, _) | Self::Delete(k) => k,
        }
    }
}

/// One scanned entry.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    pub key: String,
    pub size: u64,
    pub value: Option<Vec<u8>>,
}

/// What one disk has done, counted (not journalled: an `each-call` disk may take many writes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiskStats {
    /// Calls served, of any kind.
    pub calls: u64,
    /// Calls that changed it.
    pub writes: u64,
    /// `sync` calls.
    pub syncs: u64,
    /// Calls answered with an error.
    pub errors: u64,
    /// The most quota bytes it held.
    pub peak: u64,
}

/// A record for the device's journal: its kind and fields (`disk` first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rec {
    pub kind: &'static str,
    pub fields: Vec<(&'static str, String)>,
}

impl Rec {
    fn new(kind: &'static str, disk: &str) -> Self {
        Self {
            kind,
            fields: vec![("disk", disk.to_owned())],
        }
    }

    fn with(mut self, key: &'static str, value: impl ToString) -> Self {
        self.fields.push((key, value.to_string()));
        self
    }
}

/// A key and its value, if it has one (`get-many`).
pub(crate) type Found = (String, Option<Vec<u8>>);

/// What a call changed, oldest first: each key with its value before (to roll back).
type Undo = Vec<Found>;

pub(crate) struct Disk {
    /// What the device declared, and the quota in force (a fault may change it).
    declared: DiskSpec,
    quota: u64,
    map: BTreeMap<String, Vec<u8>>,
    /// Key and value bytes held.
    data: u64,
    /// The unsynced tail: one undo list per changing call since the last durable point.
    tail: Vec<Undo>,
    /// Changing calls so far (for `CrashAt`), and seeded faults drawn (for their seeds).
    writes: u64,
    draws: u64,
    crash_at: Option<(u64, Keep)>,
    power_loss: Option<(Keep, bool)>,
    fail: Option<(u64, String)>,
    stats: DiskStats,
}

impl Disk {
    fn new(spec: DiskSpec) -> Self {
        Self {
            quota: spec.quota,
            declared: spec,
            map: BTreeMap::new(),
            data: 0,
            tail: Vec::new(),
            writes: 0,
            draws: 0,
            crash_at: None,
            power_loss: None,
            fail: None,
            stats: DiskStats::default(),
        }
    }

    /// Quota bytes held.
    fn used(&self) -> u64 {
        self.data + RECORD_OVERHEAD * self.map.len() as u64
    }

    fn put(&mut self, key: String, value: Option<Vec<u8>>, undo: &mut Undo) {
        if let Some(v) = &value {
            self.data += (key.len() + v.len()) as u64;
        }
        let old = match value {
            Some(v) => self.map.insert(key.clone(), v),
            None => self.map.remove(&key),
        };
        if let Some(o) = &old {
            self.data -= (key.len() + o.len()) as u64;
        }
        undo.push((key, old));
    }

    fn roll_back(&mut self, undo: Undo) {
        let mut scratch = Vec::new();
        for (key, old) in undo.into_iter().rev() {
            self.put(key, old, &mut scratch);
            scratch.clear();
        }
    }

    /// The quota bytes `changes` would add (net; negative if they free some).
    fn growth(&self, changes: &[Change]) -> i64 {
        let mut last = BTreeMap::<&str, Option<usize>>::new();
        for c in changes {
            let v = match c {
                Change::Set(_, v) => Some(v.len()),
                Change::Delete(_) => None,
            };
            last.insert(c.key(), v);
        }
        let cost = |k: &str, v: Option<usize>| {
            v.map_or(0, |v| (k.len() + v) as i64 + RECORD_OVERHEAD as i64)
        };
        last.iter()
            .map(|(k, new)| cost(k, *new) - cost(k, self.map.get(*k).map(Vec::len)))
            .sum()
    }

    fn rng(&mut self, seed: u64, device: &str) -> SimRng {
        self.draws += 1;
        SimRng::from_seed(derive_seed(
            seed,
            device,
            &format!("disk:{}:{}", self.declared.name, self.draws),
        ))
    }

    fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        image::write(self.entries(), &mut |b| h.update(b));
        h.finalize().into()
    }

    fn entries(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.map.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    fn note_peak(&mut self) {
        self.stats.peak = self.stats.peak.max(self.used());
    }

    /// Replaces the contents with an image's (durable), within the quota.
    fn load(&mut self, bytes: &[u8], room: u64) -> Result<(), String> {
        let mut map = BTreeMap::new();
        let mut data = 0u64;
        for e in image::read(bytes).map_err(|e| e.to_string())? {
            let (k, v) = e.map_err(|e| e.to_string())?;
            data += (k.len() + v.len()) as u64;
            map.insert(k.to_owned(), v.to_vec());
        }
        let used = data + RECORD_OVERHEAD * map.len() as u64;
        if used > self.quota || used > room {
            return Err(format!(
                "an image of {used} quota bytes does not fit disk `{}` (quota {}, room {room})",
                self.declared.name, self.quota
            ));
        }
        self.map = map;
        self.data = data;
        self.tail.clear();
        self.note_peak();
        Ok(())
    }
}

#[derive(Default)]
struct Inner {
    /// Device name -> disk name -> disk.
    devices: BTreeMap<String, BTreeMap<String, Disk>>,
    /// Quota bytes every disk holds together, and the most they may.
    used: u64,
    total: u64,
    /// The network's seed.
    seed: u64,
}

impl Inner {
    fn recount(&mut self) {
        self.used = self
            .devices
            .values()
            .flat_map(|m| m.values())
            .map(Disk::used)
            .sum();
    }
}

/// Every disk of a network, shared by the extension (ops, life events, reads) and the devices'
/// servers.
#[derive(Clone)]
pub(crate) struct DiskSet {
    inner: Arc<Mutex<Inner>>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A read-only look at one disk ([`crate::Disks::read`]).
pub struct DiskRead<'a> {
    disk: &'a Disk,
}

impl DiskRead<'_> {
    /// Its entries.
    pub fn records(&self) -> u64 {
        self.disk.map.len() as u64
    }
    /// Its key and value bytes.
    pub fn bytes(&self) -> u64 {
        self.disk.data
    }
    /// Its quota bytes held (key + value + [`RECORD_OVERHEAD`] per record), and its quota.
    pub fn used(&self) -> u64 {
        self.disk.used()
    }
    pub fn quota(&self) -> u64 {
        self.disk.quota
    }
    pub fn durability(&self) -> Durability {
        self.disk.declared.durability
    }
    /// Changing calls not yet durable (an `on-sync` disk's unsynced tail).
    pub fn unsynced(&self) -> u64 {
        self.disk.tail.len() as u64
    }
    pub fn stats(&self) -> DiskStats {
        self.disk.stats
    }
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.disk.map.get(key).map(Vec::as_slice)
    }
    /// Its entries whose keys start with `prefix`, ascending.
    pub fn iter<'b>(&'b self, prefix: &'b str) -> impl Iterator<Item = (&'b str, &'b [u8])> + 'b {
        self.disk
            .map
            .range::<str, _>((Bound::Included(prefix), Bound::Unbounded))
            .take_while(move |(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.as_str(), v.as_slice()))
    }
    /// SHA-256 of its image, computed in one pass without a copy.
    pub fn digest(&self) -> [u8; 32] {
        self.disk.digest()
    }
    /// Its image, written to `out` a piece at a time.
    pub fn export(&self, out: &mut dyn FnMut(&[u8])) {
        image::write(self.disk.entries(), out);
    }
}

/// A digest as text (64 hex digits), as records show it.
pub fn digest_hex(d: &[u8; 32]) -> String {
    hex(d)
}

impl DiskSet {
    pub(crate) fn new(total: u64) -> Self {
        let set = Self {
            inner: Arc::default(),
        };
        set.lock().total = total;
        set
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn set_seed(&self, seed: u64) {
        self.lock().seed = seed;
    }

    pub(crate) fn set_total(&self, total: u64) {
        self.lock().total = total;
    }

    /// `device` is set up with `specs`: disks it has already keep their contents (and a quota a
    /// fault set, unless the declared quota changed), new ones start empty or from their
    /// initial image (`disk-created`), ones no longer declared go (`disk-dropped`).
    pub(crate) fn declare(&self, device: &str, specs: &[DiskSpec]) -> Vec<Rec> {
        let mut recs = Vec::new();
        let mut inner = self.lock();
        let room = inner.total.saturating_sub(inner.used);
        let disks = inner.devices.entry(device.to_owned()).or_default();
        disks.retain(|name, d| {
            let keep = specs.iter().any(|s| &s.name == name);
            if !keep {
                recs.push(
                    Rec::new("disk-dropped", name)
                        .with("records", d.map.len())
                        .with("bytes", d.data),
                );
            }
            keep
        });
        for s in specs {
            match disks.get_mut(&s.name) {
                Some(d) => {
                    if d.declared.quota != s.quota {
                        d.quota = s.quota;
                    }
                    d.declared = s.clone();
                }
                None => {
                    let mut d = Disk::new(s.clone());
                    if let Some(img) = &s.initial
                        && let Err(e) = d.load(img, room)
                    {
                        // `check_options` refused a bad image before; one that no longer fits
                        // the network's room starts the disk empty, and says so.
                        recs.push(Rec::new("disk-error", &s.name).with("error", e));
                    }
                    recs.push(
                        Rec::new("disk-created", &s.name)
                            .with("records", d.map.len())
                            .with("bytes", d.data)
                            .with("digest", hex(&d.digest())),
                    );
                    disks.insert(s.name.clone(), d);
                }
            }
        }
        if disks.is_empty() {
            inner.devices.remove(device);
        }
        inner.recount();
        recs
    }

    /// The device was removed (not recreated): its disks go.
    pub(crate) fn removed(&self, device: &str) -> Vec<Rec> {
        self.declare(device, &[])
    }

    /// The device lost power (a stop, a crash, a recreation): each disk's unsynced tail goes,
    /// or survives in part as an armed [`DiskFault::PowerLoss`] says.
    pub(crate) fn power_loss(&self, device: &str) -> Vec<Rec> {
        let mut recs = Vec::new();
        let mut inner = self.lock();
        let seed = inner.seed;
        let Some(disks) = inner.devices.get_mut(device) else {
            return recs;
        };
        for (name, d) in disks.iter_mut() {
            let armed = d.power_loss.take();
            d.crash_at = None;
            d.fail = None;
            if d.tail.is_empty() && armed.is_none() {
                continue;
            }
            let (keep, tear) = armed.unwrap_or((Keep::None, false));
            let n = d.tail.len();
            let mut tail = std::mem::take(&mut d.tail);
            let mut rng = (keep == Keep::Prefix || tear).then(|| d.rng(seed, device));
            let kept = match keep {
                Keep::None => 0,
                Keep::All => n,
                Keep::Prefix => (rng.as_mut().expect("drawn").next_u64() % (n as u64 + 1)) as usize,
            };
            let mut torn = None;
            if tear && kept < n {
                let len = tail[kept].len() as u64;
                torn = Some((rng.as_mut().expect("drawn").next_u64() % len.max(1)) as usize);
            }
            // Roll back every call after the kept ones; the torn one only past its prefix.
            while tail.len() > kept {
                let mut undo = tail.pop().expect("not empty");
                match torn {
                    Some(t) if tail.len() == kept => {
                        let rest = undo.split_off(t);
                        d.roll_back(rest);
                    }
                    _ => d.roll_back(undo),
                }
            }
            recs.push(
                Rec::new("disk-power-loss", name)
                    .with("kept", kept)
                    .with("lost", n - kept)
                    .with("torn", torn.map_or("none".to_owned(), |t| t.to_string()))
                    .with("records", d.map.len())
                    .with("bytes", d.data),
            );
        }
        inner.recount();
        recs
    }

    /// Applies an operator's fault to `device`'s disk `disk`; `Err` is the op's refusal.
    pub(crate) fn fault(&self, device: &str, disk: &str, fault: &DiskFault) -> Result<Rec, String> {
        let mut inner = self.lock();
        let seed = inner.seed;
        let d = inner
            .devices
            .get_mut(device)
            .and_then(|m| m.get_mut(disk))
            .ok_or_else(|| format!("device `{device}` has no disk `{disk}`"))?;
        let rec = match fault {
            DiskFault::Lose => {
                let rec = Rec::new("disk-lost", disk)
                    .with("records", d.map.len())
                    .with("bytes", d.data);
                d.map.clear();
                d.data = 0;
                d.tail.clear();
                rec
            }
            DiskFault::PowerLoss { keep, tear } => {
                d.power_loss = Some((*keep, *tear));
                Rec::new("disk-armed", disk)
                    .with("fault", "power-loss")
                    .with("keep", keep_name(*keep))
                    .with("tear", tear)
            }
            DiskFault::CrashAt { call, keep } => {
                if *call == 0 {
                    return Err("crash-at counts writes from 1".to_owned());
                }
                d.crash_at = Some((d.writes + call, *keep));
                Rec::new("disk-armed", disk)
                    .with("fault", "crash-at")
                    .with("call", call)
                    .with("keep", keep_name(*keep))
            }
            DiskFault::FailCalls { count, text } => {
                d.fail = (*count > 0).then(|| (*count, text.clone()));
                Rec::new("disk-armed", disk)
                    .with("fault", "fail")
                    .with("count", count)
            }
            DiskFault::Corrupt { prefix, how } => {
                let mut rng = d.rng(seed, device);
                let mut values = 0u64;
                let keys: Vec<String> = d
                    .map
                    .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                    .take_while(|(k, _)| k.starts_with(prefix.as_str()))
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in keys {
                    let v = d.map.get_mut(&k).expect("listed");
                    values += 1;
                    corrupt(v, *how, &mut rng);
                }
                Rec::new("disk-corrupted", disk)
                    .with("prefix", prefix)
                    .with("how", corruption_name(*how))
                    .with("values", values)
            }
            DiskFault::Quota(bytes) => {
                d.quota = *bytes;
                Rec::new("disk-quota", disk)
                    .with("quota", bytes)
                    .with("used", d.used())
            }
        };
        inner.recount();
        Ok(rec)
    }

    /// Replaces a declared disk's contents with an image (`disk-loaded`).
    pub(crate) fn load(&self, device: &str, disk: &str, bytes: &[u8]) -> Result<Rec, String> {
        let mut inner = self.lock();
        let held = inner
            .devices
            .get(device)
            .and_then(|m| m.get(disk))
            .map(Disk::used)
            .ok_or_else(|| format!("device `{device}` has no disk `{disk}`"))?;
        let room = inner.total.saturating_sub(inner.used) + held;
        let d = inner
            .devices
            .get_mut(device)
            .and_then(|m| m.get_mut(disk))
            .expect("found above");
        d.load(bytes, room)?;
        let rec = Rec::new("disk-loaded", disk)
            .with("records", d.map.len())
            .with("bytes", d.data)
            .with("digest", hex(&d.digest()));
        inner.recount();
        Ok(rec)
    }

    pub(crate) fn names(&self, device: &str) -> Vec<String> {
        self.lock()
            .devices
            .get(device)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn devices(&self) -> Vec<String> {
        self.lock().devices.keys().cloned().collect()
    }

    pub(crate) fn used(&self) -> (u64, u64) {
        let inner = self.lock();
        (inner.used, inner.total)
    }

    pub(crate) fn read<R>(
        &self,
        device: &str,
        disk: &str,
        f: impl FnOnce(&DiskRead<'_>) -> R,
    ) -> Option<R> {
        let inner = self.lock();
        let d = inner.devices.get(device)?.get(disk)?;
        Some(f(&DiskRead { disk: d }))
    }

    /// One device's calls.
    pub(crate) fn calls<'a>(&'a self, device: &'a str) -> Calls<'a> {
        Calls { set: self, device }
    }
}

fn keep_name(k: Keep) -> &'static str {
    match k {
        Keep::None => "none",
        Keep::All => "all",
        Keep::Prefix => "prefix",
    }
}

fn corruption_name(c: Corruption) -> String {
    match c {
        Corruption::FlipFirstByte => "flip-first-byte".to_owned(),
        Corruption::SeededBytes(n) => format!("seeded-bytes {n}"),
        Corruption::Garbage => "garbage".to_owned(),
    }
}

fn corrupt(v: &mut [u8], how: Corruption, rng: &mut SimRng) {
    match how {
        Corruption::FlipFirstByte => {
            if let Some(b) = v.first_mut() {
                *b ^= 0x5a;
            }
        }
        Corruption::SeededBytes(n) => {
            if v.is_empty() {
                return;
            }
            for _ in 0..n {
                let r = rng.next_u64();
                let at = (r % v.len() as u64) as usize;
                let x = ((r >> 32) % 255) as u8 + 1;
                v[at] ^= x;
            }
        }
        Corruption::Garbage => {
            for chunk in v.chunks_mut(8) {
                let r = rng.next_u64().to_le_bytes();
                chunk.copy_from_slice(&r[..chunk.len()]);
            }
        }
    }
}

fn check_key(k: &str) -> Result<(), DiskError> {
    if k.len() > MAX_KEY {
        return Err(DiskError::TooLarge(format!(
            "a key of {} bytes (at most {MAX_KEY})",
            k.len()
        )));
    }
    Ok(())
}

/// What a call that faults its device leaves for the journal, before the fault.
pub(crate) struct Crash {
    pub rec: Rec,
    pub message: String,
}

/// The calls of one device on its disks, by disk name: every function of
/// `wasi:keyvalue/{store,batch}` and `wasmnet:keyvalue-ext`.
pub(crate) struct Calls<'a> {
    set: &'a DiskSet,
    device: &'a str,
}

impl Calls<'_> {
    /// Runs `f` on the disk, after an armed failure (which answers instead) and counting it.
    fn with<T>(
        &self,
        disk: &str,
        f: impl FnOnce(&mut Disk, &mut Inner2) -> Result<T, DiskError>,
    ) -> Result<T, DiskError> {
        let mut inner = self.set.lock();
        let Inner {
            devices,
            used,
            total,
            seed,
        } = &mut *inner;
        let d = devices
            .get_mut(self.device)
            .and_then(|m| m.get_mut(disk))
            .ok_or(DiskError::NoSuchStore)?;
        d.stats.calls += 1;
        if let Some((n, text)) = &mut d.fail {
            let text = text.clone();
            *n -= 1;
            if *n == 0 {
                d.fail = None;
            }
            d.stats.errors += 1;
            return Err(DiskError::Failed(text));
        }
        let before = d.used();
        let mut ctx = Inner2 {
            room: total.saturating_sub(*used),
            seed: *seed,
            device: self.device,
        };
        let r = f(d, &mut ctx);
        if r.is_err() {
            d.stats.errors += 1;
        }
        let after = d.used();
        *used = used.saturating_sub(before) + after;
        r
    }

    /// `store.open`: the disk exists for this device.
    pub(crate) fn open(&self, disk: &str) -> Result<(), DiskError> {
        self.with(disk, |_, _| Ok(()))
    }

    pub(crate) fn get(&self, disk: &str, key: &str) -> Result<Option<Vec<u8>>, DiskError> {
        check_key(key)?;
        self.with(disk, |d, _| Ok(d.map.get(key).cloned()))
    }

    pub(crate) fn exists(&self, disk: &str, key: &str) -> Result<bool, DiskError> {
        check_key(key)?;
        self.with(disk, |d, _| Ok(d.map.contains_key(key)))
    }

    /// `list-keys`: ascending, a page of [`LIST_PAGE`] after the cursor (the last key given).
    pub(crate) fn list_keys(
        &self,
        disk: &str,
        cursor: Option<String>,
    ) -> Result<(Vec<String>, Option<String>), DiskError> {
        self.with(disk, |d, _| {
            let start = cursor.map_or(Bound::Unbounded, Bound::Excluded);
            let keys: Vec<String> = d
                .map
                .range::<String, _>((start, Bound::Unbounded))
                .take(LIST_PAGE)
                .map(|(k, _)| k.clone())
                .collect();
            let next = (keys.len() == LIST_PAGE).then(|| keys[LIST_PAGE - 1].clone());
            Ok((keys, next))
        })
    }

    pub(crate) fn get_many(&self, disk: &str, keys: Vec<String>) -> Result<Vec<Found>, DiskError> {
        for k in &keys {
            check_key(k)?;
        }
        if keys.len() > MAX_CHANGES {
            return Err(DiskError::TooLarge(format!(
                "{} keys (at most {MAX_CHANGES})",
                keys.len()
            )));
        }
        self.with(disk, |d, _| {
            let mut bytes = 0usize;
            let mut out = Vec::with_capacity(keys.len());
            for k in keys {
                let v = d.map.get(&k).cloned();
                bytes += v.as_ref().map_or(0, Vec::len);
                if bytes > MAX_WRITE_BYTES {
                    return Err(DiskError::TooLarge(format!(
                        "values of more than {MAX_WRITE_BYTES} bytes in one call"
                    )));
                }
                out.push((k, v));
            }
            Ok(out)
        })
    }

    /// `ordered.write` (and every standard function that changes the disk): all or none,
    /// unless a [`DiskFault::CrashAt`] tears it, in which case the error is
    /// [`DiskError::Fault`] and `crash` holds the record to journal first.
    pub(crate) fn write(
        &self,
        disk: &str,
        changes: Vec<Change>,
        crash: &mut Option<Crash>,
    ) -> Result<(), DiskError> {
        let mut bytes = 0usize;
        for c in &changes {
            let v = match c {
                Change::Set(_, v) => v.len(),
                Change::Delete(_) => 0,
            };
            check_key(c.key())?;
            if v > MAX_VALUE {
                return Err(DiskError::TooLarge(format!(
                    "a value of {v} bytes (at most {MAX_VALUE})"
                )));
            }
            bytes += c.key().len() + v;
        }
        if changes.len() > MAX_CHANGES || bytes > MAX_WRITE_BYTES {
            return Err(DiskError::TooLarge(format!(
                "a write of {} changes and {bytes} bytes (at most {MAX_CHANGES} and {MAX_WRITE_BYTES})",
                changes.len()
            )));
        }
        self.with(disk, |d, ctx| {
            let growth = d.growth(&changes);
            if growth > 0 {
                let g = growth as u64;
                if d.used() + g > d.quota {
                    return Err(DiskError::Full(format!(
                        "disk `{}` holds {} of its {} quota bytes; this write adds {g}",
                        d.declared.name,
                        d.used(),
                        d.quota
                    )));
                }
                if g > ctx.room {
                    return Err(DiskError::Full(format!(
                        "the network's disks have {} quota bytes left; this write adds {g}",
                        ctx.room
                    )));
                }
            }
            d.writes += 1;
            let mut apply = changes.len();
            let mut faulted = None;
            if let Some((at, keep)) = d.crash_at
                && d.writes == at
            {
                d.crash_at = None;
                apply = match keep {
                    Keep::None => 0,
                    Keep::All => changes.len(),
                    Keep::Prefix => {
                        let n = changes.len() as u64;
                        (d.rng(ctx.seed, ctx.device).next_u64() % n.max(1)) as usize
                    }
                };
                faulted = Some((d.writes, apply, changes.len()));
            }
            let mut undo = Undo::new();
            for c in changes.into_iter().take(apply) {
                match c {
                    Change::Set(k, v) => d.put(k, Some(v), &mut undo),
                    Change::Delete(k) => d.put(k, None, &mut undo),
                }
            }
            if d.declared.durability == Durability::OnSync && !undo.is_empty() {
                d.tail.push(undo);
            }
            d.note_peak();
            if let Some((call, kept, of)) = faulted {
                let name = d.declared.name.clone();
                *crash = Some(Crash {
                    rec: Rec::new("disk-crash", &name)
                        .with("write", call)
                        .with("kept", kept)
                        .with("of", of),
                    message: format!("disk `{name}` failed inside write {call}"),
                });
                return Err(DiskError::Fault(format!(
                    "disk `{name}` failed inside write {call}"
                )));
            }
            d.stats.writes += 1;
            Ok(())
        })
    }

    /// `ordered.scan`.
    pub(crate) fn scan(
        &self,
        disk: &str,
        prefix: &str,
        after: Option<String>,
        limit: u32,
        values: bool,
    ) -> Result<Vec<Entry>, DiskError> {
        check_key(prefix)?;
        if limit == 0 || limit > MAX_SCAN {
            return Err(DiskError::TooLarge(format!(
                "a scan limit of {limit} (1 to {MAX_SCAN})"
            )));
        }
        self.with(disk, |d, _| {
            let start = match after {
                Some(a) if a.as_str() >= prefix => Bound::Excluded(a),
                _ => Bound::Included(prefix.to_owned()),
            };
            let mut page = Vec::new();
            let mut bytes = 0usize;
            for (k, v) in d.map.range::<String, _>((start, Bound::Unbounded)) {
                if !k.starts_with(prefix) || page.len() >= limit as usize {
                    break;
                }
                let len = k.len() + if values { v.len() } else { 0 };
                if !page.is_empty() && bytes + len > MAX_PAGE_BYTES {
                    break;
                }
                bytes += len;
                page.push(Entry {
                    key: k.clone(),
                    size: v.len() as u64,
                    value: values.then(|| v.clone()),
                });
            }
            Ok(page)
        })
    }

    /// `ordered.get-range`.
    pub(crate) fn get_range(
        &self,
        disk: &str,
        key: &str,
        offset: u64,
        len: u32,
    ) -> Result<Option<Vec<u8>>, DiskError> {
        check_key(key)?;
        if len as usize > MAX_VALUE {
            return Err(DiskError::TooLarge(format!(
                "a read of {len} bytes (at most {MAX_VALUE})"
            )));
        }
        self.with(disk, |d, _| {
            Ok(d.map.get(key).map(|v| {
                let s = offset.min(v.len() as u64) as usize;
                let e = s.saturating_add(len as usize).min(v.len());
                v[s..e].to_vec()
            }))
        })
    }

    /// `durable.mode`.
    pub(crate) fn durability(&self, disk: &str) -> Result<Durability, DiskError> {
        self.with(disk, |d, _| Ok(d.declared.durability))
    }

    /// `durable.sync`: the record to journal (`disk-sync`, for an `on-sync` disk).
    pub(crate) fn sync(&self, disk: &str) -> Result<Option<Rec>, DiskError> {
        self.with(disk, |d, _| {
            d.stats.syncs += 1;
            if d.declared.durability == Durability::EachCall {
                return Ok(None);
            }
            let calls = d.tail.len();
            d.tail.clear();
            Ok(Some(
                Rec::new("disk-sync", &d.declared.name)
                    .with("writes", calls)
                    .with("records", d.map.len())
                    .with("bytes", d.data),
            ))
        })
    }
}

/// What a call may need beyond its disk.
pub(crate) struct Inner2<'a> {
    room: u64,
    seed: u64,
    device: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn set_with(specs: &[DiskSpec]) -> DiskSet {
        let s = DiskSet::new(DEFAULT_TOTAL);
        s.set_seed(7);
        s.declare("d", specs);
        s
    }

    fn set(c: &Calls<'_>, k: &str, v: &[u8]) -> Result<(), DiskError> {
        c.write("a", vec![Change::Set(k.into(), v.to_vec())], &mut None)
    }

    fn keys(s: &DiskSet) -> Vec<String> {
        s.read("d", "a", |r| {
            r.iter("").map(|(k, _)| k.to_owned()).collect()
        })
        .unwrap()
    }

    /// One step of the model test.
    #[derive(Clone, Debug)]
    enum Step {
        Write(Vec<(u8, Option<u8>)>),
        Get(u8),
        Scan(u8, Option<u8>, u32),
        List,
    }

    fn key(k: u8) -> String {
        format!("{}/{k:03}", ["a", "ab", "b"][usize::from(k % 3)])
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            4 => prop::collection::vec((0u8..40, prop::option::of(0u8..4)), 1..6).prop_map(Step::Write),
            2 => (0u8..40).prop_map(Step::Get),
            2 => (0u8..3, prop::option::of(0u8..40), 1u32..8).prop_map(|(p, a, l)| Step::Scan(p, a, l)),
            1 => Just(Step::List),
        ]
    }

    proptest! {
        /// The disk answers what an ordered map would, for any sequence of calls.
        #[test]
        fn the_disk_is_an_ordered_map(steps in prop::collection::vec(step(), 1..60)) {
            let s = set_with(&[DiskSpec::new("a")]);
            let c = s.calls("d");
            let mut model = BTreeMap::<String, Vec<u8>>::new();
            for st in steps {
                match st {
                    Step::Write(changes) => {
                        let changes: Vec<Change> = changes
                            .into_iter()
                            .map(|(k, v)| match v {
                                Some(v) => Change::Set(key(k), vec![v; usize::from(v)]),
                                None => Change::Delete(key(k)),
                            })
                            .collect();
                        for ch in &changes {
                            match ch {
                                Change::Set(k, v) => { model.insert(k.clone(), v.clone()); }
                                Change::Delete(k) => { model.remove(k); }
                            }
                        }
                        c.write("a", changes, &mut None).unwrap();
                    }
                    Step::Get(k) => prop_assert_eq!(c.get("a", &key(k)).unwrap(), model.get(&key(k)).cloned()),
                    Step::Scan(p, after, limit) => {
                        let prefix = ["a", "ab", "b"][usize::from(p)];
                        let after = after.map(key);
                        let got = c.scan("a", prefix, after.clone(), limit, true).unwrap();
                        let want: Vec<Entry> = model
                            .iter()
                            .filter(|(k, _)| k.starts_with(prefix) && after.as_ref().is_none_or(|a| *k > a))
                            .take(limit as usize)
                            .map(|(k, v)| Entry { key: k.clone(), size: v.len() as u64, value: Some(v.clone()) })
                            .collect();
                        prop_assert_eq!(got, want);
                    }
                    Step::List => {
                        let (keys, cursor) = c.list_keys("a", None).unwrap();
                        prop_assert_eq!(keys, model.keys().cloned().collect::<Vec<_>>());
                        prop_assert_eq!(cursor, None);
                    }
                }
                let data: u64 = model.iter().map(|(k, v)| (k.len() + v.len()) as u64).sum();
                let (bytes, used) = s.read("d", "a", |r| (r.bytes(), r.used())).unwrap();
                prop_assert_eq!(bytes, data);
                prop_assert_eq!(used, data + RECORD_OVERHEAD * model.len() as u64);
                prop_assert_eq!(s.used().0, used);
            }
        }

        /// A power loss with a seeded prefix keeps exactly the first `kept` writes, and the torn
        /// one only a prefix of its changes; the same seed tears alike.
        #[test]
        fn a_power_loss_keeps_a_prefix_of_the_tail(writes in 1usize..8, seed in 0u64..50) {
            let run = || {
                let s = DiskSet::new(DEFAULT_TOTAL);
                s.set_seed(seed);
                s.declare("d", &[DiskSpec::new("a").durability(Durability::OnSync)]);
                let c = s.calls("d");
                set(&c, "base", b"0").unwrap();
                c.sync("a").unwrap();
                for w in 0..writes {
                    let changes = (0..3).map(|i| Change::Set(format!("w{w}/{i}"), vec![w as u8])).collect();
                    c.write("a", changes, &mut None).unwrap();
                }
                s.fault("d", "a", &DiskFault::PowerLoss { keep: Keep::Prefix, tear: true }).unwrap();
                let rec = s.power_loss("d").remove(0);
                (keys(&s), rec)
            };
            let (keys, rec) = run();
            prop_assert_eq!(run().0, keys.clone());
            let field = |k: &str| rec.fields.iter().find(|(f, _)| *f == k).unwrap().1.clone();
            let kept: usize = field("kept").parse().unwrap();
            let torn: Option<usize> = field("torn").parse().ok();
            let mut want = vec!["base".to_owned()];
            for w in 0..kept {
                want.extend((0..3).map(|i| format!("w{w}/{i}")));
            }
            if let Some(t) = torn {
                prop_assert!(kept < writes && t < 3);
                want.extend((0..t).map(|i| format!("w{kept}/{i}")));
            }
            want.sort();
            prop_assert_eq!(keys, want);
        }
    }

    #[test]
    fn durability_modes_at_a_power_loss() {
        let s = set_with(&[
            DiskSpec::new("a").durability(Durability::OnSync),
            DiskSpec::new("b"),
        ]);
        let c = s.calls("d");
        set(&c, "k1", b"1").unwrap();
        assert!(c.sync("a").unwrap().is_some());
        set(&c, "k2", b"2").unwrap();
        c.write("b", vec![Change::Set("x".into(), vec![1])], &mut None)
            .unwrap();
        assert!(
            c.sync("b").unwrap().is_none(),
            "each-call disks journal no sync"
        );
        let recs = s.power_loss("d");
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(keys(&s), ["k1"]);
        assert_eq!(s.read("d", "b", |r| r.records()), Some(1));
        // An armed policy keeping everything.
        set(&c, "k3", b"3").unwrap();
        s.fault(
            "d",
            "a",
            &DiskFault::PowerLoss {
                keep: Keep::All,
                tear: false,
            },
        )
        .unwrap();
        s.power_loss("d");
        assert_eq!(keys(&s), ["k1", "k3"]);
    }

    #[test]
    fn a_crash_inside_a_write_keeps_none_all_or_a_prefix() {
        for (keep, want) in [(Keep::None, 0usize), (Keep::All, 4)] {
            let s = set_with(&[DiskSpec::new("a")]);
            let c = s.calls("d");
            s.fault("d", "a", &DiskFault::CrashAt { call: 2, keep })
                .unwrap();
            set(&c, "first", b"").unwrap();
            let changes = (0..4)
                .map(|i| Change::Set(format!("k{i}"), vec![]))
                .collect();
            let mut crash = None;
            assert!(matches!(
                c.write("a", changes, &mut crash),
                Err(DiskError::Fault(_))
            ));
            let crash = crash.expect("a crash record");
            assert_eq!(crash.rec.kind, "disk-crash");
            assert_eq!(keys(&s).len(), 1 + want);
            // Once only.
            set(&c, "after", b"").unwrap();
        }
        let s = set_with(&[DiskSpec::new("a")]);
        let c = s.calls("d");
        s.fault(
            "d",
            "a",
            &DiskFault::CrashAt {
                call: 1,
                keep: Keep::Prefix,
            },
        )
        .unwrap();
        let changes = (0..4)
            .map(|i| Change::Set(format!("k{i}"), vec![]))
            .collect();
        assert!(c.write("a", changes, &mut None).is_err());
        let k = keys(&s);
        assert!(
            k.len() < 4 && k.iter().enumerate().all(|(i, x)| *x == format!("k{i}")),
            "{k:?}"
        );
        assert!(
            s.fault(
                "d",
                "a",
                &DiskFault::CrashAt {
                    call: 0,
                    keep: Keep::None
                }
            )
            .is_err()
        );
    }

    #[test]
    fn quotas_count_records_and_leave_nothing_changed_when_full() {
        let quota = 3 * RECORD_OVERHEAD + 30;
        let s = set_with(&[DiskSpec::new("a").quota(quota)]);
        let c = s.calls("d");
        set(&c, "k1", &[0; 8]).unwrap(); // 10 + 64
        set(&c, "k2", &[0; 8]).unwrap(); // 148
        let before = s.read("d", "a", |r| r.digest()).unwrap();
        // Two more records do not fit: nothing of the write happens.
        let w = vec![
            Change::Set("k3".into(), vec![1]),
            Change::Set("k4".into(), vec![1]),
        ];
        assert!(matches!(
            c.write("a", w, &mut None),
            Err(DiskError::Full(_))
        ));
        assert_eq!(s.read("d", "a", |r| r.digest()).unwrap(), before);
        // Replacing in place and deleting are no growth.
        set(&c, "k1", &[1; 8]).unwrap();
        c.write("a", vec![Change::Delete("k2".into())], &mut None)
            .unwrap();
        // A quota fault below its use: growing is full, shrinking is fine.
        s.fault("d", "a", &DiskFault::Quota(10)).unwrap();
        assert!(matches!(set(&c, "k9", b""), Err(DiskError::Full(_))));
        c.write("a", vec![Change::Delete("k1".into())], &mut None)
            .unwrap();
        // The network's total.
        let s = DiskSet::new(RECORD_OVERHEAD + 2);
        s.declare("d", &[DiskSpec::new("a")]);
        let c = s.calls("d");
        set(&c, "k", b"").unwrap();
        let e = set(&c, "j", b"").unwrap_err();
        assert!(e.text().contains("network"), "{e:?}");
        // Per-call limits.
        assert!(matches!(
            set(&c, &"k".repeat(MAX_KEY + 1), b""),
            Err(DiskError::TooLarge(_))
        ));
        assert!(matches!(
            c.scan("a", "", None, 0, false),
            Err(DiskError::TooLarge(_))
        ));
    }

    #[test]
    fn failures_corruption_loss_and_images() {
        let s = set_with(&[DiskSpec::new("a")]);
        let c = s.calls("d");
        for i in 0..5 {
            set(&c, &format!("v/{i}"), &[i; 32]).unwrap();
        }
        s.fault(
            "d",
            "a",
            &DiskFault::FailCalls {
                count: 2,
                text: "bad sector".into(),
            },
        )
        .unwrap();
        assert_eq!(
            c.get("a", "v/0"),
            Err(DiskError::Failed("bad sector".into()))
        );
        assert!(set(&c, "x", b"").is_err());
        assert!(
            c.get("a", "x").unwrap().is_none(),
            "a failed call changes nothing"
        );
        // Corruption is seeded, the same at the same seed.
        let image = s
            .read("d", "a", |r| {
                let mut v = Vec::new();
                r.export(&mut |b| v.extend_from_slice(b));
                v
            })
            .unwrap();
        let corrupted = |how| {
            let t = set_with(&[DiskSpec::new("a").initial(image.clone())]);
            t.fault(
                "d",
                "a",
                &DiskFault::Corrupt {
                    prefix: "v/".into(),
                    how,
                },
            )
            .unwrap();
            t.read("d", "a", |r| r.digest()).unwrap()
        };
        for how in [
            Corruption::FlipFirstByte,
            Corruption::SeededBytes(3),
            Corruption::Garbage,
        ] {
            assert_eq!(corrupted(how), corrupted(how));
            assert_ne!(corrupted(how), s.read("d", "a", |r| r.digest()).unwrap());
        }
        // The digest is the image's hash; an image loads back to the same disk.
        let digest: [u8; 32] = Sha256::digest(&image).into();
        assert_eq!(s.read("d", "a", |r| r.digest()), Some(digest));
        let t = set_with(&[DiskSpec::new("a")]);
        t.load("d", "a", &image).unwrap();
        assert_eq!(t.read("d", "a", |r| r.digest()), Some(digest));
        assert!(t.load("d", "a", b"junk").is_err());
        let lost = t.fault("d", "a", &DiskFault::Lose).unwrap();
        assert_eq!(lost.kind, "disk-lost");
        assert_eq!(t.read("d", "a", |r| r.records()), Some(0));
        // Declaring again keeps; dropping a name drops it.
        t.declare("d", &[DiskSpec::new("a"), DiskSpec::new("b")]);
        assert_eq!(t.names("d"), ["a", "b"]);
        assert_eq!(t.removed("d").len(), 2);
    }
}
