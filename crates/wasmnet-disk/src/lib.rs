//! wasmnet-disk: a device's disks, as a portable extension on the library's public extension
//! points only.
//!
//! A device declares named disks in its options ([`DiskOptions`], or the option key `disks`
//! from a controller's spec or a page's plain object). Each disk is an ordered map from string
//! keys to byte values that belongs to the device and outlives its store. Guests reach it
//! through the standard `wasi:keyvalue@0.2.0-draft2` (`store`, `batch`) and
//! `wasmnet:keyvalue-ext@0.1.0` (`ordered`, `durable`), every backend linking them from one
//! implementation:
//!
//! * [`Disks`] is the network extension: register it on a network (`add_extension`), and on
//!   wasmtime give the host the typed adapter (`DiskAdapter`, feature `wasmtime`); in a page,
//!   add it from the embedder's own page module (`wasmnet_web::install!`,
//!   `crates/wasmnet-disk-page`). Nothing is installed by default.
//! * Durability per disk ([`Durability`]): every call durable on return, or durable at `sync`.
//!   A stop or a crash of the device, whatever its cause, is a power loss for what is not.
//! * Faults are device-timed operator events ([`DiskOp`], or the op kinds `disk.lose`,
//!   `disk.power-loss`, `disk.crash-at`, `disk.fail`, `disk.corrupt`, `disk.quota`).
//! * Contents never enter the journal: sizes and digests do. Between runs an embedder reads a
//!   disk ([`Disks::read`]), hashes it ([`Disks::digest`]), exports its canonical image
//!   ([`Disks::export`], format `wasmnet-disk/1`, [`image`]) and loads one ([`Disks::load`]).
//!
//! The design note is `docs/design/disk.md`.

mod engine;
pub mod image;
mod server;

use std::collections::BTreeMap;
use std::sync::Arc;

use wasmnet_core::ext::{
    DeviceExt, DeviceLife, DeviceSetup, ExtOp, ExtOpParser, ExtOption, ExtensionOp, LifeEvent,
    NetworkExtension, OpContext, OpError,
};
use wasmnet_core::journal::{JournalEnd, Record};
use wasmnet_core::value::Value;
use wasmnet_core::{DeviceOptions, ImportServer, Interface, VirtualClock};

pub use engine::{
    Change, Corruption, DEFAULT_QUOTA, DEFAULT_TOTAL, DiskError, DiskFault, DiskRead, DiskSpec,
    DiskStats, Durability, Entry, Keep, LIST_PAGE, MAX_CHANGES, MAX_KEY, MAX_PAGE_BYTES, MAX_SCAN,
    MAX_VALUE, MAX_WRITE_BYTES, RECORD_OVERHEAD, digest_hex,
};

use engine::{DiskSet, Rec};

/// The interfaces a disk is served through, by their full names.
pub const STORE: &str = "wasi:keyvalue/store@0.2.0-draft2";
pub const BATCH: &str = "wasi:keyvalue/batch@0.2.0-draft2";
pub const ORDERED: &str = "wasmnet:keyvalue-ext/ordered@0.1.0";
pub const DURABLE: &str = "wasmnet:keyvalue-ext/durable@0.1.0";

/// The import patterns a device that uses disks needs beyond [`wasmnet_core::ImportPolicy::devices`]:
/// an embedder whose controllers supply components that use disks admits them with
/// `ImportPolicy::devices().and(wasmnet_disk::IMPORTS)`.
pub const IMPORTS: [&str; 3] = [
    "wasi:keyvalue/store",
    "wasi:keyvalue/batch",
    "wasmnet:keyvalue-ext/*",
];

/// The device option key that declares disks (a list of `{name, quota, durability, initial}`).
pub const OPTION: &str = "disks";

#[cfg(feature = "wasmtime")]
mod adapter {
    wasmnet_host::portable_adapter!({
        name: DiskAdapter,
        path: ["../../wit/deps/keyvalue", "../../wit/keyvalue-ext"],
        world: "wasmnet:keyvalue-ext/disk-user",
    });
}

/// The wasmtime half (feature `wasmtime`): give it to the host,
/// `Host::builder().extension(DiskAdapter)`.
#[cfg(feature = "wasmtime")]
pub use adapter::DiskAdapter;

/// A device's disks (`DeviceOptions::ext`): `options.ext.set(DiskOptions::new(vec![...]))`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiskOptions {
    pub disks: Vec<DiskSpec>,
}

impl DiskOptions {
    pub fn new(disks: Vec<DiskSpec>) -> Self {
        Self { disks }
    }

    /// With one more disk.
    pub fn disk(mut self, spec: DiskSpec) -> Self {
        self.disks.push(spec);
        self
    }
}

/// Where one device's records go, from its setup.
#[derive(Clone)]
struct End {
    journal: JournalEnd,
    clock: VirtualClock,
}

impl End {
    fn push(&self, rec: Rec) {
        self.journal.push(self.clock.now(), record(rec));
    }
}

fn record(rec: Rec) -> Record {
    Record::Event {
        kind: rec.kind.to_owned(),
        fields: rec
            .fields
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    }
}

/// The network extension: every disk of a network. `network.add_extension(Disks::default())`.
pub struct Disks {
    set: DiskSet,
    ends: BTreeMap<String, End>,
}

impl Default for Disks {
    fn default() -> Self {
        Self::new()
    }
}

impl Disks {
    /// No disks yet, at most [`DEFAULT_TOTAL`] quota bytes on all of them together.
    pub fn new() -> Self {
        Self {
            set: DiskSet::new(DEFAULT_TOTAL),
            ends: BTreeMap::new(),
        }
    }

    /// Sets the most every disk holds together, in quota bytes (key + value +
    /// [`RECORD_OVERHEAD`] per record). Past it a call that would grow a disk answers `full`.
    pub fn total(self, bytes: u64) -> Self {
        self.set.set_total(bytes);
        self
    }

    /// The interfaces every backend links for it.
    pub fn interfaces() -> Vec<Interface> {
        server::interfaces()
    }

    /// The devices that have disks, and the names of one device's disks (ascending).
    pub fn devices(&self) -> Vec<String> {
        self.set.devices()
    }

    pub fn names(&self, device: &str) -> Vec<String> {
        self.set.names(device)
    }

    /// The quota bytes every disk holds together, and the most they may.
    pub fn used(&self) -> (u64, u64) {
        self.set.used()
    }

    /// Reads one disk (between runs, or from an embedder's action): `None` if the device has no
    /// disk of that name.
    pub fn read<R>(
        &self,
        device: &str,
        disk: &str,
        f: impl FnOnce(&DiskRead<'_>) -> R,
    ) -> Option<R> {
        self.set.read(device, disk, f)
    }

    /// SHA-256 of one disk's image.
    pub fn digest(&self, device: &str, disk: &str) -> Option<[u8; 32]> {
        self.read(device, disk, |r| r.digest())
    }

    /// One disk's image, a piece at a time; `false` if there is no such disk.
    pub fn export(&self, device: &str, disk: &str, out: &mut dyn FnMut(&[u8])) -> bool {
        self.read(device, disk, |r| r.export(out)).is_some()
    }

    /// One disk's image, whole.
    pub fn export_vec(&self, device: &str, disk: &str) -> Option<Vec<u8>> {
        let mut v = Vec::new();
        self.export(device, disk, &mut |b| v.extend_from_slice(b))
            .then_some(v)
    }

    /// Replaces a declared disk's contents with an image, durable at once, journalled as
    /// `disk-loaded {disk, records, bytes, digest}`. Refused for a disk the device does not have,
    /// a bad image or one past the quota or the network's room.
    pub fn load(&self, device: &str, disk: &str, image: &[u8]) -> Result<(), String> {
        let rec = self.set.load(device, disk, image)?;
        if let Some(end) = self.ends.get(device) {
            end.push(rec);
        }
        Ok(())
    }
}

fn specs_of(options: &DeviceOptions) -> Vec<DiskSpec> {
    options
        .ext
        .get::<DiskOptions>()
        .map(|o| o.disks.clone())
        .unwrap_or_default()
}

impl NetworkExtension for Disks {
    fn device_setup(&mut self, setup: &DeviceSetup<'_>, ext: &mut DeviceExt) {
        let end = End {
            journal: setup.journal.clone(),
            clock: setup.clock.clone(),
        };
        self.set.set_seed(setup.seed);
        let specs = specs_of(setup.options);
        let had = !self.set.names(setup.name).is_empty();
        if !specs.is_empty() || had {
            for rec in self.set.declare(setup.name, &specs) {
                end.push(rec);
            }
            self.ends.insert(setup.name.to_owned(), end.clone());
        }
        // Every device gets a server, so one that declares no disk and opens one anyway is told
        // `no-such-store` (a device that imports none of the interfaces never calls it).
        let server: Arc<dyn ImportServer> =
            Arc::new(server::Server::new(self.set.clone(), setup.name, end));
        for i in [STORE, BATCH, ORDERED, DURABLE] {
            ext.serve(i, server.clone());
        }
    }

    fn device_life(&mut self, life: &DeviceLife<'_>) {
        let recs = match life.event {
            LifeEvent::Stopped | LifeEvent::Crashed { .. } => self.set.power_loss(life.name),
            // A recreation stops the old store: a power loss. Its new setup declares again.
            LifeEvent::Removed if life.replaced => self.set.power_loss(life.name),
            LifeEvent::Removed => {
                self.ends.remove(life.name);
                self.set.removed(life.name)
            }
            _ => Vec::new(),
        };
        for rec in recs {
            life.journal.push(life.at, record(rec));
        }
    }

    fn interfaces(&self) -> Vec<Interface> {
        server::interfaces()
    }

    /// `disks`: a list of `{name, quota, durability, initial}` (all but `name` optional).
    fn options(&self) -> Vec<ExtOption> {
        vec![ExtOption::new(OPTION, parse_options)]
    }

    /// Names unique and not empty, quotas not 0 and within the network's total, images valid.
    fn check_options(&self, _name: &str, options: &DeviceOptions) -> Result<(), String> {
        let specs = specs_of(options);
        let (_, total) = self.set.used();
        let mut seen = std::collections::BTreeSet::new();
        for s in &specs {
            if s.name.is_empty() {
                return Err("a disk needs a name".to_owned());
            }
            if !seen.insert(s.name.as_str()) {
                return Err(format!("disk `{}` is declared twice", s.name));
            }
            if s.quota == 0 || s.quota > total {
                return Err(format!(
                    "disk `{}`: a quota of {} (1 to the network's {total})",
                    s.name, s.quota
                ));
            }
            if let Some(img) = &s.initial {
                image::read(img)
                    .and_then(|e| e.collect::<Result<Vec<_>, _>>())
                    .map_err(|e| format!("disk `{}`: {e}", s.name))?;
            }
        }
        Ok(())
    }

    fn ops(&self) -> Vec<ExtOpParser> {
        let op = |kind: &'static str, f: fn(&Value) -> Result<DiskFault, String>| {
            ExtOpParser::new(kind, move |v| {
                let disk = text(v, "disk")?.ok_or_else(|| format!("{kind}: `disk` is required"))?;
                Ok(ExtensionOp::new(DiskOp::new(disk, f(v)?)))
            })
        };
        vec![
            op("disk.lose", |_| Ok(DiskFault::Lose)),
            op("disk.power-loss", |v| {
                Ok(DiskFault::PowerLoss {
                    keep: keep(v)?,
                    tear: flag(v, "tear")?,
                })
            }),
            op("disk.crash-at", |v| {
                Ok(DiskFault::CrashAt {
                    call: number(v, "call")?.unwrap_or(1),
                    keep: keep(v)?,
                })
            }),
            op("disk.fail", |v| {
                Ok(DiskFault::FailCalls {
                    count: number(v, "count")?.unwrap_or(1),
                    text: text(v, "text")?.unwrap_or_else(|| "an injected disk failure".to_owned()),
                })
            }),
            op("disk.corrupt", |v| {
                let how = match text(v, "how")?.as_deref() {
                    None | Some("flip-first-byte") => Corruption::FlipFirstByte,
                    Some("garbage") => Corruption::Garbage,
                    Some("seeded-bytes") => Corruption::SeededBytes(
                        u32::try_from(number(v, "bytes")?.unwrap_or(1))
                            .map_err(|e| e.to_string())?,
                    ),
                    Some(other) => return Err(format!("disk.corrupt: no corruption `{other}`")),
                };
                Ok(DiskFault::Corrupt {
                    prefix: text(v, "prefix")?.unwrap_or_default(),
                    how,
                })
            }),
            op("disk.quota", |v| {
                Ok(DiskFault::Quota(
                    number(v, "bytes")?.ok_or("disk.quota: `bytes` is required")?,
                ))
            }),
        ]
    }
}

/// A field of a record value.
fn field<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    match v {
        Value::Record(fields) => fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
            .filter(|v| !matches!(v, Value::None)),
        _ => None,
    }
}

fn text(v: &Value, name: &str) -> Result<Option<String>, String> {
    match field(v, name) {
        None => Ok(None),
        Some(Value::Str(s) | Value::Enum(s)) => Ok(Some(s.clone())),
        Some(Value::Some(b)) => match &**b {
            Value::Str(s) => Ok(Some(s.clone())),
            other => Err(format!("`{name}`: want text, got {other:?}")),
        },
        Some(other) => Err(format!("`{name}`: want text, got {other:?}")),
    }
}

fn number(v: &Value, name: &str) -> Result<Option<u64>, String> {
    match field(v, name) {
        None => Ok(None),
        Some(Value::U32(n)) => Ok(Some(u64::from(*n))),
        Some(Value::U64(n)) => Ok(Some(*n)),
        Some(other) => Err(format!("`{name}`: want a number, got {other:?}")),
    }
}

fn flag(v: &Value, name: &str) -> Result<bool, String> {
    match field(v, name) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(other) => Err(format!("`{name}`: want true or false, got {other:?}")),
    }
}

fn keep(v: &Value) -> Result<Keep, String> {
    match text(v, "keep")?.as_deref() {
        None | Some("none") => Ok(Keep::None),
        Some("all") => Ok(Keep::All),
        Some("prefix") => Ok(Keep::Prefix),
        Some(other) => Err(format!("`keep`: none, all or prefix, not `{other}`")),
    }
}

/// [`OPTION`]'s value: a list of disk records.
fn parse_options(v: &Value) -> Result<DiskOptions, String> {
    let Value::List(items) = v else {
        return Err(format!("`{OPTION}`: want a list of disks, got {v:?}"));
    };
    let mut out = DiskOptions::default();
    for item in items {
        let name = text(item, "name")?.ok_or("a disk needs a `name`")?;
        let mut spec = DiskSpec::new(name);
        if let Some(q) = number(item, "quota")? {
            spec = spec.quota(q);
        }
        spec = spec.durability(match text(item, "durability")?.as_deref() {
            None | Some("each-call") => Durability::EachCall,
            Some("on-sync") => Durability::OnSync,
            Some(other) => {
                return Err(format!("`durability`: each-call or on-sync, not `{other}`"));
            }
        });
        match field(item, "initial") {
            None => {}
            Some(Value::Bytes(b)) => spec = spec.initial(b.clone()),
            Some(other) => return Err(format!("`initial`: want an image's bytes, got {other:?}")),
        }
        out.disks.push(spec);
    }
    Ok(out)
}

/// A fault on a disk of the device the op is timed at:
/// `Op::extension_at(device, ExtensionOp::new(DiskOp::new("state", DiskFault::Lose)))`.
/// Its record is journalled on the device when it applies; a split network applies it on the
/// device's own site.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiskOp {
    pub disk: String,
    pub fault: DiskFault,
}

impl DiskOp {
    pub fn new(disk: impl Into<String>, fault: DiskFault) -> Self {
        Self {
            disk: disk.into(),
            fault,
        }
    }
}

impl ExtOp for DiskOp {
    fn apply(&self, ctx: &mut OpContext<'_>) -> Result<(), OpError> {
        let device = ctx
            .device()
            .ok_or_else(|| OpError::from("a disk fault is timed at a device"))?;
        let name = ctx.device_name(device).to_owned();
        let disks = ctx
            .extension_mut::<Disks>()
            .ok_or_else(|| OpError::from("this network has no disks"))?;
        let rec = disks
            .set
            .fault(&name, &self.disk, &self.fault)
            .map_err(OpError::from)?;
        ctx.journal_event(&name, rec.kind, rec.fields);
        Ok(())
    }

    fn same(&self, other: &dyn ExtOp) -> bool {
        (other as &dyn std::any::Any).downcast_ref::<Self>() == Some(self)
    }
}
