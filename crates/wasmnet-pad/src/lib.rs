//! wasmnet-pad: a test fixture, and the worked example of a portable extension.
//!
//! It keeps a few named notes per device and serves them as `wasmnet-test:pad/notes`
//! (`wit/test-pad/pad.wit`) on every backend from this one implementation, using only the
//! core's public API:
//!
//! * [`Pad`] is a [`NetworkExtension`]: `device_setup` hands each device a server of the
//!   interface ([`DeviceExt::serve`]), `device_life` reacts to its life (a crash clears its
//!   notes, a removal drops them, a controller's recreation keeps them), `interfaces` declares
//!   what backends link.
//! * The server is an [`ImportServer`]: it reads and answers [`Value`]s, hands out resource
//!   handles of its own (`note`), and faults the device at the append its options arm
//!   ([`PadOptions::fault_at`]), with a message every backend journals alike.
//!
//! On wasmtime an adapter generated from the WIT links it
//! (`wasmnet_host::portable_adapter!`); a page links it from [`Pad::interfaces`] alone.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use wasmnet_core::ext::{
    DeviceExt, DeviceLife, DeviceSetup, ExtOp, ExtOpParser, ExtOption, ExtensionOp, LifeEvent,
    NetworkExtension, OpContext, OpError,
};
use wasmnet_core::journal::{JournalEnd, Record};
use wasmnet_core::value::Value;
use wasmnet_core::{DeviceOptions, ImportServer, Interface, Served, VirtualClock};

/// The interface, as devices import it.
pub const NOTES: &str = "wasmnet-test:pad/notes@0.1.0";

/// The most bytes one device's notes hold; an append past it answers `full`.
pub const MAX_BYTES: u64 = 256 << 20;

/// A device's options for the pad (`DeviceOptions::ext`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PadOptions {
    /// The device faults inside its `n`-th append (counted from its setup), which does not
    /// happen.
    pub fault_at: Option<u32>,
}

impl PadOptions {
    /// Sets [`fault_at`](Self::fault_at).
    pub fn fault_at(mut self, n: u32) -> Self {
        self.fault_at = Some(n);
        self
    }
}

#[derive(Default)]
struct Note {
    bytes: Vec<u8>,
    appends: u32,
}

/// One device's notes.
#[derive(Default)]
struct Notes {
    notes: BTreeMap<String, Note>,
    /// Open handles, by number: the note's name (`None` once dropped).
    handles: Vec<Option<String>>,
    /// Appends since setup, and the one that faults.
    appends: u32,
    fault_at: Option<u32>,
}

impl Notes {
    fn bytes(&self) -> u64 {
        self.notes.values().map(|n| n.bytes.len() as u64).sum()
    }
}

type Shared = Arc<Mutex<Notes>>;

fn lock(n: &Shared) -> MutexGuard<'_, Notes> {
    n.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The network extension. `network.add_extension(Pad::default())`.
#[derive(Default)]
pub struct Pad {
    devices: BTreeMap<String, Shared>,
    /// Faults armed by device name ([`Pad::fault_at`]), for devices whose options cannot say.
    faults: BTreeMap<String, u32>,
    /// Devices given no server ([`Pad::without`]).
    without: Vec<String>,
}

impl Pad {
    /// Arms a fault for the device called `name`: its `n`-th append faults it (as
    /// [`PadOptions::fault_at`], which wins when both are set).
    pub fn fault_at(mut self, name: impl Into<String>, n: u32) -> Self {
        self.faults.insert(name.into(), n);
        self
    }

    /// Gives the device called `name` no server: its first call faults it, as a device whose
    /// import no extension serves.
    pub fn without(mut self, name: impl Into<String>) -> Self {
        self.without.push(name.into());
        self
    }

    /// The interface every backend links for it.
    pub fn interfaces() -> Vec<Interface> {
        vec![
            Interface::new(NOTES)
                .function("[constructor]note")
                .function("[method]note.append")
                .function("[method]note.read")
                .function("[method]note.info")
                .function("[static]note.find")
                .function("names")
                .function("totals")
                .resource("note"),
        ]
    }

    /// `device`'s notes, by name, with their bytes (between runs).
    pub fn notes(&self, device: &str) -> BTreeMap<String, Vec<u8>> {
        self.devices
            .get(device)
            .map(|n| {
                lock(n)
                    .notes
                    .iter()
                    .map(|(k, v)| (k.clone(), v.bytes.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn event(journal: &JournalEnd, at: u64, kind: &str, fields: Vec<(&str, String)>) {
    journal.push(
        at,
        Record::Event {
            kind: kind.to_owned(),
            fields: fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        },
    );
}

impl NetworkExtension for Pad {
    fn device_setup(&mut self, setup: &DeviceSetup<'_>, ext: &mut DeviceExt) {
        let notes = self
            .devices
            .entry(setup.name.to_owned())
            .or_default()
            .clone();
        {
            let mut n = lock(&notes);
            // A new store: the old one's handles went with it.
            n.handles.clear();
            n.appends = 0;
            n.fault_at = setup
                .options
                .ext
                .get::<PadOptions>()
                .and_then(|o| o.fault_at)
                .or_else(|| self.faults.get(setup.name).copied());
        }
        if self.without.iter().any(|w| w == setup.name) {
            return;
        }
        ext.serve(
            NOTES,
            Arc::new(Server {
                notes,
                journal: setup.journal.clone(),
                clock: setup.clock.clone(),
            }),
        );
    }

    fn device_life(&mut self, life: &DeviceLife<'_>) {
        match life.event {
            LifeEvent::Crashed { .. } => {
                if let Some(n) = self.devices.get(life.name) {
                    let mut n = lock(n);
                    let count = n.notes.len();
                    n.notes.clear();
                    event(
                        life.journal,
                        life.at,
                        "pad-cleared",
                        vec![("notes", count.to_string())],
                    );
                }
            }
            LifeEvent::Removed if !life.replaced => {
                if let Some(n) = self.devices.remove(life.name) {
                    let count = lock(&n).notes.len();
                    event(
                        life.journal,
                        life.at,
                        "pad-dropped",
                        vec![("notes", count.to_string())],
                    );
                }
            }
            _ => {}
        }
    }

    fn interfaces(&self) -> Vec<Interface> {
        Self::interfaces()
    }

    /// `pad.fault-at`: [`PadOptions::fault_at`] from a number (a controller's spec, the page's
    /// device options).
    fn options(&self) -> Vec<ExtOption> {
        vec![ExtOption::new("pad.fault-at", |v| match v {
            Value::U32(n) => Ok(PadOptions::default().fault_at(*n)),
            Value::U64(n) => u32::try_from(*n)
                .map(|n| PadOptions::default().fault_at(n))
                .map_err(|_| "a u32".to_owned()),
            other => Err(format!("want a number, got {other:?}")),
        })]
    }

    /// An append counted from 1: `fault_at` 0 never happens, and is refused.
    fn check_options(&self, _name: &str, options: &DeviceOptions) -> Result<(), String> {
        match options.ext.get::<PadOptions>() {
            Some(PadOptions {
                fault_at: Some(0), ..
            }) => Err("pad.fault-at counts appends from 1".to_owned()),
            _ => Ok(()),
        }
    }

    /// `pad.clear`: [`PadOp::Clear`], at the device it is timed at.
    fn ops(&self) -> Vec<ExtOpParser> {
        vec![ExtOpParser::new("pad.clear", |_| {
            Ok(ExtensionOp::new(PadOp::Clear))
        })]
    }
}

/// One device's server.
struct Server {
    notes: Shared,
    journal: JournalEnd,
    clock: VirtualClock,
}

fn malformed(function: &str, args: &[Value]) -> Served {
    Served::Fault(format!(
        "pad: {function}: arguments of the wrong shape: {args:?}"
    ))
}

impl ImportServer for Server {
    fn call(&self, _interface: &str, function: &str, args: Vec<Value>) -> Served {
        let mut n = lock(&self.notes);
        let name_of = |n: &Notes, h: u32| n.handles.get(h as usize).cloned().flatten();
        match (function, args.as_slice()) {
            ("[constructor]note", [Value::Str(name)]) => {
                n.notes.entry(name.clone()).or_default();
                n.handles.push(Some(name.clone()));
                Served::Ok(Value::resource("note", (n.handles.len() - 1) as u32))
            }
            ("[static]note.find", [Value::Str(name)]) => {
                if n.notes.contains_key(name) {
                    n.handles.push(Some(name.clone()));
                    let h = (n.handles.len() - 1) as u32;
                    Served::Ok(Value::option(Some(Value::resource("note", h))))
                } else {
                    Served::Ok(Value::None)
                }
            }
            ("[method]note.append", [Value::Resource(_, h), Value::Bytes(bytes)]) => {
                n.appends += 1;
                if n.fault_at == Some(n.appends) {
                    let at = n.appends;
                    drop(n);
                    event(
                        &self.journal,
                        self.clock.now(),
                        "pad-fault",
                        vec![("append", at.to_string())],
                    );
                    return Served::Fault(format!("pad: append {at} failed"));
                }
                let total = n.bytes();
                if total + bytes.len() as u64 > MAX_BYTES {
                    return Served::Err(Value::case("full", Value::U64(total)));
                }
                let Some(name) = name_of(&n, *h) else {
                    return Served::Err(Value::Variant("gone".into(), None));
                };
                match n.notes.get_mut(&name) {
                    Some(note) => {
                        note.bytes.extend_from_slice(bytes);
                        note.appends += 1;
                        Served::Ok(Value::U64(note.bytes.len() as u64))
                    }
                    None => Served::Err(Value::Variant("gone".into(), None)),
                }
            }
            ("[method]note.read", [Value::Resource(_, h), Value::U64(offset), Value::U32(len)]) => {
                let bytes = name_of(&n, *h)
                    .and_then(|name| n.notes.get(&name))
                    .map(|note| {
                        let s = (*offset).min(note.bytes.len() as u64) as usize;
                        let e = s.saturating_add(*len as usize).min(note.bytes.len());
                        note.bytes[s..e].to_vec()
                    })
                    .unwrap_or_default();
                Served::Ok(Value::Bytes(bytes))
            }
            ("[method]note.info", [Value::Resource(_, h)]) => {
                let name = name_of(&n, *h).unwrap_or_default();
                let (size, appends) = n
                    .notes
                    .get(&name)
                    .map_or((0, 0), |note| (note.bytes.len() as u64, note.appends));
                let state = if size == 0 { "empty" } else { "written" };
                Served::Ok(Value::record(vec![
                    ("name", Value::Str(name)),
                    ("size", Value::U64(size)),
                    ("appends", Value::U32(appends)),
                    ("state", Value::Enum(state.into())),
                ]))
            }
            ("names", []) => Served::Ok(Value::List(
                n.notes.keys().cloned().map(Value::Str).collect(),
            )),
            ("totals", []) => Served::Ok(Value::Tuple(vec![
                Value::U32(n.notes.len() as u32),
                Value::U64(n.bytes()),
            ])),
            _ => {
                drop(n);
                malformed(function, &args)
            }
        }
    }

    fn drop_resource(&self, _interface: &str, _resource: &str, handle: u32) {
        if let Some(slot) = lock(&self.notes).handles.get_mut(handle as usize) {
            *slot = None;
        }
    }
}

/// The fixture's operator events.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PadOp {
    /// Clears the notes of the device the op is timed at (`Op::ExtensionAt`), journalled as
    /// `pad-cleared {notes, by: operator}`.
    Clear,
}

impl ExtOp for PadOp {
    fn apply(&self, ctx: &mut OpContext<'_>) -> Result<(), OpError> {
        let device = ctx
            .device()
            .ok_or_else(|| OpError::from("pad.clear is timed at a device"))?;
        let name = ctx.device_name(device).to_owned();
        let pad = ctx
            .extension_mut::<Pad>()
            .ok_or_else(|| OpError::from("this network has no pad"))?;
        let count = pad.devices.get(&name).map_or(0, |n| {
            let mut n = lock(n);
            let count = n.notes.len();
            n.notes.clear();
            count
        });
        ctx.journal_event(
            &name,
            "pad-cleared",
            vec![("notes", count.to_string()), ("by", "operator".to_owned())],
        );
        Ok(())
    }

    fn same(&self, other: &dyn ExtOp) -> bool {
        (other as &dyn std::any::Any).downcast_ref::<Self>() == Some(self)
    }
}
