//! One device's server of the four interfaces: [`Value`]s in, [`Value`]s out, in jco's shapes
//! (an option's value may come bare, a tuple as a list), on every backend.

use std::sync::{Mutex, PoisonError};

use wasmnet_core::value::Value;
use wasmnet_core::{ImportServer, Interface, Served};

use crate::engine::{Change, DiskError, DiskSet};
use crate::{BATCH, DURABLE, End, ORDERED, STORE};

/// What every backend links.
pub(crate) fn interfaces() -> Vec<Interface> {
    vec![
        Interface::new(STORE)
            .function("open")
            .function("[method]bucket.get")
            .function("[method]bucket.set")
            .function("[method]bucket.delete")
            .function("[method]bucket.exists")
            .function("[method]bucket.list-keys")
            .resource("bucket"),
        Interface::new(BATCH)
            .function("get-many")
            .function("set-many")
            .function("delete-many"),
        Interface::new(ORDERED)
            .function("write")
            .function("scan")
            .function("get-range"),
        Interface::new(DURABLE).function("mode").function("sync"),
    ]
}

pub(crate) struct Server {
    set: DiskSet,
    device: String,
    end: End,
    /// Open buckets by handle: the disk's name (`None` once dropped).
    handles: Mutex<Vec<Option<String>>>,
}

impl Server {
    pub(crate) fn new(set: DiskSet, device: &str, end: End) -> Self {
        Self {
            set,
            device: device.to_owned(),
            end,
            handles: Mutex::default(),
        }
    }

    fn disk(&self, a: &[Value], i: usize) -> Result<String, String> {
        let h = match a.get(i) {
            Some(Value::Resource(_, h)) => *h,
            other => return Err(format!("argument {i}: want a bucket, got {other:?}")),
        };
        self.handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(h as usize)
            .cloned()
            .flatten()
            .ok_or_else(|| format!("no bucket {h}"))
    }
}

/// An error in the function's own type: the standard's (`no-such-store`, `other`), or the
/// extension's.
fn error(e: &DiskError, ext: bool) -> Value {
    match (e, ext) {
        (DiskError::NoSuchStore, _) => Value::Variant("no-such-store".into(), None),
        (e, false) => Value::case("other", Value::Str(e.text())),
        (DiskError::TooLarge(t), true) => Value::case("too-large", Value::str(t)),
        (DiskError::Full(t), true) => Value::case("full", Value::str(t)),
        (e, true) => Value::case("failed", Value::Str(e.text())),
    }
}

fn str_at(a: &[Value], i: usize) -> Result<String, String> {
    match a.get(i) {
        Some(Value::Str(s)) => Ok(s.clone()),
        other => Err(format!("argument {i}: want a string, got {other:?}")),
    }
}

fn opt_str(a: &[Value], i: usize) -> Result<Option<String>, String> {
    match a.get(i).cloned().map(Value::into_option) {
        None | Some(None) => Ok(None),
        Some(Some(Value::Str(s))) => Ok(Some(s)),
        Some(other) => Err(format!(
            "argument {i}: want an optional string, got {other:?}"
        )),
    }
}

fn take_bytes(a: &mut [Value], i: usize) -> Result<Vec<u8>, String> {
    match a.get_mut(i) {
        Some(Value::Bytes(b)) => Ok(std::mem::take(b)),
        Some(Value::List(l)) if l.is_empty() => Ok(Vec::new()),
        other => Err(format!("argument {i}: want bytes, got {other:?}")),
    }
}

fn num(a: &[Value], i: usize) -> Result<u64, String> {
    match a.get(i) {
        Some(Value::U32(n)) => Ok(u64::from(*n)),
        Some(Value::U64(n)) => Ok(*n),
        other => Err(format!("argument {i}: want a number, got {other:?}")),
    }
}

fn strs(a: &[Value], i: usize) -> Result<Vec<String>, String> {
    match a.get(i) {
        Some(Value::List(l) | Value::Tuple(l)) => l
            .iter()
            .map(|k| match k {
                Value::Str(s) => Ok(s.clone()),
                o => Err(format!("a key: {o:?}")),
            })
            .collect(),
        other => Err(format!("argument {i}: want a list of keys, got {other:?}")),
    }
}

fn opt_bytes(v: Option<Vec<u8>>) -> Value {
    Value::option(v.map(Value::Bytes))
}

/// A pair (a tuple, or a list as jco gives tuples) of a key and a value.
fn pair(p: &mut Value) -> Result<(String, Vec<u8>), String> {
    match p {
        Value::List(t) | Value::Tuple(t) => Ok((str_at(t, 0)?, take_bytes(t, 1)?)),
        o => Err(format!("a key and a value: {o:?}")),
    }
}

impl ImportServer for Server {
    fn call(&self, interface: &str, function: &str, args: Vec<Value>) -> Served {
        let ext = interface == ORDERED || interface == DURABLE;
        let mut crash = None;
        let served = self.serve(function, args, &mut crash);
        if let Some(c) = crash {
            self.end.push(c.rec);
            return Served::Fault(c.message);
        }
        match served {
            Ok(Ok(v)) => Served::Ok(v),
            Ok(Err(DiskError::Fault(m))) => Served::Fault(m),
            Ok(Err(e)) => Served::Err(error(&e, ext)),
            Err(m) => Served::Fault(format!("disk: {interface}#{function}: {m}")),
        }
    }

    fn drop_resource(&self, _interface: &str, _resource: &str, handle: u32) {
        if let Some(slot) = self
            .handles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(handle as usize)
        {
            *slot = None;
        }
    }
}

impl Server {
    /// `Err`: arguments of the wrong shape (a guest's or a backend's bug: the device faults).
    fn serve(
        &self,
        function: &str,
        mut a: Vec<Value>,
        crash: &mut Option<crate::engine::Crash>,
    ) -> Result<Result<Value, DiskError>, String> {
        let c = self.set.calls(&self.device);
        let none = |r: Result<(), DiskError>| r.map(|()| Value::None);
        Ok(match function {
            "open" => {
                let name = str_at(&a, 0)?;
                c.open(&name).map(|()| {
                    let mut h = self.handles.lock().unwrap_or_else(PoisonError::into_inner);
                    h.push(Some(name));
                    Value::resource("bucket", (h.len() - 1) as u32)
                })
            }
            "[method]bucket.get" => c.get(&self.disk(&a, 0)?, &str_at(&a, 1)?).map(opt_bytes),
            "[method]bucket.set" => {
                let v = take_bytes(&mut a, 2)?;
                let change = Change::Set(str_at(&a, 1)?, v);
                none(c.write(&self.disk(&a, 0)?, vec![change], crash))
            }
            "[method]bucket.delete" => {
                let change = Change::Delete(str_at(&a, 1)?);
                none(c.write(&self.disk(&a, 0)?, vec![change], crash))
            }
            "[method]bucket.exists" => c
                .exists(&self.disk(&a, 0)?, &str_at(&a, 1)?)
                .map(Value::Bool),
            "[method]bucket.list-keys" => {
                c.list_keys(&self.disk(&a, 0)?, opt_str(&a, 1)?)
                    .map(|(keys, cursor)| {
                        Value::record(vec![
                            (
                                "keys",
                                Value::List(keys.into_iter().map(Value::Str).collect()),
                            ),
                            ("cursor", Value::option(cursor.map(Value::Str))),
                        ])
                    })
            }
            "get-many" => c.get_many(&self.disk(&a, 0)?, strs(&a, 1)?).map(|kv| {
                Value::List(
                    kv.into_iter()
                        .map(|(k, v)| Value::Tuple(vec![Value::Str(k), opt_bytes(v)]))
                        .collect(),
                )
            }),
            "set-many" => {
                let changes = match a.get_mut(1) {
                    Some(Value::List(l)) => l
                        .iter_mut()
                        .map(|p| pair(p).map(|(k, v)| Change::Set(k, v)))
                        .collect::<Result<_, String>>()?,
                    o => return Err(format!("argument 1: want pairs, got {o:?}")),
                };
                none(c.write(&self.disk(&a, 0)?, changes, crash))
            }
            "delete-many" => {
                let changes = strs(&a, 1)?.into_iter().map(Change::Delete).collect();
                none(c.write(&self.disk(&a, 0)?, changes, crash))
            }
            "write" => {
                let changes = match a.get_mut(1) {
                    Some(Value::List(l)) => l
                        .iter_mut()
                        .map(|ch| match ch {
                            Value::Variant(tag, Some(p)) if tag == "set" => {
                                pair(p).map(|(k, v)| Change::Set(k, v))
                            }
                            Value::Variant(tag, Some(p)) if tag == "delete" => match &**p {
                                Value::Str(k) => Ok(Change::Delete(k.clone())),
                                o => Err(format!("delete: {o:?}")),
                            },
                            o => Err(format!("a change: {o:?}")),
                        })
                        .collect::<Result<_, String>>()?,
                    o => return Err(format!("argument 1: want changes, got {o:?}")),
                };
                none(c.write(&self.disk(&a, 0)?, changes, crash))
            }
            "scan" => {
                let values = matches!(a.get(4), Some(Value::Bool(true)));
                let limit = u32::try_from(num(&a, 3)?).map_err(|e| e.to_string())?;
                c.scan(
                    &self.disk(&a, 0)?,
                    &str_at(&a, 1)?,
                    opt_str(&a, 2)?,
                    limit,
                    values,
                )
                .map(|es| {
                    Value::List(
                        es.into_iter()
                            .map(|e| {
                                Value::record(vec![
                                    ("key", Value::Str(e.key)),
                                    ("size", Value::U64(e.size)),
                                    ("value", opt_bytes(e.value)),
                                ])
                            })
                            .collect(),
                    )
                })
            }
            "get-range" => {
                let len = u32::try_from(num(&a, 3)?).map_err(|e| e.to_string())?;
                c.get_range(&self.disk(&a, 0)?, &str_at(&a, 1)?, num(&a, 2)?, len)
                    .map(opt_bytes)
            }
            "mode" => match c.durability(&self.disk(&a, 0)?) {
                Ok(d) => Ok(Value::Enum(d.name().to_owned())),
                // `mode` answers no error: a gone disk reads as the default.
                Err(_) => Ok(Value::Enum("each-call".to_owned())),
            },
            "sync" => match c.sync(&self.disk(&a, 0)?) {
                Ok(rec) => {
                    if let Some(rec) = rec {
                        self.end.push(rec);
                    }
                    Ok(Value::None)
                }
                Err(e) => Err(e),
            },
            other => return Err(format!("no function `{other}`")),
        })
    }
}
