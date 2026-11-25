//! The boundary's byte encoding: how structured values cross between this module and JavaScript.
//!
//! Only bytes cross the boundary, so everything that is more than a number is written in one
//! small, length-prefixed format. There is no schema negotiation and no versioning beyond this
//! crate's version: both sides are built together.
//!
//! # Primitives
//!
//! ```text
//! u8               1 byte
//! u32, u64         little-endian, 4 and 8 bytes
//! bytes            u32 length, then that many bytes
//! str              bytes holding UTF-8
//! list<T>          u32 count, then that many T
//! pairs            list<(str key, str value)>
//! ```
//!
//! A reader rejects truncated input, invalid UTF-8 and trailing bytes; it never trusts a count
//! enough to allocate for it up front.
//!
//! # Messages
//!
//! ```text
//! plan       (to js_instantiate)    str name, str component, pairs config
//! instance   (from js_instantiate)  list<port>, u32 flags, list<str> apps, list<str> exports
//!            (every exported interface, without a version)
//!            port = u32 id, str name, bytes mac (empty: none, else 6 bytes), u32 mtu
//!            flags: bit 0 exports wasmnet:link/counters, bit 1 wasmnet:link/lifecycle,
//!                   bit 2 wasmnet:control/commands, bit 3 wasmnet:reconfigure/reconfigure
//! counters   (from js_counters, out of wn_counters)   list<(str name, u64 value)>
//! event      (into wn_event)        str kind, pairs fields
//! config     (into wn_add_device, out of wn_config_all)   pairs
//! value      (into wn_add_device as its options, wn_link_with, wn_add_op; out of wn_op_states,
//!            wn_costs)   one `value` (below): plain JavaScript objects, read by `crate::ops`
//! strs       (out of wn_args; into wn_set_catalog)   list<str>: argv, the device's name first;
//!            the catalog's component names
//! imports    (from js_imports)      u8 0 unknown, or u8 1 then list<str>: a component's import names
//! pairs      (out of wn_env)        pairs, in order
//! command    (out of wn_command)   u8 0 ok, 1 refused; str text
//! infra call (into wn_infra, wn_infra_wait, wn_import; to js_export)   str function
//!            (`devices.apply`, `wasmnet:control/commands#invoke`), list<value> args
//! infra reply (out of wn_infra, wn_infra_wait, wn_import; from js_export)  u8 0 value, then
//!            value; 1 error, then value (thrown in JavaScript); 2 failed (a malformed call),
//!            then str message
//! value      u8 kind, then by kind: 0 none, 1 some + value, 2 bool (u8), 3 u32, 4 u64, 5 str,
//!            6 bytes, 7 list<value>, 8 tuple (list<value>), 9 record (list<(str field,
//!            value)>, WIT names), 10 variant (str case, u8 0 or 1 + value), 11 enum (str),
//!            12 resource (str resource, u32 handle)
//! journal    (out of wn_journal)    list<row>
//!            row = u64 at (ns), str device, u8 record, then by record:
//!              0 log:    u8 level (0 trace, 1 debug, 2 info, 3 warn, 4 error), str message
//!              1 event:  str kind, pairs fields
//!              2 output: u8 stream (0 stdout, 1 stderr), str line
//!              255:      str text (a record kind newer than this encoding, as debug text)
//! outcome    (out of wn_finish)     u8 kind, then by kind:
//!              0 quiescent: u64 at, list<str> parked, list<str> daemons
//!              1 deadline:  u64 at, u64 pending events
//!              2 failed:    u64 at, str message
//! ```

use wasmnet_core::{DeclaredPort, DeviceConfig, JournalEntry, Level, Outcome, Record, Stream};

use crate::host::Instance;
use crate::infra::Reply;
use crate::network::RunOutcome;

/// Why bytes from the other side could not be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed {what} at byte {at}")]
#[non_exhaustive]
pub struct DecodeError {
    /// Where reading stopped.
    pub at: usize,
    /// What was expected there.
    pub what: &'static str,
}

/// Builds one message.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// A count or a length. Nothing this crate writes comes near 4 GiB; longer input saturates
    /// (and the reader then fails on it).
    fn len(&mut self, n: usize) -> &mut Self {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX))
    }

    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.len(v.len());
        self.buf.extend_from_slice(v);
        self
    }

    pub fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    /// `list<str>`.
    pub fn strs<S: AsRef<str>>(&mut self, items: &[S]) -> &mut Self {
        self.len(items.len());
        for s in items {
            self.str(s.as_ref());
        }
        self
    }

    /// `pairs`, in the iterator's order.
    pub fn pairs<'a>(
        &mut self,
        items: impl ExactSizeIterator<Item = (&'a str, &'a str)>,
    ) -> &mut Self {
        self.len(items.len());
        for (k, v) in items {
            self.str(k).str(v);
        }
        self
    }

    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

/// Reads one message.
pub struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.buf.len());
        let Some(end) = end else {
            return Err(DecodeError { at: self.at, what });
        };
        let out = &self.buf[self.at..end];
        self.at = end;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1, "u8")?[0])
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4, "u32")?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8, "u64")?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.u32()? as usize;
        self.take(n, "bytes")
    }

    pub fn str(&mut self) -> Result<String, DecodeError> {
        let at = self.at;
        let b = self.bytes()?;
        std::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|_| DecodeError { at, what: "UTF-8" })
    }

    /// `list<str>`.
    pub fn strs(&mut self) -> Result<Vec<String>, DecodeError> {
        let n = self.u32()?;
        (0..n).map(|_| self.str()).collect()
    }

    /// `pairs`, in their order.
    pub fn pairs(&mut self) -> Result<Vec<(String, String)>, DecodeError> {
        let n = self.u32()?;
        (0..n).map(|_| Ok((self.str()?, self.str()?))).collect()
    }

    /// Fails unless every byte was read.
    pub fn end(&self) -> Result<(), DecodeError> {
        if self.at == self.buf.len() {
            Ok(())
        } else {
            Err(DecodeError {
                at: self.at,
                what: "end of message",
            })
        }
    }
}

/// A whole message read by `f`, with nothing left over.
fn whole<T>(
    bytes: &[u8],
    f: impl FnOnce(&mut Reader<'_>) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut r = Reader::new(bytes);
    let v = f(&mut r)?;
    r.end()?;
    Ok(v)
}

fn config_pairs(config: &DeviceConfig) -> impl ExactSizeIterator<Item = (&str, &str)> {
    config.iter().map(|(k, v)| (k.as_str(), v.as_str()))
}

// ---- plan ----------------------------------------------------------------------------------

/// The `plan` message: what [`crate::JsHost::instantiate`] gets, for JavaScript.
pub fn encode_plan(name: &str, component: &str, config: &DeviceConfig) -> Vec<u8> {
    Writer::new()
        .str(name)
        .str(component)
        .pairs(config_pairs(config))
        .finish()
}

/// Reads a `plan` message: `(name, component, config)`.
pub fn decode_plan(bytes: &[u8]) -> Result<(String, String, DeviceConfig), DecodeError> {
    whole(bytes, |r| {
        Ok((r.str()?, r.str()?, r.pairs()?.into_iter().collect()))
    })
}

// ---- instance ------------------------------------------------------------------------------

const FLAG_COUNTERS: u32 = 1;
const FLAG_LIFECYCLE: u32 = 2;
const FLAG_COMMANDS: u32 = 4;
const FLAG_RECONFIGURE: u32 = 8;

/// The `instance` message: JavaScript's answer to `js_instantiate`.
pub fn encode_instance(instance: &Instance) -> Vec<u8> {
    let mut w = Writer::new();
    w.len(instance.ports.len());
    for p in &instance.ports {
        w.u32(p.id)
            .str(&p.name)
            .bytes(p.mac.as_deref().unwrap_or_default())
            .u32(p.mtu);
    }
    let flags = u32::from(instance.counters) * FLAG_COUNTERS
        + u32::from(instance.lifecycle) * FLAG_LIFECYCLE
        + u32::from(instance.commands) * FLAG_COMMANDS
        + u32::from(instance.reconfigure) * FLAG_RECONFIGURE;
    w.u32(flags)
        .strs(&instance.apps)
        .strs(&instance.exports)
        .finish()
}

/// Reads an `instance` message. Unknown flag bits are ignored.
pub fn decode_instance(bytes: &[u8]) -> Result<Instance, DecodeError> {
    whole(bytes, |r| {
        let n = r.u32()?;
        let ports = (0..n)
            .map(|_| {
                let id = r.u32()?;
                let name = r.str()?;
                let mac = r.bytes()?;
                let mtu = r.u32()?;
                Ok(DeclaredPort {
                    id,
                    name,
                    mac: (!mac.is_empty()).then(|| mac.to_vec()),
                    mtu,
                })
            })
            .collect::<Result<Vec<_>, DecodeError>>()?;
        let flags = r.u32()?;
        let apps = r.strs()?;
        let exports = r.strs()?;
        Ok(Instance {
            ports,
            apps,
            exports,
            counters: flags & FLAG_COUNTERS != 0,
            lifecycle: flags & FLAG_LIFECYCLE != 0,
            commands: flags & FLAG_COMMANDS != 0,
            reconfigure: flags & FLAG_RECONFIGURE != 0,
        })
    })
}

// ---- counters, events, config --------------------------------------------------------------

/// The `counters` message.
pub fn encode_counters(counters: &[(String, u64)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.len(counters.len());
    for (name, value) in counters {
        w.str(name).u64(*value);
    }
    w.finish()
}

/// Reads a `counters` message.
pub fn decode_counters(bytes: &[u8]) -> Result<Vec<(String, u64)>, DecodeError> {
    whole(bytes, |r| {
        let n = r.u32()?;
        (0..n).map(|_| Ok((r.str()?, r.u64()?))).collect()
    })
}

/// The `event` message.
pub fn encode_event(kind: &str, fields: &[(String, String)]) -> Vec<u8> {
    Writer::new()
        .str(kind)
        .pairs(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .finish()
}

/// Reads an `event` message: `(kind, fields)`.
pub fn decode_event(bytes: &[u8]) -> Result<(String, Vec<(String, String)>), DecodeError> {
    whole(bytes, |r| Ok((r.str()?, r.pairs()?)))
}

/// The `config` message (sorted by key, like [`DeviceConfig`]).
pub fn encode_config(config: &DeviceConfig) -> Vec<u8> {
    Writer::new().pairs(config_pairs(config)).finish()
}

/// Reads a `config` message. A key given twice keeps its last value.
pub fn decode_config(bytes: &[u8]) -> Result<DeviceConfig, DecodeError> {
    whole(bytes, |r| Ok(r.pairs()?.into_iter().collect()))
}

/// The `list<str>` message (out of `wn_args`): a device's `argv`.
pub fn encode_strs<S: AsRef<str>>(items: &[S]) -> Vec<u8> {
    Writer::new().strs(items).finish()
}

/// Reads a `list<str>` message.
pub fn decode_strs(bytes: &[u8]) -> Result<Vec<String>, DecodeError> {
    whole(bytes, |r| r.strs())
}

/// The `imports` message (from `js_imports`): a component's import names, or `None` when
/// JavaScript does not know them.
pub fn encode_imports(imports: Option<&[String]>) -> Vec<u8> {
    match imports {
        Some(names) => Writer::new().u8(1).strs(names).finish(),
        None => Writer::new().u8(0).finish(),
    }
}

/// Reads an `imports` message.
pub fn decode_imports(bytes: &[u8]) -> Result<Option<Vec<String>>, DecodeError> {
    whole(bytes, |r| {
        let at = r.at;
        match r.u8()? {
            0 => Ok(None),
            1 => Ok(Some(r.strs()?)),
            _ => Err(DecodeError {
                at,
                what: "imports",
            }),
        }
    })
}

/// The `pairs` message in the given order (out of `wn_env`): a device's environment.
pub fn encode_pairs(pairs: &[(String, String)]) -> Vec<u8> {
    Writer::new()
        .pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .finish()
}

// ---- journal -------------------------------------------------------------------------------

fn level_code(level: Level) -> u8 {
    match level {
        Level::Trace => 0,
        Level::Debug => 1,
        Level::Info => 2,
        Level::Warn => 3,
        Level::Error => 4,
    }
}

/// A `wasmnet:link/log.level` from its code (0 trace … 4 error); `None` past 4.
pub fn level_of(code: u32) -> Option<Level> {
    Some(match code {
        0 => Level::Trace,
        1 => Level::Debug,
        2 => Level::Info,
        3 => Level::Warn,
        4 => Level::Error,
        _ => return None,
    })
}

/// The `journal` message.
pub fn encode_journal(entries: &[JournalEntry]) -> Vec<u8> {
    let mut w = Writer::new();
    w.len(entries.len());
    for e in entries {
        w.u64(e.at).str(&e.device);
        match &e.record {
            Record::Log { level, message } => {
                w.u8(0).u8(level_code(*level)).str(message);
            }
            Record::Event { kind, fields } => {
                w.u8(1)
                    .str(kind)
                    .pairs(fields.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            }
            Record::Output { stream, line } => {
                let s = match stream {
                    Stream::Stdout => 0,
                    Stream::Stderr => 1,
                };
                w.u8(2).u8(s).str(line);
            }
            other => {
                w.u8(255).str(&format!("{other:?}"));
            }
        }
    }
    w.finish()
}

/// Reads a `journal` message. A row with record kind 255 is an error: this decoder is as old
/// as the encoder that wrote it, so it never meets one.
pub fn decode_journal(bytes: &[u8]) -> Result<Vec<JournalEntry>, DecodeError> {
    whole(bytes, |r| {
        let n = r.u32()?;
        (0..n)
            .map(|_| {
                let at = r.u64()?;
                let device = r.str()?;
                let pos = r.at;
                let record = match r.u8()? {
                    0 => {
                        let level = level_of(u32::from(r.u8()?)).ok_or(DecodeError {
                            at: pos + 1,
                            what: "level",
                        })?;
                        Record::Log {
                            level,
                            message: r.str()?,
                        }
                    }
                    1 => Record::Event {
                        kind: r.str()?,
                        fields: r.pairs()?,
                    },
                    2 => {
                        let stream = match r.u8()? {
                            0 => Stream::Stdout,
                            1 => Stream::Stderr,
                            _ => {
                                return Err(DecodeError {
                                    at: pos + 1,
                                    what: "stream",
                                });
                            }
                        };
                        Record::Output {
                            stream,
                            line: r.str()?,
                        }
                    }
                    _ => {
                        return Err(DecodeError {
                            at: pos,
                            what: "record kind",
                        });
                    }
                };
                Ok(JournalEntry::new(at, device, record))
            })
            .collect()
    })
}

// ---- outcome -------------------------------------------------------------------------------

/// The `outcome` message.
pub fn encode_outcome(outcome: &RunOutcome) -> Vec<u8> {
    let mut w = Writer::new();
    match outcome {
        RunOutcome::Finished(Outcome::Quiescent {
            at,
            parked,
            daemons,
            ..
        }) => {
            w.u8(0).u64(*at).strs(parked).strs(daemons);
        }
        RunOutcome::Finished(Outcome::Deadline {
            at, pending_events, ..
        }) => {
            w.u8(1).u64(*at).u64(*pending_events as u64);
        }
        RunOutcome::Failed { at, message } => {
            w.u8(2).u64(*at).str(message);
        }
        // An outcome this encoding does not know yet reaches the page as a failure.
        RunOutcome::Finished(other) => {
            w.u8(2).u64(0).str(&format!("unencoded outcome: {other:?}"));
        }
    }
    w.finish()
}

/// Reads an `outcome` message.
pub fn decode_outcome(bytes: &[u8]) -> Result<RunOutcome, DecodeError> {
    whole(bytes, |r| {
        let pos = r.at;
        Ok(match r.u8()? {
            0 => RunOutcome::Finished(Outcome::quiescent(r.u64()?, r.strs()?, r.strs()?)),
            1 => RunOutcome::Finished(Outcome::deadline(
                r.u64()?,
                usize::try_from(r.u64()?).unwrap_or(usize::MAX),
            )),
            2 => RunOutcome::Failed {
                at: r.u64()?,
                message: r.str()?,
            },
            _ => {
                return Err(DecodeError {
                    at: pos,
                    what: "outcome kind",
                });
            }
        })
    })
}

// ---- device commands and reconfiguration ---------------------------------------------------

/// The `command` message (out of `wn_command`): the device's answer.
pub fn encode_command_answer(answer: &Result<String, String>) -> Vec<u8> {
    match answer {
        Ok(text) => Writer::new().u8(0).str(text).finish(),
        Err(text) => Writer::new().u8(1).str(text).finish(),
    }
}

/// Reads a `command` message.
pub fn decode_command_answer(bytes: &[u8]) -> Result<Result<String, String>, DecodeError> {
    whole(bytes, |r| {
        let at = r.at;
        match r.u8()? {
            0 => Ok(Ok(r.str()?)),
            1 => Ok(Err(r.str()?)),
            _ => Err(DecodeError { at, what: "answer" }),
        }
    })
}

// ---- values: wasmnet:infra calls -------------------------------------------------------------

/// A WIT value as calls carry it across the boundary (`wasmnet:infra`, the interfaces extensions
/// serve): the core's [`wasmnet_core::value::Value`], close to jco's own shapes, so the
/// JavaScript side converts generically and knows nothing of an interface.
pub use wasmnet_core::value::Value;

/// How deep values nest at most (the interface's deepest is 5); deeper input is malformed.
const MAX_DEPTH: usize = 32;

impl Writer {
    /// A `value`.
    pub fn value(&mut self, v: &Value) -> &mut Self {
        match v {
            Value::None => self.u8(0),
            Value::Some(v) => self.u8(1).value(v),
            Value::Bool(b) => self.u8(2).u8(u8::from(*b)),
            Value::U32(n) => self.u8(3).u32(*n),
            Value::U64(n) => self.u8(4).u64(*n),
            Value::Str(s) => self.u8(5).str(s),
            Value::Bytes(b) => self.u8(6).bytes(b),
            Value::List(items) | Value::Tuple(items) => {
                self.u8(if matches!(v, Value::List(_)) { 7 } else { 8 });
                self.len(items.len());
                for i in items {
                    self.value(i);
                }
                self
            }
            Value::Record(fields) => {
                self.u8(9).len(fields.len());
                for (k, v) in fields {
                    self.str(k).value(v);
                }
                self
            }
            Value::Variant(tag, payload) => {
                self.u8(10).str(tag);
                match payload {
                    Some(p) => self.u8(1).value(p),
                    None => self.u8(0),
                }
            }
            Value::Enum(name) => self.u8(11).str(name),
            Value::Resource(name, handle) => self.u8(12).str(name).u32(*handle),
        }
    }
}

impl Reader<'_> {
    /// A `value`.
    pub fn value(&mut self) -> Result<Value, DecodeError> {
        self.value_at(0)
    }

    fn value_at(&mut self, depth: usize) -> Result<Value, DecodeError> {
        let at = self.at;
        if depth > MAX_DEPTH {
            return Err(DecodeError {
                at,
                what: "value (nested too deep)",
            });
        }
        let d = depth + 1;
        Ok(match self.u8()? {
            0 => Value::None,
            1 => Value::Some(Box::new(self.value_at(d)?)),
            2 => match self.u8()? {
                0 => Value::Bool(false),
                1 => Value::Bool(true),
                _ => {
                    return Err(DecodeError {
                        at: at + 1,
                        what: "bool",
                    });
                }
            },
            3 => Value::U32(self.u32()?),
            4 => Value::U64(self.u64()?),
            5 => Value::Str(self.str()?),
            6 => Value::Bytes(self.bytes()?.to_vec()),
            kind @ (7 | 8) => {
                let n = self.u32()?;
                let items = (0..n)
                    .map(|_| self.value_at(d))
                    .collect::<Result<Vec<_>, _>>()?;
                if kind == 7 {
                    Value::List(items)
                } else {
                    Value::Tuple(items)
                }
            }
            9 => {
                let n = self.u32()?;
                Value::Record(
                    (0..n)
                        .map(|_| Ok((self.str()?, self.value_at(d)?)))
                        .collect::<Result<Vec<_>, DecodeError>>()?,
                )
            }
            10 => {
                let tag = self.str()?;
                let p = self.at;
                let payload = match self.u8()? {
                    0 => None,
                    1 => Some(Box::new(self.value_at(d)?)),
                    _ => {
                        return Err(DecodeError {
                            at: p,
                            what: "payload",
                        });
                    }
                };
                Value::Variant(tag, payload)
            }
            11 => Value::Enum(self.str()?),
            12 => Value::Resource(self.str()?, self.u32()?),
            _ => {
                return Err(DecodeError {
                    at,
                    what: "value kind",
                });
            }
        })
    }
}

/// The `value` message: one value (into `wn_add_device`'s options, `wn_link_with`, `wn_add_op`;
/// out of `wn_op_states`, `wn_costs`).
pub fn encode_value(v: &Value) -> Vec<u8> {
    Writer::new().value(v).finish()
}

/// Reads a `value` message.
pub fn decode_value(bytes: &[u8]) -> Result<Value, DecodeError> {
    whole(bytes, |r| r.value())
}

/// The `infra call` message (into `wn_infra`, `wn_infra_wait`): the function
/// (`devices.apply`, `components.list`, `changes.wait`) and its arguments, in order.
pub fn encode_infra_call(function: &str, args: &[Value]) -> Vec<u8> {
    let mut w = Writer::new();
    w.str(function).len(args.len());
    for a in args {
        w.value(a);
    }
    w.finish()
}

/// Reads an `infra call` message.
pub fn decode_infra_call(bytes: &[u8]) -> Result<(String, Vec<Value>), DecodeError> {
    whole(bytes, |r| {
        let function = r.str()?;
        let n = r.u32()?;
        let args = (0..n).map(|_| r.value()).collect::<Result<Vec<_>, _>>()?;
        Ok((function, args))
    })
}

/// The `infra reply` message (out of `wn_infra`, `wn_infra_wait`).
pub fn encode_infra_reply(reply: &Reply) -> Vec<u8> {
    let mut w = Writer::new();
    match reply {
        Reply::Value(v) => w.u8(0).value(v),
        Reply::Error(v) => w.u8(1).value(v),
        Reply::Failed(m) => w.u8(2).str(m),
    };
    w.finish()
}

/// Reads an `infra reply` message.
pub fn decode_infra_reply(bytes: &[u8]) -> Result<Reply, DecodeError> {
    whole(bytes, |r| {
        let at = r.at;
        Ok(match r.u8()? {
            0 => Reply::Value(r.value()?),
            1 => Reply::Error(r.value()?),
            2 => Reply::Failed(r.str()?),
            _ => {
                return Err(DecodeError {
                    at,
                    what: "reply kind",
                });
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_are_little_endian_and_length_prefixed() {
        let bytes = Writer::new().u8(7).u32(1).u64(2).str("hé").finish();
        assert_eq!(
            bytes,
            [
                7, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, b'h', 0xc3, 0xa9
            ]
        );
    }

    #[test]
    fn messages_round_trip() {
        let config: DeviceConfig = [("ipv4", "10.0.0.1/24"), ("mac", "02:00:00:00:00:01")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        assert_eq!(
            decode_plan(&encode_plan("web", "node:http-server", &config)),
            Ok((
                "web".to_owned(),
                "node:http-server".to_owned(),
                config.clone()
            ))
        );
        assert_eq!(decode_config(&encode_config(&config)), Ok(config));

        let instance = Instance {
            ports: vec![
                DeclaredPort {
                    id: 0,
                    name: "eth0".to_owned(),
                    mac: Some(vec![2, 0, 0, 0, 0, 1]),
                    mtu: 1500,
                },
                DeclaredPort {
                    id: 3,
                    name: "p3".to_owned(),
                    mac: None,
                    mtu: 9000,
                },
            ],
            apps: vec!["http-server".to_owned()],
            counters: true,
            lifecycle: true,
            commands: true,
            reconfigure: false,
            exports: vec!["wasmnet:control/commands".to_owned()],
        };
        assert_eq!(decode_instance(&encode_instance(&instance)), Ok(instance));

        let counters = vec![("rx".to_owned(), 3), ("tx".to_owned(), u64::MAX)];
        assert_eq!(decode_counters(&encode_counters(&counters)), Ok(counters));

        let fields = vec![
            ("b".to_owned(), "2".to_owned()),
            ("a".to_owned(), "1".to_owned()),
        ];
        assert_eq!(
            decode_event(&encode_event("mac-learned", &fields)),
            Ok(("mac-learned".to_owned(), fields.clone()))
        );

        let journal = vec![
            JournalEntry::new(
                5,
                "sw",
                Record::Log {
                    level: Level::Warn,
                    message: "hello".to_owned(),
                },
            ),
            JournalEntry::new(
                6,
                "sw",
                Record::Event {
                    kind: "k".to_owned(),
                    fields,
                },
            ),
            JournalEntry::new(
                7,
                "cli",
                Record::Output {
                    stream: Stream::Stderr,
                    line: "oops".to_owned(),
                },
            ),
        ];
        assert_eq!(decode_journal(&encode_journal(&journal)), Ok(journal));

        for outcome in [
            RunOutcome::Finished(Outcome::quiescent(
                9,
                vec!["a".to_owned()],
                vec!["b: app-x.run".to_owned()],
            )),
            RunOutcome::Finished(Outcome::deadline(10, 2)),
            RunOutcome::Failed {
                at: 11,
                message: "trap".to_owned(),
            },
        ] {
            assert_eq!(decode_outcome(&encode_outcome(&outcome)), Ok(outcome));
        }
    }

    #[test]
    fn values_and_infra_messages_round_trip() {
        let args = vec![
            Value::None,
            Value::str("r1"),
            Value::List(vec![Value::Tuple(vec![Value::str("k"), Value::str("v")])]),
            Value::Bytes(vec![1, 2]),
            Value::Some(Box::new(Value::U64(7))),
            Value::record(vec![("a", Value::Enum("running".to_owned()))]),
            Value::case("ok", Value::Bool(true)),
            Value::U32(9),
        ];
        assert_eq!(
            decode_infra_call(&encode_infra_call("devices.apply", &args)),
            Ok(("devices.apply".to_owned(), args))
        );
        for reply in [
            Reply::Value(Value::U64(1)),
            Reply::Error(Value::case("denied", Value::str("no"))),
            Reply::Failed("bad".to_owned()),
        ] {
            assert_eq!(decode_infra_reply(&encode_infra_reply(&reply)), Ok(reply));
        }
        assert_eq!(decode_imports(&encode_imports(None)), Ok(None));
        let names = vec!["wasmnet:infra/devices@0.1.2".to_owned()];
        assert_eq!(
            decode_imports(&encode_imports(Some(&names))),
            Ok(Some(names))
        );
        // A value nested deeper than any the interface has is malformed, not a stack overflow.
        let deep = vec![1u8; 100_000];
        assert!(Reader::new(&deep).value().is_err());
    }

    #[test]
    fn malformed_input_is_an_error_never_a_panic() {
        let good = encode_plan("a", "b", &DeviceConfig::new());
        for cut in 0..good.len() {
            assert!(decode_plan(&good[..cut]).is_err(), "cut at {cut}");
        }
        let mut long = good.clone();
        long.push(0);
        assert_eq!(
            decode_plan(&long),
            Err(DecodeError {
                at: good.len(),
                what: "end of message"
            })
        );
        // A count that promises far more than the input holds.
        assert!(decode_counters(&[0xff, 0xff, 0xff, 0xff]).is_err());
        // Invalid UTF-8.
        assert!(decode_event(&[1, 0, 0, 0, 0xff, 0, 0, 0, 0]).is_err());
        assert!(decode_outcome(&[9]).is_err());
    }
}
