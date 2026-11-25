//! What the page asks of the network as generic values ([`Value`], from plain JavaScript
//! objects): a device's options, a link's options, an operator event and its placement; and what
//! it reads back the same way (the operator events' states, the devices' costs).
//!
//! The shapes are decided here, in Rust, against the core's own types and constructors, so the
//! TypeScript binding converts values generically and mirrors no option and no op: a new option
//! or op of the core needs a case here, and at most a type on the TypeScript side. Field names
//! are the TypeScript ones in kebab case (`journalStdio` arrives as `journal-stdio`); integers
//! may come as numbers or bigints. A field this module does not know is refused, so a misspelt
//! option fails loudly rather than being ignored.

use std::collections::BTreeMap;

use wasmnet_core::{
    CaptureOptions, Cascade, DeviceCommand, DeviceCost, DeviceId, DeviceOptions, Impairments,
    Nanos, Op, OpState, Placement, SupplyLimits,
};

use crate::codec::Value;

/// A record's fields, read by name, every one of them accounted for.
struct Fields<'a> {
    what: &'a str,
    map: BTreeMap<&'a str, &'a Value>,
}

impl<'a> Fields<'a> {
    fn new(what: &'a str, v: &'a Value, known: &[&str]) -> Result<Self, String> {
        let Value::Record(fields) = v else {
            return Err(format!("{what}: want an object, got {v:?}"));
        };
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            if !known.contains(&k.as_str()) {
                return Err(format!(
                    "{what}: unknown field `{k}` (known: {})",
                    known.join(", ")
                ));
            }
            // An option that is absent arrives as `none`: the same as leaving it out.
            if !matches!(v, Value::None) {
                map.insert(k.as_str(), v);
            }
        }
        Ok(Self { what, map })
    }

    fn get(&self, k: &str) -> Option<&'a Value> {
        self.map.get(k).copied()
    }

    fn wrong(&self, k: &str, want: &str) -> String {
        format!("{}: `{k}` must be {want}", self.what)
    }

    fn need(&self, k: &str) -> Result<&'a Value, String> {
        self.get(k)
            .ok_or_else(|| format!("{}: `{k}` is required", self.what))
    }

    fn str(&self, k: &str) -> Result<String, String> {
        match self.need(k)? {
            Value::Str(s) => Ok(s.clone()),
            _ => Err(self.wrong(k, "a string")),
        }
    }

    fn opt_str(&self, k: &str) -> Result<Option<String>, String> {
        self.get(k).map(|_| self.str(k)).transpose()
    }

    fn bool(&self, k: &str) -> Result<bool, String> {
        match self.get(k) {
            None => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(self.wrong(k, "a boolean")),
        }
    }

    fn opt_u64(&self, k: &str) -> Result<Option<u64>, String> {
        match self.get(k) {
            None => Ok(None),
            Some(Value::U32(n)) => Ok(Some(u64::from(*n))),
            Some(Value::U64(n)) => Ok(Some(*n)),
            Some(_) => Err(self.wrong(k, "a whole number")),
        }
    }

    fn u64(&self, k: &str) -> Result<u64, String> {
        self.opt_u64(k)?
            .ok_or_else(|| format!("{}: `{k}` is required", self.what))
    }

    fn opt_u32(&self, k: &str) -> Result<Option<u32>, String> {
        self.opt_u64(k)?
            .map(|n| u32::try_from(n).map_err(|_| self.wrong(k, "a 32-bit number")))
            .transpose()
    }

    fn u32(&self, k: &str) -> Result<u32, String> {
        self.opt_u32(k)?
            .ok_or_else(|| format!("{}: `{k}` is required", self.what))
    }

    fn strs(&self, k: &str) -> Result<Vec<String>, String> {
        match self.get(k) {
            None => Ok(Vec::new()),
            Some(Value::List(items)) => items
                .iter()
                .map(|i| match i {
                    Value::Str(s) => Ok(s.clone()),
                    _ => Err(self.wrong(k, "a list of strings")),
                })
                .collect(),
            Some(_) => Err(self.wrong(k, "a list of strings")),
        }
    }

    /// A list of `[key, value]` pairs of strings.
    fn pairs(&self, k: &str) -> Result<Vec<(String, String)>, String> {
        match self.get(k) {
            None => Ok(Vec::new()),
            Some(Value::List(items)) => items
                .iter()
                .map(|i| match i {
                    Value::List(p) | Value::Tuple(p) => match p.as_slice() {
                        [Value::Str(a), Value::Str(b)] => Ok((a.clone(), b.clone())),
                        _ => Err(self.wrong(k, "a list of [key, value] string pairs")),
                    },
                    _ => Err(self.wrong(k, "a list of [key, value] string pairs")),
                })
                .collect(),
            Some(_) => Err(self.wrong(k, "a list of [key, value] string pairs")),
        }
    }

    /// Bytes, or a string as its UTF-8 bytes.
    fn bytes(&self, k: &str) -> Result<Vec<u8>, String> {
        match self.need(k)? {
            Value::Bytes(b) => Ok(b.clone()),
            Value::Str(s) => Ok(s.clone().into_bytes()),
            _ => Err(self.wrong(k, "bytes or a string")),
        }
    }
}

// ---- device options ------------------------------------------------------------------------

const OPTIONS: &[&str] = &[
    "journal-stdio",
    "infra",
    "infra-prefix",
    "infra-cascade",
    "infra-max-devices",
    "infra-supply",
    "memory",
    "fuel-per-instant",
    "crash-alone",
    "args",
    "env",
];

/// A device's options (`DeviceOptions`) from a value: the fields of `OPTIONS`, every one
/// optional. `infra-supply` is `true` (the core's default limits) or
/// `{ max-bytes, max-components, max-total }`; `env` is a list of `[name, value]` pairs.
pub fn options(v: &Value) -> Result<DeviceOptions, String> {
    let f = Fields::new("device options", v, OPTIONS)?;
    let mut o = DeviceOptions::default();
    o.journal_stdio = f.bool("journal-stdio")?;
    o.infra = f.bool("infra")?;
    o.infra_prefix = f.opt_str("infra-prefix")?;
    o.infra_cascade = match f.opt_str("infra-cascade")?.as_deref() {
        None | Some("keep") => Cascade::Keep,
        Some("stop") => Cascade::Stop,
        Some("remove") => Cascade::Remove,
        Some(_) => return Err(f.wrong("infra-cascade", "keep, stop or remove")),
    };
    o.infra_max_devices = f.opt_u32("infra-max-devices")?;
    o.infra_supply = match f.get("infra-supply") {
        None | Some(Value::Bool(false)) => None,
        Some(Value::Bool(true)) => Some(SupplyLimits::default()),
        Some(v) => {
            let s = Fields::new(
                "infra-supply",
                v,
                &["max-bytes", "max-components", "max-total"],
            )?;
            let d = SupplyLimits::default();
            Some(
                d.max_bytes(s.opt_u64("max-bytes")?.unwrap_or(d.max_bytes))
                    .max_components(s.opt_u32("max-components")?.unwrap_or(d.max_components))
                    .max_total(s.opt_u64("max-total")?.unwrap_or(d.max_total)),
            )
        }
    };
    o.memory = f.opt_u64("memory")?;
    o.fuel_per_instant = f.opt_u64("fuel-per-instant")?;
    o.crash_alone = f.bool("crash-alone")?;
    o.args = f.strs("args")?;
    o.env = f.pairs("env")?;
    Ok(o)
}

// ---- links ---------------------------------------------------------------------------------

/// How a link is set up when it is made.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkSetup {
    pub latency: Nanos,
    pub mtu: Option<u32>,
    /// By sending end: `[a -> b, b -> a]`.
    pub impairments: [Impairments; 2],
    pub capture: Option<CaptureOptions>,
}

fn impairments(what: &str, v: &Value) -> Result<Impairments, String> {
    let f = Fields::new(what, v, &["rate", "queue", "loss-ppm", "jitter"])?;
    let mut i = Impairments::default();
    i.rate = f.opt_u64("rate")?.unwrap_or(i.rate);
    i.queue = f.opt_u32("queue")?.unwrap_or(i.queue);
    i.loss_ppm = f.opt_u32("loss-ppm")?.unwrap_or(i.loss_ppm);
    i.jitter = f.opt_u64("jitter")?.unwrap_or(i.jitter);
    Ok(i)
}

/// A link's setup from a value: `latency` (ns), `mtu`, `impair` (both directions) or
/// `impair-ab` and `impair-ba` (each `{ rate, queue, loss-ppm, jitter }`), `capture`
/// (`{ record, snap-len, name-ends }`).
pub fn link(v: &Value) -> Result<LinkSetup, String> {
    let f = Fields::new(
        "link options",
        v,
        &[
            "latency",
            "mtu",
            "impair",
            "impair-ab",
            "impair-ba",
            "capture",
        ],
    )?;
    let mut s = LinkSetup {
        latency: f.opt_u64("latency")?.unwrap_or(0),
        mtu: f.opt_u32("mtu")?,
        ..LinkSetup::default()
    };
    if let Some(both) = f.get("impair") {
        let i = impairments("impair", both)?;
        s.impairments = [i, i];
    }
    for (n, k) in ["impair-ab", "impair-ba"].into_iter().enumerate() {
        if let Some(v) = f.get(k) {
            s.impairments[n] = impairments(k, v)?;
        }
    }
    if let Some(c) = f.get("capture") {
        let c = Fields::new("capture", c, &["record", "snap-len", "name-ends"])?;
        let mut o = CaptureOptions::default();
        if c.get("record").is_some() {
            o.record = c.bool("record")?;
        }
        o.snap_len = c.opt_u32("snap-len")?.unwrap_or(o.snap_len);
        o.name_ends = c.bool("name-ends")?;
        s.capture = Some(o);
    }
    Ok(s)
}

// ---- operator events -------------------------------------------------------------------------

/// An operator event and its placement from a value: `kind` (below), `at` (ns) and `end`
/// (`true`: at the end of instant `at`, after its events; default: at its start).
///
/// | `kind` | fields |
/// |---|---|
/// | `link-state` | `link` (its name), `up` |
/// | `latency` | `link`, `ns` |
/// | `impair` | `link`, `from` (0 `a`, 1 `b`; none: both), `rate`, `queue`, `loss-ppm`, `jitter` |
/// | `inject` | `device` (its index), `port`, `bytes` |
/// | `stdin` | `device` (its name), `bytes` (bytes or text) |
/// | `command` | `device`, `command`, `argument` |
/// | `add-device` | `name`, `component`, `config` (pairs), `options` (device options), `wire` (`[{ port, to, to-port, latency }]`) |
/// | `stop-device`, `resume-device`, `start-device`, `remove-device` | `device` |
/// | `pause-device` | `device`, `link-down` |
/// | `crash-device` | `device`, `message` |
/// | `wire` | `a`, `b` (each `{ device, port }`), `latency`, `mtu` |
/// | `unwire` | `link` |
///
/// Embedder actions and extensions' ops take Rust closures and values: they are not here.
pub fn op(v: &Value) -> Result<(Op, Placement), String> {
    let kind = match v {
        Value::Record(fields) => fields
            .iter()
            .find(|(k, _)| k == "kind")
            .and_then(|(_, v)| match v {
                Value::Str(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or("an operator event needs a `kind`")?,
        _ => return Err(format!("an operator event is an object, got {v:?}")),
    };
    let known: &[&str] = match kind {
        "link-state" => &["link", "up"],
        "latency" => &["link", "ns"],
        "impair" => &["link", "from", "rate", "queue", "loss-ppm", "jitter"],
        "inject" => &["device", "port", "bytes"],
        "stdin" => &["device", "bytes"],
        "command" => &["device", "command", "argument"],
        "add-device" => &["name", "component", "config", "options", "wire"],
        "stop-device" | "resume-device" | "start-device" | "remove-device" => &["device"],
        "pause-device" => &["device", "link-down"],
        "crash-device" => &["device", "message"],
        "wire" => &["a", "b", "latency", "mtu"],
        "unwire" => &["link"],
        other => return Err(format!("no operator event `{other}`")),
    };
    let mut all = vec!["kind", "at", "end"];
    all.extend_from_slice(known);
    let what = format!("operator event `{kind}`");
    let f = Fields::new(&what, v, &all)?;
    let at = f.u64("at")?;
    let placement = if f.bool("end")? {
        Placement::EndOf(at)
    } else {
        Placement::StartOf(at)
    };
    let end = |k: &str| -> Result<(String, u32), String> {
        let e = Fields::new(k, f.need(k)?, &["device", "port"])?;
        Ok((e.str("device")?, e.u32("port")?))
    };
    let op = match kind {
        "link-state" => Op::set_link(f.str("link")?).with_up(f.bool("up")?),
        "latency" => Op::set_link(f.str("link")?).with_latency(f.u64("ns")?),
        "impair" => {
            let mut i = Impairments::default();
            i.rate = f.opt_u64("rate")?.unwrap_or(i.rate);
            i.queue = f.opt_u32("queue")?.unwrap_or(i.queue);
            i.loss_ppm = f.opt_u32("loss-ppm")?.unwrap_or(i.loss_ppm);
            i.jitter = f.opt_u64("jitter")?.unwrap_or(i.jitter);
            let op = Op::impair_named(f.str("link")?, i);
            match f.opt_u32("from")? {
                Some(end) => op.with_from(end as usize),
                None => op,
            }
        }
        "inject" => Op::inject(
            DeviceId::from_index(f.u32("device")? as usize).port(f.u32("port")?),
            f.bytes("bytes")?,
        ),
        "stdin" => Op::stdin_named(f.str("device")?, f.bytes("bytes")?),
        "command" => Op::control_named(
            f.str("device")?,
            DeviceCommand::new(
                f.str("command")?,
                f.opt_str("argument")?.unwrap_or_default(),
            )
            .into_control(),
        ),
        "add-device" => {
            let mut op = Op::add_device(f.str("name")?, f.str("component")?)
                .with_config(f.pairs("config")?.into_iter().collect());
            if let Some(o) = f.get("options") {
                op = op.with_options(options(o)?);
            }
            if let Some(Value::List(cables)) = f.get("wire") {
                for c in cables {
                    let c = Fields::new("cable", c, &["port", "to", "to-port", "latency"])?;
                    let cable = wasmnet_core::Cable::new(
                        c.u32("port")?,
                        c.str("to")?,
                        c.opt_u32("to-port")?.unwrap_or(0),
                    )
                    .latency(c.opt_u64("latency")?.unwrap_or(0));
                    op = op.with_cable(cable);
                }
            }
            op
        }
        "stop-device" => Op::stop_device(f.str("device")?),
        "resume-device" => Op::resume_device(f.str("device")?),
        "start-device" => Op::start_device(f.str("device")?),
        "remove-device" => Op::remove_device(f.str("device")?),
        "pause-device" => Op::pause_device(f.str("device")?).with_link_down(f.bool("link-down")?),
        "crash-device" => Op::crash_device(f.str("device")?, f.str("message")?),
        "wire" => {
            let mut op = Op::wire(end("a")?, end("b")?);
            if let Some(ns) = f.opt_u64("latency")? {
                op = op.with_latency(ns);
            }
            if let Some(mtu) = f.opt_u32("mtu")? {
                op = op.with_mtu(mtu);
            }
            op
        }
        "unwire" => Op::unwire(f.str("link")?),
        _ => unreachable!("every kind above is matched"),
    };
    Ok((op, placement))
}

// ---- what the page reads back ------------------------------------------------------------------

/// The operator events' states, in the order they were added.
pub fn op_states(states: &[OpState]) -> Value {
    Value::List(
        states
            .iter()
            .map(|s| match s {
                OpState::Pending => Value::record(vec![("state", Value::str("pending"))]),
                OpState::Applied { at, events } => Value::record(vec![
                    ("state", Value::str("applied")),
                    ("at", Value::U64(*at)),
                    ("events", Value::U64(*events)),
                ]),
                OpState::Unreached { at } => Value::record(vec![
                    ("state", Value::str("unreached")),
                    ("at", Value::U64(*at)),
                ]),
                OpState::Failed {
                    at,
                    events,
                    message,
                } => Value::record(vec![
                    ("state", Value::str("failed")),
                    ("at", Value::U64(*at)),
                    ("events", Value::U64(*events)),
                    ("message", Value::str(message.clone())),
                ]),
                other => Value::record(vec![
                    ("state", Value::str("other")),
                    ("message", Value::str(format!("{other:?}"))),
                ]),
            })
            .collect(),
    )
}

/// Every device's cost (`Network::costs`): its name and the core's counters.
pub fn costs(costs: &[(String, DeviceCost)]) -> Value {
    Value::List(
        costs
            .iter()
            .map(|(name, c)| {
                Value::record(vec![
                    ("name", Value::str(name.clone())),
                    ("memory", Value::U64(c.memory)),
                    ("peak-memory", Value::U64(c.peak_memory)),
                    ("fuel", Value::U64(c.fuel)),
                    ("peak-fuel", Value::U64(c.peak_fuel)),
                    ("calls", Value::U64(c.calls)),
                    ("polls", Value::U64(c.polls)),
                    ("idle-polls", Value::U64(c.idle_polls)),
                ])
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(fields: Vec<(&str, Value)>) -> Value {
        Value::record(fields)
    }

    #[test]
    fn options_come_from_a_plain_object_and_refuse_unknown_fields() {
        let o = options(&rec(vec![
            ("infra", Value::Bool(true)),
            ("infra-supply", Value::Bool(true)),
            ("memory", Value::U32(1 << 20)),
            ("args", Value::List(vec![Value::str("-v")])),
            (
                "env",
                Value::List(vec![Value::List(vec![Value::str("A"), Value::str("1")])]),
            ),
            ("infra-prefix", Value::None),
        ]))
        .expect("options");
        assert!(o.infra);
        assert_eq!(o.infra_supply, Some(SupplyLimits::default()));
        assert_eq!(o.memory, Some(1 << 20));
        assert_eq!(o.env, vec![("A".to_owned(), "1".to_owned())]);
        assert_eq!(o.infra_prefix, None);
        let wrong = options(&rec(vec![("memroy", Value::U32(1))])).unwrap_err();
        assert!(wrong.contains("unknown field `memroy`"), "{wrong}");
    }

    #[test]
    fn operator_events_are_built_with_the_cores_constructors() {
        let parse = op;
        let (op, at) = parse(&rec(vec![
            ("kind", Value::str("stdin")),
            ("at", Value::U64(5)),
            ("device", Value::str("ctl")),
            ("bytes", Value::str("replicas=3\n")),
        ]))
        .expect("op");
        assert_eq!(at, Placement::StartOf(5));
        assert!(matches!(op, Op::StdinNamed { .. }));
        let (op, at) = parse(&rec(vec![
            ("kind", Value::str("link-state")),
            ("at", Value::U64(7)),
            ("end", Value::Bool(true)),
            ("link", Value::str("a.0-b.0")),
            ("up", Value::Bool(false)),
        ]))
        .expect("op");
        assert_eq!(at, Placement::EndOf(7));
        assert!(matches!(op, Op::SetLink { .. }));
        assert!(
            parse(&rec(vec![
                ("kind", Value::str("nope")),
                ("at", Value::U64(0))
            ]))
            .is_err()
        );
        assert!(
            parse(&rec(vec![
                ("kind", Value::str("stop-device")),
                ("at", Value::U64(0))
            ]))
            .unwrap_err()
            .contains("`device` is required")
        );
    }

    #[test]
    fn links_take_impairments_and_capture_options() {
        let s = link(&rec(vec![
            ("latency", Value::U64(100)),
            ("impair-ba", rec(vec![("loss-ppm", Value::U32(10))])),
            ("capture", rec(vec![("snap-len", Value::U32(64))])),
        ]))
        .expect("link");
        assert_eq!(s.latency, 100);
        assert_eq!(s.impairments[0], Impairments::default());
        assert_eq!(s.impairments[1].loss_ppm, 10);
        assert_eq!(s.capture.expect("capture").snap_len, 64);
    }
}
