//! `wasmnet:infra` for devices JavaScript instantiates: a guest's call arrives as its function
//! name and its arguments in jco's shapes ([`Value`]), is served by the sim core's
//! [`Calls`] (the same calls the wasmtime backend makes, so both answer alike), and goes back
//! as a [`Reply`] in the shapes jco expects. This file is the conversion and nothing else: the
//! JavaScript side converts values generically and knows no function of the interface but its
//! name.

use wasmnet_core::infra::{
    Calls, Change, ChangeKind, CommandAnswer, DeviceView, EventPage, Follow, InfraError, LogLine,
    Phase, Ready, TableSince,
};
use wasmnet_core::supply::StoredComponent;

use crate::codec::Value;

/// The answer to one call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The function's value (for a `result`, its `ok` value).
    Value(Value),
    /// A `result`'s `err` value: JavaScript throws it, as jco expects of an import.
    Error(Value),
    /// The call itself was malformed (an unknown function, arguments of the wrong shape): a
    /// fault of the glue, which JavaScript raises as a trap.
    Failed(String),
}

/// The functions [`serve`] answers, by interface: what the JavaScript side links.
pub const FUNCTIONS: &[&str] = &[
    "devices.apply",
    "devices.start",
    "devices.stop",
    "devices.remove",
    "devices.control",
    "devices.wire",
    "devices.unwire",
    "devices.control-answer",
    "devices.get",
    "devices.list",
    "devices.watch",
    "devices.logs",
    "components.supply",
    "components.release",
    "components.list",
    "events.read",
    "events.arm",
];

/// Serves `function` (`devices.apply`, ... as in [`FUNCTIONS`]) with `args` from `calls`.
/// The functions that wait are not served here ([`start_wait`]).
pub fn serve(calls: Calls<'_>, function: &str, args: &[Value]) -> Reply {
    match call(calls, function, &Args(args)) {
        Ok(reply) => reply,
        Err(message) => Reply::Failed(format!("wasmnet:infra/{function}: {message}")),
    }
}

/// A wait a device started (`changes.wait` or `changes.wait-any`): the future that answers the
/// call once the core says the wait is over. One mechanism for both: the actor polls it and
/// hands its [`Reply`] to JavaScript ([`crate::JsHost::wait_done`]).
pub type Wait = std::pin::Pin<Box<dyn std::future::Future<Output = Reply>>>;

/// The functions [`start_wait`] answers: the ones that wait.
pub const WAITS: &[&str] = &["changes.wait", "changes.wait-any"];

/// Starts `function` (one of [`WAITS`]) with `args` for the caller: the wait, or the call's
/// answer at once (a refusal, malformed arguments).
pub fn start_wait(calls: Calls<'_>, function: &str, args: &[Value]) -> Result<Wait, Reply> {
    let a = Args(args);
    let failed = |m: String| Reply::Failed(format!("wasmnet:infra/{function}: {m}"));
    let refused = |e: InfraError| Reply::Error(error(e));
    match function {
        "changes.wait" => {
            let (selector, since, deadline) = (|| -> Result<_, String> {
                a.arity(3)?;
                Ok((a.pairs(0)?, a.u64(1)?, a.opt_u64(2)?))
            })()
            .map_err(failed)?;
            let wait = calls.wait(selector, since, deadline).map_err(refused)?;
            Ok(Box::pin(
                async move { Reply::Value(Value::U64(wait.await)) },
            ))
        }
        "changes.wait-any" => {
            let (table, follows, deadline) = (|| -> Result<_, String> {
                a.arity(3)?;
                Ok((a.table(0)?, a.follows(1)?, a.opt_u64(2)?))
            })()
            .map_err(failed)?;
            let wait = calls.wait_any(table, follows, deadline).map_err(refused)?;
            Ok(Box::pin(async move { Reply::Value(ready(wait.await)) }))
        }
        other => Err(Reply::Failed(format!("no waiting function `{other}`"))),
    }
}

fn call(calls: Calls<'_>, function: &str, a: &Args<'_>) -> Result<Reply, String> {
    let result = |r: Result<Value, InfraError>| match r {
        Ok(v) => Reply::Value(v),
        Err(e) => Reply::Error(error(e)),
    };
    Ok(match function {
        "devices.apply" => {
            a.arity(4)?;
            result(
                calls
                    .apply(a.opt_str(0)?, &a.str(1)?, a.pairs(2)?, &a.bytes(3)?)
                    .map(|(d, changed)| {
                        Value::record(vec![
                            ("device", device(d)),
                            ("changed", Value::Bool(changed)),
                        ])
                    }),
            )
        }
        "devices.start" => {
            a.arity(2)?;
            result(calls.start(a.opt_str(0)?, &a.str(1)?).map(device))
        }
        "devices.stop" => {
            a.arity(3)?;
            result(calls.stop(a.opt_str(0)?, &a.str(1)?, a.u64(2)?).map(device))
        }
        "devices.remove" => {
            a.arity(2)?;
            result(calls.remove(a.opt_str(0)?, &a.str(1)?).map(Value::Bool))
        }
        "devices.control" => {
            a.arity(4)?;
            result(
                calls
                    .control(a.opt_str(0)?, &a.str(1)?, &a.str(2)?, &a.str(3)?)
                    .map(device),
            )
        }
        "devices.wire" => {
            a.arity(3)?;
            result(
                calls
                    .wire(a.opt_str(0)?, &a.str(1)?, &a.bytes(2)?)
                    .map(device),
            )
        }
        "devices.unwire" => {
            a.arity(3)?;
            result(
                calls
                    .unwire(a.opt_str(0)?, &a.str(1)?, a.u32(2)?)
                    .map(device),
            )
        }
        "devices.control-answer" => {
            a.arity(1)?;
            result(
                calls
                    .control_answer(&a.str(0)?)
                    .map(|answer| Value::option(answer.map(command_answer))),
            )
        }
        "devices.get" => {
            a.arity(1)?;
            result(calls.get(&a.str(0)?).map(device))
        }
        "devices.list" => {
            a.arity(1)?;
            let (rv, items) = calls.list(&a.pairs(0)?);
            Reply::Value(Value::Tuple(vec![
                Value::U64(rv),
                Value::List(items.into_iter().map(device).collect()),
            ]))
        }
        "devices.watch" => {
            a.arity(3)?;
            let (rv, changes) = calls.watch(&a.pairs(0)?, a.u64(1)?, a.u32(2)?);
            Reply::Value(Value::Tuple(vec![
                Value::U64(rv),
                Value::List(changes.into_iter().map(change).collect()),
            ]))
        }
        "devices.logs" => {
            a.arity(4)?;
            result(
                calls
                    .logs(&a.str(0)?, &a.str(1)?, a.u64(2)?, a.u32(3)?)
                    .map(|lines| Value::List(lines.into_iter().map(log_line).collect())),
            )
        }
        "components.supply" => {
            a.arity(2)?;
            result(
                calls
                    .supply(a.opt_str(0)?.as_deref(), &a.bytes(1)?)
                    .map(Value::Str),
            )
        }
        "components.release" => {
            a.arity(1)?;
            result(calls.release(&a.str(0)?).map(Value::Bool))
        }
        "components.list" => {
            a.arity(0)?;
            Reply::Value(Value::List(
                calls.supplied().into_iter().map(supplied).collect(),
            ))
        }
        "events.read" => {
            a.arity(4)?;
            result(
                calls
                    .read_events(&a.str(0)?, &a.strs(1)?, a.u64(2)?, a.u32(3)?)
                    .map(page),
            )
        }
        "events.arm" => {
            a.arity(2)?;
            result(
                calls
                    .arm(a.table(0)?, a.follows(1)?)
                    .map(|r| Value::option(r.map(ready))),
            )
        }
        other => return Err(format!("no function `{other}`")),
    })
}

// ---- arguments -----------------------------------------------------------------------------

/// A call's arguments, read by position and type.
struct Args<'a>(&'a [Value]);

impl Args<'_> {
    fn arity(&self, n: usize) -> Result<(), String> {
        if self.0.len() == n {
            Ok(())
        } else {
            Err(format!("{} arguments, want {n}", self.0.len()))
        }
    }

    fn get(&self, i: usize) -> Result<&Value, String> {
        self.0.get(i).ok_or_else(|| format!("no argument {i}"))
    }

    fn wrong(i: usize, want: &str, got: &Value) -> String {
        format!("argument {i}: want {want}, got {got:?}")
    }

    fn str(&self, i: usize) -> Result<String, String> {
        match self.get(i)? {
            Value::Str(s) => Ok(s.clone()),
            other => Err(Self::wrong(i, "a string", other)),
        }
    }

    /// `option<string>`: none, the string itself (as jco passes it), or `some`.
    fn opt_str(&self, i: usize) -> Result<Option<String>, String> {
        match self.get(i)? {
            Value::None => Ok(None),
            Value::Str(s) => Ok(Some(s.clone())),
            Value::Some(v) => match &**v {
                Value::Str(s) => Ok(Some(s.clone())),
                other => Err(Self::wrong(i, "an optional string", other)),
            },
            other => Err(Self::wrong(i, "an optional string", other)),
        }
    }

    fn u32(&self, i: usize) -> Result<u32, String> {
        match self.get(i)? {
            Value::U32(n) => Ok(*n),
            other => Err(Self::wrong(i, "a u32", other)),
        }
    }

    fn u64(&self, i: usize) -> Result<u64, String> {
        match self.get(i)? {
            Value::U64(n) => Ok(*n),
            other => Err(Self::wrong(i, "a u64", other)),
        }
    }

    fn opt_u64(&self, i: usize) -> Result<Option<u64>, String> {
        match self.get(i)? {
            Value::None => Ok(None),
            Value::U64(n) => Ok(Some(*n)),
            Value::Some(v) => match &**v {
                Value::U64(n) => Ok(Some(*n)),
                other => Err(Self::wrong(i, "an optional u64", other)),
            },
            other => Err(Self::wrong(i, "an optional u64", other)),
        }
    }

    fn bytes(&self, i: usize) -> Result<Vec<u8>, String> {
        match self.get(i)? {
            Value::Bytes(b) => Ok(b.clone()),
            other => Err(Self::wrong(i, "bytes", other)),
        }
    }

    /// `list<string>`.
    fn strs(&self, i: usize) -> Result<Vec<String>, String> {
        let Value::List(items) = self.get(i)? else {
            return Err(Self::wrong(i, "a list of strings", self.get(i)?));
        };
        items
            .iter()
            .map(|item| match item {
                Value::Str(s) => Ok(s.clone()),
                other => Err(Self::wrong(i, "a string", other)),
            })
            .collect()
    }

    /// A record's fields as arguments of their own, by name: `names` in that order.
    fn fields(i: usize, v: &Value, names: &[&str]) -> Result<Vec<Value>, String> {
        let Value::Record(fields) = v else {
            return Err(Self::wrong(i, "a record", v));
        };
        names
            .iter()
            .map(|n| {
                fields
                    .iter()
                    .find(|(k, _)| k == n)
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| format!("argument {i}: no field `{n}`"))
            })
            .collect()
    }

    /// `option<table-since>`: none, the record itself (as jco passes it), or `some`.
    fn table(&self, i: usize) -> Result<Option<TableSince>, String> {
        let v = match self.get(i)? {
            Value::None => return Ok(None),
            Value::Some(v) => &**v,
            v => v,
        };
        let f = Self::fields(i, v, &["selector", "since"])?;
        let f = Args(&f);
        Ok(Some(TableSince::new(f.pairs(0)?, f.u64(1)?)))
    }

    /// `list<follow>`.
    fn follows(&self, i: usize) -> Result<Vec<Follow>, String> {
        let Value::List(items) = self.get(i)? else {
            return Err(Self::wrong(i, "a list of follows", self.get(i)?));
        };
        items
            .iter()
            .map(|item| {
                let f = Self::fields(i, item, &["name", "kinds", "since"])?;
                let f = Args(&f);
                Ok(Follow::new(f.str(0)?, f.strs(1)?, f.u64(2)?))
            })
            .collect()
    }

    /// `list<tuple<string, string>>`.
    fn pairs(&self, i: usize) -> Result<Vec<(String, String)>, String> {
        let Value::List(items) = self.get(i)? else {
            return Err(Self::wrong(i, "a list of pairs", self.get(i)?));
        };
        items
            .iter()
            .map(|item| match item {
                Value::Tuple(p) | Value::List(p) => match p.as_slice() {
                    [Value::Str(k), Value::Str(v)] => Ok((k.clone(), v.clone())),
                    _ => Err(Self::wrong(i, "a pair of strings", item)),
                },
                other => Err(Self::wrong(i, "a pair of strings", other)),
            })
            .collect()
    }
}

// ---- answers -------------------------------------------------------------------------------

fn pairs(items: Vec<(String, String)>) -> Value {
    Value::List(
        items
            .into_iter()
            .map(|(k, v)| Value::Tuple(vec![Value::Str(k), Value::Str(v)]))
            .collect(),
    )
}

fn phase(p: Phase) -> Value {
    Value::Enum(
        match p {
            Phase::Pending => "pending",
            Phase::Running => "running",
            Phase::Stopped => "stopped",
            Phase::Crashed => "crashed",
            Phase::Removed => "removed",
            Phase::Failed => "failed",
        }
        .to_owned(),
    )
}

fn device(d: DeviceView) -> Value {
    Value::record(vec![
        ("name", Value::Str(d.name)),
        ("uid", Value::Str(d.uid)),
        ("generation", Value::U64(d.generation)),
        ("rv", Value::U64(d.rv)),
        ("labels", pairs(d.labels)),
        ("owner", Value::option(d.owner.map(Value::Str))),
        ("spec", Value::Bytes(d.spec)),
        ("phase", phase(d.phase)),
        ("target", Value::option(d.target.map(phase))),
        ("since", Value::U64(d.since)),
        ("apps", pairs(d.apps)),
        ("message", Value::option(d.message.map(Value::Str))),
    ])
}

fn change(c: Change) -> Value {
    let kind = match c.kind {
        ChangeKind::Added => "added",
        ChangeKind::Modified => "modified",
        ChangeKind::Deleted => "deleted",
    };
    Value::record(vec![
        ("kind", Value::Enum(kind.to_owned())),
        ("device", device(c.device)),
    ])
}

fn log_line(l: LogLine) -> Value {
    Value::record(vec![
        ("at", Value::U64(l.at)),
        ("stream", Value::str(l.stream.as_str())),
        ("line", Value::Str(l.line)),
    ])
}

fn command_answer(a: CommandAnswer) -> Value {
    let answer = match a.answer {
        Ok(text) => Value::case("ok", Value::Str(text)),
        Err(text) => Value::case("err", Value::Str(text)),
    };
    Value::record(vec![
        ("name", Value::Str(a.name)),
        ("command", Value::Str(a.command)),
        ("at", Value::U64(a.at)),
        ("answer", answer),
    ])
}

fn supplied(c: StoredComponent) -> Value {
    Value::record(vec![
        ("digest", Value::Str(c.digest)),
        ("size", Value::U64(c.size)),
        ("held", Value::Bool(c.held)),
        ("users", Value::U32(c.users)),
    ])
}

fn page(p: EventPage) -> Value {
    let events = p
        .events
        .into_iter()
        .map(|e| {
            Value::record(vec![
                ("seq", Value::U64(e.seq)),
                ("at", Value::U64(e.at)),
                ("kind", Value::Str(e.kind)),
                ("fields", pairs(e.fields)),
            ])
        })
        .collect();
    Value::record(vec![
        ("events", Value::List(events)),
        ("next", Value::U64(p.next)),
        ("missed", Value::U64(p.missed)),
    ])
}

fn ready(r: Ready) -> Value {
    Value::record(vec![
        ("rv", Value::U64(r.rv)),
        ("changed", Value::Bool(r.changed)),
        (
            "devices",
            Value::List(r.devices.into_iter().map(Value::Str).collect()),
        ),
    ])
}

/// `wasmnet:infra/types.error`.
fn error(e: InfraError) -> Value {
    let (tag, m) = match e {
        InfraError::Conflict(m) => ("conflict", m),
        InfraError::NotFound(m) => ("not-found", m),
        InfraError::Invalid(m) => ("invalid", m),
        InfraError::Denied(m) => ("denied", m),
    };
    Value::case(tag, Value::Str(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ungranted_caller_is_denied_in_jco_shapes() {
        let calls = Calls::new(None);
        let get = serve(calls, "devices.get", &[Value::str("x")]);
        let Reply::Error(Value::Variant(tag, Some(_))) = get else {
            panic!("{get:?}");
        };
        assert_eq!(tag, "denied");
        assert_eq!(
            serve(calls, "devices.list", &[Value::List(vec![])]),
            Reply::Value(Value::Tuple(vec![Value::U64(0), Value::List(vec![])]))
        );
        assert!(matches!(
            start_wait(
                calls,
                "changes.wait",
                &[Value::List(vec![]), Value::U64(0), Value::None]
            ),
            Err(Reply::Error(_))
        ));
        assert!(matches!(
            start_wait(
                calls,
                "changes.wait-any",
                &[Value::None, Value::List(vec![]), Value::None]
            ),
            Err(Reply::Error(_))
        ));
        let read = [
            Value::str("r1"),
            Value::List(vec![]),
            Value::U64(0),
            Value::U32(1),
        ];
        assert!(matches!(
            serve(calls, "events.read", &read),
            Reply::Error(Value::Variant(tag, _)) if tag == "denied"
        ));
        let follow = Value::record(vec![
            ("name", Value::str("r1")),
            ("kinds", Value::List(vec![Value::str("tunnel-*")])),
            ("since", Value::U64(0)),
        ]);
        assert!(matches!(
            serve(calls, "events.arm", &[Value::None, Value::List(vec![follow])]),
            Reply::Error(Value::Variant(tag, _)) if tag == "denied"
        ));
    }

    #[test]
    fn malformed_calls_fail_and_name_the_function() {
        let calls = Calls::new(None);
        for (f, args) in [
            ("devices.get", vec![]),
            ("devices.get", vec![Value::U32(1)]),
            ("devices.nope", vec![]),
            ("devices.list", vec![Value::List(vec![Value::str("k")])]),
        ] {
            let Reply::Failed(m) = serve(calls, f, &args) else {
                panic!("{f} {args:?}");
            };
            assert!(m.starts_with(&format!("wasmnet:infra/{f}: ")), "{m}");
        }
    }
}
