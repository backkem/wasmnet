//! Portable exports: a call of any optional export function of a device, by name, with values,
//! served by every backend through one mechanism ([`ControlCall::invocation`]).
//!
//! An [`ExportCall`] is a control call: it travels the device's inbox and runs inside its live
//! event loop at the current instant, between runs ([`crate::Network::invoke`]), as an operator
//! event ([`ExportRequest`] in [`crate::Op::Control`]) or from inside a run
//! ([`crate::ext::OpContext::control`]). A page calls the function by its names; wasmtime calls it
//! through the typed adapter generated for the export's interface
//! (`wasmnet_host::portable_adapter!`), or the host's own handler (commands, reconfiguration).

use std::any::Any;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use crate::clock::Nanos;
use crate::ext::{ControlAnswer, ControlCall, ControlRequest, Invocation};
use crate::value::Value;

/// What a device answered an [`ExportCall`] ([`plain`] shapes): `Ok` the function's value
/// (a `result`'s `ok`), `Err` a `result`'s `err` value.
pub type Answered = Result<Value, Value>;

/// Where an [`ExportCall`]'s answer lands.
#[derive(Debug, Default)]
pub struct ExportAnswer(Mutex<Option<Result<Answered, String>>>);

impl ExportAnswer {
    /// The device's answer once it gave it (`Ok`), or why no backend served the call (`Err`).
    pub fn get(&self) -> Option<Result<Answered, String>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set(&self, answer: Result<Answered, String>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(answer);
    }
}

impl ControlAnswer for ExportAnswer {
    fn answered(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    fn refusal(&self) -> Option<String> {
        match &*self.0.lock().unwrap_or_else(PoisonError::into_inner) {
            Some(Err(why)) => Some(why.clone()),
            Some(Ok(Err(v))) => Some(format!("{v:?}")),
            _ => None,
        }
    }
}

/// A call of `invocation.function` of the device's export `invocation.interface`.
pub struct ExportCall {
    name: String,
    invocation: Invocation,
    /// Its arguments were taken ([`ControlCall::invocation`]).
    taken: bool,
    reschedule: bool,
    answer: Arc<ExportAnswer>,
}

impl fmt::Debug for ExportCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportCall")
            .field("invocation", &self.invocation)
            .finish()
    }
}

impl ExportCall {
    /// A call of `invocation`. It does not move a stepped device's deadline unless
    /// [`reschedule`](Self::reschedule) says so.
    pub fn new(invocation: Invocation) -> Self {
        Self {
            name: format!("{}#{}", invocation.interface, invocation.function),
            invocation,
            taken: false,
            reschedule: false,
            answer: Arc::default(),
        }
    }

    /// The call may move a stepped device's deadline: a `poll` at the same instant follows it.
    pub fn reschedule(mut self, on: bool) -> Self {
        self.reschedule = on;
        self
    }

    /// Its answer slot.
    pub fn answer_slot(&self) -> Arc<ExportAnswer> {
        self.answer.clone()
    }

    /// `call` as an export call, or `call` back if it is another kind of control call.
    pub fn downcast(call: Box<dyn ControlCall>) -> Result<Box<ExportCall>, Box<dyn ControlCall>> {
        if (&*call as &dyn Any).is::<ExportCall>() {
            let any: Box<dyn Any> = call;
            Ok(any.downcast().expect("checked above"))
        } else {
            Err(call)
        }
    }
}

impl ControlCall for ExportCall {
    fn name(&self) -> &str {
        &self.name
    }

    fn export(&self) -> &str {
        &self.invocation.interface
    }

    fn may_reschedule(&self) -> bool {
        self.reschedule
    }

    fn answer(&self) -> Arc<dyn ControlAnswer> {
        self.answer.clone()
    }

    fn unsupported(self: Box<Self>) {
        self.answer.set(Err(format!(
            "this device's backend does not serve {}#{}",
            self.invocation.interface, self.invocation.function
        )));
    }

    fn target(&self) -> Option<(&str, &str)> {
        Some((&self.invocation.interface, &self.invocation.function))
    }

    /// The invocation, its arguments moved out of the call (not copied); the call keeps its
    /// names. A second call answers `None`.
    fn invocation(&mut self, _now: Nanos) -> Option<Invocation> {
        if self.taken {
            return None;
        }
        self.taken = true;
        Some(Invocation::new(
            self.invocation.interface.clone(),
            self.invocation.function.clone(),
            std::mem::take(&mut self.invocation.args),
        ))
    }

    fn invoked(self: Box<Self>, answer: Answered, _config: &mut crate::DeviceConfig) {
        self.answer.set(Ok(answer.map(plain).map_err(plain)));
    }
}

/// An [`ExportCall`] an operator event makes when it applies ([`crate::Op::Control`] with
/// [`crate::ext::Control::new`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRequest {
    invocation: Invocation,
    reschedule: bool,
}

impl ExportRequest {
    pub fn new(invocation: Invocation) -> Self {
        Self {
            invocation,
            reschedule: false,
        }
    }

    /// Its calls may move a stepped device's deadline ([`ExportCall::reschedule`]).
    pub fn reschedule(mut self, on: bool) -> Self {
        self.reschedule = on;
        self
    }

    /// As an operator event's call ([`crate::Op::control`]).
    pub fn into_control(self) -> crate::ext::Control {
        crate::ext::Control::new(self)
    }
}

impl ControlRequest for ExportRequest {
    fn export(&self) -> &str {
        &self.invocation.interface
    }

    fn call(&self) -> Box<dyn ControlCall> {
        Box::new(ExportCall::new(self.invocation.clone()).reschedule(self.reschedule))
    }

    fn same(&self, other: &dyn ControlRequest) -> bool {
        (other as &dyn Any).downcast_ref::<Self>() == Some(self)
    }
}

/// `v` in the shapes every backend answers with (jco's, which the browser backend gets): an
/// option's value bare (`none` stays [`Value::None`]), a tuple as a list. So an answer reads the
/// same whichever backend gave it ([`ExportAnswer::get`]).
pub fn plain(v: Value) -> Value {
    match v {
        Value::Some(v) => plain(*v),
        Value::Tuple(items) | Value::List(items) => {
            Value::List(items.into_iter().map(plain).collect())
        }
        Value::Record(fields) => {
            Value::Record(fields.into_iter().map(|(k, v)| (k, plain(v))).collect())
        }
        Value::Variant(tag, payload) => Value::Variant(tag, payload.map(|p| Box::new(plain(*p)))),
        other => other,
    }
}

/// An export's name as devices report it: without its version (`wasmnet:control/commands@0.1.0`
/// is `wasmnet:control/commands`).
pub fn unversioned(name: &str) -> &str {
    name.split_once('@').map_or(name, |(n, _)| n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_export_call_answers_into_its_slot() {
        let inv = Invocation::new("example:pad/inspect", "count", vec![]);
        let request = ExportRequest::new(inv.clone());
        let call = request.call();
        assert_eq!(call.name(), "example:pad/inspect#count");
        assert_eq!(call.export(), "example:pad/inspect");
        assert!(!call.may_reschedule());
        let mut call = call;
        assert_eq!(call.target(), Some(("example:pad/inspect", "count")));
        assert_eq!(call.invocation(5), Some(inv));
        assert_eq!(call.invocation(5), None, "taken once");
        let call = ExportCall::downcast(call).expect("an export call");
        let slot = call.answer_slot();
        let mut config = crate::DeviceConfig::new();
        call.invoked(Ok(Value::U32(3)), &mut config);
        assert_eq!(slot.get(), Some(Ok(Ok(Value::U32(3)))));
        assert_eq!(unversioned("a:b/c@0.1.0"), "a:b/c");
    }

    /// The bytes of an argument move out of the call: the invocation a backend takes holds the
    /// very buffer the caller gave (no copy of a large write).
    #[test]
    fn an_export_call_moves_its_arguments() {
        let bytes = vec![7u8; 1 << 20];
        let at = bytes.as_ptr();
        let mut call = ExportCall::new(Invocation::new(
            "example:pad/inspect",
            "write",
            vec![Value::str("x"), Value::Bytes(bytes)],
        ));
        let inv = call.invocation(0).expect("an invocation");
        match &inv.args[1] {
            Value::Bytes(b) => assert_eq!(b.as_ptr(), at),
            other => panic!("{other:?}"),
        }
        // The call still names itself and answers.
        assert_eq!(call.export(), "example:pad/inspect");
        let slot = call.answer_slot();
        Box::new(call).unsupported();
        assert_eq!(
            slot.get(),
            Some(Err(
                "this device's backend does not serve example:pad/inspect#write".to_owned()
            ))
        );
    }
}
