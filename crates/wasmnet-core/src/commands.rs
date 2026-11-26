//! Device commands: the control call into a device's `wasmnet:control/commands` export
//! (`wit/control/control.wit`), the one control call the core itself makes.
//!
//! A device that takes commands (the router: `route-add`, `route-remove`, ...) exports
//! `wasmnet:control/commands`, and its backend reports [`COMMANDS_EXPORT`] among the device's
//! optional exports. Three paths reach it, all through the same [`CommandCall`]:
//!
//! * between runs, [`crate::Network::command`] (like [`crate::Network::counters`]);
//! * as an operator event, [`crate::Op::Control`] or [`crate::Op::ControlNamed`] carrying a
//!   [`DeviceCommand`] (`Control::new(DeviceCommand::new(..))`); the device's refusal is the
//!   op's state;
//! * from an in-world controller, `wasmnet:infra/devices.control`: a derived request that makes
//!   the call when it applies; the device's refusal is journalled on the controller
//!   (`infra-failed`) and shown on the device.
//!
//! The core never reads a command or its answer: text in, text out. Every call is followed by a
//! `poll` of the device at the same instant ([`ControlCall::may_reschedule`]).

use std::any::Any;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use crate::ext::{Control, ControlAnswer, ControlCall, ControlRequest};
use crate::infra::Infra;

/// The optional export a device takes commands through: the name its backend reports in
/// [`crate::DeviceInstance::exports`] when the component exports `wasmnet:control/commands`
/// (any version).
pub const COMMANDS_EXPORT: &str = "wasmnet:control/commands";

/// A command for a device's `wasmnet:control/commands` export: its name and its argument, as
/// the device documents them (a router's `route-add` takes `10.0.3.0/24 via 10.0.2.2`).
///
/// As an operator event's payload it makes a fresh [`CommandCall`] each time the op applies.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceCommand {
    pub command: String,
    pub argument: String,
}

impl DeviceCommand {
    pub fn new(command: impl Into<String>, argument: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            argument: argument.into(),
        }
    }

    /// The command as an operator event's control call ([`crate::Op::Control`]).
    pub fn into_control(self) -> Control {
        Control::new(self)
    }
}

impl ControlRequest for DeviceCommand {
    fn export(&self) -> &str {
        COMMANDS_EXPORT
    }

    fn call(&self) -> Box<dyn ControlCall> {
        Box::new(CommandCall::new(self.clone()))
    }

    fn same(&self, other: &dyn ControlRequest) -> bool {
        (other as &dyn Any).downcast_ref::<Self>() == Some(self)
    }
}

/// Where a command's answer lands: the device's `ok` text or its refusal.
#[derive(Debug, Default)]
pub struct CommandAnswer(Mutex<Option<Result<String, String>>>);

impl CommandAnswer {
    /// The answer, once the device gave it.
    pub fn get(&self) -> Option<Result<String, String>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ControlAnswer for CommandAnswer {
    fn answered(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    fn refusal(&self) -> Option<String> {
        match &*self.0.lock().unwrap_or_else(PoisonError::into_inner) {
            Some(Err(message)) => Some(message.clone()),
            _ => None,
        }
    }
}

/// One call of a [`DeviceCommand`]: what travels the device's inbox. The backend serves it with
/// [`command`](Self::command) and [`argument`](Self::argument), then hands the device's answer
/// to [`finish`](Self::finish).
pub struct CommandCall {
    command: DeviceCommand,
    name: String,
    answer: Arc<CommandAnswer>,
    /// A controller's derived request: its index in the network's device table.
    derived: Option<(Infra, usize)>,
}

impl fmt::Debug for CommandCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandCall")
            .field("command", &self.command)
            .field("derived", &self.derived.as_ref().map(|(_, n)| n))
            .finish()
    }
}

impl CommandCall {
    pub fn new(command: DeviceCommand) -> Self {
        Self {
            name: format!("command({})", command.command),
            command,
            answer: Arc::default(),
            derived: None,
        }
    }

    /// The call of derived request `request` (`wasmnet:infra/devices.control`).
    pub(crate) fn derived(command: DeviceCommand, infra: Infra, request: usize) -> Self {
        Self {
            derived: Some((infra, request)),
            ..Self::new(command)
        }
    }

    pub fn command(&self) -> &str {
        &self.command.command
    }

    pub fn argument(&self) -> &str {
        &self.command.argument
    }

    /// Its answer slot.
    pub fn answer_slot(&self) -> Arc<CommandAnswer> {
        self.answer.clone()
    }

    /// Records the device's answer. A controller's request learns of a refusal here, at the
    /// instant (and in the processing context) the device gave it.
    pub fn finish(self, answer: Result<String, String>) {
        if let Some((infra, request)) = &self.derived {
            infra.command_answered(*request, &answer);
        }
        *self.answer.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(answer);
    }

    /// `call` as a command call, or `call` back if it is another kind of control call.
    pub fn downcast(call: Box<dyn ControlCall>) -> Result<Box<CommandCall>, Box<dyn ControlCall>> {
        if (&*call as &dyn Any).is::<CommandCall>() {
            let any: Box<dyn Any> = call;
            Ok(any.downcast().expect("checked above"))
        } else {
            Err(call)
        }
    }
}

impl ControlCall for CommandCall {
    fn name(&self) -> &str {
        &self.name
    }

    fn export(&self) -> &str {
        COMMANDS_EXPORT
    }

    fn may_reschedule(&self) -> bool {
        true
    }

    fn answer(&self) -> Arc<dyn ControlAnswer> {
        self.answer.clone()
    }

    fn unsupported(self: Box<Self>) {
        self.finish(Err(format!(
            "this device's backend does not serve {COMMANDS_EXPORT}"
        )));
    }

    fn target(&self) -> Option<(&str, &str)> {
        Some((COMMANDS_EXPORT, "invoke"))
    }

    /// `invoke(now, command, argument)`.
    fn invocation(&mut self, now: crate::Nanos) -> Option<crate::ext::Invocation> {
        use crate::value::Value;
        Some(crate::ext::Invocation::new(
            COMMANDS_EXPORT,
            "invoke",
            vec![
                Value::U64(now),
                Value::str(self.command()),
                Value::str(self.argument()),
            ],
        ))
    }

    fn invoked(
        self: Box<Self>,
        answer: Result<crate::value::Value, crate::value::Value>,
        _config: &mut crate::DeviceConfig,
    ) {
        let text = |v: crate::value::Value| match v {
            crate::value::Value::Str(s) => s,
            other => format!("an answer of the wrong shape: {other:?}"),
        };
        self.finish(answer.map(text).map_err(text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_call_answers_into_its_slot_and_downcasts() {
        let request = DeviceCommand::new("route-add", "10.0.3.0/24 via 10.0.2.2");
        assert!(request.same(&DeviceCommand::new("route-add", "10.0.3.0/24 via 10.0.2.2")));
        assert!(!request.same(&DeviceCommand::new("route-remove", "10.0.3.0/24")));
        let call = ControlRequest::call(&request);
        assert_eq!(call.name(), "command(route-add)");
        assert_eq!(call.export(), COMMANDS_EXPORT);
        assert!(call.may_reschedule());
        let answer = call.answer();
        let call = CommandCall::downcast(call).expect("a command call");
        assert_eq!(call.argument(), "10.0.3.0/24 via 10.0.2.2");
        assert!(!answer.answered());
        call.finish(Err("a route for 10.0.3.0/24 exists".into()));
        assert!(answer.answered());
        assert_eq!(
            answer.refusal().as_deref(),
            Some("a route for 10.0.3.0/24 exists")
        );
        let ok = CommandCall::new(DeviceCommand::new("routes", ""));
        let slot = ok.answer_slot();
        Box::new(ok).unsupported();
        assert!(slot.get().expect("answered").is_err());
    }
}
