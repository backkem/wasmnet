//! In-place configuration changes: the control call into a device's
//! `wasmnet:reconfigure/reconfigure` export (`wit/reconfigure/reconfigure.wit`).
//!
//! A device that can take a changed configuration while it runs, keeping its state, exports
//! `wasmnet:reconfigure/reconfigure`, and its backend reports [`RECONFIGURE_EXPORT`] among the
//! device's optional exports. A controller's `apply` that changes only a device's config sends
//! it a [`ReconfigureCall`] when the request applies; the device answers:
//!
//! * `ok`: it runs on with the new config (no recreation: its frames in flight, state, links
//!   and captures stay);
//! * [`Refusal::Restart`]: it cannot take this change in place, so the device is recreated, as
//!   for a device without the export;
//! * [`Refusal::Invalid`]: the config is wrong; the device keeps its old one and the request
//!   fails (`infra-failed`).
//!
//! The core never reads a config: it passes the device's full new config, as `wasi:config`
//! would serve it. Every call is followed by a `poll` of the device at the same instant.

use std::any::Any;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use crate::config::DeviceConfig;
use crate::ext::{ControlAnswer, ControlCall};
use crate::infra::Infra;

/// The optional export a device takes configuration changes through: the name its backend
/// reports in [`crate::DeviceInstance::exports`] when the component exports
/// `wasmnet:reconfigure/reconfigure` (any version).
pub const RECONFIGURE_EXPORT: &str = "wasmnet:reconfigure/reconfigure";

/// Why a device did not take a configuration in place.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The change needs a restart (a different number of ports, say): recreate it.
    Restart(String),
    /// The configuration is wrong: nothing changed.
    Invalid(String),
}

/// Where a reconfiguration's answer lands.
#[derive(Debug, Default)]
pub struct ReconfigureAnswer(Mutex<Option<Result<(), Refusal>>>);

impl ReconfigureAnswer {
    /// The answer, once the device gave it.
    pub fn get(&self) -> Option<Result<(), Refusal>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ControlAnswer for ReconfigureAnswer {
    fn answered(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    fn refusal(&self) -> Option<String> {
        match &*self.0.lock().unwrap_or_else(PoisonError::into_inner) {
            Some(Err(Refusal::Restart(m) | Refusal::Invalid(m))) => Some(m.clone()),
            _ => None,
        }
    }
}

/// One call of a device's `reconfigure`: the device's whole new config. The backend serves it
/// with [`config`](Self::config), then hands the device's answer to [`finish`](Self::finish).
pub struct ReconfigureCall {
    config: DeviceConfig,
    answer: Arc<ReconfigureAnswer>,
    /// A controller's derived request: its index in the network's device table.
    derived: Option<(Infra, usize)>,
}

impl fmt::Debug for ReconfigureCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconfigureCall")
            .field("config", &self.config)
            .field("derived", &self.derived.as_ref().map(|(_, n)| n))
            .finish()
    }
}

impl ReconfigureCall {
    pub fn new(config: DeviceConfig) -> Self {
        Self {
            config,
            answer: Arc::default(),
            derived: None,
        }
    }

    /// The call of derived request `request` (an `apply` that changes only the config).
    pub(crate) fn derived(config: DeviceConfig, infra: Infra, request: usize) -> Self {
        Self {
            derived: Some((infra, request)),
            ..Self::new(config)
        }
    }

    /// The device's new config, every key.
    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    /// Its answer slot.
    pub fn answer_slot(&self) -> Arc<ReconfigureAnswer> {
        self.answer.clone()
    }

    /// Records the device's answer, at the instant (and in the processing context) it gave it.
    pub fn finish(self, answer: Result<(), Refusal>) {
        if let Some((infra, request)) = &self.derived {
            infra.reconfigured(*request, &answer);
        }
        *self.answer.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(answer);
    }

    /// [`finish`](Self::finish) for a backend: on `ok`, `served` (the configuration the device's
    /// `wasi:config/store` serves) becomes the new one first, so the device reads it from then
    /// on; after a refusal it keeps the old one.
    pub fn finish_serving(self, answer: Result<(), Refusal>, served: &mut DeviceConfig) {
        if answer.is_ok() {
            served.clone_from(&self.config);
        }
        self.finish(answer);
    }

    /// `call` as a reconfiguration, or `call` back if it is another kind of control call.
    pub fn downcast(
        call: Box<dyn ControlCall>,
    ) -> Result<Box<ReconfigureCall>, Box<dyn ControlCall>> {
        if (&*call as &dyn Any).is::<ReconfigureCall>() {
            let any: Box<dyn Any> = call;
            Ok(any.downcast().expect("checked above"))
        } else {
            Err(call)
        }
    }
}

impl ControlCall for ReconfigureCall {
    fn name(&self) -> &str {
        "reconfigure"
    }

    fn export(&self) -> &str {
        RECONFIGURE_EXPORT
    }

    fn may_reschedule(&self) -> bool {
        true
    }

    fn answer(&self) -> Arc<dyn ControlAnswer> {
        self.answer.clone()
    }

    fn unsupported(self: Box<Self>) {
        self.finish(Err(Refusal::Restart(format!(
            "this device's backend does not serve {RECONFIGURE_EXPORT}"
        ))));
    }
}
