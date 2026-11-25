//! `wasmnet:infra` as every backend serves it: one method per function of the interfaces
//! (`devices`, `components`, `changes`), answered from the calling device's [`InfraEnd`].
//!
//! A backend links the imports for every device and turns each guest call into one call here,
//! then the answer back into its own types; it decides nothing itself. What a device without
//! the grant gets (`denied`, or an empty answer for the functions that cannot fail), which
//! stream names `devices.logs` takes and which components may import `wasmnet:infra` at all are
//! decided here, once.

use crate::clock::Nanos;
use crate::supply::StoredComponent;

use super::{Change, ChangeWait, CommandAnswer, DeviceView, InfraEnd, InfraError, LogLine};

/// The error of every call from a device the network did not grant `wasmnet:infra`.
pub fn ungranted() -> InfraError {
    InfraError::Denied(
        "this device is not granted wasmnet:infra (`DeviceOptions::infra`)".to_owned(),
    )
}

/// Refuses a component that imports `wasmnet:infra` (any interface, any version) for a device
/// the network did not grant it: a clear error at instantiation, before the guest ever runs.
/// `imports` are the component's import names, as its backend reads them.
pub fn require_grant<S: AsRef<str>>(
    device: &str,
    imports: impl IntoIterator<Item = S>,
    granted: bool,
) -> Result<(), String> {
    if granted
        || !imports
            .into_iter()
            .any(|name| name.as_ref().starts_with("wasmnet:infra/"))
    {
        return Ok(());
    }
    Err(format!(
        "device `{device}` imports wasmnet:infra, but the network does not grant it (`DeviceOptions::infra`)"
    ))
}

/// The calls of one device: its [`InfraEnd`] if the network granted it `wasmnet:infra`
/// ([`crate::DeviceContext::infra`]), else every call is refused with [`ungranted`] (or
/// answered empty, where the function cannot fail).
#[derive(Clone, Copy)]
pub struct Calls<'a> {
    end: Option<&'a InfraEnd>,
}

impl<'a> Calls<'a> {
    pub fn new(end: Option<&'a InfraEnd>) -> Self {
        Self { end }
    }

    fn end(&self) -> Result<&'a InfraEnd, InfraError> {
        self.end.ok_or_else(ungranted)
    }

    /// `devices.apply`: the device and whether anything changed.
    pub fn apply(
        &self,
        request_id: Option<String>,
        name: &str,
        labels: Vec<(String, String)>,
        spec: &[u8],
    ) -> Result<(DeviceView, bool), InfraError> {
        self.end()?.apply(request_id, name, labels, spec)
    }

    /// `devices.start`.
    pub fn start(&self, request_id: Option<String>, name: &str) -> Result<DeviceView, InfraError> {
        self.end()?.start(request_id, name)
    }

    /// `devices.stop`.
    pub fn stop(
        &self,
        request_id: Option<String>,
        name: &str,
        grace_ns: u64,
    ) -> Result<DeviceView, InfraError> {
        self.end()?.stop(request_id, name, grace_ns)
    }

    /// `devices.remove`.
    pub fn remove(&self, request_id: Option<String>, name: &str) -> Result<bool, InfraError> {
        self.end()?.remove(request_id, name)
    }

    /// `devices.control`.
    pub fn control(
        &self,
        request_id: Option<String>,
        name: &str,
        command: &str,
        argument: &str,
    ) -> Result<DeviceView, InfraError> {
        self.end()?.control(request_id, name, command, argument)
    }

    /// `devices.wire` (the cable as CBOR).
    pub fn wire(
        &self,
        request_id: Option<String>,
        name: &str,
        cable: &[u8],
    ) -> Result<DeviceView, InfraError> {
        self.end()?.wire(request_id, name, cable)
    }

    /// `devices.unwire`.
    pub fn unwire(
        &self,
        request_id: Option<String>,
        name: &str,
        port: u32,
    ) -> Result<DeviceView, InfraError> {
        self.end()?.unwire(request_id, name, port)
    }

    /// `devices.control-answer`.
    pub fn control_answer(&self, request_id: &str) -> Result<Option<CommandAnswer>, InfraError> {
        self.end()?.control_answer(request_id)
    }

    /// `devices.get`.
    pub fn get(&self, name: &str) -> Result<DeviceView, InfraError> {
        self.end()?.get(name)
    }

    /// `devices.list`: without the grant, nothing at resource version 0.
    pub fn list(&self, selector: &[(String, String)]) -> (u64, Vec<DeviceView>) {
        match self.end {
            Some(end) => end.list(selector),
            None => (0, Vec::new()),
        }
    }

    /// `devices.watch`: without the grant, no change, at `since`.
    pub fn watch(&self, selector: &[(String, String)], since: u64, max: u32) -> (u64, Vec<Change>) {
        match self.end {
            Some(end) => end.watch(selector, since, max),
            None => (since, Vec::new()),
        }
    }

    /// `devices.logs`, the stream by its name (`stdout` or `stderr`).
    pub fn logs(
        &self,
        name: &str,
        stream: &str,
        since: Nanos,
        tail: u32,
    ) -> Result<Vec<LogLine>, InfraError> {
        let end = self.end()?;
        let stream = super::parse_stream(stream)?;
        end.logs(name, stream, since, tail)
    }

    /// `components.supply`: the bytes' digest reference.
    pub fn supply(&self, digest: Option<&str>, bytes: &[u8]) -> Result<String, InfraError> {
        self.end()?.supply(digest, bytes)
    }

    /// `components.release`.
    pub fn release(&self, digest: &str) -> Result<bool, InfraError> {
        self.end()?.release(digest)
    }

    /// `components.list`: nothing without the grant (to infra or to supplied components).
    pub fn supplied(&self) -> Vec<StoredComponent> {
        self.end
            .and_then(|end| end.supplied().ok())
            .unwrap_or_default()
    }

    /// `changes.wait`: the future the backend awaits on the device's behalf.
    pub fn wait(
        &self,
        selector: Vec<(String, String)>,
        since: u64,
        deadline: Option<Nanos>,
    ) -> Result<ChangeWait, InfraError> {
        Ok(self.end()?.wait(selector, since, deadline))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ungranted_device_is_refused_or_answered_empty() {
        let calls = Calls::new(None);
        assert_eq!(calls.get("x"), Err(ungranted()));
        assert_eq!(calls.list(&[]), (0, Vec::new()));
        assert_eq!(calls.watch(&[], 7, 10), (7, Vec::new()));
        assert!(calls.supplied().is_empty());
        assert!(matches!(
            calls.wait(Vec::new(), 0, None),
            Err(InfraError::Denied(_))
        ));
        assert!(matches!(
            calls.logs("x", "stdout", 0, 0),
            Err(InfraError::Denied(_))
        ));
    }

    #[test]
    fn only_an_ungranted_importer_is_refused() {
        let imports = [
            "wasi:clocks/wall-clock@0.2.6",
            "wasmnet:infra/devices@0.1.2",
        ];
        assert!(require_grant("ctl", imports, true).is_ok());
        assert!(require_grant("sw", ["wasmnet:link/wire@0.1.0"], false).is_ok());
        let refused = require_grant("ctl", imports, false).unwrap_err();
        assert!(
            refused.contains("device `ctl` imports wasmnet:infra"),
            "{refused}"
        );
    }
}
