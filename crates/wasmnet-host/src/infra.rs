//! `wasmnet:infra` on the wasmtime backend: an in-world controller's calls, served from its
//! [`wasmnet_core::InfraEnd`] (the sim core does the work, so every runtime answers the same).
//! Every store links it; a device the network did not grant it
//! ([`wasmnet_core::DeviceOptions::infra`]) gets `denied` for every call, and a component that
//! imports it without the grant does not instantiate ([`require_grant`]). See
//! `docs/design/topology-and-infra.md`.

use wasmnet_core::infra::{ChangeKind, DeviceView, InfraError, Phase};
use wasmtime::component::{Component, HasData, Linker};

use crate::wasi::HostState;

mod bindings {
    wasmtime::component::bindgen!({
        path: ["../../wit/infra"],
        world: "wasmnet:infra/controller",
    });
}

use bindings::wasmnet::infra::{devices, types};

/// [`HasData`] marker: the state is the store's [`HostState`].
struct Infra;

impl HasData for Infra {
    type Data<'a> = &'a mut HostState;
}

fn phase(p: Phase) -> types::Phase {
    match p {
        Phase::Pending => types::Phase::Pending,
        Phase::Running => types::Phase::Running,
        Phase::Stopped => types::Phase::Stopped,
        Phase::Crashed => types::Phase::Crashed,
        Phase::Removed => types::Phase::Removed,
        Phase::Failed => types::Phase::Failed,
    }
}

fn device(d: DeviceView) -> types::Device {
    types::Device {
        name: d.name,
        uid: d.uid,
        generation: d.generation,
        rv: d.rv,
        labels: d.labels,
        owner: d.owner,
        spec: d.spec,
        phase: phase(d.phase),
        target: d.target.map(phase),
        since: d.since,
        apps: d.apps,
        message: d.message,
    }
}

fn error(e: InfraError) -> types::Error {
    match e {
        InfraError::Conflict(m) => types::Error::Conflict(m),
        InfraError::NotFound(m) => types::Error::NotFound(m),
        InfraError::Invalid(m) => types::Error::Invalid(m),
        InfraError::Denied(m) => types::Error::Denied(m),
    }
}

fn ungranted() -> types::Error {
    types::Error::Denied(
        "this device is not granted wasmnet:infra (`DeviceOptions::infra`)".to_owned(),
    )
}

impl types::Host for HostState {}

impl devices::Host for HostState {
    fn apply(
        &mut self,
        request_id: Option<String>,
        name: String,
        labels: Vec<(String, String)>,
        spec: Vec<u8>,
    ) -> Result<types::Applied, types::Error> {
        let end = self.infra.as_ref().ok_or_else(ungranted)?;
        let (d, changed) = end.apply(request_id, &name, labels, &spec).map_err(error)?;
        Ok(types::Applied {
            device: device(d),
            changed,
        })
    }

    fn start(
        &mut self,
        request_id: Option<String>,
        name: String,
    ) -> Result<types::Device, types::Error> {
        let end = self.infra.as_ref().ok_or_else(ungranted)?;
        end.start(request_id, &name).map(device).map_err(error)
    }

    fn stop(
        &mut self,
        request_id: Option<String>,
        name: String,
        grace_ns: u64,
    ) -> Result<types::Device, types::Error> {
        let end = self.infra.as_ref().ok_or_else(ungranted)?;
        end.stop(request_id, &name, grace_ns)
            .map(device)
            .map_err(error)
    }

    fn remove(&mut self, request_id: Option<String>, name: String) -> Result<bool, types::Error> {
        let end = self.infra.as_ref().ok_or_else(ungranted)?;
        end.remove(request_id, &name).map_err(error)
    }

    fn get(&mut self, name: String) -> Result<types::Device, types::Error> {
        let end = self.infra.as_ref().ok_or_else(ungranted)?;
        end.get(&name).map(device).map_err(error)
    }

    fn list(&mut self, selector: Vec<(String, String)>) -> (u64, Vec<types::Device>) {
        match &self.infra {
            Some(end) => {
                let (rv, items) = end.list(&selector);
                (rv, items.into_iter().map(device).collect())
            }
            None => (0, Vec::new()),
        }
    }

    fn watch(
        &mut self,
        selector: Vec<(String, String)>,
        since: u64,
        max: u32,
    ) -> (u64, Vec<types::Change>) {
        match &self.infra {
            Some(end) => {
                let (rv, changes) = end.watch(&selector, since, max);
                let changes = changes
                    .into_iter()
                    .map(|c| types::Change {
                        kind: match c.kind {
                            ChangeKind::Added => types::ChangeKind::Added,
                            ChangeKind::Modified => types::ChangeKind::Modified,
                            ChangeKind::Deleted => types::ChangeKind::Deleted,
                        },
                        device: device(c.device),
                    })
                    .collect();
                (rv, changes)
            }
            None => (since, Vec::new()),
        }
    }

    fn logs(
        &mut self,
        name: String,
        stream: String,
        since: u64,
        tail: u32,
    ) -> Result<Vec<types::LogLine>, types::Error> {
        let end = self.infra.as_ref().ok_or_else(ungranted)?;
        let stream = wasmnet_core::infra::parse_stream(&stream).map_err(error)?;
        Ok(end
            .logs(&name, stream, since, tail)
            .map_err(error)?
            .into_iter()
            .map(|l| types::LogLine {
                at: l.at,
                stream: l.stream.as_str().to_owned(),
                line: l.line,
            })
            .collect())
    }
}

pub(crate) fn add_to_linker(l: &mut Linker<HostState>) -> wasmtime::Result<()> {
    devices::add_to_linker::<_, Infra>(l, |s| s)
}

/// Whether `component` imports `wasmnet:infra` (any interface, any version).
pub(crate) fn imports_infra(component: &Component) -> bool {
    component
        .component_type()
        .imports(component.engine())
        .any(|(name, _)| name.starts_with("wasmnet:infra/"))
}

/// Refuses a component that imports `wasmnet:infra` for a device the network did not grant it:
/// a clear error at instantiation, before the guest ever runs.
pub(crate) fn require_grant(
    device: &str,
    component: &Component,
    granted: bool,
) -> Result<(), String> {
    if granted || !imports_infra(component) {
        return Ok(());
    }
    Err(format!(
        "device `{device}` imports wasmnet:infra, but the network does not grant it (`DeviceOptions::infra`)"
    ))
}
