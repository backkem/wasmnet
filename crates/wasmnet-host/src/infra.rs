//! `wasmnet:infra` on the wasmtime backend: an in-world controller's calls, served by the sim
//! core's [`Calls`] from its [`wasmnet_core::InfraEnd`] (the core does the work and decides
//! what a device without the grant gets, so every runtime answers the same). This file only
//! converts between the WIT bindings and the core's types. Every store links it; a device the
//! network did not grant it ([`wasmnet_core::DeviceOptions::infra`]) gets `denied`, and a
//! component that imports it without the grant does not instantiate ([`require_grant`]). See
//! `docs/design/topology-and-infra.md`.

use wasmnet_core::infra::{Calls, ChangeKind, DeviceView, InfraError, Phase};
use wasmtime::component::{Accessor, Component, HasData, Linker};

use crate::wasi::HostState;

mod bindings {
    wasmtime::component::bindgen!({
        path: ["../../wit/infra"],
        world: "wasmnet:infra/controller",
    });
}

use bindings::wasmnet::infra::{changes, components, devices, types};

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

impl HostState {
    fn calls(&self) -> Calls<'_> {
        Calls::new(self.infra.as_ref())
    }
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
        let (d, changed) = self
            .calls()
            .apply(request_id, &name, labels, &spec)
            .map_err(error)?;
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
        self.calls()
            .start(request_id, &name)
            .map(device)
            .map_err(error)
    }

    fn stop(
        &mut self,
        request_id: Option<String>,
        name: String,
        grace_ns: u64,
    ) -> Result<types::Device, types::Error> {
        self.calls()
            .stop(request_id, &name, grace_ns)
            .map(device)
            .map_err(error)
    }

    fn remove(&mut self, request_id: Option<String>, name: String) -> Result<bool, types::Error> {
        self.calls().remove(request_id, &name).map_err(error)
    }

    fn control(
        &mut self,
        request_id: Option<String>,
        name: String,
        command: String,
        argument: String,
    ) -> Result<types::Device, types::Error> {
        self.calls()
            .control(request_id, &name, &command, &argument)
            .map(device)
            .map_err(error)
    }

    fn wire(
        &mut self,
        request_id: Option<String>,
        name: String,
        cable: Vec<u8>,
    ) -> Result<types::Device, types::Error> {
        self.calls()
            .wire(request_id, &name, &cable)
            .map(device)
            .map_err(error)
    }

    fn unwire(
        &mut self,
        request_id: Option<String>,
        name: String,
        port: u32,
    ) -> Result<types::Device, types::Error> {
        self.calls()
            .unwire(request_id, &name, port)
            .map(device)
            .map_err(error)
    }

    fn control_answer(
        &mut self,
        request_id: String,
    ) -> Result<Option<types::CommandAnswer>, types::Error> {
        Ok(self
            .calls()
            .control_answer(&request_id)
            .map_err(error)?
            .map(|a| types::CommandAnswer {
                name: a.name,
                command: a.command,
                at: a.at,
                answer: a.answer,
            }))
    }

    fn get(&mut self, name: String) -> Result<types::Device, types::Error> {
        self.calls().get(&name).map(device).map_err(error)
    }

    fn list(&mut self, selector: Vec<(String, String)>) -> (u64, Vec<types::Device>) {
        let (rv, items) = self.calls().list(&selector);
        (rv, items.into_iter().map(device).collect())
    }

    fn watch(
        &mut self,
        selector: Vec<(String, String)>,
        since: u64,
        max: u32,
    ) -> (u64, Vec<types::Change>) {
        let (rv, changes) = self.calls().watch(&selector, since, max);
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

    fn logs(
        &mut self,
        name: String,
        stream: String,
        since: u64,
        tail: u32,
    ) -> Result<Vec<types::LogLine>, types::Error> {
        Ok(self
            .calls()
            .logs(&name, &stream, since, tail)
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

impl components::Host for HostState {
    fn supply(&mut self, digest: Option<String>, bytes: Vec<u8>) -> Result<String, types::Error> {
        self.calls()
            .supply(digest.as_deref(), &bytes)
            .map_err(error)
    }

    fn release(&mut self, digest: String) -> Result<bool, types::Error> {
        self.calls().release(&digest).map_err(error)
    }

    fn list(&mut self) -> Vec<components::Supplied> {
        self.calls()
            .supplied()
            .into_iter()
            .map(|c| components::Supplied {
                digest: c.digest,
                size: c.size,
                held: c.held,
                users: c.users,
            })
            .collect()
    }
}

impl changes::Host for HostState {}

impl<U> changes::HostWithStore<U> for Infra {
    /// Waits on virtual time for a change in the caller's view ([`wasmnet_core::InfraEnd::wait`]).
    async fn wait(
        store: &Accessor<U, Self>,
        selector: Vec<(String, String)>,
        since: u64,
        deadline: Option<u64>,
    ) -> Result<u64, types::Error> {
        let end = store.with(|mut view| view.get().infra.clone());
        let wait = Calls::new(end.as_ref())
            .wait(selector, since, deadline)
            .map_err(error)?;
        Ok(wait.await)
    }
}

pub(crate) fn add_to_linker(l: &mut Linker<HostState>) -> wasmtime::Result<()> {
    devices::add_to_linker::<_, Infra>(l, |s| s)?;
    components::add_to_linker::<_, Infra>(l, |s| s)?;
    changes::add_to_linker::<_, Infra>(l, |s| s)
}

/// Refuses a component that imports `wasmnet:infra` for a device the network did not grant it
/// ([`wasmnet_core::infra::require_grant`], over the component's import names).
pub(crate) fn require_grant(
    device: &str,
    component: &Component,
    granted: bool,
) -> Result<(), String> {
    let ty = component.component_type();
    wasmnet_core::infra::require_grant(
        device,
        ty.imports(component.engine()).map(|(name, _)| name),
        granted,
    )
}
