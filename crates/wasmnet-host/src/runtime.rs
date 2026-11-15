//! The wasmtime backend of the sim core: [`Host`] implements [`wasmnet_core::Runtime`].
//!
//! One device is one `Store` with deterministic WASI ([`HostState`]), instantiated from a
//! compiled component. `ports()` runs right away in a short `run_concurrent` of its own; then
//! the device's actor ([`DeviceActor`]) keeps exactly one `run_concurrent` alive for the
//! device's whole life (`docs/design/async-under-virtual-time.md`).

use wasmnet_core::{DeclaredPort, DeviceContext, DeviceInstance, Runtime, Stalled, block_on};
use wasmtime::Store;
use wasmtime::component::Component;

use crate::actor::{App, DeviceActor};
use crate::bindings::exports::wasmnet::link::{counters, device, lifecycle};
use crate::wasi::HostState;
use crate::{Host, runtime_error};

impl Runtime for Host {
    type Component = Component;

    fn instantiate(
        &self,
        ctx: DeviceContext,
        component: &Component,
    ) -> wasmnet_core::Result<DeviceInstance> {
        let name = ctx.name.as_str();
        crate::infra::require_grant(name, component, ctx.infra.is_some())
            .map_err(wasmnet_core::Error::Refused)?;
        let mut state = HostState::new(
            &ctx.clock,
            ctx.seed,
            name,
            &[],
            ctx.stdout.clone(),
            ctx.stderr.clone(),
        );
        state.wire = Some(ctx.wire.clone());
        state.journal = Some(ctx.journal.clone());
        state.config = ctx.config.clone();
        state.infra = ctx.infra.clone();
        self.init_store(&mut state)?;
        self.init_device(&mut state, &ctx)?;
        // The component's own engine: metered, or not (see `Host::load_unmetered`).
        let (linker, metered) = self.linker_for(component);
        let mut store = Store::new(component.engine(), state);
        self.store_created(&mut store);
        if metered {
            store
                .set_fuel(ctx.fuel_per_instant)
                .map_err(runtime_error)?;
        }

        let pre = linker.instantiate_pre(component).map_err(runtime_error)?;
        let device_indices = device::GuestIndices::new(&pre).map_err(runtime_error)?;
        let lifecycle_indices = lifecycle::GuestIndices::new(&pre).ok();
        let counters_indices = counters::GuestIndices::new(&pre).ok();
        let deadlock = |what: &'static str| {
            move |stalled: Stalled| wasmnet_core::Error::Deadlock {
                at: stalled.at,
                outstanding: vec![(name.to_owned(), what.to_owned())],
            }
        };
        let instance = block_on(&ctx.clock, pre.instantiate_async(&mut store))
            .map_err(deadlock("instantiate"))?
            .map_err(runtime_error)?;
        let device = device_indices
            .load(&mut store, &instance)
            .map_err(runtime_error)?;
        let lifecycle = lifecycle_indices
            .map(|i| i.load(&mut store, &instance))
            .transpose()
            .map_err(runtime_error)?;
        let counters = counters_indices
            .map(|i| i.load(&mut store, &instance))
            .transpose()
            .map_err(runtime_error)?;
        let has_counters = counters.is_some();
        // Optional exports the extensions serve control calls for.
        let mut exports = Vec::new();
        let mut controls = Vec::new();
        for e in self.extension_hooks() {
            if let Some((export, handler)) = e
                .instance_ready(&pre, &mut store, &instance)
                .map_err(runtime_error)?
            {
                exports.push(export);
                controls.push(handler);
            }
        }
        let apps = load_apps(component, &mut store, &instance).map_err(runtime_error)?;
        let app_names = apps
            .iter()
            .map(|a| a.export.trim_start_matches("app-").to_owned())
            .collect();
        let ports = block_on(
            &ctx.clock,
            store.run_concurrent(async |acc| device.call_ports(acc).await),
        )
        .map_err(deadlock("ports"))?
        .map_err(runtime_error)?
        .map_err(runtime_error)?;
        let ports = ports
            .into_iter()
            .map(|p| DeclaredPort {
                id: p.id,
                name: p.name,
                mac: p.mac,
                mtu: p.mtu,
            })
            .collect();

        let actor = DeviceActor {
            idx: ctx.index,
            store,
            device,
            lifecycle,
            counters,
            controls,
            apps,
            journal: ctx.journal,
            inbox: ctx.inbox,
            status: ctx.status,
            clock: ctx.clock,
            fuel_per_instant: ctx.fuel_per_instant,
            metered,
        };
        Ok(DeviceInstance {
            ports,
            actor: actor.into_future(),
            has_counters,
            exports,
            apps: app_names,
        })
    }

    fn install(&self, network: &mut wasmnet_core::Network<'_, Self>) {
        for e in self.extension_hooks() {
            e.install(network);
        }
    }

    /// Wasmtime's reports end with their root cause (`Caused by:` and the chain, the trap
    /// last, such as `wasm trap: all fuel consumed by WebAssembly`): that line, else the first.
    fn summarize(&self, message: &str) -> String {
        let cause = message
            .rsplit_once("Caused by:")
            .and_then(|(_, rest)| rest.lines().map(str::trim).rfind(|l| !l.is_empty()));
        wasmnet_core::infra::one_line(cause.unwrap_or(message))
    }
}
/// The apps of a composed node: every export named `app-<name>` must be an instance with a
/// `run: async func() -> result` (an app's renamed `wasi:cli/run@0.3.x`). Sorted by
/// name, which is the order they start in.
fn load_apps(
    component: &Component,
    store: &mut Store<HostState>,
    instance: &wasmtime::component::Instance,
) -> wasmtime::Result<Vec<App>> {
    let mut exports: Vec<String> = component
        .component_type()
        .exports(component.engine())
        .map(|(name, _)| name.to_owned())
        .filter(|name| name.starts_with("app-"))
        .collect();
    exports.sort();
    exports
        .into_iter()
        .map(|export| {
            let run = instance
                .get_export_index(&mut *store, None, &export)
                .and_then(|app| instance.get_export_index(&mut *store, Some(&app), "run"))
                .ok_or_else(|| {
                    wasmtime::format_err!("export `{export}` has no `run` (an app's wasi:cli/run)")
                })?;
            let run = instance.get_typed_func::<(), (Result<(), ()>,)>(&mut *store, run)?;
            Ok(App { export, run })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use wasmnet_core::Runtime;

    #[test]
    fn a_wasmtime_report_summarizes_to_its_cause() {
        let host = crate::Host::new().expect("host");
        let m = "error while executing at wasm backtrace:\n    0:  0xd4c9f - netstack.wasm!calloc\n\nCaused by:\n    wasm trap: all fuel consumed by WebAssembly\n";
        assert_eq!(
            host.summarize(m),
            "wasm trap: all fuel consumed by WebAssembly"
        );
        assert_eq!(host.summarize("no free port\nmore"), "no free port");
    }
}
