//! `wasmnet:reconfigure/reconfigure` on the wasmtime backend: a device that takes configuration
//! changes in place. A device that exports it is reported with
//! [`wasmnet_core::RECONFIGURE_EXPORT`], and every [`wasmnet_core::ReconfigureCall`] the network
//! sends it becomes one `reconfigure` call inside its live event loop. On `ok` the store's
//! `wasi:config/store` serves the new configuration from then on
//! (`docs/design/topology-and-infra.md`).

use wasmnet_core::ext::ControlCall;
use wasmnet_core::{ReconfigureCall, Refusal, VirtualClock};
use wasmtime::Store;
use wasmtime::component::{Accessor, Instance, InstancePre};

use crate::extension::{ControlFuture, ControlHandler};
use crate::wasi::HostState;

mod bindings {
    wasmtime::component::bindgen!({
        path: ["../../wit/reconfigure"],
        world: "wasmnet:reconfigure/reconfigurable",
        exports: { default: async | store },
    });
}

use bindings::exports::wasmnet::reconfigure::reconfigure;

/// A device's `reconfigure` export.
pub(crate) struct Reconfigure {
    guest: reconfigure::Guest,
    clock: VirtualClock,
}

impl Reconfigure {
    /// The device's `reconfigure` export, if it has one.
    pub(crate) fn find(
        pre: &InstancePre<HostState>,
        store: &mut Store<HostState>,
        instance: &Instance,
        clock: &VirtualClock,
    ) -> wasmtime::Result<Option<Self>> {
        let Ok(indices) = reconfigure::GuestIndices::new(pre) else {
            return Ok(None);
        };
        Ok(Some(Self {
            guest: indices.load(store, instance)?,
            clock: clock.clone(),
        }))
    }
}

impl ControlHandler for Reconfigure {
    fn serve<'a>(
        &'a self,
        acc: &'a Accessor<HostState>,
        call: Box<dyn ControlCall>,
    ) -> Result<ControlFuture<'a>, Box<dyn ControlCall>> {
        let call = ReconfigureCall::downcast(call)?;
        Ok(Box::pin(async move {
            let now = self.clock.now();
            let config: Vec<(String, String)> = call
                .config()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let answer = self.guest.call_reconfigure(acc, now, config).await?;
            let answer = match answer {
                Ok(()) => Ok(()),
                Err(reconfigure::Refusal::Restart(m)) => Err(Refusal::Restart(m)),
                Err(reconfigure::Refusal::Invalid(m)) => Err(Refusal::Invalid(m)),
            };
            // On `ok` the device reads its new configuration from now on.
            acc.with(|mut s| call.finish_serving(answer, &mut s.get().config));
            Ok(())
        }))
    }
}
