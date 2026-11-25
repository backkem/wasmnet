//! `wasmnet:control/commands` on the wasmtime backend: the one optional export the host serves
//! control calls for itself. A device that exports it is reported with
//! [`wasmnet_core::COMMANDS_EXPORT`], and every [`wasmnet_core::CommandCall`] the network sends
//! it becomes one `invoke` call inside its live event loop. The host reads neither the command
//! nor the answer (`docs/design/topology-and-infra.md`).

use wasmnet_core::ext::ControlCall;
use wasmnet_core::{CommandCall, VirtualClock};
use wasmtime::Store;
use wasmtime::component::{Accessor, Instance, InstancePre};

use crate::extension::{ControlFuture, ControlHandler};
use crate::wasi::HostState;

mod bindings {
    wasmtime::component::bindgen!({
        path: ["../../wit/control"],
        world: "wasmnet:control/controllable",
        exports: { default: async | store },
    });
}

use bindings::exports::wasmnet::control::commands;

/// A device's `commands` export.
pub(crate) struct Commands {
    guest: commands::Guest,
    clock: VirtualClock,
}

impl Commands {
    /// The device's `commands` export, if it has one.
    pub(crate) fn find(
        pre: &InstancePre<HostState>,
        store: &mut Store<HostState>,
        instance: &Instance,
        clock: &VirtualClock,
    ) -> wasmtime::Result<Option<Self>> {
        let Ok(indices) = commands::GuestIndices::new(pre) else {
            return Ok(None);
        };
        Ok(Some(Self {
            guest: indices.load(store, instance)?,
            clock: clock.clone(),
        }))
    }
}

impl ControlHandler for Commands {
    fn serve<'a>(
        &'a self,
        acc: &'a Accessor<HostState>,
        call: Box<dyn ControlCall>,
    ) -> Result<ControlFuture<'a>, Box<dyn ControlCall>> {
        let call = CommandCall::downcast(call)?;
        Ok(Box::pin(async move {
            let now = self.clock.now();
            let answer = self
                .guest
                .call_invoke(
                    acc,
                    now,
                    call.command().to_owned(),
                    call.argument().to_owned(),
                )
                .await?;
            call.finish(answer);
            Ok(())
        }))
    }
}
