//! Portable extensions on wasmtime: the runtime half of the adapters `portable_adapter!`
//! generates.
//!
//! A portable extension serves an interface to devices through the core's
//! [`ImportServer`] (`DeviceExt::serve`), the same on every backend.
//! On wasmtime an adapter generated from the interface's WIT links it (typed, so bytes move
//! once) and hands each call here: [`attach`] puts the device's servers into its store,
//! [`call`] finds the interface's server and calls it, a [`Served::Fault`] faults the device
//! with the server's message (the same text the browser backend journals).

use std::sync::Arc;

use wasmnet_core::value::Value;
use wasmnet_core::{DeviceContext, ImportServer, Served, Status};

use crate::wasi::HostState;

/// A store's portable servers, from its device's context.
struct Servers {
    servers: Vec<(String, Arc<dyn ImportServer>)>,
    status: Status,
}

/// Puts the servers the network's extensions gave `device` into its store (once per store;
/// every generated adapter calls it from `init_device`).
pub fn attach(state: &mut HostState, device: &DeviceContext) {
    if state.extension::<Servers>().is_some() {
        return;
    }
    state.insert_extension(Servers {
        servers: device
            .ext
            .servers()
            .map(|(i, s)| (i.to_owned(), s.clone()))
            .collect(),
        status: device.status.clone(),
    });
}

fn server(state: &HostState, interface: &str) -> Option<Arc<dyn ImportServer>> {
    state
        .extension::<Servers>()?
        .servers
        .iter()
        .find(|(i, _)| i == interface)
        .map(|(_, s)| s.clone())
}

/// Calls `function` of `interface` for the store's device. A fault (or a device that was given
/// no server of the interface) is a trap: the device faults inside the call, with the server's
/// message recorded for its crash.
pub fn call(
    state: &mut HostState,
    interface: &str,
    function: &str,
    args: Vec<Value>,
) -> wasmtime::Result<Served> {
    let Some(server) = server(state, interface) else {
        let message =
            format!("{interface} is not served to this device (no extension gave it a server)");
        fault(state, &message);
        return Err(wasmtime::format_err!("{message}"));
    };
    match server.call(interface, function, args) {
        Served::Fault(message) => {
            fault(state, &message);
            Err(wasmtime::format_err!("{message}"))
        }
        served => Ok(served),
    }
}

fn fault(state: &HostState, message: &str) {
    if let Some(s) = state.extension::<Servers>() {
        s.status.set_fault(message);
    }
}

/// The device dropped a resource handle of `interface`'s server.
pub fn drop_resource(state: &mut HostState, interface: &str, resource: &str, handle: u32) {
    if let Some(server) = server(state, interface) {
        server.drop_resource(interface, resource, handle);
    }
}

/// The trap for a server's answer that does not fit the function's type (a bug in the
/// extension): the device faults, with that said.
pub fn bad_answer(interface: &str, function: &str, why: &str) -> wasmtime::Error {
    wasmtime::format_err!(
        "{interface}#{function}: the extension answered a value of the wrong shape: {why}"
    )
}

/// The device's virtual instant inside a control call (an export adapter's
/// [`ControlCall::invocation`](wasmnet_core::ext::ControlCall::invocation)).
pub fn now(acc: &wasmtime::component::Accessor<HostState>) -> wasmnet_core::Nanos {
    acc.with(|mut s| s.get().clock().now())
}

/// Hands a device's answer to an export call to `call`
/// ([`ControlCall::invoked`](wasmnet_core::ext::ControlCall::invoked)), with the configuration
/// the device's `wasi:config/store` serves, which the call may replace.
pub fn invoked(
    acc: &wasmtime::component::Accessor<HostState>,
    call: Box<dyn wasmnet_core::ext::ControlCall>,
    answer: Result<Value, Value>,
) {
    acc.with(|mut s| call.invoked(answer, &mut s.get().config));
}
