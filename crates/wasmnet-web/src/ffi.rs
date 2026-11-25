//! The wasm32 boundary: hand-rolled exports and imports (no wasm-bindgen, so no extra tool pin).
//!
//! # Conventions
//!
//! * One module instance holds at most one network (`wn_network_new` replaces it). Device
//!   indices (`dev`) are the network's creation order: the first device added is 0.
//! * Bytes cross as `(ptr, len)` in this module's memory. JavaScript allocates what it passes in
//!   with [`wn_alloc`] and frees it with [`wn_free`] once the call returned; this module never
//!   keeps a pointer past the call that received it.
//! * Results flow back through one buffer owned by this module: an export that returns data
//!   leaves it there and answers its length; JavaScript reads it at [`wn_result_ptr`] /
//!   [`wn_result_len`] right away, because any later export may replace it. Errors are UTF-8
//!   messages in the same buffer.
//! * An import that returns data answers its length (negative: an error message of that length)
//!   and is then asked once, with `js_take(ptr)`, to copy exactly that many bytes to `ptr`. Every
//!   such answer is followed by exactly one `js_take`, also for length 0.
//! * Structured values use the encoding of [`crate::codec`].
//! * Everything is single-threaded (one Worker). Module memory may grow during any call, so
//!   JavaScript re-reads `memory.buffer` after each one.
//!
//! # Re-entrancy
//!
//! The network exports (`wn_network_new`, `wn_add_device`, `wn_link`, `wn_step`, `wn_finish`,
//! `wn_journal`, `wn_link_*`, `wn_add_op`, `wn_op_states`, `wn_costs`, `wn_pcap`, `wn_counters`,
//! `wn_command`, `wn_schedule_command`, `wn_stdout`) hold the network for their whole call, and
//! several call into JavaScript while they do (`wn_add_device` instantiates, `wn_step`, `wn_finish`, `wn_counters` and
//! `wn_command` run devices). JavaScript must not call a network export from inside one of
//! those imports, also not while a JSPI-suspended import waits: it is refused (an error, never
//! a corrupted network). The device-side exports (`wn_transmit`, `wn_log`, `wn_event`,
//! `wn_output`, `wn_now`, `wn_wall_now`, `wn_config_*`, `wn_args`, `wn_env`, `wn_stdin`, `wn_random_*`,
//! `wn_insecure_seed`, `wn_timer`, `wn_infra`, `wn_infra_wait`, `wn_call_done`,
//! `wn_take_dirty`) touch only the per-device [`Registry`] (and, for `wasmnet:infra`, the
//! network's device table, which only records and queues) and may be called at any time, also
//! from inside any import. A device-side call for a device that does not exist is counted and
//! otherwise ignored.
//!
//! # Imports (module `wasmnet_js`)
//!
//! | Import | Meaning |
//! |---|---|
//! | `js_take(ptr)` | copy the pending answer (see above) to `ptr` |
//! | `js_instantiate(dev, plan, plan_len) -> i32` | instantiate the device of the `plan` message; answers an `instance` message |
//! | `js_receive(dev, port, now: u64, frame, len) -> i32` | `device.receive`; 0, or a negative error |
//! | `js_link_state(dev, port, up, now: u64) -> i32` | `device.link-state` (`up` 0 or 1); 0, or a negative error |
//! | `js_poll(dev, now: u64) -> i64` | `device.poll`: the deadline, `-1` none, `-2` error (its length from `js_stash_len`) |
//! | `js_stash_len() -> i32` | the length of the error message `js_poll` left |
//! | `js_counters(dev) -> i32` | `counters.counters`; answers a `counters` message |
//! | `js_start(dev, call) -> i32` | start `lifecycle.start()`, to end as `wn_call_done(dev, call, ..)`; 0, or a negative error |
//! | `js_run_app(dev, app, call) -> i32` | start app number `app`'s `run()`, likewise |
//! | `js_timer_fire(timer)` | the virtual timer `timer` (from `wn_timer`) is due: resolve the guest's wait |
//! | `js_invoke(dev, now: u64, command, len, argument, len) -> i32` | `commands.invoke`; answers a `command` message (the device's `ok` or refusal), or a negative error (a trap) |
//! | `js_reconfigure(dev, now: u64, config, len) -> i32` | `reconfigure.reconfigure` with a `config` message; answers a `reconfigured` message, or a negative error |
//! | `js_wait_done(wait, reply, len)` | the waiting call `wait` (`changes.wait`, `changes.wait-any`; from `wn_infra_wait`) is answered with an `infra reply`: resolve (or reject) the guest's call |
//! | `js_imports(component, len) -> i32` | the component's import names, if known: answers an `imports` message (asked before it is instantiated, for the grant check) |
//! | `js_release(dev)` | device `dev`'s instance is gone (stopped, crashed, removed): drop it |
//! | `js_memory(dev) -> i64` | the bytes device `dev`'s linear memories hold now, all together; -1 unknown |
//! | `js_stdin_ready(dev)` | bytes for device `dev`'s stdin arrived (`wn_stdin` has them): a waiting read may go on |
//! | `js_compile(digest, len, bytes, len) -> i32` | make a supplied component instantiable as `digest` (the core checked it already); 0, or a negative error. May suspend (JSPI) |
//! | `js_panic(msg, len)` | a panic's message, before the module traps |

#![allow(unsafe_code)] // FFI exports and imports; every unsafe block is commented.

use std::cell::RefCell;
use std::sync::Once;

use wasmnet_core::{DeviceConfig, DeviceId, LinkId, Nanos, Refusal};

use crate::codec::{self, Value};
use crate::host::{CallEnd, Instance, JsHost};
use crate::infra::Reply;
use crate::network::Network;
use crate::ops;
use crate::runtime::{Entropy, Registry};

mod js {
    #[link(wasm_import_module = "wasmnet_js")]
    unsafe extern "C" {
        pub fn js_take(ptr: *mut u8);
        pub fn js_instantiate(dev: u32, plan: *const u8, plan_len: usize) -> i32;
        pub fn js_receive(dev: u32, port: u32, now: u64, frame: *const u8, len: usize) -> i32;
        pub fn js_link_state(dev: u32, port: u32, up: u32, now: u64) -> i32;
        pub fn js_poll(dev: u32, now: u64) -> i64;
        pub fn js_stash_len() -> i32;
        pub fn js_counters(dev: u32) -> i32;
        pub fn js_start(dev: u32, call: u32) -> i32;
        pub fn js_run_app(dev: u32, app: u32, call: u32) -> i32;
        pub fn js_timer_fire(timer: u32);
        pub fn js_invoke(
            dev: u32,
            now: u64,
            command: *const u8,
            command_len: usize,
            argument: *const u8,
            argument_len: usize,
        ) -> i32;
        pub fn js_reconfigure(dev: u32, now: u64, config: *const u8, config_len: usize) -> i32;
        pub fn js_wait_done(wait: u32, reply: *const u8, reply_len: usize);
        pub fn js_imports(component: *const u8, component_len: usize) -> i32;
        pub fn js_release(dev: u32);
        pub fn js_memory(dev: u32) -> i64;
        pub fn js_stdin_ready(dev: u32);
        pub fn js_compile(
            digest: *const u8,
            digest_len: usize,
            bytes: *const u8,
            bytes_len: usize,
        ) -> i32;
        pub fn js_panic(msg: *const u8, len: usize);
    }
}

/// Copies the pending answer of `n` bytes out of JavaScript.
fn take_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    // SAFETY: `buf` is a live, writable allocation of exactly the `n` bytes JavaScript announced
    // (for `n = 0` a dangling but aligned pointer, to which JavaScript copies nothing).
    unsafe { js::js_take(buf.as_mut_ptr()) };
    buf
}

/// An import's answer: `len` bytes, or (negative) an error message of `-len` bytes.
fn answer(len: i32) -> Result<Vec<u8>, String> {
    let bytes = take_bytes(len.unsigned_abs() as usize);
    if len < 0 {
        Err(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        Ok(bytes)
    }
}

/// An import's status: 0 (or any non-negative value), or an error message.
fn status(code: i32) -> Result<(), String> {
    if code < 0 {
        answer(code).map(drop)
    } else {
        Ok(())
    }
}

/// The JavaScript side (a ZST: everything goes through the imports).
#[derive(Clone, Copy)]
/// The browser host: the page's JavaScript, through the module's imports.
pub struct Js;

impl JsHost for Js {
    fn instantiate(
        &self,
        dev: u32,
        name: &str,
        component: &str,
        config: &DeviceConfig,
    ) -> Result<Instance, String> {
        let plan = codec::encode_plan(name, component, config);
        // SAFETY: `plan` is live for the duration of the call; JavaScript only reads it.
        let len = unsafe { js::js_instantiate(dev, plan.as_ptr(), plan.len()) };
        let bytes = answer(len)?;
        codec::decode_instance(&bytes).map_err(|e| format!("instance: {e}"))
    }

    fn receive(&self, dev: u32, port: u32, now: Nanos, frame: &[u8]) -> Result<(), String> {
        // SAFETY: `frame` is live for the duration of the call; JavaScript only reads it.
        status(unsafe { js::js_receive(dev, port, now, frame.as_ptr(), frame.len()) })
    }

    fn link_state(&self, dev: u32, port: u32, up: bool, now: Nanos) -> Result<(), String> {
        // SAFETY: plain values.
        status(unsafe { js::js_link_state(dev, port, u32::from(up), now) })
    }

    fn poll(&self, dev: u32, now: Nanos) -> Result<Option<Nanos>, String> {
        // SAFETY: plain values.
        match unsafe { js::js_poll(dev, now) } {
            -1 => Ok(None),
            t if t >= 0 => Ok(Some(t.unsigned_abs())),
            _ => {
                // SAFETY: a plain call.
                let n = unsafe { js::js_stash_len() };
                let message = take_bytes(n.unsigned_abs() as usize);
                Err(String::from_utf8_lossy(&message).into_owned())
            }
        }
    }

    fn counters(&self, dev: u32) -> Result<Vec<(String, u64)>, String> {
        // SAFETY: plain values.
        let bytes = answer(unsafe { js::js_counters(dev) })?;
        codec::decode_counters(&bytes).map_err(|e| format!("counters: {e}"))
    }

    fn start(&self, dev: u32, call: u32) -> Result<(), String> {
        // SAFETY: plain values.
        status(unsafe { js::js_start(dev, call) })
    }

    fn run_app(&self, dev: u32, app: u32, call: u32) -> Result<(), String> {
        // SAFETY: plain values.
        status(unsafe { js::js_run_app(dev, app, call) })
    }

    fn timer_fire(&self, timer: u32) {
        // SAFETY: a plain value.
        unsafe { js::js_timer_fire(timer) }
    }

    fn invoke(
        &self,
        dev: u32,
        now: Nanos,
        command: &str,
        argument: &str,
    ) -> Result<Result<String, String>, String> {
        // SAFETY: both strings are live for the duration of the call; JavaScript only reads
        // them.
        let len = unsafe {
            js::js_invoke(
                dev,
                now,
                command.as_ptr(),
                command.len(),
                argument.as_ptr(),
                argument.len(),
            )
        };
        let bytes = answer(len)?;
        codec::decode_command_answer(&bytes).map_err(|e| format!("command answer: {e}"))
    }

    fn reconfigure(
        &self,
        dev: u32,
        now: Nanos,
        config: &DeviceConfig,
    ) -> Result<Result<(), Refusal>, String> {
        let config = codec::encode_config(config);
        // SAFETY: `config` is live for the duration of the call; JavaScript only reads it.
        let len = unsafe { js::js_reconfigure(dev, now, config.as_ptr(), config.len()) };
        let bytes = answer(len)?;
        codec::decode_reconfigured(&bytes).map_err(|e| format!("reconfigure answer: {e}"))
    }

    fn wait_done(&self, wait: u32, reply: &Reply) {
        let reply = codec::encode_infra_reply(reply);
        // SAFETY: `reply` is live for the duration of the call; JavaScript only reads it.
        unsafe { js::js_wait_done(wait, reply.as_ptr(), reply.len()) }
    }

    fn imports(&self, component: &str) -> Option<Vec<String>> {
        // SAFETY: `component` is live for the duration of the call; JavaScript only reads it.
        let len = unsafe { js::js_imports(component.as_ptr(), component.len()) };
        // JavaScript failing to say is the same as not knowing: nothing is refused here.
        let bytes = answer(len).ok()?;
        codec::decode_imports(&bytes).ok().flatten()
    }

    fn release(&self, dev: u32) {
        // SAFETY: a plain value.
        unsafe { js::js_release(dev) }
    }

    fn memory(&self, dev: u32) -> Option<u64> {
        // SAFETY: a plain value.
        u64::try_from(unsafe { js::js_memory(dev) }).ok()
    }

    fn stdin_ready(&self, dev: u32) {
        // SAFETY: a plain value.
        unsafe { js::js_stdin_ready(dev) }
    }

    fn compile(&self, digest: &str, bytes: &[u8]) -> Result<(), String> {
        // SAFETY: both are live for the duration of the call; JavaScript only reads them.
        status(unsafe {
            js::js_compile(digest.as_ptr(), digest.len(), bytes.as_ptr(), bytes.len())
        })
    }
}

thread_local! {
    /// The network, borrowed for the whole of each network export.
    static NETWORK: RefCell<Option<Network<Js>>> = const { RefCell::new(None) };
    /// The network's registry (for the device-side exports) and the result buffer; borrowed
    /// only briefly, never across a call into JavaScript.
    static STATE: RefCell<State> = RefCell::default();
}

#[derive(Default)]
struct State {
    registry: Option<Registry>,
    result: Vec<u8>,
}

/// Leaves `bytes` in the result buffer; answers their length.
pub(crate) fn set_result(bytes: Vec<u8>) -> i32 {
    let n = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
    STATE.with_borrow_mut(|s| s.result = bytes);
    n
}

/// Leaves an error message in the result buffer; answers -1.
pub(crate) fn fail(message: impl Into<String>) -> i32 {
    set_result(message.into().into_bytes());
    -1
}

fn registry() -> Option<Registry> {
    STATE.with_borrow(|s| s.registry.clone())
}

/// Runs `f` on the network, or says why it cannot: there is none yet, or a network export is
/// still running (a re-entrant call from JavaScript).
fn with_network<T>(f: impl FnOnce(&mut Network<Js>) -> T) -> Result<T, &'static str> {
    NETWORK.with(|n| match n.try_borrow_mut() {
        Ok(mut guard) => match guard.as_mut() {
            Some(network) => Ok(f(network)),
            None => Err("no network: call wn_network_new first"),
        },
        Err(_) => Err("refused: a network call is still running"),
    })
}

/// The bytes JavaScript passed at `(ptr, len)`.
pub(crate) fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    // SAFETY: by the boundary's contract JavaScript wrote `len` bytes at `ptr` (a block from
    // `wn_alloc`) right before the call and frees them only after it returns; nothing else
    // writes them meanwhile, and the slice does not outlive the export.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// A writable block JavaScript passed at `(ptr, len)`.
fn bytes_mut<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    if len == 0 {
        return &mut [];
    }
    // SAFETY: by the boundary's contract `ptr` is a block of at least `len` bytes from
    // `wn_alloc`, live until the export returns, and nothing else reads or writes it meanwhile.
    unsafe { std::slice::from_raw_parts_mut(ptr, len) }
}

fn text(ptr: *const u8, len: usize) -> String {
    String::from_utf8_lossy(bytes(ptr, len)).into_owned()
}

fn entropy(which: u32) -> Entropy {
    if which == 0 {
        Entropy::Secure
    } else {
        Entropy::Insecure
    }
}

/// A device index of the network, if it is one.
fn device(network: &Network<Js>, dev: u32) -> Option<DeviceId> {
    let id = DeviceId::from_index(dev as usize);
    network.devices().contains(&id).then_some(id)
}

/// A link index of the network, if it is one.
fn link(network: &Network<Js>, link: u32) -> Option<LinkId> {
    let id = LinkId::from_index(link as usize);
    network.links().contains(&id).then_some(id)
}

// ---- memory ------------------------------------------------------------------------------

/// Allocates `len` bytes (at least 1) for JavaScript to write arguments into. JavaScript owns the
/// block and frees it with [`wn_free`] with the same `len`. Never re-enters JavaScript.
#[unsafe(no_mangle)]
pub extern "C" fn wn_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// Frees a block from [`wn_alloc`]; `len` must be the length it was allocated with.
#[unsafe(no_mangle)]
pub extern "C" fn wn_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: `ptr` came from `wn_alloc(len)`, which allocated a `Vec<u8>` of capacity
    // `len.max(1)` and forgot it; JavaScript frees each block once.
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len.max(1)) });
}

/// Where the result buffer starts. Owned by this module; valid until the next export call.
#[unsafe(no_mangle)]
pub extern "C" fn wn_result_ptr() -> *const u8 {
    STATE.with_borrow(|s| s.result.as_ptr())
}

/// The result buffer's length.
#[unsafe(no_mangle)]
pub extern "C" fn wn_result_len() -> usize {
    STATE.with_borrow(|s| s.result.len())
}

// ---- the network -------------------------------------------------------------------------

/// Creates an empty network with `seed`, replacing (and dropping) the previous one: JavaScript
/// drops the old devices' instances first. Answers 0, or -1 (message in the result) when a
/// network export is still running. Never calls JavaScript.
#[unsafe(no_mangle)]
pub extern "C" fn wn_network_new(seed: u64) -> i32 {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let msg = info.to_string();
            // SAFETY: `msg` is live for the duration of the call; JavaScript copies it.
            unsafe { js::js_panic(msg.as_ptr(), msg.len()) }
        }));
    });
    let replaced = NETWORK.with(|n| match n.try_borrow_mut() {
        Ok(mut guard) => {
            let mut network = Network::new(Js, seed);
            crate::install::run(network.sim_mut());
            let registry = network.registry().clone();
            // The old network (if any) is dropped here, before its successor is published.
            *guard = Some(network);
            Ok(registry)
        }
        Err(_) => Err(()),
    });
    match replaced {
        Ok(registry) => {
            STATE.with_borrow_mut(|s| s.registry = Some(registry));
            0
        }
        Err(()) => fail("refused: a network call is still running"),
    }
}

/// Adds a device called `name` (UTF-8 at `name`), made from `component` (a key JavaScript
/// understands), with `config` (a `config` message) and `options` (a `value`: the device's options as a plain object, read by `crate::ops::options`). Calls
/// `js_instantiate` once, during which the device-side exports already serve it. Answers the
/// device's index, or -1 with the message in the result (JavaScript then drops whatever it made
/// for that index: the next device gets it). All inputs are JavaScript's to free.
#[unsafe(no_mangle)]
pub extern "C" fn wn_add_device(
    name: *const u8,
    name_len: usize,
    component: *const u8,
    component_len: usize,
    config: *const u8,
    config_len: usize,
    options: *const u8,
    options_len: usize,
) -> i32 {
    let name = text(name, name_len);
    let component = text(component, component_len);
    let config = match codec::decode_config(bytes(config, config_len)) {
        Ok(c) => c,
        Err(e) => return fail(format!("config: {e}")),
    };
    let options = match codec::decode_value(bytes(options, options_len)) {
        Ok(v) => v,
        Err(e) => return fail(format!("options: {e}")),
    };
    // The network's extensions read options of their own (`NetworkExtension::options`).
    let added = with_network(|n| {
        let sim = n.sim();
        let options =
            ops::options_with(&options, &sim.option_keys(), &|k, v| sim.parse_option(k, v))
                .map_err(|e| format!("options: {e}"))?;
        n.device_with_options(&name, &component, config, options)
    });
    match added {
        Ok(Ok(id)) => i32::try_from(id.index()).unwrap_or(i32::MAX),
        Ok(Err(e)) => fail(e),
        Err(e) => fail(e),
    }
}

/// Links port `port_a` of device `dev_a` to port `port_b` of device `dev_b`, with a one-way
/// `latency` in virtual ns. Answers the link's index, or -1 with the message in the result.
/// Never calls JavaScript.
#[unsafe(no_mangle)]
pub extern "C" fn wn_link(dev_a: u32, port_a: u32, dev_b: u32, port_b: u32, latency: u64) -> i32 {
    let a = DeviceId::from_index(dev_a as usize).port(port_a);
    let b = DeviceId::from_index(dev_b as usize).port(port_b);
    match with_network(|n| n.link(a, b, latency)) {
        Ok(Ok(id)) => i32::try_from(id.index()).unwrap_or(i32::MAX),
        Ok(Err(e)) => fail(e),
        Err(e) => fail(e),
    }
}

/// [`wn_link`] with its options as a `value` (`crate::ops::link`: `latency`, `mtu`,
/// impairments by direction, capture options). Answers the link's index, or -1 with the message
/// in the result. Never calls JavaScript.
#[unsafe(no_mangle)]
pub extern "C" fn wn_link_with(
    dev_a: u32,
    port_a: u32,
    dev_b: u32,
    port_b: u32,
    options: *const u8,
    options_len: usize,
) -> i32 {
    let setup = match codec::decode_value(bytes(options, options_len))
        .map_err(|e| e.to_string())
        .and_then(|v| ops::link(&v))
    {
        Ok(s) => s,
        Err(e) => return fail(format!("link options: {e}")),
    };
    let a = DeviceId::from_index(dev_a as usize).port(port_a);
    let b = DeviceId::from_index(dev_b as usize).port(port_b);
    match with_network(|n| n.link_with(a, b, &setup)) {
        Ok(Ok(id)) => i32::try_from(id.index()).unwrap_or(i32::MAX),
        Ok(Err(e)) => fail(e),
        Err(e) => fail(e),
    }
}

/// Adds an operator event (a `value`: `crate::ops::op`, its kind, fields and placement). Answers
/// its index (its state is in `wn_op_states`), or -1 with the message in the result (a
/// malformed event, or one the network refuses when added). Never calls JavaScript.
#[unsafe(no_mangle)]
pub extern "C" fn wn_add_op(op: *const u8, len: usize) -> i32 {
    let value = match codec::decode_value(bytes(op, len)) {
        Ok(v) => v,
        Err(e) => return fail(format!("operator event: {e}")),
    };
    // An extension's operator event at a device is built by the extension (`NetworkExtension::ops`).
    let added = with_network(|n| {
        let sim = n.sim();
        let (op, placement) = ops::op_with(&value, &|device, kind, v| {
            let id = sim
                .live_device(device)
                .ok_or_else(|| format!("no device `{device}`"))?;
            Ok(wasmnet_core::Op::extension_at(id, sim.parse_op(kind, v)?))
        })
        .map_err(|e| format!("operator event: {e}"))?;
        n.sim_mut().add_op(op, placement).map_err(|e| e.to_string())
    });
    match added {
        Ok(Ok(i)) => i32::try_from(i).unwrap_or(i32::MAX),
        Ok(Err(e)) => fail(e),
        Err(e) => fail(e),
    }
}

/// The operator events' states, in the order they were added, as a `value` in the result;
/// answers its length, or -1.
#[unsafe(no_mangle)]
pub extern "C" fn wn_op_states() -> i32 {
    match with_network(|n| ops::op_states(&n.sim().op_states())) {
        Ok(v) => set_result(codec::encode_value(&v)),
        Err(e) => fail(e),
    }
}

/// Every device's cost (its memory and peak memory, calls, polls, ...) as a `value` in the
/// result; answers its length, or -1.
#[unsafe(no_mangle)]
pub extern "C" fn wn_costs() -> i32 {
    match with_network(|n| ops::costs(&n.sim().costs())) {
        Ok(v) => set_result(codec::encode_value(&v)),
        Err(e) => fail(e),
    }
}

/// Runs every event at or before `until` (and every device JavaScript woke, first). Answers 1;
/// 0 once the network failed (stop stepping; `wn_finish` reports why); -1 with the message in
/// the result when there is no network or a network export is still running. Calls into
/// JavaScript for every device that runs.
#[unsafe(no_mangle)]
pub extern "C" fn wn_step(until: u64) -> i32 {
    match with_network(|n| n.step(until)) {
        Ok(ran) => i32::from(ran),
        Err(e) => fail(e),
    }
}

/// 1 if JavaScript woke a device (a completion, a timer) since the last call, then 0 until the
/// next wake: step at `wn_now()` before time may move. A device-side export.
#[unsafe(no_mangle)]
pub extern "C" fn wn_take_dirty() -> u32 {
    registry().is_some_and(|r| r.take_dirty()).into()
}

/// The time of the earliest queued event, or -1 if nothing is queued (or there is no network,
/// or a network export is still running).
#[unsafe(no_mangle)]
pub extern "C" fn wn_next_event() -> i64 {
    with_network(|n| n.next_event_time())
        .ok()
        .flatten()
        .map_or(-1, |t| i64::try_from(t).unwrap_or(i64::MAX))
}

/// Current virtual time (`wasi:clocks` monotonic `now`), in ns. A device-side export.
#[unsafe(no_mangle)]
pub extern "C" fn wn_now() -> u64 {
    registry().map_or(0, |r| r.now())
}

/// Ends the run: to quiescence for a negative `deadline`, else to `deadline` (ns). Call it once
/// the JavaScript event loop settled and nothing is due before the deadline (see the crate
/// docs). Leaves an `outcome` message in the result and answers its length; -1 with the message
/// when there is no network or a network export is still running.
#[unsafe(no_mangle)]
pub extern "C" fn wn_finish(deadline: i64) -> i32 {
    let deadline = u64::try_from(deadline).ok();
    match with_network(|n| n.finish(deadline)) {
        Ok(outcome) => set_result(codec::encode_outcome(&outcome)),
        Err(e) => fail(e),
    }
}

/// The journal from entry `from` on, as a `journal` message in the result; answers the index
/// where the next increment starts. With no network (or one busy) the message is empty and the
/// answer is `from`. Never calls JavaScript.
#[unsafe(no_mangle)]
pub extern "C" fn wn_journal(from: u32) -> u32 {
    let entries = with_network(|n| n.journal_from(from as usize)).unwrap_or_default();
    let next = from.saturating_add(u32::try_from(entries.len()).unwrap_or(u32::MAX));
    set_result(codec::encode_journal(&entries));
    next
}

/// How many links the network has (0 without one).
#[unsafe(no_mangle)]
pub extern "C" fn wn_link_count() -> u32 {
    with_network(|n| u32::try_from(n.links().len()).unwrap_or(u32::MAX)).unwrap_or(0)
}

/// Link `link`'s name (UTF-8, after its two ends) in the result; answers its length, or -1.
#[unsafe(no_mangle)]
pub extern "C" fn wn_link_name(index: u32) -> i32 {
    match with_network(|n| link(n, index).map(|l| n.link_name(l))) {
        Ok(Some(name)) => set_result(name.into_bytes()),
        Ok(None) => fail(format!("no link {index}")),
        Err(e) => fail(e),
    }
}

/// Link `link`'s pcap-ng capture so far in the result; answers its length, or -1.
#[unsafe(no_mangle)]
pub extern "C" fn wn_pcap(index: u32) -> i32 {
    match with_network(|n| link(n, index).map(|l| n.pcap(l))) {
        Ok(Some(pcap)) => set_result(pcap),
        Ok(None) => fail(format!("no link {index}")),
        Err(e) => fail(e),
    }
}

/// Device `dev`'s counters, read through `js_counters` at the current instant (between steps),
/// as a `counters` message in the result; answers its length. -1 (message in the result): no
/// such device, no network, or busy. -2: the device exports no counters. -3 (message in the
/// result): the device trapped, and the network failed.
#[unsafe(no_mangle)]
pub extern "C" fn wn_counters(dev: u32) -> i32 {
    let read = with_network(|n| device(n, dev).map(|id| n.counters(id)));
    match read {
        Ok(Some(Ok(Some(c)))) => set_result(codec::encode_counters(&c)),
        Ok(Some(Ok(None))) => -2,
        Ok(Some(Err(e))) => {
            fail(e);
            -3
        }
        Ok(None) => fail(format!("no device {dev}")),
        Err(e) => fail(e),
    }
}

/// Everything device `dev` wrote to stdout (`stderr = 0`) or stderr so far, in the result;
/// answers its length, or -1.
#[unsafe(no_mangle)]
pub extern "C" fn wn_stdout(dev: u32, stderr: u32) -> i32 {
    let read = with_network(|n| {
        device(n, dev).map(|id| {
            if stderr == 0 {
                n.stdout(id)
            } else {
                n.stderr(id)
            }
        })
    });
    match read {
        Ok(Some(out)) => set_result(out),
        Ok(None) => fail(format!("no device {dev}")),
        Err(e) => fail(e),
    }
}

/// The components in-world controllers may create devices from (`devices.apply`), by the keys
/// JavaScript instantiates them by: a `list<str>` message. Answers 0, or -1 with the message
/// in the result. Never calls JavaScript.
#[unsafe(no_mangle)]
pub extern "C" fn wn_set_catalog(names: *const u8, len: usize) -> i32 {
    let names = match codec::decode_strs(bytes(names, len)) {
        Ok(n) => n,
        Err(e) => return fail(format!("catalog: {e}")),
    };
    match with_network(|n| n.sim_mut().set_infra_catalog(names)) {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

/// Admits the components controllers supply ([`wasmnet_core::Network::set_supply_admission`]) by
/// the core's [`wasmnet_core::ImportPolicy`]: a `list<str>` message of import patterns
/// (`wasi:*`, `wasmnet:link/*`). Without a call every supply is refused. Answers 0, or -1 with
/// the message in the result. Never calls JavaScript.
#[unsafe(no_mangle)]
pub extern "C" fn wn_set_supply_admission(patterns: *const u8, len: usize) -> i32 {
    let patterns = match codec::decode_strs(bytes(patterns, len)) {
        Ok(p) => p,
        Err(e) => return fail(format!("admission: {e}")),
    };
    let policy = wasmnet_core::ImportPolicy::new(patterns);
    match with_network(|n| n.sim_mut().set_supply_admission(policy.admission())) {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

// ---- device commands -----------------------------------------------------------------------

/// Runs a command in device `dev`'s `wasmnet:control/commands` export at the current instant,
/// between steps (calls `js_invoke`): leaves a `command` message (its answer) in the result
/// and answers its length. -1 (message in the result): no such device, no network, busy, or
/// refused (a paused device). -2: the device takes no commands. -3 (message in the result):
/// the device trapped, and the network failed.
#[unsafe(no_mangle)]
pub extern "C" fn wn_command(
    dev: u32,
    command: *const u8,
    command_len: usize,
    argument: *const u8,
    argument_len: usize,
) -> i32 {
    let (command, argument) = (text(command, command_len), text(argument, argument_len));
    let run = with_network(|n| {
        device(n, dev).map(|id| {
            let answer = n.command(id, &command, &argument);
            (answer, n.failure().is_some())
        })
    });
    match run {
        Ok(Some((Ok(Some(answer)), _))) => set_result(codec::encode_command_answer(&answer)),
        Ok(Some((Ok(None), _))) => -2,
        Ok(Some((Err(e), failed))) => {
            fail(e);
            if failed { -3 } else { -1 }
        }
        Ok(None) => fail(format!("no device {dev}")),
        Err(e) => fail(e),
    }
}
/// Sends a command to device `dev` at the start of instant `at` (an operator event): answers
/// the op's index, or -1 with the message in the result (no such device, or it takes no
/// commands). Never calls JavaScript.
#[unsafe(no_mangle)]
pub extern "C" fn wn_schedule_command(
    dev: u32,
    at: u64,
    command: *const u8,
    command_len: usize,
    argument: *const u8,
    argument_len: usize,
) -> i32 {
    let (command, argument) = (text(command, command_len), text(argument, argument_len));
    let added = with_network(|n| {
        device(n, dev)
            .ok_or_else(|| format!("no device {dev}"))
            .and_then(|id| n.schedule_command(id, at, &command, &argument))
    });
    match added {
        Ok(Ok(op)) => i32::try_from(op).unwrap_or(i32::MAX),
        Ok(Err(e)) => fail(e),
        Err(e) => fail(e),
    }
}

// ---- arguments, environment, wasmnet:infra -------------------------------------------------

/// `wasi:cli/environment.get-arguments` of device `dev`: its `argv` (its name first) as a
/// `list<str>` message in the result; answers its length.
#[unsafe(no_mangle)]
pub extern "C" fn wn_args(dev: u32) -> i32 {
    let args = registry().map(|r| r.args(dev)).unwrap_or_default();
    set_result(codec::encode_strs(&args))
}

/// Device `dev`'s stdin: everything queued for it (by `Op::Stdin`) in the result, which is
/// empty when nothing is; answers its length. `js_stdin_ready` says when more comes.
#[unsafe(no_mangle)]
pub extern "C" fn wn_stdin(dev: u32) -> i32 {
    set_result(registry().map(|r| r.stdin(dev)).unwrap_or_default())
}

/// `wasi:cli/environment.get-environment` of device `dev`, as a `pairs` message in the result;
/// answers its length.
#[unsafe(no_mangle)]
pub extern "C" fn wn_env(dev: u32) -> i32 {
    let env = registry().map(|r| r.env(dev)).unwrap_or_default();
    set_result(codec::encode_pairs(&env))
}

/// One `wasmnet:infra` call of device `dev` (an `infra call` message), served at once: leaves
/// an `infra reply` in the result and answers its length. A device-side export.
#[unsafe(no_mangle)]
pub extern "C" fn wn_infra(dev: u32, call: *const u8, len: usize) -> i32 {
    let reply = match codec::decode_infra_call(bytes(call, len)) {
        Ok((function, args)) => match registry() {
            Some(r) => r.infra(dev, &function, &args),
            None => Reply::Failed("no network".to_owned()),
        },
        Err(e) => Reply::Failed(format!("infra call: {e}")),
    };
    set_result(codec::encode_infra_reply(&reply))
}

/// A waiting call of device `dev` (an `infra call` message for `changes.wait` or
/// `changes.wait-any`): answers a wait id (`js_wait_done(id, reply)` brings its answer, during a
/// later step), or -1 with an
/// `infra reply` in the result (answered at once: a refusal). Wakes the device. A device-side
/// export.
#[unsafe(no_mangle)]
pub extern "C" fn wn_infra_wait(dev: u32, call: *const u8, len: usize) -> i32 {
    let started = match codec::decode_infra_call(bytes(call, len)) {
        Ok((function, args)) => match registry() {
            Some(r) => r.infra_wait(dev, &function, &args),
            None => Err(Reply::Failed("no network".to_owned())),
        },
        Err(e) => Err(Reply::Failed(format!("infra call: {e}"))),
    };
    match started {
        Ok(id) => i32::try_from(id).unwrap_or(i32::MAX),
        Err(reply) => {
            set_result(codec::encode_infra_reply(&reply));
            -1
        }
    }
}
/// One call of a portable interface device `dev` imports (an `infra call` message whose
/// function is `interface#function`), served at once by the server an extension gave the
/// device: leaves an `infra reply` in the result and answers its length. A device-side export.
#[unsafe(no_mangle)]
pub extern "C" fn wn_import(dev: u32, call: *const u8, len: usize) -> i32 {
    let reply = match codec::decode_infra_call(bytes(call, len)) {
        Ok((function, args)) => match registry() {
            Some(r) => r.import(dev, &function, args),
            None => Reply::Failed("no network".to_owned()),
        },
        Err(e) => Reply::Failed(format!("import call: {e}")),
    };
    set_result(codec::encode_infra_reply(&reply))
}

/// Device `dev` dropped its handle `handle` to `interface#resource` (UTF-8 at `name`). A
/// device-side export.
#[unsafe(no_mangle)]
pub extern "C" fn wn_import_drop(dev: u32, name: *const u8, len: usize, handle: u32) {
    if let (Some(r), Ok(name)) = (registry(), std::str::from_utf8(bytes(name, len))) {
        r.import_drop(dev, name, handle);
    }
}

/// The portable interfaces the network's extensions serve, for the page to link: an `infra
/// reply` whose value is a list of records `{name, functions, resources}`; its length.
#[unsafe(no_mangle)]
pub extern "C" fn wn_interfaces() -> i32 {
    let list =
        NETWORK.with_borrow(|n| n.as_ref().map(|n| n.sim().interfaces()).unwrap_or_default());
    let strs = |v: Vec<String>| Value::List(v.into_iter().map(Value::Str).collect());
    let value = Value::List(
        list.into_iter()
            .map(|i| {
                Value::record(vec![
                    ("name", Value::Str(i.name)),
                    ("functions", strs(i.functions)),
                    ("resources", strs(i.resources)),
                ])
            })
            .collect(),
    );
    set_result(codec::encode_infra_reply(&Reply::Value(value)))
}

// ---- the devices' imports ----------------------------------------------------------------

/// The wall clock (`wasi:clocks` wall-clock `now`): the network's epoch plus virtual time, in ns
/// since the Unix epoch.
#[unsafe(no_mangle)]
pub extern "C" fn wn_wall_now() -> u64 {
    registry().map_or(0, |r| r.wall_now_ns())
}

/// `wasmnet:link/wire.transmit`: device `dev` sends `frame` (copied) on `port`. Only enqueues:
/// the peer gets it at now + latency.
#[unsafe(no_mangle)]
pub extern "C" fn wn_transmit(dev: u32, port: u32, frame: *const u8, len: usize) {
    if let Some(r) = registry() {
        r.transmit(dev, port, bytes(frame, len).to_vec());
    }
}

/// `wasmnet:link/log.log`: `level` 0 trace, 1 debug, 2 info, 3 warn, 4 (or more) error; the
/// message is UTF-8 (invalid sequences are replaced). Stamped with virtual time.
#[unsafe(no_mangle)]
pub extern "C" fn wn_log(dev: u32, level: u32, msg: *const u8, len: usize) {
    let level = codec::level_of(level).unwrap_or(wasmnet_core::Level::Error);
    if let Some(r) = registry() {
        r.log(dev, level, text(msg, len));
    }
}

/// `wasmnet:link/log.event`: an `event` message. A malformed one is dropped.
#[unsafe(no_mangle)]
pub extern "C" fn wn_event(dev: u32, event: *const u8, len: usize) {
    if let (Some(r), Ok((kind, fields))) = (registry(), codec::decode_event(bytes(event, len))) {
        r.event(dev, kind, fields);
    }
}

/// Bytes device `dev` wrote to stdout (`stderr = 0`) or stderr.
#[unsafe(no_mangle)]
pub extern "C" fn wn_output(dev: u32, stderr: u32, data: *const u8, len: usize) {
    if let Some(r) = registry() {
        r.output(dev, stderr != 0, bytes(data, len));
    }
}

/// `wasi:config/store.get`: device `dev`'s value for the key (UTF-8) in the result; answers its
/// length, or -1 when the key (or the device) does not exist.
#[unsafe(no_mangle)]
pub extern "C" fn wn_config_get(dev: u32, key: *const u8, len: usize) -> i32 {
    let key = text(key, len);
    match registry().and_then(|r| r.config_get(dev, &key)) {
        Some(value) => set_result(value.into_bytes()),
        None => -1,
    }
}

/// `wasi:config/store.get-all`: device `dev`'s whole config as a `config` message (sorted by
/// key) in the result; answers its length, or -1 for an unknown device.
#[unsafe(no_mangle)]
pub extern "C" fn wn_config_all(dev: u32) -> i32 {
    match registry().and_then(|r| r.config(dev)) {
        Some(config) => set_result(codec::encode_config(&config)),
        None => -1,
    }
}

/// The next 64 bits of device `dev`'s entropy: `which` 0 `wasi:random/random`, 1
/// `wasi:random/insecure`.
#[unsafe(no_mangle)]
pub extern "C" fn wn_random_u64(dev: u32, which: u32) -> u64 {
    registry().map_or(0, |r| r.random_u64(dev, entropy(which)))
}

/// Fills `len` bytes at `buf` (a block from `wn_alloc`) from device `dev`'s `which` stream.
#[unsafe(no_mangle)]
pub extern "C" fn wn_random_fill(dev: u32, which: u32, buf: *mut u8, len: usize) {
    if let Some(r) = registry() {
        r.random_fill(dev, entropy(which), bytes_mut(buf, len));
    }
}

/// Writes `wasi:random/insecure-seed`'s two u64 halves, little-endian, to the 16 bytes at `out`.
#[unsafe(no_mangle)]
pub extern "C" fn wn_insecure_seed(dev: u32, out: *mut u8) {
    let (a, b) = registry().map_or((0, 0), |r| r.insecure_seed(dev));
    let out = bytes_mut(out, 16);
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
}

/// A virtual timer for device `dev` at `at` (ns): answers its id; `js_timer_fire(id)` comes when
/// it is due (during a later step). Wakes the device (`wn_take_dirty` answers 1).
#[unsafe(no_mangle)]
pub extern "C" fn wn_timer(dev: u32, at: u64) -> u32 {
    registry().map_or(u32::MAX, |r| r.timer(dev, at))
}

/// An async call (`js_start`, `js_run_app`) of device `dev` ended: `end` 0 returned (`ok`), 1
/// returned `err`, 2 trapped with the UTF-8 message at `msg` (the device crashes at the next
/// step). Wakes the device.
#[unsafe(no_mangle)]
pub extern "C" fn wn_call_done(dev: u32, call: u32, end: u32, msg: *const u8, len: usize) {
    let end = match end {
        0 => CallEnd::Ok,
        1 => CallEnd::Err,
        _ => CallEnd::Trap(text(msg, len)),
    };
    if let Some(r) = registry() {
        r.call_done(dev, call, end);
    }
}

/// Runs `f` on the page's simulator, if a network exists and no network export is running
/// ([`crate::install::with_network`]).
pub(crate) fn with_sim<R>(f: impl FnOnce(&mut crate::install::PageNetwork) -> R) -> Option<R> {
    NETWORK.with(|n| n.try_borrow_mut().ok()?.as_mut().map(|n| f(n.sim_mut())))
}
