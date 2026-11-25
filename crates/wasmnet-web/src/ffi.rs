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
//! `wn_journal`, `wn_link_*`, `wn_pcap`, `wn_counters`, `wn_stdout`) hold the network for their
//! whole call, and several call into JavaScript while they do (`wn_add_device` instantiates,
//! `wn_step`, `wn_finish` and `wn_counters` run devices). JavaScript must not call a network
//! export from inside one of those imports, also not while a JSPI-suspended import waits: it is
//! refused (an error, never a corrupted network). The device-side exports (`wn_transmit`,
//! `wn_log`, `wn_event`, `wn_output`, `wn_now`, `wn_wall_now`, `wn_config_*`, `wn_random_*`,
//! `wn_insecure_seed`, `wn_timer`, `wn_call_done`, `wn_take_dirty`) touch only the per-device
//! [`Registry`] and may be called at any time, also from inside any import. A device-side call
//! for a device that does not exist is counted and otherwise ignored.
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
//! | `js_panic(msg, len)` | a panic's message, before the module traps |

#![allow(unsafe_code)] // FFI exports and imports; every unsafe block is commented.

use std::cell::RefCell;
use std::sync::Once;

use wasmnet_core::{DeviceConfig, DeviceId, DeviceOptions, Impairments, LinkId, Nanos};

use crate::codec;
use crate::host::{CallEnd, Instance, JsHost};
use crate::network::Network;
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
struct Js;

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
fn set_result(bytes: Vec<u8>) -> i32 {
    let n = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
    STATE.with_borrow_mut(|s| s.result = bytes);
    n
}

/// Leaves an error message in the result buffer; answers -1.
fn fail(message: impl Into<String>) -> i32 {
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
fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
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
            let network = Network::new(Js, seed);
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
/// understands), with `config` (a `config` message) and `flags` (bit 0: journal its stdout and
/// stderr lines). Calls `js_instantiate` once, during which the device-side exports already
/// serve it. Answers the device's index, or -1 with the message in the result (JavaScript then
/// drops whatever it made for that index: the next device gets it). All inputs are JavaScript's
/// to free.
#[unsafe(no_mangle)]
pub extern "C" fn wn_add_device(
    name: *const u8,
    name_len: usize,
    component: *const u8,
    component_len: usize,
    config: *const u8,
    config_len: usize,
    flags: u32,
) -> i32 {
    let name = text(name, name_len);
    let component = text(component, component_len);
    let config = match codec::decode_config(bytes(config, config_len)) {
        Ok(c) => c,
        Err(e) => return fail(format!("config: {e}")),
    };
    let options = DeviceOptions::default().journal_stdio(flags & 1 != 0);
    match with_network(|n| n.device_with_options(&name, &component, config, options)) {
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

/// [`wn_link`] with each direction's impairments (`docs/design/links.md`): `imp` holds two
/// 24-byte records, `a -> b` then `b -> a`, each `rate` (u64, bits per second, 0: unlimited),
/// `queue` (u32, frames), `loss_ppm` (u32, parts per million) and `jitter` (u64, ns), little
/// endian. Answers the link's index, or -1 with the message in the result. Never calls
/// JavaScript.
#[unsafe(no_mangle)]
pub extern "C" fn wn_link_impaired(
    dev_a: u32,
    port_a: u32,
    dev_b: u32,
    port_b: u32,
    latency: u64,
    imp: *const u8,
    imp_len: usize,
) -> i32 {
    let Some(impairments) = decode_impairments(bytes(imp, imp_len)) else {
        return fail(format!(
            "impairments: want 48 bytes (two 24-byte records), got {imp_len}"
        ));
    };
    let a = DeviceId::from_index(dev_a as usize).port(port_a);
    let b = DeviceId::from_index(dev_b as usize).port(port_b);
    match with_network(|n| n.link_impaired(a, b, latency, impairments)) {
        Ok(Ok(id)) => i32::try_from(id.index()).unwrap_or(i32::MAX),
        Ok(Err(e)) => fail(e),
        Err(e) => fail(e),
    }
}

/// Two directions' impairments from [`wn_link_impaired`]'s 48 bytes.
fn decode_impairments(b: &[u8]) -> Option<[Impairments; 2]> {
    if b.len() != 48 {
        return None;
    }
    let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().expect("8 bytes"));
    let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().expect("4 bytes"));
    Some([0, 24].map(|o| {
        Impairments::default()
            .rate(u64_at(o))
            .queue(u32_at(o + 8))
            .loss_ppm(u32_at(o + 12))
            .jitter(u64_at(o + 16))
    }))
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
