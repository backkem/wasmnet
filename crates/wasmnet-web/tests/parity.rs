//! The same scenarios on both backends: the wasmtime host (`wasmnet-host`), and the browser
//! backend's Rust half (`wasmnet-web`: its runtime, registry, actors, `wasmnet:infra` boundary
//! and codec), compared on what they do.
//!
//! In a browser, jco runs the components and the page's JavaScript serves their imports from
//! the browser backend's device-side calls. Here [`Wasm`] plays that JavaScript side with
//! wasmtime: it instantiates real components (stepped devices: the switch, the router and the
//! `infra-script` controller) and serves their imports exactly as `web/src/network.ts` does,
//! through the [`Registry`] (wire, log, config, arguments and environment) and through the
//! boundary's own encoding for `wasmnet:infra` ([`codec::Value`], generic in both directions,
//! like the TypeScript side). So everything Rust in a browser run is exercised; what is left
//! for a real browser is the TypeScript glue (`web/test`).
//!
//! The scenarios: device commands between runs and as operator events, a controller that
//! creates devices, sends them commands and reads the answers (`control-answer`) and changes a
//! switch's configuration in place (`wasmnet:reconfigure`), and a device's arguments and
//! environment. Both backends must give the same answers and journal the same events.
//!
//! Needs `wac` and `wasm-tools` on `PATH` (the components are built with `cargo xtask build`).

// Options are built field by field: their structs may gain fields this test does not set.
#![allow(clippy::field_reassign_with_default)]

#[path = "../../wasmnet-host/tests/support/mod.rs"]
mod support;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use wasmnet_core::{
    DeviceCommand, DeviceConfig, DeviceEntropy, DeviceId, DeviceOptions, JournalEntry, Nanos, Op,
    OpState, Placement, Record, Refusal,
};
use wasmnet_det_cbor::Value as Cbor;
use wasmnet_host::wasmtime::component::types::{ComponentFunc, ComponentItem, Type};
use wasmnet_host::wasmtime::component::{Component, Func, Linker, Val};
use wasmnet_host::wasmtime::{Config, Engine, Store};
use wasmnet_web::codec::{self, Value};
use wasmnet_web::infra::Reply;
use wasmnet_web::{Instance, JsHost, Registry, RunOutcome};
use wasmtime_wasi::clocks::{HostMonotonicClock, HostWallClock};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

const MS: Nanos = 1_000_000;

thread_local! {
    /// The registry of the browser backend's network under test on this thread.
    static REGISTRY: RefCell<Option<Registry>> = const { RefCell::new(None) };
}

fn registry() -> Registry {
    REGISTRY.with_borrow(|r| r.clone().expect("registry set"))
}

// ---- the browser backend's JavaScript side, played by wasmtime -------------------------------

/// What one device's store holds: its index and WASI. (The registry it is served from is a
/// thread-local, [`registry`]: WASI's state must be `Send`, the registry is not.)
struct State {
    dev: u32,
    wasi: WasiCtx,
    table: ResourceTable,
}

impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// Virtual time for WASI's clocks: the network's, as `Registry::now` gives it (kept in an
/// atomic, which WASI's clock traits need).
#[derive(Clone)]
struct Now(Arc<AtomicU64>);

impl HostMonotonicClock for Now {
    fn resolution(&self) -> u64 {
        1
    }
    fn now(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl HostWallClock for Now {
    fn resolution(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(1)
    }
    fn now(&self) -> std::time::Duration {
        wasmnet_core::DEFAULT_WALL_EPOCH
            + std::time::Duration::from_nanos(self.0.load(Ordering::Relaxed))
    }
}

struct Device {
    store: Store<State>,
    /// `(interface, function)` -> export.
    funcs: BTreeMap<(String, String), Func>,
}

impl Device {
    fn func(&self, interface: &str, name: &str) -> Option<Func> {
        self.funcs
            .iter()
            .find(|((i, f), _)| i.starts_with(interface) && f == name)
            .map(|(_, f)| *f)
    }

    fn call(&mut self, interface: &str, name: &str, args: &[Val]) -> Result<Vec<Val>, String> {
        let f = self
            .func(interface, name)
            .ok_or_else(|| format!("no export {interface}#{name}"))?;
        let n = f.ty(&self.store).results().len();
        let mut results = vec![Val::Bool(false); n];
        f.call(&mut self.store, args, &mut results)
            .map_err(|e| format!("{e:?}"))?;
        Ok(results)
    }
}

/// The JavaScript side of the browser backend, for stepped devices, on wasmtime.
#[derive(Clone)]
struct Wasm {
    engine: Engine,
    seed: u64,
    components: Rc<BTreeMap<String, Component>>,
    devices: Rc<RefCell<BTreeMap<u32, Device>>>,
    now: Now,
}

impl Wasm {
    fn new(seed: u64) -> Self {
        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = Engine::new(&config).expect("engine");
        let components = ["router", "switch", "infra_script"]
            .into_iter()
            .map(|name| {
                let path = support::built().path(name);
                let c = Component::from_file(&engine, &path)
                    .unwrap_or_else(|e| panic!("{}: {e:?}", path.display()));
                (name.to_owned(), c)
            })
            .collect();
        Self {
            engine,
            seed,
            components: Rc::new(components),
            devices: Rc::default(),
            now: Now(Arc::default()),
        }
    }

    fn with<T>(
        &self,
        dev: u32,
        now: Nanos,
        f: impl FnOnce(&mut Device) -> Result<T, String>,
    ) -> Result<T, String> {
        self.now.0.store(now, Ordering::Relaxed);
        let mut devices = self.devices.borrow_mut();
        let d = devices
            .get_mut(&dev)
            .ok_or_else(|| format!("no device {dev}"))?;
        f(d)
    }

    /// The linker for `component`: WASI 0.2, and the imports the page serves from the
    /// registry. `wasmnet:infra` is linked generically, function by function, as the page does.
    fn linker(&self, component: &Component) -> Linker<State> {
        let mut l: Linker<State> = Linker::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut l).expect("wasi");
        let ty = component.component_type();
        for (name, item) in ty.imports(&self.engine) {
            let ComponentItem::ComponentInstance(instance) = item.ty else {
                continue;
            };
            let bare = name.split('@').next().unwrap_or(name);
            let served = ["wasmnet:link/wire", "wasmnet:link/log", "wasi:config/store"];
            if !served.contains(&bare) && !bare.starts_with("wasmnet:infra/") {
                continue;
            }
            let mut li = l.instance(name).expect("instance");
            for (fname, item) in instance.exports(&self.engine) {
                let ComponentItem::ComponentFunc(_) = item.ty else {
                    continue;
                };
                let f = fname.to_owned();
                let served = match bare {
                    "wasmnet:link/wire" => li.func_new(&f, |s, _, args, _| {
                        let (Val::U32(port), Val::List(bytes)) = (&args[0], &args[1]) else {
                            panic!("transmit({args:?})");
                        };
                        let frame = bytes.iter().map(|b| match b {
                            Val::U8(b) => *b,
                            other => panic!("{other:?}"),
                        });
                        registry().transmit(s.data().dev, *port, frame.collect());
                        Ok(())
                    }),
                    "wasmnet:link/log" if f == "log" => li.func_new(&f, |s, _, args, _| {
                        let (Val::Enum(level), Val::String(m)) = (&args[0], &args[1]) else {
                            panic!("log({args:?})");
                        };
                        let code = ["trace", "debug", "info", "warn", "error"]
                            .iter()
                            .position(|l| *l == level)
                            .unwrap_or(4);
                        let level = codec::level_of(code as u32).expect("level");
                        registry().log(s.data().dev, level, m.clone());
                        Ok(())
                    }),
                    "wasmnet:link/log" => li.func_new(&f, |s, _, args, _| {
                        let Val::String(kind) = &args[0] else {
                            panic!("event({args:?})");
                        };
                        let fields = pairs_of(&args[1]);
                        registry().event(s.data().dev, kind.clone(), fields);
                        Ok(())
                    }),
                    "wasi:config/store" if f == "get" => li.func_new(&f, |s, _, args, out| {
                        let Val::String(key) = &args[0] else {
                            panic!("get({args:?})");
                        };
                        let v = registry().config_get(s.data().dev, key.as_str());
                        out[0] = Val::Result(Ok(Some(Box::new(Val::Option(
                            v.map(|v| Box::new(Val::String(v))),
                        )))));
                        Ok(())
                    }),
                    "wasi:config/store" => li.func_new(&f, |s, _, _, out| {
                        let all = registry().config(s.data().dev).unwrap_or_default();
                        let list = all
                            .into_iter()
                            .map(|(k, v)| Val::Tuple(vec![Val::String(k), Val::String(v)]))
                            .collect();
                        out[0] = Val::Result(Ok(Some(Box::new(Val::List(list)))));
                        Ok(())
                    }),
                    infra if infra.starts_with("wasmnet:infra/") => {
                        let function =
                            format!("{}.{f}", infra.trim_start_matches("wasmnet:infra/"));
                        li.func_new(&f, move |s, ty, args, out| {
                            serve_infra(&registry(), s.data().dev, &function, &ty, args, out)
                        })
                    }
                    _ => continue,
                };
                served.expect("link");
            }
        }
        l
    }
}

/// `list<tuple<string, string>>` as pairs.
fn pairs_of(v: &Val) -> Vec<(String, String)> {
    let Val::List(items) = v else {
        panic!("pairs: {v:?}");
    };
    items
        .iter()
        .map(|i| match i {
            Val::Tuple(p) => match p.as_slice() {
                [Val::String(k), Val::String(v)] => (k.clone(), v.clone()),
                other => panic!("pair {other:?}"),
            },
            other => panic!("pair {other:?}"),
        })
        .collect()
}

/// One `wasmnet:infra` call, the way the page makes it: the arguments as jco hands them over
/// ([`to_value`]), through the boundary's encoding, served by the registry, and the answer back
/// in the function's own types ([`to_val`]).
fn serve_infra(
    registry: &Registry,
    dev: u32,
    function: &str,
    ty: &ComponentFunc,
    args: &[Val],
    out: &mut [Val],
) -> wasmnet_host::wasmtime::Result<()> {
    let params: Vec<Type> = ty.params().map(|(_, t)| t).collect();
    let values: Vec<Value> = args
        .iter()
        .zip(&params)
        .map(|(a, t)| to_value(a, t))
        .collect();
    let call = codec::encode_infra_call(function, &values);
    let (function, values) = codec::decode_infra_call(&call).expect("call");
    let reply = registry.infra(dev, &function, &values);
    let reply = codec::decode_infra_reply(&codec::encode_infra_reply(&reply)).expect("reply");
    let result = ty.results().next().expect("a result");
    out[0] = match (reply, &result) {
        (Reply::Value(v), Type::Result(r)) => {
            Val::Result(Ok(r.ok().map(|t| Box::new(to_val(v, &t)))))
        }
        (Reply::Error(v), Type::Result(r)) => {
            Val::Result(Err(r.err().map(|t| Box::new(to_val(v, &t)))))
        }
        (Reply::Value(v), t) => to_val(v, t),
        (reply, _) => {
            return Err(wasmnet_host::wasmtime::format_err!("{function}: {reply:?}"));
        }
    };
    Ok(())
}

/// A guest's argument as jco hands it to JavaScript, and `codec.ts` encodes it: an option's
/// value bare, `list<u8>` as bytes, tuples as lists.
fn to_value(v: &Val, t: &Type) -> Value {
    match (v, t) {
        (Val::Option(None), _) => Value::None,
        (Val::Option(Some(v)), Type::Option(o)) => to_value(v, &o.ty()),
        (Val::Bool(b), _) => Value::Bool(*b),
        (Val::U32(n), _) => Value::U32(*n),
        (Val::U64(n), _) => Value::U64(*n),
        (Val::String(s), _) => Value::Str(s.clone()),
        (Val::List(items), Type::List(l)) if l.ty() == Type::U8 => Value::Bytes(
            items
                .iter()
                .map(|b| match b {
                    Val::U8(b) => *b,
                    other => panic!("{other:?}"),
                })
                .collect(),
        ),
        (Val::List(items), Type::List(l)) => {
            Value::List(items.iter().map(|i| to_value(i, &l.ty())).collect())
        }
        (Val::Tuple(items), Type::Tuple(tt)) => Value::List(
            items
                .iter()
                .zip(tt.types())
                .map(|(i, t)| to_value(i, &t))
                .collect(),
        ),
        other => panic!("an argument the page never sends: {other:?}"),
    }
}

/// An answer in the function's own types, as jco would lift what JavaScript returns.
fn to_val(v: Value, t: &Type) -> Val {
    match (v, t) {
        (Value::None, Type::Option(_)) => Val::Option(None),
        (Value::Some(v), Type::Option(o)) => Val::Option(Some(Box::new(to_val(*v, &o.ty())))),
        (Value::Bool(b), _) => Val::Bool(b),
        (Value::U32(n), _) => Val::U32(n),
        (Value::U64(n), _) => Val::U64(n),
        (Value::Str(s), _) => Val::String(s),
        (Value::Bytes(b), _) => Val::List(b.into_iter().map(Val::U8).collect()),
        (Value::List(items), Type::List(l)) => {
            Val::List(items.into_iter().map(|i| to_val(i, &l.ty())).collect())
        }
        (Value::Tuple(items), Type::Tuple(tt)) => Val::Tuple(
            items
                .into_iter()
                .zip(tt.types())
                .map(|(i, t)| to_val(i, &t))
                .collect(),
        ),
        (Value::Record(fields), Type::Record(r)) => {
            let mut fields: BTreeMap<String, Value> = fields.into_iter().collect();
            Val::Record(
                r.fields()
                    .map(|f| {
                        let v = fields
                            .remove(f.name)
                            .unwrap_or_else(|| panic!("no field {}", f.name));
                        (f.name.to_owned(), to_val(v, &f.ty))
                    })
                    .collect(),
            )
        }
        (Value::Variant(tag, payload), Type::Result(r)) => {
            let ok = tag == "ok";
            let ty = if ok { r.ok() } else { r.err() };
            let payload = payload.zip(ty).map(|(p, t)| Box::new(to_val(*p, &t)));
            Val::Result(if ok { Ok(payload) } else { Err(payload) })
        }
        (Value::Variant(tag, payload), Type::Variant(var)) => {
            let case = var.cases().find(|c| c.name == tag).expect("a case");
            let payload = payload.zip(case.ty).map(|(p, t)| Box::new(to_val(*p, &t)));
            Val::Variant(tag, payload)
        }
        (Value::Enum(name), _) => Val::Enum(name),
        (v, t) => panic!("an answer that does not fit its type: {v:?} as {t:?}"),
    }
}

impl JsHost for Wasm {
    fn instantiate(
        &self,
        dev: u32,
        name: &str,
        component: &str,
        _: &DeviceConfig,
    ) -> Result<Instance, String> {
        let c = self
            .components
            .get(component)
            .ok_or_else(|| format!("no component {component}"))?;
        let registry = registry();
        let entropy = DeviceEntropy::new(self.seed, name);
        let insecure_seed = entropy.insecure_seed_u128();
        let mut b = WasiCtxBuilder::new();
        b.args(&registry.args(dev))
            .envs(&registry.env(dev))
            .monotonic_clock(self.now.clone())
            .wall_clock(self.now.clone())
            .secure_random(entropy.secure)
            .insecure_random(entropy.insecure)
            .insecure_random_seed(insecure_seed);
        let mut store = Store::new(
            &self.engine,
            State {
                dev,
                wasi: b.build(),
                table: ResourceTable::new(),
            },
        );
        self.now.0.store(registry.now(), Ordering::Relaxed);
        let instance = self
            .linker(c)
            .instantiate(&mut store, c)
            .map_err(|e| format!("{e:?}"))?;
        let mut funcs = BTreeMap::new();
        for (iname, item) in c.component_type().exports(&self.engine) {
            let ComponentItem::ComponentInstance(i) = item.ty else {
                continue;
            };
            let idx = instance
                .get_export_index(&mut store, None, iname)
                .expect("export");
            for (fname, _) in i.exports(&self.engine) {
                if let Some(fi) = instance.get_export_index(&mut store, Some(&idx), fname)
                    && let Some(f) = instance.get_func(&mut store, fi)
                {
                    funcs.insert((iname.to_owned(), fname.to_owned()), f);
                }
            }
        }
        let mut d = Device { store, funcs };
        let ports = d.call("wasmnet:link/device", "ports", &[])?;
        let Val::List(ports) = &ports[0] else {
            return Err("ports".to_owned());
        };
        let ports = ports
            .iter()
            .map(|p| {
                let Val::Record(f) = p else { panic!("{p:?}") };
                let get = |k: &str| &f.iter().find(|(n, _)| n == k).expect(k).1;
                let (Val::U32(id), Val::String(name), Val::Option(mac), Val::U32(mtu)) =
                    (get("id"), get("name"), get("mac"), get("mtu"))
                else {
                    panic!("{p:?}")
                };
                wasmnet_core::DeclaredPort {
                    id: *id,
                    name: name.clone(),
                    mac: mac.as_ref().map(|m| match &**m {
                        Val::List(b) => b
                            .iter()
                            .map(|x| match x {
                                Val::U8(x) => *x,
                                _ => 0,
                            })
                            .collect(),
                        _ => Vec::new(),
                    }),
                    mtu: *mtu,
                }
            })
            .collect();
        let mut instance = Instance::default();
        instance.ports = ports;
        instance.counters = d.func("wasmnet:link/counters", "counters").is_some();
        instance.commands = d.func("wasmnet:control/commands", "invoke").is_some();
        instance.reconfigure = d
            .func("wasmnet:reconfigure/reconfigure", "reconfigure")
            .is_some();
        self.devices.borrow_mut().insert(dev, d);
        // Across the boundary, in its encoding, as the page answers.
        codec::decode_instance(&codec::encode_instance(&instance)).map_err(|e| e.to_string())
    }

    fn receive(&self, dev: u32, port: u32, now: Nanos, frame: &[u8]) -> Result<(), String> {
        self.with(dev, now, |d| {
            let frame = Val::List(frame.iter().copied().map(Val::U8).collect());
            d.call(
                "wasmnet:link/device",
                "receive",
                &[Val::U64(now), Val::U32(port), frame],
            )
            .map(drop)
        })
    }

    fn link_state(&self, dev: u32, port: u32, up: bool, now: Nanos) -> Result<(), String> {
        self.with(dev, now, |d| {
            d.call(
                "wasmnet:link/device",
                "link-state",
                &[Val::U64(now), Val::U32(port), Val::Bool(up)],
            )
            .map(drop)
        })
    }

    fn poll(&self, dev: u32, now: Nanos) -> Result<Option<Nanos>, String> {
        self.with(dev, now, |d| {
            match d
                .call("wasmnet:link/device", "poll", &[Val::U64(now)])?
                .remove(0)
            {
                Val::Option(None) => Ok(None),
                Val::Option(Some(t)) => match *t {
                    Val::U64(t) => Ok(Some(t)),
                    other => Err(format!("{other:?}")),
                },
                other => Err(format!("{other:?}")),
            }
        })
    }

    fn counters(&self, _: u32) -> Result<Vec<(String, u64)>, String> {
        Err("not used here".to_owned())
    }

    fn start(&self, _: u32, _: u32) -> Result<(), String> {
        Err("stepped devices only".to_owned())
    }

    fn run_app(&self, _: u32, _: u32, _: u32) -> Result<(), String> {
        Err("stepped devices only".to_owned())
    }

    fn timer_fire(&self, _: u32) {}

    fn invoke(
        &self,
        dev: u32,
        now: Nanos,
        command: &str,
        argument: &str,
    ) -> Result<Result<String, String>, String> {
        let answer = self.with(dev, now, |d| {
            let args = [
                Val::U64(now),
                Val::String(command.to_owned()),
                Val::String(argument.to_owned()),
            ];
            match d
                .call("wasmnet:control/commands", "invoke", &args)?
                .remove(0)
            {
                Val::Result(Ok(Some(v))) => match *v {
                    Val::String(s) => Ok(Ok(s)),
                    other => Err(format!("{other:?}")),
                },
                Val::Result(Err(Some(v))) => match *v {
                    Val::String(s) => Ok(Err(s)),
                    other => Err(format!("{other:?}")),
                },
                other => Err(format!("{other:?}")),
            }
        })?;
        // In the boundary's encoding, as the page answers.
        codec::decode_command_answer(&codec::encode_command_answer(&answer))
            .map_err(|e| e.to_string())
    }

    fn reconfigure(
        &self,
        dev: u32,
        now: Nanos,
        config: &DeviceConfig,
    ) -> Result<Result<(), Refusal>, String> {
        let answer = self.with(dev, now, |d| {
            let list = config
                .iter()
                .map(|(k, v)| Val::Tuple(vec![Val::String(k.clone()), Val::String(v.clone())]))
                .collect();
            match d
                .call(
                    "wasmnet:reconfigure/reconfigure",
                    "reconfigure",
                    &[Val::U64(now), Val::List(list)],
                )?
                .remove(0)
            {
                Val::Result(Ok(_)) => Ok(Ok(())),
                Val::Result(Err(Some(v))) => match *v {
                    Val::Variant(tag, Some(m)) => match (tag.as_str(), *m) {
                        ("restart", Val::String(m)) => Ok(Err(Refusal::Restart(m))),
                        ("invalid", Val::String(m)) => Ok(Err(Refusal::Invalid(m))),
                        other => Err(format!("{other:?}")),
                    },
                    other => Err(format!("{other:?}")),
                },
                other => Err(format!("{other:?}")),
            }
        })?;
        codec::decode_reconfigured(&codec::encode_reconfigured(&answer)).map_err(|e| e.to_string())
    }
}

// ---- one scenario, two backends ------------------------------------------------------------

/// What a scenario needs of a network, on either backend.
trait Backend {
    /// A device made from `component` (`router`, `switch`, `infra_script`).
    fn add(
        &mut self,
        name: &str,
        component: &str,
        config: DeviceConfig,
        options: DeviceOptions,
    ) -> DeviceId;
    fn run_to(&mut self, until: Nanos);
    fn command(
        &mut self,
        device: DeviceId,
        command: &str,
        argument: &str,
    ) -> Option<Result<String, String>>;
    fn op(&mut self, op: Op, placement: Placement) -> usize;
    fn op_states(&self) -> Vec<OpState>;
    fn journal(&self) -> Vec<JournalEntry>;
}

/// The catalog controllers create from: the components by their own names.
const CATALOG: [&str; 2] = ["router", "switch"];

struct Native(wasmnet_host::Network<'static>);

impl Native {
    fn new(seed: u64) -> Self {
        let b = support::built();
        let mut net = wasmnet_host::Network::new(&b.host, seed);
        net.set_component_resolver(Box::new(move |name, instantiate| {
            instantiate(&b.load(name))
        }));
        net.set_infra_catalog(CATALOG.map(String::from).to_vec());
        Self(net)
    }
}

impl Backend for Native {
    fn add(
        &mut self,
        name: &str,
        component: &str,
        config: DeviceConfig,
        options: DeviceOptions,
    ) -> DeviceId {
        let c = support::built().load(component);
        self.0
            .device_with_options(name, &c, config, options)
            .expect("device")
    }
    fn run_to(&mut self, until: Nanos) {
        self.0.run_until(until).expect("run");
    }
    fn command(
        &mut self,
        device: DeviceId,
        command: &str,
        argument: &str,
    ) -> Option<Result<String, String>> {
        self.0.command(device, command, argument).expect("command")
    }
    fn op(&mut self, op: Op, placement: Placement) -> usize {
        self.0.add_op(op, placement).expect("op")
    }
    fn op_states(&self) -> Vec<OpState> {
        self.0.op_states()
    }
    fn journal(&self) -> Vec<JournalEntry> {
        self.0.journal()
    }
}

struct Web(wasmnet_web::Network<Wasm>);

impl Web {
    fn new(seed: u64) -> Self {
        let wasm = Wasm::new(seed);
        let mut net = wasmnet_web::Network::new(wasm.clone(), seed);
        REGISTRY.set(Some(net.registry().clone()));
        net.sim_mut()
            .set_infra_catalog(CATALOG.map(String::from).to_vec());
        Self(net)
    }
}

impl Backend for Web {
    fn add(
        &mut self,
        name: &str,
        component: &str,
        config: DeviceConfig,
        options: DeviceOptions,
    ) -> DeviceId {
        self.0
            .device_with_options(name, component, config, options)
            .expect("device")
    }
    fn run_to(&mut self, until: Nanos) {
        // The page's driver loop (crate docs); nothing runs between steps here, as stepped
        // devices do all their work inside the calls.
        let net = &mut self.0;
        let mut ok = net.step(net.now());
        while ok {
            if net.take_dirty() {
                ok = net.step(net.now());
                continue;
            }
            match net.next_event_time() {
                Some(t) if t <= until => ok = net.step(t),
                _ => break,
            }
        }
        match net.finish(Some(until)) {
            RunOutcome::Finished(_) => {}
            RunOutcome::Failed { at, message } => panic!("failed at {at}: {message}"),
            other => panic!("{other:?}"),
        }
    }
    fn command(
        &mut self,
        device: DeviceId,
        command: &str,
        argument: &str,
    ) -> Option<Result<String, String>> {
        self.0.command(device, command, argument).expect("command")
    }
    fn op(&mut self, op: Op, placement: Placement) -> usize {
        self.0.sim_mut().add_op(op, placement).expect("op")
    }
    fn op_states(&self) -> Vec<OpState> {
        self.0.sim().op_states()
    }
    fn journal(&self) -> Vec<JournalEntry> {
        self.0.journal()
    }
}

fn config(pairs: &[(&str, &str)]) -> DeviceConfig {
    support::config(pairs)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A device spec for `devices.apply`: a component and its config.
fn spec(component: &str, cfg: &[(&str, &str)]) -> Vec<u8> {
    let config = cfg
        .iter()
        .map(|(k, v)| (Cbor::text(*k), Cbor::text(*v)))
        .collect();
    Cbor::Map(vec![
        (Cbor::text("component"), Cbor::text(component)),
        (Cbor::text("config"), Cbor::Map(config)),
    ])
    .encode()
}

/// A journalled event: when, which device, its kind and fields.
type Event = (Nanos, String, String, Vec<(String, String)>);

/// What a scenario must do the same on both backends: the answers it read and the events the
/// devices journalled, by device, kind and fields (with their times).
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    answers: Vec<Option<Result<String, String>>>,
    events: Vec<Event>,
    ops: Vec<String>,
}

fn seen(net: &dyn Backend, answers: Vec<Option<Result<String, String>>>, kinds: &[&str]) -> Seen {
    let events = net
        .journal()
        .into_iter()
        .filter_map(|e| match e.record {
            Record::Event { kind, fields } if kinds.contains(&kind.as_str()) => {
                Some((e.at, e.device, kind, fields))
            }
            _ => None,
        })
        .collect();
    let ops = net
        .op_states()
        .into_iter()
        .map(|s| match s {
            OpState::Applied { at, .. } => format!("applied at {at}"),
            OpState::Failed { at, message, .. } => format!("failed at {at}: {message}"),
            other => format!("{other:?}"),
        })
        .collect();
    Seen {
        answers,
        events,
        ops,
    }
}

/// Runs `scenario` on both backends at two seeds and compares what they did.
fn on_both(scenario: impl Fn(&mut dyn Backend) -> Seen) {
    for seed in [42, 7] {
        let native = scenario(&mut Native::new(seed));
        let web = scenario(&mut Web::new(seed));
        assert_eq!(native, web, "seed {seed}: the backends differ");
    }
}

fn field<'a>(seen: &'a Seen, kind: &str, key: &str) -> Vec<&'a str> {
    seen.events
        .iter()
        .filter(|e| e.2 == kind)
        .filter_map(|e| e.3.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()))
        .collect()
}

// ---- the scenarios -------------------------------------------------------------------------

fn router_config() -> DeviceConfig {
    config(&[
        ("mac", "02:00:00:00:fe:10"),
        ("port0.ipv4", "10.0.1.1/24"),
        ("port1.ipv4", "10.0.2.1/24"),
    ])
}

/// The embedder programs a router by command: between runs (`Network::command`) and as
/// operator events at set instants (`Op::Control`), a refused command among them.
fn commands(net: &mut dyn Backend) -> Seen {
    let r = net.add("r", "router", router_config(), DeviceOptions::default());
    let sw = net.add(
        "sw",
        "switch",
        config(&[("ports", "3")]),
        DeviceOptions::default(),
    );
    net.run_to(MS);
    let mut answers = vec![
        net.command(r, "routes", ""),
        net.command(r, "route-add", "10.0.3.0/24 via 10.0.2.2"),
        net.command(r, "route-add", "10.0.3.0/24 via 10.0.2.2"),
        net.command(sw, "block", "0 1"),
        net.command(sw, "paths", ""),
        net.command(sw, "nope", ""),
    ];
    for (at, command, argument) in [
        (2 * MS, "route-add", "10.0.4.0/24 via 10.0.2.3"),
        (2 * MS, "route-add", "not a route"),
        (3 * MS, "route-remove", "10.0.3.0/24"),
    ] {
        net.op(
            Op::control(r, DeviceCommand::new(command, argument).into_control()),
            Placement::StartOf(at),
        );
    }
    net.run_to(4 * MS);
    answers.push(net.command(r, "routes", ""));
    seen(
        net,
        answers,
        &[
            "route-added",
            "route-removed",
            "ports-blocked",
            "ports-unblocked",
        ],
    )
}

#[test]
fn device_commands_answer_alike() {
    on_both(|net| {
        let s = commands(net);
        assert!(matches!(&s.answers[1], Some(Ok(_))), "{s:?}");
        assert_eq!(s.answers[2], Some(Ok("unchanged".to_owned())), "{s:?}");
        assert!(
            matches!(&s.answers[5], Some(Err(e)) if e.contains("unknown command")),
            "{s:?}"
        );
        let routes = s.answers[6].clone().expect("answered").expect("ok");
        assert!(
            routes.contains("10.0.4.0/24") && !routes.contains("10.0.3.0/24"),
            "{routes}"
        );
        assert!(s.ops[1].starts_with("failed at 2000000"), "{s:?}");
        assert_eq!(
            s.events.iter().filter(|e| e.2 == "ports-blocked").count(),
            1,
            "{s:?}"
        );
        s
    });
}

/// A controller creates a router and a switch, sends the router commands and reads their
/// answers (`devices.control-answer`), adds a route only if the answer lacks it, and changes
/// the switch's configuration, which the switch takes in place (`wasmnet:reconfigure`).
fn controller(net: &mut dyn Backend) -> Seen {
    let r1 = spec(
        "router",
        &[
            ("mac", "02:00:00:00:fe:10"),
            ("port0.ipv4", "10.0.1.1/24"),
            ("port1.ipv4", "10.0.2.1/24"),
        ],
    );
    let s1 = spec("switch", &[("ports", "3")]);
    let s1_aging = spec("switch", &[("ports", "3"), ("aging", "30s")]);
    let steps = [
        format!("0ms apply r1 {}", hex(&r1)),
        format!("0ms apply s1 {}", hex(&s1)),
        "1ms id=q control r1 routes".to_owned(),
        "1ms answer q".to_owned(),
        "2ms answer q".to_owned(),
        "2ms id=add when=q!10.0.3.0/24 control r1 route-add 10.0.3.0/24 via 10.0.2.2".to_owned(),
        "3ms id=q2 control r1 routes".to_owned(),
        "4ms answer q2".to_owned(),
        "4ms answer nope".to_owned(),
        format!("5ms apply s1 {}", hex(&s1_aging)),
        "6ms id=p control s1 paths".to_owned(),
        "7ms answer p".to_owned(),
    ];
    let script = steps
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("step.{n}"), s.clone()))
        .collect();
    let mut options = DeviceOptions::default();
    options.infra = true;
    net.add("ctl", "infra_script", script, options);
    net.run_to(10 * MS);
    seen(
        net,
        Vec::new(),
        &[
            "infra-script",
            "route-added",
            "reconfigured",
            "device-reconfigured",
            "device-added",
            "infra-failed",
        ],
    )
}

#[test]
fn a_controller_commands_and_reconfigures_alike() {
    on_both(|net| {
        let s = controller(net);
        let results = field(&s, "infra-script", "result");
        assert_eq!(results[3], "pending", "{s:#?}");
        assert_eq!(results[4], "ok", "{s:#?}");
        assert_eq!(results[5], "ok", "the route was added: {s:#?}");
        assert_eq!(field(&s, "route-added", "prefix").len().max(1), 1, "{s:#?}");
        assert!(results[8].contains("NotFound"), "{s:#?}");
        assert!(
            s.events
                .iter()
                .any(|e| e.2 == "device-reconfigured" && e.1 == "s1"),
            "the switch took its new config in place: {s:#?}"
        );
        s
    });
}

/// A device's arguments and environment (`DeviceOptions::args`, `env`), as it reads them
/// itself: the `infra-script` fixture answers its commands `args` and `env` from
/// `wasi:cli/environment`.
fn environment(net: &mut dyn Backend) -> Seen {
    let mut options = DeviceOptions::default();
    options.infra = true;
    options.args = vec!["-v".to_owned(), "two words".to_owned()];
    options.env = vec![
        ("GREETING".to_owned(), "hello".to_owned()),
        ("EMPTY".to_owned(), String::new()),
    ];
    let ctl = net.add("ctl", "infra_script", DeviceConfig::new(), options);
    let bare = net.add("bare", "infra_script", DeviceConfig::new(), {
        let mut o = DeviceOptions::default();
        o.infra = true;
        o
    });
    net.run_to(MS);
    let answers = vec![
        net.command(ctl, "args", ""),
        net.command(ctl, "env", ""),
        net.command(bare, "args", ""),
        net.command(bare, "env", ""),
    ];
    seen(net, answers, &[])
}

#[test]
fn arguments_and_environment_are_served_alike() {
    on_both(|net| {
        let s = environment(net);
        assert_eq!(
            s.answers[0],
            Some(Ok("ctl\n-v\ntwo words".to_owned())),
            "{s:?}"
        );
        assert_eq!(
            s.answers[1],
            Some(Ok("GREETING=hello\nEMPTY=".to_owned())),
            "{s:?}"
        );
        assert_eq!(s.answers[2], Some(Ok("bare".to_owned())), "{s:?}");
        assert_eq!(s.answers[3], Some(Ok(String::new())), "{s:?}");
        s
    });
}
