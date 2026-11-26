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

use wasmnet_core::supply::reference_of;
use wasmnet_core::{
    DeviceCommand, DeviceConfig, DeviceEntropy, DeviceId, DeviceOptions, ImportPolicy,
    JournalEntry, Nanos, Op, OpState, Placement, Record,
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
    /// The network's seed, for its devices' entropy (a replacement sets it again).
    seed: Rc<std::cell::Cell<u64>>,
    /// By key; a supplied component under its digest ([`JsHost::compile`]).
    components: Rc<RefCell<BTreeMap<String, Component>>>,
    devices: Rc<RefCell<BTreeMap<u32, Device>>>,
    now: Now,
}

impl Wasm {
    fn new(seed: u64) -> Self {
        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = Engine::new(&config).expect("engine");
        let components = [
            "router",
            "switch",
            "infra_script",
            "pad_probe",
            "disk_probe",
        ]
        .into_iter()
        .map(|name| {
            let path = file_of(name);
            let c = Component::from_file(&engine, &path)
                .unwrap_or_else(|e| panic!("{}: {e:?}", path.display()));
            (name.to_owned(), c)
        })
        .collect();
        Self {
            engine,
            seed: Rc::new(std::cell::Cell::new(seed)),
            components: Rc::new(RefCell::new(components)),
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
            let portable = PORTABLE.with(|p| p.iter().any(|i| i.name == name));
            if !served.contains(&bare) && !bare.starts_with("wasmnet:infra/") && !portable {
                continue;
            }
            let mut li = l.instance(name).expect("instance");
            if let Some(i) = PORTABLE.with(|p| p.iter().find(|i| i.name == name).cloned()) {
                link_portable(&mut li, &i);
                continue;
            }
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
        // A record: an object, its fields by name (kebab-case, as `codec.ts` writes them).
        (Val::Record(fields), Type::Record(r)) => Value::Record(
            fields
                .iter()
                .zip(r.fields())
                .map(|((name, v), f)| (name.clone(), to_value(v, &f.ty)))
                .collect(),
        ),
        (Val::Variant(tag, payload), Type::Variant(var)) => {
            let case = var.cases().find(|c| c.name == tag).expect("a case");
            Value::Variant(
                tag.clone(),
                payload
                    .as_deref()
                    .zip(case.ty)
                    .map(|(p, t)| Box::new(to_value(p, &t))),
            )
        }
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
        (Value::Tuple(items) | Value::List(items), Type::Tuple(tt)) => Val::Tuple(
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
            .borrow()
            .get(component)
            .cloned()
            .ok_or_else(|| format!("no component {component}"))?;
        let c = &c;
        let registry = registry();
        let entropy = DeviceEntropy::new(self.seed.get(), name);
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
        // Every interface it exports, as the kit lists them, without a version.
        let mut exports: Vec<String> = d
            .funcs
            .keys()
            .map(|(i, _)| wasmnet_core::export::unversioned(i).to_owned())
            .collect();
        exports.dedup();
        instance.exports = exports;
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

    /// As an embedder's hook would: compiles the bytes the core checked already.
    fn compile(&self, digest: &str, bytes: &[u8]) -> Result<(), String> {
        let c = Component::from_binary(&self.engine, bytes).map_err(|e| format!("{e:?}"))?;
        self.components.borrow_mut().insert(digest.to_owned(), c);
        Ok(())
    }

    /// As the page calls an export by name: the arguments and the answer cross in the boundary's
    /// encoding, in jco's shapes (a `result`'s `ok` bare, its `err` a thrown payload).
    fn export(
        &self,
        dev: u32,
        now: Nanos,
        invocation: &wasmnet_core::Invocation,
    ) -> Result<Option<Result<Value, Value>>, String> {
        let name = format!("{}#{}", invocation.interface, invocation.function);
        let call = codec::encode_infra_call(&name, &invocation.args);
        let (_, args) = codec::decode_infra_call(&call).map_err(|e| e.to_string())?;
        let reply = self.with(dev, now, |d| {
            let Some(f) = d.func(&invocation.interface, &invocation.function) else {
                return Ok(Reply::Failed(format!("no export {name}")));
            };
            let ty = f.ty(&d.store);
            let params: Vec<Type> = ty.params().map(|(_, t)| t).collect();
            let result = ty.results().next();
            let args: Vec<Val> = args
                .into_iter()
                .zip(&params)
                .map(|(a, t)| to_val(a, t))
                .collect();
            let out = d.call(&invocation.interface, &invocation.function, &args)?;
            let lift = |v: Option<Box<Val>>, t: Option<Type>| {
                v.zip(t).map_or(Value::None, |(v, t)| to_value(&v, &t))
            };
            Ok(match (out.into_iter().next(), result) {
                (Some(Val::Result(Ok(v))), Some(Type::Result(rt))) => {
                    Reply::Value(lift(v, rt.ok()))
                }
                (Some(Val::Result(Err(v))), Some(Type::Result(rt))) => {
                    Reply::Error(lift(v, rt.err()))
                }
                (Some(v), Some(t)) => Reply::Value(to_value(&v, &t)),
                _ => Reply::Value(Value::None),
            })
        })?;
        match codec::decode_infra_reply(&codec::encode_infra_reply(&reply))
            .map_err(|e| e.to_string())?
        {
            Reply::Value(v) => Ok(Some(Ok(v))),
            Reply::Error(v) => Ok(Some(Err(v))),
            Reply::Failed(_) => Ok(None),
        }
    }

    /// What `network.ts` does: the old network's instances go, and the next devices' entropy
    /// comes from `seed`.
    fn network_replaced(&self, seed: u64) {
        self.devices.borrow_mut().clear();
        self.seed.set(seed);
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
    /// An operator event from a plain object, as the page's `wn_add_op` builds it
    /// (`wasmnet_web::ops::op_in`).
    fn op_value(&mut self, op: &Value) -> usize;
    fn op_states(&self) -> Vec<OpState>;
    /// Admits supplied components by their imports.
    fn admit(&mut self, policy: ImportPolicy);
    /// Adds a network extension (the order test's pair).
    fn extend(&mut self, extension: Box<dyn wasmnet_core::NetworkExtension>);
    /// The network's parse of an extension option.
    fn option(&self, key: &str, value: &Value) -> wasmnet_core::ExtValue;
    /// A call of one of the device's export functions by name, between runs.
    fn invoke(
        &mut self,
        device: DeviceId,
        invocation: wasmnet_core::Invocation,
    ) -> Option<Result<wasmnet_core::export::Answered, String>>;
    /// The interfaces the device reports it exports.
    fn exports(&mut self, device: DeviceId) -> Vec<String>;
    /// The digest of one of a device's disks, as hex.
    fn disk_digest(&mut self, device: &str, disk: &str) -> Option<String>;
    fn journal(&self) -> Vec<JournalEntry>;
}

/// The catalog controllers create from: the components by their own names.
const CATALOG: [&str; 2] = ["router", "switch"];

struct Native(wasmnet_host::Network<'static>);

impl Native {
    fn new(seed: u64) -> Self {
        let mut net = wasmnet_host::Network::new(portable_host(), seed);
        net.add_extension(pad());
        net.add_extension(wasmnet_disk::Disks::default());
        net.set_component_resolver(Box::new(move |name, instantiate| instantiate(&load(name))));
        net.set_infra_catalog(CATALOG.map(String::from).to_vec());
        Self(net)
    }
}

impl Backend for Native {
    fn invoke(
        &mut self,
        device: DeviceId,
        invocation: wasmnet_core::Invocation,
    ) -> Option<Result<wasmnet_core::export::Answered, String>> {
        self.0.invoke(device, invocation).expect("invoke")
    }
    fn exports(&mut self, device: DeviceId) -> Vec<String> {
        self.0.device_exports(device).to_vec()
    }
    fn disk_digest(&mut self, device: &str, disk: &str) -> Option<String> {
        let d = self.0.extension::<wasmnet_disk::Disks>()?;
        d.digest(device, disk).map(|h| wasmnet_disk::digest_hex(&h))
    }
    fn add(
        &mut self,
        name: &str,
        component: &str,
        config: DeviceConfig,
        options: DeviceOptions,
    ) -> DeviceId {
        let c = load(component);
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
    fn op_value(&mut self, op: &Value) -> usize {
        let (op, placement) = wasmnet_web::ops::op_in(&self.0, op).expect("op");
        self.op(op, placement)
    }
    fn op_states(&self) -> Vec<OpState> {
        self.0.op_states()
    }
    fn admit(&mut self, policy: ImportPolicy) {
        self.0.set_supply_admission(policy.admission());
    }
    fn extend(&mut self, extension: Box<dyn wasmnet_core::NetworkExtension>) {
        self.0.add_boxed_extension(extension);
    }
    fn option(&self, key: &str, value: &Value) -> wasmnet_core::ExtValue {
        self.0.parse_option(key, value).expect("option")
    }
    fn journal(&self) -> Vec<JournalEntry> {
        self.0.journal()
    }
}

struct Web(wasmnet_web::Network<Wasm>);

impl Web {
    fn new(seed: u64) -> Self {
        let mut web = Self(wasmnet_web::Network::new(Wasm::new(seed), seed));
        web.install();
        web
    }

    /// What a page module's installer does on every network it makes (`wn_install`), and the
    /// registry the device-side calls go to.
    fn install(&mut self) {
        let net = &mut self.0;
        REGISTRY.set(Some(net.registry().clone()));
        net.sim_mut().add_extension(pad());
        net.sim_mut().add_extension(wasmnet_disk::Disks::default());
        net.sim_mut()
            .set_infra_catalog(CATALOG.map(String::from).to_vec());
    }

    /// The network replaced by an empty one with `seed`, as `wn_network_new` does it.
    fn replace(&mut self, seed: u64) {
        self.0.replace(seed);
        self.install();
    }
}

impl Backend for Web {
    fn invoke(
        &mut self,
        device: DeviceId,
        invocation: wasmnet_core::Invocation,
    ) -> Option<Result<wasmnet_core::export::Answered, String>> {
        self.0.invoke(device, invocation).expect("invoke")
    }
    fn exports(&mut self, device: DeviceId) -> Vec<String> {
        self.0.sim_mut().device_exports(device).to_vec()
    }
    fn disk_digest(&mut self, device: &str, disk: &str) -> Option<String> {
        let d = self.0.sim_mut().extension::<wasmnet_disk::Disks>()?;
        d.digest(device, disk).map(|h| wasmnet_disk::digest_hex(&h))
    }
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
    fn op_value(&mut self, op: &Value) -> usize {
        let (op, placement) = wasmnet_web::ops::op_in(self.0.sim(), op).expect("op");
        self.op(op, placement)
    }
    fn op_states(&self) -> Vec<OpState> {
        self.0.sim().op_states()
    }
    fn journal(&self) -> Vec<JournalEntry> {
        self.0.journal()
    }
    fn admit(&mut self, policy: ImportPolicy) {
        self.0.sim_mut().set_supply_admission(policy.admission());
    }
    fn extend(&mut self, extension: Box<dyn wasmnet_core::NetworkExtension>) {
        self.0.sim_mut().add_boxed_extension(extension);
    }
    fn option(&self, key: &str, value: &Value) -> wasmnet_core::ExtValue {
        self.0.sim().parse_option(key, value).expect("option")
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
fn on_both(mut scenario: impl FnMut(&mut dyn Backend) -> Seen) {
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
        // A restart: a fresh instance of the router, made while the network runs.
        "8ms stop r1".to_owned(),
        "9ms start r1".to_owned(),
        "10ms id=q3 control r1 routes".to_owned(),
        "11ms answer q3".to_owned(),
    ];
    let script = steps
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("step.{n}"), s.clone()))
        .collect();
    let mut options = DeviceOptions::default();
    options.infra = true;
    net.add("ctl", "infra_script", script, options);
    net.run_to(15 * MS);
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
            "device-stopped",
            "device-started",
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
        // The restart: stopped, started as a fresh instance, and answering again.
        assert_eq!(&results[12..], ["ok", "ok", "ok", "ok"], "{s:#?}");
        for kind in ["device-stopped", "device-started"] {
            let n = s
                .events
                .iter()
                .filter(|e| e.2 == kind && e.1 == "r1")
                .count();
            assert_eq!(n, 1, "{kind}: {s:#?}");
        }
        s
    });
}

/// A controller follows the events of a router it created (`wasmnet:infra/events`): three
/// routes added at one instant, each of which sets off its rule once (the rule reads the
/// router's `route-added` events after it), a read with a filter and a cursor, and a read of
/// a device it did not create, which is refused.
fn device_events(net: &mut dyn Backend) -> Seen {
    let r1 = spec(
        "router",
        &[
            ("mac", "02:00:00:00:fe:10"),
            ("port0.ipv4", "10.0.1.1/24"),
            ("port1.ipv4", "10.0.2.1/24"),
        ],
    );
    net.add(
        "sw",
        "switch",
        config(&[("ports", "3")]),
        DeviceOptions::default(),
    );
    let steps = [
        format!("0ms apply r1 {}", hex(&r1)),
        "1ms control r1 route-add 10.0.3.0/24 via 10.0.2.2".to_owned(),
        "1ms control r1 route-add 10.0.4.0/24 via 10.0.2.2".to_owned(),
        "1ms control r1 route-add 10.0.5.0/24 via 10.0.2.2".to_owned(),
        "2ms events r1 route-* 1".to_owned(),
        "2ms events sw".to_owned(),
    ];
    let mut script: Vec<(String, String)> = steps
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("step.{n}"), s.clone()))
        .collect();
    script.push((
        "on.0".to_owned(),
        "r1 route-added : events r1 route-added".to_owned(),
    ));
    let mut options = DeviceOptions::default();
    options.infra = true;
    net.add("ctl", "infra_script", script.into_iter().collect(), options);
    net.run_to(5 * MS);
    seen(
        net,
        Vec::new(),
        &["infra-script", "route-added", "infra-script-missed"],
    )
}

#[test]
fn a_controller_follows_device_events_alike() {
    on_both(|net| {
        let s = device_events(net);
        let rules: Vec<&Event> = s
            .events
            .iter()
            .filter(|e| e.2 == "infra-script")
            .filter(|e| e.3.iter().any(|(k, v)| k == "step" && v == "on.0"))
            .collect();
        let seqs: Vec<&str> = rules
            .iter()
            .flat_map(|e| {
                e.3.iter()
                    .filter(|(k, _)| k == "seq")
                    .map(|(_, v)| v.as_str())
            })
            .collect();
        assert_eq!(seqs, ["1", "2", "3"], "each event once: {s:#?}");
        assert!(
            rules.iter().all(|e| e.0 == MS),
            "at the events' instant: {s:#?}"
        );
        let read = s
            .events
            .iter()
            .find(|e| e.3.iter().any(|(k, v)| k == "step" && v == "4"))
            .expect("the read step");
        assert!(
            read.3.contains(&("seqs".to_owned(), "2,3".to_owned())),
            "{read:?}"
        );
        let refused = s
            .events
            .iter()
            .find(|e| e.3.iter().any(|(k, v)| k == "step" && v == "5"))
            .expect("the refused step");
        assert!(
            refused
                .3
                .iter()
                .any(|(k, v)| k == "result" && v.contains("Denied")),
            "{refused:?}"
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

/// A controller supplies components as bytes (`wasmnet:infra/components`) and creates devices
/// from their digests: the switch's component runs and answers a command; bytes that are no
/// component are refused by the embedder's admission (the core's `ImportPolicy`); an app that
/// imports `wasi:sockets` is admitted but does not link on either backend, which says so in the
/// core's words.
fn supplied(net: &mut dyn Backend) -> (Seen, Vec<String>) {
    net.admit(ImportPolicy::devices().and(["wasi:sockets/*", "wasmnet:sockets-ext/*"]));
    let read = |name: &str| std::fs::read(support::built().path(name)).expect("built");
    let (sw, app) = (read("switch"), read("http_server"));
    let spec = |component: &str, cfg: &[(&str, &str)]| hex(&spec(component, cfg));
    let steps = [
        format!("0ms id=s1 supply - {}", hex(&sw)),
        // Not a component: the admission refuses it, at the call.
        format!("0ms id=s2 supply - {}", hex(b"not a component")),
        format!("0ms id=s3 supply {} {}", reference_of(&app), hex(&app)),
        format!(
            "1ms apply s9 {}",
            spec(&reference_of(&sw), &[("ports", "2")])
        ),
        format!("1ms apply a9 {}", spec(&reference_of(&app), &[])),
        "2ms id=c control s9 paths".to_owned(),
        "3ms answer c".to_owned(),
    ];
    let script = steps
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("step.{n}"), s.clone()))
        .collect();
    let mut options = DeviceOptions::default();
    options.infra = true;
    options.infra_supply = Some(wasmnet_core::SupplyLimits::default());
    // Decoding a megabyte of hex config costs more than an instant's default fuel natively.
    options.fuel_per_instant = Some(4_000_000_000);
    net.add("ctl", "infra_script", script, options);
    net.run_to(5 * MS);
    // A refusal names the backend's own reason after the core's words: compared by those.
    let failed = net
        .journal()
        .into_iter()
        .filter_map(|e| match e.record {
            Record::Event { kind, fields } if kind == "infra-failed" => fields
                .into_iter()
                .find(|(k, _)| k == "message")
                .map(|(_, m)| m),
            _ => None,
        })
        .collect();
    let seen = seen(
        net,
        Vec::new(),
        &["infra-script", "infra-supply", "device-added"],
    );
    (seen, failed)
}

#[test]
fn supplied_components_run_and_are_refused_alike() {
    let mut refusals = Vec::new();
    on_both(|net| {
        let (s, failed) = supplied(net);
        let results = field(&s, "infra-script", "result");
        assert_eq!(results[0], "ok", "{s:#?}");
        assert!(
            results[1].contains("Denied") && results[1].contains("well-formed"),
            "{s:#?}"
        );
        assert_eq!(results[2], "ok", "{s:#?}");
        assert_eq!(results[6], "ok", "the supplied switch answers: {s:#?}");
        assert!(
            s.events
                .iter()
                .any(|e| e.2 == "device-added" && e.1 == "s9"),
            "{s:#?}"
        );
        assert_eq!(failed.len(), 1, "{failed:?}");
        refusals.push(failed[0].clone());
        s
    });
    let app = std::fs::read(support::built().path("http_server")).expect("built");
    let words = format!("`{}` does not link on this host: ", reference_of(&app));
    for r in &refusals {
        assert!(r.contains(&words) && r.contains("wasi:sockets/"), "{r}");
    }
}

// ---- portable extensions ------------------------------------------------------------------

wasmnet_host::portable_adapter!({
    name: PadAdapter,
    path: "../../wit/test-pad",
    world: "wasmnet-test:pad/user",
});

thread_local! {
    /// The portable interfaces the page links (what `wn_interfaces` tells it).
    static PORTABLE: Vec<wasmnet_core::Interface> = {
        let mut i = wasmnet_pad::Pad::interfaces();
        i.extend(wasmnet_disk::Disks::interfaces());
        i
    };
}

/// The fixture as both backends install it: the third append of `q` faults it.
fn pad() -> wasmnet_pad::Pad {
    wasmnet_pad::Pad::default().fault_at("q", 3)
}

/// The file of a component key (`pad_probe` is an example).
fn file_of(name: &str) -> std::path::PathBuf {
    if name == "pad_probe" || name == "disk_probe" {
        static BUILT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        BUILT.get_or_init(|| {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            let ok = std::process::Command::new(env!("CARGO"))
                .current_dir(&root)
                .args(["build", "--release", "--target", "wasm32-wasip2"])
                .args(["-p", "wasmnet-clock-probe"])
                .args(["--example", "pad-probe", "--example", "disk-probe"])
                .status()
                .expect("spawn cargo")
                .success();
            assert!(ok, "building the probes failed");
        });
        return support::built().path(&format!("examples/{name}"));
    }
    support::built().path(name)
}

/// The native backend's host: with the fixture's generated adapter.
fn portable_host() -> &'static wasmnet_host::Host {
    static HOST: std::sync::OnceLock<wasmnet_host::Host> = std::sync::OnceLock::new();
    HOST.get_or_init(|| {
        wasmnet_host::Host::builder()
            .extension(PadAdapter)
            .extension(wasmnet_disk::DiskAdapter)
            .build()
            .expect("host")
    })
}

fn load(name: &str) -> Component {
    portable_host().load(file_of(name)).expect("load")
}

/// A resource's dynamic type on this side: one per name, as the page makes a class per name.
fn resource_type(name: &str) -> u32 {
    name.bytes().fold(0x811c_9dc5_u32, |h, b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    })
}

/// Links a portable interface the way the page does: from its names alone, every call through
/// the boundary's encoding to the registry (`wn_import`), resources as the server's handles.
fn link_portable(
    li: &mut wasmnet_host::wasmtime::component::LinkerInstance<'_, State>,
    i: &wasmnet_core::Interface,
) {
    use wasmnet_host::wasmtime::component::{ResourceDynamic, ResourceType};
    for r in &i.resources {
        let drop_name = format!("{}#{r}", i.name);
        li.resource(
            r,
            ResourceType::host_dynamic(resource_type(r)),
            move |s, rep| {
                registry().import_drop(s.data().dev, &drop_name, rep);
                Ok(())
            },
        )
        .expect("resource");
    }
    for f in &i.functions {
        let call = format!("{}#{f}", i.name);
        li.func_new(f, move |mut s, ty, args, out| {
            let params: Vec<Type> = ty.params().map(|(_, t)| t).collect();
            let mut values = Vec::new();
            for (a, t) in args.iter().zip(&params) {
                values.push(match (a, t) {
                    (Val::Resource(r), Type::Own(rt) | Type::Borrow(rt)) => {
                        let name = PORTABLE
                            .with(|p| {
                                p.iter()
                                    .flat_map(|i| i.resources.clone())
                                    .find(|n| ResourceType::host_dynamic(resource_type(n)) == *rt)
                            })
                            .expect("a known resource");
                        let r = ResourceDynamic::try_from_resource_any(*r, &mut s)?;
                        Value::Resource(name, r.rep())
                    }
                    (a, t) => to_value(a, t),
                });
            }
            let wire = codec::encode_infra_call(&call, &values);
            let (call, values) = codec::decode_infra_call(&wire).expect("call");
            let dev = s.data().dev;
            let reply = registry().import(dev, &call, values);
            let reply =
                codec::decode_infra_reply(&codec::encode_infra_reply(&reply)).expect("reply");
            let Some(result) = ty.results().next() else {
                return Ok(());
            };
            out[0] = match (reply, &result) {
                (Reply::Value(v), Type::Result(r)) => Val::Result(Ok(match r.ok() {
                    Some(t) => Some(Box::new(lift_portable(v, &t, &mut s)?)),
                    None => None,
                })),
                (Reply::Error(v), Type::Result(r)) => Val::Result(Err(match r.err() {
                    Some(t) => Some(Box::new(lift_portable(v, &t, &mut s)?)),
                    None => None,
                })),
                (Reply::Value(v), t) => lift_portable(v, t, &mut s)?,
                (Reply::Failed(m), _) => {
                    return Err(wasmnet_host::wasmtime::format_err!("{m}"));
                }
                (reply, _) => {
                    return Err(wasmnet_host::wasmtime::format_err!("{call}: {reply:?}"));
                }
            };
            Ok(())
        })
        .expect("function");
    }
}

/// An answer in the function's own types, with owned resources made from the server's handles.
fn lift_portable(
    v: Value,
    t: &Type,
    s: &mut wasmnet_host::wasmtime::StoreContextMut<'_, State>,
) -> wasmnet_host::wasmtime::Result<Val> {
    use wasmnet_host::wasmtime::component::ResourceDynamic;
    Ok(match (v, t) {
        (Value::Resource(name, h), Type::Own(_)) => Val::Resource(
            ResourceDynamic::new_own(h, resource_type(&name)).try_into_resource_any(&mut *s)?,
        ),
        (Value::None, Type::Option(_)) => Val::Option(None),
        (Value::Some(v), Type::Option(o)) => {
            Val::Option(Some(Box::new(lift_portable(*v, &o.ty(), s)?)))
        }
        (Value::Tuple(items) | Value::List(items), Type::Tuple(tt)) => Val::Tuple(
            items
                .into_iter()
                .zip(tt.types())
                .map(|(v, t)| lift_portable(v, &t, s))
                .collect::<wasmnet_host::wasmtime::Result<_>>()?,
        ),
        (Value::Record(fields), Type::Record(r)) => {
            let mut fields: BTreeMap<String, Value> = fields.into_iter().collect();
            Val::Record(
                r.fields()
                    .map(|f| {
                        let v = fields.remove(f.name).unwrap_or(Value::None);
                        Ok((f.name.to_owned(), lift_portable(v, &f.ty, s)?))
                    })
                    .collect::<wasmnet_host::wasmtime::Result<_>>()?,
            )
        }
        (v, t) => to_val(v, t),
    })
}

fn portable_scenario(net: &mut dyn Backend) -> Seen {
    let alone = DeviceOptions::default().crash_alone(true);
    net.add(
        "p",
        "pad_probe",
        config(&[("period", "10ms"), ("big", "1048576")]),
        alone.clone(),
    );
    net.add("q", "pad_probe", config(&[("period", "10ms")]), alone);
    for (at, op) in [
        (55, Op::stop_device("p")),
        (60, Op::start_device("p")),
        (85, Op::crash_device("p", "operator crash")),
        (90, Op::start_device("p")),
    ] {
        net.op(op, Placement::StartOf(at * MS));
    }
    net.run_to(120 * MS);
    seen(
        net,
        Vec::new(),
        &[
            "pad-boot",
            "pad-big",
            "pad-names",
            "pad-append",
            "pad-error",
            "pad-fault",
            "pad-cleared",
            "device-crashed",
            "device-started",
            "device-stopped",
        ],
    )
}

#[test]
fn a_portable_extension_is_served_alike() {
    on_both(|net| {
        let s = portable_scenario(net);
        assert_eq!(
            field(&s, "pad-big", "size"),
            ["1048576", "2097152", "1048576"],
            "{s:?}"
        );
        assert_eq!(
            field(&s, "device-crashed", "message"),
            ["pad: append 3 failed", "operator crash"],
            "{s:?}"
        );
        assert_eq!(
            field(&s, "pad-boot", "boots"),
            ["0", "0", "1", "0"],
            "{s:?}"
        );
        s
    });
}

// ---- fuel spans ------------------------------------------------------------------------------

/// A server in front of the pad's that opens its device's fuel span after `note.find`, opens it
/// again after `totals`, ends it after `names` (only on `p`), and journals what each answered
/// and, at every append, whether a span is open.
struct SpanServer {
    inner: Arc<dyn wasmnet_core::ImportServer>,
    span: wasmnet_core::FuelSpan,
    ends: bool,
    journal: wasmnet_core::JournalEnd,
    clock: wasmnet_core::VirtualClock,
}

impl SpanServer {
    fn note(&self, what: &str, result: bool) {
        self.journal.push(
            self.clock.now(),
            Record::Event {
                kind: "span".into(),
                fields: vec![
                    ("what".into(), what.into()),
                    ("result".into(), result.to_string()),
                ],
            },
        );
    }
}

impl wasmnet_core::ImportServer for SpanServer {
    fn call(
        &self,
        interface: &str,
        function: &str,
        args: Vec<wasmnet_core::value::Value>,
    ) -> wasmnet_core::Served {
        if function == "[method]note.append" {
            self.note("open", self.span.is_open());
        }
        let served = self.inner.call(interface, function, args);
        match function {
            "[static]note.find" | "totals" => self.note(function, self.span.begin()),
            "names" if self.ends => self.note(function, self.span.end()),
            _ => {}
        }
        served
    }

    fn drop_resource(&self, interface: &str, resource: &str, handle: u32) {
        self.inner.drop_resource(interface, resource, handle);
    }
}

struct SpanExt;

impl wasmnet_core::NetworkExtension for SpanExt {
    fn device_setup(
        &mut self,
        setup: &wasmnet_core::ext::DeviceSetup<'_>,
        ext: &mut wasmnet_core::DeviceExt,
    ) {
        let inner = ext.server(wasmnet_pad::NOTES).expect("the pad's").clone();
        let server = SpanServer {
            inner,
            span: ext.fuel_span().clone(),
            ends: setup.name == "p",
            journal: setup.journal.clone(),
            clock: setup.clock.clone(),
        };
        ext.serve(wasmnet_pad::NOTES, Arc::new(server));
    }
}

/// A fuel span reads the same on both backends: it is fuel only on wasmtime (in a page nothing
/// is metered), and its state (a second begin, an end, its close with its instant, with its
/// device) is the core's.
#[test]
fn a_fuel_span_reads_alike() {
    on_both(|net| {
        net.extend(Box::new(SpanExt));
        let alone = DeviceOptions::default().crash_alone(true);
        net.add(
            "p",
            "pad_probe",
            config(&[("period", "10ms")]),
            alone.clone(),
        );
        net.add("q", "pad_probe", config(&[("period", "10ms")]), alone);
        net.op(
            Op::crash_device("q", "operator crash"),
            Placement::StartOf(25 * MS),
        );
        net.op(Op::start_device("q"), Placement::StartOf(30 * MS));
        net.run_to(45 * MS);
        let s = seen(net, Vec::new(), &["span", "device-crashed"]);
        let of = |dev: &str| -> Vec<String> {
            s.events
                .iter()
                .filter(|e| e.1 == dev && e.2 == "span")
                .map(|e| format!("{}={}", e.3[0].1, e.3[1].1))
                .collect()
        };
        assert_eq!(
            of("p"),
            [
                "[static]note.find=true",
                "totals=false",
                "open=true",
                "names=true",
                "open=false",
                "open=false",
                "open=false",
                "open=false",
            ],
            "{s:?}"
        );
        // Never ended: open through its boot, closed at its next instant; a new one after
        // its crash and start.
        assert_eq!(
            of("q")[..4],
            [
                "[static]note.find=true",
                "totals=false",
                "open=true",
                "open=false"
            ],
            "{s:?}"
        );
        s
    });
}

// ---- the order of extensions ----------------------------------------------------------------

/// A test extension that journals what it hears, under its own name: the order of two of them
/// is the order they were added, on both backends. Two types (a network keeps one extension
/// per type).
struct Order<const N: u8>(&'static str);

impl<const N: u8> wasmnet_core::NetworkExtension for Order<N> {
    fn device_setup(
        &mut self,
        setup: &wasmnet_core::ext::DeviceSetup<'_>,
        _ext: &mut wasmnet_core::DeviceExt,
    ) {
        setup.journal.push(
            setup.clock.now(),
            Record::Event {
                kind: "order-setup".into(),
                fields: vec![("ext".into(), self.0.into())],
            },
        );
    }

    fn device_life(&mut self, life: &wasmnet_core::ext::DeviceLife<'_>) {
        life.journal.push(
            life.at,
            Record::Event {
                kind: "order-life".into(),
                fields: vec![
                    ("ext".into(), self.0.into()),
                    ("event".into(), format!("{:?}", life.event)),
                ],
            },
        );
    }
}

fn order(net: &mut dyn Backend) -> Seen {
    net.extend(Box::new(Order::<1>("first")));
    net.extend(Box::new(Order::<2>("second")));
    net.add(
        "p",
        "pad_probe",
        config(&[("period", "10ms")]),
        DeviceOptions::default(),
    );
    net.op(Op::stop_device("p"), Placement::StartOf(15 * MS));
    net.op(Op::start_device("p"), Placement::StartOf(20 * MS));
    net.run_to(30 * MS);
    seen(net, Vec::new(), &["order-setup", "order-life"])
}

#[test]
fn extensions_hear_a_device_in_the_order_they_were_added_alike() {
    on_both(|net| {
        let s = order(net);
        let heard: Vec<(&str, &str)> = s
            .events
            .iter()
            .map(|e| (e.2.as_str(), e.3[0].1.as_str()))
            .collect();
        // Every record comes as a pair, the first extension then the second: creation, the
        // stop, the start (its setup and its life event).
        assert_eq!(heard.len(), 8, "{s:?}");
        for pair in heard.chunks(2) {
            assert_eq!(
                (pair[0].0, pair[0].1, pair[1].1),
                (pair[1].0, "first", "second"),
                "{s:?}"
            );
        }
        s
    });
}

/// An extension's option set from a generic value, and its operator event at a device, alike.
fn options_and_ops(net: &mut dyn Backend) -> Seen {
    let mut faulty = DeviceOptions::default().crash_alone(true);
    faulty
        .ext
        .set_value(net.option("pad.fault-at", &Value::U32(2)));
    net.add("f", "pad_probe", config(&[("period", "10ms")]), faulty);
    let p = net.add(
        "p",
        "pad_probe",
        config(&[("period", "10ms")]),
        DeviceOptions::default(),
    );
    net.op(
        Op::extension_at(p, wasmnet_core::ExtensionOp::new(wasmnet_pad::PadOp::Clear)),
        Placement::StartOf(25 * MS),
    );
    net.run_to(40 * MS);
    seen(
        net,
        Vec::new(),
        &["pad-cleared", "pad-fault", "device-crashed"],
    )
}

#[test]
fn extension_options_and_ops_are_applied_alike() {
    on_both(|net| {
        let s = options_and_ops(net);
        assert_eq!(
            field(&s, "device-crashed", "message"),
            ["pad: append 2 failed"],
            "{s:?}"
        );
        assert_eq!(field(&s, "pad-cleared", "by"), ["operator"], "{s:?}");
        s
    });
}

// ---- portable exports ----------------------------------------------------------------------

fn inspect(function: &str, args: Vec<Value>) -> wasmnet_core::Invocation {
    wasmnet_core::Invocation::new("wasmnet-test:pad/inspect", function, args)
}

/// An op that calls the device's export from inside a run.
#[derive(Debug, PartialEq)]
struct WriteFromInside;

impl wasmnet_core::ext::ExtOp for WriteFromInside {
    fn apply(
        &self,
        ctx: &mut wasmnet_core::ext::OpContext<'_>,
    ) -> Result<(), wasmnet_core::ext::OpError> {
        let device = ctx.device().ok_or("timed at a device")?;
        let call = wasmnet_core::export::ExportCall::new(inspect(
            "write",
            vec![Value::str("ext"), Value::Bytes(b"!".to_vec())],
        ));
        ctx.control(device, Box::new(call));
        Ok(())
    }

    fn same(&self, other: &dyn wasmnet_core::ext::ExtOp) -> bool {
        (other as &dyn std::any::Any).downcast_ref::<Self>() == Some(self)
    }
}

fn exports(net: &mut dyn Backend) -> Seen {
    let p = net.add(
        "p",
        "pad_probe",
        config(&[("period", "10ms")]),
        DeviceOptions::default(),
    );
    net.run_to(MS);
    let mut answers = vec![Some(Ok(net.exports(p).join(",")))];
    let mut call = |net: &mut dyn Backend, inv| {
        answers.push(net.invoke(p, inv).map(|a| Ok(format!("{a:?}"))));
    };
    call(
        net,
        inspect(
            "write",
            vec![Value::str("ext"), Value::Bytes(b"hello".to_vec())],
        ),
    );
    // As an operator event, and from inside a run.
    net.op(
        Op::control(
            p,
            wasmnet_core::export::ExportRequest::new(inspect(
                "write",
                vec![Value::str("ext"), Value::Bytes(b" world".to_vec())],
            ))
            .into_control(),
        ),
        Placement::StartOf(5 * MS),
    );
    net.op(
        Op::extension_at(p, wasmnet_core::ExtensionOp::new(WriteFromInside)),
        Placement::StartOf(7 * MS),
    );
    net.run_to(30 * MS);
    call(net, inspect("size", vec![Value::str("ext")]));
    call(net, inspect("size", vec![Value::str("none")]));
    call(
        net,
        inspect(
            "read",
            vec![Value::str("ext"), Value::U64(0), Value::U32(100)],
        ),
    );
    // No such function: refused, the device goes on; no such interface: not reported.
    call(net, inspect("missing", Vec::new()));
    call(
        net,
        wasmnet_core::Invocation::new("wasmnet-test:pad/nope", "x", Vec::new()),
    );
    seen(
        net,
        answers,
        &["pad-written", "pad-append", "device-crashed"],
    )
}

#[test]
fn portable_exports_are_called_alike() {
    on_both(|net| {
        let s = exports(net);
        let answer = |i: usize| s.answers[i].clone().map(|a| a.unwrap_or_else(|e| e));
        let exports = answer(0).unwrap_or_default();
        assert!(
            exports.contains("wasmnet-test:pad/inspect") && exports.contains("wasmnet:link/device"),
            "{exports}"
        );
        assert_eq!(answer(1).as_deref(), Some("Ok(Ok(U64(5)))"), "{s:?}");
        assert_eq!(answer(2).as_deref(), Some("Ok(Ok(U64(12)))"), "{s:?}");
        assert_eq!(answer(3).as_deref(), Some("Ok(Ok(None))"), "{s:?}");
        assert_eq!(
            answer(4).as_deref(),
            Some(format!("Ok(Ok(Bytes({:?})))", b"hello world!".to_vec()).as_str()),
            "{s:?}"
        );
        assert!(answer(5).is_some_and(|a| a.starts_with("Err(")), "{s:?}");
        assert_eq!(answer(6), None, "{s:?}");
        assert_eq!(field(&s, "pad-written", "size"), ["5", "11", "12"], "{s:?}");
        assert!(field(&s, "device-crashed", "message").is_empty(), "{s:?}");
        s
    });
}

// ---- disks --------------------------------------------------------------------------------

/// A disk fault at a device, timed.
fn disk_fault(
    net: &mut dyn Backend,
    at: Nanos,
    device: DeviceId,
    disk: &str,
    f: wasmnet_disk::DiskFault,
) {
    let op = wasmnet_core::ExtensionOp::new(wasmnet_disk::DiskOp::new(disk, f));
    net.op(Op::extension_at(device, op), Placement::StartOf(at));
}

/// The disk probe on two disks, through every kind of fault, on either backend; the answers
/// are the disks' digests after the run.
fn disks(net: &mut dyn Backend) -> Seen {
    use wasmnet_disk::{Corruption, DiskFault, DiskOptions, DiskSpec, Durability, Keep};
    let mut options = DeviceOptions::default().crash_alone(true);
    options.ext.set(DiskOptions::new(vec![
        DiskSpec::new("state"),
        DiskSpec::new("log").durability(Durability::OnSync),
    ]));
    let p = net.add(
        "p",
        "disk_probe",
        config(&[("period", "10ms"), ("big", "1048576")]),
        options,
    );
    // An option from a generic value, as a spec or a page gives it.
    let mut small = DeviceOptions::default().crash_alone(true);
    small.ext.set_value(net.option(
        "disk.specs",
        &Value::List(vec![Value::record(vec![
            ("name", Value::str("state")),
            ("quota", Value::U32(2048)),
        ])]),
    ));
    net.add(
        "q",
        "disk_probe",
        config(&[("period", "1000ms"), ("fill", "4096")]),
        small,
    );
    for (at, op) in [
        (25, Op::stop_device("p")),
        (30, Op::start_device("p")),
        (55, Op::crash_device("p", "operator crash")),
        (58, Op::start_device("p")),
        (62, Op::start_device("p")),
        (86, Op::stop_device("p")),
        (87, Op::start_device("p")),
    ] {
        net.op(op, Placement::StartOf(at * MS));
    }
    disk_fault(
        net,
        35 * MS,
        p,
        "log",
        DiskFault::PowerLoss {
            keep: Keep::Prefix,
            tear: true,
        },
    );
    disk_fault(
        net,
        56 * MS,
        p,
        "state",
        DiskFault::CrashAt {
            call: 1,
            keep: Keep::Prefix,
        },
    );
    disk_fault(net, 60 * MS, p, "log", DiskFault::Lose);
    disk_fault(
        net,
        70 * MS,
        p,
        "log",
        DiskFault::FailCalls {
            count: 1,
            text: "a bad sector".into(),
        },
    );
    let garbage = DiskFault::Corrupt {
        prefix: "boots".into(),
        how: Corruption::Garbage,
    };
    disk_fault(net, 85 * MS, p, "state", garbage);
    disk_fault(net, 90 * MS, p, "log", DiskFault::Quota(10));
    net.run_to(100 * MS);
    let answers = [("p", "state"), ("p", "log"), ("q", "state")]
        .into_iter()
        .map(|(d, k)| net.disk_digest(d, k).map(Ok))
        .collect();
    seen(
        net,
        answers,
        &[
            "kv-boot",
            "kv-big",
            "kv-check",
            "kv-fill",
            "kv-write",
            "kv-error",
            "disk-created",
            "disk-armed",
            "disk-power-loss",
            "disk-crash",
            "disk-lost",
            "disk-corrupted",
            "disk-quota",
            "disk-sync",
            "device-crashed",
            "device-started",
            "device-stopped",
        ],
    )
}

#[test]
fn disks_are_served_and_faulted_alike() {
    on_both(|net| {
        let s = disks(net);
        assert!(s.answers.iter().all(Option::is_some), "{s:?}");
        let crashed = field(&s, "device-crashed", "message");
        assert_eq!(crashed.len(), 2, "{s:?}");
        assert!(
            crashed[1].starts_with("disk `state` failed inside write"),
            "{s:?}"
        );
        assert!(field(&s, "kv-fill", "answer")[0].contains("Full"), "{s:?}");
        assert!(
            field(&s, "kv-error", "error")
                .iter()
                .any(|e| e.contains("a bad sector")),
            "{s:?}"
        );
        assert_eq!(field(&s, "disk-power-loss", "disk").len(), 3, "{s:?}");
        s
    });
}

/// Disk faults from the page's plain objects (`wasmnet_web::ops::op_in`), by device name: a
/// crash-at over any disk, one on a disk disarmed, faults on a device an operator creates
/// later, and on a name no device has.
fn disks_by_name(net: &mut dyn Backend) -> Seen {
    use wasmnet_disk::{DiskOptions, DiskSpec, Durability};
    let two = || {
        let mut options = DeviceOptions::default().crash_alone(true);
        options.ext.set(DiskOptions::new(vec![
            DiskSpec::new("state"),
            DiskSpec::new("log").durability(Durability::OnSync),
        ]));
        options
    };
    net.add("p", "disk_probe", config(&[("period", "10ms")]), two());
    net.op(
        Op::add_device("later", "disk_probe")
            .with_config(config(&[("period", "10ms")]))
            .with_options(two()),
        Placement::StartOf(50 * MS),
    );
    let fault = |at: Nanos, device: &str, op: &str, value: Vec<(&str, Value)>| {
        Value::record(vec![
            ("kind", Value::str("extension")),
            ("at", Value::U64(at * MS)),
            ("device", Value::str(device)),
            ("op", Value::str(op)),
            ("value", Value::record(value)),
        ])
    };
    let crash = "disk.crash-at";
    for v in [
        // The second changing call on any disk (the log write at 30 ms); one on the log, armed
        // and disarmed between two writes; the one over any disk disarmed after it fired.
        fault(
            15,
            "p",
            crash,
            vec![("call", Value::U32(2)), ("keep", Value::str("all"))],
        ),
        fault(45, "p", crash, vec![("disk", Value::str("log"))]),
        fault(
            46,
            "p",
            crash,
            vec![("disk", Value::str("log")), ("call", Value::U32(0))],
        ),
        fault(47, "p", crash, vec![("call", Value::U32(0))]),
        fault(
            45,
            "later",
            "disk.lose",
            vec![("disk", Value::str("state"))],
        ),
        fault(
            55,
            "later",
            "disk.lose",
            vec![("disk", Value::str("state"))],
        ),
        fault(56, "later", crash, vec![("call", Value::U32(1))]),
        fault(60, "nobody", "disk.lose", vec![("disk", Value::str("log"))]),
    ] {
        net.op_value(&v);
    }
    net.op(Op::start_device("p"), Placement::StartOf(33 * MS));
    net.run_to(80 * MS);
    let answers = [("p", "state"), ("p", "log"), ("later", "state")]
        .into_iter()
        .map(|(d, k)| net.disk_digest(d, k).map(Ok))
        .collect();
    seen(
        net,
        answers,
        &[
            "disk-armed",
            "disk-disarmed",
            "disk-crash",
            "disk-lost",
            "device-crashed",
            "device-started",
            "device-added",
        ],
    )
}

#[test]
fn disk_faults_by_name_from_plain_objects_apply_alike() {
    on_both(|net| {
        let s = disks_by_name(net);
        assert!(s.answers.iter().all(Option::is_some), "{s:?}");
        assert_eq!(field(&s, "disk-crash", "disks"), ["any", "any"], "{s:?}");
        assert_eq!(field(&s, "disk-crash", "disk"), ["log", "log"], "{s:?}");
        assert_eq!(field(&s, "disk-disarmed", "left"), ["1", "none"], "{s:?}");
        assert_eq!(field(&s, "disk-lost", "disk"), ["state"], "{s:?}");
        let failed: Vec<&String> = s.ops.iter().filter(|o| o.starts_with("failed")).collect();
        assert_eq!(
            failed,
            [
                &format!("failed at {}: no device `later`", 45 * MS),
                &format!("failed at {}: no device `nobody`", 60 * MS),
            ],
            "{s:?}"
        );
        s
    });
}

// ---- networks in sequence -----------------------------------------------------------------

/// Two pad probes, one faulted inside its third append: what the replacement tests run.
fn pads(net: &mut dyn Backend) {
    let options = DeviceOptions::default().crash_alone(true);
    net.add(
        "p",
        "pad_probe",
        config(&[("period", "10ms")]),
        options.clone(),
    );
    let mut faulty = options;
    faulty
        .ext
        .set(wasmnet_pad::PadOptions::default().fault_at(3));
    net.add("q", "pad_probe", config(&[("period", "15ms")]), faulty);
}

/// The browser backend's half of a page's networks in sequence: a network replaced in the middle
/// of its run (devices with pending deadlines, a disk with an unsynced tail, a controller between
/// its steps) leaves nothing in the next one. The next one's journal is a fresh network's at its
/// seed, twice; the old network's registry finds no device any more, so an old guest's late call
/// reaches nothing; and the host is told before the new network exists.
#[test]
fn a_network_replaced_in_mid_run_leaves_no_trace() {
    let seed = 9;
    let mut fresh = Web::new(seed);
    pads(&mut fresh);
    fresh.run_to(60 * MS);
    let want = fresh.journal();
    assert!(
        want.iter()
            .any(|e| matches!(&e.record, Record::Event { kind, .. } if kind == "pad-append")),
        "{want:?}"
    );

    let mut web = Web::new(3);
    let _ = disks(&mut web);
    let mut options = DeviceOptions::default().crash_alone(true);
    options.ext.set(wasmnet_disk::DiskOptions::new(vec![
        wasmnet_disk::DiskSpec::new("log").durability(wasmnet_disk::Durability::OnSync),
    ]));
    web.add("late", "disk_probe", config(&[("period", "10ms")]), options);
    web.run_to(105 * MS);
    let before = web.journal().len();
    assert!(before > 0);
    let old = web.0.registry().clone();
    for _ in 0..2 {
        web.replace(seed);
        assert!(web.journal().is_empty(), "{:?}", web.journal());
        assert!(web.0.sim().op_states().is_empty());
        // What the old devices still call reaches no device of the new network.
        let orphans = old.orphans();
        old.log(0, wasmnet_core::Level::Info, "late".into());
        old.transmit(1, 0, vec![0; 64]);
        assert_eq!(old.orphans(), orphans + 2);
        pads(&mut web);
        web.run_to(60 * MS);
        assert_eq!(web.journal(), want);
        assert_eq!(
            web.disk_digest("p", "state"),
            None,
            "the old network's disks went with it"
        );
    }
}
