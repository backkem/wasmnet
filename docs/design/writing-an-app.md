# Writing an app and a node

An app is an ordinary WASI 0.3 program: it exports `wasi:cli/run@0.3.0` and uses
`wasi:sockets@0.3.0` and `wasi:clocks@0.3.0` as it would on any WASI host. A **node** is the
netstack plus one or more apps, composed with `wac` into one component. The guarantee: the app
does not know it is simulated, and everything it sends leaves the node as Ethernet frames on the
netstack's port. The composed node imports no `wasi:sockets` at all, so there is no other way
out. This note covers the app crate, the composition, and how the host runs the result.

## What an app imports

[wit/app/app.wit](../../wit/app/app.wit) names the usual set:

- `wasi:sockets/types` and `wasi:sockets/ip-name-lookup` (served by the netstack);
- `wasi:clocks/monotonic-clock` (served by the host from virtual time);
- `wasi:config/store` (the node's config) and `wasmnet:link/log` (the journal);
- optionally `wasmnet:sockets-ext/{tcp,udp,multicast,interfaces,icmp}`, for what WASI lacks
  ([socket-extensions.md](socket-extensions.md)).

A component imports only what it calls, so the world is an upper bound, not a list each app
must satisfy. Apps may also use what the host serves to every store: `wasi:random` (seeded per
device), stdout and stderr (captured), stdin. The `http-lb` app draws `wasi:random`; `http-get`
and `replicas` read stdin.

## Config: keys under `app.<name>.`

A node has one `DeviceConfig`. The netstack reads its own keys and ignores every key that starts
with `app.`; each app reads only the keys under `app.<name>.`, with `<name>` its `APP`
constant (the crate name, and the name in its `app-<name>` export).
`wasmnet_app_kit::app_pairs(all, APP)` picks them out, prefix stripped
([crates/wasmnet-app-kit](../../crates/wasmnet-app-kit), which the apps share).
`Config::from_pairs` parses the result and rejects unknown keys. The glue reads everything with
`store::get_all()`. On a bad value the app logs the error and returns `Err` from `run`; the node
keeps running. Every app's keys are in [configuration.md](configuration.md).

## The app crate

[components/apps/udp-echo-server](../../components/apps/udp-echo-server) is the smallest one.
Its `Cargo.toml` makes a `cdylib` that depends on `wasmnet-app-kit`
([crates/wasmnet-app-kit](../../crates/wasmnet-app-kit)); the apps here also name `wasip3` and
`wit-bindgen` themselves, at the workspace's versions, which the kit re-exports as
`wasmnet_app_kit::wasip3` and `wasmnet_app_kit::wit_bindgen`. The glue, `src/component.rs`, gets
the bindings of `wasmnet:app/app` with one line, `wasmnet_app_kit::app_bindings!();`. The
bindings are generated once, inside the kit (`wasmnet_app_kit::bindings`), so an app crate holds
no WIT files and no `wit_bindgen::generate!`: the standard interfaces are the `wasip3` crate's,
and only `wasi:config`, `wasmnet:link/log`, `wasmnet:sockets-ext` and the `wasi:cli/run` export
are the kit's own. The line brings the modules `wasi`, `wasmnet` and `exports` into the glue,
with the `export!` macro and an `event(kind, fields)` helper for structured log events. The kit
also converts socket addresses between `std::net` and `wasi:sockets` (`to_std`, `to_wit`). An
app that needs another world (`replicas` adds `wasmnet:infra`) writes its own `generate!`.

`run` is an `async fn` that creates a `UdpSocket`, binds it, and loops on `receive().await` and
`send(...).await`. Logic that needs no socket (config parsing, protocol encoding) lives in
`src/lib.rs` and is tested inside wasmtime with `cargo test --target wasm32-wasip2 -p
wasmnet-udp-echo-server`, like a device ([writing-a-device.md](writing-a-device.md)). New app crates
under `components/apps/` join the workspace through the `components/apps/*` member glob.

## The composition, line by line

[compositions/udp-echo-server.wac](../../compositions/udp-echo-server.wac):

```wac
package wasmnet:node-udp-echo-server;              // the composed component's own name

let net = new wasmnet:netstack { ... };            // one netstack; `...` forwards all of its
                                                   // imports (link, log, config, clocks,
                                                   // random) to the host
let server = new app:udp-echo-server {
    "wasi:sockets/types@0.3.0": net["wasi:sockets/types@0.3.0"],  // the app's sockets are
    ...                                            // the netstack's export; every other
};                                                 // import goes to the host

export net["wasmnet:link/device@0.1.0"];           // the node is a device: frames in and out
export net["wasmnet:link/lifecycle@0.1.0"];        // `start` spawns the netstack's driver
export net["wasmnet:link/counters@0.1.0"];         // `Network::counters` reads the stack
export server["wasi:cli/run@0.3.0"] as "app-udp-echo-server";  // the app's entry point
```

[compositions/http-server.wac](../../compositions/http-server.wac) has the same shape with one
more wire: `"wasmnet:sockets-ext/tcp@0.1.0": net["wasmnet:sockets-ext/tcp@0.1.0"]`, because the
app sets `TCP_NODELAY`. Every extension an app imports must be wired from the same netstack,
at the version the netstack exports. A node with several apps instantiates the netstack once and
wires each app to it ([compositions/dhcp-dns.wac](../../compositions/dhcp-dns.wac)).

`cargo xtask build` copies every component into `target/wac-deps` as `wasmnet:<component>` and
`app:<app>`, runs `wac compose` on every `compositions/<node>.wac`, writes
`target/wasm32-wasip2/release/node-<node>.wasm` and validates it. An app import left unwired is
forwarded to the host by `...`; the host links no `wasi:sockets`, so the node then fails to
instantiate, and wasmtime names the missing import.

## How the host runs a node

When the network creates the device, the host looks for every export named `app-<name>`; each
must be an instance with `run: async func() -> result` (`load_apps` in
[crates/wasmnet-host/src/runtime.rs](../../crates/wasmnet-host/src/runtime.rs)).
`Network::apps(device)` lists them. Then, in the device's actor:

1. `start()` runs first and spawns the netstack's driver.
2. Once it returns, every app's `run` starts, in export-name order, as a **daemon call**: it
   stays in flight as long as the app runs and never counts as outstanding, so a server that
   never returns is not a deadlock. `Outcome::Quiescent::daemons` lists the ones still running
   as `<device>: app-<name>.run`.
3. A `run` that returns is journalled at that instant as a log line `app <name> exited: ok` (or
   `error`) and an `app-exit {app, status}` event.

A trap in an app is a trap of the whole node, and so is a call to `wasi:cli/exit`, which ends the
store; return from `run` instead. An app's stdin never reaches end of file: its bytes arrive
only through operator events (`Op::Stdin`, `Op::StdinNamed`), at their instant
([event-order.md](event-order.md)).

## Adding an app and a node

1. Create `components/apps/<name>/` with `Cargo.toml`, `src/lib.rs` (logic, config with
   `APP = "<name>"`) and `src/component.rs` (glue), copying an existing app.
2. Write `compositions/<node>.wac`: one netstack, the app wired to every `wasi:sockets` and
   `wasmnet:sockets-ext` interface it imports, the three netstack exports, and the app's run
   exported as `app-<name>`.
3. Run `cargo xtask build`, then load `node-<node>.wasm` with `Host::load` and give the device a
   config with the netstack's keys plus `app.<name>.*`.
4. Test it end to end under the host, as
   [crates/wasmnet-host/tests/nodes.rs](../../crates/wasmnet-host/tests/nodes.rs) does with
   `http-get` and `http-server`.
