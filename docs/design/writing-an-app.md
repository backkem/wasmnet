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

## Advertising and browsing services

Service discovery is DNS-SD (RFC 6763) over Multicast DNS (RFC 6762), in apps, over ordinary
UDP sockets: nothing in the netstack knows about it.

**Advertising.** An app does not advertise itself: put `mdns-responder` in the node beside it
and name its services in the responder's config, as
[compositions/mdns-web.wac](../../compositions/mdns-web.wac) does for `http-server`:

```text
app.http-server.listen                  = 0.0.0.0:80
app.mdns-responder.hostname             = alpha
app.mdns-responder.service.web.instance = Alpha Web
app.mdns-responder.service.web.type     = _http._tcp
app.mdns-responder.service.web.port     = 80
app.mdns-responder.service.web.txt      = path=/
```

The responder claims `alpha.local` first, then probes for `Alpha Web._http._tcp.local`,
announces its PTR, SRV and TXT records, renames the instance `Alpha Web (2)` if someone else
holds the name, and answers browsers. A service with `until` is withdrawn at that time with
goodbye packets. The keys are in [configuration.md](configuration.md#mdns-responder).

**Browsing.** `wasmnet_app_kit::mdns::Browser` is a browser with no I/O and no clock, which an
app drives over its own sockets
([crates/wasmnet-app-kit/src/mdns.rs](../../crates/wasmnet-app-kit/src/mdns.rs)):

1. Open one UDP socket per family, bind it to port 5353 and join the group with
   `wasmnet:sockets-ext/multicast` (`join-multicast-group`, hop limit 255, loopback off). Wire
   `wasmnet:sockets-ext/multicast` into the app in its composition.
2. `Browser::new(seed)`, then `browse(now, "_http._tcp")` for each type.
3. Loop: wait for a datagram or `next_deadline()`. A datagram goes to `on_message(now, bytes)`,
   the timer to `tick(now)`, which also returns the queries to send to `224.0.0.251:5353` and
   `[ff02::fb]:5353`.
4. Act on the events: `Found` (a new instance; call `resolve(now, name)` to learn where it
   is), `Resolved` (host, port, TXT strings and addresses, once complete and again when they
   change) and `Removed` (by goodbye or because its TTL ran out).

The browser queries with RFC 6762's back-off (1 s doubling to an hour) and known answers,
refreshes the records it needs at 80 to 95 % of their TTL, and honours goodbyes and the
cache-flush bit. [components/apps/service-browse](../../components/apps/service-browse) is a
complete app built on it: it journals what it sees and can fetch from an instance by the
address and port it resolved. Port 5353 can be bound once per node and family, so on a node
that also runs `mdns-responder` the app binds another port; responders then answer it by
unicast with short TTLs (RFC 6762 §6.7), and the browser works the same. What of the RFCs is
not done is in [known-issues.md](../known-issues.md).

## An app in another repository

An app does not have to live in this tree. A crate anywhere needs one dependency and no WIT
files; [crates/wasmnet-host/tests/fixtures/external-app](../../crates/wasmnet-host/tests/fixtures/external-app)
is a complete one, which
[tests/external_app.rs](../../crates/wasmnet-host/tests/external_app.rs) copies to a temporary
directory, builds there, composes and runs.

**The dependency.** `wasmnet-app-kit`, by git at a fixed revision (or by path, next to a
checkout), in a crate whose library is a `cdylib`:

```toml
[lib]
name = "hello"
crate-type = ["cdylib"]

[dependencies]
wasmnet-app-kit = { git = "https://github.com/backkem/wasmnet", rev = "<commit>" }
```

The kit re-exports the two crates the bindings are made with, `wasmnet_app_kit::wasip3` (the
standard sockets and clocks) and `wasmnet_app_kit::wit_bindgen` (streams, futures,
`spawn_local`), so the app names neither. One that lists them itself must pin the versions the
kit pins, or the socket types stop matching. The toolchain needs the `wasm32-wasip2` target and
Rust 1.98 or later.

**The bindings.** One line, as for an app in this tree: `wasmnet_app_kit::app_bindings!();`.
The bindings were generated inside the kit from the WIT in its own checkout (cargo checks out
the whole repository for a git dependency), so nothing is copied. Implement
`exports::wasi::cli::run::Guest` for a type and hand it to `export!`. Then build and check:

```sh
cargo build --release --target wasm32-wasip2
wasm-tools validate target/wasm32-wasip2/release/hello.wasm
```

An app that imports more than `wasmnet:app/app` offers (as `replicas` adds `wasmnet:infra`)
still writes its own `wit_bindgen::generate!`, whose paths are literals relative to the app's
crate: it needs the WIT at a place it can name, such as a submodule. `wasmnet_app_kit::WIT_DIR`
is the directory in the kit's checkout, for a build script or a tool that wants to read or copy
it.

**A netstack.** The app runs on the netstack built from the same revision, so that the
interfaces it imports are the ones the netstack exports. In a checkout of this repository at
that revision ([components/README.md](../../components/README.md) names everything `--only`
takes):

```sh
cargo xtask build --only netstack,switch --out-dir ../my-app/parts
```

**The node.** A composition of the app's own, shaped like the one above, and `wac` with each
part given by path:

```sh
wac compose node.wac -o node-hello.wasm \
    --dep wasmnet:netstack=parts/netstack.wasm \
    --dep app:hello=target/wasm32-wasip2/release/hello.wasm
wasm-tools validate node-hello.wasm
```

**Running it.** A native crate that depends on `wasmnet-host` (the same repository, the same
revision) loads the node with `Host::load("node-hello.wasm")` and gives the device the
netstack's keys plus `app.hello.*`, as in [How the host runs a node](#how-the-host-runs-a-node).
`wasmnet_host::wasmtime` is the wasmtime the host is built on, so that crate pins none of its
own. The tool versions to install are in [tools.toml](../../tools.toml).
