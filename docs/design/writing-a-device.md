# Writing a device

A device is a component that exports `wasmnet:link/device` and imports `wasmnet:link/wire`,
`wasmnet:link/log` and `wasi:config/store` ([wit/link/link.wit](../../wit/link/link.wit)). The
host owns every wire: a device never imports another device, frames reach it as `receive`
calls and leave it through `wire.transmit`. The guarantee a device gets: its calls arrive in a
deterministic order, with virtual time passed in, and its frames reach the peer only through the
link model. What it owes in return: deterministic behaviour from those inputs, and no trap on
anything that came off the wire. This note uses the learning switch
([components/switch](../../components/switch)) and the reflector test fixture
([components/reflector](../../components/reflector)) as worked examples.

## Stepped or async

| world | exports | keeps time through | examples |
|---|---|---|---|
| `wasmnet:link/stepped-device` | `device` | the `now` argument; `poll` returns the next deadline | `switch`, `wan-port`, `reflector` |
| `wasmnet:router/router` | `device`, `counters`, `wasmnet:control/commands` | as above | `router` |
| `wasmnet:link/async-device` | `device`, `lifecycle` | virtual `wasi:clocks` waits in its own tasks | `reflector --features async-device` |
| `wasmnet:link/counted-async-device` | `device`, `lifecycle`, `counters` | as above | `netstack` (every node) |

A stepped device is synchronous: every call does its work and returns. Use it for anything that
reacts to frames and keeps timers of its own (MAC aging, ARP retries). An async device runs
long-lived tasks under virtual time; [async-under-virtual-time.md](async-under-virtual-time.md)
explains the rules it follows, and [netstack.md](netstack.md) is the full-size example.

## The calls, in order

1. `ports()`, exactly once, right after instantiation and before anything is wired. The config
   is already readable. The answer never changes: unique ids, an optional 6-byte MAC, and the IP
   MTU. The network rejects duplicate ids and MACs of another length (`Error::BadPorts`).
2. `start()`, for async devices only. It spawns the tasks and returns; commands wait for it.
3. `link-state(now, port, true)` for every port wired before the run, at the device's first
   instant. Later carrier changes arrive the same way, and only real changes are reported.
4. `poll(now)`, at the device's first instant, then at every deadline it returned.
5. `receive(now, port, frame)` whenever a frame arrives; `now` is the arrival time.

After one or more `receive` or `link-state` calls at an instant, the host calls `poll(now)` at
that same instant, after every other event already queued for it. A deadline at or before `now`
means "again at this instant"; the host allows `Guard::max_polls_per_instant` polls of one
device per instant (10,000 by default) before it fails the run with `Error::Runaway`. A stepped
device with nothing scheduled answers `None`; an async device always does.

`wire.transmit(port, frame)` may be called from inside any of these calls (or, in an async
device, from any task). It only enqueues: the frame leaves at the current `now` and the peer
gets it `latency` later as its own `receive`. Nothing is returned. A frame on an unwired or
down port, or with a payload over the link MTU, is dropped and counted by the host. A device
must drop and count a malformed frame, never trap on it: a trap is a device crash and fails the
run.

## Configuration

The embedder gives each device a flat `DeviceConfig` (string keys to string values), served
read-only through `wasi:config/store`: `get(key)`, or `get-all()` in key order. It never changes
during a run. Keep the parsing in `lib.rs` so it is tested like the rest of the logic: the
switch's `Config::from_lookup(get)` takes a lookup function and returns a typed config or a
`ConfigError` naming the key, the value and what was expected. An invalid config is a
configuration error: the glue logs it at `error` and traps, so a bad network fails at once.
Every key of every component is listed in [configuration.md](configuration.md).

Randomness comes from `wasi:random`, which the host serves from a PRNG seeded by the network
seed and the device's name. The reflector draws its MAC that way when `mac` is not configured.

## Logs, events and counters

`wasmnet:link/log` has two sync functions that never yield: `log(level, message)` for a line,
and `event(kind, fields)` for a structured record with a kebab-case `kind` and kebab-case keys.
The host stamps both with virtual time and the device's name and appends them to the network's
journal (`Network::journal`). The switch reports `mac-learned`, `mac-moved`, `mac-aged`,
`mac-flushed`, `port-up` and `port-down`. Never use `eprintln!` for diagnostics: stderr is
captured but not time-stamped, and in an async device the write is a yield point.

A device may also export `wasmnet:link/counters`: one sync function that returns
`(name, value)` pairs in a stable order. The host reads it with `Network::counters` between
runs, as a control call into the live device at its current instant. It must not transmit, log
or wake a task. The router exports it through its own world,
[wit/router/router.wit](../../wit/router/router.wit); the switch keeps per-port counters
internally but does not export them.

A device whose state an operator or a controller should change while it runs (the router's
routes) exports `wasmnet:control/commands` ([wit/control/control.wit](../../wit/control/control.wit)):
`invoke(now, command, argument) -> result<string, string>`. Commands are text, parsed in
`lib.rs` like the configuration (the router's `Router::command` reuses its route parser), and
a malformed one is an `err`, never a trap. Unlike `counters`, a command may change the device,
transmit and log, and a `poll(now)` follows it. Include the interface in the device's world
(`export wasmnet:control/commands@0.1.0;`) and the host reports it on its own: nothing else to
register. How commands reach a device is in
[topology-and-infra.md](topology-and-infra.md#commands-into-a-running-device).

## Logic in `lib.rs`, glue in `component.rs`

Every component crate splits the same way:

- `src/lib.rs`: the pure logic, no bindings. The switch's `Switch::receive`, `link_state` and
  `poll` take `now` and a `Sink` (`transmit`, `event`), so a test can collect what the switch
  sends without an instance.
- `src/component.rs`: the wit-bindgen glue, compiled only under `#[cfg(not(test))]`. It
  generates the bindings for the world, keeps the state in a `thread_local!` created on first
  use (normally by `ports()`), implements `Sink` with `wire::transmit` and `log::event`, and
  forwards each export to the logic.

```rust
wit_bindgen::generate!({
    world: "wasmnet:link/stepped-device",
    path: ["../../wit/deps/config", "../../wit/link"],
    with: { "wasi:config/store@0.2.0-rc.1": generate },
});
```

The crate is a `cdylib` built for `wasm32-wasip2`. Add it to the `members` list of the
workspace `Cargo.toml` by hand (a `components/*` glob would also match `components/apps`).
`cargo xtask build` builds every crate under `components/` and checks each output with
`wasm-tools validate`.

## Testing inside wasmtime

`.cargo/config.toml` sets `wasmtime run --` as the runner for `wasm32-wasip2`, so

```sh
cargo test --target wasm32-wasip2 -p wasmnet-switch
```

builds the logic's tests as a WASI command and runs them inside wasmtime, the same runtime the
device ships to (`cargo xtask test-guest` runs every component's tests that way). The switch
also has a property test against a small reference model; it runs with a fixed proptest seed
and no failure persistence, because a guest has no filesystem to write regressions to.

For a test of the device under the host, build it and load it into a `Network`:
[crates/wasmnet-host/tests/echo.rs](../../crates/wasmnet-host/tests/echo.rs) runs the
`blaster` fixture against the reflector and checks each echo's timing and the pcap's hash, and
[crates/wasmnet-host/tests/async_device.rs](../../crates/wasmnet-host/tests/async_device.rs)
runs the blaster against the reflector's async variant, whose `start()` spawns one task that
echoes each frame after a virtual `wasi:clocks` wait, and checks that every echo arrives at
exactly `send + 2 × latency + delay`.
