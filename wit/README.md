# The contracts

Every capability a component sees is a WIT import, and every device is known to the host only
by what it exports here.

| Package | What |
|---|---|
| `wasmnet:link` | The wire. A device exports `device` (`ports`, `receive`, `poll`, `link-state`) and imports `wire.transmit` and `log`. Worlds: `stepped-device`, `async-device`, `counted-async-device`. |
| `wasmnet:netstack` | The netstack's world: `wasmnet:link` below, `wasi:sockets@0.3.0` and `wasmnet:sockets-ext` above. |
| `wasmnet:sockets-ext` | What `wasi:sockets` lacks: TCP abort and no-delay, ICMP errors on UDP sockets, multicast, interfaces, ICMP echo sockets. Shaped to be upstreamed or dropped. |
| `wasmnet:app` | An app: a WASI 0.3 program that exports `wasi:cli/run` and imports sockets, clocks, config and the log. |
| `wasmnet:router` | The router's world: a stepped device with counters and commands (its routes change while it runs). |
| `wasmnet:control` | Commands into a live device: one export, `commands.invoke(now, command, argument)`, text in and text out. The host and the infra API carry commands without knowing any device. |
| `wasmnet:wan` | The carrier that moves frames between the sites of a network split over several processes. |
| `wasmnet:infra` | An operational API for a controller device that manages its siblings (apply, start, stop, remove, control, list, watch, logs). Granted per device, never ambient. |

## Vendored interfaces (`deps/`)

Pinned copies of the standards we build on. Do not edit them.

| Directory | Package | Source | License |
|---|---|---|---|
| `deps/{cli,clocks,filesystem,random,sockets}` | WASI 0.3.0 | exactly as `wasmtime-wasi` 50.0.1 ships it | Apache-2.0 WITH LLVM-exception |
| `deps/config` | `wasi:config@0.2.0-rc.1` | [WebAssembly/wasi-config](https://github.com/WebAssembly/wasi-config) | Apache-2.0 WITH LLVM-exception |

`deps/filesystem` is here only because `wasi:cli` names it. No component in this repository
imports `wasi:filesystem`, and the host does not serve it.
