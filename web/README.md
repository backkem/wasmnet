# wasmnet in the browser

The HTTP example ([`crates/wasmnet-host/examples/http.rs`](../crates/wasmnet-host/examples/http.rs))
as a web page: two hosts and a switch, one `GET /`, the journal line by line with virtual
timestamps, and a pcap-ng download per link. Live at <https://backkem.github.io/wasmnet/>.

**Chromium-based browsers only** (Chrome or Edge 137 or newer): the component runtime needs
WebAssembly JSPI. The page says so where it is missing.

## What is here

| Path | What |
|---|---|
| `src/network.ts` | The binding: a `Network` class over `wasmnet_web.wasm` (the simulator, [`crates/wasmnet-web`](../crates/wasmnet-web)), shaped like the Rust one. Devices are jco-transpiled components instantiated with the [codelib-web](https://github.com/backkem/codelib/tree/main/web) kit. |
| `src/codec.ts` | The boundary's byte encoding, the twin of `crates/wasmnet-web/src/codec.rs`. |
| `src/worker.ts`, `src/main.ts`, `page/` | The example: a Worker per run, and the page. |
| `scripts/build.mjs` | Assembles `dist/`: tsc, the kit's browser modules, the simulator, the components the example and its test scenarios use, transpiled with the kit (their core modules stored once by content: the nodes embed the same netstack), each with its import names and digest in `assets.json`, and the switch's raw bytes for the supplied-component test. |
| `scripts/notices.mjs`, `scripts/third-party.mjs`, `licenses/` | `NOTICES.html`: the licence files of what the page ships: this repository's, the Rust crates linked into the simulator and the devices (from `cargo metadata` and the crates' sources), and the npm packages whose code runs in the tab. |
| `test/run.mjs` | The page end to end in headless Chromium. |
| `vendor/` | The kit, as a tarball with its source and hash ([vendor/README.md](vendor/README.md)). |

```js
const net = await Network.create('wasmnet_web.wasm', { seed: 42n, components });
const sw = await net.device('sw', 'switch', { ports: '4' });
const web = await net.device('web', 'node-http-server', { ipv4: '10.0.0.1/24', /* ... */ },
  { args: ['-v'], env: [['GREETING', 'hello']] }); // what wasi:cli/environment serves it
net.link(web.port(0), sw.port(1), 150_000n); // nanoseconds
await net.command(sw, 'block', '0 3');        // { ok: 'blocked' }: wasmnet:control/commands
net.scheduleCommand(sw, 5_000_000n, 'unblock', '0 3'); // the same, as an operator event at 5 ms
const outcome = await net.run({ onJournal: (entries) => console.log(entries) });
const pcap = net.pcap(net.links()[0]); // open it in Wireshark
```

A device's options also grant `wasmnet:infra` (`infra: true`, with `infraPrefix`,
`infraCascade`, `infraMaxDevices`, `infraSupply`): its calls are served by the simulator, as
natively. `setCatalog([...])` names the components controllers may create (keys of
`components`); the page instantiates them when the network asks, also while it runs (JSPI).
`setSupplyAdmission([...])` admits components controllers supply, which run from a component
with the same `digest`, or from `NetworkOptions.supply`. A `ComponentSource`'s `imports` let the
simulator refuse an ungranted `wasmnet:infra` importer before it is instantiated. The binding
decides nothing itself; what the browser backend does not do yet is in
[docs/known-issues.md](../docs/known-issues.md).

How it works: [docs/design/browser.md](../docs/design/browser.md).

## Build and test

Needs Node 24, npm and a Chromium, besides the Rust toolchain, `wasm-tools` and `wac` the
workspace needs anyway. From the workspace root:

```sh
cargo xtask web            # components, simulator, `npm ci`, `npm run build` -> web/dist
cargo xtask web --test     # also `npm test` (headless Chromium)
```

Or step by step, in `web/`, once the Rust parts are built:

```sh
npm ci
npm run build              # dist/
npm test                   # CHROMIUM=/path/to/chrome to pick the browser
npm run serve              # http://127.0.0.1:8080/wasmnet/
```

`npm test` serves `dist/` under `/wasmnet/` (as GitHub Pages does), runs the example, checks the
client's `http-get-done` (`status=200`, `body-bytes=19`), its `app-exit`, a quiescent outcome
with the server still serving and both captures (pcap-ng with packets), runs it again with the
same seed (same journal, same capture bytes) and with another seed, runs the Worker's `controls`
scenario (the switch programmed by command between runs and by an operator event, the server
answering with its arguments and an environment variable; `window.wasmnetScenario`) and checks
the answers, the switch's events and the page the client fetched, runs the `runtime` scenario
(devices created while the network runs: an `infra-script` controller creating, commanding and
restarting a router and reading its events, a `replicas` controller woken by `changes.wait-any`,
one that supplies a
component fetched from a store node, and an ungranted `wasmnet:infra` importer refused), and
checks the message a browser without JSPI gets. With `NATIVE_JOURNAL` pointing at the native example's output
(`cargo run -p wasmnet-host --example http > target/http-native.txt`) it also checks that every
journal line of the native run appears in the browser run, at the same virtual time, and compares
the captures in `target/http/`. `.github/workflows/pages.yml` does all of this and deploys
`dist/`.
