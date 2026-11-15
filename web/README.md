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
| `scripts/build.mjs` | Assembles `dist/`: tsc, the kit's browser modules, the simulator, the three components transpiled with the kit (their core modules stored once by content: both nodes embed the same netstack). |
| `scripts/notices.mjs`, `scripts/third-party.mjs`, `licenses/` | `NOTICES.html`: the licence files of what the page ships: this repository's, the Rust crates linked into the simulator and the devices (from `cargo metadata` and the crates' sources), and the npm packages whose code runs in the tab. |
| `test/run.mjs` | The page end to end in headless Chromium. |
| `vendor/` | The kit, as a tarball with its source and hash ([vendor/README.md](vendor/README.md)). |

```js
const net = await Network.create('wasmnet_web.wasm', { seed: 42n, components });
const sw = await net.device('sw', 'switch', { ports: '4' });
const web = await net.device('web', 'node-http-server', { ipv4: '10.0.0.1/24', /* ... */ });
net.link(web.port(0), sw.port(1), 150_000n); // nanoseconds
const outcome = await net.run({ onJournal: (entries) => console.log(entries) });
const pcap = net.pcap(net.links()[0]); // open it in Wireshark
```

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
same seed (same journal, same capture bytes) and with another seed, and checks the message a
browser without JSPI gets. With `NATIVE_JOURNAL` pointing at the native example's output
(`cargo run -p wasmnet-host --example http > target/http-native.txt`) it also checks that every
journal line of the native run appears in the browser run, at the same virtual time, and compares
the captures in `target/http/`. `.github/workflows/pages.yml` does all of this and deploys
`dist/`.
