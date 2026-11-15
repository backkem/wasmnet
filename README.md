# wasmnet

**A whole IP network in one process, made of WebAssembly components.**

**Try it in your browser:** <https://backkem.github.io/wasmnet/> (two hosts, a switch and one
HTTP GET, in the tab; Chromium-based browsers; [`web/`](web)).

Hosts, switches and routers are components. Links carry real Ethernet frames. Time is
virtual, entropy is seeded, and nothing touches the machine's own network stack.
Same seed, same bytes: every run, every machine.

```text
  http-get                                               http-server
     │ wasi:sockets@0.3                                       │ wasi:sockets@0.3
  netstack (smoltcp) ──100 µs──  switch  ──150 µs──  netstack (smoltcp)
```

Capture any link and Wireshark shows the real thing: ARP, SYN, SYN-ACK, `GET / HTTP/1.1`.

## Quick start

```sh
cargo install --locked wasmtime-cli@50.0.1 wasm-tools@1.261.0 wac-cli@0.12.0

cargo xtask build                           # the components and the composed nodes
cargo run -p wasmnet-host --example http    # two hosts, a switch, one GET
```

The example prints what every device reported, stamped in virtual nanoseconds, and writes
one pcap-ng per link to `target/http/`.

## In ten lines

```rust
let host = Host::new()?;
let mut net = Network::new(&host, 42); // 42 is the seed
let sw = net.device("sw", &host.load("switch.wasm")?)?;
let web = net.device_with_config("web", &host.load("node-http-server.wasm")?, web_config)?;
let cli = net.device_with_config("cli", &host.load("node-http-get.wasm")?, cli_config)?;
net.link(web.port(0), sw.port(1))?.latency(150_000); // nanoseconds
net.link(cli.port(0), sw.port(2))?.latency(100_000);
net.run_until_quiescent()?;
let pcap = net.pcap(net.links()[0]); // open it in Wireshark
```

The full version is [`crates/wasmnet-host/examples/http.rs`](crates/wasmnet-host/examples/http.rs).

## What's in the box

| Path | What |
|---|---|
| `crates/wasmnet-core` | The simulator: virtual clock, event queue, patch panel, link model, pcap taps, journal. No wasmtime; builds for `wasm32`. |
| `crates/wasmnet-host` | The wasmtime backend: one store per device, deterministic WASI, a compile cache. |
| `crates/wasmnet-web` | The browser backend: the simulator on `wasm32-unknown-unknown`, devices supplied by JavaScript, a small network API over bytes. Live and best-effort, not byte-identical to native runs. |
| `crates/wasmnet-wire` | `no_std` wire helpers: MAC addresses, Ethernet, pcap-ng, DHCP and DNS codecs. |
| `crates/wasmnet-app-kit` | What the apps share: their bindings, config keys, socket address conversions. |
| `components/` | `netstack` (smoltcp behind `wasi:sockets@0.3`), `switch`, `router`, `wan-port`, and three test fixtures (`blaster`, `reflector`, `clock-probe`). |
| `components/apps/` | Ordinary WASI 0.3 programs: DHCP, DNS and mDNS servers, an HTTP server, client and load balancer, ping, traceroute, UDP echo. |
| `compositions/` | `wac` files that plug apps into a netstack to make a node. |
| `wit/` | The contracts. `wasmnet:link` is the wire; everything else stands on it. |
| `web/` | The browser example: a TypeScript binding for `wasmnet-web` on the codelib-web host kit, and the HTTP example as a page. `cargo xtask web` builds it (needs Node 24 and a Chromium to test). |
| `docs/design/` | How it works: virtual time, event order, multi-site runs, socket extensions, the browser. |

## House rules

1. **Determinism.** Clocks, entropy and scheduling are host imports, served from virtual time
   and a seed. No wall clock, no threads in the simulation, no `HashMap` order in the output.
2. **Packets are the truth.** Devices talk only in Ethernet frames over `wasmnet:link`.
3. **The host is a dumb backplane.** If it parses an IP header, it belongs in a component.
4. **Standards at the surface.** Apps import `wasi:sockets@0.3` and do not know they are
   simulated. What WASI lacks lives in the small `wasmnet:sockets-ext`.

## Testing

```sh
cargo test --workspace     # wire, simulator, host, and end-to-end runs of real nodes
cargo xtask test-guest     # every component's own tests, executed inside wasmtime
```

## Status

Experimental. Version 0.0.0: the Rust API and the WIT still move. Built on Rust 1.98.1 and
wasmtime 50.0.1, both pinned.

### Embedder surface, unstable

Two tiers. What the examples and tests here exercise is the core: building and running a
network, its records and captures, the components and apps. The rest is public for embedders
that build tooling on the core. It works and is exercised by such an embedder's own tests, not
by tests in this repository, and it may change between versions without notice; rustdoc and
the design notes mark it **embedder surface, unstable**:

- operator events (`Op`, `Network::add_op`, `run_stoppable`, frame rules, the transmit hook,
  the component resolver for dynamic topology);
- multi-site runs (`wasmnet_core::sites` and the `Network` methods for them) and the
  `wasmnet:wan` carrier contract;
- the extension points (`wasmnet_core::ext`, `HostExtension`, `ControlHandler`,
  `HostBuilder::unmetered_engine` and `Host::load_unmetered`);
- the netstack's snapshot interface (`wasmnet:netstack/state`, `snapshot.paused`);
- the HTTP apps' event-stream routes and `POST /echo` (`http-server`) and forward proxy
  (`http-get`).

## License

MIT or Apache-2.0, at your option ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).
Vendored code keeps its own license: see [third_party/README.md](third_party/README.md) and
[wit/README.md](wit/README.md).
