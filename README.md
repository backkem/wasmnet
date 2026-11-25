<h1 align="center">wasmnet</h1>

<p align="center">
  <b>A whole IP network in one process.</b><br>
  Hosts, switches and routers as WebAssembly components, on virtual time.<br>
  <a href="https://backkem.github.io/wasmnet/">Try it in your browser</a>
</p>

---

Plug hosts into a switch, give the links a latency, and run. What comes out is what a real
network would give you: ARP, SYN, SYN-ACK, `GET / HTTP/1.1`, in a capture Wireshark opens.
Except that this network lives in one process, touches nothing on your machine, and does
exactly the same thing every time.

- 🔁 **Same seed, same bytes.** Time is virtual and entropy is seeded. A run repeats exactly,
  captures and logs included, on every machine.
- 📡 **Real protocols on real frames.** Ethernet, ARP and NDP, IPv4 and IPv6, TCP and UDP, DHCP,
  DNS, mDNS, HTTP. Every link writes a pcap.
- 🧩 **Ordinary programs.** Apps are plain WASI 0.3 code on `wasi:sockets`. They do not know
  they are simulated.
- 🧱 **Nothing leaks.** No TAP device, no host sockets, no wall clock. Components have no
  ambient authority, so the sandbox keeps the promise.
- 🌐 **In a tab too.** The same simulator and devices run in a browser, live.

```text
  http-get                                               http-server
     │ wasi:sockets@0.3                                       │ wasi:sockets@0.3
  netstack (smoltcp) ──100 µs──  switch  ──150 µs──  netstack (smoltcp)
```

## Quick start

```sh
cargo install --locked wasmtime-cli@50.0.1 wasm-tools@1.261.0 wac-cli@0.12.0

cargo xtask build                           # the components and the composed nodes
cargo run -p wasmnet-host --example http    # two hosts, a switch, one GET
```

It prints what every device reported, stamped in virtual nanoseconds, and writes one pcap-ng
per link to `target/http/`.

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

| Path | What it does |
|---|---|
| [`crates/wasmnet-host`](crates/wasmnet-host) | Runs a network on wasmtime: one store per device, deterministic WASI. Start here. |
| [`crates/wasmnet-core`](crates/wasmnet-core) | The simulator itself: virtual clock, event queue, patch panel, link model, pcap taps. No wasmtime. |
| [`crates/wasmnet-web`](crates/wasmnet-web) | The simulator for a browser, with [`web/`](web): a TypeScript binding and the page behind the link above. |
| [`components/`](components) | `netstack` (smoltcp behind `wasi:sockets@0.3`), `switch`, `router`, `wan-port`. [All of them by name](components/README.md). |
| [`components/apps/`](components/apps) | DHCP, DNS and mDNS servers, an HTTP server, client and load balancer, ping, traceroute, UDP echo. |
| [`compositions/`](compositions) | `wac` files that plug apps into a netstack to make a node. |
| [`wit/`](wit) | The contracts. `wasmnet:link` is the wire; everything else stands on it. |

## The rules it keeps

1. **Determinism.** Clocks, entropy and scheduling are host imports, served from virtual time
   and a seed.
2. **Packets are the truth.** Devices talk only in Ethernet frames over `wasmnet:link`.
3. **The host is a dumb backplane.** If it parses an IP header, it belongs in a component.
4. **Standards at the surface.** Apps import `wasi:sockets@0.3`; what WASI lacks lives in the
   small `wasmnet:sockets-ext`.

## Going deeper

- [docs/](docs/README.md): how it works, with a reading order, and how to write a device or
  an app.
- [docs/design/configuration.md](docs/design/configuration.md): every config key.
- [docs/known-issues.md](docs/known-issues.md): what we know is wrong today.
- [docs/stability.md](docs/stability.md): which parts of the API are the core, and which move.
- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing and the rules a change keeps.

```sh
cargo test --workspace     # wire, simulator, host, and end-to-end runs of real nodes
cargo xtask test-guest     # every component's own tests, executed inside wasmtime
cargo xtask web --test     # the browser page, in headless Chromium (needs Node 24 and a Chromium)
```

## Status

Experimental, version 0.0.0: the Rust API and the WIT still move. A browser run is live and
repeats itself, but is not byte-identical to a native one. Built on Rust 1.98.1 and wasmtime
50.0.1, both pinned ([tools.toml](tools.toml) has every tool version in one place).

## License

MIT or Apache-2.0, at your option ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).
Vendored code keeps its own license: see [third_party/README.md](third_party/README.md) and
[wit/README.md](wit/README.md).
