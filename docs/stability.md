# Stability

Everything is at version 0.0.0, but not everything moves at the same speed. There are two
tiers.

## The core

What the examples and tests here exercise: building and running a network, its records and
captures, the components and the apps.

## Embedder surface, unstable

The rest is public for embedders that build tooling on the core. It works and is exercised by
such an embedder's own tests, not by tests in this repository, and it may change between
versions without notice. Rustdoc and the design notes mark it **embedder surface, unstable**:

- operator events (`Op`, `Network::add_op`, `run_stoppable`, frame rules, the transmit hook,
  the component resolver for dynamic topology);
- multi-site runs (`wasmnet_core::sites` and the `Network` methods for them) and the
  `wasmnet:wan` carrier contract;
- the extension points (`wasmnet_core::ext`, `HostExtension`, `ControlHandler`,
  `HostBuilder::unmetered_engine` and `Host::load_unmetered`);
- the netstack's snapshot interface (`wasmnet:netstack/state`, `snapshot.paused`);
- the HTTP apps' event-stream routes and `POST /echo` (`http-server`) and forward proxy
  (`http-get`).

Other parts of the tree, for reference: `crates/wasmnet-wire` (`no_std` wire helpers: MAC
addresses, Ethernet, pcap-ng, DHCP and DNS codecs), `crates/wasmnet-app-kit` (what the apps
share), and three test fixtures among the components (`blaster`, `reflector`, `clock-probe`).
