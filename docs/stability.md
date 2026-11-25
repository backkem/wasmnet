# Stability

Everything is at version 0.0.0, but not everything moves at the same speed. There are two
tiers.

## The core

What the examples and tests here exercise: building and running a network, its records and
captures, the components and the apps. Link impairments set when a link is built
(`Impairments`, `LinkMut::impair`, `LinkMut::impair_from`) and their counters in `LinkStats`
are part of it ([design/links.md](design/links.md)). So are device commands: the
`wasmnet:control/commands` export, the router's commands, `Network::command` and
`wasmnet:infra/devices.control` (`crates/wasmnet-host/tests/routes.rs`), and the router's
address translation and packet filter with their keys and commands (`tests/nat.rs`,
`tests/filter.rs`). Sending them as
operator events (`Op::Control` with a `DeviceCommand`) is embedder surface like every
operator event, though that test exercises it too. So are a device's arguments and
environment (`DeviceOptions::args` and `env`, the spec keys `args` and `env`), a controller's
`logs` of its own devices, `devices.control-answer`, `DeviceOptions::infra_cascade` and
`wasmnet:infra/changes.wait`
(`crates/wasmnet-host/tests/infra_verbs.rs`). `Runtime::Component` must be `ToOwned`, so a
network keeps each device's component to start it again.

## Embedder surface, unstable

The rest is public for embedders that build tooling on the core. It works and is exercised by
such an embedder's own tests, not by tests in this repository, and it may change between
versions without notice. Rustdoc and the design notes mark it **embedder surface, unstable**:

- operator events (`Op`, `Network::add_op`, `run_stoppable`, frame rules, the transmit hook,
  the component resolver for dynamic topology), including `Op::Impair` and `Op::ImpairNamed`,
  which change a link's impairments while the network runs;
- multi-site runs (`wasmnet_core::sites` and the `Network` methods for them) and the
  `wasmnet:wan` carrier contract (the site-sync wire format is at version 2 since impairments
  and the devices and links created while a network runs were added to its records);
- the extension points (`wasmnet_core::ext`, `HostExtension`, `ControlHandler`,
  `HostBuilder::unmetered_engine` and `Host::load_unmetered`);
- the netstack's snapshot interface (`wasmnet:netstack/state`, `snapshot.paused`);
- the HTTP apps' event-stream routes and `POST /echo` (`http-server`) and forward proxy
  (`http-get`).

Other parts of the tree, for reference: `crates/wasmnet-wire` (`no_std` wire helpers: MAC
addresses, Ethernet, pcap-ng, DHCP and DNS codecs), `crates/wasmnet-app-kit` (what an app needs: its
bindings, and what the apps here share), and four test fixtures among the components
(`blaster`, `reflector`, `clock-probe`, `infra-script`).
