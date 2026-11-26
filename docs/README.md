# Documentation

How wasmnet works and how to extend it. The code is the reference; these notes explain it and
point into it. The contracts themselves are in [wit/](../wit) ([wit/README.md](../wit/README.md)),
and [the main README](../README.md) shows a network in ten lines.

## Reading order

1. [design/async-under-virtual-time.md](design/async-under-virtual-time.md): the executor, the
   `wasmnet:link` contract, and why runs are deterministic.
2. [design/event-order.md](design/event-order.md): the causal key that orders every event, event
   boundaries, operator events and frame rules.
3. [design/writing-a-device.md](design/writing-a-device.md): a stepped or async device, from the
   call order to tests inside wasmtime.
4. [design/writing-an-app.md](design/writing-an-app.md): a WASI 0.3 app, its config, and the `wac`
   composition that makes it a node.
5. [design/netstack.md](design/netstack.md): the smoltcp stack behind `wasi:sockets`, its driver
   task, ICMP errors, DHCP and the resolver.
6. [design/socket-extensions.md](design/socket-extensions.md): `wasmnet:sockets-ext`, what WASI
   0.3 lacks.
7. [design/configuration.md](design/configuration.md): every config key of every device and app.
8. [design/nat.md](design/nat.md): address translation and the packet filter in the router: why
   they are a mode of the router, RFC 4787 behaviours, connection tracking, ICMP errors.

For embedders:

- [../components/README.md](../components/README.md): every component and node by name, its
  package and artifact, and how to build a few of them into a directory.
- [design/artifacts.md](design/artifacts.md): a revision's components as a set of files with
  hashes and a manifest, what makes a rebuild give the same bytes, where a set is meant to be
  published, and how another repository's build fetches and checks one.
- [design/runtime-and-extensions.md](design/runtime-and-extensions.md): the `Runtime` backend
  contract, what `wasmnet-host` adds, and the extension points.
- [design/links.md](design/links.md): the link model: latency, MTU, carrier, and per-direction
  impairments (a rate with a bounded transmit queue, seeded loss and jitter).
- [design/topology-and-infra.md](design/topology-and-infra.md): changing a network while it runs,
  and `wasmnet:infra` for in-world controllers.
- [design/sites.md](design/sites.md): one network split over two simulators, and the site-sync
  wire format.
- [design/browser.md](design/browser.md): the same networks in a browser tab: the simulator on
  `wasm32`, devices transpiled with jco, the stepping protocol, and why a browser run repeats
  itself without matching the native run byte for byte.
- [design/disk.md](design/disk.md): disks for devices (`crates/wasmnet-disk`): the model, the
  `wasi:keyvalue` contract, durability and faults, lifetime, images and quotas, the adapter
  pattern for a device with a storage contract of its own, and what it all costs.

What is known to be wrong or unbounded today: [known-issues.md](known-issues.md). Which parts
of the API are the core and which still move: [stability.md](stability.md).

Elsewhere: [upstream/smoltcp.md](upstream/smoltcp.md) lists what we found in smoltcp and the
patches we carry; the runnable example is
[crates/wasmnet-host/examples/http.rs](../crates/wasmnet-host/examples/http.rs).
