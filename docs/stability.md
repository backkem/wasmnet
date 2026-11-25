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
`tests/filter.rs`), and its tunnel ports with their keys and commands
(`tests/tunnel.rs`), and the switch's blocks and delays between ports
(`tests/partition.rs`). So is DNS-SD: `mdns-responder`'s services, the app kit's browser
(`wasmnet_app_kit::mdns`) and the `service-browse` app (`tests/service_discovery.rs`).
Sending device commands as
operator events (`Op::Control` with a `DeviceCommand`) is embedder surface like every
operator event, though that test exercises it too. So are a device's arguments and
environment (`DeviceOptions::args` and `env`, the spec keys `args` and `env`), a controller's
`logs` of its own devices, `devices.control-answer`, `DeviceOptions::infra_cascade` and
`wasmnet:infra/changes.wait`
(`crates/wasmnet-host/tests/infra_verbs.rs`), and `devices.wire` and `devices.unwire`, cable
impairments (also on `Op::Wire` and `Cable`), the `wasmnet:reconfigure` export and the switch's
answer to it, `DeviceOptions::infra_max_devices` and `memory`, and `DeviceCost::memory` and
`peak_memory` (`crates/wasmnet-host/tests/infra_limits.rs`). So are components a controller
supplies: `wasmnet:infra/components`, `DeviceOptions::infra_supply` with `SupplyLimits`,
`Network::set_supply_admission`, digest references in specs, `Network::supplied_compiles`
and `ImportPolicy` (`crates/wasmnet-host/tests/supply.rs`); `Runtime::compile_supplied` is
embedder surface with the rest of the `Runtime` contract. `Runtime::Component` must be
`ToOwned`, so a network keeps each device's component to start it again. So is what a run
reports for measuring it (`crates/wasmnet-host/tests/measure.rs`): `DeviceCost` with its peak
fuel per instant, `Network::link_stats` read between runs with `LinkStats::since` and `add`, a
link's series (`SeriesOptions`, `Network::link_series`), and what links record
(`CaptureOptions`, `Network::set_capture_defaults`, `LinkMut::capture`, `FrameRecord::len`) with
the `wasmnet-link-end/1` end descriptions (`pcap::LinkEnd`) ([design/links.md](design/links.md)).
So is a netstack with several ports and static routes, its `port<N>.*`, `ports` and `routes`
keys (`crates/wasmnet-host/tests/multihomed.rs`, [design/netstack.md](design/netstack.md)).

## Embedder surface, unstable

The rest is public for embedders that build tooling on the core. It works and is exercised by
such an embedder's own tests, not by tests in this repository, and it may change between
versions without notice. Rustdoc and the design notes mark it **embedder surface, unstable**:

- operator events (`Op`, `Network::add_op`, `run_stoppable`, frame rules, the transmit hook,
  the component resolver for dynamic topology), including `Op::Impair` and `Op::ImpairNamed`,
  which change a link's impairments while the network runs, and the faults: `Op::PauseDevice`,
  `Op::ResumeDevice`, `Op::CrashDevice`, `DeviceOptions::crash_alone`, `Op::Action` with
  `Network::register_action`, and `NetworkExtension::device_life`
  (`crates/wasmnet-host/tests/faults.rs`);
- multi-site runs (`wasmnet_core::sites` and the `Network` methods for them) and the
  `wasmnet:wan` carrier contract (the site-sync wire format is at version 3 since the records
  carry frame lengths and capture options; version 2 added impairments
  and the devices and links created while a network runs were added to its records);
- the extension points (`wasmnet_core::ext`, `HostExtension`, `ControlHandler`,
  `HostBuilder::unmetered_engine` and `Host::load_unmetered`);
- the netstack's snapshot interface (`wasmnet:netstack/state`, `snapshot.paused`);
- the HTTP apps' event-stream routes and `POST /echo` (`http-server`) and forward proxy
  (`http-get`).

Other parts of the tree, for reference: `crates/wasmnet-wire` (`no_std` wire helpers: MAC
addresses, Ethernet, pcap-ng, DHCP and DNS codecs, DNS-SD's helpers), `crates/wasmnet-app-kit` (what an app needs: its
bindings, and what the apps here share), and four test fixtures among the components
(`blaster`, `reflector`, `clock-probe`, `infra-script`).

## Building public types

A field added to a public type never breaks a build that constructs and matches types the way
this section says. `crates/wasmnet-host/tests/construction.rs` builds each type listed here
from outside the core, so a lost constructor fails the tests.

- **Structs an embedder builds** are `#[non_exhaustive]`. Their fields stay public (read them,
  assign them: `options.infra_prefix = prefix`), but a struct literal, or `..Default::default()`
  after some fields, does not compile outside their crate. Build them from `Default` with
  chainable setters named after their fields, or from a constructor that takes what they cannot
  do without:
  - `Impairments::default().rate(10_000_000).loss_ppm(100)`, and so `CaptureOptions`, `Guard`,
    `SupplyLimits` and `DeviceOptions` (`DeviceOptions::default().infra(true).memory(64 << 20)`;
    its `Option` fields' setters take the value) and, in `wasmnet-web`, `Instance`;
  - `Cable::new(port, to_device, to_port).latency(ns)`, `SeriesOptions::new(width, keep)`,
    `SimConfig::seeded(seed).wall_epoch(epoch)`, `Fault::new(message)`,
    `DeviceInstance::new(ports, actor).apps(apps)`, `JournalEntry::new(at, device, record)`,
    `DeviceCommand::new(command, argument)` and, in `wasmnet-app-kit`,
    `mdns::Resolved::new(name, instance, host, port)`.
- **Structs an embedder reads** (results, records, statistics and costs: `LinkStats`,
  `LinkInfo`, `DeviceCost`, `FrameRecord`, `Transmit`, `DeviceView`, `pcap::Capture`,
  `CommandOutput`, `DeviceEntropy`, ...) are `#[non_exhaustive]` too: read their fields, and destructure them
  with `..`.
- **Enums that may grow** (outcomes, events, phases, reasons, errors: `Outcome`,
  `DevicePhase`, `Cascade`, `FrameFate`, `FrameAction`, `OpState`, `Refusal`, `dns::RData`,
  `dhcp::MessageType`, the wire codecs' errors, `mdns::Event`, ...) are `#[non_exhaustive]`: a
  `match` on one needs a `_` arm. Building a variant still works.
- **Operator events** (`Op`): every variant with fields is `#[non_exhaustive]`. Build one with
  its constructor, which takes what the op needs, and set the rest with `with_*` methods:
  `Op::wire(("a", 0), ("b", 1)).with_latency(100_000)`, `Op::stop_device("web")`,
  `Op::add_device("web", "node:http-server").with_config(config).with_cable(cable)`. A `with_*`
  method on an op it does not apply to panics. Match a variant with `..`:
  `Op::Wire { a, b, .. }`. `Outcome`'s two variants are `#[non_exhaustive]` as well
  (`Outcome::Quiescent { at, .. }`); `Outcome::quiescent` and `Outcome::deadline` build them
  for code that decodes one.
- **Variants of other enums keep their fields**: new information comes as a new variant.
- **Closed on purpose.** Some types change only with a version, and then break on purpose:
  - what mirrors a versioned format or WIT record: `PortInfo` and `DeclaredPort` (the WIT
    `port-info`), the causal key (`EventKey`, `KeyLevel`, `Ctx`, `Tag`, `Origin`), the site-sync
    messages (`sites::Msg`, `sites::Sync`, `RemoteFrame`), `infra::{Phase, ChangeKind,
    InfraError}` (the `wasmnet:infra` enums), `journal::{Level, Stream}`, the DHCP and DNS
    messages (`dhcp::Message`, `dns::{Message, Question, Record}`), and the browser boundary's
    `wasmnet_web::codec::Value` and `wasmnet_web::infra::Reply`;
  - what a caller must handle in full, so that a new case is a compile error where it must be
    handled: a backend's `Command`, the stepping results `Step` and `sites::Step`, and
    `LinkKind` (Ethernet or a registered cable kind);
  - newtypes and plain pairs: `MacAddr`, `EtherType`, `Digest`, `DeviceId`, `LinkId`,
    `PortRef`, `CableKind`.
