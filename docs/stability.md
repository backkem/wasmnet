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
(`crates/wasmnet-host/tests/infra_verbs.rs`), the events of the devices a controller created:
`wasmnet:infra/events`, `changes.wait-any` and the core's `infra::{DeviceEvent, EventPage,
Follow, TableSince, Ready}` (`crates/wasmnet-host/tests/tunnel.rs`), and `devices.wire` and `devices.unwire`, cable
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
the `wasmnet-link-end/1` end descriptions (`pcap::LinkEnd`) and the notes a capture carries
(`LinkMut::capture_notes`, `Network::set_capture_notes`, `LinkInfo::capture_notes`,
`pcap::Capture::comments`, `pcap::check_notes`) ([design/links.md](design/links.md)). So are
`tcp.rto-min` (`crates/wasmnet-host/tests/congestion.rs`) and the netstack's drop of a SYN that
finds a listen backlog full, with its counter `tcp-listen-overflows` ([design/netstack.md](design/netstack.md)).
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
- multi-site runs (the crate `wasmnet-sites`, and the `Network` methods it builds on:
  `remote_device`, `run_before`, `take_outbox`, `check_remote`, `receive_remote`, `taps`, the
  record tags, with `SyncError`) and the
  `wasmnet:wan` carrier contract (the site-sync wire format is at version 3 since the records
  carry frame lengths and capture options; version 2 added impairments
  and the devices and links created while a network runs were added to its records);
- the extension points (`wasmnet_core::ext`, `HostExtension`, `ControlHandler`,
  `HostBuilder::unmetered_engine` and `Host::load_unmetered`);
- portable extensions ([design/runtime-and-extensions.md](design/runtime-and-extensions.md#portable-extensions)):
  `Interface`, `ImportServer`, `Served`, `DeviceExt::serve`, `NetworkExtension::interfaces`,
  `Status::set_fault`, `DeviceLife::replaced`, `DeviceSetup::seed`, `Network::add_boxed_extension`,
  a device's fuel span (`FuelSpan`, `DeviceExt::fuel_span`; the wasmtime adapter's calls take the
  store, `wasmnet_host::portable::call(store, ..)`),
  the value model `wasmnet_core::value`, `wasmnet_host::portable` with `portable_adapter!`, and in
  a page `wn_import`, `wn_import_drop`, `wn_interfaces` and an embedder's own page module
  (`wasmnet_web::install`, `install!`, `export!`, `install::with_network`, and in the binding
  `NetworkOptions.imports` and `Network.callExport`), and networks in sequence on one module
  instance (`install::new_network`, `wasmnet_web::Network::replace`, `JsHost::network_replaced`,
  the import `js_network_replaced`, and in the binding `Network.reset`,
  [design/browser.md](design/browser.md#networks-in-sequence)), a device's descriptor in the
  binding's per-device hooks (`DeviceDescriptor` with its clock, `deviceImports(device)`,
  `instantiateCore(module, imports, device)`), and devices whose exports answer with a promise
  (`ComponentSource.suspends`, `Instance::suspends`, the `_suspending` imports,
  [design/browser.md](design/browser.md#exports-that-answer-with-a-promise)); extension options and operator events from
  generic values (`ExtOption`, `ExtOpParser`, `NetworkExtension::{options, check_options, ops}`,
  `Network::{parse_option, set_option, option_keys, parse_op}`, `ExtOptions::set_value`,
  `Op::ExtensionAt` and `Op::ExtensionAtNamed`, `OpContext::device`, a spec's extension keys, the
  page's `extension` ops and `wasmnet_web::ops::op_in`),
  and `Network::register_cable` refusing a kind twice, `Network::try_add_extension` (and
  `try_add_boxed_extension`) refusing a second declaration of an option key or op kind; portable
  exports (`ControlCall::{target, invocation, invoked}`, `Invocation`, `wasmnet_core::export`:
  `ExportCall`, `ExportRequest`, `ExportAnswer`, `Answered`, `plain`, `unversioned`;
  `Network::invoke`, `device_exports` listing every exported interface, `portable_adapter!` on a
  world that exports interfaces, `wasmnet_host::portable::{now, invoked}`, in a page
  `js_export`, `wn_invoke`, `wn_schedule_invoke`, `wn_exports` and `JsHost::export`, and in the
  binding `Network.{invoke, scheduleInvoke, exports}`, `NetworkOptions.{deviceImports, compile,
  instantiateCore}`); the test fixture `wasmnet-pad` is their worked example.
- the disks (`crates/wasmnet-disk`, [design/disk.md](design/disk.md)): `Disks`, `DiskOptions`,
  `DiskSpec`, `Durability`, `DiskFault`, `Keep`, `Corruption`, `DiskOp`, `AnyDiskOp`, `DiskRead`,
  `DiskStats`, `DiskError`, `Entry`, `Change`, the limits and `IMPORTS`, the option key
  `disk.specs` and the op
  kinds `disk.*`, the image format `wasmnet-disk/1` (`image`), the typed adapter `DiskAdapter`
  (feature `wasmtime`), the page module `wasmnet-disk-page`, and the WIT package
  `wasmnet:keyvalue-ext@0.1.0` (served beside the vendored `wasi:keyvalue@0.2.0-draft2`);
- the netstack's snapshot interface (`wasmnet:netstack/state`, `snapshot.paused`);
- the HTTP apps' event-stream routes and `POST /echo` (`http-server`) and forward proxy
  (`http-get`).

**What "unstable" means for a crate in another repository.** An extension built on this surface
(a capability crate living elsewhere) pins the library's revision, as an embedder does, and
follows it deliberately: a change to these points may need code changes in the extension, and
the change's commit says what to do. Nothing here changes silently: a change that alters what a
device observes changes a test that compares bytes in this repository first.

Other parts of the tree, for reference: `crates/wasmnet-wire` (`no_std` wire helpers: MAC
addresses, Ethernet, pcap-ng encoding and the strict reader `wasmnet_wire::pcap` that
`wasmnet_core::pcap` re-exports, DHCP and DNS codecs, DNS-SD's helpers), `crates/wasmnet-app-kit` (what an app needs: its
bindings, and what the apps here share), and four test fixtures among the components
(`blaster`, `reflector`, `clock-probe`, `infra-script`). `crates/wasmnet-artifacts` reads and
writes the artifact manifest (its format is versioned by its `format` key, `wasmnet-artifacts/1`)
and fetches a pinned set; its Rust API is new and may still change
([design/artifacts.md](design/artifacts.md)).

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
    `DeviceCommand::new(command, argument)`, `Interface::new(name).function(f).resource(r)`,
    `ExtOption::new(key, parse)`, `ExtOpParser::new(kind, parse)`,
    `infra::Follow::new(name, kinds, since)`,
    `infra::TableSince::new(selector, since)` and, in `wasmnet-app-kit`,
    `mdns::Resolved::new(name, instance, host, port)`.
- **Structs an embedder reads** (results, records, statistics and costs: `LinkStats`,
  `LinkInfo`, `DeviceCost`, `FrameRecord`, `Transmit`, `DeviceView`, `pcap::Capture`,
  `CommandOutput`, `DeviceEntropy`, ...) are `#[non_exhaustive]` too: read their fields, and destructure them
  with `..`. Code that rebuilds records it carried elsewhere (a decoder, such as the site-sync
  format in `wasmnet-sites`) builds them with a constructor and assigns the rest:
  `LinkInfo::new(name, ends, latency, mtu)` (up, Ethernet, no impairments, the default
  `CaptureOptions`, no notes), `FrameRecord::new(link, from, to, sent_at, fate, len, bytes)`,
  `Tap::new(tag, link, end, at, inbound, len, bytes)`, `RemoteArrival::new(frame_id, fate)`,
  `LinkTransition::new(at, link, up)`, `pcap::LinkEnd::new(link, end, device, port,
  peer_device, peer_port, created_at)`, `JournalEntry::new` and `Outcome::quiescent` and
  `deadline`; `LinkStats` from `Default`.
- **Enums that may grow** (outcomes, events, phases, reasons, errors: `Outcome`,
  `DevicePhase`, `Cascade`, `FrameFate`, `FrameAction`, `OpState`, `Refusal`, `dns::RData`,
  `dhcp::MessageType`, the wire codecs' errors, `mdns::Event`, ...) are `#[non_exhaustive]`: a
  `match` on one needs a `_` arm. Building a variant still works.
- **Operator events** (`Op`): every variant with fields is `#[non_exhaustive]`. Build one with
  its constructor, which takes what the op needs, and set the rest with `with_*` methods:
  `Op::wire(("a", 0), ("b", 1)).with_latency(100_000)`, `Op::stop_device("web")`,
  `Op::add_device("web", "node:http-server").with_config(config).with_cable(cable)`. A `with_*`
  method on an op it does not apply to panics. An op on something that exists takes its id
  (`Op::stdin(device, bytes)`, `Op::control`, `Op::extension_at`, `Op::impair`, `Op::latency`,
  `Op::link_state` take a `DeviceId` or a `LinkId`); an op on something an earlier op or a
  controller creates takes its name, resolved when the op applies (`Op::stdin_named("web",
  bytes)`, `Op::control_named`, `Op::extension_at_named`, `Op::impair_named`, `Op::set_link`,
  and the device ops such as `Op::stop_device("web")`). Match a variant with `..`:
  `Op::Wire { a, b, .. }`. `Outcome`'s two variants are `#[non_exhaustive]` as well
  (`Outcome::Quiescent { at, .. }`); `Outcome::quiescent` and `Outcome::deadline` build them
  for code that decodes one.
- **Variants of other enums keep their fields**: new information comes as a new variant.
- **Closed on purpose.** Some types change only with a version, and then break on purpose:
  - what mirrors a versioned format or WIT record: `PortInfo` and `DeclaredPort` (the WIT
    `port-info`), the causal key (`EventKey`, `KeyLevel`, `Ctx`, `Tag`, `Origin`), the site-sync
    messages (`wasmnet_sites::{Msg, Sync}`, `RemoteFrame`), `infra::{Phase, ChangeKind,
    InfraError}` (the `wasmnet:infra` enums), `journal::{Level, Stream}`, the DHCP and DNS
    messages (`dhcp::Message`, `dns::{Message, Question, Record}`), and the browser boundary's
    value model `wasmnet_core::value::Value` (re-exported as `wasmnet_web::codec::Value`),
    `wasmnet_core::Served` and `wasmnet_web::infra::Reply`;
  - what a caller must handle in full, so that a new case is a compile error where it must be
    handled: a backend's `Command`, the stepping results `Step` and `wasmnet_sites::Step`, and
    `LinkKind` (Ethernet or a registered cable kind);
  - newtypes and plain pairs: `MacAddr`, `EtherType`, `Digest`, `DeviceId`, `LinkId`,
    `PortRef`, `CableKind`.

## Moved paths

Capabilities leave the core for crates of their own when they can be built on its public API
(`CONTRIBUTING.md`). A moved item keeps its old path where the dependency direction allows a
re-export, for one revision at least; a path that cannot be kept breaks once, and is listed
here.

| Old path | New path | Old path still works |
|---|---|---|
| `wasmnet_core::pcap::{parse, parse_header, Capture, Interface, Packet, PcapError, LinkEnd, LINK_END_FORMAT, Direction}` | `wasmnet_wire::pcap::*` | yes: `wasmnet_core::pcap` (and `wasmnet_host::pcap`) re-export it |
| `wasmnet_core::pcap::{MAX_NOTES, MAX_NOTE_BYTES, check_notes}` | unchanged: the core's rule for a link's notes | yes |
| `wasmnet_core::sites::*` | `wasmnet_sites::*` (crate `wasmnet-sites`) | no: the core cannot re-export a crate that depends on it |
| `wasmnet_host::sim::sites::*` | `wasmnet_sites::*` | for one revision: `wasmnet_host::sim` re-exports the crate as `sites` |
| `wasmnet_core::sites::SyncError` | `wasmnet_core::SyncError` (also `wasmnet_sites::SyncError`) | through `wasmnet_host::sim::sites::SyncError` for one revision |

`Network::check_remote` was crate-private and is public (embedder surface) so that the driver
can check a peer's frames. The wire format is unchanged at version 3.
