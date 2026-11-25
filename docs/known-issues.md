# Known issues

What we know is wrong, missing or unbounded today. Version 0.0.0 is experimental; this list is
here so that nobody has to find these the hard way. Each entry names where the code is.

## The simulator

- **Recording is unbounded in memory.** Every frame that crosses a link is kept in the frame
  log and in the link's pcap encoder (`crates/wasmnet-core/src/link.rs`), with no cap and no
  switch to turn it off. The journal and captured stdio have caps; frames do not. A long run
  with heavy traffic grows until the process runs out of memory.
- **A device has no memory limit.** Fuel bounds what a device computes per virtual instant;
  nothing bounds what it allocates.
- **An event can be lost while a device is created.** `block_on`
  (`crates/wasmnet-core/src/exec.rs`) advances time while a device is instantiated or answers
  `ports()`. An event that is not a timer and comes due in that window is dropped without an
  error. Adding every device before the first `run` avoids it.
- **A link wired by an operator event starts unimpaired.** `Op::Wire` and the cables of
  `Op::AddDevice` take a latency and an MTU but no impairments; an `Op::ImpairNamed` applies
  them one event later, so frames sent in between cross the plain link
  (`crates/wasmnet-core/src/network.rs`).
- **The transmit queue is bounded in frames only**, not in bytes, and serialisation counts the
  frame as transmitted, without Ethernet's preamble, FCS and inter-frame gap
  ([design/links.md](design/links.md)).
- **A compile cache directory must be trusted.** `Host::with_cache_dir` loads what it finds
  there as native code, and wasmtime checks only a header. Never point it at a directory other
  users can write.

## The embedder surface

- **Few tests here.** Operator events, stoppable runs, frame rules, transmit hooks, cable
  models, network extensions, control calls and the merging of two sites' recordings are used
  and tested by an embedder outside this repository. In this repository only the site-sync
  decoder has tests of its own, and operator events and control calls only as far as device
  commands use them (`crates/wasmnet-host/tests/routes.rs`), and the merging of two sites'
  recordings in `impairments.rs` and `infra_sites.rs` (in-world controllers). Treat that
  surface as unstable ([stability.md](stability.md)).
- **Device commands are native only.** The browser backend (`wasmnet-web`) reports no
  optional exports, so it does not serve `wasmnet:control/commands`: an `Op::Control` with a
  `DeviceCommand` is refused when added, and a controller's `devices.control` is refused when it
  applies (`infra-failed`).
- **Split networks keep changes on one site.** A controller changes only devices on its own
  site; a creation cabled to another site's device fails the split run (`Error::Refused`), and
  WAN links cannot be created while a network runs. Operator events there are limited to
  timed ones at a device (stdin, a control call, an injected frame); topology ops, link
  changes and events anchored before another event are refused. `Network::command` reaches
  only the devices of its own site ([design/sites.md](design/sites.md)).
- **`Network` is large.** About ninety methods on one type; the core and the embedder surface
  are told apart only by their doc comments.
- **The browser binding reports errors as strings** (`wasmnet_web::Network::link`, the
  `JsHost` methods), where the native API has one typed error.

## The netstack

- **An IGMP or MLD query makes the driver poll every millisecond** for the length of the
  response window. It costs processor time only: results and captures are the same.
- **TCP loss recovery still ends in a timeout where duplicate ACKs cannot help** (a loss
  among a transfer's last segments, while the window is under four segments, or of a
  retransmission): smoltcp has no SACK-based recovery, Limited Transmit or tail-loss probe,
  and its smallest retransmission timeout is 1 s
  ([design/netstack.md](design/netstack.md#tcp-congestion-control)).
  In `crates/wasmnet-host/tests/congestion.rs`, 1 MB at 10 Mbit/s through a 4-frame queue
  takes 1.85 s (0.83 s of it serialisation), and with 1 % loss 0.85 s to 5.8 s.
- **Colliding query ids in the resolver** (an A and an AAAA query drawing the same id) cost one
  timeout before the retry.

## The devices and apps

- **`mdns-responder` does not announce a later address change.** Once it is ready it arms no
  timer, so a new DHCP lease is not announced. It also does not answer or defend its name
  while it is still announcing.
- **`http-server` and `http-lb` have no timeouts on a slow peer.** `http-server` has no idle or
  read timeout and no cap on connections; `http-lb` writes to a client without a timeout and
  has no cap on tasks. Both are fine among well-behaved nodes and are not hardened against a
  hostile one.
- **`http-lb` has no test on the wire** for its admin API or its 400, 502 and 504 paths; its
  logic is unit-tested.
- **`http-get` takes a 1xx response as the final one.**
- **The router forwards a unicast IP packet that arrived as a link-layer broadcast.** Real
  routers drop those.
- **The router's NAT drops IPv4 fragments** in both directions (`nat-fragments`), translates
  only UDP, TCP and ICMP echo, and has no application-level gateways, NAT64/NAT66, UPnP, PCP
  or NAT-PMP ([design/nat.md](design/nat.md)). Unsolicited packets to its outside address get
  no answer.
- **The router scans its whole translation table and flow table** when a session or flow may
  expire: fine for thousands of entries, slow for the 65536 the bound allows.
- **A port that gets its first allow rule while traffic crosses it** does not know the flows
  already running: their answers are dropped unless a rule lets them in.
- **The switch scans its whole MAC table on every frame** to age entries: fine for tens of
  hosts, slow for thousands.

## Tooling

- **The browser page is tested only on pushes to `main`**, by the Pages workflow. A pull
  request that breaks `web/` passes CI.
- **The compile cache's stale-lock handling** is only exercised on Linux and Windows.
