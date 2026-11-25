# Known issues

What we know is wrong, missing or unbounded today. Version 0.0.0 is experimental; this list is
here so that nobody has to find these the hard way. Each entry names where the code is.

## The simulator

- **Recording is unbounded by default.** Unless a link's `CaptureOptions` say otherwise, every
  frame that crosses it is kept whole in the frame log and in its pcap encoder
  (`crates/wasmnet-core/src/link.rs`). A snap length bounds the bytes kept per frame and
  recording off keeps none ([design/links.md](design/links.md#what-a-link-records)), but the
  frame log still adds one fixed-size record per transmission, and captures are only held in
  memory (nothing streams them out). The journal and captured stdio have caps.
- **A memory limit is opt-in and native only.** `DeviceOptions::memory` (or a spec's `memory`)
  bounds a device's linear memory on wasmtime; a device without one may allocate as much as
  wasmtime lets it. The browser backend neither enforces it nor measures memory
  (`DeviceCost::memory` stays 0 there). Tables are not counted.
- **An event can be lost while a device is created.** `block_on`
  (`crates/wasmnet-core/src/exec.rs`) advances time while a device is instantiated or answers
  `ports()`. An event that is not a timer and comes due in that window is dropped without an
  error. Adding every device before the first `run` avoids it.
- **The transmit queue is bounded in frames only**, not in bytes, and serialisation counts the
  frame as transmitted, without Ethernet's preamble, FCS and inter-frame gap
  ([design/links.md](design/links.md)).
- **A compile cache directory must be trusted.** `Host::with_cache_dir` loads what it finds
  there as native code, and wasmtime checks only a header. Never point it at a directory other
  users can write. Components controllers supply go through it too (named by their full
  SHA-256, so code in a network cannot make its artifact stand for other bytes), which adds
  nothing to trust beyond the directory itself.

## The embedder surface

- **Few tests here.** Operator events, stoppable runs, frame rules, transmit hooks, cable
  models, network extensions, control calls and the merging of two sites' recordings are used
  and tested by an embedder outside this repository. In this repository only the site-sync
  decoder has tests of its own, and operator events and control calls only as far as device
  commands use them (`crates/wasmnet-host/tests/routes.rs`) and a device removed and added
  again (`measure.rs`), and the merging of two sites' recordings in `impairments.rs`,
  `infra_sites.rs` (in-world controllers) and `measure.rs` (capture options), and pauses,
  crashes, embedder actions and a network extension's life hooks in `faults.rs`. Treat that
  surface as unstable ([stability.md](stability.md)).
- **`wasmnet:infra` neither pauses nor shows a pause.** A controller cannot pause or resume
  the devices it created, and a paused device is `running` in the device table: a `paused`
  phase and the verbs need a new package version. A controller cannot crash a device either
  (an operator event can).
- **A paused device holds only what its own polls set.** Its timers are recognised by the
  device that set them; a timer it set while being instantiated by an operator event is not
  held, and completes at the resume's rounds instead of in its order. Its overdue work all runs
  at the resume instant, under one instant's fuel.
- **Device commands are native only.** The browser backend (`wasmnet-web`) reports no
  optional exports, so it does not serve `wasmnet:control/commands`: an `Op::Control` with a
  `DeviceCommand` is refused when added, and a controller's `devices.control` is refused when it
  applies (`infra-failed`).
- **Arguments and environment are native only.** The browser backend does not serve
  `DeviceOptions::args` and `env`: its devices see neither.
- **Supplied components are native only, and kept in memory.** The browser backend compiles
  nothing while a network runs (`Runtime::compile_supplied` keeps its default refusal), so a
  creation from a digest fails there (`failed`). On wasmtime a controller's store and the
  compiled components live in memory for the run, bounded per controller by its
  `SupplyLimits`, not across controllers. A component compiled in another process is shared
  only through a compile cache directory, which must be trusted as before.
- **A controller's limits are opt-in.** Without `DeviceOptions::infra_max_devices` nothing bounds
  how many devices a controller creates (beyond its 2^20 device numbers per run), and without a
  `memory` limit nothing bounds what they allocate.
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

- **`mdns-responder` answers on `eth0` only.** It joins and answers on interface 1; on a
  node with several ports, a question that arrives on another port goes unanswered. Answering
  on the port a question came in on, with that port's addresses (RFC 6762 §6.2), needs the
  arrival interface of a datagram, which `wasi:sockets` does not report (POSIX:
  `IP_PKTINFO`). The netstack's own one-shot queries do ask on every port.
- **A multi-homed node is a strong host** ([design/netstack.md](design/netstack.md#several-ports-and-static-routes)):
  it accepts a packet only on the port that holds its destination, and a socket bound to an
  address sends only by that address's port. Linux is a weak host; software that counts on
  reaching one port's address through another port does not work. A wildcard TCP listener's
  backlog counts per port, and an IPv6 link-local destination without a scope id leaves by the
  lowest port.
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
- **DNS-SD is partial.** `mdns-responder` has no subtypes, no unicast DNS-SD domains, no
  duplicate answer suppression (RFC 6762 §7.4) and no known-answer lists spread over several
  packets (§7.2); its services are fixed by its config, so a TXT record never changes. It
  answers NSEC for the types a service instance lacks and adds one for its host name to service
  answers when it has no address of one family, but still sends no negative answer to a
  question about its host name alone. Host and service answers to one query leave as separate
  packets. The app kit's browser (`crates/wasmnet-app-kit/src/mdns.rs`) sends no QU question
  (§5.4), suppresses no duplicate questions (§7.3), does not watch other hosts' queries go
  unanswered (§10.5), and caches at most 4096 records. A node's port 5353 can be bound once per
  family (the netstack has no `SO_REUSEPORT`), so `service-browse` beside `mdns-responder` on
  one node queries from another port and gets unicast answers with TTLs of 10 s.
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
- **The router's tunnels are unauthenticated and IPv4 outside.** A tunnel id is no credential:
  whoever can send to a tunnel's UDP port can move its peer. Outer endpoints are IPv4 only; on a
  translating router, an inside host's mapping on a tunnel's UDP port loses its inbound
  datagrams to the tunnel
  ([design/tunnels.md](design/tunnels.md)).
- **A switch's delay holds frames in the switch.** At most 4096 at once (more are dropped and
  counted, `held-dropped`); frames held for different pairs of ports may overtake each other.
  For a delay on one cable, a link's latency and jitter are the better tool
  ([design/links.md](design/links.md)).
- **The switch scans its whole MAC table on every frame** to age entries: fine for tens of
  hosts, slow for thousands.

## Tooling

- **The browser page is tested only on pushes to `main`**, by the Pages workflow. A pull
  request that breaks `web/` passes CI.
- **The compile cache's stale-lock handling** is only exercised on Linux and Windows.
