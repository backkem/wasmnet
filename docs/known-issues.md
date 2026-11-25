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
- **A memory limit is opt-in, and checked late in a browser.** `DeviceOptions::memory` (or a
  spec's `memory`) bounds a device's linear memory; a device without one may allocate as much as
  its runtime lets it. Wasmtime refuses the growth that would pass the limit, at the growing
  instruction. A browser grows memories itself, so the page reads their sizes after every poll
  of the device and the device faults there, with the same message, after the growth
  ([design/browser.md](design/browser.md#memory)): work in between can use more than the limit
  for a while, and a growth past what the tab can give fails as the browser decides. Tables are
  not counted on either backend.
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
- **A controller reads the events only of the devices it created.** `wasmnet:infra/events`
  refuses the network's own devices (`denied`), which a controller sees in the table: their
  events may be journalled on another site of a split network. A controller that must follow
  one of them needs the embedder to relay it (a command of the controller's own), or creates
  the device itself. Each device a controller created keeps up to 256 events (256 KiB) for it
  whether or not anyone reads them; `missed` counts the dropped events of every kind, not only
  those a reader's filter wants, so a reader of a few kinds from a chatty device may resync
  more often than it needs to. Log lines (`log.log`) and the network's own records about a
  device are not served as events ([design/topology-and-infra.md](design/topology-and-infra.md#events-of-the-devices-a-controller-created)).
- **A paused device holds only what its own polls set.** Its timers are recognised by the
  device that set them; a timer it set while being instantiated by an operator event is not
  held, and completes at the resume's rounds instead of in its order. Its overdue work all runs
  at the resume instant, under one instant's fuel.
- **What the browser backend does not do** ([design/browser.md](design/browser.md#what-each-backend-does-itself)):
  fuel (`fuel_per_instant` is ignored and fuel costs are 0: neither jco nor the page can meter a
  core module's instructions; the guard is `Guard::max_polls_per_instant`, 100 000 polls of one
  instant), host extensions' imports, and sites. A page creates a device while the network runs
  with JSPI (Chromium's `WebAssembly.Suspending`), and checks a component's imports against the
  `wasmnet:infra` grant only when it knows them (`ComponentSource.imports`; without them, every
  infra call of an ungranted device is `denied` instead). A WASI 0.2 stdin read with nothing
  queued waits in a page, where natively it is the end of the stream.
- **Supplied components are kept in memory, and a page cannot transpile them.** A browser page
  runs a supplied component only from a transpile it already has: a `ComponentSource` with that
  digest, or the embedder's `NetworkOptions.supply` hook. The kit's transpiler (`codelib-web/transpile`)
  is a Node tool that writes files, so the page cannot transpile supplied bytes itself
  ([design/browser.md](design/browser.md#components-a-controller-supplies)). On wasmtime a controller's store and the
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
  `JsHost` methods), where the native API has one typed error. Its TypeScript `Network` reaches
  operator events, device options and link options as plain objects that the simulator reads
  (`crates/wasmnet-web/src/ops.rs`); embedder actions and extensions' ops take Rust closures and
  values and are reachable only from Rust (`wasmnet_web::Network::sim_mut`).

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
  so such a loss costs a timeout, the round trip plus `tcp.rto-min` (200 ms by default)
  ([design/netstack.md](design/netstack.md#tcp-congestion-control)).
  In `crates/wasmnet-host/tests/congestion.rs`, 1 MB at 10 Mbit/s through a 4-frame queue
  takes 1.05 s (0.83 s of it serialisation), and with 1 % loss 0.85 s to 2.07 s.
- **A full listen backlog drops a SYN, and the client waits a timeout** (1 s for the first
  SYN, then 2 s, 4 s, ...), as on Linux, with no SYN cookies and no queue of half-open
  connections beyond the backlog itself ([design/netstack.md](design/netstack.md#sockets-on-smoltcp),
  counter `tcp-listen-overflows`). The stack recognises the SYN in an IPv4 packet or directly
  behind the IPv6 header; one behind IPv6 extension headers still draws smoltcp's RST when
  the backlog is full.
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
- **A keyless tunnel is unauthenticated.** Without a key a tunnel id is no credential: whoever
  can send to a tunnel's UDP port can move its peer or inject into it. On a translating router,
  an inside host's mapping on a tunnel's UDP port loses its inbound datagrams to the tunnel
  ([design/tunnels.md](design/tunnels.md)).
- **Tunnels discover no path MTU and prefer no family outside.** A tunnel's MTU is configured
  or the 1500-byte default of its peer's outer family; an outer packet too big for a router on
  the way is lost, and that router's Packet Too Big or fragmentation needed does not lower the
  tunnel's MTU. Candidates of both families are probed alike and the first answer wins (no
  Happy Eyeballs). There is no IPv6 translation (NAT66, NPTv6) in the router.
- **A keyed tunnel's protection has limits** ([design/tunnels.md](design/tunnels.md#what-a-key-protects-and-what-it-does-not)).
  An on-path attacker cannot read, inject, replay, reflect, bring a tunnel up or move its peer,
  but it can drop packets (and so take the tunnel down), see addresses, ports, SPIs, sizes,
  timing, the tunnel id and when keys change, and forge answers to unsigned reflexive queries.
  There is no forward secrecy and no rekeying of its own: the controller replaces the key, and
  an SA stops sending after 2^32 - 1 packets until it does. A relay sees the inner packets. The
  key derivation, epochs and signed checks are this library's own composition of standard
  parts (ESP in UDP with ChaCha20-Poly1305, HKDF-SHA256, STUN's `MESSAGE-INTEGRITY-SHA256` and
  an unregistered attribute, `TUNNEL-SA`) and have had **no outside review**. Nothing derives a
  capture's per-direction ESP keys for a decoder yet; Wireshark's source has the algorithm
  ("ChaCha20 with Poly1305 [RFC7634]"), but decrypting a capture of this library with it was
  not tried. Encryption costs fuel: about 4.6 times a keyless router's per packet (see the note on fuel in
  [design/runtime-and-extensions.md](design/runtime-and-extensions.md)).
- **A switch's delay holds frames in the switch.** At most 4096 at once (more are dropped and
  counted, `held-dropped`); frames held for different pairs of ports may overtake each other.
  For a delay on one cable, a link's latency and jitter are the better tool
  ([design/links.md](design/links.md)).
- **The switch scans its whole MAC table on every frame** to age entries: fine for tens of
  hosts, slow for thousands.

## Tooling

- **The compile cache's stale-lock handling** is only exercised on Linux and Windows.
- **Component bytes may differ between Linux and Windows.** `cargo xtask build` maps every
  source path out of the components, so a rebuild in another checkout on the same operating
  system gives the same bytes, but whether a Linux and a Windows build agree has not been
  observed: cargo likely derives the symbol hashes of the workspace's own crates from their
  relative paths with the platform's separator. CI's `platforms` job compares the two and does
  not fail the workflow; until it passes, a published set is built on Linux
  ([design/artifacts.md](design/artifacts.md#reproducible-bytes)).
- **No set of artifacts is published yet.** The workflow that would push each commit's set to
  the container registry is a proposal
  ([design/artifacts-workflow.yml.example](design/artifacts-workflow.yml.example)); until it
  runs, `Source::Oci` has nothing to fetch, and an embedder fetches from a directory built with
  `cargo xtask artifacts`.
- **The commit check reads a range.** `cargo xtask check-tree --commits BASE..HEAD` reads the
  messages and added lines of the commits in the range only; history before the base is not
  checked (the repository's first commits carry trailers it would report). A push whose base
  is not in the clone's history (a force push) fails the CI job.
