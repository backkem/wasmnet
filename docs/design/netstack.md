# The netstack

The netstack ([components/netstack](../../components/netstack)) is a smoltcp 0.14 IP stack over
`Medium::Ethernet`, packaged as an async device with one port, `eth0`, or several (`eth0`,
`eth1`, ...: [below](#several-ports-and-static-routes)). It speaks ARP, NDP,
IPv4, IPv6, ICMP, IGMP, MLD, UDP and TCP on the wire, and exports `wasi:sockets@0.3.0` and
`wasmnet:sockets-ext` to the apps composed with it (world `wasmnet:netstack/netstack`,
[wit/netstack/netstack.wit](../../wit/netstack/netstack.wit)). The guarantee: the stack's logic
(`Stack` in [src/stack.rs](../../components/netstack/src/stack.rs)) reads no clock and no RNG
of its own. Time, frames, the MAC and the seeds are explicit inputs, so the same inputs give the
same frames, and a node replays byte for byte under the same seed.

```text
  app ── wasi:sockets / sockets-ext ──┐            (calls run in the app's task)
                                      ▼
  receive ─► rx queue ─►  Stack (per port: smoltcp Interface + SocketSet; routes, our tables)
                                      │  poll(now) → frames, logs, events
                    driver task ──────┘─► wire.transmit, log, wait-until(next wakeup)
```

## One driver task

`ports()` answers `eth0` (and `eth1`, ... on a node with several ports) with the configured MAC
(or one drawn from the seeded `wasi:random`, port by port) and the IP MTU. `start()` builds the
`Stack` and spawns **one** driver task with
`wit_bindgen::spawn_local`, then returns. `receive()` pushes the frame into the stack's rx queue
and wakes the driver; `poll()` always answers `none`.

The driver (`driver` in [src/component.rs](../../components/netstack/src/component.rs)) runs
**passes** until nothing is left at the current instant. A pass:

1. polls every TCP job (below), which moves bytes between the apps' streams and smoltcp;
2. calls `Stack::poll(now)` and `Stack::next_wakeup(now)` inside one short borrow;
3. hands the frames to `wire.transmit` and the notes to `wasmnet:link/log`, in order;
4. wakes every socket call parked on the driver's progress.

Passes repeat while jobs and the stack feed each other, up to 256 per poll; past that the
driver wakes itself and continues at the same instant through the executor, which bounds it
with the host's poll cap. Then the driver makes sure a virtual `wait-until` is armed at or
before `next_wakeup`: the earliest of smoltcp's `poll_at`, the sockets' own timers and the
multicast deadline ([src/mcast.rs](../../components/netstack/src/mcast.rs): smoltcp's `poll_at`
ignores pending IGMP and MLD reports). With nothing left at all it drops its stale timers, so
the run's end is not stretched to the last of them, and parks.

## The five driver rules

[async-under-virtual-time.md](async-under-virtual-time.md) explains why an async device needs
them. The netstack applies them like this (comments tagged `rule N` in `component.rs`):

1. **Level-triggered wakes.** `wake_driver` sets `Driver::woken`; a pass clears it first, and
   the driver checks it again before it parks (`driver-rewakes` counts the second looks).
2. **Waker first.** Every driver poll stores its waker in `Driver::waker` before anything else
   and never takes it out, so an export that re-enters during this very poll still wakes it.
3. **No borrow across an import.** The stack is only borrowed inside closures that call no
   import (`with_node`, `with_stack`); frames and notes are emitted after the borrow ends.
4. **No timer cancels in the hot path.** A new `wait-until` is armed only if no armed one fires
   at or before the new deadline. The test-only config key `driver.timer-churn` breaks this
   rule on purpose, to exercise the failure.
5. **Diagnostics through `wasmnet:link/log`**, never `eprintln!`.

**Wake counting.** Every wake records the instant it happened. The `counters` export reports,
besides the stack's own counters: `driver-late-wakes` (wakes first served at a later instant
than their own: lost wakes), `driver-unserved-wakes` (1 if a wake is still waiting for a pass;
read between runs it must be 0), `driver-reentrant-calls` and `driver-reentrant-wakes`
(exports entered while the driver was suspended inside its own poll), `driver-polls`,
`driver-passes`, `driver-rewakes`, `timers-armed`, `timers-fired`, `timers-cancelled` and
`driver-jobs`. Tests assert that the late and unserved counts stay 0.

## Sockets on smoltcp

Every socket call runs in the calling app's task, inside the netstack instance. Sync calls
change the stack and wake the driver; they never spawn a task. Async calls (UDP `send` and
`receive`, TCP `connect`, `receive-error`, `resolve-addresses`) try once and, if they cannot
finish, park until the driver's next pass.

- **UDP** ([src/udp.rs](../../components/netstack/src/udp.rs)). The smoltcp socket exists from
  `bind` on (explicit, or implicit on the first `connect` or `send`). Ephemeral ports count up
  from 49152, with no RNG. Families never conflict (every WASI IPv6 socket is V6ONLY), so the
  stack demultiplexes a port bound by both families itself. `send` queues and returns like
  `sendto(2)`; a full buffer parks the call; a datagram too large for one frame is
  `datagram-too-large` (no IP fragmentation). A dropped socket with datagrams still queued
  lingers up to 3 s.
- **TCP** ([src/tcp.rs](../../components/netstack/src/tcp.rs)). `connect` and `listen` create
  smoltcp sockets with the buffer sizes set so far (64 KiB per direction by default, clamped to
  536 B to 1 MiB). The listen backlog is N smoltcp sockets in LISTEN (default 8, at most 64),
  since smoltcp has no backlog. A connect waits at most 75 s for the handshake. Every
  connection has a congestion controller, Reno by default (below).
- **ICMP echo** ([src/icmp.rs](../../components/netstack/src/icmp.rs)): Linux-style ping
  sockets. The stack picks each identifier from a rover that starts at an identifier drawn
  from the seeded `wasi:random`.
- **Name lookup** ([src/names.rs](../../components/netstack/src/names.rs)): below.

TCP's `listen`, `send` and `receive` are sync but return streams and futures, so the work
behind them is a **job**: an accept loop per listener and two byte pumps per connection. A sync
export only queues the job and wakes the driver; the driver polls every job on every pass, so a
job may wait on smoltcp state without registering a waker.

**Buffer coupling.** The send pump reads from the app's stream at most what smoltcp's transmit
buffer has free, so a slow network slows the writer. The receive pump peeks at smoltcp's
receive buffer and removes bytes only once the app's stream took them, so the advertised
window follows the app's reading speed. Dropping the send stream queues a FIN after the
accepted data; the peer's FIN ends the receive stream; an RST (from `sockets-ext/tcp.abort` or
the peer) resolves both futures to `connection-reset`; dropping the receive stream is
`SHUT_RD`: later data is acknowledged and discarded.

## TCP congestion control

Every TCP connection gets the congestion controller the node's `tcp.congestion` names
([configuration.md](configuration.md)) when its smoltcp socket is created, and keeps it.

- **`reno`** (the default): smoltcp's Reno (RFC 5681) with NewReno's partial-ACK handling
  (RFC 6582, our third smoltcp patch). Slow start begins at smoltcp's initial window of
  2048 bytes, a full segment and 588 bytes at a 1500-byte MTU. Each ACK of new data adds up
  to one segment; the receiver acknowledges every second full segment, so the window grows by
  about half per round trip, not double. Above `ssthresh` it grows by at most one segment per
  round trip. Three duplicate ACKs retransmit the first unacknowledged segment and halve the
  window (fast recovery: `ssthresh` = flight / 2, the window `ssthresh` + 3 segments, one more
  per further duplicate ACK). A partial ACK, one that stops short of everything sent before the
  loss was detected, retransmits the next hole at once and keeps fast recovery; the ACK of
  everything ends it with the window at `ssthresh`. A retransmission timeout drops the window
  to one segment and resends everything from the last ACK (go-back-N) in slow start.
- **`none`**: no congestion window, only the peer's receive window: a sender puts the whole
  window on the wire at once, and each loss waits for three duplicate ACKs of its own. This is
  the netstack's timing from before it had congestion control, byte for byte.

Why Reno: its arithmetic is integer only, so its decisions are the same on every target, and it
is the controller that builds here: smoltcp 0.14's Cubic calls `f64::powi` and `f64::mul_add`,
which only std has, and the netstack builds smoltcp without std. On the short round trips of a
simulated LAN, Cubic would mostly run in its Reno-friendly region anyway (RFC 9438 §4.3).

What recovery depends on besides the controller, all smoltcp's and unchanged:

- **The retransmission timer** (RFC 6298): 1 s before the first RTT sample, at least 1 s and at
  most 60 s, doubled on every timeout; after three timeouts in a row the RTT estimate is
  discarded. RTT is sampled once per window, in whole milliseconds of virtual time.
- **Fast retransmit** on the third duplicate ACK, with every controller.
- **Delayed ACKs**: an ACK waits up to 10 ms, except for every second full segment, an
  out-of-order segment or one that fills a hole, which are acknowledged at once.
- **Nagle** is on unless the app sets `TCP_NODELAY`.
- **No SACK-based recovery, Limited Transmit, early retransmit or tail-loss probe**: smoltcp
  sends SACK blocks as a receiver but never uses the peer's. A loss that no three duplicate
  ACKs reveal (among the last segments of a transfer, while the window is under four segments,
  or of a retransmission) costs a timeout, at least 1 s.

Measured with real nodes (`crates/wasmnet-host/tests/congestion.rs`): 1 MB over 10 Mbit/s
through a 4-frame transmit queue takes 1.85 s with Reno (the serialisation alone is 0.83 s; one
timeout at the end of the transfer), against 54 virtual minutes with `none`; with 1 % loss each
way it takes 0.85 s to 5.8 s over eight seeds, one timeout or more where duplicate ACKs could not
help. A snapshot never holds a controller's state: it is only taken with no connection open.

## ICMP errors

smoltcp ignores ICMP errors for TCP and UDP sockets. The netstack classifies its own frames
([src/observe.rs](../../components/netstack/src/observe.rs)) and, for an ICMP error that quotes
one of its packets, journals `icmp-error-received` and then:

- fails a TCP connect still in SYN-SENT to that peer from that port, as Linux does:
  `connection-refused` for a port unreachable, `remote-unreachable` for other hard errors;
  an established connection is not affected;
- queues it for a UDP socket or an ICMP echo socket that asked for its errors
  (`set-recv-errors`), at most 16 per socket;
- ends the resolver's tries with that server one round trip after the query;
- lowers a TCP connection's segment size on a "fragmentation needed" or "packet too big"
  (path MTU discovery, below).

**Path MTU discovery** (RFC 1191, RFC 8201) is per connection. A "fragmentation needed"
(ICMPv4 type 3 code 4) or "packet too big" (ICMPv6 type 2) about a TCP segment is trusted
only as Linux trusts it: it reports an MTU below the node's own, it quotes a segment of a live
connection (the four-tuple), and the quoted sequence number was sent and not yet acknowledged.
An MTU under the family's minimum counts as the minimum (552 for IPv4, Linux's floor; 1280 for
IPv6), and an error without an MTU (an old router's) is ignored, with no plateau search. The
connection's send MSS becomes the MTU less the IP and TCP headers, never higher than before,
and its data in flight goes again at once in the new size, without counting as a loss (our
smoltcp patch `Socket::path_mtu_lowered`). The journal says `effect path-mtu-lowered` and adds
`path-mtu-lowered` (`peer`, `local-port`, `mtu`, `mss`); the counter is
`tcp-path-mtu-lowered`. Nothing changes on a network where no such error arrives.

There is no per-destination cache: a new connection over the same path learns it again, at
the cost of one bounced segment and one round trip, since the resend is immediate. That keeps
the state with the connection, with nothing to expire and nothing for a snapshot to save (a
snapshot is only taken with no connection open). UDP learns nothing: an error about a
datagram is queued for a socket that asked for errors (`set-recv-errors`), with its type and
code (the MTU is not part of `wasmnet:sockets-ext/udp`), and a datagram of the same size goes
out whole again.

## DHCP and the resolver

With `ipv4 = dhcp` the stack boots without an IPv4 address and runs smoltcp's DHCPv4 client
([src/dhcp.rs](../../components/netstack/src/dhcp.rs)). Each lease sets the address, the
default route and the DNS servers; renewals and expiry are smoltcp's, on virtual time, and
transaction ids come from smoltcp's RNG, seeded from `wasi:random`. Journal: `dhcp-bound`,
`dhcp-renewed`, `dhcp-lost`.

`ip-name-lookup` answers IP literals and the `hosts.<name>` config table at once, like
`/etc/hosts`. Any other name goes to the stub resolver
([src/resolver.rs](../../components/netstack/src/resolver.rs)) when the node has DNS servers (the
`dns` key, else the lease's), with the lease's domain appended to a single-label name: A and
AAAA queries in parallel over UDP 53, one server at a time, `resolver.timeout` per try and
`resolver.attempts` rounds, ids and source ports from a seeded PRNG. A `.local` name is asked
with one-shot mDNS queries, DNS servers or not. The keys are in
[configuration.md](configuration.md).

## Several ports and static routes

A node may have up to 16 ports ([configuration.md](configuration.md#several-ports-and-static-routes)):
`port<N>.*` keys give each its MAC, MTU and addresses (static, or `ipv4 = dhcp` on any port),
the unprefixed keys are port 0's, and `routes` adds static routes in the router's syntax. A node
with one port is exactly what it was before: the same frames, counters, log lines and draws
from `wasi:random`.

**One smoltcp interface per port.** smoltcp's `Interface` is one interface: one hardware
address, one device, one neighbour cache, one route table, one set of multicast memberships. A
multi-homed host needs all of those per link, so each port is an `Interface` over its own
queue device. The alternatives were worse:

- one interface whose device multiplexes the ports would need one MAC for every port, could
  not tell which port an ARP request or a multicast report belongs on, and would mix the
  neighbours of different links in one cache;
- a patch teaching smoltcp several links would have to reach into its egress (a socket
  dispatches by the interface's routes and source addresses), its ingress (the first DHCP
  socket in the set takes every DHCP reply) and its neighbour handling: a large change to a
  vendored library for what the netstack can do above it.

**One socket set per port.** A smoltcp interface sends whatever any socket in the set it polls
has queued, by its own routes and from its own addresses, and hands every arriving packet to the
sockets of that set. Two interfaces sharing one set would both send a socket's segments. So
each port has its own `SocketSet`, a socket lives in exactly one of them, and a handle names
the port with the slot ([src/sockets.rs](../../components/netstack/src/sockets.rs)). An app
socket that is not tied to one port has a smoltcp socket on every port:

- **UDP and ICMP echo sockets** bound to the unspecified address (explicitly, or implicitly on
  the first `send`) get one smoltcp socket per port, so they receive on every port; `receive`
  takes the family demultiplexer's datagrams first, then each port's socket in port order. A
  socket bound to one of the node's addresses gets one, on that address's port.
- **TCP listeners** on the unspecified address keep their backlog of LISTEN sockets on every
  port (the backlog counts per port); a listener on an address only on its port. An accepted
  connection stays in the set of the port it arrived on. **`connect`** creates its socket on the
  port the route picks.

**The route table** ([src/route.rs](../../components/netstack/src/route.rs)) picks the port of
everything the node sends. It holds, in this order: a connected route per address of every port
(every port's link-local address brings `fe80::/64`), as the addresses are right now; the
`routes` items in the order listed, then the gateway keys' default routes, port by port; then
the default route of each DHCP lease that names a router, port by port. The lookup is a
longest-prefix match, and among routes of the same length the first in that order wins, so a
connected route beats a static one and the lowest port wins a tie between ports. A destination
no route covers is `remote-unreachable` (`ENETUNREACH`). Inside the chosen port, smoltcp picks
the next hop: each port's interface holds that port's static routes and its lease's default,
and sends on-link what lies in one of its own prefixes (so a static route inside its own port's
static prefix is refused at config time: it would never be used).

**Sources and binds: the strong host model** (RFC 1122 §3.3.4.2, Windows' default; Linux is a
weak host):

- An unbound or wildcard socket's packets leave by the route's port, and smoltcp picks the
  source address among that port's addresses: for IPv6 RFC 6724's candidate set and rule 2
  (the scope of a link-local or multicast destination) and rule 8 (longest matching prefix);
  for IPv4 the port's address in the destination's subnet, else its first. Rules 3 to 7
  (deprecated, home, interface, label and temporary preferences) have nothing to choose from:
  the outgoing interface is already fixed, and a port has at most one IPv4 address, a
  link-local and one global IPv6 address.
- A socket bound to one of the node's addresses sends only by that address's port, with only
  that port's routes; a destination they do not cover is `remote-unreachable`.
- A packet is accepted only on the port that holds its destination address: a packet for
  `eth1`'s address that arrives on `eth0` is dropped.
- **No forwarding.** A packet for an address the node does not have is dropped, whichever port
  it came in on. Forwarding is the router's job.
- An IPv6 link-local destination is ambiguous on a node with several ports: its scope id (the
  `wasi:sockets` address's `scope-id`, the interface index) picks the port, and without one the
  route table does (the lowest port). On such a node a datagram from a link-local source and an
  accepted connection from one carry their port's index as the scope id, so an answer to them
  leaves by the same port. A node with one port reports scope 0, as before.

**Multicast.** A membership belongs to a socket and an interface index (`wasmnet:sockets-ext`
indexes: port N is index N + 1, 0 the default). Each port's interface joins the groups its
sockets want there, and sends its own IGMP and MLD reports. A datagram to a group (or to
`255.255.255.255`) leaves by the socket's `multicast-interface`, else the family's default
port: the port of the family's first default route, else the lowest port with an address of the
family. Multicast loopback is per port. The resolver's one-shot mDNS queries ask on every port
with an address of their family.

**Per port**, besides the interface: the neighbour tables and their bounds, the multicast
deadline, the carrier, the DHCP client, and ICMP errors (an error counts only on the port that
holds its destination; path MTU discovery compares against that port's MTU). On a node with
several ports, the events the stack journals for one port (`arp-resolved`, `ndp-resolved`,
`icmp-error-received`, `path-mtu-lowered`, `multicast-joined`, `multicast-left`, `dhcp-*`) carry
a `port` field (`eth1`), and the log line at start lists every port and the static routes. The
DNS servers are the `dns` key's, else every lease's, port by port; a single-label name gets the
first lease's domain.

**Counters** keep their names and order: frame, neighbour, ICMP error and DHCP counts are sums
over the ports, and on a node with one port they are its port's. A node with several ports
also lists each port's own counters (`eth<N>.rx-frames`, `.rx-bytes`, `.tx-frames`,
`.tx-bytes`, `.arp-resolved`, `.ndp-resolved`, `.multicast-queries`, `.icmp-errors-received`,
`.multicast-groups`, `.dhcp-bound`, `.neighbors-evicted`), after the driver's.

**Snapshots** save every port (format version 4); a restore needs a stack built with the same
ports, MACs and addresses.

Tested in the pure multi-node simulation
([src/sim_tests/multi.rs](../../components/netstack/src/sim_tests/multi.rs): replies and
neighbours per port, no forwarding, binds across ports for UDP and TCP, routes, next hops and
source addresses, a join on one port, snapshots), against a reference for the longest-prefix
match under random tables ([src/route.rs](../../components/netstack/src/route.rs)), and end to
end with real nodes ([crates/wasmnet-host/tests/multihomed.rs](../../crates/wasmnet-host/tests/multihomed.rs):
a host on a LAN, by DHCP, and on a static second segment serves both and fetches through
either router by its routes).

## smoltcp, patched

smoltcp is vendored in [third_party/smoltcp](../../third_party/smoltcp) with six patches,
kept as files in [docs/upstream](../upstream): neighbor discovery rate-limited per address
instead of per interface (`smoltcp-0001-neighbor-rate-limit-per-address.patch`), so a host
resolves several neighbors within a second; a `snapshot` feature that reads and restores
interface state (`smoltcp-0002-snapshot-state.patch`), which `wasmnet:netstack/state` uses;
NewReno's partial-ACK retransmission in TCP fast recovery
(`smoltcp-0003-newreno-partial-acks.patch`), so several losses in one window are repaired
without a retransmission timeout; a FIN on a segment cut at the receive window's right edge
ignored with the cut bytes (`smoltcp-0004-fin-past-the-receive-window.patch`), so a stream no longer
ends with bytes missing; a fast retransmit that sends the FIN alone when only the FIN is
unacknowledged (`smoltcp-0005-fast-retransmit-of-a-lone-fin.patch`), so a closing connection
does not hang in that state; and `Socket::path_mtu_lowered`
(`smoltcp-0006-path-mtu-lowered.patch`), the hook behind path MTU discovery (below).
[docs/upstream/smoltcp.md](../upstream/smoltcp.md) lists every smoltcp issue found and the
workaround in use.

## Limits

At most 16 ports and 32 static routes; a host never forwards between its ports, and has no
policy routing, metrics or on-link routes without a next hop. No IP fragmentation, no TCP
fallback for truncated DNS answers. smoltcp
keeps time in microseconds, so link latencies below 1 µs collapse into one instant. The IPv4
identification field is always 0.
