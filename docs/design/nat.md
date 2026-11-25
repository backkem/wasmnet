# Address translation and the packet filter

The router can translate addresses (NAT44 with port translation, "masquerade") on chosen ports
and filter what it forwards with an allow list per port. Both are off unless configured: a
router without `port<N>.nat` and without `port<N>.allow` behaves, counts and journals exactly
as it did before they existed. The keys are in [configuration.md](configuration.md#router),
the commands in [wit/router/router.wit](../../wit/router/router.wit).

## A mode of the router, not a device of its own

A home router is one box: it owns the WAN address, answers ARP for it, routes between LAN and
WAN, decrements the TTL and sends ICMP errors. A NAT that is a separate layer-3 device would
need all of that again (ports, ARP and NDP, a routing table, ICMP errors), or a second router
beside it, which no home has. A layer-2 "bump in the wire" NAT would not own the WAN address at
all. So translation is a property of a router port: `port1.nat = masquerade` makes port 1 the
outside, and packets routed out of it from any port without `nat` leave with port 1's IPv4
address. The table and the filter are modules of their own, tested without a router:

| module | what it is |
|---|---|
| `components/router/src/track.rs` | the connection tracking both share: a packet's flow tuple (IPv4 and IPv6, ICMP errors' quoted flows), TCP state per connection and the idle timeouts |
| `components/router/src/nat.rs` | the translation table: mappings, their sessions, port allocation, filtering, forwards, expiry |
| `components/router/src/filter.rs` | the allow lists and the flows they let through |
| `components/router/src/wire.rs` | `adjust_checksum` (RFC 1624) and `rewrite_v4`, which change addresses and ports and patch every checksum incrementally |

The router decides where in the forwarding path each one runs; the modules only answer
questions about endpoints and flows.

## Translation

**Where it runs.** For IPv4 only (no NAT64 or NAT66):

1. A packet from the outside to the outside port's own address is looked up in the table
   *before* local delivery (destination translation). With a mapping it is rewritten to the
   inside endpoint and forwarded like any packet; without one it is dropped silently
   (`nat-no-mapping`): no port unreachable, no RST, as RFC 5382 REQ-4 asks of TCP. Echo
   requests to that address are still answered by the router, and ICMP errors without a
   mapping go to the router itself, as before.
2. A packet routed out of an outside port from a port without `nat` gets its source translated
   after the TTL, route and MTU checks and after the filter (so the filter sees inside
   addresses), right before the TTL decrement.
3. A packet from the inside to the outside address that matches a mapping is hairpinned
   (below); otherwise it is the router's own traffic, as before.

Packets between two outside ports, or between two inside ports, are not translated. Masquerade
translates; it does not firewall: an outside host that has a route to an inside prefix reaches
it untranslated. Block that with the filter.

**Mappings and sessions (RFC 4787).** A mapping binds an inside endpoint (address, port; for
ICMP echo the identifier) to an external port on the outside address. Which outbound packets
share a mapping is `nat.mapping`:

| `nat.mapping` | a new mapping for each | RFC 4787 |
|---|---|---|
| `endpoint-independent` (default) | inside endpoint | EIM, REQ-1 |
| `address-dependent` | inside endpoint and remote address | ADM |
| `address-and-port-dependent` | inside endpoint and remote endpoint ("symmetric") | APDM |

Each mapping keeps one *session* per remote endpoint it talked to, with its own idle timer and,
for TCP, the connection's state. Which inbound packets a mapping accepts is `nat.filtering`:
any remote (`endpoint-independent`, EIF), a remote whose address it sent to
(`address-dependent`, ADF), or a remote endpoint it sent to (`address-and-port-dependent`,
APDF, the default, which is what Linux connection tracking does). A refused packet is
dropped and journalled as `nat-filtered` (once per flow by default, `trace.nat-filtered`).
Every mapping gets an external port of its own: two inside endpoints never share one, and an
external port is never reused while its mapping lives.

**Ports.** `nat.port-allocation = preserve` (default) keeps the inside port when it is free on
the outside address and otherwise takes the next free port of `nat.port-range`;
`sequential` always takes the next free port of the range. Both are a cursor over the range,
so the same packets get the same ports on every run: the router has no RNG and needs none.
Random allocation (RFC 6056) would only make a run's ports harder to read; a seeded one could
come later with its own key.

**Timeouts.** Idle timeouts on virtual time, shared with the filter (`conntrack.*`): UDP 300 s
(RFC 4787 REQ-5), TCP established 7440 s and transitory 240 s (RFC 5382 REQ-5), ICMP echo 60 s
(RFC 5508 REQ-1). Outbound and inbound packets both refresh a session (RFC 4787 REQ-6 requires
outbound refresh and allows inbound refresh); ICMP errors refresh nothing. A TCP connection is
established once both sides sent a SYN, transitory before that and after a FIN or an RST. A
new TCP mapping needs a SYN from the inside (RFC 5382): another outbound segment without a
mapping is dropped. A mapping expires with its last session and is journalled
(`nat-mapping-expired`); the router's `poll` deadline includes the earliest expiry, so a table
empties on its own when the network goes quiet.

**Bounds.** At most `conntrack.max-entries` sessions (4096); a packet that would need one more
is dropped (`nat-table-full`), as is one that finds no free port (`nat-ports-exhausted`).
Fragments (IPv4 MF or a fragment offset) are dropped (`nat-fragments`): no reassembly, no
fragment tracking. Protocols other than UDP, TCP and ICMP echo, and ICMP queries other than
echo, are not translated (`nat-unsupported`).

**Hairpinning** (`nat.hairpin`, on by default as RFC 4787 REQ-9 asks): an inside host that
sends to the outside address and a mapped port reaches the inside endpoint behind it, and the
packet arrives from the sender's own external endpoint, so both see each other as the outside
sees them. Off, such packets are dropped (`nat-hairpin-refused`).

**Port forwards** (`nat.forwards`, and the `forward-*` commands): a fixed mapping from an
external port to an inside endpoint, UDP or TCP. It accepts any remote (it is
endpoint-independent by nature), and the inside server's replies leave through it. Forwards
never expire; allocation skips their ports.

**ICMP errors (RFC 5508).** An error that reaches the outside address about a packet a mapping
sent (its quoted source is the external endpoint, its quoted destination a remote of that
mapping) goes to the inside host: the outer destination, the quoted source address and port
and every checksum involved (the quoted IP header, the quoted UDP or TCP checksum when it is
inside the quote, the ICMP checksum) are rewritten. Traceroute from behind the NAT names every
hop, and a port unreachable reaches the inside client's socket. An error an inside host sends
about a translated packet is translated the other way, and so are the router's own errors
about packets it translated (a port forward's inside host that never answers ARP). An error
that matches no mapping is dropped (from the inside) or left to the router (from the outside).

**Checksums.** Every rewrite patches the IPv4 header checksum and the transport checksum with
RFC 1624's incremental update; a UDP checksum of zero stays zero and a computed zero is sent as
`0xffff`. A property test compares the result with a full recomputation for random packets.

## The packet filter

`port<N>.allow` is an allow list for packets that arrive on port N and are forwarded:

```text
<proto> [from <prefix>] [to <prefix>] [dport <port>|<low>-<high>]
```

`proto` is `any`, `tcp`, `udp`, `icmp` or `icmpv6`; `dport` needs `tcp` or `udp`; prefixes are
IPv4 or IPv6 and a rule with one only matches that family. A port with rules forwards a packet
that matches one of them, or that belongs to a flow the router already let through in either
direction: return traffic, and ICMP errors about such a flow. Everything else is dropped and
journalled as `filter-drop` (once per flow by default, `trace.filter-drop`). A port without
rules forwards everything, as before, and its packets start flows too, so their answers pass a
filtered port. Once any port has rules the router tracks flows (same tuples, TCP states and
timeouts as the NAT, `conntrack.max-entries` of them); a router that never had a rule tracks
nothing. Fragments match only rules without `dport`. Traffic to the router itself (ARP, NDP,
pings, DHCP relay) is not filtered.

The filter runs after destination translation and before source translation, so on a NAT
router rules name inside addresses: `port1.allow = "tcp to 192.168.1.10/32 dport 80"` lets the
outside reach a forwarded web server, and nothing more.

## Rules while it runs

Forwards and allow rules change through `wasmnet:control/commands`, like the routes:
`forward-add`, `forward-remove`, `forwards`, `allow-add`, `allow-remove`, `rules`, and the read
`mappings`. A rule applies to packets from then on. Removing a forward removes its sessions.
A port that gets its first rule while flows cross it does not know those flows: their answers
must match a rule, or start again. The package moved to `wasmnet:router@0.1.2` (documentation
of new commands; no interface changed).

## Not covered

NAT64 and NAT66, UPnP, PCP and NAT-PMP, application-level gateways (FTP, SIP), translation of
IPv4 fragments and a NAT that pools several outside addresses. The filter has no deny rules, no
source-port match and no rate limits, and does not filter packets from tunnel ports.

A translating router can also be a tunnel end ([tunnels.md](tunnels.md)): datagrams to a
tunnel's UDP port on the outside address are the tunnel's before the translation table is
asked, and the tunnel's outer packets leave from that address untranslated.
