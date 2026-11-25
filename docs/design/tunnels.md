# Tunnel ports

A router can have tunnel ports: point-to-point ports without a cable whose packets cross the
network inside UDP. Two routers behind NATs, in two homes, get a link of their own between
their networks: each tunnel end has a transit address, routes name the tunnel, and what crosses
the homes' NATs is ordinary UDP that the captures decode, found by hole punching. Nothing here
needs a real socket. Tunnels are off unless configured: a router without `tunnel.*` keys,
`tunnel-add` commands and `stun-server` behaves, counts and journals exactly as before.

The keys are in [configuration.md](configuration.md#router), the commands in
[wit/router/router.wit](../../wit/router/router.wit), the code in
`components/router/src/tunnel/` (the tunnel without a router) and
`components/router/src/router/tunnels.rs` (where it meets routing).

## A port of the router

A tunnel end needs an address on the outside to send from, a routing table to pick what enters
the tunnel, ICMP errors, hop limits and counters for what leaves it. The router has all of
these, so a tunnel is one more of its ports. A node (a netstack with a tunnel app) would need a
second interface, packet sockets and IP forwarding in the netstack, which is a router again; a
device of its own between the router and the outside would need its own ARP, address and
routes, as a separate NAT device would
([nat.md](nat.md#a-mode-of-the-router-not-a-device-of-its-own)).
The host learns nothing new: the router sends frames and gets frames, and its outer packets
are as real as its DHCP relay's.

**Ports and names.** A tunnel is router port `ports + slot`, after the cabled ones; it is not
in `ports()`, so no cable can be plugged into it, and it has no MAC and no neighbours. A tunnel
keeps its port while it exists; a removed tunnel frees its slot for the next one, so removing
one never moves another's routes. Port numbers stay inside the router: commands, routes, events
and counters name the tunnel (`fd00:b::/64 tunnel to-b`, `tunnel-to-b-rx-packets`, and a port
field in `route-lookup`, `ttl-decrement`, `forward-drop` and `route-added` holds `to-b`).
Tunnels from the config take their slots in name order.

**Addresses.** A tunnel's `local` is its transit address with a prefix length, the port's own
address and connected route (`fd00:ff::a/128`). The far end's transit address is not
configured: the port is point to point, and a route over it needs no next hop. Either family
works inside; the outer packets are IPv4.

## The wire format

One UDP port (default 6081) carries a tunnel's data and its checks; several tunnels may share
it, told apart by their id.

**Data** is [Geneve](https://www.rfc-editor.org/rfc/rfc8926) (RFC 8926):

```text
outer IPv4 (20) | UDP (8): from the tunnel's port to the peer's endpoint |
Geneve (8): version 0, no options, O=0 C=0 | protocol 0x86DD or 0x0800 | VNI = id | 0 |
inner packet, as routed (one hop less)
```

The outer source is the router's address on the egress port toward the peer (the IPv4 address
of the port the route to the peer's endpoint leaves by), the TTL the router's `ttl`. Received
packets must be version 0 of a known id with an inner packet of the family the protocol type
says; options are skipped, a critical option (C bit) or a control packet (O bit) is dropped.

**Checks** are [STUN](https://www.rfc-editor.org/rfc/rfc8489) Binding (RFC 8489) on the same
port:

- a check (a probe or a keepalive) is a Binding request whose `USERNAME` is the tunnel id in
  decimal (`7`); its answer is a Binding success response with `XOR-MAPPED-ADDRESS`, the
  endpoint the request came from, sent from the address and port the request was sent to;
- a Binding request without `USERNAME` asks only for that endpoint, as a STUN server is asked;
  every tunnel port answers it, and so does `stun-server`;
- a request for an id the router does not have on that port gets no answer;
- the transaction id is the kind (check or reflexive query), the tunnel id and a sequence
  number, so a response finds its tunnel and an answer to nothing it sent is ignored;
- no `MESSAGE-INTEGRITY` or `FINGERPRINT`: there are no credentials yet.

A STUN message has the magic cookie `0x2112A442` at bytes 4..8, where a Geneve header has its
VNI and a reserved zero byte, so the two never mix up. Wireshark decodes Geneve on UDP 6081 and
STUN by its heuristic; when a NAT moves a tunnel to another port, "Decode As" Geneve helps on
that port. The end-to-end tests decode every frame between the homes with their own reading of
both formats.

**Overhead and MTU.** 36 bytes: the default tunnel MTU is 1500 - 36 = **1464**. An inner
packet above it gets fragmentation needed or Packet Too Big like on any port; outer packets are
never fragmented, and an outer packet too big for its egress port is dropped
(`tunnel-<name>-outer-drops`).

**MSS clamping** (`mss-clamp`, on by default). A connection whose segments do not fit the tunnel
is told so by Packet Too Big or fragmentation needed, and the netstack's TCP then lowers its
segment size ([netstack.md](netstack.md)). That costs every connection a bounced segment and a
round trip, and a host whose stack does not act on the error stalls on retransmissions. So the
router lowers the MSS option of every TCP SYN that enters or leaves a tunnel to the tunnel MTU
minus 60 (IPv6) or 40 (IPv4) bytes and recomputes the checksum (`tunnel-<name>-mss-clamped`), as
home routers and VPNs do.

## What the router does

A tunnel is `idle` (nothing to probe), `probing`, `up` or `failed`.

- **Candidates** are endpoints where the peer may be: its `peer` setting, `tunnel-peer`
  commands, and the source of every check it receives (peer-reflexive, as ICE learns them), at
  most 8. One added by a command, or learnt while the tunnel is not up, is journalled as
  `tunnel-candidate {tunnel, endpoint, source}`; the settings' peers and the endpoints a tunnel
  comes up with or roams to are added silently (they show in `tunnel-up` and `tunnel-roamed`).
- **Probing**: every `probe` (100 ms) a check to each candidate, and a reflexive query to each
  `reflector` until one answers, for at most `rounds` (20) rounds. A new candidate is checked at
  once. After the last round without an answer the tunnel is `failed` (`tunnel-failed {tunnel,
  rounds, candidates}`) until a new candidate arrives; with nothing to probe it is `idle`, which
  is how a relay's end waits for its peer.
- **Up** on the first success response to a check, or the first data packet, with the tunnel's
  id: the endpoint it came from is the peer (`tunnel-up {tunnel, peer, after-ns}`), the port's
  carrier comes up, and routes over it carry packets. Until then they answer unreachable, as a
  down port does.
- **Keepalives**: once up, a check to the peer every `keepalive` (25 s, under every NAT UDP
  timeout RFC 4787 allows). Its answer refreshes the NAT mappings on both sides and reports the
  tunnel's reflexive endpoint.
- **Roaming**: once up, any check, response or data packet with the tunnel's id from another
  endpoint moves the peer there (`tunnel-roamed {tunnel, from, to}`). That is how a tunnel
  survives a NAT that gave the peer a new mapping (`tests/tunnel.rs`, a NAT rebinding). The id
  is not a credential, so anyone who can send to the tunnel's port can also steer it; see
  "Encryption".
- **Liveness**: nothing heard from the peer for `dead` (80 s) takes the tunnel down
  (`tunnel-down {tunnel, peer, silent-ns}`); it probes every candidate again, the old peer
  among them (unless a command removed it).
- **Reflexive endpoint**: each response's `XOR-MAPPED-ADDRESS` is the tunnel's endpoint as the
  responder saw it, journalled when it changes (`tunnel-reflexive {tunnel, endpoint, from}`) and
  listed by `tunnels`.

Inner packets are routed like any others: each router on the way decrements the hop limit, and
an ICMP error about a packet that came from a tunnel goes back through it, from the
tunnel's transit address when it has the family. Neighbour Discovery does not cross a tunnel.

**The packet filter** ([nat.md](nat.md#the-packet-filter)) takes rules for a tunnel's port by
the tunnel's name: `tunnel.<name>.allow` in the config, `allow-add <name> <rule>` and
`allow-remove <name> <rule>` as commands, and `rules` lists them under that name. Such a rule
sees the inner packets that arrive through the tunnel (decapsulated, with their own addresses
and ports), as a cabled port's rule sees what arrives on its cable; the flows they start, and
the flows that left through the tunnel, pass back as on any port. A rule on the cabled port the
outer packets use sees none of them: the tunnel's datagrams are addressed to the router, and
the filter only judges what it forwards. A router in front (a home's NAT router) filters the
outer UDP like any other forwarded traffic. A tunnel's rules go with it when it is removed.

**On a translating router** the tunnel's UDP port belongs to the router: datagrams to it on the
outside address are the tunnel's before the translation table is asked, and the tunnel's own
outer packets leave from the outside address untranslated. An inside host's mapping that gets
the same external port loses its inbound datagrams to the tunnel; keep `nat.port-range` clear of
tunnel ports.

## What a controller does

The router keeps a tunnel; a controller decides which tunnels exist and where traffic goes:

| controller | router |
|---|---|
| tunnel ids and transit addresses | encapsulation, decapsulation, MSS clamping |
| `tunnel-add` and `tunnel-remove` | checks, keepalives, liveness, roaming |
| signaling: read its tunnel's reflexive endpoint (`tunnels`), hand it to the peer's controller, which gives it to its own tunnel with `tunnel-peer` | the reflexive endpoint, from reflectors and from the peer |
| route choice: a shared LAN, a direct tunnel or a relay's; `route-replace` when a tunnel fails or comes up | routes as programmed |
| which router relays | nothing: a relay is a router |

The router has no rendezvous of its own: how two controllers find each other is theirs (a
replicated table, a server, a script). Any router with an address both sides reach can tell a
tunnel its reflexive endpoint (its `stun-server`, or any tunnel port), which is all a
rendezvous must do here.

The `tunnels` answer is meant to be parsed: one line per tunnel, by name, the name and then
`<key> <value>` pairs in a fixed order (`id`, `udp`, `local`, `state`, `peer`, `reflexive`,
`candidates`, `tx-packets`, `rx-packets`); later versions may append pairs, never reorder them.
An embedder sends the commands with `Network::command` (or as operator events) and reads their
answers; an in-world controller sends them with `wasmnet:infra/devices.control`, which does not
return a command's answer today.

**A relay** is a router with one tunnel per relayed peer and a route per relayed prefix over
each. Its tunnels need no candidates: each learns its peer from the peer's first check. A box
that cannot punch through to another (both behind symmetric NATs) adds a tunnel to the relay
and its controller replaces the route to the other's prefix with one over that tunnel. The
relay forwards at layer 3, so the inner hop limit drops once more, and it sees the inner
packets in the clear.

## Determinism

The router draws no random numbers: transaction ids are the tunnel's id and a counter, timers
run on the `now` it is given, candidates and tunnels are kept in order, and its next deadline
includes every tunnel's. The same commands at the same positions give the same packets.

A tunnel that is up sends keepalives forever, so a network with one never goes quiet: run it
with `run_until`.

## Limits and what is not covered

- At most 256 tunnels per router, 8 candidates and 8 reflectors per tunnel.
- Outer packets are IPv4 only: no IPv6 outer endpoints, no choice between several outer
  families (Happy Eyeballs).
- No path MTU discovery for the outer path: the tunnel MTU is configured.
- Commands are native only, like every device command ([known-issues.md](../known-issues.md)).
- No TURN-style relaying of outer datagrams, no WebRTC data channels.

**Encryption.** None yet. It would go between the Geneve header and the inner packet (or replace
Geneve with a WireGuard-like record), keyed by the controller through a command, with the STUN
checks carrying `MESSAGE-INTEGRITY` so that only an authenticated packet may move a tunnel's
peer. A key log, as TLS has, would let captures be decrypted.

## Tests

- Inside wasmtime (`cargo test --target wasm32-wasip2 -p wasmnet-router`): the codecs against RFC
  5769's vectors and arbitrary bytes, MSS clamping, the state machine (probing, up, keepalive,
  roaming, down, failed, reflectors), and through the whole router: encapsulation and
  decapsulation of IPv4 and IPv6 inner packets, an echo request to a transit address, routes by
  name surviving another tunnel's removal, tunnels from the config, Binding requests, a
  translating router, and arbitrary datagrams on the tunnel port.
- End to end with real nodes (`crates/wasmnet-host/tests/tunnel.rs`), each at two seeds and
  byte-identical on a rerun: HTTP across a tunnel punched through two NATs, the RFC 4787 matrix
  (it connects exactly where `tests/nat.rs` finds the `udp-punch` fixture connects), symmetric
  NATs failing and a relay carrying the fetch after the routes are replaced, a cut that takes the
  tunnel down and heals, roaming after a NAT rebinding, and a tunnel added and removed beside a
  transfer through the same router without changing a frame of it.
