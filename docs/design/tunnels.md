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
works inside, and either outside ([below](#the-outer-family)): all four combinations.

## The wire format

One UDP port (default 6081) carries a tunnel's data and its checks; several tunnels may share
it, told apart by their id.

**Data** is [Geneve](https://www.rfc-editor.org/rfc/rfc8926) (RFC 8926):

```text
outer IPv4 (20) or IPv6 (40) | UDP (8): from the tunnel's port to the peer's endpoint |
Geneve (8): version 0, no options, O=0 C=0 | protocol 0x86DD or 0x0800 | VNI = id | 0 |
inner packet, as routed (one hop less)
```

The outer source is the router's address on the egress port toward the peer (the address of the
peer's family on the port the route to the peer's endpoint leaves by; for IPv6 its configured
address, never the link-local one), the TTL or hop limit the router's `ttl`; over IPv6 the UDP
checksum is always computed, and a received datagram with a zero one is malformed (RFC 8200
§8.1). Received
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
- without a key, no `MESSAGE-INTEGRITY` and no `FINGERPRINT`: the id is not a credential;
  a keyed tunnel signs its checks ([below](#keyed-tunnels)).

A STUN message has the magic cookie `0x2112A442` at bytes 4..8, where a Geneve header has its
VNI and a reserved zero byte, so the two never mix up. Wireshark decodes Geneve on UDP 6081 and
STUN by its heuristic; when a NAT moves a tunnel to another port, "Decode As" Geneve helps on
that port. The end-to-end tests decode every frame between the homes with their own reading of
both formats.

**Overhead and MTU.** 36 bytes over IPv4, 56 over IPv6: the default tunnel MTU is 1500 - 36 =
**1464** over an IPv4 path and **1444** over an IPv6 one (keyed: 1438 and 1418, below). The
default follows the outer family of the peer the tunnel is up with (IPv4 while it is down), and
so do the port's MTU and the MSS clamp; an `mtu` that is given stays as given. An inner
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

## The outer family

A tunnel's outer path is IPv4 or IPv6, whichever its peer's endpoint is: `peer`, `reflector`
and `tunnel-peer` take `203.0.113.2:6081` and `[2001:db8::2]:6081` alike (not link-local, not
IPv4-mapped: an outer path is routed), and so do the candidates it learns, its peer, its
reflexive endpoint and the listing.

- **Sending.** The router originates the outer UDP as it originates anything: routed by the
  table to the peer's address, from the egress port's address of that family (for IPv6 its
  configured address, never the link-local one), with the router's `ttl` as TTL or hop limit,
  through ARP or NDP. Over IPv6 the UDP checksum is always computed. A family the router has no
  address or route for leaves nothing (`tunnel-<name>-outer-drops`).
- **Receiving.** A UDP datagram to a tunnel port or the `stun-server` port on one of the router's
  addresses is the tunnel's, over either family; over IPv6 one with a zero UDP checksum is
  malformed (RFC 8200 §8.1), and link-local addresses are not tunnel endpoints. Anything else to
  the router gets its usual port unreachable.
- **STUN** answers carry `XOR-MAPPED-ADDRESS` of the requester's family (RFC 8489's IPv6 form,
  checked against RFC 5769's vector), from the `stun-server` or any tunnel port.
- **No translation.** The router has no NAT for IPv6, so a box is reached at its own address
  and its reflexive endpoint is that address. A home router with a stateful filter on its
  outside port (`port<N>.allow` with no rule for the tunnel's UDP) lets the other box in only as
  part of a flow its own box started, which is hole punching as through a filtering NAT:
  `tests/tunnel6.rs` punches through two such filters.
- **MTU.** The overhead is 20 bytes larger over IPv6, and the default MTU follows the family of
  the peer the tunnel is up with: 1464 or 1444 without a key, 1438 or 1418 with one. The port's
  MTU (Packet Too Big and fragmentation needed for what does not fit) and the MSS clamp follow it
  when the tunnel comes up or its peer moves to the other family. A given `mtu` stays.
- **Mixed candidates.** A tunnel may have candidates of both families. Each round checks all of
  them alike, in order; the first answer brings it up over its family, and a later answer from
  another candidate does not move it (an answer only says a check got through). Once up, the
  peer's own checks and data move it, to an endpoint of either family, as after a NAT
  rebinding (`tunnel-roamed`), and the MTU follows. There is no preference between families
  and no racing of them (Happy Eyeballs): a controller that wants one family gives candidates of
  that family only.

## What the router does

A tunnel is `idle` (nothing to probe), `probing`, `up` or `failed`.

- **Candidates** are endpoints where the peer may be, of either family: its `peer` setting, `tunnel-peer`
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
- **Roaming**: once up, any check or data packet with the tunnel's id from another endpoint
  (of either family) moves the peer there (`tunnel-roamed {tunnel, from, to}`); an answer does
  not (it only says one of the round's checks got through, [mixed
  candidates](#the-outer-family)). That is how a tunnel survives a NAT that gave the peer a new
  mapping (`tests/tunnel.rs`, a NAT rebinding). The id is not a credential, so anyone who can send to the tunnel's port can also steer a keyless
  tunnel; a keyed one moves only for its peer ([below](#keyed-tunnels)).
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

## Keyed tunnels

A tunnel with a `key` (64 hex digits: 32 bytes, the same at both ends) carries its data
encrypted and authenticated, and lets only a holder of the key be its peer or move it. The
controllers choose and hand out the key, by config (`tunnel.<name>.key`), in `tunnel-add` (`key
<hex>`) and with `tunnel-key <name> <hex>` on a live tunnel; the router never invents,
negotiates or prints one (answers and events name a key by its id: 8 hex digits derived from
it). Agreeing on a key is the controllers' signalling, as pairing already is. A keyed tunnel's
defaults are UDP port **4500** and MTU **1438**; everything else (probing, keepalives, roaming,
liveness, the reflexive endpoint, relays, the packet filter) works as without a key, on
authenticated messages only.

### The wire format: ESP in UDP

Data is [ESP](https://www.rfc-editor.org/rfc/rfc4303) (RFC 4303) in UDP
([RFC 3948](https://www.rfc-editor.org/rfc/rfc3948)), tunnel mode, with
[ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc7634) (RFC 7634), manually keyed:

```text
outer IPv4 (20) or IPv6 (40) | UDP (8): port 4500 by default |
SPI (4, top bit set) | sequence number (4) | IV (8: the sequence number, zero-extended) |
encrypted: inner packet | padding 1, 2, 3 (to a multiple of 4) | pad length | next header 4 or 41 |
ICV (16: the Poly1305 tag)
```

The nonce is the SA's 4-byte salt and the IV; the additional data is the SPI and the sequence
number (no extended sequence numbers). The receiver checks the sequence number against a
128-packet anti-replay window before it decrypts and records it only once the tag checked;
padding and next header must be what RFC 4303 sends. A sequence number is never reused: an SA
that has sent 2^32 - 1 packets sends no more (`tunnel-key-exhausted`) until the controller
replaces the key. Overhead: 20 + 8 + 34 = 62 bytes over IPv4, 82 over IPv6 (plus up to 3 bytes
of padding), so the default MTU is 1500 - 62 = 1438 or 1500 - 82 = 1418, lengths that need no
padding, and the MSS clamp follows it (1378 and 1358 for IPv6 inside, 1398 and 1378 for IPv4).

Checks stay STUN on the same port, signed: a keyed tunnel's check and its answer carry
`TUNNEL-SA` (a comprehension-optional attribute of this library's own, `0xC0E5`, not registered
with IANA: the sender's inbound SPI and its epoch) and then `MESSAGE-INTEGRITY-SHA256` (RFC 8489
§14.6, the whole 32-byte HMAC-SHA256) under a short-term password derived from the key.
Attributes after the integrity attribute are ignored, as RFC 8489 asks. Reflexive queries (a
Binding request without `USERNAME`) and their answers stay unsigned: they say only what a STUN
server says to anyone.

The three formats share a port without confusion: STUN has its two top bits clear and the magic
cookie, Geneve has version 0 (its first byte below 0x40), and every SPI here has its top bit set.

**Why ESP, not a record inside Geneve, and not WireGuard.** This library's premise is real
protocols on real bytes that a capture tool decodes. Three choices were weighed:

- *An AEAD record inside the existing Geneve framing* would be the smallest change, but an
  invented format: a capture would show a Geneve header followed by bytes no tool decodes, and
  the replay and key rules would be ours alone.
- *WireGuard's transport data message* (type 4, receiver index, counter, ChaCha20-Poly1305) is
  standard on the wire and Wireshark decodes its header, but its keys come from its Noise
  handshake: without the handshake, which this design leaves to the controller, a tool can
  neither derive nor take the keys, and a WireGuard peer could not talk to it anyway.
- *ESP in UDP with RFC 7634* is the IPsec format with manual keys, a case RFC 4301 and every
  IPsec stack know (`ip xfrm state add ... aead rfc7539esp(chacha20,poly1305)`): the header, the
  replay window, padding and next header are RFC 4303's, the cipher's use is RFC 7634's,
  checked here against RFC 7634's own example. Its cost: 8 more bytes than WireGuard's header
  and a 4-byte alignment.

So ESP. **What a capture tool shows**, from Wireshark's source as of 2026-11 (its
`epan/dissectors/packet-ipsec-udp.c` and `packet-ipsec.c`; not tried on a capture of this
library): the `udpencap` dissector, registered on UDP 4500, calls a single 0xFF byte a NAT
keepalive, a payload whose first four bytes are zero IKE (the non-ESP marker), and anything else
ESP. So every keyed data packet is shown as ESP with its SPI and sequence number, and so are the
STUN checks on that port (their first four bytes are not zero) unless "Decode As" says STUN. A
keyed tunnel on another port needs "Decode As" UDPENCAP.

**Decrypting a capture.** Wireshark's ESP protocol preferences have "Attempt to detect/decode
encrypted ESP payloads" and the "ESP SAs" table (columns Protocol, Src IP, Dest IP, SPI,
Encryption, Encryption Key, Authentication, Authentication Key, SN, ESN High Bits), whose
Encryption choices include "ChaCha20 with Poly1305 [RFC7634]": its key is 36 bytes, the key and
then the 4-byte salt, and its nonce the salt and the packet's 8-byte IV, which is this format.
One SA row per direction: the outer addresses, the SPI, that algorithm and the 36 bytes, the SN
32-bit. The keys per direction come from the tunnel key (below), and everything else they need
is in the capture: each signed check's `TUNNEL-SA` (in the clear) gives its sender's SPI and
epoch, and a direction's 36 bytes are HKDF(tunnel key, `esp`, receiver's SPI, sender's epoch).
This library prints no key and has no tool that derives them yet.

### Keys, directions and epochs

The tunnel key is never used directly. Everything comes from HKDF-SHA256 (RFC 5869) with the
salt `wasmnet-tunnel-1` and a label per use (`components/router/src/tunnel/key.rs`):

| label | gives |
|---|---|
| `stun-password` | 32 bytes, written as 64 hex digits: the STUN password, so its bytes are the HMAC key |
| `spi`, the end's epoch, its transit address | the SPI the end receives on (top bit set) |
| `esp`, the receiver's SPI, the sender's epoch | 36 bytes: the key and salt of that direction |
| `key-id` | 4 bytes: the key's id in answers and events |

An end's **epoch** is the instant (virtual nanoseconds) its current key was set: at
`tunnel-add`, at a restart, at `tunnel-key`. Each signed check tells the peer the sender's SPI
and epoch, so each end knows which SA to send under and which to open with. Because a
direction's keys depend on the receiver's SPI and the sender's epoch, the two directions have
different keys (a packet reflected back to its sender does not open), and an end that restarts
or takes a new key starts fresh SAs with fresh sequence numbers and windows (its earlier
packets no longer open). No randomness is involved: counters, epochs and HKDF make every byte a
function of the key and virtual time.

**What counts as hearing the peer.** Only a check that checks under the current (or previous)
key, carries a `TUNNEL-SA` that is not the end's own (reflected) or older than the peer's
latest epoch (stale), and whose check counter is above the last one seen in that epoch (a
replay); only an answer that checks and answers one of the last 16 checks this end sent, each
once; only an ESP packet that opens and is not a replay. Each of these may bring the tunnel up
or move its peer (a NAT rebinding moves it on the next authenticated packet). Everything else
is refused, counted (`tunnel-<name>-auth-failed`, replays also in `-replayed`) and journalled
as `tunnel-auth-failed {tunnel, from, reason}`, once per reason until the tunnel comes up or
changes its key. The reasons: `unsigned` (no integrity, or no `TUNNEL-SA`), `integrity` (another
key, or altered), `keyed-peer` (a signed check reached a keyless tunnel), `cleartext` (Geneve
data for a keyed tunnel), `reflected`, `stale`, `replayed`, `unexpected` (an answer to nothing
outstanding), `no-sa` (ESP before the peer's SA is known), `esp` (it does not open). A refused
check gets no answer. A keyed tunnel never falls back to cleartext, and a keyed end and a
keyless end never come up together: each refuses the other, and says so.

**Replacing a key** (`tunnel-key <name> <hex>`): the new key is current at once, with a new
epoch and SPI, and the next check (at once to an up peer) is signed with it; the old one stays
*previous*, still accepted and still used to send, until the peer proves it holds the new key
(an authenticated message under it: `tunnel-key-confirmed`) or `dead` has passed
(`tunnel-key-retired`). So two controllers that replace the key within `dead` of each other
keep the tunnel up with no lost packet on in-order links; a packet sent under the old key that
arrives after the new one was confirmed is dropped (its SPI is gone, so the router counts it in
`tunnel-unknown-id`), which only a reordering path can show. Events: `tunnel-key-replaced {tunnel,
key, previous}`, `tunnel-key-confirmed {tunnel, key, previous}`, `tunnel-key-retired {tunnel,
key}`, all by id. How a controller learns that its peer moved on is its own business:
`crates/wasmnet-host/tests/tunnel.rs` has one controller replace its box's key on a timer and
the other on its box's first `tunnel-auth-failed`.

### What a key protects, and what it does not

Against an attacker on the path between the ends (it can read, drop, delay, replay, reorder and
inject outer packets, and send from any address):

- it cannot read or change what the tunnel carries, nor inject a packet into it: data is
  ChaCha20-Poly1305 under per-direction keys, checked before anything is used;
- it cannot replay data (the window) or checks (the counter per epoch), nor reflect either back;
- it cannot bring a tunnel up, move its peer to an address of its choice, or get an answer to a
  check: all three need a message signed under the key, and a captured one is refused as a
  replay;
- it learns from a keyed tunnel only what a keyless STUN server tells anyone: a Binding request
  without `USERNAME` is answered with the requester's own endpoint, as before.

It can still:

- drop or delay packets, and so take the tunnel down (`dead`) or keep it from coming up;
- see the outer addresses and ports, the SPIs, sequence numbers, packet sizes and timing, the
  tunnel id (STUN `USERNAME`), and when keys change;
- forge answers to reflexive queries (unsigned, as a STUN server's are), feeding a controller a
  wrong reflexive endpoint;
- learn about the inner traffic from a relay, which decrypts and re-encrypts: a relay holds both
  pairs' keys and sees the inner packets.

And the design has limits of its own: **no forward secrecy** (whoever learns a key can read
everything captured under it, before and after) and **no rekeying of its own** (the controller
replaces the key; nothing limits a key's age or volume except the 2^32 - 1 packets per SA); the
key derivation, the epoch scheme and the signed checks are this library's own composition of
standard parts, and **have had no outside review**. Within the simulation the key is in the
network's description and in the controllers' calls like any other configuration; it never
leaves through the router's answers, events or counters.

The primitives come from RustCrypto's pure-Rust, `no_std` crates, pinned exactly in the
workspace manifest and used only by the router: `chacha20poly1305` 0.10.1, `hkdf` 0.12.4,
`hmac` 0.12.1 and `sha2` 0.10 (`sha1` 0.10.7 only in its tests, for RFC 5769's vectors). Tags
and HMACs are compared through the crates' constant-time APIs.

## What a controller does

The router keeps a tunnel; a controller decides which tunnels exist and where traffic goes:

| controller | router |
|---|---|
| tunnel ids and transit addresses | encapsulation, decapsulation, MSS clamping |
| `tunnel-add` and `tunnel-remove` | checks, keepalives, liveness, roaming |
| keys: choosing one, giving it to both ends, `tunnel-key` to replace it | encryption, signing, replay protection, the previous key until the peer has the new one |
| signaling: read its tunnel's reflexive endpoint (`tunnels`), hand it to the peer's controller, which gives it to its own tunnel with `tunnel-peer` | the reflexive endpoint, from reflectors and from the peer |
| route choice: a shared LAN, a direct tunnel or a relay's; `route-replace` when a tunnel fails or comes up | routes as programmed |
| which router relays | nothing: a relay is a router |

The router has no rendezvous of its own: how two controllers find each other is theirs (a
replicated table, a server, a script). Any router with an address both sides reach can tell a
tunnel its reflexive endpoint (its `stun-server`, or any tunnel port), which is all a
rendezvous must do here.

The `tunnels` answer is meant to be parsed: one line per tunnel, by name, the name and then
`<key> <value>` pairs in a fixed order (`id`, `udp`, `local`, `state`, `peer`, `reflexive`,
`candidates`, `tx-packets`, `rx-packets`, and `key` with its id for a keyed tunnel); later
versions may append pairs, never reorder them.
An embedder sends the commands with `Network::command` (or as operator events) and reads their
answers; an in-world controller sends them with `wasmnet:infra/devices.control` and reads the
answer with `devices.control-answer` once the command has run.
`crates/wasmnet-host/tests/tunnel.rs` has two such controllers (the `infra-script` fixture),
one per home: each creates its box router, adds the tunnel, reads its reflexive endpoint from
`tunnels`, gives the tunnel the peer's endpoint, and adds the route once `tunnels` says `state
up`. What carries one controller's endpoint to the other is the embedder's business; in the
test the harness reads it from one controller's journal and sets it on the other with a
command, where a real embedder would use its own replicated state or a message over the network.

**Following a tunnel's state without polling.** The router journals `tunnel-reflexive
{tunnel, endpoint, from}`, `tunnel-up {tunnel, peer, after-ns}`, `tunnel-roamed {tunnel, from,
to}`, `tunnel-down {tunnel, peer, silent-ns}` and `tunnel-failed {tunnel, rounds, candidates}`
as they happen. `tunnel-reflexive` is how a controller that follows its router's events learns the
tunnel's reflexive endpoint without asking: its `endpoint` is what `tunnels` would list as
`reflexive`, journalled when it changes (the tests below still ask `tunnels` once, because the
`infra-script` fixture cannot carry an event's field to another controller).
A controller that created the router reads them with `wasmnet:infra/events.read` and waits for
them with `changes.wait-any` (an async controller) or `events.arm` (a stepped one), filtered to
`tunnel-*` so the router's other events (`route-lookup`, `route-added`) do not wake it
([topology-and-infra.md](topology-and-infra.md#events-of-the-devices-a-controller-created)).
It wakes in the instant the router changed state, at the same position on every replay, and
reacts there: `tunnel-up` with a route over the tunnel, `tunnel-down` or `tunnel-failed` with a
route over a relay or none (`routes-replace` with the whole static table, so the reaction is the
same whatever came before). A reader that fell behind (`missed` not 0: the router's events
overflowed the ring) asks `tunnels` once and goes on from there. The core keeps a router's events
for a controller only if that controller created it; a router the embedder built is followed by
the embedder, from the journal. `crates/wasmnet-host/tests/tunnel.rs`
(`controllers_follow_the_tunnel_s_events_through_a_cut_and_heal`) has two such controllers:
home B's Internet cable is cut from 3 s to 7 s, each tunnel goes down and comes back, and each
controller adds the route at each `tunnel-up` and removes it at the `tunnel-down`, in those
instants, with one `tunnels` command in the whole run (for the reflexive endpoint).

**A relay** is a router with one tunnel per relayed peer and a route per relayed prefix over
each. Its tunnels need no candidates: each learns its peer from the peer's first check. A box
that cannot punch through to another (both behind symmetric NATs) adds a tunnel to the relay
and its controller replaces the route to the other's prefix with one over that tunnel. The
relay forwards at layer 3, so the inner hop limit drops once more, and it sees the inner
packets in the clear.

## Determinism

The router draws no random numbers: transaction ids are the tunnel's id and a counter, a keyed
tunnel's nonces are sequence numbers and its keys come from HKDF of the key and its epoch (an
instant), timers run on the `now` it is given, candidates and tunnels are kept in order, and its next deadline
includes every tunnel's. The same commands at the same positions give the same packets.

A tunnel that is up sends keepalives forever, so a network with one never goes quiet: run it
with `run_until`.

## Limits and what is not covered

- At most 256 tunnels per router, 8 candidates and 8 reflectors per tunnel.
- No preference between outer families (no Happy Eyeballs): candidates of both are probed alike
  and the first answer wins ([below](#the-outer-family)).
- No path MTU discovery for the outer path: the tunnel MTU is configured, or the 1500-byte
  default of its family; an outer packet too big for a router on the way is lost there (its
  Packet Too Big or fragmentation needed is not acted on).
- No IPv6 translation (NAT66 or NPTv6): over IPv6 a box is reached at its own address, through
  whatever stateful filter its home router has.
- Commands are native only, like every device command ([known-issues.md](../known-issues.md)).
- No TURN-style relaying of outer datagrams, no WebRTC data channels.

- Keyed tunnels: no forward secrecy and no rekeying of their own (the controller replaces the
  key), no outside review; see [their threat model](#what-a-key-protects-and-what-it-does-not).

## Tests

- Inside wasmtime (`cargo test --target wasm32-wasip2 -p wasmnet-router`): the codecs against RFC
  5769's vectors and arbitrary bytes, ESP against RFC 7634's example and ChaCha20-Poly1305
  against RFC 8439's, HKDF against RFC 5869's first test case, STUN integrity against RFC
  5769's HMAC-SHA1 values, the replay window (late packets, the edge of the window, the top of
  the sequence space), and two keyed ends with an attacker between them (replays, reflection,
  forged and unsigned checks, a wrong key, a keyless peer, a key replaced, a restart), an outer
  IPv6 path through the whole router (both inner families in Geneve and in ESP, the MTU and the
  clamp per family, Packet Too Big at the tunnel port, a zero UDP checksum refused, mixed
  candidates, the `stun-server` and port unreachable over IPv6, endpoint parsing, arbitrary
  datagrams), MSS clamping, the state machine (probing, up, keepalive,
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
  Keyed: HTTP across a keyed tunnel through two NATs (ESP and signed STUN only between the homes), a wrong key and a keyed end
  facing a keyless one (neither comes up; both say why), a keyed relay behind symmetric NATs, an
  attacker on the Internet switch who replays ESP packets and checks, sends checks without the
  key and with a broken integrity (nothing injected, roamed or answered), two controllers that
  replace a live tunnel's key through `devices.control` (one on a timer, one on its box's
  `tunnel-auth-failed`) while fetches go on, the captures of a keyless tunnel pinned as they were
  before keys existed, and what the cryptography costs in fuel. Over IPv6
  (`crates/wasmnet-host/tests/tunnel6.rs`, the same way): HTTP for both inner families, keyless
  and keyed, with the clamp checked on the wire; two stateful home filters punched through; a
  tunnel whose candidates mix families coming up over the one that works. With
  `ipv4_inside_over_an_ipv4_tunnel_keyless_and_keyed` all four combinations of inner and outer
  family are covered.
