# The link model

A link is a point-to-point cable between two device ports. The patch panel
([crates/wasmnet-core/src/link.rs](../../crates/wasmnet-core/src/link.rs)) owns it: devices call
`wire.transmit`, and the panel decides when, and whether, the frame reaches the other end. It
never parses a frame beyond the length of its Ethernet header (for the MTU), and it never calls
into a device: it only queues a delivery.

A link has two **directions**, named by the sending end (0 = `a`, 1 = `b`, as in `LinkStats`).
Each direction has its own **impairments** (`Impairments`): a rate with a bounded transmit
queue, seeded loss and jitter. They default to off, and a link with none of them behaves exactly
as one without the feature: same deliveries, same keys, same captures, no random numbers drawn.

## What happens to one transmission

In order, for a frame transmitted on a wired Ethernet port at virtual time `now`:

1. **Operator rules and the transmit hook** may drop, replace or delay it
   ([event-order.md](event-order.md)). To keep two devices on one switch apart, or cut a
   segment into groups, the switch's own blocks are the simpler tool: a frame they stop never
   leaves the switch ([wit/switch/switch.wit](../../wit/switch/switch.wit)).
2. **Carrier and MTU.** On a down link it is dropped (`dropped_down`); with a payload over the
   link MTU it is dropped (`oversize`). Neither enters the wire.
3. **The transmit queue** (only while the direction's transmitter is busy). The transmitter
   serialises one frame at a time, in transmit order. A frame that finds it busy waits; if
   `queue` frames are already waiting, it is dropped at the tail (`dropped_queue`, fate
   `dropped` with reason `queue-full`). It never entered the wire: no capture record.
4. **Serialisation.** With a rate of `R` bits per second, a frame of `n` bytes occupies the
   transmitter for `ceil(n * 8 * 10^9 / R)` ns, from the moment it reaches the head of the queue
   (`start = max(now, the previous frame's finish)`). `n` is the frame as transmitted: Ethernet
   header and payload, no preamble, FCS or inter-frame gap. Without a rate, `finish = start`.
5. **Loss.** With a loss probability `p`, one draw decides whether the frame is lost on the
   wire. A lost frame entered the wire: it is captured outbound on the sender's interface,
   counted in `frames` and `bytes` and in `lost_random`, and its fate is `lost`. It still
   occupied the transmitter. Nothing is queued for it.
6. **Arrival** at `finish + latency + j + d`, where `j` is the jitter draw (uniform in
   `[0, jitter]` ns) and `d` an operator delay; with jitter, `finish + latency + j` is raised to
   the previous frame's arrival if it would come first. It is captured inbound on the
   receiver's interface when it arrives, unless the link went down meanwhile (then it is
   `lost`).

The capture's outbound timestamp is always `now`, the moment the device handed the frame to the
link (it entered the queue), so each capture stays in time order; the inbound timestamp is the
arrival of its last bit at the far end.

## The choices

- **Queue discipline: FIFO with tail drop, bounded in frames** (like a `pfifo` queue or a NIC's
  transmit ring), per direction. `queue` counts the frames waiting behind the one being
  serialised, so a frame that finds the transmitter idle is never dropped, whatever its size;
  `queue = 0` keeps no backlog at all. The default is `DEFAULT_QUEUE` (1000 frames, Linux's
  default `txqueuelen`). The queue matters only with a rate: without one the transmitter is never
  busy. A small queue is what TCP's congestion control has to live with: the netstack's Reno
  probes until the queue drops a frame and then halves its window, so a bulk transfer through
  a 4-frame queue at 10 Mbit/s keeps the link busy up to its last window
  ([netstack.md](netstack.md#tcp-congestion-control)).
- **Loss is Bernoulli per frame**, in parts per million (`loss_ppm`, 0 ..= 1 000 000), drawn
  for frames that passed the queue. Probability 0 and 1 draw nothing: 0 never loses, 1 always
  does.
- **Jitter is uniform in `[0, jitter]`** and comes on top of the latency, so a frame never
  arrives earlier than `finish + latency`. **Jitter never reorders a direction:** while a
  direction has jitter, each frame arrives no earlier than the frame transmitted before it on
  that direction (frames at one instant arrive in transmit order). A rate together with jitter
  means: the sender's queue and serialisation first, then a variable path delay; the jitter does
  not hold up the transmitter. Changing the latency or the jitter while frames are in flight can
  reorder them, as a latency change always could; an operator delay (a frame rule) can too.
- **A link going down** loses every frame in flight or waiting, and empties the queue: the
  transmitter is idle again from that instant.
- **Cables** (links of a registered cable kind) ignore impairments.

## Random numbers

Each direction draws from two streams of its own, one for loss and one for jitter, each a
`SimRng` seeded with `derive_seed(network seed, link name, "link-loss-<end>")` or
`"link-jitter-<end>"`. The link name is `<device>.<port>-<device>.<port>` (with a `-2`, `-3`, ...
suffix for the same ports wired again), so adding, removing or reordering other devices and
links does not shift a link's numbers. Every frame that passes the queue draws its jitter
(when the direction has jitter), lost or not, so changing a link's loss does not shift its
jitter. A stream is created on its first draw; a direction whose loss and jitter are off never
draws, and neither does a loss of 0 or 1 000 000 ppm.

## Setting them

- At build time: `LinkMut::impair(Impairments)` for both directions, or
  `LinkMut::impair_from(end, Impairments)` for one. `Impairments::rate`, `queue`, `loss_ppm` and
  `jitter` build a value: `Impairments::default().rate(10_000_000).queue(64)`.
- While the network runs (embedder surface, unstable): `Op::Impair { link, from, impairments }`
  by link id and `Op::ImpairNamed` by link name (a link an earlier op wires; journalled as
  `link-changed`). They apply to frames transmitted from then on; frames already queued keep
  their schedule.
- `LinkInfo::impairments` reads them back, per sending end; `LinkStats` counts `dropped_queue`
  and `lost_random` next to the other counters.
- The browser binding links with impairments through `wasmnet_web::Network::link_impaired`
  (the export `wn_link_impaired`).

## Split networks

Site sync ([sites.md](sites.md)) uses the smallest WAN-link latency as its lookahead: a frame
transmitted at `t` must not be due before `t + latency`. Impairments keep that promise. Queueing,
serialisation and jitter only add delay, and every decision (queue, loss, jitter) is made at
`wire.transmit`, on the sender's site, from the sending direction's own state and streams, so
each site decides exactly the frames it sends. A WAN link may therefore carry impairments, and a
split network with impaired links (site-local or crossing sites) gives the same records as the
unsplit one; `crates/wasmnet-host/tests/impairments.rs` checks this with real TCP over an
impaired WAN link and an impaired site-local link. Changing impairments while a split network
runs is an operator event, and split networks refuse those.

## Counters

`LinkStats` counts per sending end: `frames` and `bytes` that entered the wire, and the drops
and losses above. Each is counted at the instant it happened: everything at transmit, except
`lost` (a link that went down while the frame was in flight), counted at the instant the frame
would have arrived. Every count uses the whole frame, whatever the capture keeps.

- **As of now.** `Network::link_stats` reads the counters at the network's current position:
  between runs (`run_until`, a `run_stoppable` stop) that is every event processed so far, the
  current instant's included. Two reads subtracted (`LinkStats::since`) give the traffic of
  the interval between them, without parsing a capture; `LinkStats::add` sums.
- **Per interval.** A link can also keep a series: buckets of a fixed width, each the
  `LinkStats` counted in it (`LinkMut::series(SeriesOptions { width, keep })`, or
  `Network::set_series_defaults` for every link created from then on). Only buckets in which
  something was counted exist, and the link keeps the last `keep` of them, so its memory is
  bounded. `Network::link_series` returns `(bucket start, counters)`, oldest first; while no
  bucket was dropped, the buckets add up to `link_stats`. A series reads nothing and draws
  nothing: setting one changes no record.

## What a link records

Each Ethernet link keeps a capture (one pcap-ng file, two interfaces) and adds a record per
transmission to the network's frame log. `CaptureOptions` says what they keep, per link
(`LinkMut::capture`) or for every link created from then on, at build time or while the
network runs (`Network::set_capture_defaults`). The default keeps everything and names
nothing, so a network that sets no option records exactly the bytes it always did.

- **`snap_len`**: at most this many bytes of each frame (0: whole frames). The capture's
  interfaces carry it as their `snaplen`, and each packet keeps its original length (the
  Enhanced Packet Block's original length, which Wireshark shows as "frame length"). The frame
  log keeps the same first bytes in `FrameRecord::bytes`, with the frame's whole length in
  `FrameRecord::len`.
- **`record = false`**: no frame bytes at all. The capture is its header only (still a valid
  file), and the frame log keeps each transmission's record (link, ends, time, fate, length)
  with empty `bytes`. The records themselves remain: a link that records nothing still adds
  one fixed-size record per transmission.
- **`name_ends`**: the capture header names the link's two ends. Each interface's
  `if_description` is a `pcap::LinkEnd`, in the format
  `wasmnet-link-end/1 link=<link> end=<a|b> device=<device> port=<port> peer-device=<device> peer-port=<port> created-at=<ns>`
  (values percent-encoded; `LinkEnd::parse` reads it, ignoring keys a later version adds). A
  device removed and added again gets new links with new names (`-2`, ...), but their captures
  name the same `device`, so a tool joins them by it and orders them by `created-at`. Off by
  default: it adds options to the header, so turning it on changes the capture's bytes.

Only the records change: devices get whole frames, counters count whole frames, and the
journal, the outcome and every device's costs are the same under every option
(`crates/wasmnet-host/tests/measure.rs`). Set the options before a link's first frame: its
header is written again then; once it holds a packet, only `record` still changes. Cables have
neither a capture nor a frame log, so the options do not concern them.
