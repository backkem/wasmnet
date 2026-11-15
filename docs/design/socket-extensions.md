# Sockets: exported by the netstack, extended beside WASI

## The netstack exports `wasi:sockets@0.3`

Apps are ordinary WASI 0.3 programs: they import `wasi:sockets@0.3.0` and `wasi:clocks@0.3.0`
exactly as they would on any WASI host. In wasmnet nothing on the host serves those sockets.
Instead the netstack component **exports the real `wasi:sockets` interfaces** itself, and a node
is the netstack plus its apps **composed with `wac`**: the netstack is instantiated once and its
exports satisfy every app's socket imports. A composed node therefore imports no
`wasi:sockets` at all, and its traffic can only leave as Ethernet frames on its link ports.

`stream<u8>` ends handed between sibling instances carry TCP data with backpressure, EOF and
reset. The netstack caps what it reads from an app at the free transmit space and removes bytes
from smoltcp only once the app has taken them, so the TCP window follows the app's reading speed.
A FIN maps to the end of a stream, an RST to `connection-reset`, and dropping a receive stream
shuts down the read side.

In WASI 0.3.0, TCP `listen`, `send` and `receive` are sync functions that return streams or
futures, so the work behind them runs inside the netstack's long-lived driver task (see
[async-under-virtual-time.md](async-under-virtual-time.md) and [netstack.md](netstack.md)).
How a node is composed is in [writing-an-app.md](writing-an-app.md).

## `wasmnet:sockets-ext`: what WASI 0.3 lacks

Some programs need options that WASI 0.3 leaves out: abortive close and `TCP_NODELAY`, the ICMP
errors about a UDP socket's datagrams (what `traceroute` reads through `IP_RECVERR`), IP
multicast and the list of interfaces (mDNS), and ICMP echo sockets (`ping` without raw sockets).
They live in a small package, `wasmnet:sockets-ext`, shaped so that each part could be upstreamed
to `wasi:sockets` or dropped later:

- **Freestanding functions that take a `borrow` of a `wasi:sockets` resource.** WIT cannot add
  methods to a foreign resource and does not need to.
- **The same component exports them**, at exactly the same `wasi:sockets` version as its
  `wasi:sockets/types` export: `wac` links an app's import to the netstack's export only when both
  name the same resource.
- **Apps import only what they call**, so a portable app can degrade when a provider (stock
  wasmtime, for example) has no extension.
- **POSIX semantics and `wasi:sockets` error codes**, one function per POSIX option.

ICMP echo sockets are the one exception: WASI has no ICMP socket to borrow, so `icmp` brings its
own resource, shaped like `udp-socket`.

The package ([wit/sockets-ext/sockets-ext.wit](../../wit/sockets-ext/sockets-ext.wit),
`wasmnet:sockets-ext@0.1.0`) has five interfaces:

| interface | what | POSIX analogue |
|---|---|---|
| `tcp` | `abort` (one RST now), `set-no-delay`, `get-no-delay` | `SO_LINGER {1, 0}`, `TCP_NODELAY` |
| `udp` | `set-recv-errors`, `receive-error`: the ICMP errors that quote a socket's own datagrams | `IP_RECVERR`, `recvmsg(MSG_ERRQUEUE)` |
| `multicast` | group join and leave, multicast hop limit, loopback, outgoing interface | `IP_ADD_MEMBERSHIP`, `IP_MULTICAST_TTL`, `IP_MULTICAST_LOOP`, `IP_MULTICAST_IF` and their IPv6 forms |
| `interfaces` | `list-interfaces`: the node's interfaces and their addresses | `getifaddrs`, `if_nameindex` |
| `icmp` | `icmp-socket`: echo requests and replies, with each reply's hop limit | unprivileged ping sockets |

The package only grows by adding interfaces and functions, so a newer provider serves older
importers; a composition can re-export an interface under an older version name when an importer
asks for one.
