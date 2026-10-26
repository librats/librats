# librats Architecture

librats is a high-performance C++17 peer-to-peer networking library. It gives you
encrypted P2P connections, peer discovery (DHT, mDNS), NAT traversal, pub/sub
messaging, file transfer and more — exposed to C++, C, Node.js, Java, Python,
React Native, Android and iOS. This document explains the *shape* of the system: the layers, the key
classes, the threading model, and the one design rule that everything else
follows.

---

## Table of contents

1. [The one big idea](#1-the-one-big-idea)
2. [A 60-second mental model](#2-a-60-second-mental-model)
3. [Hello, librats (a real example)](#3-hello-librats-a-real-example)
4. [The layers, bottom to top](#4-the-layers-bottom-to-top)
   - [4.1 Core primitives](#41-core-primitives)
   - [4.2 Transport: reactors & connections](#42-transport-reactors--connections)
   - [4.3 The wire protocol](#43-the-wire-protocol)
   - [4.4 Security: identity & handshake](#44-security-identity--handshake)
   - [4.5 Identify: learning dialable addresses](#45-identify-learning-dialable-addresses)
   - [4.6 The Node facade](#46-the-node-facade)
   - [4.7 The peer directory](#47-the-peer-directory)
5. [The subsystem contract](#5-the-subsystem-contract)
6. [The subsystems](#6-the-subsystems)
7. [The threading model (read this twice)](#7-the-threading-model-read-this-twice)
8. [Lifecycle: attach → start → stop](#8-lifecycle-attach--start--stop)
9. [Language bindings](#9-language-bindings)
10. [Source layout](#10-source-layout)
11. [How to add a new feature](#11-how-to-add-a-new-feature)
12. [Glossary](#12-glossary)

---

## 1. The one big idea

**The `Node` core is small and feature-agnostic. Every capability is an opt-in
`Subsystem` that you attach before you start.**

A bare `Node`, out of the box, is *only*:

- an **encrypted transport** (Noise_XX) with a **self-certifying identity**, over
  **TCP or UDP** — both first-class, both on the same port,
- **manual dialing** (`connect(host, port)`) — it never finds peers on its own,
- a **peer table** with an admission limit,
- **raw channel messaging** (`send` / `broadcast` / `on("channel", …)`),
- connect/disconnect events and two small coordination buses.

That's it. DHT discovery, mDNS, GossipSub pub/sub, file transfer, ping/liveness,
NAT port mapping, automatic reconnection, peer exchange, typed JSON messaging,
distributed storage — **all of these are subsystems you add explicitly**:

```cpp
librats::NodeConfig config;
config.listen_port = 8080;
librats::Node node(config);

node.add_subsystem(std::make_unique<librats::PubSub>());            // pub/sub
node.add_subsystem(std::make_unique<librats::DhtDiscovery>(dht));   // discovery

node.start();   // attach BEFORE this line
```

Why build it this way? Because it keeps `Node` from becoming a god-class that
every feature reaches into. The core stays tiny and predictable, you pay only for
what you attach, and each feature can be developed, tested and reasoned about in
isolation. A subsystem never holds a `Node&` and is never a `friend` of `Node`;
it reaches the rest of the system only through three narrow interfaces (described
in [§5](#5-the-subsystem-contract)). If you remember nothing else from this
document, remember this paragraph.

---

## 2. A 60-second mental model

Think of librats as a stack of layers. Each layer only knows about the one below
it, and each is replaceable behind an interface.

```
   ┌─────────────────────────────────────────────────────────────┐
   │  Your application  /  C ABI  /  Node.js · Java · Python · …   │
   ├─────────────────────────────────────────────────────────────┤
   │  Subsystems (opt-in plugins)                                  │
   │    DhtDiscovery · MdnsDiscovery · PubSub · FileTransfer ·     │
   │    PingService · PortMappingService · HolePunch · Relay ·     │
   │    Rendezvous · ReconnectionService · PeerExchange ·          │
   │    MessageJson ·                                              │
   │    StorageManager · Bittorrent                                │
   ├───────────────┬─────────────────┬───────────────────────────┤
   │  ctx.network  │   ctx.events    │      ctx.services          │  ← the 3 contracts
   │ (PeerNetwork) │   (EventBus)    │   (ServiceRegistry)        │
   ├───────────────┴─────────────────┴───────────────────────────┤
   │  Node  — the thin facade that wires everything together       │
   ├─────────────────────────────────────────────────────────────┤
   │  Wire      : two-level framing + MessageRouter                │
   │  Security  : Identity · Handshaker · Session (Noise_XX)       │
   │  Transport : ReactorPool → Reactor(s) → Connection(s)         │
   │  Core      : sockets · IOPoller (epoll/kqueue/IOCP) · buffers │
   └─────────────────────────────────────────────────────────────┘
```

Data flows up and down this stack. Bytes arrive on a socket → a `Connection`
decrypts and parses them into a `Frame` → the `MessageRouter` dispatches the frame
to whichever subsystem (or application handler) owns it. Sending runs the same
path in reverse.

---

## 3. Hello, librats (a real example)

This is taken almost verbatim from the test suite — two nodes, one channel, an
encrypted echo:

```cpp
Node server(server_config());
Node client(client_config());          // client: enable_listen = false (dial-only)

// The server echoes whatever arrives on the "chat" channel back to the sender.
server.on("chat", [](const Peer& from, ByteView msg) {
    from.send("chat", msg);
});

client.on("chat", [](const Peer&, ByteView msg) {
    /* got the echo */
});

server.start();
client.start();

client.connect("127.0.0.1", server.listen_port());   // non-blocking dial
// ... once connected ...
client.send(server.local_id(), "chat", ByteView(std::string("hello node")));
```

Things to notice, because they are true everywhere in librats:

- **`connect` / `send` / `broadcast` are non-blocking and thread-safe.** They post
  work to the owning reactor and return immediately.
- **Handlers run on a reactor thread**, so you register them *before* `start()`.
- **A `Peer` handle is the reply path.** `from.send(...)` inside a handler reaches
  the right connection directly — no lookup, no peer id needed.
- The whole exchange is **encrypted end-to-end** and both sides have
  cryptographically **authenticated each other's identity** by the time the
  connection is up.

---

## 4. The layers, bottom to top

### 4.1 Core primitives

`src/librats/core/` is the foundation — small, dependency-free building blocks:

| Piece | Role |
|-------|------|
| `socket.h` | Thin cross-platform TCP/UDP socket wrappers. |
| `io_poller.h` | **The platform abstraction.** One interface over `epoll` (Linux), `kqueue` (macOS/BSD) and `IOCP` (Windows). Everything above it is platform-independent. |
| `bytes.h` | `Bytes` (owning buffer) and `ByteView` (non-owning span). `ByteView` is how librats passes payloads around **without copying**. |
| `receive_buffer.h` / `chained_send_buffer.h` | Per-connection RX/TX buffers. The send buffer is a chain of chunks so a shared broadcast payload isn't re-copied per peer. |
| `mpsc_queue.h` | Lock-free multi-producer/single-consumer queue — the *only* way other threads hand work to a reactor. |
| `timer_queue.h` | Timers (handshake timeouts, backoff) that ride the reactor's poll loop. |
| `notifier.h` / `wakeup_pipe.h` | How you wake a reactor that is blocked in `poll()`. |
| `event_bus.h` / `service_registry.h` | The two node-wide coordination buses (see [§5](#5-the-subsystem-contract)). |

### 4.2 Transport: reactors & connections

This is the heart of librats' performance, and it rests on one invariant:

> **A `Connection` is owned by exactly one `Reactor` and is only ever touched by
> that reactor's thread. It holds no locks and no atomics.**

This is the *shared-nothing* model. Because a connection lives behind a single
thread, the hot data path — read, decrypt, parse, encrypt, write — never contends
on a lock.

**`Connection` (`src/librats/transport/connection.{h,cpp}`)** is a per-peer state machine:

```
   Connecting ──▶ Handshaking ──▶ Established ──▶ Closing ──▶ Closed
   (link up)      (Noise / id)    (encrypted      (drain)
                                   frames flow)
```

- *Connecting* — an outbound connect is in flight (inbound connections skip this).
- *Handshaking* — a `Handshaker` runs to completion, producing a `Session` and the
  remote's authenticated `PeerId`.
- *Established* — messages flow both ways, sealed and opened by the transport.

The connection owns the lifecycle and the backpressure policy; its **transport**
does the work and reports back through `TransportSink`. It reports everything to
a `ConnectionDelegate` (which `Node` implements) and never touches the poller.

### Two transports behind one interface

Everything above the transport needs exactly one thing: a peer proven by the
handshake, and whole messages each way. That is what **`Transport`
(`src/librats/transport/transport.h`)** is — the handshake, the session keys and
nonces, the framing and the order queued messages leave in all live behind it —
and it is the one place the wires differ.

```
                      Connection  (lifecycle · backpressure)
                           │
                       Transport  ──  send / flush / on_readable / on_writable
                  ╱                         ╲
        StreamTransport                   UdpTransport ──▶ UdpConnection
   (blocks over a byte stream: Link)      (QUIC-shaped packets, on ONE socket
         ╱              ╲                  shared by every peer: UdpMux)
     TcpLink          RelayLink ──▶ Circuit
  (one kernel        (the stream borrowed from
   socket per peer)   another peer's connection)
```

- **`StreamTransport` (`stream_transport.{h,cpp}`)** runs over any ordered,
  reliable byte stream — a **`Link`** (`link.h`): length-prefixed blocks, the
  Noise handshake in the first few, then one `Session`-sealed message per block
  with implicit nonces. Messages wait unsealed in a `SendQueue` (one lane per
  `MessageType`, by priority) and are sealed only as the link takes them; TCP
  sockets get `TCP_NOTSENT_LOWAT` so the backlog stays where it can be reordered.
  - **`TcpLink`** is a thin translation of `recv`/`sendmsg`; the kernel provides
    the guarantees.
  - **`RelayLink` / `Circuit` (`relay_link.{h,cpp}`)** obtain the same byte stream
    from *another peer's connection* — `TransportKind::Relay`. `Circuit` holds the
    bytes in flight and the end-to-end credit window that bounds them; neither
    knows the relay protocol, which lives behind `CircuitCarrier` in
    `subsystems/relay.cpp`. The Noise handshake is end-to-end and the relay only
    ever moves ciphertext.
- **`UdpConnection` (`udp_connection.{h,cpp}`)** is the datagram transport: QUIC's
  shape on Noise, wire format in `udp_wire.h`. The handshake rides in long-header
  packets (the dialer's Initial *is* the first Noise message, padded so the
  responder may answer three times as much before the dialer proves its address);
  everything after is a short packet sealed on its own with its number as the
  nonce, its header masked. Messages travel on streams, one per lane, so a hole
  in one holds up only that one, and which lane goes next is decided as each
  packet is built. What is lost is re-sent as new frames in new packets.
  - **`Recovery` (`udp_recovery.{h,cpp}`)** is everything about packets: the sent
    log, RTT, RACK loss detection with its reorder timer, one reduction per loss
    episode (lasting until its repairs are through), probes before timeouts,
    proportional rate reduction for Reno, and the pacer — at the controller's
    rate, or below it at a ceiling the application set for the peer
    (`PeerNetwork::set_send_ceiling`: connections that share one uplink kept
    within it together; held by the ceiling, rate samples are app-limited, so
    the controller does not take it for the path). It never looks inside a
    packet: frames go back to the connection when their packet's fate is known.
  - **`SendStream` / `RecvStream` (`udp_streams.{h,cpp}`)** are byte-offset
    bookkeeping: what is owed again, what arrived out of order. Flow control is
    connection-wide (MAX_DATA / DATA_BLOCKED), the window auto-tuned; what is held
    out of order across all connections is bounded by one `UdpReceiveBudget`.
  - **`UdpMux` (`udp_mux.{h,cpp}`)** owns the single UDP socket, demultiplexes by
    the receiver's 64-bit connection id (they come in pairs, the dialer's even),
    admits inbound dials (address-validation tokens under load), answers packets
    for forgotten connections with stateless resets, drives every connection's
    timers from a deadline heap, and lingers a released connection until it has
    delivered what it owes. **`UdpTransport`** is the handle a `Connection` holds.

**Why UDP is the default first choice.** One socket for every peer means a NAT
holds *one* mapping rather than one per peer; the source port a peer observes is
the port it can dial back, which is the precondition for hole punching; and no
middlebox holds per-connection state that can be exhausted or timed out from
under us. TCP is an equal, not a legacy path — it is what the dialer falls back
to on networks that block or throttle UDP.

**`Dialer` (`src/librats/node/dialer.{h,cpp}`)** makes that a race rather than a guess,
in the spirit of Happy Eyeballs (RFC 8305): start the preferred transport, start
the other one too if the first has not established within
`NodeConfig::transport_fallback_ms`, keep whichever completes its handshake
first, close the rest, and report a failed dial exactly once per target. That is
why `Reactor::connect()` reserves and returns the `ConnId` synchronously — the
loser has to be cancellable.

**`Reactor` (`src/librats/transport/reactor.{h,cpp}`)** runs one thread driving an
`IOPoller`. Other threads interact with it *only* through:

- `post(task)` — enqueue a closure and wake the loop (from any thread);
- `execute(task)` — same, but run inline if already on the reactor thread;
- convenience wrappers `connect()`, `close()`, `broadcast()`, `schedule()`.

The single synchronization point is the **MPSC task queue** plus a wakeup pipe to
break the `poll()` wait. There are no other locks on the data path.

**`ReactorPool` (`src/librats/transport/reactor_pool.h`)** owns N reactors
(`NodeConfig::reactor_threads`, default **1** — which is plenty for thousands of
peers). Larger pools shard *outbound* connections round-robin across cores; each
connection is pinned to its reactor for life, so nothing on the data path changes
as the pool grows. Reactor 0 is the acceptor for inbound connections.

UDP is the deliberate exception to the round-robin: one shared socket means one
mux, so every datagram connection belongs to the reactor that owns it (reactor
0). Sharding those across threads would mean handing datagrams between reactors
on every packet, which costs more than the parallelism buys.

**Backpressure & deadlines** — two safety limits live here:

- Each connection has an **8 MiB send high-water mark**
  (`kDefaultSendHighWater`). A peer that can't keep up and pushes the send buffer
  past it is dropped with `CloseReason::SlowConsumer` — a slow consumer can never
  make the node run out of memory.
- A **15-second establish deadline** covers connect + handshake combined; a peer
  that stalls the handshake is reaped.

### 4.3 The wire protocol

The wire is **two levels** (`src/librats/wire/frame.h`). Separating them keeps encryption
clean.

**Level 1 — the outer block.** Everything on the wire is a length-prefixed frame:

```
   ┌──────────────┬───────────────────────────┐
   │ length (u32) │            body            │   body ≤ 64 MiB (kMaxBlockSize)
   └──────────────┴───────────────────────────┘
```

The body is opaque at this layer. During the handshake it's a raw handshake
message; once established it's the **`Session`-encrypted** bytes of an inner
message.

**Level 2 — the inner message.** After decryption, the body is:

```
   ┌──────┬───────┬─────────┬───────────────┐
   │ type │ flags │ channel │   payload …   │
   │  u8  │  u8   │   u16   │               │
   └──────┴───────┴─────────┴───────────────┘
```

Because the cipher wraps the *whole* inner message (the `type` byte included), the
block layer never has to understand the message — it just moves opaque bytes.
Decoding is **zero-copy**: the parsed `ByteView` points straight into the receive
buffer.

**`MessageType` is how traffic is routed.** Each value is effectively owned by one
subsystem. When you add a subsystem that needs its own traffic, you add a value
here:

| `MessageType` | Owner |
|---------------|-------|
| `App` (1) | application channel messaging (`node.on("channel", …)`) |
| `Control` (2) | core control plane — including the `identify` exchange |
| `Gossip` (3) | `PubSub` (GossipSub) |
| `FileChunk` (4) | `FileTransfer` |
| `Ping` (5) | `PingService` |
| `Storage` (6) | `StorageManager` |
| `Typed` (7) | `MessageJson` |
| `Pex` (8) | `PeerExchange` |
| `Punch` (9) | `HolePunch` (NAT hole-punch rendezvous, relayed peer→peer) |
| `Relay` (10) | `Relay` (relayed circuits: a peer's connection carried through a third node) |
| `Media` (11) | reserved for real-time media — live frames and their control plane; not a librats subsystem, claimed by an application such as ratcast's `MediaService` |
| `Rendezvous` (12) | `Rendezvous` (meeting under a key at a server, which introduces the peers) |

**`MessageRouter` (`src/librats/wire/message_router.h`)** does the dispatch. Non-`App`
frames go to the handler registered for their `MessageType`. `App` frames are
dispatched by their **channel**: the channel *name* is hashed (FNV-1a) to a stable
16-bit id, so the same name maps to the same id on every node with no shared
registry. `node.on("chat", …)` is just `App` traffic with `channel = id("chat")`.

> Note: DHT and mDNS are *not* in this table. They run their own separate
> protocols (Kademlia/KRPC over UDP, multicast DNS) and don't use the node's
> message bus at all — they only call `ctx.network.connect()` to feed discovered
> peers into the mesh.

### 4.4 Security: identity & handshake

Identity in librats is **self-certifying** — there is no PKI, no certificate
authority, no central registry.

- Every node has one static **Curve25519 keypair** (`Identity`, `security/identity.h`).
- Its **`PeerId` is the SHA-256 of its public key** (`peer/peer_id.h`).
- The Noise_XX handshake proves possession of the private key, so completing a
  handshake *proves* the remote's `PeerId`. Identity is cryptographically bound to
  the key and cannot be forged. (This is the same scheme libp2p uses.)

A `PeerId` is a cheap, hashable, ordered value type — it drops straight into an
`unordered_map` as a key.

Security is **pluggable** behind two interfaces (`security/handshaker.h`):

```
   SecurityProvider  ── create(role) ──▶  Handshaker  ── yields ──▶  Session
   (one per node:                          (one per                  (encrypt/
    keypair + policy)                       connection)               decrypt)
```

- A **`SecurityProvider`** holds the node's single keypair/policy and mints a fresh
  `Handshaker` for each new connection.
- A **`Handshaker`** is fed handshake blocks until it yields a `Session` + the
  remote `PeerId`, or fails. It is transport-agnostic — the `Connection` just
  shuttles its bytes.
- A **`Session`** (`security/session.h`) encrypts every outbound frame and
  decrypts every inbound one.

Swapping `NoiseSecurity` ⇄ `PlaintextSecurity` changes the entire security posture
without touching a line of transport code. Plaintext even supplies a *passthrough*
`Session`, so the `Connection`'s hot path is byte-for-byte identical whether or
not encryption is on — no `if (encrypted)` sprinkled through the code.

**Protocol binding.** Your app's protocol string (`NodeConfig::protocol`, e.g.
`"librats/1.0"`) is turned into a `protocol_id` blob and bound into the handshake
(as the Noise prologue). Two nodes whose protocol strings differ **cannot complete
a handshake** — a cheap, cryptographically enforced way to keep separate apps (or
app versions) from cross-connecting.

**Persistence.** Set `NodeConfig::data_dir` and the keypair is saved to
`identity.key`, giving the node a stable `PeerId` across restarts. Leave it empty
for an ephemeral identity (fresh random key each run).

### 4.5 Identify: learning dialable addresses

There's a subtle problem the socket can't solve: when a peer *dials in*, the
socket only tells you its *source* endpoint — its IP plus an ephemeral, OS-chosen
port. That's not the port it *listens* on, so you can't dial it back.

librats fixes this with the **identify** exchange (`src/librats/node/identify.{h,cpp}`).
Right after the handshake, each side sends a `Control` message carrying:

- its **`listen_port`** and self-advertised dialable **`addresses`**, and
- the **`observed`** address it saw the *other* side connecting from.

The receiver pairs the sender's reported listen port with the IP it actually sees
them at → a reconnectable address. The `observed` field also lets a node learn its
own public IP (surfaced via `Node::observed_addresses()`). The decoder is fully
bounds-checked: a hostile or malformed payload yields nothing, never misbehavior.

### 4.6 The Node facade

**`Node` (`src/librats/node/node.{h,cpp}`)** is the public entry point, and it is
deliberately *thin*. It owns the moving parts and wires them together, but the
logic lives in the layers, not here. Concretely, `Node`:

- owns the `ReactorPool`, the `SecurityProvider`, the `PeerTable`, the
  `MessageRouter`, the `EventBus` and the `ServiceRegistry`;
- **is** the `ConnectionDelegate` the reactors report to (`on_established`,
  `on_frame`, `on_closed`, `admit_inbound`);
- **is** the `PeerNetwork` that subsystems are handed (see below);
- exposes the small async API: `connect`, `send`, `broadcast`, `on`,
  `on_peer_connected`, `peers`, `add_subsystem`, `start`, `stop`.

`Node` never grows feature logic. A new capability becomes a subsystem; `Node`'s
surface stays the same. That restraint is the whole point.

### 4.7 The peer directory

**`PeerTable` (`src/librats/peer/peer_table.h`)** maps `PeerId → route + metadata`. It is
the *only* shared peer structure, and it is deliberately kept **off the per-byte
data path**: it's touched on connect/disconnect and on explicit by-id lookups
(`send`-by-id, `peers()`), never per frame. So it's read-mostly and guarded by a
`shared_mutex` with short critical sections.

It also resolves **duplicate connections** deterministically. When two peers dial
each other at the same time (a cross-connect), both compute the *same* winner from
a symmetric rule over their ids (`prefer_outbound`), so both converge on a single
link and the loser is torn down. An end that had already fired "connected" on the
loser may have sent on it what it says once per peer; that is lost with the link, so
the move fires `on_peer_rerouted`, for whoever said something on connect to say it
again (identify is sent again on the survivor by the node itself).

**`Peer` (`src/librats/peer/peer.h`)** is the lightweight handle passed to your callbacks.
It carries the peer's `id` *and* its `route` (which reactor + which connection), so
`peer.send(...)` reaches the right reactor directly with **no table lookup on the
reply path**. `peer.info()` consults the directory only when you actually ask for
metadata.

---

## 5. The subsystem contract

A subsystem reaches the rest of the node through exactly **three** narrow
interfaces, bundled into a `NodeContext` (`src/librats/node/node_context.h`) it receives at
`attach()`:

```cpp
struct NodeContext {
    PeerNetwork&     network;   // talk to peers
    EventBus&        events;    // "something happened"  (one → many, no return)
    ServiceRegistry& services;  // "do X / give me Y"    (one → one, with return)
};
```

**Rule of thumb:**

| You want to… | Use |
|--------------|-----|
| send/broadcast/connect, react to peer up/down, claim a `MessageType` | `ctx.network` |
| announce a fact others may react to (e.g. the network changed) | `ctx.events` |
| call a specific capability on a sibling module (and get a value back) | `ctx.services` |

**`PeerNetwork` (`src/librats/node/peer_network.h`)** — the *entire* contract a subsystem
has with the network: `send` / `broadcast` / `connect`, `on(MessageType, handler)`,
`peers()`, `connected_peers()`, and the `on_peer_connected` / `on_peer_disconnected`
/ `on_dial_failed` hooks. This is also exactly what you **mock in tests** — a
subsystem is tested against a fake `PeerNetwork`, with no real sockets.

**`EventBus` (`src/librats/core/event_bus.h`)** — typed, fire-and-forget pub/sub. A
publisher emits a value; every subscriber for that type runs. The publisher
neither knows nor names its subscribers (which is what stops modules from grabbing
references to each other):

```cpp
ctx.events.on<NetworkChanged>([](const NetworkChanged& e){ /* re-announce */ });
// elsewhere:
ctx.events.emit(NetworkChanged{addrs});   // all subscribers run
```

**`ServiceRegistry` (`src/librats/core/service_registry.h`)** — the targeted, *with a
return value* half. A module registers itself under a narrow capability
*interface*; another module resolves that interface and calls it directly, yet
never depends on the concrete type. `get<I>()` returns `nullptr` when no provider
is present, so callers degrade gracefully when a module is disabled:

```cpp
// provider (in attach):   ctx.services.provide<DhtService>(this);
// consumer (in start):    if (auto* dht = ctx.services.get<DhtService>()) dht->client()...
```

**The `Subsystem` interface itself is just three calls:**

```cpp
class Subsystem {
    virtual void attach(NodeContext& ctx) = 0;  // wire up: subscribe / provide / on(type,…)
    virtual void start() = 0;                    // spin up threads, announce, etc.
    virtual void stop()  = 0;                    // tear down (called in reverse order)
};
```

Subscribe to events, provide services and register message handlers during
`attach()` — before any reactor runs. This is the same "configure before `start()`"
rule the whole node follows.

---

## 6. The subsystems

Everything below is opt-in. Attach only what you need.

| Subsystem | What it does | Talks via |
|-----------|--------------|-----------|
| **`DhtDiscovery`** (`subsystems/dht_discovery.h`) | Peer discovery over a Kademlia DHT — announces the port peers are to dial under a discovery hash — over IPv4 the one the router forwards (`PortMapped`), else the one STUN sees the shared datagram socket at (asked from that socket, `ReflexiveAddressService`), else the listen port — and searches for peers, then dials them; one found again and not connected is punched (`DialProfile::punch()`) for two minutes after it was first found, so two nodes behind NATs that keep a port to every peer alike get through as their dials cross. Dual-stack IPv4/IPv6 (BEP 32). Compatible with the BitTorrent Mainline DHT. | own UDP/KRPC network; `network.connect()`; uses `DialService` + `ReflexiveAddressService`; publishes `DhtService` |
| **`MdnsDiscovery`** (`subsystems/mdns_discovery.h`) | Local-network discovery via multicast DNS. Advertises the node as an mDNS service (named from its `PeerId`) and browses for the same service type, dialing what it finds. | multicast DNS; `network.connect()` |
| **`PubSub`** (`subsystems/pubsub.h`) | A full **GossipSub** implementation: topic-based publish/subscribe with a per-topic mesh, eager forwarding, and lazy-pull recovery (IHAVE/IWANT). Runs its own heartbeat thread. | owns `MessageType::Gossip` |
| **`FileTransfer`** (`subsystems/file_transfer.h`) | Bidirectional file/directory streaming with per-chunk CRC32 + whole-file SHA-256, backpressure, pause/resume/cancel, offer/accept, atomic finalize (temp file → rename). | owns `MessageType::FileChunk` |
| **`PingService`** (`subsystems/ping_service.h`) | Liveness + RTT: periodically pings peers, who echo back, measuring round-trip time. | owns `MessageType::Ping` |
| **`PortMappingService`** (`subsystems/port_mapping_service.h`) | Auto-forwards the listen port through the home router via **UPnP IGD** and **NAT-PMP** (both, in parallel). Each mapping with a public address is told on the EventBus (`PortMapped`), for discovery to announce. | NAT protocols; reads `listen_port()`; emits `PortMapped` |
| **`HolePunch`** (`subsystems/hole_punch.h`) | UDP hole punching. Arranges through a shared peer that two NATed nodes dial each other at the same instant (the timing derived from the relayed round trip, as in DCUtR), so each side's outbound Initial opens the mapping the other's needs. The punch packet is the ordinary dial's Initial under a denser retry profile — no new wire format below the rendezvous. Published as `HolePunchService` so a discovery module can hand over an id it could not reach. | owns `MessageType::Punch`; uses `DialService` + `ExternalAddressService`; provides `HolePunchService` |
| **`Relay`** (`subsystems/relay.h`) | The last rung of the connectivity ladder. For a pair no punch can reach (a symmetric NAT, a network that drops UDP and blocks inbound TCP), the connection itself is carried through a node both ends already reach. What is relayed is a *byte stream* that becomes an ordinary `Connection` over `RelayLink`, so the Noise handshake is end-to-end and the relay moves ciphertext it cannot read. Serving other peers is **off by default** (`Config::serve`); a serving node says so to each peer as it connects (`Serving`), and is asked first — by a client probing for a way, and by `HolePunch` for its rendezvous; it forwards only between peers it already holds, never chains circuits, and caps each one by bytes, duration and count, with an end-to-end credit window bounding what a circuit can make it hold. Published as `RelayService` (`connect_via_relay`); a circuit that comes up asks `HolePunchService` to try for a direct link, which then supersedes the relayed one with no disconnect event. | owns `MessageType::Relay`; uses `CircuitService` + `HolePunchService` (optional); provides `RelayService` |
| **`ReconnectionService`** (`subsystems/reconnection.h`) | Re-dials dropped peers with exponential backoff; optionally persists targets (via `PeerBook`) so they survive a restart. With `lost_for`, a peer whose link was *lost* — closed by neither side: `IdleTimeout`, `PeerReset` — is dialed again at the addresses and endpoint it was last seen at until it is back or `lost_for` passes (`on_given_up`); a `NetworkChanged` starts those dials over at once. A stopping node says goodbye (an orderly CLOSE on UDP), so a peer that left is never taken for lost. | `network.peers()` + `on_dial_failed` + `on_peer_disconnected`'s reason; `NetworkChanged`; `network.connect()` |
| **`Rendezvous`** (`subsystems/rendezvous.h`) | Meeting at a public node, a server, under a key: two behind NATs that know of each other only by a key (a call's link) and share no peer. A serving node (`Config::serve`) says Hello to each peer; a peer registers its keys (SHA-256 of each) with every server — those of `Config::servers`, dialed and kept, and any that says Hello — and is answered with the others under the key, which are told of it in the same moment, each at the endpoint the server sees its UDP packets come from (`PeerInfo::endpoint`, the NAT's mapping of its shared socket) and the ones it identified itself with. Both sides then dial at once (`DialProfile::punch()`), timed by the server; one not connected after `punch_after` goes to `RelayService` — a circuit through the server, over which `HolePunch` tries for a direct link — or, without one, to `HolePunchService`. A server bounds keys per peer, peers per key, keys in all and registrations per second; a registration lasts while its connection does. | owns `MessageType::Rendezvous`; uses `DialService`, `RelayService` / `HolePunchService` (optional) |
| **`PeerExchange`** (`subsystems/peer_exchange.h`) | Pull-only **PEX**: on connect (and again when rerouted), asks a peer for a random sample of *its* peers and dials the new ones. Grows the mesh organically; rate-limited to avoid dial storms. With `introduce_requesters`, a node also names the asker to the peers its answer left out, so a small mesh closes when two join through one node at once. A PEX entry carries a peer's id *and* its address, so a dial that fails falls back to `HolePunchService` — the discovery half of hole punching. | owns `MessageType::Pex`; uses `HolePunchService` (optional) + `on_dial_failed` |
| **`MessageJson`** (`subsystems/message_json.h`) | Familiar `on` / `once` / `off` / `send` API for **typed JSON** messages, named by a type string; the authenticated sender is the handshake `PeerId`. | owns `MessageType::Typed` |
| **`StorageManager`** (`subsystems/../storage/storage.h`) | Distributed key-value store with typed values, **Last-Write-Wins** conflict resolution and on-disk persistence. Re-floods only when LWW is won, so epidemics terminate. A snapshot is a *stream*: the ordered key space is walked one bounded chunk at a time on the module's own thread, paced by `peer_writable()`, and a peer that fills up is owed a fresh snapshot rather than sent more entries — which is what keeps a database bigger than a send queue from costing the link. *(gated by `RATS_STORAGE`)* | owns `MessageType::Storage` |
| **`Bittorrent`** (`subsystems/bittorrent.h`) | BitTorrent client as a subsystem (magnets, torrent files, spider mode); can **share the node's DHT** instead of standing up a second one. *(gated by `RATS_SEARCH_FEATURES`)* | borrows `DhtService` |

Two of these illustrate the `ServiceRegistry` pattern nicely: `DhtDiscovery`
**provides** a `DhtService` (a handle to its DHT client), and `Bittorrent`
**resolves** it — so when both are attached, BitTorrent reuses the one DHT instead
of running its own. Disable `DhtDiscovery` and BitTorrent simply falls back; no
code changes, because the dependency is by interface and may be `nullptr`.

The only node-level event today is **`NetworkChanged`** (`src/librats/node/host_events.h`),
emitted (debounced) by the optional `NetworkMonitor` when the host's interfaces or
routes change — Wi-Fi↔cellular, VPN up/down, dock, wake-from-sleep. Long-lived
subsystems subscribe to it to renew port mappings and re-announce a public
endpoint that would otherwise go stale.

---

## 7. The threading model (read this twice)

Getting this right is the difference between code that works and code that
crashes under load. The rules:

1. **Every event callback runs on a reactor thread.** `on_peer_connected`,
   `on_peer_disconnected`, `on("channel", …)`, every `on(MessageType, …)` handler
   — all of them. So:
   - **Register them before `start()`.** After `start()` the reactors are live.
   - **Keep them non-blocking.** A handler that blocks stalls every other
     connection on that reactor. Offload heavy work to your subsystem's own thread.
   - **Don't assume which thread you're on** beyond "a reactor thread."

2. **`connect` / `send` / `broadcast` are non-blocking and thread-safe.** They post
   work to the owning reactor; you can call them from anywhere.

3. **Never touch a `Connection` from another thread.** It holds no locks precisely
   because only its reactor touches it. Cross-thread work enters a reactor *only*
   through `post()` / `execute()`.

4. **Don't add locks or blocking calls to the per-connection path.** The
   shared-nothing model is the performance story; honor it.

5. **A subsystem that needs to do periodic or blocking work runs its own thread**
   (PubSub's heartbeat, PingService's prober, ReconnectionService's redial loop,
   the NAT clients). They reach the network through the thread-safe `PeerNetwork`
   methods.

Where synchronization *does* exist, it's deliberate and narrow: the MPSC task
queue at the reactor boundary, the `shared_mutex` around the read-mostly
`PeerTable`, and the mutex inside the `EventBus`. None of it is on the per-byte
data path.

---

## 8. Lifecycle: attach → start → stop

```
   construct Node(config)         load identity, prepare layers — NO socket opened yet
        │
        ├─ add_subsystem(...)      attach order matters; returns a usable raw pointer
        ├─ on_peer_connected(...)  register callbacks
        ├─ on("channel", ...)
        │
   node.start()                    open listener → start reactor pool
        │                          → for each subsystem: attach(ctx) then start()
        │                          ── node is live; callbacks now fire ──
        │
   node.stop()                     stop subsystems in REVERSE attach order
                                   → close all connections → join reactors  (idempotent)
```

Two details that bite people:

- **Attach and register *before* `start()`.** Adding a subsystem or a handler after
  the reactors are running is a mistake (the C ABI even rejects it with
  `RATS_ERR_ALREADY_STARTED`).
- **Stop is reverse-order and idempotent.** Subsystems are torn down in the
  opposite of the order they were attached, so a dependency is never pulled out
  from under a dependent.

---

## 9. Language bindings

Everything non-C++ except React Native is built on one C ABI:
**`src/librats/bindings/rats.{h,cpp}`**.

- A `rats_t` is an opaque handle to one `Node`. `rats_create()` takes a
  `rats_config_t` in which zero is every field's default, so a zeroed struct (or
  `NULL`) is a complete config; a config no node could run with returns `NULL`.
- **Subsystems are opt-in via `rats_enable_*()`** calls made *before*
  `rats_start()` — `rats_enable_dht`, `rats_enable_mdns`,
  `rats_enable_peer_exchange`, `rats_enable_port_mapping`, `rats_enable_hole_punch`,
  `rats_enable_relay`, `rats_enable_pubsub`, `rats_enable_json`,
  `rats_enable_file_transfer`, `rats_enable_ping`, `rats_enable_reconnect`,
  `rats_enable_bittorrent`. This mirrors C++'s `add_subsystem`.
- **Error model:** fallible calls return a `rats_error_t` (`RATS_OK == 0`;
  non-zero is an error — e.g. `RATS_ERR_NOT_ENABLED`, `RATS_ERR_ALREADY_STARTED`,
  `RATS_ERR_NO_SUCH_PEER`). Pure getters return their value directly.
- **Threading is the same as C++:** callbacks fire on a reactor thread — don't
  block in them — and node callbacks must be registered before `rats_start()`.

The Node.js (`nodejs/`), Python (`python/`) and Java/Android (`android/`)
wrappers sit on top of this C ABI, and iOS (`ios/`) builds the core into an
`XCFramework` whose C ABI Swift imports directly. React Native
(`react-native/`) is the exception: one C++ Nitro Modules `HybridObject`, shared
by iOS and Android, that calls the C++ `Node` API itself. **The rule for
contributors:** when you add a public C++ capability that should be reachable
from other languages, surface it through this C API (typically as a
`rats_enable_*` plus a few calls) and keep the language wrappers in sync.

---

## 10. Source layout

The directory tree mirrors the layers in this document:

| Directory | Contents |
|-----------|----------|
| `src/librats/core` | sockets, buffers, `IOPoller`, MPSC/timer queues, `EventBus`, `ServiceRegistry` |
| `src/librats/wire` | two-level framing + `MessageRouter` |
| `src/librats/transport` | `ReactorPool`, `Reactor`, `Connection` state machine, the `Transport` interface: `StreamTransport` over a `Link` (`TcpLink`; `RelayLink` + `Circuit`) and the datagram transport (`UdpConnection` + `Recovery` + streams, `UdpMux`, `UdpTransport`) |
| `src/librats/security` | `Identity`, `Handshaker`/`Session`, Noise & plaintext providers |
| `src/librats/peer` | self-certifying `PeerId`, `PeerTable`, `Peer` handle |
| `src/librats/node` | the `Node` facade, `NodeContext`, `PeerNetwork`, the transport-choosing `Dialer`, identify, host events |
| `src/librats/subsystems` | the opt-in plugins |
| `src/librats/dht` | Kademlia + KRPC (bencode shared with BitTorrent) |
| `src/librats/mdns` | multicast DNS |
| `src/librats/nat` | STUN, UPnP, NAT-PMP |
| `src/librats/crypto` | hand-rolled curve25519 / chacha / poly1305 / blake2 / sha + the Noise framework |
| `src/librats/bittorrent` | BitTorrent (gated by `RATS_SEARCH_FEATURES`) |
| `src/librats/storage` | distributed KV store (gated by `RATS_STORAGE`) |
| `src/librats/bindings` | the C ABI all FFI bindings build on |
| `tests/` | GoogleTest suites — one `test_*.cpp` per area |
| `bench/` | benchmark suites (see `bench/README.md`) |
| `nodejs/`, `python/`, `android/`, `react-native/`, `ios/` | the language bindings and mobile packages (all over the C ABI except React Native, which uses the C++ API) |

---

## 11. How to add a new feature

The architecture is at its best when you extend it the way it expects. To add a
capability, **write a `Subsystem`** — don't touch `Node`:

1. **Create `src/librats/subsystems/your_thing.{h,cpp}`** with a class deriving from
   `Subsystem` (implement `attach` / `start` / `stop`).
2. **If it needs its own peer traffic, add a `MessageType`** to the enum in
   `wire/frame.h` and claim it in `attach()` with
   `ctx.network.on(MessageType::YourThing, handler)`. If it only needs the existing
   discovery/dialing, you may not need a new type at all.
3. **Wire up coordination in `attach()`** — subscribe to events you care about
   (`ctx.events.on<...>`), and `provide<>` / `get<>` any capability interface you
   expose or depend on.
4. **Do heavy or periodic work on your own thread**, reaching peers through the
   thread-safe `PeerNetwork` methods. Keep reactor-thread callbacks short.
5. **Register the test:** add a `tests/test_your_thing.cpp` *and* list it in the
   appropriate `TEST_SOURCES` block in `CMakeLists.txt` (there is no glob). Test
   against a mock `PeerNetwork` — no real sockets needed.
6. **If it should be reachable from other languages**, surface it through the C ABI
   (`src/librats/bindings/rats.{h,cpp}`) as a `rats_enable_*` and keep the wrappers in sync.

What **not** to do: don't widen `Node`'s public surface, don't make a subsystem
hold a `Node&` or become its `friend`, and don't add locks to the per-connection
path. If you find yourself wanting to, the design is telling you the work belongs
behind one of the three contracts instead.

---

## 12. Glossary

| Term | Meaning |
|------|---------|
| **Node** | The thin facade and public entry point; owns the layers, exposes the small async API. |
| **Subsystem** | An opt-in plugin (DHT, PubSub, …) attached before `start()`; reaches the node only via `NodeContext`. |
| **NodeContext** | The bundle (`network`, `events`, `services`) a subsystem gets at `attach()`. |
| **PeerNetwork** | The narrow network contract subsystems use; `Node` implements it; tests mock it. |
| **EventBus** | Typed fire-and-forget pub/sub for "something happened" (one → many). |
| **ServiceRegistry** | Interface-keyed lookup for "do X / give me Y" (one → one, with a return value). |
| **Reactor** | A single thread driving an `IOPoller`, owning a shard of connections with no locks. |
| **ReactorPool** | The set of reactors; shards connections across cores (default 1). |
| **Connection** | Per-peer state machine (Connecting → … → Closed); touched only by its reactor's thread. |
| **Frame** | A decoded inner message: a `FrameHeader` (`type`, `flags`, `channel`) + payload view. |
| **MessageType** | The inner `type` byte that routes a frame to its owning subsystem. |
| **MessageRouter** | Dispatches frames — `App` by channel id, everything else by `MessageType`. |
| **PeerId** | A peer's identity: SHA-256 of its static public key; self-certifying, unforgeable. |
| **Identity** | A node's static keypair + derived `PeerId`; persisted to `identity.key` if `data_dir` set. |
| **SecurityProvider / Handshaker / Session** | The pluggable security stack: node policy → per-connection handshake → per-connection cipher. |
| **identify** | The post-handshake `Control` exchange that teaches peers each other's dialable address. |
| **PeerTable** | The control-plane directory (`PeerId → route + metadata`), kept off the data path. |
| **Peer** | A lightweight handle (id + route) passed to callbacks; the zero-lookup reply path. |

---

*This document describes the architecture, not every API. For build options and the
full feature list see `README.md`; for the contributor-focused summary see
`CLAUDE.md`; for per-class detail, the header files carry thorough doc comments.*
