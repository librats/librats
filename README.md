# 🐀 librats

<p align="center"><a href="https://github.com/DEgITx/librats"><img src="https://raw.githubusercontent.com/DEgITx/librats/master/docs/logo.png"></a></p>

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Release](https://img.shields.io/github/release/DEgITx/librats.svg)](https://github.com/DEgITx/librats/releases)
[![npm](https://img.shields.io/npm/v/librats.svg)](https://www.npmjs.com/package/librats)
[![vcpkg](https://img.shields.io/vcpkg/v/librats)](https://vcpkg.io/en/package/librats)

**A high-performance, lightweight peer-to-peer networking library with C++, C, Node.js, Java, Python, React Native, Android, and iOS support**

librats is a modern P2P networking library written in C++17, with bindings for C, Node.js, Java, Python, React Native, and Android, plus an iOS build of the core. It's designed to be fast and light enough for low-power and embedded devices, while staying simple to build on: you start with a tiny core and add exactly the features you need — nothing more.

**Official Website**: [https://librats.com](https://librats.com)

## Used By

Projects and companies building on librats:

<p align="center">
  <a href="https://github.com/librats/rats-search"><img alt="rats-search" height="48" src="https://raw.githubusercontent.com/DEgITx/rats-search/master/resources/rat-logo.png"></a>
  &nbsp;&nbsp;
  <a href="https://github.com/ultravnc/ultravnc-librats"><img alt="uvnc" height="48" src="https://uvnc.com/images/bg_logo2s.gif"></a>
  &nbsp;&nbsp;
  <a href="https://github.com/librats/rasync"><img alt="rasync" height="48" src="https://raw.githubusercontent.com/librats/rasync/master/docs/logo.png"></a>
</p>

<p align="center">
  <i>Using librats in production? <a href="https://github.com/DEgITx/librats/pulls">Open a PR</a> to add your logo here.</i>
</p>

## ✨ Key Features

### **Core**
- **Native C++17** implementation for maximum performance
- **Cross-platform** support (Windows, Linux, macOS, Android, iOS)
- **Shared-nothing reactor** transport — connections are sharded across reactor threads with no cross-thread locking on the hot path
- **TCP *and* UDP as equals** — the same encrypted protocol over either wire. The UDP transport is a full ordered/reliable stream (sequencing, selective acks, RTO, congestion + flow control) on one socket shared by all peers, which is what keeps a single NAT mapping open and makes hole punching possible. A dial tries UDP first and races TCP as fallback, so a UDP-hostile network still connects
- **Self-certifying identity**: every node has a Curve25519 keypair; its `PeerId` *is* its public key, so peers authenticate each other with no PKI or central authority
- **Stable identity persistence**: point a node at a `data_dir` and its keypair (and therefore its `PeerId`) survives restarts
- **Composable subsystems**: opt-in plugins attached to a `Node`; a bare node neither discovers peers nor reconnects on its own

### **Discovery & Networking**
- **DHT Discovery**: peer discovery over a Kademlia DHT, fully compatible with the **BitTorrent Mainline DHT** — the largest distributed hash table in the world, with **millions of active nodes** (IPv4 + IPv6 / BEP 32)
- **mDNS Discovery**: automatic local-network peer discovery with service advertisement
- **IPv4/IPv6 Dual Stack**: binds dual-stack by default, so a single node accepts both IPv4 and IPv6 peers
- **Peer Exchange (PEX)**: peers gossip known addresses to grow the mesh
- **Automatic Reconnection**: re-dials dropped peers with exponential backoff; targets persist to disk when a `data_dir` is set
- **Network-change awareness**: an optional monitor detects interface/route changes and notifies subsystems so they can re-announce and renew port mappings

### **Pub/Sub (GossipSub)**
- **Scalable publish-subscribe** with mesh networking
- **Topic-based communication** with per-topic subscriptions
- **Message validation**: configurable per-topic validators to accept/reject/ignore messages

### **I/O Multiplexing**
- **Platform-optimal polling** behind one abstraction:
  - **Linux** — `epoll` (O(1) per event)
  - **macOS/BSD** — `kqueue` (O(1) per event)
  - **Windows** — `IOCP` (true async completion, O(1) per event)

### **File Transfer**
- **Streaming transfers**: files streamed in order over the reliable peer connection — bounded memory regardless of file size
- **Directory transfer**: whole directory trees sent recursively as one transfer
- **Backpressure**: windowed flow control keeps the sender from outrunning the receiver
- **Integrity**: per-chunk CRC32 plus a whole-file SHA-256 verified before delivery
- **Atomic delivery**: data lands in a temp file and is renamed to its destination only after verification
- **Transfer control**: pause, resume, and cancel from either side, with real-time progress callbacks
- **Offer/Accept model**: incoming transfers are offered to the application, which accepts (with a destination) or rejects

### **Security**
- **Noise Protocol encryption** (Noise_XX): Curve25519 key exchange + ChaCha20-Poly1305 AEAD on every connection by default
- **Mutual authentication**: both peers prove possession of the private key behind their `PeerId`
- **Perfect forward secrecy**: per-session ephemeral keys
- **Protocol binding**: your app's `protocol` id (e.g. `"myapp/1.0"`) is bound into the handshake prologue, so nodes from different apps cryptographically cannot cross-connect
- **Plaintext option**: select `Security::Plaintext` for local debugging or trusted networks

### **NAT Traversal**
- **Automatic port forwarding**: built-in **UPnP IGD** and **NAT-PMP** — the `PortMappingService` asks the router to forward the listen port (for TCP *and* UDP, which share it) on startup (both backends run in parallel; whichever the router supports wins), so peers behind a NAT can accept inbound connections with zero manual configuration. Mappings are refreshed automatically and removed on `stop()`.
- **UDP hole punching**: when no port forwarding is possible, `HolePunch` reaches a peer behind a NAT by arranging — through a peer both sides already have — that the two dial each other at the same instant, so each side's outbound packet opens the mapping the other's needs. The rendezvous is timed from the round trip itself (no clock synchronisation), and the node learns the external endpoint to advertise from its own mesh rather than from a STUN server
- **Relaying**: for the pairs a punch cannot reach — a symmetric NAT, a network that drops UDP and blocks inbound TCP — `Relay` carries the connection itself through a node both ends already reach. It is a *byte stream* that is relayed, so the Noise handshake still runs end to end and the relay moves ciphertext it cannot read; a circuit that comes up then tries to upgrade itself to a direct link, and the swap costs the application nothing
- **NAT awareness**: several peers' independent views of the node's shared UDP socket say whether its mapping is stable enough to punch through at all (endpoint-independent) or per-destination (symmetric, where punching cannot work) — see `node.nat_status()`
- **STUN**: public-IP discovery used by the DHT (BEP-42 node-id derivation and external-address reporting)

### **Distributed Storage** (optional, requires `RATS_STORAGE`)
- **Key-value storage**: typed string / int64 / double / binary / JSON values
- **Automatic P2P synchronization** across connected peers via GossipSub
- **Last-Write-Wins (LWW)** conflict resolution based on timestamps
- **Disk persistence** with an efficient binary format
- **Change notifications** for local and remote updates

### **Multi-Language Support**
- **Native C++17**: core implementation with the full feature set
- **C API** (`bindings/rats.h`): clean opaque-pointer C ABI — the foundation for all FFI bindings
- **Node.js**: N-API native addon (`RatsNode`) with TypeScript definitions ([npm package](https://www.npmjs.com/package/librats))
- **Java/Android**: JNI wrapper with a high-level Java API (`com.librats.RatsNode`)
- **Python**: ctypes package with a Pythonic `RatsNode`
- **React Native**: [`react-native/`](react-native) — a [Nitro Modules](https://nitro.margelo.com) HybridObject implemented once in C++ and shared by iOS and Android, so there is no JNI bridge and no Swift wrapper to keep in sync. Covers messaging, peer events, file transfer and pub/sub
- **iOS**: [`ios/`](ios) — the core cross-compiles to an `XCFramework` (device + simulator) and Swift imports the C ABI directly as `import LibRats`, no shim needed

## 🚀 Quick Start

Everything in librats revolves around one idea: a small, predictable core (`Node`) plus **opt-in subsystems** you attach explicitly. A bare `Node` is just the secure transport — an encrypted channel (Noise_XX) with a self-certifying peer identity, manual dialing, and raw channel messaging. Everything else — discovery, pub/sub, typed messaging, file transfer, liveness, NAT port mapping, reconnection — is a `Subsystem` you add **before** `start()`. You pay only for what you attach, and the core stays small and easy to reason about.

```cpp
librats::NodeConfig config;
config.listen_port = 8080;
librats::Node node(config);

// attach only the capabilities you need
node.add_subsystem(std::make_unique<librats::PubSub>());
node.add_subsystem(std::make_unique<librats::DhtDiscovery>(dht_config));

node.start();
```

### Two transports, one API

A connection runs over **TCP or UDP**, and nothing above the transport can tell the difference: same framing, same Noise handshake, same guarantees. UDP is not a lossy shortcut here — librats implements ordered, reliable delivery with congestion and flow control on top of datagrams (sequencing, cumulative + selective acks, RFC 6298 retransmission timing, Reno congestion control).

Both are enabled by default and bind the **same port**, so one advertised address is dialable either way. A dial tries UDP first and races TCP alongside it if UDP has not come up within `transport_fallback_ms` — the first handshake to complete wins and the other is dropped.

UDP is the default first choice because it fits peer-to-peer better: every peer shares one socket, so a NAT holds **one** mapping instead of one per peer; the source port a peer sees is the port it can dial back, which is what makes hole punching possible at all; and no middlebox holds per-connection state that can be exhausted or timed out. TCP remains a first-class equal, and is what the fallback exists for — some networks block or throttle UDP outright.

```cpp
librats::NodeConfig config;
config.enable_tcp            = true;                          // both on by default
config.enable_udp            = true;
config.preferred_transport   = librats::TransportKind::Udp;   // tried first
config.transport_fallback_ms = 1200;                          // 0 = never fall back

librats::Node node(config);
node.start();

node.transports();                 // bitmask of what is actually running
node.peers()[0].transport;         // which wire this peer's link uses
```

The examples below use the C++ `Node` API. The equivalent C API (`rats_*`) is shown in the [C API](#c-api-bindingsratsh) section.

### 1. Basic P2P connection

```cpp
#include <librats/node/node.h>
#include <iostream>

using namespace librats;

int main() {
    NodeConfig config;
    config.listen_port = 8080;       // 0 = ephemeral
    config.bind_address = "::";      // dual-stack (IPv6 + IPv4-mapped); the default

    Node node(config);

    // Register events BEFORE start(). They run on a reactor thread.
    node.on_peer_connected([](const Peer& peer) {
        std::cout << "[+] peer connected: " << peer.id().short_hex() << "\n";
    });
    node.on("chat", [](const Peer& peer, ByteView data) {
        std::cout << peer.id().short_hex() << ": "
                  << std::string(reinterpret_cast<const char*>(data.data()), data.size()) << "\n";
    });

    if (!node.start()) {
        std::cerr << "failed to start node\n";
        return 1;
    }
    std::cout << "node " << node.local_id().short_hex()
              << " listening on " << node.listen_port() << "\n";

    // Dial another peer (non-blocking; connects asynchronously).
    node.connect("127.0.0.1", 8081);

    // Send raw bytes on a named channel to every connected peer.
    node.broadcast("chat", ByteView(std::string("Hello from librats!")));

    std::string line;
    while (std::getline(std::cin, line)) node.broadcast("chat", ByteView(line));

    node.stop();
    return 0;
}
```

### 2. Custom protocol & stable identity

```cpp
NodeConfig config;
config.listen_port = 8080;
config.protocol = "my_app/1.0";       // bound into the handshake — only peers with
                                      // the same protocol id can connect
config.data_dir = "./node-data";      // persist identity.key → stable PeerId across restarts

Node node(config);
node.start();

std::cout << "protocol: " << node.protocol() << "\n";
std::cout << "peer id:  " << node.local_id().to_hex() << "\n";
```

Two nodes whose `protocol` id differs cannot complete a handshake — a cheap, cryptographically-enforced way to keep separate apps (or app versions) from cross-connecting. The id is an opaque string compared for exact equality; by convention `"<name>/<version>"`. See [Private Network Formation](#private-network-formation).

### 3. Typed JSON messaging

Attach the `MessageJson` subsystem and reach it through `node.json()`.

```cpp
#include <librats/node/node.h>
#include <librats/subsystems/message_json.h>

Node node(NodeConfig{/*listen_port=*/8080});
node.add_subsystem(std::make_unique<MessageJson>());

// Handlers are additive and keyed by message type. `from` is the authenticated PeerId.
node.json()->on("chat", [](const PeerId& from, const librats::Json& data) {
    std::cout << "[chat] " << from.short_hex() << ": " << data.value("text", "") << "\n";
});

node.start();

// Broadcast / direct send.
node.json()->send("chat", librats::Json{{"text", "Hello, P2P chat!"}});
node.json()->send(some_peer_id, "chat", librats::Json{{"text", "private hi"}});
```

### 4. GossipSub publish-subscribe

```cpp
#include <librats/node/node.h>
#include <librats/subsystems/pubsub.h>

Node node(NodeConfig{8080});
auto* pubsub = node.add_subsystem(std::make_unique<PubSub>());

pubsub->subscribe("news", [](const PeerId& from, const std::string& topic, ByteView data) {
    std::cout << "[" << topic << "] " << from.short_hex() << ": "
              << std::string(reinterpret_cast<const char*>(data.data()), data.size()) << "\n";
});

node.start();

pubsub->publish("news", ByteView(std::string("Breaking: librats is awesome!")));

std::cout << "subscribers in 'news': " << pubsub->peers_for_topic("news").size() << "\n";
```

### 5. File and directory transfer

```cpp
#include <librats/node/node.h>
#include <librats/subsystems/file_transfer.h>

Node node(NodeConfig{8080});
auto* files = node.add_subsystem(std::make_unique<FileTransfer>("./downloads"));  // temp dir

// Incoming offers must be accepted (with a destination) or rejected.
files->on_offer([&](const FileTransfer::Offer& offer) {
    std::cout << "[file] offer from " << offer.from.short_hex() << ": " << offer.name
              << " (" << offer.size << " bytes)\n";
    if (offer.size < 100 * 1024 * 1024)
        files->accept(offer.from, offer.id, "./downloads/" + offer.name);
    else
        files->reject(offer.from, offer.id);
});
files->on_progress([](const FileTransfer::Progress& p) { /* p.bytes_transferred / p.total_bytes */ });
files->on_complete([](uint64_t id, bool ok, const std::string& path) {
    std::cout << "[file] transfer " << id << (ok ? " complete: " : " FAILED: ") << path << "\n";
});

node.start();

// Push a file / directory to a connected peer (returns a transfer id, 0 on failure).
uint64_t id  = files->send_file(peer_id, "my_file.txt");
uint64_t dir = files->send_directory(peer_id, "./my_folder");
// Control either side: files->pause(peer, id) / resume(...) / cancel(...)
```

### 6. Security

Encryption is **on by default** — every connection runs Noise_XX (Curve25519 + ChaCha20-Poly1305) with mutual authentication. There is nothing to enable.

```cpp
NodeConfig config;
config.listen_port = 8080;
config.security = NodeConfig::Security::Noise;   // default; Plaintext for trusted/debug nets
config.data_dir = "./node-data";                 // persist the Noise keypair → stable PeerId

Node node(config);
node.start();
// node.local_id() is the node's static public key — peers authenticate it during the handshake.
```

### 7. NAT traversal (UPnP / NAT-PMP)

Attach `PortMappingService` to forward the listen port automatically on startup. Both UPnP IGD and NAT-PMP are attempted in parallel; whichever the router supports wins. The mappings are refreshed automatically and removed on `stop()`.

The port is forwarded under **both protocols the node is listening on** — TCP *and* UDP, since both transports share one port. UDP matters most: it is the dialer's first choice, so a TCP-only mapping would leave inbound peers on the TCP fallback. A node configured with only one transport gets only that one mapped.

```cpp
#include <librats/node/node.h>
#include <librats/subsystems/port_mapping_service.h>

Node node(NodeConfig{8080});
auto* portmap = node.add_subsystem(std::make_unique<PortMappingService>());
node.start();

// Public endpoint as seen from outside the NAT (if a mapping succeeded).
// Each protocol is mapped independently; a router may accept one and refuse the other.
if (auto pub = portmap->mapped_public_address(PortMapProtocol::TCP))
    std::cout << "public tcp: " << pub->first << ":" << pub->second << "\n";
if (auto pub = portmap->mapped_public_address(PortMapProtocol::UDP))
    std::cout << "public udp: " << pub->first << ":" << pub->second << "\n";
```

Where the router forwards nothing — carrier-grade NAT, a locked-down office network, a router with UPnP off — `HolePunch` is the other half. Two peers that cannot be dialed can still reach each other if they dial *at the same moment*: each side's outbound packet opens the mapping the other side's needs. The moment is agreed through a peer both already have, and timed from that relayed round trip rather than from any clock.

```cpp
#include <librats/node/node.h>
#include <librats/subsystems/hole_punch.h>

Node node(config);
auto* punch = node.add_subsystem(std::make_unique<HolePunch>());
node.start();

// ... once connected to at least one datagram peer (that is where the node
// learns the external endpoint to advertise) ...

// What the mesh says about our own side of the NAT.
switch (node.nat_status().udp_mapping()) {
    case NatMapping::Open:                break;  // directly dialable; no punch needed
    case NatMapping::EndpointIndependent: break;  // punchable
    case NatMapping::EndpointDependent:   break;  // symmetric NAT — a relay is the only way
    case NatMapping::Unknown:             break;  // not enough independent observations yet
}

punch->punch(peer_id);   // non-blocking; success arrives as an ordinary peer-connected event
```

Every node involved must have the subsystem attached — including the one carrying the rendezvous, which forwards a few dozen bytes per punch and only ever to peers it already holds. The C ABI mirrors this as `rats_enable_hole_punch()` / `rats_punch_peer()` / `rats_nat_mapping()`.

Calling `punch()` by hand assumes you know *which* peer is unreachable — which is the discovery half of the problem, not the traversal half. Attach `PeerExchange` alongside and it answers that on its own: PEX learns peers as an id *plus* an address, and when that address will not dial (exactly what a NATed peer looks like) it hands the id to `HolePunchService`, the capability `HolePunch` publishes. Nothing to wire up — attach both and unreachable peers start getting punched:

```cpp
node.add_subsystem(std::make_unique<HolePunch>());     // provides HolePunchService
node.add_subsystem(std::make_unique<PeerExchange>());  // resolves it, if present
```

Some pairs cannot be punched at all: a symmetric NAT gives a fresh mapping per destination, so no endpoint either side can advertise is the one the other's packets would arrive on. `Relay` is the last rung — it routes the connection itself through a node both ends already reach.

The relayed thing is a **byte stream**, not a message, so it becomes an ordinary `Connection`: the Noise handshake runs **end to end** and the relay moves ciphertext it cannot read, cannot forge and cannot replay. Every subsystem — pub/sub, file transfer, PEX — works over a relayed peer without a line of its own, and `PeerInfo::transport` is the only thing that says the path is not direct.

```cpp
#include <librats/subsystems/relay.h>

Relay::Config relay_config;
relay_config.serve = true;   // ALSO carry other peers' connections — off by default

node.add_subsystem(std::make_unique<Relay>(relay_config));  // provides RelayService
node.add_subsystem(std::make_unique<HolePunch>());          // escalates to it on failure
```

Attach both and the ladder runs itself: a punch that cannot work hands the target to `RelayService`, and a circuit that comes up asks `HolePunchService` to try again — now that the two ends are peers they can arrange a punch over the very circuit carrying them. If it lands, the peer table prefers the direct link at *both* ends and swaps the route with no disconnect event, so the application never sees the seam.

Serving as a relay is opt-in because, unlike a hole-punch rendezvous, it spends real bandwidth on somebody else's traffic. A serving node is protected by an end-to-end credit window that bounds what one circuit can make it hold, by forwarding only between peers it already holds (it never dials and never resolves an address, so it cannot become an open reflector), by refusing to chain circuits, and by per-circuit byte and duration caps. The C ABI mirrors this as `rats_enable_relay()` / `rats_connect_via_relay()`.

### 8. Peer discovery (DHT + mDNS) and reconnection

```cpp
#include <librats/node/node.h>
#include <librats/subsystems/dht_discovery.h>
#include <librats/subsystems/mdns_discovery.h>
#include <librats/subsystems/reconnection.h>

NodeConfig config;
config.listen_port = 8080;
config.data_dir = "./node-data";
Node node(config);

// Wide-area discovery via the BitTorrent Mainline DHT (IPv4 + IPv6).
DhtDiscovery::Config dc;
dc.data_dir = config.data_dir;          // co-locate the routing tables with identity + peers
node.add_subsystem(std::make_unique<DhtDiscovery>(std::move(dc)));

// Local-network discovery.
node.add_subsystem(std::make_unique<MdnsDiscovery>());

// Auto-reconnect dropped peers with exponential backoff; persist targets to disk.
ReconnectionService::Config rc;
rc.store_path = config.data_dir + "/peers.txt";
rc.max_attempts = 10;
auto* reconnect = node.add_subsystem(std::make_unique<ReconnectionService>(rc));

node.start();
reconnect->add(Address{"203.0.113.7", 8080});   // keep this target connected
```

### 9. Liveness (RTT probing)

```cpp
#include <librats/subsystems/ping_service.h>

auto* ping = node.add_subsystem(std::make_unique<PingService>());
node.start();
// ...later:
if (auto rtt = ping->last_rtt(peer_id))
    std::cout << "rtt = " << rtt->count() << "ms\n";
```

### 10. Distributed storage (requires `RATS_STORAGE`)

```cpp
#include <librats/storage/storage.h>

auto* storage = node.add_subsystem(std::make_unique<StorageManager>());
node.start();

storage->put("greeting", "hello");   // replicated to connected peers (Last-Write-Wins)
if (auto v = storage->get_string("greeting")) std::cout << *v << "\n";
```

On connect the two sides exchange a full snapshot, streamed in bounded chunks
paced against each link's send queue, so a database far larger than that queue
syncs without the peer being dropped as a slow consumer. `StorageConfig` tunes
the two sizes that matter — `max_value_size` (1 MiB) and `sync_batch_bytes`
(256 KiB); both must stay under a quarter of `NodeConfig::send_queue_limit`, and
both are clamped to that assumption for the default 8 MiB queue.

## 📖 API Documentation

### `Node` — the entry point

`Node` (in `node/node.h`) owns the reactor pool, the security provider, the peer directory and the message router. `connect`/`send`/`broadcast` are non-blocking and thread-safe; event callbacks run on a reactor thread, so **register them before `start()`**.

```cpp
// Construction
explicit Node(NodeConfig config);

// Lifecycle
bool start();                  // open listener + reactors + subsystems; false if bind fails
void stop();                   // stop subsystems (reverse order), close connections, join

// Identity & protocol
const PeerId&      local_id() const;          // our self-certifying id (== public key)
uint16_t           listen_port() const;       // actual bound port (when config requested 0)
const std::string& protocol() const;          // app protocol id bound into the handshake

// Subsystems (attach BEFORE start(); the node owns them and returns a non-owning pointer)
template <class T> T* add_subsystem(std::unique_ptr<T> subsystem);
template <class T> T* subsystem();            // typed lookup, nullptr if not attached
MessageJson*          json();                 // shortcut for subsystem<MessageJson>()

// Connections
void   connect(const Address& address);
void   connect(const std::string& host, uint16_t port);
size_t peer_count() const;
std::vector<PeerInfo> peers() const;          // snapshot: id, addresses, direction
std::optional<Peer>   peer(const PeerId& id);
std::vector<Address>  observed_addresses() const;  // our addresses as peers report them

// Peer admission limit (0 = unlimited; guards inbound, not our own dials)
size_t max_peers() const;
void   set_max_peers(size_t n);
bool   peer_limit_reached() const;

// Messaging (raw bytes on a named channel)
void send(const PeerId& to, std::string_view channel, ByteView payload);
void broadcast(std::string_view channel, ByteView payload);

// Events (additive; run on a reactor thread)
void on_peer_connected(PeerEventHandler cb);     // (const Peer&)
void on_peer_disconnected(PeerDisconnectHandler cb);  // (const PeerId&)
void on(std::string_view channel, MessageRouter::Handler cb);  // (const Peer&, ByteView)

// Node-scoped coordination shared with subsystems
EventBus&        events();      // fire-and-forget, one→many (e.g. NetworkChanged)
ServiceRegistry& services();    // targeted capability lookup, one→one
```

### `NodeConfig`

```cpp
struct NodeConfig {
    uint16_t    listen_port = 0;            // 0 = ephemeral; ignored if !enable_listen
    bool        enable_listen = true;       // false = dial-only (no listener)
    std::string bind_address = "";          // "" / "::" dual-stack, "0.0.0.0", or an IP literal
    size_t      reactor_threads = 1;        // 1 handles thousands of peers; more shards cores
    size_t      max_peers = 0;              // 0 = unlimited (guards inbound only)
    enum class Security { Noise, Plaintext };
    Security    security = Security::Noise; // Noise_XX by default
    std::string protocol = "librats/1.0";   // app id bound into the handshake; must match to connect
    std::string data_dir = "";              // "" = ephemeral identity; else identity.key persists
    bool        enable_network_monitor = true;  // watch host network changes → NetworkChanged
};
```

### Subsystems

Each subsystem is attached with `node.add_subsystem(std::make_unique<T>(...))` **before** `start()`. A bare node has none of these.

| Subsystem | Header | What it adds |
|-----------|--------|--------------|
| `PubSub` | `subsystems/pubsub.h` | GossipSub topics: `subscribe` / `unsubscribe` / `publish`, per-topic validators |
| `MessageJson` | `subsystems/message_json.h` | Typed JSON messaging: `on` / `once` / `off` / `send`; reached via `node.json()` |
| `FileTransfer` | `subsystems/file_transfer.h` | Push file/dir transfer: `send_file` / `send_directory` / `accept` / `reject` / `pause` / `resume` / `cancel` |
| `DhtDiscovery` | `subsystems/dht_discovery.h` | Wide-area discovery over the BitTorrent Mainline DHT (IPv4 + IPv6) |
| `MdnsDiscovery` | `subsystems/mdns_discovery.h` | Local-network discovery + advertisement |
| `PingService` | `subsystems/ping_service.h` | Periodic liveness ping/pong + `last_rtt(id)` |
| `ReconnectionService` | `subsystems/reconnection.h` | Auto-reconnect with exponential backoff; persistent targets |
| `PortMappingService` | `subsystems/port_mapping_service.h` | UPnP IGD + NAT-PMP automatic port forwarding |
| `HolePunch` | `subsystems/hole_punch.h` | UDP hole punching: two NATed peers dial each other at the same instant, arranged through a peer they share |
| `Relay` | `subsystems/relay.h` | Last-resort connectivity: the connection itself is carried through a peer both ends reach, still encrypted end to end |
| `PeerExchange` | `subsystems/peer_exchange.h` | PEX: gossip known peer addresses to grow the mesh |
| `StorageManager` | `storage/storage.h` | Distributed key-value store (requires `RATS_STORAGE`) |

### C API (`bindings/rats.h`)

The canonical opaque-pointer C ABI — the foundation for every language binding. A `rats_t` wraps a `Node`. Fallible calls return `rats_error_t` (`RATS_OK == 0`); pure getters return their value directly. Subsystems are opt-in: enable each with the matching `rats_enable_*()` **before** `rats_start()`. Strings returned by the library are heap-allocated — free them with `rats_string_free()`.

```c
#include <librats/bindings/rats.h>
#include <stdio.h>

static void on_connected(void* user, const char* peer_id_hex) {
    printf("[+] connected: %s\n", peer_id_hex);
}
static void on_chat(void* user, const char* peer_id_hex, const void* data, size_t len) {
    printf("%s: %.*s\n", peer_id_hex, (int)len, (const char*)data);
}

int main(void) {
    rats_t node = rats_create(8080);

    rats_on_peer_connected(node, on_connected, NULL);
    rats_on(node, "chat", on_chat, NULL);

    rats_enable_pubsub(node);          // before start
    rats_enable_dht(node, 0, NULL);

    if (rats_start(node) != RATS_OK) return 1;

    rats_connect(node, "127.0.0.1", 8081);
    rats_broadcast(node, "chat", "hello", 5);

    /* ... run ... */
    rats_stop(node);
    rats_destroy(node);
    return 0;
}
```

Key entry points: `rats_create` / `rats_create_config` / `rats_config_default` / `rats_destroy`, `rats_start` / `rats_stop`, `rats_connect`, `rats_send` / `rats_broadcast`, `rats_on` / `rats_on_peer_connected` / `rats_on_peer_disconnected`, `rats_enable_{dht,mdns,pubsub,json,file_transfer,ping,reconnect,port_mapping}`, `rats_subscribe` / `rats_publish`, `rats_on_json` / `rats_send_json`, `rats_send_file` / `rats_accept_file`, `rats_peer_ids`, `rats_local_id`, `rats_protocol`, `rats_version` / `rats_version_string` / `rats_git_describe` / `rats_abi`, `rats_set_log_level` / `rats_set_log_file`.

## 🏢 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ Application                                                        │
│   composes a Node + exactly the subsystems it needs               │
├──────────────────────────────────────────────────────────────────┤
│ Subsystems (opt-in plugins attached to a Node)                    │
│ ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐       │
│ │  PubSub    │ │ MessageJson│ │ FileTransfer│ │ Reconnect  │      │
│ │ (GossipSub)│ │ (typed JSON)│ │  (push)    │ │  Service   │      │
│ └────────────┘ └────────────┘ └────────────┘ └────────────┘       │
│ ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐       │
│ │ DhtDiscovery│ │MdnsDiscovery│ │PingService │ │PortMapping │      │
│ │  (Mainline)│ │  (local)   │ │ (liveness) │ │UPnP/NAT-PMP │      │
│ └────────────┘ └────────────┘ └────────────┘ └────────────┘       │
│ ┌─────────────────────────┐ ┌─────────────────────────────┐       │
│ │ PeerExchange (PEX)       │ │ StorageManager (RATS_STORAGE)│     │
│ └─────────────────────────┘ └─────────────────────────────┘       │
├──────────────────────────────────────────────────────────────────┤
│ Node core                                                         │
│   peer directory · message router · EventBus · ServiceRegistry    │
├──────────────────────────────────────────────────────────────────┤
│ Security  — Noise_XX (Curve25519 + ChaCha20-Poly1305) / plaintext │
│             over a self-certifying PeerId                          │
├──────────────────────────────────────────────────────────────────┤
│ Transport — shared-nothing reactor pool, per-connection state      │
│             machine, length-prefixed wire framing                  │
├──────────────────────────────────────────────────────────────────┤
│ I/O multiplexing — epoll (Linux) · kqueue (macOS/BSD) · IOCP (Win) │
├──────────────────────────────────────────────────────────────────┤
│ Platform — WinSock2/bcrypt (Windows) · BSD sockets (Linux/macOS)   │
└──────────────────────────────────────────────────────────────────┘
```

The source tree mirrors these layers: `src/librats/core`, `src/librats/util`, `src/librats/wire`, `src/librats/transport`, `src/librats/peer`, `src/librats/security`, `src/librats/node`, `src/librats/subsystems`, `src/librats/dht`, `src/librats/mdns`, `src/librats/nat`, `src/librats/crypto`, `src/librats/bittorrent`, `src/librats/storage`, `src/librats/bindings`.

## Frequently Asked Questions (FAQ)

### Understanding DHT vs peer connections

**librats has two distinct peer systems that serve different purposes:**

| Layer | Protocol | Purpose | Where |
|-------|----------|---------|-------|
| **DHT layer** | UDP (Kademlia) | **Peer discovery** only | `DhtDiscovery` subsystem |
| **Peer connection layer** | TCP or UDP (Noise) | **Message exchange** | `Node` core: `peers()`, `send`, `broadcast` |

**Key points:**
- The **DHT routing table** is NOT your connected peers. It holds DHT nodes (often from the global BitTorrent Mainline DHT) that help you *discover* peers.
- **Peer connections** (`node.peers()`, `node.peer_count()`) are the actual authenticated connections used for communication — over TCP or over the reliable UDP transport, whichever the dial settled on.
- The DHT is for **discovery**, not message routing. For messaging, use the Node core (channels), `MessageJson`, or `PubSub`.

### Private Network Formation

To create a private overlay limited to your application's peers:

1. **Set a unique protocol id before starting:**

```cpp
NodeConfig config;
config.protocol = "my_private_app/1.0";
Node node(config);
node.add_subsystem(std::make_unique<DhtDiscovery>(dht_config));
node.start();   // discovery uses a hash derived from your protocol identity
```

2. **How it works:**
   - `DhtDiscovery` derives a discovery hash from your protocol identity and announces under it in the global DHT.
   - Only peers with the **same** `protocol` id discover each other — and even if a stranger dials you, the protocol identity is bound into the Noise handshake, so the connection cannot complete.
   - Once discovered, peers connect over the authenticated channel (UDP first, TCP as fallback) and grow the mesh via Peer Exchange.

3. **Discovery timing:**
   - DHT discovery is asynchronous — initial peers typically appear in 1–30 seconds.
   - For fast local testing, attach `MdnsDiscovery` instead (or as well).

## 🛠️ Building

### Supported Platforms & Language Bindings

#### Native C++ Support

| Platform | Build Environment | Compiler | Status |
|----------|------------------|----------|---------|
| **Windows** | MinGW-w64 | GCC 7+ | ✅ **Fully Supported** |
| **Windows** | Visual Studio | MSVC 2017+ | ✅ **Fully Supported** |
| **Linux** | Native | GCC 7+, Clang 5+ | ✅ **Fully Supported** |
| **macOS** | Xcode/Native | Clang 10+ | ✅ **Fully Supported** |
| **iOS** | Xcode + CMake | Clang 14+ | 🔶 **In Development** |

#### Language Bindings & Wrappers

| Language/Platform | Binding Type | Status | Notes |
|-------------------|--------------|--------|-------|
| **C/C++** | Native Library | ✅ **Fully Supported** | Core implementation with the full feature set |
| **Android (NDK)** | Native C++ | ✅ **Fully Supported** | Android NDK integration with JNI bindings |
| **Android (Java)** | JNI Wrapper | ✅ **Fully Supported** | High-level Java API for Android apps |
| **Node.js** | N-API Addon | ✅ **Fully Supported** | `RatsNode` + TypeScript definitions ([npm](https://www.npmjs.com/package/librats)) |
| **Python** | ctypes Package | ✅ **Fully Supported** | `RatsNode` with context-manager lifecycle |
| **React Native** | Nitro Modules (C++) | 🔶 **In Development** | One C++ HybridObject for both platforms ([`react-native/`](react-native)). Messaging, peer events, file transfer, pub/sub; no discovery yet. Verified on simulator + emulator |
| **iOS / Swift** | C ABI via modulemap | 🔶 **In Development** | `XCFramework` build of the core ([`ios/`](ios)); `import LibRats` reaches the C ABI directly. No idiomatic Swift wrapper yet |
| **Rust** | FFI Bindings | 📋 **Planned** | Safe bindings with tokio async support |
| **Go** | CGO Bindings | 📋 **Future** | CGO wrapper for Go applications |
| **C#/.NET** | P/Invoke | 📋 **Future** | .NET bindings for Windows/Linux/macOS |

**Legend:** ✅ Fully Supported · 🔶 In Development · 📋 Planned/Future/Research

### Prerequisites
- **CMake 3.10+**
- **C++17 compatible compiler**:
  - GCC 7+ (Linux, MinGW)
  - Clang 5+ (macOS, Linux)
  - MSVC 2017+ (Windows)
- **Git** (for dependency management)

### Building on Linux/macOS

```bash
git clone https://github.com/DEgITx/librats.git
cd librats
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Building on Windows

```powershell
git clone https://github.com/DEgITx/librats.git
cd librats
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

### Build Options

```bash
# Disable tests
cmake .. -DRATS_BUILD_TESTS=OFF

# Debug build with full logging
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Release build optimized for performance
cmake .. -DCMAKE_BUILD_TYPE=Release
```

### Complete Build Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `RATS_BUILD_TESTS` | `ON` | Build unit tests with GoogleTest |
| `RATS_BUILD_CLIENT` | `ON` | Build the `rats-client` reference/demo application |
| `RATS_BUILD_EXAMPLES` | `OFF` | Build the `examples/` programs |
| `RATS_ENABLE_ASAN` | `OFF` | Enable AddressSanitizer for memory debugging |
| `RATS_ENABLE_TSAN` | `OFF` | Enable ThreadSanitizer for data-race debugging |
| `RATS_BINDINGS` | `ON` | Build the C API bindings for FFI support |
| `RATS_CROSSCOMPILING` | `OFF` | Force cross-compilation flags |
| `RATS_SHARED_LIBRARY` | `OFF` | Build as shared library (.dll/.so/.dylib) |
| `RATS_STATIC_LIBRARY` | `ON` | Build as static library (.a/.lib) |
| `RATS_SEARCH_FEATURES` | `OFF` | Enable Rats Search features (BitTorrent / DHT spider) |
| `RATS_STORAGE` | `OFF` | Enable the distributed key-value storage subsystem |

**Examples:**

```bash
# Build as shared library without tests, client or examples
cmake .. -DRATS_SHARED_LIBRARY=ON -DRATS_STATIC_LIBRARY=OFF \
         -DRATS_BUILD_TESTS=OFF -DRATS_BUILD_CLIENT=OFF -DRATS_BUILD_EXAMPLES=OFF

# Build with BitTorrent support and debug symbols
cmake .. -DRATS_SEARCH_FEATURES=ON -DCMAKE_BUILD_TYPE=Debug

# Build with distributed storage support
cmake .. -DRATS_STORAGE=ON -DCMAKE_BUILD_TYPE=Release

# Build with all optional features enabled
cmake .. -DRATS_STORAGE=ON -DRATS_SEARCH_FEATURES=ON -DCMAKE_BUILD_TYPE=Release

# Cross-compile for Android (requires NDK)
cmake .. -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-21 \
         -DRATS_CROSSCOMPILING=ON -DRATS_BUILD_TESTS=OFF

# Build for iOS -- device + simulator slices and the XCFramework.
# Driven by its own script, not by `cmake ..`, so run it from the repository root.
cd .. && ios/build-xcframework.sh     # -> build/ios/LibRats.xcframework
```

See [`ios/README.md`](ios/README.md) for how to consume that from Xcode, and
[`react-native/README.md`](react-native/README.md) for the React Native package.

### Integrating librats Into Your Application

#### Method 1: CMake FetchContent (recommended)

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyP2PApp)
set(CMAKE_CXX_STANDARD 17)

include(FetchContent)
FetchContent_Declare(
    librats
    GIT_REPOSITORY https://github.com/DEgITx/librats.git
    GIT_TAG master  # or a specific version/tag
)
set(RATS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(RATS_BUILD_CLIENT OFF CACHE BOOL "" FORCE)
set(RATS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(librats)

add_executable(my_p2p_app main.cpp)
target_link_libraries(my_p2p_app PRIVATE rats)
```

#### Method 2: CMake add_subdirectory

```bash
# As a git submodule
git submodule add https://github.com/DEgITx/librats.git external/librats
```

```cmake
set(RATS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(RATS_BUILD_CLIENT OFF CACHE BOOL "" FORCE)
set(RATS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(external/librats)

add_executable(my_p2p_app main.cpp)
target_link_libraries(my_p2p_app PRIVATE rats)
# Include directories are propagated automatically (use #include <librats/node/node.h>).
```

#### Method 3: vcpkg

librats is in the official [vcpkg](https://vcpkg.io/en/package/librats) registry:

```bash
vcpkg install librats
# optional features:
vcpkg install librats[bindings,search-features,storage]
```

```cmake
find_package(rats CONFIG REQUIRED)
target_link_libraries(my_p2p_app PRIVATE rats::rats)
```

(The port lives in [`ports/librats/`](ports/librats) in this repository and can also be used as an
overlay port with `vcpkg install librats --overlay-ports=<path-to-librats>/ports`.)

#### Required System Libraries

When linking against a pre-built librats, add these system libraries:

| Platform | Required Libraries |
|----------|-------------------|
| **Windows** | `ws2_32`, `iphlpapi`, `bcrypt` |
| **Linux** | `pthread` |
| **macOS** | `pthread` |
| **Android** | `log` |
| **iOS** | — (the `XCFramework` carries what it needs) |

### Running Tests

```bash
# In the build directory
ctest -j$(nproc) --output-on-failure

# Or run the test binary directly
./bin/librats_tests
```

### Output Files

After building, you'll find:
- **Library**: `build/lib/librats.a` (static library)
- **Executable**: `build/bin/rats-client` (reference/demo application, built by default; disable with `RATS_BUILD_CLIENT=OFF`)
- **Examples**: `build/bin/examples/*` (the [`examples/`](examples/) programs, if `RATS_BUILD_EXAMPLES=ON`)
- **Tests**: `build/bin/librats_tests` (if `RATS_BUILD_TESTS=ON`)

## 🎯 Usage Examples

### The reference application

`rats-client` (built from `src/main.cpp`) wires up the full set of subsystems so every capability can be exercised from one binary:

```bash
# Terminal 1: start a node on port 8080 with DHT + mDNS discovery
./build/bin/rats-client 8080 --dht --mdns

# Terminal 2: start a second node and dial the first
./build/bin/rats-client 8081 --connect 127.0.0.1 8080
```

Options: `--bind <addr>`, `--data <dir>` (stable identity + reconnect store), `--connect <host> <port>` (repeatable), `--dht`, `--mdns`, `--upnp`, `--reconnect`, `--no-ping`. Pub/sub, typed JSON messaging and file transfer are always on. Type `/help` once running for the interactive command list (`/peers`, `/connect`, `/sub`, `/pub`, `/msg`, `/file`, …).

### Runnable examples

The [`examples/`](examples/) directory holds small, focused programs — one capability each, built on the public `Node` API. They are **off by default**; enable them with `-DRATS_BUILD_EXAMPLES=ON` (add `-DRATS_SEARCH_FEATURES=ON` for the BitTorrent one). Binaries land in `build/bin/examples/`.

| Program | Shows |
|---------|-------|
| `chat` | A bare `Node`: encrypted transport + raw channel messaging, manual dialing |
| `pubsub` | The `PubSub` (GossipSub) subsystem — a topic mesh that relays across hops |
| `typed_messaging` | `MessageJson` typed JSON messages, keyed by the authenticated sender |
| `file_transfer` | `FileTransfer` — streaming a file with CRC32 / SHA-256 integrity + progress |
| `dht_discovery` | `DhtDiscovery` — automatic peer discovery over the Kademlia DHT |
| `full_chat` | "Batteries-included" chat: DHT + mDNS + PEX discovery, reconnection, ping and pub/sub — peers find each other with no addresses typed in |
| `bittorrent_download` | Downloading a magnet link (requires `RATS_SEARCH_FEATURES`) |

```bash
cmake -B build -DRATS_BUILD_EXAMPLES=ON && cmake --build build -j

# find each other automatically in the "lobby" room (LAN via mDNS, WAN via DHT):
./build/bin/examples/full_chat 9000 lobby
./build/bin/examples/full_chat 9001 lobby
```

See [`examples/README.md`](examples/README.md) for the full list and per-example usage.

### Minimal chat

```cpp
#include <librats/node/node.h>
#include <librats/subsystems/message_json.h>
#include <iostream>

using namespace librats;

int main() {
    Node node(NodeConfig{/*listen_port=*/8080});
    node.add_subsystem(std::make_unique<MessageJson>());

    node.json()->on("chat", [](const PeerId& from, const librats::Json& d) {
        std::cout << "[" << d.value("user", "?") << "]: " << d.value("text", "") << "\n";
    });

    node.start();

    const std::string user = "User_" + node.local_id().short_hex();
    std::cout << "🐀 librats chat — type messages, 'quit' to exit\n";

    std::string line;
    while (std::getline(std::cin, line) && line != "quit") {
        if (!line.empty())
            node.json()->send("chat", librats::Json{{"user", user}, {"text", line}});
    }
    node.stop();
    return 0;
}
```

## 🔧 Persistent State

When a node is given a `data_dir`, it co-locates its persistent state there:

- **`identity.key`** — the node's Noise/Curve25519 private key. Loaded on startup (or generated and saved on first run), giving a **stable `PeerId` across restarts**. An empty `data_dir` means a fresh random identity each run.
- **`peers.txt`** — reconnection targets, written by `ReconnectionService` when configured with a `store_path` (typically `<data_dir>/peers.txt`).
- **DHT routing tables** — persisted by `DhtDiscovery` when its `Config::data_dir` is set, so the DHT warm-starts on the next run.

There is no central `config.json`: configuration is supplied programmatically via `NodeConfig` and each subsystem's `Config`.

## 🚀 Benchmark Performance

librats is **engineered for resource efficiency**, which makes it a good fit for
**low-power devices**, **edge computing** and **embedded systems** where memory
and CPU are the scarce things.

### vs js-libp2p

**Environment**: Intel Core Ultra 7 265KF (16 cores), 36 GB RAM, Linux, GCC 15.2
`-O3`, Node.js v24.18.0, js-libp2p 3.3.8. Both sides run **TCP + Noise_XX** over
loopback, 3 runs per cell, median reported.

| Metric | librats (JS) | js-libp2p (JS) | librats advantage |
|--------|-----------------|----------------|-------------------|
| **Memory, node started** | **5.0 MB** | 110.9 MB | **22x less** |
| **Memory per connected peer** | **8.1 KB** | 475.1 KB | **59x less** |
| **Memory, 100 peers** | **5.8 MB** | 158.4 MB | **27x less** |
| **Cold start** | **21 ms** | 188 ms | **9x faster** |
| **Connection setup** | **1 746 /s** | 317 /s | **5.5x faster** |
| **CPU per handshake** | **1.61 ms** | 9.19 ms | **5.7x less** |
| **Small messages (256 B)** | **863 517 msg/s** | 92 711 msg/s | **9.3x faster** |
| **CPU per small message** | **2.27 µs** | 23.38 µs | **10x less** |
| **Bulk throughput (64 KiB)** | 600 MB/s | **603 MB/s** | *parity* |
| **CPU per GB** | **3.27 s/GB** | 4.68 s/GB | **1.4x less** |
| **Runtime dependencies** | **none** |  139 npm packages, 66 MB | — |

## Why Choose librats?

### **Performance**
- **Native C++17**: maximum performance with minimal overhead
- **Shared-nothing reactor**: no cross-thread locking on the connection hot path
- **Platform-optimal I/O**: epoll / kqueue / IOCP behind one abstraction

### **Reliability**
- **Comprehensive testing**: unit and integration tests across all components
- **Memory safety**: RAII and smart pointers throughout
- **Cross-platform**: consistent behaviour across Windows, Linux, and macOS

### **Developer Experience**
- **Small, predictable core**: a bare `Node` does exactly one thing — secure transport
- **Composable subsystems**: attach only the capabilities you need
- **Self-certifying identity**: authentication with no PKI or central authority
- **Modern C++**: takes advantage of C++17 features

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for guidelines on code style, development setup, running tests, and submitting pull requests.

### Quick Start for Contributors

```bash
git clone https://github.com/DEgITx/librats.git
cd librats
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DRATS_BUILD_TESTS=ON
make -j$(nproc)
./bin/librats_tests
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

librats also embeds a few adapted third-party cryptographic and platform-compatibility sources under BSD terms; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the component list and full notices.

## 🙏 Acknowledgments

- **libtorrent**: a huge source of inspiration for librats' DHT and BitTorrent stacks. Many algorithmic ideas and improvements — the traversal/lookup algorithm, the ordered-bucket routing table, IP-diversity admission and other hardening details — are borrowed from its battle-tested design. Big thanks to the libtorrent team for their outstanding work.
- **[noise-c](https://github.com/rweather/noise-c)** by Rhys Weatherley / Southern Storm Software: the reference librats' Noise Protocol implementation was written against. The ChaCha20, SHA-256/512 and BLAKE2b/BLAKE2s primitives in `src/librats/crypto/` are derived from it (MIT), as are — through it — [curve25519-donna](https://github.com/agl/curve25519-donna) by Adam Langley (BSD-3-Clause) and [poly1305-donna](https://github.com/floodyberry/poly1305-donna) by Andrew Moon (MIT). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for provenance and the full notices.
- **nlohmann/json**: inspiration for the API surface of librats' own self-contained `librats::Json` type
- **Contributors**: everyone who has helped make librats better

