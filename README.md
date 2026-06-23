# 🐀 librats

<p align="center"><a href="https://github.com/DEgITx/librats"><img src="https://raw.githubusercontent.com/DEgITx/librats/master/docs/logo.png"></a></p>

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Release](https://img.shields.io/github/release/DEgITx/librats.svg)](https://github.com/DEgITx/librats/releases)
[![npm](https://img.shields.io/npm/v/librats.svg)](https://www.npmjs.com/package/librats)

**A high-performance, lightweight peer-to-peer networking library with C++, C, Node.js, Java, Python, and Android support**

librats is a modern P2P networking library designed for **superior performance** and **simplicity**. Built from the ground up in C++17 with comprehensive language bindings, it provides enterprise-grade P2P networking with minimal overhead and maximum efficiency.

**Official Website**: [https://librats.com](https://librats.com)

## 🧱 Design at a glance

librats is built around a small, predictable core (`Node`) and a set of **opt-in subsystems** you attach explicitly. A bare `Node` is just the secure transport: an encrypted TCP channel (Noise_XX) with a self-certifying peer identity, manual dialing, and raw channel messaging. Everything else — discovery, pub/sub, typed messaging, file transfer, liveness, NAT port mapping, reconnection — is a `Subsystem` you add **before** `start()`. You pay only for what you attach, and the core stays small and easy to reason about.

```cpp
librats::NodeConfig config;
config.listen_port = 8080;
librats::Node node(config);

// attach only the capabilities you need
node.add_subsystem(std::make_unique<librats::PubSub>());
node.add_subsystem(std::make_unique<librats::DhtDiscovery>(dht_config));

node.start();
```

## ✨ Key Features

### **Core**
- **Native C++17** implementation for maximum performance
- **Cross-platform** support (Windows, Linux, macOS, Android)
- **Shared-nothing reactor** transport — connections are sharded across reactor threads with no cross-thread locking on the hot path
- **Self-certifying identity**: every node has a Curve25519 keypair; its `PeerId` *is* its public key, so peers authenticate each other with no PKI or central authority
- **Stable identity persistence**: point a node at a `data_dir` and its keypair (and therefore its `PeerId`) survives restarts
- **Composable subsystems**: opt-in plugins attached to a `Node`; a bare node neither discovers peers nor reconnects on its own

### **Discovery & Networking**
- **DHT Discovery**: peer discovery over a Kademlia DHT, fully compatible with the **BitTorrent Mainline DHT** — the largest distributed hash table in the world, with **millions of active nodes** (IPv4 + IPv6 / BEP 32)
- **mDNS Discovery**: automatic local-network peer discovery with service advertisement
- **IPv4/IPv6 Dual Stack**: bind dual-stack by default; full support for modern internet protocols
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
- **Automatic port forwarding**: built-in **UPnP IGD** and **NAT-PMP** — the `PortMappingService` asks the router to forward the listen port on startup (both backends run in parallel; whichever the router supports wins), so peers behind a NAT can accept inbound connections with zero manual configuration. Mappings are refreshed automatically and removed on `stop()`.
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
- **Node.js**: native addon with async/await and TypeScript definitions ([npm package](https://www.npmjs.com/package/librats))
- **Java/Android**: JNI wrapper with a high-level Java API
- **Python**: ctypes-based package with asyncio support

## 🚀 Quick Start

> Examples use the C++ `Node` API. The equivalent C API (`rats_*`) is shown in the [C API](#c-api-bindingsratsh) section.

### 1. Basic P2P connection

```cpp
#include "node/node.h"
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
#include "node/node.h"
#include "subsystems/message_json.h"

Node node(NodeConfig{/*listen_port=*/8080});
node.add_subsystem(std::make_unique<MessageJson>());

// Handlers are additive and keyed by message type. `from` is the authenticated PeerId.
node.json()->on("chat", [](const PeerId& from, const nlohmann::json& data) {
    std::cout << "[chat] " << from.short_hex() << ": " << data.value("text", "") << "\n";
});

node.start();

// Broadcast / direct send.
node.json()->send("chat", nlohmann::json{{"text", "Hello, P2P chat!"}});
node.json()->send(some_peer_id, "chat", nlohmann::json{{"text", "private hi"}});
```

### 4. GossipSub publish-subscribe

```cpp
#include "node/node.h"
#include "subsystems/pubsub.h"

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
#include "node/node.h"
#include "subsystems/file_transfer.h"

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

Attach `PortMappingService` to forward the listen port automatically on startup. Both UPnP IGD and NAT-PMP are attempted in parallel; whichever the router supports wins. The mapping is refreshed automatically and removed on `stop()`.

```cpp
#include "node/node.h"
#include "subsystems/port_mapping_service.h"

Node node(NodeConfig{8080});
auto* portmap = node.add_subsystem(std::make_unique<PortMappingService>());
node.start();

// Public endpoint as seen from outside the NAT (if a mapping succeeded).
if (auto pub = portmap->mapped_public_address())
    std::cout << "public: " << pub->first << ":" << pub->second << "\n";
```

### 8. Peer discovery (DHT + mDNS) and reconnection

```cpp
#include "node/node.h"
#include "subsystems/dht_discovery.h"
#include "subsystems/mdns_discovery.h"
#include "subsystems/reconnection.h"

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
#include "subsystems/ping_service.h"

auto* ping = node.add_subsystem(std::make_unique<PingService>());
node.start();
// ...later:
if (auto rtt = ping->last_rtt(peer_id))
    std::cout << "rtt = " << rtt->count() << "ms\n";
```

### 10. Distributed storage (requires `RATS_STORAGE`)

```cpp
#include "storage/storage.h"

auto* storage = node.add_subsystem(std::make_unique<StorageManager>());
node.start();

storage->put("greeting", "hello");                       // syncs to connected peers via GossipSub
if (auto v = storage->get_string("greeting")) std::cout << *v << "\n";
```

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
| `PeerExchange` | `subsystems/peer_exchange.h` | PEX: gossip known peer addresses to grow the mesh |
| `StorageManager` | `storage/storage.h` | Distributed key-value store (requires `RATS_STORAGE`) |

### C API (`bindings/rats.h`)

The canonical opaque-pointer C ABI — the foundation for every language binding. A `rats_t` wraps a `Node`. Fallible calls return `rats_error_t` (`RATS_OK == 0`); pure getters return their value directly. Subsystems are opt-in: enable each with the matching `rats_enable_*()` **before** `rats_start()`. Strings returned by the library are heap-allocated — free them with `rats_string_free()`.

```c
#include "bindings/rats.h"
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

The source tree mirrors these layers: `src/core`, `src/util`, `src/wire`, `src/transport`, `src/peer`, `src/security`, `src/node`, `src/subsystems`, `src/dht`, `src/mdns`, `src/nat`, `src/crypto`, `src/bittorrent`, `src/storage`, `src/bindings`.

## Frequently Asked Questions (FAQ)

### Understanding DHT vs peer connections

**librats has two distinct peer systems that serve different purposes:**

| Layer | Protocol | Purpose | Where |
|-------|----------|---------|-------|
| **DHT layer** | UDP (Kademlia) | **Peer discovery** only | `DhtDiscovery` subsystem |
| **Peer connection layer** | TCP (Noise) | **Message exchange** | `Node` core: `peers()`, `send`, `broadcast` |

**Key points:**
- The **DHT routing table** is NOT your connected peers. It holds DHT nodes (often from the global BitTorrent Mainline DHT) that help you *discover* peers.
- **Peer connections** (`node.peers()`, `node.peer_count()`) are the actual authenticated TCP connections used for communication.
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
   - Once discovered, peers connect over authenticated TCP and grow the mesh via Peer Exchange.

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

#### Language Bindings & Wrappers

| Language/Platform | Binding Type | Status | Notes |
|-------------------|--------------|--------|-------|
| **C/C++** | Native Library | ✅ **Fully Supported** | Core implementation with the full feature set |
| **Android (NDK)** | Native C++ | ✅ **Fully Supported** | Android NDK integration with JNI bindings |
| **Android (Java)** | JNI Wrapper | ✅ **Fully Supported** | High-level Java API for Android apps |
| **Node.js** | Native Addon | ✅ **Fully Supported** | async/await support ([npm](https://www.npmjs.com/package/librats)) |
| **Python** | C Extension | ✅ **Fully Supported** | CPython extension with asyncio integration |
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
| `RATS_BUILD_EXAMPLES` | `ON` | Build the `rats-client` demo application |
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
# Build as shared library without tests or examples
cmake .. -DRATS_SHARED_LIBRARY=ON -DRATS_STATIC_LIBRARY=OFF \
         -DRATS_BUILD_TESTS=OFF -DRATS_BUILD_EXAMPLES=OFF

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
```

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
set(RATS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(external/librats)

add_executable(my_p2p_app main.cpp)
target_link_libraries(my_p2p_app PRIVATE rats)
# Include directories are propagated automatically (use #include "node/node.h").
```

#### Required System Libraries

When linking against a pre-built librats, add these system libraries:

| Platform | Required Libraries |
|----------|-------------------|
| **Windows** | `ws2_32`, `iphlpapi`, `bcrypt` |
| **Linux** | `pthread` |
| **macOS** | `pthread` |
| **Android** | `log` |

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
- **Executable**: `build/bin/rats-client` (reference/demo application)
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

### Minimal chat

```cpp
#include "node/node.h"
#include "subsystems/message_json.h"
#include <iostream>

using namespace librats;

int main() {
    Node node(NodeConfig{/*listen_port=*/8080});
    node.add_subsystem(std::make_unique<MessageJson>());

    node.json()->on("chat", [](const PeerId& from, const nlohmann::json& d) {
        std::cout << "[" << d.value("user", "?") << "]: " << d.value("text", "") << "\n";
    });

    node.start();

    const std::string user = "User_" + node.local_id().short_hex();
    std::cout << "🐀 librats chat — type messages, 'quit' to exit\n";

    std::string line;
    while (std::getline(std::cin, line) && line != "quit") {
        if (!line.empty())
            node.json()->send("chat", nlohmann::json{{"user", user}, {"text", line}});
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

librats is **engineered for resource efficiency**, making it ideal for **low-power devices**, **edge computing**, and **embedded systems** where memory and CPU are precious.

### Performance Comparison vs libp2p (JavaScript)

**Test Environment**: AMD Ryzen 7 5700U, 16GB RAM

| Metric | librats (C++17) | libp2p (JavaScript) | **Improvement** |
|--------|-----------------|---------------------|-----------------|
| **Startup Memory** | ~1.6 MB | ~50-80 MB | **31-50x less** |
| **Memory per Peer** | ~80 KB | ~4-6 MB | **50-75x less** |
| **Peak Memory (100 peers)** | ~9.4 MB | 400-600 MB | **42-64x less** |
| **CPU Usage (idle)** | 0-1% | 15-25% | **15-25x less** |
| **CPU Usage (peak)** | 1-2% | 80-100% | **5-16x less** |

### Network Traffic (DHT Discovery)

| Metric | Traffic |
|--------|---------|
| **DHT Discovery (idle)** | ~350-450 bytes/sec |

DHT discovery uses minimal bandwidth — only **350-450 bytes per second** during continuous peer discovery — making librats ideal for bandwidth-constrained environments and mobile devices.

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

## 🙏 Acknowledgments

- **nlohmann/json**: for the excellent JSON library integration
- **Contributors**: everyone who has helped make librats better
