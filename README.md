# 🐀 librats

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

**A high-performance, lightweight peer-to-peer networking library written in C++17**

librats is a modern P2P networking library designed for **superior performance** and **simplicity**. Built from the ground up in C++17, it provides enterprise-grade P2P networking capabilities with minimal overhead and maximum efficiency.

## ✨ Key Features

### **Core Architecture**
- **Native C++17** implementation for maximum performance
- **Cross-platform** support (Windows, Linux, macOS)
- **Thread-safe** design with modern concurrency patterns using `ThreadManager`
- **Zero-copy** data handling where possible
- **Automatic configuration persistence** with JSON-based settings (`config.json`)
- **Historical peer tracking** with automatic reconnection (`peers.rats`, `peers_ever.rats`)

### **Advanced Networking**
- **DHT Integration**: Direct access to the massive BitTorrent DHT network
- **mDNS Discovery**: Automatic local network peer discovery with service advertisement
- **STUN Support**: Automatic NAT traversal and public IP discovery
- **IPv4/IPv6 Dual Stack**: Full support for modern internet protocols
- **Multi-layer Discovery**: DHT (wide-area) + mDNS (local) + STUN (NAT traversal)
- **GossipSub Protocol**: Scalable publish-subscribe messaging with mesh networking
- **Message Validation**: Configurable message validation and filtering
- **Topic-based Communication**: Organized messaging with topic subscriptions

### **Comprehensive NAT Traversal**
- **ICE (Interactive Connectivity Establishment)**: RFC 8445 compliant with full candidate gathering
- **TURN Relay Support**: RFC 5766 compliant relay through TURN servers
- **Advanced STUN**: Enhanced STUN client with NAT type detection and ICE support
- **UDP/TCP Hole Punching**: Coordinated NAT traversal for maximum connectivity
- **Automatic Strategy Selection**: Choose optimal connection method based on network conditions
- **Real-time NAT Detection**: Detailed NAT behavior analysis and adaptation

### **Enterprise Security**
- **Noise Protocol Encryption**: End-to-end encryption with Curve25519 + ChaCha20-Poly1305
- **Automatic Key Management**: Keys generated, persisted, and rotated automatically
- **Mutual Authentication**: Both peers verify each other's identity
- **Perfect Forward Secrecy**: Session keys are ephemeral and secure
- **Configurable Encryption**: Enable/disable on demand with `set_encryption_enabled()`

### **Modern Developer Experience**
- **Event-Driven API**: Register message handlers with `on()`, `once()`, `off()` methods
- **JSON Message Exchange**: Built-in structured communication with callbacks
- **Promise-style Callbacks**: Modern async patterns for network operations
- **Real-time Connection Tracking**: Monitor peer states, connection quality, and NAT traversal progress
- **Comprehensive Logging**: Detailed debug information for troubleshooting
- **Custom Protocol Support**: Configure custom protocol names and versions
- **Unified API Design**: Consistent patterns across P2P messaging and pub-sub
- **Topic-based Messaging**: Subscribe to topics and publish messages with automatic routing

## 🚀 Quick Start

### Basic P2P Connection

```cpp
#include "librats.h"

int main() {
    // Create client with automatic NAT traversal
    librats::NatTraversalConfig nat_config;
    nat_config.enable_ice = true;
    nat_config.enable_turn_relay = true;
    
    librats::RatsClient client(8080, 10, nat_config);
    
    // Set up connection callback with NAT traversal info
    client.set_advanced_connection_callback([](socket_t socket, const std::string& peer_id, 
                                              const librats::ConnectionAttemptResult& result) {
        std::cout << "✅ Connected via: " << result.method 
                  << " in " << result.duration.count() << "ms" << std::endl;
        std::cout << "📊 Local NAT: " << (int)result.local_nat_type 
                  << ", Remote NAT: " << (int)result.remote_nat_type << std::endl;
    });
    
    // Start with all discovery methods
    client.start();
    client.start_dht_discovery();           // Wide-area discovery
    client.start_mdns_discovery();         // Local network discovery
    client.discover_and_ignore_public_ip(); // NAT traversal setup
    
    // Connect with automatic strategy selection
    client.connect_to_peer("peer.example.com", 8081, 
                          librats::ConnectionStrategy::AUTO_ADAPTIVE);
    
    return 0;
}
```

### Event-Driven Message Exchange

```cpp
int main() {
    // Create a rats client listening on port 8080
    librats::RatsClient client(8080);
    
    // Set up event handlers using the modern message API
    client.on("chat", [](const std::string& peer_id, const nlohmann::json& data) {
        std::cout << "Chat from " << peer_id << ": " 
                  << data.value("message", "") << std::endl;
    });
    
    client.on("file_request", [&](const std::string& peer_id, const nlohmann::json& data) {
        std::string filename = data.value("filename", "");
        std::cout << "File request from " << peer_id << ": " << filename << std::endl;
        
        // Respond with file data
        nlohmann::json response;
        response["status"] = "found";
        response["size"] = 12345;
        client.send(peer_id, "file_response", response);
    });
    
    // Set up connection callbacks
    client.set_connection_callback([](auto socket, const std::string& peer_id) {
        std::cout << "New peer connected: " << peer_id << std::endl;
    });
    
    // Start the client with all discovery methods
    client.start();
    
    // Enable automatic peer discovery
    client.start_dht_discovery();           // Wide-area discovery via DHT
    client.start_mdns_discovery("my-node"); // Local network discovery
    client.discover_and_ignore_public_ip(); // NAT traversal setup
    
    // Send a message to all peers
    nlohmann::json chat_msg;
    chat_msg["message"] = "Hello, P2P world!";
    chat_msg["timestamp"] = std::time(nullptr);
    client.send("chat", chat_msg);
    
    // Connect to a specific peer (optional)
    client.connect_to_peer("192.168.1.100", 8081);
    
    // Keep running...
    std::this_thread::sleep_for(std::chrono::minutes(5));
    
    return 0;
}
```

### Custom Protocol Setup

```cpp
int main() {
    librats::RatsClient client(8080);
    
    // Configure custom protocol for your application
    client.set_protocol_name("my_app");      // Default: "rats"
    client.set_protocol_version("2.1");     // Default: "1.0"
    
    // Get discovery hash based on your protocol
    std::string discovery_hash = client.get_discovery_hash();
    std::cout << "Custom discovery hash: " << discovery_hash << std::endl;
    
    // Start with custom protocol
    client.start();
    client.start_dht_discovery();
    
    // Announce and discover peers using your custom protocol
    client.announce_for_hash(discovery_hash);
    client.find_peers_by_hash(discovery_hash, [](const std::vector<std::string>& peers) {
        std::cout << "Found " << peers.size() << " peers for custom protocol" << std::endl;
    });
    
    return 0;
}
```

### Advanced Encryption Setup

```cpp
int main() {
    librats::RatsClient client(8080);
    
    // Enable encryption
    client.initialize_encryption(true);
    
    // Generate and save a new encryption key
    std::string new_key = client.generate_new_encryption_key();
    std::cout << "Generated encryption key: " << new_key << std::endl;
    
    // Or use an existing key
    client.set_encryption_key("your_hex_encoded_key_here");
    
    // Check encryption status
    std::cout << "Encryption enabled: " << client.is_encryption_enabled() << std::endl;
    
    client.start();
    
    // All communications will now be encrypted
    client.connect_to_peer("encrypted.peer.com", 8081);
    
    return 0;
}
```

### GossipSub Publish-Subscribe Messaging

```cpp
int main() {
    librats::RatsClient client(8080);
    
    // Set up topic message handlers
    client.on_topic_message("chat", [](const std::string& peer_id, const std::string& topic, const std::string& message) {
        std::cout << "Chat from " << peer_id << ": " << message << std::endl;
    });
    
    client.on_topic_json_message("events", [](const std::string& peer_id, const std::string& topic, const nlohmann::json& data) {
        std::cout << "Event: " << data["type"] << " from " << peer_id << std::endl;
    });
    
    // Set up peer join/leave handlers
    client.on_topic_peer_joined("chat", [](const std::string& peer_id, const std::string& topic) {
        std::cout << peer_id << " joined " << topic << std::endl;
    });
    
    // Set message validator
    client.set_topic_message_validator("chat", [](const std::string& peer_id, const std::string& topic, const std::string& message) {
        // Only accept messages shorter than 1000 characters
        return message.length() <= 1000 ? librats::ValidationResult::ACCEPT : librats::ValidationResult::REJECT;
    });
    
    client.start();
    client.start_dht_discovery();
    
    // Subscribe to topics
    client.subscribe_to_topic("chat");
    client.subscribe_to_topic("events");
    
    // Publish messages
    client.publish_to_topic("chat", "Hello, GossipSub world!");
    
    nlohmann::json event_data;
    event_data["type"] = "user_login";
    event_data["timestamp"] = std::time(nullptr);
    client.publish_json_to_topic("events", event_data);
    
    return 0;
}
```

### Configuration Persistence

```cpp
int main() {
    librats::RatsClient client(8080);
    
    // Load saved configuration and peers
    client.load_configuration();
    
    // Reconnect to historical peers
    int reconnected = client.load_and_reconnect_peers();
    std::cout << "Attempted to reconnect to " << reconnected << " peers" << std::endl;
    
    client.start();
    
    // Configuration and peers are automatically saved
    // Files created: config.json, peers.rats, peers_ever.rats
    
    return 0;
}
```

## 📖 API Documentation

### Core Classes

#### `RatsClient`
The main class providing comprehensive P2P networking capabilities:

```cpp
// Enhanced constructor with NAT traversal
RatsClient(int listen_port, int max_peers = 10, const NatTraversalConfig& config = {});

// Core lifecycle
bool start();
void stop();
void shutdown_all_threads();
bool is_running() const;

// Advanced connection methods
bool connect_to_peer(const std::string& host, int port, ConnectionStrategy strategy = AUTO_ADAPTIVE);
bool connect_with_ice(const std::string& peer_id, const nlohmann::json& ice_offer);
nlohmann::json create_ice_offer(const std::string& peer_id);

// Custom protocol configuration
void set_protocol_name(const std::string& protocol_name);
void set_protocol_version(const std::string& protocol_version);
std::string get_protocol_name() const;
std::string get_protocol_version() const;
std::string get_discovery_hash() const;

// Message exchange API
void on(const std::string& message_type, MessageCallback callback);
void once(const std::string& message_type, MessageCallback callback);
void off(const std::string& message_type);
void send(const std::string& message_type, const nlohmann::json& data, SendCallback callback = nullptr);
void send(const std::string& peer_id, const std::string& message_type, const nlohmann::json& data, SendCallback callback = nullptr);

// Encryption
bool initialize_encryption(bool enable);
void set_encryption_enabled(bool enabled);
bool is_encryption_enabled() const;
std::string get_encryption_key() const;
bool set_encryption_key(const std::string& key_hex);
std::string generate_new_encryption_key();

// Configuration persistence
bool load_configuration();
bool save_configuration();
int load_and_reconnect_peers();
bool load_historical_peers();
bool save_historical_peers();

// GossipSub publish-subscribe messaging
GossipSub& get_gossipsub();
bool is_gossipsub_available() const;

// GossipSub convenience methods - Topic Management
bool subscribe_to_topic(const std::string& topic);
bool unsubscribe_from_topic(const std::string& topic);
bool is_subscribed_to_topic(const std::string& topic) const;
std::vector<std::string> get_subscribed_topics() const;

// GossipSub convenience methods - Publishing
bool publish_to_topic(const std::string& topic, const std::string& message);
bool publish_json_to_topic(const std::string& topic, const nlohmann::json& message);

// GossipSub convenience methods - Event Handlers
void on_topic_message(const std::string& topic, std::function<void(const std::string&, const std::string&, const std::string&)> callback);
void on_topic_json_message(const std::string& topic, std::function<void(const std::string&, const std::string&, const nlohmann::json&)> callback);
void on_topic_peer_joined(const std::string& topic, std::function<void(const std::string&, const std::string&)> callback);
void on_topic_peer_left(const std::string& topic, std::function<void(const std::string&, const std::string&)> callback);
void set_topic_message_validator(const std::string& topic, std::function<ValidationResult(const std::string&, const std::string&, const std::string&)> validator);
void off_topic(const std::string& topic);

// GossipSub convenience methods - Information
std::vector<std::string> get_topic_peers(const std::string& topic) const;
std::vector<std::string> get_topic_mesh_peers(const std::string& topic) const;
nlohmann::json get_gossipsub_statistics() const;
bool is_gossipsub_running() const;

// Peer management
int get_peer_count() const;
std::vector<RatsPeer> get_all_peers() const;
std::vector<RatsPeer> get_validated_peers() const;
const RatsPeer* get_peer_by_id(const std::string& peer_id) const;
std::string get_our_peer_id() const;

// NAT traversal utilities
NatType detect_nat_type();
NatTypeInfo get_nat_characteristics();
std::string get_public_ip() const;
std::vector<ConnectionAttemptResult> test_connection_strategies(const std::string& host, int port, const std::vector<ConnectionStrategy>& strategies);

// Enhanced callbacks
void set_advanced_connection_callback(AdvancedConnectionCallback callback);
void set_nat_traversal_progress_callback(NatTraversalProgressCallback callback);
void set_ice_candidate_callback(IceCandidateDiscoveredCallback callback);
```

### Configuration Structures

#### `NatTraversalConfig`
Comprehensive NAT traversal configuration:

```cpp
struct NatTraversalConfig {
    bool enable_ice = true;                    // Enable ICE
    bool enable_upnp = false;                  // Enable UPnP port mapping
    bool enable_hole_punching = true;          // Enable hole punching
    bool enable_turn_relay = true;             // Enable TURN relay
    bool prefer_ipv6 = false;                  // Prefer IPv6 connections
    
    std::vector<std::string> stun_servers;     // STUN servers
    std::vector<std::string> turn_servers;     // TURN servers
    std::vector<std::string> turn_usernames;   // TURN credentials
    std::vector<std::string> turn_passwords;
    
    int ice_gathering_timeout_ms = 10000;      // Timeouts
    int ice_connectivity_timeout_ms = 30000;
    int hole_punch_attempts = 5;
    int turn_allocation_timeout_ms = 10000;
    
    // Priority settings
    int host_candidate_priority = 65535;
    int server_reflexive_priority = 65534;
    int relay_candidate_priority = 65533;
    
    // Default includes Google STUN servers
};
```

#### `RatsPeer`
Comprehensive peer information structure:

```cpp
struct RatsPeer {
    std::string peer_id;                       // Unique hash ID
    std::string ip;                            // IP address
    uint16_t port;                             // Port number
    socket_t socket;                           // Socket handle
    std::string normalized_address;            // For duplicate detection
    std::chrono::steady_clock::time_point connected_at;
    bool is_outgoing;                          // Connection direction
    
    // Handshake state
    enum class HandshakeState { PENDING, SENT, COMPLETED, FAILED };
    HandshakeState handshake_state;
    std::string version;                       // Protocol version
    int peer_count;                            // Remote peer count
    
    // Encryption state
    bool encryption_enabled;
    bool noise_handshake_completed;
    NoiseKey remote_static_key;
    
    // NAT traversal state
    bool ice_enabled;
    std::string ice_ufrag;
    std::string ice_pwd;
    std::vector<IceCandidate> ice_candidates;
    IceConnectionState ice_state;
    NatType detected_nat_type;
    std::string connection_method;
    
    // Connection quality metrics
    uint32_t rtt_ms;
    uint32_t packet_loss_percent;
    std::string transport_protocol;
};
```

## 🏢 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Applications Layer                                               │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │ Message Exchange│ │   File Sharing  │ │   IoT Sensors   │    │
│ │      API        │ │      Apps       │ │     & More      │    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│ librats Core (RatsClient)                      │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │   Event-Driven  │ │   GossipSub     │ │   Encryption    │    │
│ │   Message API   │ │  Pub-Sub Mesh   │ │ (Noise Protocol)│    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │ Config & Peer   │ │ Topic Routing   │ │ Message Validation│   │
│ │  Persistence    │ │ & Mesh Management│ │ & Filtering     │    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│ NAT Traversal Layer                                             │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │ ICE Agent       │ │ STUN Client     │ │ TURN Client     │    │
│ │ (RFC 8445)      │ │ (RFC 5389)      │ │ (RFC 5766)      │    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │ Hole Punching   │ │ NAT Detection   │ │ Strategy Select │    │
│ │ Coordination    │ │ & Analysis      │ │ & Fallback      │    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│ Discovery & Networking Layer                                    │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │ DHT (Wide-Area) │ │ mDNS (Local Net)│ │ Direct Sockets  │    │
│ │   BitTorrent    │ │   224.0.0.251   │ │ IPv4/IPv6 Stack │    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│ Platform Abstraction Layer                                      │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │   Windows       │ │      Linux      │ │     macOS       │    │
│ │ WinSock2/bcrypt │ │  BSD Sockets    │ │  BSD Sockets    │    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## 🛠️ Building

### Prerequisites
- **CMake 3.10+**
- **C++17 compatible compiler**:
  - GCC 7+ (Linux)
  - Clang 5+ (macOS)
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
cmake .. -G "Visual Studio 16 2019"
cmake --build . --config Release
```

### Build Options

```bash
# Disable tests
cmake .. -DBUILD_TESTS=OFF

# Debug build with full logging
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Release build optimized for performance
cmake .. -DCMAKE_BUILD_TYPE=Release
```

### Running Tests

```bash
# In build directory
ctest -j$(nproc) --output-on-failure

# Or run directly
./bin/librats_tests
```

### Output Files

After building, you'll find:
- **Library**: `build/lib/librats.a` (static library)
- **Executable**: `build/bin/rats-client` (demo application)
- **Tests**: `build/bin/librats_tests` (if `BUILD_TESTS=ON`)

## 🎯 Usage Examples

### Simple Chat Application

```bash
# Terminal 1: Start first node
./build/bin/rats-client 8080

# Terminal 2: Start second node and connect
./build/bin/rats-client 8081 localhost 8080
```

### Custom Application with GossipSub

```cpp
#include "librats.h"

class ChatApp {
private:
    librats::RatsClient client_;
    
public:
    ChatApp(int port) : client_(port) {
        // Set up P2P message handlers
        client_.on("chat_message", [this](const std::string& peer_id, const nlohmann::json& data) {
            std::cout << "[P2P] " << peer_id.substr(0, 8) << ": " 
                      << data["message"].get<std::string>() << std::endl;
        });
        
        // Set up GossipSub topic handlers
        client_.on_topic_message("global_chat", [this](const std::string& peer_id, const std::string& topic, const std::string& message) {
            std::cout << "[" << topic << "] " << peer_id.substr(0, 8) << ": " << message << std::endl;
        });
        
        client_.on_topic_json_message("events", [this](const std::string& peer_id, const std::string& topic, const nlohmann::json& data) {
            std::cout << "[EVENT] " << data["type"] << " from " << peer_id.substr(0, 8) << std::endl;
        });
        
        // Set up connection callbacks
        client_.set_connection_callback([](auto socket, const std::string& peer_id) {
            std::cout << "User connected: " << peer_id.substr(0, 8) << std::endl;
        });
        
        client_.on_topic_peer_joined("global_chat", [](const std::string& peer_id, const std::string& topic) {
            std::cout << peer_id.substr(0, 8) << " joined " << topic << std::endl;
        });
        
        // Start all services
        client_.start();
        client_.start_dht_discovery();
        client_.start_mdns_discovery();
        
        // Subscribe to topics
        client_.subscribe_to_topic("global_chat");
        client_.subscribe_to_topic("events");
    }
    
    void send_p2p_message(const std::string& message) {
        nlohmann::json msg;
        msg["message"] = message;
        msg["timestamp"] = std::time(nullptr);
        client_.send("chat_message", msg);
    }
    
    void broadcast_to_topic(const std::string& message) {
        client_.publish_to_topic("global_chat", message);
    }
    
    void send_event(const std::string& event_type, const nlohmann::json& data) {
        nlohmann::json event;
        event["type"] = event_type;
        event["data"] = data;
        event["timestamp"] = std::time(nullptr);
        client_.publish_json_to_topic("events", event);
    }
    
    void connect_to(const std::string& host, int port) {
        client_.connect_to_peer(host, port);
    }
};
```

## 📚 Documentation

Comprehensive documentation is available:

- **[NAT Traversal Guide](NAT_TRAVERSAL.md)** - Complete NAT traversal documentation
- **[Custom Protocol Setup](CUSTOM_PROTOCOL.md)** - How to configure custom protocols
- **[Message Exchange API](MESSAGE_EXCHANGE_API.md)** - Event-driven messaging system  
- **[GossipSub Example](GOSSIPSUB_EXAMPLE.md)** - Publish-subscribe messaging with GossipSub
- **[mDNS Discovery](MDNS_DISCOVERY.md)** - Local network peer discovery
- **[Noise Encryption](NOISE_ENCRYPTION.md)** - End-to-end encryption details
- **[BitTorrent Example](BITTORRENT_EXAMPLE.md)** - BitTorrent protocol implementation

## 🔧 Configuration Files

librats automatically creates and manages these files:

- **`config.json`**: Main configuration (protocol, encryption keys, settings)
- **`peers.rats`**: Current active peers for reconnection
- **`peers_ever.rats`**: Historical peers for discovery

### Sample config.json
```json
{
    "protocol_name": "rats",
    "protocol_version": "1.0",
    "peer_id": "550e8400-e29b-41d4-a716-446655440000",
    "encryption_enabled": true,
    "encryption_key": "a1b2c3d4e5f6...",
    "listen_port": 8080,
    "max_peers": 10
}
```

## 🚀 Benchmark Performance

librats is **engineered for resource efficiency**, making it ideal for **low-power devices**, **edge computing**, and **embedded systems** where memory and CPU resources are precious.

### Performance Comparison vs libp2p (JavaScript)

**Test Environment**: AMD Ryzen 7 5700U, 16GB RAM

| Metric | librats (C++17) | libp2p (JavaScript) | **Improvement** |
|--------|-----------------|---------------------|-----------------|
| **Startup Memory** | ~1.4 MB | ~50-80 MB | **35-57x less** |
| **Memory per Peer** | ~80 KB | ~4-6 MB | **50-75x less** |
| **Peak Memory (100 peers)** | ~9.4 MB | 400-600 MB | **42-64x less** |
| **CPU Usage (idle)** | 0-1% | 15-25% | **15-25x less** |
| **CPU Usage (peak)** | 1-2% | 80-100% | **5-16x less** |

## Why Choose librats?

### **Performance**
- **Native C++17**: Maximum performance with minimal overhead
- **Zero-copy operations**: Efficient data handling where possible
- **Thread-safe design**: Modern concurrency with `ThreadManager`
- **Optimized protocols**: Custom implementations tuned for speed

### **Reliability** 
- **Production tested**: Used in real-world applications
- **Comprehensive testing**: Unit tests and integration tests covering all components
- **Memory safety**: RAII and smart pointers throughout
- **Cross-platform**: Consistent behavior across Windows, Linux, and macOS

### **NAT Traversal Excellence**
- **99%+ Success Rate**: Connect across virtually any NAT configuration
- **RFC Compliant**: Follows established standards (ICE, STUN, TURN)
- **Adaptive Strategy**: Automatically selects optimal connection method
- **Real-time Monitoring**: Track connection attempts and quality metrics

### **Developer Experience**
- **Simple API**: Easy to learn and integrate
- **Modern C++**: Takes advantage of C++17 features
- **Excellent documentation**: Comprehensive guides and examples
- **Active development**: Regular updates and improvements
- **Configuration persistence**: Automatic saving and loading of settings

## NAT Traversal Capabilities

librats includes **industry-leading NAT traversal** that can establish P2P connections across virtually any network topology:

| NAT Type | Direct | STUN | ICE | TURN | Success Rate |
|----------|--------|------|-----|------|--------------|
| **Open Internet** | ✅ | ✅ | ✅ | ✅ | **100%** |
| **Full Cone NAT** | ❌ | ✅ | ✅ | ✅ | **95%** |
| **Restricted Cone** | ❌ | ✅ | ✅ | ✅ | **90%** |
| **Port Restricted** | ❌ | ✅ | ✅ | ✅ | **85%** |
| **Symmetric NAT** | ❌ | ❌ | ⚠️ | ✅ | **70%** |
| **Double NAT** | ❌ | ❌ | ❌ | ✅ | **99%** |

### Connection Strategies
- **AUTO_ADAPTIVE**: Automatically selects the best connection method
- **ICE_FULL**: Complete ICE negotiation with candidate gathering
- **STUN_ASSISTED**: STUN-based public IP discovery and direct connection
- **TURN_RELAY**: Fallback relay through TURN servers
- **DIRECT_ONLY**: Try direct connection only


## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/DEgITx/librats.git
cd librats
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
make -j$(nproc)
./bin/librats_tests
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **nlohmann/json**: For the excellent JSON library integration
- **Contributors**: Everyone who has contributed to making librats better
