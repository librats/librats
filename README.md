# 🐀 librats

<p align="center"><a href="https://github.com/DEgITx/librats"><img src="https://raw.githubusercontent.com/DEgITx/librats/master/docs/logo.png"></a></p>

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Release](https://img.shields.io/github/release/DEgITx/librats.svg)](https://github.com/DEgITx/librats/releases)
[![npm](https://img.shields.io/npm/v/librats.svg)](https://www.npmjs.com/package/librats)

**A high-performance, lightweight peer-to-peer networking library with C++, C, Node.js, Java, Python, and Android support**

librats is a modern P2P networking library designed for **superior performance** and **simplicity**. Built from the ground up in C++17 with comprehensive language bindings, it provides enterprise-grade P2P networking capabilities with minimal overhead and maximum efficiency.

**Official Website**: [https://librats.com](https://librats.com)

## ✨ Key Features

### **Core Architecture**
- **Native C++17** implementation for maximum performance
- **Cross-platform** support (Windows, Linux, macOS)
- **Thread-safe** design with modern concurrency patterns using `ThreadManager`
- **Zero-copy** data handling where possible
- **Automatic configuration persistence** with JSON-based settings (`config.json`)
- **Historical peer tracking** with automatic reconnection (`peers.rats`, `peers_ever.rats`)

### **Advanced Networking**
- **DHT Discovery**: Supports peer discovery over the DHT protocol. librats DHT Discovery is fully compatible with the **BitTorrent Mainline DHT** — the largest distributed hash table network in the world with **millions of active nodes**.
- **mDNS Discovery**: Automatic local network peer discovery with service advertisement
- **IPv4/IPv6 Dual Stack**: Full support for modern internet protocols
- **Multi-layer Discovery**: DHT (wide-area) + mDNS (local)
- **Automatic Reconnection**: Smart reconnection system with configurable retry intervals, stable peer detection, and exponential backoff (enabled by default)
- **GossipSub Protocol**: Scalable publish-subscribe messaging with mesh networking
- **Message Validation**: Configurable message validation and filtering
- **Topic-based Communication**: Organized messaging with topic subscriptions

### **High-Performance File Transfer**
- **Chunked Transfers**: Efficient file splitting with parallel chunk transmission
- **Resume Capability**: Automatic resume of interrupted transfers with checksum validation
- **Directory Transfer**: Complete directory trees with recursive subdirectory support
- **Transfer Control**: Pause, resume, cancel operations with real-time progress tracking
- **Security Validation**: SHA256 checksums for data integrity verification
- **Configurable Performance**: Adjustable chunk size, concurrency, and timeout settings
- **Request/Response Model**: Secure file requests with acceptance/rejection callbacks
- **Transfer Statistics**: Comprehensive metrics including speed, ETA, and completion rates

### **Enterprise Security**
- **Noise Protocol Encryption**: End-to-end encryption with Curve25519 + ChaCha20-Poly1305
- **Automatic Key Management**: Keys generated, persisted, and rotated automatically
- **Mutual Authentication**: Both peers verify each other's identity
- **Perfect Forward Secrecy**: Session keys are ephemeral and secure
- **Configurable Encryption**: Enable/disable on demand with `set_encryption_enabled()`

### **NAT Traversal (ICE/STUN/TURN)**
- **ICE-lite Implementation**: RFC 5245 compliant NAT traversal for P2P connectivity
- **STUN Support**: Discover public IP address through STUN servers (compatible with Google's public STUN servers)
- **TURN Relay**: Fallback relay connectivity when direct P2P connection fails
- **Automatic Candidate Gathering**: Host, server-reflexive, and relay candidates
- **Connectivity Checks**: Automatic NAT traversal with candidate pair prioritization
- **Trickle ICE**: Support for incremental candidate exchange
- **Public Address Discovery**: Simple API to discover your public IP address
- **Event-Driven API**: Callbacks for gathering state, connection state, and candidate events

### **Modern Developer Experience**
- **Event-Driven API**: Register message handlers with `on()`, `once()`, `off()` methods
- **JSON Message Exchange**: Built-in structured communication with callbacks
- **Promise-style Callbacks**: Modern async patterns for network operations
- **Real-time Connection Tracking**: Monitor peer states and connection quality
- **Comprehensive Logging API**: Full control over logging levels, file rotation, and output formatting
- **Custom Protocol Support**: Configure custom protocol names and versions
- **Unified API Design**: Consistent patterns across P2P messaging and pub-sub
- **Topic-based Messaging**: Subscribe to topics and publish messages with automatic routing
- **Enhanced Peer Management**: Detailed peer information with encryption status

### **Distributed Storage** (Optional, requires `RATS_STORAGE`)
- **Key-Value Storage**: Simple, typed key-value storage with string, int64, double, binary, and JSON support
- **Automatic P2P Synchronization**: Real-time sync across connected peers via GossipSub
- **Last-Write-Wins (LWW)**: Automatic conflict resolution based on timestamps
- **Disk Persistence**: Optional persistence to disk with efficient binary format
- **Change Notifications**: Callbacks for storage changes (local and remote)
- **Prefix Queries**: Find keys matching a prefix pattern
- **Configurable**: Adjustable sync batch size, compression, and storage limits

### **Multi-Language Support**
- **Native C++17**: Core implementation with full feature set and maximum performance
- **C API**: Clean C interface for legacy systems and FFI bindings
- **Node.js Bindings**: Native addon with async/await support and full TypeScript definitions ([npm package](https://www.npmjs.com/package/librats))
- **Java/Android**: Complete JNI wrapper with high-level Java API for Android development
- **Python Bindings**: Full-featured Python package with ctypes wrapper and asyncio support
- **Cross-Platform**: Consistent API across Windows, Linux, macOS, and Android platforms

## 🚀 Quick Start

### 1. Basic P2P Connection

```cpp
#include "librats.h"
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    // Create a simple P2P client
    librats::RatsClient client(8080);
    
    // Set up connection callback
    client.set_connection_callback([](socket_t socket, const std::string& peer_id) {
        std::cout << "✅ New peer connected: " << peer_id << std::endl;
    });
    
    // Set up message callback
    client.set_string_data_callback([](socket_t socket, const std::string& peer_id, const std::string& message) {
        std::cout << "💬 Message from " << peer_id << ": " << message << std::endl;
    });
    
    // Start the client
    if (!client.start()) {
        std::cerr << "Failed to start client" << std::endl;
        return 1;
    }
    
    std::cout << "🐀 librats client running on port 8080" << std::endl;
    
    // Connect to another peer (optional)
    // client.connect_to_peer("127.0.0.1", 8081);
    
    // Send a message to all connected peers
    client.broadcast_string_to_peers("Hello from librats!");
    
    // Keep running
    std::this_thread::sleep_for(std::chrono::minutes(1));
    
    return 0;
}
```

### 2. Custom Protocol Setup

```cpp
#include "librats.h"
#include <iostream>

int main() {
    librats::RatsClient client(8080);
    
    // Configure custom protocol for your application
    client.set_protocol_name("my_app");
    client.set_protocol_version("1.0");
    
    std::cout << "Protocol: " << client.get_protocol_name() 
              << " v" << client.get_protocol_version() << std::endl;
    std::cout << "Discovery hash: " << client.get_discovery_hash() << std::endl;
    
    client.start();
    
    // Start DHT discovery with custom protocol
    if (client.start_dht_discovery()) {
        // Announce our presence
        client.announce_for_hash(client.get_discovery_hash());
        
        // Search for other peers using same protocol
        client.find_peers_by_hash(client.get_discovery_hash(), 
            [](const std::vector<std::string>& peers) {
                std::cout << "Found " << peers.size() << " peers" << std::endl;
            });
    }
    
    return 0;
}
```

### 3. Chat Application with Message Exchange API

```cpp
#include "librats.h"
#include <iostream>
#include <string>

int main() {
    librats::RatsClient client(8080);
    
    // Set up message handlers using the modern API
    client.on("chat", [](const std::string& peer_id, const nlohmann::json& data) {
        std::cout << "[CHAT] " << peer_id << ": " << data["message"].get<std::string>() << std::endl;
    });
    
    client.on("user_join", [](const std::string& peer_id, const nlohmann::json& data) {
        std::cout << "[JOIN] " << data["username"].get<std::string>() << " joined" << std::endl;
    });
    
    // Connection callback
    client.set_connection_callback([&](socket_t socket, const std::string& peer_id) {
        std::cout << "✅ Peer connected: " << peer_id << std::endl;
        
        // Send welcome message
        nlohmann::json welcome;
        welcome["username"] = "User_" + client.get_our_peer_id().substr(0, 8);
        client.send("user_join", welcome);
    });
    
    client.start();
    
    // Send a chat message
    nlohmann::json chat_msg;
    chat_msg["message"] = "Hello, P2P chat!";
    chat_msg["timestamp"] = std::time(nullptr);
    client.send("chat", chat_msg);
    
    return 0;
}
```

### 4. GossipSub Publish-Subscribe

```cpp
#include "librats.h"
#include <iostream>

int main() {
    librats::RatsClient client(8080);
    
    // Set up topic message handlers
    client.on_topic_message("news", [](const std::string& peer_id, const std::string& topic, const std::string& message) {
        std::cout << "📰 [" << topic << "] " << peer_id << ": " << message << std::endl;
    });
    
    client.on_topic_json_message("events", [](const std::string& peer_id, const std::string& topic, const nlohmann::json& data) {
        std::cout << "🎉 [" << topic << "] Event: " << data["type"].get<std::string>() << std::endl;
    });
    
    // Peer join/leave notifications
    client.on_topic_peer_joined("news", [](const std::string& peer_id, const std::string& topic) {
        std::cout << "➕ " << peer_id << " joined " << topic << std::endl;
    });
    
    client.start();
    client.start_dht_discovery();
    
    // Subscribe to topics
    client.subscribe_to_topic("news");
    client.subscribe_to_topic("events");
    
    // Publish messages
    client.publish_to_topic("news", "Breaking: librats is awesome!");
    
    nlohmann::json event;
    event["type"] = "celebration";
    event["reason"] = "successful_connection";
    client.publish_json_to_topic("events", event);
    
    std::cout << "📊 Peers in 'news': " << client.get_topic_peers("news").size() << std::endl;
    
    return 0;
}
```

### 5. File and Directory Transfer

```cpp
#include "librats.h"
#include <iostream>

int main() {
    librats::RatsClient client(8080);
    
    // Set up file transfer callbacks
    client.on_file_transfer_progress([](const librats::FileTransferProgress& progress) {
        std::cout << "📁 Transfer " << progress.transfer_id.substr(0, 8) 
                  << ": " << progress.get_completion_percentage() << "% complete"
                  << " (" << (progress.transfer_rate_bps / 1024) << " KB/s)" << std::endl;
    });
    
    client.on_file_transfer_completed([](const std::string& transfer_id, bool success, const std::string& error) {
        if (success) {
            std::cout << "✅ Transfer completed: " << transfer_id.substr(0, 8) << std::endl;
        } else {
            std::cout << "❌ Transfer failed: " << error << std::endl;
        }
    });
    
    // Auto-accept incoming file transfers
    client.on_file_transfer_request([](const std::string& peer_id, 
                                      const librats::FileMetadata& metadata, 
                                      const std::string& transfer_id) {
        std::cout << "📥 Incoming: " << metadata.filename 
                  << " (" << metadata.file_size << " bytes) from " << peer_id.substr(0, 8) << std::endl;
        return true; // Auto-accept
    });
    
    // Allow file requests from "shared" directory
    client.on_file_request([](const std::string& peer_id, const std::string& file_path, const std::string& transfer_id) {
        std::cout << "📤 Request: " << file_path << " from " << peer_id.substr(0, 8) << std::endl;
        return file_path.find("../") == std::string::npos; // Prevent path traversal
    });
    
    client.start();
    
    // Configure transfer settings
    librats::FileTransferConfig config;
    config.chunk_size = 64 * 1024;       // 64KB chunks
    config.max_concurrent_chunks = 4;    // 4 parallel chunks
    config.verify_checksums = true;      // Verify integrity
    client.set_file_transfer_config(config);
    
    // Example transfers (replace "peer_id" with actual peer ID)
    // std::string file_transfer = client.send_file("peer_id", "my_file.txt");
    // std::string dir_transfer = client.send_directory("peer_id", "./my_folder");
    // std::string file_request = client.request_file("peer_id", "remote_file.txt", "./downloaded_file.txt");
    
    std::cout << "File transfer ready. Connect peers and exchange files!" << std::endl;
    
    return 0;
}
```

### 6. Encryption

```cpp
#include "librats.h"
#include <iostream>

int main() {
    librats::RatsClient client(8080);
    
    // Enable Noise Protocol encryption - that's it!
    client.initialize_encryption(true);
    
    client.set_connection_callback([](socket_t socket, const std::string& peer_id) {
        std::cout << "🔒 Peer connected (encrypted): " << peer_id.substr(0, 16) << std::endl;
    });
    
    client.set_string_data_callback([](socket_t socket, const std::string& peer_id, const std::string& message) {
        std::cout << "💬 Message from " << peer_id.substr(0, 8) << ": " << message << std::endl;
    });
    
    client.start();
    
    std::cout << "🐀 Encrypted P2P client running on port 8080" << std::endl;
    
    // All messages are automatically encrypted with Noise Protocol
    // (Curve25519 key exchange + ChaCha20-Poly1305 encryption)
    client.broadcast_string_to_peers("This message is end-to-end encrypted!");
    
    std::this_thread::sleep_for(std::chrono::minutes(1));
    return 0;
}
```

### 7. NAT Traversal (ICE/STUN/TURN)

```cpp
#include "librats.h"
#include <iostream>

int main() {
    librats::RatsClient client(8080);
    
    client.start();
    
    // =========================================================================
    // Simple Public Address Discovery
    // =========================================================================
    
    // Quick way to discover your public IP address
    auto public_addr = client.discover_public_address("stun.l.google.com", 19302, 5000);
    if (public_addr) {
        std::cout << "🌐 Your public address: " << public_addr->address 
                  << ":" << public_addr->port << std::endl;
    } else {
        std::cout << "❌ Could not discover public address" << std::endl;
    }
    
    // =========================================================================
    // Full ICE Setup for NAT Traversal
    // =========================================================================
    
    // Add STUN servers for public address discovery
    client.add_stun_server("stun.l.google.com", 19302);
    client.add_stun_server("stun1.l.google.com", 19302);
    
    // Add TURN server for relay fallback (when direct connection fails)
    // client.add_turn_server("turn.example.com", 3478, "username", "password");
    
    // Configure ICE settings
    librats::IceConfig ice_config;
    ice_config.gather_host_candidates = true;      // Local interface addresses
    ice_config.gather_srflx_candidates = true;     // Public addresses via STUN
    ice_config.gather_relay_candidates = false;    // TURN relay (requires TURN server)
    ice_config.gathering_timeout_ms = 5000;        // 5 second timeout
    client.set_ice_config(ice_config);
    
    // Set up ICE event callbacks
    client.on_ice_gathering_state_changed([](librats::IceGatheringState state) {
        switch (state) {
            case librats::IceGatheringState::New:
                std::cout << "📡 ICE: Not started" << std::endl;
                break;
            case librats::IceGatheringState::Gathering:
                std::cout << "📡 ICE: Gathering candidates..." << std::endl;
                break;
            case librats::IceGatheringState::Complete:
                std::cout << "📡 ICE: Gathering complete!" << std::endl;
                break;
        }
    });
    
    client.on_ice_connection_state_changed([](librats::IceConnectionState state) {
        switch (state) {
            case librats::IceConnectionState::Checking:
                std::cout << "🔄 ICE: Checking connectivity..." << std::endl;
                break;
            case librats::IceConnectionState::Connected:
                std::cout << "✅ ICE: Connected!" << std::endl;
                break;
            case librats::IceConnectionState::Completed:
                std::cout << "✅ ICE: Connection established!" << std::endl;
                break;
            case librats::IceConnectionState::Failed:
                std::cout << "❌ ICE: Connection failed" << std::endl;
                break;
            default:
                break;
        }
    });
    
    // Callback for each new candidate (trickle ICE)
    client.on_ice_new_candidate([](const librats::IceCandidate& candidate) {
        std::cout << "🆕 New candidate: " << candidate.type_string() 
                  << " " << candidate.address << ":" << candidate.port << std::endl;
        
        // In a real app, send this to remote peer via signaling channel
        std::string sdp = candidate.to_sdp_attribute();
        std::cout << "   SDP: " << sdp << std::endl;
    });
    
    // Callback when all candidates gathered
    client.on_ice_candidates_gathered([](const std::vector<librats::IceCandidate>& candidates) {
        std::cout << "📋 Gathered " << candidates.size() << " candidates:" << std::endl;
        for (const auto& c : candidates) {
            std::cout << "   - " << c.type_string() << ": " 
                      << c.address << ":" << c.port << std::endl;
        }
    });
    
    // Callback when best candidate pair is selected
    client.on_ice_selected_pair([](const librats::IceCandidatePair& pair) {
        std::cout << "🎯 Selected pair: " << std::endl;
        std::cout << "   Local:  " << pair.local.address << ":" << pair.local.port << std::endl;
        std::cout << "   Remote: " << pair.remote.address << ":" << pair.remote.port << std::endl;
    });
    
    // Start gathering ICE candidates
    if (client.gather_ice_candidates()) {
        std::cout << "🚀 Started ICE candidate gathering" << std::endl;
    }
    
    // Wait for gathering to complete
    while (!client.is_ice_gathering_complete()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Get our local candidates
    auto local_candidates = client.get_ice_candidates();
    std::cout << "📤 Send these candidates to remote peer:" << std::endl;
    for (const auto& c : local_candidates) {
        std::cout << c.to_sdp_attribute() << std::endl;
    }
    
    // In a real app, receive remote candidates via signaling and add them:
    // std::vector<std::string> remote_sdp_lines = { /* from signaling */ };
    // client.add_remote_ice_candidates_from_sdp(remote_sdp_lines);
    // client.end_of_remote_ice_candidates();  // Signal end of trickle ICE
    
    // Start connectivity checks
    // client.start_ice_checks();
    
    // Check if connected
    if (client.is_ice_connected()) {
        auto selected = client.get_ice_selected_pair();
        if (selected) {
            std::cout << "🔗 Connected via: " 
                      << selected->local.address << ":" << selected->local.port
                      << " -> " 
                      << selected->remote.address << ":" << selected->remote.port 
                      << std::endl;
        }
    }
    
    // Restart ICE if needed (e.g., network change)
    // client.restart_ice();
    
    // Clean up
    // client.close_ice();
    
    std::this_thread::sleep_for(std::chrono::minutes(1));
    
    return 0;
}
```

### 8. Configuration Persistence

```cpp
#include "librats.h"
#include <iostream>

int main() {
    librats::RatsClient client(8080);
    
    // Set custom data directory for config files
    client.set_data_directory("./my_app_data");
    
    // Load saved configuration (if exists)
    if (client.load_configuration()) {
        std::cout << "📄 Loaded existing configuration" << std::endl;
    } else {
        std::cout << "📄 Using default configuration" << std::endl;
    }
    
    // Get our persistent peer ID
    std::cout << "🆔 Our peer ID: " << client.get_our_peer_id() << std::endl;
    
    client.start();
    
    // Try to reconnect to previously connected peers
    int reconnect_attempts = client.load_and_reconnect_peers();
    std::cout << "🔄 Attempted to reconnect to " << reconnect_attempts << " previous peers" << std::endl;
    
    // Configuration is automatically saved when client stops
    // Files created: config.json, peers.rats, peers_ever.rats
    
    // Manual save if needed
    client.save_configuration();
    client.save_historical_peers();
    
    std::cout << "💾 Configuration will be saved to: " << client.get_data_directory() << std::endl;
    
    return 0;
}
```

### 9. Logging Configuration

```cpp
#include "librats.h"
#include <iostream>

int main() {
    librats::RatsClient client(8080);
    
    // Enable and configure logging
    client.set_logging_enabled(true);
    client.set_log_file_path("librats_app.log");
    client.set_log_level("INFO");  // DEBUG, INFO, WARN, ERROR
    client.set_log_colors_enabled(true);
    client.set_log_timestamps_enabled(true);
    
    // Configure log file rotation
    client.set_log_rotation_size(5 * 1024 * 1024);  // 5MB max file size
    client.set_log_retention_count(3);               // Keep 3 old log files
    
    std::cout << "📝 Logging to: " << client.get_log_file_path() << std::endl;
    std::cout << "📊 Log level: " << static_cast<int>(client.get_log_level()) << std::endl;
    std::cout << "🎨 Colors enabled: " << (client.is_log_colors_enabled() ? "Yes" : "No") << std::endl;
    
    client.start();
    
    // All librats operations will now be logged
    client.broadcast_string_to_peers("This action will be logged!");
    
    // Clear log file if needed (uncomment to use)
    // client.clear_log_file();
    
    return 0;
}
```

### 10. Distributed Storage (requires `RATS_STORAGE`)

```cpp
#include "librats.h"
#include <iostream>

int main() {
    librats::RatsClient client(8080);
    
    // Start the client first
    client.start();
    client.start_dht_discovery();
    
    // Check if storage is available (requires RATS_STORAGE build flag)
    if (!client.is_storage_available()) {
        std::cerr << "Storage not available (rebuild with RATS_STORAGE=ON)" << std::endl;
        return 1;
    }
    
    // Store different types of data
    client.storage_put("user:name", "Alice");
    client.storage_put("user:age", int64_t(25));
    client.storage_put("user:score", 98.5);
    client.storage_put_json("user:preferences", {{"theme", "dark"}, {"notifications", true}});
    
    // Store binary data
    std::vector<uint8_t> avatar_data = {0x89, 0x50, 0x4E, 0x47}; // PNG header
    client.storage_put("user:avatar", avatar_data);
    
    // Read data back with type-safe getters
    auto name = client.storage_get_string("user:name");
    auto age = client.storage_get_int("user:age");
    auto score = client.storage_get_double("user:score");
    auto prefs = client.storage_get_json("user:preferences");
    
    if (name) std::cout << "Name: " << *name << std::endl;
    if (age) std::cout << "Age: " << *age << std::endl;
    if (score) std::cout << "Score: " << *score << std::endl;
    if (prefs) std::cout << "Theme: " << (*prefs)["theme"] << std::endl;
    
    // Check if key exists
    if (client.storage_has("user:name")) {
        std::cout << "User name is stored" << std::endl;
    }
    
    // Query keys by prefix
    std::vector<std::string> user_keys = client.storage_keys_with_prefix("user:");
    std::cout << "Found " << user_keys.size() << " user keys" << std::endl;
    
    // Delete a key
    client.storage_delete("user:avatar");
    
    // Get storage statistics
    auto stats = client.get_storage_statistics();
    std::cout << "Total entries: " << stats["total_entries"] << std::endl;
    std::cout << "Synced: " << (client.is_storage_synced() ? "Yes" : "No") << std::endl;
    
    // Request sync from connected peers
    client.storage_request_sync();
    
    // Keep running to allow P2P sync
    std::this_thread::sleep_for(std::chrono::minutes(1));
    
    return 0;
}
```

### 11. Node.js Quick Start

For more Node.js examples and TypeScript usage, see the [Node.js documentation](nodejs/README.md).

## 📖 API Documentation

### Core Classes

#### `RatsClient`
The main class providing comprehensive P2P networking capabilities:

```cpp
// Constructor
RatsClient(int listen_port, int max_peers = 10, const std::string& bind_address = "");

// Core lifecycle
bool start();
void stop();
void shutdown_all_threads();
bool is_running() const;

// Connection methods
bool connect_to_peer(const std::string& host, int port);

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

// Configuration persistence
bool load_configuration();
bool save_configuration();
bool set_data_directory(const std::string& directory_path);
std::string get_data_directory() const;
int load_and_reconnect_peers();
bool load_historical_peers();
bool save_historical_peers();
void clear_historical_peers();
std::vector<RatsPeer> get_historical_peers() const;

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

// Logging Control API
void set_logging_enabled(bool enabled);
bool is_logging_enabled() const;
void set_log_file_path(const std::string& file_path);
std::string get_log_file_path() const;
void set_log_level(LogLevel level);
void set_log_level(const std::string& level_str);
LogLevel get_log_level() const;
void set_log_colors_enabled(bool enabled);
bool is_log_colors_enabled() const;
void set_log_timestamps_enabled(bool enabled);
bool is_log_timestamps_enabled() const;
void set_log_rotation_size(size_t max_size_bytes);
void set_log_retention_count(int count);
void clear_log_file();

// File Transfer API
FileTransferManager& get_file_transfer_manager();
bool is_file_transfer_available() const;

// File Transfer Operations
std::string send_file(const std::string& peer_id, const std::string& file_path, const std::string& remote_filename = "");
std::string send_directory(const std::string& peer_id, const std::string& directory_path, const std::string& remote_directory_name = "", bool recursive = true);
std::string request_file(const std::string& peer_id, const std::string& remote_file_path, const std::string& local_path);
std::string request_directory(const std::string& peer_id, const std::string& remote_directory_path, const std::string& local_directory_path, bool recursive = true);

// Transfer Control
bool accept_file_transfer(const std::string& transfer_id, const std::string& local_path);
bool reject_file_transfer(const std::string& transfer_id, const std::string& reason = "");
bool pause_file_transfer(const std::string& transfer_id);
bool resume_file_transfer(const std::string& transfer_id);
bool cancel_file_transfer(const std::string& transfer_id);

// Transfer Information
std::shared_ptr<FileTransferProgress> get_file_transfer_progress(const std::string& transfer_id) const;
std::vector<std::shared_ptr<FileTransferProgress>> get_active_file_transfers() const;
nlohmann::json get_file_transfer_statistics() const;
void set_file_transfer_config(const FileTransferConfig& config);
const FileTransferConfig& get_file_transfer_config() const;

// Transfer Event Handlers
void on_file_transfer_progress(FileTransferProgressCallback callback);
void on_file_transfer_completed(FileTransferCompletedCallback callback);
void on_file_transfer_request(FileTransferRequestCallback callback);
void on_directory_transfer_progress(DirectoryTransferProgressCallback callback);
void on_file_request(FileRequestCallback callback);
void on_directory_request(DirectoryRequestCallback callback);

// ICE/NAT Traversal API
IceManager& get_ice_manager();
bool is_ice_available() const;

// ICE Server Configuration
void add_stun_server(const std::string& host, uint16_t port = 3478);
void add_turn_server(const std::string& host, uint16_t port,
                     const std::string& username, const std::string& password);
void clear_ice_servers();

// ICE Candidate Gathering
bool gather_ice_candidates();
std::vector<IceCandidate> get_ice_candidates() const;
bool is_ice_gathering_complete() const;

// Public Address Discovery
std::optional<std::pair<std::string, uint16_t>> get_public_address() const;
std::optional<StunMappedAddress> discover_public_address(
    const std::string& server = "stun.l.google.com",
    uint16_t port = 19302, int timeout_ms = 5000);

// Remote Candidates (from signaling)
void add_remote_ice_candidate(const IceCandidate& candidate);
void add_remote_ice_candidates_from_sdp(const std::vector<std::string>& sdp_lines);
void end_of_remote_ice_candidates();

// ICE Connectivity
void start_ice_checks();
IceConnectionState get_ice_connection_state() const;
IceGatheringState get_ice_gathering_state() const;
bool is_ice_connected() const;
std::optional<IceCandidatePair> get_ice_selected_pair() const;

// ICE Event Callbacks
void on_ice_candidates_gathered(IceCandidatesCallback callback);
void on_ice_new_candidate(IceNewCandidateCallback callback);
void on_ice_gathering_state_changed(IceGatheringStateCallback callback);
void on_ice_connection_state_changed(IceConnectionStateCallback callback);
void on_ice_selected_pair(IceSelectedPairCallback callback);

// ICE Configuration and Lifecycle
void set_ice_config(const IceConfig& config);
const IceConfig& get_ice_config() const;
void close_ice();
void restart_ice();

// Encryption API
bool initialize_encryption(bool enable);
void set_encryption_enabled(bool enabled);
bool is_encryption_enabled() const;
bool is_peer_encrypted(const std::string& peer_id) const;
bool set_noise_static_keypair(const uint8_t private_key[32]);
std::vector<uint8_t> get_noise_static_public_key() const;
std::vector<uint8_t> get_peer_noise_public_key(const std::string& peer_id) const;
std::vector<uint8_t> get_peer_handshake_hash(const std::string& peer_id) const;

// Automatic Reconnection API (enabled by default)
void set_reconnect_enabled(bool enabled);
bool is_reconnect_enabled() const;
void set_reconnect_config(const ReconnectConfig& config);
const ReconnectConfig& get_reconnect_config() const;
size_t get_reconnect_queue_size() const;
void clear_reconnect_queue();
std::vector<ReconnectInfo> get_reconnect_queue() const;
```

### Configuration Structures

#### `ReconnectConfig`
Automatic reconnection configuration structure:

```cpp
struct ReconnectConfig {
    int max_attempts = 3;                                      // Maximum reconnection attempts
    std::vector<int> retry_intervals_seconds = {5, 30, 120};   // Intervals between attempts
    int stable_connection_threshold_seconds = 60;              // Duration to be considered "stable"
    int stable_first_retry_seconds = 2;                        // First retry for stable peers (faster)
    bool enabled = true;                                       // Auto-reconnection enabled by default
};
```

#### `ReconnectInfo`
Information about a peer pending reconnection:

```cpp
struct ReconnectInfo {
    std::string peer_id;                                       // Peer ID for identification
    std::string ip;                                            // IP address to reconnect to
    uint16_t port;                                             // Port number
    int attempt_count;                                         // Current reconnection attempt number
    std::chrono::milliseconds connection_duration;             // How long peer was connected
    bool is_stable;                                            // Was this a stable connection?
    std::chrono::steady_clock::time_point next_attempt_time;   // When to attempt next reconnection
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
    
    // Encryption state
    bool encryption_enabled;
    bool noise_handshake_completed;
    std::shared_ptr<rats::NoiseCipherState> send_cipher;
    std::shared_ptr<rats::NoiseCipherState> recv_cipher;
    std::vector<uint8_t> remote_static_key;
    
    // Helper methods
    bool is_handshake_completed() const;
    bool is_handshake_failed() const;
    bool is_noise_encrypted() const;
};
```

#### `FileTransferConfig`
File transfer configuration structure:

```cpp
struct FileTransferConfig {
    uint32_t chunk_size;            // Size of each chunk (default: 64KB)
    uint32_t max_concurrent_chunks; // Max chunks in flight (default: 4)
    uint32_t max_retries;           // Max retry attempts per chunk (default: 3)
    uint32_t timeout_seconds;       // Timeout per chunk (default: 30)
    bool verify_checksums;          // Verify chunk checksums (default: true)
    bool allow_resume;              // Allow resuming interrupted transfers (default: true)
    std::string temp_directory;     // Temporary directory for incomplete files
    
    FileTransferConfig() 
        : chunk_size(65536),        // 64KB chunks
          max_concurrent_chunks(4), 
          max_retries(3),
          timeout_seconds(30),
          verify_checksums(true),
          allow_resume(true),
          temp_directory("./temp_transfers") {}
};
```

#### `FileTransferProgress`
Transfer progress tracking structure:

```cpp
struct FileTransferProgress {
    std::string transfer_id;        // Transfer identifier
    std::string peer_id;            // Peer we're transferring with
    FileTransferDirection direction; // Send or receive
    FileTransferStatus status;      // Current status
    
    // File information
    std::string filename;           // File being transferred
    std::string local_path;         // Local file path
    uint64_t file_size;             // Total file size
    
    // Progress tracking
    uint64_t bytes_transferred;     // Bytes completed
    uint64_t total_bytes;           // Total bytes to transfer
    uint32_t chunks_completed;      // Chunks successfully transferred
    uint32_t total_chunks;          // Total chunks in transfer
    
    // Performance metrics
    std::chrono::steady_clock::time_point start_time;    // Transfer start time
    std::chrono::steady_clock::time_point last_update;   // Last progress update
    double transfer_rate_bps;       // Current transfer rate (bytes/second)
    double average_rate_bps;        // Average transfer rate since start
    std::chrono::milliseconds estimated_time_remaining; // ETA
    
    // Error information
    std::string error_message;      // Error details if failed
    uint32_t retry_count;           // Number of retries attempted
    
    // Helper methods
    double get_completion_percentage() const;  // 0.0 to 100.0
    std::chrono::milliseconds get_elapsed_time() const;
    void update_transfer_rates(uint64_t new_bytes_transferred);
};
```

#### `FileMetadata`
File information structure:

```cpp
struct FileMetadata {
    std::string filename;           // Original filename
    std::string relative_path;      // Relative path within directory structure
    uint64_t file_size;             // Total file size in bytes
    uint64_t last_modified;         // Last modification timestamp
    std::string mime_type;          // MIME type of the file
    std::string checksum;           // Full file checksum
};
```

#### `StunMappedAddress`
Structure returned by STUN public address discovery:

```cpp
struct StunMappedAddress {
    StunAddressFamily family;   // IPv4 or IPv6
    std::string address;        // Public IP address
    uint16_t port;              // Mapped port number
    
    bool is_valid() const;      // Check if address is valid
};
```

#### `IceConfig`
ICE configuration structure for NAT traversal:

```cpp
struct IceConfig {
    std::vector<IceServer> ice_servers;     // STUN/TURN servers
    bool gather_host_candidates = true;      // Gather local interface addresses
    bool gather_srflx_candidates = true;     // Gather public addresses via STUN
    bool gather_relay_candidates = false;    // Gather TURN relay addresses
    int gathering_timeout_ms = 5000;         // Candidate gathering timeout
    int check_timeout_ms = 500;              // Connectivity check timeout per attempt
    int check_max_retries = 5;               // Max connectivity check retries
    std::string software = "librats";        // Software attribute for STUN
    
    // Helper methods
    void add_stun_server(const std::string& host, uint16_t port = 3478);
    void add_turn_server(const std::string& host, uint16_t port,
                         const std::string& username, const std::string& password);
};
```

#### `IceCandidate`
ICE candidate structure representing a network endpoint:

```cpp
struct IceCandidate {
    IceCandidateType type;          // Host, ServerReflexive, PeerReflexive, Relay
    std::string foundation;          // Unique identifier for candidate
    uint32_t component_id;           // Component ID (typically 1)
    IceTransportProtocol transport;  // UDP or TCP
    uint32_t priority;               // Candidate priority
    std::string address;             // IP address
    uint16_t port;                   // Port number
    std::string related_address;     // Related address (for srflx/relay)
    uint16_t related_port;           // Related port
    
    // Helper methods
    std::string to_sdp_attribute() const;   // Format as SDP "a=candidate:..."
    static std::optional<IceCandidate> from_sdp_attribute(const std::string& sdp);
    std::string type_string() const;        // "host", "srflx", "prflx", "relay"
    std::string address_string() const;     // "ip:port" format
    
    // Priority calculation (RFC 5245)
    static uint32_t compute_priority(IceCandidateType type, 
                                     uint32_t local_preference = 65535,
                                     uint32_t component_id = 1);
};
```

#### `IceCandidatePair`
ICE candidate pair representing a local-remote connection attempt:

```cpp
struct IceCandidatePair {
    IceCandidate local;              // Local candidate
    IceCandidate remote;             // Remote candidate
    IceCandidatePairState state;     // Frozen, Waiting, InProgress, Succeeded, Failed
    uint64_t priority;               // Pair priority
    bool nominated;                  // Nominated for use
    int check_count;                 // Number of checks performed
    
    std::string key() const;         // Unique identifier for the pair
    
    // Priority calculation (RFC 5245)
    static uint64_t compute_priority(uint32_t controlling_priority,
                                     uint32_t controlled_priority,
                                     bool is_controlling);
};
```

#### `IceConnectionState`
ICE connection state enumeration:

```cpp
enum class IceConnectionState {
    New,            // Initial state
    Gathering,      // Gathering candidates
    Checking,       // Performing connectivity checks
    Connected,      // At least one valid pair found
    Completed,      // ICE processing complete
    Failed,         // ICE processing failed
    Disconnected,   // Connection lost
    Closed          // ICE agent closed
};
```

#### `IceGatheringState`
ICE gathering state enumeration:

```cpp
enum class IceGatheringState {
    New,            // Not started
    Gathering,      // Gathering in progress
    Complete        // Gathering complete
};
```

#### `StorageConfig` (requires `RATS_STORAGE`)
Distributed storage configuration structure:

```cpp
struct StorageConfig {
    std::string data_directory;      // Directory for storage files (default: "./storage")
    std::string database_name;       // Database filename prefix (default: "rats_storage")
    bool enable_compression;         // Enable LZ4 compression for values (default: false)
    bool enable_sync;                // Enable network synchronization (default: true)
    uint32_t sync_batch_size;        // Number of entries per sync batch (default: 100)
    uint32_t compaction_threshold;   // Number of tombstones before compaction (default: 1000)
    uint32_t max_value_size;         // Maximum value size in bytes (default: 16MB)
    bool persist_to_disk;            // Whether to persist data to disk (default: true)
};
```

#### `StorageEntry` (requires `RATS_STORAGE`)
Storage entry structure representing a single key-value pair:

```cpp
struct StorageEntry {
    std::string key;                 // Key string
    StorageValueType type;           // Value type (BINARY, STRING, INT64, DOUBLE, JSON)
    std::vector<uint8_t> data;       // Serialized value data
    uint64_t timestamp_ms;           // Unix timestamp in milliseconds (for LWW)
    std::string origin_peer_id;      // Peer that created/modified this entry
    uint32_t checksum;               // CRC32 checksum for integrity
    bool deleted;                    // Tombstone marker for deleted entries
    
    // Compare for LWW resolution (returns true if this entry wins)
    bool wins_over(const StorageEntry& other) const;
};
```

#### `StorageChangeEvent` (requires `RATS_STORAGE`)
Storage change event structure passed to change callbacks:

```cpp
struct StorageChangeEvent {
    StorageOperation operation;      // PUT or DELETE
    std::string key;                 // Affected key
    StorageValueType type;           // Value type (for PUT)
    std::vector<uint8_t> old_data;   // Previous value (if any)
    std::vector<uint8_t> new_data;   // New value (for PUT)
    uint64_t timestamp_ms;           // Operation timestamp
    std::string origin_peer_id;      // Peer that made the change
    bool is_remote;                  // True if change came from another peer
};
```

#### Storage API Methods (requires `RATS_STORAGE`)

The `RatsClient` class provides the following storage methods when built with `RATS_STORAGE`:

```cpp
// Storage availability
StorageManager& get_storage_manager();
bool is_storage_available() const;

// Put operations (store values)
bool storage_put(const std::string& key, const std::string& value);
bool storage_put(const std::string& key, int64_t value);
bool storage_put(const std::string& key, double value);
bool storage_put(const std::string& key, const std::vector<uint8_t>& value);
bool storage_put_json(const std::string& key, const nlohmann::json& value);

// Get operations (retrieve values)
std::optional<std::string> storage_get_string(const std::string& key) const;
std::optional<int64_t> storage_get_int(const std::string& key) const;
std::optional<double> storage_get_double(const std::string& key) const;
std::optional<std::vector<uint8_t>> storage_get_binary(const std::string& key) const;
std::optional<nlohmann::json> storage_get_json(const std::string& key) const;

// Delete and query operations
bool storage_delete(const std::string& key);
bool storage_has(const std::string& key) const;
std::vector<std::string> storage_keys() const;
std::vector<std::string> storage_keys_with_prefix(const std::string& prefix) const;
size_t storage_size() const;

// Synchronization
bool storage_request_sync();
bool is_storage_synced() const;

// Statistics and configuration
nlohmann::json get_storage_statistics() const;
void set_storage_config(const StorageConfig& config);
const StorageConfig& get_storage_config() const;

// Event handlers
void on_storage_change(StorageChangeCallback callback);
void on_storage_sync_complete(StorageSyncCompleteCallback callback);
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
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │ File Transfer   │ │Distributed Storage│ │ BitTorrent      │   │
│ │    Manager      │ │   (RATS_STORAGE)│ │(RATS_SEARCH)    │    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│ Discovery & Networking Layer                                    │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │ DHT (Wide-Area) │ │ mDNS (Local Net)│ │ ICE/STUN/TURN   │    │
│ │ BT Mainline DHT │ │   224.0.0.251   │ │  NAT Traversal  │    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
│ ┌─────────────────────────────────────────────────────────┐    │
│ │           Direct Sockets - IPv4/IPv6 Stack              │    │
│ └─────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│ Platform Abstraction Layer                                      │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │   Windows       │ │      Linux      │ │     macOS       │    │
│ │ WinSock2/bcrypt │ │  BSD Sockets    │ │  BSD Sockets    │    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## 🛠️ Building

### Supported Platforms & Language Bindings

librats provides comprehensive cross-platform support with bindings for multiple programming languages:

#### Native C++ Support

| Platform | Build Environment | Compiler | Status |
|----------|------------------|----------|---------|
| **Windows** | MinGW-w64 | GCC 7+ | ✅ **Fully Supported** |
| **Windows** | Visual Studio | MSVC 2017+ | ✅ **Fully Supported** |
| **Linux** | Native | GCC 7+, Clang 5+ | ✅ **Fully Supported** |
| **macOS** | Xcode/Native | Clang 10+ | ✅ **Fully Supported** |

#### Language Bindings & Wrappers

| Language/Platform | Binding Type | Status | Timeline | Notes |
|-------------------|--------------|--------|----------|-------|
| **C/C++** | Native Library | ✅ **Fully Supported** | **Available Now** | Core implementation with full feature set |
| **Android (NDK)** | Native C++ | ✅ **Fully Supported** | **Available Now** | Android NDK integration with JNI bindings |
| **Android (Java)** | JNI Wrapper | ✅ **Fully Supported** | **Available Now** | High-level Java API for Android apps |
| **Node.js** | Native Addon | ✅ **Fully Supported** | **Available Now** | Native addon with async/await support ([npm](https://www.npmjs.com/package/librats)) |
| **Python** | C Extension | ✅ **Fully Supported** | **Available Now** | CPython extension with asyncio integration |
| **Rust** | FFI Bindings | 📋 **Planned** | **Soon** | Safe Rust bindings with tokio async support |
| **Go** | CGO Bindings | 📋 **Future** | **Soon** | CGO wrapper for Go applications |
| **C#/.NET** | P/Invoke | 📋 **Future** | **Soon** | .NET bindings for Windows/Linux/macOS |

#### Mobile Platform Support

| Platform | Implementation | Status | Features |
|----------|----------------|--------|----------|
| **Android** | NDK + JNI | ✅ **Fully Supported** | Full P2P networking, file transfer, GossipSub |
| **iOS** | Native C++ | 📋 **Planned** | Swift/Objective-C bindings planned |
| **React Native** | Native Module | 📋 **Future** | Cross-platform mobile development |
| **Flutter** | FFI Plugin | 📋 **Future** | Dart FFI integration |

#### Web Platform Support

| Platform | Technology | Status | Limitations |
|----------|------------|--------|-------------|
| **Browser (WASM)** | WebAssembly | 📋 **Research** | Limited by browser networking APIs |
| **Electron** | Node.js Module | 📋 **Planned** | Desktop app development |
| **Tauri** | Rust Bindings | 📋 **Future** | Lightweight desktop apps |

**Legend:**
- ✅ **Fully Supported**: Production-ready with comprehensive testing
- 🔶 **In Development**: Active development, preview/beta available
- 📋 **Planned**: Confirmed for development, timeline estimated
- 📋 **Future**: Under consideration, timeline not confirmed
- 📋 **Research**: Investigating feasibility and implementation approach

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
cmake .. -G "Visual Studio 16 2019"
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

librats provides several CMake options to customize your build:

| Option | Default | Description |
|--------|---------|-------------|
| `RATS_BUILD_TESTS` | `ON` | Build unit tests with GoogleTest |
| `RATS_ENABLE_ASAN` | `OFF` | Enable AddressSanitizer for memory debugging |
| `RATS_BINDINGS` | `ON` | Enable C API bindings for FFI support |
| `RATS_CROSSCOMPILING` | `OFF` | Force cross-compilation flags |
| `RATS_SHARED_LIBRARY` | `OFF` | Build as shared library (.dll/.so/.dylib) |
| `RATS_STATIC_LIBRARY` | `ON` | Build as static library (.a/.lib) |
| `RATS_SEARCH_FEATURES` | `OFF` | Enable Rats Search feature (like Bittorrent / DHT spider algorithm) |
| `RATS_STORAGE` | `OFF` | Enable distributed key-value storage with P2P synchronization |

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

#### Method 1: Using CMake FetchContent (Recommended)

Add librats directly to your CMakeLists.txt:

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyP2PApp)

set(CMAKE_CXX_STANDARD 17)

# Fetch librats from GitHub
include(FetchContent)
FetchContent_Declare(
    librats
    GIT_REPOSITORY https://github.com/DEgITx/librats.git
    GIT_TAG master  # or specify a specific version/tag
)

# Configure librats build options before making it available
set(RATS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(RATS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(librats)

# Create your application
add_executable(my_p2p_app main.cpp)

# Link against librats
target_link_libraries(my_p2p_app PRIVATE rats)
```

#### Method 2: Using CMake add_subdirectory

Clone librats into your project or as a git submodule:

```bash
# As a git submodule
git submodule add https://github.com/DEgITx/librats.git external/librats

# Or just clone it
git clone https://github.com/DEgITx/librats.git external/librats
```

Then in your CMakeLists.txt:

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyP2PApp)

set(CMAKE_CXX_STANDARD 17)

# Configure librats options
set(RATS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(RATS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

# Add librats subdirectory
add_subdirectory(external/librats)

# Create your application
add_executable(my_p2p_app main.cpp)

# Link against librats
target_link_libraries(my_p2p_app PRIVATE rats)

# Include directories are automatically propagated
```

#### Method 3: Using Pre-built Library

If you've built librats separately:

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyP2PApp)

set(CMAKE_CXX_STANDARD 17)

# Specify librats location
set(LIBRATS_DIR "/path/to/librats")

# Create your application
add_executable(my_p2p_app main.cpp)

# Link against pre-built librats
target_include_directories(my_p2p_app PRIVATE 
    ${LIBRATS_DIR}/src
    ${LIBRATS_DIR}/build/src
)

target_link_libraries(my_p2p_app PRIVATE 
    ${LIBRATS_DIR}/build/lib/librats.a
    # Add system libraries based on platform
    $<$<PLATFORM_ID:Windows>:ws2_32 iphlpapi bcrypt>
    Threads::Threads
)

# Find threading library
find_package(Threads REQUIRED)
```

#### Method 4: Manual Compilation and Linking

**Compile your application:**

```bash
# Linux/macOS
g++ -std=c++17 -I/path/to/librats/src -I/path/to/librats/build/src \
    my_app.cpp /path/to/librats/build/lib/librats.a \
    -lpthread -o my_p2p_app

# Windows (MinGW)
g++ -std=c++17 -I/path/to/librats/src -I/path/to/librats/build/src \
    my_app.cpp /path/to/librats/build/lib/librats.a \
    -lws2_32 -liphlpapi -lbcrypt -o my_p2p_app.exe

# Windows (MSVC)
cl /std:c++17 /EHsc /I"C:\path\to\librats\src" /I"C:\path\to\librats\build\src" \
   my_app.cpp "C:\path\to\librats\build\lib\rats.lib" \
   ws2_32.lib iphlpapi.lib bcrypt.lib
```

#### Simple Integration Example

```cpp
// my_p2p_app.cpp
#include "librats.h"
#include <iostream>

int main() {
    // Create client on port 8080
    librats::RatsClient client(8080);
    
    // Set up callbacks
    client.set_connection_callback([](auto socket, const std::string& peer_id) {
        std::cout << "Peer connected: " << peer_id << std::endl;
    });
    
    client.set_string_data_callback([](auto socket, const std::string& peer_id, 
                                       const std::string& message) {
        std::cout << "Message from " << peer_id << ": " << message << std::endl;
    });
    
    // Start the client
    if (!client.start()) {
        std::cerr << "Failed to start client" << std::endl;
        return 1;
    }
    
    std::cout << "P2P client running on port 8080" << std::endl;
    
    // Your application logic here
    std::this_thread::sleep_for(std::chrono::hours(24));
    
    return 0;
}
```

#### Required System Libraries

When linking against librats, include these system libraries:

| Platform | Required Libraries |
|----------|-------------------|
| **Windows** | `ws2_32`, `iphlpapi`, `bcrypt` |
| **Linux** | `pthread` |
| **macOS** | `pthread` |
| **Android** | `log` |

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
- **Tests**: `build/bin/librats_tests` (if `RATS_BUILD_TESTS=ON`)

## 🎯 Usage Examples

### Simple Chat Application

```bash
# Terminal 1: Start first node
./build/bin/rats-client 8080

# Terminal 2: Start second node and connect
./build/bin/rats-client 8081 localhost 8080
```

### File Sharing Application

```cpp
#include "librats.h"

class FileShareApp {
private:
    librats::RatsClient client_;
    
public:
    FileShareApp(int port) : client_(port) {
        // Set up file transfer callbacks
        client_.on_file_transfer_progress([](const librats::FileTransferProgress& progress) {
            std::cout << "📊 " << progress.filename << ": " 
                      << progress.get_completion_percentage() << "% complete" << std::endl;
            std::cout << "Rate: " << (progress.transfer_rate_bps / 1024 / 1024) << " MB/s" << std::endl;
        });
        
        client_.on_file_transfer_completed([](const std::string& transfer_id, bool success, const std::string& error) {
            if (success) {
                std::cout << "✅ Transfer completed: " << transfer_id.substr(0, 8) << std::endl;
            } else {
                std::cout << "❌ Transfer failed: " << error << std::endl;
            }
        });
        
        client_.on_file_transfer_request([](const std::string& peer_id, const librats::FileMetadata& metadata, const std::string& transfer_id) {
            std::cout << "📥 File request from " << peer_id.substr(0, 8) << std::endl;
            std::cout << "File: " << metadata.filename << " (" << metadata.file_size << " bytes)" << std::endl;
            
            // Auto-accept files smaller than 100MB
            return metadata.file_size < 100 * 1024 * 1024;
        });
        
        client_.on_file_request([](const std::string& peer_id, const std::string& file_path, const std::string& transfer_id) {
            std::cout << "📤 File request from " << peer_id.substr(0, 8) << ": " << file_path << std::endl;
            
            // Allow access to files in "shared" directory only
            return file_path.find("../") == std::string::npos && 
                   file_path.substr(0, 7) == "shared/";
        });
        
        // Set up connection callbacks
        client_.set_connection_callback([](auto socket, const std::string& peer_id) {
            std::cout << "Peer connected: " << peer_id.substr(0, 8) << std::endl;
        });
        
        // Configure optimized file transfer settings
        librats::FileTransferConfig config;
        config.chunk_size = 256 * 1024;         // 256KB chunks for better performance
        config.max_concurrent_chunks = 8;       // 8 parallel chunks
        config.verify_checksums = true;         // Ensure data integrity
        config.allow_resume = true;             // Enable resume capability
        client_.set_file_transfer_config(config);
        
        // Start all services
        client_.start();
        client_.start_dht_discovery();
        client_.start_mdns_discovery("file-share");
    }
    
    std::string share_file(const std::string& peer_id, const std::string& file_path) {
        return client_.send_file(peer_id, file_path);
    }
    
    std::string share_directory(const std::string& peer_id, const std::string& directory_path) {
        return client_.send_directory(peer_id, directory_path, "", true);
    }
    
    std::string request_file(const std::string& peer_id, const std::string& remote_file, const std::string& local_path) {
        return client_.request_file(peer_id, remote_file, local_path);
    }
    
    void pause_transfer(const std::string& transfer_id) {
        client_.pause_file_transfer(transfer_id);
    }
    
    void resume_transfer(const std::string& transfer_id) {
        client_.resume_file_transfer(transfer_id);
    }
    
    void get_transfer_stats() {
        auto stats = client_.get_file_transfer_statistics();
        std::cout << "Total bytes transferred: " << stats["total_bytes_transferred"] << std::endl;
        std::cout << "Active transfers: " << stats["active_transfers"] << std::endl;
    }
    
    void connect_to(const std::string& host, int port) {
        client_.connect_to_peer(host, port);
    }
};
```

## 🎯 More Examples

### Complete Chat Application

```cpp
#include "librats.h"
#include <iostream>
#include <string>
#include <thread>

int main() {
    librats::RatsClient client(8080);
    
    // Set up chat message handling
    client.on("chat_message", [](const std::string& peer_id, const nlohmann::json& data) {
        std::string username = data.value("username", "Unknown");
        std::string message = data.value("message", "");
        std::cout << "[" << username << "]: " << message << std::endl;
    });
    
    // Handle user join/leave
    client.on("user_joined", [](const std::string& peer_id, const nlohmann::json& data) {
        std::cout << "*** " << data["username"].get<std::string>() << " joined the chat ***" << std::endl;
    });
    
    client.set_connection_callback([&](socket_t socket, const std::string& peer_id) {
        // Announce our presence
        nlohmann::json join_msg;
        join_msg["username"] = "User_" + client.get_our_peer_id().substr(0, 8);
        client.send("user_joined", join_msg);
    });
    
    client.start();
    client.start_dht_discovery(); // Auto-discover other chat users
    
    std::cout << "🐀 librats Chat - Type messages and press Enter" << std::endl;
    std::cout << "Type 'quit' to exit" << std::endl;
    
    std::string input;
    while (std::getline(std::cin, input)) {
        if (input == "quit") break;
        
        if (!input.empty()) {
            nlohmann::json chat_msg;
            chat_msg["username"] = "User_" + client.get_our_peer_id().substr(0, 8);
            chat_msg["message"] = input;
            chat_msg["timestamp"] = std::time(nullptr);
            client.send("chat_message", chat_msg);
        }
    }
    
    return 0;
}
```

## 📚 Documentation

Comprehensive documentation is available:

- **[File Transfer Example](docs/FILE_TRANSFER_EXAMPLE.md)** - Efficient P2P file and directory transfer
- **[Custom Protocol Setup](docs/CUSTOM_PROTOCOL.md)** - How to configure custom protocols
- **[Message Exchange API](docs/MESSAGE_EXCHANGE_API.md)** - Event-driven messaging system  
- **[GossipSub Example](docs/GOSSIPSUB_EXAMPLE.md)** - Publish-subscribe messaging with GossipSub
- **[mDNS Discovery](docs/MDNS_DISCOVERY.md)** - Local network peer discovery
- **[Noise Encryption](docs/NOISE_ENCRYPTION.md)** - End-to-end encryption details
- **[BitTorrent Example](docs/BITTORRENT_EXAMPLE.md)** - BitTorrent protocol implementation
- **Distributed Storage** - Synchronized key-value storage (see API examples above, requires `RATS_STORAGE`)

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
| **Startup Memory** | ~1.6 MB | ~50-80 MB | **31-50x less** |
| **Memory per Peer** | ~80 KB | ~4-6 MB | **50-75x less** |
| **Peak Memory (100 peers)** | ~9.4 MB | 400-600 MB | **42-64x less** |
| **CPU Usage (idle)** | 0-1% | 15-25% | **15-25x less** |
| **CPU Usage (peak)** | 1-2% | 80-100% | **5-16x less** |

### Network Traffic (DHT Discovery)

| Metric | Traffic |
|--------|---------|
| **DHT Discovery (idle)** | ~350-450 bytes/sec |

The DHT discovery process uses minimal network bandwidth — only **350-450 bytes per second** during continuous peer discovery. This ultra-low network footprint makes librats ideal for bandwidth-constrained environments, mobile devices, and applications where network efficiency is critical.

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

### **Developer Experience**
- **Simple API**: Easy to learn and integrate
- **Modern C++**: Takes advantage of C++17 features
- **Excellent documentation**: Comprehensive guides and examples
- **Active development**: Regular updates and improvements
- **Configuration persistence**: Automatic saving and loading of settings

## Contributing

We welcome contributions from the community! There are many ways to contribute:

Please see our [Contributing Guide](CONTRIBUTING.md) for detailed guidelines on:
- Code style and conventions
- Setting up your development environment
- Running tests
- Submitting pull requests

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

- **nlohmann/json**: For the excellent JSON library integration
- **Contributors**: Everyone who has contributed to making librats better
