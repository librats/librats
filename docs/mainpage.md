# librats API Reference {#mainpage}

Welcome to the **librats** API documentation. librats is a high-performance, lightweight peer-to-peer networking library with C++, C, Node.js, Java, Python, and Android support.

## Quick Links

- [Main Website](https://librats.com)
- [GitHub Repository](https://github.com/DEgITx/librats)
- [npm Package](https://www.npmjs.com/package/librats)

## Getting Started

The main entry point for librats is the librats::RatsClient class. Here's a quick example:

```cpp
#include "librats.h"

int main() {
    // Create a P2P client on port 8080
    librats::RatsClient client(8080);
    
    // Set up callbacks
    client.set_connection_callback([](socket_t socket, const std::string& peer_id) {
        std::cout << "Peer connected: " << peer_id << std::endl;
    });
    
    client.set_string_data_callback([](socket_t socket, const std::string& peer_id, 
                                       const std::string& message) {
        std::cout << "Message: " << message << std::endl;
    });
    
    // Start the client
    client.start();
    
    // Connect to another peer
    client.connect_to_peer("192.168.1.100", 8080);
    
    return 0;
}
```

## Core Modules

### Connection Management
- librats::RatsClient - Main P2P client class
- librats::RatsPeer - Peer information structure
- librats::NatTraversalConfig - NAT traversal configuration

### Messaging
- Message Exchange API (`on()`, `once()`, `off()`, `send()`)
- librats::GossipSub - Publish-subscribe messaging

### File Transfer
- librats::FileTransferManager - File transfer management
- librats::FileTransferConfig - Transfer configuration
- librats::FileTransferProgress - Transfer progress tracking

### Discovery
- librats::DhtClient - DHT peer discovery
- librats::MdnsClient - Local network discovery
- librats::StunClient - STUN/NAT traversal

### Security
- Noise Protocol encryption (Curve25519 + ChaCha20-Poly1305)
- librats::NoiseKey - Encryption key management

## Feature Highlights

### NAT Traversal
librats provides industry-leading NAT traversal with 99%+ success rate:
- ICE (Interactive Connectivity Establishment)
- STUN for public IP discovery
- TURN relay support
- UDP/TCP hole punching

### GossipSub Messaging
Scalable publish-subscribe messaging:
```cpp
client.subscribe_to_topic("chat");
client.publish_to_topic("chat", "Hello, world!");

client.on_topic_message("chat", [](const std::string& peer_id, 
    const std::string& topic, const std::string& message) {
    std::cout << "Received: " << message << std::endl;
});
```

### File Transfer
Chunked file transfers with resume capability:
```cpp
client.send_file("peer_id", "/path/to/file.txt");
client.send_directory("peer_id", "/path/to/folder");
```

## Build Configuration

librats supports various build options:

| Option | Description |
|--------|-------------|
| `RATS_BUILD_TESTS` | Build unit tests |
| `RATS_STORAGE` | Enable distributed storage |
| `RATS_SEARCH_FEATURES` | Enable BitTorrent features |
| `RATS_SHARED_LIBRARY` | Build as shared library |

## License

librats is released under the MIT License.
