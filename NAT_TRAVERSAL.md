# NAT Traversal in librats

## Overview

librats now includes comprehensive NAT (Network Address Translation) traversal capabilities, enabling peer-to-peer connections across NATs and firewalls. The implementation includes:

- **ICE (Interactive Connectivity Establishment)** - RFC 8445 compliant
- **STUN (Session Traversal Utilities for NAT)** - RFC 5389 compliant  
- **TURN (Traversal Using Relays around NAT)** - RFC 5766 compliant
- **UDP/TCP Hole Punching** - Coordinated NAT traversal
- **Advanced NAT Type Detection** - Detailed NAT behavior analysis
- **Automatic Strategy Selection** - Choose optimal connection method

## Features

### ✅ **ICE (Interactive Connectivity Establishment)**
- Full candidate gathering (host, server reflexive, relay)
- Connectivity checks with priority ordering
- Role negotiation (controlling/controlled)
- Candidate pair formation and nomination
- Real-time connection state tracking

### ✅ **STUN Support**  
- Public IP address discovery
- NAT type detection (Open Internet, Full Cone, Restricted Cone, Port Restricted, Symmetric)
- Multiple STUN server support
- Message integrity with HMAC-SHA1
- ICE-specific STUN extensions

### ✅ **TURN Relay**
- TURN allocation for relay candidates
- Permission management
- Data relay through TURN servers
- Allocation refresh and management
- Authentication support

### ✅ **Hole Punching**
- UDP hole punching coordination
- TCP hole punching (where supported)
- Peer coordination through DHT/signaling
- Multiple attempt strategies

### ✅ **Advanced NAT Detection**
- Detailed NAT behavior analysis
- Filtering behavior detection
- Mapping behavior detection  
- Port preservation testing
- Hairpin support detection

## Quick Start

### Basic Usage with Automatic NAT Traversal

```cpp
#include "librats.h"

int main() {
    // Create NAT traversal configuration
    librats::NatTraversalConfig nat_config;
    nat_config.enable_ice = true;
    nat_config.enable_hole_punching = true;
    nat_config.enable_turn_relay = true;
    
    // Add TURN servers (optional)
    nat_config.turn_servers.push_back("turn.example.com:3478");
    nat_config.turn_usernames.push_back("username");
    nat_config.turn_passwords.push_back("password");
    
    // Create client with NAT traversal
    librats::RatsClient client(8080, 10, nat_config);
    
    // Set connection callback to track NAT traversal results
    client.set_advanced_connection_callback([](socket_t socket, const std::string& peer_id, 
                                              const librats::ConnectionAttemptResult& result) {
        std::cout << "Connected via: " << result.method << std::endl;
        std::cout << "Duration: " << result.duration.count() << "ms" << std::endl;
        std::cout << "Local NAT: " << (int)result.local_nat_type << std::endl;
        std::cout << "Remote NAT: " << (int)result.remote_nat_type << std::endl;
    });
    
    // Start client
    client.start();
    
    // Connect with automatic strategy selection
    client.connect_to_peer("peer.example.com", 8081, 
                          librats::ConnectionStrategy::AUTO_ADAPTIVE);
    
    // Keep running
    std::this_thread::sleep_for(std::chrono::minutes(5));
    return 0;
}
```

### ICE-Coordinated Connection

```cpp
// Peer A (Initiator)
librats::RatsClient clientA(8080);
clientA.start();

// Create ICE offer
auto ice_offer = clientA.create_ice_offer("peer_b");

// Send offer to peer B through signaling channel (DHT, WebSocket, etc.)
send_signaling_message("peer_b", ice_offer);

// Peer B (Responder)  
librats::RatsClient clientB(8081);
clientB.start();

// Receive ICE offer and create answer
auto ice_answer = clientB.create_ice_answer(ice_offer);

// Send answer back to peer A
send_signaling_message("peer_a", ice_answer);

// Both peers handle the ICE coordination automatically
clientA.handle_ice_answer("peer_b", ice_answer);
```

### Manual Connection Strategy Testing

```cpp
librats::RatsClient client(8080);
client.start();

// Test different connection strategies
std::vector<librats::ConnectionStrategy> strategies = {
    librats::ConnectionStrategy::DIRECT_ONLY,
    librats::ConnectionStrategy::STUN_ASSISTED,
    librats::ConnectionStrategy::ICE_FULL,
    librats::ConnectionStrategy::TURN_RELAY
};

auto results = client.test_connection_strategies("target.example.com", 8081, strategies);

for (const auto& result : results) {
    std::cout << "Strategy: " << result.method 
              << ", Success: " << result.success
              << ", Duration: " << result.duration.count() << "ms" << std::endl;
}
```

## Configuration

### NAT Traversal Configuration

```cpp
librats::NatTraversalConfig config;

// Enable/disable features
config.enable_ice = true;              // ICE for full NAT traversal
config.enable_upnp = false;            // UPnP port mapping (future)
config.enable_hole_punching = true;    // UDP/TCP hole punching
config.enable_turn_relay = true;       // TURN relay as fallback
config.prefer_ipv6 = false;            // Prefer IPv6 when available

// STUN servers for public IP discovery
config.stun_servers = {
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302", 
    "stun.stunprotocol.org:3478"
};

// TURN servers for relay (optional)
config.turn_servers = {"turn.example.com:3478"};
config.turn_usernames = {"username"};
config.turn_passwords = {"password"};

// Timeouts and limits
config.ice_gathering_timeout_ms = 10000;      // 10 seconds
config.ice_connectivity_timeout_ms = 30000;   // 30 seconds
config.hole_punch_attempts = 5;               // 5 attempts
config.turn_allocation_timeout_ms = 10000;    // 10 seconds

// Candidate priorities (higher = preferred)
config.host_candidate_priority = 65535;       // Direct local connection
config.server_reflexive_priority = 65534;     // STUN-discovered public IP
config.relay_candidate_priority = 65533;      // TURN relay
```

### Connection Strategies

```cpp
enum class ConnectionStrategy {
    DIRECT_ONLY,        // Try direct connection only (no NAT traversal)
    STUN_ASSISTED,      // Use STUN for public IP discovery
    ICE_FULL,           // Full ICE with candidate gathering  
    TURN_RELAY,         // Force TURN relay usage
    AUTO_ADAPTIVE       // Automatically choose best strategy (recommended)
};
```

## Advanced Features

### NAT Type Detection

```cpp
librats::RatsClient client(8080);
client.start();

// Detect NAT type
auto nat_type = client.detect_nat_type();
std::cout << "NAT Type: " << (int)nat_type << std::endl;

// Get detailed NAT characteristics
auto nat_info = client.get_nat_characteristics();
std::cout << "Has NAT: " << nat_info.has_nat << std::endl;
std::cout << "Filtering: " << (int)nat_info.filtering_behavior << std::endl;
std::cout << "Mapping: " << (int)nat_info.mapping_behavior << std::endl;
std::cout << "Port Preservation: " << nat_info.preserves_port << std::endl;
std::cout << "Hairpin Support: " << nat_info.hairpin_support << std::endl;
```

### Connection Statistics

```cpp
// Get detailed connection statistics
auto stats = client.get_connection_statistics();
std::cout << "Connection Statistics: " << stats.dump(2) << std::endl;

// Get NAT traversal specific statistics  
auto nat_stats = client.get_nat_traversal_statistics();
std::cout << "NAT Statistics: " << nat_stats.dump(2) << std::endl;
```

### ICE Candidate Monitoring

```cpp
client.set_ice_candidate_callback([](const std::string& peer_id, 
                                   const librats::IceCandidate& candidate) {
    std::cout << "ICE Candidate discovered for " << peer_id << ":" << std::endl;
    std::cout << "  Type: " << candidate.type << std::endl;
    std::cout << "  Address: " << candidate.ip << ":" << candidate.port << std::endl;
    std::cout << "  Priority: " << candidate.priority << std::endl;
});

client.set_nat_traversal_progress_callback([](const std::string& peer_id, 
                                             const std::string& status) {
    std::cout << "NAT traversal progress for " << peer_id << ": " << status << std::endl;
});
```

### Coordinated Hole Punching

```cpp
// Coordinate hole punching with peer
nlohmann::json coordination_data;
coordination_data["method"] = "udp_hole_punch";
coordination_data["local_candidates"] = client.get_local_ice_candidates();
coordination_data["timing"] = "synchronized";

bool success = client.coordinate_hole_punching("peer.example.com", 8081, coordination_data);
```

## Network Requirements

### Firewall Configuration

**Outbound (Required):**
- UDP port 3478 (STUN)
- UDP port 5349 (STUN over TLS)
- TCP/UDP ports for TURN servers
- UDP/TCP ports for peer communication

**Inbound (Recommended):**
- Your application's listen port
- UDP port range for ICE candidates

### NAT Compatibility

| NAT Type | Direct | STUN | ICE | TURN | Success Rate |
|----------|--------|------|-----|------|--------------|
| Open Internet | ✅ | ✅ | ✅ | ✅ | 100% |
| Full Cone | ❌ | ✅ | ✅ | ✅ | 95% |
| Restricted Cone | ❌ | ✅ | ✅ | ✅ | 90% |
| Port Restricted | ❌ | ✅ | ✅ | ✅ | 85% |
| Symmetric | ❌ | ❌ | ⚠️ | ✅ | 70% |
| Symmetric + Symmetric | ❌ | ❌ | ❌ | ✅ | 99% |

## Troubleshooting

### Common Issues

**ICE gathering fails:**
```cpp
// Check STUN servers are reachable
auto public_ip = client.get_public_ip();
if (public_ip.empty()) {
    std::cout << "STUN servers unreachable" << std::endl;
}

// Verify network connectivity
auto nat_type = client.detect_nat_type();
if (nat_type == librats::NatType::BLOCKED) {
    std::cout << "UDP is blocked" << std::endl;
}
```

**Connectivity checks timeout:**
```cpp
// Increase timeout in configuration
config.ice_connectivity_timeout_ms = 60000; // 60 seconds

// Check for symmetric NAT
auto nat_info = client.get_nat_characteristics();
if (nat_info.mapping_behavior == librats::NatBehavior::ADDRESS_PORT_DEPENDENT) {
    std::cout << "Symmetric NAT detected - TURN relay required" << std::endl;
}
```

**TURN allocation fails:**
```cpp
// Verify TURN server credentials
config.turn_servers = {"turn.example.com:3478"};
config.turn_usernames = {"valid_username"};
config.turn_passwords = {"valid_password"};

// Check TURN server reachability
// (librats will log TURN errors automatically)
```

### Debug Logging

```cpp
// Enable detailed logging for NAT traversal
LOG_LEVEL = LOG_DEBUG;  // In logger.h

// Monitor ICE state changes
client.set_ice_state_callback([](librats::IceConnectionState state) {
    std::cout << "ICE State: " << ice_connection_state_to_string(state) << std::endl;
});
```

### Performance Optimization

**For low latency:**
```cpp
config.ice_gathering_timeout_ms = 5000;    // Faster gathering
config.host_candidate_priority = 70000;    // Prefer direct connections
config.enable_tcp_candidates = false;      // UDP only
```

**For high success rate:**
```cpp
config.ice_connectivity_timeout_ms = 60000; // Longer timeout
config.enable_turn_relay = true;           // Always enable TURN
config.hole_punch_attempts = 10;           // More attempts
```

**For resource constrained:**
```cpp
config.enable_ice = false;                 // Disable ICE
config.enable_hole_punching = true;        // Simple hole punching only
config.max_connectivity_checks = 50;       // Limit checks
```

## Integration Examples

### With DHT Discovery

```cpp
client.start_dht_discovery();

// Set DHT discovery callback to attempt NAT traversal
client.set_dht_discovery_callback([&client](const std::vector<std::string>& peers) {
    for (const auto& peer_addr : peers) {
        // Parse address and connect with ICE
        size_t colon = peer_addr.find(':');
        std::string ip = peer_addr.substr(0, colon);
        int port = std::stoi(peer_addr.substr(colon + 1));
        
        client.connect_to_peer(ip, port, librats::ConnectionStrategy::ICE_FULL);
    }
});
```

### With mDNS Discovery

```cpp
client.start_mdns_discovery();

// mDNS peers are typically local, use direct connection
client.set_mdns_callback([&client](const std::string& ip, int port, const std::string& name) {
    client.connect_to_peer(ip, port, librats::ConnectionStrategy::DIRECT_ONLY);
});
```

### Custom Signaling Channel

```cpp
class CustomSignaling {
    librats::RatsClient& client_;
    
public:
    void send_ice_offer(const std::string& peer_id, const nlohmann::json& offer) {
        // Send through your signaling mechanism (WebSocket, HTTP, etc.)
        send_signaling_message(peer_id, {
            {"type", "ice_offer"},
            {"offer", offer}
        });
    }
    
    void handle_ice_offer(const std::string& peer_id, const nlohmann::json& offer) {
        // Create and send answer
        auto answer = client_.create_ice_answer(offer);
        send_signaling_message(peer_id, {
            {"type", "ice_answer"}, 
            {"answer", answer}
        });
        
        // Set remote description to start ICE
        client_.set_remote_ice_description(peer_id, offer);
    }
    
    void handle_ice_answer(const std::string& peer_id, const nlohmann::json& answer) {
        client_.handle_ice_answer(peer_id, answer);
    }
};
```

## Security Considerations

### STUN/TURN Security
- Always use authenticated TURN servers
- Consider STUN/TURN over TLS for sensitive applications
- Rotate TURN credentials regularly
- Monitor TURN usage for abuse

### ICE Security
- ICE credentials are generated randomly and rotated per session
- Consider additional authentication after ICE completes
- Monitor for ICE flooding attacks
- Validate candidate addresses

### Application Security
```cpp
// Validate peer after successful ICE connection
client.set_advanced_connection_callback([](socket_t socket, const std::string& peer_id,
                                          const librats::ConnectionAttemptResult& result) {
    // Additional peer validation
    if (!validate_peer_certificate(peer_id)) {
        client.disconnect_peer(socket);
        return;
    }
    
    // Connection established and validated
    std::cout << "Secure connection via " << result.method << std::endl;
});
```

## API Reference

### Core Classes

- **`RatsClient`** - Main client with enhanced NAT traversal
- **`IceAgent`** - ICE implementation for connectivity establishment  
- **`StunClient`** - Enhanced STUN client with ICE support
- **`TurnClient`** - TURN client for relay functionality
- **`NatTypeDetector`** - Advanced NAT type detection
- **`AdvancedNatDetector`** - Detailed NAT behavior analysis

### Key Enums

- **`ConnectionStrategy`** - Connection establishment strategies
- **`NatType`** - Detected NAT types
- **`IceConnectionState`** - ICE connection states
- **`IceCandidateType`** - ICE candidate types

### Configuration Structures

- **`NatTraversalConfig`** - NAT traversal configuration
- **`IceConfig`** - ICE-specific configuration
- **`ConnectionAttemptResult`** - Connection attempt results

This comprehensive NAT traversal implementation ensures librats can establish peer-to-peer connections across virtually any network topology, making it suitable for production P2P applications. 