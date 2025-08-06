# GossipSub Messaging Example

This example demonstrates how to use the new GossipSub (gossip-based publish-subscribe) messaging functionality in librats.

## What is GossipSub?

GossipSub is a robust publish-subscribe protocol that provides:
- **Topic-based messaging**: Subscribe to specific topics and receive relevant messages
- **Mesh networking**: Maintains optimal mesh topologies for efficient message delivery
- **Message validation**: Validate messages before processing them
- **Peer scoring**: Automatically score peers based on behavior to improve network quality
- **Deduplication**: Prevent duplicate messages from being processed
- **Gossip protocol**: Use gossip to disseminate message metadata for improved reliability

## Basic Usage

### 1. Setting up RatsClient with GossipSub

```cpp
#include "librats.h"
#include <iostream>

using namespace librats;

int main() {
    // Create and start RatsClient
    RatsClient client(8080);
    if (!client.start()) {
        std::cerr << "Failed to start RatsClient" << std::endl;
        return 1;
    }
    
    // Check if GossipSub is available
    if (!client.is_gossipsub_available()) {
        std::cerr << "GossipSub not available" << std::endl;
        return 1;
    }
    
    // Get GossipSub instance
    auto& gossipsub = client.get_gossipsub();
    
    // ... use gossipsub
    
    client.stop();
    return 0;
}
```

### 2. Subscribing to Topics

```cpp
auto& gossipsub = client.get_gossipsub();

// Subscribe to a topic
std::string topic = "chat-room";
if (gossipsub.subscribe(topic)) {
    std::cout << "Successfully subscribed to " << topic << std::endl;
} else {
    std::cout << "Failed to subscribe to " << topic << std::endl;
}

// Check subscription status
if (gossipsub.is_subscribed(topic)) {
    std::cout << "Currently subscribed to " << topic << std::endl;
}

// Get all subscribed topics
auto topics = gossipsub.get_subscribed_topics();
for (const auto& t : topics) {
    std::cout << "Subscribed to: " << t << std::endl;
}
```

### 3. Setting Up Message Handlers

```cpp
// Set message handler for a topic
gossipsub.set_message_handler("chat-room", [](const std::string& topic, const std::string& message, const std::string& sender_peer_id) {
    std::cout << "[" << topic << "] " << sender_peer_id << ": " << message << std::endl;
});

// Set peer event handlers
gossipsub.set_peer_joined_handler("chat-room", [](const std::string& topic, const std::string& peer_id) {
    std::cout << "Peer " << peer_id << " joined topic " << topic << std::endl;
});

gossipsub.set_peer_left_handler("chat-room", [](const std::string& topic, const std::string& peer_id) {
    std::cout << "Peer " << peer_id << " left topic " << topic << std::endl;
});
```

### 4. Publishing Messages

```cpp
// Publish text message
std::string topic = "chat-room";
std::string message = "Hello, everyone!";
if (gossipsub.publish(topic, message)) {
    std::cout << "Message published successfully" << std::endl;
}

// Publish JSON message
nlohmann::json json_message;
json_message["type"] = "user_status";
json_message["status"] = "online";
json_message["timestamp"] = std::time(nullptr);

if (gossipsub.publish(topic, json_message)) {
    std::cout << "JSON message published successfully" << std::endl;
}
```

### 5. Message Validation

```cpp
// Set up message validator
gossipsub.set_message_validator("chat-room", [](const std::string& topic, const std::string& message, const std::string& sender_peer_id) {
    // Reject messages that are too long
    if (message.length() > 1000) {
        return ValidationResult::REJECT;
    }
    
    // Ignore spam messages
    if (message.find("SPAM") != std::string::npos) {
        return ValidationResult::IGNORE_MSG;
    }
    
    // Accept all other messages
    return ValidationResult::ACCEPT;
});

// Global validator for all topics
gossipsub.set_message_validator("", [](const std::string& topic, const std::string& message, const std::string& sender_peer_id) {
    // Global validation logic
    return ValidationResult::ACCEPT;
});
```

## Complete Chat Application Example

```cpp
#include "librats.h"
#include <iostream>
#include <thread>
#include <string>
#include <atomic>

using namespace librats;

class ChatClient {
private:
    std::unique_ptr<RatsClient> client_;
    std::string username_;
    std::atomic<bool> running_{true};
    
public:
    ChatClient(const std::string& username, int port) : username_(username) {
        client_ = std::make_unique<RatsClient>(port);
    }
    
    bool start() {
        if (!client_->start()) {
            return false;
        }
        
        if (!client_->is_gossipsub_available()) {
            return false;
        }
        
        auto& gossipsub = client_->get_gossipsub();
        
        // Subscribe to chat topic
        if (!gossipsub.subscribe("global-chat")) {
            return false;
        }
        
        // Set up message handler
        gossipsub.set_message_handler("global-chat", [this](const std::string& topic, const std::string& message, const std::string& sender_peer_id) {
            try {
                auto json_msg = nlohmann::json::parse(message);
                std::string username = json_msg.value("username", "Unknown");
                std::string text = json_msg.value("text", "");
                std::cout << "[CHAT] " << username << ": " << text << std::endl;
            } catch (const std::exception& e) {
                std::cout << "[RAW] " << message << std::endl;
            }
        });
        
        // Set up peer event handlers
        gossipsub.set_peer_joined_handler("global-chat", [](const std::string& topic, const std::string& peer_id) {
            std::cout << "[INFO] Peer joined: " << peer_id.substr(0, 8) << "..." << std::endl;
        });
        
        gossipsub.set_peer_left_handler("global-chat", [](const std::string& topic, const std::string& peer_id) {
            std::cout << "[INFO] Peer left: " << peer_id.substr(0, 8) << "..." << std::endl;
        });
        
        // Set up message validator
        gossipsub.set_message_validator("global-chat", [](const std::string& topic, const std::string& message, const std::string& sender_peer_id) {
            try {
                auto json_msg = nlohmann::json::parse(message);
                // Must have username and text fields
                if (!json_msg.contains("username") || !json_msg.contains("text")) {
                    return ValidationResult::REJECT;
                }
                
                // Text must not be empty
                std::string text = json_msg["text"];
                if (text.empty() || text.length() > 500) {
                    return ValidationResult::REJECT;
                }
                
                return ValidationResult::ACCEPT;
            } catch (const std::exception&) {
                return ValidationResult::REJECT;
            }
        });
        
        return true;
    }
    
    void connect_to_peer(const std::string& host, int port) {
        if (!client_->connect_to_peer(host, port)) {
            std::cout << "[ERROR] Failed to connect to " << host << ":" << port << std::endl;
        }
    }
    
    void send_message(const std::string& text) {
        auto& gossipsub = client_->get_gossipsub();
        
        nlohmann::json message;
        message["username"] = username_;
        message["text"] = text;
        message["timestamp"] = std::time(nullptr);
        
        if (!gossipsub.publish("global-chat", message)) {
            std::cout << "[ERROR] Failed to send message" << std::endl;
        }
    }
    
    void run_input_loop() {
        std::string line;
        std::cout << "Chat started. Type messages and press Enter to send." << std::endl;
        std::cout << "Type '/quit' to exit, '/connect <host> <port>' to connect to peer." << std::endl;
        
        while (running_ && std::getline(std::cin, line)) {
            if (line == "/quit") {
                running_ = false;
                break;
            } else if (line.substr(0, 8) == "/connect") {
                // Parse /connect command
                std::istringstream iss(line);
                std::string cmd, host;
                int port;
                if (iss >> cmd >> host >> port) {
                    connect_to_peer(host, port);
                } else {
                    std::cout << "[ERROR] Usage: /connect <host> <port>" << std::endl;
                }
            } else if (!line.empty()) {
                send_message(line);
            }
        }
    }
    
    void show_statistics() {
        auto& gossipsub = client_->get_gossipsub();
        auto stats = gossipsub.get_statistics();
        std::cout << "GossipSub Statistics:" << std::endl;
        std::cout << "  Topics: " << stats["total_topics_count"] << std::endl;
        std::cout << "  Subscribed: " << stats["subscribed_topics_count"] << std::endl;
        std::cout << "  Peers: " << stats["peers_count"] << std::endl;
    }
    
    void stop() {
        running_ = false;
        if (client_) {
            client_->stop();
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <username> <port> [peer_host] [peer_port]" << std::endl;
        return 1;
    }
    
    std::string username = argv[1];
    int port = std::stoi(argv[2]);
    
    ChatClient chat(username, port);
    
    if (!chat.start()) {
        std::cerr << "Failed to start chat client" << std::endl;
        return 1;
    }
    
    // Connect to peer if specified
    if (argc >= 5) {
        std::string peer_host = argv[3];
        int peer_port = std::stoi(argv[4]);
        chat.connect_to_peer(peer_host, peer_port);
        
        // Wait a bit for connection to establish
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    chat.run_input_loop();
    chat.show_statistics();
    chat.stop();
    
    return 0;
}
```

## Configuration Options

You can customize GossipSub behavior by providing a custom configuration:

```cpp
GossipSubConfig config;
config.mesh_low = 3;              // Minimum peers in mesh
config.mesh_high = 8;             // Maximum peers in mesh  
config.mesh_optimal = 5;          // Optimal peers in mesh
config.fanout_size = 4;           // Fanout size for non-subscribed topics
config.gossip_factor = 2;         // Number of peers to gossip to
config.heartbeat_interval = std::chrono::seconds(2);  // Heartbeat frequency
config.message_cache_ttl = std::chrono::minutes(10);  // Message cache TTL
config.score_threshold_mesh = -5.0;     // Min score to stay in mesh
config.score_threshold_gossip = -50.0;  // Min score for gossip

// Create GossipSub with custom config
auto gossipsub = std::make_unique<GossipSub>(client, config);
```

## Advanced Features

### Multiple Topics

```cpp
std::vector<std::string> topics = {"general", "tech", "random"};

for (const auto& topic : topics) {
    gossipsub.subscribe(topic);
    
    gossipsub.set_message_handler(topic, [topic](const std::string& t, const std::string& message, const std::string& sender) {
        std::cout << "[" << topic << "] " << message << std::endl;
    });
}
```

### Mesh Information

```cpp
// Get peers in topic mesh
auto mesh_peers = gossipsub.get_mesh_peers("chat-room");
std::cout << "Mesh peers: " << mesh_peers.size() << std::endl;

// Get all topic peers
auto topic_peers = gossipsub.get_topic_peers("chat-room");
std::cout << "Topic peers: " << topic_peers.size() << std::endl;

// Get peer score
for (const auto& peer_id : topic_peers) {
    double score = gossipsub.get_peer_score(peer_id);
    std::cout << "Peer " << peer_id.substr(0, 8) << " score: " << score << std::endl;
}
```

### Statistics and Monitoring

```cpp
// Get comprehensive statistics
auto stats = gossipsub.get_statistics();
std::cout << "Running: " << stats["running"] << std::endl;
std::cout << "Topics: " << stats["total_topics_count"] << std::endl;
std::cout << "Average peer score: " << stats["average_peer_score"] << std::endl;

// Get cache statistics  
auto cache_stats = gossipsub.get_cache_statistics();
std::cout << "Cached messages: " << cache_stats["cached_messages_count"] << std::endl;
std::cout << "Seen message IDs: " << cache_stats["seen_message_ids_count"] << std::endl;
```

## Building the Example

1. Make sure you have the GossipSub files in your project
2. Update your CMakeLists.txt to include `gossipsub.cpp` and `gossipsub.h`
3. Build your project:

```bash
mkdir build && cd build
cmake ..
make
```

4. Run the chat example:

```bash
# Terminal 1 (first peer)
./chat-example Alice 8080

# Terminal 2 (second peer)  
./chat-example Bob 8081 127.0.0.1 8080

# Terminal 3 (third peer)
./chat-example Charlie 8082 127.0.0.1 8080
```

This creates a mesh network where all participants can communicate via the "global-chat" topic using GossipSub's efficient message propagation. 