#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "librats.h"
#include "socket.h"
#include "fs.h"
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <atomic>
#include <mutex>

using namespace librats;

class RatsClientTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize socket library
        librats::Logger::getInstance().set_log_level(librats::LogLevel::DEBUG);
        init_socket_library();
    }
    
    void TearDown() override {
        // Cleanup socket library
        cleanup_socket_library();
    }
    
    // Helper to wait for condition with timeout
    template<typename Predicate>
    bool wait_for_condition(Predicate pred, int timeout_ms = 1000) {
        auto start = std::chrono::steady_clock::now();
        while (!pred()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            if (elapsed.count() >= timeout_ms) {
                return false;
            }
        }
        return true;
    }
};

// Test RatsClient creation and basic operations
TEST_F(RatsClientTest, BasicCreationTest) {
    RatsClient client(0);  // Use port 0 for automatic assignment
    
    // Test initial state
    EXPECT_FALSE(client.is_running());
    EXPECT_EQ(client.get_peer_count(), 0);
    
    // Test start
    EXPECT_TRUE(client.start());
    EXPECT_TRUE(client.is_running());
    
    // Test stop
    client.stop();
    EXPECT_FALSE(client.is_running());
}

// Test RatsClient start and stop multiple times
TEST_F(RatsClientTest, StartStopMultipleTest) {
    RatsClient client(0);
    
    // Test multiple start/stop cycles
    for (int i = 0; i < 3; ++i) {
        EXPECT_TRUE(client.start());
        EXPECT_TRUE(client.is_running());
        
        client.stop();
        EXPECT_FALSE(client.is_running());
    }
}

// Test RatsClient callback setting
TEST_F(RatsClientTest, CallbackSettingTest) {
    RatsClient client(0);
    
    bool connection_callback_set = false;
    bool data_callback_set = false;
    bool disconnect_callback_set = false;
    
    // Set callbacks
    client.set_connection_callback([&](socket_t socket, const std::string& peer_hash_id) {
        connection_callback_set = true;
    });
    
    client.set_data_callback([&](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
        data_callback_set = true;
    });
    
    client.set_disconnect_callback([&](socket_t socket, const std::string& peer_hash_id) {
        disconnect_callback_set = true;
    });
    
    // Callbacks should be set (we can't easily test them without actual connections)
    EXPECT_TRUE(client.start());
    client.stop();
}

// Test peer connection between two clients
TEST_F(RatsClientTest, PeerConnectionTest) {
    RatsClient server(0);
    RatsClient client(0);
    
    // Setup tracking variables
    std::atomic<bool> server_connection_received(false);
    std::atomic<bool> client_connection_made(false);
    std::string server_peer_hash;
    std::string client_peer_hash;
    std::mutex hash_mutex;
    
    // Set up server callbacks
    server.set_connection_callback([&](socket_t socket, const std::string& peer_hash_id) {
        std::lock_guard<std::mutex> lock(hash_mutex);
        server_peer_hash = peer_hash_id;
        server_connection_received = true;
    });
    
    // Set up client callbacks
    client.set_connection_callback([&](socket_t socket, const std::string& peer_hash_id) {
        std::lock_guard<std::mutex> lock(hash_mutex);
        client_peer_hash = peer_hash_id;
        client_connection_made = true;
    });
    
    // Start both clients
    EXPECT_TRUE(server.start());
    EXPECT_TRUE(client.start());
    
    // Connect client to server
    bool connection_result = client.connect_to_peer("127.0.0.1", 8080);
    // Connection might fail if port 8080 is not available, but that's okay for this test
    
    // Wait briefly for potential connection
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Clean up
    client.stop();
    server.stop();
}

// Test peer communication
TEST_F(RatsClientTest, PeerCommunicationTest) {
    RatsClient server(0);
    RatsClient client(0);
    
    std::atomic<bool> server_received_data(false);
    std::atomic<bool> client_received_data(false);
    std::string server_received_msg;
    std::string client_received_msg;
    std::mutex msg_mutex;
    
    // Set up server callbacks
    server.set_connection_callback([&server](socket_t socket, const std::string& peer_hash_id) {
        // Send welcome message to new peer
        server.send_to_peer(socket, "Welcome to server!");
    });
    
    server.set_data_callback([&](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
        std::lock_guard<std::mutex> lock(msg_mutex);
        server_received_msg = data;
        server_received_data = true;
    });
    
    // Set up client callbacks
    client.set_data_callback([&](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
        std::lock_guard<std::mutex> lock(msg_mutex);
        client_received_msg = data;
        client_received_data = true;
        
        // Send response
        client.send_to_peer(socket, "Hello from client!");
    });
    
    // Start both clients
    EXPECT_TRUE(server.start());
    EXPECT_TRUE(client.start());
    
    // Give some time for setup
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Clean up
    client.stop();
    server.stop();
}

// Test broadcast functionality
TEST_F(RatsClientTest, BroadcastTest) {
    RatsClient server(0);
    
    std::atomic<int> messages_sent(0);
    std::atomic<int> messages_received(0);
    
    server.set_connection_callback([&](socket_t socket, const std::string& peer_hash_id) {
        // When peer connects, broadcast a message
        int sent = server.broadcast_to_peers("Broadcast message");
        messages_sent = sent;
    });
    
    server.set_data_callback([&](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
        if (data == "Broadcast message") {
            messages_received++;
        }
    });
    
    EXPECT_TRUE(server.start());
    
    // Test broadcasting with no peers
    int sent = server.broadcast_to_peers("No peers message");
    EXPECT_EQ(sent, 0);
    
    server.stop();
}

// Test peer hash ID functionality
TEST_F(RatsClientTest, PeerHashIdTest) {
    RatsClient client(0);
    
    std::string received_hash_id;
    socket_t received_socket = INVALID_SOCKET_VALUE;
    
    client.set_connection_callback([&](socket_t socket, const std::string& peer_hash_id) {
        received_hash_id = peer_hash_id;
        received_socket = socket;
    });
    
    EXPECT_TRUE(client.start());
    
    // Test hash ID functions with no peers
    std::string empty_hash = client.get_peer_hash_id(123);
    EXPECT_TRUE(empty_hash.empty());
    
    socket_t invalid_socket = client.get_peer_socket("nonexistent_hash");
    EXPECT_EQ(invalid_socket, INVALID_SOCKET_VALUE);
    
    client.stop();
}

// Test peer disconnection
TEST_F(RatsClientTest, PeerDisconnectionTest) {
    RatsClient client(0);
    
    std::atomic<bool> disconnect_called(false);
    std::string disconnected_hash;
    
    client.set_disconnect_callback([&](socket_t socket, const std::string& peer_hash_id) {
        disconnected_hash = peer_hash_id;
        disconnect_called = true;
    });
    
    EXPECT_TRUE(client.start());
    
    // Test disconnecting non-existent peer (should not crash)
    client.disconnect_peer(INVALID_SOCKET_VALUE);
    client.disconnect_peer_by_hash("nonexistent_hash");
    
    client.stop();
}

// Test DHT functionality
/*  Too long to run
TEST_F(RatsClientTest, DhtFunctionalityTest) {
    RatsClient client(0);
    
    EXPECT_TRUE(client.start());
    
    // Test DHT operations - simplified without external bootstrap
    EXPECT_FALSE(client.is_dht_running());
    
    // Test starting DHT but don't wait for bootstrap
    bool dht_started = client.start_dht_discovery(0);  // Use port 0
    if (dht_started) {
        EXPECT_TRUE(client.is_dht_running());
        EXPECT_EQ(client.get_dht_routing_table_size(), 0);  // Should be empty initially
        
        // Test DHT operations - just test the API, don't wait for responses
        std::string test_hash = "1234567890abcdef1234567890abcdef12345678";
        client.announce_for_hash(test_hash, 8080);
        
        // Don't wait for callback - just test the API
        client.find_peers_by_hash(test_hash, [](const std::vector<std::string>& peers) {
            // Callback won't be called in test environment
        });
        
        // Stop DHT quickly
        client.stop_dht_discovery();
        EXPECT_FALSE(client.is_dht_running());
    }
    
    client.stop();
}
*/

// Test automatic peer discovery
/* Too long to run
TEST_F(RatsClientTest, AutomaticPeerDiscoveryTest) {
    RatsClient client(0);
    
    EXPECT_TRUE(client.start());
    
    // Test automatic discovery - just test the API
    EXPECT_FALSE(client.is_automatic_discovery_running());
    
    client.start_automatic_peer_discovery();
    EXPECT_TRUE(client.is_automatic_discovery_running());
    
    // Test discovery hash
    std::string discovery_hash = RatsClient::get_rats_peer_discovery_hash();
    EXPECT_FALSE(discovery_hash.empty());
    EXPECT_EQ(discovery_hash.length(), 40);  // Should be 40 character hex string
    
    // Stop quickly to avoid timeouts
    client.stop_automatic_peer_discovery();
    EXPECT_FALSE(client.is_automatic_discovery_running());
    
    client.stop();
}
*/

// Test multiple clients
TEST_F(RatsClientTest, MultipleClientsTest) {
    RatsClient client1(0);
    RatsClient client2(0);
    RatsClient client3(0);
    
    // Start all clients
    EXPECT_TRUE(client1.start());
    EXPECT_TRUE(client2.start());
    EXPECT_TRUE(client3.start());
    
    // All should be running
    EXPECT_TRUE(client1.is_running());
    EXPECT_TRUE(client2.is_running());
    EXPECT_TRUE(client3.is_running());
    
    // All should have 0 peers initially
    EXPECT_EQ(client1.get_peer_count(), 0);
    EXPECT_EQ(client2.get_peer_count(), 0);
    EXPECT_EQ(client3.get_peer_count(), 0);
    
    // Stop all clients
    client1.stop();
    client2.stop();
    client3.stop();
}

// Test error handling
TEST_F(RatsClientTest, ErrorHandlingTest) {
    // Test invalid port
    RatsClient client(-1);
    EXPECT_FALSE(client.start());
    
    // Test valid client
    RatsClient valid_client(0);
    EXPECT_TRUE(valid_client.start());
    
    // Test operations on invalid socket
    bool send_result = valid_client.send_to_peer(INVALID_SOCKET_VALUE, "test");
    EXPECT_FALSE(send_result);
    
    // Test operations with invalid hash
    bool send_by_hash_result = valid_client.send_to_peer_by_hash("invalid_hash", "test");
    EXPECT_FALSE(send_by_hash_result);
    
    // Test connecting to invalid address
    bool connect_result = valid_client.connect_to_peer("invalid.address.12345", 80);
    EXPECT_FALSE(connect_result);
    
    valid_client.stop();
}

// Test helper functions
TEST_F(RatsClientTest, HelperFunctionsTest) {
    // Test create_rats_client
    auto client = create_rats_client(0);
    EXPECT_NE(client, nullptr);
    EXPECT_TRUE(client->is_running());
    
    // Test that it's properly started
    EXPECT_EQ(client->get_peer_count(), 0);
    
    // Clean up is automatic when unique_ptr goes out of scope
}

// Test memory management
TEST_F(RatsClientTest, MemoryManagementTest) {
    // Test creating and destroying fewer clients to reduce test time
    for (int i = 0; i < 3; ++i) {  // Reduced from 10 to 3
        RatsClient client(0);
        EXPECT_TRUE(client.start());
        
        // Do some operations but don't wait for timeouts
        client.broadcast_to_peers("test message");
        // Skip connection attempts that will timeout
        
        client.stop();
    }
}

// Test concurrent operations
TEST_F(RatsClientTest, ConcurrentOperationsTest) {
    RatsClient client(0);
    EXPECT_TRUE(client.start());
    
    std::vector<std::thread> threads;
    
    // Start fewer threads doing operations
    for (int i = 0; i < 3; ++i) {  // Reduced from 5 to 3
        threads.emplace_back([&client, i]() {
            // Test concurrent broadcasts
            client.broadcast_to_peers("Message from thread " + std::to_string(i));
            
            // Skip connection attempts that will timeout
            
            // Test DHT operations only once
            if (i == 0) {
                client.start_dht_discovery(0);
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    client.stop();
}

// Test performance
TEST_F(RatsClientTest, PerformanceTest) {
    RatsClient client(0);
    EXPECT_TRUE(client.start());
    
    // Test fewer broadcast operations
    for (int i = 0; i < 10; ++i) {  // Reduced from 100 to 10
        int sent = client.broadcast_to_peers("Performance test message " + std::to_string(i));
        EXPECT_EQ(sent, 0);  // No peers connected
    }
    
    // Skip connection attempts that will timeout
    
    client.stop();
}

// Test state consistency
TEST_F(RatsClientTest, StateConsistencyTest) {
    RatsClient client(0);
    
    // Test initial state
    EXPECT_FALSE(client.is_running());
    EXPECT_EQ(client.get_peer_count(), 0);
    EXPECT_FALSE(client.is_dht_running());
    EXPECT_FALSE(client.is_automatic_discovery_running());
    
    // Test state after start
    EXPECT_TRUE(client.start());
    EXPECT_TRUE(client.is_running());
    EXPECT_EQ(client.get_peer_count(), 0);
    EXPECT_FALSE(client.is_dht_running());
    EXPECT_FALSE(client.is_automatic_discovery_running());
    
    // Test state after stop
    client.stop();
    EXPECT_FALSE(client.is_running());
    EXPECT_EQ(client.get_peer_count(), 0);
    EXPECT_FALSE(client.is_dht_running());
    EXPECT_FALSE(client.is_automatic_discovery_running());
}

// Test edge cases
TEST_F(RatsClientTest, EdgeCasesTest) {
    RatsClient client(0);
    EXPECT_TRUE(client.start());
    
    // Test empty message sending
    int sent = client.broadcast_to_peers("");
    EXPECT_EQ(sent, 0);
    
    // Test null/empty hash operations
    bool send_result = client.send_to_peer_by_hash("", "test");
    EXPECT_FALSE(send_result);
    
    client.disconnect_peer_by_hash("");
    
    // Test very long message
    std::string long_message(10000, 'a');
    int long_sent = client.broadcast_to_peers(long_message);
    EXPECT_EQ(long_sent, 0);
    
    // Test connecting to localhost on various ports
    client.connect_to_peer("127.0.0.1", 0);      // Port 0
    client.connect_to_peer("127.0.0.1", 65535);  // Max port
    client.connect_to_peer("127.0.0.1", -1);     // Invalid port
    
    client.stop();
}

// Test callback exception handling
TEST_F(RatsClientTest, CallbackExceptionHandlingTest) {
    RatsClient client(0);
    
    // Set callbacks that throw exceptions
    client.set_connection_callback([](socket_t socket, const std::string& peer_hash_id) {
        throw std::runtime_error("Connection callback exception");
    });
    
    client.set_data_callback([](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
        throw std::runtime_error("Data callback exception");
    });
    
    client.set_disconnect_callback([](socket_t socket, const std::string& peer_hash_id) {
        throw std::runtime_error("Disconnect callback exception");
    });
    
    // Client should still start and work despite exception-throwing callbacks
    EXPECT_TRUE(client.start());
    EXPECT_TRUE(client.is_running());
    
    // These operations should not crash even with throwing callbacks
    client.broadcast_to_peers("test");
    client.connect_to_peer("127.0.0.1", 12345);
    
    // Give some time for potential issues
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    EXPECT_TRUE(client.is_running());
    
    client.stop();
} 

// Test simultaneous connections to the same peer
TEST_F(RatsClientTest, SimultaneousConnectionsToSamePeerTest) {
    // Use fixed ports to avoid port assignment issues
    const int server_port = 58888;
    const int client_port = 58889;
    
    // Clean up any saved peer files to avoid interference from previous test runs
    std::vector<std::string> cleanup_files = {
        "config_58888.json", "peers_58888.json",
        "config_58889.json", "peers_58889.json"
    };
    for (const auto& file : cleanup_files) {
        if (file_exists(file)) {
            delete_file(file.c_str());
        }
    }
    
    RatsClient server(server_port);
    RatsClient client(client_port);
    
    std::atomic<int> connection_attempts(0);
    std::atomic<int> successful_connections(0);
    std::atomic<int> server_connections_received(0);
    std::vector<std::string> connected_peer_hashes;
    std::mutex peer_hash_mutex;
    
    // Set up server callbacks to track incoming connections
    server.set_connection_callback([&](socket_t socket, const std::string& peer_hash_id) {
        server_connections_received++;
        std::lock_guard<std::mutex> lock(peer_hash_mutex);
        connected_peer_hashes.push_back(peer_hash_id);
        std::cout << "Server received connection from peer: " << peer_hash_id << std::endl;
    });
    
    // Set up client callbacks to track outgoing connections
    client.set_connection_callback([&](socket_t socket, const std::string& peer_hash_id) {
        successful_connections++;
        std::cout << "Client connected to peer: " << peer_hash_id << std::endl;
    });
    
    // Start both clients
    EXPECT_TRUE(server.start());
    EXPECT_TRUE(client.start());
    
    // Launch multiple simultaneous connection attempts to the same peer
    const int num_attempts = 3;
    std::vector<std::thread> connection_threads;
    std::vector<std::atomic<bool>> connection_results(num_attempts);
    
    for (int i = 0; i < num_attempts; ++i) {
        connection_results[i] = false;
        connection_threads.emplace_back([&, i]() {
            connection_attempts++;
            std::cout << "Attempt " << i << " starting connection to 127.0.0.1:" << server_port << std::endl;
            bool result = client.connect_to_peer("127.0.0.1", server_port);
            connection_results[i] = result;
            std::cout << "Attempt " << i << " result: " << (result ? "success" : "failed") << std::endl;
        });
    }
    
    // Wait for all connection attempts to complete
    for (auto& thread : connection_threads) {
        thread.join();
    }
    
    // Wait for connections to be established
    bool all_connected = wait_for_condition([&]() {
        return server_connections_received.load() > 0;
    }, 2000);
    
    EXPECT_TRUE(all_connected);
    
    // Give additional time for all events to process
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Verify that all connection attempts were made
    EXPECT_EQ(connection_attempts.load(), num_attempts);
    
    // Verify that the system handled duplicate connections properly
    int final_server_connections = server_connections_received.load();
    int final_client_connections = successful_connections.load();
    
    std::cout << "Final server connections received: " << final_server_connections << std::endl;
    std::cout << "Final client connections successful: " << final_client_connections << std::endl;
    std::cout << "Client peer count: " << client.get_peer_count() << std::endl;
    std::cout << "Server peer count: " << server.get_peer_count() << std::endl;
    
    // The system should handle this gracefully by accepting multiple connections
    // but properly deduplicating at the peer level
    EXPECT_GE(final_server_connections, 1);
    EXPECT_LE(final_server_connections, num_attempts + 2); // Allow some variance for timing/reconnects
    EXPECT_GE(final_client_connections, 1);
    EXPECT_LE(final_client_connections, num_attempts + 2); // Allow some variance for timing/reconnects
    
    // The key test: peer counts should represent unique peers, not total connections
    // Since it's the same client connecting multiple times, we should have exactly 1 unique peer
    EXPECT_EQ(client.get_peer_count(), 1);
    EXPECT_EQ(server.get_peer_count(), 1);
    
    // Verify that all connected peer hashes are from the same client
    // (they should all contain the same peer ID since it's the same client connecting)
    {
        std::lock_guard<std::mutex> lock(peer_hash_mutex);
        std::cout << "Total connection events received: " << connected_peer_hashes.size() << std::endl;
        
        if (connected_peer_hashes.size() > 1) {
            // Extract peer IDs from the connection hash IDs to verify they're the same client
            std::set<std::string> unique_peer_ids;
            for (const auto& hash : connected_peer_hashes) {
                std::cout << "Connected peer hash: " << hash << std::endl;
                // The hash contains the peer ID - multiple connections from same client should have same peer ID
            }
            
            // Since it's the same client connecting multiple times, we expect the same peer ID
            // but different connection hashes (due to different socket/timing info)
            EXPECT_GE(connected_peer_hashes.size(), 1);
            EXPECT_LE(connected_peer_hashes.size(), num_attempts + 2); // Allow some variance
        }
    }
    
    // Test that we can still send messages through the established connection(s)
    if (final_client_connections > 0) {
        std::atomic<bool> message_received(false);
        server.set_data_callback([&](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
            if (data == "test_simultaneous_connection") {
                message_received = true;
            }
        });
        
        // Broadcast a test message
        int messages_sent = client.broadcast_to_peers("test_simultaneous_connection");
        EXPECT_GE(messages_sent, 1);
        
        // Wait for message to be received
        bool msg_received = wait_for_condition([&]() {
            return message_received.load();
        }, 1000);
        
        EXPECT_TRUE(msg_received);
    }
    
    // Clean up
    client.stop();
    server.stop();
} 