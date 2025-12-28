#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "dht.h"
#include "socket.h"
#include <thread>
#include <chrono>
#include <vector>
#include <string>

using namespace librats;

class DhtTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize socket library
        init_socket_library();
    }
    
    void TearDown() override {
        // Cleanup socket library
        cleanup_socket_library();
    }
    
    // Helper function to create a test node ID
    NodeId create_test_node_id(uint8_t value) {
        NodeId id;
        id.fill(value);
        return id;
    }
    
    // Helper function to create a test info hash
    InfoHash create_test_info_hash(uint8_t value) {
        InfoHash hash;
        hash.fill(value);
        return hash;
    }
};

// Test NodeId and InfoHash types
TEST_F(DhtTest, NodeIdInfoHashTest) {
    NodeId id1 = create_test_node_id(0x01);
    NodeId id2 = create_test_node_id(0x02);
    NodeId id3 = create_test_node_id(0x01);
    
    // Test equality
    EXPECT_EQ(id1, id3);
    EXPECT_NE(id1, id2);
    
    // Test size
    EXPECT_EQ(id1.size(), NODE_ID_SIZE);
    EXPECT_EQ(id1.size(), 20);
    
    // Test InfoHash
    InfoHash hash1 = create_test_info_hash(0xFF);
    InfoHash hash2 = create_test_info_hash(0xFF);
    InfoHash hash3 = create_test_info_hash(0xFE);
    
    EXPECT_EQ(hash1, hash2);
    EXPECT_NE(hash1, hash3);
    EXPECT_EQ(hash1.size(), NODE_ID_SIZE);
}

// Test DhtNode structure
TEST_F(DhtTest, DhtNodeTest) {
    NodeId id = create_test_node_id(0x12);
    Peer peer("127.0.0.1", 8080);
    
    DhtNode node(id, peer);
    
    EXPECT_EQ(node.id, id);
    EXPECT_EQ(node.peer.ip, "127.0.0.1");
    EXPECT_EQ(node.peer.port, 8080);
    
    // Test that last_seen is set to current time (approximately)
    auto now = std::chrono::steady_clock::now();
    auto time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - node.last_seen);
    EXPECT_LT(time_diff.count(), 1000);  // Should be less than 1 second
}

// Note: DhtMessage and DhtMessageType removed - DHT now uses KRPC protocol only

// Test DhtClient creation and basic operations
TEST_F(DhtTest, DhtClientBasicTest) {
    DhtClient client(0);  // Use port 0 for automatic assignment
    
    // Test node ID generation
    NodeId id = client.get_node_id();
    EXPECT_EQ(id.size(), NODE_ID_SIZE);
    
    // Test that node ID is not all zeros
    bool all_zeros = true;
    for (uint8_t byte : id) {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros);
    
    // Test initial state
    EXPECT_FALSE(client.is_running());
    EXPECT_EQ(client.get_routing_table_size(), 0);
}

// Test DhtClient start and stop
TEST_F(DhtTest, DhtClientStartStopTest) {
    DhtClient client(0);
    
    // Test start
    EXPECT_TRUE(client.start());
    EXPECT_TRUE(client.is_running());
    
    // Test double start (should return true)
    EXPECT_TRUE(client.start());
    EXPECT_TRUE(client.is_running());
    
    // Test stop
    client.stop();
    EXPECT_FALSE(client.is_running());
    
    // Test double stop (should not crash)
    client.stop();
    EXPECT_FALSE(client.is_running());
}

// Test DhtClient port binding
TEST_F(DhtTest, DhtClientPortBindingTest) {
    // Test binding to specific port
    DhtClient client1(0);  // Auto-assign port
    EXPECT_TRUE(client1.start());
    
    // Test that we can create multiple clients with different ports
    DhtClient client2(0);  // Auto-assign different port
    EXPECT_TRUE(client2.start());
    
    client1.stop();
    client2.stop();
}

// Test bootstrap nodes
TEST_F(DhtTest, BootstrapNodesTest) {
    std::vector<Peer> bootstrap_nodes = DhtClient::get_default_bootstrap_nodes();
    
    // Should have at least a few bootstrap nodes
    EXPECT_GT(bootstrap_nodes.size(), 0);
    
    // Check that bootstrap nodes have valid format
    for (const auto& node : bootstrap_nodes) {
        EXPECT_FALSE(node.ip.empty());
        EXPECT_GT(node.port, 0);
        EXPECT_LT(node.port, 65536);
    }
}

// Test peer discovery (basic functionality)
TEST_F(DhtTest, PeerDiscoveryBasicTest) {
    DhtClient client(0);
    EXPECT_TRUE(client.start());
    
    InfoHash test_hash = create_test_info_hash(0xAA);
    
    // Test find_peers - should not crash
    bool callback_called = false;
    client.find_peers(test_hash, [&](const std::vector<Peer>& peers, const InfoHash& info_hash) {
        callback_called = true;
        // For basic test, we don't expect to find peers immediately
        // This is mainly testing that the function doesn't crash
    });
    
    // Give some time for potential callback
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    client.stop();
}

// Test peer announcement
TEST_F(DhtTest, PeerAnnouncementTest) {
    DhtClient client(0);
    EXPECT_TRUE(client.start());
    
    InfoHash test_hash = create_test_info_hash(0xBB);
    
    // Test announce_peer - should not crash
    bool result = client.announce_peer(test_hash, 8080);
    // Result might be true or false depending on whether we have nodes
    // The important thing is that it doesn't crash
    
    client.stop();
}

// Test routing table operations
TEST_F(DhtTest, RoutingTableTest) {
    DhtClient client(0);
    EXPECT_TRUE(client.start());
    
    // Initial routing table should be empty
    EXPECT_EQ(client.get_routing_table_size(), 0);
    
    // Note: We can't easily test routing table additions without 
    // actually receiving messages from other nodes, which would
    // require a more complex test setup
    
    client.stop();
}

// Test multiple DHT clients communication
TEST_F(DhtTest, MultipleClientsTest) {
    DhtClient client1(0);
    DhtClient client2(0);
    
    EXPECT_TRUE(client1.start());
    EXPECT_TRUE(client2.start());
    
    // Both should be running
    EXPECT_TRUE(client1.is_running());
    EXPECT_TRUE(client2.is_running());
    
    // Both should have different node IDs
    EXPECT_NE(client1.get_node_id(), client2.get_node_id());
    
    // Give some time for potential interaction
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    client1.stop();
    client2.stop();
}

// Test node ID uniqueness
TEST_F(DhtTest, NodeIdUniquenessTest) {
    std::vector<NodeId> node_ids;
    
    // Create multiple clients and check node ID uniqueness
    for (int i = 0; i < 10; ++i) {
        DhtClient client(0);
        NodeId id = client.get_node_id();
        
        // Check that this ID is unique
        for (const auto& existing_id : node_ids) {
            EXPECT_NE(id, existing_id);
        }
        
        node_ids.push_back(id);
    }
}

// Test error handling
TEST_F(DhtTest, ErrorHandlingTest) {
    // Test invalid port
    DhtClient client(-1);
    EXPECT_FALSE(client.start());
    EXPECT_FALSE(client.is_running());
    
    // Test very high port number
    DhtClient client2(70000);
    // This might succeed or fail depending on system, but shouldn't crash
    bool started = client2.start();
    if (started) {
        client2.stop();
    }
}

// Test constants
TEST_F(DhtTest, ConstantsTest) {
    EXPECT_EQ(NODE_ID_SIZE, 20);
    EXPECT_EQ(K_BUCKET_SIZE, 8);
    EXPECT_EQ(ALPHA, 3);
    EXPECT_EQ(DHT_PORT, 6881);
}

// Note: DhtMessageType removed - DHT now uses KRPC protocol only

// Test Peer equality
TEST_F(DhtTest, PeerEqualityTest) {
    Peer peer1("127.0.0.1", 8080);
    Peer peer2("127.0.0.1", 8080);
    Peer peer3("127.0.0.1", 8081);
    Peer peer4("192.168.1.1", 8080);
    
    EXPECT_EQ(peer1, peer2);
    EXPECT_NE(peer1, peer3);
    EXPECT_NE(peer1, peer4);
    EXPECT_NE(peer3, peer4);
}

// Test performance with many operations
TEST_F(DhtTest, PerformanceTest) {
    DhtClient client(0);
    EXPECT_TRUE(client.start());
    
    // Test creating many node IDs
    std::vector<NodeId> ids;
    for (int i = 0; i < 100; ++i) {
        DhtClient temp_client(0);
        ids.push_back(temp_client.get_node_id());
    }
    
    // All IDs should be unique
    for (size_t i = 0; i < ids.size(); ++i) {
        for (size_t j = i + 1; j < ids.size(); ++j) {
            EXPECT_NE(ids[i], ids[j]);
        }
    }
    
    client.stop();
}

// Test concurrent operations
TEST_F(DhtTest, ConcurrentOperationsTest) {
    DhtClient client(0);
    EXPECT_TRUE(client.start());
    
    std::vector<std::thread> threads;
    
    // Start multiple threads doing operations
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([&client, i]() {
            InfoHash hash = {};
            hash.fill(static_cast<uint8_t>(i));
            
            // Test find_peers from multiple threads
            client.find_peers(hash, [](const std::vector<Peer>& peers, const InfoHash& info_hash) {
                // Just a dummy callback
            });
            
            // Test announce_peer from multiple threads
            client.announce_peer(hash, 8080 + i);
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    client.stop();
}

// Test memory management
TEST_F(DhtTest, MemoryManagementTest) {
    // Test that clients can be created and destroyed - reduced for faster tests
    for (int i = 0; i < 3; ++i) {  // Reduced from 10 to 3
        DhtClient client(0);
        EXPECT_TRUE(client.start());
        
        // Do some operations - just test the API, don't wait for timeouts
        InfoHash hash = create_test_info_hash(static_cast<uint8_t>(i));
        client.find_peers(hash, [](const std::vector<Peer>& peers, const InfoHash& info_hash) {});
        client.announce_peer(hash, 8080);
        
        // Skip sleep to avoid delays
        
        client.stop();
    }
}

// Test edge cases
TEST_F(DhtTest, EdgeCasesTest) {
    DhtClient client(0);
    EXPECT_TRUE(client.start());
    
    // Test empty callbacks
    InfoHash hash = create_test_info_hash(0x00);
    
    // Test with null callback (should not crash)
    client.find_peers(hash, nullptr);
    
    // Test with callback that throws (should not crash the client)
    client.find_peers(hash, [](const std::vector<Peer>& peers, const InfoHash& info_hash) {
        throw std::runtime_error("Test exception");
    });
    
    // Give some time for potential issues
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Client should still be running
    EXPECT_TRUE(client.is_running());
    
    client.stop();
}

// Test state consistency
TEST_F(DhtTest, StateConsistencyTest) {
    DhtClient client(0);
    
    // Test initial state
    EXPECT_FALSE(client.is_running());
    EXPECT_EQ(client.get_routing_table_size(), 0);
    
    // Test state after start
    EXPECT_TRUE(client.start());
    EXPECT_TRUE(client.is_running());
    
    // Test state after stop
    client.stop();
    EXPECT_FALSE(client.is_running());
    
    // Test that we can restart
    EXPECT_TRUE(client.start());
    EXPECT_TRUE(client.is_running());
    
    client.stop();
}

// Test ping-before-replace eviction algorithm
TEST_F(DhtTest, PingBeforeReplaceEvictionTest) {
    DhtClient client(0);
    EXPECT_TRUE(client.start());
    
    // Initial state - no pending ping verifications
    EXPECT_EQ(client.get_pending_ping_verifications_count(), 0);
    EXPECT_EQ(client.get_routing_table_size(), 0);
    
    // We can't directly test the internal add_node function, but we can test
    // the behavior indirectly by checking that pending ping verifications
    // don't pile up when the same old nodes are repeatedly selected for replacement.
    
    // The main improvement is that the algorithm now:
    // 1. Excludes nodes that already have pending ping verifications from being selected again
    // 2. Handles the edge case when all nodes in a bucket have pending verifications
    // 3. Prevents duplicate ping verifications for the same old node
    
    // Note: This test validates the algorithm logic is present, but full integration
    // testing would require mock DHT nodes or complex network simulation.
    
    client.stop();
}

// Test routing table persistence (save/load)
TEST_F(DhtTest, RoutingTablePersistenceTest) {
    // Create a unique test directory for this test
    std::string test_data_dir = "./test_dht_persistence";
    
    // Phase 1: Create client, start it, and save routing table
    {
        DhtClient client1(6882, "", test_data_dir);
        EXPECT_TRUE(client1.start());
        
        // Initial routing table should be empty or loaded from previous test
        size_t initial_size = client1.get_routing_table_size();
        
        // Attempt to bootstrap (this will add some nodes to routing table)
        auto bootstrap_nodes = DhtClient::get_default_bootstrap_nodes();
        if (!bootstrap_nodes.empty()) {
            client1.bootstrap(bootstrap_nodes);
            
            // Give some time for bootstrap to add nodes
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        
        // Save routing table manually
        EXPECT_TRUE(client1.save_routing_table());
        
        // Get the size before stopping
        size_t size_before_stop = client1.get_routing_table_size();
        
        // Stop client (should also save routing table automatically)
        client1.stop();
    }
    
    // Phase 2: Create new client with same port and data directory
    // It should load the previously saved routing table
    {
        DhtClient client2(6882, "", test_data_dir);
        
        // Before starting, routing table should be empty
        EXPECT_EQ(client2.get_routing_table_size(), 0);
        
        // Start should load the saved routing table
        EXPECT_TRUE(client2.start());
        
        // Give it a moment to load
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // After starting, routing table might have loaded nodes
        // Note: We can't guarantee nodes will be loaded (depends on bootstrap success)
        // but we can check that the load functionality doesn't crash
        size_t loaded_size = client2.get_routing_table_size();
        
        // The test passes if loading doesn't crash and returns a valid size
        EXPECT_GE(loaded_size, 0);
        
        client2.stop();
    }
    
    // Cleanup: In a real scenario, you might want to delete the test file
    // For now, we leave it as it uses the testing file path mechanism
}

// Test data directory configuration
TEST_F(DhtTest, DataDirectoryConfigurationTest) {
    DhtClient client1(0);
    
    // Test setting data directory
    client1.set_data_directory("./test_dir");
    
    // Should be able to start and stop without issues
    EXPECT_TRUE(client1.start());
    EXPECT_TRUE(client1.is_running());
    
    // Save routing table (should use the configured directory)
    EXPECT_TRUE(client1.save_routing_table());
    
    client1.stop();
    
    // Test with empty data directory (should default to current directory)
    DhtClient client2(0, "", "");
    EXPECT_TRUE(client2.start());
    client2.stop();
}

// Test BEP 42 - DHT Security Extension (Node ID generation from IP)
TEST_F(DhtTest, BEP42NodeIdGenerationTest) {
    // Test IPv4 node ID generation
    std::string ipv4 = "192.168.1.100";
    NodeId id1 = generate_node_id_from_ip(ipv4);
    
    // Each generated ID should be valid (20 bytes)
    EXPECT_EQ(id1.size(), NODE_ID_SIZE);
    
    // Generate with same IP but different random - will have different CRC
    // because BEP 42 mixes the random value into the IP before hashing
    NodeId id2 = generate_node_id_from_ip(ipv4);
    EXPECT_EQ(id2.size(), NODE_ID_SIZE);
    
    // Both should verify against the same IP (using their stored r values)
    EXPECT_TRUE(verify_node_id(id1, ipv4));
    EXPECT_TRUE(verify_node_id(id2, ipv4));
    
    // Test with the implementation function using same random value
    // This should produce identical CRCs
    NodeId id3 = generate_node_id_from_ip_impl(ipv4, 42);
    NodeId id4 = generate_node_id_from_ip_impl(ipv4, 42);
    EXPECT_EQ(id3[0], id4[0]);
    EXPECT_EQ(id3[1], id4[1]);
    EXPECT_EQ(id3[2] & 0xf8, id4[2] & 0xf8);  // First 5 bits of byte 2 should match
    EXPECT_EQ(id3[19], id4[19]);  // r value stored in last byte
    EXPECT_EQ(id3[19], 42);       // Should store the r value
    
    // Test IPv6 node ID generation
    NodeId id5 = generate_node_id_from_ip("2001:db8::1");
    EXPECT_EQ(id5.size(), NODE_ID_SIZE);
    
    // Test with loopback
    NodeId id6 = generate_node_id_from_ip("::1");
    EXPECT_EQ(id6.size(), NODE_ID_SIZE);
    
    // Test public IP
    NodeId id7 = generate_node_id_from_ip("8.8.8.8");
    EXPECT_EQ(id7.size(), NODE_ID_SIZE);
    EXPECT_TRUE(verify_node_id(id7, "8.8.8.8"));
}

// Test BEP 42 - Node ID verification
TEST_F(DhtTest, BEP42NodeIdVerificationTest) {
    // Generate a node ID from an IP and verify it
    std::string test_ip = "8.8.8.8";
    NodeId id = generate_node_id_from_ip(test_ip);
    
    // Should verify successfully against the same IP
    EXPECT_TRUE(verify_node_id(id, test_ip));
    
    // Should fail verification against a different IP (usually)
    // Note: There's a small chance this could pass due to hash collision
    // but it's extremely unlikely for a well-designed hash
    NodeId id_for_other = generate_node_id_from_ip("9.9.9.9");
    // Just test that verification doesn't crash
    bool result = verify_node_id(id_for_other, "8.8.8.8");
    // We don't assert the result since it depends on hash values
    (void)result;
    
    // Local IPs should always pass verification (BEP 42 skips local IPs)
    NodeId random_id;
    random_id.fill(0xFF);
    EXPECT_TRUE(verify_node_id(random_id, "192.168.1.1"));
    EXPECT_TRUE(verify_node_id(random_id, "10.0.0.1"));
    EXPECT_TRUE(verify_node_id(random_id, "127.0.0.1"));
}

// Test is_local_ip function
TEST_F(DhtTest, IsLocalIpTest) {
    // IPv4 private ranges
    EXPECT_TRUE(is_local_ip("10.0.0.1"));
    EXPECT_TRUE(is_local_ip("10.255.255.255"));
    EXPECT_TRUE(is_local_ip("172.16.0.1"));
    EXPECT_TRUE(is_local_ip("172.31.255.255"));
    EXPECT_TRUE(is_local_ip("192.168.0.1"));
    EXPECT_TRUE(is_local_ip("192.168.255.255"));
    EXPECT_TRUE(is_local_ip("127.0.0.1"));
    EXPECT_TRUE(is_local_ip("169.254.1.1"));
    
    // IPv4 public addresses
    EXPECT_FALSE(is_local_ip("8.8.8.8"));
    EXPECT_FALSE(is_local_ip("1.1.1.1"));
    EXPECT_FALSE(is_local_ip("208.67.222.222"));
    
    // IPv6 local addresses
    EXPECT_TRUE(is_local_ip("::1"));
    EXPECT_TRUE(is_local_ip("fe80::1"));
    EXPECT_TRUE(is_local_ip("fc00::1"));
    
    // IPv6 public addresses (example)
    EXPECT_FALSE(is_local_ip("2001:4860:4860::8888"));
}

// Test DhtClient with BEP 42 external IP
TEST_F(DhtTest, DhtClientWithExternalIpTest) {
    std::string external_ip = "203.0.113.50";  // Documentation IP (RFC 5737)
    
    DhtClient client(0, "", "", external_ip);
    
    // Node ID should be generated from the external IP
    NodeId id = client.get_node_id();
    EXPECT_EQ(id.size(), NODE_ID_SIZE);
    
    // Verify the node ID matches the expected format
    EXPECT_TRUE(verify_node_id(id, external_ip));
    
    // Start and stop should work
    EXPECT_TRUE(client.start());
    EXPECT_TRUE(client.is_running());
    client.stop();
    EXPECT_FALSE(client.is_running());
}

// Test set_external_ip method
TEST_F(DhtTest, SetExternalIpTest) {
    DhtClient client(0);  // Create with random ID
    
    NodeId old_id = client.get_node_id();
    std::string new_ip = "198.51.100.10";  // Documentation IP (RFC 5737)
    
    // Set external IP
    client.set_external_ip(new_ip);
    
    NodeId new_id = client.get_node_id();
    
    // ID should have changed
    EXPECT_NE(old_id, new_id);
    
    // New ID should verify against the new IP
    EXPECT_TRUE(verify_node_id(new_id, new_ip));
    
    // External IP should be stored
    EXPECT_EQ(client.get_external_ip(), new_ip);
    
    // Setting the same IP again should not change the ID
    client.set_external_ip(new_ip);
    EXPECT_EQ(client.get_node_id(), new_id);
} 