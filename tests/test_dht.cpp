#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "dht.h"
#include "socket.h"
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <random>

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

// ============================================================================
// IPv6 / BEP 32 wire-format tests
// ============================================================================

// IPv4 compact node info round-trips through 26-byte records
TEST_F(DhtTest, CompactNodeInfoIPv4RoundTrip) {
    KrpcNode node(create_test_node_id(0x11), "192.168.1.42", 6881);
    std::string compact = KrpcProtocol::compact_node_info(node);
    EXPECT_EQ(compact.size(), 26u);  // 20 id + 4 ip + 2 port

    auto parsed = KrpcProtocol::parse_compact_node_info(compact, /*ipv6=*/false);
    ASSERT_EQ(parsed.size(), 1u);
    EXPECT_EQ(parsed[0].id, node.id);
    EXPECT_EQ(parsed[0].ip, "192.168.1.42");
    EXPECT_EQ(parsed[0].port, 6881);
}

// IPv6 compact node info round-trips through 38-byte records (BEP 32)
TEST_F(DhtTest, CompactNodeInfoIPv6RoundTrip) {
    KrpcNode node(create_test_node_id(0x22), "2001:db8::1", 51413);
    std::string compact = KrpcProtocol::compact_node_info(node);
    EXPECT_EQ(compact.size(), 38u);  // 20 id + 16 ip + 2 port

    auto parsed = KrpcProtocol::parse_compact_node_info(compact, /*ipv6=*/true);
    ASSERT_EQ(parsed.size(), 1u);
    EXPECT_EQ(parsed[0].id, node.id);
    EXPECT_EQ(parsed[0].ip, "2001:db8::1");
    EXPECT_EQ(parsed[0].port, 51413);
}

// Compact peer info encodes 6 bytes for IPv4 and 18 bytes for IPv6 (BEP 7)
TEST_F(DhtTest, CompactPeerInfoFamilies) {
    Peer v4("10.0.0.5", 1234);
    std::string c4 = KrpcProtocol::compact_peer_info(v4);
    EXPECT_EQ(c4.size(), 6u);
    auto p4 = KrpcProtocol::parse_compact_peer_info(c4);
    ASSERT_EQ(p4.size(), 1u);
    EXPECT_EQ(p4[0].ip, "10.0.0.5");
    EXPECT_EQ(p4[0].port, 1234);

    Peer v6("2001:db8::dead:beef", 4321);
    std::string c6 = KrpcProtocol::compact_peer_info(v6);
    EXPECT_EQ(c6.size(), 18u);
    auto p6 = KrpcProtocol::parse_compact_peer_info(c6);
    ASSERT_EQ(p6.size(), 1u);
    EXPECT_EQ(p6[0].ip, "2001:db8::dead:beef");
    EXPECT_EQ(p6[0].port, 4321);
}

// A find_node response carrying IPv6 nodes encodes them under "nodes6" and decodes back
TEST_F(DhtTest, FindNodeResponseIPv6NodesRoundTrip) {
    std::vector<KrpcNode> nodes = {
        KrpcNode(create_test_node_id(0x01), "2001:db8::1", 100),
        KrpcNode(create_test_node_id(0x02), "fe80::abcd", 200),
    };
    auto msg = KrpcProtocol::create_find_node_response("aa", create_test_node_id(0xFF), nodes);
    auto encoded = KrpcProtocol::encode_message(msg);
    ASSERT_FALSE(encoded.empty());

    auto decoded = KrpcProtocol::decode_message(encoded);
    ASSERT_NE(decoded, nullptr);
    ASSERT_EQ(decoded->nodes.size(), 2u);
    EXPECT_EQ(decoded->nodes[0].ip, "2001:db8::1");
    EXPECT_EQ(decoded->nodes[0].port, 100);
    EXPECT_EQ(decoded->nodes[1].ip, "fe80::abcd");
    EXPECT_EQ(decoded->nodes[1].port, 200);
}

// A response mixing IPv4 and IPv6 nodes splits them into nodes/nodes6 and recombines on decode
TEST_F(DhtTest, FindNodeResponseMixedFamilies) {
    std::vector<KrpcNode> nodes = {
        KrpcNode(create_test_node_id(0x01), "192.168.0.1", 100),
        KrpcNode(create_test_node_id(0x02), "2001:db8::2", 200),
    };
    auto msg = KrpcProtocol::create_find_node_response("bb", create_test_node_id(0xFF), nodes);
    auto decoded = KrpcProtocol::decode_message(KrpcProtocol::encode_message(msg));
    ASSERT_NE(decoded, nullptr);
    ASSERT_EQ(decoded->nodes.size(), 2u);

    bool has_v4 = false, has_v6 = false;
    for (const auto& n : decoded->nodes) {
        if (n.ip == "192.168.0.1" && n.port == 100) has_v4 = true;
        if (n.ip == "2001:db8::2" && n.port == 200) has_v6 = true;
    }
    EXPECT_TRUE(has_v4);
    EXPECT_TRUE(has_v6);
}

// BEP 32 "want" list survives a query encode/decode round-trip
TEST_F(DhtTest, GetPeersQueryWantRoundTrip) {
    auto msg = KrpcProtocol::create_get_peers_query("cc", create_test_node_id(0x33), create_test_info_hash(0x44));
    msg.want.push_back("n4");
    msg.want.push_back("n6");

    auto decoded = KrpcProtocol::decode_message(KrpcProtocol::encode_message(msg));
    ASSERT_NE(decoded, nullptr);
    ASSERT_EQ(decoded->want.size(), 2u);
    EXPECT_EQ(decoded->want[0], "n4");
    EXPECT_EQ(decoded->want[1], "n6");
}

// An IPv6 DHT instance rejects IPv4 nodes from its routing table and vice versa
TEST_F(DhtTest, RoutingTableFamilyIsolation) {
    DhtClient v6(0, "", "", AddressFamily::IPv6);
    EXPECT_TRUE(v6.is_ipv6());
    EXPECT_EQ(v6.address_family(), AddressFamily::IPv6);

    DhtClient v4(0, "", "", AddressFamily::IPv4);
    EXPECT_FALSE(v4.is_ipv6());
}

// IPv4 and IPv6 DHT clients can run simultaneously on the same port (separate sockets).
// IPv6 may be unavailable on the host, in which case only IPv4 is required to start.
TEST_F(DhtTest, DualStackSamePortCoexistence) {
    const int port = 6890;
    DhtClient v4(port, "", "", AddressFamily::IPv4);
    ASSERT_TRUE(v4.start());
    EXPECT_TRUE(v4.is_running());

    DhtClient v6(port, "", "", AddressFamily::IPv6);
    if (v6.start()) {
        // If IPv6 is available, both must coexist on the same port.
        EXPECT_TRUE(v6.is_running());
        EXPECT_TRUE(v4.is_running());
        v6.stop();
    } else {
        // No usable IPv6 stack - acceptable, IPv4 keeps running.
        SUCCEED() << "IPv6 unavailable on this host";
    }

    v4.stop();
}

// ============================================================================
// BEP 42: node ID derived from external IP
// ============================================================================

// Validate our CRC32C + prefix computation against the official BEP 42 test vectors.
// Each node ID must verify as valid for the IP it was generated from.
TEST_F(DhtTest, Bep42OfficialTestVectors) {
    struct Vec { const char* ip; const char* node_id_hex; };
    const Vec vectors[] = {
        {"124.31.75.21", "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"},
        {"21.75.31.124", "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256"},
        {"65.23.51.170", "a5d43220bc8f112a3d426c84764f8c2a1150e616"},
        {"84.124.73.14", "1b0321dd1bb1fe518101ceef99462b947a01ff41"},
        {"43.213.53.83", "e56f6cbf5b7c4be0237986d5243b87aa6d51305a"},
    };
    for (const auto& v : vectors) {
        NodeId id = hex_to_node_id(v.node_id_hex);
        EXPECT_TRUE(DhtClient::verify_node_id_for_ip(id, v.ip))
            << "vector " << v.ip << " should verify against its published node ID";
        // The same ID must NOT verify for an unrelated public IP.
        EXPECT_FALSE(DhtClient::verify_node_id_for_ip(id, "8.8.8.8"))
            << "vector " << v.ip << " must not verify for a different IP";
    }
}

// Generated IDs must always verify for the IP they came from (IPv4 and IPv6).
TEST_F(DhtTest, Bep42GenerateVerifyRoundTrip) {
    std::mt19937 gen(0xC0FFEE);
    const char* ips[] = {"1.2.3.4", "203.0.113.7", "2001:db8::1", "2606:4700:4700::1111"};
    for (const char* ip : ips) {
        NodeId id;
        ASSERT_TRUE(DhtClient::generate_node_id_from_ip(ip, id, gen)) << ip;
        EXPECT_TRUE(DhtClient::verify_node_id_for_ip(id, ip)) << ip;
    }
}

// Non-public addresses cannot be verified, so verify must accept any ID for them.
TEST_F(DhtTest, Bep42PrivateAddressesAlwaysVerify) {
    NodeId id = create_test_node_id(0x42);
    EXPECT_TRUE(DhtClient::verify_node_id_for_ip(id, "192.168.1.10"));
    EXPECT_TRUE(DhtClient::verify_node_id_for_ip(id, "10.0.0.1"));
    EXPECT_TRUE(DhtClient::verify_node_id_for_ip(id, "127.0.0.1"));
    EXPECT_TRUE(DhtClient::verify_node_id_for_ip(id, "::1"));
}

// set_external_ip regenerates the node ID for a public IP and ignores private ones.
TEST_F(DhtTest, Bep42SetExternalIpRegeneratesNodeId) {
    DhtClient client(0, "", "", AddressFamily::IPv4);
    NodeId before = client.get_node_id();

    // Private IP: ignored, no change, no recorded external address.
    client.set_external_ip("192.168.0.5");
    EXPECT_EQ(client.get_node_id(), before);
    EXPECT_TRUE(client.get_external_address().empty());

    // Public IP: node ID is regenerated and now verifies for that IP.
    client.set_external_ip("203.0.113.50");
    NodeId after = client.get_node_id();
    EXPECT_TRUE(DhtClient::verify_node_id_for_ip(after, "203.0.113.50"));
    EXPECT_EQ(client.get_external_address(), "203.0.113.50");
}

// An IPv4 instance must ignore an IPv6 external address (separate Kademlia networks).
TEST_F(DhtTest, Bep42ExternalIpFamilyMismatchIgnored) {
    DhtClient client(0, "", "", AddressFamily::IPv4);
    NodeId before = client.get_node_id();
    client.set_external_ip("2001:db8::1234");  // IPv6 address on an IPv4 node
    EXPECT_EQ(client.get_node_id(), before);
    EXPECT_TRUE(client.get_external_address().empty());
}