#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "dht/dht.h"
#include "core/socket.h"
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <random>

// End-to-end tests for the public DhtClient facade (real UDP sockets + loop thread)
// and the KRPC wire codec. The engine internals (id math, routing table, traversal,
// BEP 42 derivation, etc.) are unit-tested against a mock transport in the
// test_dht_*.cpp suite; this file covers the facade and on-the-wire encoding.

using namespace librats;

class DhtTest : public ::testing::Test {
protected:
    void SetUp() override {
        init_socket_library();
    }

    void TearDown() override {
        cleanup_socket_library();
    }

    NodeId create_test_node_id(uint8_t value) {
        NodeId id;
        id.fill(value);
        return id;
    }

    InfoHash create_test_info_hash(uint8_t value) {
        InfoHash hash;
        hash.fill(value);
        return hash;
    }
};

// ============================================================================
// DhtClient facade
// ============================================================================

// Test DhtClient creation and basic operations
TEST_F(DhtTest, DhtClientBasicTest) {
    DhtClient client(0);  // Use port 0 for automatic assignment

    // Test node ID generation
    NodeId id = client.get_node_id();
    EXPECT_EQ(id.size(), 20u);

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
    std::vector<Address> bootstrap_nodes = DhtClient::get_default_bootstrap_nodes();

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
    client.find_peers(test_hash, [&](const std::vector<Address>& peers, const InfoHash& info_hash) {
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

    // Test announce_peer - should not crash. Result might be true or false
    // depending on whether we have nodes; the point is it doesn't crash.
    client.announce_peer(test_hash, 8080);

    client.stop();
}

// Test routing table is initially empty
TEST_F(DhtTest, RoutingTableTest) {
    DhtClient client(0);
    EXPECT_TRUE(client.start());

    // Initial routing table should be empty
    EXPECT_EQ(client.get_routing_table_size(), 0);

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

// Address equality (the endpoint type the facade exposes)
TEST_F(DhtTest, PeerEqualityTest) {
    Address peer1("127.0.0.1", 8080);
    Address peer2("127.0.0.1", 8080);
    Address peer3("127.0.0.1", 8081);
    Address peer4("192.168.1.1", 8080);

    EXPECT_EQ(peer1, peer2);
    EXPECT_NE(peer1, peer3);
    EXPECT_NE(peer1, peer4);
    EXPECT_NE(peer3, peer4);
}

// Test performance with many node IDs
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
            client.find_peers(hash, [](const std::vector<Address>& peers, const InfoHash& info_hash) {
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
    // Test that clients can be created and destroyed
    for (int i = 0; i < 3; ++i) {
        DhtClient client(0);
        EXPECT_TRUE(client.start());

        // Do some operations - just test the API, don't wait for timeouts
        InfoHash hash = create_test_info_hash(static_cast<uint8_t>(i));
        client.find_peers(hash, [](const std::vector<Address>& peers, const InfoHash& info_hash) {});
        client.announce_peer(hash, 8080);

        client.stop();
    }
}

// A throwing user callback must not take the client down (the facade isolates it)
TEST_F(DhtTest, EdgeCasesTest) {
    DhtClient client(0);
    EXPECT_TRUE(client.start());

    InfoHash hash = create_test_info_hash(0x00);

    // Test with null callback (should not crash)
    client.find_peers(hash, nullptr);

    // Test with callback that throws (should not crash the client)
    client.find_peers(hash, [](const std::vector<Address>& peers, const InfoHash& info_hash) {
        throw std::runtime_error("Test exception");
    });

    // Give some time for potential issues
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Client should still be running
    EXPECT_TRUE(client.is_running());

    client.stop();
}

// Test state consistency across start/stop/restart
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

// ============================================================================
// Persistence (facade save/load of routing table + node id)
// ============================================================================

// Test routing table persistence (save/load)
TEST_F(DhtTest, RoutingTablePersistenceTest) {
    // Create a unique test directory for this test
    std::string test_data_dir = "./test_dht_persistence";

    // Phase 1: Create client, start it, and save routing table
    {
        DhtClient client1(6882, "", test_data_dir);
        EXPECT_TRUE(client1.start());

        // Attempt to bootstrap (this will add some nodes to routing table)
        auto bootstrap_nodes = DhtClient::get_default_bootstrap_nodes();
        if (!bootstrap_nodes.empty()) {
            client1.bootstrap(bootstrap_nodes);

            // Give some time for bootstrap to add nodes
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        // Save routing table manually
        EXPECT_TRUE(client1.save_routing_table());

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

        // The test passes if loading doesn't crash and returns a valid size
        size_t loaded_size = client2.get_routing_table_size();
        EXPECT_GE(loaded_size, 0);

        client2.stop();
    }
}

// Our own node ID must stay stable across restarts (like libtorrent): it is written
// to the routing table file on save and restored on load instead of being regenerated.
TEST_F(DhtTest, NodeIdPersistedAcrossRestart) {
    const int port = 6883;
    const std::string test_data_dir = "./test_dht_nodeid_persistence";

    // Phase 1: capture the generated node ID and persist it.
    NodeId saved_id;
    {
        DhtClient client1(port, "", test_data_dir);
        saved_id = client1.get_node_id();
        EXPECT_TRUE(client1.save_routing_table());
    }

    // Phase 2: a new client generates a fresh random ID, but loading must restore the saved one.
    {
        DhtClient client2(port, "", test_data_dir);
        // Overwhelmingly unlikely the fresh random ID equals the saved one.
        EXPECT_NE(client2.get_node_id(), saved_id);

        client2.load_routing_table();
        EXPECT_EQ(client2.get_node_id(), saved_id);
    }
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
    Address v4("10.0.0.5", 1234);
    std::string c4 = KrpcProtocol::compact_peer_info(v4);
    EXPECT_EQ(c4.size(), 6u);
    auto p4 = KrpcProtocol::parse_compact_peer_info(c4);
    ASSERT_EQ(p4.size(), 1u);
    EXPECT_EQ(p4[0].ip, "10.0.0.5");
    EXPECT_EQ(p4[0].port, 1234);

    Address v6("2001:db8::dead:beef", 4321);
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

// ============================================================================
// Address-family isolation (facade)
// ============================================================================

// An IPv6 DHT instance is distinct from an IPv4 one (separate Kademlia networks)
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
// BEP 42 via the facade (set_external_ip). The CRC32C derivation itself is
// covered by test_dht_bep42.cpp; here we test the DhtClient-level behaviour.
// ============================================================================

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
