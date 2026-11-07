#include <gtest/gtest.h>
#include "librats/mdns/mdns.h"
#include "librats/util/logger.h"
#include "librats/core/socket.h"  // Add socket header for init/cleanup functions
#include <algorithm>
#include <iostream>
#include <thread>
#include <chrono>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

using namespace librats;

class MdnsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize socket library before any socket operations
        ASSERT_TRUE(init_socket_library()) << "Failed to initialize socket library";
    }
    
    void TearDown() override {
        // Cleanup socket library after tests
        cleanup_socket_library();
    }
};

TEST_F(MdnsTest, BasicMdnsFunctionality) {
    std::cout << "=== Testing Basic mDNS Functionality ===" << std::endl;
    
    // Create mDNS client
    MdnsClient mdns("test-node", 8080);
    
    // Test starting the client
    EXPECT_TRUE(mdns.start()) << "Failed to start mDNS client";
    EXPECT_TRUE(mdns.is_running()) << "mDNS client should be running after start";
    
    std::cout << "✓ mDNS client started successfully" << std::endl;
    
    // Test service announcement
    std::map<std::string, std::string> txt_records;
    txt_records["version"] = "1.0";
    txt_records["protocol"] = "test";
    
    EXPECT_TRUE(mdns.announce_service("test-node", 8080, txt_records)) 
        << "Failed to announce service";
    EXPECT_TRUE(mdns.is_announcing()) << "mDNS client should be announcing after announce_service";
    
    std::cout << "✓ Service announcement started" << std::endl;
    
    // Test service discovery
    bool service_discovered = false;
    mdns.set_service_callback([&service_discovered](const MdnsService& service, bool is_new) {
        if (is_new) {
            std::cout << "✓ Discovered service: " << service.service_name 
                     << " at " << service.ip_address << ":" << service.port << std::endl;
            service_discovered = true;
        }
    });
    
    EXPECT_TRUE(mdns.start_discovery()) << "Failed to start service discovery";
    EXPECT_TRUE(mdns.is_discovering()) << "mDNS client should be discovering after start_discovery";
    
    std::cout << "✓ Service discovery started" << std::endl;
    
    // Query for services
    EXPECT_TRUE(mdns.query_services()) << "Failed to send service query";
    std::cout << "✓ Service query sent" << std::endl;
    
    // Wait a bit for network activity
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Check discovered services
    auto services = mdns.get_discovered_services();
    std::cout << "✓ Retrieved " << services.size() << " discovered services" << std::endl;
    
    // Stop the client
    mdns.stop();
    EXPECT_FALSE(mdns.is_running()) << "mDNS client should not be running after stop";
    
    std::cout << "✓ mDNS client stopped successfully" << std::endl;
    std::cout << "=== Basic mDNS Test Completed ===" << std::endl << std::endl;
}

TEST_F(MdnsTest, MdnsTxtRecords) {
    std::cout << "=== Testing mDNS TXT Records ===" << std::endl;
    
    MdnsClient mdns("txt-test-node", 8090);
    
    // Start mDNS client
    EXPECT_TRUE(mdns.start()) << "Failed to start mDNS client for TXT records test";
    
    // Create TXT records with various data
    std::map<std::string, std::string> txt_records;
    txt_records["version"] = "2.1.0";
    txt_records["protocol"] = "librats";
    txt_records["features"] = "encryption,dht,mdns";
    txt_records["max_peers"] = "10";
    txt_records["node_id"] = "test-node-12345";
    
    // Announce service with TXT records
    EXPECT_TRUE(mdns.announce_service("txt-test-node", 8090, txt_records)) 
        << "Failed to announce service with TXT records";
    
    std::cout << "✓ Service announced with TXT records" << std::endl;
    
    // Set up discovery callback to check TXT records
    bool txt_records_verified = false;
    mdns.set_service_callback([&txt_records_verified, &txt_records](const MdnsService& service, bool is_new) {
        if (is_new && service.service_name.find("txt-test-node") != std::string::npos) {
            std::cout << "Verifying TXT records for service: " << service.service_name << std::endl;
            
            for (const auto& pair : service.txt_records) {
                std::cout << "  " << pair.first << " = " << pair.second << std::endl;
                
                // Verify some key TXT records
                auto it = txt_records.find(pair.first);
                if (it != txt_records.end() && it->second == pair.second) {
                    std::cout << "  ✓ TXT record verified: " << pair.first << std::endl;
                }
            }
            
            txt_records_verified = true;
        }
    });
    
    // Start discovery
    EXPECT_TRUE(mdns.start_discovery()) << "Failed to start discovery for TXT records test";
    
    // Wait for self-discovery (may not happen due to loopback filtering)
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    std::cout << "✓ TXT records test completed" << std::endl;
    
    // Stop client
    mdns.stop();
    
    std::cout << "=== mDNS TXT Records Test Completed ===" << std::endl << std::endl;
}

// The receiver waits on the multicast socket with no timeout, so the only thing that
// can end that wait is stop() signalling the wakeup pipe. This pins that: if the pipe
// ever stops being wired up, the loop falls back to waiting out a poll interval and
// stop() starts costing up to that interval instead of the round trip through a
// loopback datagram.
//
// It is a latency assertion rather than a CPU one because the cost being avoided —
// one wakeup per interval on an idle process — is too small to measure reliably in a
// unit test, while the shutdown latency it also causes is not: with a 100 ms poll the
// wait ends at a uniformly random point inside the interval, so ten stops landing
// under 50 ms each has a ~1-in-1000 chance. Measured here, it is about 1 ms.
TEST_F(MdnsTest, StopDoesNotWaitOutAPollInterval) {
    constexpr int    kCycles       = 10;
    constexpr double kMaxStopMs    = 50.0;

    double worst_ms = 0.0;
    for (int i = 0; i < kCycles; ++i) {
        MdnsClient mdns("stop-latency-test", 8100);
        ASSERT_TRUE(mdns.start()) << "cycle " << i;

        // Give the receiver time to reach its wait; stopping before it parks would
        // measure nothing.
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        const auto before = std::chrono::steady_clock::now();
        mdns.stop();
        const double ms =
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - before).count();

        EXPECT_FALSE(mdns.is_running()) << "cycle " << i;
        worst_ms = (std::max)(worst_ms, ms);
    }

    EXPECT_LT(worst_ms, kMaxStopMs)
        << "slowest stop() took " << worst_ms << " ms over " << kCycles
        << " cycles — the receiver is waiting out a timeout instead of being woken";
}

// Two nodes on one host meet over mDNS like any other two: they send from the same
// address, so nothing may be filtered by it, and multicast has to loop back. Each
// one also hears its own announcement and must not report it.
TEST_F(MdnsTest, TwoClientsOnOneHostFindEachOther) {
    // Unique names, so another run on the network cannot stand in for the peer.
    const std::string tag = std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count() % 1000000007);
    const std::string name_a = "same-host-a-" + tag;
    const std::string name_b = "same-host-b-" + tag;

    struct Seen {
        std::mutex mutex;
        std::vector<std::string> names;
        bool has(const std::string& part) {
            std::lock_guard<std::mutex> lock(mutex);
            return std::any_of(names.begin(), names.end(),
                               [&](const std::string& n) { return n.find(part) != std::string::npos; });
        }
    } seen_by_a, seen_by_b;

    MdnsClient a(name_a, 8201);
    MdnsClient b(name_b, 8202);
    for (auto [client, seen] : {std::pair{&a, &seen_by_a}, std::pair{&b, &seen_by_b}}) {
        client->set_service_callback([seen = seen](const MdnsService& service, bool) {
            std::lock_guard<std::mutex> lock(seen->mutex);
            seen->names.push_back(service.service_name);
        });
        ASSERT_TRUE(client->start());
        ASSERT_TRUE(client->start_discovery());
    }
    ASSERT_TRUE(a.announce_service(name_a, 8201));
    ASSERT_TRUE(b.announce_service(name_b, 8202));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline &&
           !(seen_by_a.has(name_b) && seen_by_b.has(name_a))) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(seen_by_a.has(name_b)) << "a never saw b";
    EXPECT_TRUE(seen_by_b.has(name_a)) << "b never saw a";
    EXPECT_FALSE(seen_by_a.has(name_a)) << "a reported its own announcement";
    EXPECT_FALSE(seen_by_b.has(name_b)) << "b reported its own announcement";

    a.stop();
    b.stop();
}
