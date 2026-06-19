#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/dht_discovery.h"

#include <chrono>
#include <memory>
#include <thread>

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return pred();
}

NodeConfig listening_config() {
    NodeConfig c; c.bind_address = "127.0.0.1"; c.security = NodeConfig::Security::Noise; return c;
}

DhtDiscovery::Config disc_config(const std::vector<Peer>& bootstrap) {
    DhtDiscovery::Config c;
    c.discovery_key = "librats-test-net";
    c.bind_address = "127.0.0.1";
    c.bootstrap_nodes = bootstrap;
    c.search_interval = 500ms;
    c.announce_interval = 1000ms;
    return c;
}

} // namespace

// The discovery hash is a deterministic function of the key.
TEST(DhtDiscoveryTest, HashIsDeterministicPerKey) {
    EXPECT_EQ(DhtDiscovery::hash_for_key("app-a"), DhtDiscovery::hash_for_key("app-a"));
    EXPECT_NE(DhtDiscovery::hash_for_key("app-a"), DhtDiscovery::hash_for_key("app-b"));
}

// The adapter brings a DhtClient up on a real UDP port and tears down cleanly.
TEST(DhtDiscoveryTest, StartsAndStopsCleanly) {
    Node node(listening_config());
    auto disc = std::make_unique<DhtDiscovery>(disc_config({}));  // no bootstrap (offline)
    DhtDiscovery* d = disc.get();
    node.add_subsystem(std::move(disc));

    ASSERT_TRUE(node.start());
    EXPECT_TRUE(wait_for([&] { return d->is_running() && d->dht_port() != 0; }, 5s));
    node.stop();
    EXPECT_FALSE(d->is_running());
}

// Two nodes bootstrap their DHTs off each other on loopback, announce the same
// discovery hash, find each other's TCP port and form an encrypted peer link —
// all offline. (DHT convergence is timing-dependent; generous timeout.)
TEST(DhtDiscoveryTest, TwoNodesDiscoverViaDht) {
    Node a(listening_config());
    auto disc_a = std::make_unique<DhtDiscovery>(disc_config({}));  // seed: no bootstrap
    DhtDiscovery* da = disc_a.get();
    a.add_subsystem(std::move(disc_a));
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(wait_for([&] { return da->dht_port() != 0; }, 5s));

    // b bootstraps from a's DHT node.
    Node b(listening_config());
    std::vector<Peer> bootstrap{ Peer("127.0.0.1", da->dht_port()) };
    b.add_subsystem(std::make_unique<DhtDiscovery>(disc_config(bootstrap)));
    ASSERT_TRUE(b.start());

    EXPECT_TRUE(wait_for([&] { return a.peer_count() >= 1 && b.peer_count() >= 1; }, 30s))
        << "discovered: a=" << a.peer_count() << " b=" << b.peer_count();

    b.stop();
    a.stop();
}
