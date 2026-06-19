#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/mdns_discovery.h"

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

} // namespace

// The adapter starts an mDNS client and tears down cleanly.
TEST(MdnsDiscoveryTest, StartsAndStopsCleanly) {
    Node node(listening_config());
    auto disc = std::make_unique<MdnsDiscovery>();
    MdnsDiscovery* d = disc.get();
    node.add_subsystem(std::move(disc));

    ASSERT_TRUE(node.start());
    EXPECT_TRUE(wait_for([&] { return d->is_running(); }, 5s));
    node.stop();
    EXPECT_FALSE(d->is_running());
}

// NOTE: end-to-end "two nodes discover each other over mDNS" is intentionally
// NOT unit-tested here. mDNS relies on LAN multicast and advertises the real
// interface address, so it cannot run in a network-less/loopback-only sandbox
// (unlike the DHT adapter, whose loopback test does run). The multicast
// machinery is covered by the MdnsClient's own tests; this adapter only bridges
// MdnsClient's discovery callback to PeerNetwork::connect(), mirroring the
// integration-tested DhtDiscovery adapter. Validate mDNS discovery on a real LAN.
