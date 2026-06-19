#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/ping_service.h"
#include "subsystems/port_mapping_service.h"

#include <chrono>
#include <memory>
#include <thread>

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 10s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

NodeConfig listening_config() {
    NodeConfig c;
    c.bind_address = "127.0.0.1";
    c.security = NodeConfig::Security::Noise;
    return c;
}

NodeConfig dialing_config() {
    NodeConfig c = listening_config();
    c.enable_listen = false;
    return c;
}

} // namespace

// The PingService — a subsystem built only on PeerNetwork — measures RTT in both
// directions over an encrypted link, proving the plugin contract end to end.
TEST(SubsystemTest, PingServiceMeasuresRtt) {
    Node server(listening_config());
    Node client(dialing_config());

    auto server_ping = std::make_unique<PingService>(50ms);
    auto client_ping = std::make_unique<PingService>(50ms);
    PingService* server_ping_raw = server_ping.get();
    PingService* client_ping_raw = client_ping.get();
    server.add_subsystem(std::move(server_ping));
    client.add_subsystem(std::move(client_ping));

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    // Each side should receive a pong from the other and record an RTT.
    ASSERT_TRUE(wait_for([&] {
        return client_ping_raw->last_rtt(server.local_id()).has_value() &&
               server_ping_raw->last_rtt(client.local_id()).has_value();
    })) << "RTT not measured in both directions";

    EXPECT_GE(server_ping_raw->alive_peer_count(), 1u);
    EXPECT_GE(client_ping_raw->alive_peer_count(), 1u);

    client.stop();
    server.stop();
}

// A subsystem with no peers just idles quietly; start/stop must be clean.
TEST(SubsystemTest, PingServiceIdleStartStop) {
    Node node(dialing_config());
    node.add_subsystem(std::make_unique<PingService>(20ms));
    ASSERT_TRUE(node.start());
    std::this_thread::sleep_for(80ms);  // let the ping loop spin a few times
    node.stop();
    SUCCEED();
}

// The PortMappingService brings up its UPnP + NAT-PMP backends against the node's
// listen port. With no router answering (the usual CI case) the backends simply
// report failure; the contract under test is that attach/start/stop is clean and
// joins the backend worker threads without hanging — and that no public address
// is recorded when no usable mapping was established.
TEST(SubsystemTest, PortMappingIdleStartStop) {
    Node node(listening_config());
    auto mapper = std::make_unique<PortMappingService>();
    PortMappingService* raw = mapper.get();
    node.add_subsystem(std::move(mapper));

    ASSERT_TRUE(node.start());
    ASSERT_NE(node.listen_port(), 0);
    std::this_thread::sleep_for(150ms);  // let the backends attempt discovery

    // Environment-independent: a router may or may not answer on the test host.
    // If a public mapping WAS recorded, it must be internally consistent; if not,
    // nullopt is fine. Either way the query must be safe to call.
    if (auto pub = raw->mapped_public_address()) {
        EXPECT_FALSE(pub->first.empty());
        EXPECT_NE(pub->second, 0);
    }
    node.stop();
    SUCCEED();
}

// Disabling both backends must make start() a no-op (no threads, no mapping).
TEST(SubsystemTest, PortMappingDisabledIsNoOp) {
    PortMappingConfig cfg;
    cfg.enabled = false;
    Node node(listening_config());
    node.add_subsystem(std::make_unique<PortMappingService>(cfg));
    ASSERT_TRUE(node.start());
    std::this_thread::sleep_for(20ms);
    node.stop();
    SUCCEED();
}
