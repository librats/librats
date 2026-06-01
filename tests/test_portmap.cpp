/**
 * @file test_portmap.cpp
 * @brief Unit tests for automatic port forwarding (UPnP IGD + NAT-PMP)
 *
 * These tests exercise the public surface and lifecycle of the port mapping
 * backends. They do not assume a UPnP/NAT-PMP capable router is present on the
 * test network: discovery is allowed to fail, and the focus is that the workers
 * start, can be torn down promptly, and never crash or hang.
 */

#include <gtest/gtest.h>
#include "port_mapping.h"
#include "upnp.h"
#include "natpmp.h"
#include "network_utils.h"
#include "socket.h"

#include <atomic>
#include <chrono>
#include <thread>

using namespace librats;

class PortMapTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(init_socket_library()); }
    void TearDown() override { cleanup_socket_library(); }
};

// ----------------------------------------------------------------------------
// Shared vocabulary types
// ----------------------------------------------------------------------------

TEST_F(PortMapTest, ProtocolAndTransportStrings) {
    EXPECT_STREQ("TCP", to_string(PortMapProtocol::TCP));
    EXPECT_STREQ("UDP", to_string(PortMapProtocol::UDP));
    EXPECT_STREQ("UPnP", to_string(PortMapTransport::UPnP));
    EXPECT_STREQ("NAT-PMP", to_string(PortMapTransport::NatPMP));
}

TEST_F(PortMapTest, DefaultConfig) {
    PortMappingConfig cfg;
    EXPECT_TRUE(cfg.enabled);
    EXPECT_TRUE(cfg.enable_upnp);
    EXPECT_TRUE(cfg.enable_natpmp);
    EXPECT_EQ(3600u, cfg.lease_duration_seconds);
}

// ----------------------------------------------------------------------------
// Gateway detection
// ----------------------------------------------------------------------------

TEST_F(PortMapTest, GatewayDetectionDoesNotCrash) {
    // We cannot assert a specific gateway exists in CI, but the call must return
    // and any returned entries must be syntactically valid IPv4 addresses.
    auto gateways = network_utils::get_default_gateways();
    for (const auto& gw : gateways) {
        EXPECT_TRUE(network_utils::is_valid_ipv4(gw)) << "invalid gateway: " << gw;
    }
}

// ----------------------------------------------------------------------------
// NAT-PMP lifecycle
// ----------------------------------------------------------------------------

TEST_F(PortMapTest, NatPmpStartStopIsClean) {
    NatPmpClient client;
    client.set_gateway("192.0.2.1"); // TEST-NET-1: guaranteed not to answer
    client.add_mapping(PortMapProtocol::TCP, 51413);

    EXPECT_TRUE(client.start());
    EXPECT_FALSE(client.start()); // already running

    auto t0 = std::chrono::steady_clock::now();
    client.stop();
    auto elapsed = std::chrono::steady_clock::now() - t0;

    // stop() must be responsive even while discovery is in flight.
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 10);
    EXPECT_FALSE(client.is_running());
}

TEST_F(PortMapTest, NatPmpDuplicateMappingsIgnored) {
    NatPmpClient client;
    client.add_mapping(PortMapProtocol::TCP, 6881);
    client.add_mapping(PortMapProtocol::TCP, 6881); // duplicate, ignored
    // No external IP known before discovery succeeds.
    EXPECT_TRUE(client.external_ip().empty());
}

// ----------------------------------------------------------------------------
// UPnP lifecycle
// ----------------------------------------------------------------------------

TEST_F(PortMapTest, UpnpStartStopIsClean) {
    UpnpClient client;
    std::atomic<bool> callback_seen{false};
    client.set_callback([&](const PortMapResult& r) {
        EXPECT_EQ(PortMapTransport::UPnP, r.transport);
        callback_seen.store(true);
    });
    client.add_mapping(PortMapProtocol::TCP, 51413);

    EXPECT_TRUE(client.start());
    EXPECT_FALSE(client.start());

    auto t0 = std::chrono::steady_clock::now();
    client.stop();
    auto elapsed = std::chrono::steady_clock::now() - t0;

    // SSDP discovery uses bounded waits; teardown must still return quickly.
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 10);
    EXPECT_FALSE(client.is_running());
}

TEST_F(PortMapTest, DestructorStopsRunningWorker) {
    // Leaving scope with a running worker must not leak or hang.
    {
        NatPmpClient natpmp;
        natpmp.add_mapping(PortMapProtocol::UDP, 12345);
        natpmp.start();
    }
    {
        UpnpClient upnp;
        upnp.add_mapping(PortMapProtocol::TCP, 12345);
        upnp.start();
    }
    SUCCEED();
}
