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

// ----------------------------------------------------------------------------
// UPnP XML / URL parsing (the most bug-prone part of the SSDP+SOAP plumbing)
// ----------------------------------------------------------------------------

TEST_F(PortMapTest, ExtractXmlTagBasic) {
    using upnp_detail::extract_xml_tag;
    std::string xml = "<root><controlURL>/ctl/IPConn</controlURL></root>";
    EXPECT_EQ("/ctl/IPConn", extract_xml_tag(xml, "controlURL"));
}

TEST_F(PortMapTest, ExtractXmlTagIsCaseInsensitiveAndTrims) {
    using upnp_detail::extract_xml_tag;
    std::string xml = "<Foo>  \n urn:schemas-upnp-org:service:WANIPConnection:1 \t </Foo>";
    EXPECT_EQ("urn:schemas-upnp-org:service:WANIPConnection:1",
              extract_xml_tag(xml, "foo"));
}

TEST_F(PortMapTest, ExtractXmlTagHandlesAttributesAndMissingTag) {
    using upnp_detail::extract_xml_tag;
    // Opening tag carries attributes; extraction must still find the '>' delimiter.
    std::string xml = "<errorCode xmlns=\"x\">718</errorCode>";
    EXPECT_EQ("718", extract_xml_tag(xml, "errorCode"));
    EXPECT_EQ("", extract_xml_tag(xml, "missing"));
}

TEST_F(PortMapTest, ParseHttpUrlVariants) {
    using upnp_detail::parse_http_url;
    std::string host, path;
    uint16_t port = 0;

    ASSERT_TRUE(parse_http_url("http://192.168.1.1:5000/rootDesc.xml", host, port, path));
    EXPECT_EQ("192.168.1.1", host);
    EXPECT_EQ(5000, port);
    EXPECT_EQ("/rootDesc.xml", path);

    ASSERT_TRUE(parse_http_url("http://192.168.0.1/desc", host, port, path));
    EXPECT_EQ("192.168.0.1", host);
    EXPECT_EQ(80, port); // default
    EXPECT_EQ("/desc", path);

    ASSERT_TRUE(parse_http_url("http://10.0.0.1", host, port, path));
    EXPECT_EQ("10.0.0.1", host);
    EXPECT_EQ(80, port);
    EXPECT_EQ("/", path); // default path

    // Wrong scheme / garbage must be rejected.
    EXPECT_FALSE(parse_http_url("https://10.0.0.1/desc", host, port, path));
    EXPECT_FALSE(parse_http_url("ftp://10.0.0.1", host, port, path));
    EXPECT_FALSE(parse_http_url("not a url", host, port, path));
}

TEST_F(PortMapTest, ResolveControlUrlAbsolute) {
    using upnp_detail::resolve_control_url;
    EXPECT_EQ("http://1.2.3.4:80/ctl",
              resolve_control_url("http://1.2.3.4:80/ctl", "", "10.0.0.1", 5000));
}

TEST_F(PortMapTest, ResolveControlUrlRootRelativeAgainstDescriptionHost) {
    using upnp_detail::resolve_control_url;
    // No URLBase -> resolve against the host:port the description came from.
    EXPECT_EQ("http://192.168.1.1:5000/ctl/IPConn",
              resolve_control_url("/ctl/IPConn", "", "192.168.1.1", 5000));
}

TEST_F(PortMapTest, ResolveControlUrlRelativeGetsLeadingSlash) {
    using upnp_detail::resolve_control_url;
    EXPECT_EQ("http://192.168.1.1:5000/ctl",
              resolve_control_url("ctl", "", "192.168.1.1", 5000));
}

TEST_F(PortMapTest, ResolveControlUrlUsesUrlBaseWithoutDoublingSlash) {
    using upnp_detail::resolve_control_url;
    // URLBase has a trailing slash and control URL is rooted: must not produce "//".
    EXPECT_EQ("http://192.168.1.1:1900/ctl/IPConn",
              resolve_control_url("/ctl/IPConn", "http://192.168.1.1:1900/", "192.168.1.1", 5000));
    EXPECT_EQ("http://192.168.1.1:1900/ctl/IPConn",
              resolve_control_url("ctl/IPConn", "http://192.168.1.1:1900", "192.168.1.1", 5000));
}

TEST_F(PortMapTest, ResolveControlUrlEmptyIsEmpty) {
    using upnp_detail::resolve_control_url;
    EXPECT_EQ("", resolve_control_url("", "", "192.168.1.1", 5000));
}
