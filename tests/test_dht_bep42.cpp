#include <gtest/gtest.h>
#include "core/ip_address.h"
#include "dht/bep42.h"
#include "dht/id.h"

#include <random>

using namespace librats::dht;
using librats::IpAddress;

// Official BEP 42 test vectors: each IP paired with a node id that must verify for
// it. These pin our CRC32C derivation to the spec's published values.
TEST(DhtBep42, OfficialTestVectors) {
    struct Vec { const char* ip; const char* id_hex; };
    const Vec vectors[] = {
        {"124.31.75.21", "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"},
        {"21.75.31.124", "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256"},
        {"65.23.51.170", "a5d43220bc8f112a3d426c84764f8c2a1150e616"},
        {"84.124.73.14", "1b0321dd1bb1fe518101ceef99462b947a01ff41"},
        {"43.213.53.83", "e56f6cbf5b7c4be0237986d5243b87aa6d51305a"},
    };
    for (const auto& v : vectors) {
        const NodeId id = from_hex(v.id_hex);
        EXPECT_TRUE(verify_node_id_for_ip(id, v.ip)) << v.ip;
        EXPECT_FALSE(verify_node_id_for_ip(id, "8.8.8.8")) << v.ip;  // must not verify elsewhere
    }
}

// A freshly generated id must always verify for the IP it came from (v4 and v6).
TEST(DhtBep42, GenerateVerifyRoundTrip) {
    std::mt19937 rng(0xC0FFEE);
    for (const char* ip : {"1.2.3.4", "198.51.100.7", "2606:4700:4700::1111"}) {
        NodeId id;
        ASSERT_TRUE(generate_node_id_from_ip(*IpAddress::parse(ip), id, rng)) << ip;
        EXPECT_TRUE(verify_node_id_for_ip(id, ip)) << ip;
    }
}

TEST(DhtBep42, GenerateRejectsUnspecifiedIp) {
    std::mt19937 rng(1);
    NodeId id;
    id.fill(0xAB);
    const NodeId before = id;
    EXPECT_FALSE(generate_node_id_from_ip(IpAddress{}, id, rng));
    EXPECT_EQ(id, before);  // left untouched on failure
}

// Non-public addresses can't be verified, so verify must accept any id for them.
TEST(DhtBep42, PrivateAddressesAlwaysVerify) {
    NodeId any;
    any.fill(0x42);
    for (const char* ip : {"192.168.1.10", "10.0.0.1", "127.0.0.1", "::1"})
        EXPECT_TRUE(verify_node_id_for_ip(any, ip)) << ip;
}

TEST(DhtBep42, IsPublicAddress) {
    EXPECT_TRUE(is_public_address(*IpAddress::parse("8.8.8.8")));
    EXPECT_FALSE(is_public_address(*IpAddress::parse("192.168.0.1")));
    EXPECT_FALSE(is_public_address(*IpAddress::parse("127.0.0.1")));
    EXPECT_FALSE(is_public_address(*IpAddress::parse("10.0.0.1")));
}
