#include <gtest/gtest.h>
#include "dht/id.h"

#include <type_traits>
#include <unordered_set>

using namespace librats::dht;

namespace {
NodeId id_filled(uint8_t v) {
    NodeId id;
    id.fill(v);
    return id;
}
}

TEST(DhtId, Constants) {
    EXPECT_EQ(kIdSize, 20u);
    EXPECT_EQ(kBucketSize, 8u);
    EXPECT_EQ(kAlpha, 3u);
    EXPECT_EQ(kBucketCount, 160);
    static_assert(std::is_same<InfoHash, NodeId>::value, "InfoHash shares the keyspace");
}

TEST(DhtId, DistanceIsXor) {
    const NodeId a = id_filled(0xF0);
    const NodeId b = id_filled(0x0F);
    for (uint8_t byte : distance(a, b)) EXPECT_EQ(byte, 0xFF);
    for (uint8_t byte : distance(a, a)) EXPECT_EQ(byte, 0x00);  // d(x, x) == 0
}

TEST(DhtId, CloserTo) {
    const NodeId target{};                       // all zero
    NodeId near{};  near[19] = 0x01;             // distance 1 (last bit)
    NodeId far{};   far[0]   = 0x80;             // distance 2^159 (first bit)

    EXPECT_TRUE(closer_to(near, far, target));
    EXPECT_FALSE(closer_to(far, near, target));
    EXPECT_TRUE(closer_to(target, near, target));  // target is closest to itself
    EXPECT_FALSE(closer_to(near, near, target));   // equal distance is not "closer"
}

TEST(DhtId, SharedPrefixBits) {
    const NodeId self{};
    EXPECT_EQ(shared_prefix_bits(self, self), kBucketCount);  // identical -> whole prefix shared

    NodeId msb{}; msb[0] = 0x80;     // differs in the very first bit
    EXPECT_EQ(shared_prefix_bits(self, msb), 0);

    NodeId lsb{}; lsb[19] = 0x01;    // differs only in the last bit
    EXPECT_EQ(shared_prefix_bits(self, lsb), kBucketCount - 1);

    NodeId mid{}; mid[1] = 0x40;     // byte 1, bit 6 -> 1*8 + (7-6) = 9
    EXPECT_EQ(shared_prefix_bits(self, mid), 9);
}

TEST(DhtId, BitsAt) {
    NodeId id{};
    id[0] = 0xA0;  // 1010 0000

    EXPECT_EQ(bits_at(id, 0, 3), 0b101u);   // top 3 bits
    EXPECT_EQ(bits_at(id, 1, 3), 0b010u);   // shifted by one
    EXPECT_EQ(bits_at(id, 0, 1), 0b1u);
    EXPECT_EQ(bits_at(id, kBucketCount - 2, 4), 0u);  // reads past the end as zero
}

TEST(DhtId, HexRoundTrip) {
    NodeId id;
    for (std::size_t i = 0; i < kIdSize; ++i) id[i] = static_cast<uint8_t>(i * 7 + 1);

    const std::string hex = to_hex(id);
    EXPECT_EQ(hex.size(), 40u);
    EXPECT_EQ(from_hex(hex), id);
    EXPECT_EQ(to_hex(NodeId{}), std::string(40, '0'));
}

TEST(DhtId, HexRejectsBadInput) {
    EXPECT_EQ(from_hex("too short"), NodeId{});           // wrong length -> zero
    EXPECT_EQ(from_hex(std::string(40, 'g')), NodeId{});  // non-hex char -> zero
}

TEST(DhtId, BytesRoundTrip) {
    NodeId id;
    for (std::size_t i = 0; i < kIdSize; ++i) id[i] = static_cast<uint8_t>(255 - i);

    const std::string raw = to_bytes(id);
    EXPECT_EQ(raw.size(), kIdSize);
    EXPECT_EQ(from_bytes(raw), id);
    EXPECT_EQ(from_bytes("short"), NodeId{});  // wrong size -> zero
}

TEST(DhtId, NodeIdHashIsDeterministicAndReadsLeadingBytes) {
    NodeIdHash h;
    NodeId a{};
    for (std::size_t i = 0; i < kIdSize; ++i) a[i] = static_cast<uint8_t>(i + 1);

    EXPECT_EQ(h(a), h(a));  // deterministic

    // The hash is the leading sizeof(size_t) bytes reinterpreted (libtorrent-style):
    // changing a byte past that window must NOT change the hash, changing one inside it must.
    NodeId tail = a;
    tail[kIdSize - 1] ^= 0xff;
    EXPECT_EQ(h(a), h(tail));  // trailing byte differs -> same hash

    NodeId head = a;
    head[0] ^= 0xff;
    EXPECT_NE(h(a), h(head));  // leading byte differs -> different hash
}

TEST(DhtId, NodeIdHashWorksAsUnorderedKey) {
    std::unordered_set<NodeId, NodeIdHash> seen;
    EXPECT_TRUE(seen.insert(id_filled(0x11)).second);
    EXPECT_FALSE(seen.insert(id_filled(0x11)).second);  // dedups equal ids
    EXPECT_TRUE(seen.insert(id_filled(0x22)).second);
    EXPECT_EQ(seen.size(), 2u);
    EXPECT_EQ(seen.count(id_filled(0x11)), 1u);
    EXPECT_EQ(seen.count(id_filled(0x33)), 0u);
}
