#include <gtest/gtest.h>

#include "bittorrent/types.h"

#include <array>
#include <string>

using namespace librats::bittorrent;

namespace {
/// Build a 20-byte peer id from a printable string (zero-padded / truncated).
PeerId make_peer_id(const std::string& s) {
    PeerId id{};
    for (std::size_t i = 0; i < std::min(s.size(), id.size()); ++i) id[i] = std::uint8_t(s[i]);
    return id;
}
} // namespace

TEST(BtTypes, ToHex) {
    InfoHash h{};
    h[0] = 0x00; h[1] = 0xAB; h[19] = 0xFF;
    const std::string hex = to_hex(h);
    EXPECT_EQ(hex.size(), 40u);
    EXPECT_EQ(hex.substr(0, 4), "00ab");
    EXPECT_EQ(hex.substr(38, 2), "ff");
}

TEST(BtTypes, HexRoundTrip) {
    const std::string hex = "0123456789abcdef0123456789abcdef01234567";
    auto h = info_hash_from_hex(hex);
    ASSERT_TRUE(h.has_value());
    EXPECT_EQ(to_hex(*h), hex);
}

TEST(BtTypes, HexUppercaseAccepted) {
    auto lower = info_hash_from_hex("abcdefabcdefabcdefabcdefabcdefabcdefabcd");
    auto upper = info_hash_from_hex("ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD");
    ASSERT_TRUE(lower.has_value());
    ASSERT_TRUE(upper.has_value());
    EXPECT_EQ(*lower, *upper);
}

TEST(BtTypes, HexRejectsBadInput) {
    EXPECT_FALSE(info_hash_from_hex("").has_value());
    EXPECT_FALSE(info_hash_from_hex("abcd").has_value());                          // too short
    EXPECT_FALSE(info_hash_from_hex(std::string(41, 'a')).has_value());            // too long
    EXPECT_FALSE(info_hash_from_hex("zz23456789abcdef0123456789abcdef01234567").has_value());  // non-hex
}

TEST(BtTypes, IsAllZero) {
    InfoHash zero{};
    EXPECT_TRUE(is_all_zero(zero));
    zero[10] = 1;
    EXPECT_FALSE(is_all_zero(zero));
}

TEST(BtTypes, GeneratePeerIdHasPrefixAndIsRandom) {
    PeerId a = generate_peer_id("-LR0001-");
    PeerId b = generate_peer_id("-LR0001-");

    // Prefix preserved.
    const std::string prefix(reinterpret_cast<const char*>(a.data()), 8);
    EXPECT_EQ(prefix, "-LR0001-");

    // Random tails should differ (vanishingly small chance of collision).
    EXPECT_NE(a, b);
}

TEST(BtTypes, ReservedBits) {
    ReservedBytes r{};
    EXPECT_FALSE(reserved::has_dht(r));
    EXPECT_FALSE(reserved::has_fast(r));
    EXPECT_FALSE(reserved::has_extensions(r));

    reserved::enable_dht(r);
    reserved::enable_extensions(r);

    EXPECT_TRUE(reserved::has_dht(r));
    EXPECT_FALSE(reserved::has_fast(r));
    EXPECT_TRUE(reserved::has_extensions(r));
    EXPECT_EQ(r[7], 0x01u);  // DHT bit
    EXPECT_EQ(r[5], 0x10u);  // extension-protocol bit

    reserved::enable_fast(r);
    EXPECT_TRUE(reserved::has_fast(r));
    EXPECT_EQ(r[7], 0x05u);  // DHT | FAST
}

TEST(BtTypes, IdentifyClientAzureusStyle) {
    EXPECT_EQ(identify_client(make_peer_id("-LR0001-abcdefghijkl")), "librats 0.0.0.1");
    EXPECT_EQ(identify_client(make_peer_id("-qB4250-abcdefghijkl")).substr(0, 11), "qBittorrent");
    EXPECT_EQ(identify_client(make_peer_id("-UT3550-abcdefghijkl")).substr(0, 8), "uTorrent");
}

TEST(BtTypes, IdentifyClientGeneratedRoundTrip) {
    EXPECT_EQ(identify_client(generate_peer_id("-LR0001-")), "librats 0.0.0.1");
}

TEST(BtTypes, IdentifyClientUnknown) {
    PeerId weird{};
    weird[0] = '!';  // not zero, not a recognised scheme
    weird[1] = '#';
    const std::string name = identify_client(weird);
    EXPECT_EQ(name.substr(0, 7), "Unknown");
}
