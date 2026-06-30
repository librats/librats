#include <gtest/gtest.h>

#include "bittorrent/magnet_uri.h"

using namespace librats::bittorrent;

TEST(BtMagnet, HexInfoHash) {
    const std::string hex = "0123456789abcdef0123456789abcdef01234567";
    auto m = MagnetUri::parse("magnet:?xt=urn:btih:" + hex);
    ASSERT_TRUE(m.has_value());
    EXPECT_TRUE(m->is_valid());
    EXPECT_EQ(to_hex(m->info_hash), hex);
}

TEST(BtMagnet, Base32InfoHash) {
    // Base32 and hex of the same 20-byte value must decode identically.
    // 20×0xFF => hex "ff"×20, base32 "7"×32 (each symbol = 0b11111).
    auto hex = MagnetUri::parse("magnet:?xt=urn:btih:" + std::string(40, 'f'));
    auto b32 = MagnetUri::parse("magnet:?xt=urn:btih:" + std::string(32, '7'));
    ASSERT_TRUE(hex.has_value());
    ASSERT_TRUE(b32.has_value());
    EXPECT_EQ(hex->info_hash, b32->info_hash);
}

TEST(BtMagnet, Base32RoundTripNonZero) {
    // 31×'A' (=0) then 'B' (=1): 160 bits = 19 zero bytes + 0x01.
    auto m = MagnetUri::parse("magnet:?xt=urn:btih:" + std::string(31, 'A') + "B");
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(to_hex(m->info_hash), std::string(38, '0') + "01");
}

TEST(BtMagnet, NameTrackersWebSeeds) {
    auto m = MagnetUri::parse(
        "magnet:?xt=urn:btih:" + std::string(40, 'a') +
        "&dn=My%20Torrent&tr=udp%3A%2F%2Ftracker.example%3A80&tr=http://t2.example/announce"
        "&ws=http://seed.example/file");
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->display_name, "My Torrent");
    ASSERT_EQ(m->trackers.size(), 2u);
    EXPECT_EQ(m->trackers[0], "udp://tracker.example:80");
    EXPECT_EQ(m->trackers[1], "http://t2.example/announce");
    ASSERT_EQ(m->web_seeds.size(), 1u);
    EXPECT_EQ(m->web_seeds[0], "http://seed.example/file");
}

TEST(BtMagnet, RejectsNonMagnet) {
    EXPECT_FALSE(MagnetUri::parse("http://example.com").has_value());
    EXPECT_FALSE(MagnetUri::parse("magnet:?dn=no+hash").has_value());          // no xt
    EXPECT_FALSE(MagnetUri::parse("magnet:?xt=urn:btih:tooshort").has_value()); // bad length
}
