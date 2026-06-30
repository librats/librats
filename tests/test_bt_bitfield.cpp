#include <gtest/gtest.h>

#include "bittorrent/bitfield.h"

#include <vector>

using namespace librats::bittorrent;

TEST(BtBitfield, DefaultEmpty) {
    Bitfield bf;
    EXPECT_EQ(bf.size(), 0u);
    EXPECT_EQ(bf.num_bytes(), 0u);
    EXPECT_TRUE(bf.empty());
    EXPECT_EQ(bf.count(), 0u);
    EXPECT_TRUE(bf.none_set());
}

TEST(BtBitfield, SizingRoundsUpToBytes) {
    EXPECT_EQ(Bitfield(1).num_bytes(), 1u);
    EXPECT_EQ(Bitfield(8).num_bytes(), 1u);
    EXPECT_EQ(Bitfield(9).num_bytes(), 2u);
    EXPECT_EQ(Bitfield(17).num_bytes(), 3u);
}

TEST(BtBitfield, SetGetReset) {
    Bitfield bf(20);
    EXPECT_FALSE(bf.get(0));
    bf.set(0);
    bf.set(7);
    bf.set(19);
    EXPECT_TRUE(bf.get(0));
    EXPECT_TRUE(bf[7]);
    EXPECT_TRUE(bf.get(19));
    EXPECT_FALSE(bf.get(1));
    EXPECT_EQ(bf.count(), 3u);

    bf.reset(7);
    EXPECT_FALSE(bf.get(7));
    EXPECT_EQ(bf.count(), 2u);

    bf.set(1, true);
    bf.set(0, false);
    EXPECT_TRUE(bf.get(1));
    EXPECT_FALSE(bf.get(0));
}

TEST(BtBitfield, MsbFirstWireLayout) {
    // Bit 0 must be the most-significant bit of byte 0 (BEP 3 layout).
    Bitfield bf(8);
    bf.set(0);
    EXPECT_EQ(bf.data()[0], 0x80u);
    bf.set(1);
    EXPECT_EQ(bf.data()[0], 0xC0u);
    bf.clear_all();
    bf.set(7);
    EXPECT_EQ(bf.data()[0], 0x01u);
}

TEST(BtBitfield, SetAllAndClearAllRespectSpareBits) {
    Bitfield bf(12);  // 2 bytes, 4 spare bits in the last byte
    bf.set_all();
    EXPECT_EQ(bf.count(), 12u);
    EXPECT_TRUE(bf.all_set());
    EXPECT_FALSE(bf.none_set());
    // Spare bits must stay zero so count() stays exact.
    EXPECT_EQ(bf.data()[1], 0xF0u);

    bf.clear_all();
    EXPECT_EQ(bf.count(), 0u);
    EXPECT_TRUE(bf.none_set());
    EXPECT_FALSE(bf.all_set());
}

TEST(BtBitfield, ConstructedWithValueTrue) {
    Bitfield bf(10, true);
    EXPECT_EQ(bf.count(), 10u);
    EXPECT_TRUE(bf.all_set());
    EXPECT_EQ(bf.data()[1], 0xC0u);  // only the top 2 bits of the 2nd byte are real
}

TEST(BtBitfield, FindFirstUnset) {
    Bitfield bf(10, true);
    EXPECT_EQ(bf.find_first_unset(), bf.size());  // all set
    bf.reset(5);
    EXPECT_EQ(bf.find_first_unset(), 5u);
    bf.reset(0);
    EXPECT_EQ(bf.find_first_unset(), 0u);
}

TEST(BtBitfield, ResizeGrowPreservesAndFills) {
    Bitfield bf(4);
    bf.set(1);
    bf.set(3);
    bf.resize(12);                 // grow, default false
    EXPECT_EQ(bf.size(), 12u);
    EXPECT_TRUE(bf.get(1));
    EXPECT_TRUE(bf.get(3));
    EXPECT_FALSE(bf.get(4));
    EXPECT_EQ(bf.count(), 2u);

    Bitfield bf2(4);
    bf2.set(0);
    bf2.resize(12, true);          // grow, fill new bits with 1
    EXPECT_EQ(bf2.count(), 1u + 8u);
    EXPECT_TRUE(bf2.get(0));
    EXPECT_FALSE(bf2.get(1));       // old, was unset — preserved
    EXPECT_TRUE(bf2.get(4));        // newly added
    EXPECT_TRUE(bf2.get(11));
}

TEST(BtBitfield, ResizeShrink) {
    Bitfield bf(16, true);
    bf.resize(5);
    EXPECT_EQ(bf.size(), 5u);
    EXPECT_EQ(bf.num_bytes(), 1u);
    EXPECT_EQ(bf.count(), 5u);
    EXPECT_TRUE(bf.all_set());
}

TEST(BtBitfield, WireRoundTrip) {
    Bitfield bf(20);
    bf.set(0);
    bf.set(9);
    bf.set(19);

    // Send: copy data()/data_size(); Receive: assign().
    std::vector<std::uint8_t> wire(bf.data(), bf.data() + bf.data_size());
    Bitfield rx;
    rx.assign(wire.data(), wire.size(), 20);

    EXPECT_EQ(rx, bf);
    EXPECT_EQ(rx.count(), 3u);
    EXPECT_TRUE(rx.get(0));
    EXPECT_TRUE(rx.get(9));
    EXPECT_TRUE(rx.get(19));
}

TEST(BtBitfield, AssignClearsSpareBits) {
    // A malicious/sloppy peer sets spare bits in the trailing byte; we must ignore them.
    std::uint8_t wire[2] = {0x00u, 0xFFu};  // 12 bits: real bits 8..11 are clear, 12..15 are spare
    Bitfield bf;
    bf.assign(wire, 2, 12);
    EXPECT_EQ(bf.count(), 4u);              // only bits 8,9,10,11 count
    EXPECT_EQ(bf.data()[1], 0xF0u);         // spare bits masked off
}
