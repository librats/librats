#include <gtest/gtest.h>

#include "bittorrent/store_buffer.h"

using namespace librats::bittorrent;
using librats::Bytes;

TEST(BtStoreBuffer, EmptyByDefault) {
    StoreBuffer sb;
    EXPECT_TRUE(sb.empty());
    EXPECT_EQ(sb.size(), 0u);

    Bytes out(4, 0);
    sb.overlay(0, 0, out);              // no entries — out unchanged
    EXPECT_EQ(out, (Bytes{0, 0, 0, 0}));
}

TEST(BtStoreBuffer, InsertEraseSize) {
    StoreBuffer sb;
    sb.insert(0, 0, Bytes{1, 2, 3});
    sb.insert(0, 16, Bytes{4, 5});
    EXPECT_EQ(sb.size(), 2u);
    EXPECT_FALSE(sb.empty());
    sb.erase(0, 0);
    EXPECT_EQ(sb.size(), 1u);
    sb.erase(0, 16);
    EXPECT_TRUE(sb.empty());
}

TEST(BtStoreBuffer, OverlayExactBlock) {
    StoreBuffer sb;
    sb.insert(5, 0, Bytes{0xAA, 0xBB, 0xCC, 0xDD});
    Bytes out(4, 0);
    sb.overlay(5, 0, out);
    EXPECT_EQ(out, (Bytes{0xAA, 0xBB, 0xCC, 0xDD}));
}

TEST(BtStoreBuffer, OverlayIgnoresOtherPieces) {
    StoreBuffer sb;
    sb.insert(4, 0, Bytes{0xFF, 0xFF});
    sb.insert(6, 0, Bytes{0xEE, 0xEE});
    Bytes out(2, 0);
    sb.overlay(5, 0, out);              // piece 5 has nothing
    EXPECT_EQ(out, (Bytes{0, 0}));
}

TEST(BtStoreBuffer, OverlayPartialIntersection) {
    StoreBuffer sb;
    // Stored block covers piece bytes [4, 8).
    sb.insert(1, 4, Bytes{0x11, 0x22, 0x33, 0x44});

    // Read [2, 8): bytes 0,1 untouched; bytes 2..5 (out idx 2..5) overlaid with the
    // first 4 stored bytes.
    Bytes out(6, 0);
    sb.overlay(1, 2, out);
    EXPECT_EQ(out, (Bytes{0, 0, 0x11, 0x22, 0x33, 0x44}));
}

TEST(BtStoreBuffer, OverlayClipsToReadWindow) {
    StoreBuffer sb;
    // Stored block covers [0, 8).
    sb.insert(0, 0, Bytes{1, 2, 3, 4, 5, 6, 7, 8});
    // Read only [2, 5): should pick stored bytes at offsets 2,3,4 => values 3,4,5.
    Bytes out(3, 0);
    sb.overlay(0, 2, out);
    EXPECT_EQ(out, (Bytes{3, 4, 5}));
}

TEST(BtStoreBuffer, OverlayMultipleBlocks) {
    StoreBuffer sb;
    sb.insert(0, 0, Bytes{1, 1});
    sb.insert(0, 4, Bytes{2, 2});
    Bytes out(6, 0);                    // read [0,6)
    sb.overlay(0, 0, out);
    EXPECT_EQ(out, (Bytes{1, 1, 0, 0, 2, 2}));
}
