#include <gtest/gtest.h>

#include "bittorrent/byte_io.h"

using namespace librats::bittorrent;

TEST(BtByteIo, Read16) {
    const std::uint8_t b[] = {0x12, 0x34};
    EXPECT_EQ(read_u16_be(b), 0x1234u);
}

TEST(BtByteIo, Read32) {
    const std::uint8_t b[] = {0x12, 0x34, 0x56, 0x78};
    EXPECT_EQ(read_u32_be(b), 0x12345678u);
}

TEST(BtByteIo, Read64) {
    const std::uint8_t b[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    EXPECT_EQ(read_u64_be(b), 0x0123456789ABCDEFull);
}

TEST(BtByteIo, WriteRoundTrip16) {
    std::uint8_t b[2];
    write_u16_be(b, 0xBEEFu);
    EXPECT_EQ(b[0], 0xBEu);
    EXPECT_EQ(b[1], 0xEFu);
    EXPECT_EQ(read_u16_be(b), 0xBEEFu);
}

TEST(BtByteIo, WriteRoundTrip32) {
    std::uint8_t b[4];
    write_u32_be(b, 0xDEADBEEFu);
    EXPECT_EQ(read_u32_be(b), 0xDEADBEEFu);
    EXPECT_EQ(b[0], 0xDEu);
    EXPECT_EQ(b[3], 0xEFu);
}

TEST(BtByteIo, WriteRoundTrip64) {
    std::uint8_t b[8];
    write_u64_be(b, 0x0102030405060708ull);
    EXPECT_EQ(read_u64_be(b), 0x0102030405060708ull);
    EXPECT_EQ(b[0], 0x01u);
    EXPECT_EQ(b[7], 0x08u);
}

TEST(BtByteIo, AppendHelpers) {
    librats::Bytes buf;
    append_u8(buf, 0xAA);
    append_u16_be(buf, 0x1122u);
    append_u32_be(buf, 0x33445566u);

    ASSERT_EQ(buf.size(), 1u + 2u + 4u);
    const std::uint8_t expected[] = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    for (std::size_t i = 0; i < buf.size(); ++i) EXPECT_EQ(buf[i], expected[i]) << "at " << i;
}

TEST(BtByteIo, AppendU64) {
    librats::Bytes buf;
    append_u64_be(buf, 0xCAFEBABEDEADBEEFull);
    ASSERT_EQ(buf.size(), 8u);
    EXPECT_EQ(read_u64_be(buf.data()), 0xCAFEBABEDEADBEEFull);
}
