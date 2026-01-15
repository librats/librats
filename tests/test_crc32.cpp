#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "crc32.h"
#include <string>
#include <vector>

using namespace librats;

class CRC32Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup if needed
    }
    
    void TearDown() override {
        // Cleanup if needed
    }
};

// Test empty data
TEST_F(CRC32Test, EmptyDataTest) {
    CRC32 crc;
    uint32_t result = crc.finalize();
    
    // CRC32 of empty data should be 0x00000000
    EXPECT_EQ(result, 0x00000000);
}

// Test single byte
TEST_F(CRC32Test, SingleByteTest) {
    CRC32 crc;
    crc.update(static_cast<uint8_t>('a'));
    uint32_t result = crc.finalize();
    
    // CRC32 of 'a' (0x61)
    EXPECT_EQ(result, 0xE8B7BE43);
}

// Test short string
TEST_F(CRC32Test, ShortStringTest) {
    uint32_t result = CRC32::calculate("hello");
    
    // Known CRC32 of "hello" (standard zlib/gzip compatible)
    EXPECT_EQ(result, 0x3610A686);
}

// Test "123456789" - standard test vector
TEST_F(CRC32Test, StandardTestVectorTest) {
    uint32_t result = CRC32::calculate("123456789");
    
    // CRC32 of "123456789" is 0xCBF43926 (standard test vector)
    EXPECT_EQ(result, 0xCBF43926);
}

// Test incremental update
TEST_F(CRC32Test, IncrementalUpdateTest) {
    CRC32 crc;
    crc.update("hello");
    crc.update(" ");
    crc.update("world");
    uint32_t incremental_result = crc.finalize();
    
    // Should match single-shot calculation
    uint32_t single_result = CRC32::calculate("hello world");
    
    EXPECT_EQ(incremental_result, single_result);
}

// Test byte-by-byte update
TEST_F(CRC32Test, ByteByByteUpdateTest) {
    std::string input = "test";
    
    CRC32 crc;
    for (char c : input) {
        crc.update(static_cast<uint8_t>(c));
    }
    uint32_t byte_result = crc.finalize();
    
    // Should match single-shot calculation
    uint32_t single_result = CRC32::calculate(input);
    
    EXPECT_EQ(byte_result, single_result);
}

// Test vector update
TEST_F(CRC32Test, VectorUpdateTest) {
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    
    uint32_t result = CRC32::calculate(data);
    
    // Should match string calculation (case-sensitive)
    uint32_t string_result = CRC32::calculate("Hello");
    
    EXPECT_EQ(result, string_result);
}

// Test reset functionality
TEST_F(CRC32Test, ResetTest) {
    CRC32 crc;
    crc.update("first data");
    crc.reset();
    crc.update("second data");
    uint32_t reset_result = crc.finalize();
    
    // Should match just "second data"
    uint32_t expected = CRC32::calculate("second data");
    
    EXPECT_EQ(reset_result, expected);
}

// Test null data handling
TEST_F(CRC32Test, NullDataTest) {
    CRC32 crc;
    crc.update(nullptr, 0);
    crc.update(nullptr, 100); // Should not crash
    uint32_t result = crc.finalize();
    
    // Should be same as empty
    EXPECT_EQ(result, 0x00000000);
}

// Test zero length handling
TEST_F(CRC32Test, ZeroLengthTest) {
    CRC32 crc;
    uint8_t dummy[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    crc.update(dummy, 0);
    uint32_t result = crc.finalize();
    
    // Should be same as empty
    EXPECT_EQ(result, 0x00000000);
}

// Test binary data with zeros
TEST_F(CRC32Test, BinaryDataWithZerosTest) {
    std::vector<uint8_t> data = {0x00, 0x00, 0x00, 0x00};
    uint32_t result = CRC32::calculate(data);
    
    // CRC32 of four zero bytes
    EXPECT_EQ(result, 0x2144DF1C);
}

// Test binary data with all 0xFF
TEST_F(CRC32Test, BinaryDataAllOnesTest) {
    std::vector<uint8_t> data = {0xFF, 0xFF, 0xFF, 0xFF};
    uint32_t result = CRC32::calculate(data);
    
    // CRC32 of four 0xFF bytes
    EXPECT_EQ(result, 0xFFFFFFFF);
}

// Test determinism
TEST_F(CRC32Test, DeterministicTest) {
    std::string input = "deterministic test";
    
    uint32_t result1 = CRC32::calculate(input);
    uint32_t result2 = CRC32::calculate(input);
    uint32_t result3 = CRC32::calculate(input);
    
    EXPECT_EQ(result1, result2);
    EXPECT_EQ(result2, result3);
}

// Test different inputs produce different results
TEST_F(CRC32Test, DifferentInputsTest) {
    uint32_t crc1 = CRC32::calculate("input1");
    uint32_t crc2 = CRC32::calculate("input2");
    uint32_t crc3 = CRC32::calculate("Input1"); // Case difference
    
    EXPECT_NE(crc1, crc2);
    EXPECT_NE(crc1, crc3);
    EXPECT_NE(crc2, crc3);
}

// Test large data
TEST_F(CRC32Test, LargeDataTest) {
    std::string large_data;
    large_data.reserve(100000);
    
    // Create 100KB of data
    for (int i = 0; i < 100000; ++i) {
        large_data += static_cast<char>('a' + (i % 26));
    }
    
    uint32_t result1 = CRC32::calculate(large_data);
    uint32_t result2 = CRC32::calculate(large_data);
    
    // Should be consistent
    EXPECT_EQ(result1, result2);
    
    // Should not be zero or all ones (very unlikely for valid data)
    EXPECT_NE(result1, 0x00000000);
    EXPECT_NE(result1, 0xFFFFFFFF);
}

// Test get_value vs finalize
TEST_F(CRC32Test, GetValueVsFinalizeTest) {
    CRC32 crc;
    crc.update("test");
    
    // get_value and finalize should return the same result
    uint32_t value1 = crc.get_value();
    uint32_t value2 = crc.finalize();
    
    EXPECT_EQ(value1, value2);
}

// Test multiple finalize calls
TEST_F(CRC32Test, MultipleFinalizeTest) {
    CRC32 crc;
    crc.update("test");
    
    uint32_t result1 = crc.finalize();
    uint32_t result2 = crc.finalize();
    
    // finalize should be idempotent
    EXPECT_EQ(result1, result2);
}

// Test legacy function compatibility
TEST_F(CRC32Test, LegacyFunctionTest) {
    std::string data = "legacy test data";
    
    uint32_t legacy_result = storage_calculate_crc32(data.c_str(), data.size());
    uint32_t class_result = CRC32::calculate(data);
    
    EXPECT_EQ(legacy_result, class_result);
}

// Test all printable ASCII characters
TEST_F(CRC32Test, AllPrintableASCIITest) {
    std::string printable;
    for (char c = 32; c < 127; c++) {
        printable += c;
    }
    
    uint32_t result = CRC32::calculate(printable);
    
    // Should be consistent
    uint32_t result2 = CRC32::calculate(printable);
    EXPECT_EQ(result, result2);
}

// Test known CRC32 values (verified against online calculators)
TEST_F(CRC32Test, KnownValuesTest) {
    // These are standard CRC32 (IEEE 802.3) test vectors
    EXPECT_EQ(CRC32::calculate(""), 0x00000000);
    EXPECT_EQ(CRC32::calculate("a"), 0xE8B7BE43);
    EXPECT_EQ(CRC32::calculate("abc"), 0x352441C2);
    EXPECT_EQ(CRC32::calculate("message digest"), 0x20159D7F);
    EXPECT_EQ(CRC32::calculate("abcdefghijklmnopqrstuvwxyz"), 0x4C2750BD);
    EXPECT_EQ(CRC32::calculate("123456789"), 0xCBF43926);
}

// Test boundary - exactly 64 bytes (block size for some implementations)
TEST_F(CRC32Test, BlockBoundaryTest) {
    std::string exactly64(64, 'X');
    std::string exactly63(63, 'X');
    std::string exactly65(65, 'X');
    
    uint32_t crc64 = CRC32::calculate(exactly64);
    uint32_t crc63 = CRC32::calculate(exactly63);
    uint32_t crc65 = CRC32::calculate(exactly65);
    
    // All should be different
    EXPECT_NE(crc63, crc64);
    EXPECT_NE(crc64, crc65);
    EXPECT_NE(crc63, crc65);
}

// Test special characters
TEST_F(CRC32Test, SpecialCharactersTest) {
    uint32_t result = CRC32::calculate("!@#$%^&*()_+-=[]{}|;':\",./<>?");
    
    // Should be consistent
    uint32_t result2 = CRC32::calculate("!@#$%^&*()_+-=[]{}|;':\",./<>?");
    EXPECT_EQ(result, result2);
}

// Test whitespace sensitivity
TEST_F(CRC32Test, WhitespaceSensitivityTest) {
    uint32_t crc1 = CRC32::calculate("hello world");
    uint32_t crc2 = CRC32::calculate("hello  world");  // Two spaces
    uint32_t crc3 = CRC32::calculate("hello\tworld");  // Tab
    uint32_t crc4 = CRC32::calculate("hello\nworld");  // Newline
    
    // All should be different
    EXPECT_NE(crc1, crc2);
    EXPECT_NE(crc1, crc3);
    EXPECT_NE(crc1, crc4);
    EXPECT_NE(crc2, crc3);
    EXPECT_NE(crc2, crc4);
    EXPECT_NE(crc3, crc4);
}

// Test order sensitivity
TEST_F(CRC32Test, OrderSensitivityTest) {
    uint32_t crc1 = CRC32::calculate("abc");
    uint32_t crc2 = CRC32::calculate("cba");
    uint32_t crc3 = CRC32::calculate("bac");
    
    // All should be different
    EXPECT_NE(crc1, crc2);
    EXPECT_NE(crc1, crc3);
    EXPECT_NE(crc2, crc3);
}
