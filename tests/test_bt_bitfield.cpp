#include <gtest/gtest.h>
#include "bt_bitfield.h"
#include <vector>

using namespace librats;

//=============================================================================
// Construction Tests
//=============================================================================

TEST(BtBitfieldTest, DefaultConstructor) {
    Bitfield bf;
    EXPECT_EQ(bf.size(), 0);
    EXPECT_TRUE(bf.empty());
    EXPECT_TRUE(bf.all_set());  // Empty bitfield is considered "all set"
    EXPECT_TRUE(bf.none_set());
    EXPECT_EQ(bf.count(), 0);
}

TEST(BtBitfieldTest, SizeConstructorZeroValue) {
    Bitfield bf(100, false);
    EXPECT_EQ(bf.size(), 100);
    EXPECT_FALSE(bf.empty());
    EXPECT_TRUE(bf.none_set());
    EXPECT_EQ(bf.count(), 0);
    
    for (size_t i = 0; i < 100; ++i) {
        EXPECT_FALSE(bf.get_bit(i));
    }
}

TEST(BtBitfieldTest, SizeConstructorOneValue) {
    Bitfield bf(100, true);
    EXPECT_EQ(bf.size(), 100);
    EXPECT_TRUE(bf.all_set());
    EXPECT_EQ(bf.count(), 100);
    
    for (size_t i = 0; i < 100; ++i) {
        EXPECT_TRUE(bf.get_bit(i));
    }
}

TEST(BtBitfieldTest, CopyConstructor) {
    Bitfield original(50);
    original.set_bit(10);
    original.set_bit(25);
    original.set_bit(49);
    
    Bitfield copy(original);
    EXPECT_EQ(copy.size(), 50);
    EXPECT_TRUE(copy.get_bit(10));
    EXPECT_TRUE(copy.get_bit(25));
    EXPECT_TRUE(copy.get_bit(49));
    EXPECT_FALSE(copy.get_bit(0));
    EXPECT_EQ(copy.count(), 3);
}

TEST(BtBitfieldTest, MoveConstructor) {
    Bitfield original(50);
    original.set_bit(10);
    
    Bitfield moved(std::move(original));
    EXPECT_EQ(moved.size(), 50);
    EXPECT_TRUE(moved.get_bit(10));
    EXPECT_EQ(original.size(), 0);  // NOLINT: testing moved-from state
}

//=============================================================================
// Bit Operations Tests
//=============================================================================

TEST(BtBitfieldTest, SetAndGetBit) {
    Bitfield bf(64);
    
    bf.set_bit(0);
    bf.set_bit(31);
    bf.set_bit(32);
    bf.set_bit(63);
    
    EXPECT_TRUE(bf.get_bit(0));
    EXPECT_TRUE(bf.get_bit(31));
    EXPECT_TRUE(bf.get_bit(32));
    EXPECT_TRUE(bf.get_bit(63));
    
    EXPECT_FALSE(bf.get_bit(1));
    EXPECT_FALSE(bf.get_bit(30));
    EXPECT_FALSE(bf.get_bit(33));
    EXPECT_FALSE(bf.get_bit(62));
}

TEST(BtBitfieldTest, ClearBit) {
    Bitfield bf(32, true);
    EXPECT_TRUE(bf.all_set());
    
    bf.clear_bit(15);
    EXPECT_FALSE(bf.get_bit(15));
    EXPECT_FALSE(bf.all_set());
    EXPECT_EQ(bf.count(), 31);
    
    bf.set_bit(15);
    EXPECT_TRUE(bf.get_bit(15));
    EXPECT_TRUE(bf.all_set());
}

TEST(BtBitfieldTest, SetAllAndClearAll) {
    Bitfield bf(100);
    
    bf.set_all();
    EXPECT_TRUE(bf.all_set());
    EXPECT_EQ(bf.count(), 100);
    
    bf.clear_all();
    EXPECT_TRUE(bf.none_set());
    EXPECT_EQ(bf.count(), 0);
}

TEST(BtBitfieldTest, OperatorBrackets) {
    Bitfield bf(10);
    bf.set_bit(5);
    
    EXPECT_TRUE(bf[5]);
    EXPECT_FALSE(bf[4]);
    EXPECT_FALSE(bf[6]);
}

TEST(BtBitfieldTest, OutOfBoundsAccess) {
    Bitfield bf(10);
    
    // Out of bounds should not crash, just be ignored/return false
    bf.set_bit(100);  // Should be ignored
    EXPECT_FALSE(bf.get_bit(100));  // Should return false
    
    bf.clear_bit(100);  // Should be ignored
}

//=============================================================================
// Query Operations Tests
//=============================================================================

TEST(BtBitfieldTest, AllSetWithDifferentSizes) {
    // Test with size not divisible by 32
    Bitfield bf1(37, true);
    EXPECT_TRUE(bf1.all_set());
    
    // Test with size exactly 32
    Bitfield bf2(32, true);
    EXPECT_TRUE(bf2.all_set());
    
    // Test with size 1
    Bitfield bf3(1, true);
    EXPECT_TRUE(bf3.all_set());
}

TEST(BtBitfieldTest, CountBits) {
    Bitfield bf(100);
    EXPECT_EQ(bf.count(), 0);
    
    for (int i = 0; i < 100; i += 2) {
        bf.set_bit(i);
    }
    EXPECT_EQ(bf.count(), 50);  // Even indices
}

TEST(BtBitfieldTest, NumBytes) {
    EXPECT_EQ(Bitfield(8).num_bytes(), 1);
    EXPECT_EQ(Bitfield(9).num_bytes(), 2);
    EXPECT_EQ(Bitfield(16).num_bytes(), 2);
    EXPECT_EQ(Bitfield(17).num_bytes(), 3);
    EXPECT_EQ(Bitfield(100).num_bytes(), 13);
}

//=============================================================================
// Bitwise Operations Tests
//=============================================================================

TEST(BtBitfieldTest, BitwiseAnd) {
    Bitfield a(8);
    Bitfield b(8);
    
    a.set_bit(0);
    a.set_bit(1);
    a.set_bit(2);
    
    b.set_bit(1);
    b.set_bit(2);
    b.set_bit(3);
    
    Bitfield result = a & b;
    EXPECT_FALSE(result.get_bit(0));
    EXPECT_TRUE(result.get_bit(1));
    EXPECT_TRUE(result.get_bit(2));
    EXPECT_FALSE(result.get_bit(3));
}

TEST(BtBitfieldTest, BitwiseOr) {
    Bitfield a(8);
    Bitfield b(8);
    
    a.set_bit(0);
    a.set_bit(1);
    
    b.set_bit(2);
    b.set_bit(3);
    
    Bitfield result = a | b;
    EXPECT_TRUE(result.get_bit(0));
    EXPECT_TRUE(result.get_bit(1));
    EXPECT_TRUE(result.get_bit(2));
    EXPECT_TRUE(result.get_bit(3));
    EXPECT_FALSE(result.get_bit(4));
}

TEST(BtBitfieldTest, BitwiseXor) {
    Bitfield a(8);
    Bitfield b(8);
    
    a.set_bit(0);
    a.set_bit(1);
    
    b.set_bit(1);
    b.set_bit(2);
    
    Bitfield result = a ^ b;
    EXPECT_TRUE(result.get_bit(0));
    EXPECT_FALSE(result.get_bit(1));
    EXPECT_TRUE(result.get_bit(2));
}

TEST(BtBitfieldTest, BitwiseNot) {
    Bitfield bf(8);
    bf.set_bit(0);
    bf.set_bit(2);
    bf.set_bit(4);
    bf.set_bit(6);
    
    Bitfield result = ~bf;
    EXPECT_FALSE(result.get_bit(0));
    EXPECT_TRUE(result.get_bit(1));
    EXPECT_FALSE(result.get_bit(2));
    EXPECT_TRUE(result.get_bit(3));
    EXPECT_FALSE(result.get_bit(4));
    EXPECT_TRUE(result.get_bit(5));
    EXPECT_FALSE(result.get_bit(6));
    EXPECT_TRUE(result.get_bit(7));
}

TEST(BtBitfieldTest, HasBitsNotIn) {
    Bitfield a(8);
    Bitfield b(8);
    
    a.set_bit(0);
    a.set_bit(1);
    
    b.set_bit(0);
    
    EXPECT_TRUE(a.has_bits_not_in(b));   // a has bit 1 that b doesn't have
    EXPECT_FALSE(b.has_bits_not_in(a));  // b's only bit is also in a
}

//=============================================================================
// Serialization Tests
//=============================================================================

TEST(BtBitfieldTest, ToBytesSimple) {
    Bitfield bf(8);
    bf.set_bit(0);
    bf.set_bit(7);
    
    auto bytes = bf.to_bytes();
    EXPECT_EQ(bytes.size(), 1);
    EXPECT_EQ(bytes[0], 0x81);  // 10000001 in binary
}

TEST(BtBitfieldTest, ToBytesMultipleBytes) {
    Bitfield bf(16);
    bf.set_bit(0);
    bf.set_bit(8);
    bf.set_bit(15);
    
    auto bytes = bf.to_bytes();
    EXPECT_EQ(bytes.size(), 2);
    EXPECT_EQ(bytes[0], 0x80);  // bit 0 set
    EXPECT_EQ(bytes[1], 0x81);  // bits 8 and 15 set
}

TEST(BtBitfieldTest, FromBytes) {
    std::vector<uint8_t> bytes = {0x81, 0xFF};  // 10000001 11111111
    
    Bitfield bf = Bitfield::from_bytes(bytes, 16);
    EXPECT_EQ(bf.size(), 16);
    
    EXPECT_TRUE(bf.get_bit(0));
    EXPECT_FALSE(bf.get_bit(1));
    EXPECT_TRUE(bf.get_bit(7));
    EXPECT_TRUE(bf.get_bit(8));
    EXPECT_TRUE(bf.get_bit(15));
}

TEST(BtBitfieldTest, FromBytesPartialLastByte) {
    std::vector<uint8_t> bytes = {0xFF};  // All bits set
    
    Bitfield bf = Bitfield::from_bytes(bytes, 5);  // Only use first 5 bits
    EXPECT_EQ(bf.size(), 5);
    EXPECT_EQ(bf.count(), 5);
    EXPECT_TRUE(bf.all_set());
}

TEST(BtBitfieldTest, RoundTrip) {
    Bitfield original(100);
    for (int i = 0; i < 100; i += 3) {
        original.set_bit(i);
    }
    
    auto bytes = original.to_bytes();
    Bitfield restored = Bitfield::from_bytes(bytes, 100);
    
    EXPECT_EQ(original, restored);
}

//=============================================================================
// Resize Tests
//=============================================================================

TEST(BtBitfieldTest, ResizeGrow) {
    Bitfield bf(10);
    bf.set_bit(5);
    
    bf.resize(20);
    EXPECT_EQ(bf.size(), 20);
    EXPECT_TRUE(bf.get_bit(5));
    EXPECT_FALSE(bf.get_bit(15));  // New bits default to false
}

TEST(BtBitfieldTest, ResizeShrink) {
    Bitfield bf(20);
    bf.set_bit(5);
    bf.set_bit(15);
    
    bf.resize(10);
    EXPECT_EQ(bf.size(), 10);
    EXPECT_TRUE(bf.get_bit(5));
    // Bit 15 is now out of range
}

//=============================================================================
// Iteration Helpers Tests
//=============================================================================

TEST(BtBitfieldTest, FindFirstSet) {
    Bitfield bf(100);
    EXPECT_EQ(bf.find_first_set(), 100);  // None set
    
    bf.set_bit(50);
    EXPECT_EQ(bf.find_first_set(), 50);
    
    bf.set_bit(10);
    EXPECT_EQ(bf.find_first_set(), 10);
}

TEST(BtBitfieldTest, FindFirstClear) {
    Bitfield bf(100, true);
    EXPECT_EQ(bf.find_first_clear(), 100);  // None clear
    
    bf.clear_bit(50);
    EXPECT_EQ(bf.find_first_clear(), 50);
    
    bf.clear_bit(10);
    EXPECT_EQ(bf.find_first_clear(), 10);
}

TEST(BtBitfieldTest, FindNextSet) {
    Bitfield bf(100);
    bf.set_bit(10);
    bf.set_bit(50);
    bf.set_bit(99);
    
    EXPECT_EQ(bf.find_next_set(0), 10);
    EXPECT_EQ(bf.find_next_set(10), 50);
    EXPECT_EQ(bf.find_next_set(50), 99);
    EXPECT_EQ(bf.find_next_set(99), 100);  // No more
}

TEST(BtBitfieldTest, FindNextClear) {
    Bitfield bf(10, true);
    bf.clear_bit(3);
    bf.clear_bit(7);
    
    EXPECT_EQ(bf.find_next_clear(0), 3);
    EXPECT_EQ(bf.find_next_clear(3), 7);
    EXPECT_EQ(bf.find_next_clear(7), 10);  // No more
}

//=============================================================================
// Comparison Tests
//=============================================================================

TEST(BtBitfieldTest, Equality) {
    Bitfield a(10);
    Bitfield b(10);
    
    a.set_bit(5);
    b.set_bit(5);
    
    EXPECT_EQ(a, b);
    
    b.set_bit(6);
    EXPECT_NE(a, b);
}

TEST(BtBitfieldTest, EqualityDifferentSizes) {
    Bitfield a(10);
    Bitfield b(20);
    
    EXPECT_NE(a, b);
}

//=============================================================================
// Debug/String Tests
//=============================================================================

TEST(BtBitfieldTest, ToString) {
    Bitfield bf(8);
    bf.set_bit(0);
    bf.set_bit(4);
    bf.set_bit(7);
    
    std::string str = bf.to_string();
    EXPECT_EQ(str, "10001001");
}

//=============================================================================
// Edge Cases
//=============================================================================

TEST(BtBitfieldTest, SingleBit) {
    Bitfield bf(1);
    EXPECT_EQ(bf.size(), 1);
    EXPECT_FALSE(bf.get_bit(0));
    
    bf.set_bit(0);
    EXPECT_TRUE(bf.get_bit(0));
    EXPECT_TRUE(bf.all_set());
    EXPECT_EQ(bf.count(), 1);
}

TEST(BtBitfieldTest, LargeBitfield) {
    Bitfield bf(10000);
    EXPECT_EQ(bf.size(), 10000);
    EXPECT_TRUE(bf.none_set());
    
    bf.set_bit(9999);
    EXPECT_TRUE(bf.get_bit(9999));
    EXPECT_EQ(bf.count(), 1);
    
    bf.set_all();
    EXPECT_TRUE(bf.all_set());
    EXPECT_EQ(bf.count(), 10000);
}

TEST(BtBitfieldTest, WordBoundaries) {
    // Test bits at word boundaries (32-bit words)
    Bitfield bf(96);  // 3 words exactly
    
    // First word boundaries
    bf.set_bit(0);
    bf.set_bit(31);
    
    // Second word boundaries
    bf.set_bit(32);
    bf.set_bit(63);
    
    // Third word boundaries
    bf.set_bit(64);
    bf.set_bit(95);
    
    EXPECT_EQ(bf.count(), 6);
    
    for (int b : {0, 31, 32, 63, 64, 95}) {
        EXPECT_TRUE(bf.get_bit(b)) << "Bit " << b << " should be set";
    }
}
