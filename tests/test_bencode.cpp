#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "bencode.h"
#include <vector>
#include <string>

using namespace librats;

class BencodeTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup if needed
    }
    
    void TearDown() override {
        // Cleanup if needed
    }
};

// Test BencodeValue creation and type checking
TEST_F(BencodeTest, ValueCreationTest) {
    // Test integer creation
    BencodeValue int_val(42);
    EXPECT_TRUE(int_val.is_integer());
    EXPECT_FALSE(int_val.is_string());
    EXPECT_FALSE(int_val.is_list());
    EXPECT_FALSE(int_val.is_dict());
    EXPECT_EQ(int_val.get_type(), BencodeValue::Type::Integer);
    
    // Test string creation
    BencodeValue str_val("hello");
    EXPECT_TRUE(str_val.is_string());
    EXPECT_FALSE(str_val.is_integer());
    EXPECT_FALSE(str_val.is_list());
    EXPECT_FALSE(str_val.is_dict());
    EXPECT_EQ(str_val.get_type(), BencodeValue::Type::String);
    
    // Test list creation
    BencodeValue list_val = BencodeValue::create_list();
    EXPECT_TRUE(list_val.is_list());
    EXPECT_FALSE(list_val.is_integer());
    EXPECT_FALSE(list_val.is_string());
    EXPECT_FALSE(list_val.is_dict());
    EXPECT_EQ(list_val.get_type(), BencodeValue::Type::List);
    
    // Test dictionary creation
    BencodeValue dict_val = BencodeValue::create_dict();
    EXPECT_TRUE(dict_val.is_dict());
    EXPECT_FALSE(dict_val.is_integer());
    EXPECT_FALSE(dict_val.is_string());
    EXPECT_FALSE(dict_val.is_list());
    EXPECT_EQ(dict_val.get_type(), BencodeValue::Type::Dictionary);
}

// Test value access methods
TEST_F(BencodeTest, ValueAccessTest) {
    // Test integer access
    BencodeValue int_val(42);
    EXPECT_EQ(int_val.as_integer(), 42);
    
    // Test string access
    BencodeValue str_val("hello world");
    EXPECT_EQ(str_val.as_string(), "hello world");
    
    // Test list access
    BencodeValue list_val = BencodeValue::create_list();
    list_val.push_back(BencodeValue(1));
    list_val.push_back(BencodeValue("test"));
    
    const BencodeList& list = list_val.as_list();
    EXPECT_EQ(list.size(), 2);
    EXPECT_EQ(list[0].as_integer(), 1);
    EXPECT_EQ(list[1].as_string(), "test");
    
    // Test dictionary access
    BencodeValue dict_val = BencodeValue::create_dict();
    dict_val["key1"] = BencodeValue(123);
    dict_val["key2"] = BencodeValue("value");
    
    const BencodeDict& dict = dict_val.as_dict();
    EXPECT_EQ(dict.size(), 2);
    EXPECT_TRUE(dict_val.has_key("key1"));
    EXPECT_TRUE(dict_val.has_key("key2"));
    EXPECT_FALSE(dict_val.has_key("nonexistent"));
    EXPECT_EQ(dict_val["key1"].as_integer(), 123);
    EXPECT_EQ(dict_val["key2"].as_string(), "value");
}

// Test list operations
TEST_F(BencodeTest, ListOperationsTest) {
    BencodeValue list_val = BencodeValue::create_list();
    
    // Test push_back
    list_val.push_back(BencodeValue(1));
    list_val.push_back(BencodeValue(2));
    list_val.push_back(BencodeValue("three"));
    
    EXPECT_EQ(list_val.size(), 3);
    
    // Test indexing
    EXPECT_EQ(list_val[0].as_integer(), 1);
    EXPECT_EQ(list_val[1].as_integer(), 2);
    EXPECT_EQ(list_val[2].as_string(), "three");
    
    // Test mutable access
    list_val[0] = BencodeValue(10);
    EXPECT_EQ(list_val[0].as_integer(), 10);
}

// Test dictionary operations
TEST_F(BencodeTest, DictionaryOperationsTest) {
    BencodeValue dict_val = BencodeValue::create_dict();
    
    // Test key assignment
    dict_val["number"] = BencodeValue(42);
    dict_val["text"] = BencodeValue("hello");
    dict_val["nested"] = BencodeValue::create_dict();
    
    EXPECT_EQ(dict_val.size(), 3);
    EXPECT_TRUE(dict_val.has_key("number"));
    EXPECT_TRUE(dict_val.has_key("text"));
    EXPECT_TRUE(dict_val.has_key("nested"));
    
    // Test nested dictionary
    dict_val["nested"]["inner"] = BencodeValue(100);
    EXPECT_EQ(dict_val["nested"]["inner"].as_integer(), 100);
}

// Test integer encoding
TEST_F(BencodeTest, IntegerEncodingTest) {
    BencodeValue int_val(42);
    std::string encoded = int_val.encode_string();
    EXPECT_EQ(encoded, "i42e");
    
    BencodeValue negative_val(-123);
    std::string neg_encoded = negative_val.encode_string();
    EXPECT_EQ(neg_encoded, "i-123e");
    
    BencodeValue zero_val(static_cast<int64_t>(0));
    std::string zero_encoded = zero_val.encode_string();
    EXPECT_EQ(zero_encoded, "i0e");
}

// Test string encoding
TEST_F(BencodeTest, StringEncodingTest) {
    BencodeValue str_val("hello");
    std::string encoded = str_val.encode_string();
    EXPECT_EQ(encoded, "5:hello");
    
    BencodeValue empty_str("");
    std::string empty_encoded = empty_str.encode_string();
    EXPECT_EQ(empty_encoded, "0:");
    
    BencodeValue long_str("this is a longer string for testing");
    std::string long_encoded = long_str.encode_string();
    EXPECT_EQ(long_encoded, "35:this is a longer string for testing");
}

// Test list encoding
TEST_F(BencodeTest, ListEncodingTest) {
    BencodeValue list_val = BencodeValue::create_list();
    list_val.push_back(BencodeValue(1));
    list_val.push_back(BencodeValue(2));
    list_val.push_back(BencodeValue("three"));
    
    std::string encoded = list_val.encode_string();
    EXPECT_EQ(encoded, "li1ei2e5:threee");
    
    // Test empty list
    BencodeValue empty_list = BencodeValue::create_list();
    std::string empty_encoded = empty_list.encode_string();
    EXPECT_EQ(empty_encoded, "le");
}

// Test dictionary encoding
TEST_F(BencodeTest, DictionaryEncodingTest) {
    BencodeValue dict_val = BencodeValue::create_dict();
    dict_val["age"] = BencodeValue(25);
    dict_val["name"] = BencodeValue("Alice");
    
    std::string encoded = dict_val.encode_string();
    // Dictionary keys should be sorted
    EXPECT_EQ(encoded, "d3:agei25e4:name5:Alicee");
    
    // Test empty dictionary
    BencodeValue empty_dict = BencodeValue::create_dict();
    std::string empty_encoded = empty_dict.encode_string();
    EXPECT_EQ(empty_encoded, "de");
}

// Test complex nested encoding
TEST_F(BencodeTest, NestedEncodingTest) {
    BencodeValue root = BencodeValue::create_dict();
    
    // Add simple values
    root["number"] = BencodeValue(42);
    root["text"] = BencodeValue("hello");
    
    // Add nested list
    BencodeValue list = BencodeValue::create_list();
    list.push_back(BencodeValue(1));
    list.push_back(BencodeValue(2));
    list.push_back(BencodeValue(3));
    root["list"] = list;
    
    // Add nested dictionary
    BencodeValue nested_dict = BencodeValue::create_dict();
    nested_dict["inner"] = BencodeValue("value");
    root["dict"] = nested_dict;
    
    std::string encoded = root.encode_string();
    // Keys should be sorted: dict, list, number, text
    EXPECT_EQ(encoded, "d4:dictd5:inner5:valuee4:listli1ei2ei3ee6:numberi42e4:text5:helloe");
}

// Test integer decoding
TEST_F(BencodeTest, IntegerDecodingTest) {
    std::string encoded = "i42e";
    BencodeValue decoded = bencode::decode(encoded);
    EXPECT_TRUE(decoded.is_integer());
    EXPECT_EQ(decoded.as_integer(), 42);
    
    std::string negative_encoded = "i-123e";
    BencodeValue negative_decoded = bencode::decode(negative_encoded);
    EXPECT_TRUE(negative_decoded.is_integer());
    EXPECT_EQ(negative_decoded.as_integer(), -123);
    
    std::string zero_encoded = "i0e";
    BencodeValue zero_decoded = bencode::decode(zero_encoded);
    EXPECT_TRUE(zero_decoded.is_integer());
    EXPECT_EQ(zero_decoded.as_integer(), 0);
}

// Test string decoding
TEST_F(BencodeTest, StringDecodingTest) {
    std::string encoded = "5:hello";
    BencodeValue decoded = bencode::decode(encoded);
    EXPECT_TRUE(decoded.is_string());
    EXPECT_EQ(decoded.as_string(), "hello");
    
    std::string empty_encoded = "0:";
    BencodeValue empty_decoded = bencode::decode(empty_encoded);
    EXPECT_TRUE(empty_decoded.is_string());
    EXPECT_EQ(empty_decoded.as_string(), "");
    
    std::string long_encoded = "35:this is a longer string for testing";
    BencodeValue long_decoded = bencode::decode(long_encoded);
    EXPECT_TRUE(long_decoded.is_string());
    EXPECT_EQ(long_decoded.as_string(), "this is a longer string for testing");
}

// Test list decoding
TEST_F(BencodeTest, ListDecodingTest) {
    std::string encoded = "li1ei2e5:threee";
    BencodeValue decoded = bencode::decode(encoded);
    EXPECT_TRUE(decoded.is_list());
    
    const BencodeList& list = decoded.as_list();
    EXPECT_EQ(list.size(), 3);
    EXPECT_EQ(list[0].as_integer(), 1);
    EXPECT_EQ(list[1].as_integer(), 2);
    EXPECT_EQ(list[2].as_string(), "three");
    
    std::string empty_encoded = "le";
    BencodeValue empty_decoded = bencode::decode(empty_encoded);
    EXPECT_TRUE(empty_decoded.is_list());
    EXPECT_EQ(empty_decoded.as_list().size(), 0);
}

// Test dictionary decoding
TEST_F(BencodeTest, DictionaryDecodingTest) {
    std::string encoded = "d3:agei25e4:name5:Alicee";
    BencodeValue decoded = bencode::decode(encoded);
    EXPECT_TRUE(decoded.is_dict());
    
    EXPECT_TRUE(decoded.has_key("age"));
    EXPECT_TRUE(decoded.has_key("name"));
    EXPECT_EQ(decoded["age"].as_integer(), 25);
    EXPECT_EQ(decoded["name"].as_string(), "Alice");
    
    std::string empty_encoded = "de";
    BencodeValue empty_decoded = bencode::decode(empty_encoded);
    EXPECT_TRUE(empty_decoded.is_dict());
    EXPECT_EQ(empty_decoded.as_dict().size(), 0);
}

// Test complex nested decoding
TEST_F(BencodeTest, NestedDecodingTest) {
    std::string encoded = "d4:dictd5:inner5:valuee4:listli1ei2ei3ee6:numberi42e4:text5:helloe";
    BencodeValue decoded = bencode::decode(encoded);
    EXPECT_TRUE(decoded.is_dict());
    
    EXPECT_TRUE(decoded.has_key("number"));
    EXPECT_TRUE(decoded.has_key("text"));
    EXPECT_TRUE(decoded.has_key("list"));
    EXPECT_TRUE(decoded.has_key("dict"));
    
    EXPECT_EQ(decoded["number"].as_integer(), 42);
    EXPECT_EQ(decoded["text"].as_string(), "hello");
    
    // Test nested list
    EXPECT_TRUE(decoded["list"].is_list());
    const BencodeList& list = decoded["list"].as_list();
    EXPECT_EQ(list.size(), 3);
    EXPECT_EQ(list[0].as_integer(), 1);
    EXPECT_EQ(list[1].as_integer(), 2);
    EXPECT_EQ(list[2].as_integer(), 3);
    
    // Test nested dictionary
    EXPECT_TRUE(decoded["dict"].is_dict());
    EXPECT_TRUE(decoded["dict"].has_key("inner"));
    EXPECT_EQ(decoded["dict"]["inner"].as_string(), "value");
}

// Test round-trip encoding/decoding
TEST_F(BencodeTest, RoundTripTest) {
    // Create complex structure
    BencodeValue original = BencodeValue::create_dict();
    original["int"] = BencodeValue(42);
    original["str"] = BencodeValue("test");
    
    BencodeValue list = BencodeValue::create_list();
    list.push_back(BencodeValue(1));
    list.push_back(BencodeValue("item"));
    original["list"] = list;
    
    BencodeValue nested = BencodeValue::create_dict();
    nested["key"] = BencodeValue("value");
    original["nested"] = nested;
    
    // Encode and decode
    std::string encoded = original.encode_string();
    BencodeValue decoded = bencode::decode(encoded);
    
    // Verify round-trip
    EXPECT_TRUE(decoded.is_dict());
    EXPECT_EQ(decoded["int"].as_integer(), 42);
    EXPECT_EQ(decoded["str"].as_string(), "test");
    EXPECT_EQ(decoded["list"][0].as_integer(), 1);
    EXPECT_EQ(decoded["list"][1].as_string(), "item");
    EXPECT_EQ(decoded["nested"]["key"].as_string(), "value");
}

// Test error handling
TEST_F(BencodeTest, ErrorHandlingTest) {
    // Test invalid integer format
    EXPECT_THROW(bencode::decode("iabce"), std::runtime_error);
    
    // Test invalid string format
    EXPECT_THROW(bencode::decode("10:short"), std::runtime_error);
    
    // Test incomplete data
    EXPECT_THROW(bencode::decode("i42"), std::runtime_error);
    
    // Test invalid list format
    EXPECT_THROW(bencode::decode("li42ei23"), std::runtime_error);
    
    // Test invalid dictionary format
    EXPECT_THROW(bencode::decode("d3:key"), std::runtime_error);
}

// Test binary data handling
TEST_F(BencodeTest, BinaryDataTest) {
    // Create binary data
    std::vector<uint8_t> binary_data = {0x00, 0x01, 0x02, 0xFF, 0xFE};
    std::string binary_str(binary_data.begin(), binary_data.end());
    
    BencodeValue binary_val(binary_str);
    std::vector<uint8_t> encoded = binary_val.encode();
    
    BencodeValue decoded = BencodeDecoder::decode(encoded);
    EXPECT_TRUE(decoded.is_string());
    EXPECT_EQ(decoded.as_string(), binary_str);
}

// Test copy and assignment
TEST_F(BencodeTest, CopyAndAssignmentTest) {
    BencodeValue original(42);
    
    // Test copy constructor
    BencodeValue copy(original);
    EXPECT_EQ(copy.as_integer(), 42);
    
    // Test assignment operator
    BencodeValue assigned = original;
    EXPECT_EQ(assigned.as_integer(), 42);
    
    // Test move constructor
    BencodeValue moved(std::move(original));
    EXPECT_EQ(moved.as_integer(), 42);
} 