#include <gtest/gtest.h>
#include "storage.h"
#include "librats.h"
#include "fs.h"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

#ifdef RATS_STORAGE

using namespace librats;

// Mock RatsClient for testing StorageManager independently
class MockRatsClient : public RatsClient {
public:
    MockRatsClient() : RatsClient(0, 1) {}
    
    // Override to avoid actual network operations
    bool is_gossipsub_available() const { return false; }
    std::string get_our_peer_id() const { return "test_peer_id_12345"; }
};

class StorageTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a temporary test directory
        test_dir_ = "./test_storage_data";
        create_directories(test_dir_.c_str());
        
        // Clean up any previous test data
        cleanup_test_dir();
    }
    
    void TearDown() override {
        // Clean up test data
        cleanup_test_dir();
        delete_directory(test_dir_.c_str());
    }
    
    void cleanup_test_dir() {
        delete_file((test_dir_ + "/rats_storage.dat").c_str());
        delete_file((test_dir_ + "/rats_storage.idx").c_str());
        delete_file((test_dir_ + "/rats_storage.dat.tmp").c_str());
    }
    
    std::string test_dir_;
};

//=============================================================================
// StorageEntry Tests
//=============================================================================

TEST_F(StorageTest, EntrySerializationRoundtrip) {
    StorageEntry entry;
    entry.key = "test_key";
    entry.type = StorageValueType::STRING;
    entry.data = {'h', 'e', 'l', 'l', 'o'};
    entry.timestamp_ms = 1234567890123ULL;
    entry.origin_peer_id = "peer123";
    entry.deleted = false;
    entry.calculate_checksum();
    
    // Serialize
    std::vector<uint8_t> serialized = entry.serialize();
    ASSERT_GT(serialized.size(), 0);
    
    // Deserialize
    StorageEntry restored;
    size_t bytes_read = 0;
    bool success = StorageEntry::deserialize(serialized, 0, restored, bytes_read);
    
    ASSERT_TRUE(success);
    EXPECT_EQ(restored.key, entry.key);
    EXPECT_EQ(restored.type, entry.type);
    EXPECT_EQ(restored.data, entry.data);
    EXPECT_EQ(restored.timestamp_ms, entry.timestamp_ms);
    EXPECT_EQ(restored.origin_peer_id, entry.origin_peer_id);
    EXPECT_EQ(restored.deleted, entry.deleted);
    EXPECT_EQ(restored.checksum, entry.checksum);
    EXPECT_EQ(bytes_read, serialized.size());
}

TEST_F(StorageTest, EntryChecksumVerification) {
    StorageEntry entry;
    entry.key = "checksum_test";
    entry.type = StorageValueType::INT64;
    entry.data = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A}; // 42 in big endian
    entry.timestamp_ms = 1000000;
    entry.origin_peer_id = "peer_abc";
    entry.calculate_checksum();
    
    EXPECT_TRUE(entry.verify_checksum());
    
    // Corrupt the data
    entry.data[0] = 0xFF;
    EXPECT_FALSE(entry.verify_checksum());
}

TEST_F(StorageTest, EntryLWWComparison) {
    StorageEntry older;
    older.key = "test";
    older.timestamp_ms = 1000;
    older.origin_peer_id = "peer_a";
    
    StorageEntry newer;
    newer.key = "test";
    newer.timestamp_ms = 2000;
    newer.origin_peer_id = "peer_b";
    
    // Newer timestamp wins
    EXPECT_TRUE(newer.wins_over(older));
    EXPECT_FALSE(older.wins_over(newer));
    
    // Same timestamp - lexicographically greater peer_id wins
    StorageEntry same_time_a;
    same_time_a.key = "test";
    same_time_a.timestamp_ms = 1000;
    same_time_a.origin_peer_id = "peer_a";
    
    StorageEntry same_time_b;
    same_time_b.key = "test";
    same_time_b.timestamp_ms = 1000;
    same_time_b.origin_peer_id = "peer_b";
    
    EXPECT_TRUE(same_time_b.wins_over(same_time_a));
    EXPECT_FALSE(same_time_a.wins_over(same_time_b));
}

TEST_F(StorageTest, DeletedEntrySerializationRoundtrip) {
    StorageEntry entry;
    entry.key = "deleted_key";
    entry.type = StorageValueType::STRING;
    entry.data = {}; // Empty data for deleted entry
    entry.timestamp_ms = 9999999999ULL;
    entry.origin_peer_id = "deleter";
    entry.deleted = true;
    entry.calculate_checksum();
    
    std::vector<uint8_t> serialized = entry.serialize();
    
    StorageEntry restored;
    size_t bytes_read = 0;
    ASSERT_TRUE(StorageEntry::deserialize(serialized, 0, restored, bytes_read));
    
    EXPECT_EQ(restored.key, entry.key);
    EXPECT_TRUE(restored.deleted);
    EXPECT_TRUE(restored.data.empty());
}

//=============================================================================
// Value Type Conversion Tests
//=============================================================================

TEST_F(StorageTest, ValueTypeConversions) {
    EXPECT_EQ(storage_value_type_to_string(StorageValueType::BINARY), "binary");
    EXPECT_EQ(storage_value_type_to_string(StorageValueType::STRING), "string");
    EXPECT_EQ(storage_value_type_to_string(StorageValueType::INT64), "int64");
    EXPECT_EQ(storage_value_type_to_string(StorageValueType::DOUBLE), "double");
    EXPECT_EQ(storage_value_type_to_string(StorageValueType::JSON), "json");
    
    EXPECT_EQ(string_to_storage_value_type("binary"), StorageValueType::BINARY);
    EXPECT_EQ(string_to_storage_value_type("string"), StorageValueType::STRING);
    EXPECT_EQ(string_to_storage_value_type("int64"), StorageValueType::INT64);
    EXPECT_EQ(string_to_storage_value_type("double"), StorageValueType::DOUBLE);
    EXPECT_EQ(string_to_storage_value_type("json"), StorageValueType::JSON);
    
    // Unknown type defaults to binary
    EXPECT_EQ(string_to_storage_value_type("unknown"), StorageValueType::BINARY);
}

//=============================================================================
// StorageManager Basic Operations Tests
//=============================================================================

class StorageManagerTest : public StorageTest {
protected:
    void SetUp() override {
        StorageTest::SetUp();
        
        // Create a RatsClient for testing
        client_ = std::make_unique<RatsClient>(0, 1);
        
        // Create storage config for testing
        config_.data_directory = test_dir_;
        config_.database_name = "test_storage";
        config_.persist_to_disk = true;
        config_.enable_sync = false;  // Disable sync for unit tests
    }
    
    void TearDown() override {
        // Stop storage manager first
        storage_.reset();
        client_.reset();
        
        // Clean up test files
        delete_file((test_dir_ + "/test_storage.dat").c_str());
        delete_file((test_dir_ + "/test_storage.idx").c_str());
        delete_file((test_dir_ + "/test_storage.dat.tmp").c_str());
        
        StorageTest::TearDown();
    }
    
    std::unique_ptr<RatsClient> client_;
    std::unique_ptr<StorageManager> storage_;
    StorageConfig config_;
};

TEST_F(StorageManagerTest, PutAndGetString) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    ASSERT_TRUE(storage_->put("key1", std::string("value1")));
    
    auto result = storage_->get_string("key1");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "value1");
    
    // Non-existent key
    auto missing = storage_->get_string("nonexistent");
    EXPECT_FALSE(missing.has_value());
}

TEST_F(StorageManagerTest, PutAndGetInt64) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    ASSERT_TRUE(storage_->put("int_key", int64_t(42)));
    
    auto result = storage_->get_int("int_key");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 42);
    
    // Test negative values
    ASSERT_TRUE(storage_->put("neg_key", int64_t(-12345)));
    auto neg_result = storage_->get_int("neg_key");
    ASSERT_TRUE(neg_result.has_value());
    EXPECT_EQ(*neg_result, -12345);
    
    // Test large values
    ASSERT_TRUE(storage_->put("large_key", int64_t(9223372036854775807LL)));
    auto large_result = storage_->get_int("large_key");
    ASSERT_TRUE(large_result.has_value());
    EXPECT_EQ(*large_result, 9223372036854775807LL);
}

TEST_F(StorageManagerTest, PutAndGetDouble) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    ASSERT_TRUE(storage_->put("double_key", 3.14159265359));
    
    auto result = storage_->get_double("double_key");
    ASSERT_TRUE(result.has_value());
    EXPECT_DOUBLE_EQ(*result, 3.14159265359);
    
    // Test special values
    ASSERT_TRUE(storage_->put("zero", 0.0));
    auto zero_result = storage_->get_double("zero");
    ASSERT_TRUE(zero_result.has_value());
    EXPECT_DOUBLE_EQ(*zero_result, 0.0);
}

TEST_F(StorageManagerTest, PutAndGetBinary) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    std::vector<uint8_t> binary_data = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0x80};
    ASSERT_TRUE(storage_->put("binary_key", binary_data));
    
    auto result = storage_->get_binary("binary_key");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, binary_data);
}

TEST_F(StorageManagerTest, PutAndGetJson) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    nlohmann::json json_data = {
        {"name", "test"},
        {"count", 42},
        {"nested", {{"a", 1}, {"b", 2}}},
        {"array", {1, 2, 3, 4, 5}}
    };
    
    ASSERT_TRUE(storage_->put_json("json_key", json_data));
    
    auto result = storage_->get_json("json_key");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, json_data);
}

TEST_F(StorageManagerTest, TypeMismatchReturnsNullopt) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    // Store as string
    ASSERT_TRUE(storage_->put("str_key", std::string("hello")));
    
    // Try to get as int - should fail
    EXPECT_FALSE(storage_->get_int("str_key").has_value());
    EXPECT_FALSE(storage_->get_double("str_key").has_value());
    EXPECT_FALSE(storage_->get_binary("str_key").has_value());
    EXPECT_FALSE(storage_->get_json("str_key").has_value());
    
    // But getting as string should work
    EXPECT_TRUE(storage_->get_string("str_key").has_value());
}

TEST_F(StorageManagerTest, DeleteKey) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    ASSERT_TRUE(storage_->put("to_delete", std::string("value")));
    EXPECT_TRUE(storage_->has("to_delete"));
    
    ASSERT_TRUE(storage_->remove("to_delete"));
    EXPECT_FALSE(storage_->has("to_delete"));
    
    // Deleting non-existent key should return false
    EXPECT_FALSE(storage_->remove("nonexistent"));
    
    // Deleting already deleted key should return false
    EXPECT_FALSE(storage_->remove("to_delete"));
}

TEST_F(StorageManagerTest, HasKey) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    EXPECT_FALSE(storage_->has("key"));
    
    ASSERT_TRUE(storage_->put("key", std::string("value")));
    EXPECT_TRUE(storage_->has("key"));
    
    ASSERT_TRUE(storage_->remove("key"));
    EXPECT_FALSE(storage_->has("key"));
}

TEST_F(StorageManagerTest, KeysAndSize) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    EXPECT_EQ(storage_->size(), 0);
    EXPECT_TRUE(storage_->empty());
    
    ASSERT_TRUE(storage_->put("key1", std::string("v1")));
    ASSERT_TRUE(storage_->put("key2", std::string("v2")));
    ASSERT_TRUE(storage_->put("key3", std::string("v3")));
    
    EXPECT_EQ(storage_->size(), 3);
    EXPECT_FALSE(storage_->empty());
    
    auto all_keys = storage_->keys();
    EXPECT_EQ(all_keys.size(), 3);
    EXPECT_TRUE(std::find(all_keys.begin(), all_keys.end(), "key1") != all_keys.end());
    EXPECT_TRUE(std::find(all_keys.begin(), all_keys.end(), "key2") != all_keys.end());
    EXPECT_TRUE(std::find(all_keys.begin(), all_keys.end(), "key3") != all_keys.end());
}

TEST_F(StorageManagerTest, KeysWithPrefix) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    ASSERT_TRUE(storage_->put("user:1", std::string("alice")));
    ASSERT_TRUE(storage_->put("user:2", std::string("bob")));
    ASSERT_TRUE(storage_->put("post:1", std::string("hello")));
    ASSERT_TRUE(storage_->put("post:2", std::string("world")));
    
    auto user_keys = storage_->keys_with_prefix("user:");
    EXPECT_EQ(user_keys.size(), 2);
    
    auto post_keys = storage_->keys_with_prefix("post:");
    EXPECT_EQ(post_keys.size(), 2);
    
    auto no_match = storage_->keys_with_prefix("comment:");
    EXPECT_EQ(no_match.size(), 0);
}

TEST_F(StorageManagerTest, Clear) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    ASSERT_TRUE(storage_->put("k1", std::string("v1")));
    ASSERT_TRUE(storage_->put("k2", std::string("v2")));
    EXPECT_EQ(storage_->size(), 2);
    
    storage_->clear();
    EXPECT_EQ(storage_->size(), 0);
    EXPECT_TRUE(storage_->empty());
}

TEST_F(StorageManagerTest, UpdateExistingKey) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    ASSERT_TRUE(storage_->put("key", std::string("original")));
    EXPECT_EQ(*storage_->get_string("key"), "original");
    
    // Wait a moment to ensure different timestamp
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    ASSERT_TRUE(storage_->put("key", std::string("updated")));
    EXPECT_EQ(*storage_->get_string("key"), "updated");
    
    // Size should still be 1
    EXPECT_EQ(storage_->size(), 1);
}

//=============================================================================
// Persistence Tests
//=============================================================================

TEST_F(StorageManagerTest, SaveAndLoad) {
    // Create and populate storage
    {
        auto storage = std::make_unique<StorageManager>(*client_, config_);
        
        storage->put("str", std::string("hello"));
        storage->put("int", int64_t(42));
        storage->put("dbl", 3.14);
        storage->put("bin", std::vector<uint8_t>{1, 2, 3});
        storage->put_json("json", nlohmann::json({{"a", 1}}));
        
        ASSERT_TRUE(storage->save());
    }
    
    // Load in new instance
    {
        auto storage = std::make_unique<StorageManager>(*client_, config_);
        
        EXPECT_EQ(storage->size(), 5);
        EXPECT_EQ(*storage->get_string("str"), "hello");
        EXPECT_EQ(*storage->get_int("int"), 42);
        EXPECT_DOUBLE_EQ(*storage->get_double("dbl"), 3.14);
        EXPECT_EQ(*storage->get_binary("bin"), (std::vector<uint8_t>{1, 2, 3}));
        EXPECT_EQ(*storage->get_json("json"), nlohmann::json({{"a", 1}}));
    }
}

TEST_F(StorageManagerTest, PersistenceWithDeletedKeys) {
    // Create storage with some deleted keys
    {
        auto storage = std::make_unique<StorageManager>(*client_, config_);
        
        storage->put("keep", std::string("value"));
        storage->put("delete", std::string("gone"));
        storage->remove("delete");
        
        ASSERT_TRUE(storage->save());
    }
    
    // Load and verify
    {
        auto storage = std::make_unique<StorageManager>(*client_, config_);
        
        EXPECT_TRUE(storage->has("keep"));
        EXPECT_FALSE(storage->has("delete"));
        EXPECT_EQ(storage->size(), 1);
    }
}

TEST_F(StorageManagerTest, Compaction) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    // Create and delete some entries
    for (int i = 0; i < 10; i++) {
        storage_->put("key" + std::to_string(i), std::string("value"));
    }
    
    for (int i = 0; i < 5; i++) {
        storage_->remove("key" + std::to_string(i));
    }
    
    EXPECT_EQ(storage_->size(), 5);
    
    // Compact should remove tombstones
    size_t removed = storage_->compact();
    EXPECT_EQ(removed, 5);
    EXPECT_EQ(storage_->size(), 5);
}

//=============================================================================
// Statistics Tests
//=============================================================================

TEST_F(StorageManagerTest, Statistics) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    storage_->put("k1", std::string("value1"));
    storage_->put("k2", std::string("value2"));
    storage_->put("k3", std::string("value3"));
    storage_->remove("k2");
    
    auto stats = storage_->get_statistics();
    EXPECT_EQ(stats.total_entries, 2);
    EXPECT_EQ(stats.deleted_entries, 1);
    EXPECT_GT(stats.total_data_bytes, 0);
}

TEST_F(StorageManagerTest, StatisticsJson) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    storage_->put("key", std::string("value"));
    
    auto json_stats = storage_->get_statistics_json();
    EXPECT_TRUE(json_stats.contains("total_entries"));
    EXPECT_TRUE(json_stats.contains("deleted_entries"));
    EXPECT_TRUE(json_stats.contains("total_data_bytes"));
    EXPECT_TRUE(json_stats.contains("sync_status"));
    
    EXPECT_EQ(json_stats["total_entries"], 1);
}

//=============================================================================
// Edge Cases Tests
//=============================================================================

TEST_F(StorageManagerTest, EmptyKeyRejected) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    EXPECT_FALSE(storage_->put("", std::string("value")));
    EXPECT_FALSE(storage_->has(""));
}

TEST_F(StorageManagerTest, LargeValue) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    // Create a 1MB string
    std::string large_value(1024 * 1024, 'x');
    
    ASSERT_TRUE(storage_->put("large", large_value));
    
    auto result = storage_->get_string("large");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), large_value.size());
    EXPECT_EQ(*result, large_value);
}

TEST_F(StorageManagerTest, SpecialCharactersInKey) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    std::string special_key = "key/with:special\nchars\t!@#$%";
    
    ASSERT_TRUE(storage_->put(special_key, std::string("value")));
    EXPECT_TRUE(storage_->has(special_key));
    EXPECT_EQ(*storage_->get_string(special_key), "value");
}

TEST_F(StorageManagerTest, BinaryValueWithNullBytes) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    std::vector<uint8_t> binary_with_nulls = {0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00};
    
    ASSERT_TRUE(storage_->put("nullbytes", binary_with_nulls));
    
    auto result = storage_->get_binary("nullbytes");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, binary_with_nulls);
}

//=============================================================================
// Change Callback Tests
//=============================================================================

TEST_F(StorageManagerTest, ChangeCallback) {
    storage_ = std::make_unique<StorageManager>(*client_, config_);
    
    StorageChangeEvent last_event;
    int callback_count = 0;
    
    storage_->set_change_callback([&](const StorageChangeEvent& event) {
        last_event = event;
        callback_count++;
    });
    
    // Test PUT
    storage_->put("key", std::string("value"));
    EXPECT_EQ(callback_count, 1);
    EXPECT_EQ(last_event.operation, StorageOperation::OP_PUT);
    EXPECT_EQ(last_event.key, "key");
    EXPECT_EQ(last_event.type, StorageValueType::STRING);
    
    // Test DELETE
    storage_->remove("key");
    EXPECT_EQ(callback_count, 2);
    EXPECT_EQ(last_event.operation, StorageOperation::OP_DELETE);
    EXPECT_EQ(last_event.key, "key");
}

#endif // RATS_STORAGE
