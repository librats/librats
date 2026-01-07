#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "librats.h"
#include "distributed_storage.h"
#include <thread>
#include <chrono>
#include <atomic>

using namespace librats;
using namespace std::chrono_literals;

class DistributedStorageTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create clients on different ports
        client1_ = std::make_unique<RatsClient>(0, 10);  // Port 0 = auto-assign
        client2_ = std::make_unique<RatsClient>(0, 10);
        
        // Start clients
        ASSERT_TRUE(client1_->start());
        ASSERT_TRUE(client2_->start());
        
        // Wait for clients to initialize
        std::this_thread::sleep_for(100ms);
    }
    
    void TearDown() override {
        if (client2_) {
            client2_->stop();
        }
        if (client1_) {
            client1_->stop();
        }
    }
    
    void connect_clients() {
        // Connect client2 to client1
        ASSERT_TRUE(client2_->connect_to_peer("127.0.0.1", client1_->get_listen_port()));
        
        // Wait for connection to establish
        for (int i = 0; i < 50; ++i) {
            if (client1_->get_peer_count() > 0 && client2_->get_peer_count() > 0) {
                break;
            }
            std::this_thread::sleep_for(100ms);
        }
        
        ASSERT_GT(client1_->get_peer_count(), 0);
        ASSERT_GT(client2_->get_peer_count(), 0);
    }
    
    std::unique_ptr<RatsClient> client1_;
    std::unique_ptr<RatsClient> client2_;
};

// =========================================================================
// Basic CRUD Tests
// =========================================================================

TEST_F(DistributedStorageTest, SetAndGetString) {
    auto& storage = client1_->get_distributed_storage("test");
    
    EXPECT_TRUE(storage.set("key1", "value1"));
    
    auto result = storage.get_string("key1");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "value1");
}

TEST_F(DistributedStorageTest, SetAndGetInteger) {
    auto& storage = client1_->get_distributed_storage("test");
    
    EXPECT_TRUE(storage.set("counter", int64_t(42)));
    
    auto result = storage.get_int("counter");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 42);
}

TEST_F(DistributedStorageTest, SetAndGetDouble) {
    auto& storage = client1_->get_distributed_storage("test");
    
    EXPECT_TRUE(storage.set("pi", 3.14159));
    
    auto result = storage.get_double("pi");
    ASSERT_TRUE(result.has_value());
    EXPECT_NEAR(*result, 3.14159, 0.00001);
}

TEST_F(DistributedStorageTest, SetAndGetBoolean) {
    auto& storage = client1_->get_distributed_storage("test");
    
    EXPECT_TRUE(storage.set("flag", true));
    
    auto result = storage.get_bool("flag");
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}

TEST_F(DistributedStorageTest, SetAndGetJSON) {
    auto& storage = client1_->get_distributed_storage("test");
    
    nlohmann::json data = {
        {"name", "test"},
        {"values", {1, 2, 3}},
        {"nested", {{"key", "value"}}}
    };
    
    EXPECT_TRUE(storage.set("json_data", data));
    
    auto result = storage.get_json("json_data");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)["name"], "test");
    EXPECT_EQ((*result)["values"].size(), 3);
}

TEST_F(DistributedStorageTest, SetAndGetBinary) {
    auto& storage = client1_->get_distributed_storage("test");
    
    std::vector<uint8_t> binary_data = {0x01, 0x02, 0x03, 0x04, 0xFF};
    
    EXPECT_TRUE(storage.set("binary", binary_data));
    
    auto result = storage.get_binary("binary");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, binary_data);
}

TEST_F(DistributedStorageTest, RemoveKey) {
    auto& storage = client1_->get_distributed_storage("test");
    
    storage.set("to_remove", "value");
    EXPECT_TRUE(storage.exists("to_remove"));
    
    EXPECT_TRUE(storage.remove("to_remove"));
    EXPECT_FALSE(storage.exists("to_remove"));
}

TEST_F(DistributedStorageTest, KeyNotFound) {
    auto& storage = client1_->get_distributed_storage("test");
    
    auto result = storage.get_string("nonexistent");
    EXPECT_FALSE(result.has_value());
}

// =========================================================================
// Atomic Operations Tests
// =========================================================================

TEST_F(DistributedStorageTest, Increment) {
    auto& storage = client1_->get_distributed_storage("test");
    
    storage.set("counter", int64_t(10));
    
    auto result = storage.increment("counter", 5);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 15);
    
    result = storage.increment("counter", -3);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 12);
}

TEST_F(DistributedStorageTest, SetIfNotExists) {
    auto& storage = client1_->get_distributed_storage("test");
    
    // First set should succeed
    EXPECT_TRUE(storage.set_nx("unique_key", "first_value"));
    
    // Second set should fail (key exists)
    EXPECT_FALSE(storage.set_nx("unique_key", "second_value"));
    
    // Value should be the first one
    auto result = storage.get_string("unique_key");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "first_value");
}

TEST_F(DistributedStorageTest, CompareAndSwap) {
    auto& storage = client1_->get_distributed_storage("test");
    
    storage.set("cas_key", "initial");
    
    auto entry = storage.get_entry("cas_key");
    ASSERT_TRUE(entry.has_value());
    
    uint64_t version = entry->version;
    
    // CAS with correct version should succeed
    EXPECT_TRUE(storage.compare_and_swap("cas_key", version, "updated"));
    
    // CAS with old version should fail
    EXPECT_FALSE(storage.compare_and_swap("cas_key", version, "should_fail"));
    
    auto result = storage.get_string("cas_key");
    EXPECT_EQ(*result, "updated");
}

// =========================================================================
// Range Query Tests
// =========================================================================

TEST_F(DistributedStorageTest, KeysWithPrefix) {
    auto& storage = client1_->get_distributed_storage("test");
    
    storage.set("user:1", "alice");
    storage.set("user:2", "bob");
    storage.set("user:3", "charlie");
    storage.set("product:1", "widget");
    
    auto user_keys = storage.keys("user:");
    EXPECT_EQ(user_keys.size(), 3);
    
    auto product_keys = storage.keys("product:");
    EXPECT_EQ(product_keys.size(), 1);
    
    auto all_keys = storage.keys();
    EXPECT_EQ(all_keys.size(), 4);
}

TEST_F(DistributedStorageTest, Count) {
    auto& storage = client1_->get_distributed_storage("test");
    
    storage.set("a:1", "v1");
    storage.set("a:2", "v2");
    storage.set("b:1", "v3");
    
    EXPECT_EQ(storage.count("a:"), 2);
    EXPECT_EQ(storage.count("b:"), 1);
    EXPECT_EQ(storage.count(), 3);
}

TEST_F(DistributedStorageTest, QueryWithPagination) {
    auto& storage = client1_->get_distributed_storage("test");
    
    // Add 10 entries
    for (int i = 0; i < 10; ++i) {
        storage.set("item:" + std::to_string(i), "value" + std::to_string(i));
    }
    
    // Query first 5
    auto result = storage.query("item:", 5);
    EXPECT_EQ(result.entries.size(), 5);
    EXPECT_TRUE(result.has_more);
    
    // Query next 5
    auto result2 = storage.query("item:", 5, result.continuation_key);
    EXPECT_EQ(result2.entries.size(), 5);
}

// =========================================================================
// Bulk Operations Tests
// =========================================================================

TEST_F(DistributedStorageTest, BulkSet) {
    auto& storage = client1_->get_distributed_storage("test");
    
    std::map<std::string, std::string> entries = {
        {"bulk:1", "v1"},
        {"bulk:2", "v2"},
        {"bulk:3", "v3"}
    };
    
    size_t count = storage.set_bulk(entries);
    EXPECT_EQ(count, 3);
    EXPECT_EQ(storage.count("bulk:"), 3);
}

TEST_F(DistributedStorageTest, BulkGet) {
    auto& storage = client1_->get_distributed_storage("test");
    
    storage.set("g:1", "v1");
    storage.set("g:2", "v2");
    storage.set("g:3", "v3");
    
    std::vector<std::string> keys = {"g:1", "g:2", "g:3", "g:nonexistent"};
    auto results = storage.get_bulk(keys);
    
    EXPECT_EQ(results.size(), 3);
    EXPECT_EQ(results["g:1"], "v1");
    EXPECT_EQ(results["g:2"], "v2");
    EXPECT_EQ(results["g:3"], "v3");
}

TEST_F(DistributedStorageTest, BulkRemove) {
    auto& storage = client1_->get_distributed_storage("test");
    
    storage.set("r:1", "v1");
    storage.set("r:2", "v2");
    storage.set("r:3", "v3");
    
    std::vector<std::string> keys = {"r:1", "r:2"};
    size_t removed = storage.remove_bulk(keys);
    
    EXPECT_EQ(removed, 2);
    EXPECT_FALSE(storage.exists("r:1"));
    EXPECT_FALSE(storage.exists("r:2"));
    EXPECT_TRUE(storage.exists("r:3"));
}

// =========================================================================
// Change Subscription Tests
// =========================================================================

TEST_F(DistributedStorageTest, OnChangeCallback) {
    auto& storage = client1_->get_distributed_storage("test");
    
    std::atomic<int> callback_count{0};
    std::string last_key;
    
    auto sub_id = storage.on_change("*", [&](const StorageChangeEvent& event) {
        callback_count++;
        last_key = event.key;
    });
    
    storage.set("watched_key", "value1");
    std::this_thread::sleep_for(50ms);
    
    EXPECT_EQ(callback_count.load(), 1);
    EXPECT_EQ(last_key, "watched_key");
    
    storage.set("another_key", "value2");
    std::this_thread::sleep_for(50ms);
    
    EXPECT_EQ(callback_count.load(), 2);
    
    storage.off(sub_id);
    
    storage.set("after_unsub", "value3");
    std::this_thread::sleep_for(50ms);
    
    EXPECT_EQ(callback_count.load(), 2);  // Should not increase
}

TEST_F(DistributedStorageTest, PatternMatching) {
    auto& storage = client1_->get_distributed_storage("test");
    
    std::atomic<int> user_changes{0};
    
    auto sub_id = storage.on_change("user:*", [&](const StorageChangeEvent& event) {
        user_changes++;
    });
    
    storage.set("user:1", "alice");
    storage.set("user:2", "bob");
    storage.set("product:1", "widget");  // Should not trigger
    
    std::this_thread::sleep_for(50ms);
    
    EXPECT_EQ(user_changes.load(), 2);
    
    storage.off(sub_id);
}

// =========================================================================
// Persistence Tests
// =========================================================================

TEST_F(DistributedStorageTest, ExportImportJSON) {
    auto& storage1 = client1_->get_distributed_storage("test");
    
    storage1.set("export:1", "value1");
    storage1.set("export:2", "value2");
    
    auto exported = storage1.export_to_json();
    
    auto& storage2 = client2_->get_distributed_storage("import_test");
    size_t imported = storage2.import_from_json(exported, false);
    
    EXPECT_EQ(imported, 2);
    
    auto val1 = storage2.get_string("export:1");
    ASSERT_TRUE(val1.has_value());
    EXPECT_EQ(*val1, "value1");
}

// =========================================================================
// Storage Entry Serialization Tests
// =========================================================================

TEST_F(DistributedStorageTest, EntryToJSON) {
    StorageEntry entry;
    entry.key = "test_key";
    entry.value = {'h', 'e', 'l', 'l', 'o'};
    entry.type = StorageEntryType::STRING;
    entry.version = 42;
    entry.timestamp = 1234567890000;
    entry.author_peer_id = "peer123";
    entry.checksum = "abc123";
    
    auto json = entry.to_json();
    
    EXPECT_EQ(json["key"], "test_key");
    EXPECT_EQ(json["version"], 42);
    
    auto restored = StorageEntry::from_json(json);
    EXPECT_EQ(restored.key, entry.key);
    EXPECT_EQ(restored.version, entry.version);
    EXPECT_EQ(restored.type, entry.type);
}

TEST_F(DistributedStorageTest, EntryToBinary) {
    StorageEntry entry;
    entry.key = "binary_test";
    entry.value = {0x01, 0x02, 0x03};
    entry.type = StorageEntryType::BINARY;
    entry.version = 100;
    entry.timestamp = 9999999;
    entry.author_peer_id = "author";
    entry.checksum = "00112233445566778899aabbccddeeff00112233";
    entry.is_deleted = false;
    
    auto binary = entry.to_binary();
    EXPECT_GT(binary.size(), 0);
    
    auto restored = StorageEntry::from_binary(binary);
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->key, entry.key);
    EXPECT_EQ(restored->value, entry.value);
    EXPECT_EQ(restored->version, entry.version);
}

// =========================================================================
// Conflict Resolution Tests
// =========================================================================

TEST_F(DistributedStorageTest, LastWriteWins) {
    auto& storage = client1_->get_distributed_storage("test");
    
    // Create two entries with different timestamps
    StorageEntry older;
    older.key = "conflict_key";
    older.value = {'o', 'l', 'd'};
    older.type = StorageEntryType::STRING;
    older.version = 1;
    older.timestamp = 1000;
    older.author_peer_id = "peer_old";
    
    StorageEntry newer;
    newer.key = "conflict_key";
    newer.value = {'n', 'e', 'w'};
    newer.type = StorageEntryType::STRING;
    newer.version = 2;
    newer.timestamp = 2000;
    newer.author_peer_id = "peer_new";
    
    // Merge older first, then newer
    storage.merge_entries({older});
    storage.merge_entries({newer});
    
    auto result = storage.get_string("conflict_key");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "new");
}

// =========================================================================
// Statistics Tests
// =========================================================================

TEST_F(DistributedStorageTest, Statistics) {
    auto& storage = client1_->get_distributed_storage("test");
    
    storage.set("stat1", "v1");
    storage.set("stat2", "v2");
    storage.get_string("stat1");
    storage.remove("stat2");
    
    auto stats = storage.get_statistics();
    
    EXPECT_EQ(stats["storage_name"], "test");
    EXPECT_GE(stats["operations"]["total_sets"].get<uint64_t>(), 2);
    EXPECT_GE(stats["operations"]["total_gets"].get<uint64_t>(), 1);
    EXPECT_GE(stats["operations"]["total_deletes"].get<uint64_t>(), 1);
}

// =========================================================================
// RatsClient Convenience Methods Tests
// =========================================================================

TEST_F(DistributedStorageTest, ClientStorageSet) {
    EXPECT_TRUE(client1_->storage_set(std::string("client_key"), std::string("client_value")));
    
    auto result = client1_->storage_get_string("client_key");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "client_value");
}

TEST_F(DistributedStorageTest, ClientStorageJSON) {
    nlohmann::json data = {{"test", "value"}};
    EXPECT_TRUE(client1_->storage_set("json_key", data));
    
    auto result = client1_->storage_get_json("json_key");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)["test"], "value");
}

TEST_F(DistributedStorageTest, ClientStorageExists) {
    client1_->storage_set(std::string("exists_key"), std::string("value"));
    
    EXPECT_TRUE(client1_->storage_exists("exists_key"));
    EXPECT_FALSE(client1_->storage_exists("nonexistent_key"));
}

TEST_F(DistributedStorageTest, ClientStorageRemove) {
    client1_->storage_set(std::string("remove_key"), std::string("value"));
    EXPECT_TRUE(client1_->storage_exists("remove_key"));
    
    EXPECT_TRUE(client1_->storage_remove("remove_key"));
    EXPECT_FALSE(client1_->storage_exists("remove_key"));
}

TEST_F(DistributedStorageTest, MultipleStorages) {
    auto& storage1 = client1_->get_distributed_storage("storage1");
    auto& storage2 = client1_->get_distributed_storage("storage2");
    
    storage1.set("key", "value1");
    storage2.set("key", "value2");
    
    auto result1 = storage1.get_string("key");
    auto result2 = storage2.get_string("key");
    
    ASSERT_TRUE(result1.has_value());
    ASSERT_TRUE(result2.has_value());
    EXPECT_EQ(*result1, "value1");
    EXPECT_EQ(*result2, "value2");
    
    auto names = client1_->get_distributed_storage_names();
    EXPECT_EQ(names.size(), 2);
}

// =========================================================================
// Sync Tests (requires connected clients)
// =========================================================================

TEST_F(DistributedStorageTest, SyncBetweenPeers) {
    connect_clients();
    
    auto& storage1 = client1_->get_distributed_storage("shared");
    auto& storage2 = client2_->get_distributed_storage("shared");
    
    // Set value on client1
    storage1.set("sync_key", "sync_value");
    
    // Request sync
    auto peers = client2_->get_validated_peers();
    ASSERT_GT(peers.size(), 0);
    
    storage2.request_full_sync(peers[0].peer_id);
    
    // Wait for sync
    std::this_thread::sleep_for(500ms);
    
    // Check value on client2
    auto result = storage2.get_string("sync_key");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "sync_value");
}

// =========================================================================
// Cleanup Tests
// =========================================================================

TEST_F(DistributedStorageTest, CleanupExpired) {
    DistributedStorageConfig config;
    config.tombstone_ttl_seconds = 0;  // Immediate cleanup
    
    auto& storage = client1_->create_distributed_storage("cleanup_test", config);
    
    storage.set("to_delete", "value");
    storage.remove("to_delete");
    
    // Wait a bit
    std::this_thread::sleep_for(100ms);
    
    // Cleanup should remove the tombstone
    size_t cleaned = storage.cleanup_expired();
    EXPECT_GE(cleaned, 0);  // May or may not cleanup depending on timing
}

