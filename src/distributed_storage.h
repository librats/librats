#pragma once

#include "socket.h"
#include "json.hpp"
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <map>
#include <atomic>
#include <chrono>
#include <optional>
#include <regex>
#include <thread>
#include <condition_variable>

// Undefine Windows macros that conflict with our code
#ifdef DELETE
#undef DELETE
#endif

namespace librats {

// Forward declaration
class RatsClient;
class DistributedStorage;

/**
 * Storage entry data types
 */
enum class StorageEntryType : uint8_t {
    STRING = 0x01,      // UTF-8 string data
    BINARY = 0x02,      // Raw binary data
    JSON = 0x03,        // JSON object
    INTEGER = 0x04,     // 64-bit signed integer
    DOUBLE = 0x05,      // 64-bit floating point
    BOOLEAN = 0x06,     // Boolean value
    DELETED = 0xFF      // Tombstone marker for deletions
};

/**
 * Conflict resolution strategies
 */
enum class ConflictResolution {
    LAST_WRITE_WINS,    // Use the entry with the highest timestamp (default)
    HIGHEST_VERSION,    // Use the entry with the highest version number
    CUSTOM_MERGE,       // Call custom merge callback
    REJECT_CONFLICT     // Reject conflicting updates
};

/**
 * Sync mode for distributed storage
 */
enum class SyncMode {
    FULL_SYNC,          // Transfer entire storage
    INCREMENTAL,        // Only sync changes since last sync
    DELTA_SYNC          // Optimized delta synchronization
};

/**
 * Storage entry with CRDT-compatible metadata
 * Uses Last-Write-Wins Element Set (LWW-Element-Set) semantics
 */
struct StorageEntry {
    std::string key;                    // Unique key identifier
    std::vector<uint8_t> value;         // Entry value (serialized)
    StorageEntryType type;              // Data type
    
    // CRDT metadata for conflict resolution
    uint64_t version;                   // Logical clock (Lamport timestamp)
    uint64_t timestamp;                 // Wall clock timestamp (milliseconds since epoch)
    std::string author_peer_id;         // Peer that created/modified this entry
    std::string checksum;               // SHA1 hash of value for integrity
    
    // Tombstone support for deletions
    bool is_deleted;                    // True if entry is a tombstone
    uint64_t deleted_at;                // When the entry was deleted
    
    StorageEntry() 
        : type(StorageEntryType::STRING), version(0), timestamp(0), 
          is_deleted(false), deleted_at(0) {}
    
    StorageEntry(const std::string& k, const std::vector<uint8_t>& v, StorageEntryType t)
        : key(k), value(v), type(t), version(1), is_deleted(false), deleted_at(0) {
        timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    
    // Compare entries for conflict resolution (LWW)
    bool is_newer_than(const StorageEntry& other) const {
        if (timestamp != other.timestamp) {
            return timestamp > other.timestamp;
        }
        // Tie-breaker: use version number
        if (version != other.version) {
            return version > other.version;
        }
        // Final tie-breaker: lexicographic comparison of peer ID
        return author_peer_id > other.author_peer_id;
    }
    
    // Serialize entry to JSON
    nlohmann::json to_json() const;
    
    // Deserialize entry from JSON
    static StorageEntry from_json(const nlohmann::json& j);
    
    // Serialize entry to binary format
    std::vector<uint8_t> to_binary() const;
    
    // Deserialize entry from binary format
    static std::optional<StorageEntry> from_binary(const std::vector<uint8_t>& data);
};

/**
 * Storage change event
 */
struct StorageChangeEvent {
    std::string key;                    // Changed key
    StorageEntry old_entry;             // Previous value (empty if new)
    StorageEntry new_entry;             // New value
    bool is_local;                      // True if change originated locally
    std::string source_peer_id;         // Peer that made the change (if remote)
    
    enum class ChangeType {
        INSERT,     // New key added
        UPDATE,     // Existing key modified
        REMOVE      // Key deleted (named REMOVE to avoid Windows DELETE macro conflict)
    } change_type;
};

/**
 * Sync progress information
 */
struct SyncProgress {
    std::string peer_id;                // Peer being synced with
    SyncMode mode;                      // Sync mode used
    uint64_t entries_synced;            // Entries synchronized so far
    uint64_t total_entries;             // Total entries to sync
    uint64_t bytes_transferred;         // Bytes transferred
    bool is_complete;                   // Whether sync is complete
    std::string error_message;          // Error if sync failed
    
    double get_progress_percentage() const {
        if (total_entries == 0) return 100.0;
        return (static_cast<double>(entries_synced) / total_entries) * 100.0;
    }
};

/**
 * Configuration for distributed storage
 */
struct DistributedStorageConfig {
    // Storage settings
    std::string storage_name;           // Unique name for this storage (default: "default")
    std::string storage_path;           // Path for persistence (default: data_directory/storage_name.db)
    uint64_t max_entries;               // Maximum number of entries (0 = unlimited)
    uint64_t max_storage_size_bytes;    // Maximum storage size (0 = unlimited)
    uint64_t max_entry_size_bytes;      // Maximum size per entry (default: 16MB)
    
    // Sync settings
    bool auto_sync;                     // Automatically sync changes (default: true)
    uint32_t sync_interval_seconds;     // Interval for periodic full sync (default: 300)
    uint32_t sync_batch_size;           // Max entries per sync batch (default: 100)
    bool sync_on_connect;               // Sync when peer connects (default: true)
    
    // Persistence settings
    bool persist_to_disk;               // Save to disk (default: true)
    bool auto_save;                     // Auto-save on changes (default: true)
    uint32_t auto_save_interval_seconds;// Auto-save interval (default: 60)
    
    // Conflict resolution
    ConflictResolution conflict_resolution;  // Strategy for conflicts (default: LAST_WRITE_WINS)
    
    // Tombstone settings
    uint64_t tombstone_ttl_seconds;     // How long to keep tombstones (default: 86400 = 24h)
    
    // GossipSub settings
    bool use_gossipsub;                 // Use GossipSub for change propagation (default: true)
    std::string gossipsub_topic;        // Topic for storage updates (default: "storage/{name}")
    
    DistributedStorageConfig()
        : storage_name("default"),
          max_entries(0),
          max_storage_size_bytes(0),
          max_entry_size_bytes(16 * 1024 * 1024),  // 16MB
          auto_sync(true),
          sync_interval_seconds(300),
          sync_batch_size(100),
          sync_on_connect(true),
          persist_to_disk(true),
          auto_save(true),
          auto_save_interval_seconds(60),
          conflict_resolution(ConflictResolution::LAST_WRITE_WINS),
          tombstone_ttl_seconds(86400),
          use_gossipsub(true) {}
};

/**
 * Callback types for storage events
 */
using StorageChangeCallback = std::function<void(const StorageChangeEvent&)>;
using SyncProgressCallback = std::function<void(const SyncProgress&)>;
using ConflictMergeCallback = std::function<StorageEntry(const StorageEntry& local, const StorageEntry& remote)>;

/**
 * Query result for range queries
 */
struct QueryResult {
    std::vector<StorageEntry> entries;
    bool has_more;                      // More results available
    std::string continuation_key;       // Key to continue from
};

/**
 * DistributedStorage - Peer-to-peer synchronized key-value store
 * 
 * Features:
 * - Automatic synchronization between peers
 * - CRDT-based conflict resolution (Last-Write-Wins)
 * - Persistence to disk
 * - Subscribe to changes
 * - Range queries with prefix matching
 * - TTL support for automatic expiration
 * - Tombstone support for proper deletion propagation
 */
class DistributedStorage {
public:
    /**
     * Constructor
     * @param client Reference to RatsClient for peer communication
     * @param config Storage configuration
     */
    DistributedStorage(RatsClient& client, const DistributedStorageConfig& config = DistributedStorageConfig());
    
    /**
     * Destructor
     */
    ~DistributedStorage();
    
    // =========================================================================
    // Configuration
    // =========================================================================
    
    /**
     * Get current configuration
     * @return Configuration settings
     */
    const DistributedStorageConfig& get_config() const;
    
    /**
     * Update configuration (some settings require restart)
     * @param config New configuration
     */
    void set_config(const DistributedStorageConfig& config);
    
    // =========================================================================
    // Basic CRUD Operations
    // =========================================================================
    
    /**
     * Set a string value
     * @param key Key identifier
     * @param value String value
     * @param ttl_seconds Optional TTL (0 = no expiration)
     * @return true if successful
     */
    bool set(const std::string& key, const std::string& value, uint64_t ttl_seconds = 0);
    
    /**
     * Set a binary value
     * @param key Key identifier
     * @param value Binary data
     * @param ttl_seconds Optional TTL (0 = no expiration)
     * @return true if successful
     */
    bool set(const std::string& key, const std::vector<uint8_t>& value, uint64_t ttl_seconds = 0);
    
    /**
     * Set a JSON value
     * @param key Key identifier
     * @param value JSON object
     * @param ttl_seconds Optional TTL (0 = no expiration)
     * @return true if successful
     */
    bool set(const std::string& key, const nlohmann::json& value, uint64_t ttl_seconds = 0);
    
    /**
     * Set an integer value
     * @param key Key identifier
     * @param value Integer value
     * @param ttl_seconds Optional TTL (0 = no expiration)
     * @return true if successful
     */
    bool set(const std::string& key, int64_t value, uint64_t ttl_seconds = 0);
    
    /**
     * Set a double value
     * @param key Key identifier
     * @param value Double value
     * @param ttl_seconds Optional TTL (0 = no expiration)
     * @return true if successful
     */
    bool set(const std::string& key, double value, uint64_t ttl_seconds = 0);
    
    /**
     * Set a boolean value
     * @param key Key identifier
     * @param value Boolean value
     * @param ttl_seconds Optional TTL (0 = no expiration)
     * @return true if successful
     */
    bool set(const std::string& key, bool value, uint64_t ttl_seconds = 0);
    
    /**
     * Get a string value
     * @param key Key identifier
     * @return Value if exists and is string type, nullopt otherwise
     */
    std::optional<std::string> get_string(const std::string& key) const;
    
    /**
     * Get a binary value
     * @param key Key identifier
     * @return Value if exists, nullopt otherwise
     */
    std::optional<std::vector<uint8_t>> get_binary(const std::string& key) const;
    
    /**
     * Get a JSON value
     * @param key Key identifier
     * @return Value if exists and is JSON type, nullopt otherwise
     */
    std::optional<nlohmann::json> get_json(const std::string& key) const;
    
    /**
     * Get an integer value
     * @param key Key identifier
     * @return Value if exists and is integer type, nullopt otherwise
     */
    std::optional<int64_t> get_int(const std::string& key) const;
    
    /**
     * Get a double value
     * @param key Key identifier
     * @return Value if exists and is double type, nullopt otherwise
     */
    std::optional<double> get_double(const std::string& key) const;
    
    /**
     * Get a boolean value
     * @param key Key identifier
     * @return Value if exists and is boolean type, nullopt otherwise
     */
    std::optional<bool> get_bool(const std::string& key) const;
    
    /**
     * Get raw entry with metadata
     * @param key Key identifier
     * @return Entry if exists, nullopt otherwise
     */
    std::optional<StorageEntry> get_entry(const std::string& key) const;
    
    /**
     * Remove a key
     * @param key Key identifier
     * @return true if key existed and was removed
     */
    bool remove(const std::string& key);
    
    /**
     * Check if key exists
     * @param key Key identifier
     * @return true if key exists and is not deleted
     */
    bool exists(const std::string& key) const;
    
    /**
     * Get entry type
     * @param key Key identifier
     * @return Entry type or nullopt if not exists
     */
    std::optional<StorageEntryType> get_type(const std::string& key) const;
    
    // =========================================================================
    // Atomic Operations
    // =========================================================================
    
    /**
     * Increment an integer value atomically
     * @param key Key identifier
     * @param delta Amount to increment (can be negative)
     * @return New value after increment, or nullopt if key doesn't exist or isn't integer
     */
    std::optional<int64_t> increment(const std::string& key, int64_t delta = 1);
    
    /**
     * Set if not exists
     * @param key Key identifier
     * @param value Value to set
     * @return true if key was set (didn't exist), false if key already exists
     */
    bool set_nx(const std::string& key, const std::string& value);
    
    /**
     * Compare and swap
     * @param key Key identifier
     * @param expected_version Expected version number
     * @param new_value New value to set
     * @return true if swap succeeded (version matched)
     */
    bool compare_and_swap(const std::string& key, uint64_t expected_version, const std::string& new_value);
    
    // =========================================================================
    // Range Queries
    // =========================================================================
    
    /**
     * Get all keys
     * @param prefix Optional prefix filter
     * @return Vector of keys matching prefix
     */
    std::vector<std::string> keys(const std::string& prefix = "") const;
    
    /**
     * Get all entries
     * @param prefix Optional prefix filter
     * @return Vector of entries matching prefix
     */
    std::vector<StorageEntry> entries(const std::string& prefix = "") const;
    
    /**
     * Query with pagination
     * @param prefix Key prefix to match
     * @param limit Maximum entries to return
     * @param continuation_key Start from this key (for pagination)
     * @return Query result with entries and continuation info
     */
    QueryResult query(const std::string& prefix = "", size_t limit = 100, 
                     const std::string& continuation_key = "") const;
    
    /**
     * Find keys matching a regex pattern
     * @param pattern Regex pattern to match keys
     * @return Vector of matching keys
     */
    std::vector<std::string> find_keys(const std::string& pattern) const;
    
    /**
     * Get count of entries
     * @param prefix Optional prefix filter
     * @return Number of entries matching prefix
     */
    size_t count(const std::string& prefix = "") const;
    
    /**
     * Get total storage size in bytes
     * @return Total size of all values
     */
    uint64_t size_bytes() const;
    
    // =========================================================================
    // Bulk Operations
    // =========================================================================
    
    /**
     * Set multiple entries at once
     * @param entries Map of key-value pairs
     * @return Number of entries successfully set
     */
    size_t set_bulk(const std::map<std::string, std::string>& entries);
    
    /**
     * Get multiple entries at once
     * @param keys Keys to retrieve
     * @return Map of key to value for existing keys
     */
    std::map<std::string, std::string> get_bulk(const std::vector<std::string>& keys) const;
    
    /**
     * Remove multiple keys at once
     * @param keys Keys to remove
     * @return Number of keys removed
     */
    size_t remove_bulk(const std::vector<std::string>& keys);
    
    /**
     * Clear all entries
     * @param propagate Whether to propagate clear to peers (default: true)
     */
    void clear(bool propagate = true);
    
    // =========================================================================
    // Synchronization
    // =========================================================================
    
    /**
     * Start automatic synchronization
     */
    void start_sync();
    
    /**
     * Stop automatic synchronization
     */
    void stop_sync();
    
    /**
     * Check if sync is running
     * @return true if sync is active
     */
    bool is_sync_running() const;
    
    /**
     * Request full sync with a specific peer
     * @param peer_id Target peer ID
     * @return true if sync request was sent
     */
    bool request_full_sync(const std::string& peer_id);
    
    /**
     * Sync with all connected peers
     */
    void sync_with_all_peers();
    
    /**
     * Get entries that have changed since a version
     * @param since_version Get changes since this version
     * @return Vector of changed entries
     */
    std::vector<StorageEntry> get_changes_since(uint64_t since_version) const;
    
    /**
     * Get current logical clock value
     * @return Current version number
     */
    uint64_t get_current_version() const;
    
    /**
     * Merge entries from another source (manual sync)
     * @param entries Entries to merge
     * @return Number of entries merged
     */
    size_t merge_entries(const std::vector<StorageEntry>& entries);
    
    // =========================================================================
    // Event Handlers
    // =========================================================================
    
    /**
     * Subscribe to changes for a key pattern
     * @param key_pattern Key pattern (supports * and ? wildcards)
     * @param callback Function to call on changes
     * @return Subscription ID for later removal
     */
    std::string on_change(const std::string& key_pattern, StorageChangeCallback callback);
    
    /**
     * Subscribe to all changes
     * @param callback Function to call on any change
     * @return Subscription ID
     */
    std::string on_any_change(StorageChangeCallback callback);
    
    /**
     * Subscribe to sync progress updates
     * @param callback Function to call with sync progress
     * @return Subscription ID
     */
    std::string on_sync_progress(SyncProgressCallback callback);
    
    /**
     * Remove a subscription
     * @param subscription_id ID returned from on_* methods
     */
    void off(const std::string& subscription_id);
    
    /**
     * Set custom conflict merge callback
     * @param callback Function to merge conflicting entries
     */
    void set_conflict_merge_callback(ConflictMergeCallback callback);
    
    // =========================================================================
    // Persistence
    // =========================================================================
    
    /**
     * Save storage to disk
     * @return true if saved successfully
     */
    bool save_to_disk();
    
    /**
     * Load storage from disk
     * @return true if loaded successfully
     */
    bool load_from_disk();
    
    /**
     * Export storage to JSON
     * @return JSON representation of all entries
     */
    nlohmann::json export_to_json() const;
    
    /**
     * Import storage from JSON
     * @param data JSON data to import
     * @param merge Whether to merge with existing data (true) or replace (false)
     * @return Number of entries imported
     */
    size_t import_from_json(const nlohmann::json& data, bool merge = true);
    
    /**
     * Get storage file path
     * @return Path to storage file
     */
    std::string get_storage_path() const;
    
    // =========================================================================
    // Statistics
    // =========================================================================
    
    /**
     * Get storage statistics
     * @return JSON object with statistics
     */
    nlohmann::json get_statistics() const;
    
    /**
     * Clean up expired entries and old tombstones
     * @return Number of entries cleaned
     */
    size_t cleanup_expired();
    
private:
    RatsClient& client_;
    DistributedStorageConfig config_;
    
    // Storage data
    mutable std::shared_mutex storage_mutex_;  // Reader-writer lock for storage
    std::map<std::string, StorageEntry> storage_;  // Ordered map for range queries
    
    // Logical clock for versioning
    std::atomic<uint64_t> logical_clock_;
    
    // Sync state
    std::atomic<bool> sync_running_;
    std::thread sync_thread_;
    std::thread auto_save_thread_;
    std::condition_variable sync_cv_;
    std::mutex sync_mutex_;
    
    // Event subscriptions
    mutable std::mutex subscriptions_mutex_;
    struct Subscription {
        std::string id;
        std::string pattern;
        StorageChangeCallback callback;
        bool is_regex;
    };
    std::vector<Subscription> change_subscriptions_;
    std::vector<std::pair<std::string, SyncProgressCallback>> sync_subscriptions_;
    ConflictMergeCallback conflict_merge_callback_;
    
    // Statistics
    std::atomic<uint64_t> total_sets_;
    std::atomic<uint64_t> total_gets_;
    std::atomic<uint64_t> total_deletes_;
    std::atomic<uint64_t> total_syncs_;
    std::atomic<uint64_t> conflicts_resolved_;
    
    // Private methods
    void initialize();
    void shutdown();
    
    // Core operations
    bool set_internal(const std::string& key, const std::vector<uint8_t>& value, 
                     StorageEntryType type, uint64_t ttl_seconds, bool propagate);
    std::optional<StorageEntry> get_internal(const std::string& key) const;
    bool remove_internal(const std::string& key, bool propagate);
    
    // Synchronization
    void sync_thread_loop();
    void auto_save_thread_loop();
    void handle_sync_request(const std::string& peer_id, const nlohmann::json& message);
    void handle_sync_response(const std::string& peer_id, const nlohmann::json& message);
    void handle_entry_update(const std::string& peer_id, const nlohmann::json& message);
    void handle_entry_delete(const std::string& peer_id, const nlohmann::json& message);
    void handle_bulk_sync(const std::string& peer_id, const nlohmann::json& message);
    void broadcast_entry_change(const StorageEntry& entry, bool is_delete);
    
    // Conflict resolution
    StorageEntry resolve_conflict(const StorageEntry& local, const StorageEntry& remote);
    
    // Event notification
    void notify_change(const StorageChangeEvent& event);
    void notify_sync_progress(const SyncProgress& progress);
    bool matches_pattern(const std::string& key, const std::string& pattern) const;
    
    // Message handlers registration
    void register_message_handlers();
    void unregister_message_handlers();
    
    // Utility
    std::string generate_subscription_id() const;
    std::string calculate_checksum(const std::vector<uint8_t>& data) const;
    uint64_t next_version();
    
    // Persistence helpers
    std::string get_default_storage_path() const;
    bool ensure_storage_directory() const;
};

} // namespace librats

