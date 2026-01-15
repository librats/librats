#pragma once

#include "socket.h"
#include "json.hpp"
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <chrono>
#include <thread>
#include <optional>
#include <condition_variable>

namespace librats {

// Forward declaration
class RatsClient;

/**
 * Value types supported by the distributed storage
 */
enum class StorageValueType : uint8_t {
    BINARY = 0x01,      // Raw binary data
    STRING = 0x02,      // UTF-8 string
    INT64 = 0x03,       // 64-bit signed integer
    DOUBLE = 0x04,      // 64-bit floating point
    JSON = 0x05         // JSON document
};

/**
 * Storage operation types for synchronization
 */
enum class StorageOperation : uint8_t {
    OP_PUT = 0x01,         // Insert or update
    OP_DELETE = 0x02       // Delete key
};

/**
 * Storage synchronization status
 */
enum class StorageSyncStatus {
    NOT_STARTED,        // Sync not initiated
    IN_PROGRESS,        // Sync currently running
    COMPLETED,          // Sync completed successfully
    FAILED              // Sync failed
};

/**
 * Storage entry - represents a single key-value pair in the database
 */
struct StorageEntry {
    std::string key;                    // Key string
    StorageValueType type;              // Value type
    std::vector<uint8_t> data;          // Serialized value data
    uint64_t timestamp_ms;              // Unix timestamp in milliseconds (for LWW)
    std::string origin_peer_id;         // Peer that created/modified this entry
    uint32_t checksum;                  // CRC32 checksum for integrity
    bool deleted;                       // Tombstone marker for deleted entries
    
    StorageEntry() 
        : type(StorageValueType::BINARY), 
          timestamp_ms(0), 
          checksum(0), 
          deleted(false) {}
    
    StorageEntry(const std::string& k, StorageValueType t, 
                 const std::vector<uint8_t>& d, uint64_t ts, 
                 const std::string& peer_id)
        : key(k), type(t), data(d), timestamp_ms(ts), 
          origin_peer_id(peer_id), checksum(0), deleted(false) {
        calculate_checksum();
    }
    
    // Calculate CRC32 checksum
    void calculate_checksum();
    
    // Verify checksum
    bool verify_checksum() const;
    
    // Serialize entry to binary format
    std::vector<uint8_t> serialize() const;
    
    // Deserialize entry from binary format
    static bool deserialize(const std::vector<uint8_t>& data, size_t offset, 
                           StorageEntry& entry, size_t& bytes_read);
    
    // Compare for LWW resolution (returns true if this entry wins)
    bool wins_over(const StorageEntry& other) const;
};

/**
 * Storage change event - passed to change callbacks
 */
struct StorageChangeEvent {
    StorageOperation operation;         // PUT or DELETE
    std::string key;                    // Affected key
    StorageValueType type;              // Value type (for PUT)
    std::vector<uint8_t> old_data;      // Previous value (if any)
    std::vector<uint8_t> new_data;      // New value (for PUT)
    uint64_t timestamp_ms;              // Operation timestamp
    std::string origin_peer_id;         // Peer that made the change
    bool is_remote;                     // True if change came from another peer
};

/**
 * Storage configuration
 */
struct StorageConfig {
    std::string data_directory;         // Directory for storage files
    std::string database_name;          // Database filename prefix
    bool enable_compression;            // Enable LZ4 compression for values
    bool enable_sync;                   // Enable network synchronization
    uint32_t sync_batch_size;           // Number of entries per sync batch
    uint32_t compaction_threshold;      // Number of tombstones before compaction
    uint32_t max_value_size;            // Maximum value size in bytes
    bool persist_to_disk;               // Whether to persist data to disk
    
    StorageConfig()
        : data_directory("./storage"),
          database_name("rats_storage"),
          enable_compression(false),
          enable_sync(true),
          sync_batch_size(100),
          compaction_threshold(1000),
          max_value_size(16 * 1024 * 1024),  // 16MB max value size
          persist_to_disk(true) {}
};

/**
 * Storage statistics
 */
struct StorageStatistics {
    size_t total_entries;               // Total number of entries
    size_t deleted_entries;             // Number of tombstones
    uint64_t total_data_bytes;          // Total size of stored data
    uint64_t disk_usage_bytes;          // Disk space used
    uint64_t entries_synced;            // Entries synced from peers
    uint64_t entries_sent;              // Entries sent to peers
    uint64_t sync_requests_received;    // Number of sync requests received
    uint64_t sync_requests_sent;        // Number of sync requests sent
    std::chrono::steady_clock::time_point last_sync_time;  // Last sync timestamp
    StorageSyncStatus sync_status;      // Current sync status
};

/**
 * Callback function types for storage events
 */
using StorageChangeCallback = std::function<void(const StorageChangeEvent&)>;
using StorageSyncCompleteCallback = std::function<void(bool success, const std::string& error_message)>;

/**
 * StorageManager - Distributed key-value storage with peer synchronization
 * 
 * Features:
 * - Binary on-disk storage for efficiency
 * - In-memory index for O(1) key lookups
 * - Real-time synchronization via GossipSub
 * - Last-Write-Wins conflict resolution
 * - Full database sync for new peers
 * - Typed value support (string, int64, double, binary, JSON)
 */
class StorageManager {
public:
    /**
     * Constructor
     * @param client Reference to RatsClient for network communication
     * @param config Storage configuration settings
     */
    StorageManager(RatsClient& client, const StorageConfig& config = StorageConfig());
    
    /**
     * Destructor - saves data and cleans up resources
     */
    ~StorageManager();
    
    // =========================================================================
    // Configuration
    // =========================================================================
    
    /**
     * Update storage configuration
     * @param config New configuration settings
     */
    void set_config(const StorageConfig& config);
    
    /**
     * Get current configuration
     * @return Current configuration settings
     */
    const StorageConfig& get_config() const;
    
    // =========================================================================
    // Put Operations (Write)
    // =========================================================================
    
    /**
     * Store a string value
     * @param key Key to store under
     * @param value String value to store
     * @return true if stored successfully
     */
    bool put(const std::string& key, const std::string& value);
    
    /**
     * Store a 64-bit integer value
     * @param key Key to store under
     * @param value Integer value to store
     * @return true if stored successfully
     */
    bool put(const std::string& key, int64_t value);
    
    /**
     * Store a double-precision floating point value
     * @param key Key to store under
     * @param value Double value to store
     * @return true if stored successfully
     */
    bool put(const std::string& key, double value);
    
    /**
     * Store binary data
     * @param key Key to store under
     * @param value Binary data to store
     * @return true if stored successfully
     */
    bool put(const std::string& key, const std::vector<uint8_t>& value);
    
    /**
     * Store a JSON document
     * @param key Key to store under
     * @param value JSON value to store
     * @return true if stored successfully
     */
    bool put_json(const std::string& key, const nlohmann::json& value);
    
    // =========================================================================
    // Get Operations (Read)
    // =========================================================================
    
    /**
     * Get a string value
     * @param key Key to retrieve
     * @return Optional containing value if found and type matches
     */
    std::optional<std::string> get_string(const std::string& key) const;
    
    /**
     * Get a 64-bit integer value
     * @param key Key to retrieve
     * @return Optional containing value if found and type matches
     */
    std::optional<int64_t> get_int(const std::string& key) const;
    
    /**
     * Get a double-precision floating point value
     * @param key Key to retrieve
     * @return Optional containing value if found and type matches
     */
    std::optional<double> get_double(const std::string& key) const;
    
    /**
     * Get binary data
     * @param key Key to retrieve
     * @return Optional containing value if found and type matches
     */
    std::optional<std::vector<uint8_t>> get_binary(const std::string& key) const;
    
    /**
     * Get a JSON document
     * @param key Key to retrieve
     * @return Optional containing value if found and type matches
     */
    std::optional<nlohmann::json> get_json(const std::string& key) const;
    
    /**
     * Get raw entry (for advanced usage)
     * @param key Key to retrieve
     * @return Pointer to entry or nullptr if not found
     */
    const StorageEntry* get_entry(const std::string& key) const;
    
    /**
     * Get the type of a stored value
     * @param key Key to check
     * @return Optional containing type if key exists
     */
    std::optional<StorageValueType> get_type(const std::string& key) const;
    
    // =========================================================================
    // Delete and Query Operations
    // =========================================================================
    
    /**
     * Delete a key
     * @param key Key to delete
     * @return true if key existed and was deleted
     */
    bool remove(const std::string& key);
    
    /**
     * Check if a key exists
     * @param key Key to check
     * @return true if key exists and is not deleted
     */
    bool has(const std::string& key) const;
    
    /**
     * Get all keys
     * @return Vector of all keys in storage
     */
    std::vector<std::string> keys() const;
    
    /**
     * Get keys matching a prefix
     * @param prefix Prefix to match
     * @return Vector of matching keys
     */
    std::vector<std::string> keys_with_prefix(const std::string& prefix) const;
    
    /**
     * Get the number of stored entries (excluding tombstones)
     * @return Number of active entries
     */
    size_t size() const;
    
    /**
     * Check if storage is empty
     * @return true if no active entries exist
     */
    bool empty() const;
    
    /**
     * Clear all entries
     */
    void clear();
    
    // =========================================================================
    // Persistence Operations
    // =========================================================================
    
    /**
     * Save storage to disk
     * @return true if saved successfully
     */
    bool save();
    
    /**
     * Load storage from disk
     * @return true if loaded successfully
     */
    bool load();
    
    /**
     * Compact storage (remove tombstones)
     * @return Number of tombstones removed
     */
    size_t compact();
    
    // =========================================================================
    // Synchronization Operations
    // =========================================================================
    
    /**
     * Request full sync from connected peers
     * @return true if sync request was sent
     */
    bool request_sync();
    
    /**
     * Get current sync status
     * @return Current synchronization status
     */
    StorageSyncStatus get_sync_status() const;
    
    /**
     * Check if initial sync is complete
     * @return true if at least one full sync has completed
     */
    bool is_synced() const;
    
    // =========================================================================
    // Event Callbacks
    // =========================================================================
    
    /**
     * Set callback for storage changes
     * @param callback Function to call when storage changes
     */
    void set_change_callback(StorageChangeCallback callback);
    
    /**
     * Set callback for sync completion
     * @param callback Function to call when sync completes
     */
    void set_sync_complete_callback(StorageSyncCompleteCallback callback);
    
    // =========================================================================
    // Statistics and Debugging
    // =========================================================================
    
    /**
     * Get storage statistics
     * @return Statistics structure
     */
    StorageStatistics get_statistics() const;
    
    /**
     * Get statistics as JSON
     * @return JSON object with statistics
     */
    nlohmann::json get_statistics_json() const;
    
    // =========================================================================
    // Internal Network Message Handlers (called by RatsClient)
    // =========================================================================
    
    /**
     * Handle storage-related GossipSub message
     * @param peer_id Source peer ID
     * @param topic Topic name
     * @param message Message content
     */
    void handle_gossip_message(const std::string& peer_id, const std::string& topic, 
                               const std::string& message);
    
    /**
     * Handle storage sync request from peer
     * @param peer_id Requesting peer ID
     * @param data Request data
     */
    void handle_sync_request(const std::string& peer_id, const nlohmann::json& data);
    
    /**
     * Handle storage sync response from peer
     * @param peer_id Responding peer ID
     * @param data Response data containing entries
     */
    void handle_sync_response(const std::string& peer_id, const nlohmann::json& data);
    
    /**
     * Called when a new peer connects (to trigger sync if needed)
     * @param peer_id Connected peer ID
     */
    void on_peer_connected(const std::string& peer_id);
    
private:
    RatsClient& client_;
    StorageConfig config_;
    
    // In-memory storage
    mutable std::mutex storage_mutex_;
    std::unordered_map<std::string, StorageEntry> entries_;
    
    // Sync state
    mutable std::mutex sync_mutex_;
    StorageSyncStatus sync_status_;
    bool initial_sync_complete_;
    std::string sync_peer_id_;  // Peer we're syncing from
    std::chrono::steady_clock::time_point last_sync_time_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    StorageStatistics stats_;
    
    // Callbacks
    StorageChangeCallback change_callback_;
    StorageSyncCompleteCallback sync_complete_callback_;
    
    // Background threads
    std::atomic<bool> running_;
    std::thread persistence_thread_;
    std::condition_variable persistence_cv_;
    std::mutex persistence_mutex_;
    bool dirty_;  // Flag indicating unsaved changes
    
    // GossipSub topic for real-time sync
    static constexpr const char* STORAGE_GOSSIP_TOPIC = "_rats_storage";
    
    // Message type identifiers
    static constexpr const char* MSG_TYPE_PUT = "storage_put";
    static constexpr const char* MSG_TYPE_DELETE = "storage_delete";
    static constexpr const char* MSG_TYPE_SYNC_REQUEST = "storage_sync_request";
    static constexpr const char* MSG_TYPE_SYNC_RESPONSE = "storage_sync_response";
    
    // Private methods
    void initialize();
    void shutdown();
    void persistence_thread_loop();
    
    // Internal put with full control
    bool put_internal(const std::string& key, StorageValueType type, 
                     const std::vector<uint8_t>& data, 
                     uint64_t timestamp_ms = 0,
                     const std::string& origin_peer_id = "",
                     bool broadcast = true);
    
    // Serialization helpers
    std::vector<uint8_t> serialize_value(int64_t value) const;
    std::vector<uint8_t> serialize_value(double value) const;
    std::vector<uint8_t> serialize_value(const std::string& value) const;
    int64_t deserialize_int64(const std::vector<uint8_t>& data) const;
    double deserialize_double(const std::vector<uint8_t>& data) const;
    std::string deserialize_string(const std::vector<uint8_t>& data) const;
    
    // Network operations
    void broadcast_put(const StorageEntry& entry);
    void broadcast_delete(const std::string& key, uint64_t timestamp_ms);
    void send_sync_request(const std::string& peer_id);
    void send_sync_response(const std::string& peer_id);
    
    // Apply remote changes with LWW resolution
    bool apply_remote_entry(const StorageEntry& entry);
    
    // File path helpers
    std::string get_data_file_path() const;
    std::string get_index_file_path() const;
    
    // Disk I/O
    bool write_data_file();
    bool read_data_file();
    
    // Utility
    uint64_t get_current_timestamp_ms() const;
    std::string get_our_peer_id() const;
    void notify_change(const StorageChangeEvent& event);
    void mark_dirty();
};

// CRC32 calculation utility function
uint32_t storage_calculate_crc32(const void* data, size_t length);

// Convert StorageValueType to string
std::string storage_value_type_to_string(StorageValueType type);

// Convert string to StorageValueType
StorageValueType string_to_storage_value_type(const std::string& str);

} // namespace librats
