#pragma once

/**
 * @file storage.h
 * @brief Distributed key-value store as a pluggable Node subsystem.
 *
 * A replicated key-value database with Last-Write-Wins (LWW) conflict
 * resolution, typed values, binary on-disk persistence, and peer
 * synchronization. It is a `Subsystem`: it reaches the mesh only through
 * `PeerNetwork` (never the Node), exactly like PubSub/FileTransfer.
 *
 * Replication model — an epidemic LWW broadcast:
 *   - A local put/remove builds a StorageEntry (a delete is a tombstone entry
 *     with `deleted=true`) and broadcasts it to all connected peers.
 *   - On receiving an entry, a node applies it under LWW. It re-forwards the
 *     entry to its *other* peers ONLY if the entry actually won (carried new
 *     information). A duplicate loses LWW and is not forwarded, so flooding
 *     terminates naturally — no separate dedup table needed.
 *   - On peer connect, both sides exchange a full snapshot (anti-entropy) so a
 *     late joiner catches up. LWW makes the merge order-independent.
 *
 * Wire format (MessageType::Storage payload, opcode in byte 0):
 *   ENTRY:         [1][StorageEntry.serialize()]
 *   SYNC_REQUEST:  [2]
 *   SYNC_RESPONSE: [3][count:u32][StorageEntry.serialize()] * count
 *
 * The class is also usable standalone (no network attached) as a local,
 * persistent key-value store; all network operations no-op until attach().
 */

#include "node/peer_network.h"
#include "peer/peer.h"
#include "peer/peer_id.h"
#include "core/bytes.h"
#include "util/json.hpp"

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
 * Storage operation types for change events
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
    std::string origin_peer_id;         // Peer that created/modified this entry (hex PeerId)
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
    bool enable_sync;                   // Enable network synchronization
    uint32_t compaction_threshold;      // Number of tombstones before compaction
    uint32_t max_value_size;            // Maximum value size in bytes
    bool persist_to_disk;               // Whether to persist data to disk

    StorageConfig()
        : data_directory("./storage"),
          database_name("rats_storage"),
          enable_sync(true),
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
 * StorageManager - Distributed key-value storage with peer synchronization.
 *
 * A Node subsystem: attach()/start()/stop() plug it into a Node, and it reaches
 * the mesh only via PeerNetwork. It can also be used standalone as a local,
 * persistent key-value store (network operations no-op until attached).
 */
class StorageManager final : public Subsystem {
public:
    /**
     * Constructor.
     * @param config Storage configuration settings.
     *
     * Loads any existing data from disk and starts the background persistence
     * thread immediately, so the store is usable for local reads/writes before
     * (and without) being added to a Node.
     */
    explicit StorageManager(const StorageConfig& config = StorageConfig());

    /**
     * Destructor - saves data and cleans up resources.
     */
    ~StorageManager() override;

    StorageManager(const StorageManager&) = delete;
    StorageManager& operator=(const StorageManager&) = delete;

    // =========================================================================
    // Subsystem
    // =========================================================================

    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

    // =========================================================================
    // Configuration
    // =========================================================================

    void set_config(const StorageConfig& config);
    const StorageConfig& get_config() const;

    // =========================================================================
    // Put Operations (Write)
    // =========================================================================

    bool put(const std::string& key, const std::string& value);
    bool put(const std::string& key, int64_t value);
    bool put(const std::string& key, double value);
    bool put(const std::string& key, const std::vector<uint8_t>& value);
    bool put_json(const std::string& key, const nlohmann::json& value);

    // =========================================================================
    // Get Operations (Read)
    // =========================================================================

    std::optional<std::string> get_string(const std::string& key) const;
    std::optional<int64_t> get_int(const std::string& key) const;
    std::optional<double> get_double(const std::string& key) const;
    std::optional<std::vector<uint8_t>> get_binary(const std::string& key) const;
    std::optional<nlohmann::json> get_json(const std::string& key) const;
    std::optional<StorageValueType> get_type(const std::string& key) const;

    // =========================================================================
    // Delete and Query Operations
    // =========================================================================

    bool remove(const std::string& key);
    bool has(const std::string& key) const;
    std::vector<std::string> keys() const;
    std::vector<std::string> keys_with_prefix(const std::string& prefix) const;
    size_t size() const;
    bool empty() const;
    void clear();

    // =========================================================================
    // Persistence Operations
    // =========================================================================

    bool save();
    bool load();
    size_t compact();

    // =========================================================================
    // Synchronization Operations
    // =========================================================================

    /// Request a full snapshot from one connected peer.
    bool request_sync();
    StorageSyncStatus get_sync_status() const;
    bool is_synced() const;

    // =========================================================================
    // Event Callbacks
    // =========================================================================

    void set_change_callback(StorageChangeCallback callback);
    void set_sync_complete_callback(StorageSyncCompleteCallback callback);

    // =========================================================================
    // Statistics
    // =========================================================================

    StorageStatistics get_statistics() const;
    nlohmann::json get_statistics_json() const;

private:
    // Network message handlers (run on a reactor thread).
    void on_storage_message(const PeerId& from, ByteView payload);
    void on_peer_connected(const PeerId& peer_id);

    PeerNetwork* network_ = nullptr;
    StorageConfig config_;

    // In-memory storage
    mutable std::mutex storage_mutex_;
    std::unordered_map<std::string, StorageEntry> entries_;

    // Sync state
    mutable std::mutex sync_mutex_;
    StorageSyncStatus sync_status_;
    bool initial_sync_complete_;
    std::chrono::steady_clock::time_point last_sync_time_;

    // Statistics
    mutable std::mutex stats_mutex_;
    StorageStatistics stats_;

    // Callbacks
    StorageChangeCallback change_callback_;
    StorageSyncCompleteCallback sync_complete_callback_;

    // Background persistence thread
    std::atomic<bool> running_;
    std::thread persistence_thread_;
    std::condition_variable persistence_cv_;
    std::mutex persistence_mutex_;
    bool dirty_;  // Flag indicating unsaved changes

    // Wire opcodes (MessageType::Storage payload, byte 0)
    static constexpr uint8_t OP_ENTRY         = 1;
    static constexpr uint8_t OP_SYNC_REQUEST  = 2;
    static constexpr uint8_t OP_SYNC_RESPONSE = 3;

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
    void broadcast_entry(const StorageEntry& entry);              ///< to all peers
    void forward_entry(const StorageEntry& entry, const PeerId& except);  ///< re-flood
    void send_sync_request(const PeerId& peer_id);
    void send_sync_response(const PeerId& peer_id);

    // Apply a remote entry with LWW; fills `out_event` and returns true if applied.
    bool apply_remote_entry(const StorageEntry& entry, StorageChangeEvent* out_event);

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
