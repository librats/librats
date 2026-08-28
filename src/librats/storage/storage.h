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
 *     with `deleted=true`) and sends it to every connected peer.
 *   - On receiving an entry, a node applies it under LWW. It re-forwards the
 *     entry to its *other* peers ONLY if the entry actually won (carried new
 *     information). A duplicate loses LWW and is not forwarded, so flooding
 *     terminates naturally — no separate dedup table needed.
 *   - On peer connect, both sides ask each other for a full snapshot
 *     (anti-entropy) so a late joiner catches up. LWW makes the merge
 *     order-independent.
 *
 * Backpressure — why a snapshot is a *stream*, not a message:
 *   A database is unbounded, a peer's send queue is not. One message carrying
 *   the whole store stops being sendable at the connection's low-water mark,
 *   gets the peer dropped as a slow consumer past its high-water mark, and is
 *   not even representable past the block-size ceiling — and since both ends
 *   request a snapshot on connect, two of them cross on every single link. So
 *   a snapshot is served as a sequence of bounded SYNC_CHUNK messages walking
 *   the (ordered) key space, one chunk at a time, and the next chunk is only
 *   produced while `PeerNetwork::peer_writable()` says there is room. Every
 *   send() return value is honoured: a peer that fills up stops receiving
 *   individual entries and is instead owed a fresh snapshot, which the sync
 *   thread starts once on_peer_writable says the link has drained. Losing live
 *   updates to a congested peer is safe precisely because the store is LWW —
 *   the snapshot that follows carries the winning state either way.
 *
 *   All of that runs on this module's own sync thread. Serialising even one
 *   chunk happens off the reactor thread, so a reactor never spends time (or
 *   holds storage_mutex_) proportional to the size of the database.
 *
 * Wire format (MessageType::Storage payload, opcode in byte 0):
 *   ENTRY:         [1][StorageEntry.serialize()]
 *   SYNC_REQUEST:  [2]
 *   SYNC_CHUNK:    [3][flags:u8][count:u32][StorageEntry.serialize()] * count
 *                  flags bit0 (LAST) marks the final chunk of a snapshot; a
 *                  snapshot of an empty store is one chunk with count 0.
 *
 * The class is also usable standalone (no network attached) as a local,
 * persistent key-value store; all network operations no-op until attach().
 */

#include "librats/util/rats_export.h"
#include "librats/node/peer_network.h"
#include "librats/peer/peer.h"
#include "librats/peer/peer_id.h"
#include "librats/core/bytes.h"
#include "librats/util/json.h"

#include <string>
#include <vector>
#include <functional>
#include <map>
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
struct RATS_API StorageEntry {
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

    /// Append the serialized entry to `out`. What serialize() is built on: a
    /// batch appends entry after entry into one buffer instead of allocating a
    /// vector per entry only to copy it away again.
    void serialize_into(std::vector<uint8_t>& out) const;

    /// Serialized size in bytes, without serializing.
    size_t serialized_size() const;

    /// Deserialize one entry from `data[offset..]`, setting `bytes_read` to the
    /// bytes it consumed. Every field is bounds-checked against the entry's own
    /// declared length as well as the buffer, so a hostile length can neither
    /// read past the buffer nor reach into the entry that follows.
    static bool deserialize(const uint8_t* data, size_t size, size_t offset,
                            StorageEntry& entry, size_t& bytes_read);

    /// Vector overload of the above; the wire path uses the pointer form to
    /// parse straight out of the receive buffer without copying it first.
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
 * Storage configuration.
 *
 * The two size limits are not free parameters: both are bounded by what one
 * peer's send queue can hold. A connection drops its peer as a slow consumer
 * past its high-water mark (8 MiB by default, NodeConfig::send_queue_limit) and
 * reports "no room" at a quarter of it, so a single value — and a single
 * snapshot chunk — must stay well inside that quarter, or the very first one
 * would kill the link it travels on. Both are clamped to kMaxValueSize /
 * kMaxSyncBatchBytes on construction and in set_config().
 */
struct StorageConfig {
    /// Ceiling on max_value_size: the default connection low-water mark. One
    /// value at the ceiling makes a peer unwritable and is then waited out,
    /// rather than counting toward the high-water mark that drops it.
    static constexpr uint32_t kMaxValueSize      = 2 * 1024 * 1024;
    /// Ceiling on sync_batch_bytes, for the same reason.
    static constexpr uint32_t kMaxSyncBatchBytes = 2 * 1024 * 1024;
    /// Floor on sync_batch_bytes: below this a snapshot costs more in per-message
    /// framing and round trips than it saves in queue occupancy.
    static constexpr uint32_t kMinSyncBatchBytes = 16 * 1024;

    std::string data_directory;         // Directory for storage files
    std::string database_name;          // Database filename prefix
    bool enable_sync;                   // Enable network synchronization
    uint32_t compaction_threshold;      // Number of tombstones before compaction
    uint32_t max_value_size;            // Maximum value size in bytes (<= kMaxValueSize)
    bool persist_to_disk;               // Whether to persist data to disk
    /// Target payload size of one snapshot chunk. The walk stops at the first
    /// entry that takes the buffer past this, so a chunk is this size plus at
    /// most one entry — which is why max_value_size shares the same ceiling.
    uint32_t sync_batch_bytes;
    /// Minimum gap between two snapshots served to the same peer. Bounds what a
    /// peer can make us spend by asking, and paces the re-sync a peer is owed
    /// after it has been congested.
    uint32_t sync_min_interval_ms;

    StorageConfig()
        : data_directory("./storage"),
          database_name("rats_storage"),
          enable_sync(true),
          compaction_threshold(1000),
          max_value_size(1024 * 1024),        // 1 MiB max value size
          persist_to_disk(true),
          sync_batch_bytes(256 * 1024),       // 256 KiB per snapshot chunk
          sync_min_interval_ms(5000) {}
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
    uint64_t sync_chunks_sent;          // Snapshot chunks put on the wire
    uint64_t sync_chunks_received;      // Snapshot chunks applied from peers
    uint64_t resyncs_scheduled;         // Snapshots owed to peers that filled up
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
class RATS_API StorageManager final : public Subsystem {
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

    /// Replace the configuration. Size limits are clamped (see StorageConfig).
    /// Call it before start(): the sync thread reads its tuning once when it
    /// starts, and the store's other threads read the config without a lock.
    void set_config(const StorageConfig& config);
    const StorageConfig& get_config() const;

    // =========================================================================
    // Put Operations (Write)
    // =========================================================================

    bool put(const std::string& key, const std::string& value);
    bool put(const std::string& key, int64_t value);
    bool put(const std::string& key, double value);
    bool put(const std::string& key, const std::vector<uint8_t>& value);
    bool put_json(const std::string& key, const librats::Json& value);

    // =========================================================================
    // Get Operations (Read)
    // =========================================================================

    std::optional<std::string> get_string(const std::string& key) const;
    std::optional<int64_t> get_int(const std::string& key) const;
    std::optional<double> get_double(const std::string& key) const;
    std::optional<std::vector<uint8_t>> get_binary(const std::string& key) const;
    std::optional<librats::Json> get_json(const std::string& key) const;
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
    librats::Json get_statistics_json() const;

private:
    // Network message handlers (run on a reactor thread).
    void on_storage_message(const PeerId& from, ByteView payload);
    void on_peer_connected(const PeerId& peer_id);
    void on_peer_disconnected(const PeerId& peer_id);
    void on_peer_writable(const PeerId& peer_id);

    PeerNetwork* network_ = nullptr;
    StorageConfig config_;

    // In-memory storage.
    //
    // Ordered, not hashed, and that is load-bearing: a snapshot is streamed one
    // bounded chunk at a time, and between chunks the only thing carried over is
    // the last key sent. An ordered map turns that key back into a position with
    // upper_bound(), so a stream costs nothing to keep alive and cannot be
    // derailed by concurrent writes — an unordered_map would need either a
    // materialised key list per peer or iterators that a rehash invalidates.
    // It also makes keys_with_prefix() a range scan instead of a full walk.
    mutable std::mutex storage_mutex_;
    std::map<std::string, StorageEntry> entries_;

    // Sync state.
    //
    // Lock order, exactly one rule: storage_mutex_ and sync_mutex_ are never held
    // at the same time, and neither is ever held across a call into PeerNetwork.
    mutable std::mutex sync_mutex_;
    StorageSyncStatus sync_status_;
    bool initial_sync_complete_;
    std::chrono::steady_clock::time_point last_sync_time_;

    /// What we owe one peer. A snapshot is served as a walk over the key space
    /// whose whole resumable state is `cursor` — the last key already sent.
    struct PeerSync {
        bool                                  streaming = false;  ///< a snapshot is in flight
        bool                                  started   = false;  ///< cursor is meaningful
        std::string                           cursor;             ///< last key sent
        bool                                  owed      = false;  ///< a (re)snapshot is due
        std::chrono::steady_clock::time_point last_start{};       ///< for sync_min_interval_ms
    };
    std::unordered_map<PeerId, PeerSync, PeerId::Hash> peers_;    ///< guarded by sync_mutex_
    /// Bumped, under sync_mutex_, whenever something the sync thread would act on
    /// changes — a snapshot scheduled, a link drained, a peer gone. The thread
    /// reads it before it scans and compares it before it waits, because between
    /// those two points it is outside the lock (serializing and sending), and a
    /// notify that arrives there would otherwise be one nobody is waiting for.
    uint64_t sync_epoch_ = 0;

    // The sync thread: serializes and paces every snapshot chunk, so no reactor
    // thread ever does work proportional to the size of the database.
    std::atomic<bool>       sync_running_{false};
    std::thread             sync_thread_;
    std::condition_variable sync_cv_;   ///< paired with sync_mutex_
    // Sync tuning, copied out of the config when the thread starts and read-only
    // afterwards, so the thread never races a set_config() on another thread.
    size_t                    batch_bytes_{0};
    std::chrono::milliseconds sync_interval_{0};

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
    static constexpr uint8_t OP_ENTRY        = 1;
    static constexpr uint8_t OP_SYNC_REQUEST = 2;
    static constexpr uint8_t OP_SYNC_CHUNK   = 3;

    // SYNC_CHUNK flags (byte 1)
    static constexpr uint8_t FLAG_LAST = 0x01;   ///< final chunk of this snapshot

    /// Refuse an inbound Storage message larger than this before parsing it. Our
    /// own sender never comes near it (one chunk is sync_batch_bytes plus at most
    /// one value, both capped at 2 MiB), while the block layer would happily hand
    /// us 64 MiB from a peer that means us harm.
    static constexpr size_t kMaxInboundMessage = 8 * 1024 * 1024;

    // Private methods
    void initialize();
    void shutdown();
    void persistence_thread_loop();
    void start_sync_thread();
    void stop_sync_thread();
    void sync_thread_loop();
    /// What one turn of a peer's snapshot stream left behind.
    enum class ChunkResult {
        Continue,   ///< a chunk went out and the link has room for the next
        Blocked,    ///< a chunk went out and filled the link; retry when it drains
        Finished    ///< the snapshot is complete (or the peer is gone)
    };
    /// Serialize and send the next chunk of `peer`'s snapshot.
    ChunkResult stream_snapshot_chunk(const PeerId& peer);
    /// Note that `peer` is due a snapshot; the sync thread starts it once the
    /// link has room and the per-peer interval has elapsed.
    void schedule_snapshot(const PeerId& peer, bool requested_by_peer);

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

    // Network operations. Every one of them honours send()'s return value: a peer
    // that answers "no room" is owed a snapshot instead of further entries.
    /// Send one entry to every connected peer except `except` (null for none).
    void replicate_entry(const StorageEntry& entry, const PeerId* except);
    void broadcast_entry(const StorageEntry& entry) { replicate_entry(entry, nullptr); }
    void forward_entry(const StorageEntry& entry, const PeerId& except) {
        replicate_entry(entry, &except);
    }
    void send_sync_request(const PeerId& peer_id);

    // Apply a remote entry with LWW; fills `out_event` and returns true if applied.
    bool apply_remote_entry(const StorageEntry& entry, StorageChangeEvent* out_event);
    /// Parse and apply the entries in one SYNC_CHUNK body. @return how many won.
    uint32_t apply_chunk(const PeerId& from, const uint8_t* data, size_t size, uint32_t count);

    // File path helpers
    std::string get_data_file_path() const;
    std::string get_index_file_path() const;

    // Disk I/O
    bool write_data_file();
    bool read_data_file();

    // Utility
    /// Clamp the size limits to what one connection's send queue can carry.
    static void sanitize_config(StorageConfig& config);
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
