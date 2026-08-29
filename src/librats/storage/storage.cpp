#include "librats/storage/storage.h"
#include "librats/node/node_context.h"
#include "librats/crypto/crc32.h"
#include "librats/util/fs.h"
#include "librats/util/logger.h"
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>

// Define logging module for this file
#define LOG_STORAGE_INFO(message) LOG_INFO("storage", message)
#define LOG_STORAGE_ERROR(message) LOG_ERROR("storage", message)
#define LOG_STORAGE_WARN(message) LOG_WARN("storage", message)
#define LOG_STORAGE_DEBUG(message) LOG_DEBUG("storage", message)

namespace librats {

namespace {

void put_u32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 3; i >= 0; --i) b.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

void write_u32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>((v >> ((3 - i) * 8)) & 0xFF);
}

uint32_t read_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}

} // namespace

//=============================================================================
// StorageEntry Implementation
//=============================================================================

void StorageEntry::calculate_checksum() {
    // Calculate CRC32 over key + type + data + timestamp + peer_id
    std::vector<uint8_t> buffer;

    // Add key
    buffer.insert(buffer.end(), key.begin(), key.end());

    // Add type
    buffer.push_back(static_cast<uint8_t>(type));

    // Add data
    buffer.insert(buffer.end(), data.begin(), data.end());

    // Add timestamp (8 bytes, big endian)
    for (int i = 7; i >= 0; i--) {
        buffer.push_back(static_cast<uint8_t>((timestamp_ms >> (i * 8)) & 0xFF));
    }

    // Add peer_id
    buffer.insert(buffer.end(), origin_peer_id.begin(), origin_peer_id.end());

    // Add deleted flag
    buffer.push_back(deleted ? 1 : 0);

    checksum = storage_calculate_crc32(buffer.data(), buffer.size());
}

bool StorageEntry::verify_checksum() const {
    StorageEntry temp = *this;
    temp.calculate_checksum();
    return temp.checksum == checksum;
}

size_t StorageEntry::serialized_size() const {
    return 4 + 4 + key.size() + 1 + 1 + 8 + 4 + origin_peer_id.size() + 4 + data.size() + 4;
}

void StorageEntry::serialize_into(std::vector<uint8_t>& buffer) const {
    // Format:
    // [4 bytes] total_length (excluding this field)
    // [4 bytes] key_length
    // [key_length bytes] key
    // [1 byte] type
    // [1 byte] deleted flag
    // [8 bytes] timestamp_ms (big endian)
    // [4 bytes] peer_id_length
    // [peer_id_length bytes] origin_peer_id
    // [4 bytes] data_length
    // [data_length bytes] data
    // [4 bytes] checksum

    const uint32_t key_len     = static_cast<uint32_t>(key.size());
    const uint32_t peer_id_len = static_cast<uint32_t>(origin_peer_id.size());
    const uint32_t data_len    = static_cast<uint32_t>(data.size());
    const uint32_t total_len   = 4 + key_len + 1 + 1 + 8 + 4 + peer_id_len + 4 + data_len + 4;

    // Deliberately no reserve() here. Appending entry after entry into one
    // buffer is the whole point of this overload, and a reserve() of exactly
    // what the next entry needs re-allocates on every single call — turning the
    // batch into O(n^2) copying. The vector's own geometric growth is what makes
    // the append amortised; callers that know the total up front (serialize(),
    // the snapshot chunk) reserve once, outside the loop.
    put_u32(buffer, total_len);
    put_u32(buffer, key_len);
    buffer.insert(buffer.end(), key.begin(), key.end());
    buffer.push_back(static_cast<uint8_t>(type));
    buffer.push_back(deleted ? 1 : 0);
    for (int i = 7; i >= 0; i--) {
        buffer.push_back(static_cast<uint8_t>((timestamp_ms >> (i * 8)) & 0xFF));
    }
    put_u32(buffer, peer_id_len);
    buffer.insert(buffer.end(), origin_peer_id.begin(), origin_peer_id.end());
    put_u32(buffer, data_len);
    buffer.insert(buffer.end(), data.begin(), data.end());
    put_u32(buffer, checksum);
}

std::vector<uint8_t> StorageEntry::serialize() const {
    std::vector<uint8_t> buffer;
    buffer.reserve(serialized_size());
    serialize_into(buffer);
    return buffer;
}

bool StorageEntry::deserialize(const uint8_t* buffer, size_t size, size_t offset,
                               StorageEntry& entry, size_t& bytes_read) {
    bytes_read = 0;

    if (offset > size || size - offset < 4) return false;

    // The entry declares its own length; every field below is read against that
    // end rather than against the end of the buffer, so an entry can neither
    // overrun the buffer nor reach into the entry that follows it in a batch.
    const uint32_t total_len = read_u32(buffer + offset);
    if (size - offset - 4 < total_len) return false;

    size_t       pos = offset + 4;
    const size_t end = pos + total_len;

    // Reads the next `n` bytes if the entry still declares that many.
    const auto take = [&](size_t n) -> const uint8_t* {
        if (end - pos < n) return nullptr;
        const uint8_t* p = buffer + pos;
        pos += n;
        return p;
    };

    const uint8_t* p = take(4);
    if (!p) return false;
    const uint32_t key_len = read_u32(p);

    p = take(key_len);
    if (!p) return false;
    entry.key.assign(reinterpret_cast<const char*>(p), key_len);

    p = take(2);   // type + deleted flag
    if (!p) return false;
    entry.type    = static_cast<StorageValueType>(p[0]);
    entry.deleted = p[1] != 0;

    p = take(8);
    if (!p) return false;
    entry.timestamp_ms = 0;
    for (int i = 0; i < 8; i++) entry.timestamp_ms = (entry.timestamp_ms << 8) | p[i];

    p = take(4);
    if (!p) return false;
    const uint32_t peer_id_len = read_u32(p);

    p = take(peer_id_len);
    if (!p) return false;
    entry.origin_peer_id.assign(reinterpret_cast<const char*>(p), peer_id_len);

    p = take(4);
    if (!p) return false;
    const uint32_t data_len = read_u32(p);

    p = take(data_len);
    if (!p) return false;
    entry.data.assign(p, p + data_len);

    p = take(4);
    if (!p) return false;
    entry.checksum = read_u32(p);

    // Trailing bytes inside the declared length are skipped, not rejected: that
    // is what lets a field be appended to the format without a version bump.
    bytes_read = end - offset;
    return true;
}

bool StorageEntry::deserialize(const std::vector<uint8_t>& buffer, size_t offset,
                               StorageEntry& entry, size_t& bytes_read) {
    return deserialize(buffer.data(), buffer.size(), offset, entry, bytes_read);
}

bool StorageEntry::wins_over(const StorageEntry& other) const {
    // Last-Write-Wins: compare timestamps first
    if (timestamp_ms != other.timestamp_ms) {
        return timestamp_ms > other.timestamp_ms;
    }

    // Tie-breaker: lexicographic comparison of peer IDs
    return origin_peer_id > other.origin_peer_id;
}

//=============================================================================
// Helper Functions
//=============================================================================

std::string storage_value_type_to_string(StorageValueType type) {
    switch (type) {
        case StorageValueType::BINARY: return "binary";
        case StorageValueType::STRING: return "string";
        case StorageValueType::INT64: return "int64";
        case StorageValueType::DOUBLE: return "double";
        case StorageValueType::JSON: return "json";
        default: return "unknown";
    }
}

StorageValueType string_to_storage_value_type(const std::string& str) {
    if (str == "binary") return StorageValueType::BINARY;
    if (str == "string") return StorageValueType::STRING;
    if (str == "int64") return StorageValueType::INT64;
    if (str == "double") return StorageValueType::DOUBLE;
    if (str == "json") return StorageValueType::JSON;
    return StorageValueType::BINARY;
}

//=============================================================================
// StorageManager Implementation
//=============================================================================

void StorageManager::sanitize_config(StorageConfig& config) {
    // A value or a chunk bigger than what one send queue reports room for would
    // make the very first one it travels on unwritable — and two of them would
    // trip the high-water mark and drop the peer. Clamp rather than reject: the
    // limits are a safety belt, not something a caller tunes for correctness.
    config.max_value_size =
        (std::min)(config.max_value_size, StorageConfig::kMaxValueSize);
    config.sync_batch_bytes =
        (std::min)(config.sync_batch_bytes, StorageConfig::kMaxSyncBatchBytes);
    config.sync_batch_bytes =
        (std::max)(config.sync_batch_bytes, StorageConfig::kMinSyncBatchBytes);
}

StorageManager::StorageManager(const StorageConfig& config)
    : config_(config),
      sync_status_(StorageSyncStatus::NOT_STARTED),
      initial_sync_complete_(false),
      running_(true),
      dirty_(false) {

    sanitize_config(config_);

    // Initialize statistics
    stats_ = StorageStatistics();
    stats_.sync_status = StorageSyncStatus::NOT_STARTED;

    initialize();
}

StorageManager::~StorageManager() {
    shutdown();
}

void StorageManager::initialize() {
    // Ensure data directory exists and load any existing data from disk.
    if (config_.persist_to_disk) {
        create_directories(config_.data_directory.c_str());
        load();
        persistence_thread_ = std::thread(&StorageManager::persistence_thread_loop, this);
    }

    LOG_STORAGE_INFO("StorageManager initialized with data directory: " << config_.data_directory);
}

void StorageManager::shutdown() {
    // Idempotent: safe to call from both stop() and the destructor.
    if (!running_.exchange(false)) return;

    LOG_STORAGE_INFO("StorageManager shutting down...");

    stop_sync_thread();

    // Wake up persistence thread
    {
        std::lock_guard<std::mutex> lock(persistence_mutex_);
        persistence_cv_.notify_all();
    }

    // Join persistence thread
    if (persistence_thread_.joinable()) {
        persistence_thread_.join();
    }

    // Final save
    bool needs_save;
    {
        std::lock_guard<std::mutex> lock(persistence_mutex_);
        needs_save = dirty_;
    }
    if (config_.persist_to_disk && needs_save) {
        save();
    }

    LOG_STORAGE_INFO("StorageManager shut down");
}

void StorageManager::persistence_thread_loop() {
    const auto save_interval = std::chrono::seconds(5);

    while (running_.load()) {
        std::unique_lock<std::mutex> lock(persistence_mutex_);
        persistence_cv_.wait_for(lock, save_interval, [this] {
            return !running_.load() || dirty_;
        });

        if (!running_.load()) break;

        if (dirty_) {
            lock.unlock();
            save();
        }
    }
}

//=============================================================================
// Subsystem
//=============================================================================

void StorageManager::attach(NodeContext& ctx) {
    network_ = &ctx.network;

    if (!config_.enable_sync) return;

    network_->on(MessageType::Storage,
        [this](const Peer& peer, ByteView payload) { on_storage_message(peer.id(), payload); });
    network_->on_peer_connected(
        [this](const Peer& peer) { on_peer_connected(peer.id()); });
    // Without this the per-peer sync state of every peer that ever connected
    // would be kept forever, snapshot cursors and all.
    network_->on_peer_disconnected(
        [this](const PeerId& id, CloseReason) { on_peer_disconnected(id); });
    // The other half of honouring send()'s return value: a peer that filled up is
    // owed a snapshot, and this is what says the link has room to serve it.
    network_->on_peer_writable(
        [this](const Peer& peer) { on_peer_writable(peer.id()); });
}

void StorageManager::start() {
    // The persistence thread is already running (started in the constructor).
    // The sync thread only exists once there is a network to pace against.
    if (config_.enable_sync && network_) start_sync_thread();
}

void StorageManager::stop() {
    shutdown();
}

void StorageManager::start_sync_thread() {
    if (sync_running_.exchange(true)) return;
    batch_bytes_   = config_.sync_batch_bytes;
    sync_interval_ = std::chrono::milliseconds(config_.sync_min_interval_ms);
    sync_thread_ = std::thread(&StorageManager::sync_thread_loop, this);
}

void StorageManager::stop_sync_thread() {
    if (!sync_running_.exchange(false)) return;
    // Taken and dropped for the ordering alone: it puts the flag store above
    // before any wait the thread is about to enter, so the notify below cannot
    // slip past a thread that had already decided to sleep.
    { std::lock_guard<std::mutex> lock(sync_mutex_); }
    sync_cv_.notify_all();
    if (sync_thread_.joinable()) sync_thread_.join();
}

void StorageManager::set_config(const StorageConfig& config) {
    std::lock_guard<std::mutex> lock(storage_mutex_);
    config_ = config;
    sanitize_config(config_);

    if (config_.persist_to_disk) {
        create_directories(config_.data_directory.c_str());
    }
}

const StorageConfig& StorageManager::get_config() const {
    return config_;
}

//=============================================================================
// Put Operations
//=============================================================================

bool StorageManager::put(const std::string& key, const std::string& value) {
    return put_internal(key, StorageValueType::STRING, serialize_value(value));
}

bool StorageManager::put(const std::string& key, int64_t value) {
    return put_internal(key, StorageValueType::INT64, serialize_value(value));
}

bool StorageManager::put(const std::string& key, double value) {
    return put_internal(key, StorageValueType::DOUBLE, serialize_value(value));
}

bool StorageManager::put(const std::string& key, const std::vector<uint8_t>& value) {
    return put_internal(key, StorageValueType::BINARY, value);
}

bool StorageManager::put_json(const std::string& key, const librats::Json& value) {
    std::string json_str = value.dump();
    return put_internal(key, StorageValueType::JSON, serialize_value(json_str));
}

bool StorageManager::put_internal(const std::string& key, StorageValueType type,
                                  const std::vector<uint8_t>& data,
                                  uint64_t timestamp_ms,
                                  const std::string& origin_peer_id,
                                  bool broadcast) {
    if (key.empty()) {
        LOG_STORAGE_ERROR("Cannot put with empty key");
        return false;
    }

    if (data.size() > config_.max_value_size) {
        LOG_STORAGE_ERROR("Value size " << data.size() << " exceeds maximum " << config_.max_value_size);
        return false;
    }

    // Use current time if not provided
    if (timestamp_ms == 0) {
        timestamp_ms = get_current_timestamp_ms();
    }

    // Use our peer ID if not provided
    std::string peer_id = origin_peer_id.empty() ? get_our_peer_id() : origin_peer_id;

    StorageEntry new_entry(key, type, data, timestamp_ms, peer_id);

    StorageChangeEvent event;
    event.operation = StorageOperation::OP_PUT;
    event.key = key;
    event.type = type;
    event.new_data = data;
    event.timestamp_ms = timestamp_ms;
    event.origin_peer_id = peer_id;
    event.is_remote = !origin_peer_id.empty() && origin_peer_id != get_our_peer_id();

    {
        std::lock_guard<std::mutex> lock(storage_mutex_);

        auto it = entries_.find(key);
        if (it != entries_.end()) {
            // Check LWW - only update if new entry wins
            if (!new_entry.wins_over(it->second)) {
                LOG_STORAGE_DEBUG("Rejected put for key '" << key << "' - existing entry is newer");
                return false;
            }

            event.old_data = it->second.data;
            it->second = new_entry;
        } else {
            entries_[key] = new_entry;
        }
    }

    mark_dirty();

    // Broadcast to peers if this is a local change
    if (broadcast && config_.enable_sync) {
        broadcast_entry(new_entry);
    }

    // Notify change callback
    notify_change(event);

    LOG_STORAGE_DEBUG("Put key '" << key << "' with type " << storage_value_type_to_string(type));
    return true;
}

//=============================================================================
// Get Operations
//=============================================================================

std::optional<std::string> StorageManager::get_string(const std::string& key) const {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.deleted) {
        return std::nullopt;
    }

    if (it->second.type != StorageValueType::STRING) {
        return std::nullopt;
    }

    return deserialize_string(it->second.data);
}

std::optional<int64_t> StorageManager::get_int(const std::string& key) const {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.deleted) {
        return std::nullopt;
    }

    if (it->second.type != StorageValueType::INT64) {
        return std::nullopt;
    }

    return deserialize_int64(it->second.data);
}

std::optional<double> StorageManager::get_double(const std::string& key) const {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.deleted) {
        return std::nullopt;
    }

    if (it->second.type != StorageValueType::DOUBLE) {
        return std::nullopt;
    }

    return deserialize_double(it->second.data);
}

std::optional<std::vector<uint8_t>> StorageManager::get_binary(const std::string& key) const {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.deleted) {
        return std::nullopt;
    }

    if (it->second.type != StorageValueType::BINARY) {
        return std::nullopt;
    }

    return it->second.data;
}

std::optional<librats::Json> StorageManager::get_json(const std::string& key) const {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.deleted) {
        return std::nullopt;
    }

    if (it->second.type != StorageValueType::JSON) {
        return std::nullopt;
    }

    try {
        std::string json_str = deserialize_string(it->second.data);
        return librats::Json::parse(json_str);
    } catch (const std::exception& e) {
        LOG_STORAGE_ERROR("Failed to parse JSON for key '" << key << "': " << e.what());
        return std::nullopt;
    }
}

std::optional<StorageValueType> StorageManager::get_type(const std::string& key) const {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.deleted) {
        return std::nullopt;
    }

    return it->second.type;
}

//=============================================================================
// Delete and Query Operations
//=============================================================================

bool StorageManager::remove(const std::string& key) {
    uint64_t timestamp_ms = get_current_timestamp_ms();
    std::string our_peer_id = get_our_peer_id();

    StorageChangeEvent event;
    event.operation = StorageOperation::OP_DELETE;
    event.key = key;
    event.timestamp_ms = timestamp_ms;
    event.origin_peer_id = our_peer_id;
    event.is_remote = false;

    StorageEntry tombstone;
    {
        std::lock_guard<std::mutex> lock(storage_mutex_);

        auto it = entries_.find(key);
        if (it == entries_.end()) {
            return false;
        }

        if (it->second.deleted) {
            return false;  // Already deleted
        }

        event.old_data = it->second.data;

        // Mark as deleted (tombstone)
        it->second.deleted = true;
        it->second.timestamp_ms = timestamp_ms;
        it->second.origin_peer_id = our_peer_id;
        it->second.data.clear();
        it->second.calculate_checksum();
        tombstone = it->second;
    }

    mark_dirty();

    // Broadcast the tombstone to peers
    if (config_.enable_sync) {
        broadcast_entry(tombstone);
    }

    // Notify change callback
    notify_change(event);

    LOG_STORAGE_DEBUG("Deleted key '" << key << "'");
    return true;
}

bool StorageManager::has(const std::string& key) const {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    auto it = entries_.find(key);
    return it != entries_.end() && !it->second.deleted;
}

std::vector<std::string> StorageManager::keys() const {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    std::vector<std::string> result;
    result.reserve(entries_.size());

    for (const auto& pair : entries_) {
        if (!pair.second.deleted) {
            result.push_back(pair.first);
        }
    }

    return result;
}

std::vector<std::string> StorageManager::keys_with_prefix(const std::string& prefix) const {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    // A range scan, not a full walk: the map is ordered, so the matching keys are
    // exactly the contiguous run starting at lower_bound(prefix).
    std::vector<std::string> result;
    for (auto it = entries_.lower_bound(prefix); it != entries_.end(); ++it) {
        if (it->first.compare(0, prefix.size(), prefix) != 0) break;
        if (!it->second.deleted) result.push_back(it->first);
    }

    return result;
}

size_t StorageManager::size() const {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    size_t count = 0;
    for (const auto& pair : entries_) {
        if (!pair.second.deleted) {
            count++;
        }
    }

    return count;
}

bool StorageManager::empty() const {
    return size() == 0;
}

void StorageManager::clear() {
    std::vector<std::string> keys_to_delete;

    {
        std::lock_guard<std::mutex> lock(storage_mutex_);

        for (auto& pair : entries_) {
            if (!pair.second.deleted) {
                keys_to_delete.push_back(pair.first);
            }
        }
    }

    for (const auto& key : keys_to_delete) {
        remove(key);
    }

    LOG_STORAGE_INFO("Cleared all entries");
}

//=============================================================================
// Persistence Operations
//=============================================================================

bool StorageManager::save() {
    if (!config_.persist_to_disk) {
        return true;
    }

    std::lock_guard<std::mutex> lock(storage_mutex_);

    bool result = write_data_file();

    if (result) {
        // dirty_ belongs to persistence_mutex_, not storage_mutex_ — the persistence
        // thread reads it under that lock. Same order as load() (storage → persistence).
        {
            std::lock_guard<std::mutex> dirty_lock(persistence_mutex_);
            dirty_ = false;
        }
        LOG_STORAGE_DEBUG("Saved " << entries_.size() << " entries to disk");
    }

    return result;
}

bool StorageManager::load() {
    if (!config_.persist_to_disk) {
        return true;
    }

    std::lock_guard<std::mutex> lock(storage_mutex_);

    std::string data_path = get_data_file_path();
    if (!file_exists(data_path.c_str())) {
        LOG_STORAGE_DEBUG("No existing data file found at " << data_path);
        return true;  // Not an error, just no data yet
    }

    bool result = read_data_file();

    if (result) {
        LOG_STORAGE_INFO("Loaded " << entries_.size() << " entries from disk");
    }

    return result;
}

size_t StorageManager::compact() {
    std::lock_guard<std::mutex> lock(storage_mutex_);

    size_t removed = 0;

    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->second.deleted) {
            it = entries_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    if (removed > 0) {
        mark_dirty();
        LOG_STORAGE_INFO("Compacted storage, removed " << removed << " tombstones");
    }

    return removed;
}

//=============================================================================
// Synchronization Operations
//=============================================================================

bool StorageManager::request_sync() {
    if (!config_.enable_sync || !network_) {
        return false;
    }

    // Get a connected peer to sync from
    auto peers = network_->connected_peers();
    if (peers.empty()) {
        LOG_STORAGE_WARN("No peers available for sync");
        return false;
    }

    const PeerId& peer_id = peers[0];

    {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        sync_status_ = StorageSyncStatus::IN_PROGRESS;
    }

    send_sync_request(peer_id);

    LOG_STORAGE_INFO("Requested sync from peer " << peer_id.short_hex());
    return true;
}

StorageSyncStatus StorageManager::get_sync_status() const {
    std::lock_guard<std::mutex> lock(sync_mutex_);
    return sync_status_;
}

bool StorageManager::is_synced() const {
    std::lock_guard<std::mutex> lock(sync_mutex_);
    return initial_sync_complete_;
}

//=============================================================================
// Event Callbacks
//=============================================================================

void StorageManager::set_change_callback(StorageChangeCallback callback) {
    change_callback_ = callback;
}

void StorageManager::set_sync_complete_callback(StorageSyncCompleteCallback callback) {
    sync_complete_callback_ = callback;
}

//=============================================================================
// Statistics
//=============================================================================

StorageStatistics StorageManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);

    StorageStatistics result = stats_;

    // Calculate current counts
    {
        std::lock_guard<std::mutex> storage_lock(storage_mutex_);

        result.total_entries = 0;
        result.deleted_entries = 0;
        result.total_data_bytes = 0;

        for (const auto& pair : entries_) {
            if (pair.second.deleted) {
                result.deleted_entries++;
            } else {
                result.total_entries++;
                result.total_data_bytes += pair.second.data.size();
            }
        }
    }

    {
        std::lock_guard<std::mutex> sync_lock(sync_mutex_);
        result.sync_status = sync_status_;
        result.last_sync_time = last_sync_time_;
    }

    return result;
}

librats::Json StorageManager::get_statistics_json() const {
    StorageStatistics stats = get_statistics();

    librats::Json result;
    result["total_entries"] = stats.total_entries;
    result["deleted_entries"] = stats.deleted_entries;
    result["total_data_bytes"] = stats.total_data_bytes;
    result["disk_usage_bytes"] = stats.disk_usage_bytes;
    result["entries_synced"] = stats.entries_synced;
    result["entries_sent"] = stats.entries_sent;
    result["sync_requests_received"] = stats.sync_requests_received;
    result["sync_requests_sent"] = stats.sync_requests_sent;
    result["sync_chunks_sent"] = stats.sync_chunks_sent;
    result["sync_chunks_received"] = stats.sync_chunks_received;
    result["resyncs_scheduled"] = stats.resyncs_scheduled;

    switch (stats.sync_status) {
        case StorageSyncStatus::NOT_STARTED: result["sync_status"] = "not_started"; break;
        case StorageSyncStatus::IN_PROGRESS: result["sync_status"] = "in_progress"; break;
        case StorageSyncStatus::COMPLETED: result["sync_status"] = "completed"; break;
        case StorageSyncStatus::FAILED: result["sync_status"] = "failed"; break;
    }

    return result;
}

//=============================================================================
// Network Message Handlers (run on a reactor thread)
//=============================================================================

void StorageManager::on_storage_message(const PeerId& from, ByteView payload) {
    if (payload.empty()) return;
    if (payload.size() > kMaxInboundMessage) {
        LOG_STORAGE_WARN("Oversized storage message (" << payload.size() << " B) from "
                         << from.short_hex() << "; ignored");
        return;
    }

    const uint8_t* p = payload.data();
    const size_t   n = payload.size();

    switch (p[0]) {
    case OP_ENTRY: {
        // Parsed straight out of the receive buffer — no copy of the payload.
        StorageEntry entry;
        size_t bytes_read = 0;
        if (!StorageEntry::deserialize(p, n, 1, entry, bytes_read)) {
            LOG_STORAGE_WARN("Malformed storage entry from " << from.short_hex());
            return;
        }
        if (!entry.verify_checksum()) {
            LOG_STORAGE_WARN("Checksum mismatch on entry '" << entry.key << "' from " << from.short_hex());
            return;
        }

        StorageChangeEvent event;
        if (apply_remote_entry(entry, &event)) {
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.entries_synced++;
            }
            mark_dirty();
            notify_change(event);
            // Re-flood to other peers; LWW makes a duplicate lose, so this stops.
            forward_entry(entry, from);
        }
        break;
    }

    case OP_SYNC_REQUEST: {
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.sync_requests_received++;
        }
        // Queue the work; the sync thread serializes and paces it. Serializing
        // the database here would be doing it on a reactor thread, under
        // storage_mutex_, for as long as the database is big.
        schedule_snapshot(from, /*requested_by_peer=*/true);
        break;
    }

    case OP_SYNC_CHUNK: {
        // [3][flags:u8][count:u32][entry]*
        if (n < 6) return;
        const bool     last  = (p[1] & FLAG_LAST) != 0;
        const uint32_t count = read_u32(p + 2);

        const uint32_t applied = apply_chunk(from, p + 6, n - 6, count);
        if (applied > 0) mark_dirty();
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.entries_synced += applied;
            stats_.sync_chunks_received++;
        }

        LOG_STORAGE_DEBUG("Snapshot chunk from " << from.short_hex() << ": " << count
                          << " entries, " << applied << " applied" << (last ? " (last)" : ""));
        if (!last) break;

        {
            std::lock_guard<std::mutex> lock(sync_mutex_);
            sync_status_           = StorageSyncStatus::COMPLETED;
            initial_sync_complete_ = true;
            last_sync_time_        = std::chrono::steady_clock::now();
        }
        LOG_STORAGE_INFO("Snapshot from " << from.short_hex() << " complete");
        if (sync_complete_callback_) sync_complete_callback_(true, "");
        break;
    }

    default:
        LOG_STORAGE_WARN("Unknown storage opcode " << static_cast<int>(p[0])
                         << " from " << from.short_hex());
        break;
    }
}

uint32_t StorageManager::apply_chunk(const PeerId& from, const uint8_t* data, size_t size,
                                     uint32_t count) {
    uint32_t applied = 0;
    size_t   offset  = 0;

    for (uint32_t i = 0; i < count && offset < size; i++) {
        StorageEntry entry;
        size_t bytes_read = 0;
        if (!StorageEntry::deserialize(data, size, offset, entry, bytes_read)) {
            LOG_STORAGE_WARN("Truncated snapshot chunk from " << from.short_hex()
                             << " at entry " << i);
            break;
        }
        offset += bytes_read;
        if (!entry.verify_checksum()) continue;

        StorageChangeEvent event;
        if (apply_remote_entry(entry, &event)) {
            applied++;
            notify_change(event);
        }
    }
    return applied;
}

void StorageManager::on_peer_connected(const PeerId& peer_id) {
    if (!config_.enable_sync) return;

    // Anti-entropy: ask the new peer for a full snapshot. Both ends do this on
    // connect, so the two databases converge via LWW. Both snapshots are streams
    // paced against their own link, so the pair crossing costs bandwidth and
    // nothing else.
    {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        if (sync_status_ == StorageSyncStatus::NOT_STARTED)
            sync_status_ = StorageSyncStatus::IN_PROGRESS;
        peers_.emplace(peer_id, PeerSync{});
    }
    send_sync_request(peer_id);
}

void StorageManager::on_peer_disconnected(const PeerId& peer_id) {
    {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        if (peers_.erase(peer_id) == 0) return;   // drops any snapshot in flight to it
        ++sync_epoch_;
    }
    sync_cv_.notify_all();
}

void StorageManager::on_peer_writable(const PeerId& peer_id) {
    // The link drained. Either a snapshot was waiting for room, or one is owed
    // because live entries were dropped while it was full — the sync thread
    // decides which; all this has to do is wake it.
    {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        if (peers_.find(peer_id) == peers_.end()) return;
        ++sync_epoch_;
    }
    sync_cv_.notify_all();
}

//=============================================================================
// Private Methods - Serialization
//=============================================================================

std::vector<uint8_t> StorageManager::serialize_value(int64_t value) const {
    std::vector<uint8_t> data(8);
    for (int i = 7; i >= 0; i--) {
        data[7 - i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
    return data;
}

std::vector<uint8_t> StorageManager::serialize_value(double value) const {
    std::vector<uint8_t> data(8);
    uint64_t bits;
    std::memcpy(&bits, &value, sizeof(double));
    for (int i = 7; i >= 0; i--) {
        data[7 - i] = static_cast<uint8_t>((bits >> (i * 8)) & 0xFF);
    }
    return data;
}

std::vector<uint8_t> StorageManager::serialize_value(const std::string& value) const {
    return std::vector<uint8_t>(value.begin(), value.end());
}

int64_t StorageManager::deserialize_int64(const std::vector<uint8_t>& data) const {
    if (data.size() < 8) return 0;

    int64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | data[i];
    }
    return value;
}

double StorageManager::deserialize_double(const std::vector<uint8_t>& data) const {
    if (data.size() < 8) return 0.0;

    uint64_t bits = 0;
    for (int i = 0; i < 8; i++) {
        bits = (bits << 8) | data[i];
    }

    double value;
    std::memcpy(&value, &bits, sizeof(double));
    return value;
}

std::string StorageManager::deserialize_string(const std::vector<uint8_t>& data) const {
    return std::string(data.begin(), data.end());
}

//=============================================================================
// Private Methods - Network Operations
//=============================================================================

void StorageManager::replicate_entry(const StorageEntry& entry, const PeerId* except) {
    if (!network_ || !config_.enable_sync) return;

    std::vector<uint8_t> msg;
    msg.reserve(1 + entry.serialized_size());
    msg.push_back(OP_ENTRY);
    entry.serialize_into(msg);
    const ByteView view(msg);

    uint64_t             sent = 0;
    std::vector<PeerId>  congested;

    for (const PeerId& peer : network_->connected_peers()) {
        if (except && peer == *except) continue;

        // A peer already owed a snapshot is skipped outright: it is behind by
        // more than this entry, and the snapshot that is coming carries the
        // winning state for this key too.
        {
            std::lock_guard<std::mutex> lock(sync_mutex_);
            const auto it = peers_.find(peer);
            if (it != peers_.end() && it->second.owed) continue;
        }

        // The message is queued either way; a false says the queue is past the
        // mark and that continuing is what gets the peer dropped. So we stop
        // sending this peer individual entries and owe it a snapshot instead —
        // safe because the store is LWW and the snapshot is the whole state.
        if (network_->send(peer, MessageType::Storage, view)) {
            ++sent;
        } else {
            congested.push_back(peer);
        }
    }

    for (const PeerId& peer : congested) schedule_snapshot(peer, /*requested_by_peer=*/false);

    if (sent > 0) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.entries_sent += sent;
    }
}

void StorageManager::send_sync_request(const PeerId& peer_id) {
    if (!network_) return;

    const std::vector<uint8_t> msg{OP_SYNC_REQUEST};
    // One byte cannot fill a queue on its own, so a false here means the queue
    // was already full — the peer will ask us for a snapshot on its own side
    // anyway, and this request is retried the next time it connects.
    if (!network_->send(peer_id, MessageType::Storage, ByteView(msg))) {
        LOG_STORAGE_DEBUG("Sync request to " << peer_id.short_hex() << " queued behind a full link");
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.sync_requests_sent++;
    }

    LOG_STORAGE_DEBUG("Sent sync request to peer " << peer_id.short_hex());
}

void StorageManager::schedule_snapshot(const PeerId& peer, bool requested_by_peer) {
    {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        PeerSync& st = peers_[peer];
        if (st.streaming || st.owed) return;   // one snapshot at a time, per peer
        st.owed = true;
        ++sync_epoch_;
    }
    if (!requested_by_peer) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.resyncs_scheduled++;
    }
    sync_cv_.notify_all();
}

//=============================================================================
// The sync thread — every snapshot chunk is serialized and paced here, never
// on a reactor thread.
//=============================================================================

void StorageManager::sync_thread_loop() {
    // How long to leave a link that had no room before asking it again. There is
    // no event for bytes a caller handed over that the reactor never had to
    // queue, so writability is polled rather than waited on — see
    // PeerNetwork::peer_writable.
    constexpr auto kBlockedPoll = std::chrono::milliseconds(20);
    const auto     never        = (std::chrono::steady_clock::time_point::max)();

    while (sync_running_.load()) {
        const auto now = std::chrono::steady_clock::now();

        // Promote what has come due, and collect what can be streamed now. The
        // network is never called under sync_mutex_, so writability is tested
        // once the lock is dropped.
        std::vector<PeerId> streaming;
        auto                wake_at = never;
        uint64_t            epoch   = 0;
        {
            std::lock_guard<std::mutex> lock(sync_mutex_);
            epoch = sync_epoch_;
            for (auto& [id, st] : peers_) {
                if (!st.streaming && st.owed) {
                    const auto ready_at = st.last_start + sync_interval_;
                    if (st.last_start.time_since_epoch().count() != 0 && now < ready_at) {
                        wake_at = (std::min)(wake_at, ready_at);   // still cooling down
                        continue;
                    }
                    st.streaming  = true;
                    st.started    = false;
                    st.cursor.clear();
                    st.owed       = false;
                    st.last_start = now;
                }
                if (st.streaming) streaming.push_back(id);
            }
        }

        bool progressed = false;
        for (const PeerId& peer : streaming) {
            if (!sync_running_.load()) return;
            if (!network_->peer_writable(peer)) {
                wake_at = (std::min)(wake_at, now + kBlockedPoll);
                continue;
            }
            switch (stream_snapshot_chunk(peer)) {
                case ChunkResult::Continue: progressed = true; break;
                case ChunkResult::Blocked:  wake_at = (std::min)(wake_at, now + kBlockedPoll); break;
                case ChunkResult::Finished: break;
            }
        }
        if (progressed) continue;   // more to send and room to send it: no wait

        std::unique_lock<std::mutex> lock(sync_mutex_);
        if (!sync_running_.load()) return;
        // Everything above ran outside this lock, so a snapshot may have been
        // scheduled — and its notify already delivered to nobody — since the scan.
        // The epoch is what catches that; without it a wait() here could be a
        // wait forever with work sitting in the map.
        if (sync_epoch_ != epoch) continue;
        if (wake_at == never) sync_cv_.wait(lock);
        else                  sync_cv_.wait_until(lock, wake_at);
    }
}

StorageManager::ChunkResult StorageManager::stream_snapshot_chunk(const PeerId& peer) {
    std::string cursor;
    bool        started = false;
    {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        const auto it = peers_.find(peer);
        if (it == peers_.end() || !it->second.streaming) return ChunkResult::Finished;
        cursor  = it->second.cursor;
        started = it->second.started;
    }

    std::vector<uint8_t> msg;
    msg.reserve(batch_bytes_ + 64);
    msg.push_back(OP_SYNC_CHUNK);
    msg.push_back(0);        // flags, filled in below
    put_u32(msg, 0);         // count, filled in below

    uint32_t    count = 0;
    std::string last  = cursor;
    bool        done  = false;
    {
        // The one place the whole database is walked, and it is walked a chunk at
        // a time: storage_mutex_ is held for `batch_bytes_` worth of work and no
        // more, on this thread rather than a reactor's. Between chunks nothing is
        // held at all — the cursor alone resumes the walk, so writes landing
        // mid-snapshot neither block nor derail it.
        std::lock_guard<std::mutex> lock(storage_mutex_);
        auto it = started ? entries_.upper_bound(cursor) : entries_.begin();
        while (it != entries_.end()) {
            it->second.serialize_into(msg);
            last = it->first;
            ++count;
            ++it;
            // Checked after appending, so an entry larger than the target still
            // goes out on its own instead of stalling the walk forever.
            if (msg.size() >= batch_bytes_) break;
        }
        done = (it == entries_.end());
    }

    if (done) msg[1] = FLAG_LAST;
    write_u32(msg.data() + 2, count);

    const bool room = network_->send(peer, MessageType::Storage, ByteView(msg));

    {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        const auto it = peers_.find(peer);
        // The peer may have disconnected while the chunk was being built; its
        // state is gone and this chunk was the last of it.
        if (it == peers_.end()) return ChunkResult::Finished;
        it->second.cursor  = last;
        it->second.started = true;
        if (done) it->second.streaming = false;
    }
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.sync_chunks_sent++;
        stats_.entries_sent += count;
    }

    LOG_STORAGE_DEBUG("Snapshot chunk to " << peer.short_hex() << ": " << count << " entries, "
                      << msg.size() << " B" << (done ? " (last)" : ""));
    if (done) return ChunkResult::Finished;
    return room ? ChunkResult::Continue : ChunkResult::Blocked;
}

bool StorageManager::apply_remote_entry(const StorageEntry& entry, StorageChangeEvent* out_event) {
    // The same limit a local put() is held to. Without it a peer could push a
    // value this node would then have to re-serialize into every snapshot it
    // serves — and one big enough to blow through a send queue on its way out.
    if (entry.data.size() > config_.max_value_size) {
        LOG_STORAGE_WARN("Remote entry '" << entry.key << "' of " << entry.data.size()
                         << " B exceeds maximum " << config_.max_value_size << "; rejected");
        return false;
    }
    if (entry.key.empty()) return false;

    StorageChangeEvent event;
    event.operation = entry.deleted ? StorageOperation::OP_DELETE : StorageOperation::OP_PUT;
    event.key = entry.key;
    event.type = entry.type;
    event.new_data = entry.data;
    event.timestamp_ms = entry.timestamp_ms;
    event.origin_peer_id = entry.origin_peer_id;
    event.is_remote = true;

    {
        std::lock_guard<std::mutex> lock(storage_mutex_);

        auto it = entries_.find(entry.key);
        if (it != entries_.end()) {
            // Check LWW
            if (!entry.wins_over(it->second)) {
                return false;  // Our entry is newer or identical, don't apply
            }
            event.old_data = it->second.data;
            it->second = entry;
        } else {
            entries_[entry.key] = entry;
        }
    }

    if (out_event) *out_event = event;
    return true;
}

//=============================================================================
// Private Methods - File I/O
//=============================================================================

std::string StorageManager::get_data_file_path() const {
    return combine_paths(config_.data_directory, config_.database_name + ".dat");
}

std::string StorageManager::get_index_file_path() const {
    return combine_paths(config_.data_directory, config_.database_name + ".idx");
}

bool StorageManager::write_data_file() {
    std::string data_path = get_data_file_path();
    std::string temp_path = data_path + ".tmp";

    try {
        FILE* file = fopen(temp_path.c_str(), "wb");
        if (!file) {
            LOG_STORAGE_ERROR("Failed to open temp file for writing: " << temp_path);
            return false;
        }

        // Write file header
        // Magic: "RATS" (4 bytes)
        // Version: 1 (4 bytes)
        // Entry count (4 bytes)
        const char* magic = "RATS";
        uint32_t version = 1;
        uint32_t entry_count = static_cast<uint32_t>(entries_.size());

        fwrite(magic, 1, 4, file);

        uint8_t version_bytes[4] = {
            static_cast<uint8_t>((version >> 24) & 0xFF),
            static_cast<uint8_t>((version >> 16) & 0xFF),
            static_cast<uint8_t>((version >> 8) & 0xFF),
            static_cast<uint8_t>(version & 0xFF)
        };
        fwrite(version_bytes, 1, 4, file);

        uint8_t count_bytes[4] = {
            static_cast<uint8_t>((entry_count >> 24) & 0xFF),
            static_cast<uint8_t>((entry_count >> 16) & 0xFF),
            static_cast<uint8_t>((entry_count >> 8) & 0xFF),
            static_cast<uint8_t>(entry_count & 0xFF)
        };
        fwrite(count_bytes, 1, 4, file);

        // Write each entry, reusing one buffer rather than allocating per entry.
        std::vector<uint8_t> serialized;
        for (const auto& pair : entries_) {
            serialized.clear();
            pair.second.serialize_into(serialized);
            fwrite(serialized.data(), 1, serialized.size(), file);
        }

        fclose(file);

        // On Windows, rename fails if destination exists, so delete it first
        if (file_exists(data_path.c_str())) {
            delete_file(data_path.c_str());
        }

        // Atomically rename temp file to final
        if (!rename_file(temp_path.c_str(), data_path.c_str())) {
            LOG_STORAGE_ERROR("Failed to rename temp file to final: " << temp_path << " -> " << data_path);
            delete_file(temp_path.c_str());
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        LOG_STORAGE_ERROR("Exception while writing data file: " << e.what());
        delete_file(temp_path.c_str());
        return false;
    }
}

bool StorageManager::read_data_file() {
    std::string data_path = get_data_file_path();

    try {
        size_t file_size;
        void* file_data = read_file_binary(data_path.c_str(), &file_size);
        if (!file_data) {
            LOG_STORAGE_ERROR("Failed to read data file: " << data_path);
            return false;
        }

        std::vector<uint8_t> buffer(static_cast<uint8_t*>(file_data),
                                    static_cast<uint8_t*>(file_data) + file_size);
        free_file_buffer(file_data);

        // Read header
        if (buffer.size() < 12) {
            LOG_STORAGE_ERROR("Data file too small: " << buffer.size());
            return false;
        }

        // Check magic
        if (buffer[0] != 'R' || buffer[1] != 'A' || buffer[2] != 'T' || buffer[3] != 'S') {
            LOG_STORAGE_ERROR("Invalid magic in data file");
            return false;
        }

        // Read version
        uint32_t version = (static_cast<uint32_t>(buffer[4]) << 24) |
                          (static_cast<uint32_t>(buffer[5]) << 16) |
                          (static_cast<uint32_t>(buffer[6]) << 8) |
                          static_cast<uint32_t>(buffer[7]);

        if (version != 1) {
            LOG_STORAGE_ERROR("Unsupported data file version: " << version);
            return false;
        }

        // Read entry count
        uint32_t entry_count = (static_cast<uint32_t>(buffer[8]) << 24) |
                              (static_cast<uint32_t>(buffer[9]) << 16) |
                              (static_cast<uint32_t>(buffer[10]) << 8) |
                              static_cast<uint32_t>(buffer[11]);

        // Read entries
        entries_.clear();
        size_t offset = 12;

        for (uint32_t i = 0; i < entry_count && offset < buffer.size(); i++) {
            StorageEntry entry;
            size_t bytes_read = 0;

            if (!StorageEntry::deserialize(buffer, offset, entry, bytes_read)) {
                LOG_STORAGE_ERROR("Failed to deserialize entry " << i << " at offset " << offset);
                return false;
            }

            // Verify checksum
            if (!entry.verify_checksum()) {
                LOG_STORAGE_WARN("Checksum mismatch for entry '" << entry.key << "', skipping");
                offset += bytes_read;
                continue;
            }

            entries_[entry.key] = entry;
            offset += bytes_read;
        }

        return true;

    } catch (const std::exception& e) {
        LOG_STORAGE_ERROR("Exception while reading data file: " << e.what());
        return false;
    }
}

//=============================================================================
// Private Methods - Utility
//=============================================================================

uint64_t StorageManager::get_current_timestamp_ms() const {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

std::string StorageManager::get_our_peer_id() const {
    if (!network_) return "";
    return network_->local_id().to_hex();
}

void StorageManager::notify_change(const StorageChangeEvent& event) {
    if (change_callback_) {
        change_callback_(event);
    }
}

void StorageManager::mark_dirty() {
    {
        std::lock_guard<std::mutex> lock(persistence_mutex_);
        dirty_ = true;
    }
    persistence_cv_.notify_one();
}

} // namespace librats
