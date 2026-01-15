#include "storage.h"
#include "crc32.h"
#include "librats.h"
#include "fs.h"
#include "logger.h"
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>

// Define logging module for this file
#define LOG_STORAGE_INFO(message) LOG_INFO("storage", message)
#define LOG_STORAGE_ERROR(message) LOG_ERROR("storage", message)
#define LOG_STORAGE_WARN(message) LOG_WARN("storage", message)
#define LOG_STORAGE_DEBUG(message) LOG_DEBUG("storage", message)

namespace librats {

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

std::vector<uint8_t> StorageEntry::serialize() const {
    std::vector<uint8_t> buffer;
    
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
    
    // Calculate total size first
    uint32_t key_len = static_cast<uint32_t>(key.size());
    uint32_t peer_id_len = static_cast<uint32_t>(origin_peer_id.size());
    uint32_t data_len = static_cast<uint32_t>(data.size());
    uint32_t total_len = 4 + key_len + 1 + 1 + 8 + 4 + peer_id_len + 4 + data_len + 4;
    
    buffer.reserve(4 + total_len);
    
    // Total length (big endian)
    buffer.push_back((total_len >> 24) & 0xFF);
    buffer.push_back((total_len >> 16) & 0xFF);
    buffer.push_back((total_len >> 8) & 0xFF);
    buffer.push_back(total_len & 0xFF);
    
    // Key length (big endian)
    buffer.push_back((key_len >> 24) & 0xFF);
    buffer.push_back((key_len >> 16) & 0xFF);
    buffer.push_back((key_len >> 8) & 0xFF);
    buffer.push_back(key_len & 0xFF);
    
    // Key
    buffer.insert(buffer.end(), key.begin(), key.end());
    
    // Type
    buffer.push_back(static_cast<uint8_t>(type));
    
    // Deleted flag
    buffer.push_back(deleted ? 1 : 0);
    
    // Timestamp (big endian)
    for (int i = 7; i >= 0; i--) {
        buffer.push_back(static_cast<uint8_t>((timestamp_ms >> (i * 8)) & 0xFF));
    }
    
    // Peer ID length (big endian)
    buffer.push_back((peer_id_len >> 24) & 0xFF);
    buffer.push_back((peer_id_len >> 16) & 0xFF);
    buffer.push_back((peer_id_len >> 8) & 0xFF);
    buffer.push_back(peer_id_len & 0xFF);
    
    // Peer ID
    buffer.insert(buffer.end(), origin_peer_id.begin(), origin_peer_id.end());
    
    // Data length (big endian)
    buffer.push_back((data_len >> 24) & 0xFF);
    buffer.push_back((data_len >> 16) & 0xFF);
    buffer.push_back((data_len >> 8) & 0xFF);
    buffer.push_back(data_len & 0xFF);
    
    // Data
    buffer.insert(buffer.end(), data.begin(), data.end());
    
    // Checksum (big endian)
    buffer.push_back((checksum >> 24) & 0xFF);
    buffer.push_back((checksum >> 16) & 0xFF);
    buffer.push_back((checksum >> 8) & 0xFF);
    buffer.push_back(checksum & 0xFF);
    
    return buffer;
}

bool StorageEntry::deserialize(const std::vector<uint8_t>& buffer, size_t offset, 
                               StorageEntry& entry, size_t& bytes_read) {
    bytes_read = 0;
    
    // Minimum size check (4 bytes for total_length)
    if (offset + 4 > buffer.size()) {
        return false;
    }
    
    // Read total length
    uint32_t total_len = (static_cast<uint32_t>(buffer[offset]) << 24) |
                         (static_cast<uint32_t>(buffer[offset + 1]) << 16) |
                         (static_cast<uint32_t>(buffer[offset + 2]) << 8) |
                         static_cast<uint32_t>(buffer[offset + 3]);
    
    // Check if we have enough data
    if (offset + 4 + total_len > buffer.size()) {
        return false;
    }
    
    size_t pos = offset + 4;
    
    // Read key length
    if (pos + 4 > buffer.size()) return false;
    uint32_t key_len = (static_cast<uint32_t>(buffer[pos]) << 24) |
                       (static_cast<uint32_t>(buffer[pos + 1]) << 16) |
                       (static_cast<uint32_t>(buffer[pos + 2]) << 8) |
                       static_cast<uint32_t>(buffer[pos + 3]);
    pos += 4;
    
    // Read key
    if (pos + key_len > buffer.size()) return false;
    entry.key = std::string(buffer.begin() + pos, buffer.begin() + pos + key_len);
    pos += key_len;
    
    // Read type
    if (pos + 1 > buffer.size()) return false;
    entry.type = static_cast<StorageValueType>(buffer[pos]);
    pos += 1;
    
    // Read deleted flag
    if (pos + 1 > buffer.size()) return false;
    entry.deleted = buffer[pos] != 0;
    pos += 1;
    
    // Read timestamp
    if (pos + 8 > buffer.size()) return false;
    entry.timestamp_ms = 0;
    for (int i = 0; i < 8; i++) {
        entry.timestamp_ms = (entry.timestamp_ms << 8) | buffer[pos + i];
    }
    pos += 8;
    
    // Read peer ID length
    if (pos + 4 > buffer.size()) return false;
    uint32_t peer_id_len = (static_cast<uint32_t>(buffer[pos]) << 24) |
                           (static_cast<uint32_t>(buffer[pos + 1]) << 16) |
                           (static_cast<uint32_t>(buffer[pos + 2]) << 8) |
                           static_cast<uint32_t>(buffer[pos + 3]);
    pos += 4;
    
    // Read peer ID
    if (pos + peer_id_len > buffer.size()) return false;
    entry.origin_peer_id = std::string(buffer.begin() + pos, buffer.begin() + pos + peer_id_len);
    pos += peer_id_len;
    
    // Read data length
    if (pos + 4 > buffer.size()) return false;
    uint32_t data_len = (static_cast<uint32_t>(buffer[pos]) << 24) |
                        (static_cast<uint32_t>(buffer[pos + 1]) << 16) |
                        (static_cast<uint32_t>(buffer[pos + 2]) << 8) |
                        static_cast<uint32_t>(buffer[pos + 3]);
    pos += 4;
    
    // Read data
    if (pos + data_len > buffer.size()) return false;
    entry.data = std::vector<uint8_t>(buffer.begin() + pos, buffer.begin() + pos + data_len);
    pos += data_len;
    
    // Read checksum
    if (pos + 4 > buffer.size()) return false;
    entry.checksum = (static_cast<uint32_t>(buffer[pos]) << 24) |
                     (static_cast<uint32_t>(buffer[pos + 1]) << 16) |
                     (static_cast<uint32_t>(buffer[pos + 2]) << 8) |
                     static_cast<uint32_t>(buffer[pos + 3]);
    pos += 4;
    
    bytes_read = pos - offset;
    return true;
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

StorageManager::StorageManager(RatsClient& client, const StorageConfig& config)
    : client_(client), 
      config_(config),
      sync_status_(StorageSyncStatus::NOT_STARTED),
      initial_sync_complete_(false),
      running_(true),
      dirty_(false) {
    
    // Initialize statistics
    stats_ = StorageStatistics();
    stats_.sync_status = StorageSyncStatus::NOT_STARTED;
    
    initialize();
}

StorageManager::~StorageManager() {
    shutdown();
}

void StorageManager::initialize() {
    // Ensure data directory exists
    if (config_.persist_to_disk) {
        create_directories(config_.data_directory.c_str());
    }
    
    // Load existing data from disk
    if (config_.persist_to_disk) {
        load();
    }
    
    // Subscribe to GossipSub topic for real-time updates
    if (config_.enable_sync && client_.is_gossipsub_available()) {
        client_.subscribe_to_topic(STORAGE_GOSSIP_TOPIC);
        
        // Set up message handler for storage updates
        client_.on_topic_message(STORAGE_GOSSIP_TOPIC, 
            [this](const std::string& peer_id, const std::string& topic, const std::string& message) {
                handle_gossip_message(peer_id, topic, message);
            });
    }
    
    // Register message handlers for sync protocol
    if (config_.enable_sync) {
        client_.on(MSG_TYPE_SYNC_REQUEST, [this](const std::string& peer_id, const nlohmann::json& data) {
            handle_sync_request(peer_id, data);
        });
        
        client_.on(MSG_TYPE_SYNC_RESPONSE, [this](const std::string& peer_id, const nlohmann::json& data) {
            handle_sync_response(peer_id, data);
        });
    }
    
    // Start persistence thread
    if (config_.persist_to_disk) {
        persistence_thread_ = std::thread(&StorageManager::persistence_thread_loop, this);
    }
    
    LOG_STORAGE_INFO("StorageManager initialized with data directory: " << config_.data_directory);
}

void StorageManager::shutdown() {
    LOG_STORAGE_INFO("StorageManager shutting down...");
    
    running_.store(false);
    
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
    if (config_.persist_to_disk && dirty_) {
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

void StorageManager::set_config(const StorageConfig& config) {
    std::lock_guard<std::mutex> lock(storage_mutex_);
    config_ = config;
    
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

bool StorageManager::put_json(const std::string& key, const nlohmann::json& value) {
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
        broadcast_put(new_entry);
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

std::optional<nlohmann::json> StorageManager::get_json(const std::string& key) const {
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
        return nlohmann::json::parse(json_str);
    } catch (const std::exception& e) {
        LOG_STORAGE_ERROR("Failed to parse JSON for key '" << key << "': " << e.what());
        return std::nullopt;
    }
}

const StorageEntry* StorageManager::get_entry(const std::string& key) const {
    std::lock_guard<std::mutex> lock(storage_mutex_);
    
    auto it = entries_.find(key);
    if (it == entries_.end() || it->second.deleted) {
        return nullptr;
    }
    
    return &it->second;
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
    }
    
    mark_dirty();
    
    // Broadcast delete to peers
    if (config_.enable_sync) {
        broadcast_delete(key, timestamp_ms);
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
    
    std::vector<std::string> result;
    
    for (const auto& pair : entries_) {
        if (!pair.second.deleted && 
            pair.first.size() >= prefix.size() &&
            pair.first.compare(0, prefix.size(), prefix) == 0) {
            result.push_back(pair.first);
        }
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
    uint64_t timestamp_ms = get_current_timestamp_ms();
    
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
        dirty_ = false;
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
    if (!config_.enable_sync) {
        return false;
    }
    
    // Get a connected peer to sync from
    auto peers = client_.get_validated_peers();
    if (peers.empty()) {
        LOG_STORAGE_WARN("No peers available for sync");
        return false;
    }
    
    // Pick first available peer
    std::string peer_id = peers[0].peer_id;
    
    {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        sync_status_ = StorageSyncStatus::IN_PROGRESS;
        sync_peer_id_ = peer_id;
    }
    
    send_sync_request(peer_id);
    
    LOG_STORAGE_INFO("Requested sync from peer " << peer_id);
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

nlohmann::json StorageManager::get_statistics_json() const {
    StorageStatistics stats = get_statistics();
    
    nlohmann::json result;
    result["total_entries"] = stats.total_entries;
    result["deleted_entries"] = stats.deleted_entries;
    result["total_data_bytes"] = stats.total_data_bytes;
    result["disk_usage_bytes"] = stats.disk_usage_bytes;
    result["entries_synced"] = stats.entries_synced;
    result["entries_sent"] = stats.entries_sent;
    result["sync_requests_received"] = stats.sync_requests_received;
    result["sync_requests_sent"] = stats.sync_requests_sent;
    
    switch (stats.sync_status) {
        case StorageSyncStatus::NOT_STARTED: result["sync_status"] = "not_started"; break;
        case StorageSyncStatus::IN_PROGRESS: result["sync_status"] = "in_progress"; break;
        case StorageSyncStatus::COMPLETED: result["sync_status"] = "completed"; break;
        case StorageSyncStatus::FAILED: result["sync_status"] = "failed"; break;
    }
    
    return result;
}

//=============================================================================
// Network Message Handlers
//=============================================================================

void StorageManager::handle_gossip_message(const std::string& peer_id, const std::string& topic, 
                                           const std::string& message) {
    if (topic != STORAGE_GOSSIP_TOPIC) {
        return;
    }
    
    try {
        nlohmann::json msg = nlohmann::json::parse(message);
        
        std::string msg_type = msg.value("type", "");
        
        if (msg_type == "put") {
            // Decode entry from message
            std::string key = msg["key"];
            std::string type_str = msg["value_type"];
            std::string data_base64 = msg["data"];
            uint64_t timestamp_ms = msg["timestamp"];
            std::string origin_peer = msg["origin_peer"];
            
            // Decode base64 data
            std::vector<uint8_t> data;
            // Simple base64 decode (we'll implement inline)
            static const std::string base64_chars = 
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            
            std::vector<int> T(256, -1);
            for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(base64_chars[i])] = i;
            
            int val = 0, valb = -8;
            for (unsigned char c : data_base64) {
                if (T[c] == -1) break;
                val = (val << 6) + T[c];
                valb += 6;
                if (valb >= 0) {
                    data.push_back((val >> valb) & 0xFF);
                    valb -= 8;
                }
            }
            
            StorageValueType value_type = string_to_storage_value_type(type_str);
            
            // Apply with LWW resolution
            put_internal(key, value_type, data, timestamp_ms, origin_peer, false);
            
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.entries_synced++;
            }
            
        } else if (msg_type == "delete") {
            std::string key = msg["key"];
            uint64_t timestamp_ms = msg["timestamp"];
            std::string origin_peer = msg["origin_peer"];
            
            // Apply delete with LWW
            {
                std::lock_guard<std::mutex> lock(storage_mutex_);
                
                auto it = entries_.find(key);
                if (it != entries_.end()) {
                    // Check if this delete is newer
                    if (timestamp_ms > it->second.timestamp_ms ||
                        (timestamp_ms == it->second.timestamp_ms && origin_peer > it->second.origin_peer_id)) {
                        it->second.deleted = true;
                        it->second.timestamp_ms = timestamp_ms;
                        it->second.origin_peer_id = origin_peer;
                        it->second.data.clear();
                        it->second.calculate_checksum();
                        mark_dirty();
                    }
                }
            }
            
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.entries_synced++;
            }
        }
        
    } catch (const std::exception& e) {
        LOG_STORAGE_ERROR("Failed to handle gossip message: " << e.what());
    }
}

void StorageManager::handle_sync_request(const std::string& peer_id, const nlohmann::json& data) {
    LOG_STORAGE_INFO("Received sync request from peer " << peer_id);
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.sync_requests_received++;
    }
    
    // Send full database snapshot
    send_sync_response(peer_id);
}

void StorageManager::handle_sync_response(const std::string& peer_id, const nlohmann::json& data) {
    LOG_STORAGE_INFO("Received sync response from peer " << peer_id);
    
    try {
        if (!data.contains("entries") || !data["entries"].is_array()) {
            LOG_STORAGE_ERROR("Invalid sync response format");
            
            {
                std::lock_guard<std::mutex> lock(sync_mutex_);
                sync_status_ = StorageSyncStatus::FAILED;
            }
            
            if (sync_complete_callback_) {
                sync_complete_callback_(false, "Invalid sync response format");
            }
            return;
        }
        
        int applied = 0;
        
        for (const auto& entry_json : data["entries"]) {
            std::string key = entry_json["key"];
            std::string type_str = entry_json["value_type"];
            std::string data_base64 = entry_json["data"];
            uint64_t timestamp_ms = entry_json["timestamp"];
            std::string origin_peer = entry_json["origin_peer"];
            bool deleted = entry_json.value("deleted", false);
            
            // Decode base64 data
            std::vector<uint8_t> decoded_data;
            static const std::string base64_chars = 
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            
            std::vector<int> T(256, -1);
            for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(base64_chars[i])] = i;
            
            int val = 0, valb = -8;
            for (unsigned char c : data_base64) {
                if (T[c] == -1) break;
                val = (val << 6) + T[c];
                valb += 6;
                if (valb >= 0) {
                    decoded_data.push_back((val >> valb) & 0xFF);
                    valb -= 8;
                }
            }
            
            StorageValueType value_type = string_to_storage_value_type(type_str);
            
            // Create entry
            StorageEntry entry;
            entry.key = key;
            entry.type = value_type;
            entry.data = decoded_data;
            entry.timestamp_ms = timestamp_ms;
            entry.origin_peer_id = origin_peer;
            entry.deleted = deleted;
            entry.calculate_checksum();
            
            if (apply_remote_entry(entry)) {
                applied++;
            }
        }
        
        {
            std::lock_guard<std::mutex> lock(sync_mutex_);
            sync_status_ = StorageSyncStatus::COMPLETED;
            initial_sync_complete_ = true;
            last_sync_time_ = std::chrono::steady_clock::now();
        }
        
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.entries_synced += applied;
        }
        
        mark_dirty();
        
        LOG_STORAGE_INFO("Sync completed, applied " << applied << " entries from peer " << peer_id);
        
        if (sync_complete_callback_) {
            sync_complete_callback_(true, "");
        }
        
    } catch (const std::exception& e) {
        LOG_STORAGE_ERROR("Failed to handle sync response: " << e.what());
        
        {
            std::lock_guard<std::mutex> lock(sync_mutex_);
            sync_status_ = StorageSyncStatus::FAILED;
        }
        
        if (sync_complete_callback_) {
            sync_complete_callback_(false, e.what());
        }
    }
}

void StorageManager::on_peer_connected(const std::string& peer_id) {
    if (!config_.enable_sync) {
        return;
    }
    
    // If we haven't synced yet, request sync from this peer
    {
        std::lock_guard<std::mutex> lock(sync_mutex_);
        if (!initial_sync_complete_ && sync_status_ != StorageSyncStatus::IN_PROGRESS) {
            sync_status_ = StorageSyncStatus::IN_PROGRESS;
            sync_peer_id_ = peer_id;
        } else {
            return;  // Already synced or in progress
        }
    }
    
    send_sync_request(peer_id);
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

void StorageManager::broadcast_put(const StorageEntry& entry) {
    if (!client_.is_gossipsub_available()) {
        return;
    }
    
    // Base64 encode data
    static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string data_base64;
    
    int val = 0, valb = -6;
    for (uint8_t c : entry.data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            data_base64.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) data_base64.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (data_base64.size() % 4) data_base64.push_back('=');
    
    nlohmann::json msg;
    msg["type"] = "put";
    msg["key"] = entry.key;
    msg["value_type"] = storage_value_type_to_string(entry.type);
    msg["data"] = data_base64;
    msg["timestamp"] = entry.timestamp_ms;
    msg["origin_peer"] = entry.origin_peer_id;
    
    client_.publish_to_topic(STORAGE_GOSSIP_TOPIC, msg.dump());
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.entries_sent++;
    }
}

void StorageManager::broadcast_delete(const std::string& key, uint64_t timestamp_ms) {
    if (!client_.is_gossipsub_available()) {
        return;
    }
    
    nlohmann::json msg;
    msg["type"] = "delete";
    msg["key"] = key;
    msg["timestamp"] = timestamp_ms;
    msg["origin_peer"] = get_our_peer_id();
    
    client_.publish_to_topic(STORAGE_GOSSIP_TOPIC, msg.dump());
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.entries_sent++;
    }
}

void StorageManager::send_sync_request(const std::string& peer_id) {
    nlohmann::json request;
    request["request_id"] = get_current_timestamp_ms();
    
    client_.send(peer_id, MSG_TYPE_SYNC_REQUEST, request);
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.sync_requests_sent++;
    }
    
    LOG_STORAGE_DEBUG("Sent sync request to peer " << peer_id);
}

void StorageManager::send_sync_response(const std::string& peer_id) {
    nlohmann::json response;
    nlohmann::json entries_json = nlohmann::json::array();
    
    {
        std::lock_guard<std::mutex> lock(storage_mutex_);
        
        for (const auto& pair : entries_) {
            const StorageEntry& entry = pair.second;
            
            // Base64 encode data
            static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string data_base64;
            
            int val = 0, valb = -6;
            for (uint8_t c : entry.data) {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0) {
                    data_base64.push_back(base64_chars[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6) data_base64.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
            while (data_base64.size() % 4) data_base64.push_back('=');
            
            nlohmann::json entry_json;
            entry_json["key"] = entry.key;
            entry_json["value_type"] = storage_value_type_to_string(entry.type);
            entry_json["data"] = data_base64;
            entry_json["timestamp"] = entry.timestamp_ms;
            entry_json["origin_peer"] = entry.origin_peer_id;
            entry_json["deleted"] = entry.deleted;
            
            entries_json.push_back(entry_json);
        }
    }
    
    response["entries"] = entries_json;
    
    client_.send(peer_id, MSG_TYPE_SYNC_RESPONSE, response);
    
    LOG_STORAGE_DEBUG("Sent sync response to peer " << peer_id << " with " << entries_json.size() << " entries");
}

bool StorageManager::apply_remote_entry(const StorageEntry& entry) {
    std::lock_guard<std::mutex> lock(storage_mutex_);
    
    auto it = entries_.find(entry.key);
    if (it != entries_.end()) {
        // Check LWW
        if (!entry.wins_over(it->second)) {
            return false;  // Our entry is newer, don't apply
        }
    }
    
    entries_[entry.key] = entry;
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
        
        // Write each entry
        for (const auto& pair : entries_) {
            std::vector<uint8_t> serialized = pair.second.serialize();
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
    return client_.get_our_peer_id();
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
