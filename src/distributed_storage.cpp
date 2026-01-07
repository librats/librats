#include "distributed_storage.h"
#include "librats.h"
#include "sha1.h"
#include "fs.h"
#include "logger.h"
#include <fstream>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace librats {

// Logging macros
#define LOG_STORAGE_DEBUG(message) LOG_DEBUG("storage", message)
#define LOG_STORAGE_INFO(message)  LOG_INFO("storage", message)
#define LOG_STORAGE_WARN(message)  LOG_WARN("storage", message)
#define LOG_STORAGE_ERROR(message) LOG_ERROR("storage", message)

// =========================================================================
// StorageEntry serialization
// =========================================================================

nlohmann::json StorageEntry::to_json() const {
    nlohmann::json j;
    j["key"] = key;
    j["value"] = nlohmann::json::binary_t(value);
    j["type"] = static_cast<uint8_t>(type);
    j["version"] = version;
    j["timestamp"] = timestamp;
    j["author"] = author_peer_id;
    j["checksum"] = checksum;
    j["deleted"] = is_deleted;
    j["deleted_at"] = deleted_at;
    return j;
}

StorageEntry StorageEntry::from_json(const nlohmann::json& j) {
    StorageEntry entry;
    entry.key = j.value("key", "");
    
    if (j.contains("value")) {
        if (j["value"].is_binary()) {
            entry.value = j["value"].get_binary();
        } else if (j["value"].is_string()) {
            // Handle base64 or plain string
            std::string str_val = j["value"].get<std::string>();
            entry.value = std::vector<uint8_t>(str_val.begin(), str_val.end());
        } else if (j["value"].is_array()) {
            entry.value = j["value"].get<std::vector<uint8_t>>();
        }
    }
    
    entry.type = static_cast<StorageEntryType>(j.value("type", static_cast<uint8_t>(StorageEntryType::STRING)));
    entry.version = j.value("version", 0ULL);
    entry.timestamp = j.value("timestamp", 0ULL);
    entry.author_peer_id = j.value("author", "");
    entry.checksum = j.value("checksum", "");
    entry.is_deleted = j.value("deleted", false);
    entry.deleted_at = j.value("deleted_at", 0ULL);
    
    return entry;
}

std::vector<uint8_t> StorageEntry::to_binary() const {
    // Binary format:
    // [4 bytes] Total size
    // [4 bytes] Key length
    // [N bytes] Key
    // [1 byte]  Type
    // [8 bytes] Version
    // [8 bytes] Timestamp
    // [4 bytes] Author length
    // [N bytes] Author
    // [4 bytes] Value length
    // [N bytes] Value
    // [1 byte]  Is deleted
    // [8 bytes] Deleted at
    // [20 bytes] Checksum (SHA1)
    
    std::vector<uint8_t> data;
    
    auto write_u32 = [&data](uint32_t val) {
        data.push_back(static_cast<uint8_t>(val >> 24));
        data.push_back(static_cast<uint8_t>(val >> 16));
        data.push_back(static_cast<uint8_t>(val >> 8));
        data.push_back(static_cast<uint8_t>(val));
    };
    
    auto write_u64 = [&data](uint64_t val) {
        for (int i = 7; i >= 0; --i) {
            data.push_back(static_cast<uint8_t>(val >> (i * 8)));
        }
    };
    
    auto write_string = [&data, &write_u32](const std::string& str) {
        write_u32(static_cast<uint32_t>(str.size()));
        data.insert(data.end(), str.begin(), str.end());
    };
    
    // Reserve space for total size (will fill later)
    size_t size_pos = data.size();
    write_u32(0);
    
    // Write data
    write_string(key);
    data.push_back(static_cast<uint8_t>(type));
    write_u64(version);
    write_u64(timestamp);
    write_string(author_peer_id);
    write_u32(static_cast<uint32_t>(value.size()));
    data.insert(data.end(), value.begin(), value.end());
    data.push_back(is_deleted ? 1 : 0);
    write_u64(deleted_at);
    
    // Write checksum as raw bytes (40 hex chars -> 20 bytes)
    for (size_t i = 0; i < 20 && i * 2 < checksum.size(); ++i) {
        std::string hex_byte = checksum.substr(i * 2, 2);
        data.push_back(static_cast<uint8_t>(std::stoul(hex_byte, nullptr, 16)));
    }
    // Pad with zeros if checksum is shorter
    while (data.size() < size_pos + 4 + key.size() + 4 + 1 + 8 + 8 + 4 + author_peer_id.size() + 4 + value.size() + 1 + 8 + 20) {
        data.push_back(0);
    }
    
    // Fill in total size
    uint32_t total_size = static_cast<uint32_t>(data.size() - 4);
    data[size_pos] = static_cast<uint8_t>(total_size >> 24);
    data[size_pos + 1] = static_cast<uint8_t>(total_size >> 16);
    data[size_pos + 2] = static_cast<uint8_t>(total_size >> 8);
    data[size_pos + 3] = static_cast<uint8_t>(total_size);
    
    return data;
}

std::optional<StorageEntry> StorageEntry::from_binary(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return std::nullopt;
    }
    
    size_t pos = 0;
    
    auto read_u32 = [&data, &pos]() -> uint32_t {
        if (pos + 4 > data.size()) return 0;
        uint32_t val = (static_cast<uint32_t>(data[pos]) << 24) |
                       (static_cast<uint32_t>(data[pos + 1]) << 16) |
                       (static_cast<uint32_t>(data[pos + 2]) << 8) |
                       static_cast<uint32_t>(data[pos + 3]);
        pos += 4;
        return val;
    };
    
    auto read_u64 = [&data, &pos]() -> uint64_t {
        if (pos + 8 > data.size()) return 0;
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val = (val << 8) | static_cast<uint64_t>(data[pos + i]);
        }
        pos += 8;
        return val;
    };
    
    auto read_string = [&data, &pos, &read_u32]() -> std::string {
        uint32_t len = read_u32();
        if (pos + len > data.size()) return "";
        std::string str(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return str;
    };
    
    StorageEntry entry;
    
    uint32_t total_size = read_u32();
    if (data.size() < total_size + 4) {
        return std::nullopt;
    }
    
    entry.key = read_string();
    if (pos >= data.size()) return std::nullopt;
    
    entry.type = static_cast<StorageEntryType>(data[pos++]);
    entry.version = read_u64();
    entry.timestamp = read_u64();
    entry.author_peer_id = read_string();
    
    uint32_t value_len = read_u32();
    if (pos + value_len > data.size()) return std::nullopt;
    entry.value = std::vector<uint8_t>(data.begin() + pos, data.begin() + pos + value_len);
    pos += value_len;
    
    if (pos >= data.size()) return std::nullopt;
    entry.is_deleted = (data[pos++] != 0);
    entry.deleted_at = read_u64();
    
    // Read checksum (20 bytes -> 40 hex chars)
    std::ostringstream checksum_stream;
    for (size_t i = 0; i < 20 && pos + i < data.size(); ++i) {
        checksum_stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[pos + i]);
    }
    entry.checksum = checksum_stream.str();
    
    return entry;
}

// =========================================================================
// Constructor and Destructor
// =========================================================================

DistributedStorage::DistributedStorage(RatsClient& client, const DistributedStorageConfig& config)
    : client_(client), config_(config), logical_clock_(0), sync_running_(false),
      total_sets_(0), total_gets_(0), total_deletes_(0), total_syncs_(0), conflicts_resolved_(0) {
    
    LOG_STORAGE_INFO("Creating DistributedStorage: " << config_.storage_name);
    initialize();
}

DistributedStorage::~DistributedStorage() {
    LOG_STORAGE_INFO("Destroying DistributedStorage: " << config_.storage_name);
    shutdown();
}

void DistributedStorage::initialize() {
    // Set default storage path if not specified
    if (config_.storage_path.empty()) {
        config_.storage_path = get_default_storage_path();
    }
    
    // Set default GossipSub topic if not specified
    if (config_.gossipsub_topic.empty()) {
        config_.gossipsub_topic = "storage/" + config_.storage_name;
    }
    
    // Load from disk if enabled
    if (config_.persist_to_disk) {
        load_from_disk();
    }
    
    // Register message handlers
    register_message_handlers();
    
    // Subscribe to GossipSub topic if enabled
    if (config_.use_gossipsub && client_.is_gossipsub_available()) {
        client_.subscribe_to_topic(config_.gossipsub_topic);
    }
    
    // Start sync if auto_sync is enabled
    if (config_.auto_sync) {
        start_sync();
    }
    
    LOG_STORAGE_INFO("DistributedStorage initialized with " << count() << " entries");
}

void DistributedStorage::shutdown() {
    // Stop sync
    stop_sync();
    
    // Unregister message handlers
    unregister_message_handlers();
    
    // Unsubscribe from GossipSub
    if (config_.use_gossipsub && client_.is_gossipsub_available()) {
        client_.unsubscribe_from_topic(config_.gossipsub_topic);
    }
    
    // Save to disk if enabled
    if (config_.persist_to_disk) {
        save_to_disk();
    }
    
    LOG_STORAGE_INFO("DistributedStorage shutdown complete");
}

// =========================================================================
// Configuration
// =========================================================================

const DistributedStorageConfig& DistributedStorage::get_config() const {
    return config_;
}

void DistributedStorage::set_config(const DistributedStorageConfig& config) {
    config_ = config;
}

// =========================================================================
// Basic CRUD Operations
// =========================================================================

bool DistributedStorage::set(const std::string& key, const std::string& value, uint64_t ttl_seconds) {
    std::vector<uint8_t> data(value.begin(), value.end());
    return set_internal(key, data, StorageEntryType::STRING, ttl_seconds, true);
}

bool DistributedStorage::set(const std::string& key, const std::vector<uint8_t>& value, uint64_t ttl_seconds) {
    return set_internal(key, value, StorageEntryType::BINARY, ttl_seconds, true);
}

bool DistributedStorage::set(const std::string& key, const nlohmann::json& value, uint64_t ttl_seconds) {
    std::string json_str = value.dump();
    std::vector<uint8_t> data(json_str.begin(), json_str.end());
    return set_internal(key, data, StorageEntryType::JSON, ttl_seconds, true);
}

bool DistributedStorage::set(const std::string& key, int64_t value, uint64_t ttl_seconds) {
    std::vector<uint8_t> data(8);
    for (int i = 7; i >= 0; --i) {
        data[7 - i] = static_cast<uint8_t>(value >> (i * 8));
    }
    return set_internal(key, data, StorageEntryType::INTEGER, ttl_seconds, true);
}

bool DistributedStorage::set(const std::string& key, double value, uint64_t ttl_seconds) {
    std::vector<uint8_t> data(8);
    std::memcpy(data.data(), &value, 8);
    return set_internal(key, data, StorageEntryType::DOUBLE, ttl_seconds, true);
}

bool DistributedStorage::set(const std::string& key, bool value, uint64_t ttl_seconds) {
    std::vector<uint8_t> data = {static_cast<uint8_t>(value ? 1 : 0)};
    return set_internal(key, data, StorageEntryType::BOOLEAN, ttl_seconds, true);
}

bool DistributedStorage::set_internal(const std::string& key, const std::vector<uint8_t>& value, 
                                      StorageEntryType type, uint64_t ttl_seconds, bool propagate) {
    if (key.empty()) {
        LOG_STORAGE_ERROR("Cannot set entry with empty key");
        return false;
    }
    
    if (config_.max_entry_size_bytes > 0 && value.size() > config_.max_entry_size_bytes) {
        LOG_STORAGE_ERROR("Entry value exceeds maximum size: " << value.size() << " > " << config_.max_entry_size_bytes);
        return false;
    }
    
    StorageEntry entry;
    entry.key = key;
    entry.value = value;
    entry.type = type;
    entry.version = next_version();
    entry.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    entry.author_peer_id = client_.get_our_peer_id();
    entry.checksum = calculate_checksum(value);
    entry.is_deleted = false;
    entry.deleted_at = 0;
    
    StorageChangeEvent event;
    event.key = key;
    event.new_entry = entry;
    event.is_local = true;
    event.source_peer_id = client_.get_our_peer_id();
    
    {
        std::unique_lock<std::shared_mutex> lock(storage_mutex_);
        
        // Check entry limit
        if (config_.max_entries > 0 && storage_.size() >= config_.max_entries) {
            auto it = storage_.find(key);
            if (it == storage_.end()) {
                LOG_STORAGE_ERROR("Maximum entries limit reached: " << config_.max_entries);
                return false;
            }
        }
        
        // Get old entry for change event
        auto it = storage_.find(key);
        if (it != storage_.end()) {
            event.old_entry = it->second;
            event.change_type = StorageChangeEvent::ChangeType::UPDATE;
        } else {
            event.change_type = StorageChangeEvent::ChangeType::INSERT;
        }
        
        storage_[key] = entry;
    }
    
    total_sets_++;
    
    // Notify change subscribers
    notify_change(event);
    
    // Propagate to peers
    if (propagate) {
        broadcast_entry_change(entry, false);
    }
    
    LOG_STORAGE_DEBUG("Set key '" << key << "' (type=" << static_cast<int>(type) << ", size=" << value.size() << ")");
    
    return true;
}

std::optional<std::string> DistributedStorage::get_string(const std::string& key) const {
    auto entry = get_internal(key);
    if (!entry || entry->type != StorageEntryType::STRING) {
        return std::nullopt;
    }
    return std::string(entry->value.begin(), entry->value.end());
}

std::optional<std::vector<uint8_t>> DistributedStorage::get_binary(const std::string& key) const {
    auto entry = get_internal(key);
    if (!entry) {
        return std::nullopt;
    }
    return entry->value;
}

std::optional<nlohmann::json> DistributedStorage::get_json(const std::string& key) const {
    auto entry = get_internal(key);
    if (!entry || entry->type != StorageEntryType::JSON) {
        return std::nullopt;
    }
    try {
        std::string json_str(entry->value.begin(), entry->value.end());
        return nlohmann::json::parse(json_str);
    } catch (const std::exception& e) {
        LOG_STORAGE_ERROR("Failed to parse JSON for key '" << key << "': " << e.what());
        return std::nullopt;
    }
}

std::optional<int64_t> DistributedStorage::get_int(const std::string& key) const {
    auto entry = get_internal(key);
    if (!entry || entry->type != StorageEntryType::INTEGER || entry->value.size() != 8) {
        return std::nullopt;
    }
    int64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | static_cast<int64_t>(entry->value[i]);
    }
    return val;
}

std::optional<double> DistributedStorage::get_double(const std::string& key) const {
    auto entry = get_internal(key);
    if (!entry || entry->type != StorageEntryType::DOUBLE || entry->value.size() != 8) {
        return std::nullopt;
    }
    double val;
    std::memcpy(&val, entry->value.data(), 8);
    return val;
}

std::optional<bool> DistributedStorage::get_bool(const std::string& key) const {
    auto entry = get_internal(key);
    if (!entry || entry->type != StorageEntryType::BOOLEAN || entry->value.empty()) {
        return std::nullopt;
    }
    return entry->value[0] != 0;
}

std::optional<StorageEntry> DistributedStorage::get_entry(const std::string& key) const {
    return get_internal(key);
}

std::optional<StorageEntry> DistributedStorage::get_internal(const std::string& key) const {
    std::shared_lock<std::shared_mutex> lock(storage_mutex_);
    
    auto it = storage_.find(key);
    if (it == storage_.end() || it->second.is_deleted) {
        return std::nullopt;
    }
    
    // Note: Not incrementing total_gets_ here since this is a const method
    // and it's used internally by other methods that may already count stats
    return it->second;
}

bool DistributedStorage::remove(const std::string& key) {
    return remove_internal(key, true);
}

bool DistributedStorage::remove_internal(const std::string& key, bool propagate) {
    StorageEntry tombstone;
    StorageChangeEvent event;
    event.key = key;
    event.is_local = true;
    event.source_peer_id = client_.get_our_peer_id();
    event.change_type = StorageChangeEvent::ChangeType::REMOVE;
    
    {
        std::unique_lock<std::shared_mutex> lock(storage_mutex_);
        
        auto it = storage_.find(key);
        if (it == storage_.end() || it->second.is_deleted) {
            return false;
        }
        
        event.old_entry = it->second;
        
        // Create tombstone
        tombstone = it->second;
        tombstone.is_deleted = true;
        tombstone.deleted_at = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        tombstone.version = next_version();
        tombstone.type = StorageEntryType::DELETED;
        tombstone.author_peer_id = client_.get_our_peer_id();
        
        storage_[key] = tombstone;
    }
    
    event.new_entry = tombstone;
    total_deletes_++;
    
    // Notify change subscribers
    notify_change(event);
    
    // Propagate to peers
    if (propagate) {
        broadcast_entry_change(tombstone, true);
    }
    
    LOG_STORAGE_DEBUG("Removed key '" << key << "'");
    
    return true;
}

bool DistributedStorage::exists(const std::string& key) const {
    std::shared_lock<std::shared_mutex> lock(storage_mutex_);
    auto it = storage_.find(key);
    return it != storage_.end() && !it->second.is_deleted;
}

std::optional<StorageEntryType> DistributedStorage::get_type(const std::string& key) const {
    auto entry = get_internal(key);
    if (!entry) {
        return std::nullopt;
    }
    return entry->type;
}

// =========================================================================
// Atomic Operations
// =========================================================================

std::optional<int64_t> DistributedStorage::increment(const std::string& key, int64_t delta) {
    std::unique_lock<std::shared_mutex> lock(storage_mutex_);
    
    auto it = storage_.find(key);
    if (it == storage_.end() || it->second.is_deleted || 
        it->second.type != StorageEntryType::INTEGER || it->second.value.size() != 8) {
        return std::nullopt;
    }
    
    int64_t current = 0;
    for (int i = 0; i < 8; ++i) {
        current = (current << 8) | static_cast<int64_t>(it->second.value[i]);
    }
    
    int64_t new_val = current + delta;
    
    // Update value
    for (int i = 7; i >= 0; --i) {
        it->second.value[7 - i] = static_cast<uint8_t>(new_val >> (i * 8));
    }
    
    it->second.version = next_version();
    it->second.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    it->second.author_peer_id = client_.get_our_peer_id();
    it->second.checksum = calculate_checksum(it->second.value);
    
    StorageEntry entry_copy = it->second;
    lock.unlock();
    
    // Propagate
    broadcast_entry_change(entry_copy, false);
    
    return new_val;
}

bool DistributedStorage::set_nx(const std::string& key, const std::string& value) {
    std::unique_lock<std::shared_mutex> lock(storage_mutex_);
    
    auto it = storage_.find(key);
    if (it != storage_.end() && !it->second.is_deleted) {
        return false;  // Key exists
    }
    
    lock.unlock();
    return set(key, value);
}

bool DistributedStorage::compare_and_swap(const std::string& key, uint64_t expected_version, const std::string& new_value) {
    std::unique_lock<std::shared_mutex> lock(storage_mutex_);
    
    auto it = storage_.find(key);
    if (it == storage_.end() || it->second.is_deleted || it->second.version != expected_version) {
        return false;
    }
    
    lock.unlock();
    return set(key, new_value);
}

// =========================================================================
// Range Queries
// =========================================================================

std::vector<std::string> DistributedStorage::keys(const std::string& prefix) const {
    std::shared_lock<std::shared_mutex> lock(storage_mutex_);
    
    std::vector<std::string> result;
    
    if (prefix.empty()) {
        // Get all keys
        for (const auto& [k, v] : storage_) {
            if (!v.is_deleted) {
                result.push_back(k);
            }
        }
    } else {
        // Get keys with prefix
        auto it = storage_.lower_bound(prefix);
        while (it != storage_.end() && it->first.compare(0, prefix.size(), prefix) == 0) {
            if (!it->second.is_deleted) {
                result.push_back(it->first);
            }
            ++it;
        }
    }
    
    return result;
}

std::vector<StorageEntry> DistributedStorage::entries(const std::string& prefix) const {
    std::shared_lock<std::shared_mutex> lock(storage_mutex_);
    
    std::vector<StorageEntry> result;
    
    if (prefix.empty()) {
        for (const auto& [k, v] : storage_) {
            if (!v.is_deleted) {
                result.push_back(v);
            }
        }
    } else {
        auto it = storage_.lower_bound(prefix);
        while (it != storage_.end() && it->first.compare(0, prefix.size(), prefix) == 0) {
            if (!it->second.is_deleted) {
                result.push_back(it->second);
            }
            ++it;
        }
    }
    
    return result;
}

QueryResult DistributedStorage::query(const std::string& prefix, size_t limit, 
                                      const std::string& continuation_key) const {
    std::shared_lock<std::shared_mutex> lock(storage_mutex_);
    
    QueryResult result;
    result.has_more = false;
    
    auto it = continuation_key.empty() 
        ? storage_.lower_bound(prefix) 
        : storage_.upper_bound(continuation_key);
    
    size_t count = 0;
    while (it != storage_.end() && 
           (prefix.empty() || it->first.compare(0, prefix.size(), prefix) == 0)) {
        if (!it->second.is_deleted) {
            if (count >= limit) {
                result.has_more = true;
                result.continuation_key = result.entries.back().key;
                break;
            }
            result.entries.push_back(it->second);
            count++;
        }
        ++it;
    }
    
    return result;
}

std::vector<std::string> DistributedStorage::find_keys(const std::string& pattern) const {
    std::shared_lock<std::shared_mutex> lock(storage_mutex_);
    
    std::vector<std::string> result;
    
    try {
        std::regex regex_pattern(pattern);
        
        for (const auto& [k, v] : storage_) {
            if (!v.is_deleted && std::regex_match(k, regex_pattern)) {
                result.push_back(k);
            }
        }
    } catch (const std::regex_error& e) {
        LOG_STORAGE_ERROR("Invalid regex pattern '" << pattern << "': " << e.what());
    }
    
    return result;
}

size_t DistributedStorage::count(const std::string& prefix) const {
    std::shared_lock<std::shared_mutex> lock(storage_mutex_);
    
    size_t cnt = 0;
    
    if (prefix.empty()) {
        for (const auto& [k, v] : storage_) {
            if (!v.is_deleted) cnt++;
        }
    } else {
        auto it = storage_.lower_bound(prefix);
        while (it != storage_.end() && it->first.compare(0, prefix.size(), prefix) == 0) {
            if (!it->second.is_deleted) cnt++;
            ++it;
        }
    }
    
    return cnt;
}

uint64_t DistributedStorage::size_bytes() const {
    std::shared_lock<std::shared_mutex> lock(storage_mutex_);
    
    uint64_t total = 0;
    for (const auto& [k, v] : storage_) {
        if (!v.is_deleted) {
            total += k.size() + v.value.size() + sizeof(StorageEntry);
        }
    }
    
    return total;
}

// =========================================================================
// Bulk Operations
// =========================================================================

size_t DistributedStorage::set_bulk(const std::map<std::string, std::string>& entries) {
    size_t success_count = 0;
    for (const auto& [key, value] : entries) {
        if (set(key, value)) {
            success_count++;
        }
    }
    return success_count;
}

std::map<std::string, std::string> DistributedStorage::get_bulk(const std::vector<std::string>& keys) const {
    std::map<std::string, std::string> result;
    for (const auto& key : keys) {
        auto value = get_string(key);
        if (value) {
            result[key] = *value;
        }
    }
    return result;
}

size_t DistributedStorage::remove_bulk(const std::vector<std::string>& keys) {
    size_t success_count = 0;
    for (const auto& key : keys) {
        if (remove(key)) {
            success_count++;
        }
    }
    return success_count;
}

void DistributedStorage::clear(bool propagate) {
    std::vector<std::string> all_keys;
    
    {
        std::shared_lock<std::shared_mutex> lock(storage_mutex_);
        for (const auto& [k, v] : storage_) {
            if (!v.is_deleted) {
                all_keys.push_back(k);
            }
        }
    }
    
    for (const auto& key : all_keys) {
        remove_internal(key, propagate);
    }
    
    LOG_STORAGE_INFO("Cleared all entries (" << all_keys.size() << " keys)");
}

// =========================================================================
// Synchronization
// =========================================================================

void DistributedStorage::start_sync() {
    if (sync_running_.load()) {
        return;
    }
    
    sync_running_.store(true);
    
    sync_thread_ = std::thread(&DistributedStorage::sync_thread_loop, this);
    
    if (config_.auto_save && config_.persist_to_disk) {
        auto_save_thread_ = std::thread(&DistributedStorage::auto_save_thread_loop, this);
    }
    
    LOG_STORAGE_INFO("Sync started for storage: " << config_.storage_name);
}

void DistributedStorage::stop_sync() {
    if (!sync_running_.load()) {
        return;
    }
    
    sync_running_.store(false);
    sync_cv_.notify_all();
    
    if (sync_thread_.joinable()) {
        sync_thread_.join();
    }
    
    if (auto_save_thread_.joinable()) {
        auto_save_thread_.join();
    }
    
    LOG_STORAGE_INFO("Sync stopped for storage: " << config_.storage_name);
}

bool DistributedStorage::is_sync_running() const {
    return sync_running_.load();
}

void DistributedStorage::sync_thread_loop() {
    LOG_STORAGE_DEBUG("Sync thread started");
    
    while (sync_running_.load()) {
        std::unique_lock<std::mutex> lock(sync_mutex_);
        
        // Wait for sync interval or shutdown
        sync_cv_.wait_for(lock, std::chrono::seconds(config_.sync_interval_seconds), 
                         [this] { return !sync_running_.load(); });
        
        if (!sync_running_.load()) {
            break;
        }
        
        // Perform periodic sync with all peers
        sync_with_all_peers();
        
        // Cleanup expired entries
        cleanup_expired();
    }
    
    LOG_STORAGE_DEBUG("Sync thread stopped");
}

void DistributedStorage::auto_save_thread_loop() {
    LOG_STORAGE_DEBUG("Auto-save thread started");
    
    while (sync_running_.load()) {
        std::unique_lock<std::mutex> lock(sync_mutex_);
        
        sync_cv_.wait_for(lock, std::chrono::seconds(config_.auto_save_interval_seconds),
                         [this] { return !sync_running_.load(); });
        
        if (!sync_running_.load()) {
            break;
        }
        
        save_to_disk();
    }
    
    LOG_STORAGE_DEBUG("Auto-save thread stopped");
}

bool DistributedStorage::request_full_sync(const std::string& peer_id) {
    nlohmann::json sync_request;
    sync_request["action"] = "full_sync_request";
    sync_request["storage_name"] = config_.storage_name;
    sync_request["current_version"] = logical_clock_.load();
    sync_request["entry_count"] = count();
    
    client_.send(peer_id, "storage_sync", sync_request);
    
    LOG_STORAGE_INFO("Requested full sync from peer: " << peer_id);
    total_syncs_++;
    
    return true;
}

void DistributedStorage::sync_with_all_peers() {
    auto peers = client_.get_validated_peers();
    
    for (const auto& peer : peers) {
        request_full_sync(peer.peer_id);
    }
}

std::vector<StorageEntry> DistributedStorage::get_changes_since(uint64_t since_version) const {
    std::shared_lock<std::shared_mutex> lock(storage_mutex_);
    
    std::vector<StorageEntry> changes;
    
    for (const auto& [k, v] : storage_) {
        if (v.version > since_version) {
            changes.push_back(v);
        }
    }
    
    // Sort by version
    std::sort(changes.begin(), changes.end(), 
              [](const StorageEntry& a, const StorageEntry& b) {
                  return a.version < b.version;
              });
    
    return changes;
}

uint64_t DistributedStorage::get_current_version() const {
    return logical_clock_.load();
}

size_t DistributedStorage::merge_entries(const std::vector<StorageEntry>& entries) {
    size_t merged = 0;
    
    for (const auto& remote_entry : entries) {
        std::unique_lock<std::shared_mutex> lock(storage_mutex_);
        
        auto it = storage_.find(remote_entry.key);
        
        if (it == storage_.end()) {
            // New entry
            storage_[remote_entry.key] = remote_entry;
            
            // Update logical clock
            if (remote_entry.version > logical_clock_.load()) {
                logical_clock_.store(remote_entry.version);
            }
            
            merged++;
            
            // Notify change
            StorageChangeEvent event;
            event.key = remote_entry.key;
            event.new_entry = remote_entry;
            event.is_local = false;
            event.source_peer_id = remote_entry.author_peer_id;
            event.change_type = remote_entry.is_deleted ? 
                StorageChangeEvent::ChangeType::REMOVE : 
                StorageChangeEvent::ChangeType::INSERT;
            
            lock.unlock();
            notify_change(event);
        } else {
            // Conflict resolution
            StorageEntry& local_entry = it->second;
            
            if (remote_entry.is_newer_than(local_entry)) {
                StorageEntry resolved = resolve_conflict(local_entry, remote_entry);
                
                StorageChangeEvent event;
                event.key = remote_entry.key;
                event.old_entry = local_entry;
                event.new_entry = resolved;
                event.is_local = false;
                event.source_peer_id = remote_entry.author_peer_id;
                event.change_type = resolved.is_deleted ? 
                    StorageChangeEvent::ChangeType::REMOVE : 
                    StorageChangeEvent::ChangeType::UPDATE;
                
                storage_[remote_entry.key] = resolved;
                merged++;
                conflicts_resolved_++;
                
                // Update logical clock
                if (resolved.version > logical_clock_.load()) {
                    logical_clock_.store(resolved.version);
                }
                
                lock.unlock();
                notify_change(event);
            }
        }
    }
    
    return merged;
}

// =========================================================================
// Event Handlers
// =========================================================================

std::string DistributedStorage::on_change(const std::string& key_pattern, StorageChangeCallback callback) {
    std::lock_guard<std::mutex> lock(subscriptions_mutex_);
    
    Subscription sub;
    sub.id = generate_subscription_id();
    sub.pattern = key_pattern;
    sub.callback = callback;
    sub.is_regex = (key_pattern.find('*') != std::string::npos || 
                    key_pattern.find('?') != std::string::npos);
    
    change_subscriptions_.push_back(sub);
    
    return sub.id;
}

std::string DistributedStorage::on_any_change(StorageChangeCallback callback) {
    return on_change("*", callback);
}

std::string DistributedStorage::on_sync_progress(SyncProgressCallback callback) {
    std::lock_guard<std::mutex> lock(subscriptions_mutex_);
    
    std::string id = generate_subscription_id();
    sync_subscriptions_.emplace_back(id, callback);
    
    return id;
}

void DistributedStorage::off(const std::string& subscription_id) {
    std::lock_guard<std::mutex> lock(subscriptions_mutex_);
    
    // Remove from change subscriptions
    change_subscriptions_.erase(
        std::remove_if(change_subscriptions_.begin(), change_subscriptions_.end(),
                      [&subscription_id](const Subscription& s) { return s.id == subscription_id; }),
        change_subscriptions_.end());
    
    // Remove from sync subscriptions
    sync_subscriptions_.erase(
        std::remove_if(sync_subscriptions_.begin(), sync_subscriptions_.end(),
                      [&subscription_id](const auto& p) { return p.first == subscription_id; }),
        sync_subscriptions_.end());
}

void DistributedStorage::set_conflict_merge_callback(ConflictMergeCallback callback) {
    conflict_merge_callback_ = callback;
}

void DistributedStorage::notify_change(const StorageChangeEvent& event) {
    std::vector<StorageChangeCallback> callbacks_to_call;
    
    {
        std::lock_guard<std::mutex> lock(subscriptions_mutex_);
        
        for (const auto& sub : change_subscriptions_) {
            if (matches_pattern(event.key, sub.pattern)) {
                callbacks_to_call.push_back(sub.callback);
            }
        }
    }
    
    // Call callbacks outside of lock
    for (const auto& callback : callbacks_to_call) {
        try {
            callback(event);
        } catch (const std::exception& e) {
            LOG_STORAGE_ERROR("Exception in change callback: " << e.what());
        }
    }
}

void DistributedStorage::notify_sync_progress(const SyncProgress& progress) {
    std::vector<SyncProgressCallback> callbacks_to_call;
    
    {
        std::lock_guard<std::mutex> lock(subscriptions_mutex_);
        for (const auto& [id, callback] : sync_subscriptions_) {
            callbacks_to_call.push_back(callback);
        }
    }
    
    for (const auto& callback : callbacks_to_call) {
        try {
            callback(progress);
        } catch (const std::exception& e) {
            LOG_STORAGE_ERROR("Exception in sync progress callback: " << e.what());
        }
    }
}

bool DistributedStorage::matches_pattern(const std::string& key, const std::string& pattern) const {
    if (pattern == "*") {
        return true;
    }
    
    if (pattern.find('*') == std::string::npos && pattern.find('?') == std::string::npos) {
        return key == pattern;
    }
    
    // Convert wildcard pattern to regex
    std::string regex_pattern;
    for (char c : pattern) {
        switch (c) {
            case '*': regex_pattern += ".*"; break;
            case '?': regex_pattern += "."; break;
            case '.': case '^': case '$': case '+':
            case '(': case ')': case '[': case ']':
            case '{': case '}': case '|': case '\\':
                regex_pattern += '\\';
                regex_pattern += c;
                break;
            default:
                regex_pattern += c;
        }
    }
    
    try {
        return std::regex_match(key, std::regex(regex_pattern));
    } catch (...) {
        return false;
    }
}

// =========================================================================
// Persistence
// =========================================================================

bool DistributedStorage::save_to_disk() {
    if (!ensure_storage_directory()) {
        LOG_STORAGE_ERROR("Failed to create storage directory");
        return false;
    }
    
    std::string path = get_storage_path();
    
    nlohmann::json data = export_to_json();
    
    try {
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) {
            LOG_STORAGE_ERROR("Failed to open file for writing: " << path);
            return false;
        }
        
        std::string content = data.dump(2);
        file.write(content.c_str(), content.size());
        file.close();
        
        LOG_STORAGE_DEBUG("Saved " << count() << " entries to disk: " << path);
        return true;
    } catch (const std::exception& e) {
        LOG_STORAGE_ERROR("Failed to save to disk: " << e.what());
        return false;
    }
}

bool DistributedStorage::load_from_disk() {
    std::string path = get_storage_path();
    
    if (!file_exists(path)) {
        LOG_STORAGE_DEBUG("No storage file found at: " << path);
        return true;  // Not an error, just no saved data
    }
    
    try {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            LOG_STORAGE_ERROR("Failed to open file for reading: " << path);
            return false;
        }
        
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();
        
        nlohmann::json data = nlohmann::json::parse(content);
        import_from_json(data, false);  // Replace existing data
        
        LOG_STORAGE_INFO("Loaded " << count() << " entries from disk: " << path);
        return true;
    } catch (const std::exception& e) {
        LOG_STORAGE_ERROR("Failed to load from disk: " << e.what());
        return false;
    }
}

nlohmann::json DistributedStorage::export_to_json() const {
    std::shared_lock<std::shared_mutex> lock(storage_mutex_);
    
    nlohmann::json data;
    data["storage_name"] = config_.storage_name;
    data["version"] = logical_clock_.load();
    data["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    nlohmann::json entries_json = nlohmann::json::array();
    for (const auto& [k, v] : storage_) {
        entries_json.push_back(v.to_json());
    }
    data["entries"] = entries_json;
    
    return data;
}

size_t DistributedStorage::import_from_json(const nlohmann::json& data, bool merge) {
    std::unique_lock<std::shared_mutex> lock(storage_mutex_);
    
    if (!merge) {
        storage_.clear();
    }
    
    size_t imported = 0;
    
    if (data.contains("entries") && data["entries"].is_array()) {
        for (const auto& entry_json : data["entries"]) {
            StorageEntry entry = StorageEntry::from_json(entry_json);
            
            if (merge) {
                auto it = storage_.find(entry.key);
                if (it != storage_.end() && !entry.is_newer_than(it->second)) {
                    continue;  // Skip older entries
                }
            }
            
            storage_[entry.key] = entry;
            imported++;
            
            // Update logical clock
            if (entry.version > logical_clock_.load()) {
                logical_clock_.store(entry.version);
            }
        }
    }
    
    if (data.contains("version")) {
        uint64_t imported_version = data["version"].get<uint64_t>();
        if (imported_version > logical_clock_.load()) {
            logical_clock_.store(imported_version);
        }
    }
    
    return imported;
}

std::string DistributedStorage::get_storage_path() const {
    if (!config_.storage_path.empty()) {
        return config_.storage_path;
    }
    return get_default_storage_path();
}

std::string DistributedStorage::get_default_storage_path() const {
    std::string data_dir = client_.get_data_directory();
    if (data_dir.empty()) {
        data_dir = ".";
    }
    return data_dir + "/" + config_.storage_name + ".db";
}

bool DistributedStorage::ensure_storage_directory() const {
    std::string path = get_storage_path();
    size_t last_sep = path.find_last_of("/\\");
    if (last_sep != std::string::npos) {
        std::string dir = path.substr(0, last_sep);
        return create_directories(dir.c_str());
    }
    return true;
}

// =========================================================================
// Statistics
// =========================================================================

nlohmann::json DistributedStorage::get_statistics() const {
    nlohmann::json stats;
    
    stats["storage_name"] = config_.storage_name;
    stats["entry_count"] = count();
    stats["size_bytes"] = size_bytes();
    stats["current_version"] = logical_clock_.load();
    stats["sync_running"] = sync_running_.load();
    
    stats["operations"] = {
        {"total_sets", total_sets_.load()},
        {"total_gets", total_gets_.load()},
        {"total_deletes", total_deletes_.load()},
        {"total_syncs", total_syncs_.load()},
        {"conflicts_resolved", conflicts_resolved_.load()}
    };
    
    // Count tombstones
    size_t tombstone_count = 0;
    {
        std::shared_lock<std::shared_mutex> lock(storage_mutex_);
        for (const auto& [k, v] : storage_) {
            if (v.is_deleted) tombstone_count++;
        }
    }
    stats["tombstone_count"] = tombstone_count;
    
    return stats;
}

size_t DistributedStorage::cleanup_expired() {
    std::unique_lock<std::shared_mutex> lock(storage_mutex_);
    
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    uint64_t tombstone_ttl_ms = config_.tombstone_ttl_seconds * 1000;
    
    std::vector<std::string> keys_to_remove;
    
    for (const auto& [k, v] : storage_) {
        // Remove old tombstones
        if (v.is_deleted && (now - v.deleted_at) > tombstone_ttl_ms) {
            keys_to_remove.push_back(k);
        }
    }
    
    for (const auto& key : keys_to_remove) {
        storage_.erase(key);
    }
    
    if (!keys_to_remove.empty()) {
        LOG_STORAGE_DEBUG("Cleaned up " << keys_to_remove.size() << " expired entries");
    }
    
    return keys_to_remove.size();
}

// =========================================================================
// Private Methods
// =========================================================================

StorageEntry DistributedStorage::resolve_conflict(const StorageEntry& local, const StorageEntry& remote) {
    switch (config_.conflict_resolution) {
        case ConflictResolution::LAST_WRITE_WINS:
            return remote.is_newer_than(local) ? remote : local;
            
        case ConflictResolution::HIGHEST_VERSION:
            return remote.version > local.version ? remote : local;
            
        case ConflictResolution::CUSTOM_MERGE:
            if (conflict_merge_callback_) {
                return conflict_merge_callback_(local, remote);
            }
            // Fall through to LWW if no callback
            return remote.is_newer_than(local) ? remote : local;
            
        case ConflictResolution::REJECT_CONFLICT:
            return local;  // Keep local
            
        default:
            return remote.is_newer_than(local) ? remote : local;
    }
}

void DistributedStorage::broadcast_entry_change(const StorageEntry& entry, bool is_delete) {
    if (!config_.auto_sync) {
        return;
    }
    
    nlohmann::json message;
    message["action"] = is_delete ? "entry_delete" : "entry_update";
    message["storage_name"] = config_.storage_name;
    message["entry"] = entry.to_json();
    
    if (config_.use_gossipsub && client_.is_gossipsub_available()) {
        client_.publish_json_to_topic(config_.gossipsub_topic, message);
    } else {
        // Direct broadcast to all peers
        client_.send("storage_update", message);
    }
}

void DistributedStorage::register_message_handlers() {
    // Register handler for storage sync messages
    client_.on("storage_sync", [this](const std::string& peer_id, const nlohmann::json& data) {
        std::string action = data.value("action", "");
        std::string storage_name = data.value("storage_name", "");
        
        if (storage_name != config_.storage_name) {
            return;  // Not for this storage
        }
        
        if (action == "full_sync_request") {
            handle_sync_request(peer_id, data);
        } else if (action == "full_sync_response") {
            handle_sync_response(peer_id, data);
        } else if (action == "bulk_sync") {
            handle_bulk_sync(peer_id, data);
        }
    });
    
    // Register handler for storage updates
    client_.on("storage_update", [this](const std::string& peer_id, const nlohmann::json& data) {
        std::string action = data.value("action", "");
        std::string storage_name = data.value("storage_name", "");
        
        if (storage_name != config_.storage_name) {
            return;
        }
        
        if (action == "entry_update") {
            handle_entry_update(peer_id, data);
        } else if (action == "entry_delete") {
            handle_entry_delete(peer_id, data);
        }
    });
    
    // Subscribe to GossipSub topic if enabled
    if (config_.use_gossipsub && client_.is_gossipsub_available()) {
        client_.on_topic_json_message(config_.gossipsub_topic, 
            [this](const std::string& peer_id, const std::string& topic, const nlohmann::json& message) {
                std::string action = message.value("action", "");
                std::string storage_name = message.value("storage_name", "");
                
                if (storage_name != config_.storage_name) {
                    return;
                }
                
                if (action == "entry_update") {
                    handle_entry_update(peer_id, message);
                } else if (action == "entry_delete") {
                    handle_entry_delete(peer_id, message);
                }
            });
    }
}

void DistributedStorage::unregister_message_handlers() {
    client_.off("storage_sync");
    client_.off("storage_update");
    
    if (config_.use_gossipsub) {
        client_.off_topic(config_.gossipsub_topic);
    }
}

void DistributedStorage::handle_sync_request(const std::string& peer_id, const nlohmann::json& message) {
    LOG_STORAGE_INFO("Received sync request from peer: " << peer_id);
    
    uint64_t peer_version = message.value("current_version", 0ULL);
    
    // Get entries that the peer doesn't have
    std::vector<StorageEntry> changes = get_changes_since(peer_version);
    
    // Send in batches
    size_t batch_size = config_.sync_batch_size;
    size_t total_entries = changes.size();
    
    for (size_t i = 0; i < changes.size(); i += batch_size) {
        nlohmann::json response;
        response["action"] = "bulk_sync";
        response["storage_name"] = config_.storage_name;
        response["batch_index"] = i / batch_size;
        response["total_batches"] = (changes.size() + batch_size - 1) / batch_size;
        
        nlohmann::json entries_json = nlohmann::json::array();
        for (size_t j = i; j < (std::min)(i + batch_size, changes.size()); ++j) {
            entries_json.push_back(changes[j].to_json());
        }
        response["entries"] = entries_json;
        response["current_version"] = logical_clock_.load();
        
        client_.send(peer_id, "storage_sync", response);
    }
    
    // Notify progress
    SyncProgress progress;
    progress.peer_id = peer_id;
    progress.mode = SyncMode::FULL_SYNC;
    progress.entries_synced = total_entries;
    progress.total_entries = total_entries;
    progress.is_complete = true;
    notify_sync_progress(progress);
}

void DistributedStorage::handle_sync_response(const std::string& peer_id, const nlohmann::json& message) {
    // Legacy handler - kept for compatibility
    handle_bulk_sync(peer_id, message);
}

void DistributedStorage::handle_bulk_sync(const std::string& peer_id, const nlohmann::json& message) {
    LOG_STORAGE_DEBUG("Received bulk sync from peer: " << peer_id);
    
    std::vector<StorageEntry> entries;
    
    if (message.contains("entries") && message["entries"].is_array()) {
        for (const auto& entry_json : message["entries"]) {
            entries.push_back(StorageEntry::from_json(entry_json));
        }
    }
    
    size_t merged = merge_entries(entries);
    
    // Notify progress
    SyncProgress progress;
    progress.peer_id = peer_id;
    progress.mode = SyncMode::INCREMENTAL;
    progress.entries_synced = merged;
    progress.total_entries = entries.size();
    progress.is_complete = true;
    notify_sync_progress(progress);
    
    LOG_STORAGE_INFO("Merged " << merged << " entries from peer: " << peer_id);
}

void DistributedStorage::handle_entry_update(const std::string& peer_id, const nlohmann::json& message) {
    if (!message.contains("entry")) {
        return;
    }
    
    StorageEntry remote_entry = StorageEntry::from_json(message["entry"]);
    
    std::vector<StorageEntry> entries = {remote_entry};
    merge_entries(entries);
}

void DistributedStorage::handle_entry_delete(const std::string& peer_id, const nlohmann::json& message) {
    // Delete is handled the same as update (tombstone)
    handle_entry_update(peer_id, message);
}

std::string DistributedStorage::generate_subscription_id() const {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::ostringstream ss;
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << dis(gen);
    }
    
    return ss.str();
}

std::string DistributedStorage::calculate_checksum(const std::vector<uint8_t>& data) const {
    return SHA1::hash(std::string(data.begin(), data.end()));
}

uint64_t DistributedStorage::next_version() {
    return ++logical_clock_;
}

} // namespace librats

