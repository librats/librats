#include "librats.h"
#include "distributed_storage.h"
#include "logger.h"
#include <memory>

namespace librats {

// Logging macros
#define LOG_STORAGE_CLIENT_DEBUG(message) LOG_DEBUG("storage-client", message)
#define LOG_STORAGE_CLIENT_INFO(message)  LOG_INFO("storage-client", message)
#define LOG_STORAGE_CLIENT_WARN(message)  LOG_WARN("storage-client", message)
#define LOG_STORAGE_CLIENT_ERROR(message) LOG_ERROR("storage-client", message)

// =========================================================================
// Storage Management (stored in RatsClient as unique_ptr map)
// =========================================================================

// Thread-local storage map for distributed storages
static std::mutex storage_map_mutex;
static std::unordered_map<const RatsClient*, std::unordered_map<std::string, std::unique_ptr<DistributedStorage>>> storage_map;

// Helper to get or create storage instance
static DistributedStorage* get_or_create_storage(RatsClient& client, const std::string& name, 
                                                  const DistributedStorageConfig* config = nullptr) {
    std::lock_guard<std::mutex> lock(storage_map_mutex);
    
    auto& client_storages = storage_map[&client];
    auto it = client_storages.find(name);
    
    if (it != client_storages.end()) {
        return it->second.get();
    }
    
    // Create new storage
    DistributedStorageConfig storage_config;
    if (config) {
        storage_config = *config;
    }
    storage_config.storage_name = name;
    
    auto storage = std::make_unique<DistributedStorage>(client, storage_config);
    DistributedStorage* ptr = storage.get();
    client_storages[name] = std::move(storage);
    
    LOG_STORAGE_CLIENT_INFO("Created distributed storage: " << name);
    
    return ptr;
}

static DistributedStorage* get_storage(const RatsClient& client, const std::string& name) {
    std::lock_guard<std::mutex> lock(storage_map_mutex);
    
    auto client_it = storage_map.find(&client);
    if (client_it == storage_map.end()) {
        return nullptr;
    }
    
    auto& client_storages = client_it->second;
    auto it = client_storages.find(name);
    
    return (it != client_storages.end()) ? it->second.get() : nullptr;
}

static void cleanup_client_storages(const RatsClient& client) {
    std::lock_guard<std::mutex> lock(storage_map_mutex);
    storage_map.erase(&client);
}

// =========================================================================
// RatsClient Distributed Storage API Implementation
// =========================================================================

DistributedStorage& RatsClient::get_distributed_storage(const std::string& name) {
    auto* storage = get_or_create_storage(*this, name);
    return *storage;
}

DistributedStorage* RatsClient::get_distributed_storage_ptr(const std::string& name) const {
    return get_storage(*this, name);
}

bool RatsClient::has_distributed_storage(const std::string& name) const {
    return get_storage(*this, name) != nullptr;
}

DistributedStorage& RatsClient::create_distributed_storage(const std::string& name, 
                                                           const DistributedStorageConfig& config) {
    DistributedStorageConfig storage_config = config;
    storage_config.storage_name = name;
    
    auto* storage = get_or_create_storage(*this, name, &storage_config);
    return *storage;
}

bool RatsClient::destroy_distributed_storage(const std::string& name) {
    std::lock_guard<std::mutex> lock(storage_map_mutex);
    
    auto client_it = storage_map.find(this);
    if (client_it == storage_map.end()) {
        return false;
    }
    
    auto& client_storages = client_it->second;
    auto it = client_storages.find(name);
    
    if (it == client_storages.end()) {
        return false;
    }
    
    client_storages.erase(it);
    LOG_STORAGE_CLIENT_INFO("Destroyed distributed storage: " << name);
    
    return true;
}

std::vector<std::string> RatsClient::get_distributed_storage_names() const {
    std::lock_guard<std::mutex> lock(storage_map_mutex);
    
    std::vector<std::string> names;
    
    auto client_it = storage_map.find(this);
    if (client_it != storage_map.end()) {
        for (const auto& [name, storage] : client_it->second) {
            names.push_back(name);
        }
    }
    
    return names;
}

nlohmann::json RatsClient::get_distributed_storage_statistics() const {
    std::lock_guard<std::mutex> lock(storage_map_mutex);
    
    nlohmann::json stats;
    stats["storages"] = nlohmann::json::array();
    
    auto client_it = storage_map.find(this);
    if (client_it != storage_map.end()) {
        for (const auto& [name, storage] : client_it->second) {
            nlohmann::json storage_stats = storage->get_statistics();
            stats["storages"].push_back(storage_stats);
        }
    }
    
    stats["total_storages"] = stats["storages"].size();
    
    return stats;
}

// =========================================================================
// Convenience Methods for Default Storage
// =========================================================================

bool RatsClient::storage_set(const std::string& key, const std::string& value, 
                            const std::string& storage_name) {
    auto& storage = get_distributed_storage(storage_name);
    return storage.set(key, value);
}

bool RatsClient::storage_set(const std::string& key, const nlohmann::json& value,
                            const std::string& storage_name) {
    auto& storage = get_distributed_storage(storage_name);
    return storage.set(key, value);
}

bool RatsClient::storage_set(const std::string& key, const std::vector<uint8_t>& value,
                            const std::string& storage_name) {
    auto& storage = get_distributed_storage(storage_name);
    return storage.set(key, value);
}

std::optional<std::string> RatsClient::storage_get_string(const std::string& key,
                                                          const std::string& storage_name) const {
    auto* storage = get_distributed_storage_ptr(storage_name);
    if (!storage) {
        return std::nullopt;
    }
    return storage->get_string(key);
}

std::optional<nlohmann::json> RatsClient::storage_get_json(const std::string& key,
                                                           const std::string& storage_name) const {
    auto* storage = get_distributed_storage_ptr(storage_name);
    if (!storage) {
        return std::nullopt;
    }
    return storage->get_json(key);
}

std::optional<std::vector<uint8_t>> RatsClient::storage_get_binary(const std::string& key,
                                                                    const std::string& storage_name) const {
    auto* storage = get_distributed_storage_ptr(storage_name);
    if (!storage) {
        return std::nullopt;
    }
    return storage->get_binary(key);
}

bool RatsClient::storage_remove(const std::string& key, const std::string& storage_name) {
    auto* storage = get_distributed_storage_ptr(storage_name);
    if (!storage) {
        return false;
    }
    return storage->remove(key);
}

bool RatsClient::storage_exists(const std::string& key, const std::string& storage_name) const {
    auto* storage = get_distributed_storage_ptr(storage_name);
    if (!storage) {
        return false;
    }
    return storage->exists(key);
}

std::vector<std::string> RatsClient::storage_keys(const std::string& prefix,
                                                   const std::string& storage_name) const {
    auto* storage = get_distributed_storage_ptr(storage_name);
    if (!storage) {
        return {};
    }
    return storage->keys(prefix);
}

size_t RatsClient::storage_count(const std::string& prefix, const std::string& storage_name) const {
    auto* storage = get_distributed_storage_ptr(storage_name);
    if (!storage) {
        return 0;
    }
    return storage->count(prefix);
}

void RatsClient::storage_sync_with_peer(const std::string& peer_id, const std::string& storage_name) {
    auto* storage = get_distributed_storage_ptr(storage_name);
    if (storage) {
        storage->request_full_sync(peer_id);
    }
}

void RatsClient::storage_sync_all(const std::string& storage_name) {
    auto* storage = get_distributed_storage_ptr(storage_name);
    if (storage) {
        storage->sync_with_all_peers();
    }
}

std::string RatsClient::storage_on_change(const std::string& key_pattern, 
                                          StorageChangeCallback callback,
                                          const std::string& storage_name) {
    auto& storage = get_distributed_storage(storage_name);
    return storage.on_change(key_pattern, callback);
}

void RatsClient::storage_off_change(const std::string& subscription_id,
                                    const std::string& storage_name) {
    auto* storage = get_distributed_storage_ptr(storage_name);
    if (storage) {
        storage->off(subscription_id);
    }
}

// =========================================================================
// Cleanup Hook (should be called from RatsClient destructor)
// =========================================================================

void cleanup_distributed_storages_for_client(const RatsClient& client) {
    cleanup_client_storages(client);
}

} // namespace librats

