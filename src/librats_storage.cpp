#include "librats.h"

#ifdef RATS_STORAGE

#include "storage.h"
#include "logger.h"

namespace librats {

//=============================================================================
// Storage Manager Access
//=============================================================================

StorageManager& RatsClient::get_storage_manager() {
    if (!storage_manager_) {
        // Initialize storage manager on first access
        StorageConfig config;
        config.data_directory = data_directory_.empty() ? "./storage" : data_directory_ + "/storage";
        storage_manager_ = std::make_unique<StorageManager>(*this, config);
    }
    return *storage_manager_;
}

bool RatsClient::is_storage_available() const {
    return storage_manager_ != nullptr;
}

//=============================================================================
// Put Operations
//=============================================================================

bool RatsClient::storage_put(const std::string& key, const std::string& value) {
    return get_storage_manager().put(key, value);
}

bool RatsClient::storage_put(const std::string& key, int64_t value) {
    return get_storage_manager().put(key, value);
}

bool RatsClient::storage_put(const std::string& key, double value) {
    return get_storage_manager().put(key, value);
}

bool RatsClient::storage_put(const std::string& key, const std::vector<uint8_t>& value) {
    return get_storage_manager().put(key, value);
}

bool RatsClient::storage_put_json(const std::string& key, const nlohmann::json& value) {
    return get_storage_manager().put_json(key, value);
}

//=============================================================================
// Get Operations
//=============================================================================

std::optional<std::string> RatsClient::storage_get_string(const std::string& key) const {
    if (!storage_manager_) {
        return std::nullopt;
    }
    return storage_manager_->get_string(key);
}

std::optional<int64_t> RatsClient::storage_get_int(const std::string& key) const {
    if (!storage_manager_) {
        return std::nullopt;
    }
    return storage_manager_->get_int(key);
}

std::optional<double> RatsClient::storage_get_double(const std::string& key) const {
    if (!storage_manager_) {
        return std::nullopt;
    }
    return storage_manager_->get_double(key);
}

std::optional<std::vector<uint8_t>> RatsClient::storage_get_binary(const std::string& key) const {
    if (!storage_manager_) {
        return std::nullopt;
    }
    return storage_manager_->get_binary(key);
}

std::optional<nlohmann::json> RatsClient::storage_get_json(const std::string& key) const {
    if (!storage_manager_) {
        return std::nullopt;
    }
    return storage_manager_->get_json(key);
}

//=============================================================================
// Delete and Query Operations
//=============================================================================

bool RatsClient::storage_delete(const std::string& key) {
    if (!storage_manager_) {
        return false;
    }
    return storage_manager_->remove(key);
}

bool RatsClient::storage_has(const std::string& key) const {
    if (!storage_manager_) {
        return false;
    }
    return storage_manager_->has(key);
}

std::vector<std::string> RatsClient::storage_keys() const {
    if (!storage_manager_) {
        return {};
    }
    return storage_manager_->keys();
}

std::vector<std::string> RatsClient::storage_keys_with_prefix(const std::string& prefix) const {
    if (!storage_manager_) {
        return {};
    }
    return storage_manager_->keys_with_prefix(prefix);
}

size_t RatsClient::storage_size() const {
    if (!storage_manager_) {
        return 0;
    }
    return storage_manager_->size();
}

//=============================================================================
// Synchronization
//=============================================================================

bool RatsClient::storage_request_sync() {
    return get_storage_manager().request_sync();
}

bool RatsClient::is_storage_synced() const {
    if (!storage_manager_) {
        return false;
    }
    return storage_manager_->is_synced();
}

//=============================================================================
// Statistics and Configuration
//=============================================================================

nlohmann::json RatsClient::get_storage_statistics() const {
    if (!storage_manager_) {
        nlohmann::json empty;
        empty["available"] = false;
        return empty;
    }
    
    nlohmann::json stats = storage_manager_->get_statistics_json();
    stats["available"] = true;
    return stats;
}

void RatsClient::set_storage_config(const StorageConfig& config) {
    get_storage_manager().set_config(config);
}

const StorageConfig& RatsClient::get_storage_config() const {
    // Need to ensure storage manager exists for this call
    // Create a static default config to return if not available
    static StorageConfig default_config;
    if (!storage_manager_) {
        return default_config;
    }
    return storage_manager_->get_config();
}

//=============================================================================
// Event Handlers
//=============================================================================

void RatsClient::on_storage_change(StorageChangeCallback callback) {
    get_storage_manager().set_change_callback(callback);
}

void RatsClient::on_storage_sync_complete(StorageSyncCompleteCallback callback) {
    get_storage_manager().set_sync_complete_callback(callback);
}

} // namespace librats

#endif // RATS_STORAGE
