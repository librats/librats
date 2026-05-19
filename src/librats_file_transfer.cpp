#include "librats.h"
#include "librats_log_macros.h"

namespace librats {

// =============================================================================
// File transfer API - thin forwarding layer over FileTransferManager
// =============================================================================

FileTransferManager& RatsClient::get_file_transfer_manager() {
    if (!file_transfer_manager_) {
        throw std::runtime_error("File transfer manager not initialized");
    }
    return *file_transfer_manager_;
}

bool RatsClient::is_file_transfer_available() const {
    return file_transfer_manager_ != nullptr;
}

std::string RatsClient::send_file(const std::string& peer_id, const std::string& file_path,
                                  const std::string& remote_filename) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return "";
    }
    return file_transfer_manager_->send_file(peer_id, file_path, remote_filename);
}

std::string RatsClient::send_directory(const std::string& peer_id, const std::string& directory_path,
                                       const std::string& remote_name) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return "";
    }
    return file_transfer_manager_->send_directory(peer_id, directory_path, remote_name);
}

bool RatsClient::accept_file_transfer(const std::string& transfer_id, const std::string& local_path) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return false;
    }
    return file_transfer_manager_->accept(transfer_id, local_path);
}

bool RatsClient::reject_file_transfer(const std::string& transfer_id, const std::string& reason) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return false;
    }
    return file_transfer_manager_->reject(transfer_id, reason);
}

bool RatsClient::pause_file_transfer(const std::string& transfer_id) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return false;
    }
    return file_transfer_manager_->pause(transfer_id);
}

bool RatsClient::resume_file_transfer(const std::string& transfer_id) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return false;
    }
    return file_transfer_manager_->resume(transfer_id);
}

bool RatsClient::cancel_file_transfer(const std::string& transfer_id) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return false;
    }
    return file_transfer_manager_->cancel(transfer_id);
}

std::shared_ptr<FileTransferProgress>
RatsClient::get_file_transfer_progress(const std::string& transfer_id) const {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return nullptr;
    }
    return file_transfer_manager_->get_progress(transfer_id);
}

std::vector<std::shared_ptr<FileTransferProgress>>
RatsClient::get_active_file_transfers() const {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return {};
    }
    return file_transfer_manager_->get_active_transfers();
}

nlohmann::json RatsClient::get_file_transfer_statistics() const {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return nlohmann::json::object();
    }
    return file_transfer_manager_->get_statistics();
}

void RatsClient::set_file_transfer_config(const FileTransferConfig& config) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return;
    }
    file_transfer_manager_->set_config(config);
}

FileTransferConfig RatsClient::get_file_transfer_config() const {
    if (!is_file_transfer_available()) {
        throw std::runtime_error("File transfer manager not available");
    }
    return file_transfer_manager_->get_config();
}

void RatsClient::on_file_transfer_progress(TransferProgressCallback callback) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return;
    }
    file_transfer_manager_->set_progress_callback(std::move(callback));
}

void RatsClient::on_file_transfer_completed(TransferCompletedCallback callback) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return;
    }
    file_transfer_manager_->set_completed_callback(std::move(callback));
}

void RatsClient::on_file_transfer_request(TransferOfferCallback callback) {
    if (!is_file_transfer_available()) {
        LOG_CLIENT_ERROR("File transfer manager not available");
        return;
    }
    file_transfer_manager_->set_offer_callback(std::move(callback));
}

} // namespace librats
