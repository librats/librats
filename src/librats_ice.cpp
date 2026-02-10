/**
 * @file librats_ice.cpp
 * @brief ICE (NAT Traversal) API implementation for RatsClient
 * 
 * Provides STUN/TURN/ICE functionality for NAT traversal and public address discovery.
 */

#include "librats.h"
#include "logger.h"

namespace librats {

// ============================================================================
// ICE Manager Access
// ============================================================================

IceManager& RatsClient::get_ice_manager() {
    if (!ice_manager_) {
        ice_manager_ = std::make_unique<IceManager>();
    }
    return *ice_manager_;
}

bool RatsClient::is_ice_available() const {
    return ice_manager_ != nullptr;
}

// ============================================================================
// Server Configuration
// ============================================================================

void RatsClient::add_stun_server(const std::string& host, uint16_t port) {
    get_ice_manager().add_stun_server(host, port);
    LOG_INFO("ice", "Added STUN server: " << host << ":" << port);
}

void RatsClient::add_turn_server(const std::string& host, uint16_t port,
                                  const std::string& username, const std::string& password) {
    get_ice_manager().add_turn_server(host, port, username, password);
    LOG_INFO("ice", "Added TURN server: " << host << ":" << port);
}

void RatsClient::clear_ice_servers() {
    get_ice_manager().clear_ice_servers();
    LOG_DEBUG("ice", "Cleared all ICE servers");
}

// ============================================================================
// Candidate Gathering
// ============================================================================

bool RatsClient::gather_ice_candidates() {
    LOG_INFO("ice", "Starting ICE candidate gathering");
    return get_ice_manager().gather_candidates();
}

std::vector<IceCandidate> RatsClient::get_ice_candidates() const {
    if (!ice_manager_) {
        return {};
    }
    return ice_manager_->get_local_candidates();
}

bool RatsClient::is_ice_gathering_complete() const {
    if (!ice_manager_) {
        return false;
    }
    return ice_manager_->is_gathering_complete();
}

// ============================================================================
// Public Address Discovery
// ============================================================================

std::optional<std::pair<std::string, uint16_t>> RatsClient::get_public_address() const {
    if (!ice_manager_) {
        return std::nullopt;
    }
    return ice_manager_->get_public_address();
}

std::optional<StunMappedAddress> RatsClient::discover_public_address(
    const std::string& server,
    uint16_t port,
    int timeout_ms) {
    
    LOG_INFO("ice", "Discovering public address via STUN: " << server << ":" << port);
    
    StunClient stun_client;
    auto result = stun_client.binding_request(server, port, timeout_ms);
    
    if (result.success && result.mapped_address) {
        LOG_INFO("ice", "Discovered public address: " << result.mapped_address->to_string());
        return result.mapped_address;
    }
    
    LOG_WARN("ice", "Failed to discover public address via STUN");
    return std::nullopt;
}

// ============================================================================
// Remote Candidates
// ============================================================================

void RatsClient::add_remote_ice_candidate(const IceCandidate& candidate) {
    get_ice_manager().add_remote_candidate(candidate);
}

void RatsClient::add_remote_ice_candidates_from_sdp(const std::vector<std::string>& sdp_lines) {
    get_ice_manager().add_remote_candidates_from_sdp(sdp_lines);
}

void RatsClient::end_of_remote_ice_candidates() {
    get_ice_manager().end_of_remote_candidates();
}

// ============================================================================
// Connectivity
// ============================================================================

void RatsClient::start_ice_checks() {
    LOG_INFO("ice", "Starting ICE connectivity checks");
    get_ice_manager().start_checks();
}

IceConnectionState RatsClient::get_ice_connection_state() const {
    if (!ice_manager_) {
        return IceConnectionState::New;
    }
    return ice_manager_->get_connection_state();
}

IceGatheringState RatsClient::get_ice_gathering_state() const {
    if (!ice_manager_) {
        return IceGatheringState::New;
    }
    return ice_manager_->get_gathering_state();
}

bool RatsClient::is_ice_connected() const {
    if (!ice_manager_) {
        return false;
    }
    return ice_manager_->is_connected();
}

std::optional<IceCandidatePair> RatsClient::get_ice_selected_pair() const {
    if (!ice_manager_) {
        return std::nullopt;
    }
    return ice_manager_->get_selected_pair();
}

// ============================================================================
// Event Callbacks
// ============================================================================

void RatsClient::on_ice_candidates_gathered(IceCandidatesCallback callback) {
    get_ice_manager().set_on_candidates_gathered(std::move(callback));
}

void RatsClient::on_ice_new_candidate(IceNewCandidateCallback callback) {
    get_ice_manager().set_on_new_candidate(std::move(callback));
}

void RatsClient::on_ice_gathering_state_changed(IceGatheringStateCallback callback) {
    get_ice_manager().set_on_gathering_state_changed(std::move(callback));
}

void RatsClient::on_ice_connection_state_changed(IceConnectionStateCallback callback) {
    get_ice_manager().set_on_connection_state_changed(std::move(callback));
}

void RatsClient::on_ice_selected_pair(IceSelectedPairCallback callback) {
    get_ice_manager().set_on_selected_pair(std::move(callback));
}

// ============================================================================
// Configuration
// ============================================================================

void RatsClient::set_ice_config(const IceConfig& config) {
    get_ice_manager().set_config(config);
}

IceConfig RatsClient::get_ice_config() const {
    // Need to cast away const to get mutable reference for lazy initialization
    return const_cast<RatsClient*>(this)->get_ice_manager().config();
}

// ============================================================================
// Lifecycle
// ============================================================================

void RatsClient::close_ice() {
    if (ice_manager_) {
        ice_manager_->close();
        LOG_INFO("ice", "ICE manager closed");
    }
}

void RatsClient::restart_ice() {
    if (ice_manager_) {
        LOG_INFO("ice", "Restarting ICE");
        ice_manager_->restart();
    }
}

} // namespace librats
