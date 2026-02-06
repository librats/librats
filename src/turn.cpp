/**
 * @file turn.cpp
 * @brief TURN (Traversal Using Relays around NAT) Client Implementation
 * 
 * Implements RFC 5766 - TURN protocol for NAT traversal via relay.
 */

#include "turn.h"
#include "logger.h"
#include "network_utils.h"
#include <cstring>
#include <algorithm>

namespace librats {

// ============================================================================
// Logging Macros
// ============================================================================

#define LOG_TURN_DEBUG(msg) LOG_DEBUG("turn", msg)
#define LOG_TURN_INFO(msg) LOG_INFO("turn", msg)
#define LOG_TURN_WARN(msg) LOG_WARN("turn", msg)
#define LOG_TURN_ERROR(msg) LOG_ERROR("turn", msg)

// ============================================================================
// TurnClient Implementation
// ============================================================================

TurnClient::TurnClient() = default;

TurnClient::TurnClient(const TurnClientConfig& config) : config_(config) {}

TurnClient::~TurnClient() {
    close();
}

TurnClient::TurnClient(TurnClient&& other) noexcept
    : config_(std::move(other.config_)),
      socket_(other.socket_),
      stun_client_(std::move(other.stun_client_)),
      state_(other.state_),
      allocation_(std::move(other.allocation_)),
      nonce_(std::move(other.nonce_)),
      realm_(std::move(other.realm_)),
      permissions_(std::move(other.permissions_)),
      channels_(std::move(other.channels_)),
      peer_to_channel_(std::move(other.peer_to_channel_)),
      next_channel_(other.next_channel_),
      data_callback_(std::move(other.data_callback_)),
      state_callback_(std::move(other.state_callback_)) {
    other.socket_ = INVALID_SOCKET_VALUE;
    other.state_ = TurnAllocationState::None;
}

TurnClient& TurnClient::operator=(TurnClient&& other) noexcept {
    if (this != &other) {
        close();
        config_ = std::move(other.config_);
        socket_ = other.socket_;
        stun_client_ = std::move(other.stun_client_);
        state_ = other.state_;
        allocation_ = std::move(other.allocation_);
        nonce_ = std::move(other.nonce_);
        realm_ = std::move(other.realm_);
        permissions_ = std::move(other.permissions_);
        channels_ = std::move(other.channels_);
        peer_to_channel_ = std::move(other.peer_to_channel_);
        next_channel_ = other.next_channel_;
        data_callback_ = std::move(other.data_callback_);
        state_callback_ = std::move(other.state_callback_);
        other.socket_ = INVALID_SOCKET_VALUE;
        other.state_ = TurnAllocationState::None;
    }
    return *this;
}

void TurnClient::set_config(const TurnClientConfig& config) {
    config_ = config;
}

void TurnClient::close() {
    stop_refresh_thread();
    
    if (is_allocated()) {
        release();
    }
    
    if (is_valid_socket(socket_)) {
        close_socket(socket_);
        socket_ = INVALID_SOCKET_VALUE;
    }
    
    set_state(TurnAllocationState::None);
}

bool TurnClient::ensure_socket() {
    if (is_valid_socket(socket_)) {
        return true;
    }
    
    socket_ = create_udp_socket(0);
    if (!is_valid_socket(socket_)) {
        LOG_TURN_ERROR("Failed to create UDP socket");
        return false;
    }
    
    return true;
}

std::vector<uint8_t> TurnClient::compute_message_integrity_key() const {
    std::string effective_realm = realm_.empty() ? config_.realm : realm_;
    return stun_compute_long_term_key(config_.username, effective_realm, config_.password);
}

void TurnClient::set_state(TurnAllocationState new_state) {
    if (state_ != new_state) {
        state_ = new_state;
        if (state_callback_) {
            state_callback_(new_state);
        }
    }
}

std::string TurnClient::peer_key(const StunMappedAddress& peer) const {
    return peer.address + ":" + std::to_string(peer.port);
}

// ============================================================================
// Allocation Management
// ============================================================================

TurnResult TurnClient::allocate() {
    LOG_TURN_INFO("Requesting TURN allocation from " << config_.server << ":" << config_.port);
    
    if (!ensure_socket()) {
        return TurnResult::Error("Failed to create socket");
    }
    
    set_state(TurnAllocationState::Allocating);
    
    // First request without credentials to get nonce and realm
    auto result = send_allocate_request(false);
    
    if (!result.success && result.error) {
        if (result.error->code == StunErrorCode::Unauthorized) {
            // Expected - server sends 401 with nonce and realm
            // Retry with credentials
            LOG_TURN_DEBUG("Got 401 response, retrying with credentials");
            result = send_allocate_request(true);
        }
    }
    
    if (result.success) {
        set_state(TurnAllocationState::Allocated);
        LOG_TURN_INFO("TURN allocation successful: " << allocation_.relay_address.to_string());
        
        if (config_.auto_refresh) {
            start_refresh_thread();
        }
    } else {
        set_state(TurnAllocationState::Failed);
        LOG_TURN_ERROR("TURN allocation failed: " << result.error_message);
    }
    
    return result;
}

TurnResult TurnClient::send_allocate_request(bool with_credentials) {
    StunMessage request(StunMessageType::AllocateRequest);
    request.add_requested_transport(TURN_TRANSPORT_UDP);
    request.add_lifetime(config_.requested_lifetime);
    
    if (!config_.software.empty()) {
        request.add_software(config_.software);
    }
    
    if (with_credentials && !config_.username.empty()) {
        request.add_username(config_.username);
        std::string effective_realm = realm_.empty() ? config_.realm : realm_;
        if (!effective_realm.empty()) {
            request.add_realm(effective_realm);
        }
        if (!nonce_.empty()) {
            request.add_nonce(nonce_);
        }
    }
    
    std::vector<uint8_t> data;
    if (with_credentials && !config_.password.empty()) {
        auto key = compute_message_integrity_key();
        data = request.serialize_with_integrity(std::string(key.begin(), key.end()));
    } else {
        data = request.serialize();
    }
    
    auto response = stun_client_.send_request(socket_, request, config_.server, 
                                               config_.port, config_.timeout_ms);
    
    if (!response) {
        return TurnResult::Error("Request timed out");
    }
    
    // Extract nonce and realm from any response
    if (auto new_nonce = response->get_nonce()) {
        nonce_ = *new_nonce;
    }
    if (auto new_realm = response->get_realm()) {
        realm_ = *new_realm;
    }
    
    if (response->is_error_response()) {
        auto error = response->get_error();
        if (error) {
            return TurnResult::Error(error->code, error->reason);
        }
        return TurnResult::Error("Unknown error");
    }
    
    if (response->is_success_response()) {
        // Parse allocation response
        auto relay_addr = response->get_xor_relayed_address();
        auto mapped_addr = response->get_xor_mapped_address();
        auto lifetime = response->get_lifetime();
        
        if (!relay_addr || !lifetime) {
            return TurnResult::Error("Invalid allocation response");
        }
        
        allocation_.relay_address = *relay_addr;
        if (mapped_addr) {
            allocation_.mapped_address = *mapped_addr;
        }
        allocation_.lifetime = *lifetime;
        allocation_.allocated_at = std::chrono::steady_clock::now();
        allocation_.expires_at = allocation_.allocated_at + 
                                  std::chrono::seconds(allocation_.lifetime);
        
        return TurnResult::Success();
    }
    
    return TurnResult::Error("Unexpected response type");
}

TurnResult TurnClient::refresh(uint32_t lifetime) {
    if (!is_allocated()) {
        return TurnResult::Error("No active allocation");
    }
    
    LOG_TURN_DEBUG("Refreshing TURN allocation");
    set_state(TurnAllocationState::Refreshing);
    
    auto result = send_refresh_request(lifetime == 0 ? config_.requested_lifetime : lifetime);
    
    if (result.success) {
        set_state(TurnAllocationState::Allocated);
    } else {
        set_state(TurnAllocationState::Failed);
    }
    
    return result;
}

TurnResult TurnClient::send_refresh_request(uint32_t lifetime) {
    StunMessage request(StunMessageType::RefreshRequest);
    request.add_lifetime(lifetime);
    request.add_username(config_.username);
    
    std::string effective_realm = realm_.empty() ? config_.realm : realm_;
    if (!effective_realm.empty()) {
        request.add_realm(effective_realm);
    }
    if (!nonce_.empty()) {
        request.add_nonce(nonce_);
    }
    
    auto key = compute_message_integrity_key();
    auto data = request.serialize_with_integrity(std::string(key.begin(), key.end()));
    
    auto response = stun_client_.send_request(socket_, request, config_.server,
                                               config_.port, config_.timeout_ms);
    
    if (!response) {
        return TurnResult::Error("Refresh request timed out");
    }
    
    // Update nonce if changed
    if (auto new_nonce = response->get_nonce()) {
        nonce_ = *new_nonce;
    }
    
    if (response->is_error_response()) {
        auto error = response->get_error();
        if (error) {
            if (error->code == StunErrorCode::StaleNonce) {
                // Retry with new nonce
                return send_refresh_request(lifetime);
            }
            return TurnResult::Error(error->code, error->reason);
        }
        return TurnResult::Error("Unknown error");
    }
    
    if (response->is_success_response()) {
        auto new_lifetime = response->get_lifetime();
        if (new_lifetime) {
            allocation_.lifetime = *new_lifetime;
            allocation_.expires_at = std::chrono::steady_clock::now() + 
                                      std::chrono::seconds(allocation_.lifetime);
            LOG_TURN_DEBUG("Allocation refreshed, new lifetime: " << allocation_.lifetime);
        }
        return TurnResult::Success();
    }
    
    return TurnResult::Error("Unexpected response type");
}

TurnResult TurnClient::release() {
    if (!is_allocated()) {
        return TurnResult::Success();  // Already released
    }
    
    LOG_TURN_INFO("Releasing TURN allocation");
    stop_refresh_thread();
    
    auto result = send_refresh_request(0);  // Lifetime 0 = release
    
    allocation_ = TurnAllocation();
    set_state(TurnAllocationState::None);
    
    return result;
}

// ============================================================================
// Permission Management
// ============================================================================

TurnResult TurnClient::create_permission(const std::string& peer_address) {
    StunMappedAddress peer(StunAddressFamily::IPv4, peer_address, 0);
    return create_permission(peer);
}

TurnResult TurnClient::create_permission(const StunMappedAddress& peer) {
    return create_permissions({peer.address});
}

TurnResult TurnClient::create_permissions(const std::vector<std::string>& peer_addresses) {
    if (!is_allocated()) {
        return TurnResult::Error("No active allocation");
    }
    
    std::vector<StunMappedAddress> peers;
    for (const auto& addr : peer_addresses) {
        peers.emplace_back(StunAddressFamily::IPv4, addr, 0);
    }
    
    return send_create_permission_request(peers);
}

TurnResult TurnClient::send_create_permission_request(const std::vector<StunMappedAddress>& peers) {
    StunMessage request(StunMessageType::CreatePermissionRequest);
    
    for (const auto& peer : peers) {
        request.add_xor_peer_address(peer);
    }
    
    request.add_username(config_.username);
    std::string effective_realm = realm_.empty() ? config_.realm : realm_;
    if (!effective_realm.empty()) {
        request.add_realm(effective_realm);
    }
    if (!nonce_.empty()) {
        request.add_nonce(nonce_);
    }
    
    auto key = compute_message_integrity_key();
    auto data = request.serialize_with_integrity(std::string(key.begin(), key.end()));
    
    auto response = stun_client_.send_request(socket_, request, config_.server,
                                               config_.port, config_.timeout_ms);
    
    if (!response) {
        return TurnResult::Error("CreatePermission request timed out");
    }
    
    if (auto new_nonce = response->get_nonce()) {
        nonce_ = *new_nonce;
    }
    
    if (response->is_error_response()) {
        auto error = response->get_error();
        if (error) {
            if (error->code == StunErrorCode::StaleNonce) {
                return send_create_permission_request(peers);
            }
            return TurnResult::Error(error->code, error->reason);
        }
        return TurnResult::Error("Unknown error");
    }
    
    if (response->is_success_response()) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(5);
        
        for (const auto& peer : peers) {
            TurnPermission perm;
            perm.peer_address = peer.address;
            perm.expires_at = expires_at;
            permissions_[peer.address] = perm;
        }
        
        LOG_TURN_DEBUG("Created permissions for " << peers.size() << " peers");
        return TurnResult::Success();
    }
    
    return TurnResult::Error("Unexpected response type");
}

bool TurnClient::has_permission(const std::string& peer_address) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = permissions_.find(peer_address);
    if (it == permissions_.end()) return false;
    return !it->second.is_expired();
}

// ============================================================================
// Channel Binding
// ============================================================================

uint16_t TurnClient::bind_channel(const StunMappedAddress& peer) {
    if (!is_allocated()) {
        return 0;
    }
    
    std::string key = peer_key(peer);
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = peer_to_channel_.find(key);
        if (it != peer_to_channel_.end()) {
            auto& binding = channels_[it->second];
            if (!binding.is_expired()) {
                return it->second;  // Already bound
            }
        }
    }
    
    uint16_t channel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        channel = next_channel_++;
        if (next_channel_ > TURN_CHANNEL_MAX) {
            next_channel_ = TURN_CHANNEL_MIN;
        }
    }
    
    auto result = send_channel_bind_request(channel, peer);
    if (!result.success) {
        LOG_TURN_ERROR("Channel binding failed: " << result.error_message);
        return 0;
    }
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        TurnChannelBinding binding;
        binding.channel_number = channel;
        binding.peer_address = peer;
        binding.expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(10);
        
        channels_[channel] = binding;
        peer_to_channel_[key] = channel;
    }
    
    LOG_TURN_DEBUG("Bound channel " << channel << " to " << peer.to_string());
    return channel;
}

TurnResult TurnClient::send_channel_bind_request(uint16_t channel, const StunMappedAddress& peer) {
    StunMessage request(StunMessageType::ChannelBindRequest);
    request.add_channel_number(channel);
    request.add_xor_peer_address(peer);
    
    request.add_username(config_.username);
    std::string effective_realm = realm_.empty() ? config_.realm : realm_;
    if (!effective_realm.empty()) {
        request.add_realm(effective_realm);
    }
    if (!nonce_.empty()) {
        request.add_nonce(nonce_);
    }
    
    auto key = compute_message_integrity_key();
    auto data = request.serialize_with_integrity(std::string(key.begin(), key.end()));
    
    auto response = stun_client_.send_request(socket_, request, config_.server,
                                               config_.port, config_.timeout_ms);
    
    if (!response) {
        return TurnResult::Error("ChannelBind request timed out");
    }
    
    if (auto new_nonce = response->get_nonce()) {
        nonce_ = *new_nonce;
    }
    
    if (response->is_error_response()) {
        auto error = response->get_error();
        if (error) {
            if (error->code == StunErrorCode::StaleNonce) {
                return send_channel_bind_request(channel, peer);
            }
            return TurnResult::Error(error->code, error->reason);
        }
        return TurnResult::Error("Unknown error");
    }
    
    if (response->is_success_response()) {
        return TurnResult::Success();
    }
    
    return TurnResult::Error("Unexpected response type");
}

uint16_t TurnClient::get_channel(const StunMappedAddress& peer) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = peer_key(peer);
    auto it = peer_to_channel_.find(key);
    if (it == peer_to_channel_.end()) return 0;
    
    auto ch_it = channels_.find(it->second);
    if (ch_it == channels_.end() || ch_it->second.is_expired()) return 0;
    
    return it->second;
}

std::optional<StunMappedAddress> TurnClient::get_channel_peer(uint16_t channel) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = channels_.find(channel);
    if (it == channels_.end() || it->second.is_expired()) {
        return std::nullopt;
    }
    return it->second.peer_address;
}

TurnResult TurnClient::refresh_channel(uint16_t channel) {
    std::optional<StunMappedAddress> peer;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(channel);
        if (it != channels_.end()) {
            peer = it->second.peer_address;
        }
    }
    
    if (!peer) {
        return TurnResult::Error("Channel not found");
    }
    
    auto result = send_channel_bind_request(channel, *peer);
    if (result.success) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(channel);
        if (it != channels_.end()) {
            it->second.expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(10);
        }
    }
    
    return result;
}

// ============================================================================
// Data Transfer
// ============================================================================

bool TurnClient::send_data(const StunMappedAddress& peer, const std::vector<uint8_t>& data) {
    uint16_t channel = get_channel(peer);
    if (channel != 0) {
        return send_channel_data(channel, data);
    }
    return send_indication(peer, data);
}

bool TurnClient::send_indication(const StunMappedAddress& peer, const std::vector<uint8_t>& data) {
    if (!is_allocated()) {
        return false;
    }
    
    // Ensure permission exists
    if (!has_permission(peer.address)) {
        auto result = create_permission(peer);
        if (!result.success) {
            LOG_TURN_ERROR("Failed to create permission for " << peer.address);
            return false;
        }
    }
    
    StunMessage indication;
    indication.type = StunMessageType::SendIndication;
    indication.generate_transaction_id();
    indication.add_xor_peer_address(peer);
    indication.add_data(data);
    
    auto msg_data = indication.serialize();
    int sent = send_udp_data(socket_, msg_data, config_.server, config_.port);
    
    return sent > 0;
}

bool TurnClient::send_channel_data(uint16_t channel, const std::vector<uint8_t>& data) {
    if (!is_allocated()) {
        return false;
    }
    
    // Channel data format: 2-byte channel + 2-byte length + data (padded to 4 bytes)
    std::vector<uint8_t> msg;
    msg.reserve(TURN_CHANNEL_HEADER_SIZE + data.size() + 3);
    
    msg.push_back(static_cast<uint8_t>(channel >> 8));
    msg.push_back(static_cast<uint8_t>(channel));
    msg.push_back(static_cast<uint8_t>(data.size() >> 8));
    msg.push_back(static_cast<uint8_t>(data.size()));
    msg.insert(msg.end(), data.begin(), data.end());
    
    // Pad to 4-byte boundary
    while (msg.size() % 4 != 0) {
        msg.push_back(0);
    }
    
    int sent = send_udp_data(socket_, msg, config_.server, config_.port);
    return sent > 0;
}

std::optional<std::pair<StunMappedAddress, std::vector<uint8_t>>> TurnClient::receive_data(int timeout_ms) {
    if (!is_valid_socket(socket_)) {
        return std::nullopt;
    }
    
    Peer sender;
    auto data = receive_udp_data(socket_, STUN_MAX_MESSAGE_SIZE, sender, timeout_ms);
    
    if (data.empty()) {
        return std::nullopt;
    }
    
    // Check if it's a STUN message (Data indication)
    if (StunMessage::is_stun_message(data)) {
        auto msg = StunMessage::deserialize(data);
        if (msg && msg->type == StunMessageType::DataIndication) {
            auto peer_addr = msg->get_xor_peer_address();
            auto payload = msg->get_data();
            
            if (peer_addr && payload) {
                return std::make_pair(*peer_addr, *payload);
            }
        }
        return std::nullopt;
    }
    
    // Check if it's channel data
    if (data.size() >= TURN_CHANNEL_HEADER_SIZE) {
        uint16_t channel = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        
        if (channel >= TURN_CHANNEL_MIN && channel <= TURN_CHANNEL_MAX) {
            uint16_t length = (static_cast<uint16_t>(data[2]) << 8) | data[3];
            
            if (data.size() >= TURN_CHANNEL_HEADER_SIZE + length) {
                auto peer = get_channel_peer(channel);
                if (peer) {
                    std::vector<uint8_t> payload(data.begin() + TURN_CHANNEL_HEADER_SIZE,
                                                  data.begin() + TURN_CHANNEL_HEADER_SIZE + length);
                    return std::make_pair(*peer, payload);
                }
            }
        }
    }
    
    return std::nullopt;
}

void TurnClient::set_data_callback(TurnDataCallback callback) {
    data_callback_ = std::move(callback);
}

void TurnClient::set_state_callback(TurnStateCallback callback) {
    state_callback_ = std::move(callback);
}

void TurnClient::process_incoming() {
    auto result = receive_data(0);  // Non-blocking
    if (result && data_callback_) {
        data_callback_(result->first, result->second);
    }
}

// ============================================================================
// Refresh Thread
// ============================================================================

void TurnClient::start_refresh_thread() {
    if (refresh_running_) return;
    
    refresh_running_ = true;
    refresh_thread_ = std::thread(&TurnClient::refresh_loop, this);
}

void TurnClient::stop_refresh_thread() {
    refresh_running_ = false;
    if (refresh_thread_.joinable()) {
        refresh_thread_.join();
    }
}

void TurnClient::refresh_loop() {
    LOG_TURN_DEBUG("Refresh thread started");
    
    while (refresh_running_) {
        // Sleep for a bit
        for (int i = 0; i < 10 && refresh_running_; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        if (!refresh_running_) break;
        
        // Check if allocation needs refresh (refresh at 80% of lifetime)
        if (is_allocated()) {
            auto remaining = allocation_.remaining_lifetime();
            auto threshold = allocation_.lifetime * 0.2;  // Refresh when 20% remaining
            
            if (remaining <= threshold) {
                LOG_TURN_DEBUG("Allocation lifetime low (" << remaining << "s), refreshing");
                refresh();
            }
        }
        
        // Refresh permissions and channels
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Clean up expired permissions
            for (auto it = permissions_.begin(); it != permissions_.end();) {
                if (it->second.is_expired()) {
                    it = permissions_.erase(it);
                } else {
                    ++it;
                }
            }
            
            // Clean up expired channels
            for (auto it = channels_.begin(); it != channels_.end();) {
                if (it->second.is_expired()) {
                    peer_to_channel_.erase(peer_key(it->second.peer_address));
                    it = channels_.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }
    
    LOG_TURN_DEBUG("Refresh thread stopped");
}

} // namespace librats
