/**
 * @file ice.cpp
 * @brief ICE-lite (Interactive Connectivity Establishment) Implementation
 * 
 * Implements RFC 5245 ICE-lite for NAT traversal.
 */

#include "ice.h"
#include "logger.h"
#include "network_utils.h"
#include <algorithm>
#include <sstream>
#include <cstring>
#include <regex>
#include <iomanip>

namespace librats {

// ============================================================================
// Logging Macros
// ============================================================================

#define LOG_ICE_DEBUG(msg) LOG_DEBUG("ice", msg)
#define LOG_ICE_INFO(msg) LOG_INFO("ice", msg)
#define LOG_ICE_WARN(msg) LOG_WARN("ice", msg)
#define LOG_ICE_ERROR(msg) LOG_ERROR("ice", msg)

// ============================================================================
// IceCandidate Implementation
// ============================================================================

uint32_t IceCandidate::compute_priority(IceCandidateType type,
                                         uint32_t local_preference,
                                         uint32_t component_id) {
    // RFC 5245 Section 4.1.2.1:
    // priority = (2^24) * type_preference + (2^8) * local_preference + (256 - component_id)
    
    uint32_t type_preference;
    switch (type) {
        case IceCandidateType::Host:
            type_preference = ICE_PRIORITY_HOST;
            break;
        case IceCandidateType::ServerReflexive:
        case IceCandidateType::PeerReflexive:
            type_preference = ICE_PRIORITY_SRFLX;
            break;
        case IceCandidateType::Relay:
            type_preference = ICE_PRIORITY_RELAY;
            break;
        default:
            type_preference = 0;
    }
    
    return (type_preference << 24) + (local_preference << 8) + (256 - component_id);
}

std::string IceCandidate::generate_foundation(IceCandidateType type,
                                               const std::string& base_address,
                                               const std::string& server_address) {
    // Foundation should be unique for same type + base + server combination
    std::stringstream ss;
    
    switch (type) {
        case IceCandidateType::Host:
            ss << "host_";
            break;
        case IceCandidateType::ServerReflexive:
            ss << "srflx_";
            break;
        case IceCandidateType::PeerReflexive:
            ss << "prflx_";
            break;
        case IceCandidateType::Relay:
            ss << "relay_";
            break;
    }
    
    // Simple hash of base address
    uint32_t hash = 0;
    for (char c : base_address) {
        hash = hash * 31 + static_cast<uint8_t>(c);
    }
    if (!server_address.empty()) {
        for (char c : server_address) {
            hash = hash * 31 + static_cast<uint8_t>(c);
        }
    }
    
    ss << std::hex << hash;
    return ss.str();
}

std::string IceCandidate::type_string() const {
    switch (type) {
        case IceCandidateType::Host: return "host";
        case IceCandidateType::ServerReflexive: return "srflx";
        case IceCandidateType::PeerReflexive: return "prflx";
        case IceCandidateType::Relay: return "relay";
        default: return "unknown";
    }
}

std::string IceCandidate::to_sdp_attribute() const {
    // Format: candidate:foundation component-id transport priority address port typ type [raddr rport]
    std::stringstream ss;
    ss << "candidate:" << foundation << " "
       << component_id << " "
       << (transport == IceTransportProtocol::UDP ? "UDP" : "TCP") << " "
       << priority << " "
       << address << " "
       << port << " "
       << "typ " << type_string();
    
    if (type != IceCandidateType::Host && !related_address.empty()) {
        ss << " raddr " << related_address << " rport " << related_port;
    }
    
    return ss.str();
}

std::optional<IceCandidate> IceCandidate::from_sdp_attribute(const std::string& sdp) {
    // Parse SDP candidate line
    // Example: candidate:0 1 UDP 2130706431 192.168.1.100 54321 typ host
    
    std::string line = sdp;
    
    // Remove "a=" prefix if present
    if (line.find("a=") == 0) {
        line = line.substr(2);
    }
    
    // Remove "candidate:" prefix if present
    if (line.find("candidate:") == 0) {
        line = line.substr(10);
    }
    
    std::istringstream iss(line);
    IceCandidate candidate;
    
    std::string transport_str, typ_keyword, type_str;
    
    // Parse required fields
    if (!(iss >> candidate.foundation >> candidate.component_id >> transport_str 
          >> candidate.priority >> candidate.address >> candidate.port
          >> typ_keyword >> type_str)) {
        return std::nullopt;
    }
    
    // Parse transport
    std::transform(transport_str.begin(), transport_str.end(), transport_str.begin(), ::toupper);
    candidate.transport = (transport_str == "UDP") ? IceTransportProtocol::UDP : IceTransportProtocol::TCP;
    
    // Parse type
    if (type_str == "host") {
        candidate.type = IceCandidateType::Host;
    } else if (type_str == "srflx") {
        candidate.type = IceCandidateType::ServerReflexive;
    } else if (type_str == "prflx") {
        candidate.type = IceCandidateType::PeerReflexive;
    } else if (type_str == "relay") {
        candidate.type = IceCandidateType::Relay;
    } else {
        return std::nullopt;
    }
    
    // Parse optional related address
    std::string token;
    while (iss >> token) {
        if (token == "raddr") {
            iss >> candidate.related_address;
        } else if (token == "rport") {
            iss >> candidate.related_port;
        }
    }
    
    return candidate;
}

// ============================================================================
// IceCandidatePair Implementation
// ============================================================================

uint64_t IceCandidatePair::compute_priority(uint32_t controlling_priority,
                                            uint32_t controlled_priority,
                                            bool is_controlling) {
    // RFC 5245 Section 5.7.2:
    // pair priority = 2^32 * MIN(G, D) + 2 * MAX(G, D) + (G > D ? 1 : 0)
    // where G = controlling candidate priority, D = controlled candidate priority
    
    uint64_t g = controlling_priority;
    uint64_t d = controlled_priority;
    
    uint64_t min_val = std::min(g, d);
    uint64_t max_val = std::max(g, d);
    
    return (min_val << 32) + (max_val << 1) + (g > d ? 1 : 0);
}

// ============================================================================
// IceServer Implementation
// ============================================================================

bool IceServer::parse_url(std::string& host, uint16_t& port) const {
    // Parse URL format: stun:host:port or turn:host:port
    std::string url_copy = url;
    
    // Remove protocol prefix
    size_t pos = url_copy.find("://");
    if (pos == std::string::npos) {
        pos = url_copy.find(':');
        if (pos != std::string::npos && (url_copy.substr(0, pos) == "stun" || 
            url_copy.substr(0, pos) == "turn" || url_copy.substr(0, pos) == "turns")) {
            url_copy = url_copy.substr(pos + 1);
        }
    } else {
        url_copy = url_copy.substr(pos + 3);
    }
    
    // Find port separator
    pos = url_copy.rfind(':');
    if (pos != std::string::npos) {
        host = url_copy.substr(0, pos);
        try {
            port = static_cast<uint16_t>(std::stoi(url_copy.substr(pos + 1)));
        } catch (...) {
            port = is_turn() ? TURN_DEFAULT_PORT : STUN_DEFAULT_PORT;
        }
    } else {
        host = url_copy;
        port = is_turn() ? TURN_DEFAULT_PORT : STUN_DEFAULT_PORT;
    }
    
    return !host.empty();
}

// ============================================================================
// IceManager Implementation
// ============================================================================

IceManager::IceManager() {
    stun_client_ = std::make_unique<StunClient>();
}

IceManager::IceManager(const IceConfig& config) : config_(config) {
    stun_client_ = std::make_unique<StunClient>();
}

IceManager::~IceManager() {
    close();
}

void IceManager::set_config(const IceConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

void IceManager::add_stun_server(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.add_stun_server(host, port);
}

void IceManager::add_turn_server(const std::string& host, uint16_t port,
                                  const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.add_turn_server(host, port, username, password);
}

void IceManager::clear_ice_servers() {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.ice_servers.clear();
}

bool IceManager::ensure_socket() {
    if (is_valid_socket(socket_)) {
        return true;
    }
    
    socket_ = create_udp_socket(0);
    if (!is_valid_socket(socket_)) {
        LOG_ICE_ERROR("Failed to create UDP socket");
        return false;
    }
    
    local_port_ = static_cast<uint16_t>(get_ephemeral_port(socket_));
    LOG_ICE_DEBUG("Created ICE socket on port " << local_port_);
    return true;
}

// ============================================================================
// Candidate Gathering
// ============================================================================

bool IceManager::gather_candidates() {
    if (gathering_) {
        LOG_ICE_WARN("Candidate gathering already in progress");
        return false;
    }
    
    if (!ensure_socket()) {
        return false;
    }
    
    LOG_ICE_INFO("Starting ICE candidate gathering");
    
    gathering_ = true;
    set_gathering_state(IceGatheringState::Gathering);
    
    // Clear previous candidates
    {
        std::lock_guard<std::mutex> lock(mutex_);
        local_candidates_.clear();
    }
    
    // Start gathering in background thread
    gathering_thread_ = std::thread([this]() {
        // Gather host candidates
        if (config_.gather_host_candidates) {
            gather_host_candidates();
        }
        
        // Gather server-reflexive candidates
        if (config_.gather_srflx_candidates) {
            gather_srflx_candidates();
        }
        
        // Gather relay candidates
        if (config_.gather_relay_candidates) {
            gather_relay_candidates();
        }
        
        gathering_complete();
    });
    
    return true;
}

void IceManager::gather_host_candidates() {
    LOG_ICE_DEBUG("Gathering host candidates");
    
    // Get local interface addresses
    auto addresses = network_utils::get_local_interface_addresses();
    
    for (const auto& addr : addresses) {
        // Skip loopback and link-local for now
        if (addr.find("127.") == 0 || addr.find("::1") == 0) {
            continue;
        }
        if (addr.find("169.254.") == 0 || addr.find("fe80:") == 0) {
            continue;
        }
        
        IceCandidate candidate;
        candidate.type = IceCandidateType::Host;
        candidate.address = addr;
        candidate.port = local_port_;
        candidate.transport = IceTransportProtocol::UDP;
        candidate.component_id = 1;
        candidate.foundation = IceCandidate::generate_foundation(
            IceCandidateType::Host, addr);
        candidate.priority = IceCandidate::compute_priority(
            IceCandidateType::Host, 65535, 1);
        
        add_local_candidate(candidate);
    }
}

void IceManager::gather_srflx_candidates() {
    LOG_ICE_DEBUG("Gathering server-reflexive candidates");
    
    std::vector<IceServer> stun_servers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& server : config_.ice_servers) {
            if (server.is_stun()) {
                stun_servers.push_back(server);
            }
        }
    }
    
    for (const auto& server : stun_servers) {
        std::string host;
        uint16_t port;
        if (!server.parse_url(host, port)) {
            continue;
        }
        
        LOG_ICE_DEBUG("Querying STUN server: " << host << ":" << port);
        
        auto result = stun_client_->binding_request_with_socket(
            socket_, host, port, config_.gathering_timeout_ms);
        
        if (result.success && result.mapped_address) {
            IceCandidate candidate;
            candidate.type = IceCandidateType::ServerReflexive;
            candidate.address = result.mapped_address->address;
            candidate.port = result.mapped_address->port;
            candidate.transport = IceTransportProtocol::UDP;
            candidate.component_id = 1;
            
            // Get related (base) address
            auto local_addrs = network_utils::get_local_interface_addresses();
            if (!local_addrs.empty()) {
                candidate.related_address = local_addrs[0];
                candidate.related_port = local_port_;
            }
            
            candidate.foundation = IceCandidate::generate_foundation(
                IceCandidateType::ServerReflexive, candidate.related_address, host);
            candidate.priority = IceCandidate::compute_priority(
                IceCandidateType::ServerReflexive, 65534, 1);
            
            add_local_candidate(candidate);
            
            LOG_ICE_INFO("Discovered public address: " << candidate.address_string());
            break;  // One srflx candidate is usually enough
        } else {
            LOG_ICE_WARN("STUN request failed for " << host << ":" << port);
        }
    }
}

void IceManager::gather_relay_candidates() {
    LOG_ICE_DEBUG("Gathering relay candidates");
    
    std::vector<IceServer> turn_servers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& server : config_.ice_servers) {
            if (server.is_turn()) {
                turn_servers.push_back(server);
            }
        }
    }
    
    for (const auto& server : turn_servers) {
        std::string host;
        uint16_t port;
        if (!server.parse_url(host, port)) {
            continue;
        }
        
        LOG_ICE_DEBUG("Allocating TURN relay: " << host << ":" << port);
        
        TurnClientConfig turn_config;
        turn_config.server = host;
        turn_config.port = port;
        turn_config.username = server.username;
        turn_config.password = server.password;
        turn_config.timeout_ms = config_.gathering_timeout_ms;
        turn_config.auto_refresh = true;
        
        turn_client_ = std::make_unique<TurnClient>(turn_config);
        auto result = turn_client_->allocate();
        
        if (result.success && turn_client_->is_allocated()) {
            const auto& alloc = turn_client_->get_allocation();
            
            IceCandidate candidate;
            candidate.type = IceCandidateType::Relay;
            candidate.address = alloc.relay_address.address;
            candidate.port = alloc.relay_address.port;
            candidate.transport = IceTransportProtocol::UDP;
            candidate.component_id = 1;
            
            auto local_addrs = network_utils::get_local_interface_addresses();
            if (!local_addrs.empty()) {
                candidate.related_address = local_addrs[0];
                candidate.related_port = local_port_;
            }
            
            candidate.foundation = IceCandidate::generate_foundation(
                IceCandidateType::Relay, candidate.related_address, host);
            candidate.priority = IceCandidate::compute_priority(
                IceCandidateType::Relay, 65533, 1);
            
            add_local_candidate(candidate);
            
            LOG_ICE_INFO("Got relay address: " << candidate.address_string());
            break;  // One relay is usually enough
        } else {
            LOG_ICE_WARN("TURN allocation failed for " << host << ":" << port);
        }
    }
}

void IceManager::add_local_candidate(const IceCandidate& candidate) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check for duplicates
        for (const auto& c : local_candidates_) {
            if (c == candidate) {
                return;
            }
        }
        
        local_candidates_.push_back(candidate);
    }
    
    LOG_ICE_DEBUG("Added local candidate: " << candidate.type_string() 
                 << " " << candidate.address_string());
    
    // Notify callback (trickle ICE)
    if (on_new_candidate_) {
        on_new_candidate_(candidate);
    }
}

void IceManager::gathering_complete() {
    gathering_ = false;
    
    std::vector<IceCandidate> candidates;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        candidates = local_candidates_;
    }
    
    LOG_ICE_INFO("Candidate gathering complete: " << candidates.size() << " candidates");
    
    set_gathering_state(IceGatheringState::Complete);
    
    if (on_candidates_gathered_) {
        on_candidates_gathered_(candidates);
    }
    
    // Form initial candidate pairs if we have remote candidates
    form_candidate_pairs();
}

std::vector<IceCandidate> IceManager::get_local_candidates() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return local_candidates_;
}

// ============================================================================
// Remote Candidates
// ============================================================================

void IceManager::add_remote_candidate(const IceCandidate& candidate) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check for duplicates
        for (const auto& c : remote_candidates_) {
            if (c == candidate) {
                return;
            }
        }
        
        remote_candidates_.push_back(candidate);
    }
    
    LOG_ICE_DEBUG("Added remote candidate: " << candidate.type_string() 
                 << " " << candidate.address_string());
    
    // Update candidate pairs
    form_candidate_pairs();
    
    // Start checking if not already running
    if (!checking_ && gathering_state_ == IceGatheringState::Complete) {
        start_checks();
    }
}

void IceManager::add_remote_candidates_from_sdp(const std::vector<std::string>& sdp_lines) {
    for (const auto& line : sdp_lines) {
        auto candidate = IceCandidate::from_sdp_attribute(line);
        if (candidate) {
            add_remote_candidate(*candidate);
        }
    }
}

std::vector<IceCandidate> IceManager::get_remote_candidates() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return remote_candidates_;
}

void IceManager::end_of_remote_candidates() {
    remote_candidates_complete_ = true;
    
    // Start checks if not already running
    if (!checking_ && gathering_state_ == IceGatheringState::Complete) {
        start_checks();
    }
}

// ============================================================================
// Connectivity Checks
// ============================================================================

void IceManager::form_candidate_pairs() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Clear existing pairs
    candidate_pairs_.clear();
    
    // Form pairs from local and remote candidates
    for (const auto& local : local_candidates_) {
        for (const auto& remote : remote_candidates_) {
            // Only pair UDP with UDP, same component
            if (local.transport != remote.transport ||
                local.component_id != remote.component_id) {
                continue;
            }
            
            IceCandidatePair pair;
            pair.local = local;
            pair.remote = remote;
            pair.state = IceCandidatePairState::Frozen;
            
            // ICE-lite is always controlled, so remote is controlling
            pair.priority = IceCandidatePair::compute_priority(
                remote.priority, local.priority, false);
            
            candidate_pairs_.push_back(pair);
        }
    }
    
    // Sort by priority (highest first)
    std::sort(candidate_pairs_.begin(), candidate_pairs_.end(),
              [](const IceCandidatePair& a, const IceCandidatePair& b) {
                  return a.priority > b.priority;
              });
    
    LOG_ICE_DEBUG("Formed " << candidate_pairs_.size() << " candidate pairs");
}

void IceManager::start_checks() {
    if (checking_) {
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (candidate_pairs_.empty()) {
            LOG_ICE_WARN("No candidate pairs to check");
            return;
        }
    }
    
    LOG_ICE_INFO("Starting connectivity checks");
    
    checking_ = true;
    set_connection_state(IceConnectionState::Checking);
    
    checking_thread_ = std::thread(&IceManager::perform_connectivity_checks, this);
}

void IceManager::stop_checks() {
    checking_ = false;
    if (checking_thread_.joinable()) {
        checking_thread_.join();
    }
}

void IceManager::perform_connectivity_checks() {
    while (checking_) {
        IceCandidatePair* next_pair = nullptr;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Find next pair to check
            for (auto& pair : candidate_pairs_) {
                if (pair.state == IceCandidatePairState::Frozen ||
                    pair.state == IceCandidatePairState::Waiting) {
                    
                    // Check if we should retry
                    if (pair.state == IceCandidatePairState::Waiting && 
                        pair.check_count >= config_.check_max_retries) {
                        pair.state = IceCandidatePairState::Failed;
                        continue;
                    }
                    
                    next_pair = &pair;
                    break;
                }
            }
        }
        
        if (!next_pair) {
            // No more pairs to check
            update_connection_state();
            break;
        }
        
        next_pair->state = IceCandidatePairState::InProgress;
        next_pair->check_count++;
        next_pair->last_check = std::chrono::steady_clock::now();
        
        bool success = perform_check(*next_pair);
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (success) {
                next_pair->state = IceCandidatePairState::Succeeded;
                LOG_ICE_INFO("Connectivity check succeeded: " << next_pair->key());
                
                // First successful pair
                if (connection_state_ == IceConnectionState::Checking) {
                    set_connection_state(IceConnectionState::Connected);
                }
                
                select_best_pair();
            } else {
                next_pair->state = IceCandidatePairState::Waiting;  // Will retry
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    update_connection_state();
}

bool IceManager::perform_check(IceCandidatePair& pair) {
    // Send STUN binding request to remote candidate
    StunMessage request(StunMessageType::BindingRequest);
    
    if (!config_.software.empty()) {
        request.add_software(config_.software);
    }
    
    // TODO: Add ICE-specific attributes (USE-CANDIDATE, PRIORITY, ICE-CONTROLLING/CONTROLLED)
    
    auto response = stun_client_->send_request(
        socket_, request, pair.remote.address, pair.remote.port,
        config_.check_timeout_ms);
    
    return response.has_value() && response->is_success_response();
}

void IceManager::update_connection_state() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    bool has_succeeded = false;
    bool all_failed = true;
    
    for (const auto& pair : candidate_pairs_) {
        if (pair.state == IceCandidatePairState::Succeeded) {
            has_succeeded = true;
            all_failed = false;
        } else if (pair.state != IceCandidatePairState::Failed) {
            all_failed = false;
        }
    }
    
    if (has_succeeded && remote_candidates_complete_) {
        set_connection_state(IceConnectionState::Completed);
    } else if (all_failed && remote_candidates_complete_) {
        set_connection_state(IceConnectionState::Failed);
    }
}

void IceManager::select_best_pair() {
    // Find highest priority succeeded pair
    for (auto& pair : candidate_pairs_) {
        if (pair.state == IceCandidatePairState::Succeeded) {
            pair.nominated = true;
            selected_pair_ = pair;
            
            LOG_ICE_INFO("Selected pair: " << pair.key());
            
            if (on_selected_pair_) {
                on_selected_pair_(pair);
            }
            
            break;
        }
    }
}

std::vector<IceCandidatePair> IceManager::get_candidate_pairs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return candidate_pairs_;
}

std::optional<IceCandidatePair> IceManager::get_selected_pair() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return selected_pair_;
}

// ============================================================================
// Public Address Discovery
// ============================================================================

std::optional<std::pair<std::string, uint16_t>> IceManager::get_public_address() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& c : local_candidates_) {
        if (c.type == IceCandidateType::ServerReflexive) {
            return std::make_pair(c.address, c.port);
        }
    }
    
    return std::nullopt;
}

// ============================================================================
// Callbacks
// ============================================================================

void IceManager::set_on_candidates_gathered(IceCandidatesCallback callback) {
    on_candidates_gathered_ = std::move(callback);
}

void IceManager::set_on_new_candidate(IceNewCandidateCallback callback) {
    on_new_candidate_ = std::move(callback);
}

void IceManager::set_on_gathering_state_changed(IceGatheringStateCallback callback) {
    on_gathering_state_changed_ = std::move(callback);
}

void IceManager::set_on_connection_state_changed(IceConnectionStateCallback callback) {
    on_connection_state_changed_ = std::move(callback);
}

void IceManager::set_on_selected_pair(IceSelectedPairCallback callback) {
    on_selected_pair_ = std::move(callback);
}

// ============================================================================
// State Management
// ============================================================================

void IceManager::set_gathering_state(IceGatheringState state) {
    if (gathering_state_ != state) {
        gathering_state_ = state;
        if (on_gathering_state_changed_) {
            on_gathering_state_changed_(state);
        }
    }
}

void IceManager::set_connection_state(IceConnectionState state) {
    if (connection_state_ != state) {
        connection_state_ = state;
        if (on_connection_state_changed_) {
            on_connection_state_changed_(state);
        }
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

void IceManager::close() {
    gathering_ = false;
    checking_ = false;
    
    if (gathering_thread_.joinable()) {
        gathering_thread_.join();
    }
    
    if (checking_thread_.joinable()) {
        checking_thread_.join();
    }
    
    if (turn_client_) {
        turn_client_->close();
        turn_client_.reset();
    }
    
    if (is_valid_socket(socket_)) {
        close_socket(socket_);
        socket_ = INVALID_SOCKET_VALUE;
    }
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        local_candidates_.clear();
        remote_candidates_.clear();
        candidate_pairs_.clear();
        selected_pair_.reset();
    }
    
    set_connection_state(IceConnectionState::Closed);
}

void IceManager::restart() {
    close();
    
    connection_state_ = IceConnectionState::New;
    gathering_state_ = IceGatheringState::New;
    remote_candidates_complete_ = false;
    
    gather_candidates();
}

} // namespace librats
