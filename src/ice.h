#pragma once

/**
 * @file ice.h
 * @brief ICE-lite (Interactive Connectivity Establishment) Implementation
 * 
 * Implements RFC 5245 ICE-lite for NAT traversal.
 * Provides candidate gathering, connectivity checks, and connection establishment.
 * 
 * ICE-lite is a minimal implementation suitable for servers and most P2P scenarios.
 * It doesn't perform full ICE with controlling/controlled roles negotiation.
 */

#include "stun.h"
#include "turn.h"
#include "socket.h"
#include <vector>
#include <string>
#include <optional>
#include <memory>
#include <mutex>
#include <functional>
#include <chrono>
#include <atomic>
#include <thread>

namespace librats {

// ============================================================================
// ICE Constants
// ============================================================================

/// Default ICE candidate priority for host candidates
constexpr uint32_t ICE_PRIORITY_HOST = 126;

/// Default ICE candidate priority for server-reflexive candidates  
constexpr uint32_t ICE_PRIORITY_SRFLX = 100;

/// Default ICE candidate priority for relay candidates
constexpr uint32_t ICE_PRIORITY_RELAY = 0;

/// Connectivity check timeout (ms)
constexpr int ICE_CHECK_TIMEOUT_MS = 500;

/// Maximum connectivity check retries
constexpr int ICE_CHECK_MAX_RETRIES = 5;

// ============================================================================
// ICE Data Structures
// ============================================================================

/**
 * ICE candidate type
 */
enum class IceCandidateType {
    Host,           ///< Local interface address
    ServerReflexive,///< Address discovered via STUN (public address)
    PeerReflexive,  ///< Address discovered during connectivity checks
    Relay           ///< TURN relay address
};

/**
 * ICE candidate transport protocol
 */
enum class IceTransportProtocol {
    UDP,
    TCP
};

/**
 * ICE connection state
 */
enum class IceConnectionState {
    New,            ///< Initial state
    Gathering,      ///< Gathering candidates
    Checking,       ///< Performing connectivity checks
    Connected,      ///< At least one valid pair found
    Completed,      ///< ICE processing complete
    Failed,         ///< ICE processing failed
    Disconnected,   ///< Connection lost
    Closed          ///< ICE agent closed
};

/**
 * ICE gathering state
 */
enum class IceGatheringState {
    New,            ///< Not started
    Gathering,      ///< Gathering in progress
    Complete        ///< Gathering complete
};

/**
 * ICE candidate
 */
struct IceCandidate {
    IceCandidateType type;
    std::string foundation;         ///< Unique identifier for candidate
    uint32_t component_id;          ///< Component ID (typically 1 for RTP)
    IceTransportProtocol transport;
    uint32_t priority;              ///< Candidate priority
    std::string address;            ///< IP address
    uint16_t port;                  ///< Port number
    std::string related_address;    ///< Related address (for srflx/relay)
    uint16_t related_port;          ///< Related port
    
    IceCandidate() : type(IceCandidateType::Host), component_id(1), 
                     transport(IceTransportProtocol::UDP), priority(0),
                     port(0), related_port(0) {}
    
    /**
     * Compute candidate priority (RFC 5245 Section 4.1.2.1)
     */
    static uint32_t compute_priority(IceCandidateType type, 
                                     uint32_t local_preference = 65535,
                                     uint32_t component_id = 1);
    
    /**
     * Generate foundation string
     */
    static std::string generate_foundation(IceCandidateType type,
                                           const std::string& base_address,
                                           const std::string& server_address = "");
    
    /**
     * Format candidate as SDP attribute string (a=candidate:...)
     */
    std::string to_sdp_attribute() const;
    
    /**
     * Parse candidate from SDP attribute string
     */
    static std::optional<IceCandidate> from_sdp_attribute(const std::string& sdp);
    
    /**
     * Get candidate type as string
     */
    std::string type_string() const;
    
    /**
     * Get address:port string
     */
    std::string address_string() const {
        return address + ":" + std::to_string(port);
    }
    
    bool operator==(const IceCandidate& other) const {
        return type == other.type && address == other.address && 
               port == other.port && transport == other.transport;
    }
};

/**
 * ICE candidate pair state
 */
enum class IceCandidatePairState {
    Frozen,     ///< Not yet checked
    Waiting,    ///< Waiting to be checked
    InProgress, ///< Check in progress
    Succeeded,  ///< Check succeeded
    Failed      ///< Check failed
};

/**
 * ICE candidate pair
 */
struct IceCandidatePair {
    IceCandidate local;
    IceCandidate remote;
    IceCandidatePairState state;
    uint64_t priority;          ///< Pair priority
    bool nominated;             ///< Nominated for use
    int check_count;            ///< Number of checks performed
    std::chrono::steady_clock::time_point last_check;
    
    IceCandidatePair() : state(IceCandidatePairState::Frozen), 
                         priority(0), nominated(false), check_count(0) {}
    
    /**
     * Compute pair priority (RFC 5245 Section 5.7.2)
     */
    static uint64_t compute_priority(uint32_t controlling_priority,
                                     uint32_t controlled_priority,
                                     bool is_controlling);
    
    /**
     * Get pair key for deduplication
     */
    std::string key() const {
        return local.address_string() + "->" + remote.address_string();
    }
};

/**
 * STUN/TURN server configuration
 */
struct IceServer {
    std::string url;            ///< Server URL (stun:host:port or turn:host:port)
    std::string username;       ///< Username (for TURN)
    std::string password;       ///< Password/credential (for TURN)
    
    IceServer() = default;
    IceServer(const std::string& u) : url(u) {}
    IceServer(const std::string& u, const std::string& user, const std::string& pass)
        : url(u), username(user), password(pass) {}
    
    /**
     * Check if this is a STUN server
     */
    bool is_stun() const { return url.find("stun:") == 0; }
    
    /**
     * Check if this is a TURN server
     */
    bool is_turn() const { return url.find("turn:") == 0 || url.find("turns:") == 0; }
    
    /**
     * Parse host and port from URL
     */
    bool parse_url(std::string& host, uint16_t& port) const;
};

/**
 * ICE configuration
 */
struct IceConfig {
    std::vector<IceServer> ice_servers;     ///< STUN/TURN servers
    bool gather_host_candidates = true;      ///< Gather host candidates
    bool gather_srflx_candidates = true;     ///< Gather server-reflexive candidates
    bool gather_relay_candidates = false;    ///< Gather relay candidates (requires TURN)
    int gathering_timeout_ms = 5000;         ///< Candidate gathering timeout
    int check_timeout_ms = ICE_CHECK_TIMEOUT_MS;    ///< Connectivity check timeout
    int check_max_retries = ICE_CHECK_MAX_RETRIES;  ///< Max connectivity check retries
    std::string software = "librats";        ///< Software attribute
    
    IceConfig() = default;
    
    /**
     * Add a STUN server
     */
    void add_stun_server(const std::string& host, uint16_t port = STUN_DEFAULT_PORT) {
        ice_servers.emplace_back("stun:" + host + ":" + std::to_string(port));
    }
    
    /**
     * Add a TURN server with credentials
     */
    void add_turn_server(const std::string& host, uint16_t port,
                         const std::string& username, const std::string& password) {
        ice_servers.emplace_back("turn:" + host + ":" + std::to_string(port),
                                 username, password);
    }
};

// ============================================================================
// ICE Callbacks
// ============================================================================

/// Callback when candidates are gathered
using IceCandidatesCallback = std::function<void(const std::vector<IceCandidate>&)>;

/// Callback when gathering state changes
using IceGatheringStateCallback = std::function<void(IceGatheringState)>;

/// Callback when connection state changes
using IceConnectionStateCallback = std::function<void(IceConnectionState)>;

/// Callback when a new candidate is discovered (trickle ICE)
using IceNewCandidateCallback = std::function<void(const IceCandidate&)>;

/// Callback when ICE completes with selected pair
using IceSelectedPairCallback = std::function<void(const IceCandidatePair&)>;

// ============================================================================
// ICE Manager
// ============================================================================

/**
 * ICE-lite Manager for NAT traversal
 * 
 * Provides:
 * - Candidate gathering from local interfaces, STUN, and TURN
 * - Connectivity checks via STUN binding requests
 * - Candidate pair prioritization and selection
 * 
 * Example usage:
 * @code
 *   IceConfig config;
 *   config.add_stun_server("stun.l.google.com", 19302);
 *   
 *   IceManager ice(config);
 *   
 *   ice.set_on_candidates_gathered([](const std::vector<IceCandidate>& candidates) {
 *       // Send candidates to remote peer via signaling
 *       for (const auto& c : candidates) {
 *           std::cout << c.to_sdp_attribute() << std::endl;
 *       }
 *   });
 *   
 *   ice.set_on_connection_state_changed([](IceConnectionState state) {
 *       if (state == IceConnectionState::Connected) {
 *           std::cout << "ICE connected!" << std::endl;
 *       }
 *   });
 *   
 *   // Start gathering
 *   ice.gather_candidates();
 *   
 *   // Add remote candidates from signaling
 *   ice.add_remote_candidate(remote_candidate);
 *   
 *   // Wait for connection
 *   while (ice.get_connection_state() != IceConnectionState::Connected) {
 *       std::this_thread::sleep_for(std::chrono::milliseconds(100));
 *   }
 *   
 *   // Get selected pair for data transfer
 *   auto pair = ice.get_selected_pair();
 * @endcode
 */
class IceManager {
public:
    IceManager();
    explicit IceManager(const IceConfig& config);
    ~IceManager();
    
    // Non-copyable
    IceManager(const IceManager&) = delete;
    IceManager& operator=(const IceManager&) = delete;
    
    // =========================================================================
    // Configuration
    // =========================================================================
    
    /**
     * Set ICE configuration
     */
    void set_config(const IceConfig& config);
    
    /**
     * Get current configuration
     */
    const IceConfig& config() const { return config_; }
    
    /**
     * Add a STUN server
     */
    void add_stun_server(const std::string& host, uint16_t port = STUN_DEFAULT_PORT);
    
    /**
     * Add a TURN server with credentials
     */
    void add_turn_server(const std::string& host, uint16_t port,
                         const std::string& username, const std::string& password);
    
    /**
     * Clear all ICE servers
     */
    void clear_ice_servers();
    
    // =========================================================================
    // Candidate Gathering
    // =========================================================================
    
    /**
     * Start gathering ICE candidates
     * @return true if gathering started successfully
     */
    bool gather_candidates();
    
    /**
     * Get local candidates
     */
    std::vector<IceCandidate> get_local_candidates() const;
    
    /**
     * Get gathering state
     */
    IceGatheringState get_gathering_state() const { return gathering_state_; }
    
    /**
     * Check if gathering is complete
     */
    bool is_gathering_complete() const { 
        return gathering_state_ == IceGatheringState::Complete;
    }
    
    // =========================================================================
    // Remote Candidates
    // =========================================================================
    
    /**
     * Add a remote candidate
     * @param candidate Remote candidate to add
     */
    void add_remote_candidate(const IceCandidate& candidate);
    
    /**
     * Add remote candidates from SDP
     * @param sdp_lines SDP attribute lines (a=candidate:...)
     */
    void add_remote_candidates_from_sdp(const std::vector<std::string>& sdp_lines);
    
    /**
     * Get remote candidates
     */
    std::vector<IceCandidate> get_remote_candidates() const;
    
    /**
     * Signal end of remote candidates (for trickle ICE)
     */
    void end_of_remote_candidates();
    
    // =========================================================================
    // Connectivity Checks
    // =========================================================================
    
    /**
     * Start connectivity checks
     */
    void start_checks();
    
    /**
     * Stop connectivity checks
     */
    void stop_checks();
    
    /**
     * Get candidate pairs
     */
    std::vector<IceCandidatePair> get_candidate_pairs() const;
    
    /**
     * Get the selected (best) candidate pair
     */
    std::optional<IceCandidatePair> get_selected_pair() const;
    
    // =========================================================================
    // Connection State
    // =========================================================================
    
    /**
     * Get connection state
     */
    IceConnectionState get_connection_state() const { return connection_state_; }
    
    /**
     * Check if connected
     */
    bool is_connected() const {
        return connection_state_ == IceConnectionState::Connected ||
               connection_state_ == IceConnectionState::Completed;
    }
    
    // =========================================================================
    // Public Address Discovery
    // =========================================================================
    
    /**
     * Get our public address (from server-reflexive candidate)
     * @return Public IP and port, or nullopt if not discovered
     */
    std::optional<std::pair<std::string, uint16_t>> get_public_address() const;
    
    // =========================================================================
    // Socket Access
    // =========================================================================
    
    /**
     * Get the UDP socket used for ICE
     * Can be used for data transfer after ICE completes
     */
    socket_t get_socket() const { return socket_; }
    
    /**
     * Get local port
     */
    uint16_t get_local_port() const { return local_port_; }
    
    // =========================================================================
    // Callbacks
    // =========================================================================
    
    void set_on_candidates_gathered(IceCandidatesCallback callback);
    void set_on_new_candidate(IceNewCandidateCallback callback);
    void set_on_gathering_state_changed(IceGatheringStateCallback callback);
    void set_on_connection_state_changed(IceConnectionStateCallback callback);
    void set_on_selected_pair(IceSelectedPairCallback callback);
    
    // =========================================================================
    // Lifecycle
    // =========================================================================
    
    /**
     * Close ICE manager and release resources
     */
    void close();
    
    /**
     * Restart ICE (gather new candidates and start checks)
     */
    void restart();
    
private:
    // Configuration
    IceConfig config_;
    
    // Network
    socket_t socket_ = INVALID_SOCKET_VALUE;
    uint16_t local_port_ = 0;
    
    // STUN/TURN clients
    std::unique_ptr<StunClient> stun_client_;
    std::unique_ptr<TurnClient> turn_client_;
    
    // State
    mutable std::mutex mutex_;
    IceGatheringState gathering_state_ = IceGatheringState::New;
    IceConnectionState connection_state_ = IceConnectionState::New;
    
    // Candidates
    std::vector<IceCandidate> local_candidates_;
    std::vector<IceCandidate> remote_candidates_;
    std::vector<IceCandidatePair> candidate_pairs_;
    std::optional<IceCandidatePair> selected_pair_;
    
    // Flags
    std::atomic<bool> gathering_ {false};
    std::atomic<bool> checking_ {false};
    bool remote_candidates_complete_ = false;
    
    // Threads
    std::thread gathering_thread_;
    std::thread checking_thread_;
    
    // Callbacks
    IceCandidatesCallback on_candidates_gathered_;
    IceNewCandidateCallback on_new_candidate_;
    IceGatheringStateCallback on_gathering_state_changed_;
    IceConnectionStateCallback on_connection_state_changed_;
    IceSelectedPairCallback on_selected_pair_;
    
    // Internal methods
    bool ensure_socket();
    void gather_host_candidates();
    void gather_srflx_candidates();
    void gather_relay_candidates();
    void gathering_complete();
    void add_local_candidate(const IceCandidate& candidate);
    void form_candidate_pairs();
    void perform_connectivity_checks();
    bool perform_check(IceCandidatePair& pair);
    void update_connection_state();
    void select_best_pair();
    void set_gathering_state(IceGatheringState state);
    void set_connection_state(IceConnectionState state);
};

} // namespace librats
