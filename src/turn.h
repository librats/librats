#pragma once

/**
 * @file turn.h
 * @brief TURN (Traversal Using Relays around NAT) Client Implementation
 * 
 * Implements RFC 5766 - TURN protocol for NAT traversal via relay.
 * Provides functionality to allocate relay addresses and relay data
 * when direct peer-to-peer connectivity is not possible.
 */

#include "stun.h"
#include <memory>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <functional>
#include <thread>
#include <atomic>

namespace librats {

// ============================================================================
// TURN Constants
// ============================================================================

/// Default TURN port
constexpr uint16_t TURN_DEFAULT_PORT = 3478;

/// Default TURN TLS port
constexpr uint16_t TURNS_DEFAULT_PORT = 5349;

/// Default allocation lifetime (seconds)
constexpr uint32_t TURN_DEFAULT_LIFETIME = 600;

/// Minimum channel number (RFC 5766)
constexpr uint16_t TURN_CHANNEL_MIN = 0x4000;

/// Maximum channel number (RFC 5766)
constexpr uint16_t TURN_CHANNEL_MAX = 0x7FFF;

/// Channel header size
constexpr size_t TURN_CHANNEL_HEADER_SIZE = 4;

/// UDP transport protocol number
constexpr uint8_t TURN_TRANSPORT_UDP = 17;

/// TCP transport protocol number  
constexpr uint8_t TURN_TRANSPORT_TCP = 6;

// ============================================================================
// TURN Data Structures
// ============================================================================

/**
 * TURN allocation state
 */
enum class TurnAllocationState {
    None,           ///< No allocation
    Allocating,     ///< Allocation in progress
    Allocated,      ///< Successfully allocated
    Refreshing,     ///< Refreshing allocation
    Failed          ///< Allocation failed
};

/**
 * TURN allocation information
 */
struct TurnAllocation {
    StunMappedAddress relay_address;     ///< Relay address assigned by server
    StunMappedAddress mapped_address;    ///< Our reflexive address as seen by server
    uint32_t lifetime;                   ///< Remaining lifetime in seconds
    std::chrono::steady_clock::time_point allocated_at;  ///< When allocation was made
    std::chrono::steady_clock::time_point expires_at;    ///< When allocation expires
    
    TurnAllocation() : lifetime(0) {}
    
    bool is_valid() const {
        return relay_address.is_valid() && lifetime > 0;
    }
    
    bool is_expired() const {
        return std::chrono::steady_clock::now() >= expires_at;
    }
    
    uint32_t remaining_lifetime() const {
        auto now = std::chrono::steady_clock::now();
        if (now >= expires_at) return 0;
        return static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(expires_at - now).count());
    }
};

/**
 * TURN permission for a peer
 */
struct TurnPermission {
    std::string peer_address;   ///< Peer IP address (without port)
    std::chrono::steady_clock::time_point expires_at;
    
    bool is_expired() const {
        return std::chrono::steady_clock::now() >= expires_at;
    }
};

/**
 * TURN channel binding
 */
struct TurnChannelBinding {
    uint16_t channel_number;
    StunMappedAddress peer_address;
    std::chrono::steady_clock::time_point expires_at;
    
    bool is_expired() const {
        return std::chrono::steady_clock::now() >= expires_at;
    }
};

/**
 * TURN client configuration
 */
struct TurnClientConfig {
    std::string server;                  ///< TURN server hostname/IP
    uint16_t port = TURN_DEFAULT_PORT;   ///< TURN server port
    std::string username;                ///< Long-term credential username
    std::string password;                ///< Long-term credential password
    std::string realm;                   ///< Authentication realm (usually discovered)
    uint32_t requested_lifetime = TURN_DEFAULT_LIFETIME;  ///< Requested allocation lifetime
    int timeout_ms = 5000;               ///< Request timeout in milliseconds
    bool auto_refresh = true;            ///< Automatically refresh allocation
    std::string software = "librats";    ///< Software attribute value
    
    TurnClientConfig() = default;
    TurnClientConfig(const std::string& srv, const std::string& user, const std::string& pass)
        : server(srv), username(user), password(pass) {}
};

/**
 * TURN operation result
 */
struct TurnResult {
    bool success = false;
    std::optional<StunError> error;
    std::string error_message;
    
    TurnResult() = default;
    explicit TurnResult(bool s) : success(s) {}
    
    static TurnResult Success() { return TurnResult(true); }
    static TurnResult Error(const std::string& msg) {
        TurnResult r;
        r.error_message = msg;
        return r;
    }
    static TurnResult Error(StunErrorCode code, const std::string& msg = "") {
        TurnResult r;
        r.error = StunError(code, msg);
        r.error_message = msg;
        return r;
    }
};

/**
 * Callback for received data via TURN relay
 */
using TurnDataCallback = std::function<void(const StunMappedAddress& peer, 
                                            const std::vector<uint8_t>& data)>;

/**
 * Callback for allocation state changes
 */
using TurnStateCallback = std::function<void(TurnAllocationState state)>;

// ============================================================================
// TURN Client
// ============================================================================

/**
 * TURN Client for NAT traversal via relay
 * 
 * Provides:
 * - Allocation management with automatic refresh
 * - Permission creation for peers
 * - Channel binding for efficient data transfer
 * - Data relay via Send/Data indications or channels
 * 
 * Example usage:
 * @code
 *   TurnClientConfig config;
 *   config.server = "turn.example.com";
 *   config.username = "user";
 *   config.password = "pass";
 *   
 *   TurnClient client(config);
 *   
 *   auto alloc_result = client.allocate();
 *   if (alloc_result.success) {
 *       auto& alloc = client.get_allocation();
 *       std::cout << "Relay: " << alloc.relay_address.to_string() << std::endl;
 *       
 *       // Create permission for a peer
 *       client.create_permission("192.168.1.100");
 *       
 *       // Send data to peer via relay
 *       std::vector<uint8_t> data = {...};
 *       client.send_data(StunMappedAddress(StunAddressFamily::IPv4, "192.168.1.100", 5000), data);
 *   }
 * @endcode
 */
class TurnClient {
public:
    TurnClient();
    explicit TurnClient(const TurnClientConfig& config);
    ~TurnClient();
    
    // Non-copyable, movable
    TurnClient(const TurnClient&) = delete;
    TurnClient& operator=(const TurnClient&) = delete;
    TurnClient(TurnClient&&) noexcept;
    TurnClient& operator=(TurnClient&&) noexcept;
    
    // =========================================================================
    // Configuration
    // =========================================================================
    
    /**
     * Set client configuration
     */
    void set_config(const TurnClientConfig& config);
    
    /**
     * Get current configuration
     */
    const TurnClientConfig& config() const { return config_; }
    
    // =========================================================================
    // Allocation Management
    // =========================================================================
    
    /**
     * Request allocation from TURN server
     * @return Result of allocation request
     */
    TurnResult allocate();
    
    /**
     * Refresh existing allocation
     * @param lifetime New lifetime (0 = use configured default)
     * @return Result of refresh request
     */
    TurnResult refresh(uint32_t lifetime = 0);
    
    /**
     * Release allocation (set lifetime to 0)
     * @return Result of release request
     */
    TurnResult release();
    
    /**
     * Get current allocation state
     */
    TurnAllocationState get_state() const { return state_; }
    
    /**
     * Get allocation information
     */
    const TurnAllocation& get_allocation() const { return allocation_; }
    
    /**
     * Check if allocation is active
     */
    bool is_allocated() const { 
        return state_ == TurnAllocationState::Allocated && !allocation_.is_expired();
    }
    
    // =========================================================================
    // Permission Management
    // =========================================================================
    
    /**
     * Create permission for a peer address
     * @param peer_address Peer IP address (port is ignored)
     * @return Result of permission request
     */
    TurnResult create_permission(const std::string& peer_address);
    
    /**
     * Create permission for a peer
     * @param peer Peer address (port is ignored)
     * @return Result of permission request
     */
    TurnResult create_permission(const StunMappedAddress& peer);
    
    /**
     * Create permissions for multiple peers
     * @param peer_addresses List of peer IP addresses
     * @return Result of permission request
     */
    TurnResult create_permissions(const std::vector<std::string>& peer_addresses);
    
    /**
     * Check if permission exists for a peer
     */
    bool has_permission(const std::string& peer_address) const;
    
    // =========================================================================
    // Channel Binding
    // =========================================================================
    
    /**
     * Bind a channel to a peer for efficient data transfer
     * @param peer Peer address to bind
     * @return Channel number on success, 0 on failure
     */
    uint16_t bind_channel(const StunMappedAddress& peer);
    
    /**
     * Get channel number for a peer (if bound)
     * @return Channel number or 0 if not bound
     */
    uint16_t get_channel(const StunMappedAddress& peer) const;
    
    /**
     * Get peer address for a channel
     * @return Peer address or empty if channel not bound
     */
    std::optional<StunMappedAddress> get_channel_peer(uint16_t channel) const;
    
    /**
     * Refresh channel binding
     */
    TurnResult refresh_channel(uint16_t channel);
    
    // =========================================================================
    // Data Transfer
    // =========================================================================
    
    /**
     * Send data to a peer via TURN relay
     * Uses channel if bound, otherwise Send indication
     * @param peer Destination peer
     * @param data Data to send
     * @return true if sent successfully
     */
    bool send_data(const StunMappedAddress& peer, const std::vector<uint8_t>& data);
    
    /**
     * Send data to a peer via Send indication (creates permission if needed)
     * @param peer Destination peer
     * @param data Data to send
     * @return true if sent successfully
     */
    bool send_indication(const StunMappedAddress& peer, const std::vector<uint8_t>& data);
    
    /**
     * Send data via channel (more efficient, requires channel binding)
     * @param channel Channel number
     * @param data Data to send
     * @return true if sent successfully
     */
    bool send_channel_data(uint16_t channel, const std::vector<uint8_t>& data);
    
    /**
     * Receive data from TURN server
     * Call this periodically or when socket is readable
     * @param timeout_ms Timeout in milliseconds (0 = non-blocking)
     * @return Received data with peer info, or empty if no data
     */
    std::optional<std::pair<StunMappedAddress, std::vector<uint8_t>>> receive_data(int timeout_ms = 0);
    
    /**
     * Set callback for received data
     */
    void set_data_callback(TurnDataCallback callback);
    
    /**
     * Set callback for state changes
     */
    void set_state_callback(TurnStateCallback callback);
    
    // =========================================================================
    // Socket Access
    // =========================================================================
    
    /**
     * Get the UDP socket used for TURN communication
     * Useful for select/poll integration
     */
    socket_t get_socket() const { return socket_; }
    
    /**
     * Process incoming data on socket
     * Should be called when socket becomes readable
     */
    void process_incoming();
    
    // =========================================================================
    // Lifecycle
    // =========================================================================
    
    /**
     * Start automatic refresh thread
     */
    void start_refresh_thread();
    
    /**
     * Stop automatic refresh thread
     */
    void stop_refresh_thread();
    
    /**
     * Close client and release resources
     */
    void close();
    
private:
    // Configuration
    TurnClientConfig config_;
    
    // Network
    socket_t socket_ = INVALID_SOCKET_VALUE;
    StunClient stun_client_;
    
    // State
    TurnAllocationState state_ = TurnAllocationState::None;
    TurnAllocation allocation_;
    std::string nonce_;     // Server nonce for authentication
    std::string realm_;     // Discovered realm
    
    // Permissions and channels
    mutable std::mutex mutex_;
    std::unordered_map<std::string, TurnPermission> permissions_;
    std::unordered_map<uint16_t, TurnChannelBinding> channels_;
    std::unordered_map<std::string, uint16_t> peer_to_channel_;
    uint16_t next_channel_ = TURN_CHANNEL_MIN;
    
    // Callbacks
    TurnDataCallback data_callback_;
    TurnStateCallback state_callback_;
    
    // Refresh thread
    std::atomic<bool> refresh_running_{false};
    std::thread refresh_thread_;
    
    // Internal methods
    bool ensure_socket();
    std::vector<uint8_t> compute_message_integrity_key() const;
    TurnResult send_allocate_request(bool with_credentials);
    TurnResult send_refresh_request(uint32_t lifetime);
    TurnResult send_create_permission_request(const std::vector<StunMappedAddress>& peers);
    TurnResult send_channel_bind_request(uint16_t channel, const StunMappedAddress& peer);
    void handle_response(const StunMessage& response);
    void handle_data_indication(const StunMessage& indication);
    void handle_channel_data(const std::vector<uint8_t>& data);
    void set_state(TurnAllocationState new_state);
    void refresh_loop();
    std::string peer_key(const StunMappedAddress& peer) const;
};

} // namespace librats
