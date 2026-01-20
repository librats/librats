#pragma once

/**
 * @file stun.h
 * @brief STUN (Session Traversal Utilities for NAT) Protocol Implementation
 * 
 * Implements RFC 5389 - STUN protocol for NAT traversal.
 * Provides functionality to discover public IP address and port mappings.
 */

#include "socket.h"
#include <array>
#include <vector>
#include <string>
#include <optional>
#include <cstdint>
#include <memory>
#include <chrono>
#include <random>

namespace librats {

// ============================================================================
// STUN Constants (RFC 5389)
// ============================================================================

/// STUN Magic Cookie (fixed value per RFC 5389)
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

/// STUN header size in bytes
constexpr size_t STUN_HEADER_SIZE = 20;

/// STUN transaction ID size in bytes
constexpr size_t STUN_TRANSACTION_ID_SIZE = 12;

/// Default STUN port
constexpr uint16_t STUN_DEFAULT_PORT = 3478;

/// STUN over TLS default port
constexpr uint16_t STUNS_DEFAULT_PORT = 5349;

/// Maximum STUN message size (RFC 5389 recommends path MTU, typically ~1500)
constexpr size_t STUN_MAX_MESSAGE_SIZE = 1500;

/// Default retransmission timeout (ms)
constexpr int STUN_DEFAULT_RTO_MS = 500;

/// Maximum retransmissions
constexpr int STUN_MAX_RETRANSMISSIONS = 7;

// ============================================================================
// STUN Message Types (RFC 5389 Section 6)
// ============================================================================

/**
 * STUN message class (2 bits)
 */
enum class StunMessageClass : uint8_t {
    Request         = 0x00,
    Indication      = 0x01,
    SuccessResponse = 0x02,
    ErrorResponse   = 0x03
};

/**
 * STUN method (12 bits, only Binding is defined in RFC 5389)
 */
enum class StunMethod : uint16_t {
    Binding = 0x001,
    // TURN methods (RFC 5766)
    Allocate = 0x003,
    Refresh = 0x004,
    Send = 0x006,
    Data = 0x007,
    CreatePermission = 0x008,
    ChannelBind = 0x009
};

/**
 * Combined STUN message type (method + class)
 */
enum class StunMessageType : uint16_t {
    // Binding
    BindingRequest         = 0x0001,
    BindingIndication      = 0x0011,
    BindingSuccessResponse = 0x0101,
    BindingErrorResponse   = 0x0111,
    
    // TURN Allocate
    AllocateRequest         = 0x0003,
    AllocateSuccessResponse = 0x0103,
    AllocateErrorResponse   = 0x0113,
    
    // TURN Refresh
    RefreshRequest         = 0x0004,
    RefreshSuccessResponse = 0x0104,
    RefreshErrorResponse   = 0x0114,
    
    // TURN Send/Data
    SendIndication = 0x0016,
    DataIndication = 0x0017,
    
    // TURN CreatePermission
    CreatePermissionRequest         = 0x0008,
    CreatePermissionSuccessResponse = 0x0108,
    CreatePermissionErrorResponse   = 0x0118,
    
    // TURN ChannelBind
    ChannelBindRequest         = 0x0009,
    ChannelBindSuccessResponse = 0x0109,
    ChannelBindErrorResponse   = 0x0119
};

// ============================================================================
// STUN Attribute Types (RFC 5389 Section 15)
// ============================================================================

enum class StunAttributeType : uint16_t {
    // Comprehension-required (0x0000-0x7FFF)
    MappedAddress     = 0x0001,
    Username          = 0x0006,
    MessageIntegrity  = 0x0008,
    ErrorCode         = 0x0009,
    UnknownAttributes = 0x000A,
    Realm             = 0x0014,
    Nonce             = 0x0015,
    XorMappedAddress  = 0x0020,
    
    // TURN attributes (RFC 5766)
    ChannelNumber     = 0x000C,
    Lifetime          = 0x000D,
    XorPeerAddress    = 0x0012,
    Data              = 0x0013,
    XorRelayedAddress = 0x0016,
    RequestedTransport = 0x0019,
    DontFragment      = 0x001A,
    
    // Comprehension-optional (0x8000-0xFFFF)
    Software          = 0x8022,
    AlternateServer   = 0x8023,
    Fingerprint       = 0x8028
};

// ============================================================================
// STUN Address Family
// ============================================================================

enum class StunAddressFamily : uint8_t {
    IPv4 = 0x01,
    IPv6 = 0x02
};

// ============================================================================
// STUN Error Codes (RFC 5389 Section 15.6)
// ============================================================================

enum class StunErrorCode : uint16_t {
    TryAlternate     = 300,
    BadRequest       = 400,
    Unauthorized     = 401,
    Forbidden        = 403,
    UnknownAttribute = 420,
    StaleNonce       = 438,
    ServerError      = 500,
    
    // TURN error codes (RFC 5766)
    AllocationMismatch = 437,
    WrongCredentials   = 441,
    UnsupportedTransportProtocol = 442,
    AllocationQuotaReached = 486,
    InsufficientCapacity = 508
};

// ============================================================================
// STUN Data Structures
// ============================================================================

/**
 * STUN mapped address (result of binding request)
 */
struct StunMappedAddress {
    StunAddressFamily family;
    std::string address;
    uint16_t port;
    
    StunMappedAddress() : family(StunAddressFamily::IPv4), port(0) {}
    StunMappedAddress(StunAddressFamily f, const std::string& addr, uint16_t p)
        : family(f), address(addr), port(p) {}
    
    bool is_valid() const { return !address.empty() && port > 0; }
    
    std::string to_string() const {
        if (family == StunAddressFamily::IPv6) {
            return "[" + address + "]:" + std::to_string(port);
        }
        return address + ":" + std::to_string(port);
    }
};

/**
 * STUN error information
 */
struct StunError {
    StunErrorCode code;
    std::string reason;
    
    StunError() : code(StunErrorCode::ServerError) {}
    StunError(StunErrorCode c, const std::string& r = "") : code(c), reason(r) {}
};

/**
 * STUN attribute base class
 */
struct StunAttribute {
    StunAttributeType type;
    std::vector<uint8_t> value;
    
    StunAttribute() : type(StunAttributeType::MappedAddress) {}
    StunAttribute(StunAttributeType t, const std::vector<uint8_t>& v) : type(t), value(v) {}
    
    size_t padded_length() const {
        // STUN attributes are padded to 4-byte boundary
        return (value.size() + 3) & ~3;
    }
};

/**
 * STUN message structure
 */
struct StunMessage {
    StunMessageType type;
    std::array<uint8_t, STUN_TRANSACTION_ID_SIZE> transaction_id;
    std::vector<StunAttribute> attributes;
    
    StunMessage() : type(StunMessageType::BindingRequest) {
        transaction_id.fill(0);
    }
    
    explicit StunMessage(StunMessageType t) : type(t) {
        generate_transaction_id();
    }
    
    /// Generate random transaction ID
    void generate_transaction_id();
    
    /// Get message class from type
    StunMessageClass get_class() const;
    
    /// Get method from type
    StunMethod get_method() const;
    
    /// Check if this is a request
    bool is_request() const { return get_class() == StunMessageClass::Request; }
    
    /// Check if this is a success response
    bool is_success_response() const { return get_class() == StunMessageClass::SuccessResponse; }
    
    /// Check if this is an error response
    bool is_error_response() const { return get_class() == StunMessageClass::ErrorResponse; }
    
    /// Find attribute by type
    const StunAttribute* find_attribute(StunAttributeType attr_type) const;
    
    /// Add an attribute
    void add_attribute(StunAttributeType attr_type, const std::vector<uint8_t>& value);
    
    /// Add XOR-MAPPED-ADDRESS attribute
    void add_xor_mapped_address(const StunMappedAddress& addr);
    
    /// Add XOR-RELAYED-ADDRESS attribute (TURN)
    void add_xor_relayed_address(const StunMappedAddress& addr);
    
    /// Add ERROR-CODE attribute
    void add_error_code(StunErrorCode code, const std::string& reason = "");
    
    /// Add USERNAME attribute
    void add_username(const std::string& username);
    
    /// Add REALM attribute
    void add_realm(const std::string& realm);
    
    /// Add NONCE attribute
    void add_nonce(const std::string& nonce);
    
    /// Add SOFTWARE attribute
    void add_software(const std::string& software);
    
    /// Add LIFETIME attribute (TURN)
    void add_lifetime(uint32_t seconds);
    
    /// Add REQUESTED-TRANSPORT attribute (TURN)
    void add_requested_transport(uint8_t protocol);
    
    /// Add XOR-PEER-ADDRESS attribute (TURN)
    void add_xor_peer_address(const StunMappedAddress& addr);
    
    /// Add DATA attribute (TURN)
    void add_data(const std::vector<uint8_t>& data);
    
    /// Add CHANNEL-NUMBER attribute (TURN)
    void add_channel_number(uint16_t channel);
    
    /// Parse XOR-MAPPED-ADDRESS from attributes
    std::optional<StunMappedAddress> get_xor_mapped_address() const;
    
    /// Parse MAPPED-ADDRESS from attributes (legacy)
    std::optional<StunMappedAddress> get_mapped_address() const;
    
    /// Parse XOR-RELAYED-ADDRESS from attributes (TURN)
    std::optional<StunMappedAddress> get_xor_relayed_address() const;
    
    /// Parse XOR-PEER-ADDRESS from attributes (TURN)
    std::optional<StunMappedAddress> get_xor_peer_address() const;
    
    /// Parse ERROR-CODE from attributes
    std::optional<StunError> get_error() const;
    
    /// Parse LIFETIME from attributes (TURN)
    std::optional<uint32_t> get_lifetime() const;
    
    /// Parse DATA from attributes (TURN)
    std::optional<std::vector<uint8_t>> get_data() const;
    
    /// Parse REALM from attributes
    std::optional<std::string> get_realm() const;
    
    /// Parse NONCE from attributes
    std::optional<std::string> get_nonce() const;
    
    /// Serialize message to bytes
    std::vector<uint8_t> serialize() const;
    
    /// Serialize message with MESSAGE-INTEGRITY and FINGERPRINT
    std::vector<uint8_t> serialize_with_integrity(const std::string& key) const;
    
    /// Deserialize message from bytes
    static std::optional<StunMessage> deserialize(const std::vector<uint8_t>& data);
    
    /// Check if data looks like a STUN message
    static bool is_stun_message(const std::vector<uint8_t>& data);
};

// ============================================================================
// STUN Client
// ============================================================================

/**
 * STUN client configuration
 */
struct StunClientConfig {
    int rto_ms = STUN_DEFAULT_RTO_MS;           // Initial retransmission timeout
    int max_retransmissions = STUN_MAX_RETRANSMISSIONS;
    int total_timeout_ms = 39500;               // Total timeout (RFC 5389: 39.5 seconds)
    std::string software = "librats";           // Software attribute value
    
    StunClientConfig() = default;
};

/**
 * STUN transaction result
 */
struct StunResult {
    bool success;
    std::optional<StunMappedAddress> mapped_address;
    std::optional<StunError> error;
    int rtt_ms;  // Round-trip time in milliseconds
    
    StunResult() : success(false), rtt_ms(0) {}
};

/**
 * STUN Client for NAT traversal
 * 
 * Example usage:
 * @code
 *   StunClient client;
 *   auto result = client.binding_request("stun.l.google.com", 19302);
 *   if (result.success && result.mapped_address) {
 *       std::cout << "Public address: " << result.mapped_address->to_string() << std::endl;
 *   }
 * @endcode
 */
class StunClient {
public:
    StunClient();
    explicit StunClient(const StunClientConfig& config);
    ~StunClient();
    
    // Non-copyable, movable
    StunClient(const StunClient&) = delete;
    StunClient& operator=(const StunClient&) = delete;
    StunClient(StunClient&&) noexcept;
    StunClient& operator=(StunClient&&) noexcept;
    
    /**
     * Send STUN Binding Request to discover public address
     * @param server STUN server hostname or IP
     * @param port STUN server port (default: 3478)
     * @param timeout_ms Total timeout in milliseconds (0 for config default)
     * @return Result containing mapped address or error
     */
    StunResult binding_request(const std::string& server, 
                               uint16_t port = STUN_DEFAULT_PORT,
                               int timeout_ms = 0);
    
    /**
     * Send STUN Binding Request using existing socket
     * Useful when you need to discover the mapped address for a specific local socket
     * @param socket UDP socket to use (must be bound)
     * @param server STUN server hostname or IP
     * @param port STUN server port
     * @param timeout_ms Total timeout in milliseconds
     * @return Result containing mapped address or error
     */
    StunResult binding_request_with_socket(socket_t socket,
                                           const std::string& server,
                                           uint16_t port,
                                           int timeout_ms = 0);
    
    /**
     * Send a raw STUN message and wait for response
     * @param socket UDP socket to use
     * @param request STUN message to send
     * @param server Destination server
     * @param port Destination port
     * @param timeout_ms Total timeout
     * @return Response message or empty if timeout/error
     */
    std::optional<StunMessage> send_request(socket_t socket,
                                            const StunMessage& request,
                                            const std::string& server,
                                            uint16_t port,
                                            int timeout_ms);
    
    /**
     * Get the configuration
     */
    const StunClientConfig& config() const { return config_; }
    
    /**
     * Set configuration
     */
    void set_config(const StunClientConfig& config) { config_ = config; }
    
private:
    StunClientConfig config_;
    std::mt19937 rng_;
};

// ============================================================================
// STUN Utility Functions
// ============================================================================

/**
 * Compute CRC32 for STUN FINGERPRINT attribute
 * Uses CRC-32 as defined in RFC 5389 (ISO 3309)
 */
uint32_t stun_crc32(const uint8_t* data, size_t length);

/**
 * Compute HMAC-SHA1 for MESSAGE-INTEGRITY attribute
 * @param key The key (typically: MD5(username:realm:password))
 * @param data The message data to authenticate
 * @return 20-byte HMAC-SHA1 result
 */
std::array<uint8_t, 20> stun_hmac_sha1(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& data);

/**
 * Compute long-term credential key: MD5(username:realm:password)
 */
std::vector<uint8_t> stun_compute_long_term_key(const std::string& username,
                                                 const std::string& realm,
                                                 const std::string& password);

/**
 * XOR an address with the magic cookie and transaction ID
 * Used for XOR-MAPPED-ADDRESS encoding/decoding
 */
StunMappedAddress stun_xor_address(const StunMappedAddress& addr,
                                   const std::array<uint8_t, STUN_TRANSACTION_ID_SIZE>& transaction_id);

/**
 * Get a list of well-known public STUN servers
 */
std::vector<std::pair<std::string, uint16_t>> get_public_stun_servers();

} // namespace librats
