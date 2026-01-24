#pragma once

/**
 * @file bt_peer_connection.h
 * @brief BitTorrent peer connection management
 * 
 * Handles TCP connections to peers, message buffering, and state management.
 */

#include "bt_types.h"
#include "bt_bitfield.h"
#include "bt_messages.h"
#include "bt_handshake.h"

#include <vector>
#include <queue>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>

namespace librats {

//=============================================================================
// Connection State
//=============================================================================

/**
 * @brief State of a peer connection
 */
enum class PeerConnectionState : uint8_t {
    Disconnected,       ///< Not connected
    Connecting,         ///< TCP connection in progress
    Handshaking,        ///< Waiting for handshake
    Connected,          ///< Connected and ready
    Closing             ///< Connection closing
};

/**
 * @brief Convert state to string
 */
const char* peer_state_to_string(PeerConnectionState state);

//=============================================================================
// Peer Statistics
//=============================================================================

/**
 * @brief Statistics for a peer connection
 */
struct PeerStats {
    uint64_t bytes_downloaded;      ///< Total bytes downloaded from peer
    uint64_t bytes_uploaded;        ///< Total bytes uploaded to peer
    uint32_t pieces_received;       ///< Number of pieces received
    uint32_t pieces_sent;           ///< Number of pieces sent
    uint32_t messages_received;     ///< Total messages received
    uint32_t messages_sent;         ///< Total messages sent
    
    std::chrono::steady_clock::time_point connected_at;
    std::chrono::steady_clock::time_point last_message_at;
    std::chrono::steady_clock::time_point last_piece_at;
    
    PeerStats() 
        : bytes_downloaded(0), bytes_uploaded(0)
        , pieces_received(0), pieces_sent(0)
        , messages_received(0), messages_sent(0) {}
    
    /**
     * @brief Calculate download speed (bytes/sec over last interval)
     */
    double download_rate() const;
    
    /**
     * @brief Calculate upload speed (bytes/sec over last interval)
     */
    double upload_rate() const;
};

//=============================================================================
// Peer Connection
//=============================================================================

/**
 * @brief Represents a connection to a BitTorrent peer
 * 
 * This class manages:
 * - TCP connection state
 * - Handshake exchange
 * - Message buffering and parsing
 * - Choking/interest state
 * - Pending block requests
 * 
 * Thread-safety: Most methods require external synchronization.
 * The connection uses callbacks for received data/messages.
 */
class BtPeerConnection {
public:
    //=========================================================================
    // Types
    //=========================================================================
    
    /// Callback for received messages
    using MessageCallback = std::function<void(BtPeerConnection*, const BtMessage&)>;
    
    /// Callback for connection state changes
    using StateCallback = std::function<void(BtPeerConnection*, PeerConnectionState)>;
    
    /// Callback for handshake completion
    using HandshakeCallback = std::function<void(BtPeerConnection*, const Handshake&)>;
    
    /// Callback for errors
    using ErrorCallback = std::function<void(BtPeerConnection*, const std::string&)>;
    
    //=========================================================================
    // Construction
    //=========================================================================
    
    /**
     * @brief Create a peer connection
     * 
     * @param info_hash Our info hash
     * @param our_peer_id Our peer ID
     * @param num_pieces Number of pieces in torrent
     */
    BtPeerConnection(const BtInfoHash& info_hash, 
                     const PeerID& our_peer_id,
                     uint32_t num_pieces);
    
    /**
     * @brief Destructor
     */
    ~BtPeerConnection();
    
    // Non-copyable
    BtPeerConnection(const BtPeerConnection&) = delete;
    BtPeerConnection& operator=(const BtPeerConnection&) = delete;
    
    // Movable
    BtPeerConnection(BtPeerConnection&&) noexcept;
    BtPeerConnection& operator=(BtPeerConnection&&) noexcept;
    
    //=========================================================================
    // Connection Management
    //=========================================================================
    
    /**
     * @brief Set the socket descriptor (after successful connect)
     */
    void set_socket(int socket_fd);
    
    /**
     * @brief Get the socket descriptor
     */
    int socket() const { return socket_fd_; }
    
    /**
     * @brief Set peer address for identification
     */
    void set_address(const std::string& ip, uint16_t port);
    
    /**
     * @brief Get peer IP address
     */
    const std::string& ip() const { return ip_; }
    
    /**
     * @brief Get peer port
     */
    uint16_t port() const { return port_; }
    
    /**
     * @brief Get connection state
     */
    PeerConnectionState state() const { return state_; }
    
    /**
     * @brief Check if connected and ready
     */
    bool is_connected() const { return state_ == PeerConnectionState::Connected; }
    
    /**
     * @brief Start handshake (send our handshake)
     */
    void start_handshake();
    
    /**
     * @brief Close the connection
     */
    void close();
    
    //=========================================================================
    // Data Processing
    //=========================================================================
    
    /**
     * @brief Process received data from socket
     * 
     * Buffers data and parses complete messages.
     * Calls message callbacks as messages are received.
     * 
     * @param data Received data
     * @param length Data length
     */
    void on_receive(const uint8_t* data, size_t length);
    
    /**
     * @brief Get data to send (from send queue)
     * 
     * @param buffer Output buffer
     * @param max_length Maximum bytes to copy
     * @return Number of bytes copied
     */
    size_t get_send_data(uint8_t* buffer, size_t max_length);
    
    /**
     * @brief Check if there's data to send
     */
    bool has_send_data() const;
    
    /**
     * @brief Mark bytes as sent (remove from queue)
     */
    void mark_sent(size_t bytes);
    
    //=========================================================================
    // Callbacks
    //=========================================================================
    
    void set_message_callback(MessageCallback cb) { on_message_ = std::move(cb); }
    void set_state_callback(StateCallback cb) { on_state_change_ = std::move(cb); }
    void set_handshake_callback(HandshakeCallback cb) { on_handshake_ = std::move(cb); }
    void set_error_callback(ErrorCallback cb) { on_error_ = std::move(cb); }
    
    //=========================================================================
    // Protocol State
    //=========================================================================
    
    /**
     * @brief Check if we are choking the peer
     */
    bool am_choking() const { return am_choking_; }
    
    /**
     * @brief Check if we are interested in the peer
     */
    bool am_interested() const { return am_interested_; }
    
    /**
     * @brief Check if peer is choking us
     */
    bool peer_choking() const { return peer_choking_; }
    
    /**
     * @brief Check if peer is interested in us
     */
    bool peer_interested() const { return peer_interested_; }
    
    /**
     * @brief Get peer's have bitfield
     */
    const Bitfield& peer_pieces() const { return peer_pieces_; }
    
    /**
     * @brief Check if peer has a specific piece
     */
    bool peer_has_piece(uint32_t piece) const;
    
    /**
     * @brief Get peer's info hash (from handshake)
     */
    const BtInfoHash& peer_info_hash() const { return peer_info_hash_; }
    
    /**
     * @brief Get peer's peer ID (from handshake)
     */
    const PeerID& peer_id() const { return peer_id_; }
    
    /**
     * @brief Get extension flags from handshake
     */
    const ExtensionFlags& peer_extensions() const { return peer_extensions_; }
    
    //=========================================================================
    // Extension Handshake Data (stored for late callback registration)
    //=========================================================================
    
    /**
     * @brief Check if we've received the peer's extension handshake
     */
    bool extension_handshake_received() const { return extension_handshake_received_; }
    
    /**
     * @brief Get peer's metadata size (from extension handshake, 0 if not available)
     */
    size_t peer_metadata_size() const { return peer_metadata_size_; }
    
    /**
     * @brief Get peer's ut_metadata message ID (from extension handshake, 0 if not supported)
     */
    uint8_t peer_ut_metadata_id() const { return peer_ut_metadata_id_; }
    
    //=========================================================================
    // Sending Messages
    //=========================================================================
    
    /**
     * @brief Send a choke message
     */
    void send_choke();
    
    /**
     * @brief Send an unchoke message
     */
    void send_unchoke();
    
    /**
     * @brief Send an interested message
     */
    void send_interested();
    
    /**
     * @brief Send a not interested message
     */
    void send_not_interested();
    
    /**
     * @brief Send a have message
     */
    void send_have(uint32_t piece_index);
    
    /**
     * @brief Send our bitfield
     */
    void send_bitfield(const Bitfield& bitfield);
    
    /**
     * @brief Send a request message
     */
    void send_request(uint32_t piece, uint32_t begin, uint32_t length);
    
    /**
     * @brief Send a piece (block data)
     */
    void send_piece(uint32_t piece, uint32_t begin, const uint8_t* data, size_t length);
    
    /**
     * @brief Send a cancel message
     */
    void send_cancel(uint32_t piece, uint32_t begin, uint32_t length);
    
    /**
     * @brief Send a keep-alive
     */
    void send_keepalive();
    
    /**
     * @brief Send an extended message
     */
    void send_extended(uint8_t extension_id, const std::vector<uint8_t>& payload);
    
    //=========================================================================
    // Request Tracking
    //=========================================================================
    
    /**
     * @brief Get number of pending requests to this peer
     */
    size_t pending_requests() const { return pending_requests_.size(); }
    
    /**
     * @brief Get maximum allowed pending requests
     */
    size_t max_pending_requests() const { return max_pending_requests_; }
    
    /**
     * @brief Set maximum pending requests
     */
    void set_max_pending_requests(size_t max) { max_pending_requests_ = max; }
    
    /**
     * @brief Check if we can send more requests
     */
    bool can_request() const { 
        return !peer_choking_ && pending_requests_.size() < max_pending_requests_; 
    }
    
    /**
     * @brief Add a pending request
     */
    void add_pending_request(const RequestMessage& req);
    
    /**
     * @brief Remove a pending request (when received or cancelled)
     */
    void remove_pending_request(const RequestMessage& req);
    
    /**
     * @brief Clear all pending requests
     */
    void clear_pending_requests();
    
    /**
     * @brief Get all pending requests
     */
    const std::vector<RequestMessage>& get_pending_requests() const { return pending_requests_; }
    
    //=========================================================================
    // Statistics
    //=========================================================================
    
    /**
     * @brief Get connection statistics
     */
    const PeerStats& stats() const { return stats_; }
    
    /**
     * @brief Get a mutable reference to stats
     */
    PeerStats& stats() { return stats_; }
    
private:
    //=========================================================================
    // Internal Methods
    //=========================================================================
    
    void set_state(PeerConnectionState new_state);
    void queue_send(const std::vector<uint8_t>& data);
    void process_handshake();
    void process_messages();
    void handle_message(const BtMessage& msg);
    void parse_extension_handshake(const std::vector<uint8_t>& payload);
    
    //=========================================================================
    // Data Members
    //=========================================================================
    
    // Connection
    int socket_fd_;
    std::string ip_;
    uint16_t port_;
    std::atomic<PeerConnectionState> state_;
    
    // Our identity
    BtInfoHash our_info_hash_;
    PeerID our_peer_id_;
    uint32_t num_pieces_;
    
    // Peer identity (from handshake)
    BtInfoHash peer_info_hash_;
    PeerID peer_id_;
    ExtensionFlags peer_extensions_;
    bool handshake_received_;
    bool handshake_sent_;
    
    // Extension handshake data (stored for late callback registration)
    bool extension_handshake_received_;
    size_t peer_metadata_size_;
    uint8_t peer_ut_metadata_id_;
    
    // Protocol state
    bool am_choking_;
    bool am_interested_;
    bool peer_choking_;
    bool peer_interested_;
    
    // Peer's pieces
    Bitfield peer_pieces_;
    
    // Buffers
    std::vector<uint8_t> recv_buffer_;
    std::vector<uint8_t> send_buffer_;
    size_t send_offset_;
    
    // Pending requests
    std::vector<RequestMessage> pending_requests_;
    size_t max_pending_requests_;
    
    // Statistics
    PeerStats stats_;
    
    // Callbacks
    MessageCallback on_message_;
    StateCallback on_state_change_;
    HandshakeCallback on_handshake_;
    ErrorCallback on_error_;
};

} // namespace librats
