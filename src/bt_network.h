#pragma once

/**
 * @file bt_network.h
 * @brief Network layer for BitTorrent peer connections
 * 
 * Handles:
 * - TCP connections to peers (outgoing)
 * - Listening for incoming peer connections
 * - Non-blocking I/O with select/poll
 * - Connection state management
 */

#include "bt_types.h"
#include "bt_peer_connection.h"
#include "socket.h"

#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>
#include <unordered_map>
#include <queue>
#include <chrono>

namespace librats {

//=============================================================================
// Forward Declarations
//=============================================================================

class BtNetworkManager;

//=============================================================================
// Connection Request
//=============================================================================

/**
 * @brief Request to connect to a peer
 */
struct PeerConnectRequest {
    std::string ip;
    uint16_t port;
    BtInfoHash info_hash;
    PeerID our_peer_id;
    uint32_t num_pieces;
    std::chrono::steady_clock::time_point requested_at;
    
    PeerConnectRequest() : port(0), num_pieces(0), 
        requested_at(std::chrono::steady_clock::now()) {}
    
    PeerConnectRequest(const std::string& ip_, uint16_t port_,
                       const BtInfoHash& hash, const PeerID& peer_id,
                       uint32_t pieces)
        : ip(ip_), port(port_), info_hash(hash), our_peer_id(peer_id),
          num_pieces(pieces), requested_at(std::chrono::steady_clock::now()) {}
};

//=============================================================================
// Active Connection
//=============================================================================

/**
 * @brief Active peer connection wrapper
 */
struct ActiveConnection {
    socket_t socket;
    std::shared_ptr<BtPeerConnection> connection;
    BtInfoHash info_hash;
    bool is_incoming;
    bool callback_invoked;  ///< Whether on_peer_connected callback was invoked
    std::chrono::steady_clock::time_point connected_at;
    std::chrono::steady_clock::time_point last_activity;
    
    ActiveConnection() 
        : socket(INVALID_SOCKET_VALUE), 
          is_incoming(false),
          callback_invoked(false),
          connected_at(std::chrono::steady_clock::now()),
          last_activity(std::chrono::steady_clock::now()) {}
};

//=============================================================================
// Pending Connection (connecting)
//=============================================================================

/**
 * @brief Connection in progress (non-blocking connect)
 */
struct PendingConnection {
    socket_t socket;
    PeerConnectRequest request;
    std::chrono::steady_clock::time_point started_at;
    
    PendingConnection() : socket(INVALID_SOCKET_VALUE),
        started_at(std::chrono::steady_clock::now()) {}
};

//=============================================================================
// Network Manager Callbacks
//=============================================================================

/**
 * @brief Callback when a new peer connection is established
 */
using PeerConnectedCallback = std::function<void(
    const BtInfoHash& info_hash,
    std::shared_ptr<BtPeerConnection> connection,
    socket_t socket,
    bool is_incoming
)>;

/**
 * @brief Callback when a peer disconnects
 */
using PeerDisconnectedCallback = std::function<void(
    const BtInfoHash& info_hash,
    BtPeerConnection* connection
)>;

/**
 * @brief Callback when data is received from a peer
 */
using PeerDataCallback = std::function<void(
    const BtInfoHash& info_hash,
    BtPeerConnection* connection,
    socket_t socket
)>;

//=============================================================================
// Network Manager Configuration
//=============================================================================

struct BtNetworkConfig {
    uint16_t listen_port;           ///< Port for incoming connections (0 = random)
    size_t max_connections;         ///< Maximum total connections
    size_t max_pending_connects;    ///< Max simultaneous connect attempts
    int connect_timeout_ms;         ///< Timeout for connection attempts
    int socket_timeout_ms;          ///< General socket timeout
    bool enable_incoming;           ///< Accept incoming connections
    
    BtNetworkConfig()
        : listen_port(6881)
        , max_connections(200)
        , max_pending_connects(30)
        , connect_timeout_ms(10000)
        , socket_timeout_ms(30000)
        , enable_incoming(true) {}
};

//=============================================================================
// BitTorrent Network Manager
//=============================================================================

/**
 * @brief Manages all BitTorrent peer network connections
 * 
 * This class handles:
 * - Listening for incoming peer connections
 * - Initiating outgoing connections to peers
 * - Non-blocking socket I/O
 * - Connection lifecycle management
 * 
 * Thread-safe: Uses internal locking for all operations.
 */
class BtNetworkManager {
public:
    //=========================================================================
    // Construction
    //=========================================================================
    
    explicit BtNetworkManager(const BtNetworkConfig& config = BtNetworkConfig());
    ~BtNetworkManager();
    
    // Non-copyable
    BtNetworkManager(const BtNetworkManager&) = delete;
    BtNetworkManager& operator=(const BtNetworkManager&) = delete;
    
    //=========================================================================
    // Lifecycle
    //=========================================================================
    
    /**
     * @brief Start the network manager
     * @return true if started successfully
     */
    bool start();
    
    /**
     * @brief Stop the network manager
     */
    void stop();
    
    /**
     * @brief Check if running
     */
    bool is_running() const { return running_.load(); }
    
    /**
     * @brief Get the actual listen port (may differ if 0 was configured)
     */
    uint16_t listen_port() const { return actual_listen_port_; }
    
    //=========================================================================
    // Connection Management
    //=========================================================================
    
    /**
     * @brief Queue a connection request to a peer
     * 
     * @param ip Peer IP address
     * @param port Peer port
     * @param info_hash Info hash of the torrent
     * @param our_peer_id Our peer ID
     * @param num_pieces Number of pieces in the torrent
     * @return true if queued successfully
     */
    bool connect_peer(const std::string& ip, uint16_t port,
                      const BtInfoHash& info_hash,
                      const PeerID& our_peer_id,
                      uint32_t num_pieces);
    
    /**
     * @brief Register info hash for accepting incoming connections
     */
    void register_torrent(const BtInfoHash& info_hash,
                          const PeerID& our_peer_id,
                          uint32_t num_pieces);
    
    /**
     * @brief Unregister info hash
     */
    void unregister_torrent(const BtInfoHash& info_hash);
    
    /**
     * @brief Send data to a peer
     */
    bool send_to_peer(socket_t socket, const std::vector<uint8_t>& data);
    
    /**
     * @brief Close a peer connection
     */
    void close_connection(socket_t socket);
    
    /**
     * @brief Get number of active connections
     */
    size_t num_connections() const;
    
    /**
     * @brief Get number of pending connect attempts
     */
    size_t num_pending() const;
    
    //=========================================================================
    // Callbacks
    //=========================================================================
    
    void set_connected_callback(PeerConnectedCallback cb) { 
        on_peer_connected_ = std::move(cb); 
    }
    
    void set_disconnected_callback(PeerDisconnectedCallback cb) { 
        on_peer_disconnected_ = std::move(cb); 
    }
    
    void set_data_callback(PeerDataCallback cb) { 
        on_peer_data_ = std::move(cb); 
    }
    
private:
    //=========================================================================
    // Internal Methods
    //=========================================================================
    
    void network_loop();
    void process_connect_queue();
    void process_pending_connects();
    void process_listen_socket();
    void process_active_connections();
    void handle_incoming_connection(socket_t client_socket, const std::string& peer_addr);
    void handle_connection_established(PendingConnection& pending);
    void handle_peer_data(ActiveConnection& conn);
    void flush_send_buffer(socket_t sock);
    void flush_send_buffer_internal(ActiveConnection& conn);
    void cleanup_stale_connections();
    
    //=========================================================================
    // Data Members
    //=========================================================================
    
    BtNetworkConfig config_;
    std::atomic<bool> running_;
    uint16_t actual_listen_port_;
    
    // Listen socket
    socket_t listen_socket_;
    
    // Network thread
    std::thread network_thread_;
    
    // Connection queues
    std::queue<PeerConnectRequest> connect_queue_;
    std::mutex queue_mutex_;
    
    // Pending connections (connecting)
    std::vector<PendingConnection> pending_connections_;
    mutable std::mutex pending_mutex_;
    
    // Active connections
    std::unordered_map<socket_t, ActiveConnection> active_connections_;
    mutable std::mutex connections_mutex_;
    
    // Registered torrents (for incoming connections)
    struct TorrentRegistration {
        PeerID our_peer_id;
        uint32_t num_pieces;
    };
    std::unordered_map<BtInfoHash, TorrentRegistration, InfoHashHash> registered_torrents_;
    std::mutex torrents_mutex_;
    
    // Callbacks
    PeerConnectedCallback on_peer_connected_;
    PeerDisconnectedCallback on_peer_disconnected_;
    PeerDataCallback on_peer_data_;
};

} // namespace librats
