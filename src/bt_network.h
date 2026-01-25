#pragma once

/**
 * @file bt_network.h
 * @brief Async network layer for BitTorrent peer connections
 * 
 * Provides efficient multiplexed I/O for managing multiple peer connections
 * with non-blocking sockets and chained send buffers.
 */

#include "bt_types.h"
#include "bt_peer_connection.h"
#include "socket.h"

#include <vector>
#include <queue>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>

namespace librats {

//=============================================================================
// Chained Send Buffer
//=============================================================================

/**
 * @brief A chunk of data in the send buffer
 */
struct SendChunk {
    std::vector<uint8_t> data;  ///< Owned data
    size_t offset;               ///< Current read offset (for partial sends)
    
    SendChunk() : offset(0) {}
    explicit SendChunk(std::vector<uint8_t> d) : data(std::move(d)), offset(0) {}
    
    /// Bytes remaining to send
    size_t remaining() const { return data.size() - offset; }
    
    /// Pointer to current data position
    const uint8_t* current() const { return data.data() + offset; }
};

/**
 * @brief Zero-copy chained send buffer for efficient queuing
 * 
 * Zero-copy chained buffer for efficient sending. Allows appending
 * data chunks without copying, and efficient draining via
 * scatter-gather I/O patterns.
 */
class ChainedSendBuffer {
public:
    ChainedSendBuffer() : total_bytes_(0) {}
    
    /**
     * @brief Append data to the send queue
     */
    void append(std::vector<uint8_t> data);
    
    /**
     * @brief Append data by copying
     */
    void append(const uint8_t* data, size_t length);
    
    /**
     * @brief Pop bytes from the front of the buffer
     * 
     * @param bytes Number of bytes that were successfully sent
     */
    void pop_front(size_t bytes);
    
    /**
     * @brief Build a contiguous buffer for sending
     * 
     * Copies up to max_bytes into the output buffer.
     * 
     * @param buffer Output buffer
     * @param max_bytes Maximum bytes to copy
     * @return Actual bytes copied
     */
    size_t copy_to(uint8_t* buffer, size_t max_bytes) const;
    
    /**
     * @brief Get total bytes pending
     */
    size_t size() const { return total_bytes_; }
    
    /**
     * @brief Check if buffer is empty
     */
    bool empty() const { return total_bytes_ == 0; }
    
    /**
     * @brief Clear all pending data
     */
    void clear();
    
    /**
     * @brief Get number of chunks
     */
    size_t chunk_count() const { return chunks_.size(); }
    
private:
    std::deque<SendChunk> chunks_;
    size_t total_bytes_;
};

//=============================================================================
// Network Configuration
//=============================================================================

/**
 * @brief Configuration for the network manager
 */
struct BtNetworkConfig {
    uint16_t listen_port;           ///< Port for incoming connections (0 = random)
    size_t max_connections;         ///< Maximum total connections
    bool enable_incoming;           ///< Accept incoming connections
    int connect_timeout_ms;         ///< Timeout for outgoing connections (ms)
    int select_timeout_ms;          ///< Timeout for select() call (ms)
    size_t recv_buffer_size;        ///< Size of receive buffer
    size_t send_buffer_high_water;  ///< High water mark for send buffer
    
    BtNetworkConfig()
        : listen_port(6881)
        , max_connections(200)
        , enable_incoming(true)
        , connect_timeout_ms(30000)
        , select_timeout_ms(15)
        , recv_buffer_size(65536)
        , send_buffer_high_water(1024 * 1024) {}  // 1MB
};

//=============================================================================
// Connection State
//=============================================================================

/**
 * @brief State of a network connection
 */
enum class NetConnectionState : uint8_t {
    Connecting,     ///< TCP connect in progress
    Handshaking,    ///< Waiting for BitTorrent handshake
    Connected,      ///< Fully connected and operational
    Closing         ///< Connection being closed
};

/**
 * @brief Information about a pending outgoing connection
 */
struct PendingConnect {
    std::string ip;
    uint16_t port;
    BtInfoHash info_hash;
    PeerID peer_id;
    uint32_t num_pieces;
    socket_t socket;
    std::chrono::steady_clock::time_point start_time;
    
    PendingConnect() : port(0), num_pieces(0), socket(INVALID_SOCKET_VALUE) {}
};

/**
 * @brief Per-socket connection context
 */
struct SocketContext {
    socket_t socket;
    BtInfoHash info_hash;
    std::shared_ptr<BtPeerConnection> connection;
    ChainedSendBuffer send_buffer;
    NetConnectionState state;
    bool incoming;
    std::chrono::steady_clock::time_point connected_at;
    std::chrono::steady_clock::time_point last_activity;
    
    SocketContext()
        : socket(INVALID_SOCKET_VALUE)
        , state(NetConnectionState::Connecting)
        , incoming(false) {}
};

/**
 * @brief Per-torrent registration info
 */
struct TorrentRegistration {
    BtInfoHash info_hash;
    PeerID peer_id;
    uint32_t num_pieces;
    
    TorrentRegistration() : num_pieces(0) {}
};

//=============================================================================
// Network Manager
//=============================================================================

/**
 * @brief Manages all BitTorrent peer connections
 * 
 * Provides async I/O via select() multiplexing:
 * - Listens for incoming connections
 * - Manages outgoing connection queue
 * - Handles non-blocking reads/writes
 * - Invokes callbacks for events
 * 
 * Thread-safety: The manager runs its own I/O thread.
 * Callbacks are invoked from the I/O thread.
 * Public methods are thread-safe.
 */
class BtNetworkManager {
public:
    //=========================================================================
    // Types
    //=========================================================================
    
    /// Callback when a peer connection is established (handshake complete)
    using ConnectedCallback = std::function<void(
        const BtInfoHash& info_hash,
        std::shared_ptr<BtPeerConnection> connection,
        socket_t socket,
        bool incoming
    )>;
    
    /// Callback when a peer disconnects
    using DisconnectedCallback = std::function<void(
        const BtInfoHash& info_hash,
        BtPeerConnection* connection
    )>;
    
    /// Callback when data is received and processed
    using DataCallback = std::function<void(
        const BtInfoHash& info_hash,
        BtPeerConnection* connection,
        socket_t socket
    )>;
    
    //=========================================================================
    // Construction
    //=========================================================================
    
    /**
     * @brief Create network manager with config
     */
    explicit BtNetworkManager(const BtNetworkConfig& config);
    
    /**
     * @brief Destructor - stops the manager
     */
    ~BtNetworkManager();
    
    // Non-copyable
    BtNetworkManager(const BtNetworkManager&) = delete;
    BtNetworkManager& operator=(const BtNetworkManager&) = delete;
    
    //=========================================================================
    // Lifecycle
    //=========================================================================
    
    /**
     * @brief Start the network manager
     * 
     * Creates listen socket and starts I/O thread.
     * 
     * @return true if started successfully
     */
    bool start();
    
    /**
     * @brief Stop the network manager
     * 
     * Closes all connections and stops I/O thread.
     */
    void stop();
    
    /**
     * @brief Check if manager is running
     */
    bool is_running() const { return running_; }
    
    /**
     * @brief Get the actual listen port
     */
    uint16_t listen_port() const { return actual_listen_port_; }
    
    //=========================================================================
    // Torrent Registration
    //=========================================================================
    
    /**
     * @brief Register a torrent to accept connections for
     * 
     * @param info_hash Torrent info hash
     * @param peer_id Our peer ID
     * @param num_pieces Number of pieces in torrent
     */
    void register_torrent(const BtInfoHash& info_hash, 
                          const PeerID& peer_id,
                          uint32_t num_pieces);
    
    /**
     * @brief Unregister a torrent
     * 
     * Closes all connections for this torrent.
     */
    void unregister_torrent(const BtInfoHash& info_hash);
    
    //=========================================================================
    // Connection Management
    //=========================================================================
    
    /**
     * @brief Initiate connection to a peer
     * 
     * @param ip Peer IP address
     * @param port Peer port
     * @param info_hash Torrent info hash
     * @param peer_id Our peer ID
     * @param num_pieces Number of pieces (0 for magnet links)
     * @return true if connection was queued
     */
    bool connect_peer(const std::string& ip, uint16_t port,
                      const BtInfoHash& info_hash,
                      const PeerID& peer_id,
                      uint32_t num_pieces);
    
    /**
     * @brief Close a connection
     * 
     * @param socket Socket to close
     */
    void close_connection(socket_t socket);
    
    /**
     * @brief Send data to a peer
     * 
     * Queues data in the send buffer; actual send is async.
     * 
     * @param socket Target socket
     * @param data Data to send
     * @return true if queued successfully
     */
    bool send_to_peer(socket_t socket, const std::vector<uint8_t>& data);
    
    /**
     * @brief Get number of active connections
     */
    size_t connection_count() const;
    
    /**
     * @brief Get number of pending outgoing connections
     */
    size_t pending_connect_count() const;
    
    //=========================================================================
    // Callbacks
    //=========================================================================
    
    void set_connected_callback(ConnectedCallback cb) { 
        on_connected_ = std::move(cb); 
    }
    
    void set_disconnected_callback(DisconnectedCallback cb) { 
        on_disconnected_ = std::move(cb); 
    }
    
    void set_data_callback(DataCallback cb) { 
        on_data_ = std::move(cb); 
    }
    
private:
    //=========================================================================
    // Internal Methods
    //=========================================================================
    
    /// Main I/O loop (runs in separate thread)
    void io_loop();
    
    /// Process the queue of pending connections
    void process_pending_connects();
    
    /// Accept incoming connections
    void accept_incoming();
    
    /// Handle readable socket
    void handle_readable(socket_t socket);
    
    /// Handle writable socket (drain send buffer)
    void handle_writable(socket_t socket);
    
    /// Handle connection completion
    void handle_connect_complete(socket_t socket, bool success);
    
    /// Handle data received from a peer
    void handle_peer_data(SocketContext& ctx, const uint8_t* data, size_t length);
    
    /// Send handshake on new connection
    void send_handshake(SocketContext& ctx);
    
    /// Process handshake response
    bool process_handshake(SocketContext& ctx);
    
    /// Close connection with cleanup
    void close_connection_internal(socket_t socket, bool notify);
    
    /// Flush send buffers for a socket
    void flush_send_buffer(SocketContext& ctx);
    
    /// Get socket context (must hold mutex_)
    SocketContext* get_context(socket_t socket);
    
    /// Create socket for outgoing connection
    socket_t create_connect_socket(const std::string& ip, uint16_t port);
    
    //=========================================================================
    // Data Members
    //=========================================================================
    
    BtNetworkConfig config_;
    
    std::atomic<bool> running_;
    std::atomic<uint16_t> actual_listen_port_;
    
    socket_t listen_socket_;
    
    mutable std::mutex mutex_;
    
    /// Active connections by socket
    std::unordered_map<socket_t, SocketContext> connections_;
    
    /// Registered torrents by info hash
    std::unordered_map<BtInfoHash, TorrentRegistration, InfoHashHash> torrents_;
    
    /// Queue of pending outgoing connections
    std::queue<PendingConnect> pending_connects_;
    
    /// Pending connects that are in progress (by socket)
    std::unordered_map<socket_t, PendingConnect> connecting_;
    
    /// I/O thread
    std::thread io_thread_;
    
    /// Receive buffer (reused)
    std::vector<uint8_t> recv_buffer_;
    
    /// Callbacks
    ConnectedCallback on_connected_;
    DisconnectedCallback on_disconnected_;
    DataCallback on_data_;
};

} // namespace librats
