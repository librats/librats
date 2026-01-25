#include "bt_network.h"
#include "bt_handshake.h"
#include "network_utils.h"
#include "logger.h"

#include <algorithm>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/select.h>
    #include <netinet/tcp.h>
    #include <fcntl.h>
    #include <errno.h>
#endif

// Module logging macros
#define LOG_NET_DEBUG(msg) LOG_DEBUG("BtNetwork", msg)
#define LOG_NET_INFO(msg)  LOG_INFO("BtNetwork", msg)
#define LOG_NET_WARN(msg)  LOG_WARN("BtNetwork", msg)
#define LOG_NET_ERROR(msg) LOG_ERROR("BtNetwork", msg)

namespace librats {

//=============================================================================
// ChainedSendBuffer Implementation
//=============================================================================

void ChainedSendBuffer::append(std::vector<uint8_t> data) {
    if (data.empty()) return;
    total_bytes_ += data.size();
    chunks_.emplace_back(std::move(data));
}

void ChainedSendBuffer::append(const uint8_t* data, size_t length) {
    if (length == 0) return;
    std::vector<uint8_t> chunk(data, data + length);
    append(std::move(chunk));
}

void ChainedSendBuffer::pop_front(size_t bytes) {
    while (bytes > 0 && !chunks_.empty()) {
        SendChunk& front = chunks_.front();
        size_t remaining = front.remaining();
        
        if (bytes >= remaining) {
            // Consume entire chunk
            bytes -= remaining;
            total_bytes_ -= remaining;
            chunks_.pop_front();
        } else {
            // Partial consume
            front.offset += bytes;
            total_bytes_ -= bytes;
            bytes = 0;
        }
    }
}

size_t ChainedSendBuffer::copy_to(uint8_t* buffer, size_t max_bytes) const {
    size_t copied = 0;
    
    for (const auto& chunk : chunks_) {
        if (copied >= max_bytes) break;
        
        size_t remaining = chunk.remaining();
        size_t to_copy = std::min(remaining, max_bytes - copied);
        
        std::memcpy(buffer + copied, chunk.current(), to_copy);
        copied += to_copy;
    }
    
    return copied;
}

void ChainedSendBuffer::clear() {
    chunks_.clear();
    total_bytes_ = 0;
}

//=============================================================================
// BtNetworkManager Construction
//=============================================================================

BtNetworkManager::BtNetworkManager(const BtNetworkConfig& config)
    : config_(config)
    , running_(false)
    , actual_listen_port_(0)
    , listen_socket_(INVALID_SOCKET_VALUE) {
    recv_buffer_.resize(config_.recv_buffer_size);
}

BtNetworkManager::~BtNetworkManager() {
    stop();
}

//=============================================================================
// Lifecycle
//=============================================================================

bool BtNetworkManager::start() {
    if (running_) return true;
    
    // Create listen socket if incoming enabled
    if (config_.enable_incoming) {
        listen_socket_ = create_tcp_server(config_.listen_port, 50);
        if (!is_valid_socket(listen_socket_)) {
            LOG_NET_ERROR("Failed to create listen socket on port " + 
                          std::to_string(config_.listen_port));
            return false;
        }
        
        // Set non-blocking
        if (!set_socket_nonblocking(listen_socket_)) {
            LOG_NET_ERROR("Failed to set listen socket non-blocking");
            close_socket(listen_socket_);
            listen_socket_ = INVALID_SOCKET_VALUE;
            return false;
        }
        
        // Get actual port (in case 0 was specified)
        actual_listen_port_ = static_cast<uint16_t>(get_ephemeral_port(listen_socket_));
        if (actual_listen_port_ == 0) {
            actual_listen_port_ = config_.listen_port;
        }
        
        LOG_NET_INFO("Listening on port " + std::to_string(actual_listen_port_));
    }
    
    running_ = true;
    
    // Start I/O thread
    io_thread_ = std::thread(&BtNetworkManager::io_loop, this);
    
    LOG_NET_INFO("Network manager started");
    return true;
}

void BtNetworkManager::stop() {
    if (!running_) return;
    
    running_ = false;
    
    // Wait for I/O thread
    if (io_thread_.joinable()) {
        io_thread_.join();
    }
    
    std::vector<DisconnectedEvent> disconnected_events;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Collect disconnected events for all connections
        for (auto& [socket, ctx] : connections_) {
            if (ctx.connection) {
                DisconnectedEvent event;
                event.info_hash = ctx.info_hash;
                event.connection = ctx.connection;
                disconnected_events.push_back(std::move(event));
            }
            close_socket(socket, true);
        }
        connections_.clear();
        
        // Close connecting sockets
        for (auto& [socket, pending] : connecting_) {
            close_socket(socket, true);
        }
        connecting_.clear();
        
        // Clear pending queue
        while (!pending_connects_.empty()) {
            pending_connects_.pop();
        }
        
        // Close listen socket
        if (is_valid_socket(listen_socket_)) {
            close_socket(listen_socket_);
            listen_socket_ = INVALID_SOCKET_VALUE;
        }
        
        LOG_NET_INFO("Network manager stopped");
    }
    
    // Invoke callbacks outside mutex
    for (const auto& event : disconnected_events) {
        if (on_disconnected_) {
            on_disconnected_(event.info_hash, event.connection.get());
        }
    }
}

//=============================================================================
// Torrent Registration
//=============================================================================

void BtNetworkManager::register_torrent(const BtInfoHash& info_hash,
                                         const PeerID& peer_id,
                                         uint32_t num_pieces) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    TorrentRegistration reg;
    reg.info_hash = info_hash;
    reg.peer_id = peer_id;
    reg.num_pieces = num_pieces;
    
    torrents_[info_hash] = reg;
    
    LOG_NET_DEBUG("Registered torrent " + info_hash_to_hex(info_hash).substr(0, 8) + "...");
}

void BtNetworkManager::unregister_torrent(const BtInfoHash& info_hash) {
    std::vector<DisconnectedEvent> disconnected_events;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Close all connections for this torrent
        std::vector<socket_t> to_close;
        for (auto& [socket, ctx] : connections_) {
            if (ctx.info_hash == info_hash) {
                to_close.push_back(socket);
            }
        }
        
        for (socket_t s : to_close) {
            close_connection_internal(s, disconnected_events);
        }
        
        torrents_.erase(info_hash);
        
        LOG_NET_DEBUG("Unregistered torrent " + info_hash_to_hex(info_hash).substr(0, 8) + "...");
    }
    
    // Invoke callbacks outside mutex
    for (const auto& event : disconnected_events) {
        if (on_disconnected_) {
            on_disconnected_(event.info_hash, event.connection.get());
        }
    }
}

//=============================================================================
// Connection Management
//=============================================================================

bool BtNetworkManager::connect_peer(const std::string& ip, uint16_t port,
                                     const BtInfoHash& info_hash,
                                     const PeerID& peer_id,
                                     uint32_t num_pieces) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check connection limit
    if (connections_.size() + connecting_.size() >= config_.max_connections) {
        LOG_NET_DEBUG("Connection limit reached, cannot connect to " + ip);
        return false;
    }
    
    // Check if already connected/connecting to this peer
    for (const auto& [sock, ctx] : connections_) {
        if (ctx.connection && ctx.connection->ip() == ip && 
            ctx.connection->port() == port) {
            LOG_NET_DEBUG("Already connected to " + ip + ":" + std::to_string(port));
            return false;
        }
    }
    
    for (const auto& [sock, pending] : connecting_) {
        if (pending.ip == ip && pending.port == port) {
            LOG_NET_DEBUG("Already connecting to " + ip + ":" + std::to_string(port));
            return false;
        }
    }
    
    // Queue the connection
    PendingConnect pending;
    pending.ip = ip;
    pending.port = port;
    pending.info_hash = info_hash;
    pending.peer_id = peer_id;
    pending.num_pieces = num_pieces;
    pending.socket = INVALID_SOCKET_VALUE;
    pending.start_time = std::chrono::steady_clock::now();
    
    pending_connects_.push(std::move(pending));
    
    LOG_NET_DEBUG("Queued connection to " + ip + ":" + std::to_string(port));
    return true;
}

void BtNetworkManager::close_connection(socket_t socket) {
    std::vector<DisconnectedEvent> disconnected_events;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        close_connection_internal(socket, disconnected_events);
    }
    
    // Invoke callbacks outside mutex
    for (const auto& event : disconnected_events) {
        if (on_disconnected_) {
            on_disconnected_(event.info_hash, event.connection.get());
        }
    }
}

bool BtNetworkManager::send_to_peer(socket_t socket, const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = connections_.find(socket);
    if (it == connections_.end()) {
        return false;
    }
    
    // Check high water mark
    if (it->second.send_buffer.size() + data.size() > config_.send_buffer_high_water) {
        LOG_NET_WARN("Send buffer high water reached for " + 
                     it->second.connection->ip());
        return false;
    }
    
    it->second.send_buffer.append(data.data(), data.size());
    return true;
}

size_t BtNetworkManager::connection_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connections_.size();
}

size_t BtNetworkManager::pending_connect_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_connects_.size() + connecting_.size();
}

//=============================================================================
// I/O Loop
//=============================================================================

void BtNetworkManager::io_loop() {
    LOG_NET_DEBUG("I/O loop started");
    
    // Event vectors for deferred callback invocation (outside mutex)
    std::vector<ConnectedEvent> connected_events;
    std::vector<DataEvent> data_events;
    std::vector<DisconnectedEvent> disconnected_events;
    
    while (running_) {
        // Clear event vectors for this iteration
        connected_events.clear();
        data_events.clear();
        disconnected_events.clear();
        
        // Process pending connect queue
        process_pending_connects();
        
        // Build fd_sets
        fd_set read_fds, write_fds, error_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_ZERO(&error_fds);
        
        socket_t max_fd = 0;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Add listen socket
            if (is_valid_socket(listen_socket_)) {
                FD_SET(listen_socket_, &read_fds);
                if (listen_socket_ > max_fd) max_fd = listen_socket_;
            }
            
            // Add connected sockets
            for (auto& [socket, ctx] : connections_) {
                FD_SET(socket, &read_fds);
                FD_SET(socket, &error_fds);
                
                // Only monitor for write if we have data to send
                if (!ctx.send_buffer.empty()) {
                    FD_SET(socket, &write_fds);
                }
                
                if (socket > max_fd) max_fd = socket;
            }
            
            // Add connecting sockets (monitor for write = connect complete)
            for (auto& [socket, pending] : connecting_) {
                FD_SET(socket, &write_fds);
                FD_SET(socket, &error_fds);
                if (socket > max_fd) max_fd = socket;
            }
        }
        
        // If no sockets to monitor, sleep to avoid CPU spinning.
        // This happens when enable_incoming=false and no connections yet.
        if (max_fd == 0) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.select_timeout_ms));
            continue;
        }
        
        // Select with timeout
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = config_.select_timeout_ms * 1000;
        
        int result = select(static_cast<int>(max_fd) + 1, 
                           &read_fds, &write_fds, &error_fds, &timeout);
        
        if (result < 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err != WSAEINTR) {
                LOG_NET_ERROR("select() failed: " + std::to_string(err));
                // Avoid spinning on persistent errors
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
#else
            if (errno != EINTR) {
                LOG_NET_ERROR("select() failed: " + std::string(strerror(errno)));
                // Avoid spinning on persistent errors
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
#endif
            continue;
        }
        
        if (result == 0) {
            // Timeout - check for connection timeouts
            auto now = std::chrono::steady_clock::now();
            
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<socket_t> timed_out;
            for (auto& [socket, pending] : connecting_) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - pending.start_time).count();
                if (elapsed > config_.connect_timeout_ms) {
                    timed_out.push_back(socket);
                }
            }
            
            for (socket_t s : timed_out) {
                LOG_NET_DEBUG("Connection timed out to " + connecting_[s].ip);
                close_socket(s);
                connecting_.erase(s);
            }
            
            continue;
        }
        
        LOG_NET_DEBUG("process_pending_connects: select() returned " + std::to_string(result) + " ready");
        
        // Handle listen socket
        if (is_valid_socket(listen_socket_) && FD_ISSET(listen_socket_, &read_fds)) {
            accept_incoming();
        }
        
        // Handle connecting sockets
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<socket_t> completed;
            for (auto& [socket, pending] : connecting_) {
                if (FD_ISSET(socket, &error_fds)) {
                    completed.push_back(socket);
                } else if (FD_ISSET(socket, &write_fds)) {
                    // Check if connection succeeded
                    int sock_error = 0;
                    socklen_t len = sizeof(sock_error);
                    getsockopt(socket, SOL_SOCKET, SO_ERROR, 
                              reinterpret_cast<char*>(&sock_error), &len);
                    
                    if (sock_error == 0) {
                        LOG_NET_INFO("Connected to peer " + pending.ip + ":" + 
                                    std::to_string(pending.port));
                        
                        // Create connection object
                        auto conn = std::make_shared<BtPeerConnection>(
                            pending.info_hash, pending.peer_id, pending.num_pieces);
                        conn->set_address(pending.ip, pending.port);
                        conn->set_socket(static_cast<int>(socket));
                        
                        // Create socket context
                        SocketContext ctx;
                        ctx.socket = socket;
                        ctx.info_hash = pending.info_hash;
                        ctx.connection = conn;
                        ctx.state = NetConnectionState::Handshaking;
                        ctx.incoming = false;
                        ctx.connected_at = std::chrono::steady_clock::now();
                        ctx.last_activity = ctx.connected_at;
                        
                        // Send handshake
                        LOG_NET_DEBUG("Sending handshake (" + 
                                     std::to_string(BT_HANDSHAKE_SIZE) + " bytes) to " + 
                                     pending.ip);
                        auto hs = BtHandshake::encode_with_extensions(
                            pending.info_hash, pending.peer_id);
                        ctx.send_buffer.append(std::move(hs));
                        
                        connections_[socket] = std::move(ctx);
                        
                        LOG_NET_DEBUG("Handshake sent successfully to " + pending.ip);
                    } else {
                        LOG_NET_DEBUG("Connection failed to " + pending.ip + ": " + 
                                     std::to_string(sock_error));
                        close_socket(socket);
                    }
                    completed.push_back(socket);
                }
            }
            
            for (socket_t s : completed) {
                connecting_.erase(s);
            }
        }
        
        // Handle active connections (collect events under mutex)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<socket_t> to_close;
            
            for (auto& [socket, ctx] : connections_) {
                bool should_close = false;
                
                if (FD_ISSET(socket, &error_fds)) {
                    if (ctx.connection) {
                        LOG_NET_DEBUG("Error on socket for " + ctx.connection->ip());
                    }
                    should_close = true;
                }
                
                if (!should_close && FD_ISSET(socket, &read_fds)) {
                    handle_readable(socket, connected_events, data_events, disconnected_events);
                    
                    // Check if connection was closed
                    auto it = connections_.find(socket);
                    if (it == connections_.end()) {
                        continue;  // Already removed
                    }
                }
                
                if (!should_close && FD_ISSET(socket, &write_fds)) {
                    handle_writable(socket, disconnected_events);
                }
                
                if (should_close) {
                    to_close.push_back(socket);
                }
            }
            
            for (socket_t s : to_close) {
                close_connection_internal(s, disconnected_events);
            }
        }
        
        // Invoke callbacks OUTSIDE the mutex to prevent deadlocks
        for (const auto& event : connected_events) {
            if (on_connected_) {
                on_connected_(event.info_hash, event.connection, 
                             event.socket, event.incoming);
            }
        }
        
        for (const auto& event : data_events) {
            if (on_data_) {
                on_data_(event.info_hash, event.connection.get(), event.socket);
            }
        }
        
        for (const auto& event : disconnected_events) {
            if (on_disconnected_) {
                on_disconnected_(event.info_hash, event.connection.get());
            }
        }
    }
    
    LOG_NET_DEBUG("I/O loop stopped");
}

void BtNetworkManager::process_pending_connects() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Limit concurrent connects
    const size_t max_concurrent = 30;
    
    while (!pending_connects_.empty() && 
           connecting_.size() < max_concurrent &&
           connections_.size() + connecting_.size() < config_.max_connections) {
        
        PendingConnect pending = std::move(pending_connects_.front());
        pending_connects_.pop();
        
        // Create non-blocking socket
        socket_t sock = create_connect_socket(pending.ip, pending.port);
        if (!is_valid_socket(sock)) {
            continue;
        }
        
        pending.socket = sock;
        pending.start_time = std::chrono::steady_clock::now();
        
        connecting_[sock] = std::move(pending);
    }
    
    if (!pending_connects_.empty()) {
        LOG_NET_DEBUG("process_pending_connects: " + 
                     std::to_string(connecting_.size()) + " pending");
    }
}

socket_t BtNetworkManager::create_connect_socket(const std::string& ip, uint16_t port) {
    // Create socket
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (!is_valid_socket(sock)) {
        LOG_NET_ERROR("Failed to create socket");
        return INVALID_SOCKET_VALUE;
    }
    
    // Set non-blocking
    if (!set_socket_nonblocking(sock)) {
        LOG_NET_ERROR("Failed to set socket non-blocking");
        close_socket(sock);
        return INVALID_SOCKET_VALUE;
    }
    
    // Resolve and connect
    std::string resolved = network_utils::resolve_hostname(ip);
    if (resolved.empty()) {
        LOG_NET_ERROR("Failed to resolve " + ip);
        close_socket(sock);
        return INVALID_SOCKET_VALUE;
    }
    
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, resolved.c_str(), &addr.sin_addr) <= 0) {
        LOG_NET_ERROR("Invalid address: " + resolved);
        close_socket(sock);
        return INVALID_SOCKET_VALUE;
    }
    
    LOG_NET_DEBUG("Connecting to " + ip + ":" + std::to_string(port));
    
    int result = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (result < 0) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            LOG_NET_DEBUG("Connect failed immediately: " + std::to_string(err));
            close_socket(sock);
            return INVALID_SOCKET_VALUE;
        }
#else
        if (errno != EINPROGRESS) {
            LOG_NET_DEBUG("Connect failed immediately: " + std::string(strerror(errno)));
            close_socket(sock);
            return INVALID_SOCKET_VALUE;
        }
#endif
    }
    
    return sock;
}

void BtNetworkManager::accept_incoming() {
    socket_t client = accept_client(listen_socket_);
    if (!is_valid_socket(client)) {
        return;
    }
    
    // Check connection limit
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (connections_.size() >= config_.max_connections) {
            LOG_NET_DEBUG("Connection limit reached, rejecting incoming");
            close_socket(client);
            return;
        }
    }
    
    // Set non-blocking
    if (!set_socket_nonblocking(client)) {
        close_socket(client);
        return;
    }
    
    // Get peer address
    std::string peer_addr = get_peer_address(client);
    std::string ip;
    uint16_t port = 0;
    
    size_t colon = peer_addr.rfind(':');
    if (colon != std::string::npos) {
        ip = peer_addr.substr(0, colon);
        port = static_cast<uint16_t>(std::stoi(peer_addr.substr(colon + 1)));
    }
    
    LOG_NET_INFO("Accepted incoming connection from " + peer_addr);
    
    // For incoming connections, we don't know the info_hash yet
    // We'll get it from the handshake
    std::lock_guard<std::mutex> lock(mutex_);
    
    SocketContext ctx;
    ctx.socket = client;
    ctx.state = NetConnectionState::Handshaking;
    ctx.incoming = true;
    ctx.connected_at = std::chrono::steady_clock::now();
    ctx.last_activity = ctx.connected_at;
    
    // Connection will be created after handshake
    connections_[client] = std::move(ctx);
}

void BtNetworkManager::handle_readable(socket_t socket,
                                        std::vector<ConnectedEvent>& connected_events,
                                        std::vector<DataEvent>& data_events,
                                        std::vector<DisconnectedEvent>& disconnected_events) {
    auto it = connections_.find(socket);
    if (it == connections_.end()) return;
    
    SocketContext& ctx = it->second;
    
    // Receive data
    int bytes = recv(socket, reinterpret_cast<char*>(recv_buffer_.data()), 
                    static_cast<int>(recv_buffer_.size()), 0);
    
    if (bytes <= 0) {
        if (bytes == 0) {
            LOG_NET_DEBUG("Connection closed by peer");
        } else {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                LOG_NET_DEBUG("Receive error: " + std::to_string(err));
            } else {
                return;  // Would block, try again later
            }
#else
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG_NET_DEBUG("Receive error: " + std::string(strerror(errno)));
            } else {
                return;  // Would block, try again later
            }
#endif
        }
        
        close_connection_internal(socket, disconnected_events);
        return;
    }
    
    ctx.last_activity = std::chrono::steady_clock::now();
    
    std::string ip = ctx.connection ? ctx.connection->ip() : "unknown";
    LOG_NET_DEBUG("handle_peer_data: recv " + std::to_string(bytes) + " bytes from " + ip);
    
    handle_peer_data(ctx, recv_buffer_.data(), static_cast<size_t>(bytes),
                     connected_events, data_events, disconnected_events);
}

void BtNetworkManager::handle_writable(socket_t socket,
                                        std::vector<DisconnectedEvent>& disconnected_events) {
    auto it = connections_.find(socket);
    if (it == connections_.end()) return;
    
    flush_send_buffer(it->second, disconnected_events);
}

void BtNetworkManager::handle_peer_data(SocketContext& ctx, 
                                         const uint8_t* data, size_t length,
                                         std::vector<ConnectedEvent>& connected_events,
                                         std::vector<DataEvent>& data_events,
                                         std::vector<DisconnectedEvent>& disconnected_events) {
    if (ctx.state == NetConnectionState::Handshaking) {
        // For incoming connections, we need to create the connection object
        // once we receive the handshake
        if (ctx.incoming && !ctx.connection) {
            // Check if we have enough data for handshake
            if (length < BT_HANDSHAKE_SIZE) {
                // Buffer and wait for more
                // For now, we'll just wait for complete handshake
                return;
            }
            
            // Parse handshake to get info_hash
            auto hs = BtHandshake::decode(data, length);
            if (!hs) {
                LOG_NET_ERROR("Invalid handshake from incoming connection");
                close_connection_internal(ctx.socket, disconnected_events);
                return;
            }
            
            // Find registered torrent
            auto torrent_it = torrents_.find(hs->info_hash);
            if (torrent_it == torrents_.end()) {
                LOG_NET_DEBUG("Unknown info_hash from incoming connection");
                close_connection_internal(ctx.socket, disconnected_events);
                return;
            }
            
            const auto& reg = torrent_it->second;
            
            // Create connection object
            ctx.connection = std::make_shared<BtPeerConnection>(
                hs->info_hash, reg.peer_id, reg.num_pieces);
            ctx.info_hash = hs->info_hash;
            
            // Get peer address
            std::string peer_addr = get_peer_address(ctx.socket);
            std::string ip;
            uint16_t port = 0;
            size_t colon = peer_addr.rfind(':');
            if (colon != std::string::npos) {
                ip = peer_addr.substr(0, colon);
                port = static_cast<uint16_t>(std::stoi(peer_addr.substr(colon + 1)));
            }
            
            ctx.connection->set_address(ip, port);
            ctx.connection->set_socket(static_cast<int>(ctx.socket));
        }
        
        // Process handshake data
        if (ctx.connection) {
            ctx.connection->on_receive(data, length);
            
            // Check if handshake complete
            if (ctx.connection->is_connected()) {
                ctx.state = NetConnectionState::Connected;
                
                LOG_NET_DEBUG("Handshake complete with " + ctx.connection->ip() + 
                             ", queueing callback");
                
                // Queue connected event (callback will be invoked outside mutex)
                ConnectedEvent event;
                event.info_hash = ctx.info_hash;
                event.connection = ctx.connection;
                event.socket = ctx.socket;
                event.incoming = ctx.incoming;
                connected_events.push_back(std::move(event));
            }
            
            // Check if connection has data to send
            if (ctx.connection->has_send_data()) {
                std::vector<uint8_t> buffer(16384);
                size_t len = ctx.connection->get_send_data(
                    buffer.data(), buffer.size());
                if (len > 0) {
                    buffer.resize(len);
                    ctx.send_buffer.append(std::move(buffer));
                    ctx.connection->mark_sent(len);
                }
            }
        }
    } else if (ctx.state == NetConnectionState::Connected && ctx.connection) {
        // Process message data
        ctx.connection->on_receive(data, length);
        
        // Queue data event (callback will be invoked outside mutex)
        DataEvent event;
        event.info_hash = ctx.info_hash;
        event.connection = ctx.connection;
        event.socket = ctx.socket;
        data_events.push_back(std::move(event));
        
        // Check for data to send
        if (ctx.connection->has_send_data()) {
            std::vector<uint8_t> buffer(16384);
            size_t len = ctx.connection->get_send_data(buffer.data(), buffer.size());
            if (len > 0) {
                buffer.resize(len);
                ctx.send_buffer.append(std::move(buffer));
                ctx.connection->mark_sent(len);
            }
        }
    }
}

void BtNetworkManager::flush_send_buffer(SocketContext& ctx,
                                          std::vector<DisconnectedEvent>& disconnected_events) {
    if (ctx.send_buffer.empty()) return;
    
    // Copy data to temporary buffer for sending
    std::vector<uint8_t> buffer(std::min(ctx.send_buffer.size(), size_t(65536)));
    size_t to_send = ctx.send_buffer.copy_to(buffer.data(), buffer.size());
    
    if (to_send == 0) return;

    if (ctx.connection) {
        LOG_NET_DEBUG("flush_send_buffer: sending " + std::to_string(to_send) + " bytes to " + ctx.connection->ip());
    }
    
    int sent = send(ctx.socket, reinterpret_cast<const char*>(buffer.data()),
                   static_cast<int>(to_send), 0);
    
    if (sent > 0) {
        ctx.send_buffer.pop_front(static_cast<size_t>(sent));
        ctx.last_activity = std::chrono::steady_clock::now();
    } else if (sent < 0) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            LOG_NET_DEBUG("Send error: " + std::to_string(err));
            close_connection_internal(ctx.socket, disconnected_events);
        }
#else
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_NET_DEBUG("Send error: " + std::string(strerror(errno)));
            close_connection_internal(ctx.socket, disconnected_events);
        }
#endif
    }
}

void BtNetworkManager::close_connection_internal(socket_t socket,
                                                  std::vector<DisconnectedEvent>& disconnected_events) {
    auto it = connections_.find(socket);
    if (it == connections_.end()) return;
    
    SocketContext& ctx = it->second;
    
    // Queue disconnected event (callback will be invoked outside mutex)
    if (ctx.connection) {
        DisconnectedEvent event;
        event.info_hash = ctx.info_hash;
        event.connection = ctx.connection;
        disconnected_events.push_back(std::move(event));
    }
    
    close_socket(socket, true);
    connections_.erase(it);
}

SocketContext* BtNetworkManager::get_context(socket_t socket) {
    auto it = connections_.find(socket);
    if (it != connections_.end()) {
        return &it->second;
    }
    return nullptr;
}

} // namespace librats
