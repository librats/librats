#include "bt_network.h"
#include "bt_handshake.h"
#include "logger.h"

#include <algorithm>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/select.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <netinet/tcp.h>
#endif

namespace librats {

//=============================================================================
// Constructor / Destructor
//=============================================================================

BtNetworkManager::BtNetworkManager(const BtNetworkConfig& config)
    : config_(config)
    , running_(false)
    , actual_listen_port_(0)
    , listen_socket_(INVALID_SOCKET_VALUE) {
}

BtNetworkManager::~BtNetworkManager() {
    stop();
}

//=============================================================================
// Lifecycle
//=============================================================================

bool BtNetworkManager::start() {
    if (running_.load()) {
        return true;
    }
    
    // Create listen socket if enabled
    if (config_.enable_incoming) {
        listen_socket_ = create_tcp_server_v4(config_.listen_port, 10, "");
        if (!is_valid_socket(listen_socket_)) {
            LOG_ERROR("BtNetwork", "Failed to create listen socket on port " 
                      + std::to_string(config_.listen_port));
            return false;
        }
        
        // Get actual port
        actual_listen_port_ = static_cast<uint16_t>(get_ephemeral_port(listen_socket_));
        if (actual_listen_port_ == 0) {
            actual_listen_port_ = config_.listen_port;
        }
        
        // Set non-blocking
        set_socket_nonblocking(listen_socket_);
        
        LOG_INFO("BtNetwork", "Listening for incoming connections on port " 
                 + std::to_string(actual_listen_port_));
    }
    
    running_.store(true);
    network_thread_ = std::thread(&BtNetworkManager::network_loop, this);
    
    return true;
}

void BtNetworkManager::stop() {
    if (!running_.load()) {
        return;
    }
    
    running_.store(false);
    
    // Close listen socket
    if (is_valid_socket(listen_socket_)) {
        close_socket(listen_socket_);
        listen_socket_ = INVALID_SOCKET_VALUE;
    }
    
    // Close all connections
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (auto& [sock, conn] : active_connections_) {
            close_socket(sock);
        }
        active_connections_.clear();
    }
    
    // Close pending connections
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        for (auto& pending : pending_connections_) {
            if (is_valid_socket(pending.socket)) {
                close_socket(pending.socket);
            }
        }
        pending_connections_.clear();
    }
    
    // Wait for network thread
    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    
    LOG_INFO("BtNetwork", "Network manager stopped");
}

//=============================================================================
// Connection Management
//=============================================================================

bool BtNetworkManager::connect_peer(const std::string& ip, uint16_t port,
                                    const BtInfoHash& info_hash,
                                    const PeerID& our_peer_id,
                                    uint32_t num_pieces) {
    if (!running_.load()) {
        return false;
    }
    
    // Check if already connected or connecting
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (const auto& [sock, conn] : active_connections_) {
            if (conn.connection && 
                conn.connection->ip() == ip && 
                conn.connection->port() == port) {
                return true; // Already connected
            }
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        for (const auto& pending : pending_connections_) {
            if (pending.request.ip == ip && pending.request.port == port) {
                return true; // Already connecting
            }
        }
    }
    
    // Queue the connection request
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        connect_queue_.emplace(ip, port, info_hash, our_peer_id, num_pieces);
    }
    
    LOG_DEBUG("BtNetwork", "Queued connection to " + ip + ":" + std::to_string(port));
    return true;
}

void BtNetworkManager::register_torrent(const BtInfoHash& info_hash,
                                        const PeerID& our_peer_id,
                                        uint32_t num_pieces) {
    std::lock_guard<std::mutex> lock(torrents_mutex_);
    registered_torrents_[info_hash] = {our_peer_id, num_pieces};
}

void BtNetworkManager::unregister_torrent(const BtInfoHash& info_hash) {
    std::lock_guard<std::mutex> lock(torrents_mutex_);
    registered_torrents_.erase(info_hash);
    
    // Close connections for this torrent
    std::vector<socket_t> to_close;
    {
        std::lock_guard<std::mutex> conn_lock(connections_mutex_);
        for (const auto& [sock, conn] : active_connections_) {
            if (conn.info_hash == info_hash) {
                to_close.push_back(sock);
            }
        }
    }
    
    for (socket_t sock : to_close) {
        close_connection(sock);
    }
}

bool BtNetworkManager::send_to_peer(socket_t socket, const std::vector<uint8_t>& data) {
    if (!is_valid_socket(socket) || data.empty()) {
        return false;
    }
    
    // Find peer IP for logging
    std::string peer_ip = "unknown";
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = active_connections_.find(socket);
        if (it != active_connections_.end() && it->second.connection) {
            peer_ip = it->second.connection->ip();
        }
    }
    
    int sent = send(socket, reinterpret_cast<const char*>(data.data()), 
                    static_cast<int>(data.size()), 0);
    
    if (sent <= 0) {
        LOG_DEBUG("BtNetwork", "send_to_peer: send failed to " + peer_ip + ", closing connection");
        close_connection(socket);
        return false;
    }
    
    LOG_DEBUG("BtNetwork", "send_to_peer: sent " + std::to_string(sent) + "/" + 
              std::to_string(data.size()) + " bytes to " + peer_ip);
    
    return sent == static_cast<int>(data.size());
}

void BtNetworkManager::close_connection(socket_t socket) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    auto it = active_connections_.find(socket);
    if (it != active_connections_.end()) {
        BtInfoHash info_hash = it->second.info_hash;
        BtPeerConnection* conn = it->second.connection.get();
        
        if (on_peer_disconnected_ && conn) {
            on_peer_disconnected_(info_hash, conn);
        }
        
        close_socket(socket);
        active_connections_.erase(it);
    }
}

size_t BtNetworkManager::num_connections() const {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    return active_connections_.size();
}

size_t BtNetworkManager::num_pending() const {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    return pending_connections_.size();
}

//=============================================================================
// Network Loop
//=============================================================================

void BtNetworkManager::network_loop() {
    LOG_INFO("BtNetwork", "Network loop started");
    
    while (running_.load()) {
        // Process queued connection requests
        process_connect_queue();
        
        // Check pending connections
        process_pending_connects();
        
        // Accept incoming connections
        if (is_valid_socket(listen_socket_)) {
            process_listen_socket();
        }
        
        // Process active connections
        process_active_connections();
        
        // Cleanup stale connections
        cleanup_stale_connections();
        
        // Small sleep to prevent busy-wait
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    LOG_INFO("BtNetwork", "Network loop stopped");
}

void BtNetworkManager::process_connect_queue() {
    std::vector<PeerConnectRequest> requests;
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        size_t current_pending;
        {
            std::lock_guard<std::mutex> pending_lock(pending_mutex_);
            current_pending = pending_connections_.size();
        }
        
        // Limit pending connections
        while (!connect_queue_.empty() && 
               current_pending < config_.max_pending_connects) {
            requests.push_back(std::move(connect_queue_.front()));
            connect_queue_.pop();
            ++current_pending;
        }
    }
    
    for (auto& request : requests) {
        // Create non-blocking socket and start connect
        socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (!is_valid_socket(sock)) {
            LOG_ERROR("BtNetwork", "Failed to create socket for " + request.ip);
            continue;
        }
        
        // Set non-blocking
        set_socket_nonblocking(sock);
        
        // Disable Nagle's algorithm for lower latency
        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, 
                   reinterpret_cast<const char*>(&flag), sizeof(flag));
        
        // Start non-blocking connect
        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(request.port);
        inet_pton(AF_INET, request.ip.c_str(), &addr.sin_addr);
        
        int result = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        
#ifdef _WIN32
        bool in_progress = (result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
#else
        bool in_progress = (result == -1 && errno == EINPROGRESS);
#endif
        
        if (result == 0 || in_progress) {
            LOG_DEBUG("BtNetwork", "Connecting to " + request.ip + ":" + std::to_string(request.port));
            
            PendingConnection pending;
            pending.socket = sock;
            pending.request = std::move(request);
            pending.started_at = std::chrono::steady_clock::now();
            
            std::lock_guard<std::mutex> lock(pending_mutex_);
            pending_connections_.push_back(std::move(pending));
        } else {
            LOG_DEBUG("BtNetwork", "Connect failed immediately for " + request.ip);
            close_socket(sock);
        }
    }
}

void BtNetworkManager::process_pending_connects() {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    
    if (pending_connections_.empty()) {
        return;
    }
    
    LOG_DEBUG("BtNetwork", "process_pending_connects: " + std::to_string(pending_connections_.size()) + " pending");
    
    auto now = std::chrono::steady_clock::now();
    
    // Build fd_set for select
    fd_set write_fds;
    fd_set error_fds;
    FD_ZERO(&write_fds);
    FD_ZERO(&error_fds);
    
    socket_t max_fd = 0;
    for (const auto& pending : pending_connections_) {
        if (is_valid_socket(pending.socket)) {
            FD_SET(pending.socket, &write_fds);
            FD_SET(pending.socket, &error_fds);
            if (pending.socket > max_fd) {
                max_fd = pending.socket;
            }
        }
    }
    
    if (max_fd == 0) {
        return;
    }
    
    // Non-blocking select
    struct timeval tv = {0, 0};
    int ready = select(static_cast<int>(max_fd + 1), nullptr, &write_fds, &error_fds, &tv);
    
    if (ready > 0) {
        LOG_DEBUG("BtNetwork", "process_pending_connects: select() returned " + std::to_string(ready) + " ready");
    }
    
    if (ready <= 0) {
        // Check for timeouts
        auto it = pending_connections_.begin();
        while (it != pending_connections_.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->started_at).count();
            
            if (elapsed > config_.connect_timeout_ms) {
                LOG_DEBUG("BtNetwork", "Connection timeout for " + it->request.ip);
                close_socket(it->socket);
                it = pending_connections_.erase(it);
            } else {
                ++it;
            }
        }
        return;
    }
    
    // Check each pending connection
    auto it = pending_connections_.begin();
    while (it != pending_connections_.end()) {
        if (!is_valid_socket(it->socket)) {
            it = pending_connections_.erase(it);
            continue;
        }
        
        bool connected = FD_ISSET(it->socket, &write_fds) != 0;
        bool error = FD_ISSET(it->socket, &error_fds) != 0;
        
        if (error) {
            LOG_DEBUG("BtNetwork", "Connection error for " + it->request.ip);
            close_socket(it->socket);
            it = pending_connections_.erase(it);
            continue;
        }
        
        if (connected) {
            // Check if actually connected (not error)
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(it->socket, SOL_SOCKET, SO_ERROR, 
                       reinterpret_cast<char*>(&err), &len);
            
            if (err == 0) {
                handle_connection_established(*it);
            } else {
                LOG_DEBUG("BtNetwork", "Connection failed for " + it->request.ip + 
                          " (error: " + std::to_string(err) + ")");
                close_socket(it->socket);
            }
            it = pending_connections_.erase(it);
        } else {
            ++it;
        }
    }
}

void BtNetworkManager::handle_connection_established(PendingConnection& pending) {
    LOG_INFO("BtNetwork", "Connected to peer " + pending.request.ip + ":" + 
             std::to_string(pending.request.port));
    
    // Create peer connection
    auto connection = std::make_shared<BtPeerConnection>(
        pending.request.info_hash,
        pending.request.our_peer_id,
        pending.request.num_pieces
    );
    
    connection->set_socket(static_cast<int>(pending.socket));
    connection->set_address(pending.request.ip, pending.request.port);
    
    // Send handshake
    ExtensionFlags extensions;
    extensions.enable_all();
    auto handshake = BtHandshake::encode(
        pending.request.info_hash,
        pending.request.our_peer_id,
        extensions
    );
    
    LOG_DEBUG("BtNetwork", "Sending handshake (" + std::to_string(handshake.size()) + 
              " bytes) to " + pending.request.ip);
    
    int sent = send(pending.socket, reinterpret_cast<const char*>(handshake.data()),
                    static_cast<int>(handshake.size()), 0);
    
    if (sent != static_cast<int>(handshake.size())) {
        LOG_ERROR("BtNetwork", "Failed to send handshake to " + pending.request.ip + 
                  " (sent " + std::to_string(sent) + "/" + std::to_string(handshake.size()) + ")");
        close_socket(pending.socket);
        return;
    }
    
    LOG_DEBUG("BtNetwork", "Handshake sent successfully to " + pending.request.ip);
    
    // Add to active connections
    ActiveConnection active;
    active.socket = pending.socket;
    active.info_hash = pending.request.info_hash;
    active.is_incoming = false;
    active.connected_at = std::chrono::steady_clock::now();
    active.last_activity = active.connected_at;
    active.connection = connection;  // shared_ptr - both network manager and torrent can hold it
    
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        active_connections_[pending.socket] = std::move(active);
    }
}

void BtNetworkManager::process_listen_socket() {
    // Accept incoming connections (non-blocking)
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(listen_socket_, &read_fds);
    
    struct timeval tv = {0, 0};
    int ready = select(static_cast<int>(listen_socket_ + 1), &read_fds, nullptr, nullptr, &tv);
    
    if (ready > 0 && FD_ISSET(listen_socket_, &read_fds)) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        socket_t client_socket = accept(listen_socket_, 
            reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);
        
        if (is_valid_socket(client_socket)) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
            std::string peer_addr = std::string(ip_str) + ":" + 
                                    std::to_string(ntohs(client_addr.sin_port));
            
            handle_incoming_connection(client_socket, peer_addr);
        }
    }
}

void BtNetworkManager::handle_incoming_connection(socket_t client_socket, 
                                                   const std::string& peer_addr) {
    LOG_INFO("BtNetwork", "Incoming connection from " + peer_addr);
    
    // Set non-blocking
    set_socket_nonblocking(client_socket);
    
    // Disable Nagle
    int flag = 1;
    setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, 
               reinterpret_cast<const char*>(&flag), sizeof(flag));
    
    // Wait for handshake with timeout
    uint8_t handshake_buf[68];
    size_t received = 0;
    auto start = std::chrono::steady_clock::now();
    
    while (received < 68) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);
        
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        int ready = select(static_cast<int>(client_socket + 1), &read_fds, nullptr, nullptr, &tv);
        
        if (ready <= 0) {
            LOG_DEBUG("BtNetwork", "Timeout waiting for handshake from " + peer_addr);
            close_socket(client_socket);
            return;
        }
        
        int n = recv(client_socket, reinterpret_cast<char*>(handshake_buf + received),
                     static_cast<int>(68 - received), 0);
        
        if (n <= 0) {
            LOG_DEBUG("BtNetwork", "Connection closed during handshake from " + peer_addr);
            close_socket(client_socket);
            return;
        }
        
        received += n;
        
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > 10) {
            LOG_DEBUG("BtNetwork", "Handshake timeout from " + peer_addr);
            close_socket(client_socket);
            return;
        }
    }
    
    // Parse handshake
    auto handshake = BtHandshake::decode(handshake_buf, 68);
    if (!handshake) {
        LOG_DEBUG("BtNetwork", "Invalid handshake from " + peer_addr);
        close_socket(client_socket);
        return;
    }
    
    // Find registered torrent
    TorrentRegistration reg;
    {
        std::lock_guard<std::mutex> lock(torrents_mutex_);
        auto it = registered_torrents_.find(handshake->info_hash);
        if (it == registered_torrents_.end()) {
            LOG_DEBUG("BtNetwork", "Unknown info hash from " + peer_addr);
            close_socket(client_socket);
            return;
        }
        reg = it->second;
    }
    
    // Send our handshake
    ExtensionFlags extensions;
    extensions.enable_all();
    auto our_handshake = BtHandshake::encode(
        handshake->info_hash,
        reg.our_peer_id,
        extensions
    );
    
    LOG_DEBUG("BtNetwork", "Sending handshake response (" + std::to_string(our_handshake.size()) + 
              " bytes) to " + peer_addr);
    
    int sent = send(client_socket, reinterpret_cast<const char*>(our_handshake.data()),
                    static_cast<int>(our_handshake.size()), 0);
    
    if (sent != static_cast<int>(our_handshake.size())) {
        LOG_ERROR("BtNetwork", "Failed to send handshake response to " + peer_addr);
        close_socket(client_socket);
        return;
    }
    
    LOG_DEBUG("BtNetwork", "Handshake response sent successfully to " + peer_addr);
    
    // Parse peer address
    size_t colon = peer_addr.find(':');
    std::string ip = peer_addr.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(std::stoi(peer_addr.substr(colon + 1)));
    
    // Create peer connection
    auto connection = std::make_shared<BtPeerConnection>(
        handshake->info_hash,
        reg.our_peer_id,
        reg.num_pieces
    );
    
    connection->set_socket(static_cast<int>(client_socket));
    connection->set_address(ip, port);
    
    // The peer already sent handshake, process it
    connection->on_receive(handshake_buf, 68);
    
    BtInfoHash info_hash_copy = handshake->info_hash;
    
    // Add socket to active connections for tracking
    // Connection is shared_ptr so both network manager and torrent can access it
    ActiveConnection active;
    active.socket = client_socket;
    active.info_hash = info_hash_copy;
    active.is_incoming = true;
    active.callback_invoked = true;  // Will invoke below
    active.connected_at = std::chrono::steady_clock::now();
    active.last_activity = active.connected_at;
    active.connection = connection;  // Keep shared ownership
    
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        active_connections_[client_socket] = std::move(active);
    }
    
    // For incoming connections, invoke callback immediately (handshake is already complete)
    // Pass shared_ptr - both network manager and torrent will hold a reference
    if (on_peer_connected_) {
        on_peer_connected_(info_hash_copy, connection, client_socket, true);
    }
    
    LOG_INFO("BtNetwork", "Accepted peer " + peer_addr + " for torrent " + 
             info_hash_to_hex(info_hash_copy).substr(0, 8) + "...");
}

void BtNetworkManager::process_active_connections() {
    std::vector<socket_t> sockets;
    std::vector<socket_t> sockets_with_pending_data;
    
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (const auto& [sock, conn] : active_connections_) {
            sockets.push_back(sock);
            // Check if this connection has data waiting to be sent
            if (conn.connection && conn.connection->has_send_data()) {
                sockets_with_pending_data.push_back(sock);
            }
        }
    }
    
    if (sockets.empty()) {
        return;
    }
    
    // Build fd_sets for both reading and writing
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    
    socket_t max_fd = 0;
    for (socket_t sock : sockets) {
        FD_SET(sock, &read_fds);
        if (sock > max_fd) {
            max_fd = sock;
        }
    }
    
    // Add sockets with pending data to write_fds
    for (socket_t sock : sockets_with_pending_data) {
        FD_SET(sock, &write_fds);
    }
    
    struct timeval tv = {0, 0};
    fd_set* write_fds_ptr = sockets_with_pending_data.empty() ? nullptr : &write_fds;
    int ready = select(static_cast<int>(max_fd + 1), &read_fds, write_fds_ptr, nullptr, &tv);
    
    if (ready <= 0) {
        return;
    }
    
    // Handle readable sockets (incoming data)
    // IMPORTANT: We must NOT hold connections_mutex_ when invoking callbacks,
    // as callbacks may call back into network methods (deadlock prevention).
    for (socket_t sock : sockets) {
        if (FD_ISSET(sock, &read_fds)) {
            // Copy connection info under lock, then release before processing
            std::shared_ptr<BtPeerConnection> connection;
            BtInfoHash info_hash;
            bool is_incoming = false;
            bool callback_invoked = false;
            
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                auto it = active_connections_.find(sock);
                if (it == active_connections_.end()) {
                    continue;
                }
                connection = it->second.connection;
                info_hash = it->second.info_hash;
                is_incoming = it->second.is_incoming;
                callback_invoked = it->second.callback_invoked;
            }
            // Mutex released here - safe to call callbacks
            
            if (connection) {
                handle_peer_data_unlocked(sock, connection, info_hash, 
                                          is_incoming, callback_invoked);
            }
        }
    }
    
    // Handle writable sockets (send pending data)
    if (write_fds_ptr) {
        for (socket_t sock : sockets_with_pending_data) {
            if (FD_ISSET(sock, &write_fds)) {
                flush_send_buffer(sock);
            }
        }
    }
}

void BtNetworkManager::handle_peer_data_unlocked(
    socket_t sock,
    std::shared_ptr<BtPeerConnection> connection,
    const BtInfoHash& info_hash,
    bool is_incoming,
    bool callback_already_invoked) {
    
    // NOTE: This function is called WITHOUT holding connections_mutex_
    // to prevent deadlocks when callbacks call back into network methods.
    
    uint8_t buffer[16384];
    
    int n = recv(sock, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
    
    if (n <= 0) {
        // Connection closed or error
        std::string peer_ip = connection ? connection->ip() : "unknown";
        LOG_DEBUG("BtNetwork", "handle_peer_data: recv returned " + std::to_string(n) + 
                  " from " + peer_ip + " (closing)");
        
        // Invoke disconnect callback (without holding lock)
        if (on_peer_disconnected_ && connection) {
            on_peer_disconnected_(info_hash, connection.get());
        }
        
        // Now close and remove under lock
        close_connection(sock);
        return;
    }
    
    std::string peer_ip = connection ? connection->ip() : "unknown";
    LOG_DEBUG("BtNetwork", "handle_peer_data: recv " + std::to_string(n) + " bytes from " + peer_ip);
    
    // Update last activity under lock
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = active_connections_.find(sock);
        if (it != active_connections_.end()) {
            it->second.last_activity = std::chrono::steady_clock::now();
        }
    }
    
    // Pass data to peer connection (no lock needed, connection is shared_ptr)
    if (connection) {
        connection->on_receive(buffer, static_cast<size_t>(n));
    }
    
    // Check if connection just completed handshake (for outgoing connections)
    // and we haven't invoked the callback yet
    if (!callback_already_invoked && connection && connection->is_connected()) {
        // Mark callback as invoked under lock
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            auto it = active_connections_.find(sock);
            if (it != active_connections_.end()) {
                it->second.callback_invoked = true;
            }
        }
        
        LOG_DEBUG("BtNetwork", "Handshake complete with " + connection->ip() + 
                  ", invoking callback");
        
        // Invoke on_peer_connected callback (WITHOUT holding lock - prevents deadlock)
        if (on_peer_connected_) {
            on_peer_connected_(info_hash, connection, sock, is_incoming);
        }
    }
    
    // Notify data callback (WITHOUT holding lock - prevents deadlock)
    if (on_peer_data_ && connection) {
        on_peer_data_(info_hash, connection.get(), sock);
    }
    
    // After processing received data, immediately try to send any pending data
    // This ensures responses are sent without waiting for the next poll cycle
    if (connection && connection->has_send_data()) {
        size_t pending = connection->send_buffer_size();
        LOG_DEBUG("BtNetwork", "Flushing send buffer for " + connection->ip() + 
                  ": pending=" + std::to_string(pending) + " bytes");
        
        // Flush directly using the socket (no lock needed for send)
        flush_send_buffer_direct(sock, connection);
    }
}

void BtNetworkManager::flush_send_buffer(socket_t sock) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = active_connections_.find(sock);
    if (it == active_connections_.end()) {
        return;
    }
    flush_send_buffer_internal(it->second);
}

void BtNetworkManager::flush_send_buffer_internal(ActiveConnection& conn) {
    if (!conn.connection || !conn.connection->has_send_data()) {
        return;
    }
    
    flush_send_buffer_direct(conn.socket, conn.connection);
    conn.last_activity = std::chrono::steady_clock::now();
}

void BtNetworkManager::flush_send_buffer_direct(
    socket_t sock, 
    std::shared_ptr<BtPeerConnection> connection) {
    
    // NOTE: This function does NOT require connections_mutex_ to be held.
    // It only uses the socket (which is valid) and the connection shared_ptr.
    
    if (!connection || !connection->has_send_data()) {
        return;
    }
    
    uint8_t buffer[16384];
    
    while (connection->has_send_data()) {
        size_t len = connection->get_send_data(buffer, sizeof(buffer));
        if (len == 0) {
            break;
        }
        
        // Try to send data
        int sent = ::send(sock, reinterpret_cast<const char*>(buffer), 
                          static_cast<int>(len), 0);
        
        if (sent > 0) {
            connection->mark_sent(static_cast<size_t>(sent));
            
            LOG_DEBUG("BtNetwork", "Sent " + std::to_string(sent) + " bytes to " + 
                      connection->ip());
            
            // If we couldn't send everything, the socket buffer is full
            // Wait for next write opportunity
            if (static_cast<size_t>(sent) < len) {
                break;
            }
        } else {
            // EAGAIN/EWOULDBLOCK means socket buffer is full, try again later
            // Other errors - connection might be broken
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                LOG_DEBUG("BtNetwork", "Send error " + std::to_string(err) + 
                          " to " + connection->ip());
            }
#else
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG_DEBUG("BtNetwork", "Send error " + std::to_string(errno) + 
                          " to " + connection->ip());
            }
#endif
            break;
        }
    }
}

void BtNetworkManager::cleanup_stale_connections() {
    auto now = std::chrono::steady_clock::now();
    std::vector<socket_t> to_close;
    
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (auto& [sock, conn] : active_connections_) {
            auto inactive = std::chrono::duration_cast<std::chrono::seconds>(
                now - conn.last_activity).count();
            
            // Close connections inactive for too long
            if (inactive > 120) { // 2 minutes
                LOG_DEBUG("BtNetwork", "Closing inactive connection");
                to_close.push_back(sock);
            }
        }
    }
    
    for (socket_t sock : to_close) {
        close_connection(sock);
    }
}

} // namespace librats
