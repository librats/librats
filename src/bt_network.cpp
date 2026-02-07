#include "bt_network.h"
#include "network_utils.h"
#include "logger.h"

#include <algorithm>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
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
// BtNetworkManager Construction
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
// TCP_NODELAY helper
//=============================================================================

bool BtNetworkManager::set_tcp_nodelay(socket_t sock) {
    int flag = 1;
    int result = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                            reinterpret_cast<const char*>(&flag), sizeof(flag));
    if (result < 0) {
        LOG_NET_WARN("Failed to set TCP_NODELAY on socket " + std::to_string(static_cast<int>(sock)));
        return false;
    }
    return true;
}

//=============================================================================
// Lifecycle
//=============================================================================

bool BtNetworkManager::start() {
    if (running_) return true;
    
    // Initialize socket library (required on Windows)
    if (!init_socket_library()) {
        LOG_NET_ERROR("Failed to initialize socket library");
        return false;
    }
    
    // Create the I/O poller
    poller_ = IOPoller::create();
    if (!poller_) {
        LOG_NET_ERROR("Failed to create I/O poller");
        return false;
    }
    LOG_NET_INFO("Using I/O backend: " + std::string(poller_->name()));
    
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
        actual_listen_port_ = static_cast<uint16_t>(get_bound_port(listen_socket_));
        if (actual_listen_port_ == 0) {
            actual_listen_port_ = config_.listen_port;
        }
        
        // Register listen socket with poller (interested in incoming connections)
        poller_->add(listen_socket_, PollIn);
        poller_state_[listen_socket_] = PollIn;
        
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
            poller_->remove(socket);
            close_socket(socket, true);
        }
        connections_.clear();
        
        // Close connecting sockets
        for (auto& [socket, pending] : connecting_) {
            poller_->remove(socket);
            close_socket(socket, true);
        }
        connecting_.clear();
        
        // Clear pending queue
        while (!pending_connects_.empty()) {
            pending_connects_.pop();
        }
        
        // Close listen socket
        if (is_valid_socket(listen_socket_)) {
            poller_->remove(listen_socket_);
            close_socket(listen_socket_);
            listen_socket_ = INVALID_SOCKET_VALUE;
        }
        
        poller_state_.clear();
        poller_.reset();
        
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
    
    // Check connection limit (include pending queue in the count)
    size_t total = connections_.size() + connecting_.size() + pending_connects_.size();
    if (total >= config_.max_connections) {
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
    
    // Check pending queue for duplicates
    // Note: std::queue doesn't support iteration, so we use a temporary copy
    std::queue<PendingConnect> temp_queue = pending_connects_;
    while (!temp_queue.empty()) {
        const auto& queued = temp_queue.front();
        if (queued.ip == ip && queued.port == port) {
            LOG_NET_DEBUG("Already queued connection to " + ip + ":" + std::to_string(port));
            return false;
        }
        temp_queue.pop();
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
    if (it == connections_.end() || !it->second.connection) {
        return false;
    }
    
    auto& send_buf = it->second.connection->send_buffer();
    
    // Check high water mark
    if (send_buf.size() + data.size() > config_.send_buffer_high_water) {
        LOG_NET_WARN("Send buffer high water reached for " + 
                     it->second.connection->ip());
        return false;
    }
    
    bool was_empty = send_buf.empty();
    
    // Append directly to connection's send buffer (single source of truth)
    send_buf.append(data.data(), data.size());
    
    // If buffer was empty, we need to start watching for writability.
    // Update poller to add PollOut interest.
    if (was_empty && poller_) {
        uint32_t desired = PollIn | PollOut;
        auto ps = poller_state_.find(socket);
        if (ps != poller_state_.end() && ps->second != desired) {
            poller_->modify(socket, desired);
            ps->second = desired;
        }
    }
    
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
// Poller State Sync
//=============================================================================

void BtNetworkManager::sync_poller() {
    // Called under mutex. Ensures poller registrations match current state.
    // This is the primary sync point for connections whose send buffer
    // state may have changed (e.g., after flush_send_buffer drains it).
    
    for (auto& [socket, ctx] : connections_) {
        // Determine desired events
        uint32_t desired = PollIn;  // Always interested in reading
        if (ctx.connection && !ctx.connection->send_buffer().empty()) {
            desired |= PollOut;  // Also interested in writing
        }
        
        auto ps = poller_state_.find(socket);
        if (ps == poller_state_.end()) {
            // Not yet registered (shouldn't happen normally, but be safe)
            poller_->add(socket, desired);
            poller_state_[socket] = desired;
        } else if (ps->second != desired) {
            poller_->modify(socket, desired);
            ps->second = desired;
        }
    }
    
    // Connecting sockets: interested in write (connect complete) + error
    for (auto& [socket, pending] : connecting_) {
        auto ps = poller_state_.find(socket);
        uint32_t desired = PollOut;
        if (ps == poller_state_.end()) {
            poller_->add(socket, desired);
            poller_state_[socket] = desired;
        }
        // Connecting sockets don't change their interest, no modify needed
    }
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
    
    // Poll results buffer
    static constexpr int MAX_POLL_EVENTS = 256;
    PollResult poll_results[MAX_POLL_EVENTS];
    
    while (running_) {
        // Clear event vectors for this iteration
        connected_events.clear();
        data_events.clear();
        disconnected_events.clear();
        
        // Process pending connect queue (adds new sockets to poller)
        process_pending_connects();
        
        // Sync poller state (update write interest based on send buffer state)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            sync_poller();
        }
        
        // Wait for I/O events (NO mutex held — this is the blocking call)
        int num_events = poller_->wait(poll_results, MAX_POLL_EVENTS, 
                                        config_.poll_timeout_ms);
        
        if (num_events < 0) {
            // Error (EINTR already filtered by poller implementations)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        if (num_events == 0) {
            // Timeout — check for connection timeouts
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
                poller_->remove(s);
                poller_state_.erase(s);
                close_socket(s);
                connecting_.erase(s);
            }
            
            continue;
        }
        
        LOG_NET_DEBUG("I/O poll returned " + std::to_string(num_events) + " events");
        
        // Process all events under mutex
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<socket_t> to_close;
            
            for (int i = 0; i < num_events; ++i) {
                socket_t fd = poll_results[i].fd;
                uint32_t events = poll_results[i].events;
                
                //--------------------------------------------------------------
                // Listen socket — accept incoming
                //--------------------------------------------------------------
                if (fd == listen_socket_) {
                    if (events & PollIn) {
                        // NOTE: accept_incoming acquires mutex internally,
                        // but we are already holding it. We need to call
                        // the internal version without re-locking.
                        accept_incoming();
                    }
                    continue;
                }
                
                //--------------------------------------------------------------
                // Connecting socket — check connect completion
                //--------------------------------------------------------------
                auto connecting_it = connecting_.find(fd);
                if (connecting_it != connecting_.end()) {
                    auto& pending = connecting_it->second;
                    
                    if (events & PollErr) {
                        // Connection failed
                        LOG_NET_DEBUG("Connection failed (poll error) to " + pending.ip);
                        poller_->remove(fd);
                        poller_state_.erase(fd);
                        close_socket(fd);
                        connecting_.erase(connecting_it);
                        continue;
                    }
                    
                    if (events & PollOut) {
                        // Check if connection succeeded
                        int sock_error = 0;
                        socklen_t len = sizeof(sock_error);
                        getsockopt(fd, SOL_SOCKET, SO_ERROR,
                                  reinterpret_cast<char*>(&sock_error), &len);
                        
                        if (sock_error == 0) {
                            LOG_NET_INFO("Connected to peer " + pending.ip + ":" + 
                                        std::to_string(pending.port));
                            
                            // Set TCP_NODELAY for low latency
                            set_tcp_nodelay(fd);
                            
                            // Create connection object
                            auto conn = std::make_shared<BtPeerConnection>(
                                pending.info_hash, pending.peer_id, pending.num_pieces);
                            conn->set_address(pending.ip, pending.port);
                            conn->set_socket(static_cast<int>(fd));
                            
                            // Create socket context
                            SocketContext ctx;
                            ctx.socket = fd;
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
                            conn->start_handshake();
                            
                            connections_[fd] = std::move(ctx);
                            
                            // Update poller: now interested in read (+ write if handshake queued)
                            uint32_t desired = PollIn;
                            if (!conn->send_buffer().empty()) {
                                desired |= PollOut;
                            }
                            poller_->modify(fd, desired);
                            poller_state_[fd] = desired;
                            
                            LOG_NET_DEBUG("Handshake queued to " + pending.ip);
                        } else {
                            LOG_NET_DEBUG("Connection failed to " + pending.ip + ": " + 
                                         std::to_string(sock_error));
                            poller_->remove(fd);
                            poller_state_.erase(fd);
                            close_socket(fd);
                        }
                        
                        connecting_.erase(connecting_it);
                    }
                    continue;
                }
                
                //--------------------------------------------------------------
                // Active connection — handle read/write/error
                //--------------------------------------------------------------
                auto conn_it = connections_.find(fd);
                if (conn_it == connections_.end()) {
                    // Unknown fd — remove from poller
                    poller_->remove(fd);
                    poller_state_.erase(fd);
                    continue;
                }
                
                bool should_close = false;
                
                if (events & PollErr) {
                    if (conn_it->second.connection) {
                        LOG_NET_DEBUG("Error on socket for " + conn_it->second.connection->ip());
                    }
                    should_close = true;
                }
                
                if (!should_close && (events & PollHup)) {
                    if (conn_it->second.connection) {
                        LOG_NET_DEBUG("Peer hung up: " + conn_it->second.connection->ip());
                    }
                    should_close = true;
                }
                
                if (!should_close && (events & PollIn)) {
                    should_close = handle_readable(fd, connected_events, data_events);
                }
                
                if (!should_close && (events & PollOut)) {
                    should_close = handle_writable(fd);
                }
                
                if (should_close) {
                    to_close.push_back(fd);
                }
            }
            
            // Close connections AFTER processing all events to avoid iterator invalidation
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
        
        // Register with poller: interested in write (connect complete)
        poller_->add(sock, PollOut);
        poller_state_[sock] = PollOut;
        
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
    
    // Set TCP_NODELAY immediately (before connect)
    set_tcp_nodelay(sock);
    
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
    // NOTE: called with mutex_ already held from io_loop
    
    socket_t client = accept_client(listen_socket_);
    if (!is_valid_socket(client)) {
        return;
    }
    
    // Check connection limit
    if (connections_.size() >= config_.max_connections) {
        LOG_NET_DEBUG("Connection limit reached, rejecting incoming");
        close_socket(client);
        return;
    }
    
    // Set non-blocking
    if (!set_socket_nonblocking(client)) {
        close_socket(client);
        return;
    }
    
    // Set TCP_NODELAY for low latency
    set_tcp_nodelay(client);
    
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
    
    // Create connection object immediately (info_hash unknown until handshake)
    auto conn = std::make_shared<BtPeerConnection>(config_.peer_id);
    conn->set_address(ip, port);
    conn->set_socket(static_cast<int>(client));
    
    // Set up callback for when handshake reveals the info_hash
    conn->set_info_hash_callback([this](BtPeerConnection* peer, const BtInfoHash& info_hash) {
        on_incoming_info_hash(peer, info_hash);
    });
    
    SocketContext ctx;
    ctx.socket = client;
    ctx.state = NetConnectionState::Handshaking;
    ctx.incoming = true;
    ctx.connected_at = std::chrono::steady_clock::now();
    ctx.last_activity = ctx.connected_at;
    ctx.connection = conn;
    
    connections_[client] = std::move(ctx);
    
    // Register with poller (interested in reading handshake)
    poller_->add(client, PollIn);
    poller_state_[client] = PollIn;
}

void BtNetworkManager::on_incoming_info_hash(BtPeerConnection* conn, const BtInfoHash& info_hash) {
    // This is called from within process_incoming() when an incoming connection
    // receives a handshake and discovers the info_hash. We need to look up the
    // torrent and set the correct info.
    
    // Note: We're already holding the mutex (called from io_loop -> handle_readable -> process_incoming)
    
    auto torrent_it = torrents_.find(info_hash);
    if (torrent_it == torrents_.end()) {
        LOG_NET_DEBUG("Unknown info_hash " + info_hash_to_hex(info_hash).substr(0, 8) + 
                      "... from incoming connection " + conn->ip());
        // Connection will be closed by BtPeerConnection when set_torrent_info is not called
        return;
    }
    
    const auto& reg = torrent_it->second;
    
    LOG_NET_DEBUG("Routing incoming connection from " + conn->ip() + 
                  " to torrent " + info_hash_to_hex(info_hash).substr(0, 8) + "...");
    
    // Set the torrent info on the connection
    conn->set_torrent_info(info_hash, reg.num_pieces);
    
    // Update the SocketContext with the info_hash
    for (auto& [socket, ctx] : connections_) {
        if (ctx.connection.get() == conn) {
            ctx.info_hash = info_hash;
            break;
        }
    }
}

bool BtNetworkManager::handle_readable(socket_t socket,
                                        std::vector<ConnectedEvent>& connected_events,
                                        std::vector<DataEvent>& data_events) {
    auto it = connections_.find(socket);
    if (it == connections_.end()) return false;
    
    SocketContext& ctx = it->second;
    
    // Connection object should always exist now (created in accept_incoming or connect_peer)
    if (!ctx.connection) {
        LOG_NET_ERROR("handle_readable: no connection object for socket");
        return true;  // Should close
    }
    
    // Drain all available data from the kernel buffer (loop until EWOULDBLOCK)
    auto& recv_buf = ctx.connection->recv_buffer();
    bool got_data = false;
    
    while (true) {
        const size_t recv_size = 16384;
        recv_buf.ensure_space(recv_size);
        
        int bytes = recv(socket, reinterpret_cast<char*>(recv_buf.write_ptr()), 
                        static_cast<int>(recv_buf.write_space()), 0);
        
        if (bytes > 0) {
            recv_buf.received(bytes);
            got_data = true;
            
            LOG_NET_DEBUG("handle_readable: recv " + std::to_string(bytes) + 
                          " bytes from " + ctx.connection->ip());
            continue;  // Try to read more
        }
        
        if (bytes == 0) {
            // Peer closed connection gracefully
            LOG_NET_DEBUG("Connection closed by peer: " + ctx.connection->ip());
            return true;  // Should close
        }
        
        // bytes < 0: error
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            break;  // No more data available, exit recv loop
        }
        LOG_NET_DEBUG("Receive error: " + std::to_string(err));
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;  // No more data available, exit recv loop
        }
        LOG_NET_DEBUG("Receive error: " + std::string(strerror(errno)));
#endif
        return true;  // Should close on real errors
    }
    
    if (!got_data) {
        return false;  // Nothing received, no processing needed
    }
    
    ctx.last_activity = std::chrono::steady_clock::now();
    
    // Process all received data (handshake and messages)
    return handle_peer_data(ctx, connected_events, data_events);
}

bool BtNetworkManager::handle_writable(socket_t socket) {
    auto it = connections_.find(socket);
    if (it == connections_.end()) return false;
    
    return flush_send_buffer(it->second);
}

bool BtNetworkManager::handle_peer_data(SocketContext& ctx,
                                         std::vector<ConnectedEvent>& connected_events,
                                         std::vector<DataEvent>& data_events) {
    if (!ctx.connection) return false;
    
    // Process incoming data (handshake and messages)
    // Data is already in connection's recv_buffer - no copy needed!
    ctx.connection->process_incoming();
    
    // Check if connection was closed during processing (e.g., unknown torrent, invalid handshake)
    auto conn_state = ctx.connection->state();
    if (conn_state == PeerConnectionState::Disconnected || 
        conn_state == PeerConnectionState::Closing) {
        LOG_NET_DEBUG("Connection closed during processing for " + ctx.connection->ip());
        return true;  // Should close
    }
    
    if (ctx.state == NetConnectionState::Handshaking) {
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
    } else if (ctx.state == NetConnectionState::Connected) {
        // Queue data event (callback will be invoked outside mutex)
        DataEvent event;
        event.info_hash = ctx.info_hash;
        event.connection = ctx.connection;
        event.socket = ctx.socket;
        data_events.push_back(std::move(event));
    }
    
    // Note: send data is already in connection->send_buffer()
    // flush_send_buffer() will send it directly - no copy needed!
    return false;  // Don't close
}

bool BtNetworkManager::flush_send_buffer(SocketContext& ctx) {
    if (!ctx.connection) return false;
    
    auto& send_buf = ctx.connection->send_buffer();
    if (send_buf.empty()) return false;
    
    // Send directly from connection's buffer - NO COPY!
    const uint8_t* data = send_buf.front_data();
    size_t to_send = send_buf.front_size();
    
    if (to_send == 0 || data == nullptr) return false;

    LOG_NET_DEBUG("flush_send_buffer: sending " + std::to_string(to_send) + 
                  " bytes to " + ctx.connection->ip());
    
    int sent = send(ctx.socket, reinterpret_cast<const char*>(data),
                   static_cast<int>(to_send), 0);
    
    if (sent > 0) {
        send_buf.pop_front(static_cast<size_t>(sent));
        ctx.last_activity = std::chrono::steady_clock::now();
        
        // If send buffer is now empty, remove PollOut interest to avoid busy-looping
        if (send_buf.empty()) {
            uint32_t desired = PollIn;
            auto ps = poller_state_.find(ctx.socket);
            if (ps != poller_state_.end() && ps->second != desired) {
                poller_->modify(ctx.socket, desired);
                ps->second = desired;
            }
        }
    } else if (sent < 0) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            LOG_NET_DEBUG("Send error: " + std::to_string(err));
            return true;  // Should close
        }
#else
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_NET_DEBUG("Send error: " + std::string(strerror(errno)));
            return true;  // Should close
        }
#endif
    }
    return false;  // Don't close
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
    
    // Remove from poller before closing socket
    poller_->remove(socket);
    poller_state_.erase(socket);
    
    close_socket(socket, true);
    connections_.erase(it);
}

} // namespace librats
