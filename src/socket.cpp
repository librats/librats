#include "socket.h"
#include "network_utils.h"
#include "logger.h"
#include <iostream>
#include <cstring>
#ifndef _WIN32
    #include <fcntl.h>    // for O_NONBLOCK
    #include <errno.h>    // for errno
#endif

// Socket module logging macros
#define LOG_SOCKET_DEBUG(message) LOG_DEBUG("socket", message)
#define LOG_SOCKET_INFO(message)  LOG_INFO("socket", message)
#define LOG_SOCKET_WARN(message)  LOG_WARN("socket", message)
#define LOG_SOCKET_ERROR(message) LOG_ERROR("socket", message)

namespace librats {

// Socket Library Initialization
bool init_socket_library() {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        LOG_SOCKET_ERROR("WSAStartup failed: " << result);
        return false;
    }
    LOG_SOCKET_INFO("Windows Socket API initialized");
#endif
    LOG_SOCKET_INFO("Socket library initialized");
    return true;
}

void cleanup_socket_library() {
#ifdef _WIN32
    WSACleanup();
    LOG_SOCKET_INFO("Windows Socket API cleaned up");
#endif
    LOG_SOCKET_INFO("Socket library cleaned up");
}

// TCP Socket Functions
socket_t create_tcp_client(const std::string& host, int port) {
    LOG_SOCKET_DEBUG("Creating TCP client socket (dual stack) for " << host << ":" << port);
    
    // Try IPv6 first
    socket_t client_socket = create_tcp_client_v6(host, port);
    if (client_socket != INVALID_SOCKET_VALUE) {
        LOG_SOCKET_INFO("Successfully connected using IPv6");
        return client_socket;
    }
    
    // Fall back to IPv4
    LOG_SOCKET_DEBUG("IPv6 connection failed, trying IPv4");
    client_socket = create_tcp_client_v4(host, port);
    if (client_socket != INVALID_SOCKET_VALUE) {
        LOG_SOCKET_INFO("Successfully connected using IPv4");
        return client_socket;
    }
    
    LOG_SOCKET_ERROR("Failed to connect using both IPv6 and IPv4");
    return INVALID_SOCKET_VALUE;
}

socket_t create_tcp_client_v4(const std::string& host, int port) {
    LOG_SOCKET_DEBUG("Creating TCP client socket for " << host << ":" << port);
    
    // Validate port number
    if (port < 0 || port > 65535) {
        LOG_SOCKET_ERROR("Invalid port number: " << port << " (must be 0-65535)");
        return INVALID_SOCKET_VALUE;
    }
    
    socket_t client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create client socket");
        return INVALID_SOCKET_VALUE;
    }

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Resolve hostname to IP address
    std::string resolved_ip = network_utils::resolve_hostname(host);
    if (resolved_ip.empty()) {
        LOG_SOCKET_ERROR("Failed to resolve hostname: " << host);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }
    
    // Convert IP address from string to binary form
    if (inet_pton(AF_INET, resolved_ip.c_str(), &server_addr.sin_addr) <= 0) {
        LOG_SOCKET_ERROR("Invalid address: " << resolved_ip);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Connect to server
    LOG_SOCKET_DEBUG("Connecting to " << resolved_ip << ":" << port);
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Connection to " << resolved_ip << ":" << port << " failed");
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_SOCKET_INFO("Successfully connected to " << resolved_ip << ":" << port);
    return client_socket;
}

socket_t create_tcp_client_v6(const std::string& host, int port) {
    LOG_SOCKET_DEBUG("Creating TCP client socket for IPv6 " << host << ":" << port);
    
    // Validate port number
    if (port < 0 || port > 65535) {
        LOG_SOCKET_ERROR("Invalid port number: " << port << " (must be 0-65535)");
        return INVALID_SOCKET_VALUE;
    }
    
    socket_t client_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create IPv6 client socket");
        return INVALID_SOCKET_VALUE;
    }

    sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(port);
    
    // Resolve hostname to IPv6 address
    std::string resolved_ip = network_utils::resolve_hostname_v6(host);
    if (resolved_ip.empty()) {
        LOG_SOCKET_ERROR("Failed to resolve hostname to IPv6: " << host);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }
    
    // Convert IPv6 address from string to binary form
    if (inet_pton(AF_INET6, resolved_ip.c_str(), &server_addr.sin6_addr) <= 0) {
        LOG_SOCKET_ERROR("Invalid IPv6 address: " << resolved_ip);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Connect to server
    LOG_SOCKET_DEBUG("Connecting to IPv6 " << resolved_ip << ":" << port);
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Connection to IPv6 " << resolved_ip << ":" << port << " failed");
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_SOCKET_INFO("Successfully connected to IPv6 " << resolved_ip << ":" << port);
    return client_socket;
}

socket_t create_tcp_server(int port, int backlog) {
    LOG_SOCKET_DEBUG("Creating TCP server socket (dual stack) on port " << port);
    
    // Validate port number
    if (port < 0 || port > 65535) {
        LOG_SOCKET_ERROR("Invalid port number: " << port << " (must be 0-65535)");
        return INVALID_SOCKET_VALUE;
    }
    
    socket_t server_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create dual stack server socket");
        return INVALID_SOCKET_VALUE;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to set dual stack socket options");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Disable IPv6-only mode to allow IPv4 connections
    int ipv6_only = 0;
    if (setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY,
                   (char*)&ipv6_only, sizeof(ipv6_only)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_WARN("Failed to disable IPv6-only mode, will be IPv6 only");
    }

    sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(port);

    // Bind socket to address
    LOG_SOCKET_DEBUG("Binding dual stack server socket to port " << port);
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to bind dual stack server socket to port " << port);
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Listen for connections
    if (listen(server_socket, backlog) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to listen on dual stack server socket");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_SOCKET_INFO("Dual stack server listening on port " << port << " (backlog: " << backlog << ")");
    return server_socket;
}

socket_t create_tcp_server_v4(int port, int backlog) {
    LOG_SOCKET_DEBUG("Creating TCP server socket on port " << port);
    
    // Validate port number
    if (port < 0 || port > 65535) {
        LOG_SOCKET_ERROR("Invalid port number: " << port << " (must be 0-65535)");
        return INVALID_SOCKET_VALUE;
    }
    
    socket_t server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create server socket");
        return INVALID_SOCKET_VALUE;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to set socket options");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind socket to address
    LOG_SOCKET_DEBUG("Binding server socket to port " << port);
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to bind server socket to port " << port);
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Listen for connections
    if (listen(server_socket, backlog) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to listen on server socket");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_SOCKET_INFO("Server listening on port " << port << " (backlog: " << backlog << ")");
    return server_socket;
}

socket_t create_tcp_server_v6(int port, int backlog) {
    LOG_SOCKET_DEBUG("Creating TCP server socket on IPv6 port " << port);
    
    // Validate port number
    if (port < 0 || port > 65535) {
        LOG_SOCKET_ERROR("Invalid port number: " << port << " (must be 0-65535)");
        return INVALID_SOCKET_VALUE;
    }
    
    socket_t server_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create IPv6 server socket");
        return INVALID_SOCKET_VALUE;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to set IPv6 socket options");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(port);

    // Bind socket to address
    LOG_SOCKET_DEBUG("Binding IPv6 server socket to port " << port);
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to bind IPv6 server socket to port " << port);
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Listen for connections
    if (listen(server_socket, backlog) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to listen on IPv6 server socket");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_SOCKET_INFO("IPv6 server listening on port " << port << " (backlog: " << backlog << ")");
    return server_socket;
}

socket_t accept_client(socket_t server_socket) {
    sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    socket_t client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to accept client connection");
        return INVALID_SOCKET_VALUE;
    }

    // Log client information based on address family
    if (client_addr.ss_family == AF_INET) {
        char client_ip[INET_ADDRSTRLEN];
        struct sockaddr_in* addr_in = (struct sockaddr_in*)&client_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, INET_ADDRSTRLEN);
        LOG_SOCKET_INFO("Client connected from " << client_ip << ":" << ntohs(addr_in->sin_port));
    } else if (client_addr.ss_family == AF_INET6) {
        char client_ip[INET6_ADDRSTRLEN];
        struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)&client_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, client_ip, INET6_ADDRSTRLEN);
        LOG_SOCKET_INFO("Client connected from IPv6 [" << client_ip << "]:" << ntohs(addr_in6->sin6_port));
    } else {
        LOG_SOCKET_INFO("Client connected from unknown address family");
    }
    
    return client_socket;
}

std::string get_peer_address(socket_t socket) {
    sockaddr_storage peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    
    if (getpeername(socket, (struct sockaddr*)&peer_addr, &peer_addr_len) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to get peer address for socket " << socket);
        return "";
    }
    
    std::string peer_ip;
    uint16_t peer_port = 0;
    
    if (peer_addr.ss_family == AF_INET) {
        char ip_str[INET_ADDRSTRLEN];
        struct sockaddr_in* addr_in = (struct sockaddr_in*)&peer_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
        peer_ip = ip_str;
        peer_port = ntohs(addr_in->sin_port);
    } else if (peer_addr.ss_family == AF_INET6) {
        char ip_str[INET6_ADDRSTRLEN];
        struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)&peer_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
        peer_ip = ip_str;
        peer_port = ntohs(addr_in6->sin6_port);
    } else {
        LOG_SOCKET_ERROR("Unknown address family for socket " << socket);
        return "";
    }
    
    return peer_ip + ":" + std::to_string(peer_port);
}

int send_tcp_data(socket_t socket, const std::string& data) {
    LOG_SOCKET_DEBUG("Sending " << data.length() << " bytes to TCP socket " << socket);
    
    int bytes_sent = send(socket, data.c_str(), data.length(), 0);
    if (bytes_sent == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to send TCP data to socket " << socket);
        return -1;
    }
    
    LOG_SOCKET_DEBUG("Successfully sent " << bytes_sent << " bytes to TCP socket " << socket);
    return bytes_sent;
}

std::string receive_tcp_data(socket_t socket, size_t buffer_size) {
    char* buffer = new char[buffer_size + 1];
    memset(buffer, 0, buffer_size + 1);
    
    int bytes_received = recv(socket, buffer, buffer_size, 0);
    if (bytes_received == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to receive TCP data from socket " << socket);
        delete[] buffer;
        return "";
    }
    
    if (bytes_received == 0) {
        LOG_SOCKET_INFO("Connection closed by peer on socket " << socket);
        delete[] buffer;
        return "";
    }
    
    LOG_SOCKET_DEBUG("Received " << bytes_received << " bytes from TCP socket " << socket);
    buffer[bytes_received] = '\0';
    std::string result(buffer);
    delete[] buffer;
    return result;
}

// UDP Socket Functions
socket_t create_udp_socket(int port) {
    LOG_SOCKET_DEBUG("Creating dual stack UDP socket on port " << port);
    
    // Validate port number
    if (port < 0 || port > 65535) {
        LOG_SOCKET_ERROR("Invalid port number: " << port << " (must be 0-65535)");
        return INVALID_SOCKET_VALUE;
    }
    
    socket_t udp_socket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udp_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create dual stack UDP socket");
        return INVALID_SOCKET_VALUE;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to set dual stack UDP socket options");
        close_socket(udp_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Disable IPv6-only mode to allow IPv4 connections
    int ipv6_only = 0;
    if (setsockopt(udp_socket, IPPROTO_IPV6, IPV6_V6ONLY,
                   (char*)&ipv6_only, sizeof(ipv6_only)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_WARN("Failed to disable IPv6-only mode, will be IPv6 only");
    }

    if (port > 0) {
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(port);

        if (bind(udp_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR_VALUE) {
            LOG_SOCKET_ERROR("Failed to bind dual stack UDP socket to port " << port);
            close_socket(udp_socket);
            return INVALID_SOCKET_VALUE;
        }
        
        LOG_SOCKET_INFO("Dual stack UDP socket bound to port " << port);
    }

    return udp_socket;
}

socket_t create_udp_socket_v4(int port) {
    LOG_SOCKET_DEBUG("Creating UDP socket on port " << port);
    
    // Validate port number
    if (port < 0 || port > 65535) {
        LOG_SOCKET_ERROR("Invalid port number: " << port << " (must be 0-65535)");
        return INVALID_SOCKET_VALUE;
    }
    
    socket_t udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create UDP socket");
        return INVALID_SOCKET_VALUE;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to set UDP socket options");
        close_socket(udp_socket);
        return INVALID_SOCKET_VALUE;
    }

    if (port > 0) {
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(udp_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR_VALUE) {
            LOG_SOCKET_ERROR("Failed to bind UDP socket to port " << port);
            close_socket(udp_socket);
            return INVALID_SOCKET_VALUE;
        }
        
        LOG_SOCKET_INFO("UDP socket bound to port " << port);
    }

    return udp_socket;
}

socket_t create_udp_socket_v6(int port) {
    LOG_SOCKET_DEBUG("Creating UDP socket on IPv6 port " << port);
    
    // Validate port number
    if (port < 0 || port > 65535) {
        LOG_SOCKET_ERROR("Invalid port number: " << port << " (must be 0-65535)");
        return INVALID_SOCKET_VALUE;
    }
    
    socket_t udp_socket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udp_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create IPv6 UDP socket");
        return INVALID_SOCKET_VALUE;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to set IPv6 UDP socket options");
        close_socket(udp_socket);
        return INVALID_SOCKET_VALUE;
    }

    if (port > 0) {
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(port);

        if (bind(udp_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR_VALUE) {
            LOG_SOCKET_ERROR("Failed to bind IPv6 UDP socket to port " << port);
            close_socket(udp_socket);
            return INVALID_SOCKET_VALUE;
        }
        
        LOG_SOCKET_INFO("IPv6 UDP socket bound to port " << port);
    }

    return udp_socket;
}



int send_udp_data(socket_t socket, const std::vector<uint8_t>& data, const Peer& peer) {
    LOG_SOCKET_DEBUG("Sending " << data.size() << " bytes to " << peer.ip << ":" << peer.port);
    
    // Check if it's an IPv6 address
    if (network_utils::is_valid_ipv6(peer.ip)) {
        // Handle IPv6 address
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(peer.port);
        
        if (inet_pton(AF_INET6, peer.ip.c_str(), &addr.sin6_addr) <= 0) {
            LOG_SOCKET_ERROR("Invalid IPv6 address: " << peer.ip);
            return -1;
        }

        int bytes_sent = sendto(socket, (char*)data.data(), data.size(), 0, 
                               (struct sockaddr*)&addr, sizeof(addr));
        if (bytes_sent == SOCKET_ERROR_VALUE) {
            LOG_SOCKET_ERROR("Failed to send UDP data to IPv6 " << peer.ip << ":" << peer.port);
            return -1;
        }
        
        LOG_SOCKET_DEBUG("Successfully sent " << bytes_sent << " bytes to IPv6 " << peer.ip << ":" << peer.port);
        return bytes_sent;
    } else {
        // Handle IPv4 address or hostname
        std::string resolved_ip = network_utils::resolve_hostname(peer.ip);
        if (resolved_ip.empty()) {
            LOG_SOCKET_ERROR("Failed to resolve hostname: " << peer.ip);
            return -1;
        }
        
        // For dual-stack sockets, we need to use IPv6 address structure
        // and convert IPv4 to IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(peer.port);
        
        // Convert IPv4 to IPv4-mapped IPv6 address
        struct in_addr ipv4_addr;
        if (inet_pton(AF_INET, resolved_ip.c_str(), &ipv4_addr) <= 0) {
            LOG_SOCKET_ERROR("Invalid IPv4 address: " << resolved_ip);
            return -1;
        }
        
        // Create IPv4-mapped IPv6 address: ::ffff:x.x.x.x
        addr.sin6_addr.s6_addr[10] = 0xff;
        addr.sin6_addr.s6_addr[11] = 0xff;
        memcpy(&addr.sin6_addr.s6_addr[12], &ipv4_addr.s_addr, 4);
        
        LOG_SOCKET_DEBUG("Converting IPv4 " << resolved_ip << " to IPv4-mapped IPv6 for dual-stack socket");

        int bytes_sent = sendto(socket, (char*)data.data(), data.size(), 0, 
                               (struct sockaddr*)&addr, sizeof(addr));
        if (bytes_sent == SOCKET_ERROR_VALUE) {
#ifdef _WIN32
            LOG_SOCKET_ERROR("Failed to send UDP data to " << resolved_ip << ":" << peer.port << " (error: " << WSAGetLastError() << ")");
#else
            LOG_SOCKET_ERROR("Failed to send UDP data to " << resolved_ip << ":" << peer.port << " (error: " << strerror(errno) << ")");
#endif
            return -1;
        }
        
        LOG_SOCKET_DEBUG("Successfully sent " << bytes_sent << " bytes to " << resolved_ip << ":" << peer.port << " via IPv4-mapped IPv6");
        return bytes_sent;
    }
}

std::vector<uint8_t> receive_udp_data(socket_t socket, size_t buffer_size, Peer& sender_peer) {
    std::vector<uint8_t> buffer(buffer_size);
    sockaddr_storage sender_addr;
    socklen_t sender_addr_len = sizeof(sender_addr);
    
    int bytes_received = recvfrom(socket, (char*)buffer.data(), buffer_size, 0,
                                 (struct sockaddr*)&sender_addr, &sender_addr_len);
    
    if (bytes_received == SOCKET_ERROR_VALUE) {
        // Check if this is just a non-blocking socket with no data available
#ifdef _WIN32
        int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            // No data available on non-blocking socket - this is normal
            return std::vector<uint8_t>();
        } else {
            LOG_SOCKET_ERROR("Failed to receive UDP data: " << error);
            return std::vector<uint8_t>();
        }
#else
        int error = errno;
        if (error == EAGAIN || error == EWOULDBLOCK) {
            // No data available on non-blocking socket - this is normal
            return std::vector<uint8_t>();
        } else {
            LOG_SOCKET_ERROR("Failed to receive UDP data: " << strerror(error));
            return std::vector<uint8_t>();
        }
#endif
    }
    
    if (bytes_received == 0) {
        LOG_SOCKET_DEBUG("Received empty UDP packet");
        return std::vector<uint8_t>();
    }
    
    // Extract sender information based on address family
    if (sender_addr.ss_family == AF_INET) {
        char sender_ip[INET_ADDRSTRLEN];
        struct sockaddr_in* addr_in = (struct sockaddr_in*)&sender_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, sender_ip, INET_ADDRSTRLEN);
        sender_peer.ip = sender_ip;
        sender_peer.port = ntohs(addr_in->sin_port);
        
        LOG_SOCKET_DEBUG("Received " << bytes_received << " bytes from " << sender_peer.ip << ":" << sender_peer.port);
    } else if (sender_addr.ss_family == AF_INET6) {
        char sender_ip[INET6_ADDRSTRLEN];
        struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)&sender_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, sender_ip, INET6_ADDRSTRLEN);
        sender_peer.ip = sender_ip;
        sender_peer.port = ntohs(addr_in6->sin6_port);
        
        LOG_SOCKET_DEBUG("Received " << bytes_received << " bytes from IPv6 [" << sender_peer.ip << "]:" << sender_peer.port);
    } else {
        LOG_SOCKET_WARN("Received UDP data from unknown address family");
        sender_peer.ip = "unknown";
        sender_peer.port = 0;
    }
    
    buffer.resize(bytes_received);
    return buffer;
}

// Common Socket Functions
void close_socket(socket_t socket) {
    if (is_valid_socket(socket)) {
        LOG_SOCKET_DEBUG("Closing socket " << socket);
        closesocket(socket);
    }
}

bool is_valid_socket(socket_t socket) {
    return socket != INVALID_SOCKET_VALUE;
}

bool set_socket_nonblocking(socket_t socket) {
#ifdef _WIN32
    unsigned long mode = 1;
    if (ioctlsocket(socket, FIONBIO, &mode) != 0) {
        LOG_SOCKET_ERROR("Failed to set socket to non-blocking mode");
        return false;
    }
#else
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        LOG_SOCKET_ERROR("Failed to get socket flags");
        return false;
    }
    
    if (fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_SOCKET_ERROR("Failed to set socket to non-blocking mode");
        return false;
    }
#endif
    
    LOG_SOCKET_DEBUG("Socket set to non-blocking mode");
    return true;
}

} // namespace librats 