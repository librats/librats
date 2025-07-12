#include "network.h"
#include "network_utils.h"
#include "logger.h"
#include <iostream>
#include <cstring>

// Network module logging macros
#define LOG_NETWORK_DEBUG(message) LOG_DEBUG("network", message)
#define LOG_NETWORK_INFO(message)  LOG_INFO("network", message)
#define LOG_NETWORK_WARN(message)  LOG_WARN("network", message)
#define LOG_NETWORK_ERROR(message) LOG_ERROR("network", message)

namespace librats {

bool init_networking() {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        LOG_NETWORK_ERROR("WSAStartup failed: " << result);
        return false;
    }
    LOG_NETWORK_INFO("Windows Socket API initialized");
#endif
    LOG_NETWORK_INFO("Networking initialized");
    return true;
}

void cleanup_networking() {
#ifdef _WIN32
    WSACleanup();
    LOG_NETWORK_INFO("Windows Socket API cleaned up");
#endif
    LOG_NETWORK_INFO("Networking cleaned up");
}

socket_t create_tcp_client(const std::string& host, int port) {
    LOG_NETWORK_DEBUG("Creating TCP client socket for " << host << ":" << port);
    
    socket_t client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET_VALUE) {
        LOG_NETWORK_ERROR("Failed to create client socket");
        return INVALID_SOCKET_VALUE;
    }

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Resolve hostname to IP address
    std::string resolved_ip = network_utils::resolve_hostname(host);
    if (resolved_ip.empty()) {
        LOG_NETWORK_ERROR("Failed to resolve hostname: " << host);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }
    
    // Convert IP address from string to binary form
    if (inet_pton(AF_INET, resolved_ip.c_str(), &server_addr.sin_addr) <= 0) {
        LOG_NETWORK_ERROR("Invalid address: " << resolved_ip);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Connect to server
    LOG_NETWORK_DEBUG("Connecting to " << resolved_ip << ":" << port);
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Connection to " << resolved_ip << ":" << port << " failed");
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_NETWORK_INFO("Successfully connected to " << resolved_ip << ":" << port);
    return client_socket;
}

socket_t create_tcp_client_v6(const std::string& host, int port) {
    LOG_NETWORK_DEBUG("Creating TCP client socket for IPv6 " << host << ":" << port);
    
    socket_t client_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET_VALUE) {
        LOG_NETWORK_ERROR("Failed to create IPv6 client socket");
        return INVALID_SOCKET_VALUE;
    }

    sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(port);
    
    // Resolve hostname to IPv6 address
    std::string resolved_ip = network_utils::resolve_hostname_v6(host);
    if (resolved_ip.empty()) {
        LOG_NETWORK_ERROR("Failed to resolve hostname to IPv6: " << host);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }
    
    // Convert IPv6 address from string to binary form
    if (inet_pton(AF_INET6, resolved_ip.c_str(), &server_addr.sin6_addr) <= 0) {
        LOG_NETWORK_ERROR("Invalid IPv6 address: " << resolved_ip);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Connect to server
    LOG_NETWORK_DEBUG("Connecting to IPv6 " << resolved_ip << ":" << port);
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Connection to IPv6 " << resolved_ip << ":" << port << " failed");
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_NETWORK_INFO("Successfully connected to IPv6 " << resolved_ip << ":" << port);
    return client_socket;
}

socket_t create_tcp_client_dual(const std::string& host, int port) {
    LOG_NETWORK_DEBUG("Creating TCP client socket (dual stack) for " << host << ":" << port);
    
    // Try IPv6 first
    socket_t client_socket = create_tcp_client_v6(host, port);
    if (client_socket != INVALID_SOCKET_VALUE) {
        LOG_NETWORK_INFO("Successfully connected using IPv6");
        return client_socket;
    }
    
    // Fall back to IPv4
    LOG_NETWORK_DEBUG("IPv6 connection failed, trying IPv4");
    client_socket = create_tcp_client(host, port);
    if (client_socket != INVALID_SOCKET_VALUE) {
        LOG_NETWORK_INFO("Successfully connected using IPv4");
        return client_socket;
    }
    
    LOG_NETWORK_ERROR("Failed to connect using both IPv6 and IPv4");
    return INVALID_SOCKET_VALUE;
}

socket_t create_tcp_server(int port, int backlog) {
    LOG_NETWORK_DEBUG("Creating TCP server socket on port " << port);
    
    socket_t server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET_VALUE) {
        LOG_NETWORK_ERROR("Failed to create server socket");
        return INVALID_SOCKET_VALUE;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to set socket options");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind socket to address
    LOG_NETWORK_DEBUG("Binding server socket to port " << port);
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to bind server socket to port " << port);
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Listen for connections
    if (listen(server_socket, backlog) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to listen on server socket");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_NETWORK_INFO("Server listening on port " << port << " (backlog: " << backlog << ")");
    return server_socket;
}

socket_t create_tcp_server_v6(int port, int backlog) {
    LOG_NETWORK_DEBUG("Creating TCP server socket on IPv6 port " << port);
    
    socket_t server_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET_VALUE) {
        LOG_NETWORK_ERROR("Failed to create IPv6 server socket");
        return INVALID_SOCKET_VALUE;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to set IPv6 socket options");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(port);

    // Bind socket to address
    LOG_NETWORK_DEBUG("Binding IPv6 server socket to port " << port);
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to bind IPv6 server socket to port " << port);
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Listen for connections
    if (listen(server_socket, backlog) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to listen on IPv6 server socket");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_NETWORK_INFO("IPv6 server listening on port " << port << " (backlog: " << backlog << ")");
    return server_socket;
}

socket_t create_tcp_server_dual(int port, int backlog) {
    LOG_NETWORK_DEBUG("Creating TCP server socket (dual stack) on port " << port);
    
    socket_t server_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET_VALUE) {
        LOG_NETWORK_ERROR("Failed to create dual stack server socket");
        return INVALID_SOCKET_VALUE;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to set dual stack socket options");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Disable IPv6-only mode to allow IPv4 connections
    int ipv6_only = 0;
    if (setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY,
                   (char*)&ipv6_only, sizeof(ipv6_only)) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_WARN("Failed to disable IPv6-only mode, will be IPv6 only");
    }

    sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(port);

    // Bind socket to address
    LOG_NETWORK_DEBUG("Binding dual stack server socket to port " << port);
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to bind dual stack server socket to port " << port);
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Listen for connections
    if (listen(server_socket, backlog) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to listen on dual stack server socket");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_NETWORK_INFO("Dual stack server listening on port " << port << " (backlog: " << backlog << ")");
    return server_socket;
}

socket_t accept_client(socket_t server_socket) {
    sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    socket_t client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_socket == INVALID_SOCKET_VALUE) {
        LOG_NETWORK_ERROR("Failed to accept client connection");
        return INVALID_SOCKET_VALUE;
    }

    // Log client information based on address family
    if (client_addr.ss_family == AF_INET) {
        char client_ip[INET_ADDRSTRLEN];
        struct sockaddr_in* addr_in = (struct sockaddr_in*)&client_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, INET_ADDRSTRLEN);
        LOG_NETWORK_INFO("Client connected from " << client_ip << ":" << ntohs(addr_in->sin_port));
    } else if (client_addr.ss_family == AF_INET6) {
        char client_ip[INET6_ADDRSTRLEN];
        struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)&client_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, client_ip, INET6_ADDRSTRLEN);
        LOG_NETWORK_INFO("Client connected from IPv6 [" << client_ip << "]:" << ntohs(addr_in6->sin6_port));
    } else {
        LOG_NETWORK_INFO("Client connected from unknown address family");
    }
    
    return client_socket;
}

int send_data(socket_t socket, const std::string& data) {
    LOG_NETWORK_DEBUG("Sending " << data.length() << " bytes to socket " << socket);
    
    int bytes_sent = send(socket, data.c_str(), data.length(), 0);
    if (bytes_sent == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to send data to socket " << socket);
        return -1;
    }
    
    LOG_NETWORK_DEBUG("Successfully sent " << bytes_sent << " bytes to socket " << socket);
    return bytes_sent;
}

std::string receive_data(socket_t socket, size_t buffer_size) {
    char* buffer = new char[buffer_size + 1];
    memset(buffer, 0, buffer_size + 1);
    
    int bytes_received = recv(socket, buffer, buffer_size, 0);
    if (bytes_received == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Failed to receive data from socket " << socket);
        delete[] buffer;
        return "";
    }
    
    if (bytes_received == 0) {
        LOG_NETWORK_INFO("Connection closed by peer on socket " << socket);
        delete[] buffer;
        return "";
    }
    
    LOG_NETWORK_DEBUG("Received " << bytes_received << " bytes from socket " << socket);
    buffer[bytes_received] = '\0';
    std::string result(buffer);
    delete[] buffer;
    return result;
}

void close_socket(socket_t socket) {
    if (is_valid_socket(socket)) {
        LOG_NETWORK_DEBUG("Closing socket " << socket);
        closesocket(socket);
    }
}

bool is_valid_socket(socket_t socket) {
    return socket != INVALID_SOCKET_VALUE;
}

} // namespace librats 