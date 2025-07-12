#include "network.h"
#include "logger.h"
#include <iostream>
#include <cstring>

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
    
    // Convert IP address from string to binary form
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        LOG_NETWORK_ERROR("Invalid address: " << host);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Connect to server
    LOG_NETWORK_DEBUG("Connecting to " << host << ":" << port);
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
        LOG_NETWORK_ERROR("Connection to " << host << ":" << port << " failed");
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_NETWORK_INFO("Successfully connected to " << host << ":" << port);
    return client_socket;
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

socket_t accept_client(socket_t server_socket) {
    sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    socket_t client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_socket == INVALID_SOCKET_VALUE) {
        LOG_NETWORK_ERROR("Failed to accept client connection");
        return INVALID_SOCKET_VALUE;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    LOG_NETWORK_INFO("Client connected from " << client_ip << ":" << ntohs(client_addr.sin_port));
    
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