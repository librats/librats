#include "udp_network.h"
#include "logger.h"
#include <cstring>
#include <iostream>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define INVALID_SOCKET_VALUE INVALID_SOCKET
    #define SOCKET_ERROR_VALUE SOCKET_ERROR
#else
    #include <unistd.h>
    #include <fcntl.h>
    #define INVALID_SOCKET_VALUE -1
    #define SOCKET_ERROR_VALUE -1
    #define closesocket close
#endif

// UDP network module logging macros
#define LOG_UDP_DEBUG(message) LOG_DEBUG("udp_network", message)
#define LOG_UDP_INFO(message)  LOG_INFO("udp_network", message)
#define LOG_UDP_WARN(message)  LOG_WARN("udp_network", message)
#define LOG_UDP_ERROR(message) LOG_ERROR("udp_network", message)

namespace librats {

udp_socket_t create_udp_socket(int port) {
    LOG_UDP_DEBUG("Creating UDP socket on port " << port);
    
    udp_socket_t udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket == INVALID_UDP_SOCKET) {
        LOG_UDP_ERROR("Failed to create UDP socket");
        return INVALID_UDP_SOCKET;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_UDP_ERROR("Failed to set UDP socket options");
        close_udp_socket(udp_socket);
        return INVALID_SOCKET_VALUE;
    }

    if (port > 0) {
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(udp_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR_VALUE) {
            LOG_UDP_ERROR("Failed to bind UDP socket to port " << port);
            close_udp_socket(udp_socket);
            return INVALID_SOCKET_VALUE;
        }
        
        LOG_UDP_INFO("UDP socket bound to port " << port);
    }

    return udp_socket;
}

int send_udp_data(udp_socket_t socket, const std::vector<uint8_t>& data, const UdpPeer& peer) {
    LOG_UDP_DEBUG("Sending " << data.size() << " bytes to " << peer.ip << ":" << peer.port);
    
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer.port);
    
    if (inet_pton(AF_INET, peer.ip.c_str(), &addr.sin_addr) <= 0) {
        LOG_UDP_ERROR("Invalid IP address: " << peer.ip);
        return -1;
    }

    int bytes_sent = sendto(socket, (char*)data.data(), data.size(), 0, 
                           (struct sockaddr*)&addr, sizeof(addr));
    if (bytes_sent == SOCKET_ERROR_VALUE) {
        LOG_UDP_ERROR("Failed to send UDP data to " << peer.ip << ":" << peer.port);
        return -1;
    }
    
    LOG_UDP_DEBUG("Successfully sent " << bytes_sent << " bytes to " << peer.ip << ":" << peer.port);
    return bytes_sent;
}

std::vector<uint8_t> receive_udp_data(udp_socket_t socket, size_t buffer_size, UdpPeer& sender_peer) {
    std::vector<uint8_t> buffer(buffer_size);
    sockaddr_in sender_addr;
    socklen_t sender_addr_len = sizeof(sender_addr);
    
    int bytes_received = recvfrom(socket, (char*)buffer.data(), buffer_size, 0,
                                 (struct sockaddr*)&sender_addr, &sender_addr_len);
    
    if (bytes_received == SOCKET_ERROR_VALUE) {
        LOG_UDP_ERROR("Failed to receive UDP data");
        return std::vector<uint8_t>();
    }
    
    if (bytes_received == 0) {
        LOG_UDP_DEBUG("Received empty UDP packet");
        return std::vector<uint8_t>();
    }
    
    // Extract sender information
    char sender_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, INET_ADDRSTRLEN);
    sender_peer.ip = sender_ip;
    sender_peer.port = ntohs(sender_addr.sin_port);
    
    LOG_UDP_DEBUG("Received " << bytes_received << " bytes from " << sender_peer.ip << ":" << sender_peer.port);
    
    buffer.resize(bytes_received);
    return buffer;
}

void close_udp_socket(udp_socket_t socket) {
    if (is_valid_udp_socket(socket)) {
        LOG_UDP_DEBUG("Closing UDP socket " << socket);
        closesocket(socket);
    }
}

bool is_valid_udp_socket(udp_socket_t socket) {
    return socket != INVALID_UDP_SOCKET;
}

bool set_udp_socket_nonblocking(udp_socket_t socket) {
#ifdef _WIN32
    unsigned long mode = 1;
    if (ioctlsocket(socket, FIONBIO, &mode) != 0) {
        LOG_UDP_ERROR("Failed to set UDP socket to non-blocking mode");
        return false;
    }
#else
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        LOG_UDP_ERROR("Failed to get UDP socket flags");
        return false;
    }
    
    if (fcntl(socket, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_UDP_ERROR("Failed to set UDP socket to non-blocking mode");
        return false;
    }
#endif
    
    LOG_UDP_DEBUG("UDP socket set to non-blocking mode");
    return true;
}

} // namespace librats 