#include "udp_network.h"
#include "network_utils.h"
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
    #include <errno.h>
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

udp_socket_t create_udp_socket_v6(int port) {
    LOG_UDP_DEBUG("Creating UDP socket on IPv6 port " << port);
    
    udp_socket_t udp_socket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udp_socket == INVALID_UDP_SOCKET) {
        LOG_UDP_ERROR("Failed to create IPv6 UDP socket");
        return INVALID_UDP_SOCKET;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_UDP_ERROR("Failed to set IPv6 UDP socket options");
        close_udp_socket(udp_socket);
        return INVALID_SOCKET_VALUE;
    }

    if (port > 0) {
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(port);

        if (bind(udp_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR_VALUE) {
            LOG_UDP_ERROR("Failed to bind IPv6 UDP socket to port " << port);
            close_udp_socket(udp_socket);
            return INVALID_SOCKET_VALUE;
        }
        
        LOG_UDP_INFO("IPv6 UDP socket bound to port " << port);
    }

    return udp_socket;
}

udp_socket_t create_udp_socket_dual(int port) {
    LOG_UDP_DEBUG("Creating dual stack UDP socket on port " << port);
    
    udp_socket_t udp_socket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udp_socket == INVALID_UDP_SOCKET) {
        LOG_UDP_ERROR("Failed to create dual stack UDP socket");
        return INVALID_UDP_SOCKET;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, 
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_UDP_ERROR("Failed to set dual stack UDP socket options");
        close_udp_socket(udp_socket);
        return INVALID_SOCKET_VALUE;
    }

    // Disable IPv6-only mode to allow IPv4 connections
    int ipv6_only = 0;
    if (setsockopt(udp_socket, IPPROTO_IPV6, IPV6_V6ONLY,
                   (char*)&ipv6_only, sizeof(ipv6_only)) == SOCKET_ERROR_VALUE) {
        LOG_UDP_WARN("Failed to disable IPv6-only mode, will be IPv6 only");
    }

    if (port > 0) {
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(port);

        if (bind(udp_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR_VALUE) {
            LOG_UDP_ERROR("Failed to bind dual stack UDP socket to port " << port);
            close_udp_socket(udp_socket);
            return INVALID_SOCKET_VALUE;
        }
        
        LOG_UDP_INFO("Dual stack UDP socket bound to port " << port);
    }

    return udp_socket;
}

int send_udp_data(udp_socket_t socket, const std::vector<uint8_t>& data, const UdpPeer& peer) {
    LOG_UDP_DEBUG("Sending " << data.size() << " bytes to " << peer.ip << ":" << peer.port);
    
    // Check if it's an IPv6 address
    if (network_utils::is_valid_ipv6(peer.ip)) {
        // Handle IPv6 address
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(peer.port);
        
        if (inet_pton(AF_INET6, peer.ip.c_str(), &addr.sin6_addr) <= 0) {
            LOG_UDP_ERROR("Invalid IPv6 address: " << peer.ip);
            return -1;
        }

        int bytes_sent = sendto(socket, (char*)data.data(), data.size(), 0, 
                               (struct sockaddr*)&addr, sizeof(addr));
        if (bytes_sent == SOCKET_ERROR_VALUE) {
            LOG_UDP_ERROR("Failed to send UDP data to IPv6 " << peer.ip << ":" << peer.port);
            return -1;
        }
        
        LOG_UDP_DEBUG("Successfully sent " << bytes_sent << " bytes to IPv6 " << peer.ip << ":" << peer.port);
        return bytes_sent;
    } else {
        // Handle IPv4 address or hostname
        std::string resolved_ip = network_utils::resolve_hostname(peer.ip);
        if (resolved_ip.empty()) {
            LOG_UDP_ERROR("Failed to resolve hostname: " << peer.ip);
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
            LOG_UDP_ERROR("Invalid IPv4 address: " << resolved_ip);
            return -1;
        }
        
        // Create IPv4-mapped IPv6 address: ::ffff:x.x.x.x
        addr.sin6_addr.s6_addr[10] = 0xff;
        addr.sin6_addr.s6_addr[11] = 0xff;
        memcpy(&addr.sin6_addr.s6_addr[12], &ipv4_addr.s_addr, 4);
        
        LOG_UDP_DEBUG("Converting IPv4 " << resolved_ip << " to IPv4-mapped IPv6 for dual-stack socket");

        int bytes_sent = sendto(socket, (char*)data.data(), data.size(), 0, 
                               (struct sockaddr*)&addr, sizeof(addr));
        if (bytes_sent == SOCKET_ERROR_VALUE) {
#ifdef _WIN32
            LOG_UDP_ERROR("Failed to send UDP data to " << resolved_ip << ":" << peer.port << " (error: " << WSAGetLastError() << ")");
#else
            LOG_UDP_ERROR("Failed to send UDP data to " << resolved_ip << ":" << peer.port << " (error: " << strerror(errno) << ")");
#endif
            return -1;
        }
        
        LOG_UDP_DEBUG("Successfully sent " << bytes_sent << " bytes to " << resolved_ip << ":" << peer.port << " via IPv4-mapped IPv6");
        return bytes_sent;
    }
}

std::vector<uint8_t> receive_udp_data(udp_socket_t socket, size_t buffer_size, UdpPeer& sender_peer) {
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
            LOG_UDP_ERROR("Failed to receive UDP data: " << error);
            return std::vector<uint8_t>();
        }
#else
        int error = errno;
        if (error == EAGAIN || error == EWOULDBLOCK) {
            // No data available on non-blocking socket - this is normal
            return std::vector<uint8_t>();
        } else {
            LOG_UDP_ERROR("Failed to receive UDP data: " << strerror(error));
            return std::vector<uint8_t>();
        }
#endif
    }
    
    if (bytes_received == 0) {
        LOG_UDP_DEBUG("Received empty UDP packet");
        return std::vector<uint8_t>();
    }
    
    // Extract sender information based on address family
    if (sender_addr.ss_family == AF_INET) {
        char sender_ip[INET_ADDRSTRLEN];
        struct sockaddr_in* addr_in = (struct sockaddr_in*)&sender_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, sender_ip, INET_ADDRSTRLEN);
        sender_peer.ip = sender_ip;
        sender_peer.port = ntohs(addr_in->sin_port);
        
        LOG_UDP_DEBUG("Received " << bytes_received << " bytes from " << sender_peer.ip << ":" << sender_peer.port);
    } else if (sender_addr.ss_family == AF_INET6) {
        char sender_ip[INET6_ADDRSTRLEN];
        struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)&sender_addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, sender_ip, INET6_ADDRSTRLEN);
        sender_peer.ip = sender_ip;
        sender_peer.port = ntohs(addr_in6->sin6_port);
        
        LOG_UDP_DEBUG("Received " << bytes_received << " bytes from IPv6 [" << sender_peer.ip << "]:" << sender_peer.port);
    } else {
        LOG_UDP_WARN("Received UDP data from unknown address family");
        sender_peer.ip = "unknown";
        sender_peer.port = 0;
    }
    
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