#pragma once

#include <string>
#include <vector>
#include <cstdint>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET udp_socket_t;
    #define INVALID_UDP_SOCKET INVALID_SOCKET
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    typedef int udp_socket_t;
    #define INVALID_UDP_SOCKET -1
#endif

namespace librats {

/**
 * UDP peer information
 */
struct UdpPeer {
    std::string ip;
    uint16_t port;
    
    UdpPeer() : port(0) {}
    UdpPeer(const std::string& ip, uint16_t port) : ip(ip), port(port) {}
    
    bool operator==(const UdpPeer& other) const {
        return ip == other.ip && port == other.port;
    }
};

/**
 * Create a UDP socket
 * @param port The port to bind to (0 for any available port)
 * @return UDP socket handle, or INVALID_SOCKET_VALUE on error
 */
udp_socket_t create_udp_socket(int port = 0);

/**
 * Send UDP data to a peer
 * @param socket The UDP socket handle
 * @param data The data to send
 * @param peer The destination peer
 * @return Number of bytes sent, or -1 on error
 */
int send_udp_data(udp_socket_t socket, const std::vector<uint8_t>& data, const UdpPeer& peer);

/**
 * Receive UDP data from a peer
 * @param socket The UDP socket handle
 * @param buffer_size Maximum number of bytes to receive
 * @param sender_peer Output parameter for the sender's peer info
 * @return Received data, empty vector on error
 */
std::vector<uint8_t> receive_udp_data(udp_socket_t socket, size_t buffer_size, UdpPeer& sender_peer);

/**
 * Close UDP socket
 * @param socket The UDP socket handle to close
 */
void close_udp_socket(udp_socket_t socket);

/**
 * Check if UDP socket is valid
 * @param socket The UDP socket handle to check
 * @return true if valid, false otherwise
 */
bool is_valid_udp_socket(udp_socket_t socket);

/**
 * Set socket to non-blocking mode
 * @param socket The UDP socket handle
 * @return true if successful, false otherwise
 */
bool set_udp_socket_nonblocking(udp_socket_t socket);

} // namespace librats 