#pragma once

#include "address.h"

#include <string>
#include <functional>
#include <optional>
#include <vector>
#include <cstdint>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #ifdef _MSC_VER
        #pragma comment(lib, "ws2_32.lib")
    #endif
    typedef SOCKET socket_t;
    #define INVALID_SOCKET_VALUE INVALID_SOCKET
    #define SOCKET_ERROR_VALUE SOCKET_ERROR
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <unistd.h>
    typedef int socket_t;
    #define INVALID_SOCKET_VALUE -1
    #define SOCKET_ERROR_VALUE -1
    #define closesocket close
#endif

namespace librats {

/**
 * Address family for socket creation
 */
enum class AddressFamily {
    IPv4,       // IPv4 only
    IPv6,       // IPv6 only
    DualStack   // IPv6 socket with IPv4 support (default)
};

// Socket Library Initialization
/**
 * Initialize the socket library
 * @return true if successful, false otherwise
 */
bool init_socket_library();

/**
 * Cleanup the socket library
 */
void cleanup_socket_library();

// TCP Socket Functions
/**
 * Create a TCP client socket and connect to a server using dual stack (IPv6 with IPv4 fallback)
 * @param host The hostname or IP address to connect to
 * @param port The port number to connect to
 * @param timeout_ms Connection timeout in milliseconds (0 for blocking)
 * @return Socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t create_tcp_client(const std::string& host, int port, int timeout_ms = 0);

/**
 * Begin a non-blocking TCP connect (for use with an IOPoller / reactor).
 *
 * Creates a non-blocking socket and initiates connect() without waiting. The
 * returned socket's connection is typically still in progress: register it for
 * writable, and once it signals writable call tcp_connect_result() to learn the
 * outcome. Prefers IPv6, falls back to IPv4 at resolution time.
 *
 * @param host The hostname or IP address to connect to
 * @param port The port number to connect to
 * @return A non-blocking socket with a connect in progress (or completed), or
 *         INVALID_SOCKET_VALUE if the socket could not be created/resolved.
 */
socket_t tcp_connect_start(const std::string& host, int port);

/**
 * Report the result of a non-blocking connect once the socket is writable.
 * @param socket The socket previously returned by tcp_connect_start()
 * @return 0 if the connection succeeded, otherwise the socket error code.
 */
int tcp_connect_result(socket_t socket);

/**
 * Create a TCP server socket and bind to a port
 * @param port The port number to bind to
 * @param backlog The maximum number of pending connections
 * @param bind_address The interface IP address to bind to (empty for all interfaces)
 * @param af Address family (DualStack by default)
 * @return Socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t create_tcp_server(int port, int backlog = 5, const std::string& bind_address = "",
                           AddressFamily af = AddressFamily::DualStack);

/**
 * Accept a client connection on a server socket
 * @param server_socket The server socket handle
 * @return Client socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t accept_client(socket_t server_socket);

/**
 * Get the peer address (IP:port) from a connected socket
 * @param socket The connected socket handle
 * @return Peer address string in format "IP:port", or empty string on error
 */
std::string get_peer_address(socket_t socket);

/**
 * Get the peer endpoint as a numeric Address, straight from getpeername() with no
 * textual round-trip (IpAddress::from_sockaddr). Returns nullopt on error or an
 * unsupported address family. Note the port is the peer's ephemeral SOURCE port,
 * not its listen port.
 */
std::optional<Address> get_peer_endpoint(socket_t socket);

/**
 * Send data through a TCP socket
 * @param socket The socket handle
 * @param data The binary data to send
 * @return Number of bytes sent, or -1 on error
 */
int send_tcp_data(socket_t socket, const std::vector<uint8_t>& data);

/**
 * Receive data from a TCP socket
 * @param socket The socket handle
 * @param buffer_size Maximum number of bytes to receive
 * @return Received binary data, empty vector on error
 */
std::vector<uint8_t> receive_tcp_data(socket_t socket, size_t buffer_size = 1024);

/**
 * Send a length-prefixed framed message through a TCP socket
 * @param socket The socket handle
 * @param message The binary message to send
 * @return Total bytes sent (including length prefix), or -1 on error
 */
int send_tcp_message(socket_t socket, const std::vector<uint8_t>& message);

/**
 * Receive a complete length-prefixed framed message from a TCP socket
 * @param socket The socket handle
 * @return Complete binary message, empty vector on error or connection close
 */
std::vector<uint8_t> receive_tcp_message(socket_t socket);

/**
 * Send string data through a TCP socket (converts to binary)
 * @param socket The socket handle
 * @param data The string data to send
 * @return Number of bytes sent, or -1 on error
 */
int send_tcp_string(socket_t socket, const std::string& data);

// UDP Socket Functions
/**
 * Create a UDP socket and bind to a port
 * @param port The port to bind to (0 for any available port)
 * @param bind_address The interface IP address to bind to (empty for all interfaces)
 * @param af Address family (DualStack by default)
 * @return UDP socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t create_udp_socket(int port = 0, const std::string& bind_address = "",
                           AddressFamily af = AddressFamily::DualStack);

/**
 * Send UDP data to a destination host and port
 * @param socket The UDP socket handle
 * @param data The data to send
 * @param host The destination hostname or IP address
 * @param port The destination port
 * @param af Address family matching the socket (DualStack by default)
 * @return Number of bytes sent, or -1 on error
 */
int send_udp_data(socket_t socket, const std::vector<uint8_t>& data, const std::string& host, int port,
                  AddressFamily af = AddressFamily::DualStack);

/**
 * Send UDP data to a numeric Address. Unlike the host-string overload this does no
 * hostname resolution and no inet_pton — the destination sockaddr is filled straight
 * from the address bytes (an IPv4 address is mapped to ::ffff:x.x.x.x on a
 * DualStack/IPv6 socket). This is the hot path for engines like the DHT that already
 * hold resolved addresses.
 * @return Number of bytes sent, or -1 on error
 */
int send_udp_data(socket_t socket, const std::vector<uint8_t>& data, const Address& dest,
                  AddressFamily af = AddressFamily::DualStack);

/**
 * Receive UDP data with optional timeout
 * @param socket The UDP socket handle
 * @param buffer_size Maximum number of bytes to receive
 * @param sender_peer Output parameter for the sender's peer info
 * @param timeout_ms Timeout in milliseconds (-1 for blocking, 0 for non-blocking, >0 for timeout)
 * @param interrupt_fd Optional second socket to watch; when it becomes readable the
 *                     call returns immediately with an empty vector (used to wake a
 *                     blocking receive on shutdown). INVALID_SOCKET_VALUE disables it.
 * @return Received data, empty vector on timeout, error or interrupt
 */
std::vector<uint8_t> receive_udp_data(socket_t socket, size_t buffer_size, Address& sender_peer,
                                      int timeout_ms = -1,
                                      socket_t interrupt_fd = INVALID_SOCKET_VALUE);

// Common Socket Functions
/**
 * Close a socket
 * @param socket The socket handle to close
 * @param force If true, send RST instead of FIN (avoids TIME_WAIT)
 */
void close_socket(socket_t socket, bool force = false);

/**
 * Check if a socket is valid
 * @param socket The socket handle to check
 * @return true if valid, false otherwise
 */
bool is_valid_socket(socket_t socket);

/**
 * Set socket to non-blocking mode
 * @param socket The socket handle
 * @return true if successful, false otherwise
 */
bool set_socket_nonblocking(socket_t socket);

/**
 * Set socket to blocking mode
 * @param socket The socket handle
 * @return true if successful, false otherwise
 */
bool set_socket_blocking(socket_t socket);

/**
 * Connect to a socket address with timeout
 * @param socket The socket handle (should be non-blocking)
 * @param addr The socket address structure
 * @param addr_len Length of the address structure
 * @param timeout_ms Connection timeout in milliseconds
 * @return true if connected successfully, false on timeout or error
 */
bool connect_with_timeout(socket_t socket, struct sockaddr* addr, socklen_t addr_len, int timeout_ms);

/**
 * Get the port that a socket is bound to
 * @param socket The socket handle
 * @return The bound port, or 0 on error
 */
int get_bound_port(socket_t socket);

} // namespace librats
