#pragma once

#include <string>
#include <functional>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
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
 * Initialize the networking library
 * @return true if successful, false otherwise
 */
bool init_networking();

/**
 * Cleanup the networking library
 */
void cleanup_networking();

/**
 * Create a TCP client socket and connect to a server
 * @param host The hostname or IP address to connect to
 * @param port The port number to connect to
 * @return Socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t create_tcp_client(const std::string& host, int port);

/**
 * Create a TCP client socket and connect to a server using IPv6
 * @param host The hostname or IPv6 address to connect to
 * @param port The port number to connect to
 * @return Socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t create_tcp_client_v6(const std::string& host, int port);

/**
 * Create a TCP client socket and connect to a server using dual stack (try IPv6 first, then IPv4)
 * @param host The hostname or IP address to connect to
 * @param port The port number to connect to
 * @return Socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t create_tcp_client_dual(const std::string& host, int port);

/**
 * Create a TCP server socket and bind to a port
 * @param port The port number to bind to
 * @param backlog The maximum number of pending connections
 * @return Socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t create_tcp_server(int port, int backlog = 5);

/**
 * Create a TCP server socket and bind to a port using IPv6
 * @param port The port number to bind to
 * @param backlog The maximum number of pending connections
 * @return Socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t create_tcp_server_v6(int port, int backlog = 5);

/**
 * Create a TCP server socket and bind to a port using dual stack (IPv6 with IPv4 fallback)
 * @param port The port number to bind to
 * @param backlog The maximum number of pending connections
 * @return Socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t create_tcp_server_dual(int port, int backlog = 5);

/**
 * Accept a client connection on a server socket
 * @param server_socket The server socket handle
 * @return Client socket handle, or INVALID_SOCKET_VALUE on error
 */
socket_t accept_client(socket_t server_socket);

/**
 * Send data through a socket
 * @param socket The socket handle
 * @param data The data to send
 * @return Number of bytes sent, or -1 on error
 */
int send_data(socket_t socket, const std::string& data);

/**
 * Receive data from a socket
 * @param socket The socket handle
 * @param buffer_size Maximum number of bytes to receive
 * @return Received data as string, empty string on error
 */
std::string receive_data(socket_t socket, size_t buffer_size = 1024);

/**
 * Close a socket
 * @param socket The socket handle to close
 */
void close_socket(socket_t socket);

/**
 * Check if a socket is valid
 * @param socket The socket handle to check
 * @return true if valid, false otherwise
 */
bool is_valid_socket(socket_t socket);

} // namespace librats 