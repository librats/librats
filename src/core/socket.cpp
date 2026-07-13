#include "core/socket.h"
#include "util/network_utils.h"
#include "util/logger.h"
#include <iostream>
#include <cstring>
#include <mutex>
#include <thread>
#include <chrono>
#ifndef _WIN32
    #include <fcntl.h>    // for O_NONBLOCK
    #include <errno.h>    // for errno
    #include <sys/uio.h>  // for iovec (send_vectored)
    #include <limits.h>   // for IOV_MAX (send_vectored)
    // macOS/BSD have no MSG_NOSIGNAL; they suppress SIGPIPE with the SO_NOSIGPIPE
    // socket option instead, which suppress_sigpipe() sets on every TCP socket we
    // send on — so sending with no flag is the right fallback there.
    #ifndef MSG_NOSIGNAL
        #define MSG_NOSIGNAL 0
    #endif
#endif

// On Windows, SIO_UDP_CONNRESET lives in <mstcpip.h>, which mingw doesn't always pull
// in via <winsock2.h>. Define it from its well-known control code as a fallback.
#if defined(_WIN32) && !defined(SIO_UDP_CONNRESET)
    #define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

// Socket module logging macros
#define LOG_SOCKET_DEBUG(message) LOG_DEBUG("socket", message)
#define LOG_SOCKET_INFO(message)  LOG_INFO("socket", message)
#define LOG_SOCKET_WARN(message)  LOG_WARN("socket", message)
#define LOG_SOCKET_ERROR(message) LOG_ERROR("socket", message)

namespace librats {

// ── Internal helpers ────────────────────────────────────────────────────────

static bool validate_port(int port) {
    if (port < 0 || port > 65535) {
        LOG_SOCKET_ERROR("Invalid port number: " << port << " (must be 0-65535)");
        return false;
    }
    return true;
}

static int get_last_socket_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static std::string socket_error_string(int error) {
#ifdef _WIN32
    return std::to_string(error);
#else
    return strerror(error);
#endif
}

void suppress_sigpipe(socket_t socket) {
#ifdef SO_NOSIGPIPE
    int on = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE,
                   reinterpret_cast<const char*>(&on), sizeof(on)) != 0) {
        LOG_SOCKET_WARN("Failed to set SO_NOSIGPIPE on socket " << socket << ": "
                        << socket_error_string(get_last_socket_error()));
    }
#else
    (void)socket;
#endif
}

// Extract sender peer info from sockaddr_storage (shared by UDP receive).
// IpAddress::from_sockaddr copies the raw address bytes (and unwraps IPv4-mapped
// IPv6) with no textual round-trip; an unknown family yields an unspecified peer.
static void extract_sender_peer(const sockaddr_storage& sender_addr, Address& peer) {
    const auto* sa = reinterpret_cast<const sockaddr*>(&sender_addr);
    if (auto ip = IpAddress::from_sockaddr(sa)) {
        peer.ip = *ip;
        peer.port = (sender_addr.ss_family == AF_INET)
                        ? ntohs(reinterpret_cast<const sockaddr_in*>(&sender_addr)->sin_port)
                        : ntohs(reinterpret_cast<const sockaddr_in6*>(&sender_addr)->sin6_port);
    } else {
        peer = Address{};
    }
}

// ── Static TCP client helpers (IPv4 / IPv6) ─────────────────────────────────

static socket_t create_tcp_client_v4(const std::string& host, int port, int timeout_ms) {
    LOG_SOCKET_DEBUG("Creating TCP client socket (IPv4) for " << host << ":" << port);

    socket_t client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create IPv4 client socket");
        return INVALID_SOCKET_VALUE;
    }
    suppress_sigpipe(client_socket);

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    std::string resolved_ip = network_utils::resolve_hostname(host);
    if (resolved_ip.empty()) {
        LOG_SOCKET_ERROR("Failed to resolve hostname: " << host);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    if (inet_pton(AF_INET, resolved_ip.c_str(), &server_addr.sin_addr) <= 0) {
        LOG_SOCKET_ERROR("Invalid address: " << resolved_ip);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_SOCKET_DEBUG("Connecting to " << resolved_ip << ":" << port);
    bool ok;
    if (timeout_ms > 0) {
        ok = connect_with_timeout(client_socket, reinterpret_cast<sockaddr*>(&server_addr),
                                  sizeof(server_addr), timeout_ms);
    } else {
        ok = (connect(client_socket, reinterpret_cast<sockaddr*>(&server_addr),
                      sizeof(server_addr)) != SOCKET_ERROR_VALUE);
    }

    if (!ok) {
        LOG_SOCKET_DEBUG("Connection to " << resolved_ip << ":" << port << " failed");
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_SOCKET_INFO("Successfully connected to " << resolved_ip << ":" << port);
    return client_socket;
}

static socket_t create_tcp_client_v6(const std::string& host, int port, int timeout_ms) {
    LOG_SOCKET_DEBUG("Creating TCP client socket (IPv6) for " << host << ":" << port);

    socket_t client_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create IPv6 client socket");
        return INVALID_SOCKET_VALUE;
    }
    suppress_sigpipe(client_socket);

    sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(port);

    std::string resolved_ip = network_utils::resolve_hostname_v6(host);
    if (resolved_ip.empty()) {
        LOG_SOCKET_DEBUG("Failed to resolve hostname to IPv6: " << host);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    if (inet_pton(AF_INET6, resolved_ip.c_str(), &server_addr.sin6_addr) <= 0) {
        LOG_SOCKET_ERROR("Invalid IPv6 address: " << resolved_ip);
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_SOCKET_DEBUG("Connecting to IPv6 " << resolved_ip << ":" << port);
    bool ok;
    if (timeout_ms > 0) {
        ok = connect_with_timeout(client_socket, reinterpret_cast<sockaddr*>(&server_addr),
                                  sizeof(server_addr), timeout_ms);
    } else {
        ok = (connect(client_socket, reinterpret_cast<sockaddr*>(&server_addr),
                      sizeof(server_addr)) != SOCKET_ERROR_VALUE);
    }

    if (!ok) {
        LOG_SOCKET_DEBUG("Connection to IPv6 " << resolved_ip << ":" << port << " failed");
        close_socket(client_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_SOCKET_INFO("Successfully connected to IPv6 " << resolved_ip << ":" << port);
    return client_socket;
}

// ── Socket Library Initialization ───────────────────────────────────────────

static bool socket_library_initialized = false;
static std::mutex socket_init_mutex;

bool init_socket_library() {
    std::lock_guard<std::mutex> lock(socket_init_mutex);

    if (socket_library_initialized) {
        return true;
    }

#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        LOG_SOCKET_ERROR("WSAStartup failed: " << result);
        return false;
    }
    LOG_SOCKET_INFO("Windows Socket API initialized");
#endif

    socket_library_initialized = true;
    LOG_SOCKET_INFO("Socket library initialized");
    return true;
}

void cleanup_socket_library() {
    std::lock_guard<std::mutex> lock(socket_init_mutex);

    if (!socket_library_initialized) {
        return;
    }

#ifdef _WIN32
    WSACleanup();
    LOG_SOCKET_INFO("Windows Socket API cleaned up");
#endif

    socket_library_initialized = false;
    LOG_SOCKET_INFO("Socket library cleaned up");
}

// ── connect_with_timeout ────────────────────────────────────────────────────

bool connect_with_timeout(socket_t socket, struct sockaddr* addr, socklen_t addr_len, int timeout_ms) {
    if (!set_socket_nonblocking(socket)) {
        LOG_SOCKET_ERROR("Failed to set socket to non-blocking mode for timeout connection");
        return false;
    }

    int result = connect(socket, addr, addr_len);
    if (result == 0) {
        LOG_SOCKET_DEBUG("Connection succeeded immediately");
        return true;
    }

#ifdef _WIN32
    int error = WSAGetLastError();
    if (error != WSAEWOULDBLOCK) {
        LOG_SOCKET_ERROR("Connect failed immediately with error: " << error);
        return false;
    }
#else
    int error = errno;
    if (error != EINPROGRESS) {
        LOG_SOCKET_ERROR("Connect failed immediately with error: " << strerror(error));
        return false;
    }
#endif

    fd_set write_fds, error_fds;
    FD_ZERO(&write_fds);
    FD_ZERO(&error_fds);
    FD_SET(socket, &write_fds);
    FD_SET(socket, &error_fds);

    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    LOG_SOCKET_DEBUG("Waiting for connection with timeout " << timeout_ms << "ms");
    int select_result = select(socket + 1, nullptr, &write_fds, &error_fds, &timeout);

    if (select_result == 0) {
        LOG_SOCKET_DEBUG("Connection timeout after " << timeout_ms << "ms");
        return false;
    } else if (select_result < 0) {
        LOG_SOCKET_ERROR("Select error during connect: " << socket_error_string(get_last_socket_error()));
        return false;
    }

    if (FD_ISSET(socket, &error_fds)) {
        LOG_SOCKET_DEBUG("Connection failed (error detected)");
        return false;
    }

    if (FD_ISSET(socket, &write_fds)) {
        int sock_error;
        socklen_t len = sizeof(sock_error);
        if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (char*)&sock_error, &len) < 0) {
            LOG_SOCKET_ERROR("Failed to get socket error status");
            return false;
        }

        if (sock_error != 0) {
            LOG_SOCKET_ERROR("Connection failed with error: " << socket_error_string(sock_error));
            return false;
        }

        if (!set_socket_blocking(socket)) {
            LOG_SOCKET_WARN("Failed to restore socket to blocking mode after connection");
        }

        LOG_SOCKET_DEBUG("Connection succeeded within timeout");
        return true;
    }

    LOG_SOCKET_ERROR("Unexpected select result state");
    return false;
}

// ── Non-blocking connect (reactor-driven) ───────────────────────────────────

static socket_t tcp_connect_start_family(int family, const std::string& resolved_ip, int port) {
    socket_t s = socket(family, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET_VALUE) return INVALID_SOCKET_VALUE;
    suppress_sigpipe(s);

    if (!set_socket_nonblocking(s)) {
        close_socket(s);
        return INVALID_SOCKET_VALUE;
    }

    sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t addr_len = 0;

    if (family == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        a->sin_family = AF_INET;
        a->sin_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET, resolved_ip.c_str(), &a->sin_addr) <= 0) {
            close_socket(s);
            return INVALID_SOCKET_VALUE;
        }
        addr_len = sizeof(sockaddr_in);
    } else {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET6, resolved_ip.c_str(), &a->sin6_addr) <= 0) {
            close_socket(s);
            return INVALID_SOCKET_VALUE;
        }
        addr_len = sizeof(sockaddr_in6);
    }

    int r = connect(s, reinterpret_cast<sockaddr*>(&ss), addr_len);
    if (r == 0) {
        return s;  // Connected synchronously (common on loopback).
    }
#ifdef _WIN32
    int e = WSAGetLastError();
    if (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS) return s;  // In progress.
#else
    if (errno == EINPROGRESS) return s;  // In progress.
#endif
    LOG_SOCKET_DEBUG("Non-blocking connect to " << resolved_ip << ":" << port << " failed to start");
    close_socket(s);
    return INVALID_SOCKET_VALUE;
}

socket_t tcp_connect_start(const std::string& host, int port) {
    if (!validate_port(port)) return INVALID_SOCKET_VALUE;

    // Prefer IPv6, fall back to IPv4 — same precedence as create_tcp_client().
    // Note: fallback happens at *resolution* time; a v6 address that resolves
    // but fails asynchronously surfaces later as ConnectFailed (happy-eyeballs
    // sequencing belongs in the higher-level dialer).
    std::string ip6 = network_utils::resolve_hostname_v6(host);
    if (!ip6.empty()) {
        socket_t s = tcp_connect_start_family(AF_INET6, ip6, port);
        if (is_valid_socket(s)) return s;
    }

    std::string ip4 = network_utils::resolve_hostname(host);
    if (!ip4.empty()) {
        socket_t s = tcp_connect_start_family(AF_INET, ip4, port);
        if (is_valid_socket(s)) return s;
    }

    return INVALID_SOCKET_VALUE;
}

int tcp_connect_result(socket_t socket) {
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) != 0) {
#ifdef _WIN32
        return WSAGetLastError();
#else
        return errno;
#endif
    }
    return err;  // 0 == connected
}

// ── TCP Socket Functions ────────────────────────────────────────────────────

socket_t create_tcp_client(const std::string& host, int port, int timeout_ms) {
    if (!validate_port(port)) return INVALID_SOCKET_VALUE;

    LOG_SOCKET_DEBUG("Creating TCP client socket (dual stack) for " << host << ":" << port);

    // Try IPv6 first
    socket_t client_socket = create_tcp_client_v6(host, port, timeout_ms);
    if (client_socket != INVALID_SOCKET_VALUE) {
        LOG_SOCKET_INFO("Successfully connected using IPv6");
        return client_socket;
    }

    // Fall back to IPv4
    LOG_SOCKET_DEBUG("IPv6 connection failed, trying IPv4");
    client_socket = create_tcp_client_v4(host, port, timeout_ms);
    if (client_socket != INVALID_SOCKET_VALUE) {
        LOG_SOCKET_INFO("Successfully connected using IPv4");
        return client_socket;
    }

    LOG_SOCKET_DEBUG("Failed to connect using both IPv6 and IPv4");
    return INVALID_SOCKET_VALUE;
}

socket_t create_tcp_server(int port, int backlog, const std::string& bind_address, AddressFamily af) {
    if (!validate_port(port)) return INVALID_SOCKET_VALUE;

    const char* af_label = (af == AddressFamily::IPv4) ? "IPv4" :
                           (af == AddressFamily::IPv6) ? "IPv6" : "dual stack";
    LOG_SOCKET_DEBUG("Creating TCP server socket (" << af_label << ") on port " << port <<
                     (bind_address.empty() ? "" : " bound to " + bind_address));

    int family = (af == AddressFamily::IPv4) ? AF_INET : AF_INET6;

    socket_t server_socket = socket(family, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create " << af_label << " server socket");
        return INVALID_SOCKET_VALUE;
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR,
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to set " << af_label << " socket options");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    // For IPv6/DualStack sockets, configure IPV6_V6ONLY
    if (family == AF_INET6) {
        int ipv6_only = (af == AddressFamily::IPv6) ? 1 : 0;
        if (setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY,
                       (char*)&ipv6_only, sizeof(ipv6_only)) == SOCKET_ERROR_VALUE) {
            if (af == AddressFamily::DualStack) {
                LOG_SOCKET_WARN("Failed to disable IPv6-only mode, will be IPv6 only");
            }
        }
    }

    // Bind
    if (family == AF_INET) {
        sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);

        if (bind_address.empty()) {
            server_addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            if (inet_pton(AF_INET, bind_address.c_str(), &server_addr.sin_addr) != 1) {
                LOG_SOCKET_ERROR("Invalid IPv4 bind address: " << bind_address);
                close_socket(server_socket);
                return INVALID_SOCKET_VALUE;
            }
        }

        if (bind(server_socket, reinterpret_cast<sockaddr*>(&server_addr),
                 sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
            LOG_SOCKET_ERROR("Failed to bind " << af_label << " server socket to port " << port);
            close_socket(server_socket);
            return INVALID_SOCKET_VALUE;
        }
    } else {
        sockaddr_in6 server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_port = htons(port);

        if (bind_address.empty()) {
            server_addr.sin6_addr = in6addr_any;
        } else {
            if (inet_pton(AF_INET6, bind_address.c_str(), &server_addr.sin6_addr) != 1) {
                LOG_SOCKET_ERROR("Invalid IPv6 bind address: " << bind_address);
                close_socket(server_socket);
                return INVALID_SOCKET_VALUE;
            }
        }

        if (bind(server_socket, reinterpret_cast<sockaddr*>(&server_addr),
                 sizeof(server_addr)) == SOCKET_ERROR_VALUE) {
            LOG_SOCKET_ERROR("Failed to bind " << af_label << " server socket to port " << port);
            close_socket(server_socket);
            return INVALID_SOCKET_VALUE;
        }
    }

    if (listen(server_socket, backlog) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to listen on " << af_label << " server socket");
        close_socket(server_socket);
        return INVALID_SOCKET_VALUE;
    }

    LOG_SOCKET_INFO(af_label << " server listening on port " << port << " (backlog: " << backlog << ")");
    return server_socket;
}

socket_t accept_client(socket_t server_socket) {
    sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    socket_t client_socket = accept(server_socket, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);
    if (client_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to accept client connection");
        return INVALID_SOCKET_VALUE;
    }
    suppress_sigpipe(client_socket);

    if (client_addr.ss_family == AF_INET) {
        char client_ip[INET_ADDRSTRLEN];
        auto* addr_in = reinterpret_cast<sockaddr_in*>(&client_addr);
        inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, INET_ADDRSTRLEN);
        LOG_SOCKET_INFO("Client connected from " << client_ip << ":" << ntohs(addr_in->sin_port));
    } else if (client_addr.ss_family == AF_INET6) {
        char client_ip[INET6_ADDRSTRLEN];
        auto* addr_in6 = reinterpret_cast<sockaddr_in6*>(&client_addr);
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

    if (getpeername(socket, reinterpret_cast<sockaddr*>(&peer_addr), &peer_addr_len) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to get peer address for socket " << socket);
        return "";
    }

    std::string peer_ip;
    uint16_t peer_port = 0;

    if (peer_addr.ss_family == AF_INET) {
        char ip_str[INET_ADDRSTRLEN];
        auto* addr_in = reinterpret_cast<sockaddr_in*>(&peer_addr);
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
        peer_ip = ip_str;
        peer_port = ntohs(addr_in->sin_port);
    } else if (peer_addr.ss_family == AF_INET6) {
        char ip_str[INET6_ADDRSTRLEN];
        auto* addr_in6 = reinterpret_cast<sockaddr_in6*>(&peer_addr);
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
        peer_ip = ip_str;
        peer_port = ntohs(addr_in6->sin6_port);
    } else {
        LOG_SOCKET_ERROR("Unknown address family for socket " << socket);
        return "";
    }

    return peer_ip + ":" + std::to_string(peer_port);
}

std::optional<Address> get_peer_endpoint(socket_t socket) {
    sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    if (getpeername(socket, reinterpret_cast<sockaddr*>(&ss), &len) == SOCKET_ERROR_VALUE)
        return std::nullopt;
    auto ip = IpAddress::from_sockaddr(reinterpret_cast<sockaddr*>(&ss));
    if (!ip) return std::nullopt;
    const uint16_t port = (ss.ss_family == AF_INET)
                              ? ntohs(reinterpret_cast<sockaddr_in*>(&ss)->sin_port)
                              : ntohs(reinterpret_cast<sockaddr_in6*>(&ss)->sin6_port);
    return Address{*ip, port};
}

std::ptrdiff_t send_vectored(socket_t socket, const ByteView* slices, size_t count) {
    if (count == 0) return 0;
    if (count > kMaxSendSlices) count = kMaxSendSlices;
#if !defined(_WIN32) && defined(IOV_MAX)
    // sendmsg() rejects an iovec longer than IOV_MAX with EINVAL — which the callers
    // read as "the peer is gone" and would close a perfectly healthy connection over.
    // POSIX only guarantees 16 (Linux and macOS allow 1024), so clamp rather than
    // trust kMaxSendSlices to be under every platform's limit. The slices that don't
    // fit are not lost: they go out on the next round of the caller's flush loop.
    if (count > static_cast<size_t>(IOV_MAX)) count = static_cast<size_t>(IOV_MAX);
#endif

#ifdef _WIN32
    WSABUF bufs[kMaxSendSlices];
    for (size_t i = 0; i < count; ++i) {
        bufs[i].buf = reinterpret_cast<CHAR*>(const_cast<uint8_t*>(slices[i].data()));
        bufs[i].len = static_cast<ULONG>(slices[i].size());
    }
    DWORD sent = 0;
    if (WSASend(socket, bufs, static_cast<DWORD>(count), &sent, 0, nullptr, nullptr) == SOCKET_ERROR) {
        return -1;
    }
    return static_cast<std::ptrdiff_t>(sent);
#else
    struct iovec iov[kMaxSendSlices];
    for (size_t i = 0; i < count; ++i) {
        iov[i].iov_base = const_cast<uint8_t*>(slices[i].data());
        iov[i].iov_len  = slices[i].size();
    }
    struct msghdr msg = {};
    msg.msg_iov    = iov;
    msg.msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(count);
    // MSG_NOSIGNAL keeps a peer that hung up from killing the process with SIGPIPE.
    // It doesn't exist on macOS/BSD (they use SO_NOSIGPIPE on the socket instead),
    // where the fallback below makes this a plain sendmsg().
    return ::sendmsg(socket, &msg, MSG_NOSIGNAL);
#endif
}

int send_tcp_data(socket_t socket, const std::vector<uint8_t>& data) {
    LOG_SOCKET_DEBUG("Sending " << data.size() << " bytes to TCP socket " << socket);

    size_t total_sent = 0;
    const char* buffer = reinterpret_cast<const char*>(data.data());
    size_t remaining = data.size();

    while (remaining > 0) {
#ifdef _WIN32
        int bytes_sent = send(socket, buffer + total_sent, remaining, 0);
#else
        int bytes_sent = send(socket, buffer + total_sent, remaining, MSG_NOSIGNAL);
#endif
        if (bytes_sent == SOCKET_ERROR_VALUE) {
            int error = get_last_socket_error();
#ifdef _WIN32
            if (error == WSAEWOULDBLOCK) { continue; }
#else
            if (error == EAGAIN || error == EWOULDBLOCK) { continue; }
            if (error == EPIPE || error == ECONNRESET || error == ENOTCONN) {
                LOG_SOCKET_DEBUG("Connection closed during send to socket " << socket
                                 << " (error: " << strerror(error) << ")");
                return -1;
            }
#endif
            LOG_SOCKET_ERROR("Failed to send TCP data to socket " << socket
                             << " (error: " << socket_error_string(error) << ")");
            return -1;
        }

        if (bytes_sent == 0) {
            LOG_SOCKET_ERROR("Connection closed by peer during send on socket " << socket);
            return -1;
        }

        total_sent += bytes_sent;
        remaining -= bytes_sent;
        LOG_SOCKET_DEBUG("Sent " << bytes_sent << " bytes, " << remaining << " remaining");
    }

    LOG_SOCKET_DEBUG("Successfully sent all " << total_sent << " bytes to TCP socket " << socket);
    return static_cast<int>(total_sent);
}

std::vector<uint8_t> receive_tcp_data(socket_t socket, size_t buffer_size) {
    if (buffer_size == 0) {
        buffer_size = 1024;
    }

    std::vector<uint8_t> buffer(buffer_size);

    int bytes_received = recv(socket, reinterpret_cast<char*>(buffer.data()), buffer_size, 0);
    if (bytes_received == SOCKET_ERROR_VALUE) {
        int error = get_last_socket_error();
#ifdef _WIN32
        if (error == WSAEWOULDBLOCK) { return {}; }
#else
        if (error == EAGAIN || error == EWOULDBLOCK) { return {}; }
#endif
        LOG_SOCKET_ERROR("Failed to receive TCP data from socket " << socket
                         << " (error: " << socket_error_string(error) << ")");
        return {};
    }

    if (bytes_received == 0) {
        LOG_SOCKET_INFO("Connection closed by peer on socket " << socket);
        return {};
    }

    LOG_SOCKET_DEBUG("Received " << bytes_received << " bytes from TCP socket " << socket);
    buffer.resize(bytes_received);
    return buffer;
}

// ── Framed message protocol ────────────────────────────────────────────────

int send_tcp_message(socket_t socket, const std::vector<uint8_t>& message) {
    // Create length prefix (4 bytes, network byte order)
    uint32_t message_length = static_cast<uint32_t>(message.size());
    uint32_t length_prefix = htonl(message_length);

    std::vector<uint8_t> prefix_data(reinterpret_cast<const uint8_t*>(&length_prefix),
                                     reinterpret_cast<const uint8_t*>(&length_prefix) + 4);
    int prefix_sent = send_tcp_data(socket, prefix_data);
    if (prefix_sent != 4) {
        LOG_SOCKET_ERROR("Failed to send message length prefix to socket " << socket);
        return -1;
    }

    int message_sent = send_tcp_data(socket, message);
    if (message_sent != static_cast<int>(message.size())) {
        LOG_SOCKET_ERROR("Failed to send complete message to socket " << socket);
        return -1;
    }

    LOG_SOCKET_DEBUG("Successfully sent framed message (" << message.size() << " bytes) to socket " << socket);
    return prefix_sent + message_sent;
}

static std::vector<uint8_t> receive_exact_bytes(socket_t socket, size_t num_bytes) {
    std::vector<uint8_t> result;
    result.reserve(num_bytes);

    size_t total_received = 0;
    while (total_received < num_bytes) {
        std::vector<uint8_t> buffer(num_bytes - total_received);
        int bytes_received = recv(socket, reinterpret_cast<char*>(buffer.data()), buffer.size(), 0);

        if (bytes_received == SOCKET_ERROR_VALUE) {
            int error = get_last_socket_error();
#ifdef _WIN32
            if (error == WSAEWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
#else
            if (error == EAGAIN || error == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
#endif
            LOG_SOCKET_ERROR("Failed to receive exact bytes from socket " << socket
                             << " (error: " << socket_error_string(error) << ")");
            return {};
        }

        if (bytes_received == 0) {
            LOG_SOCKET_INFO("Connection closed by peer while receiving exact bytes on socket " << socket);
            return {};
        }

        result.insert(result.end(), buffer.begin(), buffer.begin() + bytes_received);
        total_received += bytes_received;
    }

    LOG_SOCKET_DEBUG("Successfully received " << total_received << " exact bytes from socket " << socket);
    return result;
}

std::vector<uint8_t> receive_tcp_message(socket_t socket) {
    // Receive the 4-byte length prefix
    std::vector<uint8_t> length_data = receive_exact_bytes(socket, 4);
    if (length_data.size() != 4) {
        if (!length_data.empty()) {
            LOG_SOCKET_ERROR("Failed to receive complete length prefix from socket " << socket
                             << " (got " << length_data.size() << " bytes)");
        }
        return {};
    }

    uint32_t length_prefix;
    memcpy(&length_prefix, length_data.data(), 4);
    uint32_t message_length = ntohl(length_prefix);

    if (message_length == 0) {
        LOG_SOCKET_DEBUG("Received keep-alive message (length 0) from socket " << socket);
        return {};
    }

    if (message_length > 100 * 1024 * 1024) { // 100MB limit
        LOG_SOCKET_ERROR("Message length too large: " << message_length << " bytes from socket " << socket);
        return {};
    }

    std::vector<uint8_t> message = receive_exact_bytes(socket, message_length);
    if (message.size() != message_length) {
        LOG_SOCKET_ERROR("Failed to receive complete message from socket " << socket
                         << " (expected " << message_length << " bytes, got " << message.size() << ")");
        return {};
    }

    LOG_SOCKET_DEBUG("Successfully received framed message (" << message_length << " bytes) from socket " << socket);
    return message;
}

// ── String convenience ──────────────────────────────────────────────────────

int send_tcp_string(socket_t socket, const std::string& data) {
    std::vector<uint8_t> binary_data(data.begin(), data.end());
    return send_tcp_data(socket, binary_data);
}

// ── UDP Socket Functions ────────────────────────────────────────────────────

socket_t create_udp_socket(int port, const std::string& bind_address, AddressFamily af) {
    if (!validate_port(port)) return INVALID_SOCKET_VALUE;

    const char* af_label = (af == AddressFamily::IPv4) ? "IPv4" :
                           (af == AddressFamily::IPv6) ? "IPv6" : "dual stack";
    LOG_SOCKET_DEBUG("Creating " << af_label << " UDP socket on port " << port <<
                     (bind_address.empty() ? "" : " bound to " + bind_address));

    int family = (af == AddressFamily::IPv4) ? AF_INET : AF_INET6;

    socket_t udp_socket = socket(family, SOCK_DGRAM, 0);
    if (udp_socket == INVALID_SOCKET_VALUE) {
        LOG_SOCKET_ERROR("Failed to create " << af_label << " UDP socket (error: "
                         << socket_error_string(get_last_socket_error()) << ")");
        return INVALID_SOCKET_VALUE;
    }

#ifdef _WIN32
    // Disable the Windows-only "UDP connection reset" behaviour. By default, when a
    // datagram we sent provokes an ICMP "port unreachable", Windows fails the *next*
    // recvfrom() on this socket with WSAECONNRESET — nonsensical for a connectionless
    // protocol. A DHT constantly sends to dead/unreachable nodes, so without this every
    // such ICMP would cost us a receive cycle. FALSE turns it off.
    {
        BOOL connreset = FALSE;
        DWORD bytes_returned = 0;
        WSAIoctl(udp_socket, SIO_UDP_CONNRESET, &connreset, sizeof(connreset),
                 nullptr, 0, &bytes_returned, nullptr, nullptr);
    }
#endif

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR,
                   (char*)&opt, sizeof(opt)) == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to set " << af_label << " UDP socket options");
        close_socket(udp_socket);
        return INVALID_SOCKET_VALUE;
    }

    // For IPv6/DualStack sockets, configure IPV6_V6ONLY
    if (family == AF_INET6) {
        int ipv6_only = (af == AddressFamily::IPv6) ? 1 : 0;
        if (setsockopt(udp_socket, IPPROTO_IPV6, IPV6_V6ONLY,
                       (char*)&ipv6_only, sizeof(ipv6_only)) == SOCKET_ERROR_VALUE) {
            if (af == AddressFamily::DualStack) {
                LOG_SOCKET_WARN("Failed to disable IPv6-only mode, will be IPv6 only");
            }
        }
    }

    // Bind
    if (family == AF_INET) {
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (bind_address.empty()) {
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            if (inet_pton(AF_INET, bind_address.c_str(), &addr.sin_addr) != 1) {
                LOG_SOCKET_ERROR("Invalid IPv4 bind address: " << bind_address);
                close_socket(udp_socket);
                return INVALID_SOCKET_VALUE;
            }
        }

        if (bind(udp_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR_VALUE) {
            LOG_SOCKET_ERROR("Failed to bind " << af_label << " UDP socket to port " << port
                             << " (error: " << socket_error_string(get_last_socket_error()) << ")");
            close_socket(udp_socket);
            return INVALID_SOCKET_VALUE;
        }
    } else {
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);

        if (bind_address.empty()) {
            addr.sin6_addr = in6addr_any;
        } else {
            if (inet_pton(AF_INET6, bind_address.c_str(), &addr.sin6_addr) != 1) {
                LOG_SOCKET_ERROR("Invalid IPv6 bind address: " << bind_address);
                close_socket(udp_socket);
                return INVALID_SOCKET_VALUE;
            }
        }

        if (bind(udp_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR_VALUE) {
            LOG_SOCKET_ERROR("Failed to bind " << af_label << " UDP socket to port " << port
                             << " (error: " << socket_error_string(get_last_socket_error()) << ")");
            close_socket(udp_socket);
            return INVALID_SOCKET_VALUE;
        }
    }

    // Log the actual bound port
    if (port == 0) {
        int actual_port = get_bound_port(udp_socket);
        if (actual_port > 0) {
            LOG_SOCKET_INFO(af_label << " UDP socket bound to ephemeral port " << actual_port);
        } else {
            LOG_SOCKET_INFO(af_label << " UDP socket bound to ephemeral port (unknown)");
        }
    } else {
        LOG_SOCKET_INFO(af_label << " UDP socket bound to port " << port);
    }

    return udp_socket;
}

// Build a sockaddr for sending UDP data to the given host:port.
// For DualStack/IPv6 sockets, IPv4 addresses are mapped to ::ffff:x.x.x.x
static bool build_udp_dest_addr(const std::string& host, int port, AddressFamily af,
                                sockaddr_storage& addr, socklen_t& addr_len) {
    memset(&addr, 0, sizeof(addr));

    // Native IPv6 address, or hostname that must resolve to IPv6 (pure IPv6 socket).
    // A pure IPv6 socket (V6ONLY) cannot send to IPv4-mapped addresses, so hostnames
    // are resolved via AAAA records here.
    std::string ipv6_host;
    if (network_utils::is_valid_ipv6(host)) {
        ipv6_host = host;
    } else if (af == AddressFamily::IPv6) {
        ipv6_host = network_utils::resolve_hostname_v6(host);
        if (ipv6_host.empty()) {
            LOG_SOCKET_DEBUG("Failed to resolve hostname to IPv6: " << host);
            return false;
        }
    }
    if (!ipv6_host.empty()) {
        auto* a6 = reinterpret_cast<sockaddr_in6*>(&addr);
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, ipv6_host.c_str(), &a6->sin6_addr) <= 0) {
            LOG_SOCKET_ERROR("Invalid IPv6 address: " << ipv6_host);
            return false;
        }
        addr_len = sizeof(sockaddr_in6);
        return true;
    }

    // Resolve IPv4 / hostname
    std::string resolved_ip = network_utils::resolve_hostname(host);
    if (resolved_ip.empty()) {
        LOG_SOCKET_ERROR("Failed to resolve hostname: " << host);
        return false;
    }

    if (af == AddressFamily::IPv4) {
        // Pure IPv4 socket
        auto* a4 = reinterpret_cast<sockaddr_in*>(&addr);
        a4->sin_family = AF_INET;
        a4->sin_port = htons(port);
        if (inet_pton(AF_INET, resolved_ip.c_str(), &a4->sin_addr) <= 0) {
            LOG_SOCKET_ERROR("Invalid IPv4 address: " << resolved_ip);
            return false;
        }
        addr_len = sizeof(sockaddr_in);
    } else {
        // DualStack / IPv6 → IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        auto* a6 = reinterpret_cast<sockaddr_in6*>(&addr);
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);

        struct in_addr ipv4_addr;
        if (inet_pton(AF_INET, resolved_ip.c_str(), &ipv4_addr) <= 0) {
            LOG_SOCKET_ERROR("Invalid IPv4 address: " << resolved_ip);
            return false;
        }
        a6->sin6_addr.s6_addr[10] = 0xff;
        a6->sin6_addr.s6_addr[11] = 0xff;
        memcpy(&a6->sin6_addr.s6_addr[12], &ipv4_addr.s_addr, 4);
        addr_len = sizeof(sockaddr_in6);
    }
    return true;
}

int send_udp_data(socket_t socket, const std::vector<uint8_t>& data,
                  const std::string& host, int port, AddressFamily af) {
    LOG_SOCKET_DEBUG("Sending " << data.size() << " bytes to " << host << ":" << port);

    sockaddr_storage dest_addr;
    socklen_t addr_len;
    if (!build_udp_dest_addr(host, port, af, dest_addr, addr_len)) {
        return -1;
    }

    int bytes_sent = sendto(socket, (char*)data.data(), data.size(), 0,
                            reinterpret_cast<sockaddr*>(&dest_addr), addr_len);
    if (bytes_sent == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to send UDP data to " << host << ":" << port
                         << " (error: " << socket_error_string(get_last_socket_error()) << ")");
        return -1;
    }

    LOG_SOCKET_DEBUG("Successfully sent " << bytes_sent << " bytes to " << host << ":" << port);
    return bytes_sent;
}

// Build a UDP destination sockaddr straight from a numeric Address — no hostname
// resolution and no inet_pton, just a memcpy of the raw address bytes. On a
// DualStack/IPv6 socket an IPv4 address is written as an IPv4-mapped IPv6 address.
static bool build_udp_dest_addr(const IpAddress& ip, int port, AddressFamily af,
                                sockaddr_storage& addr, socklen_t& addr_len) {
    memset(&addr, 0, sizeof(addr));
    if (ip.is_v6()) {
        auto* a6 = reinterpret_cast<sockaddr_in6*>(&addr);
        a6->sin6_family = AF_INET6;
        a6->sin6_port   = htons(static_cast<uint16_t>(port));
        memcpy(&a6->sin6_addr, ip.bytes().data(), 16);
        addr_len = sizeof(sockaddr_in6);
        return true;
    }
    if (ip.is_v4()) {
        if (af == AddressFamily::IPv4) {
            auto* a4 = reinterpret_cast<sockaddr_in*>(&addr);
            a4->sin_family = AF_INET;
            a4->sin_port   = htons(static_cast<uint16_t>(port));
            memcpy(&a4->sin_addr, ip.bytes().data(), 4);
            addr_len = sizeof(sockaddr_in);
        } else {
            auto* a6 = reinterpret_cast<sockaddr_in6*>(&addr);
            a6->sin6_family = AF_INET6;
            a6->sin6_port   = htons(static_cast<uint16_t>(port));
            a6->sin6_addr.s6_addr[10] = 0xff;
            a6->sin6_addr.s6_addr[11] = 0xff;
            memcpy(&a6->sin6_addr.s6_addr[12], ip.bytes().data(), 4);
            addr_len = sizeof(sockaddr_in6);
        }
        return true;
    }
    return false;  // unspecified — nothing to send to
}

int send_udp_data(socket_t socket, const std::vector<uint8_t>& data,
                  const Address& dest, AddressFamily af) {
    sockaddr_storage dest_addr;
    socklen_t addr_len;
    if (!build_udp_dest_addr(dest.ip, dest.port, af, dest_addr, addr_len)) return -1;

    int bytes_sent = sendto(socket, (char*)data.data(), data.size(), 0,
                            reinterpret_cast<sockaddr*>(&dest_addr), addr_len);
    if (bytes_sent == SOCKET_ERROR_VALUE) {
        LOG_SOCKET_ERROR("Failed to send UDP data to " << dest.to_string()
                         << " (error: " << socket_error_string(get_last_socket_error()) << ")");
        return -1;
    }
    return bytes_sent;
}

std::vector<uint8_t> receive_udp_data(socket_t socket, size_t buffer_size, Address& sender_peer,
                                      int timeout_ms, socket_t interrupt_fd) {
    // Handle timeout (and optional interrupt socket) using select. When no interrupt
    // fd is supplied this path is identical to the plain timeout behavior.
    const bool have_interrupt = is_valid_socket(interrupt_fd);
    if (timeout_ms >= 0 || have_interrupt) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socket, &read_fds);
        socket_t maxfd = socket;
        if (have_interrupt) {
            FD_SET(interrupt_fd, &read_fds);
            if (interrupt_fd > maxfd) maxfd = interrupt_fd;
        }

        struct timeval timeout;
        struct timeval* ptimeout = nullptr; // timeout_ms < 0 => block until readable
        if (timeout_ms >= 0) {
            timeout.tv_sec = timeout_ms / 1000;
            timeout.tv_usec = (timeout_ms % 1000) * 1000;
            ptimeout = &timeout;
        }

        int result = select(static_cast<int>(maxfd) + 1, &read_fds, nullptr, nullptr, ptimeout);
        if (result == 0) {
            // Timeout with no data — normal control flow for a polling/idle loop, so it's
            // deliberately not logged (it would spam every idle cycle, e.g. the DHT runner).
            return {};
        } else if (result < 0) {
            LOG_SOCKET_ERROR("Select error while waiting for UDP data");
            return {};
        }
        // Prefer real data: if a datagram arrived alongside a wakeup, read it now rather
        // than deferring it a loop iteration. The wakeup byte stays buffered and is drained
        // by the caller right after, so no wakeup is lost by checking data first.
        if (!FD_ISSET(socket, &read_fds)) {
            // No data — must have been the interrupt socket (e.g. stop/posted work).
            // Report no data so the caller can re-check its stop flag / run posted tasks.
            return {};
        }
    }

    std::vector<uint8_t> buffer(buffer_size);
    sockaddr_storage sender_addr;
    socklen_t sender_addr_len = sizeof(sender_addr);

    int bytes_received = recvfrom(socket, (char*)buffer.data(), buffer_size, 0,
                                 reinterpret_cast<sockaddr*>(&sender_addr), &sender_addr_len);

    if (bytes_received == SOCKET_ERROR_VALUE) {
        int error = get_last_socket_error();
#ifdef _WIN32
        if (error == WSAEWOULDBLOCK) { return {}; }
#else
        if (error == EAGAIN || error == EWOULDBLOCK) { return {}; }
#endif
        LOG_SOCKET_DEBUG("Failed to receive UDP data: " << socket_error_string(error));
        return {};
    }

    if (bytes_received == 0) {
        LOG_SOCKET_DEBUG("Received empty UDP packet");
        return {};
    }

    extract_sender_peer(sender_addr, sender_peer);

    LOG_SOCKET_DEBUG("Received " << bytes_received << " bytes from " << sender_peer.to_string());

    buffer.resize(bytes_received);
    return buffer;
}

// ── Common Socket Functions ─────────────────────────────────────────────────

void close_socket(socket_t socket, bool force) {
    if (is_valid_socket(socket)) {
        LOG_SOCKET_DEBUG("Closing socket " << socket);

        if (force) {
            struct linger lin;
            lin.l_onoff = 1;
            lin.l_linger = 0;
            setsockopt(socket, SOL_SOCKET, SO_LINGER,
                       (const char*)&lin, sizeof(lin));

            LOG_SOCKET_DEBUG("Performing shutdown for TCP socket " << socket);
#ifdef _WIN32
            shutdown(socket, SD_BOTH);
#else
            shutdown(socket, SHUT_RDWR);
#endif
        }

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

bool set_socket_blocking(socket_t socket) {
#ifdef _WIN32
    unsigned long mode = 0;
    if (ioctlsocket(socket, FIONBIO, &mode) != 0) {
        LOG_SOCKET_ERROR("Failed to set socket to blocking mode");
        return false;
    }
#else
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) {
        LOG_SOCKET_ERROR("Failed to get socket flags");
        return false;
    }

    if (fcntl(socket, F_SETFL, flags & ~O_NONBLOCK) == -1) {
        LOG_SOCKET_ERROR("Failed to set socket to blocking mode");
        return false;
    }
#endif

    LOG_SOCKET_DEBUG("Socket set to blocking mode");
    return true;
}

int get_bound_port(socket_t socket) {
    sockaddr_storage bound_addr;
    socklen_t addr_len = sizeof(bound_addr);
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&bound_addr), &addr_len) != 0) {
        return 0;
    }

    if (bound_addr.ss_family == AF_INET) {
        return ntohs(reinterpret_cast<sockaddr_in*>(&bound_addr)->sin_port);
    } else if (bound_addr.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<sockaddr_in6*>(&bound_addr)->sin6_port);
    }

    return 0;
}

} // namespace librats
