#pragma once

#include "librats/core/address.h"
#include "librats/core/bytes.h"

#include <string>
#include <functional>
#include <optional>
#include <vector>
#include <cstddef>
#include <cstdint>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #ifdef _MSC_VER
        #pragma comment(lib, "ws2_32.lib")
    #endif
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <unistd.h>
#endif

namespace librats {

/*
 * socket_t and the sentinel values live in the namespace, and the macros carry
 * the RATS_ prefix, because this header is installed: a bare `socket_t` typedef
 * or a bare `closesocket` macro at global scope collides with any other library
 * that installs the same portability shim (and a function-like macro named
 * `closesocket` would silently rewrite the consumer's own calls). Use
 * close_socket() below rather than reintroducing that macro.
 */
#ifdef _WIN32
    typedef SOCKET socket_t;
    #define RATS_INVALID_SOCKET INVALID_SOCKET
    #define RATS_SOCKET_ERROR SOCKET_ERROR
#else
    typedef int socket_t;
    #define RATS_INVALID_SOCKET -1
    #define RATS_SOCKET_ERROR -1
#endif

/**
 * Address family for socket creation
 */
enum class AddressFamily {
    IPv4,       // IPv4 only
    IPv6,       // IPv6 only
    DualStack   // IPv6 socket with IPv4 support (default)
};

/**
 * Whether a UDP bind is allowed to land on a port another socket already holds.
 *
 * On a datagram socket SO_REUSEADDR does not mean what it means for TCP. There is
 * no TIME_WAIT to wait out, so what the option actually buys is the right to bind
 * a port somebody else is already serving — and then the kernel hands each arriving
 * datagram to one of the two, by a rule neither of them can see. Both sockets read
 * a fraction of a stream neither of them is meant to share, and nothing reports an
 * error at any point.
 *
 * `Shared` is the historical default and is right for a port only one subsystem
 * ever wants. `Exclusive` is for a port that is *also* plausibly somebody else's —
 * the BitTorrent uTP mux, which by protocol wants the same number the DHT is
 * already serving. There the bind must fail loudly so the caller can move.
 */
enum class UdpPortMode {
    Shared,     ///< May bind over an existing holder (SO_REUSEADDR).
    Exclusive   ///< Bind fails if the port is taken, and refuses later sharers.
};

/**
 * Whether a socket bound with `af` can send to an address of the given family
 * at all.
 *
 * A socket cannot leave its own family: sendto() with a sockaddr of the wrong
 * one is refused outright. On a datagram socket that refusal arrives per packet
 * and says nothing about the destination, so a caller that does not ask this
 * first cannot tell "unreachable" from "not answering yet" — it only finds out
 * once the retransmissions run out.
 *
 * This is the exact inverse of the sockaddr build_udp_dest_addr() produces, and
 * lives next to the family it switches on so the two cannot drift apart.
 */
constexpr bool family_can_reach(AddressFamily af, bool dest_is_v6) noexcept {
    switch (af) {
        case AddressFamily::IPv4:      return !dest_is_v6;
        case AddressFamily::IPv6:      return dest_is_v6;   // V6ONLY: no mapped IPv4
        case AddressFamily::DualStack: return true;         // IPv4 goes out as ::ffff:a.b.c.d
    }
    return false;
}

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
 * @return Socket handle, or RATS_INVALID_SOCKET on error
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
 *         RATS_INVALID_SOCKET if the socket could not be created/resolved.
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
 * @return Socket handle, or RATS_INVALID_SOCKET on error
 */
socket_t create_tcp_server(int port, int backlog = 5, const std::string& bind_address = "",
                           AddressFamily af = AddressFamily::DualStack);

/**
 * Accept a client connection on a server socket
 * @param server_socket The server socket handle
 * @return Client socket handle, or RATS_INVALID_SOCKET on error
 */
socket_t accept_client(socket_t server_socket);

/**
 * Keep a peer that hung up from killing the process with SIGPIPE.
 *
 * Writing to a socket whose peer has closed raises SIGPIPE, whose default
 * disposition terminates the process. Linux suppresses it per-send with
 * MSG_NOSIGNAL; macOS/BSD have no such flag and suppress it per-socket instead, so
 * every TCP socket we may send on has to carry SO_NOSIGPIPE. Windows has no SIGPIPE
 * at all, and there this is a no-op.
 *
 * The socket helpers here (create_tcp_client / tcp_connect_start / accept_client)
 * already do this. Call it yourself only when you take a socket straight from
 * ::accept() — the option is *not* inherited from the listening socket.
 */
void suppress_sigpipe(socket_t socket);

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

/// Most slices send_vectored() will pass to the kernel in one call. Callers size
/// their slice arrays with this; anything beyond it simply goes out next round.
///
/// Sized so the syscall runs out of *bytes* before it runs out of slices. A queued
/// message costs two slices (its length prefix + its body), so 64 slices would cap a
/// single send at 32 messages — with small frames that is ~45 KiB, well under what a
/// socket will take, and a backlog would need more syscalls than a plain contiguous
/// buffer. 256 slices (4 KiB of ByteView on the stack) keeps the kernel, not this
/// array, the limiting factor. send_vectored() additionally clamps to IOV_MAX.
constexpr size_t kMaxSendSlices = 256;

/**
 * Scatter/gather send: hand several non-contiguous slices to the kernel in a
 * single syscall (sendmsg on POSIX, WSASend on Windows). A backlog of framed
 * messages then costs one syscall instead of one per message — the reason
 * ChainedSendBuffer::gather() exists.
 *
 * Non-blocking sockets may accept only part of the data, exactly as send() does.
 *
 * @param socket The socket handle
 * @param slices Contiguous runs to send, in order (slices beyond kMaxSendSlices
 *               are ignored — the caller sends them on the next round)
 * @param count  Number of slices
 * @return Bytes accepted (possibly a partial write), or -1 on error, in which case
 *         errno / WSAGetLastError() holds the reason (EWOULDBLOCK when the socket's
 *         send buffer is full).
 */
std::ptrdiff_t send_vectored(socket_t socket, const ByteView* slices, size_t count);

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
 * @param mode Whether the port may be shared with a socket that already holds it
 * @return UDP socket handle, or RATS_INVALID_SOCKET on error
 */
socket_t create_udp_socket(int port = 0, const std::string& bind_address = "",
                           AddressFamily af = AddressFamily::DualStack,
                           UdpPortMode mode = UdpPortMode::Shared);

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
 * Ask the kernel for larger socket buffers (SO_RCVBUF / SO_SNDBUF).
 *
 * Matters most for a datagram socket carrying many peers at once: the kernel has
 * nowhere to put a datagram that arrives while the receive buffer is full, so it
 * drops it — and a burst that overruns a small default buffer becomes a
 * retransmission storm rather than a queue. Best effort: the OS may clamp the
 * request, which is fine.
 *
 * @param recv_bytes Requested receive buffer; 0 leaves it alone.
 * @param send_bytes Requested send buffer; 0 leaves it alone.
 * @return true if every requested direction was accepted.
 */
bool set_socket_buffer_sizes(socket_t socket, int recv_bytes, int send_bytes);

/**
 * Turn Nagle's algorithm off on a TCP socket (TCP_NODELAY).
 *
 * Nagle holds a small write back until the last one is acknowledged, so that
 * several of them can be coalesced into one segment. That is the kernel doing —
 * late, and with no knowledge of what is coming — the batching a sender is
 * better placed to do itself. With the send queue aggregating whole batches of
 * frames into one write (see Connection::send), the coalescing has already
 * happened by the time the kernel sees the bytes, and all Nagle can still add is
 * the delay.
 *
 * Order matters: switching this on *without* that aggregation is a large step
 * backwards, because then Nagle is the only thing merging small frames at all.
 *
 * @return true if the option was accepted.
 */
bool set_tcp_nodelay(socket_t socket);

/**
 * Set the timeout for receive operations on a socket (SO_RCVTIMEO).
 *
 * @param socket the socket to configure.
 * @param timeout_ms the timeout in milliseconds; 0 disables the timeout.
 * @return true if the option was accepted.
 */
bool set_read_timeout(socket_t socket, int timeout_ms);

/**
 * Set the timeout for send operations on a socket (SO_SNDTIMEO).
 *
 *
 * @param socket the socket to configure.
 * @param timeout_ms the timeout in milliseconds; 0 disables the timeout.
 * @return true if the option was accepted.
 */
bool set_send_timeout(socket_t socket, int timeout_ms);

/**
 * Send one datagram straight from a raw buffer — no std::vector, no resolution.
 *
 * The allocation-free form of send_udp_data(), for engines that emit a packet per
 * call from a reusable scratch buffer (the reliable-UDP transport builds every
 * header + payload into one stack buffer and hands it here).
 *
 * @return Bytes sent, 0 if the send would block (a full socket send buffer — the
 *         datagram is simply dropped, exactly as a congested link would), or -1 on
 *         a real error.
 */
std::ptrdiff_t send_udp_to(socket_t socket, const void* data, size_t len,
                           const Address& dest, AddressFamily af = AddressFamily::DualStack);

/**
 * Receive one datagram into a caller-owned buffer, without blocking.
 *
 * The counterpart of send_udp_to() for a socket driven by an IOPoller: it never
 * waits, so the caller loops until it reports "nothing left".
 *
 * @param from Filled with the sender's endpoint on success.
 * @return Bytes received (0 is a legal empty datagram), -1 when nothing is pending
 *         (would-block) and -2 on a socket error.
 */
constexpr std::ptrdiff_t kUdpRecvWouldBlock = -1;
constexpr std::ptrdiff_t kUdpRecvError      = -2;
std::ptrdiff_t recv_udp_from(socket_t socket, void* buffer, size_t len, Address& from);

// ── Batched datagram I/O ────────────────────────────────────────────────────
//
// A reliability layer built on datagrams moves one packet per call, so a bulk
// transfer at a 1200-byte payload costs tens of thousands of syscalls per
// megabyte — measurably the single largest cost on that path, well above the
// framing, the congestion control and the encryption put together. Linux (and
// the BSDs that copied it) can carry a whole array of datagrams per call;
// everywhere else these fall back to a loop over the single-datagram forms, so
// callers need no #ifdef and no second code path.

/**
 * Datagrams one batched call moves. 32 is enough to make the syscall a rounding
 * error against the work of building the packets, while keeping the per-call
 * scratch (one message header, one iovec and one address per slot) small enough
 * to live on the stack.
 */
constexpr size_t kUdpBatchMax = 32;

// recvmmsg/sendmmsg — one syscall for a whole array of datagrams. Linux has had
// both since 2.6.33 (bionic exposes them from API 21); everything else takes the
// loop fallback below. FreeBSD has them too, but only as of 11, and the version
// guard is not worth the cost of being wrong there.
#if defined(__linux__) && (!defined(__ANDROID__) || __ANDROID_API__ >= 21)
    #define RATS_HAVE_MMSG 1
#endif

/**
 * Whether a batched call really is one syscall here, or a loop wearing the same
 * interface.
 *
 * Both forms are correct everywhere, so this is not needed to *use* them. It
 * matters to a caller deciding whether to stage datagrams for later: staging pays
 * a copy per datagram to save syscalls, and where the loop fallback is in force
 * there are no syscalls to save — so the copy would be pure loss and the caller
 * should hand each datagram over as it is produced instead.
 */
#ifdef RATS_HAVE_MMSG
constexpr bool kUdpBatchIsOneSyscall = true;
#else
constexpr bool kUdpBatchIsOneSyscall = false;
#endif

/**
 * One datagram in a batch. The payload buffer belongs to the caller — a receive
 * loop reuses the same storage every round and a send path stages into it — so a
 * batch of any size costs no allocation.
 */
struct UdpBatchSlot {
    uint8_t* data = nullptr;  ///< caller-owned payload buffer
    size_t   len  = 0;        ///< receive in: capacity, out: bytes filled; send: bytes to send
    Address  endpoint;        ///< receive out: the sender; send in: the destination
};

/**
 * Receive up to `count` datagrams, in one syscall where the platform has one.
 *
 * Each slot must point at a buffer with `len` bytes of room; on return `len` is
 * what actually arrived and `endpoint` is who sent it. A datagram larger than the
 * slot is truncated, exactly as recvfrom() would truncate it.
 *
 * @return Datagrams filled (> 0), kUdpRecvWouldBlock when nothing is pending, or
 *         kUdpRecvError. A result shorter than `count` does NOT prove the queue is
 *         empty — a per-datagram error truncates the batch too — so a caller that
 *         must drain (an edge-triggered poller) loops until kUdpRecvWouldBlock.
 */
std::ptrdiff_t recv_udp_batch(socket_t socket, UdpBatchSlot* slots, size_t count);

/**
 * Send `count` datagrams, in one syscall where the platform has one.
 *
 * @return How many the socket accepted. The caller must treat the whole batch as
 *         spent regardless: a datagram the socket refused (a full send buffer) is
 *         indistinguishable from one the path dropped, and retransmission covers
 *         both — so the count is for diagnostics, not for a retry.
 */
size_t send_udp_batch(socket_t socket, const UdpBatchSlot* slots, size_t count,
                      AddressFamily af = AddressFamily::DualStack);

/**
 * Receive UDP data with optional timeout
 * @param socket The UDP socket handle
 * @param buffer_size Maximum number of bytes to receive
 * @param sender_peer Output parameter for the sender's peer info
 * @param timeout_ms Timeout in milliseconds (-1 for blocking, 0 for non-blocking, >0 for timeout)
 * @param interrupt_fd Optional second socket to watch; when it becomes readable the
 *                     call returns immediately with an empty vector (used to wake a
 *                     blocking receive on shutdown). RATS_INVALID_SOCKET disables it.
 * @param error_out Optional output flag distinguishing the reasons an empty vector can
 *                  mean: set to true only when select()/recvfrom() failed hard (a dead
 *                  socket, e.g. EBADF), false for a timeout, an interrupt or an empty
 *                  datagram. A polling loop needs this to tell "nothing arrived" from
 *                  "this socket will never deliver again" instead of spinning forever.
 *                  Errors that concern a signal or one destination rather than the
 *                  socket (EINTR, ECONNREFUSED / WSAECONNRESET, WSAENETRESET) count as
 *                  "nothing arrived" — same classification as recv_udp_from().
 * @return Received data, empty vector on timeout, error or interrupt
 */
std::vector<uint8_t> receive_udp_data(socket_t socket, size_t buffer_size, Address& sender_peer,
                                      int timeout_ms = -1,
                                      socket_t interrupt_fd = RATS_INVALID_SOCKET,
                                      bool* error_out = nullptr);

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

/**
 * Whether the last socket call in this thread failed because that particular
 * port cannot be had — it is taken (EADDRINUSE / WSAEADDRINUSE), or on Windows
 * it falls in a reserved range (WSAEACCES).
 *
 * Meant for the one caller that has to tell those apart from every other bind
 * failure: they are the only ones worth answering by moving to another port,
 * since the rest — a privileged port, a bind address not on this host, IPv6
 * switched off — fail identically on all 65535 of them. The socket factories
 * above preserve the failing errno across their own cleanup, so this still
 * reports the bind error and not the close() that followed it.
 *
 * @return true if another port would plausibly work
 */
bool last_error_was_port_unavailable();

} // namespace librats
