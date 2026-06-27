#pragma once

/**
 * @file wakeup_pipe.h
 * @brief Loopback-UDP self-pipe for interrupting a blocking select()/receive.
 *
 * A worker thread that blocks in receive_udp_data() can only react to a stop
 * request (or newly posted work) after its socket timeout expires. WakeupPipe
 * provides a second socket to add to that select() set: signal() sends a one-byte
 * datagram to it, which wakes the select() immediately so the worker can react
 * without waiting out the timeout.
 *
 * Two usage patterns are supported:
 *   - one-shot (NAT-PMP/UPnP): signal() once on stop(), then tear down. No drain().
 *   - repeated (DHT runner): signal() on every posted task. The worker MUST call
 *     drain() once per wake-up, otherwise the unread byte keeps select() readable
 *     and the loop spins. The socket is non-blocking so drain() never stalls.
 *
 * UDP loopback is used (rather than a pipe) because it is selectable on every
 * platform, including Windows. If socket creation fails the pipe degrades
 * gracefully: fd() returns an invalid socket (treated as "no interrupt"), signal()
 * is a no-op and drain() is a no-op, so callers fall back to timeout-based wakeups.
 */

#include "core/socket.h"

#include <vector>

namespace librats {

class WakeupPipe {
public:
    WakeupPipe() {
        sock_ = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
        if (is_valid_socket(sock_)) {
            sockaddr_in addr;
            socklen_t len = sizeof(addr);
            if (getsockname(sock_, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
                port_ = ntohs(addr.sin_port);
            }
            set_socket_nonblocking(sock_);  // so drain() reads until empty without blocking
        }
    }

    ~WakeupPipe() {
        if (is_valid_socket(sock_)) close_socket(sock_);
    }

    WakeupPipe(const WakeupPipe&) = delete;
    WakeupPipe& operator=(const WakeupPipe&) = delete;

    /// Socket to add to a select() set (pass as receive_udp_data's interrupt_fd).
    socket_t fd() const { return sock_; }

    /// Wake any select() watching fd(). Safe to call from any thread (a one-byte UDP
    /// send), and as often as needed — drain() consumes the accumulated bytes.
    void signal() {
        if (is_valid_socket(sock_) && port_ != 0) {
            send_udp_data(sock_, std::vector<uint8_t>{1}, "127.0.0.1", port_, AddressFamily::IPv4);
        }
    }

    /// Discard all pending wakeup bytes so the next select() blocks again. Call once
    /// after each wake-up, from the waiting thread only. No-op if the pipe is degraded.
    void drain() {
        if (!is_valid_socket(sock_)) return;
        uint8_t buf[64];
        sockaddr_in from;
        socklen_t len;
        for (;;) {
            len = sizeof(from);
            const int n = recvfrom(sock_, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                                   reinterpret_cast<sockaddr*>(&from), &len);
            if (n <= 0) break;  // EWOULDBLOCK / drained (socket is non-blocking)
        }
    }

private:
    socket_t sock_ = INVALID_SOCKET_VALUE;
    uint16_t port_ = 0;
};

} // namespace librats
