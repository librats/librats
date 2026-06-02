#pragma once

/**
 * @file wakeup_pipe.h
 * @brief Loopback-UDP self-pipe for interrupting a blocking select()/receive.
 *
 * A worker thread that blocks in receive_udp_data() can only react to a stop
 * request after its socket timeout expires. WakeupPipe provides a second socket
 * to add to that select() set: stop() sends a one-byte datagram to it, which
 * wakes the select() immediately so the worker can observe stop_requested_ and
 * exit without waiting out the timeout.
 *
 * UDP loopback is used (rather than a pipe) because it is selectable on every
 * platform, including Windows. If socket creation fails the pipe degrades
 * gracefully: fd() returns an invalid socket (treated as "no interrupt") and
 * signal() is a no-op, so callers simply fall back to timeout-based wakeups.
 */

#include "socket.h"

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
        }
    }

    ~WakeupPipe() {
        if (is_valid_socket(sock_)) close_socket(sock_);
    }

    WakeupPipe(const WakeupPipe&) = delete;
    WakeupPipe& operator=(const WakeupPipe&) = delete;

    /// Socket to add to a select() set (pass as receive_udp_data's interrupt_fd).
    socket_t fd() const { return sock_; }

    /// Wake any select() watching fd(). Idempotent; only meant to be called from stop().
    void signal() {
        if (is_valid_socket(sock_) && port_ != 0) {
            send_udp_data(sock_, std::vector<uint8_t>{1}, "127.0.0.1", port_, AddressFamily::IPv4);
        }
    }

private:
    socket_t sock_ = INVALID_SOCKET_VALUE;
    uint16_t port_ = 0;
};

} // namespace librats
