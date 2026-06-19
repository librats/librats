#pragma once

/**
 * @file notifier.h
 * @brief Reliable cross-platform wakeup for a poller-driven reactor.
 *
 * A reactor blocks in IOPoller::wait(); to make it run a freshly-posted task
 * promptly we need to interrupt that wait from another thread. Notifier is a
 * self-pipe built from a *connected TCP loopback pair*:
 *
 *   reader_  ── registered in the poller for PollIn, drained on wake
 *   writer_  ── signal() writes one byte, making reader_ readable
 *
 * A connected TCP socket is the happy path for every backend — epoll, kqueue,
 * and crucially IOCP (where a bare UDP socket does not give reliable readiness).
 * If construction fails the notifier degrades to a no-op: fd() is invalid and
 * signal() does nothing, so the reactor simply falls back to its poll timeout.
 */

#include "socket.h"

#include <cstdint>

namespace librats {

class Notifier {
public:
    Notifier() {
        socket_t listener = create_tcp_server(0, 1, "127.0.0.1", AddressFamily::IPv4);
        if (!is_valid_socket(listener)) return;

        const int port = get_bound_port(listener);
        writer_ = create_tcp_client("127.0.0.1", port, /*timeout_ms=*/2000);
        if (is_valid_socket(writer_)) {
            reader_ = accept_client(listener);  // accept our own loopback connect
        }
        close_socket(listener);

        if (is_valid_socket(reader_)) set_socket_nonblocking(reader_);
        if (is_valid_socket(writer_)) set_socket_nonblocking(writer_);
    }

    ~Notifier() {
        if (is_valid_socket(reader_)) close_socket(reader_);
        if (is_valid_socket(writer_)) close_socket(writer_);
    }

    Notifier(const Notifier&) = delete;
    Notifier& operator=(const Notifier&) = delete;

    /// The pollable end; register this for PollIn. INVALID if construction failed.
    socket_t fd() const noexcept { return reader_; }

    /// Wake the reactor. Coalescing-friendly: many signals drain as one. Any thread.
    void signal() {
        if (!is_valid_socket(writer_)) return;
        const uint8_t byte = 1;
        ::send(writer_, reinterpret_cast<const char*>(&byte), 1, 0);
    }

    /// Discard pending wake bytes. Called by the reactor when reader_ is readable.
    void drain() {
        uint8_t scratch[64];
        while (::recv(reader_, reinterpret_cast<char*>(scratch), sizeof(scratch), 0) > 0) {
            // discard
        }
    }

private:
    socket_t reader_ = INVALID_SOCKET_VALUE;
    socket_t writer_ = INVALID_SOCKET_VALUE;
};

} // namespace librats
