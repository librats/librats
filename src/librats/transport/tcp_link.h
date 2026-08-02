#pragma once

/**
 * @file tcp_link.h
 * @brief Link over a kernel TCP socket — the thin, obvious implementation.
 *
 * All of the reliability, ordering and congestion control a Link promises is the
 * kernel's job here, so this is a direct translation of recv/sendmsg semantics
 * into the Link vocabulary. The socket is owned by the Reactor (which registers
 * it with the poller and closes it on teardown), not by the link.
 */

#include "librats/transport/link.h"

namespace librats {

class Reactor;

class TcpLink final : public Link {
public:
    TcpLink(socket_t sock, Reactor& reactor) : socket_(sock), reactor_(reactor) {}

    TransportKind kind() const noexcept override { return TransportKind::Tcp; }

    IoResult read(ByteSpan into) override;
    IoResult write(const ByteView* slices, size_t count) override;
    bool     connect_completed() override;
    void     want_write(bool on) override;

    std::optional<Address> remote_endpoint() const override;

    socket_t fd() const noexcept override { return socket_; }

    /// TCP needs no goodbye of its own: the Reactor closes the socket right after,
    /// which sends the FIN. (A CloseReason has no place on the wire here.)
    void close(CloseReason) override {}

private:
    socket_t socket_;
    Reactor& reactor_;
};

} // namespace librats
