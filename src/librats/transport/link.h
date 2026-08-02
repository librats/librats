#pragma once

/**
 * @file link.h
 * @brief The byte-stream a Connection runs on, independent of how it is carried.
 *
 * Everything above this line — block framing, the Noise handshake, the Session,
 * backpressure, the establish deadline — only ever needs an ordered, reliable,
 * non-blocking byte stream. A Link is exactly that and nothing more, so the same
 * Connection code drives a kernel TCP socket (TcpLink) and the library's own
 * reliability layer over datagrams (UdpStreamLink → UdpStream). Neither transport
 * is a special case of the other: both are first-class, and a peer connected over
 * either is indistinguishable to every layer above.
 *
 * Ownership and threading follow the rest of the transport layer: a Link belongs
 * to exactly one Connection, which belongs to exactly one Reactor, and is touched
 * only by that reactor's thread. It therefore holds no locks and no atomics.
 *
 * The read/write calls mirror non-blocking socket semantics deliberately, because
 * that is what the reactor loop is built around:
 *   - read()  fills the caller's span and reports WouldBlock once the link has no
 *             more data ready, or Closed when the peer has finished sending.
 *   - write() takes what it can and reports WouldBlock when it can take no more;
 *             the Connection keeps the remainder queued and calls want_write(true)
 *             so it is told when to retry.
 */

#include "librats/core/address.h"
#include "librats/core/bytes.h"
#include "librats/core/socket.h"
#include "librats/core/types.h"

#include <cstddef>
#include <optional>

namespace librats {

class Link {
public:
    virtual ~Link() = default;

    /// Outcome of a read/write attempt. `Closed` is orderly (the peer is done
    /// sending); `Error` means the link is broken and must be torn down.
    enum class Status { Ok, WouldBlock, Closed, Error };

    struct IoResult {
        size_t bytes  = 0;
        Status status = Status::WouldBlock;
    };

    virtual TransportKind kind() const noexcept = 0;

    /// Read up to `into.size()` bytes. A Closed or Error result always carries
    /// zero bytes — data and end-of-stream are never reported together, so the
    /// caller drains first and only then sees the close.
    virtual IoResult read(ByteSpan into) = 0;

    /// Hand `count` contiguous slices to the link in order, writing as many bytes
    /// as it will take (a partial write is normal and expected).
    virtual IoResult write(const ByteView* slices, size_t count) = 0;

    /// Called once the link reports writable while the connection is still
    /// connecting. Returns false if the connect attempt failed.
    virtual bool connect_completed() = 0;

    /// Ask to be woken (via Connection::on_writable) when more can be written.
    /// Called only when the state actually changes, so an implementation may
    /// treat it as an unconditional set.
    virtual void want_write(bool on) = 0;

    /// The peer's endpoint. For TCP the port is the peer's *ephemeral* source
    /// port, so only the IP is meaningful (see identify); for UDP it is the
    /// endpoint datagrams are exchanged with. nullopt if not yet known.
    virtual std::optional<Address> remote_endpoint() const = 0;

    /// The kernel socket backing this link, or RATS_INVALID_SOCKET when the link
    /// has none of its own (a UDP stream shares the mux's socket with every other
    /// stream). The Reactor uses it to decide whether the link is poller-driven.
    virtual socket_t fd() const noexcept { return RATS_INVALID_SOCKET; }

    /// Told the ConnId the Reactor assigned, right after adoption. A link that has
    /// to be reachable from somewhere other than its Connection (a UDP stream, from
    /// the datagram path) needs it; a plain socket does not.
    virtual void attach(ConnId) {}

    /// Why the link broke, consulted when read/write reported Error. Lets a
    /// transport that knows more than "the socket failed" — a dial that was never
    /// answered, a peer that went silent — say so.
    virtual CloseReason error_reason() const { return CloseReason::PeerReset; }

    /// Begin an orderly shutdown. Called by the Reactor as it tears the connection
    /// down; the Link may still linger internally to flush what it owes the peer.
    virtual void close(CloseReason reason) = 0;
};

} // namespace librats
