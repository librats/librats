#pragma once

/**
 * @file transport.h
 * @brief The secure, message-level channel a Connection runs on.
 *
 * A Connection is a peer as the reactor sees it: an id, a lifecycle, a send queue
 * with marks a caller is told about. How its messages actually reach that peer is
 * a Transport's business, and all of it is: the handshake that proves who the peer
 * is, the session keys and their nonces, the framing, and the order queued
 * messages leave in. A Connection hands a Transport whole messages and receives
 * whole messages back; it never sees a byte of the wire.
 *
 * The split is drawn there because that is where transports genuinely differ. One
 * that runs over an ordered byte stream (StreamTransport — a TCP socket, a UDP
 * stream, a relayed circuit) has to frame messages as length-prefixed blocks,
 * number them implicitly and encrypt them in exactly that order. One that owns its
 * own packets can do none of that the same way, and does not need to. Above this
 * line the two are indistinguishable.
 *
 * Threading follows the rest of the transport layer: a Transport belongs to one
 * Connection, which belongs to one Reactor, and is touched only by its thread.
 *
 * Every entry point the reactor drives returns false when the transport is broken
 * and must be torn down; error_reason() then says why. Nothing is ever torn down
 * from inside one, so a Transport is never destroyed under its own call.
 */

#include "librats/core/address.h"
#include "librats/core/bytes.h"
#include "librats/core/socket.h"
#include "librats/core/types.h"
#include "librats/peer/peer_id.h"
#include "librats/wire/frame.h"

#include <cstddef>
#include <optional>

namespace librats {

/// What a Transport reports to the Connection it carries. Called only from inside
/// one of the Transport's own entry points, on the reactor thread.
class TransportSink {
public:
    virtual ~TransportSink() = default;

    /// The path to the peer is up and the handshake has begun.
    virtual void transport_connected() = 0;

    /// The handshake completed: the peer proved it is `remote`. send() works from
    /// here on, including from inside this call.
    virtual void transport_established(const PeerId& remote) = 0;

    /// One inbound message. Its payload is valid only for the duration of the call.
    /// @return false when the connection is closing and nothing more should be
    ///         delivered; the transport then stops where it is.
    virtual bool transport_frame(const Frame& frame) = 0;
};

class Transport {
public:
    virtual ~Transport() = default;

    // ── What it is ──────────────────────────────────────────────────────────

    virtual TransportKind kind() const noexcept = 0;

    /// The kernel socket the reactor polls for this transport, or
    /// RATS_INVALID_SOCKET when there is none of its own (UDP streams share the
    /// mux's socket; a relayed circuit has no socket at all).
    virtual socket_t fd() const noexcept = 0;

    /// The peer's endpoint as the path sees it, port included. The port is the
    /// peer's ephemeral source port on TCP and the NAT's mapping on UDP; see
    /// Connection::remote_endpoint. nullopt if the path cannot say.
    virtual std::optional<Address> remote_endpoint() const = 0;

    /// Whether the established session encrypts (false for plaintext security).
    virtual bool is_secure() const noexcept = 0;

    /// Bind to the connection: its id, and where events go. Called once, before
    /// any other entry point.
    virtual void attach(ConnId id, TransportSink& sink) = 0;

    // ── Driven by the reactor ───────────────────────────────────────────────

    /// The path is already up — an accepted socket, an inbound stream, a circuit
    /// that was connected when it was handed over — so begin the handshake now.
    /// An outbound path instead waits for on_writable() to report its connect.
    virtual bool start() = 0;

    virtual bool on_readable() = 0;
    virtual bool on_writable() = 0;
    /// The poller reported an error on the transport's socket. Always breaks it.
    virtual bool on_error() = 0;

    /// Why the transport broke, once an entry point has returned false.
    virtual CloseReason error_reason() const = 0;

    // ── Messages ────────────────────────────────────────────────────────────

    /// Largest payload send() can carry, once established. A larger message can
    /// never be sent whole, so the connection refuses it rather than queue it.
    virtual size_t max_payload() const noexcept = 0;

    /// Queue one message for the peer: only once established, and no larger than
    /// max_payload(). Never drops what it is given. May write at once when enough is
    /// queued that waiting for the end of the reactor turn would only cost memory —
    /// which is the one way it can fail: false means that write broke the transport.
    virtual bool send(FrameHeader header, ByteView payload) = 0;

    /// Write out what is queued, as far as the path will take it. Called by the
    /// reactor at the end of every turn that queued something.
    virtual bool flush() = 0;

    /// Memory held for messages the path has not taken yet — what the
    /// connection's high- and low-water marks are weighed against.
    virtual size_t backlog() const noexcept = 0;

    // ── Housekeeping ────────────────────────────────────────────────────────

    /// What the path looks like (see PathStats), with this transport's own queue
    /// counted in `queued_bytes`. `loss` is left at 0: it needs an interval, which
    /// is the sampler's.
    virtual PathStats path_stats() const = 0;

    /// Periodic, from the reactor's maintenance sweep: give back memory an idle
    /// peer no longer needs. Never breaks the transport.
    virtual void on_maintenance_tick() = 0;

    /// The connection is going away. A transport that owes the peer a goodbye or a
    /// last flush arranges it here; nothing is called on it afterwards.
    virtual void close(CloseReason reason) = 0;
};

} // namespace librats
