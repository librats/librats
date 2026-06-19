#pragma once

/**
 * @file connection.h
 * @brief A single peer connection: socket + framing + lifecycle state machine.
 *
 * A Connection is owned by exactly one Reactor and is only ever touched by that
 * reactor's thread. Because of that single-threaded ownership it holds NO locks
 * and uses NO atomics — all the synchronisation lives at the reactor boundary
 * (the task queue). This is the heart of the shared-nothing model.
 *
 * Responsibilities:
 *   - drain the socket on readable, extract complete frames, deliver them;
 *   - queue outbound frames and flush them on writable;
 *   - finish a non-blocking connect (outbound) before going Established;
 *   - enforce a send high-water mark (slow-consumer protection).
 *
 * The Connection reports lifecycle/data events through a ConnectionDelegate and
 * asks the Reactor to (dis)arm write-interest; it never reaches into the poller
 * directly.
 */

#include "core/types.h"
#include "core/bytes.h"
#include "net/frame.h"
#include "receive_buffer.h"
#include "chained_send_buffer.h"
#include "socket.h"

namespace librats {

class Connection;
class Reactor;

/**
 * @brief Sink for connection lifecycle and inbound frames.
 *
 * All callbacks run on the owning reactor's thread. `on_closed` is the last
 * call for a connection; the Connection reference is valid for the duration of
 * the callback only. Note: on_established/on_frame are invoked by the
 * Connection; on_closed is invoked by the Reactor as it tears the connection
 * down (so a delegate may safely request other connections close from within).
 */
class ConnectionDelegate {
public:
    virtual ~ConnectionDelegate() = default;
    virtual void on_established(Connection& conn) = 0;
    virtual void on_frame(Connection& conn, const Frame& frame) = 0;
    virtual void on_closed(Connection& conn, CloseReason reason) = 0;
};

class Connection {
public:
    /// High-water mark for the send buffer; exceeding it closes the connection
    /// with CloseReason::SlowConsumer. Tunable per connection.
    static constexpr size_t kDefaultSendHighWater = 8 * 1024 * 1024;

    Connection(ConnId id, socket_t sock, ConnRole role,
               Reactor& reactor, ConnectionDelegate& delegate);
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // — identity / state (reactor thread) —
    ConnId    id() const noexcept     { return id_; }
    socket_t  socket() const noexcept { return socket_; }
    ConnRole  role() const noexcept   { return role_; }
    ConnState state() const noexcept  { return state_; }
    CloseReason close_reason() const noexcept { return close_reason_; }

    /// Queue a frame for delivery to the peer. No-op once closing/closed.
    void send(FrameHeader header, ByteView payload);

    /// Convenience: send raw bytes on an application channel.
    void send(uint16_t channel, ByteView payload) {
        send(FrameHeader{MessageType::App, 0, channel}, payload);
    }

    // — reactor-driven I/O callbacks. Return false to request teardown. —
    bool on_readable();
    bool on_writable();
    bool on_error();

    /// Bring an already-connected (inbound/loopback) socket up to Established
    /// and notify the delegate. Called by the Reactor right after adopt().
    void start_established();

    /// Associate the outbound connect-timeout timer so it can be cancelled once
    /// the connection establishes. Set by the Reactor right after adopt().
    void set_connect_timer(TimerId id) noexcept { connect_timer_ = id; }

private:
    void mark_established();
    bool flush();               ///< drain tx_ to the socket; false ⇒ teardown
    void arm_write();
    void disarm_write();
    bool fail(CloseReason);     ///< record reason, return false (teardown)

    ConnId              id_;
    socket_t            socket_;
    ConnRole            role_;
    ConnState           state_ = ConnState::Connecting;
    CloseReason         close_reason_ = CloseReason::PeerClosed;
    Reactor&            reactor_;
    ConnectionDelegate& delegate_;

    ReceiveBuffer     rx_{512};   ///< grows lazily; small idle footprint
    ChainedSendBuffer tx_;
    bool              want_write_ = false;
    size_t            send_high_water_ = kDefaultSendHighWater;
    TimerId           connect_timer_ = kInvalidTimerId;  ///< outbound connect timeout
};

} // namespace librats
