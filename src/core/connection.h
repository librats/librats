#pragma once

/**
 * @file connection.h
 * @brief A single peer connection: socket, secure-channel handshake, framing.
 *
 * A Connection is owned by exactly one Reactor and is only ever touched by that
 * reactor's thread. Because of that single-threaded ownership it holds NO locks
 * and uses NO atomics — all synchronisation lives at the reactor boundary (the
 * task queue). This is the heart of the shared-nothing model.
 *
 * Lifecycle: Connecting → Handshaking → Established → Closing/Closed.
 *   - Connecting:  outbound TCP connect in flight (inbound skips this).
 *   - Handshaking: a Handshaker (from the reactor's SecurityProvider) runs to
 *                  completion, yielding a Session and the remote PeerId.
 *   - Established: inbound blocks are decrypted into inner frames and delivered;
 *                  outbound frames are encrypted and queued.
 *
 * The Connection reports events through a ConnectionDelegate and asks the
 * Reactor to (dis)arm write-interest; it never touches the poller directly.
 */

#include "core/types.h"
#include "core/bytes.h"
#include "net/frame.h"
#include "net/peer_id.h"
#include "security/handshaker.h"
#include "receive_buffer.h"
#include "chained_send_buffer.h"
#include "socket.h"

#include <memory>

namespace librats {

class Connection;
class Reactor;

/**
 * @brief Sink for connection lifecycle and inbound frames.
 *
 * All callbacks run on the owning reactor's thread. `on_established` fires once
 * the secure handshake completes (so conn.remote_id() is valid). `on_closed` is
 * the last call and is invoked by the Reactor during teardown, so a delegate may
 * safely close other connections from within it.
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
    /// with CloseReason::SlowConsumer.
    static constexpr size_t kDefaultSendHighWater = 8 * 1024 * 1024;

    Connection(ConnId id, socket_t sock, ConnRole role,
               Reactor& reactor, ConnectionDelegate& delegate);
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // — identity / state (reactor thread) —
    ConnId        id() const noexcept        { return id_; }
    socket_t      socket() const noexcept    { return socket_; }
    ConnRole      role() const noexcept      { return role_; }
    ConnState     state() const noexcept     { return state_; }
    CloseReason   close_reason() const noexcept { return close_reason_; }
    const PeerId& remote_id() const noexcept { return remote_id_; }
    bool          is_secure() const noexcept { return session_ && session_->is_secure(); }

    /// Queue an application frame for the peer. No-op unless Established.
    void send(FrameHeader header, ByteView payload);

    /// Convenience: send raw bytes on an application channel.
    void send(uint16_t channel, ByteView payload) {
        send(FrameHeader{MessageType::App, 0, channel}, payload);
    }

    // — reactor-driven I/O callbacks. Return false to request teardown. —
    bool on_readable();
    bool on_writable();
    bool on_error();

    /// Bring an accepted (inbound) socket up: it is already connected, so begin
    /// the handshake immediately. Called by the Reactor right after adopt().
    void start_handshake();

    /// Associate the establishment-timeout timer so it can be cancelled once the
    /// connection reaches Established. Set by the Reactor after adopt().
    void set_establish_timer(TimerId id) noexcept { establish_timer_ = id; }

private:
    void begin_handshake();             ///< transport up → Handshaking
    bool drive_handshake(ByteView body);///< feed one handshake block; false ⇒ teardown
    bool deliver_frame(ByteView body);  ///< decrypt+parse+dispatch; false ⇒ teardown
    void complete_established();         ///< handshake done → Established
    void queue_block(ByteView body);    ///< length-prefix `body` into the send buffer
    bool flush();                       ///< drain tx_ to the socket; false ⇒ teardown
    void arm_write();
    void disarm_write();
    bool fail(CloseReason);             ///< record reason, return false (teardown)

    ConnId              id_;
    socket_t            socket_;
    ConnRole            role_;
    ConnState           state_ = ConnState::Connecting;
    CloseReason         close_reason_ = CloseReason::PeerClosed;
    Reactor&            reactor_;
    ConnectionDelegate& delegate_;

    std::unique_ptr<Handshaker> handshaker_;  ///< non-null only while Handshaking
    std::unique_ptr<Session>    session_;      ///< non-null once Established
    PeerId                      remote_id_;

    ReceiveBuffer     rx_{512};   ///< grows lazily; small idle footprint
    ChainedSendBuffer tx_;
    bool              want_write_ = false;
    size_t            send_high_water_ = kDefaultSendHighWater;
    TimerId           establish_timer_ = kInvalidTimerId;  ///< connect+handshake deadline
};

} // namespace librats
