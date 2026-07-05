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
#include "wire/frame.h"
#include "peer/peer_id.h"
#include "security/handshaker.h"
#include "core/receive_buffer.h"
#include "core/chained_send_buffer.h"
#include "core/socket.h"

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

    /// Admission gate for a freshly accepted inbound socket, asked by the Reactor
    /// before it adopts the connection (i.e. before any handshake cost is paid).
    /// Returning false makes the Reactor close the socket immediately. Runs on the
    /// acceptor reactor thread. Default: always admit.
    virtual bool admit_inbound() { return true; }

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
    uint8_t       reactor_index() const noexcept;  ///< index of the owning reactor
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

    /// Cancel the establishment-timeout timer if still armed; idempotent. Called
    /// both on success (complete_established) and on teardown (Reactor::remove) so
    /// the reaper can never outlive the connection and fire against a reused fd.
    void cancel_establish_timer();

    /// Record the address this outbound connection was dialed at (so the peer's
    /// reconnect address is known). Set by the Reactor after adopt(); reactor thread.
    void set_dial_address(std::string host, uint16_t port) {
        dial_host_ = std::move(host);
        dial_port_ = port;
    }
    bool               has_dial_address() const noexcept { return dial_port_ != 0; }
    const std::string& dial_host() const noexcept { return dial_host_; }
    uint16_t           dial_port() const noexcept { return dial_port_; }

    /// The peer's IP as seen on the socket (getpeername), without the ephemeral
    /// source port. Combined with the peer's advertised listen port by the node's
    /// identify exchange to form a dialable address — the only way to learn the
    /// dialable address of an *inbound* peer. Empty string on error.
    IpAddress          remote_ip() const;

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
    std::string       dial_host_;                          ///< address we dialed (outbound)
    uint16_t          dial_port_ = 0;
};

} // namespace librats
