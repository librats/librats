#pragma once

/**
 * @file connection.h
 * @brief A single peer connection: byte-stream link, secure handshake, framing.
 *
 * A Connection is owned by exactly one Reactor and is only ever touched by that
 * reactor's thread. Because of that single-threaded ownership it holds NO locks
 * and uses NO atomics — all synchronisation lives at the reactor boundary (the
 * task queue). This is the heart of the shared-nothing model.
 *
 * It is also transport-agnostic: everything here needs is an ordered, reliable,
 * non-blocking byte stream, which is exactly what a Link is (see link.h). A
 * connection over a kernel TCP socket and one over the library's reliable-UDP
 * stream run the *same* code — same framing, same handshake, same backpressure —
 * and differ only in which Link they hold.
 *
 * Lifecycle: Connecting → Handshaking → Established → Closing/Closed.
 *   - Connecting:  outbound transport connect in flight (inbound skips this).
 *   - Handshaking: a Handshaker (from the reactor's SecurityProvider) runs to
 *                  completion, yielding a Session and the remote PeerId.
 *   - Established: inbound blocks are decrypted into inner frames and delivered;
 *                  outbound frames are encrypted and queued.
 *
 * The Connection reports events through a ConnectionDelegate and asks its Link
 * to (dis)arm write-interest; it never touches the poller directly.
 */

#include "librats/util/rats_export.h"
#include "librats/core/types.h"
#include "librats/core/bytes.h"
#include "librats/wire/frame.h"
#include "librats/peer/peer_id.h"
#include "librats/security/handshaker.h"
#include "librats/core/receive_buffer.h"
#include "librats/core/chained_send_buffer.h"
#include "librats/core/socket.h"
#include "librats/transport/link.h"

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
class RATS_API ConnectionDelegate {
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

    /// The send queue crossed its low-water mark: `writable` is false when it
    /// filled past the mark (send() will now answer "no room") and true when it
    /// has drained back under, so a sender that was told to stop may start again.
    /// Runs on the reactor thread — from inside send() for the first, from inside
    /// the flush that emptied the queue for the second — so a handler must not
    /// block. Default: ignore.
    virtual void on_writable_changed(Connection& /*conn*/, bool /*writable*/) {}

    /// An outbound dial died before there was ever a Connection to report it on —
    /// an unresolvable host, no route, no socket. Without this a dial policy that
    /// reserved the ConnId (see Reactor::connect) would wait out a timeout for an
    /// attempt that never began. Runs on the reactor thread. Default: ignore.
    virtual void on_dial_aborted(uint8_t /*reactor_index*/, ConnId /*id*/,
                                 const std::string& /*host*/, uint16_t /*port*/) {}
};

class Connection {
public:
    /// High-water mark for the memory held by the send queue; exceeding it closes the
    /// connection with CloseReason::SlowConsumer.
    static constexpr size_t kDefaultSendHighWater = 8 * 1024 * 1024;

    /// Where send() starts answering "no room". A quarter of the hard limit, so a
    /// caller that heeds the answer never comes near the point where the
    /// connection is dropped, and one that ignores it is no worse off than before
    /// this mark existed. This is the whole difference between a transport that
    /// can be used correctly and one that merely disconnects you.
    static constexpr size_t kDefaultSendLowWater = kDefaultSendHighWater / 4;

    /// Queued bytes past which send() stops holding the batch back and writes
    /// immediately. Aggregating below this is what turns a burst of small frames
    /// into one system call; above it there is already enough to fill a write, so
    /// waiting would only cost memory and delay.
    static constexpr size_t kCoalesceLimit = 64 * 1024;

    Connection(ConnId id, std::unique_ptr<Link> link, ConnRole role,
               Reactor& reactor, ConnectionDelegate& delegate);
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // — identity / state (reactor thread) —
    ConnId        id() const noexcept        { return id_; }
    uint8_t       reactor_index() const noexcept;  ///< index of the owning reactor
    Link&         link() const noexcept      { return *link_; }
    /// The kernel socket behind this connection, or RATS_INVALID_SOCKET when the
    /// transport has none of its own (UDP streams share the mux's socket).
    socket_t      socket() const noexcept    { return link_->fd(); }
    TransportKind transport() const noexcept { return link_->kind(); }
    ConnRole      role() const noexcept      { return role_; }
    ConnState     state() const noexcept     { return state_; }
    CloseReason   close_reason() const noexcept { return close_reason_; }
    const PeerId& remote_id() const noexcept { return remote_id_; }
    bool          is_secure() const noexcept { return session_ && session_->is_secure(); }

    /// Queue an application frame for the peer. No-op unless Established.
    ///
    /// @return whether there is still room for more. False means the queue is
    ///         past its low-water mark — this frame is queued like any other,
    ///         nothing is dropped, but the caller should stop and wait for
    ///         ConnectionDelegate::on_writable rather than keep piling on until
    ///         the connection is dropped as a slow consumer.
    bool send(FrameHeader header, ByteView payload);

    /// Whether the send queue currently has room (see send()).
    bool writable() const noexcept { return !over_low_water_; }

    /// Resize the send queue's marks. `high` is where the connection is dropped
    /// as a slow consumer; the low-water mark send() reports against is derived
    /// from it, so the two can never be set inconsistently. Called once, right
    /// after the handshake, when the node's config asks for something other than
    /// the default.
    void set_send_high_water(size_t high) noexcept {
        send_high_water_ = high;
        send_low_water_  = high / 4;
    }

    /// Write out what send() queued during this reactor turn. Called by the
    /// Reactor at the end of the turn; false ⇒ the connection must be torn down.
    bool flush_pending();

    /// Convenience: send raw bytes on an application channel.
    bool send(uint16_t channel, ByteView payload) {
        return send(FrameHeader{MessageType::App, 0, channel}, payload);
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

    /// Periodic housekeeping, driven by the Reactor's maintenance timer. Hands back
    /// the receive buffer of a peer that has gone quiet — a peer that sent one big
    /// frame and then fell silent would otherwise sit on that allocation for the life
    /// of the connection. Reactor thread; never closes the connection.
    void on_maintenance_tick() { rx_.decay(); }

    /// Record the address this outbound connection was dialed at (so the peer's
    /// reconnect address is known). Set by the Reactor after adopt(); reactor thread.
    void set_dial_address(std::string host, uint16_t port) {
        dial_host_ = std::move(host);
        dial_port_ = port;
    }
    bool               has_dial_address() const noexcept { return dial_port_ != 0; }
    const std::string& dial_host() const noexcept { return dial_host_; }
    uint16_t           dial_port() const noexcept { return dial_port_; }

    /// The peer's IP as the link sees it, without the source port (ephemeral on
    /// TCP, NAT-rewritten on UDP). Combined with the peer's advertised listen port
    /// by the node's identify exchange to form a dialable address — the only way
    /// to learn the dialable address of an *inbound* peer. Unspecified on error.
    IpAddress          remote_ip() const;

    /// The peer's source endpoint as the link sees it, port included.
    ///
    /// The port is meaningless on TCP (an ephemeral one the peer's OS picked for an
    /// outbound socket) but is NOT on a datagram link: there every peer shares one
    /// socket, so what a NAT rewrote the source port to is exactly the port a third
    /// party would have to aim at to reach this peer. That is what identify carries
    /// on to it, and what a hole punch is aimed at. nullopt if the link cannot say.
    std::optional<Address> remote_endpoint() const { return link_->remote_endpoint(); }

    /// Tell the link the connection is going away, so a transport that owes the
    /// peer a goodbye (or a last flush) can arrange it. Called by the Reactor
    /// during teardown, before the Connection is destroyed.
    void shutdown_link(CloseReason reason) { link_->close(reason); }

private:
    void begin_handshake();             ///< transport up → Handshaking
    size_t read_size() const;           ///< bytes to offer the next recv() (see rx_need_)
    bool process_blocks();              ///< decode every complete block in rx_; false ⇒ teardown
    bool drive_handshake(ByteView body);///< feed one handshake block; false ⇒ teardown
    bool deliver_frame(ByteView body);  ///< decrypt+parse+dispatch; false ⇒ teardown
    void complete_established();         ///< handshake done → Established
    void queue_block(Bytes body);       ///< length-prefix `body` into the send buffer
    bool flush();                       ///< drain tx_ to the socket; false ⇒ teardown
    void arm_write();
    void disarm_write();
    bool fail(CloseReason);             ///< record reason, return false (teardown)

    ConnId                id_;
    std::unique_ptr<Link> link_;
    ConnRole              role_;
    ConnState           state_ = ConnState::Connecting;
    CloseReason         close_reason_ = CloseReason::PeerClosed;
    Reactor&            reactor_;
    ConnectionDelegate& delegate_;

    std::unique_ptr<Handshaker> handshaker_;  ///< non-null only while Handshaking
    std::unique_ptr<Session>    session_;      ///< non-null once Established
    PeerId                      remote_id_;

    ReceiveBuffer     rx_;  ///< allocates on first read, shrinks back when idle
    /// Wire size of the block rx_ is mid-way through, once its length prefix has been
    /// read; 0 when no block is in flight. Lets the next recv() size rx_ for the whole
    /// block in one go instead of growing into it. Peer-declared, hence capped.
    size_t            rx_need_ = 0;
    ChainedSendBuffer tx_;
    bool              want_write_ = false;
    /// A flush is already booked for the end of this reactor turn, so further
    /// frames only need to join the queue rather than book another one.
    bool              flush_queued_ = false;
    /// The queue went past its low-water mark and the caller has been told to
    /// stop; cleared, with a notification, once it drains back under.
    bool              over_low_water_ = false;
    /// Inside the on_writable callback — see flush().
    bool              in_writable_ = false;
    size_t            send_high_water_ = kDefaultSendHighWater;
    size_t            send_low_water_  = kDefaultSendLowWater;
    TimerId           establish_timer_ = kInvalidTimerId;  ///< connect+handshake deadline
    std::string       dial_host_;                          ///< address we dialed (outbound)
    uint16_t          dial_port_ = 0;
};

} // namespace librats
