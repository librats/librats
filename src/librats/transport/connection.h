#pragma once

/**
 * @file connection.h
 * @brief A single peer connection: lifecycle, backpressure, and the Transport under it.
 *
 * A Connection is owned by exactly one Reactor and is only ever touched by that
 * reactor's thread. Because of that single-threaded ownership it holds NO locks
 * and uses NO atomics — all synchronisation lives at the reactor boundary (the
 * task queue). This is the heart of the shared-nothing model.
 *
 * It is a peer as the reactor sees it, and no more: an id, a lifecycle, a send
 * queue whose marks a caller is told about, and the events its delegate hears.
 * Everything about how messages reach the peer — handshake, encryption, framing,
 * the order queued messages leave in — belongs to its Transport (transport.h),
 * which hands it whole messages and takes whole messages from it. A connection
 * over a TCP socket, the datagram transport or a relayed circuit runs this same code.
 *
 * Lifecycle: Connecting → Handshaking → Established → Closing/Closed.
 *   - Connecting:  outbound transport connect in flight (inbound skips this).
 *   - Handshaking: the transport's handshake is running.
 *   - Established: the peer's identity is proven; messages flow both ways.
 *
 * The Connection reports events through a ConnectionDelegate and never touches
 * the poller directly.
 */

#include "librats/util/rats_export.h"
#include "librats/core/types.h"
#include "librats/core/bytes.h"
#include "librats/wire/frame.h"
#include "librats/peer/peer_id.h"
#include "librats/core/socket.h"
#include "librats/transport/transport.h"

#include <atomic>
#include <memory>
#include <string>

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

    /// A periodic sample of an established connection's path, when the Reactor
    /// was asked for them (Reactor::sample_paths). Runs on the reactor thread, so
    /// a handler must not block. Default: ignore.
    virtual void on_path_sample(Connection& /*conn*/, const PathStats& /*stats*/) {}

    /// An outbound dial died before there was ever a Connection to report it on —
    /// an unresolvable host, no route, no socket. Without this a dial policy that
    /// reserved the ConnId (see Reactor::connect) would wait out a timeout for an
    /// attempt that never began. Runs on the reactor thread. Default: ignore.
    virtual void on_dial_aborted(uint8_t /*reactor_index*/, ConnId /*id*/,
                                 const std::string& /*host*/, uint16_t /*port*/) {}
};

class Connection final : private TransportSink {
public:
    /// High-water mark for the memory held by the send queue. A caller that offers
    /// another message while the queue is *still* over it has the connection closed
    /// with CloseReason::SlowConsumer. The mark is never applied to the message that
    /// crosses it: one message may always be queued, whatever its size (see send()),
    /// so the queue's ceiling is this plus one message rather than this exactly.
    static constexpr size_t kDefaultSendHighWater = 8 * 1024 * 1024;

    /// Where send() starts answering "no room". A quarter of the hard limit, so a
    /// caller that heeds the answer never comes near the point where the
    /// connection is dropped, and one that ignores it is no worse off than before
    /// this mark existed. This is the whole difference between a transport that
    /// can be used correctly and one that merely disconnects you.
    static constexpr size_t kDefaultSendLowWater = kDefaultSendHighWater / 4;

    Connection(ConnId id, std::unique_ptr<Transport> transport, ConnRole role,
               Reactor& reactor, ConnectionDelegate& delegate);
    ~Connection() override;

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // — identity / state (reactor thread) —
    ConnId        id() const noexcept        { return id_; }
    uint8_t       reactor_index() const noexcept;  ///< index of the owning reactor
    /// The kernel socket behind this connection, or RATS_INVALID_SOCKET when the
    /// transport has none of its own (UDP connections share the mux's socket).
    socket_t      socket() const noexcept    { return transport_->fd(); }
    TransportKind transport() const noexcept { return transport_->kind(); }
    ConnRole      role() const noexcept      { return role_; }
    ConnState     state() const noexcept     { return state_; }
    CloseReason   close_reason() const noexcept { return close_reason_; }
    const PeerId& remote_id() const noexcept { return remote_id_; }
    bool          is_secure() const noexcept { return transport_->is_secure(); }

    /// Queue an application frame for the peer. No-op unless Established.
    ///
    /// Never drops: whatever it is handed is queued, however large — except a
    /// message too large for the transport to carry at all, which is refused with
    /// nothing queued and the connection untouched. The size of a single message is
    /// not what the high-water mark is about — a message cannot be queued by halves,
    /// so a connection that is draining perfectly well must not be torn down over
    /// one big frame. What closes a connection is offering *another* message while
    /// the queue is still over the mark, which is the actual evidence that the peer
    /// is not keeping up.
    ///
    /// Messages of one MessageType reach the peer in the order they were sent —
    /// all of an application's channels included; different types may overtake
    /// each other, by priority (see send_queue.h).
    ///
    /// @return whether there is still room for more. False means the queue is
    ///         past its low-water mark — this frame is queued like any other,
    ///         nothing is dropped, but the caller should stop and wait for
    ///         ConnectionDelegate::on_writable_changed rather than keep piling on
    ///         until the connection is dropped as a slow consumer.
    bool send(FrameHeader header, ByteView payload);

    /// Convenience: send raw bytes on an application channel.
    bool send(uint16_t channel, ByteView payload) {
        return send(FrameHeader{MessageType::App, 0, channel}, payload);
    }

    /// Whether the send queue currently has room (see send()).
    bool writable() const noexcept { return !over_low_water_; }

    /// Adopt the peer's in-transit counter: bytes a caller has handed to this
    /// reactor that have not reached send() yet (see PeerTable::Entry::owed).
    ///
    /// They are as much of the backlog as the queue itself — held in the reactor's
    /// task queue rather than in the transport, and on their way here — so the marks
    /// below weigh them together with what is queued. Without that the two halves
    /// would answer separately: a caller told "no room" because its charge crossed
    /// the mark would be waiting for an opening from a queue that never crossed
    /// anything, and so would never be told the room came back.
    void set_in_transit(std::shared_ptr<const std::atomic<size_t>> owed) noexcept {
        in_transit_ = std::move(owed);
    }

    /// What this connection is carrying: queued in the transport plus still on its
    /// way to it.
    size_t backlog() const noexcept {
        return transport_->backlog() +
               (in_transit_ ? in_transit_->load(std::memory_order_relaxed) : 0);
    }

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

    // — reactor-driven I/O callbacks. Return false to request teardown. —
    bool on_readable();
    bool on_writable();
    bool on_error();

    /// Bring an accepted (inbound) path up: it is already connected, so begin the
    /// handshake immediately. Called by the Reactor right after adopt().
    void start_handshake();

    /// Associate the establishment-timeout timer so it can be cancelled once the
    /// connection reaches Established. Set by the Reactor after adopt().
    void set_establish_timer(TimerId id) noexcept { establish_timer_ = id; }

    /// Cancel the establishment-timeout timer if still armed; idempotent. Called
    /// both on success and on teardown (Reactor::remove) so the reaper can never
    /// outlive the connection and fire against a reused fd.
    void cancel_establish_timer();

    /// Periodic housekeeping, driven by the Reactor's maintenance timer: lets the
    /// transport hand back buffers a quiet peer no longer needs. Never closes.
    void on_maintenance_tick() { transport_->on_maintenance_tick(); }

    /// What the path to this peer looks like now (see PathStats): the transport's
    /// own figures, with what is still on its way to this connection added to what
    /// a new message waits behind, and the loss share taken over the interval since
    /// the previous call. Reactor thread; called by the Reactor's path sampler, the
    /// one caller, which is what gives "since the previous call" its meaning.
    PathStats sample_path();

    /// Record the address this outbound connection was dialed at (so the peer's
    /// reconnect address is known). Set by the Reactor after adopt(); reactor thread.
    void set_dial_address(std::string host, uint16_t port) {
        dial_host_ = std::move(host);
        dial_port_ = port;
    }
    bool               has_dial_address() const noexcept { return dial_port_ != 0; }
    const std::string& dial_host() const noexcept { return dial_host_; }
    uint16_t           dial_port() const noexcept { return dial_port_; }

    /// The peer's IP as the path sees it, without the source port (ephemeral on
    /// TCP, NAT-rewritten on UDP). Combined with the peer's advertised listen port
    /// by the node's identify exchange to form a dialable address — the only way
    /// to learn the dialable address of an *inbound* peer. Unspecified on error.
    IpAddress          remote_ip() const;

    /// The peer's source endpoint as the path sees it, port included.
    ///
    /// The port is meaningless on TCP (an ephemeral one the peer's OS picked for an
    /// outbound socket) but is NOT on a datagram path: there every peer shares one
    /// socket, so what a NAT rewrote the source port to is exactly the port a third
    /// party would have to aim at to reach this peer. That is what identify carries
    /// on to it, and what a hole punch is aimed at. nullopt if the path cannot say.
    std::optional<Address> remote_endpoint() const { return transport_->remote_endpoint(); }

    /// Tell the transport the connection is going away, so one that owes the peer
    /// a goodbye (or a last flush) can arrange it. Called by the Reactor during
    /// teardown, before the Connection is destroyed.
    void shutdown_link(CloseReason reason) { transport_->close(reason); }

private:
    // — TransportSink —
    void transport_connected() override;
    void transport_established(const PeerId& remote) override;
    bool transport_frame(const Frame& frame) override;

    /// A transport entry point returned `ok`; turn a failure into teardown, and
    /// tell a stopped caller if the call let the queue drain.
    bool settle(bool ok);
    /// The queue has drained back under the low-water mark: say so, once.
    void note_drained();
    bool fail(CloseReason);             ///< record reason, return false (teardown)

    ConnId                     id_;
    std::unique_ptr<Transport> transport_;
    ConnRole                   role_;
    ConnState                  state_ = ConnState::Connecting;
    CloseReason                close_reason_ = CloseReason::PeerClosed;
    Reactor&                   reactor_;
    ConnectionDelegate&        delegate_;
    PeerId                     remote_id_;

    /// A flush is already booked for the end of this reactor turn, so further
    /// frames only need to join the queue rather than book another one.
    bool              flush_queued_ = false;
    /// The queue went past its low-water mark and the caller has been told to
    /// stop; cleared, with a notification, once it drains back under.
    bool              over_low_water_ = false;
    /// Inside the on_writable_changed callback — see note_drained().
    bool              in_writable_ = false;
    /// Charged by send() callers on any thread, discharged by the reactor task
    /// just before the frame reaches send() — see set_in_transit().
    std::shared_ptr<const std::atomic<size_t>> in_transit_;
    size_t            send_high_water_ = kDefaultSendHighWater;
    size_t            send_low_water_  = kDefaultSendLowWater;
    TimerId           establish_timer_ = kInvalidTimerId;  ///< connect+handshake deadline
    std::string       dial_host_;                          ///< address we dialed (outbound)
    uint16_t          dial_port_ = 0;
    /// The transport's delivered/lost totals at the previous sample_path().
    uint64_t          sampled_delivered_ = 0;
    uint64_t          sampled_lost_      = 0;
};

} // namespace librats
