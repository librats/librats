#pragma once

/**
 * @file relay_link.h
 * @brief A peer connection carried inside another peer's connection.
 *
 * When two nodes cannot reach each other directly — a symmetric NAT on one side,
 * a network that swallows UDP, a hole punch that simply did not land — the one
 * thing left is to route their bytes through a node they can both reach. The
 * question is *where* in the stack to do that, and this file is the answer: at the
 * very bottom, as one more way of obtaining the ordered, reliable byte stream a
 * Connection runs on (see link.h).
 *
 * That choice is what makes a relayed peer indistinguishable from a direct one
 * everywhere above:
 *
 *   - the Noise_XX handshake runs END TO END between the two peers, so the relay
 *     carries ciphertext it cannot read, cannot forge and cannot replay into
 *     anything. It is a pipe, not a party;
 *   - the self-certifying PeerId and the protocol_id bound into the handshake are
 *     checked exactly as usual, so a relay cannot impersonate either end;
 *   - block framing, the send queue and its high-water mark, the establish
 *     deadline, identify, and the peer table's duplicate resolution all apply
 *     unchanged, because there is nothing here for them to know about;
 *   - every subsystem — pub/sub, file transfer, PEX — works over a relayed peer
 *     without a line of its own.
 *
 * Relaying at the message level instead (a third node forwarding application
 * frames) would have meant a second handshake, a second authentication scheme and
 * a second backpressure story — and would have handed the relay the plaintext.
 *
 * ── The two halves ──────────────────────────────────────────────────────────
 * `Circuit` is the state of one relayed connection: the bytes in flight in each
 * direction and the credit windows that bound them. `RelayLink` is the paper-thin
 * adapter that presents that state to a Connection as a Link. They are separate
 * because the Connection owns its Link outright (unique_ptr, destroyed on the
 * reactor thread) while the module driving the relay protocol has to keep hold of
 * the same circuit to feed it — so the state is shared and only the adapter is
 * owned.
 *
 * `CircuitCarrier` is the other direction: what the circuit needs from whoever
 * speaks the relay protocol. It is deliberately tiny and knows nothing about the
 * wire format, which stays entirely in the module that implements it.
 *
 * ── Flow control, and why it is not optional ────────────────────────────────
 * A relay reads from one peer and writes to another, and it cannot stop reading:
 * the reactor drains a readable connection to the end. So without a bound, a slow
 * receiver makes the relay's send queue to it grow until that peer is dropped as a
 * slow consumer — losing all of its traffic, not just the circuit's, and letting
 * any pair of peers spend a stranger's memory at will.
 *
 * The bound is an end-to-end credit window, granted by the receiver and spent by
 * the sender, exactly as in a stream multiplexer. Each end advertises how much it
 * is willing to have in flight; the sender may not exceed it, and the receiver
 * grants more as it consumes. Two things follow:
 *
 *   - the relay can never hold more than about one window per circuit, whatever
 *     either end does, so its memory is bounded by configuration rather than by
 *     the goodwill of its users;
 *   - a slow path makes the circuit slow instead of making it fail. The window
 *     only ever binds when the far end is not keeping up, which is precisely when
 *     something ought to give.
 *
 * Credit is returned as the bytes are read OUT of the circuit, not as they arrive,
 * and in batches (kCreditGrantFraction of the window) so the grant costs one small
 * message per window-worth of data rather than one per chunk.
 *
 * ── Threading ───────────────────────────────────────────────────────────────
 * A Circuit is touched only by the reactor thread that owns its Connection, which
 * is by construction the same thread that owns the carrier's connection (see
 * node/circuit_service.h). It therefore holds no locks and no atomics, like
 * everything else on this path. The module that owns circuits may keep its table
 * of them under a mutex; the state below must not be reached from off that one
 * thread.
 */

#include "librats/util/rats_export.h"
#include "librats/core/bytes.h"
#include "librats/core/types.h"
#include "librats/transport/link.h"

#include <cstdint>
#include <memory>

namespace librats {

/// What a circuit needs from whoever speaks the relay protocol on the wire.
///
/// Implemented by the relay module; called by Circuit on the reactor thread. None
/// of these say anything about the wire format — the implementer frames the
/// message and hands it to the carrier peer — so this header stays a transport
/// header with no protocol in it.
class CircuitCarrier {
public:
    virtual ~CircuitCarrier() = default;

    /// Send `count` slices (together no larger than kMaxDataChunk) toward the far
    /// end as one data message.
    /// @return whether the carrier's own send queue still has room. False does NOT
    ///         mean the data was dropped — it was queued like any other message —
    ///         it means stop, and say so again through on_carrier_writable() once
    ///         the queue drains. Exactly what PeerNetwork::send answers, which is
    ///         what an implementation normally forwards.
    virtual bool circuit_send_data(uint32_t circuit, const ByteView* slices, size_t count) = 0;

    /// Grant the far end `bytes` more of our receive window.
    virtual void circuit_send_credit(uint32_t circuit, uint32_t bytes) = 0;

    /// Tell the far end (and the relay in between) that this circuit is over.
    /// Called at most once per circuit.
    virtual void circuit_send_close(uint32_t circuit, CloseReason reason) = 0;

    /// The Link is gone: its Connection has been destroyed. The circuit will not
    /// be read or written again and its bookkeeping can be dropped.
    ///
    /// The only one of these that is NOT guaranteed to arrive on the reactor
    /// thread. It normally does — a Connection is destroyed by its reactor — but a
    /// link handed to a reactor that never ran the adoption (the node was stopping)
    /// is released when the task queue is destroyed instead, on whichever thread
    /// takes the reactor down. An implementation must therefore be safe to call
    /// here from any thread, and must not assume the circuit ever opened.
    virtual void circuit_released(uint32_t circuit) = 0;
};

/// One relayed connection's byte stream and credit windows. See the file comment.
class RATS_API Circuit {
public:
    /// Largest data message a circuit puts on the wire. Big enough that the
    /// per-message overhead (a relay header, a frame header, an AEAD tag, and the
    /// relay's own copy) is noise against the payload; small enough that one
    /// circuit cannot monopolise the carrier's send queue for long, and that the
    /// relay's per-message work stays granular.
    static constexpr size_t kMaxDataChunk = 16 * 1024;

    /// Receive window a circuit advertises unless told otherwise. This is the
    /// memory ONE circuit can make the relay (and this node) hold, so it is the
    /// knob that turns "how fast can a relayed peer go" into "how much is a relay
    /// asked to carry": a 256 KiB window keeps a 100 ms round trip busy at roughly
    /// 20 Mbit/s, which is far more than a fallback path is meant to be used for.
    static constexpr uint32_t kDefaultWindow = 256 * 1024;

    /// Credit is granted back once this much of the window has been consumed.
    /// Halves mean one small grant per half-window of data, and leave the sender
    /// the other half to work with while the grant is in flight.
    static constexpr uint32_t kCreditGrantFraction = 2;

    /// A circuit we are opening: the request is out, the far end has not answered.
    /// Nothing may be written until on_accept() brings the window it will receive.
    ///
    /// @param id          the circuit's id on the carrier link (see the relay module).
    /// @param carrier     how outbound bytes leave; a shared_ptr because a Connection
    ///                    can outlive the module that opened the circuit (subsystems
    ///                    stop before the reactors do).
    /// @param recv_window what we are willing to have in flight toward us.
    static std::shared_ptr<Circuit> opening(uint32_t id, std::shared_ptr<CircuitCarrier> carrier,
                                            uint32_t recv_window = kDefaultWindow);

    /// A circuit opened TO us: the far end is already there and its request carried
    /// the window it will accept, so the stream is open from the first instant.
    ///
    /// Two factories rather than one flag plus a window that is sometimes ignored,
    /// because "the circuit is open" and "we know what the far end will take" are
    /// the same fact — an open circuit whose send window nobody set would be a
    /// stream that silently refuses to carry anything.
    static std::shared_ptr<Circuit> accepted(uint32_t id, std::shared_ptr<CircuitCarrier> carrier,
                                             uint32_t peer_window,
                                             uint32_t recv_window = kDefaultWindow);

    Circuit(const Circuit&) = delete;
    Circuit& operator=(const Circuit&) = delete;

    uint32_t id() const noexcept { return id_; }
    /// What we advertise to the far end as our receive window.
    uint32_t recv_window() const noexcept { return recv_window_; }
    bool     is_open() const noexcept { return state_ == State::Open; }
    bool     is_closed() const noexcept { return state_ == State::Closed; }

    // ── Fed by the relay module (reactor thread) ────────────────────────────
    //
    // Each of these returns the poll-equivalent events the circuit's Connection
    // should now be given (PollIn / PollOut / PollErr), or 0 for none. The caller
    // dispatches them — the circuit deliberately knows nothing about reactors.
    // Returning the mask rather than raising it keeps that dependency out of the
    // transport layer and lets the caller batch several changes into one wake.

    /// Bytes arrived from the far end. A peer that overruns the window it was
    /// granted is a protocol error and the circuit is failed rather than allowed
    /// to grow: that window is the whole bound on what a circuit can cost.
    uint32_t on_data(ByteView bytes);

    /// The far end accepted the circuit and advertised `peer_window` bytes of
    /// receive window. No-op unless the circuit is still pending.
    uint32_t on_accept(uint32_t peer_window);

    /// The far end granted `bytes` more of send window.
    uint32_t on_credit(uint32_t bytes);

    /// The circuit is over. `orderly` means the far end closed cleanly, so
    /// whatever it already sent is still delivered before the end of stream is
    /// reported; anything else fails the connection at once.
    uint32_t on_closed(CloseReason reason, bool orderly);

    /// The carrier's send queue, which had filled up, has room again.
    uint32_t on_carrier_writable();

    // ── Driven by the Connection through RelayLink (reactor thread) ─────────

    Link::IoResult read(ByteSpan into);
    Link::IoResult write(const ByteView* slices, size_t count);
    void           want_write(bool on) noexcept { want_write_ = on; }
    CloseReason    close_reason() const noexcept { return reason_; }
    /// Begin teardown from our side: tell the far end, then refuse further I/O.
    void           shutdown(CloseReason reason);
    /// The Link is being destroyed; release the carrier's bookkeeping. Idempotent.
    void           release();

    /// Bytes waiting to be read out (diagnostics and tests).
    size_t         pending_input() const noexcept { return inbox_.size() - inbox_read_; }
    /// Send window still available (diagnostics and tests).
    uint32_t       send_credit() const noexcept { return send_credit_; }

private:
    Circuit(uint32_t id, std::shared_ptr<CircuitCarrier> carrier, bool open,
            uint32_t recv_window, uint32_t peer_window);

    enum class State : uint8_t {
        Pending,  ///< outbound: opened, waiting for the far end to accept
        Open,     ///< bytes may flow
        Closed,   ///< no further I/O; read() drains what is left, then reports the end
    };

    /// Consumed prefix tolerated before the inbox is compacted. The connection
    /// normally drains the inbox to empty on every readable event, which resets it
    /// for free; this only bounds the pathological case where it does not.
    static constexpr size_t kCompactThreshold = 64 * 1024;

    bool blocked() const noexcept { return credit_blocked_ || carrier_blocked_; }
    /// PollOut, but only if anyone is waiting for it — see want_write().
    uint32_t writable_event() const noexcept;

    uint32_t                         id_;
    std::shared_ptr<CircuitCarrier>  carrier_;
    State                            state_;
    CloseReason                      reason_ = CloseReason::PeerReset;
    bool                             orderly_ = false;   ///< the far end closed cleanly
    bool                             released_ = false;
    bool                             close_sent_ = false;

    // — inbound —
    Bytes    inbox_;
    size_t   inbox_read_ = 0;         ///< consumed prefix of inbox_
    uint32_t recv_window_;            ///< what we advertised to the far end
    uint32_t recv_in_flight_ = 0;     ///< delivered to us and not yet granted back
    uint32_t recv_ungranted_ = 0;     ///< consumed, owed back to the far end

    // — outbound —
    uint32_t send_credit_ = 0;        ///< bytes the far end still allows us to send
    bool     want_write_ = false;     ///< the Connection has more to write
    bool     credit_blocked_ = false; ///< a write stopped for want of credit
    bool     carrier_blocked_ = false;///< a write stopped on the carrier's queue
};

/// The Link a Connection holds for a relayed circuit.
///
/// Deliberately empty of logic: the state has to be reachable by the module that
/// drives the relay protocol, which the Connection's unique_ptr would not allow,
/// so everything lives in the shared Circuit and this is the handle.
class RATS_API RelayLink final : public Link {
public:
    explicit RelayLink(std::shared_ptr<Circuit> circuit) : circuit_(std::move(circuit)) {}
    ~RelayLink() override { circuit_->release(); }

    TransportKind kind() const noexcept override { return TransportKind::Relay; }

    IoResult read(ByteSpan into) override { return circuit_->read(into); }
    IoResult write(const ByteView* slices, size_t count) override {
        return circuit_->write(slices, count);
    }

    /// A circuit is "connected" once the far end has accepted it. The Connection
    /// only asks after a PollOut, which the relay module raises on acceptance; a
    /// refusal arrives as PollErr instead and never reaches here.
    bool connect_completed() override { return circuit_->is_open(); }

    void want_write(bool on) override { circuit_->want_write(on); }

    /// No endpoint of its own, and deliberately not the relay's: identify pairs the
    /// address a link reports with the peer's advertised listen port to build a
    /// dialable address, and NatStatus reads it as our own NAT mapping. Both would
    /// be wrong here — the address on this path belongs to the node in the middle.
    /// Reporting nothing is what keeps a relayed peer out of that machinery.
    std::optional<Address> remote_endpoint() const override { return std::nullopt; }

    CloseReason error_reason() const override { return circuit_->close_reason(); }
    void        close(CloseReason reason) override { circuit_->shutdown(reason); }

    Circuit& circuit() noexcept { return *circuit_; }

private:
    std::shared_ptr<Circuit> circuit_;
};

} // namespace librats
