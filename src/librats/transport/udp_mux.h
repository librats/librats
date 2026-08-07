#pragma once

/**
 * @file udp_mux.h
 * @brief One UDP socket, every peer: demultiplexing, admission and timers.
 *
 * The whole point of running peer connections over UDP is that they share a
 * single socket and a single port. That is what makes a NAT hold one mapping
 * instead of one per peer, what makes hole punching possible at all, and what
 * makes the port a peer observes us sending from the same port it can dial us
 * back on. The price is that the kernel no longer separates the peers for us, so
 * this class does it: every datagram carries a connection id (see udp_packet.h)
 * that resolves to a UdpStream in one hash lookup.
 *
 * Responsibilities, and deliberately nothing more:
 *   - own the socket and the streams on it;
 *   - route each datagram to its stream, creating one for an unrecognised Syn
 *     (after asking the delegate whether a new inbound peer is welcome);
 *   - answer a datagram for a stream we do not have with a Reset, so the peer
 *     learns immediately instead of retransmitting into a void;
 *   - drive every stream's timers from one periodic tick;
 *   - keep a stream alive briefly after its connection is gone, so the last
 *     bytes it owes the peer still get delivered (see release());
 *   - move datagrams in batches rather than one syscall at a time (see
 *     flush_output()).
 *
 * ── Why the socket is worked in batches ─────────────────────────────────────
 * A datagram transport emits one packet per call, so at a 1200-byte payload a
 * bulk transfer costs tens of thousands of syscalls per megabyte — far more than
 * the framing, the congestion control and the encryption above it put together,
 * and the reason a user-space stream costs measurably more CPU per byte than the
 * kernel's TCP. So the mux does not hand each datagram to the socket as it is
 * produced: outgoing datagrams are staged and leave together (kUdpBatchMax per
 * syscall), and incoming ones are collected the same way.
 *
 * Staging is deliberately *not* deferred past the work that produced it. Every
 * entry point flushes before it returns, and the Reactor flushes once more at the
 * end of each loop turn to cover datagrams produced by application sends — so a
 * packet never waits on a timer, and batching costs no latency, only syscalls.
 *
 * All of that is conditional on the platform actually having a batched send
 * (kUdpBatchIsOneSyscall). Where it does not — Windows, macOS — staging would pay
 * a copy per datagram to save syscalls that cannot be saved, so send_datagram()
 * hands each datagram to the socket as it is produced and the staging path is
 * compiled out entirely. The receive side has no such split: its fallback fills
 * the caller's slots directly, so it costs nothing extra either way.
 *
 * Threading follows the rest of the transport: the mux belongs to exactly one
 * Reactor and is touched only by that reactor's thread.
 *
 * Events are never delivered from inside the datagram loop. A stream records what
 * its connection should see, and the mux dispatches once the batch it is standing
 * in is finished — so a handler that tears its connection down can never free a
 * stream the loop is still walking. Per batch, not per drain: what a stream
 * delivers waits in its in-order buffer until the connection reads it out, so
 * holding every event to the end of the drain would let that buffer grow to
 * everything one peer could send in it. Events for the same connection coalesce,
 * because a bulk sender raises one per packet and only the first has work to do.
 */

#include "librats/core/address.h"
#include "librats/core/socket.h"
#include "librats/core/types.h"
#include "librats/transport/link.h"
#include "librats/transport/udp_stream.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <random>
#include <unordered_map>
#include <vector>

namespace librats {

/// What the mux needs from the reactor above it.
class UdpMuxDelegate {
public:
    virtual ~UdpMuxDelegate() = default;

    /// Adopt a freshly accepted inbound stream as a connection. Returns the new
    /// ConnId, or kInvalidConnId to refuse it (the mux then resets the peer).
    virtual ConnId adopt_inbound_link(std::unique_ptr<Link> link) = 0;

    /// Deliver poll-equivalent events (PollIn/PollOut/PollErr) to a connection.
    virtual void dispatch_link_events(ConnId id, uint32_t events) = 0;
};

/// What the mux is willing to spend on peers it has not heard a round trip from.
///
/// A TCP listener gets this for free: an inbound connection costs a file
/// descriptor, and an attacker cannot make the kernel allocate one without
/// completing a three-way handshake — which a forged source address cannot do.
/// A datagram listener has neither the descriptor nor the handshake, so an
/// unanswered Syn would otherwise buy an attacker a stream, a connection and a
/// half-built Noise handshake for the price of sixteen forged bytes. These two
/// numbers are what puts the datagram side back on the same footing.
struct UdpMuxLimits {
    /// Concurrent streams the mux will hold at all. A backstop rather than the
    /// working limit — with validation on (below), everything counted here has
    /// proved it can receive at its address, and the node's own peer cap governs
    /// long before this does. Reaching it answers further dials with a Reset.
    size_t max_streams = 8192;

    /// Streams above which a Syn must carry a valid address-validation cookie
    /// before it costs anything. This, not max_streams, is the bound on state a
    /// forged source address can create: past it a bare Syn is answered with a
    /// Retry and nothing is kept, so unvalidated state can never exceed roughly
    /// this many streams (~1.5 MiB at the default).
    ///
    /// The cost of validation is one extra round trip on an inbound dial, paid
    /// only by a node that is already carrying this many streams — so an ordinary
    /// node never pays it, and a node under a flood pays it instead of dying.
    /// 0 validates every inbound dial; SIZE_MAX never validates any.
    size_t validate_above = 1024;
};

class UdpMux final : public UdpStreamHost {
public:
    using Clock = UdpStream::Clock;

    /// How often every stream's timers are serviced. 20 ms is fine-grained enough
    /// that a delayed ack is never the bottleneck and coarse enough that sweeping
    /// thousands of streams costs nothing measurable — each visit is a handful of
    /// timestamp comparisons.
    static constexpr std::chrono::milliseconds kTickInterval{20};

    /// How long a stream is kept after its connection is gone, to finish handing
    /// over what it already accepted from the application. TCP gets this from the
    /// kernel, which keeps retransmitting after close(); without it, a node that
    /// sends a last message and disconnects would simply lose it.
    static constexpr std::chrono::seconds kLingerTimeout{5};

    /// Datagrams drained in one readable event before yielding back to the
    /// reactor, so a flood cannot monopolise the loop. Hitting it is reported so
    /// the caller can come straight back (the poller is edge-triggered on kqueue,
    /// which makes "drain until empty" a correctness requirement, not a nicety).
    static constexpr size_t kMaxDatagramsPerRead = 4096;

    /// Replies emitted per tick to datagrams that belong to no stream — the Reset
    /// that tells a peer we have forgotten it, and the Retry that asks an unproven
    /// one to come back with a cookie. Both are answers to unauthenticated traffic
    /// from an address we have not verified, so both are budgeted together: a
    /// hostile sender must not be able to turn this socket into a reflector,
    /// whichever of the two it provokes.
    static constexpr int kMaxUnsolicitedRepliesPerTick = 64;

    /// How long a cookie secret stays current. Two are kept, so a cookie is good
    /// for between one and two of these — long enough to survive a slow round trip
    /// and a retransmitted Syn, short enough that a leaked secret is worthless
    /// almost at once.
    static constexpr std::chrono::seconds kCookieSecretLifetime{30};

    /// Socket buffer requested in each direction. One socket carries every peer,
    /// so the default (tens of kilobytes on most systems) is far too small: a
    /// burst that overruns it is dropped by the kernel, and each drop costs a
    /// retransmission timeout. This is the single most effective knob there is on
    /// datagram throughput.
    static constexpr int kSocketBufferBytes = 4 * 1024 * 1024;

    UdpMux(socket_t socket, AddressFamily family, UdpMuxDelegate& delegate,
           UdpMuxLimits limits = {});
    ~UdpMux() override;

    UdpMux(const UdpMux&) = delete;
    UdpMux& operator=(const UdpMux&) = delete;

    socket_t socket() const noexcept { return socket_; }

    /// Drain the socket and route what arrives. Returns true if it stopped at
    /// kMaxDatagramsPerRead with more possibly pending.
    bool on_readable();

    /// Service every stream's timers, and retire finished lingering streams.
    void tick();

    /// Open an outbound stream to `remote`, ready to be adopted as a connection.
    /// Returns nullptr only if no free connection id could be found.
    std::unique_ptr<Link> connect(const Address& remote);

    /// Called when the Link that owned `stream` is destroyed. The stream either
    /// goes away at once or lingers until it has flushed what it owes.
    void release(UdpStream& stream);

    /// Reset every stream (the node is going down) and drop them.
    void shutdown();

    /// Put every staged datagram on the wire. Called by each of the entry points
    /// above before it returns, and by the Reactor at the end of a loop turn to
    /// cover the ones an application send produced (Connection::send → the stream's
    /// write path, which reaches this class from outside any datagram batch).
    /// Cheap and idempotent when nothing is staged.
    void flush_output();

    size_t stream_count() const noexcept { return streams_.size(); }

    // — UdpStreamHost —
    void send_datagram(const Address& to, const uint8_t* data, size_t len) override;
    void stream_events(UdpStream& stream, uint32_t events) override;

private:
    struct Entry {
        std::unique_ptr<UdpStream> stream;
        /// When a released stream stops being worth keeping. Epoch = still owned
        /// by a live connection.
        Clock::time_point linger_until{};
    };

    void        handle_datagram(const rudp::Packet& p, const Address& from, Clock::time_point now);
    /// Decide whether a Syn for an unknown stream may become one. Answers the peer
    /// itself (Reset at the ceiling, Retry when it has yet to prove its address)
    /// and returns false when nothing should be created.
    bool        admit_syn(const rudp::Packet& syn, const Address& from);
    void        accept_inbound(const rudp::Packet& syn, const Address& from, Clock::time_point now);
    void        send_reset(const Address& to, uint32_t conn_id);
    void        send_retry(const Address& to, uint32_t conn_id, uint32_t cookie);
    bool        spend_reply_budget();
    UdpStream*  find_for_reset(uint32_t conn_id, const Address& from);
    bool        allocate_ids(uint32_t& recv_id, uint32_t& send_id);
    void        dispatch_pending();

    // — address validation —
    using CookieSecret = std::array<uint8_t, 32>;
    uint32_t cookie_for(const Address& from, uint32_t conn_id, const CookieSecret& secret) const;
    bool     cookie_valid(const Address& from, uint32_t conn_id, ByteView payload) const;
    void     rotate_cookie_secret(Clock::time_point now);

    socket_t        socket_;
    AddressFamily   family_;
    UdpMuxDelegate& delegate_;
    UdpMuxLimits    limits_;

    std::unordered_map<uint32_t, Entry> streams_;  ///< keyed by our recv id
    std::vector<std::pair<ConnId, uint32_t>> pending_events_;
    std::vector<uint32_t>                    expired_;  ///< scratch for tick()

    // Batch scratch. Both directions keep kUdpBatchMax datagrams' worth of storage
    // for the life of the mux — allocated once, never grown, so neither the receive
    // loop nor the send path allocates. The slots point into the storage and are
    // set up in the constructor; only their lengths and endpoints move afterwards.
    std::vector<uint8_t>                      recv_storage_;
    std::vector<uint8_t>                      send_storage_;
    std::array<UdpBatchSlot, kUdpBatchMax>    recv_slots_{};
    std::array<UdpBatchSlot, kUdpBatchMax>    send_slots_{};
    size_t                                    staged_ = 0;  ///< datagrams awaiting flush_output()

    // Cookie secrets: [0] is current, [1] the one it replaced. A cookie is checked
    // against both, so one that was handed out just before a rotation still works.
    std::array<CookieSecret, 2> cookie_secret_{};
    Clock::time_point           secret_rotated_at_{};

    std::mt19937 rng_;
    int          replies_this_tick_ = 0;
};

/// The Link a Connection holds for a UDP stream.
///
/// The stream itself belongs to the mux, not to the connection: it has to outlive
/// the connection briefly so the last bytes still get delivered, and it has to be
/// reachable by connection id from the datagram path. So this is a handle — the
/// translation between Link's socket-shaped vocabulary and the stream's.
class UdpStreamLink final : public Link {
public:
    UdpStreamLink(UdpMux& mux, UdpStream& stream) : mux_(mux), stream_(stream) {}
    ~UdpStreamLink() override { mux_.release(stream_); }

    TransportKind kind() const noexcept override { return TransportKind::Udp; }

    IoResult read(ByteSpan into) override;
    IoResult write(const ByteView* slices, size_t count) override;
    bool     connect_completed() override { return !stream_.dead(); }
    void     want_write(bool on) override { stream_.want_write(on); }

    std::optional<Address> remote_endpoint() const override { return stream_.remote(); }

    void        attach(ConnId id) override { stream_.set_conn_id(id); }
    CloseReason error_reason() const override { return stream_.close_reason(); }
    void        close(CloseReason reason) override;

    UdpStream& stream() noexcept { return stream_; }

private:
    UdpMux&    mux_;
    UdpStream& stream_;
};

} // namespace librats
