#pragma once

/**
 * @file udp_mux.h
 * @brief One UDP socket, every peer: demultiplexing, admission, timers, batching.
 *
 * The whole point of running peer connections over UDP is that they share a
 * single socket and a single port. That is what makes a NAT hold one mapping
 * instead of one per peer, what makes hole punching possible at all, and what
 * makes the port a peer observes us sending from the same port it can dial us
 * back on. The price is that the kernel no longer separates the peers for us, so
 * this class does it: every packet names the connection id its receiver chose
 * (udp_wire.h), which resolves to a UdpConnection in one hash lookup.
 *
 * Responsibilities, and deliberately nothing more:
 *   - own the socket and the connections on it;
 *   - route each datagram to its connection, creating one for an Initial nobody
 *     owns (after asking the delegate whether a new inbound peer is welcome);
 *   - answer a packet for a connection we no longer have with a stateless reset,
 *     so the peer learns at once instead of retransmitting into a void;
 *   - run every connection's timers off one deadline queue (see below);
 *   - keep a connection briefly after its transport is gone, so the last bytes it
 *     owes the peer still get delivered (see release());
 *   - move datagrams in batches rather than one syscall at a time.
 *
 * ── Why the timers are scheduled, not swept ─────────────────────────────────
 * Every connection owes its peer work on a deadline: a loss timer, a delayed ACK,
 * a pacer release, a keep-alive and the idle timeout. A fixed sweep costs
 * O(connections) whether or not anything is due and wakes the reactor fifty times
 * a second forever. So each connection reports when it next needs servicing
 * (UdpConnection::next_deadline) and the mux keeps them in a min-heap. tick()
 * services only what has come due, and next_timeout_ms() tells the reactor how
 * long it may sleep, so an idle mux contributes no wake-ups at all.
 *
 * Keeping that honest is one rule: a deadline must never move *earlier* without
 * the mux being told. Every path that can change a connection re-arms it — the
 * datagram path here, and send/flush/close through UdpTransport, which calls
 * touch(). Moving a deadline later needs no notification: the connection is then
 * visited early, finds nothing to do, and re-arms itself.
 *
 * ── Why the socket is worked in batches ─────────────────────────────────────
 * A datagram transport emits one packet per call, so at 1220 bytes a bulk
 * transfer costs tens of thousands of trips through the kernel per megabyte. So
 * outgoing datagrams are built straight into a UdpSendBatch (udp_io.h) — sealed
 * where they will leave from — and go together, and incoming ones are collected
 * in a UdpRecvBatch and decrypted where they landed. Where the kernel has
 * segmentation offload (Linux UDP_SEGMENT/UDP_GRO, Windows USO/URO) a run of
 * equal-size datagrams to one peer goes down as one buffer, and a run from one
 * peer comes back up as one; UdpMuxLimits::offload turns it off.
 *
 * The acknowledgements follow the same shape: everything one receive brings a
 * connection is a burst (UdpConnection::begin_burst), and the ACK it owes goes
 * once, after the last of it.
 *
 * Staging is never deferred past the work that produced it: every entry point
 * flushes before it returns, and the Reactor flushes once more at the end of each
 * loop turn — so a packet never waits on a timer. And no batch is let grow past
 * one pacer release (Recovery::kPaceMaxBurst) before it goes: what one flush hands
 * the socket leaves at line rate.
 *
 * Threading follows the rest of the transport: the mux belongs to exactly one
 * Reactor and is touched only by that reactor's thread. Events are never
 * delivered from inside a connection's packet handling — a connection records
 * them and the mux dispatches between datagrams, every kUdpBatchMax of them,
 * coalescing repeats for the same connection.
 */

#include "librats/core/address.h"
#include "librats/core/socket.h"
#include "librats/core/types.h"
#include "librats/core/udp_io.h"
#include "librats/security/handshaker.h"
#include "librats/transport/transport.h"
#include "librats/transport/udp_connection.h"

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

    /// Whether an inbound dial would be adopted at all, asked before any handshake
    /// work is spent on it: a refusal decided only at adoption has already paid for
    /// the Noise reply. adopt_inbound() may still refuse.
    virtual bool admit_inbound() { return true; }

    /// Adopt a freshly accepted inbound connection. Returns the new ConnId, or
    /// kInvalidConnId to refuse it (the mux then tells the dialer).
    virtual ConnId adopt_inbound(std::unique_ptr<Transport> transport) = 0;

    /// Deliver poll-equivalent events (PollIn/PollOut/PollErr) to a connection.
    virtual void dispatch_link_events(ConnId id, uint32_t events) = 0;
};

/// What the mux is willing to spend on peers, and on peers it has not heard a
/// round trip from.
///
/// A TCP listener gets admission for free: an inbound connection costs a file
/// descriptor, and an attacker cannot make the kernel allocate one without
/// completing a three-way handshake — which a forged source address cannot do.
/// A datagram listener has neither, so an unanswered Initial would otherwise buy
/// an attacker a connection and a half-built Noise handshake for the price of
/// one datagram. These numbers put the datagram side back on the same footing.
struct UdpMuxLimits {
    /// Concurrent connections the mux holds at all. A backstop: the node's own
    /// peer cap governs long before this does. Past it a dial is refused.
    size_t max_streams = 8192;

    /// Connections above which an Initial must carry a valid address-validation
    /// token before it costs anything. Past it an Initial without one is answered
    /// with a Retry and nothing is kept, so unproven state never exceeds roughly
    /// this many connections. The cost is one round trip on an inbound dial, paid
    /// only by a node already carrying this many. 0 validates every dial; SIZE_MAX
    /// none.
    size_t validate_above = 1024;

    /// Bytes one connection's flow-control window may grow to (see
    /// UdpConnectionConfig::max_window).
    size_t receive_window = UdpConnectionConfig::kDefaultMaxWindow;

    /// Bytes every connection on this socket may hold out of order, together (see
    /// udp::UdpReceiveBudget).
    size_t receive_budget = 64 * 1024 * 1024;

    /// Whether to use the kernel's segmentation offload where it has one.
    bool offload = true;

    /// The secret stateless-reset tokens are made from. Set from something that
    /// survives a restart (the node derives it from its identity) so a restarted
    /// node can still tell its old peers it has forgotten them; all zeros means a
    /// fresh random one, which can only reset what this run of the node opened.
    std::array<uint8_t, 32> reset_key{};
};

class UdpTransport;

class UdpMux final : private UdpConnectionHost {
public:
    using Clock = UdpConnection::Clock;

    /// How long a connection is kept after its transport is gone, to finish
    /// handing over what it already accepted. TCP gets this from the kernel, which
    /// keeps retransmitting after close().
    static constexpr std::chrono::seconds kLingerTimeout{5};

    /// Datagrams drained in one readable event before yielding back to the
    /// reactor, so a flood cannot monopolise the loop. Hitting it is reported so
    /// the caller comes straight back (kqueue is edge-triggered).
    static constexpr size_t kMaxDatagramsPerRead = 4096;

    /// Replies sent per kUnsolicitedReplyWindow to datagrams no connection owns —
    /// stateless resets, Retries, refusals. All answer unauthenticated traffic from
    /// an address nobody has verified, so they share one budget: the socket must not
    /// become a reflector, whichever one an attacker provokes. Anchored to the
    /// clock, because a node with no connections has no deadlines and no ticks.
    static constexpr int                       kMaxUnsolicitedReplies = 64;
    static constexpr std::chrono::milliseconds kUnsolicitedReplyWindow{20};

    /// How long a token secret stays current. Two are kept, so a token is good for
    /// between one and two of these.
    static constexpr std::chrono::seconds kTokenSecretLifetime{30};

    /// Socket buffer requested in each direction: one socket carries every peer,
    /// and a burst that overruns it is dropped by the kernel.
    static constexpr int kSocketBufferBytes = 4 * 1024 * 1024;

    UdpMux(socket_t socket, AddressFamily family, UdpMuxDelegate& delegate,
           SecurityProvider& security, UdpMuxLimits limits = {},
           CongestionAlgorithm congestion = CongestionAlgorithm::Bbr);
    ~UdpMux() override;

    UdpMux(const UdpMux&) = delete;
    UdpMux& operator=(const UdpMux&) = delete;

    socket_t      socket() const noexcept { return socket_; }
    AddressFamily family() const noexcept { return family_; }

    /// The budget every connection's held data is charged to.
    const udp::UdpReceiveBudget& receive_budget() const noexcept { return receive_budget_; }

    /// Drain the socket and route what arrives. True if it stopped at
    /// kMaxDatagramsPerRead with more possibly pending.
    bool on_readable();

    /// Service the connections whose deadline has passed and retire finished
    /// lingering ones. One comparison when nothing is due.
    void tick();

    /// Milliseconds until the earliest deadline (rounded up), 0 if one has passed,
    /// `max_ms` when nothing is scheduled.
    int next_timeout_ms(int max_ms) const noexcept;

    /// Re-read `conn`'s deadline after something outside the datagram path changed
    /// it (a send, a flush, a close).
    void touch(UdpConnection& conn);

    /// Dial `remote`: the Initial leaves at once. nullptr only if no free
    /// connection id could be found. `profile` shapes the Initial's repeats.
    std::unique_ptr<Transport> connect(const Address& remote, DialProfile profile = {});

    /// The transport that owned `conn` is being destroyed. The connection goes at
    /// once or lingers until it has delivered what it owes.
    void release(UdpConnection& conn);

    /// Say goodbye on every connection (the node is going down) and drop them.
    void shutdown();

    /// Put every staged datagram on the wire. Cheap and idempotent when nothing is.
    void flush_output();

    size_t stream_count() const noexcept { return conns_.size(); }
    const UdpOffload& offload() const noexcept { return offload_; }

private:
    struct Entry {
        std::unique_ptr<UdpConnection> conn;
        /// When a released connection stops being worth keeping. Epoch = still
        /// owned by a live transport.
        Clock::time_point linger_until{};
        /// The deadline this entry holds a heap slot for, while `armed`; a slot
        /// whose deadline no longer matches was superseded and is dropped when it
        /// surfaces.
        Clock::time_point scheduled{};
        bool              armed = false;
    };

    struct Due {
        Clock::time_point at;
        udp::Cid          cid;
    };
    struct LaterFirst {
        bool operator()(const Due& a, const Due& b) const noexcept { return a.at > b.at; }
    };

    // — UdpConnectionHost —
    uint8_t* datagram_buffer() override;
    void     send_datagram(const Address& to, size_t len) override;
    void     connection_events(UdpConnection& conn, uint32_t events) override;
    void     reset_token(udp::Cid cid, uint8_t* out) override;

    void handle_datagram(uint8_t* data, size_t len, const Address& from, Clock::time_point now);
    void on_initial(const udp::LongPacket& initial, size_t len, const Address& from,
                    Clock::time_point now);
    void send_refusal(const Address& to, const udp::LongPacket& initial, uint64_t code);
    void send_retry(const Address& to, const udp::LongPacket& initial);
    void send_stateless_reset(const Address& to, udp::Cid dcid, size_t trigger_len);
    bool spend_reply_budget(Clock::time_point now);
    bool allocate_cid(udp::Cid& cid);
    void dispatch_pending();
    void end_bursts();
    UdpConnectionConfig connection_config(DialProfile profile = {}) noexcept;

    void arm(udp::Cid cid, Entry& entry);
    void compact_due();

    // — address validation —
    using Secret = std::array<uint8_t, 32>;
    void token_for(const Address& from, udp::Cid dcid, const Secret& secret, uint8_t* out) const;
    bool token_valid(const Address& from, udp::Cid dcid, ByteView token) const;
    void rotate_token_secret(Clock::time_point now);

    socket_t            socket_;
    AddressFamily       family_;
    UdpMuxDelegate&     delegate_;
    SecurityProvider&   security_;
    UdpMuxLimits        limits_;
    CongestionAlgorithm congestion_;
    /// What held data shares. Declared ahead of the connections, which hand back
    /// what they hold when they are destroyed.
    udp::UdpReceiveBudget receive_budget_;

    std::unordered_map<udp::Cid, Entry>      conns_;   ///< keyed by our own id
    std::vector<Due>                         due_;     ///< min-heap of deadlines
    std::vector<std::pair<ConnId, uint32_t>> pending_events_;
    std::vector<udp::Cid>                    bursts_;  ///< connections the current receive reached

    // Built from offload_, so declared after it; allocated once, never grown.
    UdpOffload   offload_;
    UdpSendBatch send_;
    UdpRecvBatch recv_;

    std::array<Secret, 2> token_secret_{};   ///< [0] current, [1] the one it replaced
    Clock::time_point     secret_rotated_at_{};
    Secret                reset_key_{};

    std::mt19937_64   rng_;
    Clock::time_point reply_window_started_{};
    int               replies_in_window_ = 0;
};

} // namespace librats
