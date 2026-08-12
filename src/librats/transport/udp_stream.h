#pragma once

/**
 * @file udp_stream.h
 * @brief An ordered, reliable byte stream over datagrams — TCP's guarantees, in
 *        user space, on a socket shared by every peer.
 *
 * ── Why ──────────────────────────────────────────────────────────────────────
 * For a peer-to-peer node UDP is the better default wire: a single socket serves
 * every peer (so a NAT keeps one mapping open, and hole punching has something to
 * punch), the port a peer sees is the port we listen on, and nothing in the path
 * has to hold per-connection kernel state. What UDP does not give is what every
 * layer above needs — order, reliability and congestion control. That is this
 * file. Above it, nothing knows the difference: the same block framing, the same
 * Noise handshake and the same Session run unchanged over TCP or over this.
 *
 * ── The protocol ─────────────────────────────────────────────────────────────
 * Wire format lives in udp_packet.h. The stream itself is a compact, standard
 * design — deliberately familiar rather than novel, because a transport is the
 * wrong place to be clever:
 *
 *   - Packet-numbered, not byte-numbered. Syn, Data and Fin each consume exactly
 *     one sequence number; a pure Ack consumes none. That single rule is what
 *     makes the retransmission queue a plain deque whose i-th entry is always
 *     `front().seq + i`, so a selective ack resolves to an index instead of a
 *     search.
 *   - Cumulative ack + a 32-bit selective-ack bitmap, so one lost packet is
 *     repaired without stalling everything queued behind it.
 *   - RFC 6298 retransmission timing (SRTT/RTTVAR → RTO, doubling on each
 *     timeout, Karn's rule so a retransmitted packet never poisons the estimate),
 *     plus fast retransmit on the third duplicate ack.
 *   - Reno-style congestion control: slow start to `ssthresh`, then additive
 *     increase; multiplicative decrease on loss. Flow control is separate and
 *     absolute — the receiver advertises, in packets, how much more it will
 *     buffer, and the sender never exceeds it.
 *   - No Nagle: a partial packet goes out rather than waiting for company, which
 *     is what keeps a request/response exchange from paying a round trip per
 *     turn. What stands in for it is write() itself — it tops up the tail packet
 *     while it has room, so consecutive small frames share one datagram anyway,
 *     and UdpMux then hands the socket a whole batch of them per syscall.
 *     Note the limit of that: Connection::send() flushes write-through, one
 *     frame at a time, so the packing only catches what a single call carries
 *     rather than everything a reactor turn produced. Measured, that is most of
 *     the per-message cost on both transports — see the note above bench_small()
 *     in bench/suites/bench_transport.cpp.
 *
 * ── Ownership and threading ──────────────────────────────────────────────────
 * A stream is owned by the UdpMux and touched only by the reactor thread that
 * drives it — no locks, no atomics, like everything else on this path. It reaches
 * the wire and reports events through UdpStreamHost, and never sees the socket,
 * the reactor or the Connection directly. Events are *recorded* by the host, not
 * delivered inline, so a stream is never destroyed underneath the call that is
 * still running inside it.
 */

#include "librats/core/address.h"
#include "librats/core/bytes.h"
#include "librats/core/receive_buffer.h"
#include "librats/core/types.h"
#include "librats/transport/udp_packet.h"

#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <unordered_map>
#include <vector>

namespace librats {

class UdpStream;

/// What a stream needs from its owner: a way to the wire, and somewhere to leave
/// the events its connection should see.
class UdpStreamHost {
public:
    virtual ~UdpStreamHost() = default;

    /// Emit one datagram. Best effort by design — a datagram the socket refuses is
    /// indistinguishable from one the path drops, and retransmission covers both.
    virtual void send_datagram(const Address& to, const uint8_t* data, size_t len) = 0;

    /// Record poll-equivalent events (PollIn/PollOut/PollErr) for the connection
    /// that owns `stream`. Implementations must only *record*: the events are
    /// dispatched once the current batch of packets or timers is done, so a
    /// handler that tears the connection down cannot pull the stream out from
    /// under the code that is still walking it. Repeated events for one stream
    /// within a batch are expected — a stream raises PollIn per packet delivered —
    /// and an implementation is free to coalesce them into one dispatch.
    virtual void stream_events(UdpStream& stream, uint32_t events) = 0;
};

class UdpStream {
public:
    using Clock = std::chrono::steady_clock;

    // ── Tunables ────────────────────────────────────────────────────────────

    /// Bytes the stream will take from the connection before it says "no more".
    /// The connection keeps the rest in its own send queue, where the existing
    /// high-water mark governs it, so this only bounds what the transport itself
    /// holds — roughly a full window plus room to keep the pipe fed.
    ///
    /// It has to stay comfortably above a full window (kMaxWindowPackets *
    /// kMaxPayload ≈ 1.2 MiB), because it caps `sent_` and `unsent_` *together*:
    /// set at or below the window it, not the window, becomes the throughput
    /// ceiling, and the pipe drains between acks because nothing is queued behind
    /// what is in flight.
    static constexpr size_t kSendQueueLimit = 2 * 1024 * 1024;

    /// Packet buffers kept for reuse after their packet is acknowledged. The send
    /// path allocates one buffer per packet, and in a bulk transfer that is one
    /// allocation per 1200 bytes shipped; recycling turns the steady state into no
    /// allocation at all. Small on purpose — creation and retirement run at the
    /// same rate once a transfer is going, so a handful covers the churn, and an
    /// idle stream should not sit on memory it is not using.
    static constexpr size_t kMaxSpareBuffers = 8;

    /// Initial congestion window. Four packets is the classic conservative start
    /// (RFC 3390 territory) — enough to get an RTT sample and trigger fast
    /// retransmit on an early loss, without a burst into an unknown path.
    static constexpr uint32_t kInitialCwnd = 4 * rudp::kMaxPayload;
    static constexpr uint32_t kMinCwnd     = 2 * rudp::kMaxPayload;
    /// A full window. Growing the congestion window past what the receiver will
    /// ever hold buys nothing: the packet-count check in can_transmit() would stop
    /// the sender first, and a cwnd that has run away above the real limit takes a
    /// spurious loss with it when it is finally halved.
    static constexpr uint32_t kMaxCwnd     = rudp::kMaxWindowPackets * rudp::kMaxPayload;

    static constexpr std::chrono::milliseconds kInitialRto{500};
    static constexpr std::chrono::milliseconds kMinRto{100};
    static constexpr std::chrono::milliseconds kMaxRto{6000};

    /// Transmissions of the Syn before an unanswered dial is called failed. Three
    /// attempts at a doubling 500 ms RTO give up after ~3.5 s — fast enough that a
    /// node on a UDP-blocking network falls back to TCP promptly (see the dialer),
    /// and slow enough to ride out a genuinely lossy path.
    static constexpr int kSynMaxAttempts = 3;
    /// Transmissions of one packet on an established stream before the peer is
    /// declared gone. With RTO doubling to its 6 s cap this is a bit over a minute.
    static constexpr int kMaxRetransmits = 12;

    /// How long an acknowledgement may wait for a packet to ride along on. Only
    /// ever delays a *pure* ack: an out-of-order packet, a Syn or a Fin is
    /// acknowledged at once, and any outgoing packet carries the ack for free.
    static constexpr std::chrono::milliseconds kDelayedAck{20};
    /// Packets a single acknowledgement may repair. Bounds the burst one ack can
    /// provoke, so a window that was mostly lost is rebuilt over a few acks
    /// instead of being dumped back onto a path that just proved it is congested.
    static constexpr int kMaxRepairsPerAck = 8;

    /// Minimum gap between two transmissions of the same packet. Selective acks
    /// arrive several times per round trip, and without this floor each of them
    /// would re-send the same not-yet-repaired packet — turning a single loss into
    /// a flood. It also stands in for the round-trip estimate on a path (loopback,
    /// LAN) whose RTT is too small to space anything out.
    static constexpr std::chrono::milliseconds kMinRepairSpacing{10};

    // ── Pacing ──────────────────────────────────────────────────────────────
    //
    // A congestion window is permission to have N bytes *outstanding*, not
    // permission to put them on the wire back to back. Emitting a whole window
    // at line rate is what turns a queue that was merely full into a queue that
    // dropped a hundred packets at once — and it happens even when the window is
    // well under what the path can hold, because the burst arrives faster than
    // the bottleneck can drain it. So transmissions are released at the rate the
    // window implies rather than as fast as the loop can produce them.
    //
    // The rate is `gain * cwnd / srtt`. The gain is above 1 on purpose: slow
    // start has to deliver a *doubling* window within one round trip, so pacing
    // it at exactly cwnd/srtt would hold growth back by a factor of two, and in
    // congestion avoidance a little headroom keeps an ack-clocked sender from
    // being throttled by its own estimate. These are the gains RFC 9002 (7.7)
    // recommends and Linux uses.
    static constexpr uint32_t kPaceGainSlowStartNum = 2;
    static constexpr uint32_t kPaceGainSlowStartDen = 1;
    static constexpr uint32_t kPaceGainSteadyNum    = 5;   ///< 1.25x
    static constexpr uint32_t kPaceGainSteadyDen    = 4;

    /// Burst the pacer tolerates, expressed as time rather than packets: it is
    /// what accrues at the current rate over one wake-up of the reactor. Below
    /// this there is nothing to gain — the timer cannot space packets finer than
    /// it can wake — and pacing every packet against a 1 ms clock would cap a
    /// stream at one packet per millisecond. Above it the smoothing is thrown
    /// away. So the pacer does not remove bursts, it bounds them to one clock
    /// tick's worth of data, which is what the queue can absorb.
    static constexpr std::chrono::milliseconds kPaceQuantum{1};
    /// Floor for that burst. Two packets is the classic allowance (a delayed ack
    /// releases two at a time), and it keeps a stream on a very slow path from
    /// pacing itself below one packet per round trip.
    static constexpr size_t kPaceMinBurst = 2 * rudp::kMaxPayload;

    // ── HyStart++ (RFC 9406): leaving slow start before the loss ─────────────
    //
    // Slow start doubles the window every round trip and, left alone, stops only
    // when something is dropped — which means it always overshoots the path by
    // roughly a factor of two and pays for the discovery with a lost window.
    // HyStart++ watches the *minimum* round-trip time per round instead: a queue
    // building in front of the bottleneck raises it well before it overflows.
    // When it rises past a threshold the sender leaves exponential growth for a
    // cautious phase (CSS), and if the rise turns out to be noise it goes back.
    static constexpr std::chrono::milliseconds kHyMinRttThresh{4};
    static constexpr std::chrono::milliseconds kHyMaxRttThresh{16};
    /// Round-trip samples a round needs before its minimum is worth comparing.
    static constexpr int kHyRttSamples = 8;
    /// Growth divisor in the cautious phase: a quarter of slow start, so the
    /// window still probes upward but cannot double while the verdict is out.
    static constexpr uint32_t kHyCssGrowthDivisor = 4;
    /// Rounds the cautious phase lasts before the exit is believed.
    static constexpr int kHyCssRounds = 5;

    /// Idle gap after which an ack is sent purely to prove we are still here.
    static constexpr std::chrono::seconds kKeepAlive{10};
    /// Silence from the peer that ends the stream. Comfortably more than four
    /// keep-alive intervals, so only real loss of contact trips it.
    static constexpr std::chrono::seconds kIdleTimeout{45};

    UdpStream(UdpStreamHost& host, const Address& remote, uint32_t recv_id, uint32_t send_id,
              ConnRole role, Clock::time_point now);

    UdpStream(const UdpStream&) = delete;
    UdpStream& operator=(const UdpStream&) = delete;

    // ── Identity ────────────────────────────────────────────────────────────

    /// The id peers put in packets addressed to this stream (our demux key).
    uint32_t       recv_id() const noexcept { return recv_id_; }
    /// The id we put in packets we send (the peer's demux key).
    uint32_t       send_id() const noexcept { return send_id_; }
    const Address& remote()  const noexcept { return remote_; }
    ConnRole       role()    const noexcept { return role_; }

    /// The connection this stream belongs to, once the reactor has adopted it.
    ConnId conn_id() const noexcept { return conn_id_; }
    void   set_conn_id(ConnId id) noexcept { conn_id_ = id; }

    // ── Driven by the mux ───────────────────────────────────────────────────

    /// Feed one decoded datagram addressed to this stream.
    void on_packet(const rudp::Packet& p, Clock::time_point now);

    /// Periodic work: retransmission, delayed acks, keep-alive, idle death.
    void tick(Clock::time_point now);

    /// When tick() next has something to do — the earliest of the retransmission
    /// timeout, an owed acknowledgement, the keep-alive and the idle deadline.
    ///
    /// This is what lets the mux schedule streams instead of sweeping them: a
    /// stream that is merely connected wants to be visited once per keep-alive
    /// (10 s), not fifty times a second, and a node with no streams at all wants
    /// no timer whatsoever. Every mutating entry point re-reads this, so a
    /// deadline can never move earlier without the owner being told.
    ///
    /// Two values are special:
    ///   - `nullopt` — never; only a dead stream, which the mux drops rather than
    ///     services.
    ///   - the clock epoch — *now*. An acknowledgement owed with no deadline (see
    ///     `ack_due_`) is one that must go out at the first opportunity, because
    ///     the peer it is meant for is stopped on a zero window and will send
    ///     nothing for it to ride on.
    std::optional<Clock::time_point> next_deadline() const noexcept;

    // ── Driven by the Link / Connection ─────────────────────────────────────

    /// Copy up to `len` bytes of in-order stream data out. 0 means nothing is
    /// ready (check eof() to tell "not yet" from "never again").
    size_t read(uint8_t* into, size_t len);

    /// Queue `count` slices for the peer, taking as much as the send queue will
    /// hold. Returns the bytes accepted; 0 means the queue is full and the caller
    /// should ask to be told when it drains (see want_write).
    size_t write(const ByteView* slices, size_t count, Clock::time_point now);

    /// Ask to be given a writable event when the send queue drains again.
    void want_write(bool on) noexcept { want_write_ = on; }

    /// Orderly shutdown: queue a Fin behind everything already written, so the
    /// peer sees every byte we owe it and then a clean end of stream.
    void begin_close(Clock::time_point now);

    /// Abrupt shutdown: tell the peer the stream is gone and stop. Used when
    /// there is nothing worth flushing, or when the stream has already failed.
    void abort(Clock::time_point now);

    // ── State ───────────────────────────────────────────────────────────────

    bool connecting() const noexcept { return state_ == State::SynSent; }
    bool connected()  const noexcept { return state_ == State::Connected; }
    bool dead()       const noexcept { return state_ == State::Dead; }

    /// The peer finished sending AND everything it sent has been read out.
    bool eof() const noexcept { return peer_fin_ && inbox_.empty(); }

    /// Why the stream died (only meaningful once dead()).
    CloseReason close_reason() const noexcept { return close_reason_; }

    /// Nothing left to deliver: every packet we queued has been acknowledged.
    /// The condition the mux lingers a released stream until.
    bool flushed() const noexcept { return sent_.empty() && unsent_.empty(); }

    // — diagnostics (tests, logging) —
    uint32_t cwnd()          const noexcept { return cwnd_; }
    /// Where slow start stops. Starts at the ceiling and comes down either when
    /// HyStart++ sees the round-trip time rise or when something is lost — which
    /// of the two happened is the whole question F2 asks.
    uint32_t ssthresh()      const noexcept { return ssthresh_; }
    size_t   bytes_in_flight() const noexcept { return flight_bytes_; }
    size_t   queued_bytes()  const noexcept { return queued_bytes_; }
    uint32_t retransmits()   const noexcept { return retransmits_; }
    /// Times the congestion window has been reduced. One per loss *episode* is the
    /// invariant that keeps a single lost packet from walking the window to the
    /// floor over the many acks that report it — see enter_recovery().
    uint32_t window_reductions() const noexcept { return window_reductions_; }

private:
    enum class State {
        SynSent,    ///< outbound: the Syn is in flight, nothing else may go yet
        Connected,  ///< both directions open (a Fin may still be queued)
        Dead,       ///< finished or failed; the mux will drop it
    };

    /// One packet occupying exactly one sequence number.
    ///
    /// `buf` is the datagram itself, laid out as
    ///
    ///     [ kMaxHeaderSize bytes of headroom ][ payload ]
    ///
    /// so transmit() writes the header into the tail of the headroom, directly in
    /// front of the payload, and hands the socket one contiguous range. The
    /// alternative — payload in its own buffer, copied into a scratch datagram
    /// behind a freshly built header — costs a full payload copy on every send
    /// *and* every retransmission, on the hottest path this transport has.
    struct OutPacket {
        Bytes             buf;              ///< headroom + payload; only headroom for Syn/Fin
        uint32_t          seq  = 0;
        rudp::PacketType  type = rudp::PacketType::Data;
        Clock::time_point sent_at{};
        int               sends = 0;        ///< transmissions so far (0 = still unsent)
        bool              acked = false;    ///< selectively acknowledged, awaiting the cumulative ack
        /// This packet's bytes are counted in flight_bytes_ right now. Set by the
        /// transmission that put them on the wire, cleared when they are either
        /// acknowledged or declared lost — because a packet a retransmission
        /// timeout has given up on is no longer occupying the path, and leaving it
        /// counted is what would stop the sender from ever refilling the pipe.
        bool              in_flight = false;

        /// Payload bytes — what the accounting (flight_bytes_, queued_bytes_) counts.
        size_t size() const noexcept {
            return buf.size() > rudp::kMaxHeaderSize ? buf.size() - rudp::kMaxHeaderSize : 0;
        }
        /// Room left in a partially filled tail packet (only meaningful while unsent).
        size_t space() const noexcept { return rudp::kMaxPayload - size(); }
    };

    /// A packet held out of order, waiting for the gap in front of it to fill.
    struct InPacket {
        Bytes payload;
        bool  fin = false;
    };

    // — outbound —
    OutPacket new_packet(rudp::PacketType type);
    void recycle(OutPacket& p);
    void transmit(OutPacket& p, Clock::time_point now);
    void send_control(rudp::PacketType type, Clock::time_point now);
    void pump(Clock::time_point now);
    void retransmit_lost(Clock::time_point now);
    bool can_transmit() const noexcept;
    /// Everything can_transmit() checks *except* the pacer: the state machine,
    /// the peer's window and our own. Split out because pump() has to tell "the
    /// pacer is holding this back" — which a timer resolves — from "a window is",
    /// which only an acknowledgement can.
    bool window_allows() const noexcept;
    bool cwnd_allows(size_t bytes) const noexcept;
    void fill_common(rudp::Packet& p) const;
    uint16_t advertised_window() const noexcept;

    // — pacing —
    /// The window the pacer meters against: cwnd scaled by the phase's gain.
    /// Zero means "not pacing" (no round-trip estimate yet, so no rate to pace at).
    uint64_t pace_window() const noexcept;
    /// Bytes the pacer may release over `dt` at the current rate.
    uint64_t pace_bytes_over(Clock::duration dt) const noexcept;
    /// Hand the token bucket whatever has accrued since it was last topped up.
    void     pace_accrue(Clock::time_point now);
    /// Whether `bytes` may go out now. Always true when nothing is in flight —
    /// a lone probe, a zero-window persist and the first packet after an idle
    /// period must never be held back by a rate derived from an empty pipe.
    bool     pace_allows(size_t bytes) const noexcept;
    /// How long until `bytes` could be released. Zero when they can go now.
    Clock::duration pace_wait(size_t bytes) const noexcept;

    // — window validation after an idle period (RFC 2861) —
    void restart_after_idle(Clock::time_point now);

    // — HyStart++ (RFC 9406) —
    void hystart_reset();
    void hystart_sample(Clock::duration rtt);
    void hystart_on_ack(uint32_t ack);
    bool in_slow_start() const noexcept { return cwnd_ < ssthresh_; }

    // — inbound —
    void handle_ack(const rudp::Packet& p, Clock::time_point now);
    void handle_retry(const rudp::Packet& p, Clock::time_point now);
    void repair_sacked_holes(Clock::time_point now);
    void handle_sequenced(const rudp::Packet& p);
    void deliver(ByteView payload, bool fin);
    void drain_reorder();
    uint32_t sack_bitmap() const noexcept;

    // — timing / congestion —
    void on_rto(Clock::time_point now);
    void sample_rtt(Clock::duration rtt);
    void enter_recovery();
    void on_loss(bool timeout);
    void grow_window(size_t acked_bytes);

    void die(CloseReason reason);
    void raise(uint32_t events) noexcept { events_ |= events; }
    void flush_events();

    UdpStreamHost& host_;
    Address        remote_;
    uint32_t       recv_id_;
    uint32_t       send_id_;
    ConnRole       role_;
    ConnId         conn_id_ = kInvalidConnId;

    State       state_;
    CloseReason close_reason_ = CloseReason::PeerClosed;
    bool        peer_fin_  = false;  ///< peer's Fin delivered in order
    bool        fin_queued_ = false; ///< our Fin is in the send queue
    bool        want_write_ = false;
    /// A Retry has already been answered on this stream. The responder is entitled
    /// to ask us to prove our address once; honouring a second one would let anyone
    /// who can forge a datagram from the peer keep the dial going round forever.
    bool        retried_    = false;
    uint32_t    events_     = 0;     ///< pending PollIn/PollOut/PollErr

    // — send side —
    // `sent_` holds transmitted-but-unacknowledged packets in strictly
    // consecutive sequence order, which is the whole reason a selective ack can
    // be resolved by index rather than by search: sent_[i].seq == sent_[0].seq + i.
    std::deque<OutPacket> sent_;
    std::deque<OutPacket> unsent_;
    std::vector<Bytes>    spare_;             ///< retired packet buffers, kept for reuse
    uint32_t              next_seq_     = 1;   ///< sequence number for the next packet created
    size_t                flight_bytes_ = 0;   ///< payload bytes transmitted and not yet acked
    size_t                queued_bytes_ = 0;   ///< payload bytes held by sent_ + unsent_
    uint32_t              cwnd_         = kInitialCwnd;
    uint32_t              ssthresh_     = kMaxCwnd;
    uint16_t              peer_window_  = rudp::kMaxWindowPackets;
    uint32_t              last_ack_recv_ = 0;
    int                   dup_acks_     = 0;
    uint32_t              retransmits_  = 0;
    uint32_t              window_reductions_ = 0;

    // Loss episodes. A window is reduced once per episode, not once per ack that
    // happens to repair something — several acks arrive per round trip, and each
    // of them halving again is what turns two losses in a window into a collapse
    // to the floor. `recover_seq_` is the NewReno recovery point: the highest
    // sequence number outstanding when the episode began, so the episode ends
    // exactly when the cumulative ack has covered everything that was in flight
    // when the loss was detected.
    bool                  in_recovery_  = false;
    uint32_t              recover_seq_  = 0;
    /// A retransmission timeout has given up on packets still sitting in `sent_`,
    /// so retransmit_lost() has work to do. Purely a hint that keeps it from
    /// scanning the whole queue on every acknowledgement of a healthy transfer.
    bool                  have_lost_    = false;

    // — pacing —
    /// Bytes the pacer will currently let through, and when the bucket was last
    /// topped up. Kept in bytes rather than packets so a partly filled tail
    /// packet costs what it actually weighs.
    uint64_t              pace_tokens_  = 0;
    Clock::time_point     pace_last_{};
    /// When the pacer expects to have enough for the packet it is holding back
    /// (epoch = it is holding nothing). This is a deadline like any other: the
    /// mux wakes the stream on it, and pump() re-arms or clears it.
    Clock::time_point     pace_due_{};
    /// When data — not a bare acknowledgement — last went out. The keep-alive
    /// writes last_send_ every ten seconds, so it cannot answer "has this stream
    /// been sending?", which is exactly what the idle-restart rule needs to know.
    Clock::time_point     last_data_send_{};

    // — HyStart++ —
    /// Cautious phase: slow start has seen the round-trip time rise and is
    /// probing gently until the rise is confirmed or withdrawn.
    bool                  css_          = false;
    int                   css_rounds_   = 0;
    Clock::duration       css_baseline_rtt_{};
    /// Lowest round-trip time seen in this round and in the one before it. The
    /// *minimum* is what matters: a queue building in front of the bottleneck
    /// lifts even the luckiest packet's round trip, where an average would just
    /// as easily be moved by one straggler.
    Clock::duration       round_min_rtt_{};
    Clock::duration       prev_round_min_rtt_{};
    int                   round_samples_ = 0;
    /// Highest sequence number outstanding when this round began; the round ends
    /// when the cumulative acknowledgement reaches it.
    uint32_t              round_end_    = 0;

    // — receive side —
    ReceiveBuffer                             inbox_;    ///< in-order bytes awaiting read()
    std::unordered_map<uint32_t, InPacket>    reorder_;  ///< packets past a gap
    uint32_t                                  recv_next_ = 1;  ///< next sequence number expected
    bool                                      need_ack_  = false;
    int                                       unacked_packets_ = 0;
    /// Cached selective-ack bitmap, rebuilt only when the reorder buffer or the
    /// expected sequence number moves. Every outgoing packet carries this field,
    /// so deriving it from 32 hash lookups per *packet* — during loss recovery,
    /// when packets are at their most frequent — was pure repeated work: it can
    /// only change when one of the two things it is derived from changes.
    mutable uint32_t                          sack_bits_  = 0;
    mutable bool                              sack_dirty_ = false;

    // — timing —
    Clock::duration   srtt_{};
    Clock::duration   rttvar_{};
    bool              have_rtt_ = false;
    Clock::duration   rto_ = kInitialRto;
    Clock::time_point last_recv_;
    Clock::time_point last_send_;
    /// When an owed acknowledgement must go out. The epoch means "no deadline",
    /// which with need_ack_ set is not "never" but "at once": read() leaves it that
    /// way to ask for a window update, because a peer stopped on a zero window sends
    /// nothing for the ack to ride on. Every other owed ack arms a real deadline.
    Clock::time_point ack_due_{};
    /// When the retransmission timeout fires (epoch = the timer is not running).
    ///
    /// One deadline for the stream, not one per packet — RFC 6298's model. It is
    /// started by a transmission that finds it idle, restarted whenever an
    /// acknowledgement covers new data, and turned off once nothing is outstanding.
    /// Deriving it instead from `sent_.front().sent_at` (the obvious shortcut) is
    /// wrong after a timeout: the packets behind the one that was resent still
    /// carry their original timestamps, so every one of them looks instantly
    /// overdue and the window is driven back to the floor on every tick.
    Clock::time_point rto_deadline_{};
};

} // namespace librats
