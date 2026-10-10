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
 *     repaired without stalling everything queued behind it — and, on pure
 *     acks to a peer that understands them, ranges naming every hole in the
 *     window, so a window with several holes is repaired in one round trip
 *     rather than one hole per round trip (udp_packet.h).
 *   - RFC 6298 retransmission timing (SRTT/RTTVAR → RTO, doubling on each
 *     timeout, Karn's rule so a retransmitted packet never poisons the
 *     estimate), one round-trip sample per ack from the newest packet it covers.
 *   - RACK-style loss detection (RFC 8985): a first transmission is lost once
 *     three packets behind it have arrived, a repair once something sent a
 *     reordering window after it has; declared-lost packets leave the flight
 *     and are repaired under the window — supplemented in recovery, for a
 *     controller that asks for it (Reno), by proportional rate reduction
 *     (RFC 6937).
 *   - Pluggable congestion control (congestion_control.h): BBRv3 by default,
 *     NewReno with HyStart++ on request. The stream owns the facts — what is
 *     outstanding, acknowledged or lost, the round-trip estimate and a
 *     delivery-rate sample per acknowledgement — and the controller turns them
 *     into a window and a pacing rate. Flow control is separate and absolute —
 *     the receiver advertises, in packets, how much more it will buffer, and the
 *     sender never exceeds it.
 *   - No Nagle: a partial packet goes out rather than waiting for company, which
 *     is what keeps a request/response exchange from paying a round trip per
 *     turn. What stands in for it is write() itself — it tops up the tail packet
 *     while it has room, so consecutive small frames share one datagram anyway,
 *     and UdpMux then hands the socket a whole batch of them per syscall. The
 *     packing catches everything a reactor turn produced, because Connection
 *     aggregates a turn's frames and writes them once rather than flushing each
 *     — which is where most of the per-message cost used to go.
 *   - Paced: the window says how much may be outstanding, not how fast it may
 *     leave, so transmissions are metered at the controller's pacing rate
 *     rather than released in a burst.
 *   - A tail loss is probed, not timed out: the last packet of a burst has
 *     nothing behind it to produce duplicate acknowledgements, so silence is
 *     answered with a question (RFC 8985) before it is treated as congestion.
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
#include "librats/transport/congestion_control.h"
#include "librats/transport/delivery_rate.h"
#include "librats/transport/udp_packet.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
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

    /// The congestion window every controller starts from, and the one none of
    /// them exceeds (see congestion_control.h).
    static constexpr uint32_t kInitialCwnd = cc::kInitialWindow;
    static constexpr uint32_t kMaxCwnd     = cc::kMaxWindow;

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
    /// Packets that must arrive behind a first transmission before it counts as
    /// lost — the classic duplicate-ack threshold, read off the selective acks.
    /// Retransmissions are judged by time instead (RACK, RFC 8985): a repair is
    /// lost once something sent a reordering window after it has arrived, which
    /// is what keeps one loss from being repaired twice and a lost repair from
    /// waiting for a timeout.
    static constexpr int32_t kReorderThreshold = 3;

    // ── Pacing ──────────────────────────────────────────────────────────────
    //
    // A congestion window is permission to have N bytes *outstanding*, not
    // permission to put them on the wire back to back. Emitting a whole window
    // at line rate is what turns a queue that was merely full into a queue that
    // dropped a hundred packets at once — and it happens even when the window is
    // well under what the path can hold, because the burst arrives faster than
    // the bottleneck can drain it. So transmissions are released at the rate the
    // controller sets (CongestionController::pacing_rate) rather than as fast as
    // the loop can produce them.

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

    // ── Tail loss probe (RFC 8985 / RFC 9002 §6.2) ──────────────────────────
    //
    // A loss is normally noticed by what arrives *after* it: duplicate
    // acknowledgements, or a selective ack naming the hole. Neither exists when
    // the packet that went missing was the last one — the receiver has nothing
    // further to acknowledge and simply falls silent. Left to the retransmission
    // timeout, that costs kMinRto (100 ms) *and* collapses the congestion window
    // to one packet, on a stream where nothing is actually congested.
    //
    // For request/response traffic — which is most of what a peer-to-peer node
    // does — the tail is not an edge case, it is every message. So the first one
    // or two expiries are treated as a question rather than a verdict: re-send
    // the packet the peer has gone quiet on, leave the window alone, and only
    // escalate to the real timeout if the silence persists.
    static constexpr int kMaxTailProbes = 2;
    /// Floor for the probe timer. Well under kMinRto — that floor exists to keep
    /// a *timeout* from firing spuriously, and a spurious timeout is expensive
    /// where a spurious probe costs one packet — but still above the delayed
    /// acknowledgement it must not race.
    static constexpr std::chrono::milliseconds kMinProbeTimeout{30};

    /// Times a re-opened receive window is announced before the matter is left to
    /// the keep-alive. A window update rides on a bare acknowledgement, and nothing
    /// retransmits one — while the sender it is meant for is stopped and produces
    /// no traffic for a second copy to ride on. So a single dropped update would
    /// cost that sender a full keep-alive interval of silence over one lost packet.
    /// Repeating it on the retransmission timeout makes the common recovery a round
    /// trip instead, and the keep-alive remains the backstop behind these.
    static constexpr int kMaxWindowAnnounces = 4;

    /// Idle gap after which an ack is sent purely to prove we are still here.
    static constexpr std::chrono::seconds kKeepAlive{10};
    /// Silence from the peer that ends the stream. Comfortably more than four
    /// keep-alive intervals, so only real loss of contact trips it.
    static constexpr std::chrono::seconds kIdleTimeout{45};

    /// @param profile How hard an OUTBOUND dial tries (see DialProfile). Ignored
    ///        for an inbound stream, which never sends a Syn. The default is the
    ///        ordinary dial; a hole punch passes DialProfile::punch().
    /// @param algorithm The congestion controller this stream runs.
    UdpStream(UdpStreamHost& host, const Address& remote, uint32_t recv_id, uint32_t send_id,
              ConnRole role, Clock::time_point now, DialProfile profile = {},
              CongestionAlgorithm algorithm = CongestionAlgorithm::Bbr);

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
    uint32_t cwnd()          const noexcept { return cc_->cwnd(); }
    /// The controller itself, for a test or a benchmark that wants to look inside
    /// it (cast to the class algorithm() names).
    const cc::CongestionController& congestion() const noexcept { return *cc_; }
    const cc::RttEstimate&          rtt()        const noexcept { return rtt_; }
    size_t   bytes_in_flight() const noexcept { return flight_bytes_; }
    size_t   queued_bytes()  const noexcept { return queued_bytes_; }
    uint32_t retransmits()   const noexcept { return retransmits_; }
    /// Tail probes sent since the last acknowledgement (diagnostics, tests).
    int      tail_probes()   const noexcept { return tail_probes_; }
    /// Times the controller was told about congestion: once per loss *episode*,
    /// plus once per retransmission timeout. One per episode is the invariant that
    /// keeps a single lost packet from walking the window to the floor over the
    /// many acks that report it — see enter_recovery().
    uint32_t congestion_events() const noexcept { return congestion_events_; }

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
        /// The delivery-rate snapshot of its latest transmission, `sent_at` included.
        cc::TxState       tx;
        int               sends = 0;        ///< transmissions so far (0 = still unsent)
        bool              acked = false;    ///< selectively acknowledged, awaiting the cumulative ack
        /// This packet's bytes are counted in flight_bytes_ right now. Set by the
        /// transmission that put them on the wire, cleared when they are either
        /// acknowledged or declared lost — because a packet a retransmission
        /// timeout has given up on is no longer occupying the path, and leaving it
        /// counted is what would stop the sender from ever refilling the pipe.
        bool              in_flight = false;
        /// Once acked: a sequence number past this one such that every packet in
        /// between is acked too — the link next_unacked() follows (and shortens) to
        /// step over a run of selectively acknowledged packets in one hop.
        uint32_t          skip = 0;

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
    /// Recovery credit `delivered` bytes earn (RFC 6937).
    uint64_t prr_share(uint64_t delivered) const noexcept;
    void fill_common(rudp::Packet& p) const;
    uint16_t advertised_window() const noexcept;

    // — pacing —
    /// Hand the token bucket whatever has accrued since it was last topped up.
    void     pace_accrue(Clock::time_point now);
    /// Whether `bytes` may go out now. Always true when nothing is in flight —
    /// the lone packet a recovering stream is allowed and the first packet after
    /// an idle period must never be held back by a rate derived from an empty
    /// pipe. A receiver's zero window is not this check's business: it stops the
    /// packet earlier, in window_allows().
    bool     pace_allows(size_t bytes) const noexcept;
    /// How long until `bytes` could be released. Zero when they can go now.
    Clock::duration pace_wait(size_t bytes) const noexcept;

    /// After a pump: record whether the window held the sender back, and whether
    /// the application ran out of data (which makes the next samples app-limited).
    void note_send_limits();

    // — inbound —
    void handle_ack(const rudp::Packet& p, Clock::time_point now);
    void handle_retry(const rudp::Packet& p, Clock::time_point now);
    /// First acknowledgement of `pkt`, cumulative or selective: settle its
    /// accounting and feed the delivery-rate and loss-detection state.
    void on_newly_acked(OutPacket& pkt, Clock::time_point now);
    /// Selectively acknowledge the packet carrying `seq`, if it is still queued.
    void sack_one(uint32_t seq, Clock::time_point now);
    /// Index of the first packet at or after sent_[idx] not yet acknowledged
    /// (sent_.size() if there is none), in amortised constant time.
    size_t next_unacked(size_t idx) noexcept;
    /// Declare lost what the acknowledgements say did not arrive (see
    /// kReorderThreshold), and open a loss episode if anything was.
    void detect_losses(Clock::time_point now);
    /// Take `pkt` off the path and queue its repair.
    void mark_lost(OutPacket& pkt, Clock::time_point now);
    void handle_sequenced(const rudp::Packet& p);
    void deliver(ByteView payload, bool fin);
    void drain_reorder();
    uint32_t sack_bitmap() const noexcept;
    /// Encode the runs of packets held past the hole into range_buf_ (cached
    /// until the reorder buffer moves). Returns how many there are.
    size_t   ack_ranges() const noexcept;
    /// Something is held past the hole that the sack word cannot reach, so only a
    /// pure acknowledgement carrying ranges can tell the peer about it.
    bool     holes_past_sack() const noexcept;
    bool     is_held(uint32_t seq) const noexcept;
    void     set_held(uint32_t seq, bool on) noexcept;

    // — timing / congestion —
    void on_rto(Clock::time_point now);
    /// How long to wait before asking whether the tail got through. A round trip
    /// plus what the peer may sit on an acknowledgement for, doubled per
    /// consecutive unanswered probe.
    Clock::duration probe_timeout() const noexcept;
    /// What the one loss-detection timer should be set to right now: the probe
    /// interval while there are probes left to spend, the retransmission timeout
    /// once there are not. One timer, two meanings — which is how RFC 9002 models
    /// it too, and why arming it in one place keeps the two from disagreeing.
    Clock::duration loss_timeout() const noexcept;
    void sample_rtt(Clock::duration rtt);
    /// The retransmission timeout the current estimate implies (no backoff).
    Clock::duration estimated_rto() const noexcept;
    void enter_recovery(Clock::time_point now);
    /// `pkt` is given up on and about to be sent again: account the loss and tell
    /// the controller, before the retransmission overwrites its send snapshot.
    void declare_lost(const OutPacket& pkt, Clock::time_point now);

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
    uint16_t              peer_window_  = rudp::kMaxWindowPackets;
    /// The cumulative acknowledgement `peer_window_` came in on. What orders two
    /// windows in time: a peer's ack never moves backwards, so a packet carrying
    /// one that has is a packet from the past, and the window on it with it.
    uint32_t              window_ack_   = 0;
    uint32_t              last_ack_recv_ = 0;
    int                   dup_acks_     = 0;
    uint32_t              retransmits_  = 0;
    uint32_t              congestion_events_ = 0;
    /// Consecutive tail probes sent with nothing acknowledged in between. Reset by
    /// any acknowledgement that covers new data, cumulatively or selectively, so it
    /// counts a single episode of silence rather than the life of the stream.
    int                   tail_probes_  = 0;

    // Loss episodes. A window is reduced once per episode, not once per ack that
    // happens to repair something — several acks arrive per round trip, and each
    // of them halving again is what turns two losses in a window into a collapse
    // to the floor. `recover_seq_` is the NewReno recovery point: the highest
    // sequence number outstanding when the episode began, so the episode ends
    // exactly when the cumulative ack has covered everything that was in flight
    // when the loss was detected.
    bool                  in_recovery_  = false;
    uint32_t              recover_seq_  = 0;
    /// The episode was opened by a retransmission timeout rather than by the
    /// acknowledgements. Probes are for a path that is still answering; one that
    /// has just gone silent for a whole timeout is left to the timer's backoff.
    bool                  timeout_recovery_ = false;
    /// Packets declared lost and not yet sent again. The count is what a healthy
    /// transfer checks; `lost_` is the work list behind it.
    size_t                lost_pending_ = 0;
    /// Sequence numbers declared lost, as a min-heap (lowest first, so a hole is
    /// repaired in the order the receiver needs it filled). Entries are not removed
    /// when their packet is delivered or re-sent by another route — a stale one is
    /// recognised and dropped when it reaches the top.
    std::vector<uint32_t> lost_;

    // Loss detection walks only what it has not judged yet, so its cost per
    // acknowledgement is the packets it newly condemns — not the window.
    /// First transmissions leave in sequence order, so both of RACK's tests for
    /// them (packets delivered behind, time elapsed since) are monotone in the
    /// sequence number. Everything before this cursor has been judged; the scan
    /// resumes here and stops at the first packet still in good standing.
    uint32_t              loss_scan_ = 0;
    /// A retransmission is judged by time alone, and repairs leave in no particular
    /// sequence order — so they are kept apart, oldest transmission first, and
    /// the scan stops at the first one too recent to condemn. Entries are dropped
    /// lazily: one no longer matching its packet (acked, given up on, or sent again
    /// since — `sends` tells) is discarded when it reaches the front.
    struct Repair {
        uint32_t seq   = 0;
        int      sends = 0;
    };
    /// A queue, held as a vector consumed from `repairs_head_` so an idle stream
    /// allocates nothing for it (an empty std::deque already holds a block).
    std::vector<Repair>   repairs_;
    size_t                repairs_head_ = 0;
    /// Packets still in `sent_` that a selective ack has already covered.
    size_t                sacked_in_queue_ = 0;
    /// Sends earned during this loss episode and not yet spent — proportional
    /// rate reduction (RFC 6937), which lets repairs and new data out while the
    /// window has just been cut below what is still in flight.
    uint64_t              recovery_credit_ = 0;
    /// PRR's RecoverFS: bytes outstanding when the episode began (0 after a
    /// timeout, which earns no credit at all).
    uint64_t              recover_fs_      = 0;
    /// Bytes in flight when the acknowledgement being processed arrived.
    uint64_t              ack_prior_flight_ = 0;

    // Loss detection. The largest sequence number known delivered, and the send
    // time of the newest transmission known delivered (RACK's reference point).
    uint32_t              largest_acked_ = 0;
    bool                  have_largest_acked_ = false;
    Clock::time_point     rack_sent_at_{};
    bool                  have_rack_ = false;
    /// The newest packet the acknowledgement being processed covers — where its
    /// one round-trip sample comes from.
    struct Newest {
        bool              have = false;
        Clock::time_point sent_at{};
        int               sends = 0;
    };
    Newest                ack_newest_;

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

    // — what the controller is told —
    /// Payload bytes declared lost since the controller last heard about an ack —
    /// by repairs during one, or by a timeout in between.
    uint64_t              lost_since_ack_  = 0;
    /// Payload bytes newly acknowledged by the ack being processed (zero outside
    /// one): what a loss episode opened mid-ack reports to the controller.
    uint64_t              ack_newly_acked_ = 0;
    /// The window held the sender back at some point since the last ack.
    bool                  cwnd_limited_    = false;

    // — receive side —
    ReceiveBuffer                             inbox_;    ///< in-order bytes awaiting read()
    std::unordered_map<uint32_t, InPacket>    reorder_;  ///< packets past a gap
    uint32_t                                  recv_next_ = 1;  ///< next sequence number expected
    bool                                      need_ack_  = false;
    int                                       unacked_packets_ = 0;
    /// Announcements left of a receive window that has just re-opened, and when the
    /// next one is due (the epoch = at once). Zero means there is nothing to
    /// announce, which is what arms this: the peer is stopped and sends nothing for
    /// an update to ride on, so this is the only clock either side has for it.
    int                                       window_announces_ = 0;
    Clock::time_point                         window_due_{};
    /// Cached selective-ack bitmap, rebuilt only when the reorder buffer or the
    /// expected sequence number moves. Every outgoing packet carries this field,
    /// so deriving it from 32 hash lookups per *packet* — during loss recovery,
    /// when packets are at their most frequent — was pure repeated work: it can
    /// only change when one of the two things it is derived from changes.
    mutable uint32_t                          sack_bits_  = 0;
    mutable bool                              sack_dirty_ = false;
    /// Which sequence numbers past the hole the reorder buffer holds, as a ring of
    /// bits indexed by sequence number. Duplicates the map's keys on purpose: the
    /// selective forms are built by scanning it a word at a time, where the map
    /// would need a hash lookup per packet of the window.
    std::array<uint64_t, rudp::kMaxWindowPackets / 64> held_{};
    /// Encoded acknowledgement ranges, rebuilt only when the reorder buffer or the
    /// expected sequence number moves.
    mutable std::array<uint8_t, rudp::kMaxAckRanges * rudp::kAckRangeSize> range_buf_{};
    mutable size_t                            range_count_  = 0;
    mutable bool                              ranges_dirty_ = false;
    /// The peer parses acknowledgement ranges (it said so with FlagExtAck).
    bool                                      peer_ext_ack_ = false;

    // — timing —
    // Declared ahead of the controller, which keeps references to both.
    cc::RttEstimate                          rtt_;
    cc::DeliveryRateSampler                  sampler_;
    std::unique_ptr<cc::CongestionController> cc_;
    // How the dial (and only the dial) is retried — see DialProfile. Kept as plain
    // members rather than a stored profile so the SynSent path costs no indirection,
    // and clamped in the constructor so a caller cannot ask for zero attempts or an
    // interval outside what the timer can honour.
    int               syn_attempts_ = kSynMaxAttempts;
    bool              syn_backoff_  = true;
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
