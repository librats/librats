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
 *   - No Nagle. Frames are already batched by the connection's send queue (one
 *     flush gathers the whole backlog into this one call), so delaying a partial
 *     packet would buy nothing and cost a round trip on every request/response
 *     exchange.
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
#include <unordered_map>

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
    /// under the code that is still walking it.
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
    static constexpr size_t kSendQueueLimit = 512 * 1024;

    /// Initial congestion window. Four packets is the classic conservative start
    /// (RFC 3390 territory) — enough to get an RTT sample and trigger fast
    /// retransmit on an early loss, without a burst into an unknown path.
    static constexpr uint32_t kInitialCwnd = 4 * rudp::kMaxPayload;
    static constexpr uint32_t kMinCwnd     = 2 * rudp::kMaxPayload;
    static constexpr uint32_t kMaxCwnd     = 2u * 1024 * 1024;

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
    size_t   bytes_in_flight() const noexcept { return flight_bytes_; }
    size_t   queued_bytes()  const noexcept { return queued_bytes_; }
    uint32_t retransmits()   const noexcept { return retransmits_; }

private:
    enum class State {
        SynSent,    ///< outbound: the Syn is in flight, nothing else may go yet
        Connected,  ///< both directions open (a Fin may still be queued)
        Dead,       ///< finished or failed; the mux will drop it
    };

    /// One packet occupying exactly one sequence number.
    struct OutPacket {
        Bytes             payload;          ///< empty for Syn/Fin
        uint32_t          seq  = 0;
        rudp::PacketType  type = rudp::PacketType::Data;
        Clock::time_point sent_at{};
        int               sends = 0;        ///< transmissions so far (0 = still unsent)
        bool              acked = false;    ///< selectively acknowledged, awaiting the cumulative ack

        size_t size() const noexcept { return payload.size(); }
        /// Room left in a partially filled tail packet (only meaningful while unsent).
        size_t space() const noexcept { return rudp::kMaxPayload - payload.size(); }
    };

    /// A packet held out of order, waiting for the gap in front of it to fill.
    struct InPacket {
        Bytes payload;
        bool  fin = false;
    };

    // — outbound —
    void transmit(OutPacket& p, Clock::time_point now);
    void send_control(rudp::PacketType type, Clock::time_point now);
    void pump(Clock::time_point now);
    bool can_transmit() const noexcept;
    void fill_common(rudp::Packet& p) const;
    uint16_t advertised_window() const noexcept;

    // — inbound —
    void handle_ack(const rudp::Packet& p, Clock::time_point now);
    void repair_sacked_holes(Clock::time_point now);
    void handle_sequenced(const rudp::Packet& p);
    void deliver(ByteView payload, bool fin);
    void drain_reorder();

    // — timing / congestion —
    void sample_rtt(Clock::duration rtt);
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
    uint32_t    events_     = 0;     ///< pending PollIn/PollOut/PollErr

    // — send side —
    // `sent_` holds transmitted-but-unacknowledged packets in strictly
    // consecutive sequence order, which is the whole reason a selective ack can
    // be resolved by index rather than by search: sent_[i].seq == sent_[0].seq + i.
    std::deque<OutPacket> sent_;
    std::deque<OutPacket> unsent_;
    uint32_t              next_seq_     = 1;   ///< sequence number for the next packet created
    size_t                flight_bytes_ = 0;   ///< payload bytes transmitted and not yet acked
    size_t                queued_bytes_ = 0;   ///< payload bytes held by sent_ + unsent_
    uint32_t              cwnd_         = kInitialCwnd;
    uint32_t              ssthresh_     = kMaxCwnd;
    uint16_t              peer_window_  = rudp::kMaxWindowPackets;
    uint32_t              last_ack_recv_ = 0;
    int                   dup_acks_     = 0;
    int                   consecutive_timeouts_ = 0;
    uint32_t              retransmits_  = 0;

    // — receive side —
    ReceiveBuffer                             inbox_;    ///< in-order bytes awaiting read()
    std::unordered_map<uint32_t, InPacket>    reorder_;  ///< packets past a gap
    uint32_t                                  recv_next_ = 1;  ///< next sequence number expected
    bool                                      need_ack_  = false;
    int                                       unacked_packets_ = 0;

    // — timing —
    Clock::duration   srtt_{};
    Clock::duration   rttvar_{};
    bool              have_rtt_ = false;
    Clock::duration   rto_ = kInitialRto;
    Clock::time_point last_recv_;
    Clock::time_point last_send_;
    Clock::time_point ack_due_{};   ///< when a delayed ack must go out (epoch = none)
};

} // namespace librats
