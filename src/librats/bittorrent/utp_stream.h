#pragma once

/**
 * @file utp_stream.h
 * @brief One uTP connection (BEP 29): an ordered, reliable, delay-controlled byte
 *        stream over datagrams.
 *
 * uTP is what most of the swarm now speaks. It exists for one reason: a BitTorrent
 * client saturating an uplink with TCP starves everything else on the same line —
 * VoIP, SSH, the web page the user is reading — because TCP only backs off once a
 * router has already filled its queue and started dropping. uTP measures the
 * *one-way delay* instead and backs off as soon as the queue starts growing, so it
 * yields to any TCP flow sharing the path. That is the whole design, and it is why
 * `wnd_size` is in bytes, why every packet carries two timestamps, and why the
 * congestion controller (LEDBAT, RFC 6817) targets 100 ms of queuing delay rather
 * than a loss event.
 *
 * ## What this is not
 *
 * The library already has a reliable-UDP transport (`transport/udp_stream.h`) for
 * the node's own mesh. This is a *second* one, deliberately: that one is ours to
 * design, this one has to be bit-compatible with uTorrent and libtorrent or it is
 * worthless. They share no code, and per the project's layering BitTorrent never
 * reaches into `transport/`.
 *
 * ## Structure
 *
 * A Stream has no socket, no thread and no locks: it is driven entirely by
 * `on_packet()` and `tick()` and emits datagrams through its `Host`, exactly like
 * `dht::Node` is driven by `on_datagram()`. The Host (utp_manager.h) owns the one
 * shared UDP socket and demultiplexes to us. Everything lives on the BitTorrent
 * reactor thread.
 *
 * Reads and writes mirror non-blocking socket semantics, because that is what the
 * layer above (`PeerLink` → `PeerConnection`) is written against: `write()` takes
 * what it can and reports WouldBlock; `read()` drains what has arrived in order and
 * reports Eof once the peer's FIN has been reached.
 *
 * ## Connection ids
 *
 * Each direction has its own 16-bit id, and the pair is always adjacent. The
 * initiator picks `recv_id` at random and uses `send_id = recv_id + 1`; the SYN
 * itself is sent carrying `recv_id` — that is, the id the initiator expects the
 * *answer* on, which is the one genuinely surprising thing about the uTP handshake.
 * The responder reads that id, and takes `send_id = id`, `recv_id = id + 1`.
 *
 * ## What is not implemented (on purpose)
 *
 * - **Path-MTU discovery.** libtorrent probes upwards from a floor. We instead fix
 *   the payload at a size that fits inside IPv6's 1280-byte minimum MTU, so no path
 *   can fragment us. That costs some throughput on a 1500-byte path and buys
 *   immunity to the whole class of black-holed-fragment failures.
 * - **The close-reason extension** (type 3). Parsed past, never acted on: it is a
 *   diagnostic uTorrent emits, and nothing downstream of us would use it.
 * - **Delayed-ACK timers.** Acks are deferred only to the end of the current socket
 *   drain (see Host::utp_defer_ack), never on a timer, so we never sit on an ack the
 *   sender's congestion control is waiting for.
 */

#include "librats/bittorrent/utp_packet.h"
#include "librats/core/address.h"
#include "librats/core/bytes.h"

#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>

namespace librats::bittorrent::utp {

// ---- Tunables, all matching libtorrent's shipping defaults --------------------

/// LEDBAT's target queuing delay. Above it we shrink the window, below it we grow:
/// this single number is what makes uTP yield to TCP rather than compete with it.
constexpr int kTargetDelayUs = 100 * 1000;
/// How aggressively the window follows the delay signal (`utp_gain_factor`).
constexpr int kGainFactor = 3000;
/// Floor on the retransmit timeout, so a very short RTT can't produce a hair
/// trigger that mistakes reordering for loss.
constexpr int kMinTimeoutMs = 500;
/// Timeout for the SYN, where there is no RTT estimate to base one on.
constexpr int kConnectTimeoutMs = 3000;
/// Retransmission budgets before the connection is declared dead.
constexpr int kSynResends = 2;
constexpr int kFinResends = 2;
constexpr int kNumResends = 3;
/// What fraction (percent) of the window survives a loss event.
constexpr int kLossMultiplier = 50;
/// The window is cut at most once per this interval, so a burst of losses inside
/// one round trip is charged once rather than collapsing the window to nothing.
constexpr int kCwndReduceTimerMs = 100;
/// Duplicate acks that trigger a fast retransmit.
constexpr int kDupAckLimit = 3;

/// In-order bytes we will hold for a reader that has not drained us, and therefore
/// the largest window we ever advertise. Also the ceiling on throughput: this many
/// bytes per RTT, i.e. ~20 Mbit/s per peer at 100 ms — far more than a single peer
/// in a swarm ever supplies, and small enough that a few hundred connections cannot
/// add up to anything alarming (the buffer is grown on demand, not preallocated).
constexpr std::size_t kRecvBufferCapacity = 256 * 1024;

/// Bytes the writer may queue ahead of what the window will pass. Backpressure
/// above this is reported as WouldBlock and handled by the layer above, which
/// already has a send queue and a high-water mark of its own.
constexpr std::size_t kSendHighWater = 256 * 1024;

/// How long a closed stream is kept around to retransmit its FIN and absorb the
/// peer's last packets before the manager reaps it.
constexpr std::chrono::milliseconds kLinger{3000};

// ---- Delay history -----------------------------------------------------------

/**
 * The lowest delay sample seen recently, used as the zero point for the delay
 * measurements LEDBAT runs on.
 *
 * The two endpoints' clocks are unrelated, so a raw one-way delay sample is a
 * meaningless number — but the *difference* between it and the smallest such
 * sample is real queuing delay. The base has to be able to rise as well as fall or
 * clock drift would slowly convince us the path is permanently congested, hence the ring of
 * per-minute minima rather than a single running minimum. Ported from libtorrent's
 * timestamp_history.
 */
class DelayHistory {
public:
    static constexpr int kHistorySize = 20;   ///< minutes of history

    bool initialized() const noexcept { return num_samples_ != kNotInitialized; }
    /// Record a sample and return it relative to the base. @p step advances the
    /// ring (called once a minute).
    std::uint32_t add_sample(std::uint32_t sample, bool step);
    std::uint32_t base() const noexcept { return base_; }
    /// Shift the whole history, to compensate for observed clock drift.
    void adjust_base(int change);

private:
    static constexpr std::uint16_t kNotInitialized = 0xffff;

    std::uint32_t history_[kHistorySize] = {};
    std::uint32_t base_        = 0;
    std::uint16_t index_       = 0;
    std::uint16_t num_samples_ = kNotInitialized;
};

/// Exponential moving average with a companion average deviation, in the fixed-point
/// form libtorrent uses for its RTT estimator (RFC 6298's SRTT/RTTVAR by another name).
class SlidingAverage {
public:
    void add_sample(int s);
    int  mean() const noexcept { return num_samples_ > 0 ? (mean_ + 32) / 64 : 0; }
    int  avg_deviation() const noexcept { return num_samples_ > 1 ? (deviation_ + 32) / 64 : 0; }
    int  num_samples() const noexcept { return num_samples_; }

private:
    static constexpr int kInvertedGain = 16;
    int mean_        = 0;   ///< fixed point, x64
    int deviation_   = 0;   ///< fixed point, x64
    int num_samples_ = 0;
};

// ---- The stream --------------------------------------------------------------

class Stream;

/// What a Stream needs from whoever owns the socket. Implemented by utp::Manager.
class Host {
public:
    virtual ~Host() = default;
    /// Put one datagram on the wire. Failures are the Host's to swallow — a stream
    /// treats a datagram as sent, and its own retransmit timer as the recovery path.
    virtual void utp_send(const Address& to, const std::uint8_t* data, std::size_t len) = 0;
    /// Ask to be called back at Stream::send_deferred_ack() once the socket's
    /// current receive burst has been fully drained, so a burst of N data packets
    /// costs one ack instead of N.
    virtual void utp_defer_ack(Stream& s) = 0;
};

class Stream {
public:
    using Clock = std::chrono::steady_clock;

    enum class State : std::uint8_t {
        Idle,       ///< created, nothing sent (a responder before its SYN arrives)
        SynSent,    ///< initiator waiting for the SYN-ack
        Connected,  ///< data may flow
        FinSent,    ///< our side is done sending; still acking theirs
        Closed,     ///< dead: reaped by the manager
    };

    enum class Status : std::uint8_t { Ok, WouldBlock, Eof, Error };
    struct IoResult {
        std::size_t bytes  = 0;
        Status      status = Status::WouldBlock;
    };

    /// All callbacks fire on the reactor thread, from inside on_packet()/tick().
    /// An observer may close the stream from within one; it must not delete it
    /// (the manager owns streams and reaps them between callbacks).
    struct Observer {
        virtual ~Observer() = default;
        virtual void on_utp_connected() {}
        virtual void on_utp_readable() {}
        virtual void on_utp_writable() {}
        /// The connection died on its own: reset, timeout, protocol error. An
        /// orderly close by the peer is *not* reported here — it surfaces as Eof
        /// from read(), exactly as a TCP recv() of 0 would.
        virtual void on_utp_error(const std::string& why) {}
    };

    Stream(Host& host, std::uint16_t recv_id, std::uint16_t send_id);
    ~Stream() = default;

    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    void set_observer(Observer* o) noexcept { obs_ = o; }
    /// Does a live user object still own this stream? The manager reaps only
    /// streams nobody is holding.
    bool has_observer() const noexcept { return obs_ != nullptr; }
    /// The user object is going away. Stop delivering callbacks; keep enough state
    /// alive to finish the close handshake.
    void detach() noexcept { obs_ = nullptr; }

    /// Start an outgoing connection: sends the SYN.
    void connect(const Address& to, Clock::time_point now);

    /// Drain in-order received bytes. Eof once the peer's FIN has been reached and
    /// everything before it delivered.
    IoResult read(ByteSpan into);
    /// Queue bytes for transmission, taking as many as the send buffer will hold.
    IoResult write(const ByteView* slices, std::size_t count, Clock::time_point now);
    /// Orderly shutdown: flush what is queued, then FIN. Idempotent.
    void close(Clock::time_point now);
    /// Abort: tell the peer the connection is gone and stop immediately.
    void reset(Clock::time_point now);

    /// Feed one datagram addressed to this stream. Returns false if it was
    /// malformed or did not belong here (the caller may then look elsewhere).
    bool on_packet(const std::uint8_t* data, std::size_t len,
                   const Address& from, Clock::time_point now);
    /// Periodic timer: retransmissions, timeouts, linger expiry.
    void tick(Clock::time_point now);
    /// Emit the acknowledgement that on_packet() deferred (see Host::utp_defer_ack).
    void send_deferred_ack(Clock::time_point now);

    // ---- state ----
    std::uint16_t  recv_id() const noexcept { return recv_id_; }
    std::uint16_t  send_id() const noexcept { return send_id_; }
    const Address& remote()  const noexcept { return remote_; }
    State          state()   const noexcept { return state_; }
    bool           connected() const noexcept { return state_ == State::Connected || state_ == State::FinSent; }
    /// True once nothing more will happen here and the manager may destroy it.
    bool           reapable(Clock::time_point now) const noexcept;
    /// Does this datagram belong to this stream? Both the id and the sender must
    /// match, so a third party cannot inject into a connection by guessing an id.
    bool           matches(const Address& from, std::uint16_t id) const noexcept {
        return id == recv_id_ && from == remote_;
    }

    // ---- introspection, for tests and logging ----
    std::size_t   bytes_in_flight()  const noexcept { return bytes_in_flight_; }
    std::size_t   send_queue_bytes() const noexcept { return pending_bytes_ + bytes_in_flight_; }
    std::uint32_t cwnd()             const noexcept { return std::uint32_t(cwnd_ >> 16); }
    std::uint16_t seq_nr()           const noexcept { return seq_nr_; }
    std::uint16_t ack_nr()           const noexcept { return ack_nr_; }

private:
    /// One packet we have sent and not yet had acknowledged. The payload is kept
    /// (not the datagram): every transmission rebuilds the header, so a retransmit
    /// carries an up-to-date ack_nr, window and SACK rather than a stale snapshot.
    struct OutPacket {
        std::uint16_t     seq  = 0;
        PacketType        type = PacketType::Data;
        Bytes             payload;
        Clock::time_point send_time{};
        std::uint16_t     transmissions = 0;
        bool              acked     = false;
        bool              in_flight = false;  ///< counted in bytes_in_flight_
    };

    // ---- sending ----
    void send_syn(Clock::time_point now);
    void send_state(Clock::time_point now);            ///< a pure ack
    void send_reset_packet(Clock::time_point now);
    /// Build and transmit one packet from outbuf_, (re)writing its header.
    void transmit(OutPacket& p, Clock::time_point now);
    /// Move as much of pending_ into flight as the windows allow.
    void pump(Clock::time_point now);
    /// Assemble a datagram into scratch_ and hand it to the host.
    void emit(PacketType type, std::uint16_t seq, const std::uint8_t* payload,
              std::size_t payload_len, Clock::time_point now, bool with_sack);
    std::size_t write_sack(std::uint8_t* out) const;
    bool        has_sack() const noexcept { return !inbuf_.empty(); }
    /// Register with the host for one acknowledgement at the end of the current
    /// receive burst. Idempotent, so N data packets still cost exactly one ack.
    void        defer_ack();

    // ---- receiving ----
    /// Apply a cumulative ack, popping everything it covers off outbuf_.
    void process_ack(std::uint16_t ack_nr, Clock::time_point now,
                     int& acked_bytes, std::uint32_t& min_rtt);
    /// Apply a selective ack bitmap; may trigger fast retransmits.
    void process_sack(std::uint16_t packet_ack, const std::uint8_t* bitmap, std::size_t len,
                      Clock::time_point now, int& acked_bytes, std::uint32_t& min_rtt);
    void ack_packet(OutPacket& p, Clock::time_point now, std::uint32_t& min_rtt);
    void pop_acked_front();
    OutPacket* packet_at(std::uint16_t seq);
    /// Deliver payload in order, draining the reorder buffer behind it.
    void consume_data(const Header& h, const std::uint8_t* payload, std::size_t len);
    void deliver(const std::uint8_t* data, std::size_t len);

    // ---- congestion control ----
    void do_ledbat(int acked_bytes, int delay, int in_flight);
    void experienced_loss(std::uint16_t seq, Clock::time_point now);
    int  packet_timeout() const;
    void resend(OutPacket& p, Clock::time_point now, bool fast);

    void fail(const std::string& why);
    /// Bytes the peer says it can still take, intersected with what we may send.
    std::size_t window_available() const noexcept;
    std::uint32_t advertised_window() const noexcept;

    Host&     host_;
    Observer* obs_ = nullptr;

    std::uint16_t recv_id_;
    std::uint16_t send_id_;
    Address       remote_{};
    State         state_ = State::Idle;

    // ---- sequence state ----
    std::uint16_t seq_nr_       = 0;  ///< sequence number of the next packet we send
    std::uint16_t acked_seq_nr_ = 0;  ///< highest of ours acknowledged in order
    std::uint16_t ack_nr_       = 0;  ///< highest of theirs received in order
    std::uint16_t fast_resend_seq_nr_ = 0;  ///< nothing below this is fast-resent again
    std::uint16_t loss_seq_nr_  = 0;  ///< a loss past this cuts the window again
    int           duplicate_acks_ = 0;

    bool          in_eof_ = false;         ///< their FIN arrived
    std::uint16_t in_eof_seq_nr_ = 0;      ///< the sequence number it carried
    bool          out_eof_ = false;        ///< our FIN has been queued
    bool          error_ = false;
    /// The writer was told WouldBlock and is waiting to be woken. Without this the
    /// layer above would sit on a full queue after the window reopened.
    bool          write_blocked_ = false;
    /// Zero-window persist is in progress: pump() may put one packet on the wire
    /// even though the peer says it has no room. See window_available().
    bool          probe_ = false;
    /// Datagrams emitted, ever. Only the *change* across one incoming packet is
    /// used — to tell whether an ack already rode out on a data packet.
    std::uint32_t out_packets_ = 0;

    // ---- send side ----
    /// Payload chunks not yet given a sequence number. All but the last are full
    /// (kMaxPayload); the last stays open so successive small writes coalesce into
    /// one packet instead of one packet each — Nagle, without a timer.
    std::deque<Bytes>     pending_;
    std::size_t           pending_bytes_ = 0;
    std::deque<OutPacket> outbuf_;   ///< outbuf_[i].seq == acked_seq_nr_ + 1 + i
    std::size_t           bytes_in_flight_ = 0;

    // ---- receive side ----
    std::deque<Bytes> recv_q_;             ///< in-order bytes waiting for the reader
    std::size_t       recv_head_ = 0;      ///< bytes already consumed from recv_q_.front()
    std::size_t       recv_bytes_ = 0;
    std::unordered_map<std::uint16_t, Bytes> inbuf_;  ///< out-of-order, keyed by seq
    std::size_t       inbuf_bytes_ = 0;

    // ---- congestion control / timing ----
    std::int64_t      cwnd_ = 0;        ///< bytes, fixed point with 16 fractional bits
    std::int32_t      ssthresh_ = 0;
    bool              slow_start_ = true;
    std::uint32_t     adv_wnd_ = kMaxPayload;  ///< the peer's advertised window, bytes
    SlidingAverage    rtt_;
    DelayHistory      their_delay_hist_;  ///< our measurement of their one-way delay
    DelayHistory      delay_hist_;        ///< the delay they measured, reflected to us
    /// The last few delay readings. LEDBAT uses the smallest of them, because a
    /// single sample is as likely to record a scheduling hiccup at either end as
    /// anything about the path.
    static constexpr int kDelaySampleCount = 3;
    std::uint32_t     delay_samples_[kDelaySampleCount] = {0xffffffffu, 0xffffffffu, 0xffffffffu};
    int               delay_sample_idx_ = 0;
    std::uint32_t     reply_micro_ = 0;   ///< what we put in timestamp_difference
    Clock::time_point last_history_step_{};
    Clock::time_point timeout_{};         ///< retransmission deadline
    Clock::time_point next_loss_{};       ///< earliest the window may be cut again
    Clock::time_point closed_at_{};       ///< when linger started
    int               num_timeouts_ = 0;
    /// Have we ever heard from this endpoint? A stream that has not is dropped on
    /// its first timeout: the address may simply have been made up by whoever
    /// handed it to us, and there is no reason to spend retransmissions on it.
    bool              confirmed_ = false;
    bool              deferred_ack_ = false;

    /// Reused datagram assembly buffer, so a packet costs no allocation.
    std::uint8_t scratch_[kMaxDatagram] = {};
};

} // namespace librats::bittorrent::utp
