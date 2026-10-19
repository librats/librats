#pragma once

/**
 * @file udp_recovery.h
 * @brief Loss recovery, congestion control and pacing for one datagram connection.
 *
 * Everything here is about *packets*, never about what is in them. A packet is a
 * number, a size, a send time and an opaque list of SentFrames; when its fate is
 * known — acknowledged, or given up on — that list goes back to the connection
 * (FrameSink), which knows what the frames meant: stream data now delivered or to
 * be sent again, a window update to repeat. The split is RFC 9002's, and it is
 * what lets the same machinery serve every kind of frame.
 *
 * ── Why packet numbers make this simpler ─────────────────────────────────────
 * A packet is sent exactly once. What is lost is re-sent as new frames in a new
 * packet with a new number, so an acknowledgement is never ambiguous: there is no
 * retransmission whose round trip cannot be measured (Karn's rule has nothing to
 * guard against) and no repair to judge apart from first transmissions. Numbers
 * rise with send time, which makes every loss test monotone in the number.
 *
 * ── What is here ─────────────────────────────────────────────────────────────
 *   - The sent log: one entry per packet, indexed by number, so an ACK range
 *     resolves to positions by subtraction. Runs already acknowledged are stepped
 *     over in one hop (skip pointers), so an ACK costs what it newly acknowledges,
 *     not the window it repeats.
 *   - RTT estimation (RFC 6298 smoothing, RFC 9002 ack-delay adjustment), one
 *     sample per ACK from its largest packet when that one is new; and, per
 *     round trip, whether the queue at the bottleneck stood through it.
 *   - Loss detection (RFC 8985 RACK): lost once three later packets have arrived,
 *     or once a round trip and a reordering window have passed since it left with
 *     a later one delivered — on a timer of its own, so the last packets of a
 *     burst do not wait for a probe. A packet given up on whose acknowledgement
 *     still comes was only overtaken: from then on the count is no evidence and
 *     the window covers how late it was (RFC 8985 §6.2), for every kind of data
 *     (see counts_packets()). Such a loss is no loss rate either: path_lost()
 *     leaves it out.
 *   - Congestion episodes: one reduction per episode, however many packets it
 *     loses; it ends once what it lost has been delivered again — its last repair
 *     acknowledged, nothing still owed: NewReno's recovery point in packet
 *     numbers. That absorbs what the round trip before the reduction loses too
 *     (RFC 9002's "a loss of a packet sent after the episode began starts a new
 *     one" halves a slow-start overshoot twice).
 *     Proportional rate reduction (RFC 6937) for a controller that asks for it.
 *   - One loss timer with two meanings: a probe timeout while probes are left —
 *     the silence after a tail loss is a question, answered with one packet — and
 *     then the retransmission timeout, which writes off the flight and backs off.
 *   - The pacer: a token bucket a millisecond deep, bounded to kPaceMaxBurst per
 *     release, keeping the lateness of a coarse host clock (see pace_accrue).
 *
 * Like everything on this path it holds no locks, never reads the clock (every
 * entry point takes `now`), and belongs to one connection on one reactor thread.
 */

#include "librats/core/ring_buffer.h"
#include "librats/core/types.h"
#include "librats/transport/congestion_control.h"
#include "librats/transport/delivery_rate.h"
#include "librats/transport/udp_wire.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace librats {
namespace udp {

/// What one sent packet carried that its fate decides. Opaque to Recovery, and
/// kept small: there is one for every frame in flight.
struct SentFrame {
    enum Kind : uint8_t {
        Stream,       ///< `length` bytes of stream `stream` at `offset`
        Live,         ///< `length` bytes of live message `offset`, `at` bytes into it
        LiveRepair,   ///< repair symbol `at` of live message `offset`, `length` bytes
        MaxData,      ///< a window update for `offset` bytes
        DataBlocked,  ///< "stopped at `offset`"
        ResetToken,
        Ping,
        Ack,          ///< an ACK whose largest packet was `offset`
    };
    Kind     kind   = Stream;
    uint8_t  stream = 0;
    uint16_t length = 0;   ///< never more than a packet
    uint32_t at     = 0;
    uint64_t offset = 0;

    /// Whether it carried data a probe may repeat.
    bool carries_data() const noexcept { return kind == Stream || kind == Live || kind == LiveRepair; }
};
static_assert(sizeof(SentFrame) == 16, "one per frame in flight: keep it small");

/// Where a packet's frames go once its fate is known.
class FrameSink {
public:
    virtual ~FrameSink() = default;
    virtual void frames_acked(const RingBuffer<SentFrame>& log, size_t first, size_t count) = 0;
    virtual void frames_lost(const RingBuffer<SentFrame>& log, size_t first, size_t count) = 0;
    /// Data given up on is still waiting to be sent again: a loss episode is not
    /// over while what it lost is still owed.
    virtual bool repairs_pending() const = 0;
};

class Recovery {
public:
    using Clock = std::chrono::steady_clock;

    // ── Timing ──────────────────────────────────────────────────────────────

    /// The loss timer before any round trip has been measured.
    static constexpr std::chrono::milliseconds kInitialRto{500};
    static constexpr std::chrono::milliseconds kMinRto{100};
    static constexpr std::chrono::milliseconds kMaxRto{6000};
    /// How long a receiver may hold an acknowledgement back — ours (see
    /// UdpConnection::kDelayedAck), and what we assume of the peer: it is in every
    /// timeout, and caps the delay a peer may claim in an ACK (RFC 9002 §5.3).
    static constexpr std::chrono::milliseconds kMaxAckDelay{20};
    /// Consecutive retransmission timeouts with nothing acknowledged in between
    /// before the peer is declared gone. Doubling to the 6 s cap, about a minute.
    static constexpr int kMaxTimeouts = 12;
    /// Packets that must arrive behind one before it counts as lost — the classic
    /// duplicate-ack threshold (RFC 9002 kPacketThreshold) — until the path is
    /// seen to reorder.
    static constexpr uint64_t kReorderThreshold = 3;
    /// Loss episodes with no packet turning up after it was given up on, before
    /// the reordering learnt is forgotten (RFC 8985 §6.2's 16 recoveries): what a
    /// path did once costs every later loss a slower detection.
    static constexpr int kReorderMemory = 16;
    /// A standing queue is measured from the least round trip of this window and
    /// the one before (see queue_stood()): a path whose own delay grows reads as a
    /// queue for two windows at most, where the all-time minimum would make it one
    /// for good.
    static constexpr std::chrono::seconds kBaseRttWindow{10};

    // ── Tail loss probe (RFC 8985 / RFC 9002 §6.2) ──────────────────────────
    //
    // A loss is noticed by what arrives after it. When the lost packet was the
    // last one there is nothing after it, and the receiver simply falls silent —
    // which for request/response traffic is every message. So the first expiries
    // of the loss timer ask rather than conclude: one packet goes out, past every
    // hole, and the ACK it draws names all of them; only silence after that is
    // treated as a timeout.
    static constexpr int kMaxTailProbes = 2;
    /// Floor for the probe timer: well under kMinRto (a spurious probe costs one
    /// packet, a spurious timeout the window), above the delayed ack it must not race.
    static constexpr std::chrono::milliseconds kMinProbeTimeout{30};

    // ── Pacing ──────────────────────────────────────────────────────────────
    //
    // A window is permission to have bytes outstanding, not to put them on the
    // wire back to back: a whole window at line rate is what turns a full queue
    // into a hundred drops. So packets leave at the controller's pacing rate.

    /// The burst the pacer tolerates, as time: what accrues over one reactor
    /// wake-up. A timer cannot space packets finer than it wakes.
    static constexpr std::chrono::milliseconds kPaceQuantum{1};
    /// Floor for that burst: the classic two packets.
    static constexpr size_t kPaceMinBurst = 2 * kMaxDatagram;
    /// Ceiling for one release, whatever the rate: one release leaves at line rate,
    /// and a shallow queue in front of the bottleneck drops what it cannot hold.
    /// On a real path (a VPS 33 ms away) a train of 96 datagrams arrived whole and
    /// one of 128 lost everything past the ~120th. 64 KiB is also one segmentation-
    /// offload send, and what Linux holds a TCP burst to. A host whose timer cannot
    /// wake often enough is allowed more (see pace_accrue).
    static constexpr size_t kPaceMaxBurst = 64 * 1024;

    Recovery(CongestionAlgorithm algorithm, Clock::time_point now, uint64_t seed);

    Recovery(const Recovery&) = delete;
    Recovery& operator=(const Recovery&) = delete;

    // ── Sending ─────────────────────────────────────────────────────────────

    uint64_t next_pn() const noexcept { return next_pn_; }
    /// The largest packet number the peer has acknowledged, if any — what the next
    /// packet number's encoded length is chosen against.
    bool     have_largest_acked() const noexcept { return have_largest_acked_; }
    uint64_t largest_acked() const noexcept { return largest_acked_; }

    /// The connection is about to look for something to send: let the controller
    /// see the opportunity, and top up the pacer.
    void begin_sending(Clock::time_point now, bool has_data);

    /// The congestion window has room for `bytes` more — or the path is empty, or
    /// proportional rate reduction has earned them.
    bool cwnd_allows(size_t bytes) const noexcept;
    /// The pacer would release `bytes` now.
    bool pace_allows(size_t bytes) const noexcept;
    /// The pacer is what holds the next `bytes` back: wake the connection when it
    /// will have released them (part of deadline()).
    void hold_for_pacer(Clock::time_point now, size_t bytes) noexcept;
    void clear_pacer_hold() noexcept { pace_due_ = Clock::time_point{}; }

    /// Packet `next_pn()` of `bytes` just left, carrying the frames add_frame()
    /// recorded since the last one. `data` says it carries stream data — what the
    /// controller hears of; a packet of control frames alone is in flight but no
    /// sign of a sender with something to say. `repair` says the data is being
    /// sent again, which in an episode gets a loss timer of its own; `probe` that
    /// it answers a probe timeout.
    void on_packet_sent(Clock::time_point now, size_t bytes, bool ack_eliciting, bool data,
                        bool repair, bool probe);

    /// Record a frame for the packet being built.
    void add_frame(const SentFrame& f) { frames_.push_back(f); }
    /// Drop the frames recorded for a packet that was not sent after all.
    void cancel_frames() noexcept;

    /// After a round of sending: whether data was left waiting with the window the
    /// only thing in its way, and whether there was nothing left to send at all
    /// (which makes the next rate samples measure the application, not the path)
    /// — with data waiting all the same, held by the peer.
    void note_send_limits(bool data_waiting, bool window_stopped, bool nothing_to_send);

    // ── Acknowledgements ────────────────────────────────────────────────────

    /// Apply an ACK. False — and nothing applied — when it acknowledges a packet
    /// that was never sent: the peer is broken or lying, a protocol error.
    bool on_ack(const AckFrame& ack, Clock::time_point now, FrameSink& sink);

    /// A round trip measured outside the sent log: the handshake's.
    void sample_rtt(Clock::duration rtt, Clock::duration ack_delay);

    // ── The loss timer ──────────────────────────────────────────────────────

    enum class Timeout {
        None,      ///< nothing was due
        Probe,     ///< send one ack-eliciting packet now, past whatever the window says
        Collapsed, ///< the flight was written off; what was in it is in the sink
        GiveUp,    ///< the peer has stopped answering for good
    };

    /// When on_timer() next has work: the loss timer, RACK's reorder timer, or the
    /// pacer's release.
    std::optional<Clock::time_point> deadline() const noexcept;
    Timeout on_timer(Clock::time_point now, FrameSink& sink);

    /// Something is waiting to be sent that will not keep — a live message — so
    /// the moment a dead path comes back matters more than how cheaply it is
    /// probed while it is gone. After a timeout the loss timer then waits no more
    /// than a probe timeout (and kMinRto) however far it has backed off: one
    /// packet that often, where backing off would leave a path that returned after
    /// a one-second outage unnoticed for up to as long again — every live message
    /// in that time lost for nothing. Such a timeout does not count towards giving
    /// up; the connection's idle timeout still ends a path that never answers.
    /// Loss is judged as for anything else: what the path has shown of its
    /// reordering is a fact about the path, whatever is waiting to cross it.
    void set_impatient(bool impatient) noexcept;

    /// Frames of the newest packet still in flight that carried data — what
    /// a probe with nothing new to say repeats, so its acknowledgement lands past
    /// every hole in front of it. False when there is none.
    bool newest_in_flight(size_t& first, size_t& count) const noexcept;
    const RingBuffer<SentFrame>& frames() const noexcept { return frames_; }

    // ── State ───────────────────────────────────────────────────────────────

    uint32_t cwnd() const noexcept { return cc_->cwnd(); }
    size_t   bytes_in_flight() const noexcept { return flight_bytes_; }
    bool     in_recovery() const noexcept { return in_recovery_; }
    const cc::CongestionController& congestion() const noexcept { return *cc_; }
    const cc::RttEstimate&          rtt() const noexcept { return rtt_; }
    const cc::DeliveryRateSampler&  sampler() const noexcept { return sampler_; }
    /// Whether the queue at the bottleneck stood through the whole of the last
    /// round trip: no round trip in it (the peer's ack delay off) came back within
    /// cc::queue_threshold() of the least of the last kBaseRttWindow or two. The
    /// bottleneck had no idle moment then — whatever is sent on top waits behind
    /// a queue, or overflows it.
    bool queue_stood() const noexcept { return queue_stood_; }
    /// The timeout a probe or a handshake retransmission waits: a round trip, the
    /// variance allowance and the peer's ack delay.
    Clock::duration probe_timeout() const noexcept;
    /// How long after a packet is sent an acknowledgement of it can still tell
    /// this end anything: its round trip, the most a reordering window waits, and
    /// an ack delay. A packet given up on stays in the log that long; a receiver
    /// keeps a hole open as long for the packet that is late.
    Clock::duration reorder_horizon() const noexcept;

    /// Packets declared lost, plus probes sent — packets the sender had to send
    /// because an earlier one went unanswered.
    uint32_t retransmits() const noexcept { return lost_packets_ + probes_; }
    /// Bytes of the losses in sampler() that timeouts wrote off: what outages
    /// took, as opposed to the loss rate of a path that answers.
    uint64_t written_off() const noexcept { return written_off_; }
    /// Bytes of the losses in sampler() acknowledged after all: reordered, not lost.
    uint64_t spurious() const noexcept { return spurious_; }
    /// The losses in sampler() that the path's own loss rate is made of: less
    /// what outages took and what was only reordered.
    uint64_t path_lost() const noexcept { return sampler_.lost() - written_off_ - spurious_; }
    /// How long after a later packet's round trip one is still given to arrive
    /// before it counts as lost.
    Clock::duration reorder_window() const noexcept;
    /// Whether kReorderThreshold later packets acknowledged make one lost, before
    /// its window is up. Not once a path has overtaken a packet by more: what it
    /// overtakes it by follows the sending rate, so a count learnt at one rate is
    /// beaten at the next (as Linux and RFC 8985 do, only the window judges then).
    /// Live data waits it out too. Judged by the default bars instead, a path that
    /// reorders every few packets — per-packet jitter, a bonded link — had up to
    /// half a video stream sent twice and every overtaken packet reported to BBR as
    /// congestion, which cut its estimate below the stream's rate: frames expired
    /// in the queue. What waiting costs a frame with little time left is FEC's to
    /// cover (UdpConnection::live_repairs counts the window in).
    bool counts_packets() const noexcept { return !reordering_seen_; }
    /// Times the controller was told about congestion: once per loss episode, plus
    /// once per retransmission timeout.
    uint32_t congestion_events() const noexcept { return congestion_events_; }
    int      tail_probes() const noexcept { return tail_probes_; }

    /// The peer is reached over another path from here on (its IP changed — see
    /// udp_connection.h, "Migration"). Nothing learnt of the old one describes
    /// it: the controller and the round trip start again, and what is in flight
    /// is written off, so its data goes again on the new path — news to neither
    /// controller. It leaves the log with that, so an acknowledgement of it that
    /// still comes is no sample of anything.
    void on_new_path(Clock::time_point now, FrameSink& sink);

    /// Forget everything outstanding (the connection is gone).
    void clear() noexcept;
    /// Give back the logs' memory if nothing is outstanding. Losses kept to see
    /// whether they were only late have had their chance by now.
    void release_memory() noexcept;

private:
    struct SentPacket {
        cc::TxState tx;               ///< delivery-rate snapshot, `sent_at` included
        uint64_t    skip = 0;         ///< once acked: a number past which every packet is acked too
        uint64_t    frames_at = 0;    ///< absolute index of its first frame
        uint32_t    bytes = 0;
        uint16_t    frame_count = 0;
        bool        ack_eliciting = false;
        bool        in_flight = false;
        bool        acked = false;
        /// Declared lost by RACK rather than written off by a timeout: kept in the
        /// log a while, since an acknowledgement that still comes says the path
        /// reordered it (see on_spurious_loss).
        bool        rack_lost = false;
    };

    SentPacket* at(uint64_t pn) noexcept;
    /// Position of the first packet at or after `idx` not acknowledged yet, in
    /// amortised constant time (skip pointers with path compression).
    size_t next_unacked(size_t idx) noexcept;
    void   on_newly_acked(uint64_t pn, SentPacket& pkt, Clock::time_point now, FrameSink& sink);
    /// True if it declared anything lost.
    bool   detect_losses(Clock::time_point now, FrameSink& sink);
    /// `rack`: declared by RACK, not written off — see SentPacket::rack_lost.
    void   mark_lost(SentPacket& pkt, Clock::time_point now, FrameSink& sink, bool rack);
    /// A packet declared lost has been acknowledged after all.
    void   on_spurious_loss(SentPacket& pkt, Clock::time_point now) noexcept;
    /// `newest_lost`: the latest packet number among those just declared lost.
    void   congestion_event(Clock::time_point now, uint64_t newest_lost);
    /// The round trip is over: judge whether its queue stood, start the next.
    void   end_round(Clock::time_point now) noexcept;
    void   retire_front(Clock::time_point now) noexcept;
    void   pop_front() noexcept;
    void   hand_over(const SentPacket& pkt, bool acked, FrameSink& sink);

    uint64_t prr_share(uint64_t delivered) const noexcept;
    void     pace_accrue(Clock::time_point now);
    Clock::duration pace_wait(size_t bytes) const noexcept;
    Clock::duration estimated_rto() const noexcept;
    /// The probe timeout before any doubling.
    Clock::duration base_probe_timeout() const noexcept;
    Clock::duration loss_timeout() const noexcept;
    /// What the loss timer waits once probing is over: the backed-off timeout, or
    /// less when impatient.
    Clock::duration timeout_wait() const noexcept;
    Clock::duration impatient_wait() const noexcept;
    /// The most a reordering window may wait (see reorder_window()).
    Clock::duration max_reorder_window() const noexcept;
    void            arm_loss_timer(Clock::time_point from) noexcept;
    void            rearm(Clock::time_point now) noexcept;

    cc::RttEstimate                           rtt_;
    cc::DeliveryRateSampler                   sampler_;
    std::unique_ptr<cc::CongestionController> cc_;
    CongestionAlgorithm                       algorithm_;   ///< what on_new_path() starts again
    uint64_t                                  seed_;

    // — round trips: the queue at the bottleneck (queue_stood()) —
    uint64_t          round_end_ = 0;   ///< the delivered total that ends this round trip
    Clock::duration   round_rtt_ = (Clock::duration::max)();   ///< its least, ack delay off
    /// The least round trip of this kBaseRttWindow and of the one before.
    Clock::duration   base_rtt_[2] = {(Clock::duration::max)(), (Clock::duration::max)()};
    Clock::time_point base_since_{};    ///< when base_rtt_[0]'s window began
    bool              queue_stood_ = false;

    // — the sent log: sent_[i] is packet log_base_ + i —
    RingBuffer<SentPacket> sent_;
    RingBuffer<SentFrame>  frames_;
    uint64_t         log_base_    = 0;
    uint64_t         frames_base_ = 0;   ///< absolute index of frames_[0]
    uint64_t         frames_mark_ = 0;   ///< absolute index where the packet being built starts
    uint64_t         next_pn_     = 0;
    size_t           flight_bytes_ = 0;
    size_t           in_flight_packets_ = 0;

    // — loss detection —
    uint64_t          largest_acked_ = 0;
    bool              have_largest_acked_ = false;
    /// Send time of the newest packet known delivered (RACK's reference point),
    /// and the round trip that delivery took.
    Clock::time_point rack_sent_at_{};
    Clock::duration   rack_rtt_{};
    /// When the first packet RACK is still giving time to will have had it.
    Clock::time_point reorder_deadline_{};
    /// Everything below this has been judged; the scan resumes here.
    uint64_t          loss_scan_ = 0;
    /// The latest past RACK's reference a packet given up on has turned up, and
    /// whether any has.
    Clock::duration   reorder_late_{};
    uint64_t          spurious_ = 0;
    int               episodes_since_reorder_ = 0;
    bool              reordering_seen_ = false;

    // — episodes —
    bool     in_recovery_      = false;
    /// The last packet sent when the latest episode began: what was sent up to it
    /// went into the congestion the episode answers, and grows no window.
    uint64_t episode_start_pn_ = 0;
    /// The last repair the episode sent (0: none yet). It is over once that is
    /// acknowledged — and something sent after it began — with nothing still owed.
    uint64_t last_repair_pn_   = 0;
    bool     had_episode_      = false;
    bool     timeout_recovery_ = false;   ///< a timeout, and the path has not answered since
    /// The episode began with a timeout: it runs in slow start rather than PRR, so
    /// what was sent after it grows the window, and a loss of that opens a new one.
    bool     timeout_episode_  = false;
    uint64_t recovery_credit_  = 0;       ///< PRR's sends earned and not spent
    uint64_t recover_fs_       = 0;       ///< PRR's RecoverFS
    uint64_t ack_prior_flight_ = 0;       ///< in flight when the ACK being applied arrived
    uint64_t ack_newly_acked_  = 0;
    uint64_t ack_newly_clean_  = 0;
    uint64_t lost_since_ack_   = 0;
    uint64_t written_off_      = 0;
    bool     cwnd_limited_     = false;
    bool     peer_limited_     = false;   ///< AckEvent::peer_limited, since the last ACK

    // — the loss timer —
    Clock::time_point loss_deadline_{};    ///< epoch = not running
    Clock::time_point loss_armed_at_{};    ///< what loss_deadline_ was measured from
    bool              impatient_ = false;
    Clock::time_point last_eliciting_sent_{};
    int               tail_probes_ = 0;
    int               timeouts_    = 0;    ///< consecutive, with no progress between

    // — pacing —
    uint64_t          pace_tokens_ = 0;
    Clock::time_point pace_last_{};
    Clock::time_point pace_due_{};         ///< epoch = holding nothing back
    /// How late the connection typically gets to a release it was holding: what
    /// tells a host with a coarse timer from one that was late once.
    Clock::duration   pace_late_{};

    uint32_t lost_packets_ = 0;
    uint32_t probes_       = 0;
    uint32_t congestion_events_ = 0;
};

} // namespace udp
} // namespace librats
