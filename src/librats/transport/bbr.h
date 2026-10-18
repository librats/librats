#pragma once

/**
 * @file bbr.h
 * @brief BBRv3 congestion control (draft-ietf-ccwg-bbr), for the datagram transport.
 *
 * ── The idea ─────────────────────────────────────────────────────────────────
 * A loss-based controller learns the path's capacity by overflowing it: it grows
 * until a queue somewhere drops a packet, then backs off. That has two costs a
 * peer-to-peer node feels constantly. Every queue on the path is kept full (so
 * every small message waits behind it), and every loss — including the ones a
 * Wi-Fi or mobile link produces with no congestion at all — halves the rate.
 *
 * BBR instead keeps a *model* of the path: the bottleneck bandwidth (the highest
 * delivery rate recently measured) and the round-trip propagation delay (the
 * lowest round trip recently measured). Their product is the bandwidth-delay
 * product, which is exactly how much data the path holds without a queue. The
 * sender paces at the measured bandwidth and keeps about that much in flight, and
 * moves the estimates by deliberately probing:
 *
 *   Startup      pacing gain 2.77: double the rate every round trip until the
 *                delivery rate stops growing (three rounds below +25%) or loss
 *                passes the threshold. The model is then full.
 *   Drain        pacing gain 0.35: let the queue Startup built drain away.
 *   ProbeBW      the steady state, a cycle of four phases:
 *     DOWN       pace at 0.9x to drain any queue left by the last probe;
 *     CRUISE     pace at 1.0x, keeping some headroom under `inflight_hi`;
 *     REFILL     one round at 1.0x with the short-term bounds lifted;
 *     UP         pace at 1.25x and raise `inflight_hi` exponentially, until the
 *                bandwidth plateaus or loss passes the threshold.
 *                A probe happens every 2–3 s, or sooner when a Reno flow sharing
 *                the bottleneck would have grown its window by then — that is
 *                what keeps BBR from starving loss-based neighbours.
 *   ProbeRTT     every 5 s without a fresh minimum, hold inflight to half a BDP
 *                for 200 ms and one round, so the queue empties and the true
 *                propagation delay can be measured again.
 *
 * ── What v3 adds over the original BBR ───────────────────────────────────────
 * The original ignored loss entirely, which made it unfair to Reno/CUBIC and made
 * it retransmit heavily into shallow buffers. v3 keeps two pairs of bounds:
 *
 *   - long-term (`inflight_hi`, plus the 2-cycle max bandwidth filter): the
 *     inflight at which loss passed 2% during the last probe, cut to 0.7x of the
 *     target when it does. Probing raises it again, slowly at first;
 *   - short-term (`bw_lo`, `inflight_lo`): when a round between probes sees any
 *     loss, both are cut to 0.7x (or to what was just delivered, if more), and
 *     reset when the next probe starts.
 *
 * Loss below the 2% threshold moves neither bound during a probe: that is what
 * lets BBR hold its rate on a lossy but uncongested link — up to 2%. Past that
 * every probe of the draft ends on its first acknowledgements and the estimate
 * stays wherever Startup left it (on a radio that loses 5%, a bulk transfer
 * held half the path). So the 2% here are counted over the loss the path has
 * by itself: the least that a few stretches of rounds spent cruising, under the
 * bounds and with no queue, lose (loss_base()), widened by the spread a flight
 * that size shows at that rate. A path that loses nothing on its own gets the
 * draft's threshold exactly.
 *
 * ── Flows that do not fill the pipe ──────────────────────────────────────────
 * The draft's model is built from samples of a sender that has more to send:
 * an app-limited sample says only "at least this fast", so it may raise the
 * bandwidth estimate and never set it. For a flow that is app-limited nearly
 * all the time — live video, a call: a burst per frame, a bigger one per
 * keyframe, idle in between — that leaves the state machine waiting for
 * evidence that never comes. So these read what such a flow does measure as
 * well as any — the queueing delay (the round trip less the peer's ack delay,
 * over the minimum; "queued" past clamp(min_rtt/8, 4, 16 ms), HyStart++'s
 * threshold, so jitter does not count) and the inflight a packet left with:
 *
 *   - An app-limited burst of ours that queues at the bottleneck — more than a
 *     BDP and at least the starting window in flight, and the round trip lifted
 *     by it past max(min_rtt/4, 10 ms) — counts as the plateau: it ends a
 *     bandwidth probe, and read more strictly, Startup. The plateau test proper
 *     needs non-app-limited samples such a flow never produces; without this
 *     every keyframe would leave at Startup's 2.77x the bandwidth already found,
 *     into a buffer it overflows, and a probe would last until loss ended it.
 *     The bar is higher than "queued": a few small messages early on (identify,
 *     a request) are more than the BDP their own rate implies — read by the
 *     lower bar, they ended Startup at a few KB/s. One sample past it ends a
 *     probe: missing a queue there costs frames, a false one only the probe.
 *     Startup ends once and for good, and a radio's jitter — a packet held
 *     15–30 ms, those behind it with it — lifts single samples past any such
 *     bar: ended by that, a call stayed at the 1–2 Mbit/s Startup had reached.
 *     So Startup wants what jitter does not do (startup_queued): the round trip
 *     rising group after group of acknowledgements, as our burst fills a queue
 *     (jitter lifts one, and those it held fall back), or standing far above the
 *     minimum for a while, as our queue does on a slow link, where a frame is
 *     too few acknowledgements to rise in and does not drain before the next.
 *   - ProbeRTT is skipped while app-limited round trips keep coming in within
 *     1/8 of the minimum (as Chromium's BBR does): the queue it would drain was
 *     empty anyway, and holding inflight to half a BDP for 200 ms is a lost
 *     keyframe for nothing.
 *   - The max-bandwidth filter ages at the end of a probe cycle that measured
 *     the path against a queue — a sample not app-limited that waited in one —
 *     not only when the acknowledgement at that instant is not app-limited: for
 *     a flow in and out of being app-limited the instant is a coin toss, and
 *     losing it every time kept a pre-drop estimate alive indefinitely.
 *   - Loss in a round whose queue emptied at some point and whose losses left
 *     with less than a BDP in flight, by a sender that keeps running dry, is not
 *     a full queue's — the bottleneck idles (loss_is_congestion()). It does not
 *     cut the short-term bounds, end a probe or lower inflight_hi, and recovery
 *     does not cut the window to what is in flight. Cutting the bounds paced the
 *     sender's bursts and repairs down to its own average rate — under 5%
 *     random loss, below the rate of the video; and the window of such a sender
 *     is what it happened to have out between two bursts, so the next keyframe
 *     left at the pace of the acknowledgements of the last frame (on a 100 ms
 *     path with 5% loss, 43% of the frames late). (The price: a policer below
 *     the video's rate, which drops without queueing, is learnt from only by the
 *     packets it drops that left with more than a BDP in flight.) A bulk sender
 *     held by the receiver's window under heavy random loss runs dry too, and
 *     keeps its rate the same way.
 *
 * A bulk flow takes these paths only in the moments it is app-limited too —
 * held by the receiver's window, or in the round after its own ProbeRTT. One
 * change is for every flow: after a timeout the window comes back with the
 * first answer from the path, not as the outage's repairs complete (see on_ack);
 * what the timeout wrote off is not reported to it again as loss (Recovery).
 *
 * ── Fidelity ─────────────────────────────────────────────────────────────────
 * The state machine, gains and constants follow draft-ietf-ccwg-bbr (and Linux's
 * tcp_bbr.c v3 where the draft defers to it). Two adaptations to this transport:
 * there is no ECN signal (the transport does not read ECN marks), and the loss
 * events Startup counts are acknowledgements that reported a new loss, since a
 * packet-numbered transport has no byte-range "discontiguous loss" to count.
 *
 * All windows are in payload bytes; bandwidth is in bytes per second; gains are
 * fixed-point in thousandths (kUnit) so the controller is deterministic across
 * platforms and the path benchmark reproduces bit for bit.
 */

#include "librats/transport/congestion_control.h"

#include <cstdint>

namespace librats {
namespace cc {

class BbrController final : public CongestionController {
public:
    enum class State : uint8_t {
        Startup,
        Drain,
        ProbeBwDown,
        ProbeBwCruise,
        ProbeBwRefill,
        ProbeBwUp,
        ProbeRtt,
    };

    // ── Parameters (draft-ietf-ccwg-bbr §5.1 and Linux tcp_bbr.c v3) ─────────

    /// Fixed-point unit for every gain and fraction below.
    static constexpr uint64_t kUnit = 1000;

    static constexpr uint64_t kStartupPacingGain = 2770;   ///< 4 ln 2: doubles per round
    static constexpr uint64_t kStartupCwndGain   = 2000;
    static constexpr uint64_t kDrainPacingGain   = 350;
    static constexpr uint64_t kProbeBwCwndGain   = 2000;
    static constexpr uint64_t kProbeBwUpCwndGain = 2250;
    static constexpr uint64_t kProbeBwDownGain   = 900;
    static constexpr uint64_t kProbeBwCruiseGain = 1000;
    static constexpr uint64_t kProbeBwRefillGain = 1000;
    static constexpr uint64_t kProbeBwUpGain     = 1250;
    static constexpr uint64_t kProbeRttCwndGain  = 500;
    /// Paced 1% below the estimate, so the sender does not build a queue at the
    /// bottleneck by pacing at exactly its rate.
    static constexpr uint64_t kPacingMargin      = 10;

    /// Loss above this fraction of what was in flight is "too high" (2%) — over
    /// the path's own loss rate (see loss_base()).
    static constexpr uint64_t kLossThresh = 20;
    /// The path's own loss rate is the least of the last kLossBaseWindows stretches
    /// of this much, seen in rounds that measure it: a radio loses in every one of
    /// them, a bottleneck someone else fills only in some.
    static constexpr uint64_t kLossBaseWindow  = 256 * kMss;
    static constexpr int      kLossBaseWindows = 4;
    /// Multiplicative cut applied to a bound on congestion (0.7).
    static constexpr uint64_t kBeta       = 700;
    /// Headroom left under inflight_hi while cruising, for other flows (15%).
    static constexpr uint64_t kHeadroom   = 150;

    /// Bandwidth growth that counts as "still growing" (25%), and how many rounds
    /// without it mean the pipe is full.
    static constexpr uint64_t kFullBwThresh = 1250;
    static constexpr int      kFullBwCount  = 3;
    /// Acknowledgements reporting new loss, in one round of Startup, that end it.
    static constexpr int      kStartupFullLossCount = 6;
    /// Acknowledgements reporting new loss, in one round of a bandwidth probe,
    /// before its loss rate is believed. Not in the draft: this is what Google's
    /// production QUIC BBRv2 does (quiche, probe_bw_full_loss_count). Below ~50
    /// packets in flight 2% is less than one packet, so a single random loss would
    /// read as "too high" — every probe on a lossy, small-BDP path (a phone on
    /// Wi-Fi) would end on its first acknowledgement and inflight_hi would ratchet
    /// down probe after probe. Congestion loss comes in bursts and clears this at
    /// once; an isolated random loss does not.
    static constexpr int      kProbeBwFullLossCount = 2;

    static constexpr uint32_t kMinPipeCwnd = 4 * kMss;

    static constexpr std::chrono::seconds      kMinRttFilterLen{10};
    static constexpr std::chrono::seconds      kProbeRttInterval{5};
    static constexpr std::chrono::milliseconds kProbeRttDuration{200};

    /// Wait between bandwidth probes: kProbeWaitBase plus up to kProbeWaitRand.
    static constexpr std::chrono::seconds kProbeWaitBase{2};
    static constexpr std::chrono::seconds kProbeWaitRand{1};
    /// Ceiling on the Reno-coexistence probe interval, in rounds.
    static constexpr uint64_t kProbeMaxRounds = 63;

    /// The queueing delay that counts as a queue: an eighth of the minimum round
    /// trip, within these bounds (RFC 9406's RTT threshold) — above the jitter a
    /// path shows with nothing queued, below what one burst of ours builds.
    static constexpr std::chrono::milliseconds kQueueMin{4};
    static constexpr std::chrono::milliseconds kQueueMax{16};
    /// What it takes for one app-limited acknowledgement to end a probe
    /// (burst_queued): a burst of at least the starting window, and a queue of a
    /// quarter of the minimum round trip, at least kBurstQueueMin — above what a
    /// host's late timer shows with nothing queued; and a few small messages are
    /// no burst at all.
    static constexpr std::chrono::milliseconds kBurstQueueMin{10};
    /// What it takes to end Startup instead (startup_queued). kQueueRises groups of
    /// acknowledgements in a row, each above the one before and the last past
    /// burst_queued's bar, are a queue our burst is filling; jitter lifts one, and
    /// the ones it held back fall again. A group is the acknowledgements arriving
    /// within kAckGroup of the first, read by the smallest round trip among them:
    /// at 10 Mbit/s, with a fifth of the packets held back, held ones follow one
    /// another closely enough that acknowledgement after acknowledgement rose six
    /// times in a row (a call sized to the estimate reached its rate in 4 runs of
    /// 12 that way, 11 by groups) — a group nearly always holds one that was not
    /// held. And acknowledgements a Wi-Fi station or a batching receiver hands back
    /// in bunches fall along each bunch even while a queue grows.
    static constexpr std::chrono::microseconds kAckGroup{2500};
    static constexpr int                       kQueueRises = 6;
    /// Or a queue that stands: every round trip for kStandingFor at least
    /// kStandingBar (in kUnit) of that bar over the minimum. On a link of a Mbit/s
    /// or two a frame is two or three acknowledgements, too few to rise in, but its
    /// queue does not drain before the next one; jitter lets the packets after the
    /// ones it held through on time.
    static constexpr std::chrono::milliseconds kStandingFor{60};
    static constexpr uint64_t                  kStandingBar = 2500;

    /// Rounds after its last app-limited sample a sender still counts as one that
    /// does not fill the pipe, for whether its loss is congestion: as long as the
    /// longest a probe waits for a Reno flow, so that the few rounds a burst of
    /// repairs keeps a video sender busy do not turn its random loss into cuts.
    static constexpr uint64_t kRanDryRounds = kProbeMaxRounds;

    /// The aggregation estimate is a max over two windows of this many rounds.
    static constexpr int kExtraAckedWindowRounds = 5;
    /// Never provision more than this much extra for aggregation.
    static constexpr std::chrono::milliseconds kExtraAckedMax{100};

    BbrController(const RttEstimate& rtt, const DeliveryRateSampler& sampler,
                  Clock::time_point now, uint64_t seed);

    CongestionAlgorithm algorithm() const noexcept override { return CongestionAlgorithm::Bbr; }
    uint32_t   cwnd() const noexcept override;
    PacingRate pacing_rate() const noexcept override { return PacingRate::per_second(pacing_rate_); }

    void on_packet_sent(Clock::time_point now, uint64_t bytes, uint64_t bytes_in_flight) override;
    void on_rtt_sample(Clock::duration rtt, Clock::duration ack_delay) override;
    void on_packet_lost(const LostPacket& lost) override;
    void on_congestion_event(Clock::time_point now, uint64_t bytes_in_flight,
                             uint64_t newly_acked) override;
    void on_recovery_exit(Clock::time_point now) override;
    void on_timeout(Clock::time_point now, uint64_t bytes_in_flight) override;
    void on_ack(const AckEvent& ack) override;
    bool on_send_opportunity(Clock::time_point now, uint64_t bytes_in_flight, bool has_data,
                             bool app_limited) override;
    bool wants_app_limited() const noexcept override { return state_ == State::ProbeRtt; }
    uint64_t bandwidth() const noexcept override { return bw_; }

    // — diagnostics (tests, benchmarks) —
    State           state()           const noexcept { return state_; }
    uint64_t        max_bw()          const noexcept { return max_bw_; }   ///< bytes/s
    uint64_t        bw()              const noexcept { return bw_; }       ///< bytes/s
    Clock::duration min_rtt()         const noexcept { return min_rtt_; }
    bool            full_bw_reached() const noexcept { return full_bw_reached_; }
    uint64_t        inflight_hi()     const noexcept { return inflight_hi_; }
    uint64_t        inflight_lo()     const noexcept { return inflight_lo_; }
    uint64_t        bw_lo()           const noexcept { return bw_lo_; }
    uint64_t        round_count()     const noexcept { return round_count_; }
    /// Estimated bandwidth-delay product at the current bandwidth estimate.
    uint64_t        bdp()             const noexcept { return bdp_multiple(bw_, kUnit); }
    /// What the path loses whatever the sender does, in thousandths: the least loss
    /// rate of the last stretches of rounds spent cruising with no queue.
    uint64_t        loss_base()       const noexcept;

    static constexpr uint64_t kInfinite = ~uint64_t{0};

    static const char* to_string(State s) noexcept;

private:
    enum class AckPhase : uint8_t {
        Init,
        ProbeStarting,   ///< sent the probe; its acknowledgements are not back yet
        ProbeFeedback,   ///< acknowledgements of the probe are arriving
        ProbeStopping,   ///< probe over; waiting out the round its packets fill
        Refilling,
    };

    // — model and state, in the order the draft runs them per acknowledgement —
    void update_model_and_state();
    void update_latest_delivery_signals();
    void update_congestion_signals();
    void update_round();
    void update_max_bw();
    void update_ack_aggregation();
    void update_queue_signals();
    void check_full_bw_reached();
    void check_startup_done();
    void check_startup_high_loss();
    void check_drain_done();
    void update_probe_bw_cycle_phase();
    bool adapt_upper_bounds();
    void update_min_rtt();
    void check_probe_rtt();
    void handle_probe_rtt();
    void check_probe_rtt_done();
    void advance_latest_delivery_signals();
    void bound_bw_for_model() noexcept;

    // — control parameters —
    void update_control_parameters();
    void set_pacing_rate_with_gain(uint64_t gain);
    void set_cwnd();

    // — states —
    void enter_startup();
    void enter_drain();
    void enter_probe_bw();
    void start_probe_bw_down();
    void start_probe_bw_cruise();
    void start_probe_bw_refill();
    void start_probe_bw_up();
    void enter_probe_rtt();
    void exit_probe_rtt();

    // — probing —
    bool check_time_to_probe_bw();
    bool check_time_to_cruise() const;
    bool is_time_to_go_down();
    bool is_reno_coexistence_probe_time() const;
    void pick_probe_wait();
    void raise_inflight_hi_slope();
    void probe_inflight_hi_upward();
    bool has_elapsed_in_phase(Clock::duration d) const noexcept { return now_ > cycle_stamp_ + d; }

    // — loss —
    /// Loss in `rs` passes the threshold, and the round has seen at least
    /// `min_events` acknowledgements reporting loss (counting the current one).
    bool     is_inflight_too_high(const RateSample& rs, int min_events) const noexcept;
    /// The share of a flight of `flight` bytes that may be lost before it is too
    /// many, in thousandths: kLossThresh over the path's own rate, and over the
    /// spread a flight that size shows at that rate.
    uint64_t loss_thresh(uint64_t flight) const noexcept;
    void     update_loss_base() noexcept;
    void     handle_inflight_too_high(const RateSample& rs);
    uint64_t inflight_at_loss(const RateSample& rs, uint64_t bytes) const noexcept;
    void     init_lower_bounds();
    void     loss_lower_bounds();
    void     adapt_lower_bounds_from_congestion();

    // — resets —
    void reset_congestion_signals() noexcept;
    void reset_short_term_model() noexcept;
    void reset_full_bw() noexcept;
    void start_round() noexcept;
    void advance_max_bw_filter() noexcept;

    // — arithmetic —
    uint64_t bdp_multiple(uint64_t bw, uint64_t gain) const noexcept;
    uint64_t quantization_budget(uint64_t inflight) const noexcept;
    uint64_t inflight(uint64_t bw, uint64_t gain) const noexcept;
    uint64_t inflight_with_headroom() const noexcept;
    uint64_t target_inflight() const noexcept;
    uint64_t probe_rtt_cwnd() const noexcept;
    uint64_t send_quantum() const noexcept;
    uint64_t save_cwnd() const noexcept;
    bool     is_in_probe_bw() const noexcept;
    bool     is_probing_bw() const noexcept;
    bool     cwnd_limited() const noexcept { return cwnd_limited_prev_ || cwnd_limited_now_; }
    /// A round trip, the peer's ack delay taken off, that shows a queue (see
    /// "Flows that do not fill the pipe" above).
    bool     queued(Clock::duration rtt_net) const noexcept;
    /// This acknowledgement is of a burst of ours that could have queued — at
    /// least the starting window in flight, more than the path holds — and has a
    /// round trip to read.
    bool     burst_in_flight() const noexcept;
    /// The queueing delay a burst must show: max(min_rtt/4, kBurstQueueMin).
    Clock::duration burst_bar() const noexcept;
    /// This acknowledgement's sample is an app-limited burst of ours that queued
    /// at the bottleneck: the end of a probe for a flow that never fills the pipe.
    bool     burst_queued() const noexcept;
    /// The same, read strictly enough to end Startup by (kAckGroup, kStandingFor).
    bool     startup_queued() const noexcept;
    /// The sender has run out of things to send within the last kRanDryRounds.
    bool     runs_dry() const noexcept { return ran_dry_ && round_count_ - ran_dry_round_ <= kRanDryRounds; }
    /// Whether the loss being reported can be a full queue's: always, unless the
    /// sender keeps running dry and the loss round so far neither queued nor lost
    /// a packet sent with more than the path holds in flight.
    bool     loss_is_congestion() const noexcept;
    uint64_t random() noexcept;

    const RttEstimate&         rtt_;
    const DeliveryRateSampler& sampler_;

    // The acknowledgement being processed.
    Clock::time_point now_{};
    RateSample        rs_;
    uint64_t          newly_acked_ = 0;
    uint64_t          newly_lost_  = 0;
    uint64_t          inflight_now_ = 0;   ///< bytes in flight, as of the last hook
    bool              ack_cwnd_limited_ = false;
    Clock::duration   ack_rtt_ = (Clock::duration::max)();   ///< min clean sample this ack
    /// The same with the peer's ack delay taken off: transit and queueing only.
    Clock::duration   ack_rtt_net_ = (Clock::duration::max)();

    State    state_     = State::Startup;
    AckPhase ack_phase_ = AckPhase::Init;
    uint64_t pacing_gain_ = kStartupPacingGain;
    uint64_t cwnd_gain_   = kStartupCwndGain;
    uint64_t pacing_rate_ = 0;   ///< bytes/s
    /// Whether the initial pacing rate was taken from a measured round trip. One
    /// set before the first sample uses a 1 ms stand-in (see the constructor).
    bool     pacing_from_rtt_ = false;
    uint64_t cwnd_        = kInitialWindow;
    uint64_t prior_cwnd_  = 0;
    uint64_t max_inflight_ = kInitialWindow;

    // Recovery.
    bool in_recovery_         = false;
    bool packet_conservation_ = false;
    /// A timeout wrote off the flight, and nothing has been acknowledged since.
    bool timed_out_           = false;

    // Bandwidth model. bw_hi_ is the two-slot max filter over probe cycles.
    uint64_t bw_hi_[2] = {0, 0};
    /// bw_hi_[1]'s cycle had a sample neither app-limited nor clear of a queue: a
    /// measurement of the path, so the filter may forget the cycle before it.
    bool     bw_hi_saturated_ = false;
    uint64_t max_bw_   = 0;
    uint64_t bw_       = 0;
    uint64_t bw_lo_       = kInfinite;
    uint64_t inflight_lo_ = kInfinite;
    uint64_t inflight_hi_ = kInfinite;
    uint64_t bw_latest_       = 0;
    uint64_t inflight_latest_ = 0;

    // Round-trip model.
    Clock::duration   min_rtt_ = (Clock::duration::max)();
    Clock::time_point min_rtt_stamp_{};
    Clock::duration   probe_rtt_min_delay_ = (Clock::duration::max)();
    Clock::time_point probe_rtt_min_stamp_{};
    bool              probe_rtt_expired_   = false;
    Clock::time_point probe_rtt_done_stamp_{};
    bool              probe_rtt_done_armed_ = false;
    bool              probe_rtt_round_done_ = false;
    bool              idle_restart_ = false;

    // Rounds.
    uint64_t next_round_delivered_ = 0;
    uint64_t round_count_          = 0;
    bool     round_start_          = false;
    uint64_t rounds_since_bw_probe_ = 0;
    uint64_t loss_round_delivered_ = 0;
    bool     loss_round_start_     = false;
    bool     loss_in_round_        = false;
    int      loss_events_in_round_ = 0;
    /// The loss round so far: its smallest round trip (ack delay off), whether it
    /// lost a packet sent with more than a BDP in flight; and the round the sender
    /// last ran dry in — whether a loss can be blamed on congestion (see
    /// adapt_lower_bounds_from_congestion).
    Clock::duration loss_round_rtt_net_ = (Clock::duration::max)();
    bool     loss_round_overfull_  = false;
    bool     ran_dry_              = false;
    uint64_t ran_dry_round_        = 0;
    /// The loss round so far: what it delivered and lost, and whether all of it
    /// was spent cruising; and, over such rounds with no queue, the stretch being
    /// measured and the loss rates (thousandths) of the last ones.
    uint64_t round_acked_          = 0;
    uint64_t round_lost_           = 0;
    bool     round_cruised_        = false;
    uint64_t loss_win_seen_        = 0;
    uint64_t loss_win_lost_        = 0;
    uint16_t loss_win_rate_[kLossBaseWindows] = {};
    int      loss_wins_            = 0;   ///< stretches measured, up to kLossBaseWindows
    bool     cwnd_limited_now_  = false;   ///< this round
    bool     cwnd_limited_prev_ = false;   ///< the round before

    // Full pipe.
    uint64_t full_bw_       = 0;
    int      full_bw_count_ = 0;
    bool     full_bw_now_     = false;
    bool     full_bw_reached_ = false;
    /// Startup's reading of the round trip (startup_queued), kept until the pipe
    /// is found full: the group of acknowledgements open since group_start_, the
    /// smallest round trip of it and of the group before, and how many groups in
    /// a row have each been above the one before; and since when every round trip
    /// has stood kStandingBar over the minimum (the epoch: the last one did not).
    Clock::time_point group_start_{};
    Clock::duration   group_rtt_      = (Clock::duration::max)();
    Clock::duration   prev_group_rtt_ = (Clock::duration::max)();
    int               group_rises_    = 0;
    Clock::time_point standing_since_{};

    // ProbeBW cycle.
    Clock::time_point cycle_stamp_{};
    Clock::duration   bw_probe_wait_{};
    uint64_t bw_probe_up_rounds_ = 0;
    uint64_t bw_probe_up_acks_   = 0;
    uint64_t probe_up_cnt_       = kInfinite;
    bool     bw_probe_samples_   = false;
    bool     prev_probe_too_high_ = false;
    bool     stopped_risky_probe_ = false;

    // ACK aggregation.
    Clock::time_point extra_acked_interval_start_{};
    uint64_t extra_acked_delivered_ = 0;
    uint64_t extra_acked_win_[2]     = {0, 0};
    int      extra_acked_win_rounds_ = 0;
    int      extra_acked_win_idx_    = 0;
    uint64_t extra_acked_            = 0;

    uint64_t rng_;
};

} // namespace cc
} // namespace librats
