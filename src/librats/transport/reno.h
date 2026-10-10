#pragma once

/**
 * @file reno.h
 * @brief NewReno congestion control with HyStart++ and idle-window validation —
 *        the loss-based controller the datagram transport started with.
 *
 *   - Slow start to `ssthresh`, then additive increase of one packet per window;
 *     multiplicative decrease once per loss episode (the stream decides what an
 *     episode is), collapse to one packet on a timeout.
 *   - HyStart++ (RFC 9406) ends slow start on a rising round trip instead of on a
 *     loss.
 *   - A window nobody has validated for a retransmission timeout is given back
 *     (RFC 2861) rather than believed.
 *   - Paced at `gain * cwnd / srtt` with the gains RFC 9002 (7.7) recommends.
 *
 * Kept for comparison and for paths where a loss-based sender is what the peer on
 * the other end of a shared bottleneck expects; BBR (bbr.h) is the default.
 */

#include "librats/transport/congestion_control.h"

namespace librats {
namespace cc {

class RenoController final : public CongestionController {
public:
    static constexpr uint32_t kMinCwnd = 2 * kMss;

    // Pacing gains: slow start has to deliver a *doubling* window within one round
    // trip, so pacing it at exactly cwnd/srtt would hold growth back by a factor of
    // two; in congestion avoidance a little headroom keeps an ack-clocked sender
    // from being throttled by its own estimate.
    static constexpr uint32_t kPaceGainSlowStartNum = 2;
    static constexpr uint32_t kPaceGainSlowStartDen = 1;
    static constexpr uint32_t kPaceGainSteadyNum    = 5;   ///< 1.25x
    static constexpr uint32_t kPaceGainSteadyDen    = 4;

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

    RenoController(const RttEstimate& rtt, Clock::time_point now);

    CongestionAlgorithm algorithm() const noexcept override { return CongestionAlgorithm::Reno; }
    uint32_t   cwnd() const noexcept override { return cwnd_; }
    PacingRate pacing_rate() const noexcept override;

    void on_packet_sent(Clock::time_point now, uint64_t bytes, uint64_t bytes_in_flight) override;
    void on_rtt_sample(Clock::duration rtt) override;
    void on_packet_lost(const LostPacket&) override {}
    void on_congestion_event(Clock::time_point now, uint64_t bytes_in_flight,
                             uint64_t newly_acked) override;
    void on_recovery_exit(Clock::time_point) override {}
    void on_timeout(Clock::time_point now, uint64_t bytes_in_flight) override;
    void on_ack(const AckEvent& ack) override;
    bool on_send_opportunity(Clock::time_point now, uint64_t bytes_in_flight, bool has_data,
                             bool app_limited) override;
    bool uses_rate_reduction() const noexcept override { return true; }

    /// Where slow start stops. Starts at the ceiling and comes down either when
    /// HyStart++ sees the round-trip time rise or when something is lost.
    uint32_t ssthresh() const noexcept { return ssthresh_; }

private:
    bool in_slow_start() const noexcept { return cwnd_ < ssthresh_; }
    void on_loss(bool timeout, uint64_t bytes_in_flight);
    void grow_window(uint64_t acked_bytes);
    void hystart_on_ack(uint32_t ack, uint32_t next_seq);

    const RttEstimate& rtt_;

    uint32_t cwnd_     = kInitialWindow;
    uint32_t ssthresh_ = kMaxWindow;

    /// When data — not a bare acknowledgement — last went out; the clock the
    /// idle-restart rule reads.
    Clock::time_point last_data_send_;

    // — HyStart++ —
    /// Cautious phase: slow start has seen the round-trip time rise and is
    /// probing gently until the rise is confirmed or withdrawn.
    bool            css_        = false;
    int             css_rounds_ = 0;
    Clock::duration css_baseline_rtt_ = (Clock::duration::max)();
    /// Lowest round-trip time seen in this round and in the one before it. The
    /// *minimum* is what matters: a queue building in front of the bottleneck
    /// lifts even the luckiest packet's round trip, where an average would just
    /// as easily be moved by one straggler.
    Clock::duration round_min_rtt_      = (Clock::duration::max)();
    Clock::duration prev_round_min_rtt_ = (Clock::duration::max)();
    int             round_samples_ = 0;
    /// Highest sequence number outstanding when this round began; the round ends
    /// when the cumulative acknowledgement reaches it.
    uint32_t        round_end_ = 0;
};

} // namespace cc
} // namespace librats
