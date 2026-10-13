#include "librats/transport/udp_recovery.h"

#include <algorithm>

namespace librats {
namespace udp {

namespace {

using Clock = Recovery::Clock;
constexpr Clock::time_point kNever{};

template <typename A, typename B>
Clock::duration clamp_duration(Clock::duration v, A lo, B hi) {
    const auto low  = std::chrono::duration_cast<Clock::duration>(lo);
    const auto high = std::chrono::duration_cast<Clock::duration>(hi);
    return v < low ? low : (v > high ? high : v);
}

} // namespace

Recovery::Recovery(CongestionAlgorithm algorithm, Clock::time_point now, uint64_t seed)
    : pace_last_(now) {
    pace_tokens_ = kPaceMinBurst;   // nothing to pace against until the first round trip
    rtt_.rto     = kInitialRto;
    cc_ = cc::make_controller(algorithm, rtt_, sampler_, now, seed);
}

// ── Sending ─────────────────────────────────────────────────────────────────

void Recovery::begin_sending(Clock::time_point now, bool has_data) {
    // The controller sees the opportunity first: a window unused for a round trip
    // is stale (Reno), and a restart from idle is no reason to probe (BBR).
    if (cc_->on_send_opportunity(now, flight_bytes_, has_data, sampler_.app_limited())) {
        // The bucket describes a rate that no longer applies: release the one
        // packet an empty pipe always allows, then pace the rest at the new rate.
        pace_tokens_ = 0;
        pace_last_   = now;
    }
    pace_accrue(now);
}

bool Recovery::cwnd_allows(size_t bytes) const noexcept {
    // One packet may always go into an empty path: a window that has collapsed to
    // nothing is still an estimate that has to be able to take a sample.
    if (flight_bytes_ == 0) return true;
    if (flight_bytes_ + bytes <= cc_->cwnd()) return true;
    // Proportional rate reduction (RFC 6937), for a controller that wants it: in
    // an episode, what has been delivered since it began earns sends even while
    // the window — just cut below what is still in flight — says no. Otherwise
    // nothing would leave until half a window of acknowledgements was back: not
    // the repairs, and not the new data whose arrival tells RACK about the rest.
    return in_recovery_ && cc_->uses_rate_reduction() && recovery_credit_ >= bytes;
}

bool Recovery::pace_allows(size_t bytes) const noexcept {
    if (!cc_->pacing_rate().paced()) return true;   // no rate to pace against
    // An empty pipe is never held back: neither the one packet a collapsed window
    // allows nor the first after an idle period can congest anything, and both
    // would deadlock against a rate derived from an empty pipe.
    if (flight_bytes_ == 0) return true;
    return pace_tokens_ >= bytes;
}

void Recovery::hold_for_pacer(Clock::time_point now, size_t bytes) noexcept {
    // The pacer is released by time, not by an acknowledgement, so it needs a
    // deadline of its own. A window holding the sender back gets none: the ACK
    // that opens it is what wakes the connection, and a timer would only spin.
    const auto wait = pace_wait(bytes);
    pace_due_ = wait > Clock::duration::zero() ? now + wait : kNever;
}

void Recovery::cancel_frames() noexcept {
    while (frames_base_ + frames_.size() > frames_mark_) frames_.pop_back();
}

void Recovery::on_packet_sent(Clock::time_point now, size_t bytes, bool ack_eliciting, bool data,
                              bool repair, bool probe) {
    const uint64_t pn = next_pn_++;
    if (sent_.empty()) log_base_ = pn;

    SentPacket pkt;
    pkt.bytes         = static_cast<uint32_t>(bytes);
    pkt.frames_at     = frames_mark_;
    pkt.frame_count   = static_cast<uint16_t>(frames_base_ + frames_.size() - frames_mark_);
    pkt.ack_eliciting = ack_eliciting;
    frames_mark_      = frames_base_ + frames_.size();

    if (!ack_eliciting) {
        // A bare acknowledgement: never in flight, never paced, never timed. It is
        // logged only so its number stays where the arithmetic expects it.
        pkt.tx.sent_at = now;
        sent_.push_back(pkt);
        return;
    }

    // Everything ack-eliciting is metered, repairs included: a repair loads the
    // bottleneck exactly as new data does.
    pace_tokens_ = pace_tokens_ > bytes ? pace_tokens_ - bytes : 0;

    const uint64_t flight_before = flight_bytes_;
    pkt.in_flight  = true;
    flight_bytes_ += bytes;
    ++in_flight_packets_;
    // Every send in an episode is charged to the credit (RFC 6937's prr_out), not
    // only the ones the window alone would have refused — credit left to pile up
    // would go out as one burst the moment the window filled.
    if (in_recovery_) recovery_credit_ -= (std::min<uint64_t>)(recovery_credit_, bytes);
    sampler_.on_sent(pkt.tx, now, flight_before, flight_bytes_);
    if (data) cc_->on_packet_sent(now, bytes, flight_bytes_);
    last_eliciting_sent_ = now;
    if (probe) ++probes_;

    // Something is outstanding, so the timer runs. A repair in an episode gets a
    // full interval of its own to be answered in (RFC 9002 arms from the last
    // packet sent for the same reason): measured from the last acknowledgement, a
    // repair sent a little after it would be given up on a little before its own
    // answer could possibly arrive.
    if (loss_deadline_ == kNever)                                      arm_loss_timer(now);
    else if (repair && in_recovery_ && now + loss_timeout() > loss_deadline_) arm_loss_timer(now);
    // An episode lasts until its repairs are answered (see on_ack).
    if (repair && in_recovery_) last_repair_pn_ = pn;

    sent_.push_back(pkt);
}

void Recovery::note_send_limits(bool data_waiting, bool window_stopped, bool nothing_to_send) {
    // Something is waiting and the window is what keeps it waiting — not the
    // pacer, which time resolves, and not the receiver, which only it can.
    if (data_waiting && window_stopped) cwnd_limited_ = true;
    // Nothing to send, nothing owed, room in the window: the sender is waiting on
    // the application, and until what is in flight now is delivered every rate
    // sample measures the application rather than the path.
    if (nothing_to_send && flight_bytes_ < cc_->cwnd()) sampler_.mark_app_limited(flight_bytes_);
}

// ── Pacing ──────────────────────────────────────────────────────────────────

void Recovery::pace_accrue(Clock::time_point now) {
    auto dt = now - pace_last_;
    if (dt < Clock::duration::zero()) dt = Clock::duration::zero();
    // The bucket is capped below, so a long silence buys nothing — and the clamp
    // keeps the multiplication finite.
    const auto cap = std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(1));
    if (dt > cap) dt = cap;
    pace_last_ = now;

    const cc::PacingRate rate = cc_->pacing_rate();
    if (!rate.paced()) {
        // Not pacing yet: keep the floor, so the first packet after the first
        // round trip is not held by a bucket that never had a chance to fill.
        pace_tokens_ = kPaceMinBurst;
        return;
    }

    pace_tokens_ += rate.bytes_over(dt);
    uint64_t burst = (std::max)(static_cast<uint64_t>(kPaceMinBurst), rate.bytes_over(kPaceQuantum));
    // Woken late for a packet the pacer was holding: what accrued since the
    // moment it asked is the host's timer slop, not a burst the connection chose,
    // and capping it away would let the clock, not the controller, set the rate.
    // A virtualised host routinely sleeps 2-15 ms on a 1 ms timeout; with a
    // one-quantum bucket that sent a fraction of the pacing rate, and BBR, reading
    // that as the path, paced lower each round. So the lateness is kept, as
    // Chromium's pacer does; the window still bounds what it can release.
    Clock::duration late{};
    if (pace_due_ != kNever && now > pace_due_) late = now - pace_due_;
    burst += rate.bytes_over(late);

    // But one release is one line-rate burst, and past kPaceMaxBurst that is what
    // a shallow queue drops. Only a host that is late *typically* gets more —
    // there a smaller ceiling would be the spiral above again — while one late
    // once does not. The first millisecond of lateness is what a millisecond
    // timeout costs every host, so only what lies past it counts, doubled to cover
    // a timer whose lateness varies around it.
    uint64_t ceiling = kPaceMaxBurst;
    if (pace_late_ > kPaceQuantum)
        ceiling = (std::max)(ceiling, rate.bytes_over(2 * (pace_late_ - kPaceQuantum)));
    if (late > Clock::duration::zero()) pace_late_ += (late - pace_late_) / 8;
    if (burst > ceiling) burst = (std::max)(ceiling, static_cast<uint64_t>(kPaceMinBurst));
    if (pace_tokens_ > burst) pace_tokens_ = burst;
}

Clock::duration Recovery::pace_wait(size_t bytes) const noexcept {
    const cc::PacingRate rate = cc_->pacing_rate();
    if (!rate.paced() || pace_tokens_ >= bytes) return Clock::duration::zero();
    return rate.time_for(static_cast<uint64_t>(bytes) - pace_tokens_);
}

uint64_t Recovery::prr_share(uint64_t delivered) const noexcept {
    // Sends earned by `delivered` bytes, in proportion to how far the controller
    // cut the window against what was outstanding when the episode began. Reno's
    // halving earns half; nothing after a timeout, which is slow start.
    if (recover_fs_ == 0) return 0;
    const uint64_t target = (std::min<uint64_t>)(cc_->cwnd(), recover_fs_);
    return cc::mul_div(delivered, target, recover_fs_);
}

// ── Acknowledgements ────────────────────────────────────────────────────────

Recovery::SentPacket* Recovery::at(uint64_t pn) noexcept {
    if (pn < log_base_ || pn - log_base_ >= sent_.size()) return nullptr;
    return &sent_[static_cast<size_t>(pn - log_base_)];
}

size_t Recovery::next_unacked(size_t idx) noexcept {
    const size_t n = sent_.size();
    if (idx >= n) return n;
    // A skip always points forward, past the packet holding it; one past the back
    // is "none yet", and stays right as the log grows, since everything it
    // stepped over is still acknowledged.
    const auto index_of = [&](uint64_t pn) {
        return static_cast<size_t>((std::min<uint64_t>)(pn - log_base_, n));
    };

    size_t root = idx;
    while (root < n && sent_[root].acked) root = index_of(sent_[root].skip);

    // Path compression: everything walked through now points straight at the
    // answer, so the next walk over the same run is a single hop.
    const uint64_t root_pn = log_base_ + root;
    while (idx < root) {
        SentPacket&  pkt  = sent_[idx];
        const size_t next = index_of(pkt.skip);
        pkt.skip = root_pn;
        idx      = next;
    }
    return root;
}

bool Recovery::on_ack(const AckFrame& ack, Clock::time_point now, FrameSink& sink) {
    if (ack.largest >= next_pn_) return false;   // names a packet never sent

    ack_prior_flight_ = flight_bytes_;
    ack_newly_acked_  = 0;
    ack_newly_clean_  = 0;
    bool              progress = false;
    bool              sample   = false;   ///< the largest packet named is newly acknowledged
    Clock::time_point sample_sent{};

    // Every ACK repeats every range the receiver still holds, so most of what one
    // names was acknowledged before; next_unacked() steps over those runs rather
    // than through them, which is what makes an ACK cost what it newly covers.
    AckRanges ranges(ack);
    uint64_t lo = 0, hi = 0;
    while (!sent_.empty() && ranges.next(lo, hi)) {
        if (hi < log_base_) break;   // highest first: the rest are older still
        const uint64_t end  = log_base_ + sent_.size();
        const uint64_t from = (std::max)(lo, log_base_);
        const uint64_t to   = (std::min)(hi + 1, end);
        if (from >= to) continue;
        const size_t stop = static_cast<size_t>(to - log_base_);
        for (size_t idx = next_unacked(static_cast<size_t>(from - log_base_)); idx < stop;
             idx = next_unacked(idx + 1)) {
            const uint64_t pn  = log_base_ + idx;
            SentPacket&    pkt = sent_[idx];
            if (pn == ack.largest && pkt.ack_eliciting) {
                sample      = true;
                sample_sent = pkt.tx.sent_at;
            }
            on_newly_acked(pn, pkt, now, sink);
            progress = true;
        }
    }
    if (!have_largest_acked_ || ack.largest > largest_acked_) {
        largest_acked_      = ack.largest;
        have_largest_acked_ = true;
    }

    // One round-trip sample per ACK, from the largest packet it names, when that
    // is news (RFC 9002 §5.1): every other packet it covers waited at the receiver
    // for that one. The delay the peer reports comes off it — but never more than
    // it may hold an acknowledgement for, so it cannot talk the estimate down.
    // Capped while still a count of units: the field is a 62-bit varint, and a
    // large one multiplied out first would overflow into a negative duration.
    if (sample) {
        constexpr uint64_t kMaxDelayUnits = kMaxAckDelay / kAckDelayUnit;
        const uint64_t units = (std::min)(ack.delay, kMaxDelayUnits);
        const auto delay = std::chrono::duration_cast<Clock::duration>(
            kAckDelayUnit * static_cast<int64_t>(units));
        sample_rtt(now - sample_sent, delay);
    }

    // What this ACK delivered earns sends in an episode already under way (one
    // opened by this ACK is credited when it opens).
    if (in_recovery_) recovery_credit_ += prr_share(ack_newly_acked_);

    const bool lost = detect_losses(now, sink);

    // The episode ends once what it lost has been delivered again: its last repair
    // acknowledged (and something sent after it began), nothing still owed —
    // NewReno's recovery point, read in packet numbers. Not on an ACK that has just
    // found more losses, whose repairs still belong to it.
    if (in_recovery_ && !lost && largest_acked_ > episode_start_pn_ &&
        largest_acked_ >= last_repair_pn_ && !sink.repairs_pending()) {
        in_recovery_      = false;
        timeout_recovery_ = false;
        timeout_episode_  = false;
        recovery_credit_  = 0;
        cc_->on_recovery_exit(now);
    }

    // Progress means the path is alive: undo whatever backoff a timeout applied.
    if (progress && rtt_.have_rtt) rtt_.rto = estimated_rto();

    // The controller hears the totals once everything the ACK implies is applied.
    const cc::RateSample rs = sampler_.take_sample(rtt_.min_or_zero());
    if (rs.acked || lost_since_ack_ > 0) {
        cc::AckEvent ev;
        ev.now               = now;
        ev.largest_acked     = largest_acked_;
        ev.next_pn           = next_pn_;
        ev.newly_acked       = ack_newly_acked_;
        ev.newly_acked_clean = ack_newly_clean_;
        ev.newly_lost        = lost_since_ack_;
        ev.bytes_in_flight   = flight_bytes_;
        ev.cwnd_limited      = cwnd_limited_;
        ev.rs                = rs;
        cc_->on_ack(ev);
        lost_since_ack_ = 0;
        cwnd_limited_   = false;
        if (cc_->wants_app_limited()) sampler_.mark_app_limited(flight_bytes_);
    }

    // RFC 9002: the timer restarts whenever something new is acknowledged, and
    // stops once nothing is outstanding. Progress also ends the silence the
    // probes were counting, and the run of timeouts — and, after a timeout, the
    // reason to hold probes back: the path is answering again, so the next
    // silence is a question for a probe, not a second collapse of the window.
    if (progress) {
        tail_probes_      = 0;
        timeouts_         = 0;
        timeout_recovery_ = false;
        rearm(now);
    }
    retire_front();
    return true;
}

void Recovery::on_newly_acked(uint64_t pn, SentPacket& pkt, Clock::time_point now,
                              FrameSink& sink) {
    pkt.acked = true;
    pkt.skip  = pn + 1;
    if (pkt.ack_eliciting) {
        if (pkt.in_flight) {
            pkt.in_flight  = false;
            flight_bytes_ -= pkt.bytes;
            --in_flight_packets_;
        }
        // A packet given up on and delivered after all still counts as delivered:
        // the rate sample and the window both describe what arrived.
        ack_newly_acked_ += pkt.bytes;
        // Clean: sent after the latest episode began, and not while a PRR episode
        // is still repairing. A timeout's episode is slow start, which is exactly
        // growth on what was sent after the collapse — withheld until every repair
        // was out, the window stayed at one packet and the backlog an outage leaves
        // drained at one packet per round trip.
        if ((!in_recovery_ || timeout_episode_) && (!had_episode_ || pn > episode_start_pn_))
            ack_newly_clean_ += pkt.bytes;
        sampler_.on_delivered(pkt.tx, pn, pkt.bytes, now);
    }
    // RACK (RFC 8985): the newest transmission known to have arrived, and the
    // round trip it took — what a packet sent before it is given to arrive in.
    if (pkt.tx.sent_at > rack_sent_at_) {
        rack_sent_at_ = pkt.tx.sent_at;
        rack_rtt_     = now - pkt.tx.sent_at;
    }
    if (pkt.frame_count) hand_over(pkt, true, sink);
}

bool Recovery::detect_losses(Clock::time_point now, FrameSink& sink) {
    reorder_deadline_ = kNever;
    if (!have_largest_acked_ || sent_.empty()) return false;

    // The reordering a path is allowed before a packet counts as lost: a quarter of
    // the minimum round trip (RFC 8985's default), at least a millisecond, never
    // more than a round trip.
    Clock::duration reo_wnd = std::chrono::milliseconds(1);
    if (rtt_.have_rtt) {
        reo_wnd = (std::max)(reo_wnd, Clock::duration(rtt_.min_rtt / 4));
        reo_wnd = (std::min)(reo_wnd, rtt_.srtt);
    }

    // RACK (RFC 8985): a packet sent before the newest one delivered is lost once
    // that delivery's round trip and the reordering window have passed since it
    // left — or at once when three packets behind it have arrived. Numbers rise
    // with send time, so both tests become true of later packets only later: the
    // scan resumes where it last stopped and ends at the first packet still in
    // good standing, and if that one only needs time, the reorder timer is set for
    // when it will have had it. Without the timer the last packets of a burst,
    // sent too close to the delivered one for the window to tell, would wait for a
    // probe timeout.
    if (loss_scan_ < log_base_) loss_scan_ = log_base_;
    bool     lost_any    = false;
    uint64_t newest_lost = 0;
    for (; loss_scan_ < largest_acked_; ++loss_scan_) {
        SentPacket* pkt = at(loss_scan_);
        if (!pkt) break;
        if (!pkt->in_flight) continue;   // acknowledged, given up on, or a bare ACK

        if (largest_acked_ - loss_scan_ < kReorderThreshold) {
            const auto due = pkt->tx.sent_at + rack_rtt_ + reo_wnd;
            if (now < due) {
                reorder_deadline_ = due;
                break;
            }
        }
        mark_lost(*pkt, now, sink);
        lost_any    = true;
        newest_lost = loss_scan_;
    }
    if (lost_any) congestion_event(now, newest_lost);
    return lost_any;
}

void Recovery::mark_lost(SentPacket& pkt, Clock::time_point now, FrameSink& sink) {
    // Off the path: it stops counting against the window, which is what lets its
    // data go out again under that window rather than past it.
    pkt.in_flight  = false;
    pkt.lost       = true;
    flight_bytes_ -= pkt.bytes;
    --in_flight_packets_;
    ++lost_packets_;

    sampler_.on_lost(pkt.bytes);
    lost_since_ack_ += pkt.bytes;
    cc::LostPacket lost;
    lost.now             = now;
    lost.bytes           = pkt.bytes;
    lost.tx_in_flight    = pkt.tx.in_flight;
    lost.lost_since_sent = sampler_.lost() - pkt.tx.lost;
    lost.app_limited     = pkt.tx.app_limited;
    cc_->on_packet_lost(lost);

    if (pkt.frame_count) hand_over(pkt, false, sink);
}

void Recovery::congestion_event(Clock::time_point now, uint64_t newest_lost) {
    // One reduction per episode, not one per packet and not one per ACK that
    // reports a loss — several arrive per round trip, and halving on each would
    // drive the window to the floor over a loss TCP rides out with one halving.
    // That includes what is lost while the episode runs: packets sent in the round
    // trip before the reduction took effect meet the same full queue.
    //
    // A timeout's episode is the exception for what was sent after it: that went
    // out under slow start from one packet, and losing it means slow start has
    // overshot — a congestion event of its own, which ends the timeout's episode
    // and begins an ordinary one (RFC 9002 §7.3.2: a recovery period ends when a
    // packet sent during it is acknowledged or lost).
    if (in_recovery_ && !(timeout_episode_ && newest_lost > episode_start_pn_)) return;
    timeout_episode_   = false;
    in_recovery_       = true;
    had_episode_       = true;
    episode_start_pn_  = next_pn_ - 1;
    last_repair_pn_    = 0;
    ++congestion_events_;
    cc_->on_congestion_event(now, flight_bytes_, ack_newly_acked_);
    // PRR's RecoverFS: what was outstanding when the episode began.
    recover_fs_      = (std::max<uint64_t>)(ack_prior_flight_, 1);
    recovery_credit_ = prr_share(ack_newly_acked_);
}

void Recovery::hand_over(const SentPacket& pkt, bool acked, FrameSink& sink) {
    // A packet's frames stay in the log until the packet leaves its front, so its
    // span is still there whenever its fate comes in — late acknowledgements of a
    // packet already given up on included.
    const size_t first = static_cast<size_t>(pkt.frames_at - frames_base_);
    if (acked) sink.frames_acked(frames_, first, pkt.frame_count);
    else       sink.frames_lost(frames_, first, pkt.frame_count);
}

void Recovery::retire_front() noexcept {
    // A packet leaves the log once nothing more can be learnt from it: delivered,
    // given up on, or a bare ACK nobody acknowledges. Its frames go with it.
    while (!sent_.empty() && !sent_.front().in_flight) {
        const SentPacket& front = sent_.front();
        for (uint16_t i = 0; i < front.frame_count; ++i) frames_.pop_front();
        frames_base_ += front.frame_count;
        sent_.pop_front();
        ++log_base_;
    }
}

void Recovery::sample_rtt(Clock::duration rtt, Clock::duration ack_delay) {
    if (rtt < Clock::duration::zero()) return;
    if (!rtt_.have_rtt) {
        rtt_.srtt     = rtt;
        rtt_.rttvar   = rtt / 2;
        rtt_.have_rtt = true;
    } else {
        // RFC 9002 §5.3: the peer's delay comes off the sample, but never so far
        // that the result is shorter than the shortest round trip ever seen.
        auto adjusted = rtt;
        if (rtt >= rtt_.min_rtt + ack_delay) adjusted -= ack_delay;
        const auto err = rtt_.srtt > adjusted ? rtt_.srtt - adjusted : adjusted - rtt_.srtt;
        rtt_.rttvar = (rtt_.rttvar * 3 + err) / 4;
        rtt_.srtt   = (rtt_.srtt * 7 + adjusted) / 8;
    }
    // The minimum and the controller see the raw sample: a minimum is only a floor
    // while nothing has been subtracted from it.
    rtt_.latest  = rtt;
    rtt_.min_rtt = (std::min)(rtt_.min_rtt, rtt);
    rtt_.rto     = estimated_rto();
    cc_->on_rtt_sample(rtt, ack_delay);
}

// ── The loss timer ──────────────────────────────────────────────────────────

Clock::duration Recovery::estimated_rto() const noexcept {
    // RFC 6298's srtt + 4 * rttvar, plus what the peer may hold an acknowledgement
    // back for: on a path steady enough for rttvar to vanish, the timeout is
    // otherwise a round trip and nothing more, and the first delayed ACK arrives
    // after it has fired.
    return clamp_duration(rtt_.srtt + 4 * rtt_.rttvar +
                              std::chrono::duration_cast<Clock::duration>(kMaxAckDelay),
                          kMinRto, kMaxRto);
}

Clock::duration Recovery::base_probe_timeout() const noexcept {
    if (!rtt_.have_rtt) return kInitialRto;
    const auto granularity = std::chrono::duration_cast<Clock::duration>(kMinProbeTimeout) / 8;
    return rtt_.srtt + (std::max)(4 * rtt_.rttvar, granularity) +
           std::chrono::duration_cast<Clock::duration>(kMaxAckDelay);
}

Clock::duration Recovery::probe_timeout() const noexcept {
    auto pto = base_probe_timeout();
    // Doubled per consecutive probe: if the first went unanswered the path is worse
    // than the estimate says, and asking again at the same spacing is asking twice.
    for (int i = 0; i < tail_probes_ && pto < std::chrono::duration_cast<Clock::duration>(kMaxRto); ++i)
        pto *= 2;
    return clamp_duration(pto, kMinProbeTimeout, kMaxRto);
}

Clock::duration Recovery::loss_timeout() const noexcept {
    // Probes run in an episode too (RFC 9002 keeps one timer in every state): a
    // lost repair with nothing sent after it has no later delivery for RACK to
    // read, and a probe costs one packet where the timeout costs kMinRto and the
    // window. Not after a timeout until the path answers again, though: it has
    // just been silent for a whole timeout, and backing off is what keeps a dead
    // path from being hammered. Never later than the timeout it stands in front of.
    if (timeout_recovery_ || tail_probes_ >= kMaxTailProbes) return timeout_wait();
    return (std::min)(probe_timeout(), timeout_wait());
}

Clock::duration Recovery::impatient_wait() const noexcept {
    return (std::max)(base_probe_timeout(), std::chrono::duration_cast<Clock::duration>(kMinRto));
}

Clock::duration Recovery::timeout_wait() const noexcept {
    return impatient_ ? (std::min)(rtt_.rto, impatient_wait()) : rtt_.rto;
}

void Recovery::set_impatient(bool impatient) noexcept {
    if (impatient == impatient_) return;
    impatient_ = impatient;
    // The timer running now was set for the other case.
    if (loss_deadline_ != kNever) loss_deadline_ = loss_armed_at_ + loss_timeout();
}

void Recovery::arm_loss_timer(Clock::time_point from) noexcept {
    loss_armed_at_ = from;
    loss_deadline_ = from + loss_timeout();
}

void Recovery::rearm(Clock::time_point now) noexcept {
    if (in_flight_packets_ > 0) arm_loss_timer(now);
    else                        loss_deadline_ = kNever;
}

std::optional<Clock::time_point> Recovery::deadline() const noexcept {
    std::optional<Clock::time_point> due;
    for (const Clock::time_point t : {loss_deadline_, reorder_deadline_, pace_due_})
        if (t != kNever && (!due || t < *due)) due = t;
    return due;
}

Recovery::Timeout Recovery::on_timer(Clock::time_point now, FrameSink& sink) {
    // A packet RACK was giving time to has had it: its data goes out again on the
    // caller's next send. The loss timer then measures from what is left.
    if (reorder_deadline_ != kNever && now >= reorder_deadline_ && detect_losses(now, sink)) {
        retire_front();
        rearm(now);
    }
    // A pacer release that has come due is the caller's to send, and the hold is
    // left for begin_sending() to read how late the host was to it.
    if (loss_deadline_ == kNever || now < loss_deadline_) return Timeout::None;
    if (in_flight_packets_ == 0) {
        loss_deadline_ = kNever;   // nothing outstanding: the timer has no work
        return Timeout::None;
    }

    // A tail loss probe, before any collapse is believed. A peer gone quiet after
    // a lost last packet is indistinguishable from one that is merely slow, and the
    // two call for opposite responses — so ask first: one packet past every hole,
    // nothing else changed, and let the answer decide.
    if (!timeout_recovery_ && tail_probes_ < kMaxTailProbes) {
        ++tail_probes_;
        arm_loss_timer(now);
        return Timeout::Probe;
    }

    // An impatient timeout with no answer since the last one is the same silence,
    // asked about sooner (set_impatient). It is not news to the controller, which
    // would otherwise cut its model again at every probe of one outage, and it does
    // not count towards giving up — silence that long is the idle timeout's to
    // judge (UdpConnection::kIdleTimeout).
    const bool asked_sooner = impatient_ && timeout_recovery_;
    if (!asked_sooner && ++timeouts_ > kMaxTimeouts) return Timeout::GiveUp;

    // A timeout always collapses the window, even mid-episode, and starts an
    // episode of its own so the acknowledgements that come back as the pipe
    // refills do not each take another reduction. The controller reads what was
    // in flight, so it hears of this before the flight is written off.
    if (!asked_sooner) {
        ++congestion_events_;
        cc_->on_timeout(now, flight_bytes_);
    }
    in_recovery_      = true;
    timeout_recovery_ = true;
    timeout_episode_  = true;
    had_episode_      = true;
    episode_start_pn_ = next_pn_ - 1;
    last_repair_pn_   = 0;

    // Everything outstanding had a whole timeout to be answered in, so it stops
    // occupying the path. Left counted, the flight would hold a full window
    // against a window of one packet and nothing could ever be sent again.
    for (size_t i = 0; i < sent_.size(); ++i)
        if (sent_[i].in_flight) mark_lost(sent_[i], now, sink);
    recovery_credit_ = 0;
    recover_fs_      = 0;   // what follows is slow start, not PRR

    // Exponential backoff, so a path that is down is probed ever more cheaply —
    // unless what is waiting will not keep (set_impatient).
    rtt_.rto = clamp_duration(rtt_.rto * 2, kMinRto, kMaxRto);
    arm_loss_timer(now);
    retire_front();
    return Timeout::Collapsed;
}

bool Recovery::newest_in_flight(size_t& first, size_t& count) const noexcept {
    // The newest packet that carried data: a window update or a PING sent
    // after it has nothing worth repeating, and a probe that only asks costs the
    // round trip its answer takes before the data can follow.
    for (size_t i = sent_.size(); i-- > 0;) {
        const SentPacket& pkt = sent_[i];
        if (!pkt.in_flight || pkt.frame_count == 0) continue;
        const size_t at = static_cast<size_t>(pkt.frames_at - frames_base_);
        for (size_t f = 0; f < pkt.frame_count; ++f) {
            if (!frames_[at + f].carries_data()) continue;
            first = at;
            count = pkt.frame_count;
            return true;
        }
    }
    return false;
}

void Recovery::clear() noexcept {
    sent_.clear();
    frames_.clear();
    frames_base_ = frames_mark_ = 0;
    log_base_          = next_pn_;
    flight_bytes_      = 0;
    in_flight_packets_ = 0;
    loss_deadline_     = kNever;
    reorder_deadline_  = kNever;
    pace_due_          = kNever;
    pace_tokens_       = 0;
    recovery_credit_   = 0;
}

} // namespace udp
} // namespace librats
