// Congestion control and loss recovery of the datagram transport, against a model
// of a real path.
//
// test_udp_connection.cpp drives connections over a path with no bandwidth and no
// queue — enough for correctness, useless for anything a congestion controller
// does. Here the path is the one every loss-based and model-based controller is a
// response to: a drop-tail queue in front of a serialiser at the link rate, then a
// propagation delay, in each direction. Time is virtual and fine-grained (a
// connection takes `now` as a parameter and never reads a clock), so every test is
// deterministic and runs in a fraction of the wall time it simulates.
//
// The connections run the plaintext handshake: the model is about packets, not
// keys, and with nothing sealed a test can read what each packet carries.

#include <gtest/gtest.h>

#include "udp_test_net.h"

#include "librats/transport/bbr.h"
#include "librats/transport/congestion_control.h"
#include "librats/transport/delivery_rate.h"
#include "librats/transport/reno.h"
#include "librats/transport/udp_wire.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

using namespace librats;
using namespace udptest;
using namespace std::chrono_literals;

namespace {

// ── The path ────────────────────────────────────────────────────────────────

struct InFlight {
    Clock::time_point arrive;
    Address           from, to;
    Bytes             bytes;
};

/// One direction: a drop-tail queue `queue_pkts` full-size packets deep in front
/// of a serialiser at `rate_bps`, then `delay` of propagation.
struct Direction {
    double               rate_bps   = 0;
    Clock::duration      delay{};
    size_t               queue_pkts = 0;
    double               loss       = 0;
    /// The share of datagrams held back `late_by` past their turn — not by the
    /// queue, which they leave on time: a host's timer, a radio's retries.
    double               late       = 0;
    Clock::duration      late_by{};
    /// A late one holds back those behind it rather than being overtaken, as a
    /// Wi-Fi receiver's block-ack window does: delay without reordering.
    bool                 late_holds = false;
    /// Datagrams handed over on the tick of a clock this far apart: a station
    /// that sends in transmit opportunities, a receiver reading in batches.
    Clock::duration      bunch{};
    /// Every datagram late by its own draw from [0, jitter]: a path that keeps no
    /// order (per-packet jitter, a bonded link), so they overtake one another.
    Clock::duration      jitter{};
    /// Every datagram's delay varied by a normal draw of this deviation (never
    /// below none), in order: netem's `delay D sd distribution normal` with a
    /// rate, a radio that holds a packet back and those behind it with it.
    Clock::duration      delay_sd{};
    Clock::time_point    busy_until{};
    std::deque<InFlight> wire;
    size_t               sent  = 0;   ///< datagrams that entered the queue
    size_t               drops = 0;
};

class PathSim final : public Wire {
public:
    /// A symmetric path of `mbps`, round trip `rtt`, `queue_pkts` of buffer, and
    /// `fwd_loss` random loss towards the receivers only (acknowledgements are not
    /// what is being tested). Seeded, so a test sees the same losses every run.
    PathSim(double mbps, Clock::duration rtt, size_t queue_pkts, double fwd_loss = 0.0,
            uint32_t seed = 1)
        : rng_(seed) {
        for (Direction* d : {&fwd_, &rev_}) {
            d->rate_bps   = mbps * 1e6;
            d->delay      = rtt / 2;
            d->queue_pkts = queue_pkts;
        }
        fwd_.loss = fwd_loss;
    }

    void attach(End* end, bool receiver) { ends_.push_back({end, receiver}); }

    void carry(const Address& from, const Address& to, const uint8_t* data, size_t len) override {
        const bool forward = is_receiver(to);
        Direction& d       = forward ? fwd_ : rev_;

        Bytes bytes(data, data + len);
        if (hook && hook(bytes, to, forward)) { ++d.drops; return; }
        if (blackout) { ++d.drops; return; }

        const auto serial = std::chrono::nanoseconds(
            static_cast<long long>((bytes.size() + 28) * 8 * 1e9 / d.rate_bps));
        const auto full = std::chrono::nanoseconds(
            static_cast<long long>((udp::kMaxDatagram + 28) * 8 * 1e9 / d.rate_bps));
        const auto backlog = d.busy_until > now_ ? d.busy_until - now_ : Clock::duration::zero();
        if (backlog > full * static_cast<long long>(d.queue_pkts)) { ++d.drops; return; }
        if (d.loss > 0 && unit_(rng_) < d.loss) { ++d.drops; return; }

        ++d.sent;
        d.busy_until = (std::max)(now_, d.busy_until) + serial;
        Clock::time_point arrive = d.busy_until + d.delay;
        if (d.bunch > Clock::duration::zero())
            arrive = Clock::time_point{} + (arrive.time_since_epoch() / d.bunch + 1) * d.bunch;
        if (d.late > 0 && unit_(rng_) < d.late) arrive += d.late_by;
        if (d.jitter > Clock::duration::zero())
            arrive += std::chrono::duration_cast<Clock::duration>(d.jitter * unit_(rng_));
        if (d.delay_sd > Clock::duration::zero()) {
            // Box-Muller off the same uniform draws: std's normal distribution is
            // not the same on every platform.
            const double u = (std::max)(unit_(rng_), 1e-12), v = unit_(rng_);
            const double z = std::sqrt(-2 * std::log(u)) * std::cos(6.283185307179586 * v);
            const auto shift = std::chrono::duration_cast<Clock::duration>(d.delay_sd * z);
            arrive = (std::max)(arrive + shift, d.busy_until);
        }
        if ((d.late_holds || d.delay_sd > Clock::duration::zero()) && !d.wire.empty())
            arrive = (std::max)(arrive, d.wire.back().arrive);
        // In arrival order: one held back is overtaken by those behind it, unless it holds them.
        auto at = std::upper_bound(d.wire.begin(), d.wire.end(), arrive,
                                   [](Clock::time_point t, const InFlight& f) { return t < f.arrive; });
        d.wire.insert(at, InFlight{arrive, from, to, std::move(bytes)});
    }

    void deliver_until(Clock::time_point now) {
        now_ = now;
        for (Direction* d : {&fwd_, &rev_}) {
            while (!d->wire.empty() && d->wire.front().arrive <= now) {
                InFlight f = std::move(d->wire.front());
                d->wire.pop_front();
                for (const auto& e : ends_)
                    if (e.end->addr() == f.to) e.end->receive(f.bytes.data(), f.bytes.size(), f.from, now);
            }
        }
    }

    void set_now(Clock::time_point now) { now_ = now; }
    Direction& fwd() { return fwd_; }
    Direction& rev() { return rev_; }

    /// Sees (and may rewrite) every datagram before the path does; true drops it.
    std::function<bool(Bytes& datagram, const Address& to, bool forward)> hook;
    /// Drop everything, both ways.
    bool blackout = false;

private:
    struct Placed {
        End* end;
        bool receiver;
    };
    bool is_receiver(const Address& a) const {
        for (const auto& e : ends_) if (e.end->addr() == a) return e.receiver;
        return false;
    }

    Direction           fwd_, rev_;
    std::vector<Placed> ends_;
    Clock::time_point   now_{};
    std::mt19937        rng_;
    std::uniform_real_distribution<double> unit_{0.0, 1.0};
};

/// Bytes a sender is kept fed with: what the old stream would take from its
/// connection — at least 2 MiB, twice the congestion window above that.
size_t feed_limit(const UdpConnection& c) {
    return (std::max)(size_t{2} << 20, 2 * size_t{c.recovery().cwnd()});
}

/// One sender and its receiver.
struct Flow {
    Flow(PathSim& path, int index, CongestionAlgorithm algo, Clock::time_point now,
         UdpConnectionConfig rx_cfg)
        : tx_sec(Identity::generate()), rx_sec(Identity::generate()),
          tx(path, Address{*IpAddress::parse("10.0.1." + std::to_string(index + 1)), 1111}, tx_sec,
             config(algo, {})),
          rx(path, Address{*IpAddress::parse("10.0.2." + std::to_string(index + 1)), 2222}, rx_sec,
             config(algo, rx_cfg)) {
        path.attach(&tx, false);
        path.attach(&rx, true);
        tx.listening  = false;
        rx.count_only = true;
        path.set_now(now);
        // Seeded per flow, so two flows probe on different schedules.
        tx.dial(rx.addr(), 0x100 + 0x10 * static_cast<udp::Cid>(index), now);
    }

    static UdpConnectionConfig config(CongestionAlgorithm algo, UdpConnectionConfig c) {
        c.congestion = algo;
        return c;
    }

    UdpConnection& sender() { return *tx.conn; }
    UdpConnection& receiver() { return *rx.conn; }
    size_t delivered() const { return rx.bytes_in; }

    PlaintextSecurity tx_sec, rx_sec;
    End    tx, rx;
    /// Bytes still to offer the sender; it is kept as full as it will take until
    /// this runs out. SIZE_MAX is a bulk transfer that never ends.
    size_t to_send = 0;
    /// When non-zero, the application produces data at this many bytes per
    /// second rather than as fast as the sender takes it.
    double app_rate   = 0;
    double app_credit = 0;
};

/// The path, its flows, and the clock.
struct Sim {
    explicit Sim(double mbps, Clock::duration rtt, size_t queue_pkts, double fwd_loss = 0.0,
                 uint32_t seed = 1)
        : path(mbps, rtt, queue_pkts, fwd_loss, seed), rtt(rtt) {}

    /// `receive` is the receiver's: how far its window may grow.
    Flow& add(CongestionAlgorithm algo, UdpConnectionConfig receive = {}) {
        flows.push_back(std::make_unique<Flow>(path, static_cast<int>(flows.size()), algo, now, receive));
        return *flows.back();
    }

    /// Advance by `d` in steps of `step` — well under any timer a connection arms,
    /// so nothing is resolved coarser than the transport would resolve it.
    void run(Clock::duration d, Clock::duration step = 250us) {
        const auto end = now + d;
        while (now < end) {
            now += step;
            path.deliver_until(now);
            for (auto& f : flows) {
                if (f->tx.established()) offer(*f, step);
                f->tx.tick(now);
                f->rx.tick(now);
                f->rx.read(now);
                f->tx.read(now);
            }
            if (on_step) on_step();
        }
    }

    void offer(Flow& f, Clock::duration step) {
        size_t allowance = SIZE_MAX;
        if (f.app_rate > 0) {
            f.app_credit += f.app_rate * std::chrono::duration<double>(step).count();
            allowance = static_cast<size_t>(f.app_credit);
        }
        UdpConnection& c = f.sender();
        bool queued = false;
        while (f.to_send > 0 && allowance > 0 && c.queued_bytes() < feed_limit(c)) {
            const size_t n = (std::min)({chunk.size(), f.to_send, allowance});
            if (!c.send_message(FrameHeader{MessageType::App, 0, 0}, ByteView(chunk.data(), n))) break;
            queued = true;
            if (f.to_send != SIZE_MAX) f.to_send -= n;
            if (f.app_rate > 0) { f.app_credit -= n; allowance -= n; }
        }
        if (queued) c.flush(now);
    }

    PathSim                            path;
    Clock::duration                    rtt;
    Clock::time_point                  now{};
    std::vector<std::unique_ptr<Flow>> flows;
    std::function<void()>              on_step;
    std::vector<uint8_t>               chunk = std::vector<uint8_t>(64 * 1024, 0xAB);
};

/// A receiver whose window stays where every connection starts it: a sender on a
/// path longer than that is held by the window, with no standing queue — a clean
/// round trip to time loss recovery by.
UdpConnectionConfig fixed_window() {
    UdpConnectionConfig c;
    c.max_window = UdpConnection::kInitialWindow;
    return c;
}

const cc::BbrController& bbr(const UdpConnection& c) {
    return static_cast<const cc::BbrController&>(c.recovery().congestion());
}

/// Stream bytes per second a path of `mbps` carries in full-size packets: a
/// datagram's header, packet number, frame header and the UDP/IP headers the
/// model charges are what is not payload.
double payload_rate(double mbps) {
    constexpr double kPayload = udp::kMaxDatagram - 20;
    return mbps * 1e6 / 8 * kPayload / (udp::kMaxDatagram + 28);
}

double mbps_of(size_t bytes, Clock::duration over) {
    return bytes * 8.0 / std::chrono::duration<double>(over).count() / 1e6;
}

/// The App stream frames of a forward datagram (plaintext: nothing is masked or
/// sealed), as (offset, length).
std::vector<std::pair<uint64_t, uint64_t>> app_frames(const Bytes& d) {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    if (d.empty() || udp::is_long_header(d[0])) return out;
    const size_t header = udp::kShortHeaderSize + (d[0] & 0x03) + 1;
    udp::FrameReader r(d.data() + header, d.size() - header);
    udp::Frame f;
    while (r.next(f))
        if (f.type == udp::kStream && f.stream.stream == static_cast<uint8_t>(MessageType::App))
            out.emplace_back(f.stream.offset, f.stream.data.size());
    return out;
}

bool has_frame(const Bytes& d, uint8_t type) {
    if (d.empty() || udp::is_long_header(d[0])) return false;
    const size_t header = udp::kShortHeaderSize + (d[0] & 0x03) + 1;
    udp::FrameReader r(d.data() + header, d.size() - header);
    udp::Frame f;
    while (r.next(f)) if (f.type == type) return true;
    return false;
}

/// A packet of padding (UdpConnection::pad): full size, a PING and nothing sent
/// for the application.
bool is_padding(const Bytes& d) {
    return d.size() >= udp::kMaxDatagram && has_frame(d, udp::kPing) && !has_frame(d, udp::kLive) &&
           !has_frame(d, udp::kLiveRepair) && !has_frame(d, udp::kStream);
}

/// Lose chosen packets of one flow's data, by their index among the packets that
/// carry new data from the moment this is armed — and, for an index listed twice,
/// the first repair of what that packet carried as well. Packets are never resent
/// here, only their data, so a hole is identified by the stream offset its packet
/// began at, and a repair by carrying that offset again.
struct HoleMaker {
    std::vector<size_t>        holes;
    bool                       armed = false;
    size_t                     index = 0;       ///< new-data packets seen since armed
    uint64_t                   high  = 0;       ///< one past the highest offset seen
    std::map<uint64_t, int>    drops_left;      ///< doomed offset → copies still to lose
    std::map<size_t, uint64_t> offset_of;       ///< hole index → its offset
    std::map<uint64_t, int>    sends;           ///< doomed offset → copies seen
    bool                       saw_ranges = false;

    void install(PathSim& path) {
        path.hook = [this](Bytes& d, const Address&, bool forward) {
            if (!forward) {
                // An ACK naming more than one range: holes are being reported.
                if (has_frame(d, udp::kAck)) {
                    const size_t header = udp::kShortHeaderSize + (d[0] & 0x03) + 1;
                    udp::FrameReader r(d.data() + header, d.size() - header);
                    udp::Frame f;
                    while (r.next(f)) if (f.type == udp::kAck && f.ack.range_count > 0) saw_ranges = true;
                }
                return false;
            }
            const auto frames = app_frames(d);
            if (frames.empty()) return false;
            const uint64_t first = frames.front().first;
            const bool fresh = first >= high;
            for (const auto& [off, len] : frames) high = (std::max)(high, off + len);
            if (fresh && !holes.empty()) {
                if (!armed) { armed = true; index = 0; }
                for (size_t h : holes)
                    if (h == index) { drops_left[first] += 1; offset_of[index] = first; }
                ++index;
            }
            bool drop = false;
            for (auto& [doomed, left] : drops_left) {
                for (const auto& [off, len] : frames) {
                    if (doomed < off || doomed >= off + len) continue;
                    ++sends[doomed];
                    if (left > 0) { --left; drop = true; }
                }
            }
            return drop;
        };
    }

    /// Copies seen of what hole `h` carried — the packet and every repair of it.
    int sends_of(size_t h) const {
        const auto it = offset_of.find(h);
        if (it == offset_of.end()) return 0;
        const auto s = sends.find(it->second);
        return s == sends.end() ? 0 : s->second;
    }
};

} // namespace

// ── Arithmetic ──────────────────────────────────────────────────────────────


TEST(CcMathTest, MulDivIsExactWhereTheProductWouldOverflow) {
    // The cases the transport actually divides: a rate over a nanosecond interval,
    // a byte count over a rate. Each product overflows 64 bits.
    EXPECT_EQ(cc::mul_div(uint64_t{1} << 40, 1000000000ull, 1000000000ull), uint64_t{1} << 40);
    EXPECT_EQ(cc::mul_div(12500000000ull, 4000000000ull, 4000000000ull), 12500000000ull);
    EXPECT_EQ(cc::mul_div(7, 3, 2), 10u);
    EXPECT_EQ(cc::mul_div(5, 5, 0), 0u) << "a zero divisor is defined, not a crash";
#ifdef __SIZEOF_INT128__
    std::mt19937_64 rng(42);
    for (int i = 0; i < 100000; ++i) {
        const uint64_t a = rng() >> (rng() % 40);
        const uint64_t b = rng() >> (rng() % 40 + 24);
        const uint64_t c = (rng() >> 33) + 1;   // below 2^31: the exact regime
        __extension__ typedef unsigned __int128 u128;
        const u128 want = static_cast<u128>(a) * b / c;
        if (want >> 64) continue;               // the result itself does not fit
        ASSERT_EQ(cc::mul_div(a, b, c), static_cast<uint64_t>(want)) << a << "*" << b << "/" << c;
    }
#endif
}

TEST(CcMathTest, APacingRateReleasesWhatItTakesTimeToRelease) {
    const cc::PacingRate rate = cc::PacingRate::per_second(1250000);   // 10 Mbit/s
    EXPECT_EQ(rate.bytes_over(1ms), 1250u);
    EXPECT_EQ(rate.time_for(1250), Clock::duration(1ms));
    EXPECT_EQ(rate.bytes_over(Clock::duration::zero()), 0u);

    const cc::PacingRate ratio{3600, 40ms};   // a window per round trip
    EXPECT_EQ(ratio.bytes_over(10ms), 900u);
    EXPECT_EQ(ratio.time_for(900), Clock::duration(10ms));
    EXPECT_FALSE(cc::PacingRate{}.paced());
}

// ── Delivery-rate estimation ────────────────────────────────────────────────

namespace {

/// A sender sending one packet every `gap`, each acknowledged `rtt` after it left.
struct SamplerRig {
    cc::DeliveryRateSampler sampler;
    struct Sent { cc::TxState tx; uint64_t seq; Clock::time_point acked_at; };
    std::deque<Sent>  flight;
    Clock::time_point now{};
    uint64_t          inflight = 0;
    uint64_t          seq      = 1;

    void send(uint64_t bytes, Clock::duration rtt) {
        Sent s;
        s.seq = seq++;
        sampler.on_sent(s.tx, now, inflight, inflight + bytes);
        inflight += bytes;
        s.acked_at = now + rtt;
        flight.push_back(s);
    }

    /// Acknowledge everything due by `now`, one acknowledgement per packet.
    std::vector<cc::RateSample> ack_due(Clock::duration min_rtt, uint64_t bytes) {
        std::vector<cc::RateSample> out;
        while (!flight.empty() && flight.front().acked_at <= now) {
            sampler.on_delivered(flight.front().tx, flight.front().seq, bytes, now);
            inflight -= bytes;
            flight.pop_front();
            out.push_back(sampler.take_sample(min_rtt));
        }
        return out;
    }
};

} // namespace

TEST(DeliveryRateTest, MeasuresTheRateAPathDelivers) {
    SamplerRig r;
    // 1200 bytes every millisecond: 1.2 MB/s, whatever the round trip.
    std::vector<cc::RateSample> samples;
    for (int i = 0; i < 400; ++i) {
        r.send(1200, 50ms);
        r.now += 1ms;
        for (const auto& s : r.ack_due(50ms, 1200)) samples.push_back(s);
    }
    ASSERT_GT(samples.size(), 300u);
    for (size_t i = 100; i < samples.size(); ++i) {
        ASSERT_TRUE(samples[i].rate_valid) << i;
        EXPECT_NEAR(static_cast<double>(samples[i].delivery_rate), 1.2e6, 1.2e6 * 0.01) << i;
        EXPECT_FALSE(samples[i].is_app_limited);
    }
}

TEST(DeliveryRateTest, AppLimitedSamplesAreFlaggedUntilTheBubbleIsDelivered) {
    SamplerRig r;
    for (int i = 0; i < 100; ++i) {
        r.send(1200, 20ms);
        r.now += 1ms;
        r.ack_due(20ms, 1200);
    }
    // The application runs dry with 20 packets in flight. Everything sent from here
    // until those, and these, are delivered measures the application.
    r.sampler.mark_app_limited(r.inflight);
    ASSERT_TRUE(r.sampler.app_limited());
    for (int i = 0; i < 5; ++i) {
        r.send(1200, 20ms);
        r.now += 4ms;
    }
    bool saw_limited = false;
    for (int i = 0; i < 100; ++i) {
        r.now += 1ms;
        for (const auto& s : r.ack_due(20ms, 1200)) saw_limited |= s.is_app_limited;
        if (r.flight.empty()) break;
    }
    EXPECT_TRUE(saw_limited) << "packets sent inside the bubble were not flagged";
    EXPECT_FALSE(r.sampler.app_limited()) << "the bubble outlived its own delivery";

    // And the next packet sent is the path's again.
    r.send(1200, 20ms);
    r.now += 20ms;
    const auto after = r.ack_due(20ms, 1200);
    ASSERT_EQ(after.size(), 1u);
    EXPECT_FALSE(after[0].is_app_limited);
}

TEST(DeliveryRateTest, AnIntervalShorterThanTheMinimumRoundTripIsNotTrusted) {
    SamplerRig r;
    // A whole window acknowledged at one instant — ack compression. Its "rate" is
    // whatever the burst size divided by a sliver of time comes to.
    for (int i = 0; i < 10; ++i) r.send(1200, 5ms);
    r.now += 5ms;
    const auto samples = r.ack_due(50ms, 1200);   // the path's real minimum is 50 ms
    ASSERT_EQ(samples.size(), 10u);
    for (const auto& s : samples) {
        EXPECT_TRUE(s.acked);
        EXPECT_FALSE(s.rate_valid) << "a compressed interval was believed";
    }
}
// ── Loss recovery ───────────────────────────────────────────────────────────

// Holes far apart in one window. The receiver names every one of them at once in
// its ACK ranges, so they are repaired within the same round trip — rather than
// each becoming visible only when the hole in front of it fills.
TEST(UdpLossRecoveryTest, HolesFarApartAreRepairedInTheSameRoundTrip) {
    Sim sim(100, 100ms, 2000);
    HoleMaker holes;
    holes.install(sim.path);

    Flow& f = sim.add(CongestionAlgorithm::Reno, fixed_window());
    f.to_send = SIZE_MAX;
    sim.run(2s);   // a window far wider than the spread of the holes
    ASSERT_GT(f.sender().recovery().cwnd(), 400u * cc::kMss);
    ASSERT_EQ(f.sender().recovery().retransmits(), 0u);

    holes.holes = {0, 60, 120, 180, 240, 300};
    const uint32_t before = f.sender().recovery().retransmits();
    Clock::time_point first{}, last{};
    uint32_t          seen = 0;
    sim.on_step = [&] {
        const uint32_t now_rtx = f.sender().recovery().retransmits() - before;
        if (now_rtx == seen) return;
        if (seen == 0) first = sim.now;
        last = sim.now;
        seen = now_rtx;
    };
    sim.run(3s);
    sim.on_step = nullptr;

    ASSERT_EQ(f.sender().recovery().retransmits() - before, holes.holes.size())
        << "something was declared lost that was not, or a hole was not";
    ASSERT_NE(first, Clock::time_point{});
    EXPECT_TRUE(holes.saw_ranges);
    EXPECT_LE(last - first, sim.rtt) << "holes named together were repaired rounds apart";
    EXPECT_EQ(f.sender().recovery().congestion_events(), 1u) << "one episode, and no timeout";
    for (size_t i = 0; i < holes.holes.size(); ++i) EXPECT_EQ(holes.sends_of(holes.holes[i]), 2) << i;
    EXPECT_FALSE(f.sender().dead());
}

// A repair can be lost too. It is not left to the retransmission timeout: once a
// packet sent after it has arrived, it is overdue by the same reasoning that
// condemned the original (RACK, RFC 8985), and its data goes out again.
TEST(UdpLossRecoveryTest, ALostRepairIsRepairedAgainWithoutATimeout) {
    for (const auto algo : {CongestionAlgorithm::Reno, CongestionAlgorithm::Bbr}) {
        SCOPED_TRACE(to_string(algo));
        // The application sends at half the link rate, so new data keeps leaving
        // after the repair: the evidence RACK reads.
        Sim sim(50, 40ms, 2000);
        HoleMaker holes;
        holes.install(sim.path);
        Flow& f    = sim.add(algo);
        f.to_send  = SIZE_MAX;
        f.app_rate = payload_rate(50) / 2;
        sim.run(2s);
        const uint32_t events = f.sender().recovery().congestion_events();
        ASSERT_EQ(f.sender().recovery().retransmits(), 0u);

        holes.holes = {10, 10};   // the packet, and then its first repair
        sim.run(2s);

        EXPECT_EQ(holes.sends_of(10), 3) << "the lost repair was not sent again";
        EXPECT_EQ(f.sender().recovery().retransmits(), 2u) << "something else was given up on";
        EXPECT_LE(f.sender().recovery().congestion_events() - events, 2u)
            << "a timeout fired over two losses";
        EXPECT_FALSE(f.sender().dead());
    }
}

// The other way a repair goes missing: as the last thing the sender has to send.
// Nothing leaves after it, so nothing can arrive after it to give the loss away.
// A probe asks, as it does outside recovery (RFC 9002 keeps the probe timer
// running in recovery for exactly this); left to the retransmission timeout it
// costs at least kMinRto — ten round trips here — and the whole window with it.
TEST(UdpLossRecoveryTest, ALostTailRepairIsProbedRatherThanTimedOut) {
    for (const auto algo : {CongestionAlgorithm::Reno, CongestionAlgorithm::Bbr}) {
        SCOPED_TRACE(to_string(algo));
        Sim sim(100, 10ms, 2000);
        HoleMaker holes;
        holes.install(sim.path);
        Flow& f = sim.add(algo);
        sim.run(100ms);   // the dial, and a round-trip estimate to time the probe by
        ASSERT_TRUE(f.tx.established());
        const uint32_t events = f.sender().recovery().congestion_events();

        // One message; the packet four from its end is lost and so is its repair.
        constexpr size_t kPackets = 20;
        constexpr size_t kHole    = kPackets - 4;
        holes.holes = {kHole, kHole};
        const size_t total = kPackets * (udp::kMaxDatagram - 40);
        f.to_send = total;

        Clock::time_point repair_lost{}, done{};
        sim.on_step = [&] {
            if (repair_lost == Clock::time_point{} && holes.sends_of(kHole) >= 2) repair_lost = sim.now;
            if (done == Clock::time_point{} && f.delivered() == total) done = sim.now;
        };
        sim.run(2s);
        sim.on_step = nullptr;

        ASSERT_NE(repair_lost, Clock::time_point{}) << "the repair was never sent";
        ASSERT_NE(done, Clock::time_point{}) << "the message never arrived";
        EXPECT_EQ(holes.sends_of(kHole), 3);
        EXPECT_LT(done - repair_lost, udp::Recovery::kMinRto)
            << "the lost repair waited for the retransmission timeout";
        EXPECT_LE(f.sender().recovery().congestion_events() - events, 2u);
        EXPECT_FALSE(f.sender().dead());
    }
}

// However many acknowledgements report the holes of one loss, the controller is
// told about one congestion event — Reno halves once, BBR runs one round of
// packet conservation.
TEST(UdpLossRecoveryTest, OneLossEpisodeIsOneCongestionEvent) {
    for (const auto algo : {CongestionAlgorithm::Reno, CongestionAlgorithm::Bbr}) {
        SCOPED_TRACE(to_string(algo));
        Sim sim(50, 40ms, 2000);
        HoleMaker holes;
        holes.install(sim.path);
        // The window held where it starts, so the only losses are the burst: with
        // room to grow Reno would also fill the 2000-packet queue to overflowing.
        Flow& f = sim.add(algo, fixed_window());
        f.to_send = SIZE_MAX;
        sim.run(2s);
        const uint32_t events = f.sender().recovery().congestion_events();
        ASSERT_EQ(f.sender().recovery().retransmits(), 0u);

        for (size_t i = 0; i < 24; ++i) holes.holes.push_back(i);   // one wide burst
        sim.run(2s);
        EXPECT_EQ(f.sender().recovery().congestion_events() - events, 1u);
        EXPECT_EQ(f.sender().recovery().retransmits(), 24u);
        EXPECT_FALSE(f.sender().dead());
    }
}

// A comb of holes across most of a full window: every eighth packet. Each ACK
// repeats the ranges the receiver holds, and the holes surface over several round
// trips — everything loss detection walks incrementally. Each hole is repaired
// exactly once, and the connection comes out of it delivering again.
TEST(UdpLossRecoveryTest, AWideCombOfHolesIsRepairedOncePerHole) {
    for (const auto algo : {CongestionAlgorithm::Reno, CongestionAlgorithm::Bbr}) {
        SCOPED_TRACE(to_string(algo));
        Sim sim(100, 100ms, 2000);
        HoleMaker holes;
        holes.install(sim.path);
        Flow& f = sim.add(algo, fixed_window());   // no queue: every loss is one of ours
        f.to_send = SIZE_MAX;
        sim.run(2s);
        ASSERT_EQ(f.sender().recovery().retransmits(), 0u);

        for (size_t i = 0; i < 100; ++i) holes.holes.push_back(8 * i);
        sim.run(3s);
        const size_t after_recovery = f.delivered();
        sim.run(1s);

        EXPECT_EQ(f.sender().recovery().retransmits(), holes.holes.size());
        for (size_t h : holes.holes) EXPECT_EQ(holes.sends_of(h), 2) << "hole " << h;
        // Reno climbs back a packet per round trip from half the window: at 1 MiB
        // per 100 ms that is past 4 MB in the second after.
        EXPECT_GT(f.delivered() - after_recovery, 4u * 1000 * 1000) << "the connection did not recover";
        EXPECT_FALSE(f.sender().dead());
    }
}

// ── Reordering ──────────────────────────────────────────────────────────────

namespace {

/// A Recovery driven by hand: packets sent and acknowledged one at a time, each
/// acknowledgement naming that packet alone.
struct HandDriven {
    struct NullSink final : udp::FrameSink {
        void frames_acked(const RingBuffer<udp::SentFrame>&, size_t, size_t) override {}
        void frames_lost(const RingBuffer<udp::SentFrame>&, size_t, size_t) override {}
        bool repairs_pending() const override { return false; }
    } sink;
    Clock::time_point now = Clock::time_point{} + 1h;
    udp::Recovery     r{CongestionAlgorithm::Reno, now, 1};

    uint64_t send() {
        const uint64_t pn = r.next_pn();
        r.on_packet_sent(now, 1000, /*ack_eliciting=*/true, /*data=*/true, false, false);
        return pn;
    }
    /// `delay`: what the peer says it held the acknowledgement for.
    void ack(uint64_t pn, Clock::duration delay = {}) {
        udp::AckFrame a;
        a.largest = pn;
        a.delay   = static_cast<uint64_t>(delay / udp::kAckDelayUnit);
        ASSERT_TRUE(r.on_ack(a, now, sink));
    }
};

} // namespace

// A packet given up on whose acknowledgement still comes was overtaken, not
// lost. From then on three packets acknowledged past one prove nothing — how
// many overtake it follows the sending rate — and the window it is given covers
// how late the overtaken one was. It is no loss rate either — and all of it
// holds while a live message is outstanding: the path is the same path.
TEST(UdpLossRecoveryTest, APacketAcknowledgedAfterItWasGivenUpOnWidensTheReorderWindow) {
    HandDriven h;
    std::vector<uint64_t> pn;
    for (int i = 0; i < 10; ++i) {
        pn.push_back(h.send());
        h.now += 1ms;
    }
    h.now = h.now - 10ms + 60ms;   // packet 0 answered after 60 ms
    h.ack(pn[0]);
    for (int i = 2; i <= 5; ++i) {
        h.now += 1ms;
        h.ack(pn[i]);
    }
    ASSERT_EQ(h.r.retransmits(), 1u) << "three acknowledged past it, packet 1 is lost";
    ASSERT_EQ(h.r.path_lost(), 1000u);
    const Clock::duration base_window = h.r.reorder_window();
    EXPECT_EQ(base_window, h.r.rtt().min_rtt / 4) << "a quarter of the minimum round trip";

    h.now += 10ms;   // packet 1 arrives 14 ms after packet 5's round trip says it should have
    h.ack(pn[1]);
    EXPECT_EQ(h.r.spurious(), 1000u);
    EXPECT_EQ(h.r.path_lost(), 0u) << "reordering counted as the path's loss";
    EXPECT_FALSE(h.r.counts_packets());
    EXPECT_EQ(h.r.reorder_window(), base_window + 14ms);
    for (int i = 6; i < 10; ++i) h.ack(pn[i]);

    // Overtaken by five, a packet is now given its window.
    std::vector<uint64_t> next;
    for (int i = 0; i < 7; ++i) next.push_back(h.send());
    h.now += 60ms;
    for (int i = 1; i <= 5; ++i) h.ack(next[i]);
    EXPECT_EQ(h.r.retransmits(), 1u) << "the count still decided";

    h.r.set_impatient(true);
    EXPECT_FALSE(h.r.counts_packets());
    EXPECT_EQ(h.r.reorder_window(), base_window + 14ms);
    h.ack(next[6]);
    EXPECT_EQ(h.r.retransmits(), 1u) << "a live message forgot what the path had shown";
}

// A path whose packets come later than its whole round trip — Wi-Fi to a peer on
// the same LAN: 2 ms, and 10 ms of jitter. A window stopped at a round trip could
// not hold that, and every such packet was a loss again; it stops at a probe
// timeout instead, past which a probe asks anyway.
TEST(UdpLossRecoveryTest, TheReorderWindowCoversLatenessPastTheRoundTrip) {
    HandDriven h;
    const auto step = [&](Clock::duration rtt, uint64_t first, uint64_t last) {
        h.now += rtt;
        for (uint64_t p = first; p <= last; ++p) h.ack(p);
    };
    for (int i = 0; i < 8; ++i) {   // a 2 ms path
        const uint64_t p = h.send();
        step(2ms, p, p);
    }

    const uint64_t overtaken = h.send();
    const uint64_t later     = h.send();
    for (int i = 0; i < 3; ++i) h.send();
    step(2ms, later, later + 3);
    ASSERT_EQ(h.r.retransmits(), 1u);
    h.now += 10ms;
    h.ack(overtaken);
    ASSERT_EQ(h.r.spurious(), 1000u) << "a packet 10 ms late was no longer kept to learn from";
    EXPECT_LT(h.r.rtt().srtt, Clock::duration(4ms));
    EXPECT_GE(h.r.reorder_window(), Clock::duration(10ms)) << "held to the round trip";
    EXPECT_LE(h.r.reorder_window(), h.r.probe_timeout());

    // The next one 8 ms late is waited for.
    const uint64_t again = h.send();
    const uint64_t after = h.send();
    for (int i = 0; i < 3; ++i) h.send();
    step(2ms, after, after + 3);
    h.now += 8ms;
    h.r.on_timer(h.now, h.sink);
    h.ack(again);
    EXPECT_EQ(h.r.retransmits(), 1u) << "taken for lost again";
}

// What a path did once is forgotten after kReorderMemory loss episodes with no
// packet turning up late: otherwise every later loss is found a window late.
TEST(UdpLossRecoveryTest, ReorderingIsForgottenAfterLossesThatWereReal) {
    HandDriven h;
    const uint64_t first = h.send(), overtaken = h.send();
    for (int i = 0; i < 3; ++i) h.send();
    h.now += 60ms;
    h.ack(first);
    for (uint64_t p = overtaken + 1; p < overtaken + 4; ++p) h.ack(p);
    h.now += 20ms;
    h.ack(overtaken);
    ASSERT_FALSE(h.r.counts_packets());

    // Each round loses its first packet for real: found by the window, an episode
    // of its own once the one before is over.
    for (int episode = 1; episode <= udp::Recovery::kReorderMemory; ++episode) {
        SCOPED_TRACE(episode);
        EXPECT_FALSE(h.r.counts_packets());
        const uint32_t events = h.r.congestion_events();
        const uint64_t lost = h.send();
        const uint64_t after = h.send();
        h.now += 60ms;
        h.ack(after);
        h.now += 60ms;
        h.r.on_timer(h.now, h.sink);
        ASSERT_EQ(h.r.congestion_events(), events + 1) << "packet " << lost << " was not one episode";
    }
    EXPECT_TRUE(h.r.counts_packets());
    EXPECT_EQ(h.r.reorder_window(), h.r.rtt().min_rtt / 4);
}

// A path that loses nothing and holds one datagram in a hundred back 8 ms,
// overtaken by every one sent meanwhile. Taken for loss, that was the data sent
// twice, a congestion event every round trip or so, and Reno's window halved
// each time; learnt, it costs a handful of repairs at the start.
TEST(UdpLossRecoveryTest, APathThatOnlyReordersIsNotTakenForALossyOne) {
    for (const auto algo : {CongestionAlgorithm::Reno, CongestionAlgorithm::Bbr}) {
        SCOPED_TRACE(to_string(algo));
        Sim sim(50, 20ms, 104);
        sim.path.fwd().late    = 0.01;
        sim.path.fwd().late_by = 8ms;
        Flow& f = sim.add(algo);
        f.to_send = SIZE_MAX;
        sim.run(10s);

        const udp::Recovery& r = f.sender().recovery();
        EXPECT_GT(r.spurious(), 0u);
        EXPECT_FALSE(r.counts_packets());
        EXPECT_GE(r.reorder_window(), Clock::duration(8ms));
        EXPECT_LT(r.retransmits(), 60u + sim.path.fwd().drops) << "beyond the queue's own drops";
        EXPECT_GT(mbps_of(f.delivered(), 10s), 35.0);
        EXPECT_FALSE(f.sender().dead());
    }
}

// The queue at the bottleneck stood through a round trip when not one packet of
// it came back near the base round trip: one that did — jitter holds some
// packets back, never all — says the queue emptied, and what the peer held its
// acknowledgement for is no queue either. A path whose own delay grew is a queue
// for a window at least, never for good: the base follows it within two.
TEST(UdpLossRecoveryTest, AQueueStandsWhileNoRoundTripOfARoundComesBackNearTheBase) {
    HandDriven h;
    // One packet a round trip, answered `rtt` after it left.
    const auto round_trip = [&](Clock::duration rtt, Clock::duration ack_delay = {}) {
        const uint64_t pn = h.send();
        h.now += rtt;
        h.ack(pn, ack_delay);
    };
    for (int i = 0; i < 5; ++i) round_trip(40ms);
    EXPECT_FALSE(h.r.queue_stood());
    round_trip(70ms);
    EXPECT_TRUE(h.r.queue_stood()) << "the whole round trip 30 ms over the base";
    round_trip(44ms);
    EXPECT_FALSE(h.r.queue_stood()) << "less than an eighth of the base over it is no queue";
    round_trip(60ms, 20ms);
    EXPECT_FALSE(h.r.queue_stood()) << "the peer's ack delay taken for a queue";

    // Two packets 30 ms apart: the first answered after 70 ms, which ends a round
    // trip of its own; the second 2 ms later, after 42 — in the next one, with a
    // third that takes 70 again.
    const uint64_t held = h.send();
    h.now += 30ms;
    const uint64_t on_time = h.send();
    h.now += 40ms;
    h.ack(held);
    EXPECT_TRUE(h.r.queue_stood());
    h.now += 2ms;
    h.ack(on_time);
    round_trip(70ms);
    EXPECT_FALSE(h.r.queue_stood()) << "one packet of the round trip came back near the base";

    const Clock::time_point rose = h.now;
    while (h.now - rose < udp::Recovery::kBaseRttWindow) {
        round_trip(70ms);
        ASSERT_TRUE(h.r.queue_stood()) << "a queue forgotten " << (h.now - rose) / 1ms << " ms on";
    }
    while (h.now - rose < 2 * udp::Recovery::kBaseRttWindow) round_trip(70ms);
    EXPECT_FALSE(h.r.queue_stood()) << "the path's own delay taken for a queue for good";
}

// Live video over such a path, two datagrams in a hundred overtaken: what turns
// up after all is not the path's loss rate, which is what repair symbols are
// sized by. Counted, it bought a stream with no loss to repair 1% of its bytes in
// repair symbols.
TEST(UdpLossRecoveryTest, ReorderingBuysALiveStreamNoRepairSymbols) {
    Sim sim(50, 20ms, 104);
    sim.path.fwd().late    = 0.02;
    sim.path.fwd().late_by = 8ms;
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(200ms);
    ASSERT_TRUE(f.tx.established());

    const std::string frame(60000, 'v');   // 30 a second: 14.4 Mbit/s
    Clock::time_point next = sim.now;
    sim.on_step = [&] {
        if (sim.now < next) return;
        next += 33ms;
        ASSERT_TRUE(f.tx.send_live(MessageType::App, frame, sim.now + 120ms));
        f.tx.conn->flush(sim.now);
    };
    sim.run(10s);
    sim.on_step = nullptr;
    sim.run(500ms);

    const PathStats st = f.sender().path_stats();
    EXPECT_GT(f.sender().recovery().spurious(), 0u) << "nothing was overtaken: the test tests nothing";
    EXPECT_EQ(st.live_expired, 0u);
    EXPECT_LT(st.live_repair_bytes, 15000u) << "repair symbols for a path that loses nothing";
}

// Live video over a path that keeps no order: every datagram, both ways, late by
// its own draw from 0-10 ms, so packets overtake one another all the time and lose
// nothing. Taken for loss by three packets acknowledged past them, as live data
// once was however much the path had shown, a quarter of the stream went twice
// and every overtaken packet reached BBR as congestion: its estimate fell below
// the stream's rate and the frames expired in the queue — 535 of 600.
TEST(UdpLossRecoveryTest, LiveVideoOverAPathThatKeepsNoOrderKeepsItsRate) {
    Sim sim(50, 20ms, 104);
    sim.path.fwd().jitter = 10ms;
    sim.path.rev().jitter = 10ms;
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(200ms);
    ASSERT_TRUE(f.tx.established());

    const std::string frame(25000, 'v');   // 60 a second: 12 Mbit/s
    Clock::time_point next = sim.now;
    int frames = 0;
    sim.on_step = [&] {
        if (sim.now < next) return;
        next += 16667us;
        ++frames;
        ASSERT_TRUE(f.tx.send_live(MessageType::App, frame, sim.now + 110ms));
        f.tx.conn->flush(sim.now);
    };
    sim.run(10s);
    sim.on_step = nullptr;
    sim.run(500ms);

    const udp::Recovery& r = f.sender().recovery();
    const PathStats st = f.sender().path_stats();
    EXPECT_GT(r.spurious(), 0u) << "nothing was overtaken: the test tests nothing";
    EXPECT_LT(st.live_expired, static_cast<uint64_t>(frames / 50)) << "of " << frames << " frames";
    EXPECT_LT(r.retransmits(), r.next_pn() / 20) << "the stream sent twice";
}

// A path that holds every datagram back by its own draw from 0-40 ms, both ways,
// overtaken by those behind it — four times the 10 ms it takes to cross. A
// round-trip sample comes from the newest packet acknowledged, the one that
// overtook the rest, so the minimum is the bare 10 ms, while a full pipe holds
// what ~50 ms of round trip does. Two BDPs over the minimum held a transfer to
// a fifth of the path.
TEST(UdpLossRecoveryTest, TheWindowHoldsWhatAPathThatReordersHoldsAtLoad) {
    for (const uint32_t seed : {1u, 2u}) {
        SCOPED_TRACE(seed);
        Sim sim(100, 10ms, 104, 0.0, seed);
        sim.path.fwd().jitter = 40ms;
        sim.path.rev().jitter = 40ms;
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        f.to_send = SIZE_MAX;
        sim.run(10s);
        EXPECT_LT(f.sender().recovery().rtt().min_rtt, 12ms) << "the path did not show the bare minimum";
        EXPECT_GT(mbps_of(f.delivered(), 10s), 30.0);
    }
}

// ── Flow control ────────────────────────────────────────────────────────────

// On a path whose bandwidth-delay product is larger than a starting window, the
// receiver's window grows past where it started — while the transfer runs, and
// from the sender's report of being held back.
TEST(UdpReceiveWindowTest, GrowsOnAPathLongerThanTheWindow) {
    Sim sim(200, 100ms, 4000);   // 2.5 MB in flight would fill it; 1 MiB is the window
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(3s);
    EXPECT_GT(f.receiver().receive_window(), UdpConnection::kInitialWindow);
    EXPECT_FALSE(f.sender().dead());
}

// A sender stopped by the peer's limit says so — DATA_BLOCKED, naming the limit —
// and only then: it is how a receiver whose window is too small finds out.
TEST(UdpReceiveWindowTest, ASenderStoppedByTheLimitSaysSo) {
    Sim sim(200, 100ms, 4000);
    std::vector<uint64_t> blocked_at;
    sim.path.hook = [&](Bytes& d, const Address&, bool forward) {
        if (!forward || !has_frame(d, udp::kDataBlocked)) return false;
        const size_t header = udp::kShortHeaderSize + (d[0] & 0x03) + 1;
        udp::FrameReader r(d.data() + header, d.size() - header);
        udp::Frame f;
        while (r.next(f)) if (f.type == udp::kDataBlocked) blocked_at.push_back(f.value);
        return false;
    };
    Flow& f = sim.add(CongestionAlgorithm::Bbr, fixed_window());
    f.to_send = SIZE_MAX;
    sim.run(2s);
    ASSERT_FALSE(blocked_at.empty()) << "a sender held at the limit never said so";
    for (const uint64_t at : blocked_at) EXPECT_GE(at, UdpConnection::kInitialWindow);
    EXPECT_TRUE(std::is_sorted(blocked_at.begin(), blocked_at.end())) << "an old limit reported again";
}

// ── Long fat paths ──────────────────────────────────────────────────────────

// A path whose bandwidth-delay product is four times what a connection starts
// with. Every limit on the way grows to meet it and the link is filled.
TEST(UdpLongPathTest, FillsAPathFourTimesTheStartingWindow) {
    Sim sim(400, 100ms, 4200);   // 5 MB in flight to fill it, 1 BDP of buffer
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(4s);
    const size_t at = f.delivered();
    sim.run(2s);

    const double mbps = mbps_of(f.delivered() - at, 2s);
    EXPECT_GT(mbps, 0.85 * payload_rate(400) * 8 / 1e6) << "only " << mbps << " Mbit/s on a 400 Mbit/s path";
    EXPECT_GT(f.receiver().receive_window(), 4 * UdpConnection::kInitialWindow) << "the window never grew";
    EXPECT_FALSE(f.sender().dead());
}

// A window held back by the receiver says nothing about what the path would carry,
// and Reno must not grow on the acks it produces: a congestion window grown that
// way runs off far past anything in flight, and takes a spurious loss with it when
// it is finally cut.
TEST(UdpLongPathTest, RenoDoesNotGrowAWindowTheReceiverKeepsFromFilling) {
    Sim sim(200, 100ms, 2000);   // a BDP twice the receiver's fixed window
    Flow& f = sim.add(CongestionAlgorithm::Reno, fixed_window());
    f.to_send = SIZE_MAX;
    sim.run(5s);
    const uint64_t window = UdpConnection::kInitialWindow;
    EXPECT_LE(f.sender().recovery().cwnd(), 2 * window + 4 * cc::kMss)
        << "the window grew to " << f.sender().recovery().cwnd() << " B with the receiver holding the flight to "
        << window;
    EXPECT_GT(f.sender().recovery().cwnd(), window / 2) << "the window did not even reach what the receiver allows";
}

// ── A coarse host clock ─────────────────────────────────────────────────────

// A virtualised or power-managed host sleeps 2-15 ms on a 1 ms poll timeout, and
// takes arrivals in the same late batches. The pacer must still release the rate
// it was given: when it kept only one quantum of tokens across a late wake-up,
// the sender sent a fraction of its pacing rate, BBR took that fraction for the
// path, and each round paced lower than the last.
TEST(UdpCoarseClockTest, APacedSenderKeepsItsRateWhenTheHostWakesLate) {
    for (const auto algo : {CongestionAlgorithm::Bbr, CongestionAlgorithm::Reno}) {
        for (const auto wake : {Clock::duration(4ms), Clock::duration(15ms)}) {
            Sim sim(100, 40ms, 400);   // 1 BDP of buffer
            Flow& f = sim.add(algo);
            f.to_send = SIZE_MAX;
            sim.run(6s, wake);
            const size_t at = f.delivered();
            sim.run(4s, wake);

            const double util = (f.delivered() - at) / 4.0 / payload_rate(100);
            EXPECT_GT(util, 0.8) << to_string(algo) << " used " << util * 100
                                 << "% of the path on a host that wakes every "
                                 << std::chrono::duration_cast<std::chrono::milliseconds>(wake).count() << " ms";
        }
    }
}

// ── What one release puts on the wire ───────────────────────────────────────

// Each release of the pacer leaves at line rate, and the queue in front of the
// bottleneck has to hold whatever of it arrives faster than it drains. A real
// path took a train of 96 datagrams whole and lost everything of one of 128 past
// the ~120th. So no step may put more than one kPaceMaxBurst on the wire, even in
// a startup at a gigabit.
TEST(UdpPacingTest, NoReleasePutsMoreThanOneBurstOnTheWire) {
    for (const auto algo : {CongestionAlgorithm::Bbr, CongestionAlgorithm::Reno}) {
        Sim sim(1000, 20ms, 1700);
        Flow& f = sim.add(algo);
        f.to_send = SIZE_MAX;
        size_t step = 0, worst = 0;
        sim.path.hook = [&](Bytes& datagram, const Address&, bool forward) {
            if (forward) step += datagram.size();
            return false;
        };
        sim.on_step = [&] { worst = (std::max)(worst, step); step = 0; };
        sim.run(3s);
        // One release of the pacer, and at most one more of repairs, which a few
        // of go without asking it.
        EXPECT_LE(worst, 2 * (udp::Recovery::kPaceMaxBurst + udp::kMaxDatagram))
            << to_string(algo) << " put " << worst << " bytes on the wire at once";
    }
}

// The same bound when the path comes back from an outage. The timeout writes off
// the whole flight, so everything that goes out next is a repair, and BBR hands
// back its window on the first acknowledgement. With repairs let past the pacer
// that window — hundreds of datagrams — left in one step, and a shallow queue
// dropped most of it: a second loss round, on a path that had only just answered.
TEST(UdpPacingTest, AnOutageEndsWithoutABurst) {
    for (const auto algo : {CongestionAlgorithm::Bbr, CongestionAlgorithm::Reno}) {
        Sim sim(100, 40ms, 120);   // a buffer of about a third of the BDP
        Flow& f   = sim.add(algo);
        f.to_send = SIZE_MAX;
        sim.run(6s);

        sim.path.blackout = true;
        sim.run(1500ms);
        sim.path.blackout = false;

        size_t step = 0, worst = 0;
        sim.path.hook = [&](Bytes& datagram, const Address&, bool forward) {
            if (forward) step += datagram.size();
            return false;
        };
        sim.on_step = [&] { worst = (std::max)(worst, step); step = 0; };
        const size_t drops = sim.path.fwd().drops;
        const size_t start = f.delivered();
        sim.run(1s);

        EXPECT_LE(worst, 2 * (udp::Recovery::kPaceMaxBurst + udp::kMaxDatagram))
            << to_string(algo) << " put " << worst << " bytes on the wire at once after the outage";
        EXPECT_LT(sim.path.fwd().drops - drops, 100u)
            << to_string(algo) << ": the queue dropped " << sim.path.fwd().drops - drops
            << " datagrams in the second after the path came back";
        EXPECT_FALSE(f.sender().dead());
        EXPECT_GT(f.delivered(), start) << to_string(algo) << " delivered nothing after the outage";
    }
}

// ── BBR ─────────────────────────────────────────────────────────────────────

// The two things BBR is for, on a path with four BDPs of buffer: it finds the
// bottleneck rate, and it does so without parking a queue in front of it. Reno on
// the same path fills the buffer.
TEST(BbrTest, FindsTheBottleneckAndKeepsTheQueueShort) {
    const auto standing_queue = [](CongestionAlgorithm algo, double& util, Flow*& out,
                                   std::unique_ptr<Sim>& keep) {
        keep = std::make_unique<Sim>(20, 40ms, 333);
        Sim& sim = *keep;
        Flow& f  = sim.add(algo);
        f.to_send = SIZE_MAX;
        sim.run(4s);
        const size_t start = f.delivered();
        std::vector<Clock::duration> rtts;
        sim.on_step = [&] { rtts.push_back(f.sender().recovery().rtt().latest); };
        sim.run(6s);
        sim.on_step = nullptr;
        util = (f.delivered() - start) / 6.0 / payload_rate(20);
        out  = &f;
        std::sort(rtts.begin(), rtts.end());
        return rtts[rtts.size() / 2] - sim.rtt;
    };

    double bbr_util = 0, reno_util = 0;
    Flow*  bf = nullptr;
    Flow*  rf = nullptr;
    std::unique_ptr<Sim> keep_b, keep_r;
    const auto bbr_queue  = standing_queue(CongestionAlgorithm::Bbr, bbr_util, bf, keep_b);
    const auto reno_queue = standing_queue(CongestionAlgorithm::Reno, reno_util, rf, keep_r);

    EXPECT_GT(bbr_util, 0.85) << "BBR left the path underused";
    EXPECT_TRUE(bbr(bf->sender()).full_bw_reached());
    // The model counts whole datagrams, payload and all.
    const double wire_rate = 20e6 / 8 * udp::kMaxDatagram / (udp::kMaxDatagram + 28);
    EXPECT_NEAR(static_cast<double>(bbr(bf->sender()).max_bw()), wire_rate, wire_rate * 0.2)
        << "the bandwidth model is off the bottleneck";
    EXPECT_LT(bbr_queue, 10ms) << "BBR is keeping a standing queue";
    EXPECT_GT(reno_queue, 50ms);
    EXPECT_GT(reno_util, 0.85);
}

// Random loss — Wi-Fi, a mobile link — is not congestion. BBR backs off only once
// loss passes its threshold, and keeps most of a path at a loss rate that leaves
// Reno with a fraction of it.
TEST(BbrTest, HoldsItsRateUnderRandomLoss) {
    const auto run = [](CongestionAlgorithm algo) {
        Sim sim(10, 100ms, 104, 0.01, 7);
        Flow& f = sim.add(algo);
        f.to_send = SIZE_MAX;
        sim.run(20s);
        EXPECT_FALSE(f.sender().dead());
        return f.delivered();
    };
    const size_t bbr_bytes  = run(CongestionAlgorithm::Bbr);
    const size_t reno_bytes = run(CongestionAlgorithm::Reno);
    EXPECT_GT(bbr_bytes / 20.0, 0.5 * payload_rate(10)) << "under half the path at 1% loss";
    EXPECT_GT(bbr_bytes, 3 * reno_bytes) << "BBR held no more of a lossy path than Reno";
}

// Every 5 s without a fresh minimum, BBR holds inflight to half a BDP long enough
// for the queue to empty — and then goes back to probing bandwidth.
TEST(BbrTest, ProbesRttAndComesBack) {
    Sim sim(20, 40ms, 83);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(3s);
    const uint64_t bdp = bbr(f.sender()).bdp();

    bool     in_probe_rtt = false, came_back = false;
    int      entries      = 0;
    uint32_t worst_cwnd   = 0;
    sim.on_step = [&] {
        const bool now_in = bbr(f.sender()).state() == cc::BbrController::State::ProbeRtt;
        if (now_in && !in_probe_rtt) { ++entries; worst_cwnd = 0; }
        if (now_in) worst_cwnd = (std::max)(worst_cwnd, f.sender().recovery().cwnd());
        if (!now_in && in_probe_rtt) came_back = true;
        in_probe_rtt = now_in;
    };
    sim.run(9s);
    sim.on_step = nullptr;

    EXPECT_GE(entries, 1) << "no ProbeRTT in nine seconds of saturation";
    EXPECT_TRUE(came_back) << "ProbeRTT never ended";
    EXPECT_LE(worst_cwnd, (std::max<uint64_t>)(bdp * 6 / 10, cc::BbrController::kMinPipeCwnd) + 4 * cc::kMss)
        << "ProbeRTT did not hold inflight near half a BDP";
}

// Two BBR flows through one bottleneck share it, the second starting late into a
// buffer of one BDP that the first already keeps busy. The pipe stays full,
// nobody starves, and the split is at least roughly fair.
TEST(BbrTest, TwoFlowsShareABottleneckWithoutStarvation) {
    Sim sim(20, 40ms, 83);
    Flow& a   = sim.add(CongestionAlgorithm::Bbr);
    a.to_send = SIZE_MAX;
    sim.run(3s);
    Flow& b   = sim.add(CongestionAlgorithm::Bbr);
    b.to_send = SIZE_MAX;
    sim.run(30s);
    const size_t a0 = a.delivered(), b0 = b.delivered();
    sim.run(30s);
    const double ra   = static_cast<double>(a.delivered() - a0);
    const double rb   = static_cast<double>(b.delivered() - b0);
    const double jain = (ra + rb) * (ra + rb) / (2 * (ra * ra + rb * rb));
    EXPECT_GT((ra + rb) / 30.0, 0.85 * payload_rate(20)) << "the pipe was not kept full";
    EXPECT_GT((std::min)(ra, rb) / (ra + rb), 0.25)
        << "a: " << mbps_of(a.delivered() - a0, 30s) << " Mbit/s, b: "
        << mbps_of(b.delivered() - b0, 30s) << " Mbit/s — one flow is starving the other";
    EXPECT_GT(jain, 0.8);
}

// A two-second outage — every packet lost both ways — costs a timeout, not the
// connection, and the model rebuilds once the path is back.
TEST(BbrTest, RecoversFromAnOutage) {
    Sim sim(20, 40ms, 83);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(4s);
    const uint32_t events = f.sender().recovery().congestion_events();

    sim.path.blackout = true;
    sim.run(2s);
    sim.path.blackout = false;
    sim.run(3s);
    const size_t start = f.delivered();
    sim.run(3s);

    EXPECT_FALSE(f.sender().dead());
    EXPECT_GT(f.sender().recovery().congestion_events(), events) << "the outage went unnoticed";
    EXPECT_GT((f.delivered() - start) / 3.0, 0.8 * payload_rate(20)) << "the rate never came back";
}

// The same outage under Reno. A timeout collapses the window to one packet, and
// what follows must be slow start: when the acknowledgements of packets sent after
// the timeout grew nothing until every repair had gone out, the backlog an outage
// leaves drained at one packet per round trip and the flow stood still for
// seconds after the path came back.
TEST(UdpLossRecoveryTest, RenoSlowStartsOutOfATimeout) {
    Sim sim(20, 40ms, 83);
    Flow& f   = sim.add(CongestionAlgorithm::Reno);
    f.to_send = SIZE_MAX;
    sim.run(4s);
    const uint32_t events = f.sender().recovery().congestion_events();

    sim.path.blackout = true;
    sim.run(2s);
    sim.path.blackout = false;
    sim.run(2s);
    const size_t start = f.delivered();
    sim.run(2s);

    EXPECT_FALSE(f.sender().dead());
    EXPECT_GT(f.sender().recovery().congestion_events(), events) << "the outage went unnoticed";
    EXPECT_FALSE(f.sender().recovery().in_recovery()) << "still repairing the outage";
    EXPECT_GT((f.delivered() - start) / 2.0, 0.7 * payload_rate(20)) << "the rate never came back";
}

// The timeouts that follow the first one while a path stays down each find a
// single packet in flight. Halving that would leave slow start no ceiling to
// climb to; only the first of a run says where the path congested.
TEST(UdpLossRecoveryTest, RenoKeepsSsthreshAcrossBackedOffTimeouts) {
    cc::RttEstimate rtt;
    cc::RenoController reno(rtt, Clock::time_point{});
    reno.on_timeout(Clock::time_point{}, 100 * cc::kMss);
    EXPECT_EQ(reno.ssthresh(), 50 * cc::kMss);
    EXPECT_EQ(reno.cwnd(), cc::kMss);
    reno.on_timeout(Clock::time_point{}, cc::kMss);
    reno.on_timeout(Clock::time_point{}, cc::kMss);
    EXPECT_EQ(reno.ssthresh(), 50 * cc::kMss) << "a backed-off timeout lowered ssthresh";

    // Once the path answers, the next timeout is a new one.
    cc::AckEvent ack;
    ack.newly_acked = cc::kMss;
    reno.on_ack(ack);
    reno.on_timeout(Clock::time_point{}, 10 * cc::kMss);
    EXPECT_EQ(reno.ssthresh(), 5 * cc::kMss);
}

// The controller's randomness (the probe schedule) is seeded from the connection,
// so a run is a pure function of its inputs — which is what makes every figure in
// this file and in bench_path reproducible.
TEST(BbrTest, IsDeterministic) {
    const auto run = [] {
        Sim sim(10, 60ms, 50, 0.005, 3);
        Flow& f   = sim.add(CongestionAlgorithm::Bbr);
        f.to_send = SIZE_MAX;
        sim.run(8s);
        return std::make_pair(f.delivered(), f.sender().recovery().retransmits());
    };
    EXPECT_EQ(run(), run());
}

// After ten seconds of application silence BBR keeps its model and lets its
// pacing rate govern the restart. What must not happen is the whole window going
// out at once.
TEST(BbrTest, AnIdleConnectionResumesAtItsPacingRateNotInABurst) {
    Sim sim(50, 40ms, 400);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(4s);
    f.to_send = 0;
    sim.run(10s);
    ASSERT_EQ(f.sender().recovery().bytes_in_flight(), 0u);
    const uint32_t window = f.sender().recovery().cwnd();
    ASSERT_GT(window, 100u * cc::kMss) << "the warm-up never grew the window";

    const size_t before = sim.path.fwd().sent;
    f.to_send = cc::kMss * 2000;
    sim.run(1ms, 1ms);
    const size_t burst = sim.path.fwd().sent - before;
    const auto   rate  = f.sender().recovery().congestion().pacing_rate();
    EXPECT_LE(burst * cc::kMss, rate.bytes_over(2ms) + 3 * cc::kMss)
        << burst << " packets in the first millisecond after idle";
    EXPECT_LT(burst * cc::kMss, window / 4) << "the window went out in one burst";
}

// Peer-to-peer traffic is app-limited most of the time, and that rate says
// nothing about the path: it must not pull the bandwidth estimate down to it.
TEST(BbrTest, AppLimitedTrafficDoesNotLowerTheEstimate) {
    Sim sim(20, 40ms, 83);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(5s);
    const uint64_t estimate = bbr(f.sender()).max_bw();
    ASSERT_GT(estimate, payload_rate(20) * 0.8);

    f.to_send = 0;
    for (int i = 0; i < 80; ++i) {
        f.to_send = 300;
        sim.run(100ms);
    }
    EXPECT_GT(bbr(f.sender()).max_bw(), estimate * 8 / 10) << "an application's pace was taken for the path's";
}

TEST(BbrTest, FillsAWindowLargerThanTheOldCeiling) {
    Sim sim(100, 100ms, 1041);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    size_t peak = 0;
    sim.on_step = [&] { peak = (std::max)(peak, f.sender().recovery().bytes_in_flight()); };
    sim.run(4s);
    EXPECT_GT(peak, 256u * cc::kMss);
    EXPECT_GT(mbps_of(f.delivered(), 4s), 50.0);
}

// A buffer a tenth of a BDP deep overflows long before Startup's bandwidth
// samples stop growing. The loss is what ends Startup there, and the inflight it
// happened at becomes the long-term bound the probes then work from.
TEST(BbrTest, AShallowBufferEndsStartupOnLoss) {
    Sim sim(10, 100ms, 10);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(5s);
    EXPECT_TRUE(bbr(f.sender()).full_bw_reached());
    EXPECT_NE(bbr(f.sender()).inflight_hi(), cc::BbrController::kInfinite)
        << "loss above the threshold never set a long-term bound";
    const size_t start = f.delivered();
    sim.run(10s);
    EXPECT_GT((f.delivered() - start) / 10.0, 0.6 * payload_rate(10));
}

// Startup only raises its pacing rate, and an app-limited flow that never queues
// stays in it; whatever the rate was before the first round trip would be the
// speed every keyframe goes out at. It comes from the handshake's round trip now,
// so it is the path's from the start.
TEST(BbrTest, AnAppLimitedFlowIsPacedFromTheMeasuredRoundTrip) {
    Sim sim(10, 40ms, 41);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    for (int i = 0; i < 90; ++i) {   // 15 KB thirty times a second: 3.6 Mbit/s
        f.to_send = 15'000;
        sim.run(33ms);
    }
    const PathStats st = f.sender().path_stats();
    EXPECT_LT(st.pacing_bps, 4 * 10e6) << "pacing at " << st.pacing_bps / 1e6 << " Mbit/s on a 10 Mbit/s path";
    EXPECT_GT(st.pacing_bps, 10e6) << "Startup paces above the estimate, not below it";
}

// ── A live feed's start ─────────────────────────────────────────────────────

namespace {

/// A live feed of constant rate on a flow, as an MPEG-TS stream is carried: six
/// TS packets a message, `mbps` from the first, each message worth `lifetime`.
struct Feed {
    static constexpr size_t kMessage = 6 * 188;

    Sim&            sim;
    Flow&           flow;
    double          mbps;
    Clock::duration lifetime;
    double          credit = 0;

    void play(Clock::duration d) {
        const std::string message(kMessage, 'f');
        const auto        until = sim.now + d;
        while (sim.now < until) {
            for (credit += mbps * 1e6 / 8 / 1000; credit >= kMessage; credit -= kMessage)
                flow.tx.send_live(MessageType::App, message, sim.now + lifetime);
            flow.sender().flush(sim.now);
            sim.run(1ms);
        }
    }
};

/// A round trip of 100 ms as each controller knows it.
cc::RttEstimate rtt_of_100ms() {
    cc::RttEstimate rtt;
    rtt.have_rtt = true;
    rtt.srtt = rtt.min_rtt = rtt.latest = 100ms;
    return rtt;
}

} // namespace

// Startup sends a few packets a round trip and doubles that each one; a feed of
// constant rate is at its rate from its first message. Until the controller has
// a verdict on the path, it sends no slower than live data is offered, through a
// window that lets that out — and no faster: the floor is the feed's own load.
TEST(BbrTest, InStartupSendsNoSlowerThanLiveDataIsOffered) {
    const cc::RttEstimate rtt = rtt_of_100ms();
    cc::DeliveryRateSampler sampler;
    cc::BbrController bbr(rtt, sampler, Clock::time_point{}, 1);
    const uint64_t pacing = bbr.pacing_rate().bytes_over(1s);
    const uint32_t cwnd   = bbr.cwnd();
    ASSERT_LT(pacing, 1'000'000u);

    bbr.on_live_offered(1'000'000);   // 8 Mbit/s
    EXPECT_EQ(bbr.pacing_rate().bytes_over(1s), 1'000'000u);
    EXPECT_EQ(bbr.cwnd(), 200'000u) << "twice what 100 ms of the feed holds";
    EXPECT_EQ(bbr.bandwidth(), 0u) << "the feed's rate taken for the path's";

    bbr.on_live_offered(0);
    EXPECT_EQ(bbr.pacing_rate().bytes_over(1s), pacing);
    EXPECT_EQ(bbr.cwnd(), cwnd);
}

// Reno likewise, in its first slow start only: after a timeout the path has said
// it could not take what was sent. What it tells the application of the path is
// its own window still: told the floor's, a source sizing itself to the figure
// raised its rate, the floor with it, until a loss.
TEST(UdpLossRecoveryTest, RenoSlowStartsNoSlowerThanLiveDataIsOfferedUntilThePathSaysNo) {
    const cc::RttEstimate rtt = rtt_of_100ms();
    cc::RenoController reno(rtt, Clock::time_point{});
    const uint64_t bandwidth = reno.bandwidth();
    EXPECT_EQ(bandwidth, uint64_t{cc::kInitialWindow} * 10) << "a window per 100 ms";
    reno.on_live_offered(1'000'000);
    EXPECT_EQ(reno.cwnd(), 200'000u);
    EXPECT_EQ(reno.pacing_rate().bytes_over(1s), 1'000'000u) << "the feed's own rate";
    EXPECT_EQ(reno.bandwidth(), bandwidth);
    reno.on_timeout(Clock::time_point{}, 200'000);
    EXPECT_EQ(reno.cwnd(), cc::kMss);
}

// An 8 Mbit/s feed from the moment the connection is up, over 100 ms: Startup
// paced it at a few hundred kbit/s at first, and the pacing rate is what a message
// not yet started is judged by — every one that could not leave in time at it was
// given up, though a few round trips on it would have: 6% of the feed in its
// first half second. Sent at the feed's own rate from the start, nothing is.
TEST(BbrTest, AFeedOfConstantRateLosesNothingOnJoining) {
    for (const auto rtt : {50ms, 100ms}) {
        SCOPED_TRACE(rtt.count());
        Sim sim(20, rtt, 300);
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.run(300ms);
        ASSERT_TRUE(f.tx.established());
        Feed{sim, f, 8, 200ms}.play(3s);
        const PathStats ps = f.sender().path_stats();
        EXPECT_EQ(ps.live_expired, 0u) << "of " << ps.live_sent;
        EXPECT_GT(f.rx.messages_in, ps.live_sent * 95 / 100);   // the rest on the way
    }
}

TEST(UdpLossRecoveryTest, AFeedOfConstantRateLosesNothingOnJoiningRenoEither) {
    Sim sim(20, 100ms, 300);
    Flow& f = sim.add(CongestionAlgorithm::Reno);
    sim.run(300ms);
    ASSERT_TRUE(f.tx.established());
    Feed{sim, f, 8, 200ms}.play(3s);
    const PathStats ps = f.sender().path_stats();
    EXPECT_EQ(ps.live_expired, 0u) << "of " << ps.live_sent;
    EXPECT_GT(f.rx.messages_in, ps.live_sent * 95 / 100);
}

// A feed the path cannot carry: the floor holds only until Startup has its
// verdict — the loss and the queue end it as they would any flow — and from then
// on the model's rate is the path's, not the feed's.
TEST(BbrTest, AFeedThePathCannotCarryStillEndsStartup) {
    Sim sim(6, 100ms, 62);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(300ms);
    Feed feed{sim, f, 8, 200ms};
    feed.play(2s);
    EXPECT_TRUE(bbr(f.sender()).full_bw_reached()) << "still in Startup";
    feed.play(5s);
    EXPECT_LT(bbr(f.sender()).bw() * 8, 7e6) << "the estimate is the feed's, not the path's";
    EXPECT_LT(f.sender().path_stats().pacing_bps, 8e6);
}

// ── Flows that do not fill the pipe ─────────────────────────────────────────

namespace {

/// A video source on a flow: 30 frames a second at `mbps`, every 60th five times
/// the others — the burst a keyframe is. Frames are reliable stream data, or with
/// a `lifetime` live messages.
struct Video {
    Sim&            sim;
    Flow&           flow;
    double          mbps;
    Clock::duration lifetime{};
    int             frame = 0;

    /// Run the simulation for `d`, a frame at a time.
    void play(Clock::duration d) {
        const double weight = mbps * 1e6 / 8 * 2 / 64;   // 64 frame-weights per 2 s
        const auto   until  = sim.now + d;
        while (sim.now < until) {
            const auto size = static_cast<size_t>(frame++ % 60 == 0 ? 5 * weight : weight);
            if (lifetime == Clock::duration::zero()) {
                flow.to_send += size;
            } else {
                flow.tx.send_live(MessageType::App, std::string(size, 'v'), sim.now + lifetime);
                flow.sender().flush(sim.now);
            }
            sim.run(std::chrono::microseconds(33'333));
        }
    }
};

} // namespace

// The plateau test that ends Startup reads only samples that are not app-limited,
// which video hardly ever produces. Left in Startup it would send every keyframe
// at 2.77x a bandwidth it found long ago, into a buffer of one BDP that cannot
// take it: every keyframe lost, every time. A burst of its own that queued at the
// bottleneck ends Startup instead, and the keyframes go at the path's rate.
TEST(BbrTest, AnAppLimitedFlowLeavesStartupOnceItsBurstsQueue) {
    Sim sim(10, 40ms, 41);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 4};
    video.play(6s);
    EXPECT_TRUE(bbr(f.sender()).full_bw_reached()) << "still in Startup";
    EXPECT_NE(bbr(f.sender()).state(), cc::BbrController::State::Startup);

    const uint32_t lost = f.sender().recovery().retransmits();
    video.play(10s);
    EXPECT_LE(f.sender().recovery().retransmits() - lost, 10u)
        << "keyframes still overflow the bottleneck";
    EXPECT_LT(f.sender().path_stats().pacing_bps, 1.4 * 10e6) << "bursts paced far above the path";
}

// The same over a path that hands the acknowledgements back in bunches 8 ms
// apart, as a Wi-Fi station's transmit opportunities do. Along each bunch the
// round trip falls — the packet sent last waited least — while the queue in front
// of the frames grows: read acknowledgement by acknowledgement it never rises for
// long, and Startup must end all the same.
TEST(BbrTest, AnAppLimitedFlowLeavesStartupOnceItsBurstsQueueWhenAcksComeInBunches) {
    Sim sim(10, 40ms, 41);
    sim.path.rev().bunch = 8ms;
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 4};
    video.play(6s);
    EXPECT_TRUE(bbr(f.sender()).full_bw_reached()) << "still in Startup";

    const uint32_t lost = f.sender().recovery().retransmits();
    video.play(10s);
    EXPECT_LE(f.sender().recovery().retransmits() - lost, 10u)
        << "keyframes still overflow the bottleneck";
    EXPECT_LT(f.sender().path_stats().pacing_bps, 1.4 * 10e6) << "bursts paced far above the path";
}

// netem's normal jitter, 25 ± 10 ms each way, in order: a packet held back holds
// those behind it, so the round trip grows with what is sent — a queue by every
// reading of the round trip, on a path that carries far more than the call. A
// call sized to the estimate, read by the round trip alone, stopped at 3 Mbit/s
// of its 8 and stayed there; verified by what the path delivers, it climbs.
TEST(BbrTest, ACallOnARadioThatHoldsPacketsInOrderGetsItsRate) {
    for (const uint32_t seed : {1u, 2u, 3u}) {
        SCOPED_TRACE(seed);
        Sim sim(200, 50ms, 1000, 0.0, seed);
        sim.path.fwd().delay_sd = 10ms;
        sim.path.rev().delay_sd = 10ms;
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.run(500ms);
        Video video{sim, f, 1, 150ms};
        for (int i = 0; i < 80; ++i) {   // 8 s, retargeted every 100 ms
            const double estimate = f.sender().path_stats().bandwidth_bps / 1e6;
            video.mbps = (std::max)(1.0, (std::min)(0.9 * estimate, 8.0));
            video.play(100ms);
        }
        EXPECT_EQ(video.mbps, 8.0) << "the call is held at " << video.mbps << " Mbit/s";
        EXPECT_GT(f.sender().path_stats().bandwidth_bps, 16e6) << "no room for a keyframe";
    }
}

// The other side of verifying: a link the call nearly fills, 1 Mbit/s with a
// radio holding a tenth of the packets back 20 ms, shows a standing queue that
// is the call's own, and a burst that queued in every probe. Each verification
// is a queue of padding in front of the frames, so one that found the queue ours
// is believed for a while: verified at every probe, the call sent ten times the
// padding, a queue in front of its frames every second or two.
TEST(BbrTest, AVerificationThatFindsTheQueueOursIsBelievedForAWhile) {
    for (const uint32_t seed : {1u, 2u, 3u}) {
        SCOPED_TRACE(seed);
        Sim sim(1, 40ms, 8, 0.0, seed);
        for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) {
            d->late       = 0.1;
            d->late_by    = 20ms;
            d->late_holds = true;
        }
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        size_t padding = 0;
        sim.path.hook = [&](Bytes& d, const Address&, bool forward) {
            if (forward && has_frame(d, udp::kPing) && !has_frame(d, udp::kLive) &&
                !has_frame(d, udp::kLiveRepair) && !has_frame(d, udp::kStream))
                padding += d.size();
            return false;
        };
        sim.run(500ms);
        Video video{sim, f, 0.15, 120ms};
        for (int i = 0; i < 200; ++i) {   // 20 s, retargeted every 100 ms
            const double estimate = f.sender().path_stats().bandwidth_bps / 1e6;
            video.mbps = (std::max)(0.15, (std::min)(0.9 * estimate, 0.9));
            video.play(100ms);
        }
        EXPECT_LT(padding, 60'000u) << "verifications of a queue found to be ours kept coming";
    }
}

// Over a deep buffer — a home router's, half a second of it — a verification's
// window was sized over the smoothed round trip, which its own padding's queue
// lifted: the window grew with the queue and the queue with the window, to half
// a second before a round of it ended, the frames behind all of it (142 frames
// of these 4800 given up). Sized over the round trip it began at, 63; ended after
// a few of those as well, 30, and a sixth less padding.
TEST(BbrTest, AVerificationOverADeepBufferDoesNotFeedOnItsOwnQueue) {
    uint64_t expired = 0;
    size_t   padding = 0, video_bytes = 0;
    for (uint32_t seed = 1; seed <= 8; ++seed) {
        SCOPED_TRACE(seed);
        Sim sim(20, 40ms, 1000, 0.0, seed);
        for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) {
            d->late       = 0.1;
            d->late_by    = 20ms;
            d->late_holds = true;
        }
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.path.hook = [&](Bytes& d, const Address&, bool forward) {
            if (forward && is_padding(d)) padding += d.size();
            return false;
        };
        sim.run(500ms);
        Video video{sim, f, 1, 150ms};
        for (int i = 0; i < 200; ++i) {   // 20 s, retargeted every 100 ms
            const double estimate = f.sender().path_stats().bandwidth_bps / 1e6;
            video.mbps = (std::max)(1.0, (std::min)(0.9 * estimate, 8.0));
            video.play(100ms);
        }
        EXPECT_EQ(video.mbps, 8.0) << "the call is held at " << video.mbps << " Mbit/s";
        expired += f.sender().path_stats().live_expired;
        video_bytes += f.delivered();
    }
    EXPECT_LT(expired, 45u) << "of 4800 frames";
    EXPECT_LT(padding, video_bytes * 6 / 100) << "padding " << padding << " B, video " << video_bytes << " B";
}

// A path that hands nothing back late has no radio to take for a queue: a queue
// read off its round trip is one. Verified all the same, each probe that found it
// was a queue of padding in front of the frames — a few late each time, and to
// each of several peers a few per peer (here 150 KB of padding in 30 s).
TEST(BbrTest, ACallOnACleanPathIsNotPadded) {
    Sim sim(10, 40ms, 41);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    size_t padding = 0;
    sim.path.hook = [&](Bytes& d, const Address&, bool forward) {
        if (forward && is_padding(d)) padding += d.size();
        return false;
    };
    sim.run(500ms);
    Video{sim, f, 4, 150ms}.play(30s);
    EXPECT_EQ(padding, 0u);
}

// A call sent both ways over 10 Mbit/s: the acknowledgements wait behind the
// other way's frames and come back in bunches, which opens verifications of the
// queue each probe builds — and that queue is ours, on a link the two calls
// nearly fill. Ended only by the loss the padding caused, each verification cost
// the frames that loss: 472 packets sent again over these eight calls, 48 frames
// given up each way. Ended as its round trip rises, before the queue overflows:
// none sent again, 24.
TEST(BbrTest, AVerificationEndsAsItsQueueRises) {
    uint64_t expired = 0, back_expired = 0;
    uint32_t retransmits = 0;
    for (uint32_t seed = 1; seed <= 8; ++seed) {
        SCOPED_TRACE(seed);
        Sim sim(10, 40ms, 41, 0.0, seed);
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.run(500ms);
        const double weight = 4e6 / 8 * 2 / 64;   // 4 Mbit/s, as Video sizes it
        for (int frame = 0; frame < 900; ++frame) {   // 30 s
            const auto size = static_cast<size_t>(frame % 60 == 0 ? 5 * weight : weight);
            f.tx.send_live(MessageType::App, std::string(size, 'v'), sim.now + 150ms);
            f.sender().flush(sim.now);
            f.rx.send_live(MessageType::App, std::string(size, 'w'), sim.now + 150ms);
            f.receiver().flush(sim.now);
            sim.run(std::chrono::microseconds(33'333));
        }
        expired += f.sender().path_stats().live_expired;
        back_expired += f.receiver().path_stats().live_expired;
        retransmits += f.sender().recovery().retransmits();
    }
    EXPECT_LT(retransmits, 50u);
    EXPECT_LT(expired, 36u) << "of 7200 frames";
    EXPECT_LT(back_expired, 36u) << "of 7200 frames";
}

// What a verification needs in flight is the rate that passes it over a round
// trip; on a path that cannot deliver that, the rest of the window is all queue
// in front of the frames. So padding stops there, short of the window: here a
// call sized to the estimate on a gigabit whose delay varies 25 ± 10 ms each
// way, verifying the queue each probe seems to build.
TEST(BbrTest, AVerificationPadsOnlyWhatItsVerdictNeeds) {
    size_t padded = 0, short_of_window = 0;
    for (const uint32_t seed : {1u, 2u, 3u, 4u}) {
        SCOPED_TRACE(seed);
        Sim sim(1000, 50ms, 100'000, 0.0, seed);
        for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) d->delay_sd = 10ms;
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.path.hook = [&](Bytes& d, const Address&, bool forward) {
            if (!forward || !is_padding(d) || bbr(f.sender()).state() != cc::BbrController::State::ProbeBwUp)
                return false;
            const auto& cc = f.sender().recovery().congestion();
            const uint64_t limit = cc.padding_limit();
            ++padded;
            EXPECT_LE(f.sender().recovery().bytes_in_flight(), limit);
            if (limit < cc.cwnd() && cc.cwnd() - limit >= 2 * udp::kMaxDatagram) ++short_of_window;
            return false;
        };
        sim.run(500ms);
        Video video{sim, f, 1, 150ms};
        for (int i = 0; i < 300; ++i) {   // 30 s, retargeted every 100 ms
            const double estimate = f.sender().path_stats().bandwidth_bps / 1e6;
            video.mbps = (std::max)(1.0, (std::min)(0.9 * estimate, 8.0));
            video.play(100ms);
        }
    }
    EXPECT_GT(padded, 0u) << "no verification in a probe";
    EXPECT_GT(short_of_window, 0u) << "padding ran to the window";
}

// On 1 Mbit/s a frame is three packets and two acknowledgements, too few for the
// round trip to rise in. But the queue Startup's bursts build there does not
// drain before the next frame: it stands, and that ends Startup.
TEST(BbrTest, AStandingQueueEndsStartupOnASlowLink) {
    Sim sim(1, 40ms, 8);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 0.8};
    video.play(6s);
    EXPECT_TRUE(bbr(f.sender()).full_bw_reached()) << "still in Startup";

    const uint32_t lost = f.sender().recovery().retransmits();
    video.play(10s);
    EXPECT_LE(f.sender().recovery().retransmits() - lost, 10u)
        << "keyframes still overflow the bottleneck";
    EXPECT_LT(f.sender().path_stats().pacing_bps, 1.4 * 1e6) << "bursts paced far above the path";
}

// A radio holds a packet back now and then, and those behind it with it: the
// round trip of an acknowledgement jumps with nothing queued. Read as a queue,
// that ended Startup a second in, at the 1-2 Mbit/s a call had reached — and a
// call whose rate control sizes it to the estimate stayed there: what it sends is
// all the estimate can see. Such a jump lifts one group of acknowledgements, and
// those it held fall back; Startup goes on and the call gets its rate. On 10
// Mbit/s, with a fifth of the datagrams late, the jumps come close together and
// one acknowledgement after another rose often enough to look like a queue; the
// smallest round trip of each group does not.
TEST(BbrTest, JitterDoesNotHoldDownACallSizedToTheEstimate) {
    struct Case {
        double          mbps;
        Clock::duration rtt;
        double          late;
        Clock::duration late_by;
        uint32_t        seed;
    };
    std::vector<Case> cases{{1000, 20ms, 0.1, 20ms, 1}};
    for (uint32_t seed = 1; seed <= 6; ++seed) cases.push_back({10, 40ms, 0.2, 8ms, seed});
    for (const Case& c : cases) {
        Sim sim(c.mbps, c.rtt, 2000, 0.0, c.seed);
        for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) {
            d->late       = c.late;
            d->late_by    = c.late_by;
            d->late_holds = true;
        }
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.run(500ms);
        Video video{sim, f, 1};
        for (int i = 0; i < 100; ++i) {
            const double estimate = f.sender().path_stats().bandwidth_bps / 1e6;
            video.mbps = (std::max)(0.15, (std::min)(0.9 * estimate, 8.0));
            video.play(100ms);
        }
        EXPECT_GT(video.mbps, 7.0) << "a call on " << c.mbps << " Mbit/s (seed " << c.seed << ") held to "
                                   << video.mbps << " Mbit/s";
    }
}

// A link that widens once Startup is over is found only by probes. A radio that
// holds a tenth of the packets back 20 ms lifts some acknowledgement of nearly
// every probe past the bar — read as our queue, each probe ended in its first
// round trip, and a call sized to the estimate stayed at the 3 Mbit/s the link
// had been for good. The bar is read past how late the path's acknowledgements
// come back by themselves (BbrController::lateness()), once for each way.
TEST(BbrTest, AProbeOnAJitteryPathFindsALinkThatWidened) {
    for (uint32_t seed = 1; seed <= 4; ++seed) {
        Sim sim(10, 40ms, 41, 0.0, seed);
        for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) {
            d->rate_bps   = 3e6;
            d->late       = 0.1;
            d->late_by    = 20ms;
            d->late_holds = true;
        }
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.run(500ms);
        Video video{sim, f, 1, 120ms};
        const auto follow = [&](Clock::duration d) {
            for (auto t = Clock::duration::zero(); t < d; t += 100ms) {
                const double estimate = f.sender().path_stats().bandwidth_bps / 1e6;
                video.mbps = (std::max)(0.15, (std::min)(0.9 * estimate, 8.0));
                video.play(100ms);
            }
        };
        follow(10s);
        for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) d->rate_bps = 10e6;
        follow(10s);
        EXPECT_GT(video.mbps, 7.0) << "seed " << seed << ": a call held to " << video.mbps
                                   << " Mbit/s ten seconds after the link went from 3 to 10";
    }
}

// What a probe forgives as the path's own lateness must not include what every
// path shows: the peer acknowledges every second packet, and on 1 Mbit/s two
// packets are 20 ms. Counted, that hid the queue a keyframe builds in a probe —
// the probe went on, and the queue in front of the frames peaked near twice as
// high.
TEST(BbrTest, AProbeOnASlowLinkStillEndsAtTheKeyframesQueue) {
    Sim sim(1, 40ms, 8);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 0.8, 300ms};
    video.play(3s);
    Clock::duration peak{};
    sim.on_step = [&] {
        const Direction& d = sim.path.fwd();
        if (d.busy_until > sim.now) peak = (std::max)(peak, d.busy_until - sim.now);
    };
    video.play(20s);
    sim.on_step = nullptr;
    EXPECT_LT(peak, 55ms) << "the queue in front of the frames peaked at "
                          << std::chrono::duration<double, std::milli>(peak).count() << " ms";
}

// Repair symbols fill the bottleneck's idle time. A call sized to the estimate
// on 1 Mbit/s leaves the link a tenth to spare, and a radio's jitter lifts the
// estimate past the link: the sender runs dry between frames with a queue still
// standing. A few early losses made the path look lossy; a repair a frame, sent
// whenever the sender had nothing else, then overflowed the queue, and the loss
// that made kept the repairs coming — 13% more bytes, frames expiring, for good.
TEST(UdpLossRecoveryTest, RepairSymbolsDoNotOverloadALinkTheVideoNearlyFills) {
    for (uint32_t seed = 1; seed <= 3; ++seed) {
        Sim sim(1, 40ms, 8, 0.0, seed);
        for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) {
            d->late       = 0.1;
            d->late_by    = 20ms;
            d->late_holds = true;
        }
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.run(500ms);
        int live = 0;   // one in a hundred of the first live packets lost
        sim.path.hook = [&](Bytes& d, const Address&, bool forward) {
            return forward && has_frame(d, udp::kLive) && ++live <= 400 && live % 100 == 0;
        };
        Video video{sim, f, 0.15, 120ms};
        const auto follow = [&](Clock::duration d) {
            for (auto t = Clock::duration::zero(); t < d; t += 100ms) {
                const double estimate = f.sender().path_stats().bandwidth_bps / 1e6;
                video.mbps = (std::max)(0.15, (std::min)(0.9 * estimate, 0.9));
                video.play(100ms);
            }
        };
        follow(10s);
        const PathStats before = f.sender().path_stats();
        const int first = video.frame;
        follow(20s);
        const PathStats after = f.sender().path_stats();
        const uint64_t frames  = static_cast<uint64_t>(video.frame - first);
        const uint64_t repairs = after.live_repair_bytes - before.live_repair_bytes;
        EXPECT_LT(repairs, static_cast<uint64_t>(0.9e6 / 8 * 20 / 20))
            << "seed " << seed << ": repair symbols past 5% of the video";
        EXPECT_LT(after.live_expired - before.live_expired, frames / 25)
            << "seed " << seed << ": of " << frames << " frames";
    }
}

// A download beside a call keeps the bottleneck's queue standing whatever the
// call sends, so no round trip of the call's comes back near the base. Read as a
// queue of its own, it held every repair back: the download's losses cost the
// call frames that a repair in a dozen symbols would have saved.
TEST(UdpLossRecoveryTest, ACallBesideADownloadStillSendsRepairs) {
    uint64_t expired = 0;
    for (int join = 0; join < 6; ++join) {
        Sim sim(10, 40ms, 41);
        Flow& f    = sim.add(CongestionAlgorithm::Bbr);
        Flow& bulk = sim.add(CongestionAlgorithm::Reno);
        sim.run(500ms);
        Video video{sim, f, 4, 150ms};
        video.play(3s + join * 370ms);
        bulk.to_send = SIZE_MAX;
        video.play(5s);
        const PathStats before = f.sender().path_stats();
        video.play(20s);
        const PathStats after = f.sender().path_stats();
        EXPECT_GT(after.live_repair_bytes - before.live_repair_bytes, 80'000u)
            << "download joined " << 3000 + join * 370 << " ms in: repairs held back";
        expired += after.live_expired - before.live_expired;
    }
    EXPECT_LT(expired, 185u) << "of 3600 frames";
}

// A radio that holds a tenth of the packets back 20 ms, both ways, lifts every
// round trip of a busy link: the queue looks as if it stood. Its losses are the
// radio's, a few in a frame of thirty symbols, and that frame's repairs are about
// what is lost — holding them back cost a third more late frames. (Eight draws:
// one draw's frames vary by a fifth either way, and four drew a bar a timing
// change anywhere crossed in either direction.)
TEST(UdpLossRecoveryTest, AJitteryLinkStillProtectsLargeFrames) {
    uint64_t expired = 0;
    for (uint32_t seed = 1; seed <= 8; ++seed) {
        Sim sim(10, 40ms, 41, 0.01, seed);
        for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) {
            d->late       = 0.1;
            d->late_by    = 20ms;
            d->late_holds = true;
        }
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.run(500ms);
        Video video{sim, f, 8, 120ms};
        video.play(5s);
        const PathStats before = f.sender().path_stats();
        video.play(20s);
        expired += f.sender().path_stats().live_expired - before.live_expired;
    }
    EXPECT_LT(expired, 300u) << "of 4800 frames";
}

// A buffer something else filled lifts the round trip past twice a frame's
// lifetime, then drains. A frame that could not arrive by the round trip was
// given up before a byte of it went, and with nothing sent nothing came back to
// show the round trip had come down: the call stayed silent for good on a path
// back at 40 ms. A PING brings the round trip back.
TEST(UdpLossRecoveryTest, ACallSpeaksAgainOnceItsRoundTripComesBack) {
    Sim sim(20, 40ms, 1000);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 2, 150ms};
    video.play(3s);
    for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) d->delay += 200ms;
    video.play(2s);
    for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) d->delay -= 200ms;
    video.play(1s);
    const size_t before = f.rx.messages_in;
    video.play(5s);
    EXPECT_GT(f.rx.messages_in - before, 140u) << "of 150 frames";
}

// ProbeRTT empties a queue to measure the path's own delay. An app-limited flow
// that keeps seeing that delay has no queue to empty — and holding its inflight
// to half a BDP for 200 ms is a keyframe lost for nothing. A flow that fills the
// pipe still probes (ProbesRttAndComesBack).
TEST(BbrTest, AnAppLimitedFlowThatSeesTheMinimumSkipsProbeRtt) {
    Sim sim(10, 40ms, 41);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    bool probed = false;
    sim.on_step = [&] { probed |= bbr(f.sender()).state() == cc::BbrController::State::ProbeRtt; };
    Video{sim, f, 2}.play(16s);
    sim.on_step = nullptr;
    EXPECT_FALSE(probed) << "ProbeRTT with an empty queue";
}

// Random loss with nothing queued is not congestion this sender caused: it is
// sending less than the path carries into a queue that is empty. Cutting the
// short-term bounds for it paced the video's bursts and repairs at the video's
// own rate — under 5% loss below what the video needs, and a quarter of the
// frames ran out of time waiting for repairs that rate let out too slowly.
TEST(BbrTest, RandomLossDoesNotCutAnAppLimitedFlowToItsOwnRate) {
    Sim sim(10, 40ms, 41, 0.05, 11);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 4, 120ms};
    video.play(3s);
    const PathStats before = f.sender().path_stats();
    double sum = 0, steps = 0;
    sim.on_step = [&] {
        sum += static_cast<double>(bbr(f.sender()).bw()) * 8;
        ++steps;
    };
    video.play(20s);
    sim.on_step = nullptr;
    const PathStats after = f.sender().path_stats();
    EXPECT_FALSE(f.sender().dead());
    const double dropped = double(after.live_expired - before.live_expired) /
                           double(after.live_sent - before.live_sent);
    EXPECT_LT(dropped, 0.11) << "frames given up: " << dropped * 100 << "%, estimate "
                             << sum / steps / 1e6 << " Mbit/s on average";
}

// Recovery cuts the window to what is in flight, and for a sender that keeps
// running dry that is what it happened to have out between two frames: after a
// loss the next keyframe left at the pace of the acknowledgements of the frame
// before it — and a probe that should have found the path ended on the radio's
// own 5%. On a 100 ms path 38% of the frames ran out of time. Loss with nothing
// queued, from less than the path holds, is no full queue's: it leaves the
// window, and the probes, alone.
TEST(BbrTest, RandomLossOnALongPathLeavesASenderThatRunsDryItsWindow) {
    Sim sim(10, 100ms, 104, 0.05, 11);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 4, 150ms};
    video.play(3s);
    const PathStats before = f.sender().path_stats();
    video.play(20s);
    const PathStats after = f.sender().path_stats();
    EXPECT_FALSE(f.sender().dead());
    const double dropped = double(after.live_expired - before.live_expired) /
                           double(after.live_sent - before.live_sent);
    EXPECT_LT(dropped, 0.02) << "frames given up: " << dropped * 100 << "%, estimate "
                             << bbr(f.sender()).bw() * 8e-6 << " Mbit/s";
}

// BBRv3 reads 2% of loss as a probe gone too far whatever the path, so on a
// radio that loses 5% by itself every probe ended on its first acknowledgements
// and a bulk transfer kept the half of the path Startup had found. Over what
// rounds cruising with no queue lose — the path's own loss — the threshold lets
// the probes through here, and is the draft's own on a path that loses nothing
// (FindsTheBottleneckAndKeepsTheQueueShort, AShallowBufferEndsStartupOnLoss).
TEST(BbrTest, AProbeIsJudgedByTheLossThePathDoesNotHaveByItself) {
    Sim sim(10, 100ms, 104, 0.05, 11);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(20s);
    EXPECT_FALSE(f.sender().dead());
    EXPECT_GT(f.delivered() / 20.0, 0.72 * payload_rate(10))
        << mbps_of(f.delivered(), 20s) << " Mbit/s of a 10 Mbit/s path that loses 5%";
}

// The loss a path has by itself is read off rounds that cruise with no queue,
// and only there: on a radio it is the radio's rate, on a path that loses
// nothing — a buffer too shallow to show a queue included, whose drops come only
// with a probe — it is none, and the threshold the draft's own.
TEST(BbrTest, ThePathsOwnLossIsReadOffRoundsThatCruiseWithNoQueue) {
    {
        Sim sim(10, 100ms, 104, 0.05, 11);
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        f.to_send = SIZE_MAX;
        sim.run(20s);
        EXPECT_GE(bbr(f.sender()).loss_base(), 20u) << "a radio that loses 5% read as losing less than 2%";
        EXPECT_LE(bbr(f.sender()).loss_base(), 60u);
    }
    {
        Sim sim(20, 40ms, 8);
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        f.to_send = SIZE_MAX;
        uint64_t most = 0;
        sim.on_step = [&] { most = (std::max)(most, bbr(f.sender()).loss_base()); };
        sim.run(20s);
        sim.on_step = nullptr;
        EXPECT_GT(f.sender().recovery().retransmits(), 0u) << "the buffer never overflowed: nothing tested";
        EXPECT_EQ(most, 0u) << "a probe's drops read as the path's own";
    }
    {
        // Nor is what a Reno flow drops by filling a buffer that shows its queue.
        Sim sim(20, 40ms, 83);
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        f.to_send = SIZE_MAX;
        sim.run(5s);
        sim.add(CongestionAlgorithm::Reno).to_send = SIZE_MAX;
        uint64_t most = 0;
        sim.on_step = [&] { most = (std::max)(most, bbr(f.sender()).loss_base()); };
        sim.run(30s);
        sim.on_step = nullptr;
        EXPECT_EQ(most, 0u) << "a full queue's drops read as the path's own";
    }
}

// Ran dry or not, a sender whose acknowledgements come back late only now and
// then — a host's timer, a radio's retries — has no queue: the round's
// smallest round trip says so. Read one acknowledgement at a time, under random
// loss every round of such a path looked congested and was cut, and the video
// was paced too slowly for its keyframes.
TEST(BbrTest, AcknowledgementsThatComeBackLateAreNoQueue) {
    Sim sim(10, 40ms, 41, 0.03, 5);
    sim.path.rev().late    = 0.3;
    sim.path.rev().late_by = 15ms;
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 4, 120ms};
    video.play(3s);
    const PathStats before = f.sender().path_stats();
    video.play(20s);
    const PathStats after = f.sender().path_stats();
    const double dropped = double(after.live_expired - before.live_expired) /
                           double(after.live_sent - before.live_sent);
    EXPECT_LT(dropped, 0.05) << "frames given up: " << dropped * 100 << "%";
}

// The receiver holds an acknowledgement back for up to its ack delay, and says by
// how much. On a long path that is more than the queue the model looks for
// (min_rtt / 8, at most 16 ms), so a round trip read with the delay left in made
// every round of a video under random loss look congested: its bounds were cut,
// and the estimate sank to its own rate.
TEST(BbrTest, TheReceiversAckDelayIsNoQueue) {
    Sim sim(10, 100ms, 200, 0.01, 11);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 4, 80ms};
    video.play(3s);
    double sum = 0, steps = 0;
    sim.on_step = [&] {
        sum += static_cast<double>(bbr(f.sender()).bw()) * 8;
        ++steps;
    };
    video.play(15s);
    sim.on_step = nullptr;
    EXPECT_GT(sum / steps, 6e6) << "estimate " << sum / steps / 1e6 << " Mbit/s of a 10 Mbit/s path";
}

// A radio that holds a tenth of the packets back 20 ms, and those behind them,
// lifts the least round trip of most rounds past the queue threshold and leaves
// more than a BDP in flight while their acknowledgements wait — with nothing
// queued. Read as a full queue, each random loss cut the bounds to what the round
// delivered, which for a video is its own rate: 8 Mbit/s of it on 10 was paced
// below 8 within a second, and over a third of the frames ran out of time. Both
// readings are taken past how late the path's acknowledgements come back
// (BbrController::lateness()); either one alone still gave up a fifth of them.
TEST(BbrTest, RandomLossOnAJitteryPathIsNoQueue) {
    double dropped = 0;
    const uint32_t seeds = 4;
    for (uint32_t seed = 1; seed <= seeds; ++seed) {
        Sim sim(10, 40ms, 41, 0.01, seed);
        for (Direction* d : {&sim.path.fwd(), &sim.path.rev()}) {
            d->late       = 0.1;
            d->late_by    = 20ms;
            d->late_holds = true;
        }
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.run(500ms);
        Video video{sim, f, 8, 120ms};
        video.play(3s);
        const PathStats before = f.sender().path_stats();
        video.play(15s);
        const PathStats after = f.sender().path_stats();
        dropped += double(after.live_expired - before.live_expired) / double(after.live_sent - before.live_sent);
    }
    EXPECT_LT(dropped / seeds, 0.12) << "frames given up: " << dropped / seeds * 100 << "% on average";
}

// A connection's first messages are small — identify, a request or two — and on
// a real path one acknowledgement in a few comes back 10 ms or more late with
// nothing queued. A handful of 64 B messages is more in flight than the BDP of
// their own rate, so that was read as a burst that queued and ended Startup at a
// few KB/s: the transfer after it had to probe its way up a quarter per cycle,
// and on a 35 ms path ran at half the rate for most of its first seconds.
TEST(BbrTest, SmallMessagesOnAJitteryPathLeaveStartupToTheTransferAfterThem) {
    Sim sim(100, 34ms, 300);
    sim.path.rev().late    = 0.3;
    sim.path.rev().late_by = 12ms;
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(200ms);
    for (int i = 0; i < 100; ++i) {   // two seconds of small talk
        f.to_send += 64;
        sim.run(20ms);
    }
    EXPECT_FALSE(bbr(f.sender()).full_bw_reached()) << "small messages ended Startup";

    f.to_send = SIZE_MAX;
    sim.run(1s);
    const size_t before = f.delivered();
    sim.run(1s);
    EXPECT_GT(f.delivered() - before, 0.8 * payload_rate(100))
        << mbps_of(f.delivered() - before, 1s) << " Mbit/s in the transfer's second second";
}

// The first round trips of a transfer are app-limited — the window, not the
// application, is what grows — and their samples are more in flight than the
// BDP measured so far. On a path whose acknowledgements come back 7 ms late now
// and then with nothing queued (a host's timer, a radio), the first late one was
// taken for a burst that queued and ended Startup at a few Mbit/s, the queue
// threshold being an eighth of the round trip: 4 ms here.
TEST(BbrTest, AJitteryPathDoesNotEndTheStartupOfATransfer) {
    Sim sim(100, 34ms, 300);
    sim.path.rev().late    = 0.3;
    sim.path.rev().late_by = 7ms;
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(200ms);
    f.to_send = SIZE_MAX;
    sim.run(1s);
    EXPECT_GT(f.delivered(), 0.5 * payload_rate(100))
        << mbps_of(f.delivered(), 1s) << " Mbit/s in the first second of a 100 Mbit/s path";
}

// A buffer shallower than the queue a round trip can show (queue_threshold())
// never looks queued, so a sender that runs dry between bursts would never be cut
// for what it loses there (RandomLossDoesNotCutAnAppLimitedFlowToItsOwnRate) —
// while every burst overflows it again. What was in flight when the lost packet left
// says it instead: more than the path holds is a queue of the sender's own.
TEST(BbrTest, ALossFromMoreThanThePathHoldsCutsASenderThatRunsDry) {
    Sim sim(50, 1ms, 3);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(100ms);
    int cuts = 0;
    uint64_t last = cc::BbrController::kInfinite;
    sim.on_step = [&] {
        const uint64_t lo = bbr(f.sender()).inflight_lo();
        if (lo < last) ++cuts;
        last = lo;
    };
    for (int burst = 0; burst < 200; ++burst) {   // 128 KiB every 25 ms: 42 Mbit/s
        f.to_send += 128 * 1024;
        sim.run(25ms);
    }
    sim.on_step = nullptr;
    EXPECT_GT(cuts, 50) << "the bursts' losses never cut the model";
    const double share = double(f.sender().recovery().retransmits()) / double(sim.path.fwd().sent);
    EXPECT_LT(share, 0.072) << "retransmitted " << share * 100 << "% of what was sent";
}

// The link loses 70% of its capacity under a live source it can no longer carry:
// the sender is backlogged, then not, as it drops the frames that cannot make it.
// The estimate must follow the link down within a few probe cycles — it used to
// age only when the one acknowledgement ending a cycle happened not to be
// app-limited, which in and out of being backlogged it seldom was, and a
// pre-drop estimate and a standing queue of a whole buffer stayed for good.
TEST(BbrTest, TheEstimateFollowsTheLinkDownUnderASourceItCannotCarry) {
    Sim sim(10, 40ms, 41);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 4, 120ms};
    video.play(5s);
    ASSERT_GT(bbr(f.sender()).max_bw(), 2 * 3e6 / 8) << "no estimate to follow down";
    sim.path.fwd().rate_bps = 3e6;
    video.play(12s);
    EXPECT_LT(bbr(f.sender()).max_bw(), 1.3 * 3e6 / 8)
        << "estimate " << bbr(f.sender()).max_bw() * 8 / 1e6 << " Mbit/s on a 3 Mbit/s link";
}

// After an outage the first acknowledgement says the path is back. The window goes
// back to what the model holds then, instead of doubling up from one packet over
// five or six round trips of a path that is idle — not only once the repairs of
// what the outage lost are through, which with a backlog behind them is long.
// (The repairs are paced: UdpPacingTest.AnOutageEndsWithoutABurst.)
TEST(BbrTest, TheWindowIsBackOnceThePathAnswersAfterATimeout) {
    Sim sim(10, 40ms, 41);
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    sim.run(500ms);
    Video video{sim, f, 4};
    video.play(6s);
    const uint32_t before = f.sender().recovery().cwnd();

    sim.path.blackout = true;
    video.play(1s);
    sim.path.blackout = false;
    // Nothing was acknowledged through the outage, so the first acknowledgement
    // after it is the one that moves this.
    const uint64_t acked = f.sender().recovery().largest_acked();
    while (f.sender().recovery().largest_acked() == acked && !f.sender().dead()) sim.run(250us);
    ASSERT_TRUE(f.sender().recovery().in_recovery()) << "nothing left to repair: not the case meant";
    EXPECT_GT(f.sender().recovery().cwnd(), before / 2)
        << "on the first acknowledgement after the outage the window is "
        << f.sender().recovery().cwnd() / cc::kMss << " packets, from " << before / cc::kMss;

    video.play(2 * sim.rtt);
    EXPECT_GT(f.sender().recovery().cwnd(), before / 2)
        << "two round trips after the path answered the window is "
        << f.sender().recovery().cwnd() / cc::kMss << " packets, from " << before / cc::kMss;
}

// One outage is one congestion signal, whenever it falls. Live data waiting
// keeps the sender probing through it (Recovery::set_impatient), and the probes
// it wrote off used to come back as loss with the first acknowledgement: a
// second cut of the short-term bounds on top of the timeout's, in the phases of
// the probe cycle where the timeout cuts at all — and a window of half what
// the path had, where it should be 0.7 of it.
TEST(BbrTest, AnOutageCutsTheModelOnceWhateverItsPhase) {
    for (int phase = 0; phase < 16; ++phase) {
        SCOPED_TRACE(phase);
        Sim sim(10, 40ms, 41);
        Flow& f = sim.add(CongestionAlgorithm::Bbr);
        sim.run(500ms);
        Video video{sim, f, 4, 150ms};
        video.play(9500ms + phase * 97ms);
        const uint32_t before = f.sender().recovery().cwnd();

        sim.path.blackout = true;
        video.play(1s);
        sim.path.blackout = false;
        const size_t delivered = f.delivered();
        while (f.delivered() == delivered && !f.sender().dead()) video.play(1ms);
        video.play(sim.rtt);
        const uint64_t lo = bbr(f.sender()).inflight_lo();
        if (lo == UINT64_MAX) continue;   // timed out while probing: no cut
        EXPECT_GT(lo, before * 6 / 10) << "inflight_lo " << lo / cc::kMss << " packets, from a window of "
                                       << before / cc::kMss;
    }
}

// ── Path statistics ─────────────────────────────────────────────────────────

// What PathStats reports has to be what the connection is actually doing: under
// bulk, the bottleneck it found and a queue in front of the next message; once the
// application stops, an empty queue, nothing in flight and an app-limited
// estimate. A live encoder sizes itself from these.
TEST(UdpPathStatsTest, ReportsTheBottleneckAndTheQueueInFrontOfIt) {
    for (const auto algo : {CongestionAlgorithm::Bbr, CongestionAlgorithm::Reno}) {
        SCOPED_TRACE(to_string(algo));
        Sim sim(20, 40ms, 83);
        Flow& f   = sim.add(algo);
        f.to_send = SIZE_MAX;
        sim.run(5s);

        PathStats st = f.sender().path_stats();
        ASSERT_TRUE(st.valid);
        const double link = 20e6;
        EXPECT_GT(st.bandwidth_bps, link * 0.7);
        EXPECT_LT(st.bandwidth_bps, link * 2.0);
        EXPECT_GT(st.queued_bytes, 0u) << "a sender kept full has nothing waiting?";
        EXPECT_GT(st.bytes_in_flight, 0u);
        EXPECT_FALSE(st.app_limited);
        EXPECT_GE(st.min_rtt_us, 40'000u);
        EXPECT_LT(st.min_rtt_us, 45'000u);
        EXPECT_GE(st.srtt_us, st.min_rtt_us);
        EXPECT_GT(st.pacing_bps, 0u);

        f.to_send = 0;
        sim.run(2s);
        st = f.sender().path_stats();
        EXPECT_EQ(st.queued_bytes, 0u);
        EXPECT_EQ(st.bytes_in_flight, 0u);
        EXPECT_TRUE(st.app_limited) << "an idle sender's estimate is a floor, and must say so";
        EXPECT_GE(st.bytes_delivered, f.delivered()) << "delivered counts whole packets";
    }
}




