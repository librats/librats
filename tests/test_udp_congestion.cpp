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
        if (d.late > 0 && unit_(rng_) < d.late) arrive += d.late_by;
        // Held back past the ones behind it: in arrival order, so it is overtaken.
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
        // A burst of repairs is not paced, but a burst is still bounded by what the
        // window lets out; new data is.
        EXPECT_LE(worst, 2 * (udp::Recovery::kPaceMaxBurst + udp::kMaxDatagram))
            << to_string(algo) << " put " << worst << " bytes on the wire at once";
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

// A buffer shallower than the queue a round trip can show (kQueueMin) never looks
// queued, so a sender that runs dry between bursts would never be cut for what
// it loses there (RandomLossDoesNotCutAnAppLimitedFlowToItsOwnRate) — while
// every burst overflows it again. What was in flight when the lost packet left
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
// five or six round trips of a path that is idle — for as long as the repairs of
// what the outage lost take to go out, which with a backlog behind them is long.
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
    const size_t delivered = f.delivered();
    while (f.delivered() == delivered && !f.sender().dead()) video.play(1ms);
    video.play(2 * sim.rtt);
    EXPECT_TRUE(f.sender().recovery().in_recovery()) << "nothing left to repair: not the case meant";
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

