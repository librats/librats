// Congestion control and loss recovery of the datagram transport, against a model
// of a real path.
//
// test_transport_udp.cpp drives streams over a path that has no bandwidth and no
// queue — enough for correctness, useless for anything a congestion controller
// does. Here the path is the one every loss-based and model-based controller is a
// response to: a drop-tail queue in front of a serialiser at the link rate, then a
// propagation delay, in each direction. Time is virtual and fine-grained (the
// streams take `now` as a parameter and never read a clock), so every test is
// deterministic and runs in a fraction of the wall time it simulates.

#include <gtest/gtest.h>

#include "librats/transport/bbr.h"
#include "librats/transport/congestion_control.h"
#include "librats/transport/delivery_rate.h"
#include "librats/transport/reno.h"
#include "librats/transport/udp_packet.h"
#include "librats/transport/udp_stream.h"

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
using namespace std::chrono_literals;

namespace {

using Clock = std::chrono::steady_clock;

// ── The path ────────────────────────────────────────────────────────────────

struct InFlight {
    Clock::time_point arrive;
    Address           to;
    Bytes             bytes;
};

/// One direction: a drop-tail queue `queue_pkts` full-size packets deep in front
/// of a serialiser at `rate_bps`, then `delay` of propagation.
struct Direction {
    double               rate_bps   = 0;
    Clock::duration      delay{};
    size_t               queue_pkts = 0;
    double               loss       = 0;
    Clock::time_point    busy_until{};
    std::deque<InFlight> wire;
    size_t               sent  = 0;   ///< datagrams that entered the queue
    size_t               drops = 0;
};

class PathSim : public UdpStreamHost {
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

    /// Say which side of the path `addr` is on. Done before the streams exist:
    /// the dialer's constructor sends the Syn, which must already know its way.
    void place(const Address& addr, bool receiver) { ends_.push_back(End{addr, nullptr, receiver}); }

    void attach(const Address& addr, UdpStream* s, bool receiver) {
        for (End& e : ends_)
            if (e.addr == addr) { e.stream = s; e.receiver = receiver; return; }
        ends_.push_back(End{addr, s, receiver});
    }

    void send_datagram(const Address& to, const uint8_t* data, size_t len) override {
        const End* end     = find(to);
        const bool forward = end && end->receiver;
        Direction& d       = forward ? fwd_ : rev_;

        Bytes bytes(data, data + len);
        if (hook && hook(bytes, to, forward)) { ++d.drops; return; }
        if (blackout) { ++d.drops; return; }

        const auto serial = std::chrono::nanoseconds(
            static_cast<long long>((bytes.size() + 28) * 8 * 1e9 / d.rate_bps));
        const auto full = std::chrono::nanoseconds(
            static_cast<long long>((rudp::kMaxDatagram + 28) * 8 * 1e9 / d.rate_bps));
        const auto backlog = d.busy_until > now_ ? d.busy_until - now_ : Clock::duration::zero();
        if (backlog > full * static_cast<long long>(d.queue_pkts)) { ++d.drops; return; }
        if (d.loss > 0 && unit_(rng_) < d.loss) { ++d.drops; return; }

        ++d.sent;
        d.busy_until = (std::max)(now_, d.busy_until) + serial;
        d.wire.push_back(InFlight{d.busy_until + d.delay, to, std::move(bytes)});
    }

    void stream_events(UdpStream&, uint32_t) override {}

    void deliver_until(Clock::time_point now) {
        now_ = now;
        for (Direction* d : {&fwd_, &rev_}) {
            while (!d->wire.empty() && d->wire.front().arrive <= now) {
                InFlight f = std::move(d->wire.front());
                d->wire.pop_front();
                rudp::Packet p;
                if (!rudp::decode(f.bytes.data(), f.bytes.size(), p)) continue;
                if (const End* e = find(f.to); e && e->stream) e->stream->on_packet(p, now);
            }
        }
    }

    Direction& fwd() { return fwd_; }

    /// Sees (and may rewrite) every datagram before the path does; true drops it.
    std::function<bool(Bytes& datagram, const Address& to, bool forward)> hook;
    /// Drop everything, both ways.
    bool blackout = false;

private:
    struct End {
        Address    addr;
        UdpStream* stream;
        bool       receiver;
    };
    const End* find(const Address& a) const {
        for (const End& e : ends_) if (e.addr == a) return &e;
        return nullptr;
    }

    Direction        fwd_, rev_;
    std::vector<End> ends_;
    Clock::time_point now_{};
    std::mt19937     rng_;
    std::uniform_real_distribution<double> unit_{0.0, 1.0};
};

/// A flow's two addresses, placed on the path before either stream exists.
struct FlowEnds {
    FlowEnds(PathSim& path, int index)
        : A{*IpAddress::parse("10.0.1." + std::to_string(index + 1)), 1111},
          B{*IpAddress::parse("10.0.2." + std::to_string(index + 1)), 2222} {
        path.place(A, false);
        path.place(B, true);
    }
    Address A, B;
};

/// One sender and its receiver.
struct Flow : FlowEnds {
    Flow(PathSim& path, int index, CongestionAlgorithm algo, Clock::time_point now,
         UdpReceiveConfig receive = {})
        : FlowEnds(path, index),
          tx(path, B, 100 + 2 * index, 101 + 2 * index, ConnRole::Outbound, now, DialProfile{}, algo),
          rx(path, A, 101 + 2 * index, 100 + 2 * index, ConnRole::Inbound, now, DialProfile{}, algo,
             receive) {
        path.attach(A, &tx, false);
        path.attach(B, &rx, true);
    }

    UdpStream tx, rx;
    size_t    delivered = 0;
    /// Bytes still to offer the sender; it is kept as full as it will take until
    /// this runs out. SIZE_MAX is a bulk transfer that never ends.
    size_t    to_send = 0;
    /// When non-zero, the application produces data at this many bytes per
    /// second rather than as fast as the sender takes it.
    double    app_rate   = 0;
    double    app_credit = 0;
};

/// The path, its flows, and the clock.
struct Sim {
    explicit Sim(double mbps, Clock::duration rtt, size_t queue_pkts, double fwd_loss = 0.0,
                 uint32_t seed = 1)
        : path(mbps, rtt, queue_pkts, fwd_loss, seed), rtt(rtt) {}

    /// `receive` is the receiver's: how far its window may grow.
    Flow& add(CongestionAlgorithm algo, UdpReceiveConfig receive = {}) {
        flows.push_back(
            std::make_unique<Flow>(path, static_cast<int>(flows.size()), algo, now, receive));
        return *flows.back();
    }

    /// Advance by `d` in steps of `step` — well under any timer a stream arms, so
    /// nothing is resolved coarser than the transport would resolve it.
    void run(Clock::duration d, Clock::duration step = 250us) {
        const auto end = now + d;
        while (now < end) {
            now += step;
            path.deliver_until(now);
            for (auto& f : flows) {
                size_t allowance = SIZE_MAX;
                if (f->app_rate > 0) {
                    f->app_credit += f->app_rate * std::chrono::duration<double>(step).count();
                    allowance = static_cast<size_t>(f->app_credit);
                }
                while (f->to_send > 0 && allowance > 0) {
                    const size_t n = (std::min)({chunk.size(), f->to_send, allowance});
                    const ByteView v(chunk.data(), n);
                    const size_t took = f->tx.write(&v, 1, now);
                    if (took == 0) break;
                    if (f->to_send != SIZE_MAX) f->to_send -= took;
                    if (f->app_rate > 0) { f->app_credit -= took; allowance -= took; }
                }
                f->tx.tick(now);
                f->rx.tick(now);
                for (size_t n; (n = f->rx.read(sink.data(), sink.size())) != 0;) f->delivered += n;
            }
            if (on_step) on_step();
        }
    }

    PathSim                            path;
    Clock::duration                    rtt;
    Clock::time_point                  now{};
    std::vector<std::unique_ptr<Flow>> flows;
    std::function<void()>              on_step;
    std::vector<uint8_t>               chunk = std::vector<uint8_t>(64 * 1024, 0xAB);
    std::vector<uint8_t>               sink  = std::vector<uint8_t>(64 * 1024);
};

/// A receiver whose window stays where every stream starts it: a sender on a path
/// longer than that is held by the window, with no standing queue — a clean round
/// trip to time loss recovery by.
UdpReceiveConfig fixed_window() {
    UdpReceiveConfig c;
    c.max_window = rudp::kInitialWindowPackets;
    return c;
}

const cc::BbrController& bbr(const UdpStream& s) {
    return static_cast<const cc::BbrController&>(s.congestion());
}

/// Payload bytes per second a path of `mbps` can carry in full-size packets.
double payload_rate(double mbps) {
    const double datagram = rudp::kHeaderSize + rudp::kMaxPayload + 28;
    return mbps * 1e6 / 8 * rudp::kMaxPayload / datagram;
}

double mbps_of(size_t bytes, Clock::duration over) {
    return bytes * 8.0 / std::chrono::duration<double>(over).count() / 1e6;
}

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
    struct Sent { cc::TxState tx; uint32_t seq; Clock::time_point acked_at; };
    std::deque<Sent>  flight;
    Clock::time_point now{};
    uint64_t          inflight = 0;
    uint32_t          seq      = 1;

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

namespace {

/// Lose chosen first transmissions of one flow's Data, by offset from the first
/// Data packet sent after this is installed (an offset listed twice also loses
/// that packet's first repair).
struct HoleMaker {
    std::vector<size_t>     holes;
    bool                    armed        = false;
    uint32_t                base         = 0;
    std::map<uint32_t, int> sends;
    std::map<uint32_t, int> drops_left;
    bool                    saw_ranges = false;

    void install(PathSim& path) {
        path.hook = [this](Bytes& d, const Address&, bool forward) {
            rudp::Packet p;
            if (!rudp::decode(d.data(), d.size(), p)) return false;
            if (!forward) {
                if (p.range_count() > 0) saw_ranges = true;
                return false;
            }
            if (p.type != rudp::PacketType::Data || holes.empty()) return false;
            if (!armed) {
                armed = true;
                base  = p.seq;
                for (size_t h : holes) drops_left[base + static_cast<uint32_t>(h)] += 1;
            }
            ++sends[p.seq];
            auto it = drops_left.find(p.seq);
            if (it != drops_left.end() && it->second > 0) { --it->second; return true; }
            return false;
        };
    }
};

} // namespace

// Holes far apart in one window. The receiver names every one of them at once in
// its ranges, so they are repaired within the same round trip — rather than each
// becoming visible only when the hole in front of it fills, a round trip per hole,
// which on a lossy path is what turns a large window into a crawl.
TEST(UdpLossRecoveryTest, HolesFarApartAreRepairedInTheSameRoundTrip) {
    // 100 Mbit/s at 100 ms holds more than a starting receive window, so with the
    // window held there the sender is window-limited with no standing queue: a
    // clean round trip to time by.
    Sim sim(100, 100ms, 2000);
    HoleMaker holes;
    holes.install(sim.path);

    Flow& f = sim.add(CongestionAlgorithm::Reno, fixed_window());
    f.to_send = SIZE_MAX;
    sim.run(2s);   // a window far wider than the spread of the holes
    ASSERT_GT(f.tx.cwnd(), 400u * rudp::kMaxPayload);
    ASSERT_EQ(f.tx.retransmits(), 0u);

    holes.holes = {0, 60, 120, 180, 240, 300};
    holes.armed = false;
    const uint32_t before = f.tx.retransmits();
    Clock::time_point first{}, last{};
    uint32_t          seen = 0;
    sim.on_step = [&] {
        const uint32_t now_rtx = f.tx.retransmits() - before;
        if (now_rtx == seen) return;
        if (seen == 0) first = sim.now;
        last = sim.now;
        seen = now_rtx;
    };
    sim.run(3s);
    sim.on_step = nullptr;

    ASSERT_EQ(f.tx.retransmits() - before, holes.holes.size())
        << "something was repaired that was never lost, or a hole was not";
    ASSERT_NE(first, Clock::time_point{});
    EXPECT_TRUE(holes.saw_ranges);
    EXPECT_LE(last - first, sim.rtt) << "holes named together were repaired rounds apart";
    EXPECT_EQ(f.tx.congestion_events(), 1u) << "one episode, and no timeout";
    EXPECT_FALSE(f.tx.dead());
}

// The round-trip estimate comes from the newest packet an acknowledgement covers.
// The cumulative acknowledgement that finally retires everything held behind a
// hole comes a round trip late, and measuring every packet it covers against it
// used to drag the estimate, the timeout and every pacing rate derived from it up
// by a round trip per hole.
TEST(UdpLossRecoveryTest, AHoleDoesNotInflateTheRoundTripEstimate) {
    Sim sim(100, 100ms, 2000);   // window-limited: no queue to inflate it either
    HoleMaker holes;
    holes.install(sim.path);
    Flow& f = sim.add(CongestionAlgorithm::Reno, fixed_window());
    f.to_send = SIZE_MAX;
    sim.run(2s);
    ASSERT_LT(f.tx.rtt().srtt, 110ms);

    holes.holes = {0, 100, 200};
    Clock::duration worst{};
    sim.on_step = [&] { worst = (std::max)(worst, f.tx.rtt().srtt); };
    sim.run(2s);
    ASSERT_EQ(f.tx.congestion_events(), 1u);
    EXPECT_LT(worst, 125ms) << "packets that waited for a hole were measured as a slow path";
}

// A repair can be lost too. It is not left to the retransmission timeout: once a
// packet sent after it has arrived, it is overdue by the same reasoning that
// condemned the original (RACK, RFC 8985), and goes out again.
TEST(UdpLossRecoveryTest, ALostRepairIsRepairedAgainWithoutATimeout) {
    for (const auto algo : {CongestionAlgorithm::Reno, CongestionAlgorithm::Bbr}) {
        SCOPED_TRACE(to_string(algo));
        // The application sends at half the link rate, so neither the window nor
        // the receiver's buffer is what stops the sender: new data keeps leaving
        // after the repair, which is the evidence RACK reads. (With a full receive
        // window behind a hole nothing new can be sent at all, and a lost repair is
        // a timeout's to find — in TCP as here.)
        Sim sim(50, 40ms, 2000);
        HoleMaker holes;
        holes.install(sim.path);
        Flow& f    = sim.add(algo);
        f.to_send  = SIZE_MAX;
        f.app_rate = payload_rate(50) / 2;
        sim.run(2s);
        const uint32_t events = f.tx.congestion_events();
        ASSERT_EQ(f.tx.retransmits(), 0u);

        holes.holes = {10, 10};   // the packet, and then its first repair
        sim.run(2s);

        EXPECT_EQ(holes.sends[holes.base + 10], 3) << "the lost repair was not sent again";
        EXPECT_EQ(f.tx.retransmits(), 2u) << "something else was repaired";
        EXPECT_EQ(f.tx.congestion_events() - events, 1u)
            << "a timeout fired (or a second episode opened) over one loss";
        EXPECT_FALSE(f.tx.dead());
    }
}

// The other way a repair goes missing: as the last thing the sender has to send.
// Nothing leaves after it, so nothing can arrive after it to give the loss away —
// RACK has no later delivery to read — and this is every request/response exchange
// that loses the same packet twice. A probe has to ask, as it does outside
// recovery (RFC 9002 keeps the probe timer running in recovery for exactly this);
// left to the retransmission timeout it costs at least kMinRto — ten round trips
// here — and the whole window with it.
TEST(UdpLossRecoveryTest, ALostTailRepairIsProbedRatherThanTimedOut) {
    for (const auto algo : {CongestionAlgorithm::Reno, CongestionAlgorithm::Bbr}) {
        SCOPED_TRACE(to_string(algo));
        Sim sim(100, 10ms, 2000);
        HoleMaker holes;
        holes.install(sim.path);
        Flow& f = sim.add(algo);
        sim.run(100ms);   // the dial, and a round-trip estimate to time the probe by
        ASSERT_TRUE(f.tx.connected());
        const uint32_t events = f.tx.congestion_events();

        // One message; the packet four from its end is lost and so is its repair.
        // The three behind it are what reveal the first loss — and once the repair
        // is out there is nothing behind *it*.
        constexpr size_t   kPackets = 20;
        constexpr size_t   kHole    = kPackets - 4;
        holes.holes = {kHole, kHole};
        f.to_send   = kPackets * rudp::kMaxPayload;

        Clock::time_point repair_lost{}, done{};
        sim.on_step = [&] {
            if (repair_lost == Clock::time_point{} && holes.sends[holes.base + static_cast<uint32_t>(kHole)] >= 2)
                repair_lost = sim.now;
            if (done == Clock::time_point{} && f.delivered == kPackets * rudp::kMaxPayload)
                done = sim.now;
        };
        sim.run(2s);
        sim.on_step = nullptr;

        ASSERT_NE(repair_lost, Clock::time_point{}) << "the repair was never sent";
        ASSERT_NE(done, Clock::time_point{}) << "the message never arrived";
        EXPECT_EQ(holes.sends[holes.base + static_cast<uint32_t>(kHole)], 3);
        EXPECT_LT(done - repair_lost, UdpStream::kMinRto)
            << "the lost repair waited for the retransmission timeout";
        EXPECT_EQ(f.tx.congestion_events() - events, 1u)
            << "a timeout fired (or a second episode opened) over one loss";
        EXPECT_FALSE(f.tx.dead());
    }
}

namespace {

/// Keeps every datagram a stream emits and delivers none: for driving one stream
/// by hand, packet by packet.
struct Capture : UdpStreamHost {
    std::vector<Bytes> out;
    void send_datagram(const Address&, const uint8_t* data, size_t len) override {
        out.emplace_back(data, data + len);
    }
    void stream_events(UdpStream&, uint32_t) override {}
};

/// Encode `p` and hand it to `s`, as the mux would.
void feed(UdpStream& s, const rudp::Packet& p, Clock::time_point now) {
    uint8_t buf[rudp::kMaxDatagram];
    rudp::Packet in;
    ASSERT_TRUE(rudp::decode(buf, rudp::encode(p, buf), in));
    s.on_packet(in, now);
}

} // namespace

// Ranges ride only on a pure acknowledgement, and a receiver with data of its own
// may not send one: when the packet that reveals a hole also opens its window, what
// it acknowledges goes out on its next Data packet instead — which carries the
// cumulative ack and nothing about what is held past it. That is the two-way case
// (a file one way, requests and gossip the other), and the sender would be left to
// find the hole a round trip later, when the one in front of it fills. So a hole
// gets a pure acknowledgement of its own, whatever else is leaving — even one
// directly behind the cumulative ack.
TEST(UdpLossRecoveryTest, AHoleIsNamedEvenWhenDataCarriesTheAck) {
    Capture       host;
    const Address peer{*IpAddress::parse("10.0.0.1"), 1111};
    auto          now = Clock::time_point{} + 1s;

    UdpStream rx(host, peer, 11, 10, ConnRole::Inbound, now, DialProfile{},
                 CongestionAlgorithm::Reno);
    rudp::Packet syn;
    syn.type    = rudp::PacketType::Syn;
    syn.conn_id = 11;
    syn.seq     = 1;
    syn.limit   = rudp::kInitialWindowPackets;
    feed(rx, syn, now);
    ASSERT_TRUE(rx.connected());

    // The receiver has a transfer of its own queued, stopped by its window.
    std::vector<uint8_t> data(64 * 1024, 0xCD);
    const ByteView v(data.data(), data.size());
    ASSERT_GT(rx.write(&v, 1, now), 0u);
    ASSERT_GT(rx.queued_bytes(), rx.bytes_in_flight()) << "nothing was left waiting";

    // One packet from the peer: it acknowledges two of the receiver's packets —
    // room for more of its data — and arrives one past a hole.
    const std::vector<uint8_t> payload(100, 0xAB);
    rudp::Packet pkt;
    pkt.type    = rudp::PacketType::Data;
    pkt.conn_id = 11;
    pkt.seq     = 3;   // 2 is the hole
    pkt.ack     = 2;
    pkt.limit   = 2 + rudp::kInitialWindowPackets;
    pkt.payload = ByteView(payload.data(), payload.size());
    host.out.clear();
    now += 10ms;
    feed(rx, pkt, now);

    size_t data_out = 0;
    bool   named    = false;
    for (const Bytes& d : host.out) {
        rudp::Packet p;
        ASSERT_TRUE(rudp::decode(d.data(), d.size(), p));
        if (p.type == rudp::PacketType::Data) ++data_out;
        if (p.type != rudp::PacketType::Ack || p.range_count() == 0) continue;
        const rudp::AckRange r = rudp::ack_range(p, 0);
        named = p.ack == 1 && r.offset == 1 && r.length == 1;
    }
    ASSERT_GT(data_out, 0u) << "the window did not open, so this tested nothing";
    EXPECT_TRUE(named) << "the hole was acknowledged only on Data, which cannot name it";
}

// A window with more runs held past the hole than one Ack can name. The Ack names
// the newest ones — what the sender's loss detection reads — and, in place of the
// oldest, the run the latest arrival joined: here a repair landing deep in the
// window, below everything else named. Left out, it would look lost to the sender
// for as long as the runs above it kept the list full, and be repaired again.
TEST(UdpLossRecoveryTest, AnAckNamesTheNewestRunsAndTheLatestArrival) {
    Capture       host;
    const Address peer{*IpAddress::parse("10.0.0.1"), 1111};
    auto          now = Clock::time_point{} + 1s;

    UdpStream rx(host, peer, 11, 10, ConnRole::Inbound, now, DialProfile{},
                 CongestionAlgorithm::Reno);
    rudp::Packet syn;
    syn.type    = rudp::PacketType::Syn;
    syn.conn_id = 11;
    syn.seq     = 1;
    syn.limit   = rudp::kInitialWindowPackets;
    feed(rx, syn, now);
    ASSERT_TRUE(rx.connected());

    // Every other packet from 4 up: 60 runs of one, across more than one word of
    // the receiver's ring, with 2 (the hole the cumulative ack stands at) and every
    // odd number between them missing.
    const std::vector<uint8_t> payload(100, 0xAB);
    const auto data = [&](uint32_t seq) {
        rudp::Packet pkt;
        pkt.type    = rudp::PacketType::Data;
        pkt.conn_id = 11;
        pkt.seq     = seq;
        pkt.limit   = rudp::kInitialWindowPackets;
        pkt.payload = ByteView(payload.data(), payload.size());
        now += 1ms;
        feed(rx, pkt, now);
    };
    constexpr uint32_t kRuns = 60;
    for (uint32_t i = 0; i < kRuns; ++i) data(4 + 2 * i);
    const uint32_t top = 4 + 2 * (kRuns - 1);

    // A repair deep in the window: it joins the second-oldest run.
    host.out.clear();
    data(7);

    rudp::Packet ack;
    ASSERT_FALSE(host.out.empty());
    ASSERT_TRUE(rudp::decode(host.out.back().data(), host.out.back().size(), ack));
    ASSERT_EQ(ack.type, rudp::PacketType::Ack);
    EXPECT_EQ(ack.ack, 1u) << "the hole at 2 is still open";
    ASSERT_EQ(ack.range_count(), rudp::kMaxAckRanges);

    const auto first_of = [&](const rudp::AckRange& r) { return ack.ack + 1 + r.offset; };
    // Newest first, one packet each, two apart.
    for (size_t i = 0; i + 1 < rudp::kMaxAckRanges; ++i) {
        const rudp::AckRange r = rudp::ack_range(ack, i);
        EXPECT_EQ(first_of(r), top - 2 * static_cast<uint32_t>(i)) << "range " << i;
        EXPECT_EQ(r.length, 1u) << "range " << i;
    }
    // And the last slot is the latest arrival's run, which the list never reached.
    const rudp::AckRange last = rudp::ack_range(ack, rudp::kMaxAckRanges - 1);
    EXPECT_LE(first_of(last), 7u);
    EXPECT_GE(first_of(last) + last.length - 1, 7u) << "the repair that just landed was not named";
}

// Flow control is the one bound on what a peer can make us buffer, so a packet
// past the limit we advertised is not held, however much room there happens to be
// for it — and the acknowledgement it draws still says where the limit stands.
TEST(UdpLossRecoveryTest, APacketPastTheAdvertisedLimitIsNotHeld) {
    Capture       host;
    const Address peer{*IpAddress::parse("10.0.0.1"), 1111};
    auto          now = Clock::time_point{} + 1s;

    UdpStream rx(host, peer, 11, 10, ConnRole::Inbound, now, DialProfile{},
                 CongestionAlgorithm::Reno);
    rudp::Packet syn;
    syn.type    = rudp::PacketType::Syn;
    syn.conn_id = 11;
    syn.seq     = 1;
    syn.limit   = rudp::kInitialWindowPackets;
    host.out.clear();
    feed(rx, syn, now);
    ASSERT_FALSE(host.out.empty());
    rudp::Packet first;
    ASSERT_TRUE(rudp::decode(host.out.back().data(), host.out.back().size(), first));
    const uint32_t limit = first.limit;
    ASSERT_EQ(first.room(), rudp::kInitialWindowPackets);

    // Ten full packets in order, left unread. The ack moves on by ten and the room
    // shrinks by ten, so the limit stands where it was — now short of everything
    // the reorder ring could physically hold, which is what makes this a test of
    // the limit rather than of the ring.
    const std::vector<uint8_t> payload(rudp::kMaxPayload, 0xAB);
    const auto data = [&](uint32_t seq) {
        rudp::Packet pkt;
        pkt.type    = rudp::PacketType::Data;
        pkt.conn_id = 11;
        pkt.seq     = seq;
        pkt.limit   = rudp::kInitialWindowPackets;
        pkt.payload = ByteView(payload.data(), payload.size());
        host.out.clear();
        now += 1ms;
        feed(rx, pkt, now);
        // Out of order, so acknowledged at once (in order, only every other one is).
        rudp::Packet ack;
        if (!host.out.empty()) rudp::decode(host.out.back().data(), host.out.back().size(), ack);
        return ack;
    };
    for (uint32_t seq = 2; seq < 12; ++seq) data(seq);

    const rudp::Packet at = data(limit);
    ASSERT_EQ(at.type, rudp::PacketType::Ack) << "a packet past a hole was not acknowledged";
    EXPECT_EQ(at.limit, limit) << "the limit moved without anything being read";
    ASSERT_EQ(at.range_count(), 1u) << "a packet at the limit is within it";
    EXPECT_EQ(at.ack + 1 + rudp::ack_range(at, 0).offset, limit);

    const rudp::Packet past = data(limit + 1);
    ASSERT_EQ(past.type, rudp::PacketType::Ack);
    EXPECT_EQ(past.limit, limit);
    ASSERT_EQ(past.range_count(), 1u);
    EXPECT_EQ(past.ack + 1 + rudp::ack_range(past, 0).offset, limit);
    EXPECT_EQ(rudp::ack_range(past, 0).length, 1u) << "a packet past the limit was held";
}

// ── Receive window ──────────────────────────────────────────────────────────

namespace {

/// An inbound stream on a Capture host with its Syn already taken, and a way to
/// hand it Data and read back the acknowledgement it answers with.
struct Receiver {
    explicit Receiver(UdpReceiveConfig cfg = {})
        : rx(host, peer, 11, 10, ConnRole::Inbound, now, DialProfile{},
             CongestionAlgorithm::Reno, cfg) {
        rudp::Packet syn;
        syn.type    = rudp::PacketType::Syn;
        syn.conn_id = 11;
        syn.seq     = 1;
        syn.limit   = rudp::kInitialWindowPackets;
        feed(rx, syn, now);
    }

    /// Deliver Data `seq` (full-sized), flagged as held back by our limit or not,
    /// and return the last thing the stream sent in reply (type Ack with nothing
    /// in it if it sent nothing).
    rudp::Packet data(uint32_t seq, bool blocked) {
        rudp::Packet pkt;
        pkt.type    = rudp::PacketType::Data;
        pkt.flags   = blocked ? rudp::FlagBlocked : rudp::FlagNone;
        pkt.conn_id = 11;
        pkt.seq     = seq;
        pkt.limit   = rudp::kInitialWindowPackets;
        pkt.payload = ByteView(payload.data(), payload.size());
        host.out.clear();
        now += 1ms;
        feed(rx, pkt, now);
        rudp::Packet reply;
        reply.conn_id = 0;
        if (!host.out.empty())
            rudp::decode(host.out.back().data(), host.out.back().size(), reply);
        return reply;
    }

    Capture              host;
    Address              peer{*IpAddress::parse("10.0.0.1"), 1111};
    Clock::time_point    now = Clock::time_point{} + 1s;
    std::vector<uint8_t> payload = std::vector<uint8_t>(rudp::kMaxPayload, 0xAB);
    UdpStream            rx;
};

} // namespace

// The receiver cannot see that its window is too small — the sender can, because
// it is the one stopped by it, and it says so (FlagBlocked). Each report doubles
// the window, at once and with an acknowledgement of its own (the sender is
// waiting on it); a report sent against a limit from before the growth is an echo
// of a stall already answered and changes nothing; and the window never passes
// what it is configured to grow to.
TEST(UdpReceiveWindowTest, GrowsWhileThePeerIsHeldBackByIt) {
    UdpReceiveConfig cfg;
    cfg.max_window = 3000;
    Receiver r(cfg);
    ASSERT_EQ(r.rx.receive_window(), rudp::kInitialWindowPackets);

    // In order, unflagged: nothing changes.
    rudp::Packet reply = r.data(2, false);
    EXPECT_EQ(r.rx.receive_window(), rudp::kInitialWindowPackets);

    // The sender reports itself stopped.
    reply = r.data(3, true);
    ASSERT_EQ(r.rx.receive_window(), 2 * rudp::kInitialWindowPackets);
    ASSERT_EQ(reply.type, rudp::PacketType::Ack) << "the stopped sender was not told at once";
    EXPECT_EQ(reply.room(), 2 * rudp::kInitialWindowPackets - 2)
        << "the acknowledgement did not carry the larger window";
    const uint32_t grown_limit = reply.limit;

    // Still flagged, but sent before the sender could have heard: an echo.
    r.data(4, true);
    EXPECT_EQ(r.rx.receive_window(), 2 * rudp::kInitialWindowPackets) << "one stall grew the window twice";

    // Stopped again, now at the new limit: it grows again — to the ceiling.
    r.data(5, false);
    reply = r.data(grown_limit, true);
    EXPECT_EQ(r.rx.receive_window(), 3000u);
    r.data(grown_limit + 1, true);   // whatever arrives, past the ceiling it stays
    EXPECT_EQ(r.rx.receive_window(), 3000u);
}

// The ring of held bits is indexed by sequence number modulo its length, so a
// window that grows moves every packet already held to a new place in it. They
// must all still be there afterwards — named by the next acknowledgement, and
// delivered when the hole fills.
TEST(UdpReceiveWindowTest, HeldPacketsSurviveTheWindowGrowing) {
    Receiver r;
    r.data(5, false);
    r.data(1000, false);   // far enough out to land elsewhere in a longer ring
    const rudp::Packet reply = r.data(7, true);
    ASSERT_EQ(r.rx.receive_window(), 2 * rudp::kInitialWindowPackets);

    ASSERT_EQ(reply.type, rudp::PacketType::Ack);
    ASSERT_EQ(reply.range_count(), 3u);
    const uint32_t want[3] = {1000, 7, 5};   // newest first
    for (size_t i = 0; i < 3; ++i) {
        const rudp::AckRange range = rudp::ack_range(reply, i);
        EXPECT_EQ(reply.ack + 1 + range.offset, want[i]) << "range " << i;
        EXPECT_EQ(range.length, 1u) << "range " << i;
    }

    // Fill 2..4 and 6: everything up to 7 is delivered, 1000 is still held.
    for (const uint32_t seq : {2u, 3u, 4u, 6u}) r.data(seq, false);
    std::vector<uint8_t> sink(64 * 1024);
    size_t got = 0;
    for (size_t n; (n = r.rx.read(sink.data(), sink.size())) != 0;) got += n;
    EXPECT_EQ(got, 6 * rudp::kMaxPayload);
    const rudp::Packet after = r.data(8, false);
    ASSERT_EQ(after.range_count(), 1u);
    EXPECT_EQ(after.ack + 1 + rudp::ack_range(after, 0).offset, 1000u);
}

// A sender held back because the application has stopped reading is flow control
// doing its job: a larger window would only let the peer park more of what nobody
// reads in our memory.
TEST(UdpReceiveWindowTest, DoesNotGrowForAReaderThatHasStopped) {
    Receiver r;
    // A third of the window delivered in order and left unread.
    const uint32_t unread = rudp::kInitialWindowPackets / 3;
    for (uint32_t i = 0; i < unread; ++i) r.data(2 + i, false);

    r.data(2 + unread, true);
    EXPECT_EQ(r.rx.receive_window(), rudp::kInitialWindowPackets)
        << "the window grew for a reader that is not reading";

    // Once the reader catches up, the same report is honoured.
    std::vector<uint8_t> sink(64 * 1024);
    while (r.rx.read(sink.data(), sink.size()) != 0) {}
    r.data(3 + unread, true);
    EXPECT_EQ(r.rx.receive_window(), 2 * rudp::kInitialWindowPackets);
}

// A grown window is a promise the budget has to cover if a peer fills it with
// holes, so once the transfer it was grown for goes quiet it is given back.
TEST(UdpReceiveWindowTest, ShrinksBackAfterSilence) {
    Receiver r;
    r.data(2, true);
    ASSERT_EQ(r.rx.receive_window(), 2 * rudp::kInitialWindowPackets);

    r.rx.tick(r.now + UdpStream::kWindowDecay / 2);
    EXPECT_EQ(r.rx.receive_window(), 2 * rudp::kInitialWindowPackets) << "given back too soon";
    r.rx.tick(r.now + UdpStream::kWindowDecay);
    EXPECT_EQ(r.rx.receive_window(), rudp::kInitialWindowPackets);
}

// The other end of it: a sender that has data waiting and is stopped by the peer's
// limit says so on what it sends — exactly then, not on the packets before.
TEST(UdpReceiveWindowTest, ASenderStoppedByTheLimitSaysSo) {
    Capture       host;
    const Address peer{*IpAddress::parse("10.0.0.1"), 1111};
    auto          now = Clock::time_point{} + 1s;
    UdpStream tx(host, peer, 10, 11, ConnRole::Outbound, now, DialProfile{},
                 CongestionAlgorithm::Reno);

    // The Syn is answered with room for four packets past it.
    rudp::Packet ack;
    ack.type    = rudp::PacketType::Ack;
    ack.conn_id = 10;
    ack.seq     = 1;
    ack.ack     = 1;
    ack.limit   = 1 + 4;
    now += 10ms;
    feed(tx, ack, now);
    ASSERT_TRUE(tx.connected());

    host.out.clear();
    std::vector<uint8_t> data(10 * rudp::kMaxPayload, 0xCD);
    const ByteView v(data.data(), data.size());
    ASSERT_GT(tx.write(&v, 1, now), 0u);
    for (int i = 0; i < 50; ++i) {   // let the pacer release what the windows allow
        now += 2ms;
        tx.tick(now);
    }

    // First transmissions only: nothing is acknowledged here, so a tail probe of
    // the last one follows in time.
    std::vector<rudp::Packet> sent;
    for (const Bytes& d : host.out) {
        rudp::Packet p;
        ASSERT_TRUE(rudp::decode(d.data(), d.size(), p));
        if (p.type != rudp::PacketType::Data) continue;
        if (!sent.empty() && !rudp::seq_less(sent.back().seq, p.seq)) continue;
        sent.push_back(p);
    }
    ASSERT_EQ(sent.size(), 4u) << "the sender went past the limit, or stopped short of it";
    for (size_t i = 0; i + 1 < sent.size(); ++i)
        EXPECT_FALSE(sent[i].flags & rudp::FlagBlocked) << "packet " << i << " was not yet held back";
    EXPECT_TRUE(sent.back().flags & rudp::FlagBlocked)
        << "the packet that reached the limit did not say the sender is held back";
}

// Holes cost memory, and the budget is what bounds it across streams: a stream
// filling its window with nothing but holes is refused once the budget is spent,
// every other stream keeps its guaranteed share regardless, what is held is given
// back as the holes fill, and a window does not grow on a budget that could not
// honour it.
TEST(UdpReceiveWindowTest, TheBudgetBoundsWhatHolesCanHold) {
    UdpReceiveBudget budget(512 * 1024);
    UdpReceiveConfig cfg;
    cfg.budget = &budget;

    Receiver greedy(cfg);
    // Every other packet, across the whole window: 2 is missing, and so is every
    // even number after it.
    for (uint32_t seq = 3; seq < 2 + rudp::kInitialWindowPackets; seq += 2) greedy.data(seq, false);
    EXPECT_LE(budget.used(), budget.limit()) << "the budget was overspent";
    EXPECT_GT(budget.used(), budget.limit() - 2 * rudp::kMaxPayload) << "the budget was not used";
    EXPECT_EQ(greedy.rx.held_bytes(), budget.used());

    // Another stream, with the budget already gone, still holds its share.
    Receiver other(cfg);
    size_t held = 0;
    for (uint32_t seq = 3; seq < 2 + 400; seq += 2) {
        other.data(seq, false);
        held = other.rx.held_bytes();
    }
    EXPECT_GT(held, UdpReceiveBudget::kGuaranteed - 2 * rudp::kMaxPayload);
    EXPECT_LE(held, UdpReceiveBudget::kGuaranteed);

    // Nor does a window grow on a spent budget.
    other.data(500, true);
    EXPECT_EQ(other.rx.receive_window(), rudp::kInitialWindowPackets);

    // Filling the hole at the front releases what was held behind it.
    const size_t before = budget.used();
    greedy.data(2, false);
    EXPECT_LT(budget.used(), before);
    EXPECT_EQ(budget.used(), greedy.rx.held_bytes() + other.rx.held_bytes());
}

// End to end, on a path whose bandwidth-delay product is larger than a starting
// window: the sender reports itself held back and the receiver's window grows
// past where it started.
TEST(UdpReceiveWindowTest, GrowsOnAPathLongerThanTheWindow) {
    Sim sim(200, 100ms, 4000);   // 2.5 MB in flight would fill it; 1.2 MB is the window
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(3s);
    EXPECT_GT(f.rx.receive_window(), rudp::kInitialWindowPackets);
    EXPECT_FALSE(f.tx.dead());
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
        Flow& f = sim.add(algo);
        f.to_send = SIZE_MAX;
        sim.run(2s);
        const uint32_t events = f.tx.congestion_events();
        ASSERT_EQ(f.tx.retransmits(), 0u);

        holes.holes.clear();
        for (size_t i = 0; i < 24; ++i) holes.holes.push_back(i);   // one wide burst
        sim.run(2s);
        EXPECT_EQ(f.tx.congestion_events() - events, 1u);
        EXPECT_EQ(f.tx.retransmits(), 24u);
        EXPECT_FALSE(f.tx.dead());
    }
}

// A comb of holes across most of a full window: every eighth packet. Each Ack
// repeats every range the receiver holds, the repairs leave in a different order
// from the packets they repair, and the holes surface over several round trips as
// the ranges' reach moves up the window — everything that loss detection now walks
// incrementally rather than from the front of the queue. Each hole is repaired
// exactly once (nothing condemned twice, nothing left behind a cursor), and the
// stream comes out of it delivering again.
TEST(UdpLossRecoveryTest, AWideCombOfHolesIsRepairedOncePerHole) {
    for (const auto algo : {CongestionAlgorithm::Reno, CongestionAlgorithm::Bbr}) {
        SCOPED_TRACE(to_string(algo));
        Sim sim(100, 100ms, 2000);
        HoleMaker holes;
        holes.install(sim.path);
        Flow& f = sim.add(algo, fixed_window());   // no queue: every loss is one of ours
        f.to_send = SIZE_MAX;
        sim.run(2s);
        ASSERT_EQ(f.tx.retransmits(), 0u);

        for (size_t i = 0; i < 100; ++i) holes.holes.push_back(8 * i);
        sim.run(3s);
        const size_t after_recovery = f.delivered;
        sim.run(1s);

        EXPECT_EQ(f.tx.retransmits(), holes.holes.size());
        for (size_t h : holes.holes)
            EXPECT_EQ(holes.sends[holes.base + static_cast<uint32_t>(h)], 2) << "hole " << h;
        EXPECT_GT(f.delivered - after_recovery, 5u * 1000 * 1000) << "the stream did not recover";
        EXPECT_FALSE(f.tx.dead());
    }
}

// ── Long fat paths ──────────────────────────────────────────────────────────

// A path whose bandwidth-delay product is four times what a stream starts with.
// Every limit on the way grows to meet it — the receiver's window on the sender's
// reports, the congestion window on the model, the send queue with the congestion
// window — and the link is filled. At the old fixed 1024-packet window this path
// topped out near 96 Mbit/s.
TEST(UdpLongPathTest, FillsAPathFourTimesTheStartingWindow) {
    Sim sim(400, 100ms, 4200);   // 5 MB in flight to fill it, 1 BDP of buffer
    Flow& f = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(4s);
    const size_t at = f.delivered;
    sim.run(2s);

    const double mbps = mbps_of(f.delivered - at, 2s);
    EXPECT_GT(mbps, 0.85 * 400 * rudp::kMaxPayload / (rudp::kHeaderSize + rudp::kMaxPayload + 28))
        << "only " << mbps << " Mbit/s on a 400 Mbit/s path";
    EXPECT_GT(f.rx.receive_window(), 4 * rudp::kInitialWindowPackets) << "the receive window never grew";
    EXPECT_GT(f.tx.send_queue_limit(), UdpStream::kSendQueueFloor)
        << "the send queue stayed at its floor under a window that outgrew it";
    // Yet no longer than the peer could ever take, plus the floor that keeps it fed.
    EXPECT_LE(f.tx.send_queue_limit(),
              size_t{f.rx.receive_window()} * rudp::kMaxPayload + UdpStream::kSendQueueFloor)
        << "the send queue outgrew the receiver's window";
    EXPECT_FALSE(f.tx.dead());
}

// A window held back by the receiver says nothing about what the path would carry,
// and Reno must not grow on the acks it produces: with nothing above the window
// but the largest receive window there is, a congestion window grown that way runs
// off far past anything in flight, and takes a spurious loss with it when it is
// finally cut.
TEST(UdpLongPathTest, RenoDoesNotGrowAWindowTheReceiverKeepsFromFilling) {
    Sim sim(200, 100ms, 2000);   // a BDP twice the receiver's fixed window
    Flow& f = sim.add(CongestionAlgorithm::Reno, fixed_window());
    f.to_send = SIZE_MAX;
    sim.run(5s);
    EXPECT_LE(f.tx.cwnd(), 2 * rudp::kInitialWindowPackets * rudp::kMaxPayload + 4 * rudp::kMaxPayload)
        << "the window grew to " << f.tx.cwnd() / rudp::kMaxPayload
        << " packets with the receiver holding the flight to " << rudp::kInitialWindowPackets;
    EXPECT_GT(f.tx.cwnd(), rudp::kInitialWindowPackets * rudp::kMaxPayload / 2)
        << "the window did not even reach what the receiver allows";
}

// ── A coarse host clock ─────────────────────────────────────────────────────

// Everything else here wakes the streams every 250 us. A virtualised or
// power-managed host does not: a 1 ms poll timeout sleeps 2-15 ms there (Windows
// rounds every one to 15.6 ms), and arrivals are taken in the same late batches.
// The pacer must still release the rate it was given. When it kept only one
// quantum of tokens across a late wake-up, the stream sent a fraction of its
// pacing rate, BBR took that fraction for the path, and each round paced lower
// than the last — a real 100 Mbit/s upload ended at half a megabyte a second.
TEST(UdpCoarseClockTest, APacedSenderKeepsItsRateWhenTheHostWakesLate) {
    for (const auto algo : {CongestionAlgorithm::Bbr, CongestionAlgorithm::Reno}) {
        for (const auto wake : {Clock::duration(4ms), Clock::duration(15ms)}) {
            Sim sim(100, 40ms, 400);   // 1 BDP of buffer
            Flow& f = sim.add(algo);
            f.to_send = SIZE_MAX;
            sim.run(6s, wake);
            const size_t at = f.delivered;
            sim.run(4s, wake);

            const double util = (f.delivered - at) / 4.0 / payload_rate(100);
            EXPECT_GT(util, 0.8) << (algo == CongestionAlgorithm::Bbr ? "BBR" : "Reno")
                                 << " used " << util * 100 << "% of the path on a host that wakes every "
                                 << std::chrono::duration_cast<std::chrono::milliseconds>(wake).count()
                                 << " ms";
        }
    }
}

// ── BBR ─────────────────────────────────────────────────────────────────────

// The two things BBR is for, on a path with four BDPs of buffer: it finds the
// bottleneck rate, and it does so without parking a queue in front of it. Reno on
// the same path fills the buffer — which is what every other message to that peer,
// and every other flow through that router, then waits behind.
TEST(BbrTest, FindsTheBottleneckAndKeepsTheQueueShort) {
    const auto standing_queue = [](CongestionAlgorithm algo, double& util, Flow*& out,
                                   std::unique_ptr<Sim>& keep) {
        keep = std::make_unique<Sim>(20, 40ms, 333);
        Sim& sim = *keep;
        Flow& f  = sim.add(algo);
        f.to_send = SIZE_MAX;
        sim.run(4s);
        const size_t start = f.delivered;
        std::vector<Clock::duration> rtts;
        sim.on_step = [&] { rtts.push_back(f.tx.rtt().latest); };
        sim.run(6s);
        sim.on_step = nullptr;
        util = (f.delivered - start) / 6.0 / payload_rate(20);
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
    EXPECT_TRUE(bbr(bf->tx).full_bw_reached());
    EXPECT_NEAR(static_cast<double>(bbr(bf->tx).max_bw()), payload_rate(20), payload_rate(20) * 0.2)
        << "the bandwidth model is off the bottleneck";
    EXPECT_LT(bbr_queue, 10ms) << "BBR is keeping a standing queue";
    // The contrast is the point of the test, so it is asserted too: if the model
    // stopped producing a full buffer for Reno, the BBR figure would mean nothing.
    EXPECT_GT(reno_queue, 50ms);
    EXPECT_GT(reno_util, 0.85);
}

// Random loss — Wi-Fi, a mobile link — is not congestion. Reno backs off on every
// one; BBR backs off only once loss passes its threshold, and keeps most of the
// path at a loss rate that leaves Reno with a fraction of it.
TEST(BbrTest, HoldsItsRateUnderRandomLoss) {
    const auto run = [](CongestionAlgorithm algo) {
        Sim sim(10, 100ms, 104, 0.01, 7);
        Flow& f = sim.add(algo);
        f.to_send = SIZE_MAX;
        sim.run(20s);
        EXPECT_FALSE(f.tx.dead());
        return f.delivered;
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
    const uint64_t bdp = bbr(f.tx).bdp();

    bool     in_probe_rtt = false, came_back = false;
    int      entries      = 0;
    uint32_t worst_cwnd   = 0;
    sim.on_step = [&] {
        const bool now_in = bbr(f.tx).state() == cc::BbrController::State::ProbeRtt;
        if (now_in && !in_probe_rtt) { ++entries; worst_cwnd = 0; }
        if (now_in) worst_cwnd = (std::max)(worst_cwnd, f.tx.cwnd());
        if (!now_in && in_probe_rtt) came_back = true;
        in_probe_rtt = now_in;
    };
    sim.run(9s);
    sim.on_step = nullptr;

    EXPECT_GE(entries, 1) << "no ProbeRTT in nine seconds of saturation";
    EXPECT_TRUE(came_back) << "ProbeRTT never ended";
    EXPECT_LE(worst_cwnd, (std::max<uint64_t>)(bdp * 6 / 10, cc::BbrController::kMinPipeCwnd) +
                              4 * rudp::kMaxPayload)
        << "ProbeRTT did not hold inflight near half a BDP";
}

// Two BBR flows through one bottleneck share it, the second one starting late
// into a buffer of one BDP that the first already keeps busy.
//
// They do not converge to an exact split quickly there — and neither do two Reno
// flows: the newcomer finds the buffer full, its first loss sets where it starts
// from, and BBRv3 moves shares only as fast as its probes raise one flow's
// inflight_hi and its loss rounds cut the other's (bench_path's compete section
// shows Jain 0.95-0.97 for both controllers over 30 s). What is asserted is what
// holds regardless: the pipe stays full, nobody starves, and the split is at
// least roughly fair.
TEST(BbrTest, TwoFlowsShareABottleneckWithoutStarvation) {
    Sim sim(20, 40ms, 83);
    Flow& a   = sim.add(CongestionAlgorithm::Bbr);
    a.to_send = SIZE_MAX;
    sim.run(3s);
    Flow& b   = sim.add(CongestionAlgorithm::Bbr);
    b.to_send = SIZE_MAX;
    sim.run(30s);
    const size_t a0 = a.delivered, b0 = b.delivered;
    sim.run(30s);
    const double ra   = static_cast<double>(a.delivered - a0);
    const double rb   = static_cast<double>(b.delivered - b0);
    const double jain = (ra + rb) * (ra + rb) / (2 * (ra * ra + rb * rb));
    EXPECT_GT((ra + rb) / 30.0, 0.85 * payload_rate(20)) << "the pipe was not kept full";
    EXPECT_GT((std::min)(ra, rb) / (ra + rb), 0.25)
        << "a: " << mbps_of(a.delivered - a0, 30s) << " Mbit/s, b: "
        << mbps_of(b.delivered - b0, 30s) << " Mbit/s — one flow is starving the other";
    EXPECT_GT(jain, 0.8);
}

// A two-second outage — every packet lost both ways — costs a timeout, not the
// connection, and the model rebuilds from the acknowledgements once the path is
// back.
TEST(BbrTest, RecoversFromAnOutage) {
    Sim sim(20, 40ms, 83);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(4s);
    const uint32_t events = f.tx.congestion_events();

    sim.path.blackout = true;
    sim.run(2s);
    sim.path.blackout = false;
    sim.run(3s);
    const size_t start = f.delivered;
    sim.run(3s);

    EXPECT_FALSE(f.tx.dead());
    EXPECT_GT(f.tx.congestion_events(), events) << "the outage went unnoticed";
    EXPECT_GT((f.delivered - start) / 3.0, 0.8 * payload_rate(20)) << "the rate never came back";
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
        return std::make_pair(f.delivered, f.tx.retransmits());
    };
    EXPECT_EQ(run(), run());
}

// After ten seconds of application silence BBR keeps its model — unlike a
// window, a bandwidth estimate does not go stale by sitting unused — and lets its
// pacing rate govern the restart. What must not happen is the whole window going
// out at once.
TEST(BbrTest, AnIdleStreamResumesAtItsPacingRateNotInABurst) {
    Sim sim(50, 40ms, 400);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(4s);
    f.to_send = 0;
    sim.run(10s);
    ASSERT_EQ(f.tx.bytes_in_flight(), 0u);
    const uint32_t window = f.tx.cwnd();
    ASSERT_GT(window, 100u * rudp::kMaxPayload) << "the warm-up never grew the window";

    const size_t before = sim.path.fwd().sent;
    f.to_send = rudp::kMaxPayload * 2000;
    sim.run(1ms, 1ms);
    const size_t burst = sim.path.fwd().sent - before;
    const auto   rate  = f.tx.congestion().pacing_rate();
    // A millisecond at the pacing rate, plus the couple of packets an empty pipe
    // is always allowed.
    EXPECT_LE(burst * rudp::kMaxPayload, rate.bytes_over(2ms) + 3 * rudp::kMaxPayload)
        << burst << " packets in the first millisecond after idle";
    EXPECT_LT(burst * rudp::kMaxPayload, window / 4) << "the window went out in one burst";
}

// Peer-to-peer traffic is app-limited most of the time. A quiet second sends at
// whatever the application gives it, and that rate says nothing about the path:
// it must not pull the bandwidth estimate down to it.
TEST(BbrTest, AppLimitedTrafficDoesNotLowerTheEstimate) {
    Sim sim(20, 40ms, 83);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(5s);
    const uint64_t estimate = bbr(f.tx).max_bw();
    ASSERT_GT(estimate, payload_rate(20) * 0.8);

    // Ten small messages a second for eight seconds — long enough for several
    // probe cycles and a ProbeRTT to come and go.
    f.to_send = 0;
    for (int i = 0; i < 80; ++i) {
        f.to_send = 300;
        sim.run(100ms);
    }
    EXPECT_GT(bbr(f.tx).max_bw(), estimate * 8 / 10)
        << "an application's pace was taken for the path's";
}

// BBR fills a real path's BDP: past the old 256-packet ceiling on 100 Mbit/s at
// 100 ms. (It does not need to on a path with no round trip, which is why the
// stream test of the same name runs Reno.)
TEST(BbrTest, FillsAWindowLargerThanTheOldCeiling) {
    Sim sim(100, 100ms, 1041);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    size_t peak = 0;
    sim.on_step = [&] { peak = (std::max)(peak, f.tx.bytes_in_flight()); };
    sim.run(4s);
    EXPECT_GT(peak, 256u * rudp::kMaxPayload);
    EXPECT_GT(mbps_of(f.delivered, 4s), 50.0);
}

// A buffer a tenth of a BDP deep overflows long before Startup's bandwidth
// samples stop growing. The loss is what ends Startup there, and the inflight it
// happened at becomes the long-term bound the probes then work from.
TEST(BbrTest, AShallowBufferEndsStartupOnLoss) {
    Sim sim(10, 100ms, 10);
    Flow& f   = sim.add(CongestionAlgorithm::Bbr);
    f.to_send = SIZE_MAX;
    sim.run(5s);
    EXPECT_TRUE(bbr(f.tx).full_bw_reached());
    EXPECT_NE(bbr(f.tx).inflight_hi(), cc::BbrController::kInfinite)
        << "loss above the threshold never set a long-term bound";
    const size_t start = f.delivered;
    sim.run(10s);
    EXPECT_GT((f.delivered - start) / 10.0, 0.6 * payload_rate(10));
}
