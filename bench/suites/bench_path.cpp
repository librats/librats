// bench_path.cpp — the transport against a path that pushes back.
//
// bench_transport measures the two wires end to end, but only over paths that
// are far too good to exercise the half of the datagram transport that exists
// for bad ones: loopback has no delay, no queue and no loss, and a LAN has a
// round trip measured in microseconds. On both of those, slow start reaches its
// ceiling before the first millisecond is out, the pacer's budget exceeds a whole
// window, nothing is ever retransmitted and the congestion window is never
// reduced. Every number they produce is therefore a *floor* on cost and says
// nothing at all about behaviour.
//
// tools/badnet.sh fills part of that gap by putting netem in the way — and it is
// the right tool for asking "does this still work when the network is hostile".
// It is the wrong tool for asking "did this change make it worse", because netem
// is random: two runs of the same binary differ by more than most regressions do,
// so a verdict needs many runs and still resolves only large effects.
//
// So this suite does not use a network at all. UdpStream never reads the clock
// itself — every entry point takes `now` — which makes the whole congestion
// controller a pure function of its inputs and lets it be driven in virtual time
// against a model of the thing that actually pushes back:
//
//     sender ──▶ [ drop-tail queue ] ──▶ [ serialiser at the link rate ] ──▶
//                                          ──▶ [ propagation delay ] ──▶ receiver
//
// A packet is dropped when the transmission backlog in front of it exceeds the
// queue, or with the configured probability. Nothing else is modelled, and
// nothing needs to be: this is the mechanism every loss-based congestion control
// is a response to.
//
// ── What is measured ────────────────────────────────────────────────────────
//
//   bulk   — one-way transfer over paths of different rate, delay and queue
//            depth. Utilisation is the headline; retransmissions and window
//            reductions say *how* it was reached. This is where a slow start
//            that overshoots, or a pacer that bursts, shows up.
//   idle   — transfer, silence, transfer. What the congestion window is worth
//            after nobody has validated it for ten seconds, and what the burst
//            that follows costs. The shape of most peer-to-peer traffic.
//   tail   — request/response, where the packet that goes missing is the last
//            one and has nothing behind it to reveal the loss. Reported as a
//            latency distribution, because the median is unaffected and the
//            whole effect lives in the tail.
//
// ── Reading the numbers ─────────────────────────────────────────────────────
//
// Everything here is deterministic: same binary, same numbers, every time. That
// is the point — it makes small regressions visible, which no real path does.
// The flip side is that a model is only ever as good as what it models: there is
// no reordering, no ack compression, no competing traffic and no variable delay,
// so these figures are not predictions of what a real network will give. They
// are a *comparison* — this build against that one — and should be read only
// that way.
//
// Build:  cmake -S bench -B bench/build && cmake --build bench/build --target bench_path

#include "framework/alloc_track.h"

#include "librats/transport/udp_stream.h"
#include "librats/transport/udp_packet.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <deque>
#include <random>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h>   // isatty
#endif

using namespace librats;

namespace {

using Clock = UdpStream::Clock;
using ms    = std::chrono::milliseconds;
using us    = std::chrono::microseconds;
using ns    = std::chrono::nanoseconds;

bool g_color = true;
/// The controller every Rig in the current pass runs.
CongestionAlgorithm g_algo = CongestionAlgorithm::Bbr;
const char* col(const char* code) { return g_color ? code : ""; }

// ── The path ────────────────────────────────────────────────────────────────

struct InFlight {
    Clock::time_point arrive;
    Address           to;
    Bytes             bytes;
};

/// One direction: a drop-tail queue in front of a serialiser, then a fixed delay.
struct Direction {
    double          rate_bps   = 0;
    Clock::duration delay{};
    size_t          queue_pkts = 0;   ///< depth in full-size packets
    double          loss       = 0;   ///< per-packet probability, on top of the queue

    /// When the serialiser finishes what it has already accepted. The backlog in
    /// front of a new packet — and therefore the queue occupancy it must fit in —
    /// is exactly this minus now.
    Clock::time_point    busy_until{};
    std::deque<InFlight> wire;
    size_t               drops = 0;
};

/// Any number of sender/receiver pairs sharing one bottleneck: everything
/// addressed to a receiver queues in the forward direction, everything addressed
/// to a sender in the reverse one.
class Path : public UdpStreamHost {
public:
    Path(Direction fwd, Direction rev) : fwd_(fwd), rev_(rev), rng_(12345) {}
    /// A path between one sender and one receiver, placed from the start.
    Path(Direction fwd, Direction rev, const Address& sender, const Address& receiver)
        : Path(fwd, rev) {
        place(sender, false);
        place(receiver, true);
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
        const End* end = find(to);
        Direction& d = (end && end->receiver) ? fwd_ : rev_;

        // Nanoseconds, not microseconds: at a gigabit a full packet serialises in
        // 9.98 us, and truncating that to 9 makes the link a tenth faster than it
        // says it is.
        const auto serial     = ns(static_cast<long long>((len + 28) * 8 * 1e9 / d.rate_bps));
        const auto pkt_serial = ns(static_cast<long long>((1200 + 28) * 8 * 1e9 / d.rate_bps));
        const auto backlog    = d.busy_until > now_ ? (d.busy_until - now_)
                                                    : Clock::duration::zero();

        if (backlog > pkt_serial * static_cast<long long>(d.queue_pkts)) { ++d.drops; return; }
        // A deliberate, deterministic hole — used by the memory section, where a
        // random one would make the figure differ from run to run.
        if (&d == &fwd_ && drop_burst_ > 0) { --drop_burst_; ++d.drops; return; }
        if (d.loss > 0 && unit_(rng_) < d.loss) { ++d.drops; return; }

        d.busy_until = (std::max)(now_, d.busy_until) + serial;
        d.wire.push_back(InFlight{d.busy_until + d.delay, to, Bytes(data, data + len)});
    }

    void stream_events(UdpStream&, uint32_t) override {}

    /// Advance the model to `now`, delivering everything that has arrived.
    void deliver_until(Clock::time_point now) {
        now_ = now;
        for (Direction* d : {&fwd_, &rev_}) {
            while (!d->wire.empty() && d->wire.front().arrive <= now) {
                InFlight f = std::move(d->wire.front());
                d->wire.pop_front();
                rudp::Packet p;
                if (!rudp::decode(f.bytes.data(), f.bytes.size(), p)) continue;
                if (const End* end = find(f.to); end && end->stream) end->stream->on_packet(p, now);
            }
        }
    }

    /// Swallow the next `n` packets travelling towards the receiver.
    void   drop_next(size_t n) { drop_burst_ = n; }
    size_t drops()     const { return fwd_.drops + rev_.drops; }
    size_t fwd_drops() const { return fwd_.drops; }

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
    size_t       drop_burst_ = 0;
    std::mt19937 rng_;
    std::uniform_real_distribution<double> unit_{0.0, 1.0};
};

/// Scratch the feeder writes from and the drain reads into. Shared and allocated
/// once, deliberately: a per-Rig buffer would be charged to whichever scenario
/// happened to build the Rig, and the memory section would be measuring the
/// benchmark's own scaffolding rather than the transport.
constexpr size_t kScratch = 64 * 1024;
std::vector<uint8_t>& feed_buffer() {
    static std::vector<uint8_t> v(kScratch, 0xAB);
    return v;
}
std::vector<uint8_t>& drain_buffer() {
    static std::vector<uint8_t> v(kScratch);
    return v;
}

/// A connected pair on a virtual clock, with the model between them.
struct Rig {

    Address A{*IpAddress::parse("10.0.0.1"), 1111};
    Address B{*IpAddress::parse("10.0.0.2"), 2222};
    Path      path;
    Clock::time_point now{};
    UdpStream tx, rx;
    std::vector<uint8_t>& chunk = feed_buffer();
    std::vector<uint8_t>& sink  = drain_buffer();
    size_t delivered = 0;

    Rig(double rate_mbps, int rtt_ms, double loss, size_t queue)
        : path(Direction{rate_mbps * 1e6, us(rtt_ms * 500), queue, loss, {}, {}, 0},
               Direction{rate_mbps * 1e6, us(rtt_ms * 500), queue, loss, {}, {}, 0}, A, B),
          tx(path, B, 1, 2, ConnRole::Outbound, {}, DialProfile{}, g_algo),
          rx(path, A, 2, 1, ConnRole::Inbound, {}, DialProfile{}, g_algo) {
        path.attach(A, &tx, false);
        path.attach(B, &rx, true);
    }

    /// Step the model forward by `d`, offering the sender as much as it will take
    /// when `feed` is set. The step is well under any timer the stream arms, so
    /// nothing is resolved coarser than the transport itself would resolve it.
    void run(Clock::duration d, bool feed) {
        constexpr auto kStep = us(200);
        const auto end = now + d;
        while (now < end) {
            now += kStep;
            path.deliver_until(now);
            if (feed) {
                for (int i = 0; i < 64; ++i) {
                    ByteView v(chunk.data(), chunk.size());
                    if (tx.write(&v, 1, now) == 0) break;
                }
            }
            tx.tick(now);
            rx.tick(now);
            for (;;) {
                const size_t n = rx.read(sink.data(), sink.size());
                if (!n) break;
                delivered += n;
            }
        }
    }
};

// ── Reporting ───────────────────────────────────────────────────────────────

void heading(const char* title, const char* c1, const char* c2,
             const char* c3, const char* c4, const char* c5) {
    std::printf("\n%s%s%s\n", col("\x1b[1m"), title, col("\x1b[0m"));
    std::printf("  %-30s %9s %9s %9s %9s %9s\n", "", c1, c2, c3, c4, c5);
    std::printf("  %-30s %9s %9s %9s %9s %9s\n", "------------------------------",
                "---------", "---------", "---------", "---------", "---------");
}

// ── bulk ────────────────────────────────────────────────────────────────────

void bulk(const char* name, double rate, int rtt, double loss, size_t queue, int secs) {
    Rig r(rate, rtt, loss, queue);
    r.run(std::chrono::seconds(secs), true);

    const double mbps = r.delivered * 8.0 / (secs * 1e6);
    const double util = mbps / rate * 100;

    char util_s[64];
    std::snprintf(util_s, sizeof(util_s), "%8.1f%%", util);
    std::string tinted = util_s;
    if (g_color) tinted = std::string(util >= 85 ? "\x1b[32m" : util >= 65 ? "" : "\x1b[33m")
                        + tinted + "\x1b[0m";

    std::printf("  %-30s %9.2f %s %9u %9u %9zu\n", name, mbps, tinted.c_str(),
                r.tx.retransmits(), r.tx.congestion_events(), r.path.drops());
}

// ── idle ────────────────────────────────────────────────────────────────────

void idle(const char* name, double rate, int rtt, size_t queue, int warm, int quiet) {
    Rig r(rate, rtt, 0.0, queue);
    r.run(std::chrono::seconds(warm), true);
    const uint32_t grown = r.tx.cwnd() / rudp::kMaxPayload;

    r.run(std::chrono::seconds(quiet), false);
    const uint32_t resumed = r.tx.cwnd() / rudp::kMaxPayload;

    const size_t   drops_before = r.path.fwd_drops();
    const uint32_t rtx_before   = r.tx.retransmits();
    r.run(std::chrono::seconds(1), true);

    std::printf("  %-30s %9u %9u %9zu %9u %9s\n", name, grown, resumed,
                r.path.fwd_drops() - drops_before, r.tx.retransmits() - rtx_before, "");
}

// ── tail ────────────────────────────────────────────────────────────────────

/// One message at a time, each one its own tail: the sender falls silent after
/// it, so a loss at the end produces no duplicate acknowledgement and no
/// selective ack — nothing but silence. Reported as a distribution because the
/// median is untouched by definition and the whole effect is in the tail.
void tail(const char* name, double rate, int rtt, double loss, int rounds, size_t bytes) {
    Rig r(rate, rtt, loss, 200);
    r.run(std::chrono::seconds(2), false);   // settle the handshake and the estimate

    std::vector<double> times;
    times.reserve(static_cast<size_t>(rounds));
    const std::string msg(bytes, 'q');

    for (int i = 0; i < rounds; ++i) {
        const auto   started = r.now;
        const size_t want    = r.delivered + msg.size();

        ByteView v(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        while (r.tx.write(&v, 1, r.now) == 0) r.run(ms(1), false);

        // A second is far past any recovery this transport can attempt, so a round
        // that reaches it did not recover at all — and shows up as the cap.
        const auto deadline = r.now + std::chrono::seconds(1);
        while (r.delivered < want && r.now < deadline) r.run(us(200), false);
        times.push_back(std::chrono::duration<double, std::milli>(r.now - started).count());
    }

    std::sort(times.begin(), times.end());
    const auto q = [&](double f) { return times[static_cast<size_t>(f * (times.size() - 1))]; };
    std::printf("  %-30s %9.1f %9.1f %9.1f %9.1f %9.1f\n",
                name, q(0.5), q(0.9), q(0.99), times.back(), q(0.99) - q(0.5));
}


// ── memory ──────────────────────────────────────────────────────────────────

/// What one connected pair actually holds, at three points in its life.
///
/// The idle figure in bench_transport answers a different question: it is
/// resident bytes per *node*, most of which is the mux's fixed batch staging
/// (~78 KiB, allocated once whatever the peer count). What is missing there is
/// the part that scales — a stream under load holds a retransmission queue on
/// one side and, once a hole opens, a reorder buffer on the other, and those are
/// what decide whether a thousand peers fit in memory.
///
/// Counted through the global allocator hook rather than resident-set size:
/// RSS moves in page-sized steps, includes allocator slack, and does not come
/// back when a buffer is freed — none of which is true of the numbers below.
void memory(const char* name, double rate, int rtt, size_t queue, size_t hole) {
    feed_buffer();    // allocated outside the measured region, not charged to it
    drain_buffer();
    track::reset();

    auto r = std::make_unique<Rig>(rate, rtt, 0.0, queue);
    r->run(std::chrono::seconds(2), false);
    const std::int64_t idle = track::snapshot().live;

    // Saturated, no loss: the retransmission queue and the send backlog are as
    // full as flow control lets them get.
    std::int64_t bulk_peak = idle;
    for (int i = 0; i < 60; ++i) {
        r->run(ms(50), true);
        bulk_peak = (std::max)(bulk_peak, track::snapshot().live);
    }

    // Now open a hole and keep feeding: everything behind it piles into the
    // receiver's reorder buffer while the sender holds it all for repair. This is
    // the worst case a single stream can reach without the peer being hostile.
    r->path.drop_next(hole);
    std::int64_t hole_peak = bulk_peak;
    for (int i = 0; i < 60; ++i) {
        r->run(ms(50), true);
        hole_peak = (std::max)(hole_peak, track::snapshot().live);
    }

    const auto kib = [](std::int64_t b) { return b / 1024.0; };
    std::printf("  %-30s %9.0f %9.0f %9.0f %9.0f %9s\n", name,
                kib(idle), kib(bulk_peak), kib(hole_peak),
                kib(hole_peak - idle), "");

    r.reset();   // freed inside the measured scope, so a leak would show as drift
    const std::int64_t after = track::snapshot().live;
    if (after > 4096)
        std::printf("  %-30s %s(%.0f KiB still held after teardown)%s\n", "",
                    col("\x1b[33m"), kib(after), col("\x1b[0m"));
}

// ── loss sweep ──────────────────────────────────────────────────────────────

/// One path, loss taken up until the transport stops coping. The interesting
/// number is not the throughput — Reno's response to loss is well known — but
/// where the curve turns into a cliff, and whether the connection survives it at
/// all: kMaxRetransmits gives up after twelve attempts on one packet.
void loss_row(double rate, int rtt, double loss, size_t queue, int secs) {
    Rig r(rate, rtt, loss, queue);
    r.run(std::chrono::seconds(secs), true);

    const double mbps = r.delivered * 8.0 / (secs * 1e6);
    char name[64];
    std::snprintf(name, sizeof(name), "%.1f%% loss", loss * 100);

    const bool  died  = r.tx.dead() || r.rx.dead();
    std::string state = died ? "died" : "alive";
    if (g_color) state = std::string(died ? "\x1b[31m" : "\x1b[32m") + state + "\x1b[0m";

    std::printf("  %-30s %9.2f %8.1f%% %9u %9u %9s\n", name, mbps,
                mbps / rate * 100, r.tx.retransmits(), r.tx.congestion_events(),
                state.c_str());
}

// ── compete ─────────────────────────────────────────────────────────────────

/// A flow's two addresses, placed on the path before either stream exists — the
/// dialer's constructor sends the Syn, which must already know its way.
struct FlowEnds {
    FlowEnds(Path& path, int index)
        : A{*IpAddress::parse("10.0.1." + std::to_string(index + 1)), 1111},
          B{*IpAddress::parse("10.0.2." + std::to_string(index + 1)), 2222} {
        path.place(A, false);
        path.place(B, true);
    }
    Address A, B;
};

/// One transfer of several sharing a bottleneck.
struct Flow : FlowEnds {
    Flow(Path& path, int index, CongestionAlgorithm algo, Clock::time_point now)
        : FlowEnds(path, index),
          tx(path, B, 10 + 2 * index, 11 + 2 * index, ConnRole::Outbound, now, DialProfile{}, algo),
          rx(path, A, 11 + 2 * index, 10 + 2 * index, ConnRole::Inbound, now, DialProfile{}, algo) {
        path.attach(A, &tx, false);
        path.attach(B, &rx, true);
    }
    UdpStream tx, rx;
    size_t    delivered = 0;
};

/// Two bulk flows through one bottleneck, the second joining after `join` s.
/// What each gets in the window after both are running — and Jain's fairness
/// index over the two, where 1.0 is an even split and 0.5 one flow taking it all.
void compete(const char* name, CongestionAlgorithm a, CongestionAlgorithm b, double rate,
             int rtt, size_t queue, int join, int secs) {
    Path path(Direction{rate * 1e6, us(rtt * 500), queue, 0.0, {}, {}, 0},
              Direction{rate * 1e6, us(rtt * 500), queue, 0.0, {}, {}, 0});
    Clock::time_point now{};
    Flow fa(path, 0, a, now);
    std::unique_ptr<Flow> fb;

    std::vector<uint8_t>& chunk = feed_buffer();
    std::vector<uint8_t>& sink  = drain_buffer();
    size_t base_a = 0, base_b = 0;
    constexpr auto kStep = us(200);
    const auto measure_from = std::chrono::seconds(join + 5);   // let the newcomer settle

    for (auto t = Clock::duration::zero(); t < std::chrono::seconds(secs); t += kStep) {
        now += kStep;
        if (!fb && t >= std::chrono::seconds(join)) fb = std::make_unique<Flow>(path, 1, b, now);
        if (t == measure_from) { base_a = fa.delivered; base_b = fb->delivered; }
        path.deliver_until(now);
        for (Flow* f : {&fa, fb.get()}) {
            if (!f) continue;
            for (int i = 0; i < 64; ++i) {
                ByteView v(chunk.data(), chunk.size());
                if (f->tx.write(&v, 1, now) == 0) break;
            }
            f->tx.tick(now);
            f->rx.tick(now);
            for (size_t n; (n = f->rx.read(sink.data(), sink.size())) != 0;) f->delivered += n;
        }
    }

    const double window = secs - std::chrono::duration<double>(measure_from).count();
    const double ma = (fa.delivered - base_a) * 8.0 / (window * 1e6);
    const double mb = (fb->delivered - base_b) * 8.0 / (window * 1e6);
    const double jain = (ma + mb) * (ma + mb) / (2 * (ma * ma + mb * mb));
    std::printf("  %-30s %9.2f %9.2f %8.1f%% %9.3f %9u\n", name, ma, mb,
                (ma + mb) / rate * 100, jain, fa.tx.retransmits() + fb->tx.retransmits());
}

// ── delay ───────────────────────────────────────────────────────────────────

/// What a bulk transfer does to everyone else on the path: the queueing delay it
/// keeps standing at the bottleneck, read off the sender's own round-trip samples
/// once it has settled. A loss-based controller fills whatever buffer there is;
/// this is the column a peer's interactive traffic actually waits in.
void delay(const char* name, double rate, int rtt, size_t queue, int secs) {
    Rig r(rate, rtt, 0.0, queue);
    r.run(std::chrono::seconds(5), true);   // past startup

    std::vector<double> samples;
    for (int i = 0; i < secs * 100; ++i) {
        r.run(ms(10), true);
        samples.push_back(std::chrono::duration<double, std::milli>(r.tx.rtt().latest).count() - rtt);
    }
    std::sort(samples.begin(), samples.end());
    const auto q = [&](double f) { return samples[static_cast<size_t>(f * (samples.size() - 1))]; };
    const double mbps = r.delivered * 8.0 / ((secs + 5) * 1e6);
    std::printf("  %-30s %9.1f %9.1f %9.1f %9.2f %9s\n", name, q(0.5), q(0.95), samples.back(),
                mbps, "");
}

} // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--no-color") == 0) g_color = false;
        if (std::strcmp(argv[i], "--cc=reno") == 0) g_algo = CongestionAlgorithm::Reno;
        if (std::strcmp(argv[i], "--cc=bbr") == 0)  g_algo = CongestionAlgorithm::Bbr;
    }
#ifndef _WIN32
    if (!isatty(1)) g_color = false;
#endif

    std::printf("%slibrats path suite — the datagram transport against a path that pushes back%s\n",
                col("\x1b[1m"), col("\x1b[0m"));
    std::printf("a model, not a network: drop-tail queue + serialiser + delay, in virtual time\n");
    std::printf("deterministic by construction — same build, same numbers; compare builds, not networks\n");
    std::printf("controller: %s%s%s (--cc=bbr | --cc=reno)\n", col("\x1b[1m"), to_string(g_algo),
                col("\x1b[0m"));

    heading("bulk — 20 s one way; buffer = 1 BDP unless the name says otherwise",
            "Mbit/s", "util", "retrans", "cwnd cuts", "dropped");
    bulk("10 Mbit,  20 ms",              10,  20, 0.0,    21, 20);
    bulk("10 Mbit, 100 ms",              10, 100, 0.0,   104, 20);
    bulk("50 Mbit,  50 ms",              50,  50, 0.0,   260, 20);
    bulk("100 Mbit, 100 ms",            100, 100, 0.0,  1041, 20);
    bulk("100 Mbit,  10 ms",            100,  10, 0.0,   104, 20);
    bulk("1 Gbit,     1 ms",           1000,   1, 0.0,   104, 20);
    bulk("10 Mbit, 100 ms, buffer 0.1", 10, 100, 0.0,     10, 20);
    bulk("10 Mbit, 100 ms, buffer 4",   10, 100, 0.0,    416, 20);
    bulk("10 Mbit, 100 ms, 0.1% loss",  10, 100, 0.001,  104, 20);
    bulk("10 Mbit, 100 ms, 1% loss",    10, 100, 0.01,   104, 20);
    std::printf("  (a low utilisation with FEW reductions is a sender that never found the "
                "path;\n   a low one with MANY is a sender that keeps losing it. The two want "
                "opposite fixes.)\n");

    heading("idle — 5 s of transfer, 10 s of silence, then transfer again",
            "cwnd grown", "on resume", "dropped", "retrans", "");
    idle("50 Mbit,  50 ms",  50,  50, 260, 5, 10);
    idle("10 Mbit, 100 ms",  10, 100, 104, 5, 10);
    idle("100 Mbit, 10 ms", 100,  10, 104, 5, 10);
    std::printf("  (cwnd is in packets. A window that survives the silence unchanged is a "
                "window\n   nobody validated — the burst behind it goes out on ten-second-old "
                "information.)\n");

    heading("loss — 10 Mbit, 100 ms, 1 BDP buffer; loss taken until it breaks",
            "Mbit/s", "util", "retrans", "cwnd cuts", "state");
    for (double l : {0.0, 0.005, 0.01, 0.02, 0.05, 0.10, 0.20, 0.30})
        loss_row(10, 100, l, 104, 20);
    std::printf("  (loss here is applied to BOTH directions, so an acknowledgement is as\n"
                "   likely to go missing as the data it acknowledges. \"died\" means the peer\n"
                "   was declared gone — twelve attempts on one packet with nothing back.)\n");

    heading("memory — what one connected pair holds (KiB, via the allocator)",
            "idle", "bulk peak", "hole peak", "growth", "");
    memory("10 Mbit, 100 ms, hole of 24",  10, 100, 104,  24);
    memory("50 Mbit,  50 ms, hole of 24",  50,  50, 260,  24);
    memory("100 Mbit, 100 ms, hole of 64",100, 100, 1041, 64);
    std::printf("  (both ends, so this is a pair rather than a peer — and the two halves are\n"
                "   not alike: the sender holds the retransmission queue, the receiver the\n"
                "   reorder buffer. What dominates is neither: it is UdpStream::kSendQueueLimit,\n"
                "   2 MiB of accepted-but-unsent application data, which is why the hole often\n"
                "   adds nothing to a peak the send queue had already set.)\n");

    heading("delay — standing queue a bulk transfer keeps (ms over the base RTT)",
            "median", "p95", "max", "Mbit/s", "");
    delay("10 Mbit,  50 ms, buffer 4",     10,  50,  208, 15);
    delay("50 Mbit,  20 ms, buffer 4",     50,  20,  416, 15);
    delay("10 Mbit, 100 ms, buffer 1",     10, 100,  104, 15);
    std::printf("  (what any other message to the same peer — or through the same home router —\n"
                "   waits behind while the transfer runs. A loss-based sender parks at the full\n"
                "   buffer; a model-based one near zero.)\n");

    heading("compete — two flows, 20 Mbit, 40 ms, 1 BDP; the second joins at 5 s, 40 s",
            "flow A", "flow B", "util", "Jain", "retrans");
    compete("bbr  vs bbr",  CongestionAlgorithm::Bbr,  CongestionAlgorithm::Bbr,  20, 40, 83, 5, 40);
    compete("reno vs reno", CongestionAlgorithm::Reno, CongestionAlgorithm::Reno, 20, 40, 83, 5, 40);
    compete("bbr  vs reno", CongestionAlgorithm::Bbr,  CongestionAlgorithm::Reno, 20, 40, 83, 5, 40);
    compete("reno vs bbr",  CongestionAlgorithm::Reno, CongestionAlgorithm::Bbr,  20, 40, 83, 5, 40);
    compete("bbr  vs reno, buffer 4", CongestionAlgorithm::Bbr, CongestionAlgorithm::Reno,
            20, 40, 333, 5, 40);
    compete("bbr  vs bbr,  buffer 2", CongestionAlgorithm::Bbr, CongestionAlgorithm::Bbr,
            20, 40, 166, 5, 40);
    compete("bbr  vs bbr,  buffer 4", CongestionAlgorithm::Bbr, CongestionAlgorithm::Bbr,
            20, 40, 333, 5, 40);
    std::printf("  (Mbit/s over the last 30 s, once both are running. Fixed per row, whatever\n"
                "   --cc says. Jain's index: 1.0 an even split, 0.5 one flow starving the other.\n"
                "   BBR against Reno is expected to be roughly even in a 1 BDP buffer and to give\n"
                "   ground in a deep one, where Reno's standing queue inflates the BDP BBR sees.)\n");

    heading("tail — request/response, delivery time in ms",
            "median", "p90", "p99", "max", "p99-med");
    tail("64 B,   100 Mbit, 10 ms, 2%",  100,  10, 0.02, 300, 64);
    tail("64 B,   100 Mbit, 10 ms, 5%",  100,  10, 0.05, 300, 64);
    tail("64 B,   50 Mbit,  50 ms, 2%",   50,  50, 0.02, 300, 64);
    tail("64 B,   10 Mbit, 100 ms, 2%",   10, 100, 0.02, 300, 64);
    tail("24 KB,  100 Mbit, 10 ms, 2%",  100,  10, 0.02, 300, 24 * 1024);
    tail("24 KB,  100 Mbit, 10 ms, 5%",  100,  10, 0.05, 300, 24 * 1024);
    tail("24 KB,  50 Mbit,  50 ms, 2%",   50,  50, 0.02, 300, 24 * 1024);
    tail("24 KB,  10 Mbit, 100 ms, 2%",   10, 100, 0.02, 200, 24 * 1024);
    std::printf("  (the 24 KB rows are the ones that separate probing the LAST unacknowledged\n"
                "   packet from probing the first: with one packet in flight they are the same\n"
                "   packet. A max at 1000.0 means the round never recovered inside the cap.)\n");

    std::printf("\nnote: no reordering, no ack compression, no competing traffic, no variable\n"
                "delay. These are not predictions about a real network — they are a comparison\n"
                "between builds, and only useful read that way. For \"does it survive a hostile\n"
                "network at all\", put tools/badnet.sh in front of bench_transport instead.\n");
    return 0;
}
