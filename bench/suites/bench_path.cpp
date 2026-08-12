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

bool g_color = true;
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

class Path : public UdpStreamHost {
public:
    Path(Direction fwd, Direction rev, Address a, Address b)
        : fwd_(fwd), rev_(rev), a_(a), b_(b), rng_(12345) {}

    void attach(const Address& addr, UdpStream* s) { (addr == a_ ? sa_ : sb_) = s; }

    void send_datagram(const Address& to, const uint8_t* data, size_t len) override {
        Direction& d = (to == b_) ? fwd_ : rev_;

        const auto serial     = us(static_cast<long long>((len + 28) * 8 * 1e6 / d.rate_bps));
        const auto pkt_serial = us(static_cast<long long>((1200 + 28) * 8 * 1e6 / d.rate_bps));
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
                if (UdpStream* s = (f.to == a_) ? sa_ : sb_) s->on_packet(p, now);
            }
        }
    }

    /// Swallow the next `n` packets travelling towards the receiver.
    void   drop_next(size_t n) { drop_burst_ = n; }
    size_t drops()     const { return fwd_.drops + rev_.drops; }
    size_t fwd_drops() const { return fwd_.drops; }

private:
    Direction  fwd_, rev_;
    Address    a_, b_;
    UdpStream* sa_ = nullptr;
    UdpStream* sb_ = nullptr;
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
        : path(Direction{rate_mbps * 1e6, ms(rtt_ms / 2), queue, loss, {}, {}, 0},
               Direction{rate_mbps * 1e6, ms(rtt_ms / 2), queue, loss, {}, {}, 0},
               Address{*IpAddress::parse("10.0.0.1"), 1111},
               Address{*IpAddress::parse("10.0.0.2"), 2222}),
          tx(path, Address{*IpAddress::parse("10.0.0.2"), 2222}, 1, 2, ConnRole::Outbound, {}),
          rx(path, Address{*IpAddress::parse("10.0.0.1"), 1111}, 2, 1, ConnRole::Inbound, {}) {
        path.attach(A, &tx);
        path.attach(B, &rx);
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
                r.tx.retransmits(), r.tx.window_reductions(), r.path.drops());
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
                mbps / rate * 100, r.tx.retransmits(), r.tx.window_reductions(),
                state.c_str());
}

} // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--no-color") == 0) g_color = false;
#ifndef _WIN32
    if (!isatty(1)) g_color = false;
#endif

    std::printf("%slibrats path suite — the datagram transport against a path that pushes back%s\n",
                col("\x1b[1m"), col("\x1b[0m"));
    std::printf("a model, not a network: drop-tail queue + serialiser + delay, in virtual time\n");
    std::printf("deterministic by construction — same build, same numbers; compare builds, not networks\n");

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
