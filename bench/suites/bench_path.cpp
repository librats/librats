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
// So this suite does not use a network at all. A UdpConnection never reads the
// clock itself — every entry point takes `now` — which makes the whole congestion
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
//   realtime — live video, one message a frame: frame latency, the share of
//            frames that miss an interactive deadline, freezes, and how long the
//            stream takes to be back on time after an outage or a capacity
//            change, with a fixed-rate source and with one that retargets
//            itself from PathStats, under random and bursty loss, competing
//            traffic and video coming back the other way; then the same
//            against source shapes — keyframe size, intra refresh, noisy
//            frames, a slow rate control, temporal layers — since how an
//            encoder spreads its rate is all a codec changes for the path.
//            Every frame is a live message (SendOptions::lifetime), dropped
//            when it cannot make the player's deadline; `--reliable-video`
//            sends them reliably instead, `--no-fec` without repair symbols.
//            `--realtime` runs only this section.
//
// ── Reading the numbers ─────────────────────────────────────────────────────
//
// Everything here is deterministic: same binary, same numbers, every time. That
// is the point — it makes small regressions visible, which no real path does.
// But a row with random loss is ONE draw of it, and a change that alters the
// packet count reshuffles which packets die: compare such rows over many seeds
// (RATS_SEED=1..N in the environment), never one.
// The flip side is that a model is only ever as good as what it models: there is
// no reordering, no ack compression, no competing traffic and no variable delay,
// so these figures are not predictions of what a real network will give. They
// are a *comparison* — this build against that one — and should be read only
// that way. (The realtime section can add loss bursts, an outage and a link
// whose rate changes on a schedule; still deterministic, still a model.)
//
// Build:  cmake -S bench -B bench/build && cmake --build bench/build --target bench_path

#include "framework/alloc_track.h"

#include "librats/security/plaintext_security.h"
#include "librats/transport/udp_connection.h"
#include "librats/transport/udp_wire.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <deque>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <random>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h>   // isatty
#endif

using namespace librats;

namespace {

using Clock = UdpConnection::Clock;
using ms    = std::chrono::milliseconds;
using us    = std::chrono::microseconds;
using ns    = std::chrono::nanoseconds;

bool g_color = true;
/// The controller every Rig in the current pass runs.
CongestionAlgorithm g_algo = CongestionAlgorithm::Bbr;
/// The realtime section sends each frame reliably, on its lane, instead of as a
/// live message — what every build before live messages did (--reliable-video).
bool g_reliable_video = false;
/// Live messages carry repair symbols on a lossy path (--no-fec: they do not).
bool g_fec = true;
const char* col(const char* code) { return g_color ? code : ""; }

// ── The path ────────────────────────────────────────────────────────────────

struct InFlight {
    Clock::time_point arrive;
    Address           to, from;
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

    /// Mean length of a loss burst. When set, `loss` is no longer drawn packet by
    /// packet: the direction alternates between clear spells and bursts that
    /// lose everything, both of exponentially distributed length, in proportion
    /// to give `loss` overall (a Gilbert-Elliott channel in time). That is the
    /// shape of loss on Wi-Fi and cellular links, where one fade or collision
    /// takes out a run of packets, not one. It runs on time rather than on
    /// packets on purpose: a burst is a property of the radio, and a sender that
    /// backs off must not thereby stretch it.
    Clock::duration   burst{};
    bool              in_burst = false;
    Clock::time_point burst_flip{};    ///< when the current spell ends
};

class Path;

/// One end of a connection on the model: the host a UdpConnection runs on, a
/// responder that accepts the first Initial it is sent, and the few questions the
/// rows below ask of either side.
///
/// Both ends run the plaintext handshake: the model is about packets, and the
/// rows are comparable with each other and across builds whatever the cipher
/// costs (bench_crypto measures that).
class Peer final : public UdpConnectionHost {
public:
    Peer(Path& path, const Address& addr, CongestionAlgorithm algo)
        : path_(path), addr_(addr), security_(Identity::generate()) {
        config_.congestion = algo;
        config_.live_fec   = g_fec;
    }

    const Address& addr() const noexcept { return addr_; }

    void dial(const Address& to, udp::Cid cid, Clock::time_point now) {
        conn_ = UdpConnection::dial(*this, security_, to, cid, now, config_);
    }

    void receive(uint8_t* data, size_t len, const Address& from, Clock::time_point now) {
        if (conn_) {
            conn_->on_datagram(data, len, from, now);
            return;
        }
        udp::LongPacket p;
        if (!udp::decode_long(data, len, p) || p.type != udp::LongType::Initial) return;
        conn_ = UdpConnection::accept(*this, security_, from, p, len, false, now, config_);
        if (conn_) conn_->answer(now);
    }

    /// Queue one message of `bytes` on `type`'s lane if the connection is kept no
    /// fuller than the old byte stream kept itself — 2 MiB, or twice the window
    /// above that — and let it send. The bytes taken: the message or nothing.
    size_t write(size_t bytes, Clock::time_point now, MessageType type = MessageType::App) {
        if (!conn_ || !conn_->established()) return 0;
        const size_t limit = (std::max)(size_t{2} << 20, 2 * size_t{conn_->recovery().cwnd()});
        if (conn_->queued_bytes() >= limit) return 0;
        static const std::vector<uint8_t> payload(1 << 20, 0xAB);
        bytes = (std::min)(bytes, payload.size());
        if (!conn_->send_message(FrameHeader{type, 0, 0}, ByteView(payload.data(), bytes))) return 0;
        conn_->flush(now);
        return bytes;
    }

    /// The channel live messages are sent on, so the far end can tell them apart.
    static constexpr uint16_t kLiveChannel = 1;

    /// Queue one live message of `bytes`, worth delivering until `deadline`, whose
    /// first four bytes are `tag` — delivery is in no order and not certain, so the
    /// far end needs to know which one it got. Taken unless it is larger than a
    /// live message may be (SendOptions::kMaxLivePayload), as the API refuses it.
    bool write_live(size_t bytes, uint32_t tag, Clock::time_point deadline, Clock::time_point now) {
        if (!conn_ || !conn_->established()) return false;
        static std::vector<uint8_t> payload(SendOptions::kMaxLivePayload, 0xAB);
        if (bytes > payload.size()) return false;
        bytes = (std::max)(sizeof(tag), bytes);
        std::memcpy(payload.data(), &tag, sizeof(tag));
        if (!conn_->send_live(FrameHeader{MessageType::App, 0, kLiveChannel},
                              ByteView(payload.data(), bytes), deadline))
            return false;
        conn_->flush(now);
        return true;
    }

    void tick(Clock::time_point now) {
        if (!conn_) return;
        const auto due = conn_->next_deadline();
        if (due && *due <= now) conn_->tick(now);
        conn_->deliver(now, [&](const Frame& f) {
            if (f.header.type == MessageType::App && f.header.channel == kLiveChannel) {
                uint32_t tag = 0;
                std::memcpy(&tag, f.payload.data(), sizeof(tag));
                live_arrivals.push_back(tag);
            } else if (f.header.type == MessageType::App) {
                ++app_messages;
            }
            delivered += f.payload.size();
            return true;
        });
    }

    UdpConnection* conn() noexcept { return conn_.get(); }
    bool     dead() const noexcept { return conn_ && conn_->dead(); }
    uint32_t cwnd() const noexcept { return conn_ ? conn_->recovery().cwnd() : 0; }
    uint32_t retransmits() const noexcept { return conn_ ? conn_->recovery().retransmits() : 0; }
    uint32_t congestion_events() const noexcept { return conn_ ? conn_->recovery().congestion_events() : 0; }
    const cc::RttEstimate& rtt() const noexcept { return conn_->recovery().rtt(); }
    const cc::CongestionController& congestion() const noexcept { return conn_->recovery().congestion(); }
    PathStats path_stats() const noexcept { return conn_ ? conn_->path_stats() : PathStats{}; }

    // — UdpConnectionHost —
    uint8_t* datagram_buffer() override { return buf_.data(); }
    void     send_datagram(const Address& to, size_t len) override;
    void     connection_events(UdpConnection&, uint32_t) override {}
    void     reset_token(udp::Cid cid, uint8_t* out) override {
        std::memset(out, 0, udp::kResetTokenSize);
        std::memcpy(out, &cid, sizeof(cid));
    }

    uint64_t delivered    = 0;   ///< payload bytes of every message handed over
    uint64_t app_messages = 0;   ///< reliable App messages handed over
    std::vector<uint32_t> live_arrivals;   ///< tags of live messages handed over, not yet looked at

private:
    Path&                                  path_;
    Address                                addr_;
    PlaintextSecurity                      security_;
    UdpConnectionConfig                    config_;
    std::unique_ptr<UdpConnection>         conn_;
    std::array<uint8_t, udp::kMaxDatagram> buf_{};
};

/// Any number of sender/receiver pairs sharing one bottleneck: everything
/// addressed to a receiver queues in the forward direction, everything addressed
/// to a sender in the reverse one.
class Path {
public:
    /// RATS_SEED in the environment changes the loss draws: one seed is one
    /// sample, and a loss row only says something over many of them.
    Path(Direction fwd, Direction rev) : fwd_(fwd), rev_(rev), rng_(seed()) {}

    /// Say which side of the path `peer` is on, before it sends anything.
    void place(Peer* peer, bool receiver) { ends_.push_back(End{peer, receiver}); }

    void send_datagram(const Address& sender, const Address& to, const uint8_t* data, size_t len) {
        const Address from = outside(sender, now_);
        const End* end = find(to, now_);
        Direction& d = (end && end->receiver) ? fwd_ : rev_;

        // Nanoseconds, not microseconds: at a gigabit a full packet serialises in
        // ~10 us, and truncating that makes the link a tenth faster than it says.
        const auto serial     = ns(static_cast<long long>((len + 28) * 8 * 1e9 / d.rate_bps));
        const auto pkt_serial = ns(static_cast<long long>((udp::kMaxDatagram + 28) * 8 * 1e9 / d.rate_bps));
        const auto backlog    = d.busy_until > now_ ? (d.busy_until - now_)
                                                    : Clock::duration::zero();

        if (dark(now_)) { ++d.drops; return; }
        if (backlog > pkt_serial * static_cast<long long>(d.queue_pkts)) { ++d.drops; return; }
        // A deliberate, deterministic hole — used by the memory section, where a
        // random one would make the figure differ from run to run.
        if (&d == &fwd_ && drop_burst_ > 0) { --drop_burst_; ++d.drops; return; }
        if (d.loss > 0 && d.burst > Clock::duration::zero()) {
            // A clear spell lasts burst * (1 - loss) / loss on average, so the
            // share of time spent in bursts — and of packets lost — is `loss`.
            while (d.burst_flip <= now_) {
                if (d.burst_flip != Clock::time_point{}) d.in_burst = !d.in_burst;
                const double mean = d.in_burst ? 1.0 : (1 - d.loss) / d.loss;
                d.burst_flip = (std::max)(d.burst_flip, Clock::time_point{} + ns(1)) +
                    std::chrono::duration_cast<Clock::duration>(d.burst * (-std::log(1 - unit_(rng_)) * mean));
            }
            if (d.in_burst) { ++d.drops; return; }
        } else if (d.loss > 0 && unit_(rng_) < d.loss) { ++d.drops; return; }

        d.busy_until = (std::max)(now_, d.busy_until) + serial;
        Clock::time_point arrive = d.busy_until + d.delay;
        if (late_.share == 0) {
            d.wire.push_back(InFlight{arrive, to, from, Bytes(data, data + len)});
            return;
        }
        if (late_.scattered)                arrive += std::chrono::duration_cast<Clock::duration>(late_.by * unit_(rng_));
        else if (unit_(rng_) < late_.share) arrive += late_.by;
        if (!late_.reorders && !d.wire.empty()) arrive = (std::max)(arrive, d.wire.back().arrive);
        // In arrival order: one held back is overtaken by those behind it.
        auto at = d.wire.end();
        while (at != d.wire.begin() && std::prev(at)->arrive > arrive) --at;
        d.wire.insert(at, InFlight{arrive, to, from, Bytes(data, data + len)});
    }

    /// Advance the model to `now`, delivering everything that has arrived.
    void deliver_until(Clock::time_point now) {
        now_ = now;
        for (Direction* d : {&fwd_, &rev_}) {
            while (!d->wire.empty() && d->wire.front().arrive <= now) {
                InFlight f = std::move(d->wire.front());
                d->wire.pop_front();
                if (dark(f.arrive)) { ++d->drops; continue; }
                if (const End* end = find(f.to, f.arrive)) end->peer->receive(f.bytes.data(), f.bytes.size(), f.from, now);
            }
        }
    }

    void set_now(Clock::time_point now) { now_ = now; }
    /// Swallow the next `n` packets travelling towards the receiver.
    void   drop_next(size_t n) { drop_burst_ = n; }
    /// Change the link rate both ways from now on — a path that loses capacity
    /// mid-transfer (a Wi-Fi rate step, a cross-traffic burst upstream). The queue
    /// keeps its depth in packets, so it now holds proportionally more time.
    void   set_rate(double bps) { fwd_.rate_bps = rev_.rate_bps = bps; }
    /// Let nothing through either way over [from, to): neither what is sent then
    /// nor what was due to land then. A link that goes dark — a Wi-Fi roam, a
    /// cellular handover — loses what it was carrying.
    void   set_outage(Clock::time_point from, Clock::time_point to) { dark_from_ = from; dark_to_ = to; }
    /// From `at` on, `inside` is seen at `outside`: what it sends leaves from
    /// there, only what is sent there reaches it, and what still goes to where it
    /// was is lost — a NAT's new mapping, or with another IP, another network.
    void   move(const Address& inside, const Address& outside, Clock::time_point at) {
        move_from_ = inside;
        move_to_   = outside;
        move_at_   = at;
    }
    /// Hold back a `share` of the datagrams, both ways, `by` past their turn — not
    /// in the queue, which they leave on time: a radio's retries, a host's late
    /// timer. One held back holds back those behind it too, as a Wi-Fi receiver's
    /// block-ack window does — delay without reordering — unless `reorders`, when
    /// those behind overtake it.
    void   hold_back(double share, Clock::duration by, bool reorders) { late_ = Late{share, by, reorders, false}; }
    /// Delay every datagram, both ways, by its own draw from [0, `up_to`]: a path
    /// whose packets do not keep to one queue — per-packet jitter, a bonded link —
    /// so they overtake one another all the time.
    void   scatter(Clock::duration up_to) { late_ = Late{1, up_to, true, true}; }
    size_t drops()     const { return fwd_.drops + rev_.drops; }
    size_t fwd_drops() const { return fwd_.drops; }

private:
    static unsigned seed() {
        const char* env = std::getenv("RATS_SEED");
        return env ? static_cast<unsigned>(std::strtoul(env, nullptr, 10)) : 12345u;
    }

    struct End {
        Peer* peer;
        bool  receiver;
    };
    bool dark(Clock::time_point t) const { return t >= dark_from_ && t < dark_to_; }
    Address outside(const Address& inside, Clock::time_point t) const {
        return move_at_ != Clock::time_point{} && t >= move_at_ && inside == move_from_ ? move_to_ : inside;
    }
    /// The end reached at `a` at `t`.
    const End* find(const Address& a, Clock::time_point t) const {
        for (const End& e : ends_) if (outside(e.peer->addr(), t) == a) return &e;
        return nullptr;
    }

    Direction        fwd_, rev_;
    std::vector<End> ends_;
    Clock::time_point now_{};
    Clock::time_point dark_from_{}, dark_to_{};
    Address           move_from_, move_to_;
    Clock::time_point move_at_{};
    size_t       drop_burst_ = 0;
    struct Late {
        double          share = 0;
        Clock::duration by{};
        bool            reorders = false;
        bool            scattered = false;   ///< every datagram late by a draw from [0, by]
    };
    Late         late_;
    std::mt19937 rng_;
    std::uniform_real_distribution<double> unit_{0.0, 1.0};
};

void Peer::send_datagram(const Address& to, size_t len) { path_.send_datagram(addr_, to, buf_.data(), len); }

/// Scratch the feeder writes from and the drain reads into. Shared and allocated
/// once, deliberately: a per-Rig buffer would be charged to whichever scenario
/// happened to build the Rig, and the memory section would be measuring the
/// benchmark's own scaffolding rather than the transport.
constexpr size_t kScratch = 64 * 1024;
std::vector<uint8_t>& feed_buffer() {
    static std::vector<uint8_t> v(kScratch, 0xAB);
    return v;
}

/// A connected pair on a virtual clock, with the model between them.
struct Rig {
    Address A{*IpAddress::parse("10.0.0.1"), 1111};
    Address B{*IpAddress::parse("10.0.0.2"), 2222};
    Path    path;
    Clock::time_point now{};
    Peer    tx, rx;
    size_t  chunk = feed_buffer().size();

    Rig(double rate_mbps, int rtt_ms, double loss, size_t queue)
        : path(Direction{rate_mbps * 1e6, us(rtt_ms * 500), queue, loss, {}, {}, 0},
               Direction{rate_mbps * 1e6, us(rtt_ms * 500), queue, loss, {}, {}, 0}),
          tx(path, A, g_algo), rx(path, B, g_algo) {
        path.place(&tx, false);
        path.place(&rx, true);
        tx.dial(B, 0x10, now);
    }

    uint64_t delivered() const { return rx.delivered; }

    /// Step the model forward by `d`, offering the sender as much as it will take
    /// when `feed` is set. The step is well under any timer the connection arms,
    /// so nothing is resolved coarser than the transport itself would resolve it.
    void run(Clock::duration d, bool feed) {
        constexpr auto kStep = us(200);
        const auto end = now + d;
        while (now < end) {
            now += kStep;
            path.deliver_until(now);
            if (feed)
                for (int i = 0; i < 64; ++i)
                    if (tx.write(chunk, now) == 0) break;
            tx.tick(now);
            rx.tick(now);
        }
    }
};

// ── Reporting ───────────────────────────────────────────────────────────────

void heading(const char* title, std::initializer_list<const char*> cols) {
    std::printf("\n%s%s%s\n", col("\x1b[1m"), title, col("\x1b[0m"));
    std::printf("  %-30s", "");
    for (const char* c : cols) std::printf(" %9s", c);
    std::printf("\n  %-30s", "------------------------------");
    for (size_t i = 0; i < cols.size(); ++i) std::printf(" %9s", "---------");
    std::printf("\n");
}
void heading(const char* title, const char* c1, const char* c2,
             const char* c3, const char* c4, const char* c5) {
    heading(title, {c1, c2, c3, c4, c5});
}

// ── bulk ────────────────────────────────────────────────────────────────────

/// `overtaken`: a share of the datagrams, both ways, 8 ms late and overtaken by
/// those behind them — a path that reorders without losing anything.
void bulk(const char* name, double rate, int rtt, double loss, size_t queue, int secs,
          double overtaken = 0) {
    Rig r(rate, rtt, loss, queue);
    if (overtaken > 0) r.path.hold_back(overtaken, std::chrono::milliseconds(8), true);
    r.run(std::chrono::seconds(secs), true);

    const double mbps = r.delivered() * 8.0 / (secs * 1e6);
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
    const uint32_t grown = r.tx.cwnd() / cc::kMss;

    r.run(std::chrono::seconds(quiet), false);
    const uint32_t resumed = r.tx.cwnd() / cc::kMss;

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
        const size_t want    = r.delivered() + msg.size();

        while (r.tx.write(msg.size(), r.now) == 0) r.run(ms(1), false);

        // A second is far past any recovery this transport can attempt, so a round
        // that reaches it did not recover at all — and shows up as the cap.
        const auto deadline = r.now + std::chrono::seconds(1);
        while (r.delivered() < want && r.now < deadline) r.run(us(200), false);
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

    const double mbps = r.delivered() * 8.0 / (secs * 1e6);
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

/// One transfer of several sharing a bottleneck. A `reverse` flow sends against
/// the path's forward direction: its data rides the other flows' acknowledgement
/// queue and its acknowledgements their data's.
struct Flow {
    Flow(Path& path, int index, CongestionAlgorithm algo, Clock::time_point now, bool reverse = false)
        : tx(path, Address{*IpAddress::parse("10.0.1." + std::to_string(index + 1)), 1111}, algo),
          rx(path, Address{*IpAddress::parse("10.0.2." + std::to_string(index + 1)), 2222}, algo) {
        path.place(&tx, reverse);
        path.place(&rx, !reverse);
        path.set_now(now);
        tx.dial(rx.addr(), 0x100 + 0x10 * static_cast<udp::Cid>(index), now);
    }
    Peer tx, rx;
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

    const size_t chunk = feed_buffer().size();
    size_t base_a = 0, base_b = 0;
    constexpr auto kStep = us(200);
    const auto measure_from = std::chrono::seconds(join + 5);   // let the newcomer settle

    for (auto t = Clock::duration::zero(); t < std::chrono::seconds(secs); t += kStep) {
        now += kStep;
        if (!fb && t >= std::chrono::seconds(join)) fb = std::make_unique<Flow>(path, 1, b, now);
        if (t == measure_from) { base_a = fa.rx.delivered; base_b = fb->rx.delivered; }
        path.deliver_until(now);
        for (Flow* f : {&fa, fb.get()}) {
            if (!f) continue;
            for (int i = 0; i < 64; ++i)
                if (f->tx.write(chunk, now) == 0) break;
            f->tx.tick(now);
            f->rx.tick(now);
        }
    }

    const double window = secs - std::chrono::duration<double>(measure_from).count();
    const double ma = (fa.rx.delivered - base_a) * 8.0 / (window * 1e6);
    const double mb = (fb->rx.delivered - base_b) * 8.0 / (window * 1e6);
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
    const double mbps = r.delivered() * 8.0 / ((secs + 5) * 1e6);
    std::printf("  %-30s %9.1f %9.1f %9.1f %9.2f %9s\n", name, q(0.5), q(0.95), samples.back(),
                mbps, "");
}

// ── realtime ────────────────────────────────────────────────────────────────

/// What a live video source puts next to the transport.
enum class Source {
    Fixed,      ///< encodes at its configured rate whatever the path does
    Adaptive,   ///< retargets its encoder from the stream's PathStats every 100 ms
};
/// What else the path is doing while the video runs. Every event starts at 10 s.
enum class Besides {
    Nothing,
    PathBulk,     ///< another peer's bulk transfer through the same bottleneck
    StreamBulk,   ///< a file to the SAME peer, on its own lane of the same connection
    Duplex,       ///< the far end sends the same video back: a call, not a broadcast
    RateDrop,     ///< the link loses 70% of its capacity
    RateRise,     ///< the link starts at 30% of its capacity and gets it all back
    RateSwing,    ///< the capacity swings between full and 30% every 2 s, as a cell's does
    Outage,       ///< nothing gets through either way for a while — a roam, a handover
    Rebind,       ///< the receiver's NAT gives it a new port
    Roam,         ///< the receiver moves to another network: a new IP, after an outage
};

/// The shape of what an encoder emits — which is all of a codec the transport
/// ever sees. AV1 and H.264 differ in how good a picture a given rate buys, not
/// in anything a path reacts to; what a path reacts to is how the rate is spread
/// over frames, and that is set by the encoder's configuration far more than by
/// its codec. These are the properties that move the numbers:
struct Profile {
    const char* name;
    double key_weight;   ///< keyframe size over a mean frame, one per GOP; 0 = none (intra refresh)
    double noise;        ///< every frame scaled by a factor uniform in [1 - noise, 1 + noise]
    int    scene_every;  ///< mean frames between scene cuts, a frame four times its budget; 0 = none
    double lag_s;        ///< time constant with which output follows a new target; 0 = at once
    int    layers;       ///< temporal layers: 1, or 3 (L1T3: T0 T2 T1 T2, T0 frames twice the rest)
};
/// Steady frames and a keyframe five times their size every two seconds: the
/// simplest shape that still has the one burst every codec with GOPs produces.
constexpr Profile kSteady{"5x keyframe, steady", 5, 0, 0, 0, 1};

/// One realtime run's conditions. The defaults are the reference row: a fixed
/// 4 Mbit/s source over 10 Mbit/s and 40 ms, a 1 BDP buffer, nothing lost.
struct Scene {
    double  link = 10;          ///< Mbit/s
    int     rtt = 40;           ///< ms
    double  loss = 0;           ///< mean share of packets lost, both ways
    int     burst_ms = 0;       ///< mean loss burst; 0 = every loss independent
    double  buffer_bdp = 1;
    double  video = 4;          ///< Mbit/s: the rate, or for Adaptive the ceiling
    Source  source = Source::Fixed;
    Besides besides = Besides::Nothing;
    int     outage_ms = 0;
    Profile profile = kSteady;
    int     fps = 30;               ///< a keyframe every 2 s whatever the rate
    double  late = 0;               ///< share of datagrams held back late_ms, both ways
    int     late_ms = 0;
    bool    late_reorders = false;  ///< overtaken by those behind, or holding them back too
    bool    late_scattered = false; ///< every datagram late by its own draw from [0, late_ms]

    Scene& round_trip(int ms) { rtt = ms; return *this; }
    Scene& over(double mbps, int ms) { link = mbps; rtt = ms; return *this; }
    Scene& sending(double mbps, int frames_per_s) { video = mbps; fps = frames_per_s; return *this; }
    Scene& jittery(double share, int ms, bool reorder = false) {
        late = share; late_ms = ms; late_reorders = reorder; return *this;
    }
    Scene& scattered(int ms) { late = 1; late_ms = ms; late_reorders = late_scattered = true; return *this; }
    Scene& lossy(double share, int burst = 0) { loss = share; burst_ms = burst; return *this; }
    Scene& buffer(double bdp) { buffer_bdp = bdp; return *this; }
    Scene& adaptive(double ceiling = 8) { source = Source::Adaptive; video = ceiling; return *this; }
    Scene& with(Besides b) { besides = b; return *this; }
    Scene& outage(int ms) { besides = Besides::Outage; outage_ms = ms; return *this; }
    Scene& roam(int ms) { besides = Besides::Roam; outage_ms = ms; return *this; }
    Scene& shaped(const Profile& p) { profile = p; return *this; }

    /// An event that ends, so a recovery from it can be timed. A swing never
    /// ends; the rows without an event have nothing to recover from.
    bool has_event() const {
        return besides == Besides::RateDrop || besides == Besides::RateRise ||
               besides == Besides::Outage || besides == Besides::Rebind || besides == Besides::Roam;
    }
};

/// What one realtime run measured.
struct RealtimeResult {
    double median, p99;     ///< frame latency over the one-way delay, ms
    double late;            ///< % of frames past the deadline, or never there
    double dropped;         ///< % of frames that never arrived
    double freeze_max;      ///< longest the picture stood still, ms
    double frozen;          ///< all the time it stood still, s
    double recover;         ///< ms from the event's end to a second of on-time frames; <0 no event, inf never
    double video;           ///< Mbit/s the encoder produced
    double fec;             ///< repair symbols sent, % of the video
    double key_median;      ///< keyframe latency over the one-way delay, ms, of those that arrived; <0 none did
    double resent;          ///< packets sent again, % of the packets sent
};

/// One live source and the player at the far end of its connection: the scene's
/// frames a second (30 unless it says otherwise), each sent as one message the
/// moment it is captured, sized by the scene's profile, with a GOP of 2 s. A
/// frame is complete once its message has been delivered.
///
/// Each frame is a live message whose deadline is the player's: captured + the
/// one-way delay (half the minimum round trip the connection has measured, which
/// is what any application can know) + 100 ms. One that cannot make it is dropped
/// by the transport rather than delivered late, and frames arrive in no order.
/// With --reliable-video each is instead a reliable message on the App lane,
/// handed over as soon as the connection takes it, arriving in capture order.
///
/// The encoder's rate control keeps the produced rate on target whatever the
/// profile's noise and scene cuts do — an overshoot is paid back over the next
/// half second, as a VBV buffer would — so rows with the same target produce the
/// same video rate and differ only in how it is spread.
struct Video {
    /// The player's patience: how far past the one-way delay a frame may land.
    static constexpr auto kJitterBudget = ms(100);

    struct Frame {
        Clock::time_point captured;
        size_t            bytes;
        bool              key = false;
        bool              arrived = false;
        Clock::time_point arrived_at{};
    };

    Video(Peer& tx, Peer& rx, const Scene& scene)
        : tx(tx), rx(rx), scene(scene), fps(scene.fps), gop(2 * scene.fps), rng(1) {
        target = scene.video * 1e6;
        if (scene.source == Source::Adaptive) target = (std::min)(target, 1e6);   // calls start low
        encoder_rate = target;
        for (int n = 0; n < gop; ++n) gop_weight += weight(n);
    }

    bool is_key(int n) const { return scene.profile.key_weight > 0 && n % gop == 0; }
    /// The encoder's view of a frame: its share of the GOP before noise.
    double weight(int n) const {
        if (is_key(n)) return scene.profile.key_weight;
        return scene.profile.layers == 3 && n % 4 == 0 ? 2.0 : 1.0;
    }
    // Fixed seed and raw draws: std's distributions are not the same on every
    // standard library, and the figures must be.
    double uniform() { return rng() / 4294967296.0; }

    /// The encoder: one frame per tick of its clock, sized from the rate it was
    /// last told.
    void capture(Clock::time_point now) {
        if (now < next_frame) return;
        const Profile& p = scene.profile;
        if (p.lag_s > 0)
            encoder_rate += (target - encoder_rate) * (1 - std::exp(-1.0 / fps / p.lag_s));
        else
            encoder_rate = target;
        const double budget = encoder_rate / 8 * gop / fps / gop_weight * weight(frame_no);
        double factor = 1 + p.noise * (2 * uniform() - 1);
        if (p.scene_every > 0 && uniform() * p.scene_every < 1) factor *= 4;
        const double size = (std::max)(budget * factor - debt / 15, budget * 0.25);
        debt += size - budget;
        const size_t bytes = static_cast<size_t>(size);
        frames.push_back(Frame{next_frame, bytes, is_key(frame_no)});
        video_bytes += bytes;
        ++frame_no;
        next_frame += std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(1)) / fps;
    }

    /// Frames go to the connection as soon as it takes them, oldest first.
    void feed(Clock::time_point now) {
        for (; fed < frames.size(); ++fed) {
            const Frame& f = frames[fed];
            if (g_reliable_video) {
                if (tx.write(f.bytes, now) == 0) break;
                continue;
            }
            const auto one_way = us(tx.path_stats().min_rtt_us / 2);
            tx.write_live(f.bytes, static_cast<uint32_t>(fed), f.captured + one_way + kJitterBudget, now);
        }
    }

    /// What has been delivered: by tag for live frames, and for reliable ones in
    /// the order they were sent — one lane.
    void play(Clock::time_point now) {
        for (const uint32_t tag : rx.live_arrivals) {
            frames[tag].arrived    = true;
            frames[tag].arrived_at = now;
        }
        rx.live_arrivals.clear();
        for (; played_messages < rx.app_messages && played_messages < frames.size(); ++played_messages) {
            frames[played_messages].arrived    = true;
            frames[played_messages].arrived_at = now;
        }
    }

    /// The adaptive encoder: what any application can do with PathStats and
    /// nothing else. Back off while a queue stands in front of the frames — in
    /// the connection or on the path — and creep up while none does: the estimate
    /// alone cannot be followed upwards, because a source that keeps to it is
    /// app-limited and the estimate is then only a floor.
    void retarget(Clock::time_point now) {
        if (scene.source != Source::Adaptive || now < next_retarget) return;
        next_retarget += ms(100);
        const PathStats st = tx.path_stats();
        uint64_t backlog = st.queued_bytes;
        for (size_t i = fed; i < frames.size(); ++i) backlog += frames[i].bytes;
        if (st.bandwidth_bps > 0) {
            const double wait  = backlog * 8.0 / st.bandwidth_bps * 1000 +
                                 (st.srtt_us - st.min_rtt_us) / 1000.0;
            const uint64_t dl  = st.bytes_delivered - prev_delivered;
            const uint64_t ls  = st.bytes_lost - prev_lost;
            const double   lr  = dl + ls ? double(ls) / double(dl + ls) : 0.0;
            if (wait > 40)
                target = (std::min)(target, st.bandwidth_bps * 1.0) * 0.85;
            else if (wait < 15 && lr < 0.1)
                target *= 1.08;
            target = (std::max)(150e3, (std::min)(target, scene.video * 1e6));
        }
        prev_delivered = st.bytes_delivered;
        prev_lost      = st.bytes_lost;
    }

    Peer&             tx;
    Peer&             rx;
    const Scene&      scene;
    const int         fps, gop;          // frames a second, and per keyframe
    std::mt19937      rng;
    std::vector<Frame> frames;           // every frame captured, by number
    size_t            fed = 0;           // frames handed to the connection
    uint64_t          played_messages = 0, video_bytes = 0;
    double            target = 0;        // bits/s the encoder is told to run at
    double            encoder_rate = 0;  // what its rate control currently produces
    double            gop_weight = 0;
    double            debt = 0;          // bytes produced over budget, still to be paid back
    int               frame_no = 0;
    Clock::time_point next_frame = Clock::time_point{} + std::chrono::seconds(1);   // after the handshake
    Clock::time_point next_retarget = next_frame;
    uint64_t          prev_delivered = 0, prev_lost = 0;
};

/// Live video over one connection, measured the way a viewer would: a frame is
/// *late* when it lands more than 100 ms after it could have — the path's
/// one-way delay — which is the whole jitter budget an interactive call has.
/// The player shows each frame at its deadline, or on arrival if it is late, and
/// the picture is *frozen* whenever two shown frames are further apart than
/// WebRTC's freeze threshold: three frame intervals or one plus 150 ms,
/// whichever is longer. *Recover* is how long after an event ends the stream
/// is back on time for good: the capture of the first frame of a full second
/// of frames all within the deadline. A second, because a clean path already
/// misses the odd keyframe, and the first on-time frame after an event can come
/// before the damage it does has reached the far end. "never" means no such
/// second followed it.
///
/// Every frame is a live message: never late by more than the transport's guess
/// at the path is wrong, but possibly not there at all — "dropped" is the share
/// that never arrived. A missing frame counts against nothing after it: what a
/// decoder makes of a gap (intra refresh, layers, asking for a keyframe) is its
/// own business. --reliable-video sends each frame reliably instead, where a loss
/// holds back the frames behind it and nothing stale is ever dropped.
RealtimeResult realtime(const Scene& sc) {
    const size_t bdp_pkts = static_cast<size_t>(sc.link * 1e6 / 8 * sc.rtt / 1000.0 / 1228);
    const size_t queue    = (std::max<size_t>)(static_cast<size_t>(bdp_pkts * sc.buffer_bdp), 8);
    const double rate0    = sc.besides == Besides::RateRise ? sc.link * 0.3e6 : sc.link * 1e6;
    Direction fwd{rate0, us(sc.rtt * 500), queue, sc.loss, {}, {}, 0};
    fwd.burst = ms(sc.burst_ms);
    Direction rev = fwd;
    Path path(fwd, rev);
    if (sc.late_scattered) path.scatter(ms(sc.late_ms));
    else                   path.hold_back(sc.late, ms(sc.late_ms), sc.late_reorders);

    const auto event     = std::chrono::seconds(10);
    const bool dark      = sc.besides == Besides::Outage || sc.besides == Besides::Roam;
    const auto event_end = event + ms(dark ? sc.outage_ms : 0);
    if (dark) path.set_outage(Clock::time_point{} + event, Clock::time_point{} + event_end);

    Clock::time_point now{};
    Flow fv(path, 0, g_algo, now);
    std::unique_ptr<Flow> other;
    if (sc.besides == Besides::PathBulk) other = std::make_unique<Flow>(path, 1, g_algo, now);
    if (sc.besides == Besides::Duplex)   other = std::make_unique<Flow>(path, 1, g_algo, now, true);
    Video video(fv.tx, fv.rx, sc);
    if (sc.besides == Besides::Rebind)
        path.move(fv.rx.addr(), Address{fv.rx.addr().ip, 3333}, Clock::time_point{} + event);
    if (sc.besides == Besides::Roam)
        path.move(fv.rx.addr(), Address{*IpAddress::parse("10.0.3.1"), 2222}, Clock::time_point{} + event_end);
    std::unique_ptr<Video> back;
    if (sc.besides == Besides::Duplex) back = std::make_unique<Video>(other->tx, other->rx, sc);

    const size_t chunk = feed_buffer().size();

    constexpr auto kStep  = us(200);
    const auto     start  = std::chrono::seconds(1);    // handshake and first estimate
    const auto     finish = std::chrono::seconds(31);
    const auto     until  = finish + std::chrono::seconds(2);   // the tail drains

    for (auto t = Clock::duration::zero(); t < until; t += kStep) {
        now += kStep;
        if (sc.besides == Besides::RateDrop && t == event) path.set_rate(sc.link * 0.3e6);
        if (sc.besides == Besides::RateRise && t == event) path.set_rate(sc.link * 1e6);
        if (sc.besides == Besides::RateSwing && t >= event && (t - event) % std::chrono::seconds(2) == Clock::duration::zero())
            path.set_rate(sc.link * ((t - event) / std::chrono::seconds(2) % 2 == 0 ? 0.3e6 : 1e6));
        path.deliver_until(now);

        // Nothing is captured after `finish`.
        for (Video* v : {&video, back.get()}) {
            if (!v) continue;
            if (t < finish) v->capture(now);
            v->feed(now);
        }
        // A file to the same peer: its own lane, at the lowest priority.
        if (sc.besides == Besides::StreamBulk && t < finish)
            for (int i = 0; i < 64; ++i)
                if (fv.tx.write(chunk, now, MessageType::FileChunk) == 0) break;
        if (sc.besides == Besides::PathBulk)
            for (int i = 0; i < 64; ++i)
                if (other->tx.write(chunk, now) == 0) break;

        for (Flow* f : {&fv, other.get()}) {
            if (!f) continue;
            f->tx.tick(now);
            f->rx.tick(now);
        }
        video.play(now);
        if (back) back->play(now);

        video.retarget(now);
        if (back) back->retarget(now);
    }

    const double base  = sc.rtt / 2.0;
    const auto   to_ms = [](Clock::duration d) { return std::chrono::duration<double, std::milli>(d).count(); };
    const auto   deadline = ms(static_cast<long long>(base)) + Video::kJitterBudget;
    const auto   on_time = [&](const Video::Frame& f) { return f.arrived && f.arrived_at - f.captured <= deadline; };

    // A frame that never arrived — dropped, or still undelivered when the run
    // ends — was not in time either.
    // Latency is of the frames that arrived; "late" counts the rest too.
    std::vector<double> latency, key_latency;
    size_t missing = 0, late_frames = 0;
    for (const Video::Frame& f : video.frames) {
        if (f.arrived) latency.push_back(to_ms(f.arrived_at - f.captured));
        else           ++missing;
        if (!on_time(f)) ++late_frames;
        if (f.key && f.arrived) key_latency.push_back(to_ms(f.arrived_at - f.captured));
    }
    if (latency.empty()) latency.push_back(2000);

    // The player: each frame shown at its deadline, or on arrival when later; a
    // frame that never came is never shown.
    const Clock::duration frame_every =
        std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(1)) / sc.fps;
    const Clock::duration freeze_at = (std::max)(frame_every * 3, frame_every + ms(150));
    double freeze_max = 0, frozen = 0;
    Clock::time_point shown_prev{};
    const auto freeze = [&](Clock::time_point shown) {
        if (shown_prev != Clock::time_point{} && shown - shown_prev > freeze_at) {
            freeze_max = (std::max)(freeze_max, to_ms(shown - shown_prev));
            frozen    += to_ms(shown - shown_prev) / 1000;
        }
        shown_prev = (std::max)(shown_prev, shown);
    };
    for (const Video::Frame& f : video.frames)
        if (f.arrived) freeze((std::max)(f.arrived_at, f.captured + deadline));
    // A stream whose last frames never came stands still until the last was due.
    if (!video.frames.empty() && !video.frames.back().arrived)
        freeze(video.frames.back().captured + deadline);

    double recover = -1;
    if (sc.has_event()) {
        recover = std::numeric_limits<double>::infinity();
        const size_t kSettled = static_cast<size_t>(sc.fps);
        const auto from = Clock::time_point{} + event_end;
        size_t run = 0;
        for (size_t i = 0; i < video.frames.size(); ++i) {
            const Video::Frame& f = video.frames[i];
            if (f.captured < from) continue;
            run = on_time(f) ? run + 1 : 0;
            if (run == kSettled) {
                recover = to_ms(video.frames[i + 1 - kSettled].captured - from);
                break;
            }
        }
    }

    std::sort(latency.begin(), latency.end());
    const auto q = [&](double f) { return latency[static_cast<size_t>(f * (latency.size() - 1))]; };
    const double frames = static_cast<double>((std::max<size_t>)(video.frames.size(), 1));
    const double late   = late_frames * 100.0 / frames;
    const double secs   = std::chrono::duration<double>(finish - start).count();
    const double fec = video.video_bytes ? fv.tx.path_stats().live_repair_bytes * 100.0 / video.video_bytes : 0;
    std::sort(key_latency.begin(), key_latency.end());
    const double key_median = key_latency.empty() ? -1 : key_latency[(key_latency.size() - 1) / 2] - base;
    return {q(0.5) - base, q(0.99) - base, late, missing * 100.0 / frames, freeze_max, frozen,
            recover, video.video_bytes * 8.0 / secs / 1e6, fec, key_median,
            fv.tx.retransmits() * 100.0 / double((std::max<uint64_t>)(fv.tx.conn()->recovery().next_pn(), 1))};
}

/// A share of frames late, as a column: green within what a call shrugs off,
/// yellow past what it visibly freezes on.
std::string late_cell(double late) {
    char s[32];
    std::snprintf(s, sizeof(s), "%8.1f%%", late);
    if (!g_color) return s;
    return std::string(late <= 1 ? "\x1b[32m" : late <= 5 ? "" : "\x1b[33m") + s + "\x1b[0m";
}

void realtime_row(const char* name, const Scene& sc) {
    const RealtimeResult r = realtime(sc);
    char recover[32];
    if (r.recover < 0)                  std::snprintf(recover, sizeof(recover), "%9s", "-");
    else if (std::isinf(r.recover))     std::snprintf(recover, sizeof(recover), "%9s", "never");
    else                                std::snprintf(recover, sizeof(recover), "%9.0f", r.recover);
    std::printf("  %-30s %9.1f %9.1f %s %8.1f%% %9.0f %9.1f %s %9.2f %8.1f%%\n", name, r.median, r.p99,
                late_cell(r.late).c_str(), r.dropped, r.freeze_max, r.frozen, recover, r.video, r.fec);
}

/// One source shape across the conditions it is most sensitive to: a clean path
/// and a lossy one, a buffer too shallow to absorb a burst, and an adaptive
/// encoder on a clean path and through a capacity drop — which is where a rate
/// control that answers slowly, or overshoots, pays.
void profile_row(const Profile& p) {
    const double cells[] = {
        realtime(Scene{}.shaped(p)).late,
        realtime(Scene{}.shaped(p).lossy(0.01)).late,
        realtime(Scene{}.shaped(p).buffer(0.5)).late,
        realtime(Scene{}.shaped(p).adaptive()).late,
        realtime(Scene{}.shaped(p).adaptive().with(Besides::RateDrop)).late,
    };
    std::printf("  %-30s", p.name);
    for (double c : cells) std::printf(" %s", late_cell(c).c_str());
    std::printf("\n");
}

// ── realtime by class ───────────────────────────────────────────────────────

/// What a kind of video asks of the path: its rate, its frame rate, and how it
/// spreads the rate over frames. Resolution and codec reach the transport only
/// through these — a 4K60 call is a 40 Mbit/s source with a frame every 17 ms
/// and a keyframe of a few hundred KB.
struct VideoClass {
    const char* name;
    double      mbps;
    int         fps;
    Profile     profile;
};
/// A screen: mostly still, a slide change now and then, a large keyframe.
constexpr Profile kScreen{"screen", 20, 0.5, 30, 0, 1};
const VideoClass kVideoClasses[] = {
    {"call 720p30, 2.5 Mbit",         2.5, 30, kSteady},
    {"1080p30, 6 Mbit",               6,   30, kSteady},
    {"1080p60 game, 12 Mbit",         12,  60, kSteady},
    {"4K60, 40 Mbit",                 40,  60, kSteady},
    {"8K60 / near-lossless, 120",     120, 60, kSteady},
    {"screen share, 3 Mbit, 15 fps",  3,   15, kScreen},
};

/// The paths such video meets, from a phone's to a LAN.
struct PathClass {
    const char* name;
    double      link;      ///< Mbit/s
    int         rtt;       ///< ms
    double      loss;      ///< both ways
    int         burst_ms;  ///< 0 = independent losses
    double      late;      ///< share of datagrams held back late_ms, both ways
    int         late_ms;
};
const PathClass kPathClasses[] = {
    {"mobile",   15,   60, 0.01,  20, 0,   0},
    {"wi-fi",    50,   20, 0.005, 20, 0.2, 8},
    {"home",     100,  20, 0,     0,  0,   0},
    {"fiber",    500,  10, 0,     0,  0,   0},
    {"LAN",      1000,  1, 0,     0,  0,   0},
    {"far",      100, 200, 0.005, 0,  0,   0},
};

/// Every class of video over every kind of path, as a fixed-rate live source:
/// where each class stops fitting, and what of it goes first. A source above
/// 90% of the link is not run — it cannot fit, whatever the transport does.
void class_tables() {
    constexpr size_t kPaths = sizeof(kPathClasses) / sizeof(kPathClasses[0]);
    struct Cell { bool run; RealtimeResult r; };
    std::vector<std::array<Cell, kPaths>> grid;
    for (const VideoClass& v : kVideoClasses) {
        grid.emplace_back();
        for (size_t i = 0; i < kPaths; ++i) {
            const PathClass& p = kPathClasses[i];
            Cell& c = grid.back()[i];
            c.run = v.mbps <= 0.9 * p.link;
            if (!c.run) continue;
            c.r = realtime(Scene{}.over(p.link, p.rtt).lossy(p.loss, p.burst_ms)
                               .jittery(p.late, p.late_ms).sending(v.mbps, v.fps).shaped(v.profile));
        }
    }
    const auto table = [&](const char* title, auto cell) {
        std::vector<const char*> names;
        for (const PathClass& p : kPathClasses) names.push_back(p.name);
        std::printf("\n%s%s%s\n  %-30s", col("\x1b[1m"), title, col("\x1b[0m"), "");
        for (const char* n : names) std::printf(" %9s", n);
        std::printf("\n  %-30s", "------------------------------");
        for (size_t i = 0; i < kPaths; ++i) std::printf(" %9s", "---------");
        std::printf("\n");
        for (size_t row = 0; row < grid.size(); ++row) {
            std::printf("  %-30s", kVideoClasses[row].name);
            for (const Cell& c : grid[row]) {
                if (!c.run) std::printf(" %9s", "-");
                else        std::printf(" %s", cell(c.r).c_str());
            }
            std::printf("\n");
        }
    };
    table(g_reliable_video ? "realtime by class — % of frames late (fixed-rate source, every frame reliable)"
                           : "realtime by class — % of frames late (fixed-rate live source)",
          [](const RealtimeResult& r) { return late_cell(r.late); });
    table("realtime by class — keyframe latency over one-way delay, median ms",
          [](const RealtimeResult& r) {
              char s[32];
              if (r.key_median < 0) std::snprintf(s, sizeof(s), "%9s", "never");
              else                  std::snprintf(s, sizeof(s), "%9.1f", r.key_median);
              return std::string(s);
          });
    std::printf("  (paths: mobile 15 Mbit/60 ms, 1%% loss in 20 ms bursts; wi-fi 50 Mbit/20 ms,\n"
                "   0.5%% in bursts, a fifth of the datagrams 8 ms late (holding back those\n"
                "   behind them, as Wi-Fi's block-ack does: no reordering); home 100 Mbit/20 ms;\n"
                "   fiber 500 Mbit/10 ms; LAN 1 Gbit/1 ms; far 100 Mbit/200 ms, 0.5%% loss.\n"
                "   Buffers 1 BDP, 8 packets at least. Classes: GOP 2 s, keyframe 5x a frame\n"
                "   (the screen 20x, mostly still, a slide change every 2 s). \"-\": the source\n"
                "   is above 90%% of the link. A frame is due 100 ms after the one-way delay, as\n"
                "   above. A frame past SendOptions::kMaxLivePayload (4 MiB) is refused by the\n"
                "   API and never arrives. The lossy cells are one draw each (RATS_SEED for\n"
                "   another).)\n");

    // Reordering, which the wi-fi column above does not do: a datagram held back
    // there holds back those behind it, as a block-ack window does. Each cell is
    // one run, read twice: the frames it made late, and what it sent twice.
    struct Column {
        const char* name;
        Scene (*on)(Scene);
    };
    const Column columns[] = {
        {"none", [](Scene s) { return s; }},
        {"0.1%", [](Scene s) { return s.jittery(0.001, 8, true); }},
        {"1%", [](Scene s) { return s.jittery(0.01, 8, true); }},
        {"5%", [](Scene s) { return s.jittery(0.05, 8, true); }},
        {"1%+loss", [](Scene s) { return s.jittery(0.01, 8, true).lossy(0.005); }},
        {"0-10 ms", [](Scene s) { return s.scattered(10); }},
        {"0-10+loss", [](Scene s) { return s.scattered(10).lossy(0.005); }},
    };
    std::vector<std::pair<const VideoClass*, std::vector<RealtimeResult>>> runs;
    for (const VideoClass& v : kVideoClasses) {
        if (v.mbps > 45) continue;
        const Scene base = Scene{}.over(50, 20).sending(v.mbps, v.fps).shaped(v.profile);
        std::vector<RealtimeResult> row;
        for (const Column& c : columns) row.push_back(realtime(c.on(base)));
        runs.emplace_back(&v, std::move(row));
    }
    const auto reorder_table = [&](const char* title, auto cell) {
        std::printf("\n%s%s%s\n  %-30s", col("\x1b[1m"), title, col("\x1b[0m"), "");
        for (const Column& c : columns) std::printf(" %9s", c.name);
        std::printf("\n  %-30s", "------------------------------");
        for (size_t i = 0; i < std::size(columns); ++i) std::printf(" %9s", "---------");
        std::printf("\n");
        for (const auto& [v, row] : runs) {
            std::printf("  %-30s", v->name);
            for (const RealtimeResult& r : row) std::printf(" %s", cell(r).c_str());
            std::printf("\n");
        }
    };
    reorder_table("realtime by class — % of frames late, 50 Mbit/20 ms, datagrams overtaken",
                  [](const RealtimeResult& r) { return late_cell(r.late); });
    reorder_table("realtime by class — % of packets sent again, same runs", [](const RealtimeResult& r) {
        char s[32];
        std::snprintf(s, sizeof(s), "%8.1f%%", r.resent);
        return std::string(s);
    });
    std::printf("  (a share of the datagrams 8 ms late, both ways: overtaken by every one sent\n"
                "   in those 8 ms — at 40 Mbit/s some thirty. \"0-10 ms\": every datagram late\n"
                "   by its own draw from 0-10 ms, as over a path that keeps no order (per-packet\n"
                "   jitter, a bonded link): overtaken all the time. \"+loss\": 0.5%% lost as\n"
                "   well, so FEC and repairs have real work. Loss detection reads three\n"
                "   packets acked past a hole as a loss until the path has shown that it\n"
                "   reorders; from then on it waits for as long as the path has been late,\n"
                "   live data and bulk alike, and FEC sizes its repairs knowing a loss is\n"
                "   found that much later. What turns up after all is no loss rate, so\n"
                "   reordering neither cuts the estimate nor buys repair symbols.)\n");
}

} // namespace

int main(int argc, char** argv) {
    bool realtime_only = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--no-color") == 0) g_color = false;
        if (std::strcmp(argv[i], "--cc=reno") == 0) g_algo = CongestionAlgorithm::Reno;
        if (std::strcmp(argv[i], "--cc=bbr") == 0)  g_algo = CongestionAlgorithm::Bbr;
        if (std::strcmp(argv[i], "--realtime") == 0) realtime_only = true;
        if (std::strcmp(argv[i], "--reliable-video") == 0) g_reliable_video = true;
        if (std::strcmp(argv[i], "--no-fec") == 0) g_fec = false;
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

    if (!realtime_only) {
    heading("bulk — 20 s one way; buffer = 1 BDP unless the name says otherwise",
            "Mbit/s", "util", "retrans", "cwnd cuts", "dropped");
    bulk("10 Mbit,  20 ms",              10,  20, 0.0,    21, 20);
    bulk("10 Mbit, 100 ms",              10, 100, 0.0,   104, 20);
    bulk("50 Mbit,  50 ms",              50,  50, 0.0,   260, 20);
    bulk("100 Mbit, 100 ms",            100, 100, 0.0,  1041, 20);
    bulk("100 Mbit,  10 ms",            100,  10, 0.0,   104, 20);
    bulk("1 Gbit,     1 ms",           1000,   1, 0.0,   104, 20);
    bulk("1 Gbit,   100 ms",           1000, 100, 0.0, 10245, 20);
    bulk("1 Gbit,   100 ms, 0.1% loss",1000, 100, 0.001, 10245, 20);
    bulk("300 Mbit, 200 ms",            300, 200, 0.0,  6147, 20);
    bulk("10 Mbit, 100 ms, buffer 0.1", 10, 100, 0.0,     10, 20);
    bulk("10 Mbit, 100 ms, buffer 4",   10, 100, 0.0,    416, 20);
    bulk("10 Mbit, 100 ms, 0.1% loss",  10, 100, 0.001,  104, 20);
    bulk("10 Mbit, 100 ms, 1% loss",    10, 100, 0.01,   104, 20);
    bulk("50 Mbit,  20 ms, 1% overtaken", 50, 20, 0.0,    104, 20, 0.01);
    bulk("50 Mbit,  20 ms, 5% overtaken", 50, 20, 0.0,    104, 20, 0.05);
    bulk("100 Mbit, 50 ms, 1% overtaken",100, 50, 0.0,    520, 20, 0.01);
    bulk("50 Mbit,  20 ms, 1% loss",     50, 20, 0.01,   104, 20);
    bulk("50 Mbit,  20 ms, 1% loss+ovt", 50, 20, 0.01,   104, 20, 0.01);
    bulk("100 Mbit, 50 ms, 0.1% loss",  100, 50, 0.001,  520, 20);
    bulk("100 Mbit, 50 ms, 0.1% loss+ovt",100, 50, 0.001, 520, 20, 0.01);
    std::printf("  (a low utilisation with FEW reductions is a sender that never found the "
                "path;\n   a low one with MANY is a sender that keeps losing it. The two want "
                "opposite fixes.)\n"
                "  (\"overtaken\": that share of the datagrams 8 ms late and overtaken by those\n"
                "   behind, nothing lost — what a sender that takes reordering for loss pays.\n"
                "   \"loss+ovt\": the row above it with 1%% overtaken as well. Once a path has\n"
                "   reordered, a loss is found by time alone, not by three packets past it:\n"
                "   what that later detection costs where both happen.)\n");

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
                "   reorder buffer. What dominates is neither: it is the send queue — twice the\n"
                "   congestion window, 2 MiB at least, of queued-but-unsent application data —\n"
                "   which is why the hole often adds little to a peak the queue had already set.)\n");

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

    }

    heading(g_reliable_video
                ? "realtime — 30 s of video (30 fps, keyframe every 2 s), every frame reliable, ms over one-way delay"
                : "realtime — 30 s of live video (30 fps, keyframe every 2 s), ms over one-way delay",
            {"median", "p99", "late", "dropped", "freeze ms", "frozen s", "recover", "video", "fec"});
    using X = Besides;
    realtime_row("4 of 10 Mbit, 40 ms",            Scene{});
    realtime_row("  1%",                           Scene{}.lossy(0.01));
    realtime_row("  1% in 20 ms bursts",          Scene{}.lossy(0.01, 20));
    realtime_row("  3% in 100 ms fades",          Scene{}.lossy(0.03, 100));
    realtime_row("  5%",                           Scene{}.lossy(0.05));
    realtime_row("  200 ms, 1%",                   Scene{}.round_trip(200).lossy(0.01));
    realtime_row("  buffer 4",                     Scene{}.buffer(4));
    realtime_row("  + bulk flow on the path",      Scene{}.with(X::PathBulk));
    realtime_row("  + file to the same peer",      Scene{}.with(X::StreamBulk));
    realtime_row("  + video back the other way",   Scene{}.with(X::Duplex));
    realtime_row("  + link drops to 3 Mbit",       Scene{}.with(X::RateDrop));
    realtime_row("  + link swings 10/3 Mbit",      Scene{}.with(X::RateSwing));
    realtime_row("  + 0.3 s outage",               Scene{}.outage(300));
    realtime_row("  + 1 s outage",                 Scene{}.outage(1000));
    realtime_row("  + 3 s outage",                 Scene{}.outage(3000));
    realtime_row("  + NAT rebinds the receiver",   Scene{}.with(X::Rebind));
    realtime_row("  + receiver moves network",     Scene{}.roam(300));
    realtime_row("adaptive <=8 of 10, 40 ms",      Scene{}.adaptive());
    realtime_row("  1%",                           Scene{}.adaptive().lossy(0.01));
    realtime_row("  1% in 20 ms bursts",          Scene{}.adaptive().lossy(0.01, 20));
    realtime_row("  5%",                           Scene{}.adaptive().lossy(0.05));
    realtime_row("  5% in 20 ms bursts",          Scene{}.adaptive().lossy(0.05, 20));
    realtime_row("  3% in 100 ms fades",          Scene{}.adaptive().lossy(0.03, 100));
    realtime_row("  + bulk flow on the path",      Scene{}.adaptive().with(X::PathBulk));
    realtime_row("  + video back the other way",   Scene{}.adaptive().with(X::Duplex));
    realtime_row("  + link drops to 3 Mbit",       Scene{}.adaptive().with(X::RateDrop));
    realtime_row("  + link rises from 3 Mbit",     Scene{}.adaptive().with(X::RateRise));
    realtime_row("  + link swings 10/3 Mbit",      Scene{}.adaptive().with(X::RateSwing));
    realtime_row("  + 1 s outage",                 Scene{}.adaptive().outage(1000));
    realtime_row("  + 3 s outage",                 Scene{}.adaptive().outage(3000));
    realtime_row("  + receiver moves network",     Scene{}.adaptive().roam(300));
    std::printf("  (\"late\" is the share of frames that landed more than 100 ms after the path\n"
                "   allowed, or never landed — a call shows neither; \"dropped\" is the share\n"
                "   that never did, and median and p99 are of the ones that did. \"freeze\" is\n"
                "   the longest the picture stood still and \"frozen\" all the time it did, by\n"
                "   WebRTC's rule: two shown frames more than max(3 frames, 1 frame + 150 ms)\n"
                "   apart. \"late\" is delay, \"freeze\" stutter: a stream can be smooth and\n"
                "   still a second behind. Events start at 10 s; \"recover\" is how long after\n"
                "   one ended it took until a full second of frames was on time again\n"
                "   (\"never\": it was not). Loss is both ways; in bursts or fades the same\n"
                "   mean loss comes as spells that lose everything, that long on average.\n");
    if (g_reliable_video)
        std::printf("   Every frame here is reliable and in order on its lane: a loss holds back\n"
                    "   the frames that follow it, and nothing stale is ever dropped.\n");
    else
        std::printf("   Every frame is a live message due at capture + min RTT/2 + 100 ms: what\n"
                    "   cannot make that is dropped, whole, and frames arrive in no order. A\n"
                    "   dropped frame spoils nothing after it here — what a decoder does with a\n"
                    "   gap is the codec's business. --reliable-video for every frame reliable.\n"
                    "   \"fec\" is the repair symbols sent with the frames on a lossy path, as a\n"
                    "   share of the video (--no-fec: none are).\n");
    std::printf("   A file to the same peer has a lane of its own. \"adaptive\" rows retarget\n"
                "   the encoder from PathStats every 100 ms, starting from 1 Mbit/s; video is\n"
                "   what it produced.)\n");

    heading("realtime by source shape — % of frames late; 10 Mbit, 40 ms",
            "clean", "1% loss", "buf 0.5", "adaptive", "adapt drop");
    profile_row(kSteady);
    profile_row({"10x keyframe",                 10,   0,    0, 0, 1});
    profile_row({"intra refresh, no keyframes",   0,   0,    0, 0, 1});
    profile_row({"noisy frames, scene cuts",      5, 0.5, 120, 0, 1});
    profile_row({"slow rate control (1 s)",       5,   0,    0, 1, 1});
    profile_row({"3 temporal layers",             5,   0,    0, 0, 3});
    std::printf("  (the first three columns are a fixed 4 Mbit/s source, buffer 1 BDP unless\n"
                "   \"buf 0.5\"; the last two the adaptive one of the table above, the second of\n"
                "   them through the drop to 3 Mbit. Every row produces the same rate — only its\n"
                "   spread over frames differs, which is all a codec changes for the path.\n"
                "   Temporal layers matter once a late frame can be dropped: a top-layer frame is\n"
                "   needed by nothing — but here a dropped frame of any layer costs the same, so\n"
                "   they only reshape.)\n");

    class_tables();

    std::printf("\nnote: no ack compression; reordering, variable delay and competing traffic only\n"
                "in the rows that say so. These are not predictions about a real network — they\n"
                "are a comparison between builds, and only useful read that way. For \"does it\n"
                "survive a hostile network at all\", put tools/badnet.sh in front of\n"
                "bench_transport instead.\n");
    return 0;
}
