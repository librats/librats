// ─────────────────────────────────────────────────────────────────────────────
//  bench_rx — the receive path, before and after 5d64343.
//
//  What is under test is NOT ReceiveBuffer in isolation — a buffer is only as
//  good as the read loop driving it. So both the old and the new read loops are
//  reproduced here verbatim from their respective commits:
//
//    mesh/old   Connection::on_readable @5d64343^  — drain the socket to
//               EWOULDBLOCK, *then* parse; normalize() once front waste > 64 KiB.
//    mesh/new   Connection::on_readable @5d64343   — parse after every read; size
//               the buffer from the block length already on the wire (rx_need_).
//    bt/old     PeerConnection::do_read @5d64343^  — same shape, 64 KiB reads,
//               normalize() past 1 MiB of front waste.
//    bt/new     PeerConnection::do_read @5d64343.
//
//  The socket is mocked (net_mock.h) so recv() call counts are exact and
//  repeatable; the allocator is instrumented (alloc_track.h) so heap churn and
//  peak residency are exact too.
//
//  Message consumption is deliberately trivial (checksum the body): this
//  measures the plumbing, not the crypto behind it.
// ─────────────────────────────────────────────────────────────────────────────

#include "framework/bench.h"
#include "framework/alloc_track.h"
#include "baseline/legacy_buffers.h"
#include "support/net_mock.h"

#include "core/receive_buffer.h"
#include "wire/frame.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using librats::ByteView;
namespace framer = librats::framer;

// ── Wire images ──────────────────────────────────────────────────────────────
//
// The exact byte stream a peer would put on the socket, so both implementations
// parse identical input.

namespace wire {

/// librats mesh: [u32 len][body] blocks.
std::vector<uint8_t> mesh(const std::vector<std::size_t>& body_sizes) {
    std::vector<uint8_t> out;
    for (std::size_t n : body_sizes) {
        std::vector<uint8_t> body(n);
        for (std::size_t i = 0; i < n; ++i) body[i] = uint8_t(i * 31 + 7);
        framer::encode_block(out, ByteView(body));
    }
    return out;
}

/// BitTorrent: [u32 len][id][payload].
std::vector<uint8_t> bt(const std::vector<std::pair<uint8_t, std::size_t>>& msgs) {
    std::vector<uint8_t> out;
    for (auto [id, payload] : msgs) {
        const std::uint32_t len = std::uint32_t(payload + 1);
        out.push_back(uint8_t(len >> 24));
        out.push_back(uint8_t(len >> 16));
        out.push_back(uint8_t(len >> 8));
        out.push_back(uint8_t(len));
        out.push_back(id);
        for (std::size_t i = 0; i < payload; ++i) out.push_back(uint8_t(i * 17 + 3));
    }
    return out;
}

std::vector<std::size_t> repeat(std::size_t n, std::size_t size) {
    return std::vector<std::size_t>(n, size);
}

}  // namespace wire

// ── Message sink ─────────────────────────────────────────────────────────────

static std::uint64_t g_sink = 0;

static inline void consume_body(const uint8_t* p, std::size_t n) {
    // Touch the head and the tail so the parse cannot be optimized away, but stay
    // cheap: the point is the buffer plumbing, not a fake payload cost.
    g_sink += n + (n ? p[0] + p[n - 1] : 0);
    bench::do_not_optimize(g_sink);
}

// ── mesh: the OLD read loop (Connection::on_readable @5d64343^) ───────────────

struct MeshRxOld {
    static constexpr std::size_t kRecvChunk    = 16 * 1024;
    static constexpr std::size_t kCompactWaste = 64 * 1024;

    librats_legacy::ReceiveBuffer rx_{512};  // Connection had `rx_{512}`

    void on_readable(mock::RxKernel& k) {
        // Drain the kernel buffer first…
        while (true) {
            rx_.ensure_space(kRecvChunk);
            const std::ptrdiff_t n = k.recv(rx_.write_ptr(), rx_.write_space());
            if (n > 0) {
                rx_.received(std::size_t(n));
                continue;
            }
            break;  // EWOULDBLOCK
        }
        // …and only then parse whatever accumulated.
        while (rx_.size() > 0) {
            const auto b = framer::try_take_block(rx_.data(), rx_.size());
            if (b.status != framer::Block::Ok) break;
            consume_body(b.body.data(), b.body.size());
            rx_.consume(b.consumed);
        }
        if (rx_.front_waste() > kCompactWaste) rx_.normalize();
    }

    std::size_t capacity() const { return rx_.capacity(); }
};

// ── mesh: the NEW read loop (Connection::on_readable @5d64343) ────────────────

struct MeshRxNew {
    static constexpr std::size_t kRecvChunk       = 16 * 1024;
    static constexpr std::size_t kMaxEagerReserve = 1024 * 1024;

    librats::ReceiveBuffer rx_;
    std::size_t            rx_need_ = 0;

    std::size_t read_size() const {
        if (rx_need_ > rx_.size())
            return (std::min)(rx_need_ - rx_.size(), kMaxEagerReserve);
        return kRecvChunk;
    }

    void process_blocks() {
        rx_need_ = 0;
        while (!rx_.empty()) {
            const auto b = framer::try_take_block(rx_.data(), rx_.size());
            if (b.status == framer::Block::Incomplete) {
                rx_need_ = b.needed;
                break;
            }
            if (b.status == framer::Block::Error) break;
            consume_body(b.body.data(), b.body.size());
            rx_.consume(b.consumed);
        }
    }

    void on_readable(mock::RxKernel& k) {
        while (true) {
            const librats::ByteSpan into = rx_.prepare(read_size());
            const std::ptrdiff_t   n     = k.recv(into.data(), into.size());
            if (n < 0) break;  // EWOULDBLOCK
            rx_.commit(std::size_t(n));
            process_blocks();
            if (std::size_t(n) < into.size()) break;  // kernel buffer drained
        }
    }

    std::size_t capacity() const { return rx_.capacity(); }
};

// ── BitTorrent: the OLD read loop (PeerConnection::do_read @5d64343^) ─────────

static inline std::uint32_t read_u32_be(const uint8_t* p) {
    return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
           (std::uint32_t(p[2]) << 8) | std::uint32_t(p[3]);
}

struct BtRxOld {
    static constexpr std::size_t kRecvChunk = 64 * 1024;

    librats_legacy::ReceiveBuffer rx_;  // default 4096

    void parse() {
        while (rx_.size() >= 4) {
            const std::uint32_t len = read_u32_be(rx_.data());
            if (rx_.size() < std::size_t(4) + len) break;
            if (len == 0) {
                rx_.consume(4);
                continue;
            }
            consume_body(rx_.data() + 5, len - 1);
            rx_.consume(std::size_t(4) + len);
        }
    }

    void on_readable(mock::RxKernel& k) {
        for (;;) {
            rx_.ensure_space(kRecvChunk);
            const std::ptrdiff_t n = k.recv(rx_.write_ptr(), rx_.write_space());
            if (n > 0) {
                rx_.received(std::size_t(n));
                continue;
            }
            break;
        }
        parse();
        if (rx_.empty()) rx_.clear();
        else if (rx_.front_waste() > (1u << 20)) rx_.normalize();
    }

    std::size_t capacity() const { return rx_.capacity(); }
};

// ── BitTorrent: the NEW read loop (PeerConnection::do_read @5d64343) ──────────

struct BtRxNew {
    static constexpr std::size_t kRecvChunk       = 64 * 1024;
    static constexpr std::size_t kMaxEagerReserve = 1024 * 1024;

    librats::ReceiveBuffer rx_;
    std::size_t            rx_need_ = 0;

    std::size_t read_size() const {
        if (rx_need_ > rx_.size())
            return (std::min)(rx_need_ - rx_.size(), kMaxEagerReserve);
        return kRecvChunk;
    }

    void parse() {
        rx_need_ = 0;
        while (rx_.size() >= 4) {
            const std::uint32_t len = read_u32_be(rx_.data());
            if (rx_.size() < std::size_t(4) + len) {
                rx_need_ = std::size_t(4) + len;
                break;
            }
            if (len == 0) {
                rx_.consume(4);
                continue;
            }
            consume_body(rx_.data() + 5, len - 1);
            rx_.consume(std::size_t(4) + len);
        }
    }

    void on_readable(mock::RxKernel& k) {
        for (;;) {
            const librats::ByteSpan into = rx_.prepare(read_size());
            const std::ptrdiff_t   n     = k.recv(into.data(), into.size());
            if (n < 0) return;
            rx_.commit(std::size_t(n));
            parse();
            if (std::size_t(n) < into.size()) return;
        }
    }

    std::size_t capacity() const { return rx_.capacity(); }
};

// ── The event loop: bursts arrive, the driver drains ─────────────────────────

/// Replay `w` through `d`, handing the kernel `burst` bytes at a time (one
/// readable event per burst). Returns the peak capacity the buffer reached.
template <typename Driver>
std::size_t replay(Driver& d, mock::RxKernel& k, const std::vector<uint8_t>& w,
                   std::size_t burst) {
    std::size_t peak = 0;
    std::size_t off  = 0;
    while (off < w.size()) {
        const std::size_t n = (std::min)(burst, w.size() - off);
        k.deliver(w.data() + off, n);
        off += n;
        d.on_readable(k);
        peak = (std::max)(peak, d.capacity());
    }
    return peak;
}

// ── Scenario table ───────────────────────────────────────────────────────────

/// A real recv() is ~1 µs; the mock charges a memcpy. See bench_tx for the
/// reasoning — 'userland' isolates the buffer, 'modelled' puts the kernel back.
constexpr double kSyscallNs = 1000.0;

struct Metrics {
    std::uint64_t recv_calls = 0;
    std::uint64_t allocs     = 0;
    std::uint64_t alloc_kb   = 0;  ///< total heap churn (KiB)
    std::size_t   peak_cap   = 0;
    std::size_t   final_cap  = 0;
    double        user_us    = 0;
    double        model_us   = 0;
};

template <typename Driver>
Metrics measure(const std::vector<uint8_t>& w, std::size_t burst) {
    Metrics      m;
    track::Stats mem;
    {
        mock::RxKernel k;
        track::Scope   scope(mem);
        Driver         d;
        m.peak_cap   = replay(d, k, w, burst);
        m.final_cap  = d.capacity();
        m.recv_calls = k.c.calls;
    }
    m.allocs   = mem.allocs;
    m.alloc_kb = mem.bytes / 1024;

    std::vector<double> t;
    for (int i = 0; i < 7; ++i) {
        mock::RxKernel k;
        Driver         d;
        const auto     t0 = std::chrono::steady_clock::now();
        replay(d, k, w, burst);
        const auto t1 = std::chrono::steady_clock::now();
        t.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
    }
    std::sort(t.begin(), t.end());
    m.user_us  = t[t.size() / 2];
    m.model_us = m.user_us + double(m.recv_calls) * kSyscallNs / 1000.0;
    return m;
}

struct Scenario {
    std::string          name;
    std::vector<uint8_t> w;
    std::size_t          burst;
    bool                 bt;  // BitTorrent framing vs mesh framing
};

static std::string kib(std::size_t b) {
    char buf[32];
    if (b >= 1024 * 1024) std::snprintf(buf, sizeof buf, "%.1f M", double(b) / (1024 * 1024));
    else if (b >= 1024)   std::snprintf(buf, sizeof buf, "%.0f K", double(b) / 1024);
    else                  std::snprintf(buf, sizeof buf, "%zu B", b);
    return buf;
}

static void print_metrics(const std::vector<Scenario>& scen) {
    std::printf("\n\033[1;36mReceive path — syscalls & memory (one replay of the wire)\033[0m\n");
    std::printf("\n  \033[2m%-33s %-4s %7s %6s %8s %8s %8s %9s %10s\033[0m\n", "scenario", "impl",
                "recv()", "allocs", "churn", "peak cap", "end cap", "userland", "modelled");

    for (const auto& s : scen) {
        Metrics o = s.bt ? measure<BtRxOld>(s.w, s.burst) : measure<MeshRxOld>(s.w, s.burst);
        Metrics n = s.bt ? measure<BtRxNew>(s.w, s.burst) : measure<MeshRxNew>(s.w, s.burst);

        auto row = [&](const char* tag, const Metrics& m, const char* color) {
            std::printf("  %s%-33s %-4s %7llu %6llu %7lluK %8s %8s %6.1f us %7.1f us\033[0m\n",
                        color, tag == std::string("old") ? s.name.c_str() : "", tag,
                        (unsigned long long)m.recv_calls, (unsigned long long)m.allocs,
                        (unsigned long long)m.alloc_kb, kib(m.peak_cap).c_str(),
                        kib(m.final_cap).c_str(), m.user_us, m.model_us);
        };
        row("old", o, "\033[33m");
        row("new", n, "\033[32m");
    }
    std::printf("\n  \033[2m'end cap'  what the connection still holds once the wire goes quiet."
                " The old\n             buffer never gives it back — multiply by peer count.\n"
                "  'churn'    every byte the allocator ever handed out. The old buffer is a\n"
                "             std::vector, so resize() ZERO-FILLS what it grows into; the new\n"
                "             one is new uint8_t[] and recv() overwrites it anyway.\n"
                "  'userland' measured with the syscall mocked down to a memcpy; 'modelled'\n"
                "             adds recv() x 1 us back.\033[0m\n");
}

// ── Buffer decay: the timeline ───────────────────────────────────────────────
//
// A picture of the thing the old buffer simply cannot do: hand memory back.

static void print_decay() {
    std::printf("\n\033[1;36mBuffer decay — a peer sends one big message, then goes quiet\033[0m\n");
    std::printf("\n  \033[2m%-28s %10s %10s %10s\033[0m\n", "step", "old cap", "new cap",
                "new watermark");

    MeshRxOld      o;
    MeshRxNew      n;
    mock::RxKernel ko, kn;

    auto step = [&](const char* what, const std::vector<uint8_t>& w, std::size_t burst) {
        if (!w.empty()) {
            replay(o, ko, w, burst);
            replay(n, kn, w, burst);
        }
        const std::size_t oc = o.capacity(), nc = n.capacity();
        const char* col = nc < oc ? "\033[32m" : "";
        std::printf("  %s%-28s %10s %10s %10s\033[0m\n", col, what, kib(oc).c_str(),
                    kib(nc).c_str(), kib(n.rx_.watermark()).c_str());
    };

    const auto chatter = wire::mesh(wire::repeat(20, 256));
    const auto big     = wire::mesh({4 * 1024 * 1024});

    step("start", {}, 0);
    step("20 x 256 B messages", chatter, 16 * 1024);
    step("one 4 MiB message", big, 64 * 1024);
    step("20 x 256 B messages", chatter, 16 * 1024);
    for (int i = 1; i <= 8; ++i) {
        char label[64];
        std::snprintf(label, sizeof label, "idle tick %d (decay)", i);
        n.rx_.decay();  // Reactor's 10 s maintenance sweep
        // the old buffer has no equivalent — nothing to call
        const std::size_t oc = o.capacity(), nc = n.capacity();
        std::printf("  \033[32m%-28s %10s %10s %10s\033[0m\n", label, kib(oc).c_str(),
                    kib(nc).c_str(), kib(n.rx_.watermark()).c_str());
    }
    std::printf("\n  \033[2mThe old buffer is pinned at its high-water mark for the life of the"
                " connection.\n  Multiply by peer count.\033[0m\n");
}

// ── main ─────────────────────────────────────────────────────────────────────

int main() {
    // Realistic-ish wire images.
    const auto mesh_small = wire::mesh(wire::repeat(512, 200));       // chatty control plane
    const auto mesh_1k    = wire::mesh(wire::repeat(256, 1400));      // ~MTU-sized app messages
    const auto mesh_big   = wire::mesh({4 * 1024 * 1024});            // one 4 MiB blob
    const auto mesh_mixed = [] {                                      // big blob, then chatter
        auto a = wire::mesh({2 * 1024 * 1024});
        auto b = wire::mesh(wire::repeat(200, 256));
        a.insert(a.end(), b.begin(), b.end());
        return a;
    }();

    std::vector<std::pair<uint8_t, std::size_t>> pieces;
    for (int i = 0; i < 256; ++i) pieces.emplace_back(7 /*piece*/, 8 + 16 * 1024);
    const auto bt_pieces = wire::bt(pieces);

    std::vector<std::pair<uint8_t, std::size_t>> bfchat;
    bfchat.emplace_back(5 /*bitfield*/, 512 * 1024);
    for (int i = 0; i < 400; ++i) bfchat.emplace_back(4 /*have*/, 4);
    const auto bt_bitfield = wire::bt(bfchat);

    const std::vector<Scenario> scen = {
        {"mesh: 512 x 200 B, 16K bursts", mesh_small, 16 * 1024, false},
        {"mesh: 256 x 1400 B, 16K bursts", mesh_1k, 16 * 1024, false},
        {"mesh: one 4 MiB blob, 64K bursts", mesh_big, 64 * 1024, false},
        {"mesh: 4 MiB blob, 1500 B dribble", mesh_big, 1500, false},
        {"mesh: 2 MiB blob then chatter", mesh_mixed, 64 * 1024, false},
        {"bt: 256 x 16 KiB pieces, 64K", bt_pieces, 64 * 1024, true},
        {"bt: 512K bitfield + 400 haves", bt_bitfield, 64 * 1024, true},
    };

    print_metrics(scen);
    print_decay();

    // ── Timing ───────────────────────────────────────────────────────────────
    bench::Bench b("Receive path — throughput");
    b.config().min_time = 0.35;

    for (const auto& s : scen) {
        b.group(s.name);
        b.bytes(double(s.w.size()));
        mock::RxKernel k;
        if (s.bt) {
            b.run("old", [&] {
                BtRxOld d;
                replay(d, k, s.w, s.burst);
            });
            b.run("new", [&] {
                BtRxNew d;
                replay(d, k, s.w, s.burst);
            });
        } else {
            b.run("old", [&] {
                MeshRxOld d;
                replay(d, k, s.w, s.burst);
            });
            b.run("new", [&] {
                MeshRxNew d;
                replay(d, k, s.w, s.burst);
            });
        }
    }
    b.report();

    std::printf("\n\033[2mchecksum %llu (keeps the parse alive)\033[0m\n",
                (unsigned long long)g_sink);
    return 0;
}
