// bench_dht.cpp — microbenchmarks comparing librats' DHT keyspace primitives
// against the equivalent libtorrent algorithms.
//
// We can't link real libtorrent here (reference/ pulls in Boost.Asio and the whole
// session machinery), so the "libtorrent" side is a faithful, standalone re-port of
// the exact algorithms from reference/kademlia/node_id.cpp + sha1_hash.hpp, kept in
// libtorrent's *native* representation (a 160-bit id as 5×uint32, like digest32) so
// the comparison isn't rigged in librats' favour. Where we model libtorrent
// favourably (e.g. skipping the network-to-host byte swap digest32::operator< does),
// it's noted — that only makes our wins conservative.
//
// Build:  cmake -S bench -B bench/build && cmake --build bench/build --target bench_dht
// Run:    ./bench/build/bin/bench_dht
//
// Header-only (src/dht/id.h) and self-timing — it predates framework/bench.h and
// brings its own loop.

#include "dht/id.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

using librats::dht::NodeId;
using librats::dht::closer_to;
using librats::dht::shared_prefix_bits;

// Keep the optimizer from deleting the work we're timing.
static volatile uint64_t g_sink = 0;

// ---------------------------------------------------------------------------
// libtorrent-equivalent primitives, native 5×uint32 representation.
// Source: reference/kademlia/node_id.cpp (distance / compare_ref / distance_exp)
//         reference/sha1_hash.hpp        (operator^ / operator< / count_leading_zeroes)
// ---------------------------------------------------------------------------
namespace ltref {

struct Id { std::array<uint32_t, 5> w; };  // digest32<160>::m_number

// digest32::operator^ — returns a full materialised copy.
inline Id xor_(const Id& a, const Id& b) {
    Id d;
    for (int i = 0; i < 5; ++i) d.w[i] = a.w[i] ^ b.w[i];
    return d;
}

// node_id.cpp compare_ref: materialise BOTH distances, then digest32::operator<.
// (We compare words directly, i.e. WITHOUT the network_to_host swap the real
// operator< performs — a deliberate handicap *in libtorrent's favour*.)
inline bool compare_ref(const Id& n1, const Id& n2, const Id& ref) {
    const Id lhs = xor_(n1, ref);
    const Id rhs = xor_(n2, ref);
    for (int i = 0; i < 5; ++i)
        if (lhs.w[i] != rhs.w[i]) return lhs.w[i] < rhs.w[i];
    return false;
}

// node_id.cpp distance_exp = max(159 - count_leading_zeroes(distance), 0).
// count_leading_zeroes over the 5-word array, using a hardware CLZ per word.
inline int clz_array(const Id& d) {
    int n = 0;
    for (int i = 0; i < 5; ++i) {
        if (d.w[i] == 0) { n += 32; continue; }
#if defined(__GNUC__) || defined(__clang__)
        return n + __builtin_clz(d.w[i]);
#else
        uint32_t v = d.w[i];
        while ((v & 0x80000000u) == 0) { ++n; v <<= 1; }
        return n;
#endif
    }
    return n;
}
inline int distance_exp(const Id& a, const Id& b) {
    return std::max(159 - clz_array(xor_(a, b)), 0);
}

// Same 160 random bits, expressed in libtorrent's word layout (big-endian words,
// matching how digest32 stores them so distances line up byte-for-byte).
inline Id from_node_id(const NodeId& id) {
    Id out{};
    for (int i = 0; i < 5; ++i)
        out.w[i] = (uint32_t(id[i * 4]) << 24) | (uint32_t(id[i * 4 + 1]) << 16)
                 | (uint32_t(id[i * 4 + 2]) << 8) | uint32_t(id[i * 4 + 3]);
    return out;
}

} // namespace ltref

// ---------------------------------------------------------------------------
// Timing harness: run `body` `repeats` times, report the *minimum* ns/op
// (min is the most stable estimator — it strips scheduler/noise spikes).
// ---------------------------------------------------------------------------
template <class F>
double bench(std::size_t ops, F&& body, int repeats = 7) {
    using clock = std::chrono::steady_clock;
    double best = 1e30;
    for (int r = 0; r < repeats; ++r) {
        auto t0 = clock::now();
        body();
        auto t1 = clock::now();
        const double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
        best = std::min(best, ns);
    }
    return best / static_cast<double>(ops);
}

static void row(const char* name, double rats_ns, double lt_ns) {
    const double ratio = lt_ns / rats_ns;  // >1 → librats faster
    const char* verdict = ratio > 1.05 ? "librats faster"
                        : ratio < 0.95 ? "libtorrent faster"
                                       : "~equal";
    std::printf("  %-26s  %8.2f   %8.2f    %5.2fx   %s\n",
                name, rats_ns, lt_ns, ratio, verdict);
}

int main() {
    std::mt19937_64 rng(0xC0FFEE);  // fixed seed → reproducible
    std::uniform_int_distribution<int> byte(0, 255);
    auto rand_id = [&] {
        NodeId id;
        for (auto& b : id) b = static_cast<uint8_t>(byte(rng));
        return id;
    };

    std::printf("librats DHT primitives vs libtorrent algorithms\n");
    std::printf("(libtorrent side = standalone re-port of reference/kademlia, native 5x uint32)\n\n");
    std::printf("  %-26s  %8s   %8s    %6s\n", "benchmark", "rats ns", "lt ns", "speedup");
    std::printf("  %-26s  %8s   %8s    %6s\n", "--------------------------",
                "-------", "-------", "------");

    // === 1) The hot comparator: closer_to vs compare_ref =====================
    {
        const std::size_t N = 1u << 20;  // 1M comparisons
        std::vector<NodeId>     a(N), b(N), t(N);
        std::vector<ltref::Id>  la(N), lb(N), lt(N);
        for (std::size_t i = 0; i < N; ++i) {
            a[i] = rand_id(); b[i] = rand_id(); t[i] = rand_id();
            la[i] = ltref::from_node_id(a[i]);
            lb[i] = ltref::from_node_id(b[i]);
            lt[i] = ltref::from_node_id(t[i]);
        }
        const double rats = bench(N, [&] {
            uint64_t acc = 0;
            for (std::size_t i = 0; i < N; ++i) acc += closer_to(a[i], b[i], t[i]);
            g_sink ^= acc;
        });
        const double ltn = bench(N, [&] {
            uint64_t acc = 0;
            for (std::size_t i = 0; i < N; ++i) acc += ltref::compare_ref(la[i], lb[i], lt[i]);
            g_sink ^= acc;
        });
        row("closer_to / compare_ref", rats, ltn);
    }

    // === 2) Prefix length: shared_prefix_bits vs distance_exp ================
    {
        const std::size_t N = 1u << 20;
        std::vector<NodeId>    a(N), b(N);
        std::vector<ltref::Id> la(N), lb(N);
        for (std::size_t i = 0; i < N; ++i) {
            a[i] = rand_id(); b[i] = rand_id();
            la[i] = ltref::from_node_id(a[i]);
            lb[i] = ltref::from_node_id(b[i]);
        }
        const double rats = bench(N, [&] {
            uint64_t acc = 0;
            for (std::size_t i = 0; i < N; ++i) acc += shared_prefix_bits(a[i], b[i]);
            g_sink ^= acc;
        });
        const double ltn = bench(N, [&] {
            uint64_t acc = 0;
            for (std::size_t i = 0; i < N; ++i) acc += ltref::distance_exp(la[i], lb[i]);
            g_sink ^= acc;
        });
        row("prefix bits (byte vs clz)", rats, ltn);
    }

    // === 3) Sorted candidate insert: linear 2-pass vs lower_bound vs 1-pass ==
    // The question from review: "is libtorrent's binary search better?"
    // Comparator is held constant (closer_to) so we isolate scan-vs-binsearch +
    // 2-pass-vs-1-pass. Each trial builds a sorted list of M nodes from scratch.
    std::printf("\n  sorted insert — build an M-node candidate list (comparator held constant)\n");
    std::printf("  %-10s  %12s  %12s  %12s\n", "M", "linear-2pass", "lower_bound", "linear-1pass");
    std::printf("  %-10s  %12s  %12s  %12s\n", "----------",
                "(librats)", "(libtorrent)", "(merged)");

    auto insert_linear_2pass = [](std::vector<NodeId>& v, int& sorted,
                                  const NodeId& id, const NodeId& target) {
        for (int i = 0; i < sorted; ++i) if (v[i] == id) return;          // dedup pass
        int pos = 0;
        while (pos < sorted && closer_to(v[pos], id, target)) ++pos;       // position pass
        v.insert(v.begin() + pos, id); ++sorted;
    };
    auto insert_lower_bound = [](std::vector<NodeId>& v, int& sorted,
                                 const NodeId& id, const NodeId& target) {
        auto end = v.begin() + sorted;
        auto it = std::lower_bound(v.begin(), end, id,
            [&](const NodeId& x, const NodeId& y) { return closer_to(x, y, target); });
        if (it == end || *it != id) { v.insert(it, id); ++sorted; }
    };
    auto insert_linear_1pass = [](std::vector<NodeId>& v, int& sorted,
                                  const NodeId& id, const NodeId& target) {
        int pos = 0;
        while (pos < sorted && closer_to(v[pos], id, target)) ++pos;
        if (pos < sorted && v[pos] == id) return;                          // dedup at pos
        v.insert(v.begin() + pos, id); ++sorted;
    };

    for (int M : {16, 64, 128, 256, 512, 1024, 2048}) {
        // Keep total work (~trials * M^2) roughly constant across sizes.
        const long long want = 120000000LL / (static_cast<long long>(M) * M);
        const int trials = static_cast<int>(std::min<long long>(20000, std::max<long long>(30, want)));
        const NodeId target = rand_id();
        std::vector<std::vector<NodeId>> sets(trials);
        for (auto& s : sets) { s.reserve(M); for (int i = 0; i < M; ++i) s.push_back(rand_id()); }

        auto run = [&](auto&& insert) {
            return bench(static_cast<std::size_t>(trials) * M, [&] {
                uint64_t acc = 0;
                std::vector<NodeId> v; v.reserve(M);
                for (auto& s : sets) {
                    v.clear(); int sorted = 0;
                    for (const auto& id : s) insert(v, sorted, id, target);
                    acc += v.front()[0];
                }
                g_sink ^= acc;
            }, 5);
        };
        const double a = run(insert_linear_2pass);
        const double b = run(insert_lower_bound);
        const double c = run(insert_linear_1pass);
        std::printf("  %-10d  %10.2f ns  %10.2f ns  %10.2f ns\n", M, a, b, c);
    }

    std::printf("\n(ns are per-operation; insert rows are per-inserted-node, build cost amortised)\n");
    std::printf("sink=%llu\n", static_cast<unsigned long long>(g_sink));
    return 0;
}
