// ─────────────────────────────────────────────────────────────────────────────
//  bench_mem.cpp — memory-footprint benchmark for librats::Json vs the reference
//  DOM libraries (nlohmann::json, RapidJSON).
//
//  Time and memory are measured by *separate* executables on purpose: the
//  allocation instrumentation here (a global operator new/delete that tags every
//  block with its size) adds a small per-allocation cost that would unfairly
//  penalise allocation-heavy DOMs in the timing run. Keeping it in its own binary
//  leaves bench_json's numbers pristine.
//
//  Two metrics are reported per parsed DOM:
//    • resident bytes — net heap still held while the DOM is alive (the input
//      string is allocated before the measurement window, so it is excluded);
//    • allocation count — how many separate allocations building it took, the
//      real driver behind the per-node-`new` vs arena gap.
//
//  All three libraries are routed through the same global operator new: librats
//  and nlohmann use it natively; RapidJSON is given a custom allocator that
//  forwards to it, so its arena chunks are counted on equal terms.
// ─────────────────────────────────────────────────────────────────────────────

#include "bench.h"
#include "bench_data.h"
#include "util/json.h"
// "stable" baseline: json.{h,cpp} from the previous commit (HEAD~1, fc81b94) under
// namespace librats_stable, so the last commit's effect on heap footprint and
// allocation count is visible side-by-side with the current librats::Json.
#include "stable_json.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <vector>

#if defined(BENCH_HAVE_NLOHMANN) || __has_include(<nlohmann/json.hpp>)
#  include <nlohmann/json.hpp>
#  define HAVE_NLOHMANN 1
#endif

#if defined(BENCH_HAVE_RAPIDJSON) || __has_include(<rapidjson/document.h>)
#  include <rapidjson/document.h>
#  define HAVE_RAPIDJSON 1
#endif

using bench::do_not_optimize;
using namespace benchdata;

// ── Allocation accounting ────────────────────────────────────────────────────
//
// Every block carries a 16-byte header holding its size, so operator delete can
// update the live-byte total exactly regardless of which delete form is used.

namespace {

struct Counters {
    std::size_t live   = 0;  // bytes currently outstanding (running total)
    std::size_t allocs = 0;  // cumulative allocation count
};
Counters g_mem;

constexpr std::size_t kHeader = 16;  // preserves 16-byte alignment for the payload

void* tracked_alloc(std::size_t n) {
    void* base = std::malloc(n + kHeader);
    if (!base) throw std::bad_alloc();
    *static_cast<std::size_t*>(base) = n;
    g_mem.live += n;
    g_mem.allocs += 1;
    return static_cast<char*>(base) + kHeader;
}

void tracked_free(void* p) noexcept {
    if (!p) return;
    void* base = static_cast<char*>(p) - kHeader;
    g_mem.live -= *static_cast<std::size_t*>(base);
    std::free(base);
}

}  // namespace

void* operator new(std::size_t n) { return tracked_alloc(n); }
void* operator new[](std::size_t n) { return tracked_alloc(n); }
void operator delete(void* p) noexcept { tracked_free(p); }
void operator delete[](void* p) noexcept { tracked_free(p); }
void operator delete(void* p, std::size_t) noexcept { tracked_free(p); }
void operator delete[](void* p, std::size_t) noexcept { tracked_free(p); }

// ── RapidJSON allocator that forwards to the tracked operator new ────────────

#ifdef HAVE_RAPIDJSON
namespace {
struct OpNewAllocator {
    static const bool kNeedFree = true;
    void* Malloc(std::size_t size) { return size ? ::operator new(size) : nullptr; }
    void* Realloc(void* p, std::size_t oldSize, std::size_t newSize) {
        if (newSize == 0) { if (p) ::operator delete(p); return nullptr; }
        void* np = ::operator new(newSize);
        if (p) {
            std::memcpy(np, p, oldSize < newSize ? oldSize : newSize);
            ::operator delete(p);
        }
        return np;
    }
    static void Free(void* p) noexcept { if (p) ::operator delete(p); }
    bool operator==(const OpNewAllocator&) const { return true; }
    bool operator!=(const OpNewAllocator&) const { return false; }
};
using RjPool = rapidjson::MemoryPoolAllocator<OpNewAllocator>;
using RjDoc  = rapidjson::GenericDocument<rapidjson::UTF8<>, RjPool, OpNewAllocator>;
}  // namespace
#endif

// ── Measurement ──────────────────────────────────────────────────────────────

namespace {

struct Stat {
    std::size_t bytes  = 0;
    std::size_t allocs = 0;
};

// Build a DOM via `make`, snapshot the heap it holds while alive, then let it die.
template <typename Make>
Stat measure(Make&& make) {
    std::size_t live0 = g_mem.live, alloc0 = g_mem.allocs;
    auto dom = make();
    do_not_optimize(dom);
    Stat s{g_mem.live - live0, g_mem.allocs - alloc0};
    return s;  // `dom` is destroyed here, after `s` is captured
}

std::string human(std::size_t b) {
    char buf[32];
    double v = static_cast<double>(b);
    if (v >= 1024.0 * 1024.0) std::snprintf(buf, sizeof buf, "%.2f MB", v / (1024.0 * 1024.0));
    else if (v >= 1024.0)     std::snprintf(buf, sizeof buf, "%.1f KB", v / 1024.0);
    else                      std::snprintf(buf, sizeof buf, "%zu B", b);
    return buf;
}

void report_dataset(const char* name, const std::string& src) {
    const double in = static_cast<double>(src.size());
    std::printf("\n  %-9s (input %s)\n", name, human(src.size()).c_str());

    auto line = [&](const char* lib, const Stat& s) {
        std::printf("    %-10s %10s   %5.2fx input   %6zu allocs\n",
                    lib, human(s.bytes).c_str(),
                    in > 0 ? static_cast<double>(s.bytes) / in : 0.0, s.allocs);
    };

    line("librats", measure([&] { return librats::Json::parse(src); }));
    line("stable", measure([&] { return librats_stable::Json::parse(src); }));
#ifdef HAVE_NLOHMANN
    line("nlohmann", measure([&] { return nlohmann::json::parse(src); }));
#endif
#ifdef HAVE_RAPIDJSON
    line("rapidjson", measure([&] {
        RjDoc d;
        d.Parse(src.c_str(), src.size());
        return d;
    }));
#endif
}

}  // namespace

int main() {
    const auto peers = make_peers(256);
    const std::string peers_src    = peers_to_json(peers);
    const std::string numbers_src  = make_numbers_json(2000);
    const std::string strings_src  = make_strings_json(1000);
    const std::string integers_src = make_integers_json(10000);
    const std::string longstr_src  = make_long_strings_json(500, 256);
    const std::string bigobj_src   = make_large_object_json(1000);

    std::printf("JSON DOM memory footprint  "
                "(resident heap held by a parsed DOM, and allocation count)\n");
    std::printf("reference libs:");
#ifdef HAVE_NLOHMANN
    std::printf(" nlohmann");
#endif
#ifdef HAVE_RAPIDJSON
    std::printf(" rapidjson");
#endif
    std::printf("\nper-value size: sizeof(librats::Json) = %zu bytes  "
                "(stable = %zu bytes)\n",
                sizeof(librats::Json), sizeof(librats_stable::Json));
    std::printf("note: RapidJSON reserves arena memory in 64 KB chunks, so its "
                "resident figure is rounded up to whole chunks.\n");

    report_dataset("peers", peers_src);
    report_dataset("numbers", numbers_src);
    report_dataset("strings", strings_src);
    report_dataset("integers", integers_src);
    report_dataset("longstr", longstr_src);
    report_dataset("bigobj", bigobj_src);

    std::printf("\nlower resident bytes and fewer allocations are better\n");
    return 0;
}
