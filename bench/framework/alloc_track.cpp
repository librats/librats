#include "framework/alloc_track.h"

#include <cstdlib>
#include <new>

#if defined(_WIN32)
#  include <malloc.h>
#  define BENCH_USABLE_SIZE(p) _msize(p)
#elif defined(__APPLE__)
#  include <malloc/malloc.h>
#  define BENCH_USABLE_SIZE(p) malloc_size(p)
#else
#  include <malloc.h>
#  define BENCH_USABLE_SIZE(p) malloc_usable_size(p)
#endif

namespace track {

Stats g_stats;

void reset() { g_stats = Stats{}; }

Stats snapshot() { return g_stats; }

}  // namespace track

namespace {

inline void* tracked_alloc(std::size_t n) {
    // A zero-sized new must still return a unique pointer.
    void* p = std::malloc(n ? n : 1);
    if (!p) return nullptr;
    const std::size_t got = BENCH_USABLE_SIZE(p);
    track::g_stats.allocs += 1;
    track::g_stats.bytes += got;
    track::g_stats.live += static_cast<std::int64_t>(got);
    if (track::g_stats.live > track::g_stats.peak) track::g_stats.peak = track::g_stats.live;
    return p;
}

inline void tracked_free(void* p) noexcept {
    if (!p) return;
    track::g_stats.frees += 1;
    track::g_stats.live -= static_cast<std::int64_t>(BENCH_USABLE_SIZE(p));
    std::free(p);
}

}  // namespace

void* operator new(std::size_t n) {
    void* p = tracked_alloc(n);
    if (!p) throw std::bad_alloc();
    return p;
}
void* operator new[](std::size_t n) {
    void* p = tracked_alloc(n);
    if (!p) throw std::bad_alloc();
    return p;
}
void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return tracked_alloc(n); }
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return tracked_alloc(n); }

void operator delete(void* p) noexcept { tracked_free(p); }
void operator delete[](void* p) noexcept { tracked_free(p); }
void operator delete(void* p, std::size_t) noexcept { tracked_free(p); }
void operator delete[](void* p, std::size_t) noexcept { tracked_free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { tracked_free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { tracked_free(p); }
