#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  alloc_track.h — global operator new/delete instrumentation.
//
//  "How many times did this touch the allocator, and how much heap did it hold
//  at the peak" is half the story of a buffer, so the benchmark overrides the
//  global operator new/delete and counts.
//
//  The block size on free comes from the allocator itself (_msize /
//  malloc_usable_size), NOT from a header prepended to every allocation: a
//  header would change the size class of every block and perturb the very thing
//  being measured. Overhead is one usable-size lookup plus three adds per
//  allocation — paid identically by the old and the new implementation, so the
//  comparison stays fair. (bench_json/bench_mem split into two binaries for the
//  same reason; here the allocation behaviour *is* the subject, so it is worth
//  measuring in-place.)
// ─────────────────────────────────────────────────────────────────────────────

#include <cstddef>
#include <cstdint>

namespace track {

struct Stats {
    std::uint64_t allocs = 0;  ///< operator new / new[] calls
    std::uint64_t frees  = 0;  ///< operator delete / delete[] calls
    std::uint64_t bytes  = 0;  ///< total bytes ever handed out (churn)
    std::int64_t  live   = 0;  ///< bytes currently held
    std::int64_t  peak   = 0;  ///< high-water of `live`
};

/// Live counters. Reset with scope(), read with snapshot().
extern Stats g_stats;

/// Zero the counters (call at the top of a scenario).
void reset();

/// Read them back.
Stats snapshot();

/// RAII: reset on entry, capture on exit into `out`.
struct Scope {
    explicit Scope(Stats& out) : out_(out) { reset(); }
    ~Scope() { out_ = snapshot(); }
    Stats& out_;
};

}  // namespace track
