#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  bench.h — a tiny, self-contained micro-benchmark harness.
//
//  Header-only, zero dependencies, project-agnostic. Drop it into any C++17
//  project to measure and *compare* the hot paths of competing implementations
//  with statistically honest numbers and a readable, colourised report.
//
//  Design goals:
//    • Honest timing — auto-calibrates iteration counts to a target wall-time,
//      warms the caches/branch-predictor, then takes several rounds and reports
//      the median (robust to OS jitter) alongside the best and a spread bar.
//    • No accidental dead-code elimination — bench::do_not_optimize() / clobber()
//      keep the optimizer from deleting the very work you are timing.
//    • Comparison-first — benchmarks are grouped; within a group every entry is
//      ranked against the fastest one ("1.00x  ← best", "2.4x", …).
//    • Pretty by default — aligned columns, human units (ns/µs/ms, K/M/G ops,
//      MB/s), ANSI colour when stdout is a TTY (auto-enabled on Windows 10+).
//
//  Quick start:
//
//      #include "bench.h"
//      int main() {
//          bench::Bench b("My benchmarks");
//          b.group("hashing 1 KiB");
//          b.bytes(1024);                       // enables MB/s for this group
//          b.run("std::hash", []{ ... });
//          b.run("mine",      []{ ... });
//          b.report();                          // (also runs on destruction)
//      }
//
//  Tuning (optional):  b.config().min_time = 0.5;  b.config().rounds = 9;
//
// ─────────────────────────────────────────────────────────────────────────────

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <io.h>       // _isatty
#  include <windows.h>  // console VT enable
#else
#  include <unistd.h>   // isatty
#endif

namespace bench {

// ── Optimizer barriers ───────────────────────────────────────────────────────
//
// Keep a value "observable" so the compiler may not delete the code producing
// it, and force pending memory writes to be considered side-effecting.

#if defined(__GNUC__) || defined(__clang__)
template <typename T>
inline void do_not_optimize(const T& value) {
    asm volatile("" : : "r,m"(value) : "memory");
}
template <typename T>
inline void do_not_optimize(T& value) {
#  if defined(__clang__)
    asm volatile("" : "+r,m"(value) : : "memory");
#  else
    asm volatile("" : "+m,r"(value) : : "memory");
#  endif
}
inline void clobber() { asm volatile("" : : : "memory"); }
#else  // MSVC and friends
namespace detail {
inline void use_ptr(const volatile void* p) {
    static const volatile void* sink;
    sink = p;
}
}  // namespace detail
template <typename T>
inline void do_not_optimize(const T& value) {
    detail::use_ptr(&value);
    _ReadWriteBarrier();
}
inline void clobber() { _ReadWriteBarrier(); }
#endif

// ── Configuration ────────────────────────────────────────────────────────────

struct Config {
    double min_time = 0.40;  // total wall-time target per benchmark (seconds)
    int    rounds   = 7;     // measured rounds; the median across them is reported
    int    warmup   = 1;     // warm-up rounds (timed but discarded)
    double calib    = 0.030; // per-round calibration floor (seconds)
    bool   color    = true;  // colourise when attached to a TTY
};

// ── A single measured benchmark ──────────────────────────────────────────────

class Result {
public:
    std::string name;
    std::string group;
    std::size_t iters = 0;             // iterations inside one round
    std::vector<double> round_ns;      // ns *per op* for each measured round
    double bytes = 0;                  // payload bytes per op (0 → hide MB/s)
    double items = 0;                  // logical items per op (0 → hide items/s)

    // Fluent annotations (applied after timing; throughput is derived lazily).
    Result& set_bytes(double b) { bytes = b; return *this; }
    Result& set_items(double n) { items = n; return *this; }

    double median() const { return percentile(0.5); }
    double best() const {
        return round_ns.empty() ? 0.0
                                 : *std::min_element(round_ns.begin(), round_ns.end());
    }
    // Spread as a coefficient of variation (%), a compact jitter indicator.
    double cv_percent() const {
        if (round_ns.size() < 2) return 0.0;
        double m = 0;
        for (double v : round_ns) m += v;
        m /= round_ns.size();
        if (m == 0) return 0.0;
        double s = 0;
        for (double v : round_ns) s += (v - m) * (v - m);
        s = std::sqrt(s / (round_ns.size() - 1));
        return 100.0 * s / m;
    }

private:
    double percentile(double p) const {
        if (round_ns.empty()) return 0.0;
        std::vector<double> v = round_ns;
        std::sort(v.begin(), v.end());
        double idx = p * (v.size() - 1);
        std::size_t lo = static_cast<std::size_t>(idx);
        double frac = idx - lo;
        if (lo + 1 < v.size()) return v[lo] * (1 - frac) + v[lo + 1] * frac;
        return v[lo];
    }
};

// ── The harness ──────────────────────────────────────────────────────────────

class Bench {
public:
    explicit Bench(std::string title = "Benchmarks") : title_(std::move(title)) {
        detect_color();
    }
    ~Bench() {
        if (!reported_ && !results_.empty()) report();
#if defined(_WIN32)
        // Restore the console code page we switched to UTF-8 in detect_color(),
        // so we don't leave the user's shell in a changed state.
        if (prev_output_cp_ && prev_output_cp_ != CP_UTF8)
            SetConsoleOutputCP(prev_output_cp_);
#endif
    }

    Config& config() { return cfg_; }

    // Start a new comparison group. Within a group, entries are ranked against
    // the fastest member.
    Bench& group(std::string name) {
        cur_group_ = std::move(name);
        cur_bytes_ = 0;
        cur_items_ = 0;
        return *this;
    }
    // Default payload size / item count applied to subsequent run()s in the
    // current group (each run may still override via the returned Result).
    Bench& bytes(double b) { cur_bytes_ = b; return *this; }
    Bench& items(double n) { cur_items_ = n; return *this; }

    // Measure `fn`. Returns the Result so you can chain .set_bytes()/.set_items().
    template <typename Fn>
    Result& run(const std::string& name, Fn&& fn) {
        Result r;
        r.name  = name;
        r.group = cur_group_;
        r.bytes = cur_bytes_;
        r.items = cur_items_;

        // 1) Calibrate: grow the per-round iteration count until a round takes
        //    at least `calib` seconds (so the clock's resolution is negligible).
        std::size_t iters = 1;
        const double round_target =
            std::max(cfg_.calib, cfg_.min_time / std::max(1, cfg_.rounds));
        for (;;) {
            double t = time_batch(fn, iters);
            if (t >= round_target || iters >= (std::size_t{1} << 31)) break;
            double scale = (t > 1e-9) ? (round_target / t) * 1.25 : 4.0;
            scale = std::min(std::max(scale, 1.5), 100.0);
            std::size_t next = static_cast<std::size_t>(iters * scale);
            iters = std::max(next, iters + 1);
        }
        r.iters = iters;

        // 2) Warm-up rounds (discarded), then the measured rounds.
        for (int i = 0; i < cfg_.warmup; ++i) time_batch(fn, iters);
        for (int i = 0; i < cfg_.rounds; ++i) {
            double t = time_batch(fn, iters);
            r.round_ns.push_back(t * 1e9 / static_cast<double>(iters));
        }

        results_.push_back(std::move(r));
        return results_.back();
    }

    void report();

private:
    template <typename Fn>
    static double time_batch(Fn&& fn, std::size_t iters) {
        using clock = std::chrono::steady_clock;
        auto t0 = clock::now();
        for (std::size_t i = 0; i < iters; ++i) fn();
        auto t1 = clock::now();
        return std::chrono::duration<double>(t1 - t0).count();
    }

    void detect_color() {
#if defined(_WIN32)
        is_tty_ = _isatty(_fileno(stdout)) != 0;
        // The report prints UTF-8 glyphs (µs, ·, ←, ±). A classic cmd console
        // defaults to an OEM code page (e.g. 437/866) and would render those as
        // mojibake ("тЖР", "┬╖"), so switch console output to UTF-8. Harmless
        // when stdout is a file/pipe; restored in the destructor.
        prev_output_cp_ = GetConsoleOutputCP();
        if (prev_output_cp_ != CP_UTF8) SetConsoleOutputCP(CP_UTF8);
        if (is_tty_) {
            HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
            DWORD mode = 0;
            if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
                SetConsoleMode(h, mode | 0x0004 /*ENABLE_VIRTUAL_TERMINAL_PROCESSING*/);
            }
        }
#else
        is_tty_ = isatty(fileno(stdout)) != 0;
#endif
    }
    bool use_color() const { return cfg_.color && is_tty_; }

    std::string title_;
    Config cfg_;
    std::string cur_group_;
    double cur_bytes_ = 0;
    double cur_items_ = 0;
    std::vector<Result> results_;
    bool is_tty_ = false;
    bool reported_ = false;
#if defined(_WIN32)
    unsigned int prev_output_cp_ = 0;  // console code page before we forced UTF-8
#endif
};

// ── Formatting helpers ───────────────────────────────────────────────────────

namespace detail {

inline std::string fmt_time(double ns) {
    char buf[32];
    const char* unit = "ns";
    double v = ns;
    if (v >= 1e9)      { v /= 1e9; unit = "s "; }
    else if (v >= 1e6) { v /= 1e6; unit = "ms"; }
    else if (v >= 1e3) { v /= 1e3; unit = "\xC2\xB5s"; }  // µs (UTF-8)
    std::snprintf(buf, sizeof buf, "%7.2f %s", v, unit);
    return buf;
}

inline std::string fmt_rate(double per_sec) {
    char buf[32];
    const char* unit = " ";
    double v = per_sec;
    if (v >= 1e9)      { v /= 1e9; unit = "G"; }
    else if (v >= 1e6) { v /= 1e6; unit = "M"; }
    else if (v >= 1e3) { v /= 1e3; unit = "K"; }
    std::snprintf(buf, sizeof buf, "%7.2f %s", v, unit);
    return buf;
}

inline std::string fmt_mbps(double bytes_per_op, double ns_per_op) {
    if (bytes_per_op <= 0 || ns_per_op <= 0) return std::string(11, ' ');
    double mbps = (bytes_per_op / 1e6) / (ns_per_op / 1e9);
    char buf[32];
    std::snprintf(buf, sizeof buf, "%8.1f MB/s", mbps);
    return buf;
}

inline std::string fmt_items(double items_per_op, double ns_per_op) {
    if (items_per_op <= 0 || ns_per_op <= 0) return std::string(11, ' ');
    double ips = items_per_op / (ns_per_op / 1e9);  // logical items per second
    const char* unit = " ";
    double v = ips;
    if (v >= 1e9)      { v /= 1e9; unit = "G"; }
    else if (v >= 1e6) { v /= 1e6; unit = "M"; }
    else if (v >= 1e3) { v /= 1e3; unit = "K"; }
    char buf[32];
    std::snprintf(buf, sizeof buf, "%6.2f %sit/s", v, unit);
    return buf;
}

// Pad a UTF-8-ish string to a visible width (good enough for our ASCII labels).
inline std::string pad(const std::string& s, std::size_t w, bool left = true) {
    if (s.size() >= w) return s;
    std::string p(w - s.size(), ' ');
    return left ? s + p : p + s;
}

}  // namespace detail

inline void Bench::report() {
    reported_ = true;
    const bool c = use_color();
    auto col = [&](const char* code) { return c ? code : ""; };
    const char* RESET = col("\x1b[0m");
    const char* DIM   = col("\x1b[2m");
    const char* BOLD  = col("\x1b[1m");
    const char* CYAN  = col("\x1b[36m");
    const char* GREEN = col("\x1b[32m");
    const char* YELL  = col("\x1b[33m");
    const char* RED   = col("\x1b[31m");

    std::printf("\n%s%s%s%s\n", BOLD, CYAN, title_.c_str(), RESET);

    // Group results in first-seen order.
    std::vector<std::string> order;
    for (const auto& r : results_)
        if (std::find(order.begin(), order.end(), r.group) == order.end())
            order.push_back(r.group);

    // Column widths.
    std::size_t name_w = 4;
    for (const auto& r : results_) name_w = std::max(name_w, r.name.size());
    name_w = std::max<std::size_t>(name_w, 8);

    for (const auto& g : order) {
        std::vector<const Result*> rs;
        for (const auto& r : results_)
            if (r.group == g) rs.push_back(&r);
        if (rs.empty()) continue;

        double fastest = rs.front()->median();
        for (auto* r : rs) fastest = std::min(fastest, r->median());

        bool any_bytes = false;
        bool any_items = false;
        for (auto* r : rs) {
            any_bytes = any_bytes || r->bytes > 0;
            any_items = any_items || r->items > 0;
        }
        // A group reports MB/s when it has payload bytes, else items/s when it
        // has a logical item count, else no throughput column.
        const char* thr_hdr = any_bytes ? "  throughput"
                            : any_items ? "     items/s"
                                        : "           ";

        // Header.
        std::printf("\n  %s%s%s\n", BOLD, g.c_str(), RESET);
        std::printf("  %s%s   %s     %s   %s   %svs best%s\n", DIM,
                    detail::pad("name", name_w).c_str(),
                    detail::pad("time/op", 12, false).c_str(),
                    detail::pad("ops/s", 11, false).c_str(),
                    thr_hdr,
                    "", RESET);

        for (auto* r : rs) {
            double med = r->median();
            double ratio = (fastest > 0) ? med / fastest : 1.0;
            bool is_best = (r == *std::min_element(
                                rs.begin(), rs.end(),
                                [](const Result* a, const Result* b) {
                                    return a->median() < b->median();
                                }));

            const char* rc = is_best ? GREEN : (ratio <= 1.5 ? "" : (ratio <= 3.0 ? YELL : RED));
            rc = c ? rc : "";

            std::string ratio_s;
            {
                char buf[32];
                std::snprintf(buf, sizeof buf, "%.2fx", ratio);
                ratio_s = buf;
            }

            double ops = med > 0 ? 1e9 / med : 0;
            std::string thr = any_bytes ? detail::fmt_mbps(r->bytes, med)
                            : any_items ? detail::fmt_items(r->items, med)
                                        : std::string(11, ' ');

            std::printf("  %s%s%s   %s   %s   %s   %s%s%s%s",
                        rc, detail::pad(r->name, name_w).c_str(), RESET,
                        detail::fmt_time(med).c_str(),
                        detail::fmt_rate(ops).c_str(),
                        thr.c_str(),
                        rc, detail::pad(ratio_s, 7).c_str(), RESET,
                        is_best ? "" : "");
            if (is_best)
                std::printf("  %s\xE2\x86\x90 best%s", GREEN, RESET);
            // Jitter note when a run was noisy.
            double cv = r->cv_percent();
            if (cv >= 8.0)
                std::printf("   %s\xC2\xB1%.0f%%%s", DIM, cv, RESET);
            std::printf("\n");
        }
    }
    std::printf("\n%smedian of %d rounds · %zu measured benchmarks · "
                "lower time/op is better%s\n",
                DIM, cfg_.rounds, results_.size(), RESET);
    std::fflush(stdout);
}

}  // namespace bench
