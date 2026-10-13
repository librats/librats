#pragma once

/**
 * @file token_bucket.h
 * @brief A rate held on average: `rate` bytes a second, up to `depth` of them at once.
 *
 * The bucket fills at the rate and holds at most `depth`; what a flow sends is
 * taken out. So a flow that keeps to the rate on average is never held back, a
 * burst of up to `depth` passes as it comes, and only what goes on above the
 * rate for longer waits. The bucket may also be overdrawn — spent on something
 * that had to go regardless — and then nothing more fits until the debt is
 * repaid at the rate.
 *
 * Not thread-safe; whoever owns it serialises access.
 */

#include <algorithm>
#include <chrono>
#include <cstdint>

namespace librats {

class TokenBucket {
public:
    using Clock = std::chrono::steady_clock;

    /// No rate at all: everything fits, always.
    TokenBucket() = default;

    /// Full from the start. A zero `rate` is no rate.
    TokenBucket(uint64_t rate, uint64_t depth, Clock::time_point now) noexcept
        : rate_(static_cast<double>(rate)),
          depth_(static_cast<double>((std::max)(depth, uint64_t{1}))),
          tokens_(depth_),
          at_(now) {}

    bool limited() const noexcept { return rate_ > 0; }

    /// Take `bytes` if they fit now.
    bool take(uint64_t bytes, Clock::time_point now) noexcept {
        if (!limited()) return true;
        refill(now);
        if (tokens_ < static_cast<double>(bytes)) return false;
        tokens_ -= static_cast<double>(bytes);
        return true;
    }

    /// Take `bytes` whether or not they fit, going into debt if need be.
    void spend(uint64_t bytes, Clock::time_point now) noexcept {
        if (!limited()) return;
        refill(now);
        tokens_ -= static_cast<double>(bytes);
    }

    /// Whether more has been spent than the rate has made up for.
    bool in_debt(Clock::time_point now) noexcept {
        if (!limited()) return false;
        refill(now);
        return tokens_ < 0;
    }

    /// When `bytes` will fit (now, if they do). Never later than the time the
    /// debt and `bytes` take to accrue, whatever happens in between.
    Clock::time_point fits_at(uint64_t bytes, Clock::time_point now) const noexcept {
        if (!limited()) return now;
        const double have = (std::min)(depth_, tokens_ + rate_ * seconds(now - at_));
        const double need = static_cast<double>(bytes) - have;
        if (need <= 0) return now;
        return now + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(need / rate_));
    }

private:
    static double seconds(Clock::duration d) noexcept {
        return std::chrono::duration<double>(d).count();
    }

    void refill(Clock::time_point now) noexcept {
        if (now <= at_) return;
        tokens_ = (std::min)(depth_, tokens_ + rate_ * seconds(now - at_));
        at_     = now;
    }

    double            rate_   = 0;   ///< bytes per second; 0 = no rate
    double            depth_  = 0;
    double            tokens_ = 0;
    Clock::time_point at_{};
};

} // namespace librats
