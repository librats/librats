#pragma once

/**
 * @file reactor_pool.h
 * @brief A fixed set of reactors; connections are sharded across them.
 *
 * Default size 1 — a single reactor, which is plenty for thousands of peers.
 * Larger pools shard outbound connections round-robin; because each Connection
 * is pinned to one reactor for life, nothing on the data path needs to change as
 * the pool grows. (Sharding *inbound* connections across reactors — handing an
 * accepted fd to a non-acceptor reactor — is a future enhancement; for now a
 * single reactor accepts and owns inbound connections.)
 */

#include "core/reactor.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>

namespace librats {

class ReactorPool {
public:
    ReactorPool(size_t count, ConnectionDelegate& delegate, SecurityProvider& security) {
        if (count == 0) count = 1;
        reactors_.reserve(count);
        for (size_t i = 0; i < count; ++i)
            reactors_.push_back(std::make_unique<Reactor>(static_cast<uint8_t>(i), delegate, security));
    }

    /// Hand the listening socket to the acceptor reactor (index 0). Before start().
    void listen(socket_t server_socket) { reactors_[0]->listen(server_socket); }

    void start() { for (auto& r : reactors_) r->start(); }
    void stop()  { for (auto& r : reactors_) r->stop(); }

    size_t   size() const noexcept { return reactors_.size(); }
    Reactor& by_index(uint8_t i) noexcept { return *reactors_[i]; }

    /// Choose a reactor for a new outbound connection (round-robin).
    Reactor& pick() noexcept {
        const size_t i = next_.fetch_add(1, std::memory_order_relaxed) % reactors_.size();
        return *reactors_[i];
    }

    template <typename F>
    void for_each(F&& fn) { for (auto& r : reactors_) fn(*r); }

    size_t connection_count() const noexcept {
        size_t total = 0;
        for (const auto& r : reactors_) total += r->connection_count();
        return total;
    }

private:
    std::vector<std::unique_ptr<Reactor>> reactors_;
    std::atomic<size_t>                   next_{0};
};

} // namespace librats
