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
 *
 * UDP is a deliberate exception to the round-robin. Every UDP connection shares
 * one socket — that is the point of it — so the mux, and therefore every stream
 * on it, belongs to the single reactor that owns that socket. Sharding those
 * across threads would mean handing datagrams between reactors on every packet,
 * which costs more than the parallelism buys. pick() honours that by routing UDP
 * dials to the mux's reactor and everything else round-robin.
 */

#include "librats/transport/reactor.h"

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

    /// Hand the shared UDP socket to the acceptor reactor (index 0), which then
    /// owns every datagram connection. Before start().
    void listen_udp(socket_t udp_socket, AddressFamily family) {
        reactors_[0]->listen_udp(udp_socket, family);
    }

    /// Whether the pool can carry UDP connections at all.
    bool has_udp() const noexcept { return reactors_[0]->has_udp(); }

    void start() { for (auto& r : reactors_) r->start(); }
    void stop()  { for (auto& r : reactors_) r->stop(); }

    size_t   size() const noexcept { return reactors_.size(); }
    Reactor& by_index(uint8_t i) noexcept { return *reactors_[i]; }

    /// Choose a reactor for a new outbound connection over `kind`. UDP always
    /// lands on the reactor that owns the socket it must go out on; anything else
    /// is spread round-robin.
    Reactor& pick(TransportKind kind = TransportKind::Tcp) noexcept {
        if (kind == TransportKind::Udp) return *reactors_[0];
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
