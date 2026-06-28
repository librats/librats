#pragma once

/**
 * @file rpc_manager.h
 * @brief Tracks outstanding DHT queries: transaction ids, timeouts, anti-spoofing.
 *
 * One unified place for every query the node sends — lookups, liveness pings,
 * bootstrap — each represented by an Observer. invoke() stamps a transaction id,
 * encodes and sends the message, and remembers it; handle_response() matches a reply
 * back to its observer (only if it came from the very endpoint we queried) and
 * dispatches it; tick() ages out the silent ones with a two-level timeout.
 *
 * Single-threaded actor: no locks, and time is passed in rather than read from a
 * clock, so behaviour is fully deterministic and testable.
 */

#include "core/address.h"
#include "dht/observer.h"
#include "dht/transport.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <random>
#include <unordered_map>

namespace librats {
struct KrpcMessage;

namespace dht {

class RpcManager {
public:
    // After the short timeout we free the query's concurrency slot but keep waiting;
    // after the full timeout we give up on it.
    static constexpr std::chrono::milliseconds kShortTimeout{2000};
    static constexpr std::chrono::milliseconds kFullTimeout{15000};

    explicit RpcManager(Transport& transport)
        : transport_(transport), rng_(std::random_device{}()) {}

    // Stamp a transaction id on `msg`, send it to `to`, and register `obs` to receive
    // the outcome. Returns false if the message could not be encoded.
    bool invoke(KrpcMessage& msg, const Address& to, const ObserverPtr& obs, TimePoint now);

    // Send a query we don't track the reply to (e.g. announce_peer). Fire-and-forget.
    void send_oneshot(KrpcMessage& msg, const Address& to);

    // Route a reply/error back to its observer. Returns true only if it matched an
    // outstanding query AND arrived from the endpoint we queried (anti-spoofing);
    // unmatched or spoofed replies are ignored.
    bool handle_response(const KrpcMessage& msg, const Address& from, TimePoint now);

    // Fire short/full timeouts for queries that have gone quiet. Call periodically.
    void tick(TimePoint now);

    // Forget the in-flight query for `obs`, if any (the traversal is abandoning it).
    void cancel(Observer* obs);

    std::size_t outstanding() const noexcept { return pending_.size(); }

private:
    struct Pending {
        ObserverPtr obs;
        Address     endpoint;
        TimePoint   sent;
    };

    uint16_t next_txn();

    Transport& transport_;
    std::unordered_map<uint16_t, Pending> pending_;
    std::mt19937 rng_;  // seeds unpredictable transaction ids (anti-spoofing)
};

} // namespace dht
} // namespace librats
