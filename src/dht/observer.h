#pragma once

/**
 * @file observer.h
 * @brief One outstanding query to a single node.
 *
 * An Observer is both the RPC callback the RpcManager invokes when a reply or
 * timeout arrives, and the little bag of per-node state (id, endpoint, flags) the
 * issuer tracks. It is owned via shared_ptr by whoever started the query (a
 * Traversal); the RpcManager holds a shared_ptr only while the query is in flight,
 * and takes a local copy across each callback so an observer can't be freed in the
 * middle of handling its own reply (e.g. if the traversal truncates it meanwhile).
 *
 * Observers reference their Traversal by plain reference, never owning it, so there
 * is no ownership cycle to untangle.
 */

#include "core/address.h"
#include "dht/id.h"

#include <chrono>
#include <cstdint>
#include <memory>

namespace librats {
struct KrpcMessage;  // defined in dht/krpc.h; only referenced by const& here

namespace dht {

using TimePoint = std::chrono::steady_clock::time_point;

class Observer {
public:
    enum Flag : uint8_t {
        kQueried      = 1 << 0,  // a query was sent
        kAlive        = 1 << 1,  // a reply was received
        kFailed       = 1 << 2,  // fully timed out / errored
        kShortTimeout = 1 << 3,  // exceeded the short timeout (slot freed, still waiting)
        kInitial      = 1 << 4,  // a seed/router node (id may be unknown until it replies)
        kDone         = 1 << 5,  // abandoned by the traversal; ignore any late reply
    };

    Observer(const NodeId& id, const Address& endpoint) : id_(id), endpoint_(endpoint) {}
    virtual ~Observer() = default;
    Observer(const Observer&) = delete;
    Observer& operator=(const Observer&) = delete;

    const NodeId&  id() const noexcept { return id_; }
    const Address& endpoint() const noexcept { return endpoint_; }

    bool has(Flag f) const noexcept { return (flags_ & f) != 0; }
    void set(Flag f) noexcept { flags_ = static_cast<uint8_t>(flags_ | f); }

    // Invoked by the RpcManager exactly once, when the query resolves.
    virtual void on_response(const KrpcMessage& msg, uint16_t rtt_ms, TimePoint now) = 0;
    virtual void on_timeout(TimePoint now) = 0;
    virtual void on_short_timeout(TimePoint now) = 0;

protected:
    NodeId  id_;
    Address endpoint_;
    uint8_t flags_ = 0;

private:
    friend class RpcManager;
    uint16_t txn_ = 0;  // transaction id, owned by the RpcManager while in flight
};

using ObserverPtr = std::shared_ptr<Observer>;

} // namespace dht
} // namespace librats
