#pragma once

/**
 * @file dialer.h
 * @brief Picks the transport for an outbound connection, and races the fallback.
 *
 * With two equal transports available, "connect to this address" stops being one
 * action. UDP is the better first choice for a peer-to-peer node — one socket and
 * one NAT mapping for every peer, and a source port that is actually dialable —
 * but some networks block or throttle it, and finding that out by waiting for a
 * dial to time out would be unacceptable. So a dial is a small race, in the
 * spirit of Happy Eyeballs (RFC 8305):
 *
 *   t = 0                start the preferred transport
 *   t = fallback_delay   if it has not established yet, start the other one too
 *   first to establish   wins; every other attempt for this target is closed
 *   all attempts failed  report the dial as failed, exactly once
 *
 * Racing rather than falling back sequentially matters: on a UDP-hostile network
 * the cost is the fallback delay, not a full connect timeout, and on a normal
 * network the second attempt is never made at all.
 *
 * Cancelling the loser is the reason Reactor::connect hands back a ConnId
 * synchronously — without it the redundant attempt would complete, and the peer
 * table's duplicate resolution (which cannot tell a raced sibling from a genuine
 * reconnect) might well keep the wrong one.
 *
 * Threading: dial() is called from any thread; the attempt callbacks arrive on
 * reactor threads. One mutex guards the (small) bookkeeping; nothing on the data
 * path goes through here.
 */

#include "librats/core/types.h"
#include "librats/peer/peer_table.h"   // PeerRoute
#include "librats/transport/reactor_pool.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace librats {

struct DialPolicy {
    TransportKind             preferred = TransportKind::Udp;
    bool                      allow_tcp = true;
    bool                      allow_udp = true;
    std::chrono::milliseconds fallback_delay{1200};
};

class Dialer {
public:
    /// Called once per target when every attempt has failed. Reactor thread.
    using FailureHandler = std::function<void(const std::string& host, uint16_t port)>;

    Dialer(ReactorPool& reactors, DialPolicy policy, FailureHandler on_failed)
        : reactors_(reactors), policy_(policy), on_failed_(std::move(on_failed)) {}

    /// Begin dialing `host:port`. Non-blocking; the outcome surfaces through the
    /// node's peer-connected / dial-failed events.
    void dial(const std::string& host, uint16_t port);

    // — attempt outcomes, reported by the Node (reactor thread) —

    /// An attempt completed its handshake; it wins the target.
    void on_established(PeerRoute route);
    /// An attempt ended (failed, was superseded, or simply closed later).
    void on_closed(PeerRoute route);

    /// Accept dials again after a stop() — a Node may be restarted.
    void start();

    /// Drop all bookkeeping; no further dials or fallbacks are started.
    void stop();

    /// Attempts currently in flight (diagnostics/tests).
    size_t in_flight() const;

private:
    struct Target {
        std::string                host;
        uint16_t                   port = 0;
        std::vector<TransportKind> pending;  ///< transports not yet tried, in order
        std::vector<PeerRoute>     routes;   ///< attempts currently in flight
        bool                       won = false;
    };

    using Key = std::pair<uint8_t, ConnId>;  ///< (reactor, conn) — unique per attempt

    /// Start the next available transport in `target`'s queue; false if the queue
    /// is exhausted (nothing was started). Caller holds the mutex — and must
    /// report a resulting failure only after releasing it.
    bool start_next(const std::shared_ptr<Target>& target);
    /// Arm the timer that brings the second transport in. Caller holds the mutex.
    void arm_fallback(const std::shared_ptr<Target>& target, Reactor& reactor);

    std::vector<TransportKind> transport_order() const;

    ReactorPool&   reactors_;
    DialPolicy     policy_;
    FailureHandler on_failed_;

    mutable std::mutex                        mutex_;
    std::map<Key, std::shared_ptr<Target>>    attempts_;
    bool                                      stopped_ = false;
};

} // namespace librats
