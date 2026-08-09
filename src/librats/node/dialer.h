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
 * ── Not paying for the same discovery twice ─────────────────────────────────
 * A peer says in its identify message which wires it accepts. Racing is how a
 * dial finds that out when it has nothing to go on; paying the fallback delay
 * *again*, on every later dial to an address that already told us, is pure loss —
 * and a reconnection policy redials the same handful of addresses for the life of
 * the node. So the dialer keeps a small cache of address → transports (fed by
 * Node::handle_identify) and starts with a transport the peer actually has.
 *
 * Two properties make that safe to act on:
 *   - It reorders, it never removes. Knowledge can be stale — a peer restarts
 *     with a different config — and a stale entry must cost a fallback delay,
 *     never a target that cannot be dialed at all. The transport the peer did not
 *     claim stays in the queue behind the one it did.
 *   - Only addresses the node can vouch for are recorded (see the caller). A
 *     peer's self-advertised address list is its unverified word about where
 *     anyone lives, so it is not allowed to set the dial order for someone else.
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
#include <unordered_map>
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
    using Clock = std::chrono::steady_clock;

    /// Called once per target when every attempt has failed. Reactor thread.
    using FailureHandler = std::function<void(const std::string& host, uint16_t port)>;

    /// Addresses the transports cache holds. A node meets far more addresses than
    /// it will ever redial (DHT and PEX see thousands), so this is a cache with a
    /// ceiling, not a directory: past it the least recently learned entry goes.
    static constexpr size_t kMaxRemembered = 1024;

    /// How long a learned transports mask is trusted. A peer may restart on a
    /// different config, and an entry that outlives the truth would send every
    /// dial to a wire the peer no longer has — which costs the very fallback delay
    /// this cache exists to avoid.
    static constexpr std::chrono::minutes kMemoryTtl{10};

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

    /// Record which transports the peer reachable at `host:port` said it accepts
    /// (a PeerTransports bitmask from its identify message). A later dial to the
    /// same address starts with one of them instead of spending the fallback delay
    /// rediscovering it. A mask of 0 ("did not say") is ignored rather than stored
    /// as "supports nothing". Thread-safe; called from a reactor thread.
    void remember(const std::string& host, uint16_t port, uint8_t transports);

    /// What is currently believed about `host:port`, 0 if nothing (or if what was
    /// learned has expired). Diagnostics and tests.
    uint8_t known_transports(const std::string& host, uint16_t port) const;

    /// The transports a dial to `host:port` would try, in order — exactly what
    /// dial() computes, without starting anything. Diagnostics and tests.
    std::vector<TransportKind> planned_order(const std::string& host, uint16_t port) const;

    /// Accept dials again after a stop() — a Node may be restarted. What identify
    /// taught us about addresses is knowledge about the network rather than
    /// in-flight bookkeeping, so it deliberately survives the cycle.
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

    /// What one address last told us about itself.
    struct Known {
        uint8_t           transports = 0;
        Clock::time_point learned_at{};
    };

    /// Start the next available transport in `target`'s queue; false if the queue
    /// is exhausted (nothing was started). Caller holds the mutex — and must
    /// report a resulting failure only after releasing it.
    bool start_next(const std::shared_ptr<Target>& target);
    /// Arm the timer that brings the second transport in. Caller holds the mutex.
    void arm_fallback(const std::shared_ptr<Target>& target, Reactor& reactor);

    /// The transports to try, in order: what the policy allows, with anything the
    /// peer at this address said it accepts (`known`, 0 for "no idea") moved to
    /// the front. Reorders only — see the note at the top of this file.
    std::vector<TransportKind> transport_order(uint8_t known) const;

    /// What is known about `host:port`, 0 if nothing or if it has expired. Caller
    /// holds the mutex.
    uint8_t recall(const std::string& host, uint16_t port) const;
    /// Make room for one entry in a full cache. Caller holds the mutex.
    void    evict_one(Clock::time_point now);

    static std::string key_for(const std::string& host, uint16_t port);

    ReactorPool&   reactors_;
    DialPolicy     policy_;
    FailureHandler on_failed_;

    mutable std::mutex                        mutex_;
    std::map<Key, std::shared_ptr<Target>>    attempts_;
    std::unordered_map<std::string, Known>    known_;   ///< address → transports it accepts
    bool                                      stopped_ = false;
};

} // namespace librats
