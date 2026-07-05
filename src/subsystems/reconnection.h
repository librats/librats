#pragma once

/**
 * @file reconnection.h
 * @brief Keeps connections to a set of peer addresses alive with backoff.
 *
 * A Subsystem that remembers peer addresses (optionally persisted via PeerBook)
 * and re-dials them when they drop, using exponential backoff. Built only on
 * PeerNetwork: it dials via connect() and, each tick, reconciles its targets
 * against the set of currently-connected peers (PeerNetwork::peers(), whose
 * addresses include the dialable endpoints learned via identify). A target whose
 * address is served by a live peer — over ANY route, inbound or outbound — is
 * left alone; only the rest are dialed. Reconciling against this snapshot, rather
 * than trusting a flag toggled on the connect event, is what stops us from
 * endlessly re-dialing a peer already connected over a link we did not initiate
 * (an inbound link, or a cross-connect the directory resolved to the other side).
 *
 * A target is dropped when the app calls remove(), or — if Config::max_attempts
 * is set — after that many consecutive failed dials without ever connecting (it
 * "gives up", freeing memory and pruning the store). A successful connection
 * resets the attempt counter, so only persistently-dead addresses are reaped.
 */

#include "node/peer_network.h"
#include "peer/peer.h"
#include "core/address.h"
#include "peer/peer_id.h"
#include "peer/peer_book.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace librats {

class ReconnectionService final : public Subsystem {
public:
    struct Config {
        std::string               store_path = "";          ///< persist the peer book here (empty = memory only)
        bool                      persist_discovered = true; ///< remember dialed peers automatically
        size_t                    max_targets = 1024;        ///< cap on ACTIVE re-dial targets (bounds memory + dial fan-out)
        size_t                    max_attempts = 0;          ///< give up actively dialing a target after this many consecutive failures; 0 = retry forever
        size_t                    startup_targets = 32;      ///< on start, actively re-dial this many best peers from the book
        size_t                    archive_max = 4096;        ///< cap on the persistent peer book (history of everyone we met)
        std::chrono::seconds      archive_max_age{std::chrono::hours(24 * 30)};  ///< forget peers unseen this long (30 days)
        std::chrono::milliseconds base_backoff{1000};
        std::chrono::milliseconds max_backoff{60000};
        std::chrono::milliseconds tick{1000};
        std::chrono::milliseconds dial_timeout{15000};  ///< assume an in-flight dial is dead after this if no connect/fail event arrives (backstop only)
    };

    ReconnectionService();
    explicit ReconnectionService(Config config);
    ~ReconnectionService() override;

    /// Register an address to keep connected. Persists it if a store is configured.
    void add(const Address& address);

    /// Stop reconnecting to an address: drops it as a target and from the store.
    /// Use when the application intentionally parts with a peer and does not want
    /// it re-dialed. (A later fresh connection to it may re-learn it if
    /// persist_discovered is on.)
    void remove(const Address& address);

    size_t target_count() const;

    /// The passive reserve pool: up to n best-known peer addresses from the book
    /// (history of everyone we have connected to), most promising first. Not dialed
    /// automatically beyond the startup seed — exposed for the app / discovery to
    /// use as a bootstrap source when peer count is low.
    std::vector<Address> known_peers(size_t n) const;

    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

private:
    struct Target {
        Address                               address;
        bool                                  dialing = false;  ///< a connect() is in flight; don't pile on a duplicate
        int                                   attempts = 0;     ///< failed dials since the target was last seen connected
        std::chrono::steady_clock::time_point next_attempt;     ///< earliest time to (re)dial
        std::chrono::steady_clock::time_point dial_deadline;    ///< backstop: give up waiting on the in-flight dial after this

        /// Record that this target is connected as of `now`: no dial is in flight
        /// any more and the failure streak resets, so a later drop re-dials at once
        /// (an address that just worked earns no backoff penalty). Used by BOTH the
        /// loop's live-snapshot reconciliation and the on_connected event, so the
        /// two paths that clear an in-flight dial can never drift apart.
        void mark_connected(std::chrono::steady_clock::time_point now) {
            dialing      = false;
            attempts     = 0;
            next_attempt = now;
        }
    };

    void on_connected(const Peer& peer);
    void on_disconnected(const PeerId& id);
    void on_dial_failed(const Address& address);
    void loop();
    std::chrono::milliseconds backoff_for(int attempts) const;

    Config                      config_;
    PeerNetwork*                network_ = nullptr;
    // Built once in the constructor (when store_path is set) and never reassigned,
    // so the pointer is safe to read from any thread; PeerBook is itself internally
    // synchronized. (Creating it in start() raced reads from on_connected, which can
    // fire on a reactor thread before this subsystem's start() returns.)
    std::unique_ptr<PeerBook>   book_;

    std::thread             thread_;
    std::atomic<bool>       running_{false};
    std::mutex              wait_mutex_;
    std::condition_variable wake_;

    mutable std::mutex                       mutex_;
    std::unordered_map<Address, Target>      targets_;  ///< keyed by the peer Address
};

} // namespace librats
