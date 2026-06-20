#pragma once

/**
 * @file reconnection.h
 * @brief Keeps connections to a set of peer addresses alive with backoff.
 *
 * A Subsystem that remembers peer addresses (optionally persisted via PeerStore)
 * and re-dials them when they drop, using exponential backoff. Built only on
 * PeerNetwork: it dials via connect(), learns addresses from peer events, and
 * matches a disconnected peer back to its target by the address it was dialed at
 * (populated into PeerInfo for outbound connections).
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
#include "peer/peer_store.h"

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
        std::string               store_path = "";          ///< persist targets (empty = memory only)
        bool                      persist_discovered = true; ///< remember dialed peers automatically
        size_t                    max_targets = 1024;        ///< cap on remembered targets (bounds memory + store growth)
        size_t                    max_attempts = 0;          ///< give up (drop the target) after this many consecutive failed dials; 0 = retry forever
        std::chrono::milliseconds base_backoff{1000};
        std::chrono::milliseconds max_backoff{60000};
        std::chrono::milliseconds tick{1000};
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

    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

private:
    struct Target {
        Address                               address;
        bool                                  connected = false;
        PeerId                                peer_id;
        int                                   attempts = 0;
        std::chrono::steady_clock::time_point next_attempt;
    };

    void on_connected(const Peer& peer);
    void on_disconnected(const PeerId& id);
    void loop();
    std::chrono::milliseconds backoff_for(int attempts) const;

    Config                      config_;
    PeerNetwork*                network_ = nullptr;
    // Built once in the constructor (when store_path is set) and never reassigned,
    // so the pointer is safe to read from any thread; PeerStore is itself internally
    // synchronized. (Creating it in start() raced reads from on_connected, which can
    // fire on a reactor thread before this subsystem's start() returns.)
    std::unique_ptr<PeerStore>  store_;

    std::thread             thread_;
    std::atomic<bool>       running_{false};
    std::mutex              wait_mutex_;
    std::condition_variable wake_;

    mutable std::mutex                       mutex_;
    std::unordered_map<std::string, Target>  targets_;  ///< keyed by address string
};

} // namespace librats
