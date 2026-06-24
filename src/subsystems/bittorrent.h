#pragma once

/**
 * @file bittorrent.h
 * @brief BitTorrent as a node Subsystem — wraps BtClient and shares the node's DHT.
 *
 * Attach it like any other subsystem, BEFORE start():
 *
 *     auto* dht = node.add_subsystem(std::make_unique<DhtDiscovery>(dht_cfg));
 *     auto* bt  = node.add_subsystem(std::make_unique<Bittorrent>(bt_cfg));
 *     node.start();
 *     bt->client()->add_magnet("magnet:?xt=urn:btih:…", "./downloads");
 *
 * BitTorrent keeps its own transport (its BtNetworkManager runs its own sockets and
 * the swarm protocol), so this subsystem does NOT touch the node's peer mesh. What
 * it integrates is lifecycle and the DHT: when a DhtDiscovery is also attached, the
 * client borrows that same Kademlia node (DhtService) instead of standing up a
 * second one — one routing table, one swarm. Attach Bittorrent AFTER DhtDiscovery
 * so the borrowed client is live at start() and (thanks to reverse-order teardown)
 * still alive through stop(). Without a DhtDiscovery it falls back to a private DHT.
 *
 * Spider mode (the rats-search infohash crawler) lives in the DHT layer; the
 * wrappers here delegate to whichever DHT the client ended up using.
 */

#include "node/peer_network.h"          // Subsystem, NodeContext (fwd)
#include "bittorrent/bt_client.h"       // BtClient, BtClientConfig, DhtClient, SpiderAnnounceCallback

#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace librats {

class ServiceRegistry;

class Bittorrent final : public Subsystem {
public:
    struct Config {
        BtClientConfig client;        ///< download path, listen port, limits, …
        bool           use_node_dht = true;  ///< borrow DhtDiscovery's DHT if attached
    };

    Bittorrent() = default;
    explicit Bittorrent(Config config);
    /// Convenience: configure the underlying client directly, share the node DHT.
    explicit Bittorrent(const BtClientConfig& client_config);
    ~Bittorrent() override;

    Bittorrent(const Bittorrent&) = delete;
    Bittorrent& operator=(const Bittorrent&) = delete;

    // — Subsystem —
    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

    /// The underlying client — drive torrents through it (add_magnet,
    /// add_torrent_file, add_torrent_for_seeding, …). Non-null between start() and
    /// stop(); nullptr otherwise.
    BtClient*       client() noexcept { return client_.get(); }
    const BtClient* client() const noexcept { return client_.get(); }

    bool is_running()      const { return client_ && client_->is_running(); }
    /// True when start() borrowed the node's DHT rather than a dedicated one.
    bool using_node_dht()  const noexcept { return shared_dht_; }

    //=========================================================================
    // Spider mode (rats-search) — DHT-wide infohash crawling.
    // Delegates to the active DHT (shared node DHT, or the client's own).
    // No-op / zero before start().
    //=========================================================================
    void   set_spider_mode(bool enable);
    bool   is_spider_mode() const;
    void   set_spider_announce_callback(SpiderAnnounceCallback callback);
    void   set_spider_ignore(bool ignore);
    bool   is_spider_ignoring() const;
    void   spider_walk();
    size_t spider_pool_size() const;
    size_t spider_visited_count() const;
    void   clear_spider_state();

    //=========================================================================
    // Metadata-only fetch (BEP 9) — the convenience the old monolithic client
    // exposed, restored here for rats-search's spider and on-demand lookups.
    //
    // Adds a temporary metadata-only magnet torrent, waits up to timeout_ms for
    // its metadata to arrive, then removes the temporary torrent and invokes
    // `callback` with the result (success=false on timeout). `callback` runs on
    // an internal worker thread; it is invoked exactly once. No-op-fail if the
    // subsystem is not running.
    //=========================================================================
    using MetadataCallback = std::function<void(const TorrentInfo& info, bool success,
                                                const std::string& error)>;

    /// Fetch metadata by searching the DHT for peers that have it.
    void get_torrent_metadata(const std::string& info_hash_hex,
                              MetadataCallback callback, int timeout_ms = 60000);

    /// Fetch metadata directly from a known peer (skips the DHT search) — the
    /// fast path used when a spider announce told us exactly who has it.
    void get_torrent_metadata_from_peer(const std::string& info_hash_hex,
                                        const std::string& ip, uint16_t port,
                                        MetadataCallback callback, int timeout_ms = 60000);

private:
    /// The DHT the client is actually using (external or its own), or nullptr.
    DhtClient* active_dht() const;

    /// Shared body for both get_torrent_metadata* entry points.
    void fetch_metadata_impl(const std::string& info_hash_hex, const std::string& ip,
                             uint16_t port, bool direct, MetadataCallback callback,
                             int timeout_ms);

    Config                    config_;
    ServiceRegistry*          services_ = nullptr;
    std::unique_ptr<BtClient> client_;
    bool                      shared_dht_ = false;

    // In-flight metadata watchers. Each runs detached; stop() signals them to
    // exit early and waits for the count to drain before tearing down client_,
    // so a watcher's client_->remove_torrent() never races teardown.
    std::mutex              meta_mutex_;
    std::condition_variable meta_cv_;        ///< metadata arrived OR stopping
    std::condition_variable meta_drain_cv_;  ///< a watcher finished
    bool                    meta_stopping_ = false;
    int                     meta_inflight_ = 0;
};

} // namespace librats
