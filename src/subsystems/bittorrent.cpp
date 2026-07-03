#include "subsystems/bittorrent.h"
#include "subsystems/dht_service.h"
#include "node/node_context.h"
#include "util/logger.h"

#include <chrono>
#include <memory>
#include <thread>
#include <utility>

namespace librats {

Bittorrent::Bittorrent(Config config) : config_(std::move(config)) {}

Bittorrent::Bittorrent(const bittorrent::Client::Config& client_config) {
    config_.client = client_config;
}

Bittorrent::~Bittorrent() { stop(); }

void Bittorrent::attach(NodeContext& ctx) {
    // We only need the service registry — to discover a sibling DhtDiscovery at
    // start(). BitTorrent runs its own transport, so it never touches ctx.network.
    services_ = &ctx.services;
}

void Bittorrent::start() {
    if (client_) return;  // already running
    client_ = std::make_unique<bittorrent::Client>(config_.client);

    // Borrow the node's DHT swarm if a DhtDiscovery published one and it is up.
    // set_external_dht() must be called before start(); otherwise the client runs
    // DHT-less (trackers/PEX/manual peers still work).
    shared_dht_ = false;
    if (config_.use_node_dht && services_) {
        if (auto* svc = services_->get<DhtService>()) {
            if (DhtClient* shared = svc->dht_client()) {
                client_->set_external_dht(shared);
                shared_dht_ = true;
            }
        }
    }
    LOG_INFO("bt.node", (shared_dht_ ? "sharing the node's DHT swarm"
                                     : "running BitTorrent without a DHT"));

    client_->start();
}

void Bittorrent::stop() {
    if (!client_) return;

    // Wake every in-flight metadata watcher and wait for them to finish before we
    // tear down client_, so a watcher's reactor.post() can't race teardown.
    {
        std::unique_lock<std::mutex> lk(meta_mutex_);
        meta_stopping_ = true;
        meta_cv_.notify_all();
        meta_drain_cv_.wait(lk, [&] { return meta_inflight_ == 0; });
    }

    client_->stop();   // never stops the borrowed external DHT (owner's lifecycle)
    client_.reset();
    shared_dht_ = false;

    std::lock_guard<std::mutex> lk(meta_mutex_);
    meta_stopping_ = false;  // ready for a future start()
}

DhtClient* Bittorrent::active_dht() const {
    return client_ ? client_->get_dht_client() : nullptr;
}

//=============================================================================
// Spider mode wrappers
//=============================================================================

void Bittorrent::set_spider_mode(bool enable) {
    if (auto* d = active_dht()) d->set_spider_mode(enable);
    else LOG_WARN("bt.node", "set_spider_mode ignored: no shared DHT");
}

bool Bittorrent::is_spider_mode() const {
    auto* d = active_dht();
    return d && d->is_spider_mode();
}

void Bittorrent::set_spider_announce_callback(SpiderAnnounceCallback callback) {
    if (auto* d = active_dht()) d->set_spider_announce_callback(std::move(callback));
    else LOG_WARN("bt.node", "set_spider_announce_callback ignored: no shared DHT");
}

void Bittorrent::set_spider_ignore(bool ignore) {
    if (auto* d = active_dht()) d->set_spider_ignore(ignore);
}

bool Bittorrent::is_spider_ignoring() const {
    auto* d = active_dht();
    return d && d->is_spider_ignoring();
}

void Bittorrent::spider_walk() {
    if (auto* d = active_dht()) d->spider_walk();
}

size_t Bittorrent::spider_pool_size() const {
    auto* d = active_dht();
    return d ? d->get_spider_pool_size() : 0;
}

size_t Bittorrent::spider_visited_count() const {
    auto* d = active_dht();
    return d ? d->get_spider_visited_count() : 0;
}

void Bittorrent::clear_spider_state() {
    if (auto* d = active_dht()) d->clear_spider_state();
}

//=============================================================================
// Metadata-only fetch (BEP 9)
//=============================================================================

void Bittorrent::get_torrent_metadata(const std::string& info_hash_hex,
                                      MetadataCallback callback, int timeout_ms) {
    fetch_metadata_impl(info_hash_hex, "", 0, /*direct=*/false, std::move(callback), timeout_ms);
}

void Bittorrent::get_torrent_metadata_from_peer(const std::string& info_hash_hex,
                                                const std::string& ip, uint16_t port,
                                                MetadataCallback callback, int timeout_ms) {
    fetch_metadata_impl(info_hash_hex, ip, port, /*direct=*/true, std::move(callback), timeout_ms);
}

void Bittorrent::fetch_metadata_impl(const std::string& info_hash_hex, const std::string& ip,
                                     uint16_t port, bool direct, MetadataCallback callback,
                                     int timeout_ms) {
    if (!client_) {
        if (callback) callback(bittorrent::TorrentInfo{}, false, "bittorrent not running");
        return;
    }
    auto ih = bittorrent::info_hash_from_hex(info_hash_hex);
    if (!ih) {
        if (callback) callback(bittorrent::TorrentInfo{}, false, "invalid info hash");
        return;
    }

    // Completion state shared between the (reactor-thread) metadata callback and
    // the watcher thread that waits on it.
    struct State {
        bool                    done = false;
        bool                    success = false;
        bittorrent::TorrentInfo info;
    };
    auto state = std::make_shared<State>();

    {
        std::lock_guard<std::mutex> lk(meta_mutex_);
        if (meta_stopping_) {
            if (callback) callback(bittorrent::TorrentInfo{}, false, "shutting down");
            return;
        }
        ++meta_inflight_;
    }

    // All Client mutations happen on its reactor thread.
    const std::string magnet = "magnet:?xt=urn:btih:" + info_hash_hex;
    client_->reactor().post([this, magnet, ip, port, direct, state] {
        bittorrent::Torrent* t = client_->add_magnet(magnet);
        if (!t) {
            std::lock_guard<std::mutex> lk(meta_mutex_);
            state->done = true;
            meta_cv_.notify_all();
            return;
        }
        t->set_metadata_callback([this, state](const bittorrent::TorrentInfo& info) {
            std::lock_guard<std::mutex> lk(meta_mutex_);
            if (state->done) return;
            state->info    = info;
            state->success = true;
            state->done    = true;
            meta_cv_.notify_all();
        });
        if (direct && !ip.empty() && port != 0) t->add_peer(ip, port);
    });

    std::thread([this, ih = *ih, callback = std::move(callback), timeout_ms, state] {
        bool                    success = false;
        bittorrent::TorrentInfo info;
        {
            std::unique_lock<std::mutex> wl(meta_mutex_);
            meta_cv_.wait_for(wl, std::chrono::milliseconds(timeout_ms),
                              [&] { return state->done || meta_stopping_; });
            state->done = true;  // block any late metadata callback
            success = state->success;
            info    = state->info;
        }

        // Drop the temporary torrent on the reactor thread. client_ is alive:
        // stop() waits on meta_drain_cv_ until meta_inflight_ hits 0.
        if (client_) client_->reactor().post([this, ih] { client_->remove_torrent(ih); });

        if (callback)
            callback(info, success, success ? std::string() : std::string("metadata timeout"));

        std::lock_guard<std::mutex> dl(meta_mutex_);
        --meta_inflight_;
        meta_drain_cv_.notify_all();
    }).detach();
}

} // namespace librats
