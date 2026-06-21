#include "subsystems/bittorrent.h"
#include "subsystems/dht_service.h"
#include "node/node_context.h"
#include "dht/dht.h"
#include "util/logger.h"

#include <utility>

namespace librats {

Bittorrent::Bittorrent(Config config) : config_(std::move(config)) {}

Bittorrent::Bittorrent(const BtClientConfig& client_config) {
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
    client_ = std::make_unique<BtClient>(config_.client);

    // Share the node's DHT swarm if a DhtDiscovery published one and it is up;
    // set_external_dht() must be called before BtClient::start(). Otherwise the
    // client brings up its own DHT on its listen port.
    shared_dht_ = false;
    if (config_.use_node_dht && services_) {
        if (auto* svc = services_->get<DhtService>()) {
            if (DhtClient* shared = svc->dht_client()) {
                client_->set_external_dht(shared);
                shared_dht_ = true;
            }
        }
    }
    LOG_INFO("bittorrent", (shared_dht_ ? "Sharing the node's DHT swarm"
                                        : "Using a dedicated BitTorrent DHT"));

    client_->start();
}

void Bittorrent::stop() {
    if (!client_) return;
    client_->stop();   // never stops a borrowed external DHT (owner's lifecycle)
    client_.reset();
    shared_dht_ = false;
}

DhtClient* Bittorrent::active_dht() const {
    return client_ ? client_->get_dht_client() : nullptr;
}

//=============================================================================
// Spider mode wrappers
//=============================================================================

void Bittorrent::set_spider_mode(bool enable) {
    if (auto* d = active_dht()) d->set_spider_mode(enable);
    else LOG_WARN("bittorrent", "set_spider_mode ignored: no DHT (call start() first)");
}

bool Bittorrent::is_spider_mode() const {
    auto* d = active_dht();
    return d && d->is_spider_mode();
}

void Bittorrent::set_spider_announce_callback(SpiderAnnounceCallback callback) {
    if (auto* d = active_dht()) d->set_spider_announce_callback(std::move(callback));
    else LOG_WARN("bittorrent", "set_spider_announce_callback ignored: no DHT (call start() first)");
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

} // namespace librats
