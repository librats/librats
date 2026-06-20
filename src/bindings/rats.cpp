#include "bindings/rats.h"

#include "node/node.h"
#include "peer/peer_info.h"
#include "subsystems/dht_discovery.h"
#include "subsystems/mdns_discovery.h"
#include "subsystems/port_mapping_service.h"
#include "subsystems/pubsub.h"
#include "subsystems/message_exchange.h"
#include "subsystems/file_transfer.h"
#include "subsystems/ping_service.h"
#include "util/logger.h"
#include "util/json.hpp"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

using namespace librats;

namespace {

// A C handle is a thin owner of the Node plus non-owning pointers to the lazily
// created subsystems (the Node owns those). Subsystems must be attached before
// start(), so the *_enable / first-use calls below are "call before start()".
struct RatsHandle {
    std::unique_ptr<Node> node;
    PubSub*          pubsub   = nullptr;
    MessageExchange* messages = nullptr;
    FileTransfer*    files    = nullptr;
    PingService*     ping     = nullptr;
};

RatsHandle* as_handle(rats_t handle) { return static_cast<RatsHandle*>(handle); }
Node*       node_of(rats_t handle)   { return as_handle(handle)->node.get(); }

char* dup_string(const std::string& s) {
    char* out = static_cast<char*>(std::malloc(s.size() + 1));
    if (out) std::memcpy(out, s.c_str(), s.size() + 1);
    return out;
}

PubSub* ensure_pubsub(RatsHandle* h) {
    if (!h->pubsub) {
        auto p = std::make_unique<PubSub>();
        h->pubsub = p.get();
        h->node->add_subsystem(std::move(p));
    }
    return h->pubsub;
}

MessageExchange* ensure_messages(RatsHandle* h) {
    if (!h->messages) {
        auto m = std::make_unique<MessageExchange>();
        h->messages = m.get();
        h->node->add_subsystem(std::move(m));
    }
    return h->messages;
}

FileTransfer* ensure_files(RatsHandle* h, const std::string& temp_dir) {
    if (!h->files) {
        auto f = std::make_unique<FileTransfer>(temp_dir);
        h->files = f.get();
        h->node->add_subsystem(std::move(f));
    }
    return h->files;
}

PingService* ensure_ping(RatsHandle* h) {
    if (!h->ping) {
        auto p = std::make_unique<PingService>();
        h->ping = p.get();
        h->node->add_subsystem(std::move(p));
    }
    return h->ping;
}

} // namespace

extern "C" {

rats_t rats_create(uint16_t listen_port) {
    NodeConfig config;
    config.listen_port = listen_port;
    auto* h = new RatsHandle();
    h->node = std::make_unique<Node>(std::move(config));
    return h;
}

rats_t rats_create_ex(uint16_t listen_port, int enable_listen,
                      const char* bind_address, rats_security_t security) {
    NodeConfig config;
    config.listen_port = listen_port;
    config.enable_listen = enable_listen != 0;
    if (bind_address) config.bind_address = bind_address;
    config.security = (security == RATS_SECURITY_PLAINTEXT) ? NodeConfig::Security::Plaintext
                                                            : NodeConfig::Security::Noise;
    auto* h = new RatsHandle();
    h->node = std::make_unique<Node>(std::move(config));
    return h;
}

void rats_destroy(rats_t node) { delete as_handle(node); }

int rats_start(rats_t node) { return node_of(node)->start() ? 1 : 0; }

void rats_stop(rats_t node) { node_of(node)->stop(); }

uint16_t rats_listen_port(rats_t node) { return node_of(node)->listen_port(); }

char* rats_local_id(rats_t node) { return dup_string(node_of(node)->local_id().to_hex()); }

void rats_connect(rats_t node, const char* host, uint16_t port) {
    if (host) node_of(node)->connect(std::string(host), port);
}

size_t rats_peer_count(rats_t node) { return node_of(node)->peer_count(); }

void rats_set_max_peers(rats_t node, size_t max_peers) {
    node_of(node)->set_max_peers(max_peers);
}

size_t rats_max_peers(rats_t node) { return node_of(node)->max_peers(); }

void rats_send(rats_t node, const char* peer_id_hex,
               const char* channel, const void* data, size_t len) {
    if (!peer_id_hex || !channel) return;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return;
    node_of(node)->send(*id, channel, ByteView(static_cast<const uint8_t*>(data), len));
}

void rats_broadcast(rats_t node, const char* channel, const void* data, size_t len) {
    if (!channel) return;
    node_of(node)->broadcast(channel, ByteView(static_cast<const uint8_t*>(data), len));
}

void rats_on_peer_connected(rats_t node, rats_peer_cb cb, void* user) {
    if (!cb) return;
    node_of(node)->on_peer_connected([cb, user](const Peer& peer) {
        cb(user, peer.id().to_hex().c_str());
    });
}

void rats_on_peer_disconnected(rats_t node, rats_peer_cb cb, void* user) {
    if (!cb) return;
    node_of(node)->on_peer_disconnected([cb, user](const PeerId& id) {
        cb(user, id.to_hex().c_str());
    });
}

void rats_on_message(rats_t node, const char* channel, rats_message_cb cb, void* user) {
    if (!channel || !cb) return;
    node_of(node)->on_message(channel, [cb, user](const Peer& peer, ByteView data) {
        cb(user, peer.id().to_hex().c_str(), data.data(), data.size());
    });
}

void rats_enable_dht(rats_t node, uint16_t dht_port, const char* discovery_key) {
    DhtDiscovery::Config config;
    config.dht_port = dht_port;
    if (discovery_key) config.discovery_key = discovery_key;
    node_of(node)->add_subsystem(std::make_unique<DhtDiscovery>(std::move(config)));
}

void rats_enable_mdns(rats_t node) {
    node_of(node)->add_subsystem(std::make_unique<MdnsDiscovery>());
}

void rats_enable_port_mapping(rats_t node, int enable_upnp, int enable_natpmp) {
    PortMappingConfig config;
    config.enable_upnp   = enable_upnp != 0;
    config.enable_natpmp = enable_natpmp != 0;
    node_of(node)->add_subsystem(std::make_unique<PortMappingService>(config));
}

/* — peer enumeration — */

char** rats_peer_ids(rats_t node, size_t* count) {
    auto infos = node_of(node)->peers();
    if (count) *count = infos.size();
    if (infos.empty()) return nullptr;
    char** ids = static_cast<char**>(std::malloc(infos.size() * sizeof(char*)));
    if (!ids) { if (count) *count = 0; return nullptr; }
    for (size_t i = 0; i < infos.size(); ++i) ids[i] = dup_string(infos[i].id.to_hex());
    return ids;
}

void rats_free_peer_ids(char** ids, size_t count) {
    if (!ids) return;
    for (size_t i = 0; i < count; ++i) std::free(ids[i]);
    std::free(ids);
}

/* — pub/sub — */

void rats_subscribe(rats_t node, const char* topic, rats_topic_cb cb, void* user) {
    if (!topic || !cb) return;
    ensure_pubsub(as_handle(node))->subscribe(topic,
        [cb, user](const PeerId& from, const std::string& t, ByteView data) {
            cb(user, from.to_hex().c_str(), t.c_str(), data.data(), data.size());
        });
}

void rats_unsubscribe(rats_t node, const char* topic) {
    if (!topic) return;
    if (auto* ps = as_handle(node)->pubsub) ps->unsubscribe(topic);
}

void rats_publish(rats_t node, const char* topic, const void* data, size_t len) {
    if (!topic) return;
    ensure_pubsub(as_handle(node))->publish(topic,
        ByteView(static_cast<const uint8_t*>(data), len));
}

/* — typed JSON messaging — */

void rats_on(rats_t node, const char* type, rats_typed_cb cb, void* user) {
    if (!type || !cb) return;
    ensure_messages(as_handle(node))->on(type,
        [cb, user](const PeerId& from, const nlohmann::json& data) {
            cb(user, from.to_hex().c_str(), data.dump().c_str());
        });
}

void rats_off(rats_t node, const char* type) {
    if (!type) return;
    if (auto* mx = as_handle(node)->messages) mx->off(type);
}

void rats_send_typed(rats_t node, const char* peer_id_hex, const char* type, const char* json) {
    if (!peer_id_hex || !type || !json) return;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return;
    auto j = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded()) return;
    ensure_messages(as_handle(node))->send(*id, type, j);
}

void rats_broadcast_typed(rats_t node, const char* type, const char* json) {
    if (!type || !json) return;
    auto j = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded()) return;
    ensure_messages(as_handle(node))->send(type, j);
}

/* — file transfer — */

void rats_enable_file_transfer(rats_t node, const char* temp_dir) {
    ensure_files(as_handle(node), temp_dir ? temp_dir : ".");
}

void rats_on_file_offer(rats_t node, rats_file_offer_cb cb, void* user) {
    if (!cb) return;
    ensure_files(as_handle(node), ".")->on_offer([cb, user](const FileTransfer::Offer& o) {
        cb(user, o.from.to_hex().c_str(), o.id, o.name.c_str(), o.size, o.is_directory ? 1 : 0);
    });
}

void rats_on_file_progress(rats_t node, rats_file_progress_cb cb, void* user) {
    if (!cb) return;
    ensure_files(as_handle(node), ".")->on_progress([cb, user](const FileTransfer::Progress& p) {
        cb(user, p.id, p.peer.to_hex().c_str(), p.bytes_transferred, p.total_bytes,
           static_cast<int>(p.status));
    });
}

void rats_on_file_complete(rats_t node, rats_file_complete_cb cb, void* user) {
    if (!cb) return;
    ensure_files(as_handle(node), ".")->on_complete(
        [cb, user](uint64_t id, bool success, const std::string& path) {
            cb(user, id, success ? 1 : 0, path.c_str());
        });
}

uint64_t rats_send_file(rats_t node, const char* peer_id_hex, const char* path) {
    if (!peer_id_hex || !path) return 0;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return 0;
    return ensure_files(as_handle(node), ".")->send_file(*id, path);
}

uint64_t rats_send_directory(rats_t node, const char* peer_id_hex, const char* dir_path) {
    if (!peer_id_hex || !dir_path) return 0;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return 0;
    return ensure_files(as_handle(node), ".")->send_directory(*id, dir_path);
}

void rats_accept_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id,
                      const char* dest_path) {
    if (!peer_id_hex || !dest_path) return;
    auto* ft = as_handle(node)->files;
    if (!ft) return;
    auto id = PeerId::from_hex(peer_id_hex);
    if (id) ft->accept(*id, transfer_id, dest_path);
}

void rats_reject_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id) {
    if (!peer_id_hex) return;
    auto* ft = as_handle(node)->files;
    if (!ft) return;
    auto id = PeerId::from_hex(peer_id_hex);
    if (id) ft->reject(*id, transfer_id);
}

int rats_cancel_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id) {
    if (!peer_id_hex) return 0;
    auto* ft = as_handle(node)->files;
    if (!ft) return 0;
    auto id = PeerId::from_hex(peer_id_hex);
    return (id && ft->cancel(*id, transfer_id)) ? 1 : 0;
}

int rats_pause_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id) {
    if (!peer_id_hex) return 0;
    auto* ft = as_handle(node)->files;
    if (!ft) return 0;
    auto id = PeerId::from_hex(peer_id_hex);
    return (id && ft->pause(*id, transfer_id)) ? 1 : 0;
}

int rats_resume_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id) {
    if (!peer_id_hex) return 0;
    auto* ft = as_handle(node)->files;
    if (!ft) return 0;
    auto id = PeerId::from_hex(peer_id_hex);
    return (id && ft->resume(*id, transfer_id)) ? 1 : 0;
}

/* — liveness — */

void rats_enable_ping(rats_t node) { ensure_ping(as_handle(node)); }

int64_t rats_peer_rtt_ms(rats_t node, const char* peer_id_hex) {
    if (!peer_id_hex) return -1;
    auto* p = as_handle(node)->ping;
    if (!p) return -1;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return -1;
    auto rtt = p->last_rtt(*id);
    return rtt ? static_cast<int64_t>(rtt->count()) : -1;
}

/* — logging — */

void rats_set_log_level(rats_log_level_t level) {
    Logger::getInstance().set_log_level(static_cast<LogLevel>(level));
}

void rats_set_log_file(const char* path) {
    auto& logger = Logger::getInstance();
    if (path && path[0] != '\0') {
        logger.set_log_file_path(path);
        logger.set_file_logging_enabled(true);
    } else {
        logger.set_file_logging_enabled(false);
    }
}

/* — utility — */

void rats_string_free(char* str) { std::free(str); }

} // extern "C"
