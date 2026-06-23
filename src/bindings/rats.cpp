#include "bindings/rats.h"

#include "node/node.h"
#include "peer/peer_info.h"
#include "subsystems/dht_discovery.h"
#include "subsystems/mdns_discovery.h"
#include "subsystems/port_mapping_service.h"
#include "subsystems/pubsub.h"
#include "subsystems/message_json.h"
#include "subsystems/file_transfer.h"
#include "subsystems/ping_service.h"
#include "subsystems/reconnection.h"
#include "core/address.h"
#include "util/logger.h"
#include "util/json.h"
#include "util/version.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

using namespace librats;

namespace {

// A C handle is a thin owner of the Node plus non-owning pointers to the
// subsystems it has enabled (the Node owns those). Subsystems are explicit: each
// rats_enable_* attaches one before start() and records it here; the *_enabled
// flags dedup the enables that don't keep a pointer. `started` gates the
// before-start contract so enables after start() can be rejected cleanly.
struct RatsHandle {
    std::unique_ptr<Node> node;
    PubSub*              pubsub    = nullptr;
    MessageJson*         messages  = nullptr;
    FileTransfer*        files     = nullptr;
    PingService*         ping      = nullptr;
    ReconnectionService* reconnect = nullptr;
    std::string data_dir;  ///< copied from NodeConfig so subsystems can co-locate state
    bool dht_enabled     = false;
    bool mdns_enabled    = false;
    bool portmap_enabled = false;
    bool started         = false;
};

// Build a handle around a freshly-constructed Node, remembering the data_dir
// (the config is moved into the Node, so copy it out first) for subsystems that
// co-locate persistent state (DHT routing table, reconnection store).
RatsHandle* make_handle(NodeConfig config) {
    auto* h = new RatsHandle();
    h->data_dir = config.data_dir;
    h->node = std::make_unique<Node>(std::move(config));
    return h;
}

RatsHandle* as_handle(rats_t handle) { return static_cast<RatsHandle*>(handle); }
Node*       node_of(rats_t handle)   { return as_handle(handle)->node.get(); }

char* dup_string(const std::string& s) {
    char* out = static_cast<char*>(std::malloc(s.size() + 1));
    if (out) std::memcpy(out, s.c_str(), s.size() + 1);
    return out;
}

} // namespace

extern "C" {

const char* rats_error_str(rats_error_t err) {
    switch (err) {
        case RATS_OK:                  return "RATS_OK";
        case RATS_ERR_INVALID_ARG:     return "RATS_ERR_INVALID_ARG";
        case RATS_ERR_NOT_STARTED:     return "RATS_ERR_NOT_STARTED";
        case RATS_ERR_ALREADY_STARTED: return "RATS_ERR_ALREADY_STARTED";
        case RATS_ERR_NOT_ENABLED:     return "RATS_ERR_NOT_ENABLED";
        case RATS_ERR_NO_SUCH_PEER:    return "RATS_ERR_NO_SUCH_PEER";
        case RATS_ERR_BIND:            return "RATS_ERR_BIND";
        case RATS_ERR_INTERNAL:        return "RATS_ERR_INTERNAL";
    }
    return "RATS_ERR_UNKNOWN";
}

/* — construction / lifecycle — */

rats_config_t rats_config_default(void) {
    rats_config_t c;
    c.listen_port      = 0;
    c.enable_listen    = 1;
    c.bind_address     = nullptr;
    c.security         = RATS_SECURITY_NOISE;
    c.data_dir         = nullptr;
    c.protocol         = nullptr;
    c.max_peers        = 0;
    return c;
}

rats_t rats_create_config(const rats_config_t* cfg) {
    NodeConfig config;
    if (cfg) {
        config.listen_port   = cfg->listen_port;
        config.enable_listen = cfg->enable_listen != 0;
        if (cfg->bind_address)     config.bind_address     = cfg->bind_address;
        config.security = (cfg->security == RATS_SECURITY_PLAINTEXT) ? NodeConfig::Security::Plaintext
                                                                     : NodeConfig::Security::Noise;
        if (cfg->data_dir)         config.data_dir         = cfg->data_dir;
        if (cfg->protocol)         config.protocol         = cfg->protocol;
        config.max_peers = cfg->max_peers;
    }
    return make_handle(std::move(config));
}

rats_t rats_create(uint16_t listen_port) {
    NodeConfig config;
    config.listen_port = listen_port;
    return make_handle(std::move(config));
}

rats_t rats_create_ex(uint16_t listen_port, int enable_listen,
                      const char* bind_address, rats_security_t security) {
    NodeConfig config;
    config.listen_port = listen_port;
    config.enable_listen = enable_listen != 0;
    if (bind_address) config.bind_address = bind_address;
    config.security = (security == RATS_SECURITY_PLAINTEXT) ? NodeConfig::Security::Plaintext
                                                            : NodeConfig::Security::Noise;
    return make_handle(std::move(config));
}

void rats_destroy(rats_t node) { delete as_handle(node); }

rats_error_t rats_start(rats_t node) {
    auto* h = as_handle(node);
    if (h->started) return RATS_ERR_ALREADY_STARTED;
    if (!h->node->start()) return RATS_ERR_BIND;
    h->started = true;
    return RATS_OK;
}

void rats_stop(rats_t node) { node_of(node)->stop(); }

uint16_t rats_listen_port(rats_t node) { return node_of(node)->listen_port(); }

char* rats_local_id(rats_t node) { return dup_string(node_of(node)->local_id().to_hex()); }

/* — connections — */

rats_error_t rats_connect(rats_t node, const char* host, uint16_t port) {
    if (!host) return RATS_ERR_INVALID_ARG;
    node_of(node)->connect(std::string(host), port);
    return RATS_OK;
}

size_t rats_peer_count(rats_t node) { return node_of(node)->peer_count(); }

void rats_set_max_peers(rats_t node, size_t max_peers) {
    node_of(node)->set_max_peers(max_peers);
}

size_t rats_max_peers(rats_t node) { return node_of(node)->max_peers(); }

/* — messaging — */

rats_error_t rats_send(rats_t node, const char* peer_id_hex,
                       const char* channel, const void* data, size_t len) {
    if (!peer_id_hex || !channel) return RATS_ERR_INVALID_ARG;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return RATS_ERR_INVALID_ARG;
    if (!node_of(node)->peer(*id)) return RATS_ERR_NO_SUCH_PEER;
    node_of(node)->send(*id, channel, ByteView(static_cast<const uint8_t*>(data), len));
    return RATS_OK;
}

rats_error_t rats_broadcast(rats_t node, const char* channel, const void* data, size_t len) {
    if (!channel) return RATS_ERR_INVALID_ARG;
    node_of(node)->broadcast(channel, ByteView(static_cast<const uint8_t*>(data), len));
    return RATS_OK;
}

rats_error_t rats_on_peer_connected(rats_t node, rats_peer_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    node_of(node)->on_peer_connected([cb, user](const Peer& peer) {
        cb(user, peer.id().to_hex().c_str());
    });
    return RATS_OK;
}

rats_error_t rats_on_peer_disconnected(rats_t node, rats_peer_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    node_of(node)->on_peer_disconnected([cb, user](const PeerId& id) {
        cb(user, id.to_hex().c_str());
    });
    return RATS_OK;
}

rats_error_t rats_on(rats_t node, const char* channel, rats_message_cb cb, void* user) {
    if (!channel || !cb) return RATS_ERR_INVALID_ARG;
    node_of(node)->on(channel, [cb, user](const Peer& peer, ByteView data) {
        cb(user, peer.id().to_hex().c_str(), data.data(), data.size());
    });
    return RATS_OK;
}

/* — discovery / NAT subsystems — */

rats_error_t rats_enable_dht(rats_t node, uint16_t dht_port, const char* discovery_key) {
    auto* h = as_handle(node);
    if (h->started) return RATS_ERR_ALREADY_STARTED;
    if (h->dht_enabled) return RATS_OK;
    DhtDiscovery::Config config;
    config.dht_port = dht_port;
    config.data_dir = h->data_dir;  // co-locate routing tables with identity (else cwd)
    if (discovery_key) config.discovery_key = discovery_key;
    h->node->add_subsystem(std::make_unique<DhtDiscovery>(std::move(config)));
    h->dht_enabled = true;
    return RATS_OK;
}

rats_error_t rats_enable_mdns(rats_t node) {
    auto* h = as_handle(node);
    if (h->started) return RATS_ERR_ALREADY_STARTED;
    if (h->mdns_enabled) return RATS_OK;
    h->node->add_subsystem(std::make_unique<MdnsDiscovery>());
    h->mdns_enabled = true;
    return RATS_OK;
}

rats_error_t rats_enable_port_mapping(rats_t node, int enable_upnp, int enable_natpmp) {
    auto* h = as_handle(node);
    if (h->started) return RATS_ERR_ALREADY_STARTED;
    if (h->portmap_enabled) return RATS_OK;
    PortMappingConfig config;
    config.enable_upnp   = enable_upnp != 0;
    config.enable_natpmp = enable_natpmp != 0;
    h->node->add_subsystem(std::make_unique<PortMappingService>(config));
    h->portmap_enabled = true;
    return RATS_OK;
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

rats_error_t rats_enable_pubsub(rats_t node) {
    auto* h = as_handle(node);
    if (h->started) return RATS_ERR_ALREADY_STARTED;
    if (!h->pubsub) h->pubsub = h->node->add_subsystem(std::make_unique<PubSub>());
    return RATS_OK;
}

rats_error_t rats_subscribe(rats_t node, const char* topic, rats_topic_cb cb, void* user) {
    if (!topic || !cb) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->pubsub) return RATS_ERR_NOT_ENABLED;
    h->pubsub->subscribe(topic,
        [cb, user](const PeerId& from, const std::string& t, ByteView data) {
            cb(user, from.to_hex().c_str(), t.c_str(), data.data(), data.size());
        });
    return RATS_OK;
}

rats_error_t rats_unsubscribe(rats_t node, const char* topic) {
    if (!topic) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->pubsub) return RATS_ERR_NOT_ENABLED;
    h->pubsub->unsubscribe(topic);
    return RATS_OK;
}

rats_error_t rats_publish(rats_t node, const char* topic, const void* data, size_t len) {
    if (!topic) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->pubsub) return RATS_ERR_NOT_ENABLED;
    h->pubsub->publish(topic, ByteView(static_cast<const uint8_t*>(data), len));
    return RATS_OK;
}

/* — typed JSON messaging — */

rats_error_t rats_enable_json(rats_t node) {
    auto* h = as_handle(node);
    if (h->started) return RATS_ERR_ALREADY_STARTED;
    if (!h->messages) h->messages = h->node->add_subsystem(std::make_unique<MessageJson>());
    return RATS_OK;
}

rats_error_t rats_on_json(rats_t node, const char* type, rats_json_cb cb, void* user) {
    if (!type || !cb) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->messages) return RATS_ERR_NOT_ENABLED;
    h->messages->on(type, [cb, user](const PeerId& from, const librats::Json& data) {
        cb(user, from.to_hex().c_str(), data.dump().c_str());
    });
    return RATS_OK;
}

rats_error_t rats_once_json(rats_t node, const char* type, rats_json_cb cb, void* user) {
    if (!type || !cb) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->messages) return RATS_ERR_NOT_ENABLED;
    h->messages->once(type, [cb, user](const PeerId& from, const librats::Json& data) {
        cb(user, from.to_hex().c_str(), data.dump().c_str());
    });
    return RATS_OK;
}

rats_error_t rats_off_json(rats_t node, const char* type) {
    if (!type) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->messages) return RATS_ERR_NOT_ENABLED;
    h->messages->off(type);
    return RATS_OK;
}

rats_error_t rats_send_json(rats_t node, const char* peer_id_hex, const char* type, const char* json) {
    if (!peer_id_hex || !type || !json) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->messages) return RATS_ERR_NOT_ENABLED;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return RATS_ERR_INVALID_ARG;
    auto j = librats::Json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded()) return RATS_ERR_INVALID_ARG;
    if (!h->node->peer(*id)) return RATS_ERR_NO_SUCH_PEER;
    h->messages->send(*id, type, j);
    return RATS_OK;
}

rats_error_t rats_broadcast_json(rats_t node, const char* type, const char* json) {
    if (!type || !json) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->messages) return RATS_ERR_NOT_ENABLED;
    auto j = librats::Json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded()) return RATS_ERR_INVALID_ARG;
    h->messages->send(type, j);
    return RATS_OK;
}

/* — file transfer — */

rats_error_t rats_enable_file_transfer(rats_t node, const char* temp_dir) {
    auto* h = as_handle(node);
    if (h->started) return RATS_ERR_ALREADY_STARTED;
    if (!h->files)
        h->files = h->node->add_subsystem(std::make_unique<FileTransfer>(temp_dir ? temp_dir : "."));
    return RATS_OK;
}

rats_error_t rats_on_file_offer(rats_t node, rats_file_offer_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->files) return RATS_ERR_NOT_ENABLED;
    h->files->on_offer([cb, user](const FileTransfer::Offer& o) {
        cb(user, o.from.to_hex().c_str(), o.id, o.name.c_str(), o.size, o.is_directory ? 1 : 0);
    });
    return RATS_OK;
}

rats_error_t rats_on_file_progress(rats_t node, rats_file_progress_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->files) return RATS_ERR_NOT_ENABLED;
    h->files->on_progress([cb, user](const FileTransfer::Progress& p) {
        cb(user, p.id, p.peer.to_hex().c_str(), p.bytes_transferred, p.total_bytes,
           static_cast<int>(p.status));
    });
    return RATS_OK;
}

rats_error_t rats_on_file_complete(rats_t node, rats_file_complete_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->files) return RATS_ERR_NOT_ENABLED;
    h->files->on_complete([cb, user](uint64_t id, bool success, const std::string& path) {
        cb(user, id, success ? 1 : 0, path.c_str());
    });
    return RATS_OK;
}

uint64_t rats_send_file(rats_t node, const char* peer_id_hex, const char* path) {
    if (!peer_id_hex || !path) return 0;
    auto* h = as_handle(node);
    if (!h->files) return 0;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return 0;
    return h->files->send_file(*id, path);
}

uint64_t rats_send_directory(rats_t node, const char* peer_id_hex, const char* dir_path) {
    if (!peer_id_hex || !dir_path) return 0;
    auto* h = as_handle(node);
    if (!h->files) return 0;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return 0;
    return h->files->send_directory(*id, dir_path);
}

rats_error_t rats_accept_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id,
                              const char* dest_path) {
    if (!peer_id_hex || !dest_path) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->files) return RATS_ERR_NOT_ENABLED;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return RATS_ERR_INVALID_ARG;
    h->files->accept(*id, transfer_id, dest_path);
    return RATS_OK;
}

rats_error_t rats_reject_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id) {
    if (!peer_id_hex) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->files) return RATS_ERR_NOT_ENABLED;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return RATS_ERR_INVALID_ARG;
    h->files->reject(*id, transfer_id);
    return RATS_OK;
}

rats_error_t rats_cancel_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id) {
    if (!peer_id_hex) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->files) return RATS_ERR_NOT_ENABLED;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return RATS_ERR_INVALID_ARG;
    return h->files->cancel(*id, transfer_id) ? RATS_OK : RATS_ERR_NO_SUCH_PEER;
}

rats_error_t rats_pause_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id) {
    if (!peer_id_hex) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->files) return RATS_ERR_NOT_ENABLED;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return RATS_ERR_INVALID_ARG;
    return h->files->pause(*id, transfer_id) ? RATS_OK : RATS_ERR_NO_SUCH_PEER;
}

rats_error_t rats_resume_file(rats_t node, const char* peer_id_hex, uint64_t transfer_id) {
    if (!peer_id_hex) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->files) return RATS_ERR_NOT_ENABLED;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return RATS_ERR_INVALID_ARG;
    return h->files->resume(*id, transfer_id) ? RATS_OK : RATS_ERR_NO_SUCH_PEER;
}

/* — liveness — */

rats_error_t rats_enable_ping(rats_t node) {
    auto* h = as_handle(node);
    if (h->started) return RATS_ERR_ALREADY_STARTED;
    if (!h->ping) h->ping = h->node->add_subsystem(std::make_unique<PingService>());
    return RATS_OK;
}

int64_t rats_peer_rtt_ms(rats_t node, const char* peer_id_hex) {
    if (!peer_id_hex) return -1;
    auto* p = as_handle(node)->ping;
    if (!p) return -1;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return -1;
    auto rtt = p->last_rtt(*id);
    return rtt ? static_cast<int64_t>(rtt->count()) : -1;
}

/* — automatic reconnection — */

rats_error_t rats_enable_reconnect(rats_t node) {
    auto* h = as_handle(node);
    if (h->started) return RATS_ERR_ALREADY_STARTED;
    if (!h->reconnect) {
        ReconnectionService::Config rc;
        if (!h->data_dir.empty()) rc.store_path = h->data_dir + "/peers.json";
        h->reconnect = h->node->add_subsystem(std::make_unique<ReconnectionService>(rc));
    }
    return RATS_OK;
}

rats_error_t rats_add_reconnect(rats_t node, const char* host, uint16_t port) {
    if (!host) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->reconnect) return RATS_ERR_NOT_ENABLED;
    h->reconnect->add(Address{host, port});
    return RATS_OK;
}

rats_error_t rats_remove_reconnect(rats_t node, const char* host, uint16_t port) {
    if (!host) return RATS_ERR_INVALID_ARG;
    auto* h = as_handle(node);
    if (!h->reconnect) return RATS_ERR_NOT_ENABLED;
    h->reconnect->remove(Address{host, port});
    return RATS_OK;
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

/* — protocol identity (node-scoped) — */

char* rats_protocol(rats_t node) {
    return dup_string(node_of(node)->protocol());
}

/* — library info (process-global) — */

const char* rats_version_string(void) { return version::STRING; }

void rats_version(int* major, int* minor, int* patch, int* build) {
    if (major) *major = version::MAJOR;
    if (minor) *minor = version::MINOR;
    if (patch) *patch = version::PATCH;
    if (build) *build = version::BUILD;
}

const char* rats_git_describe(void) { return version::GIT_DESCRIBE; }

uint32_t rats_abi(void) {
    return (static_cast<uint32_t>(version::MAJOR) << 16) |
           (static_cast<uint32_t>(version::MINOR) << 8) |
           (static_cast<uint32_t>(version::PATCH));
}

/* — utility — */

void rats_string_free(char* str) { std::free(str); }

} // extern "C"
