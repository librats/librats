#include "librats/bindings/rats.h"

#include "librats/node/node.h"
#include "librats/peer/peer_info.h"
#include "librats/subsystems/dht_discovery.h"
#include "librats/subsystems/mdns_discovery.h"
#include "librats/subsystems/peer_exchange.h"
#include "librats/subsystems/port_mapping_service.h"
#include "librats/subsystems/hole_punch.h"
#include "librats/subsystems/relay.h"
#include "librats/subsystems/pubsub.h"
#include "librats/subsystems/message_json.h"
#include "librats/subsystems/file_transfer.h"
#include "librats/subsystems/ping_service.h"
#include "librats/subsystems/reconnection.h"
#ifdef RATS_SEARCH_FEATURES
#include "librats/subsystems/bittorrent.h"
#endif
#include "librats/core/address.h"
#include "librats/util/network_utils.h"
#include "librats/util/logger.h"
#include "librats/util/json.h"
#include "librats/util/version.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace librats;

// The handle behind rats_t: the Node, plus non-owning pointers to the subsystems
// the C caller enabled (the Node owns those). A non-null pointer is also how an
// enable is deduplicated and how a subsystem call learns it was never enabled.
struct rats_node {
    std::unique_ptr<Node> node;
    std::string           local_id;   ///< hex, cached: the identity never changes
    std::string           data_dir;   ///< where subsystems co-locate their state
    std::atomic<bool>     started{false};

    DhtDiscovery*        dht       = nullptr;
    MdnsDiscovery*       mdns      = nullptr;
    PeerExchange*        pex       = nullptr;
    PortMappingService*  portmap   = nullptr;
    HolePunch*           punch     = nullptr;
    Relay*               relay     = nullptr;
    PubSub*              pubsub    = nullptr;
    MessageJson*         json      = nullptr;
    FileTransfer*        files     = nullptr;
    PingService*         ping      = nullptr;
    ReconnectionService* reconnect = nullptr;
#ifdef RATS_SEARCH_FEATURES
    Bittorrent*          bittorrent = nullptr;
#endif
};

namespace {

std::optional<PeerId> parse_peer(const char* hex) {
    if (!hex) return std::nullopt;
    return PeerId::from_hex(hex);
}

ByteView bytes(const void* data, size_t len) {
    return ByteView(static_cast<const uint8_t*>(data), len);
}

// A numeric literal is used as is; a hostname is resolved here (IPv4 first, then
// IPv6), so the reconnection subsystem only ever holds resolved endpoints.
std::optional<Address> resolve_target(const char* host, uint16_t port) {
    if (auto ip = IpAddress::parse(host)) return Address{*ip, port};
    std::string resolved = network_utils::resolve_hostname(host);
    if (resolved.empty()) resolved = network_utils::resolve_hostname_v6(host);
    if (auto ip = IpAddress::parse(resolved)) return Address{*ip, port};
    return std::nullopt;
}

char* dup_string(const std::string& s) {
    char* out = static_cast<char*>(std::malloc(s.size() + 1));
    if (out) std::memcpy(out, s.c_str(), s.size() + 1);
    return out;
}

char** dup_strings(const std::vector<std::string>& in, size_t* count) {
    if (count) *count = 0;
    if (in.empty()) return nullptr;
    char** out = static_cast<char**>(std::calloc(in.size(), sizeof(char*)));
    if (!out) return nullptr;
    for (size_t i = 0; i < in.size(); ++i) out[i] = dup_string(in[i]);
    if (count) *count = in.size();
    return out;
}

rats_transport_t to_c(TransportKind kind) {
    switch (kind) {
        case TransportKind::Udp:   return RATS_TRANSPORT_UDP;
        case TransportKind::Tcp:   return RATS_TRANSPORT_TCP;
        case TransportKind::Relay: return RATS_TRANSPORT_RELAY;
    }
    return RATS_TRANSPORT_TCP;
}

rats_close_reason_t to_c(CloseReason r) {
    switch (r) {
        case CloseReason::LocalClose:      return RATS_CLOSE_LOCAL;
        case CloseReason::PeerClosed:      return RATS_CLOSE_PEER_CLOSED;
        case CloseReason::PeerReset:       return RATS_CLOSE_PEER_RESET;
        case CloseReason::ConnectFailed:   return RATS_CLOSE_CONNECT_FAILED;
        case CloseReason::HandshakeFailed: return RATS_CLOSE_HANDSHAKE_FAILED;
        case CloseReason::ProtocolError:   return RATS_CLOSE_PROTOCOL_ERROR;
        case CloseReason::SlowConsumer:    return RATS_CLOSE_SLOW_CONSUMER;
        case CloseReason::ReactorShutdown: return RATS_CLOSE_SHUTDOWN;
        case CloseReason::DuplicateConn:   return RATS_CLOSE_DUPLICATE;
        case CloseReason::PeerLimit:       return RATS_CLOSE_PEER_LIMIT;
        case CloseReason::IdleTimeout:     return RATS_CLOSE_IDLE_TIMEOUT;
        case CloseReason::DialSuperseded:  return RATS_CLOSE_DIAL_SUPERSEDED;
    }
    return RATS_CLOSE_PEER_RESET;
}

rats_file_status_t to_c(FileTransfer::Status s) {
    switch (s) {
        case FileTransfer::Status::Pending:   return RATS_FILE_PENDING;
        case FileTransfer::Status::Active:    return RATS_FILE_ACTIVE;
        case FileTransfer::Status::Paused:    return RATS_FILE_PAUSED;
        case FileTransfer::Status::Completed: return RATS_FILE_COMPLETED;
        case FileTransfer::Status::Failed:    return RATS_FILE_FAILED;
        case FileTransfer::Status::Cancelled: return RATS_FILE_CANCELLED;
    }
    return RATS_FILE_FAILED;
}

rats_path_stats_t to_c(const PathStats& s) {
    rats_path_stats_t c{};
    c.bandwidth_bps     = s.bandwidth_bps;
    c.app_limited       = s.app_limited ? 1 : 0;
    c.pacing_bps        = s.pacing_bps;
    c.srtt_us           = s.srtt_us;
    c.min_rtt_us        = s.min_rtt_us;
    c.queued_bytes      = s.queued_bytes;
    c.bytes_in_flight   = s.bytes_in_flight;
    c.loss              = s.loss;
    c.bytes_delivered   = s.bytes_delivered;
    c.bytes_lost        = s.bytes_lost;
    c.live_sent         = s.live_sent;
    c.live_expired      = s.live_expired;
    c.live_repair_bytes = s.live_repair_bytes;
    return c;
}

SendOptions send_options(uint32_t lifetime_ms) {
    SendOptions options;
    options.lifetime = std::chrono::milliseconds(lifetime_ms);
    return options;
}

// Translate the zero-means-default C config into a NodeConfig. nullopt for a
// config no node can run with, which rats_create() reports as NULL rather than
// leaving the caller to find out from a node that never connects.
std::optional<NodeConfig> to_node_config(const rats_config_t& c) {
    NodeConfig config;

    if (c.protocol && *c.protocol) config.protocol = c.protocol;
    if (c.data_dir)                config.data_dir = c.data_dir;
    switch (c.security) {
        case RATS_SECURITY_NOISE:     config.security = NodeConfig::Security::Noise;     break;
        case RATS_SECURITY_PLAINTEXT: config.security = NodeConfig::Security::Plaintext; break;
        default: return std::nullopt;
    }

    config.listen_port   = c.listen_port;
    config.enable_listen = c.dial_only == 0;
    if (c.bind_address) config.bind_address = c.bind_address;
    config.max_peers = c.max_peers;

    const uint32_t all = RATS_TRANSPORT_MASK_TCP | RATS_TRANSPORT_MASK_UDP;
    const uint32_t transports = c.transports == 0 ? all : c.transports;
    if ((transports & ~all) != 0) return std::nullopt;
    config.enable_tcp = (transports & RATS_TRANSPORT_MASK_TCP) != 0;
    config.enable_udp = (transports & RATS_TRANSPORT_MASK_UDP) != 0;
    switch (c.preferred_transport) {
        case RATS_TRANSPORT_UDP: config.preferred_transport = TransportKind::Udp; break;
        case RATS_TRANSPORT_TCP: config.preferred_transport = TransportKind::Tcp; break;
        default: return std::nullopt;   // a relay is never dialed
    }
    if ((config.preferred_transport == TransportKind::Udp && !config.enable_udp) ||
        (config.preferred_transport == TransportKind::Tcp && !config.enable_tcp)) {
        // Only the default may follow the transports; asking for one that is off
        // is a contradiction, not a preference.
        if (c.preferred_transport != RATS_TRANSPORT_UDP) return std::nullopt;
        config.preferred_transport = TransportKind::Tcp;
    }
    if (c.transport_fallback_ms == RATS_FALLBACK_NEVER) config.transport_fallback_ms = 0;
    else if (c.transport_fallback_ms != 0)              config.transport_fallback_ms = c.transport_fallback_ms;

    config.send_queue_limit = c.send_queue_limit;
    config.path_sample_ms   = c.path_sample_ms;

    switch (c.congestion_control) {
        case RATS_CONGESTION_BBR:  config.congestion_control = CongestionAlgorithm::Bbr;  break;
        case RATS_CONGESTION_RENO: config.congestion_control = CongestionAlgorithm::Reno; break;
        default: return std::nullopt;
    }
    config.udp_receive_window = c.udp_receive_window;
    config.udp_receive_budget = c.udp_receive_budget;
    config.udp_offload        = c.disable_udp_offload == 0;

    config.reactor_threads        = c.reactor_threads == 0 ? 1 : c.reactor_threads;
    config.enable_network_monitor = c.disable_network_monitor == 0;
    return config;
}

// The gate every rats_enable_* goes through: before start, and once.
template <class T, class Make>
rats_error_t enable(rats_t h, T*& slot, Make make) {
    if (h->started) return RATS_ERR_ALREADY_STARTED;
    if (!slot) slot = h->node->add_subsystem(make());
    return RATS_OK;
}

} // namespace

// Every function below was declared extern "C" by rats.h, which is what gives it
// C linkage; the definitions need no block of their own (and the helpers between
// them are templates, which a C-linkage block may not hold).

const char* rats_error_str(rats_error_t err) {
    switch (err) {
        case RATS_OK:                  return "RATS_OK";
        case RATS_ERR_INVALID_ARG:     return "RATS_ERR_INVALID_ARG";
        case RATS_ERR_NOT_STARTED:     return "RATS_ERR_NOT_STARTED";
        case RATS_ERR_ALREADY_STARTED: return "RATS_ERR_ALREADY_STARTED";
        case RATS_ERR_NOT_ENABLED:     return "RATS_ERR_NOT_ENABLED";
        case RATS_ERR_NO_SUCH_PEER:    return "RATS_ERR_NO_SUCH_PEER";
        case RATS_ERR_NOT_FOUND:       return "RATS_ERR_NOT_FOUND";
        case RATS_ERR_DECLINED:        return "RATS_ERR_DECLINED";
        case RATS_ERR_BIND:            return "RATS_ERR_BIND";
        case RATS_ERR_INTERNAL:        return "RATS_ERR_INTERNAL";
    }
    return "RATS_ERR_UNKNOWN";
}

const char* rats_close_reason_str(rats_close_reason_t reason) {
    switch (reason) {
        case RATS_CLOSE_LOCAL:            return "RATS_CLOSE_LOCAL";
        case RATS_CLOSE_PEER_CLOSED:      return "RATS_CLOSE_PEER_CLOSED";
        case RATS_CLOSE_PEER_RESET:       return "RATS_CLOSE_PEER_RESET";
        case RATS_CLOSE_CONNECT_FAILED:   return "RATS_CLOSE_CONNECT_FAILED";
        case RATS_CLOSE_HANDSHAKE_FAILED: return "RATS_CLOSE_HANDSHAKE_FAILED";
        case RATS_CLOSE_PROTOCOL_ERROR:   return "RATS_CLOSE_PROTOCOL_ERROR";
        case RATS_CLOSE_SLOW_CONSUMER:    return "RATS_CLOSE_SLOW_CONSUMER";
        case RATS_CLOSE_SHUTDOWN:         return "RATS_CLOSE_SHUTDOWN";
        case RATS_CLOSE_DUPLICATE:        return "RATS_CLOSE_DUPLICATE";
        case RATS_CLOSE_PEER_LIMIT:       return "RATS_CLOSE_PEER_LIMIT";
        case RATS_CLOSE_IDLE_TIMEOUT:     return "RATS_CLOSE_IDLE_TIMEOUT";
        case RATS_CLOSE_DIAL_SUPERSEDED:  return "RATS_CLOSE_DIAL_SUPERSEDED";
    }
    return "RATS_CLOSE_UNKNOWN";
}

/* ─── Configuration and lifecycle ─────────────────────────────────────────── */

rats_t rats_create(const rats_config_t* config) {
    const rats_config_t defaults{};
    auto node_config = to_node_config(config ? *config : defaults);
    if (!node_config) return nullptr;
    try {
        auto h = std::make_unique<rats_node>();
        h->data_dir = node_config->data_dir;
        h->node     = std::make_unique<Node>(std::move(*node_config));
        h->local_id = h->node->local_id().to_hex();
        return h.release();
    } catch (...) {
        return nullptr;   // nothing may unwind across the C ABI
    }
}

void rats_destroy(rats_t node) { delete node; }

rats_error_t rats_start(rats_t node) {
    if (node->started) return RATS_ERR_ALREADY_STARTED;
    if (!node->node->start()) return RATS_ERR_BIND;
    node->started = true;
    return RATS_OK;
}

void rats_stop(rats_t node) {
    node->node->stop();
    node->started = false;
}

/* ─── This node ───────────────────────────────────────────────────────────── */

const char* rats_local_id(rats_t node) { return node->local_id.c_str(); }
const char* rats_protocol(rats_t node) { return node->node->protocol().c_str(); }
uint16_t    rats_listen_port(rats_t node) { return node->node->listen_port(); }
uint32_t    rats_transports(rats_t node) { return node->node->transports(); }

rats_nat_mapping_t rats_nat_mapping(rats_t node) {
    switch (node->node->nat_status().udp_mapping()) {
        case NatMapping::Open:                return RATS_NAT_OPEN;
        case NatMapping::EndpointIndependent: return RATS_NAT_ENDPOINT_INDEPENDENT;
        case NatMapping::EndpointDependent:   return RATS_NAT_ENDPOINT_DEPENDENT;
        case NatMapping::Unknown:             break;
    }
    return RATS_NAT_UNKNOWN;
}

char** rats_observed_addresses(rats_t node, size_t* count) {
    std::vector<std::string> out;
    for (const Address& a : node->node->observed_addresses()) out.push_back(a.to_string());
    return dup_strings(out, count);
}

/* ─── Peers ───────────────────────────────────────────────────────────────── */

rats_error_t rats_connect(rats_t node, const char* host, uint16_t port) {
    if (!host || !*host) return RATS_ERR_INVALID_ARG;
    if (!node->started) return RATS_ERR_NOT_STARTED;
    node->node->connect(std::string(host), port);
    return RATS_OK;
}

rats_error_t rats_disconnect(rats_t node, const char* peer_id) {
    auto id = parse_peer(peer_id);
    if (!id) return RATS_ERR_INVALID_ARG;
    auto peer = node->node->peer(*id);
    if (!peer) return RATS_ERR_NO_SUCH_PEER;
    peer->disconnect();
    return RATS_OK;
}

size_t rats_peer_count(rats_t node) { return node->node->peer_count(); }

char** rats_peer_ids(rats_t node, size_t* count) {
    std::vector<std::string> out;
    for (const PeerInfo& info : node->node->peers()) out.push_back(info.id.to_hex());
    return dup_strings(out, count);
}

rats_error_t rats_peer_info(rats_t node, const char* peer_id, rats_peer_info_t* out) {
    auto id = parse_peer(peer_id);
    if (!id || !out) return RATS_ERR_INVALID_ARG;
    for (const PeerInfo& info : node->node->peers()) {
        if (info.id != *id) continue;
        std::memset(out, 0, sizeof(*out));
        out->transport  = to_c(info.transport);
        out->transports = info.supported_transports;
        out->direction  = info.direction == ConnRole::Inbound ? RATS_DIRECTION_INBOUND
                                                              : RATS_DIRECTION_OUTBOUND;
        if (!info.addresses.empty()) {
            const std::string a = info.addresses.front().to_string();
            std::strncpy(out->address, a.c_str(), sizeof(out->address) - 1);
        }
        return RATS_OK;
    }
    return RATS_ERR_NO_SUCH_PEER;
}

void   rats_set_max_peers(rats_t node, size_t max_peers) { node->node->set_max_peers(max_peers); }
size_t rats_max_peers(rats_t node) { return node->node->max_peers(); }

/* ─── Messaging ───────────────────────────────────────────────────────────── */

static_assert(RATS_LIVE_MAX_PAYLOAD == SendOptions::kMaxLivePayload, "the C limit is the node's");

rats_error_t rats_send(rats_t node, const char* peer_id, const char* channel,
                       const void* data, size_t len, uint32_t lifetime_ms) {
    auto id = parse_peer(peer_id);
    if (!id || !channel || (!data && len)) return RATS_ERR_INVALID_ARG;
    if (lifetime_ms > 0 && len > RATS_LIVE_MAX_PAYLOAD) return RATS_ERR_INVALID_ARG;
    if (!node->node->peer(*id)) return RATS_ERR_NO_SUCH_PEER;
    node->node->send(*id, channel, bytes(data, len), send_options(lifetime_ms));
    return RATS_OK;
}

rats_error_t rats_broadcast(rats_t node, const char* channel, const void* data, size_t len,
                            uint32_t lifetime_ms) {
    if (!channel || (!data && len)) return RATS_ERR_INVALID_ARG;
    if (lifetime_ms > 0 && len > RATS_LIVE_MAX_PAYLOAD) return RATS_ERR_INVALID_ARG;
    node->node->broadcast(channel, bytes(data, len), send_options(lifetime_ms));
    return RATS_OK;
}

int rats_peer_writable(rats_t node, const char* peer_id) {
    auto id = parse_peer(peer_id);
    return id && node->node->peer_writable(*id) ? 1 : 0;
}

rats_error_t rats_path_stats(rats_t node, const char* peer_id, rats_path_stats_t* out) {
    auto id = parse_peer(peer_id);
    if (!id || !out) return RATS_ERR_INVALID_ARG;
    const auto stats = node->node->path_stats(*id);
    if (!stats) return RATS_ERR_NO_SUCH_PEER;
    *out = to_c(*stats);
    return RATS_OK;
}

/* ─── Callbacks ───────────────────────────────────────────────────────────── */

rats_error_t rats_on_peer_connected(rats_t node, rats_peer_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    if (node->started) return RATS_ERR_ALREADY_STARTED;
    node->node->on_peer_connected([cb, user](const Peer& peer) {
        cb(user, peer.id().to_hex().c_str());
    });
    return RATS_OK;
}

rats_error_t rats_on_peer_disconnected(rats_t node, rats_disconnect_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    if (node->started) return RATS_ERR_ALREADY_STARTED;
    node->node->on_peer_disconnected([cb, user](const PeerId& id, CloseReason reason) {
        cb(user, id.to_hex().c_str(), to_c(reason));
    });
    return RATS_OK;
}

rats_error_t rats_on_dial_failed(rats_t node, rats_dial_failed_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    if (node->started) return RATS_ERR_ALREADY_STARTED;
    node->node->on_dial_failed([cb, user](const Address& address) {
        cb(user, address.to_string().c_str());
    });
    return RATS_OK;
}

rats_error_t rats_on_peer_writable(rats_t node, rats_peer_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    if (node->started) return RATS_ERR_ALREADY_STARTED;
    node->node->on_peer_writable([cb, user](const Peer& peer) {
        cb(user, peer.id().to_hex().c_str());
    });
    return RATS_OK;
}

rats_error_t rats_on_peer_path(rats_t node, rats_path_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    if (node->started) return RATS_ERR_ALREADY_STARTED;
    node->node->on_peer_path([cb, user](const Peer& peer, const PathStats& stats) {
        const rats_path_stats_t c = to_c(stats);
        cb(user, peer.id().to_hex().c_str(), &c);
    });
    return RATS_OK;
}

rats_error_t rats_on(rats_t node, const char* channel, rats_message_cb cb, void* user) {
    if (!channel || !cb) return RATS_ERR_INVALID_ARG;
    if (node->started) return RATS_ERR_ALREADY_STARTED;
    node->node->on(channel, [cb, user](const Peer& peer, ByteView data) {
        cb(user, peer.id().to_hex().c_str(), data.data(), data.size());
    });
    return RATS_OK;
}

/* ─── Discovery ───────────────────────────────────────────────────────────── */

rats_error_t rats_enable_dht(rats_t node, uint16_t dht_port, const char* discovery_key) {
    return enable(node, node->dht, [&] {
        DhtDiscovery::Config config;
        config.dht_port = dht_port;
        config.data_dir = node->data_dir;   // co-locate the routing table with the identity
        if (discovery_key) config.discovery_key = discovery_key;
        return std::make_unique<DhtDiscovery>(std::move(config));
    });
}

rats_error_t rats_enable_mdns(rats_t node) {
    return enable(node, node->mdns, [] { return std::make_unique<MdnsDiscovery>(); });
}

rats_error_t rats_enable_peer_exchange(rats_t node) {
    return enable(node, node->pex, [] {
        return std::make_unique<PeerExchange>(PeerExchange::Config{});
    });
}

/* ─── NAT traversal ───────────────────────────────────────────────────────── */

rats_error_t rats_enable_port_mapping(rats_t node, int upnp, int natpmp) {
    return enable(node, node->portmap, [&] {
        PortMappingConfig config;
        config.enable_upnp   = upnp != 0;
        config.enable_natpmp = natpmp != 0;
        return std::make_unique<PortMappingService>(config);
    });
}

rats_error_t rats_enable_hole_punch(rats_t node, int serve_rendezvous) {
    return enable(node, node->punch, [&] {
        HolePunch::Config config;
        config.enable_relay = serve_rendezvous != 0;
        return std::make_unique<HolePunch>(config);
    });
}

rats_error_t rats_punch_peer(rats_t node, const char* peer_id) {
    auto id = parse_peer(peer_id);
    if (!id) return RATS_ERR_INVALID_ARG;
    if (!node->punch) return RATS_ERR_NOT_ENABLED;
    return node->punch->punch(*id) ? RATS_OK : RATS_ERR_DECLINED;
}

rats_error_t rats_enable_relay(rats_t node, int serve) {
    return enable(node, node->relay, [&] {
        Relay::Config config;
        config.serve = serve != 0;
        return std::make_unique<Relay>(config);
    });
}

rats_error_t rats_connect_via_relay(rats_t node, const char* peer_id) {
    auto id = parse_peer(peer_id);
    if (!id) return RATS_ERR_INVALID_ARG;
    if (!node->relay) return RATS_ERR_NOT_ENABLED;
    return node->relay->connect_via_relay(*id) ? RATS_OK : RATS_ERR_DECLINED;
}

/* ─── Pub/sub ─────────────────────────────────────────────────────────────── */

rats_error_t rats_enable_pubsub(rats_t node) {
    return enable(node, node->pubsub, [] { return std::make_unique<PubSub>(); });
}

rats_error_t rats_subscribe(rats_t node, const char* topic, rats_topic_cb cb, void* user) {
    if (!topic || !cb) return RATS_ERR_INVALID_ARG;
    if (!node->pubsub) return RATS_ERR_NOT_ENABLED;
    node->pubsub->subscribe(topic, [cb, user](const PeerId& from, const std::string& t, ByteView data) {
        cb(user, from.to_hex().c_str(), t.c_str(), data.data(), data.size());
    });
    return RATS_OK;
}

rats_error_t rats_unsubscribe(rats_t node, const char* topic) {
    if (!topic) return RATS_ERR_INVALID_ARG;
    if (!node->pubsub) return RATS_ERR_NOT_ENABLED;
    node->pubsub->unsubscribe(topic);
    return RATS_OK;
}

rats_error_t rats_publish(rats_t node, const char* topic, const void* data, size_t len) {
    if (!topic || (!data && len)) return RATS_ERR_INVALID_ARG;
    if (!node->pubsub) return RATS_ERR_NOT_ENABLED;
    node->pubsub->publish(topic, bytes(data, len));
    return RATS_OK;
}

/* ─── JSON messaging ──────────────────────────────────────────────────────── */

rats_error_t rats_enable_json(rats_t node) {
    return enable(node, node->json, [] { return std::make_unique<MessageJson>(); });
}

namespace {
MessageJson::Handler json_handler(rats_json_cb cb, void* user) {
    return [cb, user](const PeerId& from, const Json& data) {
        cb(user, from.to_hex().c_str(), data.dump().c_str());
    };
}
} // namespace

rats_error_t rats_on_json(rats_t node, const char* type, rats_json_cb cb, void* user) {
    if (!type || !cb) return RATS_ERR_INVALID_ARG;
    if (!node->json) return RATS_ERR_NOT_ENABLED;
    node->json->on(type, json_handler(cb, user));
    return RATS_OK;
}

rats_error_t rats_once_json(rats_t node, const char* type, rats_json_cb cb, void* user) {
    if (!type || !cb) return RATS_ERR_INVALID_ARG;
    if (!node->json) return RATS_ERR_NOT_ENABLED;
    node->json->once(type, json_handler(cb, user));
    return RATS_OK;
}

rats_error_t rats_off_json(rats_t node, const char* type) {
    if (!type) return RATS_ERR_INVALID_ARG;
    if (!node->json) return RATS_ERR_NOT_ENABLED;
    node->json->off(type);
    return RATS_OK;
}

rats_error_t rats_send_json(rats_t node, const char* peer_id, const char* type, const char* json) {
    auto id = parse_peer(peer_id);
    if (!id || !type || !json) return RATS_ERR_INVALID_ARG;
    if (!node->json) return RATS_ERR_NOT_ENABLED;
    auto value = Json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (value.is_discarded()) return RATS_ERR_INVALID_ARG;
    if (!node->node->peer(*id)) return RATS_ERR_NO_SUCH_PEER;
    node->json->send(*id, type, value);
    return RATS_OK;
}

rats_error_t rats_broadcast_json(rats_t node, const char* type, const char* json) {
    if (!type || !json) return RATS_ERR_INVALID_ARG;
    if (!node->json) return RATS_ERR_NOT_ENABLED;
    auto value = Json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (value.is_discarded()) return RATS_ERR_INVALID_ARG;
    node->json->send(type, value);
    return RATS_OK;
}

/* ─── File transfer ───────────────────────────────────────────────────────── */

rats_error_t rats_enable_file_transfer(rats_t node, const char* temp_dir) {
    return enable(node, node->files, [&] {
        return std::make_unique<FileTransfer>(temp_dir ? temp_dir : ".");
    });
}

rats_error_t rats_on_file_offer(rats_t node, rats_file_offer_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    if (!node->files) return RATS_ERR_NOT_ENABLED;
    if (node->started) return RATS_ERR_ALREADY_STARTED;
    node->files->on_offer([cb, user](const FileTransfer::Offer& o) {
        cb(user, o.from.to_hex().c_str(), o.id, o.name.c_str(), o.size, o.is_directory ? 1 : 0);
    });
    return RATS_OK;
}

rats_error_t rats_on_file_progress(rats_t node, rats_file_progress_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    if (!node->files) return RATS_ERR_NOT_ENABLED;
    if (node->started) return RATS_ERR_ALREADY_STARTED;
    node->files->on_progress([cb, user](const FileTransfer::Progress& p) {
        const std::string peer = p.peer.to_hex();
        rats_file_progress_t c{};
        c.transfer_id        = p.id;
        c.peer_id            = peer.c_str();
        c.direction          = p.direction == FileTransfer::Direction::Receiving
                                   ? RATS_DIRECTION_INBOUND : RATS_DIRECTION_OUTBOUND;
        c.status             = to_c(p.status);
        c.bytes_transferred  = p.bytes_transferred;
        c.total_bytes        = p.total_bytes;
        c.files_completed    = p.files_completed;
        c.total_files        = p.total_files;
        c.rate_bytes_per_sec = p.transfer_rate_bps;
        cb(user, &c);
    });
    return RATS_OK;
}

rats_error_t rats_on_file_complete(rats_t node, rats_file_complete_cb cb, void* user) {
    if (!cb) return RATS_ERR_INVALID_ARG;
    if (!node->files) return RATS_ERR_NOT_ENABLED;
    if (node->started) return RATS_ERR_ALREADY_STARTED;
    node->files->on_complete([cb, user](const PeerId& peer, uint64_t id, bool success,
                                        const std::string& path) {
        cb(user, peer.to_hex().c_str(), id, success ? 1 : 0, path.c_str());
    });
    return RATS_OK;
}

namespace {
template <class Offer>
rats_error_t offer(rats_t node, const char* peer_id, const char* path, uint64_t* transfer_id,
                   Offer offer_fn) {
    if (transfer_id) *transfer_id = 0;
    auto id = parse_peer(peer_id);
    if (!id || !path) return RATS_ERR_INVALID_ARG;
    if (!node->files) return RATS_ERR_NOT_ENABLED;
    if (!node->node->peer(*id)) return RATS_ERR_NO_SUCH_PEER;
    const uint64_t tid = offer_fn(*node->files, *id, path);
    if (tid == 0) return RATS_ERR_NOT_FOUND;   // the path could not be read
    if (transfer_id) *transfer_id = tid;
    return RATS_OK;
}
} // namespace

rats_error_t rats_send_file(rats_t node, const char* peer_id, const char* path,
                            uint64_t* transfer_id) {
    return offer(node, peer_id, path, transfer_id,
                 [](FileTransfer& f, const PeerId& id, const char* p) { return f.send_file(id, p); });
}

rats_error_t rats_send_directory(rats_t node, const char* peer_id, const char* path,
                                 uint64_t* transfer_id) {
    return offer(node, peer_id, path, transfer_id,
                 [](FileTransfer& f, const PeerId& id, const char* p) { return f.send_directory(id, p); });
}

rats_error_t rats_accept_file(rats_t node, const char* peer_id, uint64_t transfer_id,
                              const char* dest_path) {
    auto id = parse_peer(peer_id);
    if (!id || !dest_path) return RATS_ERR_INVALID_ARG;
    if (!node->files) return RATS_ERR_NOT_ENABLED;
    node->files->accept(*id, transfer_id, dest_path);
    return RATS_OK;
}

rats_error_t rats_reject_file(rats_t node, const char* peer_id, uint64_t transfer_id) {
    auto id = parse_peer(peer_id);
    if (!id) return RATS_ERR_INVALID_ARG;
    if (!node->files) return RATS_ERR_NOT_ENABLED;
    node->files->reject(*id, transfer_id);
    return RATS_OK;
}

namespace {
template <class Action>
rats_error_t control_file(rats_t node, const char* peer_id, Action action) {
    auto id = parse_peer(peer_id);
    if (!id) return RATS_ERR_INVALID_ARG;
    if (!node->files) return RATS_ERR_NOT_ENABLED;
    return action(*node->files, *id) ? RATS_OK : RATS_ERR_NOT_FOUND;
}
} // namespace

rats_error_t rats_cancel_file(rats_t node, const char* peer_id, uint64_t transfer_id) {
    return control_file(node, peer_id, [&](FileTransfer& f, const PeerId& id) {
        return f.cancel(id, transfer_id);
    });
}

rats_error_t rats_pause_file(rats_t node, const char* peer_id, uint64_t transfer_id) {
    return control_file(node, peer_id, [&](FileTransfer& f, const PeerId& id) {
        return f.pause(id, transfer_id);
    });
}

rats_error_t rats_resume_file(rats_t node, const char* peer_id, uint64_t transfer_id) {
    return control_file(node, peer_id, [&](FileTransfer& f, const PeerId& id) {
        return f.resume(id, transfer_id);
    });
}

/* ─── Ping ────────────────────────────────────────────────────────────────── */

rats_error_t rats_enable_ping(rats_t node) {
    return enable(node, node->ping, [] { return std::make_unique<PingService>(); });
}

int64_t rats_peer_rtt_ms(rats_t node, const char* peer_id) {
    auto id = parse_peer(peer_id);
    if (!id || !node->ping) return -1;
    auto rtt = node->ping->last_rtt(*id);
    return rtt ? static_cast<int64_t>(rtt->count()) : -1;
}

/* ─── Reconnection ────────────────────────────────────────────────────────── */

rats_error_t rats_enable_reconnect(rats_t node) {
    return enable(node, node->reconnect, [&] {
        ReconnectionService::Config config;
        if (!node->data_dir.empty()) config.store_path = node->data_dir + "/peers.json";
        return std::make_unique<ReconnectionService>(config);
    });
}

rats_error_t rats_add_reconnect(rats_t node, const char* host, uint16_t port) {
    if (!host) return RATS_ERR_INVALID_ARG;
    if (!node->reconnect) return RATS_ERR_NOT_ENABLED;
    const auto target = resolve_target(host, port);
    if (!target) return RATS_ERR_INVALID_ARG;   // neither a literal nor resolvable
    node->reconnect->add(*target);
    return RATS_OK;
}

rats_error_t rats_remove_reconnect(rats_t node, const char* host, uint16_t port) {
    if (!host) return RATS_ERR_INVALID_ARG;
    if (!node->reconnect) return RATS_ERR_NOT_ENABLED;
    const auto target = resolve_target(host, port);
    if (!target) return RATS_ERR_INVALID_ARG;
    node->reconnect->remove(*target);
    return RATS_OK;
}

/* ─── BitTorrent ──────────────────────────────────────────────────────────── */

#ifdef RATS_SEARCH_FEATURES

namespace {
std::optional<bittorrent::EncPolicy> to_policy(rats_bt_encryption_t p) {
    switch (p) {
        case RATS_BT_ENC_ENABLED:  return bittorrent::EncPolicy::Enabled;
        case RATS_BT_ENC_FORCED:   return bittorrent::EncPolicy::Forced;
        case RATS_BT_ENC_DISABLED: return bittorrent::EncPolicy::Disabled;
    }
    return std::nullopt;
}

// The client lives on its own reactor thread; a running one is reached only by
// posting to it.
bittorrent::Client* running_client(rats_t node) {
    if (!node->bittorrent || !node->bittorrent->is_running()) return nullptr;
    return node->bittorrent->client();
}
} // namespace

rats_error_t rats_enable_bittorrent(rats_t node, const rats_bt_config_t* config) {
    const rats_bt_config_t defaults{};
    const rats_bt_config_t& c = config ? *config : defaults;
    const auto out_policy = to_policy(c.outgoing_encryption);
    const auto in_policy  = to_policy(c.incoming_encryption);
    if (!out_policy || !in_policy) return RATS_ERR_INVALID_ARG;
    return enable(node, node->bittorrent, [&] {
        Bittorrent::Config cfg;
        cfg.client.listen_port         = c.listen_port;
        cfg.client.download_path       = c.download_path ? c.download_path : ".";
        cfg.client.out_enc_policy      = *out_policy;
        cfg.client.in_enc_policy       = *in_policy;
        cfg.client.enable_outgoing_utp = c.disable_outgoing_utp == 0;
        cfg.client.enable_incoming_utp = c.disable_incoming_utp == 0;
        return std::make_unique<Bittorrent>(cfg);
    });
}

rats_error_t rats_bt_add_magnet(rats_t node, const char* magnet_uri, const char* save_path) {
    if (!magnet_uri) return RATS_ERR_INVALID_ARG;
    auto* c = running_client(node);
    if (!c) return RATS_ERR_NOT_ENABLED;
    c->reactor().post([c, uri = std::string(magnet_uri),
                       sp = std::string(save_path ? save_path : "")] { c->add_magnet(uri, sp); });
    return RATS_OK;
}

rats_error_t rats_bt_add_torrent_file(rats_t node, const char* torrent_path, const char* save_path) {
    if (!torrent_path) return RATS_ERR_INVALID_ARG;
    auto* c = running_client(node);
    if (!c) return RATS_ERR_NOT_ENABLED;
    auto info = bittorrent::TorrentInfo::from_file(torrent_path);
    if (!info) return RATS_ERR_INVALID_ARG;
    c->reactor().post([c, info = *info, sp = std::string(save_path ? save_path : "")] {
        c->add_torrent(info, sp);
    });
    return RATS_OK;
}

rats_error_t rats_bt_remove_torrent(rats_t node, const char* info_hash_hex) {
    if (!info_hash_hex) return RATS_ERR_INVALID_ARG;
    auto* c = running_client(node);
    if (!c) return RATS_ERR_NOT_ENABLED;
    auto ih = bittorrent::info_hash_from_hex(info_hash_hex);
    if (!ih) return RATS_ERR_INVALID_ARG;
    c->reactor().post([c, ih = *ih] { c->remove_torrent(ih); });
    return RATS_OK;
}

#else

rats_error_t rats_enable_bittorrent(rats_t, const rats_bt_config_t*) { return RATS_ERR_NOT_ENABLED; }
rats_error_t rats_bt_add_magnet(rats_t, const char*, const char*) { return RATS_ERR_NOT_ENABLED; }
rats_error_t rats_bt_add_torrent_file(rats_t, const char*, const char*) { return RATS_ERR_NOT_ENABLED; }
rats_error_t rats_bt_remove_torrent(rats_t, const char*) { return RATS_ERR_NOT_ENABLED; }

#endif

/* ─── Process-wide ────────────────────────────────────────────────────────── */

void rats_set_log_level(rats_log_level_t level) {
    // rats_log_level_t mirrors LogLevel value for value. Cast rather than name the
    // enumerators: LogLevel::ERROR collides with the ERROR macro of <windows.h>.
    if (level < RATS_LOG_DEBUG || level > RATS_LOG_ERROR) return;
    Logger::getInstance().set_log_level(static_cast<LogLevel>(level));
}

void rats_set_log_file(const char* path) {
    auto& logger = Logger::getInstance();
    if (path && *path) {
        logger.set_log_file_path(path);
        logger.set_file_logging_enabled(true);
    } else {
        logger.set_file_logging_enabled(false);
    }
}

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
           static_cast<uint32_t>(version::PATCH);
}

void rats_strings_free(char** strings, size_t count) {
    if (!strings) return;
    for (size_t i = 0; i < count; ++i) std::free(strings[i]);
    std::free(strings);
}
