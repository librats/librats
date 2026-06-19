#include "bindings/rats_node.h"

#include "node/node.h"
#include "subsystems/dht_discovery.h"
#include "subsystems/mdns_discovery.h"
#include "subsystems/port_mapping_service.h"

#include <cstdlib>
#include <cstring>
#include <string>

using namespace librats;

namespace {

Node* as_node(rats_node_t handle) { return static_cast<Node*>(handle); }

char* dup_string(const std::string& s) {
    char* out = static_cast<char*>(std::malloc(s.size() + 1));
    if (out) std::memcpy(out, s.c_str(), s.size() + 1);
    return out;
}

} // namespace

extern "C" {

rats_node_t rats_node_create(uint16_t listen_port) {
    NodeConfig config;
    config.listen_port = listen_port;
    return new Node(std::move(config));
}

rats_node_t rats_node_create_ex(uint16_t listen_port, int enable_listen,
                                const char* bind_address, rats_security_t security) {
    NodeConfig config;
    config.listen_port = listen_port;
    config.enable_listen = enable_listen != 0;
    if (bind_address) config.bind_address = bind_address;
    config.security = (security == RATS_SECURITY_PLAINTEXT) ? NodeConfig::Security::Plaintext
                                                            : NodeConfig::Security::Noise;
    return new Node(std::move(config));
}

void rats_node_destroy(rats_node_t node) { delete as_node(node); }

int rats_node_start(rats_node_t node) { return as_node(node)->start() ? 1 : 0; }

void rats_node_stop(rats_node_t node) { as_node(node)->stop(); }

uint16_t rats_node_listen_port(rats_node_t node) { return as_node(node)->listen_port(); }

char* rats_node_local_id(rats_node_t node) { return dup_string(as_node(node)->local_id().to_hex()); }

void rats_node_connect(rats_node_t node, const char* host, uint16_t port) {
    if (host) as_node(node)->connect(std::string(host), port);
}

size_t rats_node_peer_count(rats_node_t node) { return as_node(node)->peer_count(); }

void rats_node_send(rats_node_t node, const char* peer_id_hex,
                    const char* channel, const void* data, size_t len) {
    if (!peer_id_hex || !channel) return;
    auto id = PeerId::from_hex(peer_id_hex);
    if (!id) return;
    as_node(node)->send(*id, channel, ByteView(static_cast<const uint8_t*>(data), len));
}

void rats_node_broadcast(rats_node_t node, const char* channel, const void* data, size_t len) {
    if (!channel) return;
    as_node(node)->broadcast(channel, ByteView(static_cast<const uint8_t*>(data), len));
}

void rats_node_on_peer_connected(rats_node_t node, rats_peer_cb cb, void* user) {
    if (!cb) return;
    as_node(node)->on_peer_connected([cb, user](const Peer& peer) {
        cb(user, peer.id().to_hex().c_str());
    });
}

void rats_node_on_peer_disconnected(rats_node_t node, rats_peer_cb cb, void* user) {
    if (!cb) return;
    as_node(node)->on_peer_disconnected([cb, user](const PeerId& id) {
        cb(user, id.to_hex().c_str());
    });
}

void rats_node_on_message(rats_node_t node, const char* channel, rats_message_cb cb, void* user) {
    if (!channel || !cb) return;
    as_node(node)->on_message(channel, [cb, user](const Peer& peer, ByteView data) {
        cb(user, peer.id().to_hex().c_str(), data.data(), data.size());
    });
}

void rats_node_enable_dht(rats_node_t node, uint16_t dht_port, const char* discovery_key) {
    DhtDiscovery::Config config;
    config.dht_port = dht_port;
    if (discovery_key) config.discovery_key = discovery_key;
    as_node(node)->add_subsystem(std::make_unique<DhtDiscovery>(std::move(config)));
}

void rats_node_enable_mdns(rats_node_t node) {
    as_node(node)->add_subsystem(std::make_unique<MdnsDiscovery>());
}

void rats_node_enable_port_mapping(rats_node_t node, int enable_upnp, int enable_natpmp) {
    PortMappingConfig config;
    config.enable_upnp   = enable_upnp != 0;
    config.enable_natpmp = enable_natpmp != 0;
    as_node(node)->add_subsystem(std::make_unique<PortMappingService>(config));
}

void rats_node_string_free(char* str) { std::free(str); }

} // extern "C"
