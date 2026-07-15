// 07_full_chat — a "batteries-included" chat that finds its peers by itself.
//
// The earlier chat examples dial peers by hand. This one attaches every
// discovery + resilience subsystem librats offers and then just... works: start
// two nodes with the same room name anywhere on the same LAN (or the same open
// internet, via DHT) and they find each other, form a gossip mesh, and relay
// chat across it — no addresses typed in.
//
// Wired up here:
//   • DhtDiscovery  — announce/search a room key on the global Kademlia DHT (WAN)
//   • MdnsDiscovery — zero-config discovery of peers on the local network (LAN)
//   • PeerExchange  — peers gossip the peers they know, so the mesh fills in fast
//   • ReconnectionService — remembers peers (under data_dir) and re-dials them
//   • PingService   — liveness + round-trip time
//   • PubSub        — the chat itself, as a GossipSub topic (relays across hops)
//
//   07_full_chat <listen_port> [room] [data_dir]
//
//   ./07_full_chat 9000 lobby ./node-a     # terminal / machine 1
//   ./07_full_chat 9001 lobby ./node-b     # terminal / machine 2
//
// Nodes in the same <room> discover each other; the room also namespaces the DHT
// swarm and the pub/sub topic. Passing a <data_dir> gives each node a stable
// identity and persists its known-peer list across restarts. LAN peers appear in
// a second or two (mDNS); WAN peers take a minute or two (DHT bootstrap).

#include "node/node.h"
#include "subsystems/dht_discovery.h"
#include "subsystems/mdns_discovery.h"
#include "subsystems/peer_exchange.h"
#include "subsystems/reconnection.h"
#include "subsystems/ping_service.h"
#include "subsystems/pubsub.h"

#include <iostream>
#include <string>

using namespace librats;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <listen_port> [room] [data_dir]\n";
        return 1;
    }

    const std::string room     = (argc >= 3) ? argv[2] : "lobby";
    const std::string data_dir = (argc >= 4) ? argv[3] : "";

    NodeConfig config;
    config.listen_port  = static_cast<uint16_t>(std::stoi(argv[1]));
    config.bind_address = "::";       // dual-stack
    config.data_dir     = data_dir;   // stable identity when set

    Node node(config);

    // — automatic discovery —
    // DHT (WAN): the room is the discovery key, so only same-room nodes meet.
    DhtDiscovery::Config dc;
    dc.discovery_key = room;
    dc.data_dir      = data_dir;      // co-locate the routing table with the identity
    node.add_subsystem(std::make_unique<DhtDiscovery>(std::move(dc)));

    // mDNS (LAN): zero-config discovery of peers on the same local network.
    node.add_subsystem(std::make_unique<MdnsDiscovery>());

    // PEX: once we know one peer, learn the peers it knows and dial them too.
    node.add_subsystem(std::make_unique<PeerExchange>());

    // Reconnection: remember peers we connect to and re-dial them if they drop
    // (persisted under data_dir when set, so it survives restarts).
    ReconnectionService::Config rc;
    if (!data_dir.empty()) rc.store_path = data_dir + "/peers.json";
    rc.max_attempts = 10;
    auto* reconnect = node.add_subsystem(std::make_unique<ReconnectionService>(rc));

    // Liveness + RTT.
    auto* ping = node.add_subsystem(std::make_unique<PingService>());

    // — the chat itself, as a GossipSub topic (relays across the whole mesh) —
    auto* pubsub = node.add_subsystem(std::make_unique<PubSub>());

    node.on_peer_connected([&](const Peer& peer) {
        std::cout << "[+] peer: " << peer.id().short_hex()
                  << "  (" << node.peer_count() << " total)\n";
        // Remember this peer so we reconnect to it automatically if it drops.
        if (auto info = peer.info())
            for (const Address& a : info->addresses) reconnect->add(a);
    });
    node.on_peer_disconnected([](const PeerId& id) {
        std::cout << "[-] peer gone: " << id.short_hex() << "\n";
    });

    pubsub->subscribe(room, [room](const PeerId& from, const std::string&, ByteView data) {
        std::cout << "[" << room << "] " << from.short_hex() << ": "
                  << std::string(reinterpret_cast<const char*>(data.data()), data.size()) << "\n";
    });

    if (!node.start()) {
        std::cerr << "failed to start node (port in use?)\n";
        return 1;
    }
    std::cout << "node " << node.local_id().short_hex() << " on port " << node.listen_port()
              << " in room \"" << room << "\"\n"
              << "discovering peers (mDNS on the LAN, DHT on the WAN, PEX from links)...\n"
              << "commands: type text to chat · /peers · Ctrl-D to quit\n";

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        if (line == "/peers") {
            auto peers = node.peers();
            std::cout << peers.size() << " peer(s):\n";
            for (const auto& p : peers) {
                std::cout << "  " << p.id.short_hex();
                if (auto rtt = ping->last_rtt(p.id)) std::cout << "  rtt=" << rtt->count() << "ms";
                std::cout << "\n";
            }
            continue;
        }
        pubsub->publish(room, ByteView(line));
    }

    node.stop();
    return 0;
}
