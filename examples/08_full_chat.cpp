// 08_full_chat — a "batteries-included" chat that finds its peers by itself, and
//                reaches them even from behind a NAT.
//
// The earlier chat examples dial peers by hand on a LAN. This one attaches every
// discovery, connectivity and resilience subsystem librats offers and then just...
// works: start two nodes with the same room name anywhere — the same LAN, or two
// home connections on opposite sides of the internet — and they find each other,
// get a path through their routers, form a gossip mesh, and relay chat across it.
// No addresses typed in.
//
// Wired up here:
//   • DhtDiscovery  — announce/search a room key on the global Kademlia DHT (WAN)
//   • MdnsDiscovery — zero-config discovery of peers on the local network (LAN)
//   • PeerExchange  — peers gossip the peers they know, so the mesh fills in fast
//   • PortMappingService — ask the home router (UPnP / NAT-PMP) to forward our port
//   • HolePunch     — when the router won't, both sides dial at once through a
//                     rendezvous peer and cross mid-path
//   • Relay         — and when even that cannot land, borrow a path through a node
//                     both ends can already reach (end-to-end encrypted regardless)
//   • ReconnectionService — remembers peers (under data_dir) and re-dials them
//   • PingService   — liveness + round-trip time
//   • PubSub        — the chat itself, as a GossipSub topic (relays across hops)
//
// The three NAT subsystems are a ladder, tried in that order and each cheaper than
// the next: a forwarded port is a direct connection, a punch is a direct connection
// bought with one relayed rendezvous, and a circuit spends a third node's
// bandwidth. They hand off to each other on their own — HolePunch falls through to
// RelayService, and a circuit that comes up asks HolePunch to try again so the
// relay can be dropped as soon as a direct link is possible.
//
//   08_full_chat <listen_port> [room] [data_dir] [--serve-relay]
//
//   ./08_full_chat 9000 lobby ./node-a     # terminal / machine 1
//   ./08_full_chat 9001 lobby ./node-b     # terminal / machine 2
//
// Nodes in the same <room> discover each other; the room also namespaces the DHT
// swarm and the pub/sub topic. Passing a <data_dir> gives each node a stable
// identity and persists its known-peer list across restarts. LAN peers appear in
// a second or two (mDNS); WAN peers take a minute or two (DHT bootstrap).
//
// --serve-relay carries OTHER peers' connections through this node. It is off by
// default because it spends real bandwidth on somebody else's traffic — but a mesh
// in which nobody serves cannot relay at all, so a well-connected node (a seed, a
// bootstrap) is the one that should turn it on.

#include <librats/node/node.h>
#include <librats/subsystems/dht_discovery.h>
#include <librats/subsystems/hole_punch.h>
#include <librats/subsystems/mdns_discovery.h>
#include <librats/subsystems/peer_exchange.h>
#include <librats/subsystems/ping_service.h>
#include <librats/subsystems/port_mapping_service.h>
#include <librats/subsystems/pubsub.h>
#include <librats/subsystems/reconnection.h>
#include <librats/subsystems/relay.h>

#include <iostream>
#include <string>
#include <vector>

using namespace librats;

int main(int argc, char** argv) {
    std::vector<std::string> args;
    bool serve_relay = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--serve-relay") serve_relay = true;
        else                      args.push_back(a);
    }
    if (args.empty()) {
        std::cerr << "usage: " << argv[0]
                  << " <listen_port> [room] [data_dir] [--serve-relay]\n";
        return 1;
    }

    const std::string room     = (args.size() >= 2) ? args[1] : "lobby";
    const std::string data_dir = (args.size() >= 3) ? args[2] : "";

    NodeConfig config;
    config.listen_port  = static_cast<uint16_t>(std::stoi(args[0]));
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

    // — getting through the NAT, cheapest rung first —
    // Port forwarding: ask the router for our listen port over every transport we
    // actually run. When it works there is no NAT problem left to solve.
    node.add_subsystem(std::make_unique<PortMappingService>());

    // Hole punching: for the routers that refuse. Two peers dial each other at the
    // same instant through a peer they both already have, and the two datagram
    // bursts cross mid-path. Declines by itself when the mesh has shown our NAT to
    // be symmetric, and hands the target to the relay below instead.
    node.add_subsystem(std::make_unique<HolePunch>());

    // Relay: the last rung, for pairs no punch can reach. What is relayed is a byte
    // stream, so the Noise handshake stays end-to-end — the relay moves ciphertext
    // it cannot read or forge, and pub/sub, ping and file transfer work over a
    // relayed peer with no code of their own.
    Relay::Config rr;
    rr.serve = serve_relay;           // carrying other peers' traffic is opt-in
    auto* relay = node.add_subsystem(std::make_unique<Relay>(rr));

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
    node.on_peer_disconnected([](const PeerId& id, CloseReason reason) {
        std::cout << "[-] peer gone: " << id.short_hex()
                  << " (" << to_string(reason) << ")\n";
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
              << " in room \"" << room << "\"" << (serve_relay ? "  [serving as a relay]" : "")
              << "\n"
              << "discovering peers (mDNS on the LAN, DHT on the WAN, PEX from links)...\n"
              << "commands: type text to chat · /peers · /nat · Ctrl-D to quit\n";

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        if (line == "/peers") {
            auto peers = node.peers();
            std::cout << peers.size() << " peer(s):\n";
            for (const auto& p : peers) {
                // transport says how we got to this peer: Tcp/Udp is a direct link
                // (forwarded, punched, or never NATed at all), Relay means the bytes
                // are going through a third node — and will be swapped for a direct
                // link, with no disconnect event, the moment a punch lands.
                std::cout << "  " << p.id.short_hex() << "  " << to_string(p.transport);
                if (auto rtt = ping->last_rtt(p.id)) std::cout << "  rtt=" << rtt->count() << "ms";
                std::cout << "\n";
            }
            continue;
        }
        if (line == "/nat") {
            // What the mesh has shown about our own side of the NAT, from the
            // endpoints datagram peers report seeing our shared UDP socket at.
            // Two peers agreeing means one mapping for every destination, which is
            // what a punch needs; two disagreeing means a symmetric NAT and
            // HolePunch will not waste a burst on it.
            const NatStatus& nat = node.nat_status();
            std::cout << "nat mapping: " << to_string(nat.udp_mapping())
                      << "  (" << nat.observation_count() << " peer observation(s))\n";
            for (const Address& a : nat.external_udp_endpoints())
                std::cout << "  external udp: " << a.to_string() << "\n";
            for (const Address& a : node.observed_addresses())
                std::cout << "  observed: " << a.to_string() << "\n";
            std::cout << "relayed peers: " << relay->circuits()
                      << "  carried for others: " << relay->carried_circuits() << "\n";
            continue;
        }
        pubsub->publish(room, ByteView(line));
    }

    node.stop();
    return 0;
}
