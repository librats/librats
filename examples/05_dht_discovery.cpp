// 05_dht_discovery — automatic peer discovery via the Kademlia DHT.
//
// The previous examples dial peers by hand. DhtDiscovery instead announces our
// listen port under a discovery key on the mainline DHT and searches that same
// key, dialing whatever it finds — so two nodes sharing a key find each other
// with no known addresses, across the open internet.
//
//   05_dht_discovery <listen_port> [discovery_key] [data_dir]
//
//   ./05_dht_discovery 9000 my-app-demo
//   ./05_dht_discovery 9001 my-app-demo     # on another machine, same key
//
// Discovery goes through public bootstrap nodes, so give it a minute or two to
// converge. A shared, non-guessable key namespaces your app's swarm; passing a
// data_dir persists the identity and DHT routing table across restarts.

#include "node/node.h"
#include "subsystems/dht_discovery.h"

#include <chrono>
#include <iostream>
#include <string>
#include <thread>

using namespace librats;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <listen_port> [discovery_key] [data_dir]\n";
        return 1;
    }

    NodeConfig config;
    config.listen_port  = static_cast<uint16_t>(std::stoi(argv[1]));
    config.bind_address = "::";
    if (argc >= 4) config.data_dir = argv[3];

    Node node(config);

    // Attach DHT discovery. An empty discovery_key falls back to the node's
    // protocol string, so peers of the same app/version discover each other.
    DhtDiscovery::Config dc;
    if (argc >= 3) dc.discovery_key = argv[2];
    dc.data_dir = config.data_dir;  // co-locate the routing table with the identity
    node.add_subsystem(std::make_unique<DhtDiscovery>(std::move(dc)));

    node.on_peer_connected([](const Peer& peer) {
        std::cout << "[+] discovered + connected: " << peer.id().short_hex() << "\n";
    });
    node.on_peer_disconnected([](const PeerId& id) {
        std::cout << "[-] disconnected: " << id.short_hex() << "\n";
    });

    if (!node.start()) {
        std::cerr << "failed to start node\n";
        return 1;
    }
    std::cout << "node " << node.local_id().short_hex() << " on port " << node.listen_port()
              << " — announcing on the DHT, waiting for peers...\n"
                 "(bootstrap can take a minute or two; Ctrl-C to quit)\n";

    // Report the peer count periodically; discovery runs on its own threads.
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(15));
        std::cout << "[status] " << node.peer_count() << " peer(s) connected\n";
    }

    // (unreachable — stop on Ctrl-C) node.stop();
}
