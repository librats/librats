// 02_pubsub — topic-based publish/subscribe (GossipSub) over librats.
//
// Adds the PubSub subsystem to a Node. Unlike the raw "chat" channel in
// 01_chat (which broadcasts to *directly connected* peers only), PubSub forms a
// per-topic mesh and relays messages across it, so a message reaches every
// subscriber even several hops away.
//
//   02_pubsub <listen_port> <topic> [connect_host connect_port]
//
// Example — three nodes on the same topic, chained A—B—C:
//   ./02_pubsub 9000 news
//   ./02_pubsub 9001 news 127.0.0.1 9000
//   ./02_pubsub 9002 news 127.0.0.1 9001
// A line typed at A is delivered to C even though they never connected directly.

#include "node/node.h"
#include "subsystems/pubsub.h"

#include <iostream>
#include <string>

using namespace librats;

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <listen_port> <topic> [connect_host connect_port]\n";
        return 1;
    }

    const std::string topic = argv[2];

    NodeConfig config;
    config.listen_port  = static_cast<uint16_t>(std::stoi(argv[1]));
    config.bind_address = "::";

    Node node(config);

    // add_subsystem returns a non-owning pointer we can drive after start().
    auto* pubsub = node.add_subsystem(std::make_unique<PubSub>());

    node.on_peer_connected([](const Peer& peer) {
        std::cout << "[+] connected: " << peer.id().short_hex() << "\n";
    });

    // Subscribing installs the delivery handler; it also announces our interest
    // to peers so the topic mesh can form. Safe to call before start().
    pubsub->subscribe(topic, [topic](const PeerId& from, const std::string&, ByteView data) {
        std::cout << "[" << topic << "] " << from.short_hex() << ": "
                  << std::string(reinterpret_cast<const char*>(data.data()), data.size()) << "\n";
    });

    if (!node.start()) {
        std::cerr << "failed to start node\n";
        return 1;
    }
    std::cout << "node " << node.local_id().short_hex()
              << " on port " << node.listen_port() << ", subscribed to \"" << topic << "\"\n";

    if (argc >= 5)
        node.connect(argv[3], static_cast<uint16_t>(std::stoi(argv[4])));

    std::cout << "type a message to publish (Ctrl-D to quit)\n";
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty())
            pubsub->publish(topic, ByteView(line));
    }

    node.stop();
    return 0;
}
