// rats-client — a minimal P2P chat node built on the redesigned Node API.
//
//   rats-client <listen_port> [<host> <port>]   [--dht]
//
// Lines typed on stdin are broadcast on the "chat" channel to all peers;
// messages from peers are printed. Pass a host+port to dial a peer, and --dht
// to also discover peers over the DHT.

#include "node/node.h"
#include "subsystems/dht_discovery.h"

#include <iostream>
#include <memory>
#include <string>

using namespace librats;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <listen_port> [<host> <port>] [--dht]\n";
        return 1;
    }

    NodeConfig config;
    config.listen_port = static_cast<uint16_t>(std::stoi(argv[1]));
    config.bind_address = "0.0.0.0";  // all IPv4 interfaces

    Node node(config);

    bool use_dht = false;
    for (int i = 2; i < argc; ++i)
        if (std::string(argv[i]) == "--dht") use_dht = true;
    if (use_dht)
        node.add_subsystem(std::make_unique<DhtDiscovery>(DhtDiscovery::Config{}));

    node.on_peer_connected([](const PeerHandle& peer) {
        std::cout << "[+] peer connected: " << peer.id().short_hex() << "\n";
    });
    node.on_peer_disconnected([](const PeerId& id) {
        std::cout << "[-] peer disconnected: " << id.short_hex() << "\n";
    });
    node.on_message("chat", [](const PeerHandle& peer, ByteView data) {
        std::cout << peer.id().short_hex() << ": "
                  << std::string(reinterpret_cast<const char*>(data.data()), data.size()) << "\n";
    });

    if (!node.start()) {
        std::cerr << "failed to start node\n";
        return 1;
    }
    std::cout << "node " << node.local_id().short_hex()
              << " listening on port " << node.listen_port() << "\n";

    if (argc >= 4 && std::string(argv[2]) != "--dht")
        node.connect(argv[2], static_cast<uint16_t>(std::stoi(argv[3])));

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "/quit") break;
        node.broadcast("chat", ByteView(line));
    }

    node.stop();
    return 0;
}
