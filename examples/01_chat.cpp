// 01_chat — the smallest useful librats program: an encrypted P2P chat.
//
// It shows the *bare* Node: encrypted transport (Noise_XX over a self-certifying
// PeerId) plus raw channel messaging — no subsystems attached. Peers are dialed
// manually; a bare Node never discovers peers on its own (see 05_dht_discovery
// for automatic discovery).
//
//   01_chat <listen_port> [connect_host connect_port]
//
// Start one node as a listener, then a second that dials it:
//   ./01_chat 9000
//   ./01_chat 9001 127.0.0.1 9000
// Type a line in either terminal; it is broadcast on the "chat" channel to every
// connected peer. Ctrl-D (EOF) quits.

#include "node/node.h"

#include <iostream>
#include <string>

using namespace librats;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <listen_port> [connect_host connect_port]\n";
        return 1;
    }

    NodeConfig config;
    config.listen_port  = static_cast<uint16_t>(std::stoi(argv[1]));
    config.bind_address = "::";  // dual-stack (IPv6 + IPv4-mapped)

    Node node(config);

    // Callbacks run on a reactor thread and must be registered BEFORE start().
    node.on_peer_connected([](const Peer& peer) {
        std::cout << "[+] connected: " << peer.id().short_hex() << "\n";
    });
    node.on_peer_disconnected([](const PeerId& id) {
        std::cout << "[-] disconnected: " << id.short_hex() << "\n";
    });
    node.on("chat", [](const Peer& peer, ByteView data) {
        std::cout << peer.id().short_hex() << ": "
                  << std::string(reinterpret_cast<const char*>(data.data()), data.size()) << "\n";
    });

    if (!node.start()) {
        std::cerr << "failed to start node (port in use?)\n";
        return 1;
    }
    std::cout << "node " << node.local_id().short_hex()
              << " listening on port " << node.listen_port() << "\n";

    // Optionally dial a peer at startup. connect() is non-blocking; the peer
    // surfaces asynchronously via on_peer_connected once the handshake completes.
    if (argc >= 4)
        node.connect(argv[2], static_cast<uint16_t>(std::stoi(argv[3])));

    std::cout << "type a message and press enter (Ctrl-D to quit)\n";
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty())
            node.broadcast("chat", ByteView(line));
    }

    node.stop();
    return 0;
}
