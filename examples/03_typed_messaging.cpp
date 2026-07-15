// 03_typed_messaging — typed JSON messages between peers.
//
// The MessageJson subsystem gives an on()/send() API keyed by a message *type*
// string, exchanging librats::Json payloads. The sender identity delivered to a
// handler is the *authenticated* PeerId from the handshake, never a self-reported
// field — so it cannot be spoofed.
//
//   03_typed_messaging <listen_port> [connect_host connect_port]
//
//   ./03_typed_messaging 9000
//   ./03_typed_messaging 9001 127.0.0.1 9000
// Each line you type is sent as a {"text": "..."} payload of type "chat" to all
// connected peers.

#include "node/node.h"
#include "subsystems/message_json.h"
#include "util/json.h"

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
    config.bind_address = "::";

    Node node(config);
    node.add_subsystem(std::make_unique<MessageJson>());  // reached below via node.json()

    node.on_peer_connected([](const Peer& peer) {
        std::cout << "[+] connected: " << peer.id().short_hex() << "\n";
    });

    // Register a handler for messages of type "chat". Handlers run on a reactor
    // thread; keep them non-blocking.
    node.json()->on("chat", [](const PeerId& from, const librats::Json& data) {
        std::cout << from.short_hex() << ": " << data.value("text", "") << "\n";
    });

    if (!node.start()) {
        std::cerr << "failed to start node\n";
        return 1;
    }
    std::cout << "node " << node.local_id().short_hex()
              << " on port " << node.listen_port() << "\n";

    if (argc >= 4)
        node.connect(argv[2], static_cast<uint16_t>(std::stoi(argv[3])));

    std::cout << "type a message (Ctrl-D to quit)\n";
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty())
            node.json()->send("chat", librats::Json{{"text", line}});
    }

    node.stop();
    return 0;
}
