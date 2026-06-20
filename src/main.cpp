// rats-client — the reference application for the librats Node API.
//
//   rats-client <listen_port> [options]
//
// It wires up the full set of opt-in subsystems so every capability of the
// library can be exercised from one binary. A bare Node is only the encrypted
// transport core (see node/node.h); everything below is attached explicitly.
//
// Options:
//   --bind <addr>          bind address (default "::" = dual-stack). e.g. 0.0.0.0, 127.0.0.1, ::1
//   --data <dir>           data directory (stable identity + reconnect store)
//   --connect <host> <port>  dial a peer at startup (repeatable)
//   --dht                  enable DHT peer discovery (IPv4 + IPv6)
//   --mdns                 enable mDNS (local-network) discovery
//   --upnp                 enable UPnP / NAT-PMP port mapping
//   --reconnect            enable auto-reconnection (persists targets under --data)
//   --no-ping              disable liveness ping (on by default)
//
// Pub/sub, typed JSON messaging and file transfer are always enabled. Type
// "/help" once running for the interactive command list.

#include "node/node.h"
#include "subsystems/dht_discovery.h"
#include "subsystems/mdns_discovery.h"
#include "subsystems/pubsub.h"
#include "subsystems/message_json.h"
#include "subsystems/file_transfer.h"
#include "subsystems/ping_service.h"
#include "subsystems/port_mapping_service.h"
#include "subsystems/reconnection.h"
#include "core/address.h"
#include "util/fs.h"
#include "util/json.hpp"
#ifdef RATS_STORAGE
#include "storage/storage.h"
#endif

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace librats;

namespace {

// Subsystems we keep raw pointers to so the command loop can drive them. The Node
// owns them (add_subsystem moves ownership); the pointers stay valid until the
// command loop exits and node.stop() runs.
struct Subsystems {
    PubSub*               pubsub    = nullptr;
    FileTransfer*         files     = nullptr;
    PingService*          ping      = nullptr;
    ReconnectionService*  reconnect = nullptr;
#ifdef RATS_STORAGE
    StorageManager*       storage   = nullptr;
#endif
};

std::vector<std::string> split(const std::string& line) {
    std::vector<std::string> out;
    std::istringstream in(line);
    std::string tok;
    while (in >> tok) out.push_back(tok);
    return out;
}

std::string to_text(ByteView v) {
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

void print_help() {
    std::cout <<
        "commands:\n"
        "  <text>                     broadcast on the \"chat\" channel\n"
        "  /peers                     list connected peers (index, id, RTT)\n"
        "  /connect <host> <port>     dial a peer\n"
        "  /sub <topic>               subscribe to a pub/sub topic\n"
        "  /unsub <topic>             unsubscribe\n"
        "  /pub <topic> <text...>     publish to a topic\n"
        "  /msg <text...>             send a typed JSON message (type \"msg\")\n"
        "  /file <peer#> <path>       send a file to a peer (index from /peers)\n"
        "  /reconnect <host> <port>   add an auto-reconnect target\n"
        "  /rmreconnect <host> <port> remove an auto-reconnect target\n"
#ifdef RATS_STORAGE
        "  /put <key> <value>         set a distributed-storage key\n"
        "  /get <key>                 read a distributed-storage key\n"
#endif
        "  /help                      this help\n"
        "  /quit                      exit\n";
}

// Resolve a peer by its index in the current snapshot (as shown by /peers).
bool peer_at(Node& node, size_t index, PeerId& out) {
    auto peers = node.peers();
    if (index >= peers.size()) return false;
    out = peers[index].id;
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <listen_port> [--bind addr] [--data dir]"
                     " [--connect host port] [--dht] [--mdns] [--upnp] [--reconnect] [--no-ping]\n";
        return 1;
    }

    NodeConfig config;
    config.listen_port = static_cast<uint16_t>(std::stoi(argv[1]));
    config.bind_address = "::";  // dual-stack by default

    bool use_dht = false, use_mdns = false, use_upnp = false, use_reconnect = false, use_ping = true;
    std::vector<Address> dial_at_start;

    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if      (arg == "--bind" && i + 1 < argc)   config.bind_address = argv[++i];
        else if (arg == "--data" && i + 1 < argc)   config.data_dir = argv[++i];
        else if (arg == "--connect" && i + 2 < argc) {
            dial_at_start.push_back(Address{argv[i + 1], static_cast<uint16_t>(std::stoi(argv[i + 2]))});
            i += 2;
        }
        else if (arg == "--dht")       use_dht = true;
        else if (arg == "--mdns")      use_mdns = true;
        else if (arg == "--upnp")      use_upnp = true;
        else if (arg == "--reconnect") use_reconnect = true;
        else if (arg == "--no-ping")   use_ping = false;
        else std::cerr << "ignoring unknown argument: " << arg << "\n";
    }

    Node node(config);
    Subsystems sub;

    // — always-on demo subsystems: pub/sub, typed messaging, file transfer —
    {
        auto pubsub = std::make_unique<PubSub>();
        sub.pubsub = pubsub.get();
        node.add_subsystem(std::move(pubsub));

        node.add_subsystem(std::make_unique<MessageJson>());  // reached via node.json()

        auto files = std::make_unique<FileTransfer>("./downloads");
        sub.files = files.get();
        node.add_subsystem(std::move(files));
    }

    // — optional subsystems, gated by flags —
    if (use_dht) {
        DhtDiscovery::Config dc;
        dc.data_dir = config.data_dir;  // co-locate routing tables with identity + peers
        node.add_subsystem(std::make_unique<DhtDiscovery>(std::move(dc)));
    }
    if (use_mdns)
        node.add_subsystem(std::make_unique<MdnsDiscovery>());
    if (use_upnp)
        node.add_subsystem(std::make_unique<PortMappingService>());
    if (use_ping) {
        auto ping = std::make_unique<PingService>();
        sub.ping = ping.get();
        node.add_subsystem(std::move(ping));
    }
    if (use_reconnect) {
        ReconnectionService::Config rc;
        if (!config.data_dir.empty()) rc.store_path = config.data_dir + "/peers.txt";
        rc.max_attempts = 10;  // give up on a persistently-dead target rather than retry forever
        auto reconnect = std::make_unique<ReconnectionService>(rc);
        sub.reconnect = reconnect.get();
        node.add_subsystem(std::move(reconnect));
    }
#ifdef RATS_STORAGE
    {
        auto storage = std::make_unique<StorageManager>();
        sub.storage = storage.get();
        node.add_subsystem(std::move(storage));
    }
#endif

    // — core + subsystem event wiring (register before start()) —
    node.on_peer_connected([&](const Peer& peer) {
        std::cout << "[+] peer connected: " << peer.id().short_hex() << "\n";
        if (sub.reconnect) {  // remember dialed peers for reconnection
            auto info = peer.info();
            if (info) for (const Address& a : info->addresses) sub.reconnect->add(a);
        }
    });
    node.on_peer_disconnected([](const PeerId& id) {
        std::cout << "[-] peer disconnected: " << id.short_hex() << "\n";
    });
    node.on("chat", [](const Peer& peer, ByteView data) {
        std::cout << peer.id().short_hex() << ": " << to_text(data) << "\n";
    });

    node.json()->on("msg", [](const PeerId& from, const nlohmann::json& data) {
        std::cout << "[msg] " << from.short_hex() << ": " << data.value("text", "") << "\n";
    });

    // Auto-accept incoming files into ./downloads and report progress/result.
    create_directories("./downloads");
    sub.files->on_offer([&](const FileTransfer::Offer& offer) {
        std::cout << "[file] offer from " << offer.from.short_hex() << ": " << offer.name
                  << " (" << offer.size << " bytes) — accepting into ./downloads\n";
        sub.files->accept(offer.from, offer.id, "./downloads/" + offer.name);
    });
    sub.files->on_complete([](uint64_t id, bool ok, const std::string& path) {
        std::cout << "[file] transfer " << id << (ok ? " complete: " : " FAILED: ") << path << "\n";
    });

    if (!node.start()) {
        std::cerr << "failed to start node\n";
        return 1;
    }
    std::cout << "node " << node.local_id().short_hex() << " listening on port " << node.listen_port()
              << " (dht=" << use_dht << " mdns=" << use_mdns << " upnp=" << use_upnp
              << " reconnect=" << use_reconnect << " ping=" << use_ping << ")\n"
              << "type /help for commands\n";

    for (const Address& a : dial_at_start) {
        std::cout << "dialing " << a.to_string() << "\n";
        node.connect(a);
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        if (line[0] != '/') { node.broadcast("chat", ByteView(line)); continue; }

        const auto args = split(line);
        const std::string& cmd = args[0];

        if (cmd == "/quit") break;
        else if (cmd == "/help") print_help();
        else if (cmd == "/peers") {
            auto peers = node.peers();
            std::cout << peers.size() << " peer(s):\n";
            for (size_t i = 0; i < peers.size(); ++i) {
                std::cout << "  [" << i << "] " << peers[i].id.short_hex();
                if (sub.ping) {
                    auto rtt = sub.ping->last_rtt(peers[i].id);
                    if (rtt) std::cout << "  rtt=" << rtt->count() << "ms";
                }
                std::cout << "\n";
            }
        }
        else if (cmd == "/connect" && args.size() >= 3)
            node.connect(args[1], static_cast<uint16_t>(std::stoi(args[2])));
        else if (cmd == "/sub" && args.size() >= 2) {
            const std::string topic = args[1];
            sub.pubsub->subscribe(topic, [topic](const PeerId& from, const std::string&, ByteView data) {
                std::cout << "[" << topic << "] " << from.short_hex() << ": " << to_text(data) << "\n";
            });
            std::cout << "subscribed to " << topic << "\n";
        }
        else if (cmd == "/unsub" && args.size() >= 2)
            sub.pubsub->unsubscribe(args[1]);
        else if (cmd == "/pub" && args.size() >= 3) {
            const std::string topic = args[1];
            const std::string body = line.substr(line.find(args[2]));
            sub.pubsub->publish(topic, ByteView(body));
        }
        else if (cmd == "/msg" && args.size() >= 2) {
            const std::string body = line.substr(line.find(args[1]));
            node.json()->send("msg", nlohmann::json{{"text", body}});
        }
        else if (cmd == "/file" && args.size() >= 3) {
            PeerId to;
            if (!peer_at(node, std::stoul(args[1]), to)) { std::cout << "no such peer index\n"; continue; }
            const uint64_t id = sub.files->send_file(to, args[2]);
            std::cout << (id ? "sending file, transfer id " + std::to_string(id) : std::string("send failed")) << "\n";
        }
        else if (cmd == "/reconnect" && args.size() >= 3) {
            if (!sub.reconnect) { std::cout << "reconnect not enabled (--reconnect)\n"; continue; }
            sub.reconnect->add(Address{args[1], static_cast<uint16_t>(std::stoi(args[2]))});
        }
        else if (cmd == "/rmreconnect" && args.size() >= 3) {
            if (!sub.reconnect) { std::cout << "reconnect not enabled (--reconnect)\n"; continue; }
            sub.reconnect->remove(Address{args[1], static_cast<uint16_t>(std::stoi(args[2]))});
        }
#ifdef RATS_STORAGE
        else if (cmd == "/put" && args.size() >= 3) {
            sub.storage->put(args[1], args[2]);
            std::cout << "stored " << args[1] << "\n";
        }
        else if (cmd == "/get" && args.size() >= 2) {
            auto v = sub.storage->get_string(args[1]);
            std::cout << args[1] << " = " << (v ? *v : std::string("<none>")) << "\n";
        }
#endif
        else std::cout << "unknown command (try /help)\n";
    }

    node.stop();
    return 0;
}
