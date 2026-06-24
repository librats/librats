// rats-client — the reference application for the librats Node API.
//
//   rats-client <listen_port> [options]
//
// It wires up the full set of opt-in subsystems so every capability of the
// library can be exercised from one binary. A bare Node is only the encrypted
// transport core (see node/node.h); everything below is attached explicitly.
// Every module is enabled by default ("all modules on"); use the --no-* flags to
// turn individual ones off.
//
// Options:
//   --bind <addr>          bind address (default "::" = dual-stack). e.g. 0.0.0.0, 127.0.0.1, ::1
//   --data <dir>           data directory (stable identity + reconnect/DHT store)
//   --connect <host> <port>  dial a peer at startup (repeatable)
//   --no-dht               disable DHT peer discovery (IPv4 + IPv6)
//   --no-mdns              disable mDNS (local-network) discovery
//   --no-upnp              disable UPnP / NAT-PMP port mapping
//   --no-pex               disable peer exchange (PEX)
//   --no-reconnect         disable auto-reconnection (persists targets under --data)
//   --no-ping              disable liveness ping
//   --no-bittorrent        disable BitTorrent      (only with RATS_SEARCH_FEATURES)
//   --bt-port <port>       BitTorrent listen port  (only with RATS_SEARCH_FEATURES; default 6881)
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
#include "subsystems/peer_exchange.h"
#include "subsystems/reconnection.h"
#include "core/address.h"
#include "util/fs.h"
#include "util/json.h"
#include "util/logger.h"
#ifdef RATS_SEARCH_FEATURES
#include "subsystems/bittorrent.h"
#endif
#ifdef RATS_STORAGE
#include "storage/storage.h"
#endif

#include <cstdint>
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
    DhtDiscovery*         dht       = nullptr;
#ifdef RATS_SEARCH_FEATURES
    Bittorrent*           bittorrent = nullptr;
#endif
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

// Parse a 40-character hex string into a 20-byte DHT info hash. Returns false if
// the input is not exactly 40 hex digits (so the caller can fall back to hashing
// a free-form key instead).
bool parse_info_hash(const std::string& hex, InfoHash& out) {
    if (hex.size() != out.size() * 2) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < out.size(); ++i) {
        const int hi = nibble(hex[2 * i]), lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

std::string info_hash_hex(const InfoHash& h) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(h.size() * 2);
    for (uint8_t b : h) { s.push_back(digits[b >> 4]); s.push_back(digits[b & 0xf]); }
    return s;
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
        "  /dhtfind <hash|key>        find peers via DHT (40-hex infohash, or a key string)\n"
#ifdef RATS_SEARCH_FEATURES
        "  /magnet <uri>              add a magnet link (downloads into ./downloads)\n"
        "  /torrent <file>            add a .torrent file\n"
        "  /spider <on|off>           toggle DHT spider mode (infohash crawler)\n"
        "  /bt                        show BitTorrent status\n"
#endif
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
                     " [--connect host port] [--no-dht] [--no-mdns] [--no-upnp] [--no-pex]"
                     " [--no-reconnect] [--no-ping]"
#ifdef RATS_SEARCH_FEATURES
                     " [--no-bittorrent] [--bt-port port]"
#endif
                     "\n";
        return 1;
    }

    // In a Debug build (NDEBUG undefined) surface the full DEBUG-level log; a
    // Release build keeps the default INFO threshold.
#ifndef NDEBUG
    Logger::getInstance().set_log_level(LogLevel::DEBUG);
#endif

    NodeConfig config;
    config.listen_port = static_cast<uint16_t>(std::stoi(argv[1]));
    config.bind_address = "::";  // dual-stack by default

    // Every module is on by default; --no-* turns one off. ("enable all modules")
    bool use_dht = true, use_mdns = true, use_upnp = true, use_pex = true,
         use_reconnect = true, use_ping = true;
#ifdef RATS_SEARCH_FEATURES
    bool use_bittorrent = true;
    uint16_t bt_port = 6881;
#endif
    std::vector<Address> dial_at_start;

    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if      (arg == "--bind" && i + 1 < argc)   config.bind_address = argv[++i];
        else if (arg == "--data" && i + 1 < argc)   config.data_dir = argv[++i];
        else if (arg == "--connect" && i + 2 < argc) {
            dial_at_start.push_back(Address{argv[i + 1], static_cast<uint16_t>(std::stoi(argv[i + 2]))});
            i += 2;
        }
        else if (arg == "--no-dht")       use_dht = false;
        else if (arg == "--no-mdns")      use_mdns = false;
        else if (arg == "--no-upnp")      use_upnp = false;
        else if (arg == "--no-pex")       use_pex = false;
        else if (arg == "--no-reconnect") use_reconnect = false;
        else if (arg == "--no-ping")      use_ping = false;
#ifdef RATS_SEARCH_FEATURES
        else if (arg == "--no-bittorrent") use_bittorrent = false;
        else if (arg == "--bt-port" && i + 1 < argc) bt_port = static_cast<uint16_t>(std::stoi(argv[++i]));
#endif
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

    // — optional subsystems, all enabled by default (gated by --no-* flags) —
    // DHT is attached BEFORE BitTorrent so the BitTorrent client can borrow this
    // same Kademlia node (one shared swarm) instead of standing up a second one.
    if (use_dht) {
        DhtDiscovery::Config dc;
        dc.data_dir = config.data_dir;  // co-locate routing tables with identity + peers
        auto dht = std::make_unique<DhtDiscovery>(std::move(dc));
        sub.dht = dht.get();
        node.add_subsystem(std::move(dht));
    }
    if (use_mdns)
        node.add_subsystem(std::make_unique<MdnsDiscovery>());
    if (use_upnp)
        node.add_subsystem(std::make_unique<PortMappingService>());
    if (use_pex)
        node.add_subsystem(std::make_unique<PeerExchange>());
    if (use_ping) {
        auto ping = std::make_unique<PingService>();
        sub.ping = ping.get();
        node.add_subsystem(std::move(ping));
    }
    if (use_reconnect) {
        ReconnectionService::Config rc;
        if (!config.data_dir.empty()) rc.store_path = config.data_dir + "/peers.json";
        rc.max_attempts = 10;  // give up on a persistently-dead target rather than retry forever
        auto reconnect = std::make_unique<ReconnectionService>(rc);
        sub.reconnect = reconnect.get();
        node.add_subsystem(std::move(reconnect));
    }
#ifdef RATS_SEARCH_FEATURES
    if (use_bittorrent) {
        Bittorrent::Config bc;
        bc.client.listen_port  = bt_port;
        bc.client.download_path = "./downloads";
        bc.use_node_dht = use_dht;  // share the node's DHT swarm when DHT is on
        auto bittorrent = std::make_unique<Bittorrent>(bc);
        sub.bittorrent = bittorrent.get();
        node.add_subsystem(std::move(bittorrent));
    }
#endif
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

    node.json()->on("msg", [](const PeerId& from, const librats::Json& data) {
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
              << " pex=" << use_pex << " reconnect=" << use_reconnect << " ping=" << use_ping
#ifdef RATS_SEARCH_FEATURES
              << " bittorrent=" << use_bittorrent
#endif
              << ")\n"
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
            node.json()->send("msg", librats::Json{{"text", body}});
        }
        else if (cmd == "/file" && args.size() >= 3) {
            PeerId to;
            if (!peer_at(node, std::stoul(args[1]), to)) { std::cout << "no such peer index\n"; continue; }
            const uint64_t id = sub.files->send_file(to, args[2]);
            std::cout << (id ? "sending file, transfer id " + std::to_string(id) : std::string("send failed")) << "\n";
        }
        else if (cmd == "/reconnect" && args.size() >= 3) {
            if (!sub.reconnect) { std::cout << "reconnect not enabled (--no-reconnect)\n"; continue; }
            sub.reconnect->add(Address{args[1], static_cast<uint16_t>(std::stoi(args[2]))});
        }
        else if (cmd == "/rmreconnect" && args.size() >= 3) {
            if (!sub.reconnect) { std::cout << "reconnect not enabled (--no-reconnect)\n"; continue; }
            sub.reconnect->remove(Address{args[1], static_cast<uint16_t>(std::stoi(args[2]))});
        }
        else if (cmd == "/dhtfind" && args.size() >= 2) {
            if (!sub.dht) { std::cout << "dht not enabled (--no-dht)\n"; continue; }
            DhtClient* dht = sub.dht->dht_client();
            if (!dht) { std::cout << "dht not running yet\n"; continue; }
            // Accept a 40-hex infohash directly; otherwise treat the argument as a
            // free-form key and hash it (same scheme DhtDiscovery uses internally).
            InfoHash hash;
            if (!parse_info_hash(args[1], hash)) hash = DhtDiscovery::hash_for_key(args[1]);
            std::cout << "searching DHT for " << info_hash_hex(hash) << " ...\n";
            // The callback fires on a DHT thread, possibly several times as peers
            // trickle in. Capture nothing but std::cout (process-lived).
            dht->find_peers(hash, [](const std::vector<Address>& peers, const InfoHash& h) {
                std::cout << "[dht] " << peers.size() << " peer(s) for " << info_hash_hex(h) << ":\n";
                for (const Address& a : peers) std::cout << "    " << a.to_string() << "\n";
            });
        }
#ifdef RATS_SEARCH_FEATURES
        else if (cmd == "/magnet" && args.size() >= 2) {
            if (!sub.bittorrent) { std::cout << "bittorrent not enabled (--no-bittorrent)\n"; continue; }
            auto t = sub.bittorrent->client()->add_magnet(args[1], "./downloads");
            std::cout << (t ? "added magnet\n" : "failed to add magnet\n");
        }
        else if (cmd == "/torrent" && args.size() >= 2) {
            if (!sub.bittorrent) { std::cout << "bittorrent not enabled (--no-bittorrent)\n"; continue; }
            auto t = sub.bittorrent->client()->add_torrent_file(args[1], "./downloads");
            std::cout << (t ? "added torrent\n" : "failed to add torrent\n");
        }
        else if (cmd == "/spider" && args.size() >= 2) {
            if (!sub.bittorrent) { std::cout << "bittorrent not enabled (--no-bittorrent)\n"; continue; }
            const std::string& v = args[1];
            sub.bittorrent->set_spider_mode(v == "on" || v == "1" || v == "true");
            std::cout << "spider mode " << (sub.bittorrent->is_spider_mode() ? "on" : "off") << "\n";
        }
        else if (cmd == "/bt") {
            if (!sub.bittorrent) { std::cout << "bittorrent not enabled (--no-bittorrent)\n"; continue; }
            auto* c = sub.bittorrent->client();
            std::cout << "torrents=" << c->num_torrents()
                      << " dl=" << c->total_download_rate() << "B/s"
                      << " ul=" << c->total_upload_rate() << "B/s"
                      << " peers=" << c->total_peers()
                      << " dht=" << (sub.bittorrent->using_node_dht() ? "shared" : "own")
                      << " spider=" << (sub.bittorrent->is_spider_mode() ? "on" : "off") << "\n";
        }
#endif
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
