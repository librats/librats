// 06_bittorrent_download — download a torrent by magnet link.
//
// This example is only built when the library is configured with
// -DRATS_SEARCH_FEATURES=ON (the BitTorrent subsystem is opt-in). It attaches
// DhtDiscovery *before* Bittorrent so the BitTorrent client borrows the node's
// Kademlia swarm instead of standing up a second one — the required ordering.
//
//   06_bittorrent_download "<magnet-uri>" [download_dir]
//
//   ./06_bittorrent_download "magnet:?xt=urn:btih:...." ./downloads
//
// It prints download/upload rates and peer counts once a second until the
// process is interrupted.

#include "node/node.h"
#include "subsystems/dht_discovery.h"
#include "subsystems/bittorrent.h"
#include "util/fs.h"

#include <chrono>
#include <iostream>
#include <string>
#include <thread>

using namespace librats;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " \"<magnet-uri>\" [download_dir]\n";
        return 1;
    }
    const std::string magnet       = argv[1];
    const std::string download_dir = (argc >= 3) ? argv[2] : "./downloads";
    create_directories(download_dir.c_str());

    NodeConfig config;
    config.listen_port  = 0;      // ephemeral — we only dial out here
    config.bind_address = "::";

    Node node(config);

    // DHT first: the BitTorrent client will share this swarm (peer discovery for
    // the info-hash). Bittorrent MUST be attached after DhtDiscovery.
    node.add_subsystem(std::make_unique<DhtDiscovery>(DhtDiscovery::Config{}));

    Bittorrent::Config bc;
    bc.client.download_path = download_dir;
    bc.use_node_dht         = true;  // reuse the node's DHT rather than a private one
    auto* bt = node.add_subsystem(std::make_unique<Bittorrent>(bc));

    if (!node.start()) {
        std::cerr << "failed to start node\n";
        return 1;
    }

    if (!bt->client()->add_magnet(magnet, download_dir)) {
        std::cerr << "failed to add magnet (malformed URI?)\n";
        node.stop();
        return 1;
    }
    std::cout << "added magnet, downloading into " << download_dir << "\n"
              << "resolving metadata + finding peers via DHT... (Ctrl-C to quit)\n";

    auto* c = bt->client();
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "\rtorrents=" << c->num_torrents()
                  << "  peers=" << c->total_peers()
                  << "  down=" << (c->total_download_rate() / 1024) << " KiB/s"
                  << "  up=" << (c->total_upload_rate() / 1024) << " KiB/s   " << std::flush;
    }

    // (unreachable — stop on Ctrl-C) node.stop();
}
