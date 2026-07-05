#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/bittorrent.h"
#include "subsystems/dht_discovery.h"
#include "bittorrent/bt_client.h"
#include "core/address.h"
#include "util/fs.h"

#include <chrono>
#include <memory>
#include <string>

using namespace librats;
using namespace std::chrono_literals;

namespace {

// A bare node that never opens its own listener — these tests exercise the
// BitTorrent subsystem wiring, not the peer mesh, so we keep the node minimal.
NodeConfig bare_node_config() {
    NodeConfig c;
    c.enable_listen = false;          // no inbound peer socket needed
    c.enable_network_monitor = false; // no monitor thread in tests
    c.security = NodeConfig::Security::Plaintext;
    return c;
}

// A DhtDiscovery config that stays entirely offline: no STUN, no internet
// bootstrap, IPv4 only (loopback UDP bind is all we need to get a live client).
DhtDiscovery::Config offline_dht_config() {
    DhtDiscovery::Config c;
    c.dht_port = 0;                   // ephemeral
    c.enable_ipv6 = false;
    c.discover_external_ip = false;   // skip STUN
    c.bootstrap_nodes = { HostEndpoint("127.0.0.1", 6881) };  // dummy → avoid internet defaults
    return c;
}

Bittorrent::Config offline_bt_config() {
    Bittorrent::Config c;
    c.client.listen_port = 0;         // ephemeral BT port
    c.client.download_path = "./test_node_bt_dl";
    return c;
}

constexpr const char* kMagnet =
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=test";

} // namespace

// The subsystem is dormant until the node starts it, and tears down with the node.
TEST(NodeBittorrentTest, LifecycleFollowsNode) {
    Node node(bare_node_config());
    auto* bt = node.add_subsystem(std::make_unique<Bittorrent>(offline_bt_config()));

    EXPECT_FALSE(bt->is_running());
    EXPECT_EQ(bt->client(), nullptr);

    ASSERT_TRUE(node.start());
    EXPECT_TRUE(bt->is_running());
    ASSERT_NE(bt->client(), nullptr);

    node.stop();
    EXPECT_FALSE(bt->is_running());
    EXPECT_EQ(bt->client(), nullptr);
}

// Without a DhtDiscovery attached the client stands up its own DHT.
TEST(NodeBittorrentTest, FallsBackToOwnDhtWhenNoneShared) {
    Node node(bare_node_config());
    auto* bt = node.add_subsystem(std::make_unique<Bittorrent>(offline_bt_config()));

    ASSERT_TRUE(node.start());
    EXPECT_FALSE(bt->using_node_dht());
    EXPECT_NE(bt->client()->get_dht_client(), nullptr);  // its own DHT
    node.stop();
}

// With a DhtDiscovery attached first, the client borrows that same Kademlia node.
TEST(NodeBittorrentTest, SharesNodeDht) {
    Node node(bare_node_config());
    auto* dht = node.add_subsystem(std::make_unique<DhtDiscovery>(offline_dht_config()));
    auto* bt  = node.add_subsystem(std::make_unique<Bittorrent>(offline_bt_config()));

    ASSERT_TRUE(node.start());

    if (!dht->is_running() || dht->dht_client() == nullptr) {
        node.stop();
        GTEST_SKIP() << "DHT could not bind locally; cannot verify sharing";
    }

    EXPECT_TRUE(bt->using_node_dht());
    EXPECT_EQ(bt->client()->get_dht_client(), dht->dht_client());  // one shared swarm

    node.stop();  // reverse-order teardown: Bittorrent stops before DhtDiscovery
}

// Magnet links can be added through the borrowed client once running.
TEST(NodeBittorrentTest, AddMagnetThroughClient) {
    Node node(bare_node_config());
    auto* bt = node.add_subsystem(std::make_unique<Bittorrent>(offline_bt_config()));

    ASSERT_TRUE(node.start());
    auto torrent = bt->client()->add_magnet(kMagnet, "./test_node_bt_dl", /*skip_dht_search=*/true);
    EXPECT_NE(torrent, nullptr);
    EXPECT_EQ(bt->client()->num_torrents(), 1u);
    node.stop();
}

// Spider mode (rats-search) is reachable through the subsystem and toggles the DHT.
TEST(NodeBittorrentTest, SpiderModeWrappers) {
    Node node(bare_node_config());
    auto* bt = node.add_subsystem(std::make_unique<Bittorrent>(offline_bt_config()));

    // Before start there is no DHT, so spider state is inert (and must not crash).
    EXPECT_FALSE(bt->is_spider_mode());

    ASSERT_TRUE(node.start());
    ASSERT_NE(bt->client()->get_dht_client(), nullptr);

    EXPECT_FALSE(bt->is_spider_mode());
    bt->set_spider_mode(true);
    EXPECT_TRUE(bt->is_spider_mode());

    bt->set_spider_ignore(true);
    EXPECT_TRUE(bt->is_spider_ignoring());

    bt->clear_spider_state();
    bt->spider_walk();  // must not crash with an empty pool
    EXPECT_GE(bt->spider_pool_size(), 0u);
    EXPECT_GE(bt->spider_visited_count(), 0u);

    bt->set_spider_mode(false);
    EXPECT_FALSE(bt->is_spider_mode());

    node.stop();
}
