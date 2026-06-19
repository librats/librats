#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/reconnection.h"
#include "peer/peer_store.h"
#include "util/fs.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <thread>

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 15s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(2ms);
    }
    return pred();
}

NodeConfig listening_config() {
    NodeConfig c; c.bind_address = "127.0.0.1"; c.security = NodeConfig::Security::Noise; return c;
}
NodeConfig dialing_config() { NodeConfig c = listening_config(); c.enable_listen = false; return c; }

ReconnectionService::Config fast_reconnect() {
    ReconnectionService::Config c;
    c.tick = 100ms;
    c.base_backoff = 100ms;
    return c;
}

} // namespace

// The store round-trips addresses through a file.
TEST(PeerStoreTest, RoundTrip) {
    const std::string path = "rats_test_peers.txt";
    delete_file(path.c_str());
    {
        PeerStore store(path);
        EXPECT_TRUE(store.add(*Address::parse("127.0.0.1:4001")));
        EXPECT_TRUE(store.add(*Address::parse("10.0.0.5:5002")));
        EXPECT_FALSE(store.add(*Address::parse("127.0.0.1:4001")));  // dup
        store.save();
    }
    {
        PeerStore store(path);
        store.load();
        EXPECT_EQ(store.size(), 2u);
        const auto all = store.all();
        EXPECT_NE(std::find(all.begin(), all.end(), *Address::parse("10.0.0.5:5002")), all.end());
    }
    delete_file(path.c_str());
}

// After a connection drops, the service re-dials the target and reconnects.
TEST(ReconnectionServiceTest, ReestablishesAfterDrop) {
    Node server(listening_config());
    Node client(dialing_config());

    auto reconnect = std::make_unique<ReconnectionService>(fast_reconnect());
    ReconnectionService* svc = reconnect.get();
    client.add_subsystem(std::move(reconnect));

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    svc->add(*Address::parse("127.0.0.1:" + std::to_string(server.listen_port())));
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; })) << "initial connect failed";

    // Force a drop from the client side.
    auto peer = client.peer(server.local_id());
    ASSERT_TRUE(peer.has_value());
    peer->disconnect();
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 0; })) << "did not drop";

    // The reconnection service should bring it back (server is still up).
    EXPECT_TRUE(wait_for([&] { return client.peer_count() == 1; })) << "did not reconnect";

    client.stop();
    server.stop();
}

// Outbound peers are auto-remembered (persist_discovered) and survive a restart
// of the dialing node via the on-disk store.
TEST(ReconnectionServiceTest, PersistsDiscoveredAcrossRestart) {
    const std::string store_path = "rats_test_reconnect_store.txt";
    delete_file(store_path.c_str());

    Node server(listening_config());
    ASSERT_TRUE(server.start());
    const std::string server_addr = "127.0.0.1:" + std::to_string(server.listen_port());

    // First run: client dials the server; the service should remember it.
    {
        Node client(dialing_config());
        auto cfg = fast_reconnect();
        cfg.store_path = store_path;
        auto reconnect = std::make_unique<ReconnectionService>(cfg);
        ReconnectionService* svc = reconnect.get();
        client.add_subsystem(std::move(reconnect));
        ASSERT_TRUE(client.start());
        svc->add(*Address::parse(server_addr));
        ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; }));
        client.stop();
    }

    // The store now contains the server address.
    PeerStore store(store_path);
    store.load();
    EXPECT_GE(store.size(), 1u);
    const auto all = store.all();
    EXPECT_NE(std::find(all.begin(), all.end(), *Address::parse(server_addr)), all.end());

    // Second run: a fresh client with the same store reconnects with no explicit add().
    {
        Node client(dialing_config());
        auto cfg = fast_reconnect();
        cfg.store_path = store_path;
        client.add_subsystem(std::make_unique<ReconnectionService>(cfg));
        ASSERT_TRUE(client.start());
        EXPECT_TRUE(wait_for([&] { return client.peer_count() == 1; })) << "did not reconnect from store";
        client.stop();
    }

    server.stop();
    delete_file(store_path.c_str());
}
