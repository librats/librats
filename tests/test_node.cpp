#include <gtest/gtest.h>

#include "node/node.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 10s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

std::string str(ByteView v) {
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

NodeConfig server_config() {
    NodeConfig c;
    c.listen_port = 0;          // ephemeral
    c.bind_address = "127.0.0.1";
    c.security = NodeConfig::Security::Noise;
    return c;
}

NodeConfig client_config() {
    NodeConfig c = server_config();
    c.enable_listen = false;    // dial-only
    return c;
}

} // namespace

// Connect, send on a named channel, get a reply — all encrypted end to end.
TEST(NodeTest, ConnectAndEchoMessage) {
    Node server(server_config());
    Node client(client_config());

    std::atomic<int> server_peers{0}, client_peers{0};
    server.on_peer_connected([&](const PeerHandle&) { server_peers++; });
    client.on_peer_connected([&](const PeerHandle&) { client_peers++; });

    // Server echoes whatever arrives on "chat" back to the sender.
    server.on_message("chat", [](const PeerHandle& from, ByteView msg) { from.send("chat", msg); });

    std::mutex mu;
    std::string got;
    client.on_message("chat", [&](const PeerHandle&, ByteView msg) {
        std::lock_guard<std::mutex> lock(mu);
        got = str(msg);
    });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }))
        << "peers: client=" << client.peer_count() << " server=" << server.peer_count();

    EXPECT_EQ(server_peers.load(), 1);
    EXPECT_EQ(client_peers.load(), 1);

    // Both directories learned the other's self-certifying id.
    EXPECT_TRUE(client.peer(server.local_id()).has_value());
    EXPECT_TRUE(server.peer(client.local_id()).has_value());

    client.send(server.local_id(), "chat", ByteView(std::string("hello node")));
    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(mu); return got == "hello node"; }))
        << "no echo received";

    client.stop();
    server.stop();
}

// Replying through the Peer handle passed to the message callback.
TEST(NodeTest, ReplyViaPeerHandle) {
    Node server(server_config());
    Node client(client_config());

    server.on_message("ping", [](const PeerHandle& from, ByteView) { from.send("pong", ByteView(std::string("ok"))); });

    std::atomic<bool> ponged{false};
    client.on_message("pong", [&](const PeerHandle&, ByteView msg) { if (str(msg) == "ok") ponged = true; });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; }));

    client.send(server.local_id(), "ping", ByteView());
    ASSERT_TRUE(wait_for([&] { return ponged.load(); }));

    client.stop();
    server.stop();
}

// Hub broadcasts to all connected spokes.
TEST(NodeTest, BroadcastToAllPeers) {
    Node hub(server_config());
    Node a(client_config());
    Node b(client_config());

    std::atomic<int> got_a{0}, got_b{0};
    a.on_message("news", [&](const PeerHandle&, ByteView m) { if (str(m) == "extra") got_a++; });
    b.on_message("news", [&](const PeerHandle&, ByteView m) { if (str(m) == "extra") got_b++; });

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; }))
        << "hub peers: " << hub.peer_count();

    hub.broadcast("news", ByteView(std::string("extra")));
    ASSERT_TRUE(wait_for([&] { return got_a.load() == 1 && got_b.load() == 1; }))
        << "a=" << got_a.load() << " b=" << got_b.load();

    a.stop();
    b.stop();
    hub.stop();
}

// Disconnecting one side fires the peer-disconnected event on the other.
TEST(NodeTest, DisconnectNotifiesPeer) {
    Node server(server_config());
    Node client(client_config());

    std::atomic<int> server_disconnects{0};
    server.on_peer_disconnected([&](PeerId) { server_disconnects++; });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.peer_count() == 1; }));

    client.stop();  // drops the connection
    ASSERT_TRUE(wait_for([&] { return server_disconnects.load() == 1; }));
    EXPECT_EQ(server.peer_count(), 0u);

    server.stop();
}
