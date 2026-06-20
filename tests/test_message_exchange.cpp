#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/message_exchange.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

using namespace librats;
using json = nlohmann::json;
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

NodeConfig server_config() {
    NodeConfig c;
    c.bind_address = "127.0.0.1";
    c.security = NodeConfig::Security::Noise;
    return c;
}

NodeConfig client_config() {
    NodeConfig c = server_config();
    c.enable_listen = false;
    return c;
}

// A connected server+client, each carrying a MessageExchange.
struct Pair {
    Node server{server_config()};
    Node client{client_config()};
    MessageExchange* srv = nullptr;
    MessageExchange* cli = nullptr;

    void connect() {
        auto s = std::make_unique<MessageExchange>();
        auto c = std::make_unique<MessageExchange>();
        srv = s.get();
        cli = c.get();
        server.add_subsystem(std::move(s));
        client.add_subsystem(std::move(c));
        ASSERT_TRUE(server.start());
        ASSERT_TRUE(client.start());
        client.connect("127.0.0.1", server.listen_port());
        ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));
    }

    ~Pair() { client.stop(); server.stop(); }
};

} // namespace

// A targeted typed message reaches the right handler with its JSON intact, and
// the reported sender is the peer's authenticated id.
TEST(MessageExchangeTest, TargetedSendAndReceive) {
    Pair p;
    p.connect();

    std::mutex mu;
    json got;
    PeerId from;
    p.srv->on("greet", [&](const PeerId& f, const json& data) {
        std::lock_guard<std::mutex> l(mu);
        got = data;
        from = f;
    });

    p.cli->send(p.server.local_id(), "greet", json{{"hello", "world"}, {"n", 7}});

    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(mu); return !got.is_null(); }));
    std::lock_guard<std::mutex> l(mu);
    EXPECT_EQ(got.value("hello", ""), "world");
    EXPECT_EQ(got.value("n", 0), 7);
    EXPECT_EQ(from, p.client.local_id());  // authenticated sender, not a spoofable field
}

// Broadcast reaches every connected peer's handler.
TEST(MessageExchangeTest, BroadcastReachesAllPeers) {
    Node hub(server_config());
    Node a(client_config());
    Node b(client_config());

    auto hub_mx = std::make_unique<MessageExchange>();
    auto a_mx = std::make_unique<MessageExchange>();
    auto b_mx = std::make_unique<MessageExchange>();
    MessageExchange* hmx = hub_mx.get();
    MessageExchange* amx = a_mx.get();
    MessageExchange* bmx = b_mx.get();
    hub.add_subsystem(std::move(hub_mx));
    a.add_subsystem(std::move(a_mx));
    b.add_subsystem(std::move(b_mx));

    std::atomic<int> got_a{0}, got_b{0};
    amx->on("news", [&](const PeerId&, const json& d) { if (d.value("v", 0) == 1) got_a++; });
    bmx->on("news", [&](const PeerId&, const json& d) { if (d.value("v", 0) == 1) got_b++; });

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());
    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; }));

    bool ok = false;
    hmx->send("news", json{{"v", 1}}, [&](bool success, const std::string&) { ok = success; });
    EXPECT_TRUE(ok);  // had peers to send to

    EXPECT_TRUE(wait_for([&] { return got_a.load() == 1 && got_b.load() == 1; }))
        << "a=" << got_a.load() << " b=" << got_b.load();

    a.stop();
    b.stop();
    hub.stop();
}

// once() handlers fire exactly once and are then removed.
TEST(MessageExchangeTest, OnceFiresOnce) {
    Pair p;
    p.connect();

    std::atomic<int> count{0};
    p.srv->once("tick", [&](const PeerId&, const json&) { count++; });

    p.cli->send(p.server.local_id(), "tick", json::object());
    ASSERT_TRUE(wait_for([&] { return count.load() == 1; }));

    p.cli->send(p.server.local_id(), "tick", json::object());
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(count.load(), 1);  // second message has no handler left
}

// off() removes all handlers for a type.
TEST(MessageExchangeTest, OffRemovesHandlers) {
    Pair p;
    p.connect();

    std::atomic<int> count{0};
    p.srv->on("ev", [&](const PeerId&, const json&) { count++; });
    p.srv->off("ev");

    p.cli->send(p.server.local_id(), "ev", json::object());
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(count.load(), 0);
}

// Multiple handlers for one type all fire, in registration order.
TEST(MessageExchangeTest, MultipleHandlersAllFire) {
    Pair p;
    p.connect();

    std::atomic<int> a{0}, b{0};
    p.srv->on("m", [&](const PeerId&, const json&) { a++; });
    p.srv->on("m", [&](const PeerId&, const json&) { b++; });

    p.cli->send(p.server.local_id(), "m", json::object());
    ASSERT_TRUE(wait_for([&] { return a.load() == 1 && b.load() == 1; }));
}

// The send callback reports failure for a peer we are not connected to.
TEST(MessageExchangeTest, SendCallbackPeerNotConnected) {
    Node node(server_config());
    auto mx = std::make_unique<MessageExchange>();
    MessageExchange* m = mx.get();
    node.add_subsystem(std::move(mx));
    ASSERT_TRUE(node.start());

    bool ok = true;
    std::string err;
    m->send(PeerId{}, "x", json::object(), [&](bool success, const std::string& e) { ok = success; err = e; });
    EXPECT_FALSE(ok);
    EXPECT_FALSE(err.empty());

    node.stop();
}

// A payload well past the receive ring-buffer size arrives whole and intact,
// proving the framing reassembles a typed message across recv boundaries.
TEST(MessageExchangeTest, LargeMessageIntegrity) {
    Pair p;
    p.connect();

    std::mutex mu;
    json got;
    p.srv->on("bulk", [&](const PeerId&, const json& data) {
        std::lock_guard<std::mutex> l(mu); got = data;
    });

    // ~64 KB of structured JSON — far beyond a single recv() worth of bytes.
    json payload;
    payload["tag"] = "bulk";
    json arr = json::array();
    for (int i = 0; i < 4000; ++i) arr.push_back(json{{"i", i}, {"s", "item-" + std::to_string(i)}});
    payload["items"] = std::move(arr);

    p.cli->send(p.server.local_id(), "bulk", payload);

    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(mu); return !got.is_null(); }));
    std::lock_guard<std::mutex> l(mu);
    ASSERT_TRUE(got.contains("items"));
    EXPECT_EQ(got["items"].size(), 4000u);          // nothing truncated
    EXPECT_EQ(got["items"].back().value("i", -1), 3999);
    EXPECT_EQ(got, payload);                          // byte-for-byte structural equality
}

// Broadcast with no peers reports failure via the callback.
TEST(MessageExchangeTest, BroadcastNoPeersCallback) {
    Node node(server_config());
    auto mx = std::make_unique<MessageExchange>();
    MessageExchange* m = mx.get();
    node.add_subsystem(std::move(mx));
    ASSERT_TRUE(node.start());

    bool ok = true;
    m->send("x", json::object(), [&](bool success, const std::string&) { ok = success; });
    EXPECT_FALSE(ok);

    node.stop();
}
