#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/pubsub.h"

#include <atomic>
#include <chrono>
#include <memory>
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

std::string str(ByteView v) { return std::string(reinterpret_cast<const char*>(v.data()), v.size()); }

NodeConfig listening_config() {
    NodeConfig c;
    c.bind_address = "127.0.0.1";
    c.security = NodeConfig::Security::Noise;
    return c;
}
NodeConfig dialing_config() {
    NodeConfig c = listening_config();
    c.enable_listen = false;
    return c;
}

struct PubSubNode {
    Node node;
    PubSub* ps;
    explicit PubSubNode(NodeConfig cfg) : node(std::move(cfg)) {
        auto sub = std::make_unique<PubSub>();
        ps = sub.get();
        node.add_subsystem(std::move(sub));
    }
};

} // namespace

// A message published on one node reaches a subscriber on another.
TEST(PubSubTest, DeliversAcrossPeers) {
    PubSubNode server(listening_config());
    PubSubNode client(dialing_config());

    std::mutex mu;
    std::string got_topic, got_data;
    PeerId got_from;
    client.ps->subscribe("weather", [&](const PeerId& from, const std::string& topic, ByteView data) {
        std::lock_guard<std::mutex> lock(mu);
        got_from = from; got_topic = topic; got_data = str(data);
    });

    ASSERT_TRUE(server.node.start());
    ASSERT_TRUE(client.node.start());
    client.node.connect("127.0.0.1", server.node.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.node.peer_count() == 1 && client.node.peer_count() == 1; }));

    // The server must learn the client subscribed to "weather" before publishing.
    ASSERT_TRUE(wait_for([&] { return server.ps->peers_for_topic("weather").size() == 1; }))
        << "subscription did not propagate";

    server.ps->publish("weather", ByteView(std::string("sunny")));

    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(mu); return got_data == "sunny"; }))
        << "message not delivered";
    {
        std::lock_guard<std::mutex> lock(mu);
        EXPECT_EQ(got_topic, "weather");
        EXPECT_EQ(got_from, server.node.local_id());  // origin is the publisher
    }

    client.node.stop();
    server.node.stop();
}

// Only peers subscribed to a topic receive its messages.
TEST(PubSubTest, RespectsSubscriptions) {
    PubSubNode hub(listening_config());
    PubSubNode a(dialing_config());
    PubSubNode b(dialing_config());

    std::atomic<int> got_a{0}, got_b{0};
    a.ps->subscribe("sports", [&](const PeerId&, const std::string&, ByteView) { got_a++; });
    b.ps->subscribe("music",  [&](const PeerId&, const std::string&, ByteView) { got_b++; });

    ASSERT_TRUE(hub.node.start());
    ASSERT_TRUE(a.node.start());
    ASSERT_TRUE(b.node.start());
    a.node.connect("127.0.0.1", hub.node.listen_port());
    b.node.connect("127.0.0.1", hub.node.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.node.peer_count() == 2; }));
    ASSERT_TRUE(wait_for([&] {
        return hub.ps->peers_for_topic("sports").size() == 1 &&
               hub.ps->peers_for_topic("music").size() == 1;
    }));

    hub.ps->publish("sports", ByteView(std::string("goal")));
    ASSERT_TRUE(wait_for([&] { return got_a.load() == 1; }));

    // b is not subscribed to "sports" — give it time to (not) arrive.
    std::this_thread::sleep_for(150ms);
    EXPECT_EQ(got_b.load(), 0);

    a.node.stop();
    b.node.stop();
    hub.node.stop();
}

// A subscribed hub relays a publish among its subscribers (a → hub → b).
// (Subscription-aware floodsub forwards to subscribed neighbours; multi-hop
// through an UNsubscribed relay is a GossipSub mesh feature — a future layer.)
TEST(PubSubTest, ForwardsAmongSubscribers) {
    PubSubNode hub(listening_config());
    PubSubNode a(dialing_config());
    PubSubNode b(dialing_config());

    std::atomic<int> got_hub{0}, got_b{0};
    hub.ps->subscribe("news", [&](const PeerId&, const std::string&, ByteView d) { if (str(d) == "hello") got_hub++; });
    b.ps->subscribe("news",   [&](const PeerId&, const std::string&, ByteView d) { if (str(d) == "hello") got_b++; });

    ASSERT_TRUE(hub.node.start());
    ASSERT_TRUE(a.node.start());
    ASSERT_TRUE(b.node.start());
    a.node.connect("127.0.0.1", hub.node.listen_port());
    b.node.connect("127.0.0.1", hub.node.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.node.peer_count() == 2; }));
    // a must see hub subscribed (to send it the publish); hub must see b subscribed.
    ASSERT_TRUE(wait_for([&] {
        return a.ps->peers_for_topic("news").size() == 1 &&
               hub.ps->peers_for_topic("news").size() == 1;
    }));

    a.ps->publish("news", ByteView(std::string("hello")));
    ASSERT_TRUE(wait_for([&] { return got_hub.load() == 1 && got_b.load() == 1; }))
        << "hub=" << got_hub.load() << " b=" << got_b.load();

    a.node.stop();
    b.node.stop();
    hub.node.stop();
}
