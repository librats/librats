#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/pubsub.h"

#include <algorithm>
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
    explicit PubSubNode(NodeConfig cfg, PubSub::Config ps_cfg = {}) : node(std::move(cfg)) {
        auto sub = std::make_unique<PubSub>(ps_cfg);
        ps = sub.get();
        node.add_subsystem(std::move(sub));
    }
};

// A GossipSub config with a fast heartbeat so mesh formation and IHAVE/IWANT
// gossip converge within a test's patience.
PubSub::Config fast_gossip() {
    PubSub::Config c;
    c.heartbeat_interval = std::chrono::milliseconds(50);
    return c;
}

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

// A subscribed hub relays a publish among its mesh (a → hub → b). The hub is in
// the topic mesh with b, so a message it receives is forwarded along that mesh.
// (Only subscribed mesh members relay — an UNsubscribed node never carries topic
// traffic, which is correct GossipSub behaviour, not a gap.)
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

// Two mutually-subscribed peers graft each other into the topic mesh.
TEST(PubSubTest, FormsMeshBetweenSubscribers) {
    PubSubNode server(listening_config(), fast_gossip());
    PubSubNode client(dialing_config(), fast_gossip());

    server.ps->subscribe("chat", [](const PeerId&, const std::string&, ByteView) {});
    client.ps->subscribe("chat", [](const PeerId&, const std::string&, ByteView) {});

    ASSERT_TRUE(server.node.start());
    ASSERT_TRUE(client.node.start());
    client.node.connect("127.0.0.1", server.node.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.node.peer_count() == 1 && client.node.peer_count() == 1; }));

    // Each side grafts the other once it learns of the shared subscription.
    ASSERT_TRUE(wait_for([&] {
        return server.ps->mesh_peers("chat").size() == 1 &&
               client.ps->mesh_peers("chat").size() == 1;
    })) << "mesh did not form";
    EXPECT_EQ(server.ps->mesh_peers("chat").front(), client.node.local_id());
    EXPECT_EQ(client.ps->mesh_peers("chat").front(), server.node.local_id());

    client.node.stop();
    server.node.stop();
}

// With the mesh disabled (degree 0) there is no eager push, so a published
// message can only reach a subscriber through the lazy IHAVE → IWANT pull path.
TEST(PubSubTest, LazyPullDeliversWithoutMesh) {
    PubSub::Config no_mesh = fast_gossip();
    no_mesh.mesh_low = no_mesh.mesh_target = no_mesh.mesh_high = 0;  // never graft → empty mesh
    no_mesh.gossip_factor = 16;                                     // but gossip IHAVE widely

    PubSubNode server(listening_config(), no_mesh);
    PubSubNode client(dialing_config(), no_mesh);

    std::mutex mu;
    std::string got;
    client.ps->subscribe("feed", [&](const PeerId&, const std::string&, ByteView d) {
        std::lock_guard<std::mutex> l(mu); got = str(d);
    });
    server.ps->subscribe("feed", [](const PeerId&, const std::string&, ByteView) {});  // so it emits IHAVE

    ASSERT_TRUE(server.node.start());
    ASSERT_TRUE(client.node.start());
    client.node.connect("127.0.0.1", server.node.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.ps->peers_for_topic("feed").size() == 1; }));
    // Sanity: the mesh really is empty, so eager push cannot be the delivery path.
    ASSERT_TRUE(server.ps->mesh_peers("feed").empty());

    server.ps->publish("feed", ByteView(std::string("pulled")));

    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(mu); return got == "pulled"; }))
        << "lazy IHAVE/IWANT pull did not deliver the message";

    client.node.stop();
    server.node.stop();
}

// A REJECT validator drops a message before delivery; ACCEPT lets it through.
TEST(PubSubTest, ValidatorRejectsMessages) {
    PubSubNode server(listening_config(), fast_gossip());
    PubSubNode client(dialing_config(), fast_gossip());

    std::mutex mu;
    std::vector<std::string> delivered;
    client.ps->subscribe("guarded", [&](const PeerId&, const std::string&, ByteView d) {
        std::lock_guard<std::mutex> l(mu); delivered.push_back(str(d));
    });
    client.ps->set_validator("guarded", [](const PeerId&, const std::string&, ByteView d) {
        return str(d) == "bad" ? ValidationResult::Reject : ValidationResult::Accept;
    });

    ASSERT_TRUE(server.node.start());
    ASSERT_TRUE(client.node.start());
    client.node.connect("127.0.0.1", server.node.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.ps->peers_for_topic("guarded").size() == 1; }));

    server.ps->publish("guarded", ByteView(std::string("bad")));
    server.ps->publish("guarded", ByteView(std::string("good")));

    // "good" must arrive; "bad" must be rejected at the validator and never delivered.
    ASSERT_TRUE(wait_for([&] {
        std::lock_guard<std::mutex> l(mu);
        return std::find(delivered.begin(), delivered.end(), "good") != delivered.end();
    }));
    {
        std::lock_guard<std::mutex> l(mu);
        EXPECT_EQ(std::find(delivered.begin(), delivered.end(), "bad"), delivered.end());
    }

    client.node.stop();
    server.node.stop();
}
