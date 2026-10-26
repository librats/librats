// A duplicate link the peer table turns down is held a while — the peer's
// standby — and takes over from the link it lost to if that one goes dead: the
// peer moved, and a link dialed to where it is now came up beside the old one.

#include <gtest/gtest.h>
#include "test_paths.h"
#include "udp_forwarder.h"

#include "librats/node/node.h"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 15s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

NodeConfig node_config() {
    NodeConfig c;
    c.bind_address        = "127.0.0.1";
    c.protocol            = librats_test::test_protocol();
    c.preferred_transport = TransportKind::Udp;
    return c;
}

/// Two nodes, `first` the one with the smaller id: of a link it dials and one the
/// other dials, both ends keep the first's (the peer table's cross-connect rule).
/// So `first` dials through a forwarder, the link that will go dead, and `second`
/// straight, the link turned down and held.
struct Pair {
    Node a{node_config()};
    Node b{node_config()};
    Node* first  = nullptr;
    Node* second = nullptr;
    std::atomic<int> disconnects{0}, rerouted{0}, heard{0};

    Pair() {
        for (Node* node : {&a, &b}) {
            node->on_peer_disconnected([this](const PeerId&, CloseReason) { ++disconnects; });
            node->on_peer_rerouted([this](const Peer&) { ++rerouted; });
            node->on("after", [this](const Peer&, ByteView) { ++heard; });
        }
    }
    bool start() {
        if (!a.start() || !b.start()) return false;
        first  = a.local_id() < b.local_id() ? &a : &b;
        second = first == &a ? &b : &a;
        return true;
    }
    bool connected() { return a.peer_count() == 1 && b.peer_count() == 1; }
    /// Say something each way, as a call does all the time: on a dead link it goes
    /// unanswered, which is how the link is found dead.
    void speak() {
        const std::string probe = "probe";
        a.send(b.local_id(), "probe", ByteView(probe));
        b.send(a.local_id(), "probe", ByteView(probe));
    }
    /// Speak until `pred`, or `timeout`.
    template <typename Pred>
    bool speak_until(Pred pred, std::chrono::milliseconds timeout = 10s) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred()) return true;
            speak();
            std::this_thread::sleep_for(50ms);
        }
        return pred();
    }
    /// What each says now arrives.
    bool both_heard() {
        const int before = heard.load();
        const std::string after = "after";
        a.send(b.local_id(), "after", ByteView(after));
        b.send(a.local_id(), "after", ByteView(after));
        return wait_for([&] { return heard.load() == before + 2; }, 5s);
    }
    ~Pair() {
        a.stop();
        b.stop();
    }
};

} // namespace

// A link is dead once what it sent has gone unanswered a second — or, on a path
// whose round trip is longer than a quarter of that, four round trips: a slow
// answer there is no dead link.
TEST(Standby, ALinkIsDeadAfterASecondUnansweredOrFourRoundTrips) {
    const auto now = std::chrono::steady_clock::now();
    PathStats path;
    EXPECT_TRUE(path.answers(now)) << "nothing owed an answer";
    path.unanswered_since = now - 900ms;
    EXPECT_TRUE(path.answers(now));
    path.unanswered_since = now - 1100ms;
    EXPECT_FALSE(path.answers(now));
    path.srtt_us = 600'000;  // a satellite's
    EXPECT_TRUE(path.answers(now));
    path.unanswered_since = now - 2500ms;
    EXPECT_FALSE(path.answers(now));
}

// The link both kept goes dead — the network under it gone both ways — while the
// one turned down works. Each end finds its link unanswered and hands over to the
// standby: the peer is never lost, and what is said gets through again.
TEST(Standby, TakesOverFromALinkGoneDeadAndThePeerIsNeverLost) {
    Pair pair;
    ASSERT_TRUE(pair.start());
    librats_test::UdpForwarder path(pair.second->listen_port());
    pair.first->connect("127.0.0.1", path.port());
    ASSERT_TRUE(wait_for([&] { return pair.connected(); }));

    path.cut();
    pair.second->connect("127.0.0.1", pair.first->listen_port());
    ASSERT_TRUE(wait_for([&] { return pair.a.standbys() == 1 && pair.b.standbys() == 1; }, 5s))
        << "the link turned down was not held";

    EXPECT_TRUE(pair.speak_until([&] { return pair.rerouted.load() == 2; }))
        << "the standby never took over at both ends";
    EXPECT_EQ(pair.disconnects.load(), 0) << "the peer was lost meanwhile";
    EXPECT_EQ(pair.a.standbys(), 0u);
    EXPECT_EQ(pair.b.standbys(), 0u);
    EXPECT_TRUE(pair.both_heard());
}

// Gone one way only: the second still hears the first, whose link goes unanswered
// (the second's answers are lost). The first hands over and closes its old link,
// which the second hears end as a link does that died — so it hands over too,
// though its own link still answered.
TEST(Standby, AnEndWhoseLinkTheOtherClosedForAStandbyHandsOverToo) {
    Pair pair;
    ASSERT_TRUE(pair.start());
    librats_test::UdpForwarder path(pair.second->listen_port());
    pair.first->connect("127.0.0.1", path.port());
    ASSERT_TRUE(wait_for([&] { return pair.connected(); }));

    path.drop_back = true;
    pair.second->connect("127.0.0.1", pair.first->listen_port());
    ASSERT_TRUE(wait_for([&] { return pair.a.standbys() == 1 && pair.b.standbys() == 1; }, 5s));

    EXPECT_TRUE(pair.speak_until([&] { return pair.rerouted.load() == 2; }));
    EXPECT_EQ(pair.disconnects.load(), 0);
    EXPECT_TRUE(pair.both_heard());
}

// The usual duplicate — a link that answers kept, a second turned down — changes
// nothing: the second is closed once its time is up, and the peer stays on the
// first throughout.
TEST(Standby, ALinkThatAnswersStaysAndTheStandbyIsClosedInTime) {
    Pair pair;
    ASSERT_TRUE(pair.start());
    pair.first->connect("127.0.0.1", pair.second->listen_port());
    ASSERT_TRUE(wait_for([&] { return pair.connected(); }));

    pair.second->connect("127.0.0.1", pair.first->listen_port());
    ASSERT_TRUE(wait_for([&] { return pair.a.standbys() == 1 && pair.b.standbys() == 1; }, 5s));
    EXPECT_TRUE(pair.speak_until([&] { return pair.a.standbys() == 0 && pair.b.standbys() == 0; }))
        << "the standby was held past its time";
    EXPECT_EQ(pair.rerouted.load(), 0) << "a link that answers was taken over from";
    EXPECT_EQ(pair.disconnects.load(), 0);
    EXPECT_TRUE(pair.connected());
    EXPECT_TRUE(pair.both_heard());
}

// A peer that leaves takes its standby with it: nothing is held for a peer gone.
TEST(Standby, APeerThatLeavesTakesItsStandbyWithIt) {
    Pair pair;
    ASSERT_TRUE(pair.start());
    pair.first->connect("127.0.0.1", pair.second->listen_port());
    ASSERT_TRUE(wait_for([&] { return pair.connected(); }));
    pair.second->connect("127.0.0.1", pair.first->listen_port());
    ASSERT_TRUE(wait_for([&] { return pair.a.standbys() == 1 && pair.b.standbys() == 1; }, 5s));

    pair.second->stop();
    EXPECT_TRUE(wait_for([&] { return pair.first->peer_count() == 0; }, 5s));
    EXPECT_EQ(pair.first->standbys(), 0u);
}
