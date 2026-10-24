#include <gtest/gtest.h>
#include "test_paths.h"

#include "librats/core/service_registry.h"
#include "librats/node/node.h"
#include "librats/node/node_context.h"
#include "librats/subsystems/hole_punch_service.h"
#include "librats/subsystems/relay_service.h"
#include "librats/subsystems/rendezvous.h"
#include "librats/wire/frame.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

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

NodeConfig node_config(uint16_t port = 0) {
    NodeConfig c;
    c.bind_address = "127.0.0.1";
    c.listen_port  = port;
    c.protocol     = librats_test::test_protocol();
    return c;
}

Rendezvous::Config serving() {
    Rendezvous::Config c;
    c.serve = true;
    return c;
}

Rendezvous::Config meeting(const std::string& key, uint16_t server_port) {
    Rendezvous::Config c;
    c.keys = {key};
    if (server_port != 0) c.servers = {HostEndpoint("127.0.0.1", server_port)};
    c.redial = 200ms;
    return c;
}

bool connected(Node& node, const Node& other) {
    return node.peer(other.local_id()).has_value();
}

// The wire, spelled out: [ver=1][op] — Hello is op 0; Peers op 2:
// [count] × { [32B id][n] × { [ip_len][ip][u16 port] } }.
Bytes hello() { return Bytes{1, 0}; }

Bytes peers_naming(const PeerId& id, std::array<uint8_t, 4> ip, uint16_t port) {
    Bytes out{1, 2, 1};
    const auto& raw = id.bytes();
    out.insert(out.end(), raw.begin(), raw.end());
    out.push_back(1);
    out.push_back(4);
    out.insert(out.end(), ip.begin(), ip.end());
    out.push_back(static_cast<uint8_t>(port >> 8));
    out.push_back(static_cast<uint8_t>(port));
    return out;
}

/// A HolePunch or Relay stand-in that notes whom it was asked to reach.
class Recorder {
public:
    void note(const PeerId& target) {
        std::lock_guard<std::mutex> lock(mutex_);
        asked_.push_back(target);
    }
    std::vector<PeerId> asked() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return asked_;
    }

private:
    mutable std::mutex  mutex_;
    std::vector<PeerId> asked_;
};

class PunchRecorder final : public Subsystem, public HolePunchService, public Recorder {
public:
    void attach(NodeContext& ctx) override { ctx.services.provide<HolePunchService>(this); }
    void start() override {}
    void stop() override {}
    bool punch(const PeerId& target) override {
        note(target);
        return true;
    }
};

class RelayRecorder final : public Subsystem, public RelayService, public Recorder {
public:
    void attach(NodeContext& ctx) override { ctx.services.provide<RelayService>(this); }
    void start() override {}
    void stop() override {}
    bool connect_via_relay(const PeerId& target) override {
        note(target);
        return true;
    }
};

PeerId some_id(uint8_t first) {
    std::array<uint8_t, PeerId::kSize> raw{};
    raw[0] = first;
    return *PeerId::from_bytes(ByteView(raw.data(), raw.size()));
}

} // namespace

// Two that know a key meet through the server, and only they: one with another
// key is told of nobody.
TEST(Rendezvous, PeersOfOneKeyMeetThroughTheServerAndOnlyThey) {
    Node server(node_config());
    auto* rendezvous = server.add_subsystem(std::make_unique<Rendezvous>(serving()));
    ASSERT_TRUE(server.start());
    const uint16_t port = server.listen_port();

    Node a(node_config()), b(node_config()), c(node_config());
    auto* at_a = a.add_subsystem(std::make_unique<Rendezvous>(meeting("room", port)));
    b.add_subsystem(std::make_unique<Rendezvous>(meeting("room", port)));
    c.add_subsystem(std::make_unique<Rendezvous>(meeting("another room", port)));
    ASSERT_TRUE(a.start() && b.start() && c.start());

    EXPECT_TRUE(wait_for([&] { return connected(a, b) && connected(b, a); }));
    EXPECT_TRUE(wait_for([&] { return rendezvous->registrations() == 3; }));
    EXPECT_EQ(at_a->servers(), std::vector<PeerId>{server.local_id()});
    EXPECT_TRUE(at_a->is_server(server.local_id()));
    EXPECT_FALSE(at_a->is_server(b.local_id()));
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(c.peer_count(), 1u) << "told of peers of another key";

    c.stop();
    b.stop();
    a.stop();
    server.stop();
}

// A server of the config is known for one as it connects, before it says a
// word: in a connected handler, which runs before the subsystem's own.
TEST(Rendezvous, AServerOfTheConfigIsKnownAsItConnects) {
    Node server(node_config());
    server.add_subsystem(std::make_unique<Rendezvous>(serving()));
    ASSERT_TRUE(server.start());

    Node a(node_config());
    auto* rendezvous =
        a.add_subsystem(std::make_unique<Rendezvous>(meeting("room", server.listen_port())));
    std::atomic<int> known{-1};
    a.on_peer_connected([&](const Peer& peer) { known = rendezvous->is_server(peer.id()); });
    std::atomic<int> found{0};
    rendezvous->on_server_found([&](const PeerId&) { ++found; });
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(wait_for([&] { return known.load() != -1; }));
    EXPECT_EQ(known.load(), 1);
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(found.load(), 0) << "its Hello was news";
    a.stop();
    server.stop();
}

// A node that was given no server meets through one it is connected to all the
// same: the server says Hello, and the node says it found one.
TEST(Rendezvous, ANodeRegistersWithAServerItLearnsOfByItsHello) {
    Node server(node_config());
    server.add_subsystem(std::make_unique<Rendezvous>(serving()));
    ASSERT_TRUE(server.start());

    Node a(node_config()), b(node_config());
    auto* rendezvous = a.add_subsystem(std::make_unique<Rendezvous>(meeting("room", 0)));
    std::mutex mutex;
    std::vector<PeerId> found;
    rendezvous->on_server_found([&](const PeerId& peer) {
        std::lock_guard<std::mutex> lock(mutex);
        found.push_back(peer);
    });
    b.add_subsystem(std::make_unique<Rendezvous>(meeting("room", server.listen_port())));
    ASSERT_TRUE(a.start() && b.start());
    a.connect("127.0.0.1", server.listen_port());

    EXPECT_TRUE(wait_for([&] { return connected(a, b); }));
    {
        std::lock_guard<std::mutex> lock(mutex);
        EXPECT_EQ(found, std::vector<PeerId>{server.local_id()});
    }
    b.stop();
    a.stop();
    server.stop();
}

// A registration lasts while its connection does.
TEST(Rendezvous, ARegistrationEndsWithItsConnection) {
    Node server(node_config());
    auto* rendezvous = server.add_subsystem(std::make_unique<Rendezvous>(serving()));
    ASSERT_TRUE(server.start());
    Node a(node_config());
    a.add_subsystem(std::make_unique<Rendezvous>(meeting("room", server.listen_port())));
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(wait_for([&] { return rendezvous->registrations() == 1; }));

    a.stop();
    EXPECT_TRUE(wait_for([&] { return rendezvous->registrations() == 0; }));
    server.stop();
}

// A server keeps so many peers under a key; one past them is answered all the
// same, but nobody else is told of it.
TEST(Rendezvous, AServerKeepsSoManyPeersUnderAKey) {
    Rendezvous::Config config = serving();
    config.max_peers_per_key = 2;
    Node server(node_config());
    auto* rendezvous = server.add_subsystem(std::make_unique<Rendezvous>(config));
    ASSERT_TRUE(server.start());
    const uint16_t port = server.listen_port();

    Node a(node_config()), b(node_config()), c(node_config());
    a.add_subsystem(std::make_unique<Rendezvous>(meeting("room", port)));
    b.add_subsystem(std::make_unique<Rendezvous>(meeting("room", port)));
    ASSERT_TRUE(a.start() && b.start());
    ASSERT_TRUE(wait_for([&] { return rendezvous->registrations() == 2 && connected(a, b); }));
    c.add_subsystem(std::make_unique<Rendezvous>(meeting("room", port)));
    ASSERT_TRUE(c.start());

    EXPECT_TRUE(wait_for([&] { return connected(c, a) && connected(c, b); }))
        << "the one past the cap was not answered";
    EXPECT_EQ(rendezvous->registrations(), 2u);
    c.stop();
    b.stop();
    a.stop();
    server.stop();
}

/// A node met at a hand-made server, told of a peer nowhere anyone answers
/// (TEST-NET-1): who it asks to reach it, once the dials have had their time.
struct Unreached {
    Node server{node_config()};  // speaks the wire by hand
    Node a{node_config()};
    Rendezvous* rendezvous = nullptr;
    const PeerId nowhere = some_id(7);
    const Bytes told = peers_naming(nowhere, {192, 0, 2, 1}, 9);

    explicit Unreached(const std::function<void(Node&)>& attach) {
        Rendezvous::Config config = meeting("room", 0);
        config.punch_after = 300ms;
        rendezvous = a.add_subsystem(std::make_unique<Rendezvous>(config));
        attach(a);
    }
    bool start() {
        if (!server.start() || !a.start()) return false;
        a.connect("127.0.0.1", server.listen_port());
        return wait_for([&] { return server.peer_count() == 1; });
    }
    void hello() {
        const Bytes hi = ::hello();
        server.send(a.local_id(), MessageType::Rendezvous, ByteView(hi));
        wait_for([&] { return rendezvous->is_server(server.local_id()); });
    }
    void tell() { server.send(a.local_id(), MessageType::Rendezvous, ByteView(told)); }
    ~Unreached() {
        a.stop();
        server.stop();
    }
};

// One told of that the dials do not reach is handed to a relay, which punches
// on over its circuit — and only what a server said is acted on.
TEST(Rendezvous, APeerNotReachedByDialingIsRelayed) {
    PunchRecorder* punch = nullptr;
    RelayRecorder* relay = nullptr;
    Unreached test([&](Node& a) {
        punch = a.add_subsystem(std::make_unique<PunchRecorder>());
        relay = a.add_subsystem(std::make_unique<RelayRecorder>());
    });
    ASSERT_TRUE(test.start());

    test.tell();
    std::this_thread::sleep_for(800ms);
    EXPECT_TRUE(relay->asked().empty()) << "acted on a peer that never said Hello";

    test.hello();
    test.tell();
    EXPECT_TRUE(wait_for([&] { return !relay->asked().empty(); }, 5s));
    EXPECT_EQ(relay->asked(), std::vector<PeerId>{test.nowhere});
    EXPECT_TRUE(punch->asked().empty());
    EXPECT_EQ(test.rendezvous->handed_on(), 1u);
}

// Without a relay, a punch.
TEST(Rendezvous, WithoutARelayAPeerNotReachedIsPunched) {
    PunchRecorder* punch = nullptr;
    Unreached test([&](Node& a) { punch = a.add_subsystem(std::make_unique<PunchRecorder>()); });
    ASSERT_TRUE(test.start());
    test.hello();
    test.tell();
    EXPECT_TRUE(wait_for([&] { return !punch->asked().empty(); }, 5s));
    EXPECT_EQ(punch->asked(), std::vector<PeerId>{test.nowhere});
}

// Malformed or truncated messages are dropped, never acted on.
TEST(Rendezvous, IgnoresMalformedMessages) {
    Node server(node_config());
    auto* rendezvous = server.add_subsystem(std::make_unique<Rendezvous>(serving()));
    ASSERT_TRUE(server.start());
    Node a(node_config());
    ASSERT_TRUE(a.start());
    a.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return a.peer_count() == 1; }));

    const PeerId id = server.local_id();
    for (const Bytes& junk : {Bytes{}, Bytes{1}, Bytes{2, 1}, Bytes{1, 1, 0, 0}, Bytes{1, 9},
                              Bytes(40, 1)}) {
        a.send(id, MessageType::Rendezvous, ByteView(junk));
    }
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(rendezvous->registrations(), 0u);
    EXPECT_EQ(a.peer_count(), 1u);
    a.stop();
    server.stop();
}

// A server lost is dialed again, and registered with as it comes back.
TEST(Rendezvous, AServerLostIsDialedAgain) {
    auto server = std::make_unique<Node>(node_config());
    server->add_subsystem(std::make_unique<Rendezvous>(serving()));
    ASSERT_TRUE(server->start());
    const uint16_t port = server->listen_port();

    Node a(node_config());
    auto* rendezvous = a.add_subsystem(std::make_unique<Rendezvous>(meeting("room", port)));
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(wait_for([&] { return rendezvous->is_server(server->local_id()); }));

    server->stop();
    server = std::make_unique<Node>(node_config(port));
    auto* again = server->add_subsystem(std::make_unique<Rendezvous>(serving()));
    ASSERT_TRUE(server->start());
    EXPECT_TRUE(wait_for([&] { return rendezvous->is_server(server->local_id()); }));
    EXPECT_TRUE(wait_for([&] { return again->registrations() == 1; }));
    a.stop();
    server->stop();
}
