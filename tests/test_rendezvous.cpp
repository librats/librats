#include <gtest/gtest.h>
#include "test_paths.h"
#include "udp_forwarder.h"

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
#include <string>
#include <thread>
#include <utility>
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

// The wire, spelled out: [ver=1][op] — Hello is op 0; Register op 1: [32B key];
// Peers op 2 and Moved op 3: [count] × { [32B id][n] × { [ip_len][ip][u16 port] } }.
constexpr uint8_t kOpRegister = 1;
constexpr uint8_t kOpPeers    = 2;
constexpr uint8_t kOpMoved    = 3;

Bytes hello() { return Bytes{1, 0}; }

Bytes register_message(const std::string& key) {
    Bytes out{1, kOpRegister};
    const Rendezvous::Key hashed = Rendezvous::key_of(key);
    out.insert(out.end(), hashed.begin(), hashed.end());
    return out;
}

Bytes peers_naming(const PeerId& id, std::array<uint8_t, 4> ip, uint16_t port,
                   uint8_t op = kOpPeers) {
    Bytes out{1, op, 1};
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

/// What a node without a Rendezvous of its own hears on the rendezvous wire.
class Heard {
public:
    explicit Heard(Node& node) {
        node.on(MessageType::Rendezvous, [this](const Peer&, ByteView payload) {
            std::lock_guard<std::mutex> lock(mutex_);
            seen_.emplace_back(payload.begin(), payload.end());
        });
    }
    size_t count(uint8_t op) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<size_t>(std::count_if(seen_.begin(), seen_.end(), [&](const Bytes& m) {
            return m.size() >= 2 && m[1] == op;
        }));
    }
    /// The last message of `op`, or an empty one.
    Bytes last(uint8_t op) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = seen_.rbegin(); it != seen_.rend(); ++it)
            if (it->size() >= 2 && (*it)[1] == op) return *it;
        return {};
    }

private:
    mutable std::mutex mutex_;
    std::vector<Bytes> seen_;
};

/// The first peer a Peers or Moved message names, and its first endpoint.
std::pair<PeerId, Address> first_named(const Bytes& message) {
    if (message.size() < 3 + PeerId::kSize + 1 + 1 + 4 + 2 || message[3 + PeerId::kSize + 1] != 4)
        return {};
    const uint8_t* id = message.data() + 3;
    const uint8_t* ip = id + PeerId::kSize + 2;
    const auto peer = PeerId::from_bytes(ByteView(id, PeerId::kSize));
    const auto address = IpAddress::from_bytes(ByteView(ip, 4));
    return {*peer, Address{*address, static_cast<uint16_t>((ip[4] << 8) | ip[5])}};
}

socket_t loopback_socket() {
    socket_t s = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    set_socket_nonblocking(s);
    return s;
}

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

// ── A peer that moves ───────────────────────────────────────────────────────

// A peer the server sees move — its NAT gave it another port — is told of to
// the others under its key, at where it is now, and is told where they are: its
// links to them, which their NATs no longer let in, need both sides to dial.
TEST(Rendezvous, AServerTellsThoseAPeerMeetsWhereItMovedAndItWhereTheyAre) {
    Node server(node_config());
    server.add_subsystem(std::make_unique<Rendezvous>(serving()));
    ASSERT_TRUE(server.start());
    // Both register by hand, and keep what they are told.
    Node a(node_config()), b(node_config());
    Heard heard_a(a), heard_b(b);
    ASSERT_TRUE(a.start() && b.start());
    librats_test::UdpForwarder nat(server.listen_port());
    a.connect("127.0.0.1", nat.port());
    b.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.peer_count() == 2; }));
    const Bytes registering = register_message("room");
    a.send(server.local_id(), MessageType::Rendezvous, ByteView(registering));
    ASSERT_TRUE(wait_for([&] {
        return server.subsystem<Rendezvous>()->registrations() == 1;
    }));
    b.send(server.local_id(), MessageType::Rendezvous, ByteView(registering));
    ASSERT_TRUE(wait_for([&] { return heard_a.count(kOpPeers) == 1; })) << "A never told of B";
    EXPECT_EQ(heard_a.count(kOpMoved) + heard_b.count(kOpMoved), 0u);

    nat.move();
    const Address moved_to = nat.seen_at();
    const std::string nudge = "from the new port";
    a.send(server.local_id(), "nudge", ByteView(nudge));  // the server hears A from there

    ASSERT_TRUE(wait_for([&] { return heard_b.count(kOpMoved) == 1; }, 5s))
        << "B was never told A moved";
    EXPECT_EQ(first_named(heard_b.last(kOpMoved)), std::make_pair(a.local_id(), moved_to));
    ASSERT_TRUE(wait_for([&] { return heard_a.count(kOpMoved) == 1; }, 5s))
        << "A was never told where B is";
    EXPECT_EQ(first_named(heard_a.last(kOpMoved)).first, b.local_id());

    a.stop();
    b.stop();
    server.stop();
}

// Told of a peer that moved, a node dials it where it is now even though it is
// connected to it: its link to the peer needs this side's NAT open to there. One
// it is connected to, told of as on meeting (Peers), it leaves alone.
TEST(Rendezvous, APeerThatMovedIsDialedThoughConnected) {
    Unreached test([](Node&) {});
    Node b(node_config());
    ASSERT_TRUE(b.start());
    ASSERT_TRUE(test.start());
    test.hello();
    test.a.connect("127.0.0.1", b.listen_port());
    ASSERT_TRUE(wait_for([&] { return test.a.peer(b.local_id()).has_value(); }));

    const socket_t elsewhere = loopback_socket();
    const uint16_t port = static_cast<uint16_t>(get_bound_port(elsewhere));
    const auto dialed = [&] {
        uint8_t buf[2048];
        Address from;
        bool any = false;
        while (recv_udp_from(elsewhere, buf, sizeof buf, from) >= 0) any = true;
        return any;
    };
    const Bytes met = peers_naming(b.local_id(), {127, 0, 0, 1}, port);
    test.server.send(test.a.local_id(), MessageType::Rendezvous, ByteView(met));
    std::this_thread::sleep_for(600ms);
    EXPECT_FALSE(dialed()) << "a peer connected and not moved was dialed";

    const Bytes moved = peers_naming(b.local_id(), {127, 0, 0, 1}, port, kOpMoved);
    test.server.send(test.a.local_id(), MessageType::Rendezvous, ByteView(moved));
    EXPECT_TRUE(wait_for([&] { return dialed(); }, 3s)) << "the peer that moved was not dialed";
    close_socket(elsewhere);
    b.stop();
}

// Of two peers told of as moved, the one whose link still answers is reached; the
// one whose link has gone dead — neither side's NAT letting the other in any more
// — is handed to a relay, whose circuit then takes the dead link's place.
TEST(Rendezvous, OfPeersThatMovedOnlyOneWhoseLinkIsDeadIsRelayed) {
    RelayRecorder* relay = nullptr;
    Unreached test([&](Node& a) { relay = a.add_subsystem(std::make_unique<RelayRecorder>()); });
    Node near(node_config()), far(node_config());
    ASSERT_TRUE(near.start() && far.start());
    ASSERT_TRUE(test.start());
    test.hello();
    librats_test::UdpForwarder path(far.listen_port());
    test.a.connect("127.0.0.1", near.listen_port());
    test.a.connect("127.0.0.1", path.port());
    ASSERT_TRUE(wait_for([&] {
        return test.a.peer(near.local_id()).has_value() && test.a.peer(far.local_id()).has_value();
    }));

    path.cut();
    const auto speak = [&] {
        const std::string probe = "probe";
        test.a.send(near.local_id(), "probe", ByteView(probe));
        test.a.send(far.local_id(), "probe", ByteView(probe));
    };
    const auto speak_until = [&](auto pred, std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!pred() && std::chrono::steady_clock::now() < deadline) {
            speak();
            std::this_thread::sleep_for(50ms);
        }
        return pred();
    };
    ASSERT_TRUE(speak_until([&] { return !test.a.answers(far.local_id()); }, 5s));
    EXPECT_TRUE(test.a.answers(near.local_id()));

    for (const PeerId& peer : {near.local_id(), far.local_id()}) {
        const Bytes moved = peers_naming(peer, {192, 0, 2, 1}, 9, kOpMoved);
        test.server.send(test.a.local_id(), MessageType::Rendezvous, ByteView(moved));
    }
    EXPECT_TRUE(speak_until([&] { return !relay->asked().empty(); }, 5s));
    speak_until([] { return false; }, 500ms);
    EXPECT_EQ(relay->asked(), std::vector<PeerId>{far.local_id()});
    near.stop();
    far.stop();
}

// A peer can tell a server it moved only by speaking to it, which one keeping
// quiet with the server does not do for a while. So a node whose link to a peer
// goes dead — which a move on either side does — registers again at once.
TEST(Rendezvous, ALinkGoneDeadHasTheServersSpokenToAtOnce) {
    Node server(node_config());
    Heard heard(server);
    Node a(node_config());
    a.add_subsystem(std::make_unique<Rendezvous>(meeting("room", 0)));
    Node b(node_config());
    ASSERT_TRUE(server.start() && a.start() && b.start());
    a.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.peer_count() == 1; }));
    const Bytes hi = hello();
    server.send(a.local_id(), MessageType::Rendezvous, ByteView(hi));
    ASSERT_TRUE(wait_for([&] { return heard.count(kOpRegister) == 1; }));

    librats_test::UdpForwarder path(b.listen_port());
    a.connect("127.0.0.1", path.port());
    ASSERT_TRUE(wait_for([&] { return a.peer(b.local_id()).has_value(); }));
    path.cut();
    const std::string probe = "probe";
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (heard.count(kOpRegister) == 1 && std::chrono::steady_clock::now() < deadline) {
        a.send(b.local_id(), "probe", ByteView(probe));
        std::this_thread::sleep_for(50ms);
    }
    EXPECT_EQ(heard.count(kOpRegister), 2u) << "not registered again on a link gone dead";
    a.stop();
    b.stop();
    server.stop();
}
