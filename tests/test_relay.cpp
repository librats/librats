#include <gtest/gtest.h>
#include "test_paths.h"

#include "librats/node/node.h"
#include "librats/subsystems/hole_punch.h"
#include "librats/subsystems/relay.h"
#include "librats/wire/frame.h"

#include <array>
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
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 20s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

NodeConfig listening_config() {
    NodeConfig c;
    c.bind_address = "127.0.0.1";
    c.security     = NodeConfig::Security::Noise;
    c.protocol     = librats_test::test_protocol();
    return c;
}

/// A relay that will carry circuits for others.
Relay::Config serving() {
    Relay::Config c;
    c.serve = true;
    return c;
}

/// How a peer is currently reached, or nullopt when it is not a peer at all.
std::optional<TransportKind> transport_to(Node& node, const PeerId& id) {
    for (const PeerInfo& info : node.peers())
        if (info.id == id) return info.transport;
    return std::nullopt;
}

bool relayed(Node& node, const PeerId& id) {
    const auto t = transport_to(node, id);
    return t && *t == TransportKind::Relay;
}

// The wire form, spelled out here rather than reached through the subsystem, so the
// tests below pin the format the two ends agree on and not just the code that
// happens to produce it. See the comment at the top of relay.cpp.
//   [u8 ver=1][u8 op][u32 circuit][body]
constexpr uint8_t kOpOpen    = 1;
constexpr uint8_t kOpDeny    = 4;
constexpr uint8_t kOpProbe   = 8;
constexpr uint8_t kOpProbeOk = 9;

constexpr uint8_t kDenyNoTarget      = 0;
constexpr uint8_t kDenyNotPermitted  = 1;
constexpr uint8_t kDenyResourceLimit = 2;
constexpr uint8_t kDenyLoop          = 4;

Bytes relay_message(uint8_t op, uint32_t circuit) {
    return Bytes{1, op,
                 static_cast<uint8_t>(circuit >> 24), static_cast<uint8_t>(circuit >> 16),
                 static_cast<uint8_t>(circuit >> 8),  static_cast<uint8_t>(circuit)};
}

void append_id(Bytes& out, const PeerId& id) {
    const auto& raw = id.bytes();
    out.insert(out.end(), raw.begin(), raw.end());
}

Bytes open_request(uint32_t circuit, const PeerId& dst, uint32_t window = 65536) {
    Bytes msg = relay_message(kOpOpen, circuit);
    append_id(msg, dst);
    msg.push_back(static_cast<uint8_t>(window >> 24));
    msg.push_back(static_cast<uint8_t>(window >> 16));
    msg.push_back(static_cast<uint8_t>(window >> 8));
    msg.push_back(static_cast<uint8_t>(window));
    return msg;
}

Bytes probe_request(const PeerId& dst) {
    Bytes msg = relay_message(kOpProbe, 0);
    append_id(msg, dst);
    return msg;
}

/// A node with no Relay subsystem that watches the relay wire directly, so a test
/// can see exactly what a relay answers rather than inferring it from behaviour.
class Watcher {
public:
    explicit Watcher(Node& node) {
        node.on(MessageType::Relay, [this](const Peer&, ByteView payload) {
            std::lock_guard<std::mutex> lock(mutex_);
            seen_.emplace_back(payload.begin(), payload.end());
        });
    }

    /// The reason byte of the first Deny seen, or nullopt if none arrived.
    std::optional<uint8_t> deny_reason() const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const Bytes& msg : seen_)
            if (msg.size() >= 7 && msg[1] == kOpDeny) return msg[6];
        return std::nullopt;
    }

    size_t count_of(uint8_t op) const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t n = 0;
        for (const Bytes& msg : seen_)
            if (msg.size() >= 2 && msg[1] == op) ++n;
        return n;
    }

    size_t total() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return seen_.size();
    }

private:
    mutable std::mutex mutex_;
    std::vector<Bytes> seen_;
};

/// Two peers and the node between them, wired up and connected — the shape every
/// test below starts from.
struct Trio {
    Node hub{listening_config()};
    Node a{listening_config()};
    Node b{listening_config()};
    Relay* relay_hub = nullptr;
    Relay* relay_a   = nullptr;
    Relay* relay_b   = nullptr;

    Trio(Relay::Config hub_config = serving(),
         Relay::Config end_config = Relay::Config()) {
        relay_hub = hub.add_subsystem(std::make_unique<Relay>(hub_config));
        relay_a   = a.add_subsystem(std::make_unique<Relay>(end_config));
        relay_b   = b.add_subsystem(std::make_unique<Relay>(end_config));
    }

    bool start() {
        if (!hub.start() || !a.start() || !b.start()) return false;
        a.connect("127.0.0.1", hub.listen_port());
        b.connect("127.0.0.1", hub.listen_port());
        return wait_for([this] { return hub.peer_count() == 2; });
    }

    ~Trio() {
        a.stop();
        b.stop();
        hub.stop();
    }
};

} // namespace

// The whole point, end to end: A and B have never met and neither can dial the
// other — they know only the hub. A asks for a way through, the hub carries the
// bytes, and what comes out the other side is an ordinary peer: authenticated,
// encrypted end to end, and usable by every part of the API that takes a peer.
TEST(RelayE2E, ConnectsTwoPeersThroughACommonRelay) {
    Trio trio;

    // Registered before start(), as the node's contract requires: the callback
    // lists are read by reactor threads and are not guarded for late writers.
    std::atomic<int> received{0};
    std::string      last;
    std::mutex       mutex;
    trio.b.on("chat", [&](const Peer&, ByteView payload) {
        std::lock_guard<std::mutex> lock(mutex);
        last.assign(reinterpret_cast<const char*>(payload.data()), payload.size());
        ++received;
    });

    ASSERT_TRUE(trio.start()) << "peers never reached the hub";

    ASSERT_TRUE(trio.relay_a->connect_via_relay(trio.b.local_id()))
        << "the attempt was refused before it started";

    ASSERT_TRUE(wait_for([&] { return trio.a.peer(trio.b.local_id()).has_value(); }))
        << "A never reached B";
    ASSERT_TRUE(wait_for([&] { return trio.b.peer(trio.a.local_id()).has_value(); }))
        << "B never saw A";

    // Both ends know the link for what it is — which is what lets the peer table
    // replace it later, and what an application would check before, say, starting a
    // large transfer over it.
    EXPECT_TRUE(relayed(trio.a, trio.b.local_id()));
    EXPECT_TRUE(relayed(trio.b, trio.a.local_id()));

    // And it is a peer in every ordinary sense.
    const std::string hello = "hello through the middle";
    trio.a.send(trio.b.local_id(), "chat", ByteView(hello));
    ASSERT_TRUE(wait_for([&] { return received.load() == 1; })) << "the message never arrived";
    {
        std::lock_guard<std::mutex> lock(mutex);
        EXPECT_EQ(last, hello);
    }

    EXPECT_EQ(trio.relay_hub->carried_circuits(), 1u);
    EXPECT_GT(trio.relay_hub->carried_bytes(), 0u);
    // The attempt is retired the moment the peer is there, rather than aging out.
    EXPECT_TRUE(wait_for([&] { return trio.relay_a->attempts() == 0u; }, 3s));
}

// A payload far larger than one data chunk and than the credit window has to arrive
// whole: the window is a brake on a relayed path, never a filter.
TEST(RelayE2E, CarriesAPayloadLargerThanTheWindow) {
    Trio trio;

    constexpr size_t kSize = 3 * 1024 * 1024;   // several windows' worth
    std::string      payload(kSize, '\0');
    for (size_t i = 0; i < kSize; ++i) payload[i] = static_cast<char>(i * 31 + 7);

    std::atomic<size_t> got{0};
    std::atomic<bool>   intact{false};
    trio.b.on("bulk", [&](const Peer&, ByteView data) {
        intact.store(data.size() == kSize &&
                     std::equal(data.begin(), data.end(),
                                reinterpret_cast<const uint8_t*>(payload.data())));
        got.store(data.size());
    });

    ASSERT_TRUE(trio.start());

    ASSERT_TRUE(trio.relay_a->connect_via_relay(trio.b.local_id()));
    ASSERT_TRUE(wait_for([&] { return trio.a.peer(trio.b.local_id()).has_value(); }));

    trio.a.send(trio.b.local_id(), "bulk", ByteView(payload));
    ASSERT_TRUE(wait_for([&] { return got.load() == kSize; }, 30s))
        << "only " << got.load() << " of " << kSize << " bytes arrived";
    EXPECT_TRUE(intact.load()) << "the payload arrived corrupted or out of order";
}

// Carrying other peers' traffic is opt-in, and a node that has not opted in must
// not quietly do it anyway. This is the default, so getting it wrong would put
// every node in the mesh on the hook for somebody else's bandwidth.
TEST(RelayE2E, ANodeThatDoesNotServeCarriesNothing) {
    // A short attempt window. What is under test is what a non-serving node does,
    // not how long the default waits before giving up — and at the default this one
    // test sets the wall-clock of the entire suite.
    Relay::Config ends;
    ends.open_timeout = 500ms;

    Trio trio(/*hub_config=*/Relay::Config{}, ends);   // the hub does NOT serve
    ASSERT_TRUE(trio.start());

    EXPECT_TRUE(trio.relay_a->connect_via_relay(trio.b.local_id()))
        << "the attempt should still start; there is no way to know in advance";

    // Wait out the whole attempt rather than sampling for an arbitrary while: with
    // nobody answering the probe there is nothing to open a circuit through, so the
    // attempt ends in its own time and what follows describes its entire life
    // rather than a window somewhere inside it.
    ASSERT_TRUE(wait_for([&] { return trio.relay_a->attempts() == 0u; }, 5s))
        << "the attempt never gave up";
    EXPECT_FALSE(trio.a.peer(trio.b.local_id()).has_value())
        << "a circuit was carried by a node that never offered to";
    EXPECT_EQ(trio.relay_hub->carried_circuits(), 0u);
    EXPECT_EQ(trio.relay_a->circuits(), 0u);
}

// A relay only ever forwards between peers it already holds. It never dials and
// never resolves an address, which is what keeps it from being turned into an open
// reflector for traffic aimed at somebody who never connected to it.
TEST(RelayE2E, ARelayRefusesATargetItDoesNotHold) {
    Node hub(listening_config());
    Node client(listening_config());
    hub.add_subsystem(std::make_unique<Relay>(serving()));

    Watcher watcher(client);   // no Relay subsystem: the test reads the wire itself
    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 1; }));

    std::array<uint8_t, PeerId::kSize> raw{};
    raw[0] = 0xEE;
    const PeerId stranger = *PeerId::from_bytes(ByteView(raw.data(), raw.size()));

    client.send(hub.local_id(), MessageType::Relay, ByteView(open_request(2, stranger)));
    ASSERT_TRUE(wait_for([&] { return watcher.deny_reason().has_value(); }, 5s))
        << "the relay neither carried nor refused the request";
    EXPECT_EQ(*watcher.deny_reason(), kDenyNoTarget);

    // And it does not even admit to knowing a stranger when asked.
    client.send(hub.local_id(), MessageType::Relay, ByteView(probe_request(stranger)));
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(watcher.count_of(kOpProbeOk), 0u);

    client.stop();
    hub.stop();
}

// A node that is not serving says so rather than staying silent, so a client can
// move on to the next candidate instead of waiting out its timeout.
TEST(RelayE2E, ANodeThatDoesNotServeSaysSo) {
    Node hub(listening_config());
    Node client(listening_config());
    hub.add_subsystem(std::make_unique<Relay>(Relay::Config{}));   // serve = false

    Watcher watcher(client);
    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 1; }));

    client.send(hub.local_id(), MessageType::Relay,
                ByteView(open_request(2, client.local_id())));
    ASSERT_TRUE(wait_for([&] { return watcher.deny_reason().has_value(); }, 5s));
    EXPECT_EQ(*watcher.deny_reason(), kDenyNotPermitted);

    client.stop();
    hub.stop();
}

// Circuits must not be chained. A chain multiplies one pair's bytes across several
// relays and gives a loop somewhere to form, so a node refuses the moment either
// end is itself only reachable through a relay — and it does not even answer a
// probe for such a peer. Tested on a node that DOES serve, so the refusal is the
// chain rule itself rather than a blanket "not offering that".
TEST(RelayE2E, CircuitsAreNotChained) {
    Trio trio(serving(), serving());   // A serves too
    ASSERT_TRUE(trio.start());

    ASSERT_TRUE(trio.relay_a->connect_via_relay(trio.b.local_id()));
    ASSERT_TRUE(wait_for([&] { return relayed(trio.a, trio.b.local_id()); }));

    Node onward(listening_config());
    Watcher watcher(onward);
    ASSERT_TRUE(onward.start());
    onward.connect("127.0.0.1", trio.a.listen_port());
    ASSERT_TRUE(wait_for([&] { return onward.peer_count() >= 1; }));

    onward.send(trio.a.local_id(), MessageType::Relay,
                ByteView(open_request(2, trio.b.local_id())));
    ASSERT_TRUE(wait_for([&] { return watcher.deny_reason().has_value(); }, 5s));
    EXPECT_EQ(*watcher.deny_reason(), kDenyLoop) << "a circuit was extended into a chain";

    // Nor will it point anyone at a peer it only reaches by relay.
    onward.send(trio.a.local_id(), MessageType::Relay,
                ByteView(probe_request(trio.b.local_id())));
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(watcher.count_of(kOpProbeOk), 0u);

    onward.stop();
}

// One peer must not be able to take the whole relay. The per-peer cap is what keeps
// a single client from spending everything a relay is willing to give.
TEST(RelayE2E, OnePeerCannotTakeMoreCircuitsThanItsShare) {
    Relay::Config hub_config = serving();
    hub_config.max_circuits_per_peer = 1;

    Node hub(listening_config());
    Node client(listening_config());
    Node target(listening_config());
    hub.add_subsystem(std::make_unique<Relay>(hub_config));
    target.add_subsystem(std::make_unique<Relay>(Relay::Config{}));

    Watcher watcher(client);
    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(client.start());
    ASSERT_TRUE(target.start());

    client.connect("127.0.0.1", hub.listen_port());
    target.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; }));

    // The first is carried; the second is over the client's share.
    client.send(hub.local_id(), MessageType::Relay,
                ByteView(open_request(2, target.local_id())));
    ASSERT_TRUE(wait_for([&] {
        return hub.subsystem<Relay>()->carried_circuits() == 1u;
    }, 5s)) << "the first circuit was not carried";

    client.send(hub.local_id(), MessageType::Relay,
                ByteView(open_request(4, target.local_id())));
    ASSERT_TRUE(wait_for([&] { return watcher.deny_reason().has_value(); }, 5s));
    EXPECT_EQ(*watcher.deny_reason(), kDenyResourceLimit);
    EXPECT_EQ(hub.subsystem<Relay>()->carried_circuits(), 1u);

    target.stop();
    client.stop();
    hub.stop();
}

// A relay is not a permanent bearer of somebody else's traffic. Past the byte cap
// the circuit ends — and ends properly, as a peer going away rather than as a
// stall the two ends have to discover for themselves.
TEST(RelayE2E, ACircuitEndsWhenItOutstaysItsByteCap) {
    Relay::Config hub_config = serving();
    hub_config.max_bytes_per_circuit = 256 * 1024;

    Trio trio(hub_config);

    std::atomic<bool> lost{false};
    trio.a.on_peer_disconnected([&](const PeerId& id) {
        if (id == trio.b.local_id()) lost.store(true);
    });

    ASSERT_TRUE(trio.start());

    ASSERT_TRUE(trio.relay_a->connect_via_relay(trio.b.local_id()));
    ASSERT_TRUE(wait_for([&] { return trio.a.peer(trio.b.local_id()).has_value(); }));

    const std::string payload(64 * 1024, 'x');
    for (int i = 0; i < 32; ++i) trio.a.send(trio.b.local_id(), "flood", ByteView(payload));

    ASSERT_TRUE(wait_for([&] { return lost.load(); }, 15s))
        << "the circuit outlived its byte cap";
    EXPECT_TRUE(wait_for([&] { return trio.relay_hub->carried_circuits() == 0u; }, 5s));
}

// When the node in the middle goes, so does everything riding on it — promptly, and
// as an ordinary disconnection rather than a peer that has quietly stopped
// answering.
TEST(RelayE2E, LosingTheRelayEndsTheCircuit) {
    Trio trio;

    std::atomic<bool> lost{false};
    trio.b.on_peer_disconnected([&](const PeerId& id) {
        if (id == trio.a.local_id()) lost.store(true);
    });

    ASSERT_TRUE(trio.start());

    ASSERT_TRUE(trio.relay_a->connect_via_relay(trio.b.local_id()));
    ASSERT_TRUE(wait_for([&] { return trio.b.peer(trio.a.local_id()).has_value(); }));

    trio.hub.stop();
    EXPECT_TRUE(wait_for([&] { return lost.load(); }, 10s))
        << "B never noticed that the path to A was gone";
    EXPECT_TRUE(wait_for([&] { return trio.relay_a->circuits() == 0u; }, 5s));
}

// A relay that dies while the circuit through it is still being set up must not
// take the whole attempt with it. Relays are volunteers and their churn is normal,
// so the answers other relays already gave are exactly what the attempt is holding
// them for. The target here runs no Relay subsystem, which makes it a peer the hubs
// can reach and forward to but that never answers — so the circuit stays half-open
// and the test can kill the carrier at the one moment that matters.
TEST(RelayE2E, ARelayThatDiesMidOpenIsReplacedByAnother) {
    Node hub1(listening_config());
    Node hub2(listening_config());
    Node a(listening_config());
    Node target(listening_config());   // deliberately no Relay: it will never answer

    Relay* relay_hub1 = hub1.add_subsystem(std::make_unique<Relay>(serving()));
    Relay* relay_hub2 = hub2.add_subsystem(std::make_unique<Relay>(serving()));
    Relay* relay_a    = a.add_subsystem(std::make_unique<Relay>(Relay::Config()));

    ASSERT_TRUE(hub1.start());
    ASSERT_TRUE(hub2.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(target.start());

    a.connect("127.0.0.1", hub1.listen_port());
    a.connect("127.0.0.1", hub2.listen_port());
    target.connect("127.0.0.1", hub1.listen_port());
    target.connect("127.0.0.1", hub2.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub1.peer_count() == 2 && hub2.peer_count() == 2; }))
        << "the two hubs never saw both ends";

    ASSERT_TRUE(relay_a->connect_via_relay(target.local_id()));

    // Both hubs answer the probe; A commits to one of them. Which one is a race, so
    // the test asks the hubs rather than assuming.
    ASSERT_TRUE(wait_for([&] {
        return relay_hub1->carried_circuits() == 1u || relay_hub2->carried_circuits() == 1u;
    })) << "A never opened a circuit through either hub";

    const bool through_first = relay_hub1->carried_circuits() == 1u;
    Node&  carrier = through_first ? hub1 : hub2;
    Relay* spare   = through_first ? relay_hub2 : relay_hub1;
    ASSERT_EQ(spare->carried_circuits(), 0u) << "the spare was used before it was needed";

    // The carrier goes away with the circuit still half-open.
    carrier.stop();

    EXPECT_TRUE(wait_for([&] { return spare->carried_circuits() == 1u; }, 5s))
        << "the attempt died with its carrier instead of trying the relay still standing";
    EXPECT_EQ(relay_a->attempts(), 1u) << "the attempt should still be running";

    a.stop();
    target.stop();
    hub1.stop();
    hub2.stop();
}

// Malformed input is dropped, never acted on. Every one of these is a message a
// hostile peer can send for free, so the requirement is simply that the node is
// still there afterwards and still relaying.
TEST(RelayE2E, IgnoresMalformedMessages) {
    Node hub(listening_config());
    Node client(listening_config());
    hub.add_subsystem(std::make_unique<Relay>(serving()));

    Watcher watcher(client);
    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 1; }));

    const std::vector<Bytes> junk = {
        Bytes{},                                  // empty
        Bytes{1},                                 // a version and nothing else
        Bytes{1, kOpOpen},                        // no circuit id
        Bytes{1, kOpOpen, 0, 0, 0, 2},            // an Open with no destination
        Bytes{1, kOpOpen, 0, 0, 0, 2, 0xAB},      // a truncated destination
        Bytes{9, kOpOpen, 0, 0, 0, 2},            // a version we do not speak
        Bytes{1, 0xFE, 0, 0, 0, 2},               // an op we do not know
        Bytes{1, kOpProbe, 0, 0, 0, 0},           // a probe for nobody
        relay_message(5 /*Data*/, 12345),         // data on a circuit that never was
    };
    for (const Bytes& msg : junk)
        client.send(hub.local_id(), MessageType::Relay, ByteView(msg));

    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(hub.peer_count(), 1u) << "the relay dropped its peer over malformed input";
    EXPECT_EQ(hub.subsystem<Relay>()->carried_circuits(), 0u);

    // Still working afterwards, which is the part that matters.
    std::array<uint8_t, PeerId::kSize> raw{};
    raw[0] = 0x11;
    client.send(hub.local_id(), MessageType::Relay,
                ByteView(open_request(2, *PeerId::from_bytes(ByteView(raw.data(), raw.size())))));
    EXPECT_TRUE(wait_for([&] { return watcher.deny_reason().has_value(); }, 5s));

    client.stop();
    hub.stop();
}

// The ladder: when a punch cannot possibly work, the target is handed on rather
// than written off. Here HolePunch is configured so it has nothing it could
// advertise, which is the same dead end a symmetric NAT produces — and the peer
// still ends up connected, over a circuit.
TEST(RelayE2E, AHolePunchThatCannotWorkFallsBackToARelay) {
    HolePunch::Config punch_config;
    punch_config.max_addresses = 0;   // nothing to advertise: a punch is impossible

    Node hub(listening_config());
    Node a(listening_config());
    Node b(listening_config());

    hub.add_subsystem(std::make_unique<Relay>(serving()));
    // Attached after Relay on purpose: HolePunch resolves RelayService in start(),
    // which is exactly the ordering this has to work under.
    a.add_subsystem(std::make_unique<Relay>(Relay::Config{}));
    auto* punch_a = a.add_subsystem(std::make_unique<HolePunch>(punch_config));
    b.add_subsystem(std::make_unique<Relay>(Relay::Config{}));
    b.add_subsystem(std::make_unique<HolePunch>(punch_config));

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());
    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; }));

    EXPECT_FALSE(punch_a->punch(b.local_id())) << "a punch with nothing to advertise ran anyway";
    EXPECT_TRUE(wait_for([&] { return a.peer(b.local_id()).has_value(); }, 20s))
        << "the punch failed and nothing took over";
    EXPECT_TRUE(relayed(a, b.local_id()));

    a.stop();
    b.stop();
    hub.stop();
}

// And the other direction: a circuit is a fallback, not a destination. Once the two
// ends are peers they can arrange a punch over the very circuit carrying them, and
// when it lands the peer table prefers the direct link at BOTH ends — swapping the
// route with no disconnect, so the application never sees the seam.
TEST(RelayE2E, ARelayedPeerIsUpgradedToADirectLink) {
    Node hub(listening_config());
    Node a(listening_config());
    Node b(listening_config());

    hub.add_subsystem(std::make_unique<Relay>(serving()));
    hub.add_subsystem(std::make_unique<HolePunch>());   // the hub carries the rendezvous too
    auto* relay_hub = hub.subsystem<Relay>();
    auto* relay_a = a.add_subsystem(std::make_unique<Relay>(Relay::Config{}));
    a.add_subsystem(std::make_unique<HolePunch>());
    b.add_subsystem(std::make_unique<Relay>(Relay::Config{}));
    b.add_subsystem(std::make_unique<HolePunch>());

    std::atomic<int> disconnects{0};
    a.on_peer_disconnected([&](const PeerId& id) {
        if (id == b.local_id()) ++disconnects;
    });
    // The upgrade can be quick enough that polling would never catch the circuit,
    // so the transport is recorded at the instant the peer appears. Without this the
    // test would pass just as happily if the two had connected directly all along,
    // which is precisely what it is meant to rule out.
    std::atomic<bool> connected_seen{false};
    std::atomic<bool> arrived_relayed{false};
    a.on_peer_connected([&](const Peer& peer) {
        if (peer.id() != b.local_id()) return;
        const auto info = peer.info();
        arrived_relayed.store(info && info->transport == TransportKind::Relay);
        connected_seen.store(true);
    });

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());
    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; }));
    // A punch needs to know an endpoint of its own, which is learned from a
    // datagram peer's identify.
    ASSERT_TRUE(wait_for([&] {
        return !a.nat_status().external_udp_endpoints().empty() &&
               !b.nat_status().external_udp_endpoints().empty();
    })) << "no external datagram endpoint was learned from the hub";

    ASSERT_TRUE(relay_a->connect_via_relay(b.local_id()));
    // Waiting on the EVENT, not on the peer table: the table is populated a moment
    // before the callbacks run, so watching it would race the very thing being read.
    ASSERT_TRUE(wait_for([&] { return connected_seen.load(); })) << "A never reached B";
    ASSERT_TRUE(arrived_relayed.load()) << "B did not arrive over a circuit at all";
    ASSERT_GT(relay_hub->carried_bytes(), 0u) << "the hub never carried anything";

    // The circuit gives way to a direct link, at both ends.
    EXPECT_TRUE(wait_for([&] {
        const auto t = transport_to(a, b.local_id());
        return t && *t != TransportKind::Relay;
    }, 25s)) << "the relayed peer was never upgraded";
    EXPECT_TRUE(wait_for([&] {
        const auto t = transport_to(b, a.local_id());
        return t && *t != TransportKind::Relay;
    }, 10s));

    // And the upgrade was seamless: the peer never went away and came back.
    EXPECT_EQ(disconnects.load(), 0) << "the application saw the peer disconnect mid-upgrade";

    a.stop();
    b.stop();
    hub.stop();
}

// The same upgrade, reached the way it actually happens in the field. The test
// above asks for a circuit directly, which leaves the punch's cooldown out of the
// story; here the circuit exists BECAUSE a punch gave up, and giving up is exactly
// what starts that cooldown. The escalation and the cooldown are two answers to the
// same event, and if the cooldown wins the upgrade is refused before it starts —
// nothing asks a second time, and the circuit outlives its purpose for the whole
// life of the peer. So this pins that handing a target to the relay retires it.
TEST(RelayE2E, GivingUpOnAPunchDoesNotBlockTheUpgradeItEscalatedInto) {
    HolePunch::Config punch_config;
    punch_config.attempts      = 1;       // one round, then give up (and cool down)
    punch_config.round_timeout = 1500ms;  // wide enough to see a session while it runs

    Node hub(listening_config());
    Node a(listening_config());
    Node b(listening_config());

    hub.add_subsystem(std::make_unique<Relay>(serving()));
    hub.add_subsystem(std::make_unique<HolePunch>());   // the hub carries the rendezvous

    a.add_subsystem(std::make_unique<Relay>(Relay::Config{}));
    auto* punch_a = a.add_subsystem(std::make_unique<HolePunch>(punch_config));

    // No HolePunch on b, deliberately: a's rendezvous is never answered, so a runs
    // its one round out and gives up — the only path that starts a cooldown, and the
    // path every real escalation takes.
    b.add_subsystem(std::make_unique<Relay>(Relay::Config{}));

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());
    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; }));
    // A punch needs an endpoint of its own to advertise, or it never starts a
    // session at all and never reaches the give-up this test is about.
    ASSERT_TRUE(wait_for([&] {
        return !a.nat_status().external_udp_endpoints().empty();
    })) << "no external datagram endpoint was learned from the hub";

    ASSERT_TRUE(punch_a->punch(b.local_id())) << "the punch never started";

    // Giving up hands b to the relay, and the circuit comes up. Waited on directly:
    // watching the session count drop to zero first would be watching the wrong
    // thing — give-up, escalation, circuit and the upgrade that follows all land
    // within a few milliseconds of each other, so a poll aimed at the gap between
    // them would just as likely consume the window this test is here to observe.
    ASSERT_TRUE(wait_for([&] { return relayed(a, b.local_id()); }))
        << "the punch gave up and no circuit took over";

    // Which is the moment the upgrade is asked for. It cannot succeed here — b has
    // no HolePunch to answer — but it must be ATTEMPTED, and any session standing
    // now is necessarily that attempt: the first one was erased before the
    // escalation that produced the circuit above. A session for b started after the
    // circuit is the whole difference between a fallback and a destination.
    EXPECT_TRUE(wait_for([&] { return punch_a->active_sessions() > 0; }, 5s))
        << "the circuit came up but the cooldown swallowed the upgrade punch";

    a.stop();
    b.stop();
    hub.stop();
}
