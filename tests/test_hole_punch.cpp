#include <gtest/gtest.h>
#include "test_paths.h"

#include "librats/node/node.h"
#include "librats/subsystems/hole_punch.h"
#include "librats/wire/frame.h"

#include <array>
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

PeerId id_with(uint8_t first_byte) {
    std::array<uint8_t, PeerId::kSize> raw{};
    raw[0] = first_byte;
    return *PeerId::from_bytes(ByteView(raw.data(), raw.size()));
}

// The wire form a punching peer sends to a relay: [ver][op=Relay][dst][inner].
// Spelled out here rather than reached through the subsystem so the test pins the
// format the two ends agree on, not just the code that happens to produce it.
Bytes relay_envelope(const PeerId& dst, const Bytes& inner) {
    Bytes out;
    out.push_back(1);  // version
    out.push_back(0);  // op = Relay
    const auto& id = dst.bytes();
    out.insert(out.end(), id.begin(), id.end());
    out.insert(out.end(), inner.begin(), inner.end());
    return out;
}

Bytes sync_body() { return Bytes{1}; }  // inner kind = Sync, no payload

// An opening Connect naming one endpoint in TEST-NET-1 — a well-formed rendezvous
// pointing somewhere nothing can answer from, which is what a real punch that does
// not land looks like from the responder's side.
// [kind=Connect][role=opening][count=1][ip_len=4][192.0.2.1][port=9]
Bytes unreachable_connect() { return Bytes{0, 0, 1, 4, 192, 0, 2, 1, 0, 9}; }

// Every node in a punch scenario needs a UDP link to its relay before it knows any
// external endpoint of its own — that is where the observation comes from.
bool knows_own_endpoint(Node& node) {
    return !node.nat_status().external_udp_endpoints().empty();
}

} // namespace

// The whole point, end to end: A and B have never met and each knows only the hub.
// A punches, the hub carries the rendezvous, and the two end up directly connected.
TEST(HolePunchE2E, ConnectsTwoPeersThroughACommonRelay) {
    Node hub(listening_config());
    Node a(listening_config());
    Node b(listening_config());

    hub.add_subsystem(std::make_unique<HolePunch>());
    auto* punch_a = a.add_subsystem(std::make_unique<HolePunch>());
    auto* punch_b = b.add_subsystem(std::make_unique<HolePunch>());

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; })) << "peers never reached the hub";

    // The datagram identify exchange is what teaches a node the endpoint its own
    // socket is seen at; without it there is nothing to advertise to the target.
    ASSERT_TRUE(wait_for([&] { return knows_own_endpoint(a) && knows_own_endpoint(b); }))
        << "no external datagram endpoint was learned from the hub";

    ASSERT_TRUE(punch_a->punch(b.local_id())) << "punch was refused";

    ASSERT_TRUE(wait_for([&] { return a.peer(b.local_id()).has_value(); }))
        << "A never reached B";
    EXPECT_TRUE(wait_for([&] { return b.peer(a.local_id()).has_value(); }))
        << "B never reached A";

    // Both ends fired: the responder is not a bystander, it dials at the same
    // moment — that simultaneity IS the mechanism.
    EXPECT_GE(punch_a->punches_started(), 1u);
    EXPECT_TRUE(wait_for([&] { return punch_b->punches_started() >= 1u; }, 3s));

    // And the session is retired once the peer is there, rather than left to age out.
    EXPECT_TRUE(wait_for([&] { return punch_a->active_sessions() == 0u; }, 3s));

    a.stop();
    b.stop();
    hub.stop();
}

// Both ends deciding to punch at the same moment is not an error — it is what
// happens when two peers discover each other simultaneously. Left unhandled each
// would sit waiting for the other's Sync and neither would send one, so the
// symmetric PeerId rule settles which round runs. The observable requirement is
// simply that they still end up connected, exactly once.
TEST(HolePunchE2E, SimultaneousPunchesFromBothEndsStillConnect) {
    Node hub(listening_config());
    Node a(listening_config());
    Node b(listening_config());

    hub.add_subsystem(std::make_unique<HolePunch>());
    auto* punch_a = a.add_subsystem(std::make_unique<HolePunch>());
    auto* punch_b = b.add_subsystem(std::make_unique<HolePunch>());

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; }));
    ASSERT_TRUE(wait_for([&] { return knows_own_endpoint(a) && knows_own_endpoint(b); }));

    EXPECT_TRUE(punch_a->punch(b.local_id()));

    // B decides at the same moment — but "the same moment" is itself a race against
    // A's Connect, which needs only two loopback hops to arrive. If it gets there
    // first, B is already answering A's rendezvous and declines to open a second one
    // for the same peer. That is the same collision settled one message earlier, so
    // the answer here is not the requirement; what comes out of it is.
    punch_b->punch(a.local_id());

    ASSERT_TRUE(wait_for([&] {
        return a.peer(b.local_id()).has_value() && b.peer(a.local_id()).has_value();
    })) << "a head-on pair of punches left the peers unconnected";

    // One link between them, not two: the duplicate a successful punch produces is
    // resolved identically at both ends (see peer_table.cpp).
    EXPECT_TRUE(wait_for([&] { return a.peer_count() == 2 && b.peer_count() == 2; }, 3s))
        << "a=" << a.peer_count() << " b=" << b.peer_count();

    a.stop();
    b.stop();
    hub.stop();
}

// The same collision, pinned down rather than raced for. Above, both ends opening a
// rendezvous at once depends on two Connects crossing on the wire; here the second
// one is injected by hand at a moment B is known to be holding an initiator session,
// so the symmetric rule is exercised on every run and in both directions.
//
// The stranger runs no HolePunch of its own — it answers nothing, which is what
// leaves B's opened round standing while the collision is delivered to it.
TEST(HolePunchE2E, HeadOnRendezvousIsSettledByTheSmallerPeerId) {
    Node hub(listening_config());
    Node b(listening_config());
    Node stranger(listening_config());

    auto* relay   = hub.add_subsystem(std::make_unique<HolePunch>());
    auto* punch_b = b.add_subsystem(std::make_unique<HolePunch>());

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(b.start());
    ASSERT_TRUE(stranger.start());

    b.connect("127.0.0.1", hub.listen_port());
    stranger.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2 && knows_own_endpoint(b); }));

    ASSERT_TRUE(punch_b->punch(stranger.local_id()));
    ASSERT_TRUE(wait_for([&] { return relay->relayed() >= 1u; }, 5s))
        << "B's own rendezvous never reached the relay";

    // ... and now the other end opens one of its own, into that.
    stranger.send(hub.local_id(), MessageType::Punch,
                  ByteView(relay_envelope(b.local_id(), unreachable_connect())));
    ASSERT_TRUE(wait_for([&] { return relay->relayed() >= 2u; }, 5s))
        << "the competing rendezvous never reached B";

    // Whoever holds the smaller id keeps the round and ignores the other's Connect;
    // the larger stands down and answers, which is one more message through the
    // relay. Both ends compute the same rule, so exactly one of them stands down.
    const bool b_keeps_the_round = b.local_id() < stranger.local_id();
    if (b_keeps_the_round) {
        std::this_thread::sleep_for(300ms);
        EXPECT_EQ(relay->relayed(), 2u) << "B answered a round its own id should have won";
    } else {
        ASSERT_TRUE(wait_for([&] { return relay->relayed() >= 3u; }, 5s))
            << "B neither kept its round nor stood down and answered";
        std::this_thread::sleep_for(300ms);
        EXPECT_EQ(relay->relayed(), 3u)
            << "the two ends read each other's answer as a new round and ping-ponged";
    }

    // Either way it is one session, and nothing has been dialed yet: a Sync is
    // still owed, by whichever end kept the round.
    EXPECT_EQ(punch_b->active_sessions(), 1u);
    EXPECT_EQ(punch_b->punches_started(), 0u);

    // And that is exactly what the stood-down side is waiting for — while the side
    // that kept its round is waiting for a Connect, and ignores a Sync it never asked
    // anyone to send.
    stranger.send(hub.local_id(), MessageType::Punch,
                  ByteView(relay_envelope(b.local_id(), sync_body())));
    if (b_keeps_the_round) {
        std::this_thread::sleep_for(300ms);
        EXPECT_EQ(punch_b->punches_started(), 0u) << "B punched on a Sync it never asked for";
    } else {
        EXPECT_TRUE(wait_for([&] { return punch_b->punches_started() == 1u; }, 5s))
            << "B stood down but never acted on the Sync it was waiting for";
    }

    b.stop();
    stranger.stop();
    hub.stop();
}

// A punch that does not land is retried: one lost Syn burst is the expected case,
// not a verdict on the target. `attempts` rounds go out, each a fresh rendezvous,
// and only then is the target called off for `cooldown`.
//
// The target here runs no HolePunch at all, so it answers nothing and every round
// runs to its full timeout — which makes the hub's forward count an exact census of
// the rounds the initiator opened.
TEST(HolePunchE2E, InitiatorRetriesARendezvousThatWentUnanswered) {
    HolePunch::Config impatient;
    impatient.attempts      = 3;
    impatient.round_timeout = 250ms;
    impatient.tick          = 50ms;

    Node hub(listening_config());
    Node a(listening_config());
    Node silent(listening_config());   // deliberately no HolePunch subsystem

    auto* relay   = hub.add_subsystem(std::make_unique<HolePunch>());
    auto* punch_a = a.add_subsystem(std::make_unique<HolePunch>(impatient));

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(silent.start());

    a.connect("127.0.0.1", hub.listen_port());
    silent.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2 && knows_own_endpoint(a); }));

    ASSERT_TRUE(punch_a->punch(silent.local_id())) << "punch was refused";

    // Three rendezvous rounds, not one: the retry is the whole point of this test.
    ASSERT_TRUE(wait_for([&] { return relay->relayed() >= 3u; }, 5s))
        << "the initiator opened only " << relay->relayed() << " round(s)";

    // And then it stops — `attempts` is a cap, not a floor.
    ASSERT_TRUE(wait_for([&] { return punch_a->active_sessions() == 0u; }, 5s))
        << "the session never gave up";
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(relay->relayed(), 3u) << "the initiator kept retrying past its attempt cap";

    // Having exhausted its attempts, the initiator holds the target in cooldown.
    EXPECT_FALSE(punch_a->punch(silent.local_id())) << "a given-up target was not in cooldown";

    a.stop();
    silent.stop();
    hub.stop();
}

// Regression: the responder must NOT put the initiator into cooldown when its own
// round times out. Its round started a relay hop later than the initiator's, so it
// expires at almost exactly the moment the initiator retries — and a cooldown here
// would silently swallow that retry (and every one after it) for a full minute.
//
// The rendezvous is injected by hand so the responder is driven through a round
// that cannot possibly succeed: a well-formed Connect naming an address nothing
// answers from, and no Sync ever following it.
TEST(HolePunchE2E, ResponderRoundTimingOutDoesNotBlockTheInitiatorsRetry) {
    HolePunch::Config quick;
    quick.round_timeout = 300ms;
    quick.tick          = 50ms;

    Node hub(listening_config());
    Node a(listening_config());
    Node b(listening_config());

    hub.add_subsystem(std::make_unique<HolePunch>());
    a.add_subsystem(std::make_unique<HolePunch>());
    auto* punch_b = b.add_subsystem(std::make_unique<HolePunch>(quick));

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2 && knows_own_endpoint(b); }));

    const Bytes rendezvous = relay_envelope(b.local_id(), unreachable_connect());

    a.send(hub.local_id(), MessageType::Punch, ByteView(rendezvous));
    ASSERT_TRUE(wait_for([&] { return punch_b->active_sessions() == 1u; }, 5s))
        << "the responder never took up the rendezvous";
    ASSERT_TRUE(wait_for([&] { return punch_b->active_sessions() == 0u; }, 5s))
        << "the responder's round never timed out";

    // The initiator tries again, exactly as service_sessions() does. Before the fix
    // this was dropped by a cooldown the responder had just imposed on it.
    a.send(hub.local_id(), MessageType::Punch, ByteView(rendezvous));
    EXPECT_TRUE(wait_for([&] { return punch_b->active_sessions() == 1u; }, 3s))
        << "the responder ignored the retry — it put the initiator in cooldown";

    a.stop();
    b.stop();
    hub.stop();
}

// The same bug seen from the other side: answering somebody else's failed round
// must not cost this node its own right to punch that peer.
TEST(HolePunchE2E, ResponderRoundTimingOutDoesNotBlockOurOwnPunch) {
    HolePunch::Config quick;
    quick.round_timeout = 300ms;
    quick.tick          = 50ms;

    Node hub(listening_config());
    Node a(listening_config());
    Node b(listening_config());

    hub.add_subsystem(std::make_unique<HolePunch>());
    a.add_subsystem(std::make_unique<HolePunch>());
    auto* punch_b = b.add_subsystem(std::make_unique<HolePunch>(quick));

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2 && knows_own_endpoint(b); }));

    a.send(hub.local_id(), MessageType::Punch,
           ByteView(relay_envelope(b.local_id(), unreachable_connect())));
    ASSERT_TRUE(wait_for([&] { return punch_b->active_sessions() == 1u; }, 5s));
    ASSERT_TRUE(wait_for([&] { return punch_b->active_sessions() == 0u; }, 5s))
        << "the responder's round never timed out";

    EXPECT_TRUE(punch_b->punch(a.local_id()))
        << "answering a failed round left the peer in cooldown for us too";

    a.stop();
    b.stop();
    hub.stop();
}

// A relay forwards only to a peer it already holds. Anything else would make it an
// open reflector for whoever asks.
TEST(HolePunchE2E, RelayDropsMessagesForPeersItDoesNotHave) {
    Node hub(listening_config());
    Node a(listening_config());

    auto* relay = hub.add_subsystem(std::make_unique<HolePunch>());
    auto* punch_a = a.add_subsystem(std::make_unique<HolePunch>());

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());

    a.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 1 && knows_own_endpoint(a); }));

    // A stranger the hub has never heard of.
    EXPECT_TRUE(punch_a->punch(id_with(0x5A)));

    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(relay->relayed(), 0u) << "the hub relayed for a peer it does not hold";
    EXPECT_EQ(punch_a->punches_started(), 0u) << "A punched without ever hearing back";

    a.stop();
    hub.stop();
}

// Relaying is work done on somebody else's behalf, so it is budgeted: past the
// allowance a peer's requests are dropped rather than served.
TEST(HolePunchE2E, RelayEnforcesItsPerPeerBudget) {
    HolePunch::Config relay_config;
    relay_config.relay_budget = 3;
    relay_config.relay_window = 30s;   // one window for the whole test

    Node hub(listening_config());
    Node a(listening_config());
    Node b(listening_config());

    auto* relay = hub.add_subsystem(std::make_unique<HolePunch>(relay_config));
    a.add_subsystem(std::make_unique<HolePunch>());
    b.add_subsystem(std::make_unique<HolePunch>());

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; }));

    // Hand-built envelopes, so exactly ten relay requests are made and nothing else
    // in the subsystem gets a say in how many there are. A Sync body is used because
    // B has no session and will ignore it — this test is about the hub.
    const Bytes message = relay_envelope(b.local_id(), sync_body());
    for (int i = 0; i < 10; ++i)
        a.send(hub.local_id(), MessageType::Punch, ByteView(message));

    std::this_thread::sleep_for(400ms);
    EXPECT_EQ(relay->relayed(), 3u) << "the relay budget was not enforced";

    a.stop();
    b.stop();
    hub.stop();
}

// A node with nothing to advertise cannot punch — and must say so rather than
// starting a rendezvous that can only fail.
TEST(HolePunch, RefusesWithoutAnExternalEndpoint) {
    Node lonely(listening_config());
    auto* punch = lonely.add_subsystem(std::make_unique<HolePunch>());
    ASSERT_TRUE(lonely.start());

    EXPECT_FALSE(punch->punch(id_with(0x11)));
    EXPECT_EQ(punch->active_sessions(), 0u);

    lonely.stop();
}

// Punching to somebody already connected is pointless; a caller may punch() freely
// on discovery without having to check first.
TEST(HolePunchE2E, RefusesToPunchAConnectedPeer) {
    Node hub(listening_config());
    Node a(listening_config());

    hub.add_subsystem(std::make_unique<HolePunch>());
    auto* punch_a = a.add_subsystem(std::make_unique<HolePunch>());

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());

    a.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return a.peer_count() == 1 && knows_own_endpoint(a); }));

    EXPECT_FALSE(punch_a->punch(hub.local_id()));
    EXPECT_FALSE(punch_a->punch(a.local_id()));   // and not to ourselves either
    EXPECT_EQ(punch_a->active_sessions(), 0u);

    a.stop();
    hub.stop();
}

// A malformed punch frame is ignored, never fatal: it must not crash, must not
// drop the link, and must not be relayed.
TEST(HolePunchE2E, IgnoresMalformedFrames) {
    Node hub(listening_config());
    Node a(listening_config());

    auto* relay = hub.add_subsystem(std::make_unique<HolePunch>());
    a.add_subsystem(std::make_unique<HolePunch>());

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());

    a.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 1; }));

    const uint8_t truncated[] = {0x01, 0x00, 0x11};             // envelope cut short
    const uint8_t bad_version[] = {0x99, 0x00};                 // unknown version
    a.send(hub.local_id(), MessageType::Punch, ByteView(truncated, sizeof(truncated)));
    a.send(hub.local_id(), MessageType::Punch, ByteView(bad_version, sizeof(bad_version)));

    // An envelope naming a real destination but carrying a Connect that claims more
    // addresses than it holds.
    Bytes lying_connect{0 /*kind=Connect*/, 0 /*role=opening*/, 3 /*count*/,
                        4 /*ip_len*/, 1, 2, 3, 4};
    a.send(hub.local_id(), MessageType::Punch,
           ByteView(relay_envelope(hub.local_id(), lying_connect)));

    std::this_thread::sleep_for(250ms);
    EXPECT_EQ(hub.peer_count(), 1u);
    EXPECT_EQ(a.peer_count(), 1u);
    EXPECT_EQ(relay->relayed(), 0u);   // dst was the hub itself; never forwarded

    a.stop();
    hub.stop();
}

// A relay that has been asked not to relay does not, however well-formed the ask.
TEST(HolePunchE2E, RelayCanBeTurnedOff) {
    HolePunch::Config no_relay;
    no_relay.enable_relay = false;

    Node hub(listening_config());
    Node a(listening_config());
    Node b(listening_config());

    auto* relay = hub.add_subsystem(std::make_unique<HolePunch>(no_relay));
    a.add_subsystem(std::make_unique<HolePunch>());
    b.add_subsystem(std::make_unique<HolePunch>());

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; }));

    a.send(hub.local_id(), MessageType::Punch,
           ByteView(relay_envelope(b.local_id(), sync_body())));

    std::this_thread::sleep_for(250ms);
    EXPECT_EQ(relay->relayed(), 0u);

    a.stop();
    b.stop();
    hub.stop();
}
