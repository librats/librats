#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/peer_exchange.h"
#include "wire/frame.h"

#include <chrono>
#include <memory>
#include <thread>

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

NodeConfig listening_config() {
    NodeConfig c;
    c.bind_address = "127.0.0.1";
    c.security = NodeConfig::Security::Noise;
    return c;
}

bool has_dialable_address(Node& node, const PeerId& id) {
    auto p = node.peer(id);
    return p && p->info() && !p->info()->addresses.empty();
}

} // namespace

// hub knows A and B (both dialed in). A asks hub for peers, learns B's address,
// and dials it directly — the mesh closes the triangle with no DHT/tracker.
TEST(PexE2E, DiscoversPeerThroughCommonNode) {
    Node hub(listening_config());
    Node a(listening_config());
    Node b(listening_config());

    hub.add_subsystem(std::make_unique<PeerExchange>());
    a.add_subsystem(std::make_unique<PeerExchange>());
    b.add_subsystem(std::make_unique<PeerExchange>());

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    // Bring B in first and wait until the hub actually has B's dialable address
    // (via identify) — only then can a PEX response carry it.
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] {
        return hub.peer_count() == 1 && has_dialable_address(hub, b.local_id());
    })) << "hub never learned B's dialable address";

    // Now A connects; on connect it asks the hub for peers and should learn B.
    a.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] {
        return a.peer_count() == 2 && a.peer(b.local_id()).has_value();
    })) << "A never discovered B through peer exchange";

    // The discovery is symmetric at the transport level: B now also sees A.
    EXPECT_TRUE(wait_for([&] { return b.peer(a.local_id()).has_value(); }));

    a.stop();
    b.stop();
    hub.stop();
}

// A garbage PEX frame must be ignored, never crash or drop the connection.
TEST(PexE2E, IgnoresMalformedFrame) {
    Node server(listening_config());
    Node client(listening_config());

    server.add_subsystem(std::make_unique<PeerExchange>());
    client.add_subsystem(std::make_unique<PeerExchange>());

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    // Truncated header, bad version, and a response claiming entries it doesn't carry.
    const uint8_t junk1[] = {0x01};                      // too short
    const uint8_t junk2[] = {0x99, 0x01, 0x00, 0x05};    // wrong version
    const uint8_t junk3[] = {0x01, 0x01, 0x00, 0x09};    // response: count=9, no entries
    client.send(server.local_id(), MessageType::Pex, ByteView(junk1, sizeof(junk1)));
    client.send(server.local_id(), MessageType::Pex, ByteView(junk2, sizeof(junk2)));
    client.send(server.local_id(), MessageType::Pex, ByteView(junk3, sizeof(junk3)));

    // Give the server a moment to process; the link must stay up and stable.
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(server.peer_count(), 1u);
    EXPECT_EQ(client.peer_count(), 1u);

    client.stop();
    server.stop();
}
