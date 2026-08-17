#include <gtest/gtest.h>
#include "test_paths.h"

#include "librats/node/node.h"
#include "librats/node/node_context.h"
#include "librats/subsystems/hole_punch_service.h"
#include "librats/subsystems/peer_exchange.h"
#include "librats/wire/frame.h"

#include <chrono>
#include <memory>
#include <mutex>
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

NodeConfig listening_config() {
    NodeConfig c;
    c.bind_address = "127.0.0.1";
    c.security = NodeConfig::Security::Noise;
    c.protocol = librats_test::test_protocol();
    return c;
}

bool has_dialable_address(Node& node, const PeerId& id) {
    auto p = node.peer(id);
    return p && p->info() && !p->info()->addresses.empty();
}

// Stands in for HolePunch: records who PEX asked to punch, without needing a NAT,
// a relay or a second reachable node.
class RecordingPunch final : public Subsystem, public HolePunchService {
public:
    void attach(NodeContext& ctx) override { ctx.services.provide<HolePunchService>(this); }
    void start() override {}
    void stop() override {}

    bool punch(const PeerId& target) override {
        std::lock_guard<std::mutex> lock(mutex_);
        targets_.push_back(target);
        return true;
    }

    std::vector<PeerId> targets() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return targets_;
    }

private:
    mutable std::mutex  mutex_;
    std::vector<PeerId> targets_;
};

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

// A peer learned through PEX whose advertised address will not dial (the NAT case)
// must be handed to HolePunch rather than written off.
TEST(PexE2E, PunchesPeerThatWillNotDial) {
    // TCP only: a refused connect resolves the dial at once, where a datagram dial to
    // a dead port would sit out its retries first.
    NodeConfig tcp_only = listening_config();
    tcp_only.enable_udp = false;
    tcp_only.preferred_transport = TransportKind::Tcp;

    Node server(tcp_only);
    Node client(tcp_only);

    server.add_subsystem(std::make_unique<PeerExchange>());
    auto* punch = server.add_subsystem(std::make_unique<RecordingPunch>());

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.peer_count() == 1; }));

    // One entry: an id nobody has, at an address nothing listens on.
    const Bytes ghost_id(PeerId::kSize, 0xAB);
    Bytes response = {0x01, 0x01,          // version, response
                      0x00, 0x01,          // count = 1
                      0x04, 127, 0, 0, 1,  // ip_len, 127.0.0.1
                      0x00, 0x01};         // port 1
    response.insert(response.end(), ghost_id.begin(), ghost_id.end());
    client.send(server.local_id(), MessageType::Pex, ByteView(response));

    ASSERT_TRUE(wait_for([&] { return !punch->targets().empty(); }))
        << "PEX never asked for a punch after the discovered peer refused to dial";
    EXPECT_EQ(punch->targets().front(), PeerId::from_bytes(ByteView(ghost_id)).value());

    client.stop();
    server.stop();
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
