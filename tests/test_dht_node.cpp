#include <gtest/gtest.h>
#include "dht/node.h"
#include "dht/transport.h"
#include "dht/krpc.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <vector>

using namespace librats::dht;
using librats::Address;
using librats::KrpcMessage;
using librats::KrpcNode;
using librats::KrpcProtocol;
using librats::KrpcMessageType;
using librats::KrpcQueryType;

namespace {

class RecordingTransport : public Transport {
public:
    std::vector<std::pair<Address, std::vector<uint8_t>>> sent;
    void send(const Address& to, const std::vector<uint8_t>& d) override { sent.emplace_back(to, d); }
    void clear() { sent.clear(); }
};

NodeId nid(uint8_t v) { NodeId id; id.fill(v); return id; }
TimePoint at(int sec) { return TimePoint{} + std::chrono::seconds(sec); }
std::vector<uint8_t> enc(const KrpcMessage& m) { return KrpcProtocol::encode_message(m); }
std::unique_ptr<KrpcMessage> dec(const std::vector<uint8_t>& d) { return KrpcProtocol::decode_message(d); }

// The most recent datagram decoded; null if nothing was sent.
std::unique_ptr<KrpcMessage> last(RecordingTransport& tp) {
    return tp.sent.empty() ? nullptr : dec(tp.sent.back().second);
}

// The most recent datagram sent to a particular endpoint.
std::unique_ptr<KrpcMessage> to_ep(RecordingTransport& tp, const Address& ep) {
    for (auto it = tp.sent.rbegin(); it != tp.sent.rend(); ++it)
        if (it->first == ep) return dec(it->second);
    return nullptr;
}

} // namespace

TEST(DhtNode, PingServerRespondsAndLearnsSender) {
    RecordingTransport tp;
    Node node(tp, nid(0x01), /*ipv6=*/false);
    const Address from("2.2.2.2", 5000);

    node.on_datagram(enc(KrpcProtocol::create_ping_query("aa", nid(0x09))), from, at(0));

    auto resp = last(tp);
    ASSERT_NE(resp, nullptr);
    EXPECT_EQ(resp->type, KrpcMessageType::Response);
    EXPECT_EQ(resp->transaction_id, "aa");
    EXPECT_EQ(resp->response_id, nid(0x01));      // our own id
    EXPECT_GE(node.routing_table().size(), 1u);   // the querier became a contact
}

TEST(DhtNode, FindNodeServerReturnsClosest) {
    RecordingTransport tp;
    Node node(tp, nid(0x01), false);
    node.routing_table().node_seen(nid(0x40), Address("3.3.3.3", 6), 10);

    node.on_datagram(enc(KrpcProtocol::create_find_node_query("bb", nid(0x09), nid(0x40))),
                     Address("2.2.2.2", 5000), at(0));

    auto resp = last(tp);
    ASSERT_NE(resp, nullptr);
    EXPECT_EQ(resp->type, KrpcMessageType::Response);
    ASSERT_FALSE(resp->nodes.empty());
    EXPECT_EQ(resp->nodes.front().id, nid(0x40));  // the exact target is closest
}

TEST(DhtNode, GetPeersAnnounceRoundTrip) {
    RecordingTransport tp;
    Node node(tp, nid(0x01), false);
    const Address from("2.2.2.2", 5000);
    const InfoHash ih = nid(0x55);

    // 1) get_peers on an unknown hash → nodes + a write token, no peers.
    node.on_datagram(enc(KrpcProtocol::create_get_peers_query("cc", nid(0x09), ih)), from, at(0));
    auto gp = last(tp);
    ASSERT_NE(gp, nullptr);
    EXPECT_TRUE(gp->peers.empty());
    ASSERT_FALSE(gp->token.empty());
    const std::string token = gp->token;

    // 2) announce with that token → an ack, not an error.
    tp.clear();
    node.on_datagram(enc(KrpcProtocol::create_announce_peer_query("dd", nid(0x09), ih, 6881, token, false)),
                     from, at(0));
    auto ack = last(tp);
    ASSERT_NE(ack, nullptr);
    EXPECT_EQ(ack->type, KrpcMessageType::Response);

    // 3) get_peers again now returns the announced peer.
    tp.clear();
    node.on_datagram(enc(KrpcProtocol::create_get_peers_query("ee", nid(0x09), ih)), from, at(0));
    auto gp2 = last(tp);
    ASSERT_NE(gp2, nullptr);
    ASSERT_EQ(gp2->peers.size(), 1u);
    EXPECT_EQ(gp2->peers.front(), Address("2.2.2.2", 6881));
}

TEST(DhtNode, AnnounceWithBadTokenIsRejected) {
    RecordingTransport tp;
    Node node(tp, nid(0x01), false);

    node.on_datagram(enc(KrpcProtocol::create_announce_peer_query("ff", nid(0x09), nid(0x55), 6881, "wrong", false)),
                     Address("2.2.2.2", 5000), at(0));

    auto resp = last(tp);
    ASSERT_NE(resp, nullptr);
    EXPECT_EQ(resp->type, KrpcMessageType::Error);
}

TEST(DhtNode, FloodIsRateLimited) {
    RecordingTransport tp;
    Node node(tp, nid(0x01), false);
    const Address from("7.7.7.7", 5000);

    for (int i = 0; i < 60; ++i)
        node.on_datagram(enc(KrpcProtocol::create_ping_query("aa", nid(0x09))), from, at(0));

    EXPECT_EQ(tp.sent.size(), static_cast<std::size_t>(DosBlocker::kMaxPerWindow));
}

TEST(DhtNode, FindPeersClientLookup) {
    RecordingTransport tp;
    Node node(tp, nid(0x00), false);
    const NodeId target = nid(0x55);
    const Address seed("10.0.0.1", 1);
    node.routing_table().node_seen(nid(0xF0), seed, 20);

    bool done = false;
    std::vector<Address> found;
    node.find_peers(target, {}, [&](const std::vector<Address>& all) { done = true; found = all; }, at(0));

    // It queried the seed with get_peers for our target, asking for our family.
    auto q = to_ep(tp, seed);
    ASSERT_NE(q, nullptr);
    EXPECT_EQ(q->query_type, KrpcQueryType::GetPeers);
    EXPECT_EQ(q->info_hash, target);
    EXPECT_NE(std::find(q->want.begin(), q->want.end(), "n4"), q->want.end());

    // Seed replies with a peer → the lookup completes and delivers it.
    const Address p("5.5.5.1", 100);
    KrpcMessage reply = KrpcProtocol::create_get_peers_response(q->transaction_id, nid(0xF0), {p}, "tok");
    node.on_datagram(enc(reply), seed, at(0));

    EXPECT_TRUE(done);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found.front(), p);
}

TEST(DhtNode, BootstrapQueriesRouter) {
    RecordingTransport tp;
    Node node(tp, nid(0x00), false);
    const Address router("9.9.9.9", 6881);

    node.bootstrap({router}, at(0));

    auto q = to_ep(tp, router);
    ASSERT_NE(q, nullptr);
    EXPECT_EQ(q->query_type, KrpcQueryType::GetPeers);
    EXPECT_EQ(q->info_hash, node.self());  // a self-targeted lookup
}
