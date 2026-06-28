#include <gtest/gtest.h>
#include "dht/find_peers.h"
#include "dht/announce.h"
#include "dht/routing_table.h"
#include "dht/rpc_manager.h"
#include "dht/transport.h"
#include "dht/krpc.h"

#include <chrono>
#include <string>
#include <vector>

using namespace librats::dht;
using librats::Address;
using librats::KrpcMessage;
using librats::KrpcNode;
using librats::KrpcProtocol;
using librats::KrpcQueryType;
using librats::NodeId;

namespace {

class RecordingTransport : public Transport {
public:
    std::vector<std::pair<Address, std::vector<uint8_t>>> sent;
    void send(const Address& to, const std::vector<uint8_t>& d) override { sent.emplace_back(to, d); }
};

NodeId nid(uint8_t v) { NodeId id; id.fill(v); return id; }
TimePoint at(int sec) { return TimePoint{} + std::chrono::seconds(sec); }

// The most recent query we sent to `ep`, decoded (so a test can echo its txn / inspect it).
std::unique_ptr<KrpcMessage> query_to(RecordingTransport& tp, const Address& ep) {
    for (auto it = tp.sent.rbegin(); it != tp.sent.rend(); ++it)
        if (it->first == ep) return KrpcProtocol::decode_message(it->second);
    return nullptr;
}

std::string txn_to(RecordingTransport& tp, const Address& ep) {
    auto m = query_to(tp, ep);
    return m ? m->transaction_id : std::string();
}

bool has_query_to(RecordingTransport& tp, const Address& ep) {
    return query_to(tp, ep) != nullptr;
}

} // namespace

// A lookup that fans out from one seed to the nodes it returns, then collects peers.
TEST(DhtTraversal, FindPeersDiscoversAndCollects) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const NodeId self = nid(0x00);
    const NodeId info_hash = nid(0x55);
    RoutingTable table(self);

    const Address s0("10.0.0.1", 1), n1("10.0.0.2", 2), n2("10.0.0.3", 3);
    table.node_seen(nid(0xF0), s0, 20);  // one known seed

    std::vector<Address> incremental;
    std::vector<Address> final_peers;
    bool done = false;
    FindPeers fp(table, rpc, self, info_hash,
                 [&](const std::vector<Address>& p) { incremental.insert(incremental.end(), p.begin(), p.end()); },
                 [&](const std::vector<Address>& all) { done = true; final_peers = all; });

    fp.start(at(0));

    // First round: a get_peers query to the seed for our info-hash.
    ASSERT_TRUE(has_query_to(tp, s0));
    auto q = query_to(tp, s0);
    EXPECT_EQ(q->query_type, KrpcQueryType::GetPeers);
    EXPECT_EQ(q->info_hash, info_hash);

    // Seed replies with two closer nodes and a token, no peers yet.
    std::vector<KrpcNode> nodes = {KrpcNode(nid(0x50), n1.ip, n1.port),
                                   KrpcNode(nid(0x51), n2.ip, n2.port)};
    KrpcMessage r0 = KrpcProtocol::create_get_peers_response_with_nodes(txn_to(tp, s0), nid(0xF0), nodes, "tokS0");
    ASSERT_TRUE(rpc.handle_response(r0, s0, at(0)));
    EXPECT_FALSE(done);

    // The lookup should now have fanned out to both discovered nodes.
    ASSERT_TRUE(has_query_to(tp, n1));
    ASSERT_TRUE(has_query_to(tp, n2));

    // Each of them returns a peer.
    const Address p1("5.5.5.1", 100), p2("5.5.5.2", 200);
    KrpcMessage r1 = KrpcProtocol::create_get_peers_response(txn_to(tp, n1), nid(0x50), {p1}, "t1");
    KrpcMessage r2 = KrpcProtocol::create_get_peers_response(txn_to(tp, n2), nid(0x51), {p2}, "t2");
    ASSERT_TRUE(rpc.handle_response(r1, n1, at(0)));
    ASSERT_TRUE(rpc.handle_response(r2, n2, at(0)));

    EXPECT_TRUE(done);
    EXPECT_EQ(final_peers.size(), 2u);
    EXPECT_EQ(incremental.size(), 2u);  // delivered as they arrived
    EXPECT_NE(std::find(final_peers.begin(), final_peers.end(), p1), final_peers.end());
    EXPECT_NE(std::find(final_peers.begin(), final_peers.end(), p2), final_peers.end());

    // The responders ended up as confirmed contacts in the routing table.
    EXPECT_GE(table.size(), 3u);
}

// A silent node must not stall the search — it completes once that query times out.
TEST(DhtTraversal, TimeoutDoesNotStall) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const NodeId self = nid(0x00);
    const NodeId info_hash = nid(0x55);
    RoutingTable table(self);

    const Address s0("10.0.0.1", 1), s1("10.0.0.2", 2);
    table.node_seen(nid(0xF0), s0, 20);
    table.node_seen(nid(0xF1), s1, 20);

    std::vector<Address> final_peers;
    bool done = false;
    FindPeers fp(table, rpc, self, info_hash, {},
                 [&](const std::vector<Address>& all) { done = true; final_peers = all; });
    fp.start(at(0));

    ASSERT_TRUE(has_query_to(tp, s0));
    ASSERT_TRUE(has_query_to(tp, s1));

    // s0 answers with a peer; s1 stays silent.
    const Address p1("5.5.5.1", 100);
    KrpcMessage r0 = KrpcProtocol::create_get_peers_response(txn_to(tp, s0), nid(0xF0), {p1}, "tok");
    ASSERT_TRUE(rpc.handle_response(r0, s0, at(0)));
    EXPECT_FALSE(done);             // still waiting on s1

    rpc.tick(at(20));              // s1 fully times out
    EXPECT_TRUE(done);
    ASSERT_EQ(final_peers.size(), 1u);
    EXPECT_EQ(final_peers[0], p1);
}

// A bootstrap seed is added by address with an unknown id. When it replies, its real id
// becomes known and it must be resorted into the candidate list by distance — so a seed
// that turns out to be close to the target counts as a responder and receives the announce.
TEST(DhtTraversal, SeedIsResortedOnceItsIdIsKnown) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const NodeId self = nid(0x00);
    const NodeId info_hash = nid(0x55);
    RoutingTable table(self);  // empty: the lookup must rely on the seed alone

    const Address router("10.0.0.1", 1);

    bool done = false;
    Announce ann(table, rpc, self, info_hash, /*port=*/6881, /*implied_port=*/false, {},
                 [&](const std::vector<Address>&) { done = true; });
    ann.add_seed(router);     // address only — id unknown
    ann.start(at(0));

    // The seed is queried even though we don't know its id yet.
    ASSERT_TRUE(has_query_to(tp, router));
    const std::size_t before = tp.sent.size();

    // It replies revealing an id close to the info-hash, with a token and no further nodes.
    KrpcMessage r0 = KrpcProtocol::create_get_peers_response(txn_to(tp, router), nid(0x55), {}, "tokR");
    ASSERT_TRUE(rpc.handle_response(r0, router, at(0)));
    EXPECT_TRUE(done);

    // Having been resorted in as an alive token holder, it must receive an announce_peer.
    ASSERT_GT(tp.sent.size(), before);
    auto announce = query_to(tp, router);
    ASSERT_NE(announce, nullptr);
    EXPECT_EQ(announce->query_type, KrpcQueryType::AnnouncePeer);
    EXPECT_EQ(announce->token, "tokR");
}

// On completion, announce_peer goes to the closest responders that gave a token.
TEST(DhtTraversal, AnnounceSendsToTokenHolders) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const NodeId self = nid(0x00);
    const NodeId info_hash = nid(0x55);
    RoutingTable table(self);

    const Address s0("10.0.0.1", 1);
    table.node_seen(nid(0xF0), s0, 20);

    bool done = false;
    Announce ann(table, rpc, self, info_hash, /*port=*/6881, /*implied_port=*/false, {},
                 [&](const std::vector<Address>&) { done = true; });
    ann.start(at(0));

    ASSERT_TRUE(has_query_to(tp, s0));
    const std::size_t before = tp.sent.size();

    // Seed replies with a token and nothing else → the lookup converges.
    KrpcMessage r0 = KrpcProtocol::create_get_peers_response(txn_to(tp, s0), nid(0xF0), {}, "tokS0");
    ASSERT_TRUE(rpc.handle_response(r0, s0, at(0)));
    EXPECT_TRUE(done);

    // It must have sent an announce_peer back to the token holder.
    ASSERT_GT(tp.sent.size(), before);
    auto announce = query_to(tp, s0);
    ASSERT_NE(announce, nullptr);
    EXPECT_EQ(announce->query_type, KrpcQueryType::AnnouncePeer);
    EXPECT_EQ(announce->info_hash, info_hash);
    EXPECT_EQ(announce->token, "tokS0");
    EXPECT_EQ(announce->port, 6881);
}
