// IP-diversity admission — the DHT's Sybil/eclipse defence (BEP 42, libtorrent's
// dht_restrict_routing_ips / dht_restrict_search_ips). Two layers are exercised here:
//   1. the routing table: one contact per IP table-wide, one per /24 (v4) / /64 (v6)
//      per bucket, an id that changes under a held endpoint is evicted, and — crucially —
//      the per-IP accounting index stays balanced across arbitrary churn; and
//   2. an iterative lookup: one subnet can't flood the candidate set.
// All limits apply to *public* addresses only; private/loopback stay unconstrained so a
// LAN or test topology behaves exactly as before.

#include <gtest/gtest.h>
#include "dht/routing_table.h"
#include "dht/find_peers.h"
#include "dht/rpc_manager.h"
#include "dht/transport.h"
#include "dht/krpc.h"

#include <random>
#include <string>
#include <vector>

using namespace librats::dht;
using librats::Address;
using librats::KrpcMessage;
using librats::KrpcNode;
using librats::KrpcProtocol;
using librats::KrpcQueryType;

namespace {

const NodeId kZeroSelf{};

// An id whose most-significant set bit is at `bucket` (fixing its bucket under the
// all-zero self), varied by `salt` in a lower byte so ids stay distinct in one bucket.
NodeId id_in_bucket(int bucket, uint8_t salt) {
    NodeId id{};
    id[bucket / 8] = static_cast<uint8_t>(1u << (7 - bucket % 8));
    if (bucket / 8 + 1 < static_cast<int>(kIdSize)) id[bucket / 8 + 1] = salt;
    return id;
}

// A public IPv4 endpoint. 11.0.0.0/8 is globally routable, so these are all constrained
// by the IP-diversity rules (unlike the 10.x the other routing-table tests use).
Address pub(uint8_t b, uint8_t c, uint8_t d, uint16_t port = 6881) {
    return Address("11." + std::to_string(b) + "." + std::to_string(c) + "." + std::to_string(d), port);
}

Address priv(uint8_t d, uint16_t port = 6881) { return Address("10.0.0." + std::to_string(d), port); }

} // namespace

// --- routing table: rule 2 (per-bucket subnet limit) ------------------------------

TEST(DhtIpDiversity, PrivateIpsAreUnconstrained) {
    // Regression guard: many private contacts in one /24 all still fit (the pre-existing
    // behaviour the rest of the suite relies on), and nothing lands in the public index.
    RoutingTable rt(kZeroSelf);
    for (uint8_t i = 1; i <= 8; ++i)
        EXPECT_TRUE(rt.node_seen(id_in_bucket(40, i), priv(i), 20));
    EXPECT_EQ(rt.size(), 8u);
    EXPECT_TRUE(rt.ip_index_consistent());
}

TEST(DhtIpDiversity, SameSubnetLimitedWithinBucket) {
    RoutingTable rt(kZeroSelf);
    EXPECT_TRUE(rt.node_seen(id_in_bucket(40, 1), pub(2, 3, 1), 20));   // 11.2.3.1
    EXPECT_FALSE(rt.node_seen(id_in_bucket(40, 2), pub(2, 3, 2), 20));  // 11.2.3.2 — same /24, same bucket
    EXPECT_EQ(rt.size(), 1u);
    EXPECT_TRUE(rt.ip_index_consistent());
}

TEST(DhtIpDiversity, DifferentSubnetsCoexistInABucket) {
    RoutingTable rt(kZeroSelf);
    EXPECT_TRUE(rt.node_seen(id_in_bucket(40, 1), pub(2, 3, 1), 20));   // 11.2.3.1
    EXPECT_TRUE(rt.node_seen(id_in_bucket(40, 2), pub(9, 9, 2), 20));   // 11.9.9.2 — different /24
    EXPECT_EQ(rt.size(), 2u);
    EXPECT_TRUE(rt.ip_index_consistent());
}

TEST(DhtIpDiversity, SubnetLimitIsPerBucketNotGlobal) {
    // The /24 limit is scoped to a bucket (as in libtorrent). While the table is young it
    // has a single catch-all bucket, so the limit is effectively table-wide — two contacts
    // in one /24 can't both be kept regardless of how far apart their ids are...
    RoutingTable rt(kZeroSelf);
    EXPECT_TRUE(rt.node_seen(id_in_bucket(40, 1), pub(4, 4, 1), 20));
    EXPECT_FALSE(rt.node_seen(id_in_bucket(80, 2), pub(4, 4, 2), 20));  // same /24, same (only) bucket
    EXPECT_EQ(rt.size(), 1u);
    // ...but a different /24 in that same bucket is always fine.
    EXPECT_TRUE(rt.node_seen(id_in_bucket(80, 2), pub(5, 5, 2), 20));
    EXPECT_EQ(rt.size(), 2u);
    EXPECT_TRUE(rt.ip_index_consistent());
}

// --- routing table: rule 1 (one contact per IP, table-wide) -----------------------

TEST(DhtIpDiversity, DuplicateIpDifferentPortRejected) {
    RoutingTable rt(kZeroSelf);
    EXPECT_TRUE(rt.node_seen(id_in_bucket(40, 1), pub(5, 6, 7, 1000), 20));
    // Same IP, different port, different id — a poisoning shape: ignored, old one kept.
    EXPECT_FALSE(rt.node_seen(id_in_bucket(90, 2), pub(5, 6, 7, 2000), 20));
    EXPECT_EQ(rt.size(), 1u);
    EXPECT_TRUE(rt.ip_index_consistent());
}

TEST(DhtIpDiversity, UnconfirmedIdChangeAtHeldEndpointIgnored) {
    RoutingTable rt(kZeroSelf);
    const Address a = pub(7, 7, 7);
    EXPECT_TRUE(rt.node_seen(id_in_bucket(40, 1), a, 20));  // confirmed contact
    rt.heard_about(id_in_bucket(90, 2), a);                 // same endpoint, new id, only hearsay
    EXPECT_EQ(rt.size(), 1u);                               // ignored — can't displace on hearsay
    EXPECT_TRUE(rt.ip_index_consistent());
}

TEST(DhtIpDiversity, ConfirmedIdChangeAtHeldEndpointEvictsOld) {
    RoutingTable rt(kZeroSelf);
    const Address a = pub(8, 8, 8);
    EXPECT_TRUE(rt.node_seen(id_in_bucket(40, 1), a, 20));   // old contact
    // A confirmed reply from the same endpoint under a new id is suspect: drop the old
    // entry and don't trust the new one either.
    EXPECT_FALSE(rt.node_seen(id_in_bucket(40, 2), a, 20));
    EXPECT_EQ(rt.size(), 0u);
    EXPECT_TRUE(rt.ip_index_consistent());
}

TEST(DhtIpDiversity, SameIdRoamingToNewIpKeepsIndexBalanced) {
    // A known contact legitimately re-appearing at a new IP updates in place — the index
    // must move with it, not leak the old IP.
    RoutingTable rt(kZeroSelf);
    const NodeId id = id_in_bucket(40, 1);
    EXPECT_TRUE(rt.node_seen(id, pub(1, 1, 1), 20));
    EXPECT_TRUE(rt.node_seen(id, pub(2, 2, 2), 20));  // same id, new public IP
    EXPECT_EQ(rt.size(), 1u);
    EXPECT_TRUE(rt.ip_index_consistent());
    // The freed /24 can now host a different contact, proving the old IP was released.
    EXPECT_TRUE(rt.node_seen(id_in_bucket(50, 3), pub(1, 1, 9), 20));
    EXPECT_TRUE(rt.ip_index_consistent());
}

TEST(DhtIpDiversity, Ipv6SameSlash64LimitedWithinBucket) {
    RoutingTable rt(kZeroSelf);
    EXPECT_TRUE(rt.node_seen(id_in_bucket(40, 1), Address("2001:db8::1", 6881), 20));
    // Same /64 (first 8 bytes equal), same bucket -> rejected.
    EXPECT_FALSE(rt.node_seen(id_in_bucket(40, 2), Address("2001:db8::2", 6881), 20));
    // A different /64 is fine.
    EXPECT_TRUE(rt.node_seen(id_in_bucket(40, 3), Address("2001:dead::1", 6881), 20));
    EXPECT_EQ(rt.size(), 2u);
    EXPECT_TRUE(rt.ip_index_consistent());
}

// --- routing table: the accounting invariant survives churn -----------------------

TEST(DhtIpDiversity, IpIndexStaysConsistentUnderChurn) {
    // Drive splits, spread-evictions, replacement promotion and failures with distinct
    // public /24s (so most are admitted), checking the index invariant throughout. This
    // is the real guard on the add/erase/overwrite accounting.
    RoutingTable rt(kZeroSelf);
    std::mt19937 rng(12345);
    std::vector<std::pair<NodeId, Address>> live_ids;

    for (int i = 0; i < 400; ++i) {
        const int bucket = 8 + static_cast<int>(rng() % 150);
        const NodeId id = id_in_bucket(bucket, static_cast<uint8_t>(rng()));
        // Unique /24 per node keeps rule 2 from dominating; a handful reuse a subnet to
        // also exercise the reject path.
        const Address ep = pub(static_cast<uint8_t>(i / 200),        // 0..1
                               static_cast<uint8_t>(i % 200),        // spreads /24s
                               static_cast<uint8_t>(1 + rng() % 3));
        if (rt.node_seen(id, ep, static_cast<uint16_t>(1 + rng() % 100)))
            live_ids.emplace_back(id, ep);
        ASSERT_TRUE(rt.ip_index_consistent()) << "after add #" << i;

        // Occasionally fail a previously-added contact.
        if (!live_ids.empty() && rng() % 3 == 0) {
            const auto& victim = live_ids[rng() % live_ids.size()];
            rt.node_failed(victim.first, victim.second);
            ASSERT_TRUE(rt.ip_index_consistent()) << "after fail #" << i;
        }
    }

    // A node-id change re-buckets everything; the index must survive the rebuild.
    rt.set_self(id_in_bucket(20, 7));
    EXPECT_TRUE(rt.ip_index_consistent());
}

// --- lookup: one subnet can't flood the candidate set -----------------------------

namespace {
class RecordingTransport : public Transport {
public:
    std::vector<std::pair<Address, std::vector<uint8_t>>> sent;
    void send(const Address& to, const std::vector<uint8_t>& d) override { sent.emplace_back(to, d); }
};
NodeId nid(uint8_t v) { NodeId id; id.fill(v); return id; }
std::string txn_to(RecordingTransport& tp, const Address& ep) {
    for (auto it = tp.sent.rbegin(); it != tp.sent.rend(); ++it)
        if (it->first == ep) { auto m = KrpcProtocol::decode_message(it->second); return m ? m->transaction_id : ""; }
    return "";
}
bool queried(RecordingTransport& tp, const Address& ep) {
    for (auto& s : tp.sent) if (s.first == ep) return true;
    return false;
}
} // namespace

TEST(DhtIpDiversity, LookupIgnoresFloodedSubnet) {
    RecordingTransport tp;
    RpcManager rpc(tp);
    const NodeId self = nid(0x00), info_hash = nid(0x55);
    RoutingTable table(self);

    const Address seed = priv(1);          // a private seed drives the lookup
    table.node_seen(nid(0xF0), seed, 20);

    bool done = false;
    FindPeers fp(table, rpc, self, info_hash, [](const std::vector<Address>&) {},
                 [&](const std::vector<Address>&) { done = true; });
    fp.start(librats::dht::TimePoint{});

    // The seed points us at two nodes in one public /24 plus one in a different /24.
    const Address a1 = pub(8, 8, 1), a2 = pub(8, 8, 2), b1 = pub(9, 9, 9);
    std::vector<KrpcNode> nodes = {KrpcNode(nid(0x50), a1.ip, a1.port),
                                   KrpcNode(nid(0x51), a2.ip, a2.port),
                                   KrpcNode(nid(0x52), b1.ip, b1.port)};
    KrpcMessage r = KrpcProtocol::create_get_peers_response_with_nodes(
        txn_to(tp, seed), nid(0xF0), nodes, "tok");
    ASSERT_TRUE(rpc.handle_response(r, seed, librats::dht::TimePoint{}));

    EXPECT_TRUE(queried(tp, a1));   // first node in the /24 is accepted
    EXPECT_FALSE(queried(tp, a2));  // second node in the same /24 is ignored
    EXPECT_TRUE(queried(tp, b1));   // a different /24 still gets through
}

TEST(DhtIpDiversity, LookupIgnoresFloodedSubnetIpv6) {
    // The same flood defence over IPv6: one operator holding a whole /64 can hand out many
    // distinct node-ids, yet only the first is admitted to the search — the rest of the /64
    // is ignored. Exercises register_subnet()'s v6 branch (the v4 test above covers v4).
    RecordingTransport tp;
    RpcManager rpc(tp);
    const NodeId self = nid(0x00), info_hash = nid(0x55);
    RoutingTable table(self);

    const Address seed = priv(1);          // a private seed drives the lookup
    table.node_seen(nid(0xF0), seed, 20);

    FindPeers fp(table, rpc, self, info_hash, [](const std::vector<Address>&) {},
                 [](const std::vector<Address>&) {});
    fp.start(librats::dht::TimePoint{});

    // Two nodes in one public /64 (first 8 bytes equal) plus one in a different /64.
    const Address a1("2001:db8::1", 6881), a2("2001:db8::2", 6881), b1("2001:dead::1", 6881);
    std::vector<KrpcNode> nodes = {KrpcNode(nid(0x50), a1.ip, a1.port),
                                   KrpcNode(nid(0x51), a2.ip, a2.port),
                                   KrpcNode(nid(0x52), b1.ip, b1.port)};
    KrpcMessage r = KrpcProtocol::create_get_peers_response_with_nodes(
        txn_to(tp, seed), nid(0xF0), nodes, "tok");
    ASSERT_TRUE(rpc.handle_response(r, seed, librats::dht::TimePoint{}));

    EXPECT_TRUE(queried(tp, a1));   // first node in the /64 is accepted
    EXPECT_FALSE(queried(tp, a2));  // second node in the same /64 is ignored
    EXPECT_TRUE(queried(tp, b1));   // a different /64 still gets through
}

TEST(DhtIpDiversity, LookupDoesNotRestrictPrivateSubnets) {
    // The lookup filter, like the routing table, constrains only public addresses. Several
    // candidates sharing one private /24 (a LAN / integration-test topology) must all be
    // queried, or local multi-node tests would starve. Exercises register_subnet()'s
    // is_public_address guard returning "no collision" for private endpoints.
    RecordingTransport tp;
    RpcManager rpc(tp);
    const NodeId self = nid(0x00), info_hash = nid(0x55);
    RoutingTable table(self);

    const Address seed = priv(1);
    table.node_seen(nid(0xF0), seed, 20);

    FindPeers fp(table, rpc, self, info_hash, [](const std::vector<Address>&) {},
                 [](const std::vector<Address>&) {});
    fp.start(librats::dht::TimePoint{});

    // Three nodes all in 10.0.0.0/24 — the same private /24 — must all be queried.
    const Address a1 = priv(11), a2 = priv(12), a3 = priv(13);
    std::vector<KrpcNode> nodes = {KrpcNode(nid(0x50), a1.ip, a1.port),
                                   KrpcNode(nid(0x51), a2.ip, a2.port),
                                   KrpcNode(nid(0x52), a3.ip, a3.port)};
    KrpcMessage r = KrpcProtocol::create_get_peers_response_with_nodes(
        txn_to(tp, seed), nid(0xF0), nodes, "tok");
    ASSERT_TRUE(rpc.handle_response(r, seed, librats::dht::TimePoint{}));

    EXPECT_TRUE(queried(tp, a1));
    EXPECT_TRUE(queried(tp, a2));
    EXPECT_TRUE(queried(tp, a3));
}
