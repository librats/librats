#include <gtest/gtest.h>
#include "dht/persistence.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

using namespace librats::dht;
using librats::Address;

namespace {
NodeId nid(uint8_t v) { NodeId id; id.fill(v); return id; }

const NodeEntry* find_id(const std::vector<NodeEntry>& v, const NodeId& id) {
    auto it = std::find_if(v.begin(), v.end(), [&](const NodeEntry& n) { return n.id == id; });
    return it == v.end() ? nullptr : &*it;
}
}

TEST(DhtPersistenceV2, RoundTripKeepsIdAndConfirmedContacts) {
    const NodeId self = nid(0xAB);

    NodeEntry a(nid(0x10), Address("1.2.3.4", 100)); a.record_success(50);
    NodeEntry b(nid(0x20), Address("5.6.7.8", 200)); b.record_success();   // rtt unknown
    NodeEntry c(nid(0x30), Address("9.9.9.9", 300));                       // unpinged → not saved
    const std::vector<NodeEntry> contacts = {a, b, c};

    const std::string path = "test_dht_persist_v2_tmp.json";
    ASSERT_TRUE(save_routing_table(path, self, contacts));

    NodeId loaded_self{};
    std::vector<NodeEntry> loaded;
    ASSERT_TRUE(load_routing_table(path, loaded_self, loaded));

    EXPECT_EQ(loaded_self, self);
    EXPECT_EQ(loaded.size(), 2u);  // only the two confirmed contacts

    const NodeEntry* la = find_id(loaded, nid(0x10));
    ASSERT_NE(la, nullptr);
    EXPECT_EQ(la->endpoint, Address("1.2.3.4", 100));
    EXPECT_EQ(la->rtt, 50);
    EXPECT_TRUE(la->confirmed());

    const NodeEntry* lb = find_id(loaded, nid(0x20));
    ASSERT_NE(lb, nullptr);
    EXPECT_EQ(lb->rtt, NodeEntry::kRttUnknown);  // no rtt was saved

    EXPECT_EQ(find_id(loaded, nid(0x30)), nullptr);  // unconfirmed was dropped

    std::remove(path.c_str());
}

TEST(DhtPersistenceV2, MissingFileFails) {
    NodeId self{};
    std::vector<NodeEntry> contacts;
    EXPECT_FALSE(load_routing_table("definitely_not_here_12345.json", self, contacts));
}

TEST(DhtPersistenceV2, MalformedFileFails) {
    const std::string path = "test_dht_persist_v2_bad.json";
    { std::ofstream f(path); f << "{ this is not valid json "; }

    NodeId self{};
    std::vector<NodeEntry> contacts;
    EXPECT_FALSE(load_routing_table(path, self, contacts));
    std::remove(path.c_str());
}
