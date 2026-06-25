#include <gtest/gtest.h>
#include "dht/node_entry.h"

using namespace librats::dht;

TEST(DhtNodeEntry, DefaultIsUnpinged) {
    NodeEntry e;
    EXPECT_FALSE(e.pinged());
    EXPECT_FALSE(e.confirmed());
    EXPECT_EQ(e.rtt, NodeEntry::kRttUnknown);
    EXPECT_FALSE(e.verified);
}

TEST(DhtNodeEntry, RecordSuccessConfirms) {
    NodeEntry e;
    e.record_success(40);
    EXPECT_TRUE(e.pinged());
    EXPECT_TRUE(e.confirmed());
    EXPECT_EQ(e.rtt, 40);
}

TEST(DhtNodeEntry, FailureOnlyCountsAfterPing) {
    NodeEntry e;
    e.record_failure();          // never pinged -> ignored
    EXPECT_FALSE(e.pinged());
    EXPECT_EQ(e.fail_count, NodeEntry::kNeverPinged);

    e.record_success(10);        // now pinged + confirmed
    e.record_failure();          // one real failure
    EXPECT_TRUE(e.pinged());
    EXPECT_FALSE(e.confirmed());
    EXPECT_EQ(e.fail_count, 1);
}

TEST(DhtNodeEntry, RttIsSmoothed) {
    NodeEntry e;
    e.update_rtt(NodeEntry::kRttUnknown);   // unknown sample ignored
    EXPECT_EQ(e.rtt, NodeEntry::kRttUnknown);

    e.update_rtt(90);                        // first sample seeds the value
    EXPECT_EQ(e.rtt, 90);
    e.update_rtt(30);                        // 90*2/3 + 30/3 = 70
    EXPECT_EQ(e.rtt, 70);
}

TEST(DhtNodeEntry, EvictionOrdering) {
    NodeEntry good;       good.record_success(20);  good.verified = true;
    NodeEntry slow;       slow.record_success(200); slow.verified = true;
    NodeEntry flaky;      flaky.record_success(20); flaky.record_failure();
    NodeEntry unverified; unverified.record_success(20);  // verified == false

    EXPECT_TRUE(slow.is_worse_than(good));        // higher RTT
    EXPECT_TRUE(flaky.is_worse_than(good));       // a failure beats a clean record
    EXPECT_TRUE(flaky.is_worse_than(slow));       // failures outrank RTT
    EXPECT_TRUE(unverified.is_worse_than(good));  // unverified loses the tie
    EXPECT_FALSE(good.is_worse_than(slow));
}
