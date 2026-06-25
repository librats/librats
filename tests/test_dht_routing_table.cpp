#include <gtest/gtest.h>
#include "dht/routing_table.h"

#include <algorithm>
#include <random>
#include <set>

using namespace librats::dht;
using librats::Address;

namespace {

// Rooting the table at the all-zero id makes bucket math easy to reason about:
// bucket_index(0, id) is just the position of id's most-significant set bit.
const NodeId kZeroSelf{};

// Build a distinct id that lands in `bucket`: set the bit at that position (the
// most-significant set bit → fixes the bucket) and vary lower bytes with `salt`.
NodeId id_in_bucket(int bucket, uint8_t salt) {
    NodeId id{};
    const int byte = bucket / 8;
    const int bit  = bucket % 8;
    id[byte] = static_cast<uint8_t>(1u << (7 - bit));
    if (byte + 1 < static_cast<int>(kIdSize)) id[byte + 1] = salt;  // lower bits, same bucket
    return id;
}

// Build an id that lands in a given sub-prefix "spread slot" of the top bucket while
// keeping bit 0 clear (so the bucket never splits). The slot is the top 3 bits; with
// bit 0 fixed at 0 the reachable slots are 0..3, encoded in bits 1 and 2.
NodeId id_in_slot(uint8_t slot, uint8_t salt) {
    NodeId id{};
    id[0]  = static_cast<uint8_t>((((slot >> 1) & 1) << 6) | ((slot & 1) << 5));
    id[19] = salt;  // vary the tail so ids stay distinct within a slot
    return id;
}

Address ep(uint8_t salt) { return Address("10.0.0." + std::to_string(salt), 6881); }

bool contains_id(const std::vector<NodeEntry>& v, const NodeId& id) {
    for (const auto& n : v) if (n.id == id) return true;
    return false;
}

} // namespace

TEST(DhtRoutingTable, EmptyTable) {
    RoutingTable rt(kZeroSelf);
    EXPECT_EQ(rt.size(), 0u);
    EXPECT_TRUE(rt.empty());
    EXPECT_TRUE(rt.find_closest(id_in_bucket(40, 1)).empty());
    EXPECT_FALSE(rt.next_to_refresh(std::chrono::steady_clock::now()).has_value());
}

TEST(DhtRoutingTable, NodeSeenAddsConfirmedContact) {
    RoutingTable rt(kZeroSelf);
    const NodeId id = id_in_bucket(40, 1);
    EXPECT_TRUE(rt.node_seen(id, ep(1), 30));
    EXPECT_EQ(rt.size(), 1u);

    auto closest = rt.find_closest(id);
    ASSERT_EQ(closest.size(), 1u);
    EXPECT_EQ(closest[0].id, id);
    EXPECT_TRUE(closest[0].confirmed());
    EXPECT_EQ(closest[0].rtt, 30);
}

TEST(DhtRoutingTable, HeardAboutIsUnconfirmed) {
    RoutingTable rt(kZeroSelf);
    const NodeId id = id_in_bucket(40, 2);
    rt.heard_about(id, ep(2));

    EXPECT_EQ(rt.size(), 1u);                              // occupies a live slot
    EXPECT_TRUE(rt.find_closest(id).empty());             // but not returned to queriers
    EXPECT_EQ(rt.find_closest(id, kBucketSize, true).size(), 1u);  // visible when seeding lookups
}

TEST(DhtRoutingTable, SelfIsNeverStored) {
    RoutingTable rt(kZeroSelf);
    EXPECT_FALSE(rt.node_seen(kZeroSelf, ep(0), 10));
    rt.heard_about(kZeroSelf, ep(0));
    EXPECT_EQ(rt.size(), 0u);
}

TEST(DhtRoutingTable, FindClosestOrdersByDistance) {
    RoutingTable rt(kZeroSelf);
    const NodeId a = id_in_bucket(10, 1);
    const NodeId b = id_in_bucket(60, 1);
    const NodeId c = id_in_bucket(120, 1);
    rt.node_seen(a, ep(1)); rt.node_seen(b, ep(2)); rt.node_seen(c, ep(3));

    // Querying for exactly one node's id must return it first (distance 0).
    EXPECT_EQ(rt.find_closest(b)[0].id, b);
    EXPECT_EQ(rt.find_closest(c)[0].id, c);

    auto all = rt.find_closest(a, 2);
    EXPECT_EQ(all.size(), 2u);  // honours the count cap
}

// The count cap must return the *globally* closest contacts, not just any subset
// of the right size — this is what find_closest exists to do, and what a wrong
// partial_sort/resize would silently break.
TEST(DhtRoutingTable, FindClosestReturnsGloballyNearest) {
    RoutingTable rt(kZeroSelf);
    // Rooted at id 0, distance-to-target(0) is just the id value, so a higher
    // bucket index means a smaller value means closer. Insert across five buckets.
    const NodeId far    = id_in_bucket(10, 1);
    const NodeId mid_lo = id_in_bucket(40, 1);
    const NodeId mid    = id_in_bucket(70, 1);
    const NodeId mid_hi = id_in_bucket(100, 1);
    const NodeId near   = id_in_bucket(130, 1);
    for (const auto& id : {far, mid_lo, mid, mid_hi, near})
        rt.node_seen(id, ep(1), 20);

    auto top3 = rt.find_closest(kZeroSelf, 3);
    ASSERT_EQ(top3.size(), 3u);
    EXPECT_EQ(top3[0].id, near);     // closest first
    EXPECT_EQ(top3[1].id, mid_hi);
    EXPECT_EQ(top3[2].id, mid);
    EXPECT_FALSE(contains_id(top3, mid_lo));  // the two farthest are excluded,
    EXPECT_FALSE(contains_id(top3, far));     // not merely truncated arbitrarily
}

// Beyond result[0], the whole vector must be ordered closest-first under the XOR
// metric — for a target that matches none of the stored contacts.
TEST(DhtRoutingTable, FindClosestIsFullyOrdered) {
    RoutingTable rt(kZeroSelf);
    for (int b = 5; b < 160; b += 17)            // contacts scattered across buckets
        rt.node_seen(id_in_bucket(b, 7), ep(static_cast<uint8_t>(b)), 20);

    const NodeId target = id_in_bucket(83, 99);  // not equal to any stored contact
    auto closest = rt.find_closest(target, kBucketSize);
    ASSERT_GT(closest.size(), 1u);
    for (std::size_t i = 1; i < closest.size(); ++i)
        EXPECT_FALSE(closer_to(closest[i].id, closest[i - 1].id, target))
            << "result not closest-first at index " << i;
}

// Asking for zero contacts yields nothing even when the table is populated
// (guards the begin()+k / resize boundary).
TEST(DhtRoutingTable, FindClosestZeroCountReturnsEmpty) {
    RoutingTable rt(kZeroSelf);
    rt.node_seen(id_in_bucket(40, 1), ep(1), 20);
    rt.node_seen(id_in_bucket(80, 2), ep(2), 20);
    EXPECT_TRUE(rt.find_closest(id_in_bucket(40, 1), 0).empty());
}

// With include_unconfirmed, confirmed and unpinged contacts are merged into one
// distance-ordered result — confirmation status must not perturb the ordering.
TEST(DhtRoutingTable, FindClosestUnconfirmedAreOrderedWithConfirmed) {
    RoutingTable rt(kZeroSelf);
    const NodeId near_unconf = id_in_bucket(130, 1);  // closest, but only hearsay
    const NodeId mid_conf    = id_in_bucket(70, 1);   // confirmed
    const NodeId far_unconf  = id_in_bucket(10, 1);   // farthest, hearsay
    rt.heard_about(near_unconf, ep(1));
    rt.node_seen(mid_conf, ep(2), 20);
    rt.heard_about(far_unconf, ep(3));

    auto all = rt.find_closest(kZeroSelf, kBucketSize, /*include_unconfirmed=*/true);
    ASSERT_EQ(all.size(), 3u);
    EXPECT_EQ(all[0].id, near_unconf);  // closeness wins regardless of confirmation
    EXPECT_EQ(all[1].id, mid_conf);
    EXPECT_EQ(all[2].id, far_unconf);

    // Default (confirmed-only) view still filters the unpinged ones back out.
    EXPECT_EQ(rt.find_closest(kZeroSelf, kBucketSize).size(), 1u);
}

// Property test: across several different table roots (`self`), find_closest must
// agree with a brute-force sort of the table's actual live set. A fixed-root,
// hand-placed test can't catch bucket-math bugs that only surface for some roots;
// random ids also cluster heavily in the low buckets (the XOR metric puts ~half of
// them in bucket 0), exercising the partial_sort/resize path on lopsided tables.
TEST(DhtRoutingTable, FindClosestMatchesBruteForceAcrossSelves) {
    std::mt19937 rng(0xC0FFEE);  // fixed seed → fully deterministic
    const auto random_id = [&rng] {
        NodeId id{};
        for (auto& byte : id) byte = static_cast<uint8_t>(rng());
        return id;
    };

    for (int trial = 0; trial < 6; ++trial) {
        const NodeId self = random_id();
        RoutingTable rt(self);

        // Insert ~60 distinct confirmed contacts; many collide into the same
        // (low) buckets, so the live set is whatever survived the k-cap.
        std::set<NodeId> inserted;
        while (inserted.size() < 60) {
            const NodeId id = random_id();
            if (id == self || !inserted.insert(id).second) continue;
            rt.node_seen(id, ep(static_cast<uint8_t>(inserted.size())), 20);
        }

        // Ground truth: the real live set, read via an independent code path.
        const std::vector<NodeEntry> live = rt.good_contacts();
        ASSERT_FALSE(live.empty());

        // Query for assorted targets, including self and an exact contact id.
        std::vector<NodeId> targets = {self, live.front().id, random_id(), random_id()};
        for (const NodeId& target : targets) {
            std::vector<NodeEntry> expected = live;
            std::sort(expected.begin(), expected.end(),
                [&](const NodeEntry& a, const NodeEntry& b) { return closer_to(a.id, b.id, target); });

            for (std::size_t k : {std::size_t{1}, kBucketSize, live.size()}) {
                auto got = rt.find_closest(target, k);
                const std::size_t want = std::min(k, live.size());
                ASSERT_EQ(got.size(), want) << "trial " << trial << " k=" << k;
                // Distinct ids ⇒ distinct XOR distances ⇒ one unambiguous order.
                for (std::size_t i = 0; i < want; ++i)
                    EXPECT_EQ(got[i].id, expected[i].id)
                        << "trial " << trial << " k=" << k << " pos " << i;
            }
        }
    }
}

// Buckets are uniform k-sized when the extended table is off, so a single bucket
// caps its live set at k (the extended table is exercised separately).
TEST(DhtRoutingTable, BucketCapsLiveAtK) {
    RoutingTable rt(kZeroSelf, /*extended=*/false);
    for (uint8_t i = 0; i < 12; ++i)               // 12 confirmed into one bucket
        rt.node_seen(id_in_bucket(50, i), ep(i), 20);

    EXPECT_EQ(rt.size(), kBucketSize);             // live set capped at k=8
    EXPECT_EQ(rt.find_closest(id_in_bucket(50, 0), 32).size(), kBucketSize);
}

TEST(DhtRoutingTable, ConfirmedDisplacesUnpinged) {
    RoutingTable rt(kZeroSelf, /*extended=*/false);
    for (uint8_t i = 0; i < kBucketSize; ++i)      // fill the bucket with hearsay
        rt.heard_about(id_in_bucket(50, i), ep(i));
    EXPECT_EQ(rt.find_closest(id_in_bucket(50, 0)).size(), 0u);  // none confirmed yet

    const NodeId fresh = id_in_bucket(50, 200);
    EXPECT_TRUE(rt.node_seen(fresh, ep(200), 15));  // displaces an unpinged contact
    EXPECT_EQ(rt.size(), kBucketSize);              // still full, not grown

    auto confirmed = rt.find_closest(fresh, kBucketSize);
    ASSERT_EQ(confirmed.size(), 1u);
    EXPECT_EQ(confirmed[0].id, fresh);
}

// In a full sub-prefix slot, a strictly better (lower-RTT) confirmed node displaces
// the slot's worst contact, while a worse one is only parked as a standby.
TEST(DhtRoutingTable, BetterConfirmedDisplacesWorseInFullSlot) {
    RoutingTable rt(kZeroSelf, /*extended=*/false);
    for (uint8_t i = 0; i < kBucketSize; ++i)      // bucket full, all one slot, rtt 20
        rt.node_seen(id_in_bucket(50, i), ep(i), 20);

    const NodeId better = id_in_bucket(50, 200);
    EXPECT_TRUE(rt.node_seen(better, ep(200), 5));  // lower RTT -> displaces the worst
    EXPECT_EQ(rt.size(), kBucketSize);
    EXPECT_TRUE(contains_id(rt.find_closest(better, kBucketSize), better));

    const NodeId worse = id_in_bucket(50, 201);
    EXPECT_FALSE(rt.node_seen(worse, ep(201), 80)); // higher RTT -> parked, not live
    EXPECT_EQ(rt.size(), kBucketSize);
    EXPECT_FALSE(contains_id(rt.find_closest(worse, kBucketSize), worse));
}

// A contact alone in its spread slot is never evicted by a newcomer landing in a
// different slot — that's what the prefix-spread rule protects.
TEST(DhtRoutingTable, HealthyNodeSurvivesNewcomerInAnotherSlot) {
    RoutingTable rt(kZeroSelf, /*extended=*/false);
    const NodeId lone = id_in_slot(3, 7);          // sole occupant of slot 3
    rt.node_seen(lone, ep(1), 20);
    for (uint8_t i = 0; i < kBucketSize - 1; ++i)  // pack the rest into slot 0
        rt.node_seen(id_in_slot(0, static_cast<uint8_t>(i + 1)),  // salt > 0: never the all-zero self
                     ep(static_cast<uint8_t>(100 + i)), 20);
    ASSERT_EQ(rt.size(), kBucketSize);

    // A better newcomer mapping to slot 0 must take from slot 0, never from slot 3.
    EXPECT_TRUE(rt.node_seen(id_in_slot(0, 200), ep(200), 1));
    EXPECT_EQ(rt.size(), kBucketSize);
    EXPECT_TRUE(contains_id(rt.find_closest(lone, kBucketSize), lone));
}

TEST(DhtRoutingTable, NodeFailedPromotesStandby) {
    RoutingTable rt(kZeroSelf, /*extended=*/false);
    for (uint8_t i = 0; i < kBucketSize; ++i)
        rt.node_seen(id_in_bucket(50, i), ep(i), 20);
    const NodeId standby = id_in_bucket(50, 200);
    rt.node_seen(standby, ep(200), 20);            // equal RTT -> waits in the cache
    EXPECT_FALSE(contains_id(rt.find_closest(standby, kBucketSize), standby));

    const NodeId victim = id_in_bucket(50, 0);
    rt.node_failed(victim, ep(0));                 // its liveness check failed

    EXPECT_EQ(rt.size(), kBucketSize);             // size held by the promotion
    auto live = rt.find_closest(id_in_bucket(50, 1), kBucketSize);
    EXPECT_TRUE(contains_id(live, standby));       // standby moved into the live set
    EXPECT_FALSE(contains_id(live, victim));       // failed contact gone
}

// With several standbys waiting, node_failed must promote the *best* one (lowest
// RTT / fewest failures), not just any of them.
TEST(DhtRoutingTable, NodeFailedPromotesBestStandby) {
    RoutingTable rt(kZeroSelf, /*extended=*/false);
    for (uint8_t i = 0; i < kBucketSize; ++i)      // bucket full of fast (rtt 5) contacts
        rt.node_seen(id_in_bucket(50, i), ep(i), 5);

    // Two confirmed contacts, both slower than the live set -> both parked as standbys.
    const NodeId good_standby = id_in_bucket(50, 200);
    const NodeId bad_standby  = id_in_bucket(50, 201);
    EXPECT_FALSE(rt.node_seen(good_standby, ep(200), 20));
    EXPECT_FALSE(rt.node_seen(bad_standby,  ep(201), 80));

    rt.node_failed(id_in_bucket(50, 0), ep(0));    // a live contact's liveness check failed

    EXPECT_EQ(rt.size(), kBucketSize);
    auto live = rt.find_closest(id_in_bucket(50, 1), kBucketSize);
    EXPECT_TRUE(contains_id(live, good_standby));   // the lower-RTT standby was promoted
    EXPECT_FALSE(contains_id(live, bad_standby));    // the worse one still waits
}

// The extended table keeps more than k contacts in the dense top buckets, where a
// flat table would cap at k.
TEST(DhtRoutingTable, ExtendedTableHoldsMoreThanKNearTheTop) {
    RoutingTable extended(kZeroSelf, /*extended=*/true);
    RoutingTable flat(kZeroSelf, /*extended=*/false);
    for (uint8_t i = 0; i < 20; ++i) {             // all land in the top bucket, no split
        const NodeId id = id_in_bucket(50, i);     // bit 50 set -> bit 0 clear for all
        extended.node_seen(id, ep(i), 20);
        flat.node_seen(id, ep(i), 20);
    }
    EXPECT_EQ(extended.size(), 20u);               // extended top bucket keeps them all
    EXPECT_EQ(extended.bucket_count(), 1);         // one bucket, just larger
    EXPECT_EQ(flat.size(), kBucketSize);           // flat buckets cap at k
}

// Confirmed contacts spread across both sides of the high bits deepen the table.
TEST(DhtRoutingTable, SplitsWhenBucketFillsAndSeparable) {
    RoutingTable rt(kZeroSelf, /*extended=*/false);  // small buckets split quickly
    std::mt19937 rng(0x5EED);
    std::set<NodeId> ids;
    while (ids.size() < 40) {
        NodeId id{};
        for (auto& byte : id) byte = static_cast<uint8_t>(rng());
        if (id == kZeroSelf || !ids.insert(id).second) continue;
        rt.node_seen(id, ep(static_cast<uint8_t>(ids.size())), 20);
    }
    EXPECT_GT(rt.bucket_count(), 1);               // the table deepened
    EXPECT_GT(rt.size(), kBucketSize);             // and holds more than one bucket's worth
}

// A standby parked while its bucket was full is never pinged (next_to_refresh only
// scans live), so when a split frees live slots the standbys must be pulled up.
TEST(DhtRoutingTable, SplitPromotesStandbysIntoFreedSlots) {
    RoutingTable rt(kZeroSelf, /*extended=*/false);

    // bit 0 set -> stays in the shallow bucket on a split; clear -> moves deeper.
    const auto make = [](bool high_bit, uint8_t salt) {
        NodeId id{};
        if (high_bit) id[0] = 0x80;
        id[18] = 1;        // keep it distinct from the all-zero self
        id[19] = salt;     // distinct tail per node
        return id;
    };

    // Fill one bucket with 8 confirmed contacts straddling bit 0 (4 on each side).
    for (uint8_t i = 0; i < 4; ++i) {
        rt.node_seen(make(false, static_cast<uint8_t>(1 + i)), ep(i), 20);
        rt.node_seen(make(true,  static_cast<uint8_t>(1 + i)), ep(static_cast<uint8_t>(50 + i)), 20);
    }
    ASSERT_EQ(rt.bucket_count(), 1);
    ASSERT_EQ(rt.size(), 8u);

    // Park two standbys (heard-about) while the bucket is full — one on each side.
    const NodeId standby_lo = make(false, 100);
    const NodeId standby_hi = make(true, 100);
    rt.heard_about(standby_lo, ep(100));
    rt.heard_about(standby_hi, ep(101));
    ASSERT_EQ(rt.size(), 8u);                       // still parked, not live

    // A confirmed contact straddling the full bucket triggers a split, which frees
    // live slots in both halves — the parked standbys should fill them.
    rt.node_seen(make(true, 200), ep(200), 20);
    ASSERT_GT(rt.bucket_count(), 1);

    const auto all_live = rt.find_closest(kZeroSelf, 64, /*include_unconfirmed=*/true);
    EXPECT_TRUE(contains_id(all_live, standby_lo));  // promoted into the deeper half
    EXPECT_TRUE(contains_id(all_live, standby_hi));  // promoted into the shallow half
}

// The efficient (bucket-local) find_closest must still agree exactly with a
// brute-force sort once the table has split into many buckets.
TEST(DhtRoutingTable, FindClosestExactAcrossSplitTable) {
    std::mt19937 rng(0xABCDEF);
    const auto random_id = [&rng] {
        NodeId id{};
        for (auto& byte : id) byte = static_cast<uint8_t>(rng());
        return id;
    };

    for (int trial = 0; trial < 4; ++trial) {
        const NodeId self = random_id();
        RoutingTable rt(self, /*extended=*/false);  // small buckets -> many splits

        std::set<NodeId> inserted;
        while (inserted.size() < 150) {
            const NodeId id = random_id();
            if (id == self || !inserted.insert(id).second) continue;
            rt.node_seen(id, ep(static_cast<uint8_t>(inserted.size())), 20);
        }
        ASSERT_GT(rt.bucket_count(), 1) << "expected the table to split";

        const std::vector<NodeEntry> live = rt.good_contacts();
        ASSERT_FALSE(live.empty());

        std::vector<NodeId> targets = {self, live.front().id, random_id(), random_id()};
        for (const NodeId& target : targets) {
            std::vector<NodeEntry> expected = live;
            std::sort(expected.begin(), expected.end(),
                [&](const NodeEntry& a, const NodeEntry& b) { return closer_to(a.id, b.id, target); });

            for (std::size_t k : {std::size_t{1}, kBucketSize, live.size()}) {
                auto got = rt.find_closest(target, k);
                const std::size_t want = std::min(k, live.size());
                ASSERT_EQ(got.size(), want) << "trial " << trial << " k=" << k;
                for (std::size_t i = 0; i < want; ++i)
                    EXPECT_EQ(got[i].id, expected[i].id)
                        << "trial " << trial << " k=" << k << " pos " << i;
            }
        }
    }
}

TEST(DhtRoutingTable, NodeFailedWithoutStandbyDropsAfterMaxFailures) {
    RoutingTable rt(kZeroSelf);
    const NodeId id = id_in_bucket(50, 1);
    rt.node_seen(id, ep(1), 20);

    // No standby: it survives early failures, then is dropped once exhausted.
    for (int i = 0; i < RoutingTable::kMaxFailCount - 1; ++i) {
        rt.node_failed(id, ep(1));
        EXPECT_EQ(rt.size(), 1u) << "still kept after " << (i + 1) << " failures";
    }
    rt.node_failed(id, ep(1));
    EXPECT_EQ(rt.size(), 0u);
}

// A timeout reported for a different endpoint than the one we have stored for this id
// is a different node claiming the same id; it must not penalise (or evict) our contact.
TEST(DhtRoutingTable, NodeFailedIgnoresEndpointMismatch) {
    RoutingTable rt(kZeroSelf);
    const NodeId id = id_in_bucket(50, 1);
    rt.node_seen(id, ep(1), 20);

    // Many failures, but all from the wrong endpoint -> our contact is untouched.
    for (int i = 0; i < RoutingTable::kMaxFailCount + 3; ++i)
        rt.node_failed(id, ep(99));
    EXPECT_EQ(rt.size(), 1u);

    // Once the endpoint matches, the normal exhaustion path applies and it is dropped.
    for (int i = 0; i < RoutingTable::kMaxFailCount; ++i)
        rt.node_failed(id, ep(1));
    EXPECT_EQ(rt.size(), 0u);
}

TEST(DhtRoutingTable, NextToRefreshPrefersUnpinged) {
    RoutingTable rt(kZeroSelf);
    rt.node_seen(id_in_bucket(30, 1), ep(1), 20);   // confirmed, fresh
    const NodeId unpinged = id_in_bucket(70, 2);
    rt.heard_about(unpinged, ep(2));                 // never pinged

    auto next = rt.next_to_refresh(std::chrono::steady_clock::now());
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(next->id, unpinged);                   // unpinged needs the first probe
}

// Picking a contact for refresh stamps it as touched, so the next refresh rotates to a
// different contact rather than re-probing the same one while its probe is outstanding.
TEST(DhtRoutingTable, NextToRefreshRotates) {
    RoutingTable rt(kZeroSelf, /*extended=*/false);
    rt.node_seen(id_in_bucket(30, 1), ep(1), 20);
    rt.node_seen(id_in_bucket(40, 2), ep(2), 20);

    const auto t1 = std::chrono::steady_clock::now();
    auto first = rt.next_to_refresh(t1);
    ASSERT_TRUE(first.has_value());

    auto second = rt.next_to_refresh(t1 + std::chrono::seconds(1));
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->id, second->id);                // rotated to the other contact
}

TEST(DhtRoutingTable, SetSelfRebucketsAndKeepsContacts) {
    RoutingTable rt(kZeroSelf);
    std::vector<NodeId> ids;
    for (uint8_t i = 0; i < 5; ++i) {
        const NodeId id = id_in_bucket(20 + i * 20, i);
        ids.push_back(id);
        rt.node_seen(id, ep(i), 20);
    }
    EXPECT_EQ(rt.size(), 5u);

    NodeId new_self{};
    new_self.fill(0xAB);
    rt.set_self(new_self);

    EXPECT_EQ(rt.self(), new_self);
    EXPECT_EQ(rt.size(), 5u);                        // all contacts retained
    for (const auto& id : ids)
        EXPECT_EQ(rt.find_closest(id)[0].id, id);    // still findable after re-bucketing
}

TEST(DhtRoutingTable, GoodContactsRoundTrip) {
    RoutingTable rt(kZeroSelf);
    rt.node_seen(id_in_bucket(15, 1), ep(1), 20);
    rt.node_seen(id_in_bucket(95, 2), ep(2), 40);
    rt.heard_about(id_in_bucket(60, 3), ep(3));      // unconfirmed → not saved

    auto saved = rt.good_contacts();
    EXPECT_EQ(saved.size(), 2u);

    RoutingTable restored(kZeroSelf);
    restored.load_contacts(saved);
    EXPECT_EQ(restored.size(), 2u);
    EXPECT_EQ(restored.find_closest(id_in_bucket(15, 1))[0].id, id_in_bucket(15, 1));
}
