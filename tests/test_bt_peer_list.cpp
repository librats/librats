#include <gtest/gtest.h>

#include "bittorrent/peer_list.h"

#include <algorithm>

using namespace librats::bittorrent;

namespace {
bool has(const std::vector<PeerList::Endpoint>& v, const std::string& ip, std::uint16_t port) {
    return std::any_of(v.begin(), v.end(),
                       [&](const PeerList::Endpoint& e) { return e.ip == ip && e.port == port; });
}
} // namespace

TEST(BtPeerList, AddDeduplicates) {
    PeerList pl;
    EXPECT_TRUE(pl.add("1.2.3.4", 5, PeerSource::Tracker));
    EXPECT_FALSE(pl.add("1.2.3.4", 5, PeerSource::Pex));  // same endpoint, just adds a source
    EXPECT_EQ(pl.size(), 1u);
    EXPECT_TRUE(pl.contains("1.2.3.4", 5));
}

TEST(BtPeerList, RejectsInvalid) {
    PeerList pl;
    EXPECT_FALSE(pl.add("", 5, PeerSource::Tracker));
    EXPECT_FALSE(pl.add("1.2.3.4", 0, PeerSource::Tracker));
    EXPECT_EQ(pl.size(), 0u);
}

TEST(BtPeerList, ConnectCandidatesMarkConnecting) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    pl.add("2.2.2.2", 2, PeerSource::Dht);

    auto first = pl.connect_candidates(10);
    EXPECT_EQ(first.size(), 2u);
    // Already handed out (connecting) → not returned again.
    EXPECT_TRUE(pl.connect_candidates(10).empty());
    EXPECT_EQ(pl.num_candidates(), 0u);
}

TEST(BtPeerList, RespectsMaxAndFreesOnFailure) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    pl.add("2.2.2.2", 2, PeerSource::Tracker);

    auto one = pl.connect_candidates(1);
    EXPECT_EQ(one.size(), 1u);          // capped
    EXPECT_EQ(pl.num_candidates(), 1u); // the other is still eligible

    pl.on_connect_failed(one[0].ip, one[0].port);  // frees it, increments fail count
    EXPECT_EQ(pl.num_candidates(), 2u);
}

TEST(BtPeerList, DropsAfterTooManyFailures) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    for (std::uint32_t i = 0; i < PeerList::kMaxFails; ++i) {
        auto c = pl.connect_candidates(1);
        if (!c.empty()) pl.on_connect_failed(c[0].ip, c[0].port);
    }
    EXPECT_EQ(pl.num_candidates(), 0u);  // exhausted its chances
}

TEST(BtPeerList, ConnectedClearsFailures) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    auto c = pl.connect_candidates(1);
    pl.on_connect_failed(c[0].ip, c[0].port);
    pl.set_connected("1.1.1.1", 1, true);
    EXPECT_EQ(pl.num_candidates(), 0u);  // connected, not a candidate
    pl.set_connected("1.1.1.1", 1, false);
    EXPECT_EQ(pl.num_candidates(), 1u);  // and its failure penalty was reset
}

TEST(BtPeerList, BanRemovesFromCandidates) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    pl.ban("1.1.1.1", 1);
    EXPECT_EQ(pl.num_candidates(), 0u);
    EXPECT_TRUE(pl.connect_candidates(10).empty());
}

TEST(BtPeerList, LowerFailureCountRanksFirst) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    pl.add("2.2.2.2", 2, PeerSource::Tracker);
    // Fail .1 once and release it; .2 should now rank ahead.
    auto c = pl.connect_candidates(2);
    auto fail_ep = c[0];
    pl.on_connect_failed(fail_ep.ip, fail_ep.port);
    pl.set_connected(c[1].ip, c[1].port, false);  // release the other too

    auto next = pl.connect_candidates(1);
    ASSERT_EQ(next.size(), 1u);
    EXPECT_FALSE(has(next, fail_ep.ip, fail_ep.port));  // the failed one is not first
}
