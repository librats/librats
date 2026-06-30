#include <gtest/gtest.h>

#include "bittorrent/choker.h"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace librats::bittorrent;

namespace {
const void* P(std::uintptr_t n) { return reinterpret_cast<const void*>(n); }
bool contains(const std::vector<const void*>& v, const void* p) {
    return std::find(v.begin(), v.end(), p) != v.end();
}
} // namespace

TEST(BtChoker, UnchokesAllWhenUnderSlots) {
    Choker c(4);
    auto sel = c.select({{P(1), 10}, {P(2), 20}});
    EXPECT_EQ(sel.size(), 2u);
    EXPECT_TRUE(contains(sel, P(1)));
    EXPECT_TRUE(contains(sel, P(2)));
}

TEST(BtChoker, PicksTopScoresWhenOverSlots) {
    Choker c(2);
    auto sel = c.select({{P(1), 5}, {P(2), 50}, {P(3), 30}, {P(4), 1}});
    ASSERT_EQ(sel.size(), 2u);
    EXPECT_TRUE(contains(sel, P(2)));  // highest
    EXPECT_TRUE(contains(sel, P(3)));  // second
    EXPECT_FALSE(contains(sel, P(1)));
    EXPECT_FALSE(contains(sel, P(4)));
}

TEST(BtChoker, OptimisticAlwaysIncluded) {
    Choker c(1);
    auto sel = c.select({{P(1), 100}, {P(2), 1}}, /*optimistic=*/P(2));
    EXPECT_TRUE(contains(sel, P(1)));  // top by score
    EXPECT_TRUE(contains(sel, P(2)));  // optimistic, despite low score
}

TEST(BtChoker, OptimisticNotDuplicatedIfAlreadyChosen) {
    Choker c(2);
    auto sel = c.select({{P(1), 100}, {P(2), 50}}, /*optimistic=*/P(1));
    EXPECT_EQ(sel.size(), 2u);
}

TEST(BtChoker, EmptyCandidates) {
    Choker c(4);
    EXPECT_TRUE(c.select({}).empty());
}
