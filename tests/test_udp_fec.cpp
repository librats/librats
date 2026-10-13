// Forward error correction for live messages (udp_fec.h): the code on its own —
// any `columns` symbols of a block give it back, whichever they are — how many
// repair symbols a block is given, the loss rate that is decided from, and the
// LIVE_REPAIR frame that carries a repair symbol.

#include <gtest/gtest.h>

#include "librats/transport/udp_fec.h"
#include "librats/transport/udp_wire.h"

#include <algorithm>
#include <cmath>
#include <random>
#include <vector>

using namespace librats;
using namespace librats::udp;

namespace {

std::vector<uint8_t> random_bytes(size_t n, uint32_t seed) {
    std::mt19937 rng(seed);
    std::vector<uint8_t> v(n);
    for (auto& b : v) b = static_cast<uint8_t>(rng());
    return v;
}

/// Lose `lost` source symbols and all but enough repair symbols of every block,
/// rebuild, and say whether the message came back exactly.
bool round_trip(const fec::Layout& l, uint32_t rows, const std::vector<uint8_t>& message,
                std::mt19937& rng, uint32_t lost_per_block) {
    std::vector<uint8_t> parity(size_t{rows} * l.blocks * l.symbol);
    fec::encode(l, message.data(), rows, parity.data());

    std::vector<uint8_t> data = message;
    std::vector<uint8_t> known(l.count, 1);
    for (uint32_t b = 0; b < l.blocks; ++b) {
        std::vector<uint32_t> cols(l.columns(b));
        for (uint32_t c = 0; c < cols.size(); ++c) cols[c] = c;
        std::shuffle(cols.begin(), cols.end(), rng);
        for (uint32_t i = 0; i < lost_per_block && i < cols.size(); ++i) {
            const uint32_t j = cols[i] * l.blocks + b;
            known[j] = 0;
            std::fill(data.begin() + l.offset(j), data.begin() + l.offset(j) + l.length(j), 0xEE);
        }
        // The repairs that survived: any `lost_per_block` of the block's rows.
        std::vector<uint32_t> rws(rows);
        for (uint32_t r = 0; r < rows; ++r) rws[r] = r;
        std::shuffle(rws.begin(), rws.end(), rng);
        std::vector<fec::Repair> repairs;
        for (uint32_t i = 0; i < lost_per_block; ++i) {
            const uint32_t index = rws[i] * l.blocks + b;
            repairs.push_back(fec::Repair{index, parity.data() + size_t{index} * l.symbol});
        }
        if (!fec::recover(l, b, data.data(), known.data(), repairs.data(), repairs.size())) return false;
    }
    return data == message;
}

} // namespace

// ── The code ────────────────────────────────────────────────────────────────

TEST(FecTest, ALayoutCutsAMessageIntoTheFewestSymbolsAllAlike) {
    const fec::Layout l = fec::Layout::fit(15625, 1167);
    EXPECT_EQ(l.count, 14u);
    EXPECT_EQ(l.symbol, 1117u);   // not 1167 and a last one of 454
    EXPECT_EQ(l.blocks, 1u);
    EXPECT_EQ(l.length(13), 15625u - 13 * 1117);
    const fec::Layout small = fec::Layout::fit(300, 1167);
    EXPECT_EQ(small.count, 1u);
    EXPECT_EQ(small.symbol, 300u) << "a message smaller than a symbol is one, its own size";
    const fec::Layout big = fec::Layout::fit(1 << 20, 1167);
    EXPECT_EQ(big.blocks, (big.count + fec::kMaxColumns - 1) / fec::kMaxColumns);
    uint32_t columns = 0;
    for (uint32_t b = 0; b < big.blocks; ++b) {
        EXPECT_LE(big.columns(b), fec::kMaxColumns);
        columns += big.columns(b);
    }
    EXPECT_EQ(columns, big.count);
}

TEST(FecTest, OneRepairSymbolIsTheXorOfTheMessage) {
    const auto message = random_bytes(5000, 1);
    const fec::Layout l(5000, 1200);   // five symbols, the last 200 bytes and padded
    std::vector<uint8_t> parity(l.symbol);
    fec::encode(l, message.data(), 1, parity.data());
    std::vector<uint8_t> x(l.symbol, 0);
    for (uint32_t j = 0; j < l.count; ++j)
        for (uint32_t i = 0; i < l.length(j); ++i) x[i] ^= message[l.offset(j) + i];
    EXPECT_EQ(parity, x);
}

// The property the whole design rests on: ANY `rows` losses of a block — source
// symbols, with whichever repairs survive — are given back.
TEST(FecTest, AnyLossesUpToTheRepairsAreGivenBack) {
    std::mt19937 rng(7);
    struct Case { uint32_t size, symbol, rows; };
    for (const Case c : {Case{1, 1, 1}, Case{900, 900, 1}, Case{15625, 1117, 2}, Case{78125, 1150, 6},
                         Case{200000, 1000, 3}, Case{300000, 1167, 48}}) {
        const fec::Layout l(c.size, c.symbol);
        const auto message = random_bytes(c.size, c.size);
        for (int trial = 0; trial < 4; ++trial)
            for (const uint32_t lost : {0u, 1u, c.rows / 2, c.rows})
                ASSERT_TRUE(round_trip(l, c.rows, message, rng, (std::min)(lost, l.columns(l.blocks - 1))))
                    << "size " << c.size << " rows " << c.rows << " lost " << lost << " trial " << trial;
    }
}

TEST(FecTest, FewerRepairsThanLossesRebuildNothing) {
    const fec::Layout l(4000, 1000);
    const auto message = random_bytes(4000, 3);
    std::vector<uint8_t> parity(2 * l.symbol);
    fec::encode(l, message.data(), 2, parity.data());
    std::vector<uint8_t> data = message, known = {0, 1, 0, 0};
    const fec::Repair repairs[] = {{0, parity.data()}, {1, parity.data() + l.symbol}};
    EXPECT_FALSE(fec::recover(l, 0, data.data(), known.data(), repairs, 2));
    EXPECT_EQ(data, message) << "rebuilt something from too little";
}

// ── How much ────────────────────────────────────────────────────────────────

TEST(FecTest, RepairsAreTheFewestThatMeetTheTarget) {
    EXPECT_EQ(fec::rows_for(14, 0, 0.01), 0u) << "a path that loses nothing gets none";
    EXPECT_EQ(fec::rows_for(14, 0.0005, 0.1), 0u) << "nor one that loses too little to matter";
    // 14 symbols at 5%: one repair leaves 17% of blocks beyond rebuilding, two
    // 4.3%, three 0.9%, four 0.16%.
    EXPECT_EQ(fec::rows_for(14, 0.05, 0.1), 2u);
    EXPECT_EQ(fec::rows_for(14, 0.05, 0.01), 3u);
    EXPECT_EQ(fec::rows_for(14, 0.05, 0.005), 4u);
    EXPECT_EQ(fec::rows_for(1, 0.05, 0.01), 1u) << "a one-packet message is sent twice";
    EXPECT_EQ(fec::rows_for(2, 0.5, 1e-9), 2u) << "never more repairs than data";
    EXPECT_EQ(fec::rows_for(200, 0.5, 1e-9), fec::kMaxRows);
    uint32_t prev = 0;
    for (double loss = 0.001; loss < 0.3; loss *= 1.5) {
        const uint32_t rows = fec::rows_for(60, loss, 0.01);
        EXPECT_GE(rows, prev) << loss;
        prev = rows;
    }
}

TEST(FecTest, TheLossEstimateFollowsWhatThePathLoses) {
    fec::LossEstimate e;
    uint64_t delivered = 0, lost = 0;
    const auto feed = [&](double share, uint64_t bytes) {
        for (uint64_t sent = 0; sent < bytes; sent += 1200) {
            delivered += 1200;
            if (std::fmod(double(sent / 1200) * share, 1.0) + share >= 1.0) lost += 1200;
            e.update(delivered, lost);
        }
    };
    e.update(1000, 1000);
    EXPECT_EQ(e.rate(), 0) << "a sample is taken only once enough has been resolved";
    feed(0.05, 40 * fec::LossEstimate::kInterval);
    EXPECT_NEAR(e.rate(), 0.05, 0.01);
    feed(0, 40 * fec::LossEstimate::kInterval);
    EXPECT_LT(e.rate(), 0.001) << "a path that stopped losing is believed again";
}

// ── On the wire ─────────────────────────────────────────────────────────────

TEST(FecTest, ARepairFrameRoundTrips) {
    uint8_t buf[kMaxDatagram];
    const auto symbol = random_bytes(1117, 9);
    uint8_t* p = put_live_repair_header(buf, 77, 120, 15625, 1117, 3);
    EXPECT_EQ(static_cast<size_t>(p - buf), live_repair_header_size(77, 120, 15625, 1117, 3));
    std::copy(symbol.begin(), symbol.end(), p);
    p += symbol.size();
    FrameReader r(buf, static_cast<size_t>(p - buf));
    Frame f;
    ASSERT_TRUE(r.next(f));
    ASSERT_EQ(f.type, kLiveRepair);
    EXPECT_EQ(f.repair.id, 77u);
    EXPECT_EQ(f.repair.lifetime, 120u);
    EXPECT_EQ(f.repair.size, 15625u);
    EXPECT_EQ(f.repair.symbol, 1117u);
    EXPECT_EQ(f.repair.index, 3u);
    EXPECT_TRUE(std::equal(symbol.begin(), symbol.end(), f.repair.data.begin()));
    EXPECT_FALSE(r.next(f));
    EXPECT_FALSE(r.error());
}

TEST(FecTest, ARepairFrameThatCannotBelongToAMessageIsMalformed) {
    struct Case { uint64_t size, symbol; size_t have; };
    // Symbol larger than the message, smaller than the floor, the message past
    // the limit, and data cut short.
    for (const Case c : {Case{500, 600, 600}, Case{20000, 100, 100}, Case{kMaxLiveMessage + 1, 1000, 1000},
                         Case{20000, 1000, 999}}) {
        uint8_t buf[2 * kMaxDatagram] = {};
        uint8_t* p = put_live_repair_header(buf, 1, 100, c.size, c.symbol, 0);
        p += c.have;
        FrameReader r(buf, static_cast<size_t>(p - buf));
        Frame f;
        EXPECT_FALSE(r.next(f));
        EXPECT_TRUE(r.error()) << "size " << c.size << " symbol " << c.symbol;
    }
    // A message smaller than the floor is one symbol of its own size.
    uint8_t buf[kMaxDatagram] = {};
    uint8_t* p = put_live_repair_header(buf, 1, 100, 40, 40, 0) + 40;
    FrameReader r(buf, static_cast<size_t>(p - buf));
    Frame f;
    EXPECT_TRUE(r.next(f));
}
