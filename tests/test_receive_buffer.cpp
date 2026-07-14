#include <gtest/gtest.h>
#include "core/receive_buffer.h"

#include <algorithm>
#include <numeric>
#include <random>
#include <vector>

using namespace librats;

namespace {

/// Simulate a recv() of `bytes` bytes, filling them with `fill`.
void feed(ReceiveBuffer& buf, size_t bytes, uint8_t fill = 0xAB) {
    const ByteSpan into = buf.prepare(bytes);
    ASSERT_GE(into.size(), bytes);
    std::fill_n(into.data(), bytes, fill);
    buf.commit(bytes);
}

/// Simulate a recv() that delivers exactly `data`.
void feed(ReceiveBuffer& buf, const std::vector<uint8_t>& data) {
    const ByteSpan into = buf.prepare(data.size());
    ASSERT_GE(into.size(), data.size());
    std::copy(data.begin(), data.end(), into.data());
    buf.commit(data.size());
}

std::vector<uint8_t> live(const ReceiveBuffer& buf) {
    return std::vector<uint8_t>(buf.data(), buf.data() + buf.size());
}

std::vector<uint8_t> iota_bytes(size_t n, uint8_t start = 0) {
    std::vector<uint8_t> v(n);
    std::iota(v.begin(), v.end(), start);
    return v;
}

} // namespace

// ── Construction ────────────────────────────────────────────────────────────

TEST(ReceiveBufferTest, DefaultConstructionAllocatesNothing) {
    ReceiveBuffer buf;
    EXPECT_EQ(buf.capacity(), 0u);
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_TRUE(buf.empty());
}

TEST(ReceiveBufferTest, InitialCapacityIsHonoured) {
    ReceiveBuffer buf(1000);
    EXPECT_GE(buf.capacity(), 1000u);
    EXPECT_TRUE(buf.empty());
}

// ── Write / read basics ─────────────────────────────────────────────────────

TEST(ReceiveBufferTest, PrepareGivesAtLeastWhatWasAsked) {
    ReceiveBuffer buf;
    EXPECT_GE(buf.prepare(4096).size(), 4096u);
    EXPECT_GE(buf.capacity(), 4096u);
}

TEST(ReceiveBufferTest, CommittedBytesBecomeReadable) {
    ReceiveBuffer buf(64);
    feed(buf, iota_bytes(5, 1));

    ASSERT_EQ(buf.size(), 5u);
    EXPECT_FALSE(buf.empty());
    EXPECT_EQ(live(buf), iota_bytes(5, 1));
    EXPECT_EQ(buf.view().size(), 5u);
}

TEST(ReceiveBufferTest, ReadsAccumulateInOrder) {
    ReceiveBuffer buf(8);
    feed(buf, std::vector<uint8_t>{1, 2, 3});
    feed(buf, std::vector<uint8_t>{4, 5});
    feed(buf, std::vector<uint8_t>{6});

    EXPECT_EQ(live(buf), (std::vector<uint8_t>{1, 2, 3, 4, 5, 6}));
}

// ── consume() ───────────────────────────────────────────────────────────────

TEST(ReceiveBufferTest, ConsumeMovesNoMemory) {
    ReceiveBuffer buf(1024);
    feed(buf, iota_bytes(10));

    const uint8_t* base = buf.data();
    buf.consume(4);

    // The whole point of the class: the live data did not move, only the cursor did.
    EXPECT_EQ(buf.data(), base + 4);
    EXPECT_EQ(buf.size(), 6u);
    EXPECT_EQ(buf.front_waste(), 4u);
    EXPECT_EQ(live(buf), iota_bytes(6, 4));
}

TEST(ReceiveBufferTest, DrainingRewindsTheCursors) {
    ReceiveBuffer buf(1024);
    feed(buf, 10);
    buf.consume(6);
    ASSERT_EQ(buf.front_waste(), 6u);

    buf.consume(4);  // now empty

    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(buf.front_waste(), 0u);  // rewound for free — no memmove needed
}

TEST(ReceiveBufferTest, ConsumeNothingIsANoOp) {
    ReceiveBuffer buf(64);
    feed(buf, iota_bytes(3));
    buf.consume(0);
    EXPECT_EQ(live(buf), iota_bytes(3));
}

// ── compact() ───────────────────────────────────────────────────────────────

TEST(ReceiveBufferTest, CompactReclaimsTheConsumedPrefix) {
    ReceiveBuffer buf(1024);
    feed(buf, iota_bytes(100));
    buf.consume(60);

    const size_t capacity_before = buf.capacity();
    buf.compact();

    EXPECT_EQ(buf.front_waste(), 0u);
    EXPECT_EQ(buf.size(), 40u);
    EXPECT_EQ(buf.capacity(), capacity_before);  // compaction never reallocates
    EXPECT_EQ(live(buf), iota_bytes(40, 60));    // and never corrupts the live bytes
}

TEST(ReceiveBufferTest, CompactOnANormalisedBufferIsANoOp) {
    ReceiveBuffer buf(64);
    feed(buf, iota_bytes(8));

    const uint8_t* base = buf.data();
    buf.compact();

    EXPECT_EQ(buf.data(), base);
    EXPECT_EQ(live(buf), iota_bytes(8));
}

TEST(ReceiveBufferTest, PrepareCompactsBeforeItGrows) {
    ReceiveBuffer buf(1024);
    feed(buf, 1000);
    buf.consume(990);  // 10 live bytes, 990 wasted at the front

    const size_t capacity_before = buf.capacity();
    buf.prepare(500);  // fits only if the front waste is reclaimed

    EXPECT_EQ(buf.capacity(), capacity_before);  // reclaimed, not reallocated
    EXPECT_EQ(buf.front_waste(), 0u);
    EXPECT_EQ(buf.size(), 10u);
}

// ── Growth ──────────────────────────────────────────────────────────────────

TEST(ReceiveBufferTest, GrowsWhenCompactionCannotHelp) {
    ReceiveBuffer buf(256);
    const auto payload = iota_bytes(200);
    feed(buf, payload);  // nothing consumed, so there is nothing to reclaim

    buf.prepare(4096);

    EXPECT_GE(buf.capacity(), 200u + 4096u);
    EXPECT_EQ(live(buf), payload);  // live data survives the move
}

TEST(ReceiveBufferTest, GrowthIsGeometricNotOneStepPerRead) {
    ReceiveBuffer buf;
    size_t reallocations = 0;
    size_t last_capacity = 0;

    // Stream 1 MiB in 16 KiB reads without consuming: the worst case for growth.
    for (int i = 0; i < 64; ++i) {
        feed(buf, 16 * 1024);
        if (buf.capacity() != last_capacity) {
            ++reallocations;
            last_capacity = buf.capacity();
        }
    }

    EXPECT_EQ(buf.size(), 1024u * 1024u);
    // 1.5x growth: a handful of steps, nowhere near one per read.
    EXPECT_LT(reallocations, 20u);
}

// The contract the connections rely on to avoid that growth climb entirely: once the
// length prefix tells them how big the message is, they ask prepare() for the rest of
// it, and the whole message then arrives into a single allocation.
TEST(ReceiveBufferTest, SizingForAWholeMessageCostsOneAllocation) {
    constexpr size_t kMessage = 1 << 20;
    constexpr size_t kRead    = 16 * 1024;

    ReceiveBuffer buf;
    size_t reallocations = 0;
    size_t last_capacity = 0;

    // Same 1 MiB in the same 16 KiB reads as GrowthIsGeometricNotOneStepPerRead, but
    // each prepare() asks for what the message still needs rather than the read size.
    while (buf.size() < kMessage) {
        const size_t missing = kMessage - buf.size();
        const ByteSpan into  = buf.prepare(missing);
        ASSERT_GE(into.size(), missing);

        const size_t n = (std::min)(kRead, into.size());
        std::fill_n(into.data(), n, uint8_t{0xAB});
        buf.commit(n);

        if (buf.capacity() != last_capacity) {
            ++reallocations;
            last_capacity = buf.capacity();
        }
    }

    EXPECT_EQ(buf.size(), kMessage);
    EXPECT_EQ(reallocations, 1u);
}

TEST(ReceiveBufferTest, AMessageLargerThanTheGrowthStepStillFits) {
    ReceiveBuffer buf(256);
    buf.prepare(1 << 20);
    EXPECT_GE(buf.capacity(), size_t{1} << 20);
}

// ── Shrinking ───────────────────────────────────────────────────────────────

TEST(ReceiveBufferTest, ShrinksBackAfterAnOversizedMessage) {
    ReceiveBuffer buf;

    // One 1 MiB message pins a 1 MiB allocation...
    feed(buf, 1 << 20);
    buf.consume(buf.size());
    const size_t peak_capacity = buf.capacity();
    ASSERT_GE(peak_capacity, size_t{1} << 20);

    // ...and a steady stream of small ones must get it back.
    for (int i = 0; i < 200; ++i) {
        feed(buf, 100);
        buf.consume(100);
    }

    EXPECT_LT(buf.capacity(), peak_capacity / 8);
    EXPECT_GE(buf.capacity(), ReceiveBuffer::kMinCapacity);
}

// ── Idle decay ──────────────────────────────────────────────────────────────

TEST(ReceiveBufferTest, IdleDecayReclaimsAfterOneBigMessageAndSilence) {
    // The case the traffic-driven shrink cannot reach: one large message, then the
    // peer goes quiet. consume() only ever samples when a message *arrives*, so with
    // no follow-up traffic the watermark never falls and the allocation is pinned for
    // the life of the connection. The idle tick is what hands it back.
    ReceiveBuffer buf;
    feed(buf, 1 << 20);
    buf.consume(buf.size());
    const size_t peak_capacity = buf.capacity();
    ASSERT_GE(peak_capacity, size_t{1} << 20);

    // No traffic at all — only ticks. The first is swallowed by the just-saw-traffic
    // guard, so this is ~2 ticks per halving from 1 MiB.
    for (int tick = 0; tick < 40; ++tick) buf.decay();

    EXPECT_EQ(buf.capacity(), ReceiveBuffer::kMinCapacity);
}

TEST(ReceiveBufferTest, IdleDecayLeavesABusyBufferAlone) {
    // A tick that lands on a connection which received something must not shrink it:
    // it is sized for a reason, and shrinking would only make the next prepare() grow
    // it straight back.
    constexpr size_t kRecvChunk = 64 * 1024;

    ReceiveBuffer buf;
    buf.prepare(kRecvChunk);
    buf.commit(100);
    buf.consume(100);
    const size_t settled = buf.capacity();
    ASSERT_GE(settled, kRecvChunk);

    for (int tick = 0; tick < 200; ++tick) {
        buf.prepare(kRecvChunk);       // traffic in this tick window…
        buf.commit(100);
        buf.consume(100);
        buf.decay();                   // …so the tick must be a no-op
        ASSERT_EQ(buf.capacity(), settled) << "decayed a busy buffer on tick " << tick;
    }
}

TEST(ReceiveBufferTest, IdleDecayKeepsAPartialMessageIntact) {
    // A tick may land while a message is still in flight. Ageing may reclaim the unused
    // tail (see IdleDecayReclaimsAStalledPartialMessage), but the live bytes themselves
    // are never dropped or moved out from under the parser: they keep their content and
    // enough storage to hold them.
    ReceiveBuffer buf;
    const auto payload = iota_bytes(200);
    feed(buf, payload);

    for (int tick = 0; tick < 40; ++tick) buf.decay();

    EXPECT_EQ(buf.size(), payload.size());
    EXPECT_EQ(live(buf), payload);
    EXPECT_GE(buf.capacity(), payload.size());
}

TEST(ReceiveBufferTest, IdleDecayReclaimsAStalledPartialMessage) {
    // The pinning case an empty-only shrink misses: the read path grows rx_ eagerly for
    // a large declared block, only the first slice arrives, then the peer stalls. The
    // buffer stays non-empty forever, so a decay() that bailed on !empty() could never
    // hand the allocation back. It must now shrink toward the live bytes — while keeping
    // them intact — since decay() is the only thing that visits an idle connection.
    ReceiveBuffer buf;

    buf.prepare(1 << 20);                 // eager reserve for a ~1 MiB block…
    const auto arrived = iota_bytes(16 * 1024);
    const ByteSpan into = buf.prepare(arrived.size());
    std::copy(arrived.begin(), arrived.end(), into.data());
    buf.commit(arrived.size());           // …of which only 16 KiB ever shows up

    const size_t pinned = buf.capacity();
    ASSERT_GE(pinned, size_t{1} << 20);

    // No traffic — only idle ticks. The buffer never drains (the block is incomplete),
    // yet the allocation must still come down to what actually arrived.
    for (int tick = 0; tick < 40; ++tick) buf.decay();

    EXPECT_LT(buf.capacity(), pinned / 8) << "stalled partial message pinned the buffer";
    EXPECT_GE(buf.capacity(), arrived.size());  // but never below the live bytes,
    EXPECT_EQ(buf.size(), arrived.size());      // which are all still there…
    EXPECT_EQ(live(buf), arrived);              // …and unchanged
}

TEST(ReceiveBufferTest, IdleDecayDoesNotThrashAMostlyFullBuffer) {
    // The flip side of shrinking a partial message: once the live bytes fill most of the
    // allocation there is little tail left to hand back, and giving it back costs a
    // memcpy of everything we must keep — which the very next byte undoes by growing the
    // buffer straight back. A stalled peer trickling one byte every few ticks would
    // otherwise have us memcpy its half-arrived block up and down for free.
    ReceiveBuffer buf;
    feed(buf, 64 * 1024);   // a big block, none of it parseable yet
    feed(buf, 1);           // the single grow this test allows (the buffer was exactly full)

    const size_t settled = buf.capacity();
    ASSERT_GT(settled, 64 * 1024u);

    for (int cycle = 0; cycle < 20; ++cycle) {
        for (int tick = 0; tick < 3; ++tick) buf.decay();
        ASSERT_EQ(buf.capacity(), settled) << "idle ticks shrank a mostly-full buffer";
        feed(buf, 1);       // …and the stalled peer dribbles another byte
        ASSERT_EQ(buf.capacity(), settled) << "…which grew it back: cycle " << cycle;
    }
    EXPECT_EQ(buf.size(), 64 * 1024u + 1 + 20);
}

TEST(ReceiveBufferTest, IdleDecayOnAnUnallocatedBufferIsANoOp) {
    ReceiveBuffer buf;
    for (int tick = 0; tick < 10; ++tick) buf.decay();
    EXPECT_EQ(buf.capacity(), 0u);
    EXPECT_TRUE(buf.empty());
}

TEST(ReceiveBufferTest, ShrinkingNeverDropsBelowTheFloor) {
    ReceiveBuffer buf(ReceiveBuffer::kMinCapacity);
    for (int i = 0; i < 100; ++i) {
        feed(buf, 1);
        buf.consume(1);
    }
    EXPECT_EQ(buf.capacity(), ReceiveBuffer::kMinCapacity);
}

TEST(ReceiveBufferTest, SteadyLoadDoesNotFlapTheAllocation) {
    ReceiveBuffer buf;
    feed(buf, 32 * 1024);
    buf.consume(buf.size());
    const size_t settled = buf.capacity();

    // Same demand, message after message: the buffer must hold its size instead of
    // shrinking and re-growing — each cycle would otherwise cost two allocations.
    for (int i = 0; i < 100; ++i) {
        feed(buf, 32 * 1024);
        buf.consume(buf.size());
        ASSERT_EQ(buf.capacity(), settled) << "flapped on cycle " << i;
    }
}

TEST(ReceiveBufferTest, SmallMessagesReadWithABigChunkDoNotFlapTheAllocation) {
    // How the buffer is really driven: every read offers a *fixed* chunk (16 KiB in
    // Connection, 64 KiB in the BitTorrent peer) no matter how small the message that
    // turns up. If the shrink logic only ever looks at the bytes that arrived, the
    // average sinks below the read size, the buffer shrinks — and the very next
    // prepare() has to grow it straight back, forever.
    constexpr size_t kRecvChunk = 64 * 1024;

    ReceiveBuffer buf;
    buf.prepare(kRecvChunk);
    buf.commit(100);
    buf.consume(100);
    const size_t settled = buf.capacity();
    ASSERT_GE(settled, kRecvChunk);

    for (int i = 0; i < 200; ++i) {
        buf.prepare(kRecvChunk);
        buf.commit(100);
        buf.consume(100);
        ASSERT_EQ(buf.capacity(), settled) << "flapped on message " << i;
    }
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

TEST(ReceiveBufferTest, ClearKeepsTheAllocation) {
    ReceiveBuffer buf(4096);
    feed(buf, 100);
    buf.consume(10);

    buf.clear();

    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.front_waste(), 0u);
    EXPECT_GE(buf.capacity(), 4096u);  // ready for re-use, no re-allocation
}

TEST(ReceiveBufferTest, ResetReleasesTheAllocation) {
    ReceiveBuffer buf(4096);
    feed(buf, 100);

    buf.reset();

    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.capacity(), 0u);

    feed(buf, iota_bytes(5));  // and it still works afterwards
    EXPECT_EQ(live(buf), iota_bytes(5));
}

TEST(ReceiveBufferTest, IsMovable) {
    ReceiveBuffer buf(1024);
    feed(buf, iota_bytes(16));

    ReceiveBuffer moved = std::move(buf);
    EXPECT_EQ(live(moved), iota_bytes(16));
}

TEST(ReceiveBufferTest, MovingLeavesTheSourceEmptyAndUsable) {
    ReceiveBuffer buf(1024);
    feed(buf, iota_bytes(16));

    ReceiveBuffer moved = std::move(buf);

    // The allocation went with the data. The source must not still claim the cursors
    // and capacity it no longer owns — prepare() would hand out a span into nullptr.
    EXPECT_TRUE(buf.empty());          // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(buf.capacity(), 0u);
    EXPECT_EQ(buf.front_waste(), 0u);

    // And it is a perfectly good empty buffer again, not a landmine.
    feed(buf, iota_bytes(8));
    EXPECT_EQ(live(buf), iota_bytes(8));
}

// ── Property test: it must behave exactly like the byte stream it models ─────

TEST(ReceiveBufferTest, MatchesAReferenceStreamUnderRandomTraffic) {
    std::mt19937 rng(1234);
    ReceiveBuffer buf;
    std::vector<uint8_t> reference;  // the same stream, kept the naive way
    uint8_t next = 0;

    for (int round = 0; round < 3000; ++round) {
        // A random-sized read arrives.
        const size_t incoming = std::uniform_int_distribution<size_t>(0, 5000)(rng);
        const ByteSpan into = buf.prepare(incoming ? incoming : 1);
        ASSERT_GE(into.size(), incoming);
        for (size_t i = 0; i < incoming; ++i) {
            into.data()[i] = next;
            reference.push_back(next);
            ++next;
        }
        buf.commit(incoming);

        // A random prefix of it gets parsed.
        const size_t parsed = std::uniform_int_distribution<size_t>(0, buf.size())(rng);
        buf.consume(parsed);
        reference.erase(reference.begin(), reference.begin() + std::ptrdiff_t(parsed));

        // Compaction must be invisible to the data.
        if (round % 7 == 0) buf.compact();

        ASSERT_EQ(buf.size(), reference.size()) << "round " << round;
        ASSERT_EQ(live(buf), reference) << "round " << round;
        ASSERT_LE(buf.size() + buf.front_waste(), buf.capacity()) << "round " << round;
    }
}
