#include <gtest/gtest.h>
#include "core/chained_send_buffer.h"

#include <algorithm>
#include <cstring>
#include <numeric>
#include <random>
#include <vector>

using namespace librats;

namespace {

/// Roomy enough that the helpers below always see the whole queue.
constexpr size_t kSlices = 1024;

/// No byte budget: these helpers want the whole queue, not the flush loop's one round.
constexpr size_t kNoByteLimit = SIZE_MAX;

/// Everything still queued, flattened — what the peer would receive if we sent it all.
std::vector<uint8_t> pending(const ChainedSendBuffer& buf) {
    ByteView slices[kSlices];
    const size_t count = buf.gather(slices, kSlices, kNoByteLimit);

    std::vector<uint8_t> out;
    for (size_t i = 0; i < count; ++i) out.insert(out.end(), slices[i].begin(), slices[i].end());
    return out;
}

/// Simulate a send() that accepts `accepted` bytes, and return what went out.
std::vector<uint8_t> send_some(ChainedSendBuffer& buf, size_t accepted) {
    ByteView slices[kSlices];
    const size_t count = buf.gather(slices, kSlices, kNoByteLimit);

    std::vector<uint8_t> sent;
    for (size_t i = 0; i < count && sent.size() < accepted; ++i) {
        const size_t take = (std::min)(slices[i].size(), accepted - sent.size());
        sent.insert(sent.end(), slices[i].begin(), slices[i].begin() + std::ptrdiff_t(take));
    }
    buf.pop_front(sent.size());
    return sent;
}

Bytes iota_bytes(size_t n, uint8_t start = 0) {
    Bytes v(n);
    std::iota(v.begin(), v.end(), start);
    return v;
}

ByteView view_of(const Bytes& b) { return ByteView(b); }

} // namespace

// ── Basics ──────────────────────────────────────────────────────────────────

TEST(ChainedSendBufferTest, StartsEmpty) {
    ChainedSendBuffer buf;
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(buf.allocated(), 0u);
    EXPECT_EQ(buf.chunk_count(), 0u);
    EXPECT_TRUE(buf.front().empty());
}

TEST(ChainedSendBufferTest, AppendedBytesComeBackInOrder) {
    ChainedSendBuffer buf;
    buf.append(Bytes{1, 2, 3});
    buf.append(Bytes{4, 5});

    EXPECT_EQ(buf.size(), 5u);
    EXPECT_FALSE(buf.empty());
    EXPECT_EQ(pending(buf), (std::vector<uint8_t>{1, 2, 3, 4, 5}));
}

TEST(ChainedSendBufferTest, AppendTakesOwnershipWithoutCopying) {
    ChainedSendBuffer buf;
    Bytes payload = iota_bytes(4096);
    const uint8_t* original = payload.data();

    buf.append(std::move(payload));

    // The queued bytes are the caller's original allocation, not a copy of it.
    EXPECT_EQ(buf.front().data(), original);
}

TEST(ChainedSendBufferTest, EmptyAppendsAreIgnored) {
    ChainedSendBuffer buf;
    buf.append(Bytes{});
    buf.append(ByteView{});

    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.chunk_count(), 0u);
}

// ── Coalescing: small messages must not cost a chunk each ───────────────────

TEST(ChainedSendBufferTest, SmallCopiesPackIntoOneChunk) {
    ChainedSendBuffer buf;
    std::vector<uint8_t> expected;

    for (int i = 0; i < 50; ++i) {  // 50 tiny protocol messages
        const Bytes msg = iota_bytes(5, uint8_t(i));
        buf.append(view_of(msg));
        expected.insert(expected.end(), msg.begin(), msg.end());
    }

    EXPECT_EQ(buf.size(), 250u);
    EXPECT_EQ(buf.chunk_count(), 1u);  // one allocation for all 50, not 50
    EXPECT_EQ(pending(buf), expected);
}

TEST(ChainedSendBufferTest, ALargeCopyGetsItsOwnExactlySizedChunk) {
    ChainedSendBuffer buf;
    const Bytes big = iota_bytes(16 * 1024);
    buf.append(view_of(big));

    EXPECT_EQ(buf.chunk_count(), 1u);
    // Sized to the payload: a piece-sized buffer is not padded with scratch space.
    EXPECT_LT(buf.allocated(), big.size() + ChainedSendBuffer::kScratchCapacity);
    EXPECT_EQ(pending(buf), std::vector<uint8_t>(big.begin(), big.end()));
}

TEST(ChainedSendBufferTest, CoalescingNeverInvalidatesGatheredSlices) {
    ChainedSendBuffer buf;
    buf.append(ByteView(reinterpret_cast<const uint8_t*>("head"), 4));

    ByteView slices[kSlices];
    ASSERT_EQ(buf.gather(slices, kSlices), 1u);
    const uint8_t* before = slices[0].data();

    buf.append(ByteView(reinterpret_cast<const uint8_t*>("tail"), 4));  // coalesces

    // The slice handed out earlier still points at the same live bytes: appending
    // into spare capacity must never reallocate the chunk under an in-flight send.
    EXPECT_EQ(slices[0].data(), before);
    EXPECT_EQ(std::memcmp(before, "head", 4), 0);
}

// ── Gather I/O ──────────────────────────────────────────────────────────────

TEST(ChainedSendBufferTest, GatherExposesEveryChunkInOrder) {
    ChainedSendBuffer buf;
    buf.append(iota_bytes(3, 0));
    buf.append(iota_bytes(4, 10));
    buf.append(iota_bytes(5, 20));

    ByteView slices[kSlices];
    ASSERT_EQ(buf.gather(slices, kSlices), 3u);
    EXPECT_EQ(slices[0].size(), 3u);
    EXPECT_EQ(slices[1].size(), 4u);
    EXPECT_EQ(slices[2].size(), 5u);
    EXPECT_EQ(slices[1].data()[0], 10u);
}

TEST(ChainedSendBufferTest, GatherRespectsTheSliceLimit) {
    ChainedSendBuffer buf;
    for (int i = 0; i < 10; ++i) buf.append(iota_bytes(8, uint8_t(i)));

    ByteView slices[4];
    EXPECT_EQ(buf.gather(slices, 4), 4u);  // the rest goes out on the next round
}

TEST(ChainedSendBufferTest, GatherStopsOnceItCoversTheByteBudget) {
    ChainedSendBuffer buf;
    for (int i = 0; i < 10; ++i) buf.append(iota_bytes(8, uint8_t(i)));

    // 20 bytes of budget is covered by three 8-byte chunks; the fourth would be an
    // iovec entry the kernel copies in and ignores, so it waits for the next round.
    ByteView slices[kSlices];
    EXPECT_EQ(buf.gather(slices, kSlices, 20), 3u);
    EXPECT_EQ(buf.gather(slices, kSlices, 16), 2u);   // exactly covered: no extra slice
    EXPECT_EQ(buf.gather(slices, kSlices, 1), 1u);

    // Nothing is lost — the queue still holds it all, and an unbudgeted gather sees it.
    EXPECT_EQ(buf.size(), 80u);
    EXPECT_EQ(buf.gather(slices, kSlices, kNoByteLimit), 10u);
}

TEST(ChainedSendBufferTest, GatherAlwaysDescribesAtLeastOneSlice) {
    ChainedSendBuffer buf;
    buf.append(iota_bytes(64));

    // A chunk bigger than the budget must still be sendable, or the queue would stall.
    ByteView slices[kSlices];
    ASSERT_EQ(buf.gather(slices, kSlices, 8), 1u);
    EXPECT_EQ(slices[0].size(), 64u);
}

TEST(ChainedSendBufferTest, GatherSkipsTheAlreadySentPrefix) {
    ChainedSendBuffer buf;
    buf.append(iota_bytes(10));
    buf.pop_front(6);

    ByteView slices[kSlices];
    ASSERT_EQ(buf.gather(slices, kSlices), 1u);
    EXPECT_EQ(slices[0].size(), 4u);
    EXPECT_EQ(slices[0].data()[0], 6u);
}

TEST(ChainedSendBufferTest, FrontIsTheFirstSlice) {
    ChainedSendBuffer buf;
    buf.append(iota_bytes(4));
    buf.append(iota_bytes(4, 100));

    EXPECT_EQ(buf.front().size(), 4u);
    EXPECT_EQ(buf.front().data()[0], 0u);
}

// ── pop_front() ─────────────────────────────────────────────────────────────

TEST(ChainedSendBufferTest, PartialSendAdvancesWithinTheChunk) {
    ChainedSendBuffer buf;
    buf.append(iota_bytes(10));

    buf.pop_front(4);

    EXPECT_EQ(buf.size(), 6u);
    EXPECT_EQ(buf.chunk_count(), 1u);  // the chunk stays, only its cursor moved
    EXPECT_EQ(pending(buf), iota_bytes(6, 4));
}

TEST(ChainedSendBufferTest, SendSpanningChunksDropsTheDrainedOnes) {
    ChainedSendBuffer buf;
    buf.append(Bytes{1, 2, 3});
    buf.append(Bytes{4, 5, 6});
    buf.append(Bytes{7, 8, 9});

    buf.pop_front(7);  // all of the first two chunks and one byte of the third

    EXPECT_EQ(buf.size(), 2u);
    EXPECT_EQ(buf.chunk_count(), 1u);
    EXPECT_EQ(pending(buf), (std::vector<uint8_t>{8, 9}));
}

TEST(ChainedSendBufferTest, DrainingEverythingEmptiesTheQueue) {
    ChainedSendBuffer buf;
    buf.append(iota_bytes(100));
    buf.append(iota_bytes(100));

    buf.pop_front(200);

    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(buf.chunk_count(), 0u);
    EXPECT_TRUE(buf.front().empty());
}

TEST(ChainedSendBufferTest, PopNothingIsANoOp) {
    ChainedSendBuffer buf;
    buf.append(Bytes{1, 2, 3});
    buf.pop_front(0);
    EXPECT_EQ(pending(buf), (std::vector<uint8_t>{1, 2, 3}));
}

// ── Memory accounting ───────────────────────────────────────────────────────

TEST(ChainedSendBufferTest, AllocatedCountsHeldMemoryNotJustPendingBytes) {
    ChainedSendBuffer buf;
    buf.append(iota_bytes(8192));
    ASSERT_GE(buf.allocated(), 8192u);

    buf.pop_front(8000);

    // size() is what still has to go out; allocated() is what we are actually
    // holding — the partially sent chunk keeps its whole allocation.
    EXPECT_EQ(buf.size(), 192u);
    EXPECT_GE(buf.allocated(), 8192u);
}

TEST(ChainedSendBufferTest, SmallChunksAreRecycledSoASteadyDripStopsAllocating) {
    ChainedSendBuffer buf;

    // Prime the recycler: queue a small message and send it all.
    buf.append(ByteView(reinterpret_cast<const uint8_t*>("ping"), 4));
    buf.pop_front(4);
    const size_t held = buf.allocated();
    ASSERT_GT(held, 0u);  // the drained chunk was kept for re-use

    // A steady drip of small messages must now reuse it instead of allocating.
    for (int i = 0; i < 100; ++i) {
        buf.append(ByteView(reinterpret_cast<const uint8_t*>("ping"), 4));
        EXPECT_EQ(buf.allocated(), held);
        buf.pop_front(4);
    }
}

TEST(ChainedSendBufferTest, ABacklogOfSmallMessagesDoesNotBlowUpMemory) {
    ChainedSendBuffer buf;

    // A congested socket: 10k small framed messages pile up with nothing going out.
    // Packing keeps the memory held close to the bytes queued — a chunk per message
    // would cost orders of magnitude more.
    for (int i = 0; i < 10000; ++i) {
        const Bytes header = iota_bytes(4, uint8_t(i));
        const Bytes body   = iota_bytes(20, uint8_t(i));
        buf.append(view_of(header));
        buf.append(view_of(body));
    }

    EXPECT_EQ(buf.size(), 10000u * 24u);
    EXPECT_LT(buf.allocated(), buf.size() * 2);
}

TEST(ChainedSendBufferTest, LargeChunksAreNotRecycled) {
    ChainedSendBuffer buf;
    buf.append(iota_bytes(64 * 1024));
    buf.pop_front(64 * 1024);

    // A piece-sized buffer is released, not squatted on.
    EXPECT_LE(buf.allocated(), ChainedSendBuffer::kMaxRecycledCapacity);
}

TEST(ChainedSendBufferTest, ClearReleasesEverything) {
    ChainedSendBuffer buf;
    buf.append(iota_bytes(4096));
    buf.append(Bytes{1, 2, 3});

    buf.clear();

    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(buf.allocated(), 0u);
    EXPECT_EQ(buf.chunk_count(), 0u);
}

TEST(ChainedSendBufferTest, IsMovable) {
    ChainedSendBuffer buf;
    buf.append(Bytes{1, 2, 3});

    ChainedSendBuffer moved = std::move(buf);
    EXPECT_EQ(moved.size(), 3u);
    EXPECT_EQ(pending(moved), (std::vector<uint8_t>{1, 2, 3}));
}

TEST(ChainedSendBufferTest, MovingLeavesTheSourceEmptyAndUsable) {
    ChainedSendBuffer buf;
    buf.append(Bytes{1, 2, 3});

    ChainedSendBuffer moved = std::move(buf);

    // The chunks went with the move, so the source must not still claim their bytes:
    // a queue reporting size() > 0 with nothing to gather is a flush() that never
    // finishes — it can neither send anything nor ever become empty.
    EXPECT_TRUE(buf.empty());          // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(buf.allocated(), 0u);
    EXPECT_EQ(buf.chunk_count(), 0u);
    EXPECT_TRUE(buf.front().empty());

    // And it still works as an empty queue afterwards.
    buf.append(Bytes{4, 5});
    EXPECT_EQ(pending(buf), (std::vector<uint8_t>{4, 5}));
}

// ── The real send loop ──────────────────────────────────────────────────────

TEST(ChainedSendBufferTest, SurvivesADribblingSocket) {
    ChainedSendBuffer buf;
    std::vector<uint8_t> expected;

    // A framed message: a small header chunk plus a payload chunk, as the wire path
    // queues them (prefix by copy, body by move).
    for (int i = 0; i < 20; ++i) {
        const Bytes header = iota_bytes(4, uint8_t(i));
        Bytes body = iota_bytes(500, uint8_t(i));
        expected.insert(expected.end(), header.begin(), header.end());
        expected.insert(expected.end(), body.begin(), body.end());

        buf.append(view_of(header));
        buf.append(std::move(body));
    }
    ASSERT_EQ(buf.size(), 20u * 504u);

    // The socket accepts 7 bytes at a time. Everything must arrive, in order, once.
    std::vector<uint8_t> received;
    while (!buf.empty()) {
        const auto chunk = send_some(buf, 7);
        ASSERT_FALSE(chunk.empty());
        received.insert(received.end(), chunk.begin(), chunk.end());
    }

    EXPECT_EQ(received, expected);
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(buf.chunk_count(), 0u);
}

TEST(ChainedSendBufferTest, MatchesAReferenceStreamUnderRandomTraffic) {
    std::mt19937 rng(7);
    ChainedSendBuffer buf;
    std::vector<uint8_t> queued;  // the same bytes, kept the naive way
    std::vector<uint8_t> sent;
    uint8_t next = 0;

    for (int round = 0; round < 3000; ++round) {
        // Queue a message, by move or by copy.
        const size_t len = std::uniform_int_distribution<size_t>(0, 3000)(rng);
        Bytes msg(len);
        for (auto& b : msg) b = next++;
        queued.insert(queued.end(), msg.begin(), msg.end());

        if (rng() % 2) buf.append(view_of(msg));
        else           buf.append(std::move(msg));

        ASSERT_EQ(buf.size(), queued.size()) << "round " << round;

        // The socket takes an arbitrary slice of it.
        const size_t accepted = std::uniform_int_distribution<size_t>(0, buf.size())(rng);
        const auto out = send_some(buf, accepted);
        sent.insert(sent.end(), out.begin(), out.end());
        queued.erase(queued.begin(), queued.begin() + std::ptrdiff_t(out.size()));

        ASSERT_EQ(buf.size(), queued.size()) << "round " << round;
        ASSERT_EQ(pending(buf), queued) << "round " << round;
        ASSERT_GE(buf.allocated(), buf.size()) << "round " << round;
    }

    // Drain the rest and check the whole stream came out intact, in order.
    while (!buf.empty()) {
        const auto out = send_some(buf, buf.size());
        sent.insert(sent.end(), out.begin(), out.end());
    }
    std::vector<uint8_t> whole_stream(sent.size());
    std::iota(whole_stream.begin(), whole_stream.end(), uint8_t(0));  // wraps, like `next` did
    EXPECT_EQ(sent, whole_stream);
}
