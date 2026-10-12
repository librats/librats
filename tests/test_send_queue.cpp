#include <gtest/gtest.h>

#include "librats/security/plaintext_security.h"
#include "librats/transport/send_queue.h"
#include "librats/wire/frame.h"

#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

using namespace librats;

namespace {

struct Sent {
    FrameHeader header;
    std::string payload;
};

/// Everything `out` holds, as one run of bytes.
Bytes drain(ChainedSendBuffer& out) {
    Bytes wire;
    while (!out.empty()) {
        const ByteView front = out.front();
        wire.insert(wire.end(), front.begin(), front.end());
        out.pop_front(front.size());
    }
    return wire;
}

/// Parse the plaintext blocks seal_next() produced.
std::vector<Sent> parse(const Bytes& wire) {
    std::vector<Sent> frames;
    size_t at = 0;
    while (at < wire.size()) {
        const auto block = framer::try_take_block(wire.data() + at, wire.size() - at);
        EXPECT_EQ(block.status, framer::Block::Ok);
        if (block.status != framer::Block::Ok) break;
        const auto msg = framer::parse_message(block.body);
        EXPECT_TRUE(msg.ok);
        frames.push_back({msg.frame.header,
                          std::string(msg.frame.payload.begin(), msg.frame.payload.end())});
        at += block.consumed;
    }
    return frames;
}

/// Seal everything queued, in scheduling order.
std::vector<Sent> seal_all(SendQueue& q, const Session& session) {
    ChainedSendBuffer out;
    uint64_t nonce = 0;
    while (!q.empty()) q.seal_next(session, nonce++, out);
    return parse(drain(out));
}

FrameHeader lane(MessageType type, uint16_t channel = 0) { return FrameHeader{type, 0, channel}; }

const PlaintextSession kPlain{PeerId{}};

} // namespace

TEST(SendQueueTest, OneLaneLeavesInTheOrderItWasQueued) {
    SendQueue q;
    for (int i = 0; i < 100; ++i) {
        // Both sizes, so packed and own-chunk messages interleave in one lane.
        const size_t size = (i % 7 == 0) ? 5000 : 10 + static_cast<size_t>(i);
        q.push(lane(MessageType::App, 3), ByteView(std::string(size, static_cast<char>('a' + i % 26))));
    }
    EXPECT_EQ(q.count(), 100u);

    const auto frames = seal_all(q, kPlain);
    ASSERT_EQ(frames.size(), 100u);
    for (int i = 0; i < 100; ++i) {
        const size_t size = (i % 7 == 0) ? 5000 : 10 + static_cast<size_t>(i);
        EXPECT_EQ(frames[i].payload, std::string(size, static_cast<char>('a' + i % 26))) << i;
        EXPECT_EQ(frames[i].header.channel, 3);
    }
    EXPECT_EQ(q.size(), 0u);
}

TEST(SendQueueTest, AMoreUrgentLaneGoesFirstWhateverWasQueuedBeforeIt) {
    SendQueue q;
    for (int i = 0; i < 5; ++i) q.push(lane(MessageType::FileChunk), ByteView(std::string(2000, 'f')));
    for (int i = 0; i < 5; ++i) q.push(lane(MessageType::App), ByteView(std::string("app")));
    q.push(lane(MessageType::Ping), ByteView(std::string("ping")));
    q.push(lane(MessageType::Control), ByteView(std::string("identify")));

    const auto frames = seal_all(q, kPlain);
    ASSERT_EQ(frames.size(), 12u);
    EXPECT_EQ(frames[0].header.type, MessageType::Control);
    EXPECT_EQ(frames[1].header.type, MessageType::Ping);
    for (int i = 2; i < 7; ++i)  EXPECT_EQ(frames[i].header.type, MessageType::App) << i;
    for (int i = 7; i < 12; ++i) EXPECT_EQ(frames[i].header.type, MessageType::FileChunk) << i;
}

// Lanes of one priority take turns, so a subsystem with a deep backlog cannot
// hold up another one queued behind it.
TEST(SendQueueTest, LanesOfOnePriorityTakeTurns) {
    SendQueue q;
    for (int i = 0; i < 6; ++i) q.push(lane(MessageType::App), ByteView("a" + std::to_string(i)));
    for (int i = 0; i < 3; ++i) q.push(lane(MessageType::Gossip), ByteView("g" + std::to_string(i)));
    q.push(lane(MessageType::Typed), ByteView(std::string("t")));

    std::vector<std::string> order;
    for (const auto& f : seal_all(q, kPlain)) order.push_back(f.payload);
    const std::vector<std::string> expected = {"a0", "g0", "t", "a1", "g1",
                                               "a2", "g2", "a3", "a4", "a5"};
    EXPECT_EQ(order, expected);
}

// An application's channels are one lane: whatever it sends, on whichever
// channels, arrives in the order it was sent. Code that sends a "done" on one
// channel behind data on another relies on exactly that.
TEST(SendQueueTest, AnApplicationsChannelsKeepTheOrderTheyWereSentIn) {
    SendQueue q;
    for (int i = 0; i < 10; ++i)
        q.push(lane(MessageType::App, static_cast<uint16_t>(i % 3)), ByteView(std::to_string(i)));
    q.push(lane(MessageType::Gossip), ByteView(std::string("g")));   // a lane of its own

    std::vector<std::string> app;
    for (const auto& f : seal_all(q, kPlain))
        if (f.header.type == MessageType::App) app.push_back(f.payload);
    const std::vector<std::string> expected = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};
    EXPECT_EQ(app, expected);
}

// Whatever the mix of lanes and sizes, each type's own order survives.
TEST(SendQueueTest, InterleavedPushesAndSealsKeepEveryLaneInOrder) {
    std::mt19937 rng(7);
    const MessageType types[] = {MessageType::App, MessageType::Control, MessageType::Ping,
                                 MessageType::FileChunk, MessageType::Gossip};
    SendQueue q;
    ChainedSendBuffer out;
    uint64_t nonce = 0;
    std::map<uint32_t, uint32_t> pushed;    // lane → messages pushed
    for (int round = 0; round < 2000; ++round) {
        if (rng() % 3 != 0) {
            const FrameHeader h = lane(types[rng() % 5], static_cast<uint16_t>(rng() % 3));
            const uint32_t key = static_cast<uint32_t>(h.type);
            const uint32_t seq = pushed[key]++;
            std::string payload(4, '\0');
            std::memcpy(&payload[0], &seq, 4);
            payload.append(rng() % 4 == 0 ? 1500 + rng() % 3000 : rng() % 200, 'x');
            q.push(h, ByteView(payload));
        } else if (!q.empty()) {
            q.seal_next(kPlain, nonce++, out);
        }
    }
    while (!q.empty()) q.seal_next(kPlain, nonce++, out);

    std::map<uint32_t, uint32_t> next;
    size_t total = 0;
    for (const auto& f : parse(drain(out))) {
        const uint32_t key = static_cast<uint32_t>(f.header.type);
        uint32_t seq = 0;
        std::memcpy(&seq, f.payload.data(), 4);
        EXPECT_EQ(seq, next[key]++) << "lane " << key << " out of order";
        ++total;
    }
    size_t expected = 0;
    for (const auto& [key, n] : pushed) expected += n;
    EXPECT_EQ(total, expected);
}

// Sealing writes the tag into the room push() reserved, so a real AEAD session
// round-trips through the queue — and every block is sealed under the nonce it
// was handed, in the order handed.
TEST(SendQueueTest, SealsEachMessageUnderTheNonceItLeavesWith) {
    struct XorSession final : Session {   // a stand-in AEAD: 4-byte tag, nonce-keyed
        void header_mask(bool, const uint8_t*, uint8_t* mask) const noexcept override { std::memset(mask, 0, 5); }
        size_t overhead() const noexcept override { return 4; }
        void seal(uint64_t nonce, ByteView, uint8_t* d, size_t n) const noexcept override {
            for (size_t i = 0; i < n; ++i) d[i] ^= static_cast<uint8_t>(nonce + 1);
            std::memcpy(d + n, "TAG!", 4);
        }
        std::optional<size_t> open(uint64_t nonce, ByteView, uint8_t* d, size_t n) const noexcept override {
            if (n < 4 || std::memcmp(d + n - 4, "TAG!", 4) != 0) return std::nullopt;
            for (size_t i = 0; i < n - 4; ++i) d[i] ^= static_cast<uint8_t>(nonce + 1);
            return n - 4;
        }
        const PeerId& remote_id() const override { return id; }
        bool is_secure() const override { return true; }
        PeerId id;
    } session;

    SendQueue q;
    q.set_seal_room(session.overhead());
    q.push(lane(MessageType::App), ByteView(std::string("small")));
    q.push(lane(MessageType::App), ByteView(std::string(9000, 'L')));   // a chunk of its own
    q.push(lane(MessageType::App), ByteView(std::string("tail")));

    ChainedSendBuffer out;
    for (uint64_t nonce = 0; !q.empty(); ++nonce) q.seal_next(session, nonce, out);
    Bytes wire = drain(out);

    std::vector<std::string> got;
    size_t at = 0;
    for (uint64_t nonce = 0; at < wire.size(); ++nonce) {
        const auto block = framer::try_take_block(wire.data() + at, wire.size() - at);
        ASSERT_EQ(block.status, framer::Block::Ok);
        uint8_t* body = wire.data() + at + framer::kLengthPrefixSize;
        const auto n = session.open(nonce, {}, body, block.body.size());
        ASSERT_TRUE(n);
        const auto msg = framer::parse_message(ByteView(body, *n));
        ASSERT_TRUE(msg.ok);
        got.emplace_back(msg.frame.payload.begin(), msg.frame.payload.end());
        at += block.consumed;
    }
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(got[0], "small");
    EXPECT_EQ(got[1], std::string(9000, 'L'));
    EXPECT_EQ(got[2], "tail");
}

// A stream of small messages lives in a handful of shared chunks, and an emptied
// queue keeps none of them.
TEST(SendQueueTest, PacksSmallMessagesAndGivesTheMemoryBack) {
    SendQueue q;
    for (int i = 0; i < 1000; ++i) q.push(lane(MessageType::App), ByteView(std::string(100, 'p')));
    const size_t queued = q.size();
    EXPECT_EQ(queued, 1000u * (framer::kHeaderSize + 100));
    EXPECT_LT(q.allocated(), queued + queued / 4 + SendQueue::kPackChunk)
        << "small messages are not sharing chunks";

    seal_all(q, kPlain);
    EXPECT_EQ(q.allocated(), 0u) << "an empty queue still holds memory of its own";
}
