#include <gtest/gtest.h>

#include "wire/frame.h"

#include <string>

using namespace librats;

namespace {
std::string view_str(ByteView v) {
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}
} // namespace

// ── Outer block ─────────────────────────────────────────────────────────────

TEST(FrameTest, BlockRoundTrip) {
    Bytes wire;
    const std::string body = "opaque block body";
    framer::encode_block(wire, ByteView(body));

    auto b = framer::try_take_block(wire.data(), wire.size());
    ASSERT_EQ(b.status, framer::Block::Ok);
    EXPECT_EQ(b.consumed, wire.size());
    EXPECT_EQ(view_str(b.body), body);
}

TEST(FrameTest, EmptyBlock) {
    Bytes wire;
    framer::encode_block(wire, ByteView());
    auto b = framer::try_take_block(wire.data(), wire.size());
    ASSERT_EQ(b.status, framer::Block::Ok);
    EXPECT_TRUE(b.body.empty());
}

TEST(FrameTest, BlockIncompletePrefixAndBody) {
    Bytes two = {0x00, 0x00};
    EXPECT_EQ(framer::try_take_block(two.data(), two.size()).status, framer::Block::Incomplete);

    Bytes wire;
    framer::encode_block(wire, ByteView(std::string("abcdef")));
    wire.pop_back();
    EXPECT_EQ(framer::try_take_block(wire.data(), wire.size()).status, framer::Block::Incomplete);
}

TEST(FrameTest, BlockRejectsOversize) {
    Bytes wire = {0xFF, 0xFF, 0xFF, 0xFF};  // len far over kMaxBlockSize
    EXPECT_EQ(framer::try_take_block(wire.data(), wire.size()).status, framer::Block::Error);
}

// An incomplete block reports the size it is waiting for as soon as the length prefix
// is in — that is what lets the receive path allocate for the whole block at once
// instead of growing into it 1.5x at a time.
TEST(FrameTest, IncompleteBlockReportsTheSizeItNeeds) {
    Bytes wire;
    framer::encode_block(wire, ByteView(std::string(5000, 'x')));
    const size_t total = wire.size();  // 4 + 5000

    // Prefix not fully in yet: nothing to report.
    for (size_t have = 0; have < framer::kLengthPrefixSize; ++have) {
        const auto block = framer::try_take_block(wire.data(), have);
        EXPECT_EQ(block.status, framer::Block::Incomplete);
        EXPECT_EQ(block.needed, 0u) << "at " << have << " byte(s)";
    }

    // Prefix in, body still arriving: the full wire size is known throughout.
    for (size_t have = framer::kLengthPrefixSize; have < total; ++have) {
        const auto block = framer::try_take_block(wire.data(), have);
        EXPECT_EQ(block.status, framer::Block::Incomplete);
        EXPECT_EQ(block.needed, total) << "at " << have << " byte(s)";
    }

    const auto done = framer::try_take_block(wire.data(), total);
    EXPECT_EQ(done.status, framer::Block::Ok);
    EXPECT_EQ(done.needed, total);
    EXPECT_EQ(done.consumed, total);
}

TEST(FrameTest, BackToBackBlocks) {
    Bytes wire;
    framer::encode_block(wire, ByteView(std::string("one")));
    framer::encode_block(wire, ByteView(std::string("two")));

    auto a = framer::try_take_block(wire.data(), wire.size());
    ASSERT_EQ(a.status, framer::Block::Ok);
    EXPECT_EQ(view_str(a.body), "one");

    auto b = framer::try_take_block(wire.data() + a.consumed, wire.size() - a.consumed);
    ASSERT_EQ(b.status, framer::Block::Ok);
    EXPECT_EQ(view_str(b.body), "two");
    EXPECT_EQ(a.consumed + b.consumed, wire.size());
}

// ── Inner message ───────────────────────────────────────────────────────────

TEST(FrameTest, MessageRoundTrip) {
    Bytes inner;
    const std::string payload = "hello message";
    framer::encode_message(inner, FrameHeader{MessageType::App, 0x07, 0xBEEF}, ByteView(payload));

    auto m = framer::parse_message(ByteView(inner));
    ASSERT_TRUE(m.ok);
    EXPECT_EQ(m.frame.header.type, MessageType::App);
    EXPECT_EQ(m.frame.header.flags, 0x07);
    EXPECT_EQ(m.frame.header.channel, 0xBEEF);
    EXPECT_EQ(view_str(m.frame.payload), payload);
}

TEST(FrameTest, MessageEmptyPayload) {
    Bytes inner;
    framer::encode_message(inner, FrameHeader{MessageType::Control, 0, 0}, ByteView());
    auto m = framer::parse_message(ByteView(inner));
    ASSERT_TRUE(m.ok);
    EXPECT_EQ(m.frame.header.type, MessageType::Control);
    EXPECT_TRUE(m.frame.payload.empty());
}

TEST(FrameTest, MessageRejectsShortHeader) {
    Bytes inner = {0x01, 0x02};  // fewer than the 4 header bytes
    EXPECT_FALSE(framer::parse_message(ByteView(inner)).ok);
}

TEST(FrameTest, BlockCarriesEncodedMessage) {
    // The real composition: an inner message wrapped in an outer block.
    Bytes inner;
    framer::encode_message(inner, FrameHeader{MessageType::App, 0, 42}, ByteView(std::string("payload")));
    Bytes wire;
    framer::encode_block(wire, ByteView(inner));

    auto b = framer::try_take_block(wire.data(), wire.size());
    ASSERT_EQ(b.status, framer::Block::Ok);
    auto m = framer::parse_message(b.body);
    ASSERT_TRUE(m.ok);
    EXPECT_EQ(m.frame.header.channel, 42);
    EXPECT_EQ(view_str(m.frame.payload), "payload");
}
