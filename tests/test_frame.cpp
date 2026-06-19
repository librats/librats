#include <gtest/gtest.h>

#include "net/frame.h"

#include <string>

using namespace librats;

namespace {

std::string payload_string(const Frame& f) {
    return std::string(reinterpret_cast<const char*>(f.payload.data()), f.payload.size());
}

} // namespace

TEST(FrameTest, EncodeDecodeRoundTrip) {
    Bytes wire;
    const std::string body = "hello frame";
    framer::encode(wire, FrameHeader{MessageType::App, 0x05, 0x1234}, ByteView(body));

    auto d = framer::try_decode(wire.data(), wire.size());
    ASSERT_EQ(d.status, framer::Decoded::Ok);
    EXPECT_EQ(d.consumed, wire.size());
    EXPECT_EQ(d.frame.header.type, MessageType::App);
    EXPECT_EQ(d.frame.header.flags, 0x05);
    EXPECT_EQ(d.frame.header.channel, 0x1234);
    EXPECT_EQ(payload_string(d.frame), body);
}

TEST(FrameTest, EmptyPayload) {
    Bytes wire;
    framer::encode(wire, FrameHeader{MessageType::Control, 0, 0}, ByteView());

    auto d = framer::try_decode(wire.data(), wire.size());
    ASSERT_EQ(d.status, framer::Decoded::Ok);
    EXPECT_EQ(d.frame.header.type, MessageType::Control);
    EXPECT_TRUE(d.frame.payload.empty());
}

TEST(FrameTest, IncompleteLengthPrefix) {
    Bytes wire = {0x00, 0x00};  // fewer than 4 length bytes
    auto d = framer::try_decode(wire.data(), wire.size());
    EXPECT_EQ(d.status, framer::Decoded::Incomplete);
}

TEST(FrameTest, IncompleteBody) {
    Bytes wire;
    framer::encode(wire, FrameHeader{MessageType::App, 0, 0}, ByteView(std::string("abcdef")));
    wire.pop_back();  // truncate the last payload byte

    auto d = framer::try_decode(wire.data(), wire.size());
    EXPECT_EQ(d.status, framer::Decoded::Incomplete);
}

TEST(FrameTest, RejectsBodySmallerThanHeader) {
    // length field = 1, but the fixed header needs 4 bytes → protocol error.
    Bytes wire = {0x00, 0x00, 0x00, 0x01, 0xFF};
    auto d = framer::try_decode(wire.data(), wire.size());
    EXPECT_EQ(d.status, framer::Decoded::Error);
}

TEST(FrameTest, RejectsOversizeBody) {
    Bytes wire = {0xFF, 0xFF, 0xFF, 0xFF};  // length far over kMaxFrameSize
    auto d = framer::try_decode(wire.data(), wire.size());
    EXPECT_EQ(d.status, framer::Decoded::Error);
}

TEST(FrameTest, DecodesBackToBackFrames) {
    Bytes wire;
    framer::encode(wire, FrameHeader{MessageType::App, 0, 1}, ByteView(std::string("one")));
    framer::encode(wire, FrameHeader{MessageType::App, 0, 2}, ByteView(std::string("two")));

    auto a = framer::try_decode(wire.data(), wire.size());
    ASSERT_EQ(a.status, framer::Decoded::Ok);
    EXPECT_EQ(payload_string(a.frame), "one");

    auto b = framer::try_decode(wire.data() + a.consumed, wire.size() - a.consumed);
    ASSERT_EQ(b.status, framer::Decoded::Ok);
    EXPECT_EQ(payload_string(b.frame), "two");
    EXPECT_EQ(a.consumed + b.consumed, wire.size());
}
