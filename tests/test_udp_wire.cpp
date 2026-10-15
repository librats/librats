// The datagram transport's wire format (udp_wire.h): varints, long headers,
// packet numbers and frames. Everything a hostile datagram can reach is here, so
// most of these are about what is refused.

#include <gtest/gtest.h>

#include "librats/transport/udp_wire.h"

#include <cstring>
#include <random>
#include <vector>

using namespace librats;
using namespace librats::udp;

TEST(UdpWireTest, VarintsRoundTripAtEveryWidth) {
    const uint64_t values[] = {0, 1, 63, 64, 16383, 16384, (uint64_t{1} << 30) - 1,
                               uint64_t{1} << 30, kMaxVarint};
    for (uint64_t v : values) {
        uint8_t buf[8];
        uint8_t* end = put_varint(buf, v);
        EXPECT_EQ(static_cast<size_t>(end - buf), varint_size(v)) << v;
        Reader r(buf, static_cast<size_t>(end - buf));
        uint64_t back = 0;
        ASSERT_TRUE(r.varint(back)) << v;
        EXPECT_EQ(back, v);
        EXPECT_TRUE(r.empty());
    }
    // RFC 9000's worked examples.
    const uint8_t two[] = {0x7b, 0xbd};
    uint64_t v = 0;
    Reader r(two, sizeof(two));
    ASSERT_TRUE(r.varint(v));
    EXPECT_EQ(v, 15293u);
}

TEST(UdpWireTest, AShortVarintIsRefusedNotOverread) {
    const uint8_t four[] = {0x9d, 0x7f, 0x3e};   // says four bytes, has three
    Reader r(four, sizeof(four));
    uint64_t v = 0;
    EXPECT_FALSE(r.varint(v));
    EXPECT_EQ(r.left(), sizeof(four)) << "a failed read consumed bytes";
}

TEST(UdpWireTest, LongPacketsRoundTrip) {
    uint8_t buf[kMaxDatagram];
    const uint8_t message[] = {1, 2, 3, 4, 5};
    const uint8_t token[kTokenSize] = {9, 8, 7, 6, 5, 4, 3, 2};

    size_t n = encode_initial(buf, 0x1111, 0x1110, ByteView(token, sizeof(token)),
                              ByteView(message, sizeof(message)));
    EXPECT_EQ(n, kMaxDatagram) << "an Initial is always full size";
    LongPacket p;
    ASSERT_TRUE(decode_long(buf, n, p));
    EXPECT_EQ(p.type, LongType::Initial);
    EXPECT_EQ(p.dcid, 0x1111u);
    EXPECT_EQ(p.scid, 0x1110u);
    EXPECT_EQ(p.token.size(), kTokenSize);
    EXPECT_EQ(std::memcmp(p.token.data(), token, kTokenSize), 0);
    ASSERT_EQ(p.message.size(), sizeof(message));
    EXPECT_EQ(std::memcmp(p.message.data(), message, sizeof(message)), 0);
    Cid routed = 0;
    ASSERT_TRUE(peek_dcid(buf, n, routed));
    EXPECT_EQ(routed, 0x1111u);

    n = encode_handshake(buf, 7, 8, 2, ByteView(message, sizeof(message)));
    ASSERT_TRUE(decode_long(buf, n, p));
    EXPECT_EQ(p.type, LongType::Handshake);
    EXPECT_EQ(p.number, 2);
    EXPECT_EQ(p.message.size(), sizeof(message));

    n = encode_retry(buf, 7, 8, ByteView(token, sizeof(token)));
    ASSERT_TRUE(decode_long(buf, n, p));
    EXPECT_EQ(p.type, LongType::Retry);
    EXPECT_EQ(p.token.size(), kTokenSize);

    n = encode_close(buf, 7, 8, 3);
    ASSERT_TRUE(decode_long(buf, n, p));
    EXPECT_EQ(p.type, LongType::Close);
    EXPECT_EQ(p.error, 3u);
}

TEST(UdpWireTest, LongPacketsOfAnotherVersionOrShapeAreRefused) {
    uint8_t buf[kMaxDatagram];
    const uint8_t message[] = {1, 2, 3};
    const size_t n = encode_handshake(buf, 7, 8, 1, ByteView(message, sizeof(message)));
    LongPacket p;

    Bytes other(buf, buf + n);
    other[4] ^= 0x01;   // another version
    EXPECT_FALSE(decode_long(other.data(), other.size(), p)) << "another version was parsed";

    other.assign(buf, buf + n);
    other[0] |= 0x01;   // a reserved bit
    EXPECT_FALSE(decode_long(other.data(), other.size(), p));

    other.assign(buf, buf + n);
    other.push_back(0);   // trailing bytes after a Handshake's message
    EXPECT_FALSE(decode_long(other.data(), other.size(), p));

    for (size_t cut = 0; cut < n; ++cut)
        EXPECT_FALSE(decode_long(buf, cut, p)) << "a truncated packet of " << cut << " bytes";

    // An Initial's padding is zeros and nothing else.
    const size_t init = encode_initial(buf, 1, 0, ByteView{}, ByteView(message, sizeof(message)));
    ASSERT_TRUE(decode_long(buf, init, p));
    buf[init - 1] = 0xAA;
    EXPECT_FALSE(decode_long(buf, init, p)) << "data smuggled into an Initial's padding";

    // The previous wire version's first byte has no fixed bit: never routed.
    const uint8_t v2[] = {0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Cid cid = 0;
    EXPECT_FALSE(peek_dcid(v2, sizeof(v2), cid));
}

TEST(UdpWireTest, PacketNumbersDecodeAcrossTheirTruncation) {
    // RFC 9000 §A.3's example.
    EXPECT_EQ(decode_pn(0x9b32, 2, 0xa82f30eb), 0xa82f9b32u);

    std::mt19937_64 rng(3);
    for (int i = 0; i < 20000; ++i) {
        const uint64_t largest_acked = rng() % (uint64_t{1} << 40);
        const uint64_t pn            = largest_acked + 1 + rng() % 5000;
        const size_t   len           = pn_length(pn, largest_acked, true);
        ASSERT_GE(len, 1u);
        ASSERT_LE(len, kMaxPnLength);
        const uint64_t truncated = pn & ((uint64_t{1} << (8 * len)) - 1);
        // The receiver has seen anything from what was acknowledged up to just
        // before this one.
        const uint64_t received = largest_acked + rng() % (pn - largest_acked);
        EXPECT_EQ(decode_pn(truncated, len, received + 1), pn)
            << "pn " << pn << " acked " << largest_acked << " len " << len;
    }
    EXPECT_EQ(pn_length(0, 0, false), 1u);
    EXPECT_EQ(pn_length(300, 10, true), 2u);
}

TEST(UdpWireTest, FramesRoundTrip) {
    uint8_t buf[512];
    uint8_t* p = buf;
    *p++ = kPing;
    const uint64_t los[] = {90, 50, 10};
    const uint64_t his[] = {100, 80, 20};
    p = put_ack(p, los, his, 3, 125);
    const uint8_t data[] = {'h', 'e', 'l', 'l', 'o'};
    p = put_stream_header(p, 4, 70000, sizeof(data), true);
    std::memcpy(p, data, sizeof(data));
    p += sizeof(data);
    p = put_value_frame(p, kMaxData, 1u << 20);
    p = put_value_frame(p, kDataBlocked, 999);
    uint8_t token[kResetTokenSize];
    for (size_t i = 0; i < sizeof(token); ++i) token[i] = static_cast<uint8_t>(i * 7);
    p = put_reset_token(p, token);
    *p++ = kPadding;
    *p++ = kPadding;
    p = put_value_frame(p, kClose, 0);
    // type, largest (2), delay (2), count, first range, then two (gap, length) pairs.
    EXPECT_EQ(ack_frame_size(los, his, 3, 125), size_t(1 + 2 + 2 + 1 + 1 + 4));

    FrameReader r(buf, static_cast<size_t>(p - buf));
    Frame f;
    ASSERT_TRUE(r.next(f));
    EXPECT_EQ(f.type, kPing);

    ASSERT_TRUE(r.next(f));
    ASSERT_EQ(f.type, kAck);
    EXPECT_EQ(f.ack.largest, 100u);
    EXPECT_EQ(f.ack.delay, 125u);
    AckRanges ranges(f.ack);
    uint64_t lo = 0, hi = 0;
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(ranges.next(lo, hi));
        EXPECT_EQ(lo, los[i]);
        EXPECT_EQ(hi, his[i]);
    }
    EXPECT_FALSE(ranges.next(lo, hi));

    ASSERT_TRUE(r.next(f));
    ASSERT_EQ(f.type, kStream);
    EXPECT_EQ(f.stream.stream, 4u);
    EXPECT_EQ(f.stream.offset, 70000u);
    ASSERT_EQ(f.stream.data.size(), sizeof(data));
    EXPECT_EQ(std::memcmp(f.stream.data.data(), data, sizeof(data)), 0);

    ASSERT_TRUE(r.next(f));
    EXPECT_EQ(f.type, kMaxData);
    EXPECT_EQ(f.value, 1u << 20);
    ASSERT_TRUE(r.next(f));
    EXPECT_EQ(f.type, kDataBlocked);
    EXPECT_EQ(f.value, 999u);
    ASSERT_TRUE(r.next(f));
    EXPECT_EQ(f.type, kResetToken);
    EXPECT_EQ(std::memcmp(f.token.data(), token, kResetTokenSize), 0);
    ASSERT_TRUE(r.next(f)) << "padding was not skipped";
    EXPECT_EQ(f.type, kClose);
    EXPECT_FALSE(r.next(f));
    EXPECT_FALSE(r.error());
}

TEST(UdpWireTest, AStreamFrameWithoutALengthRunsToTheEnd) {
    uint8_t buf[64];
    uint8_t* p = put_stream_header(buf, 1, 0, 0, false);
    const char text[] = "the rest of the packet";
    std::memcpy(p, text, sizeof(text));
    p += sizeof(text);
    FrameReader r(buf, static_cast<size_t>(p - buf));
    Frame f;
    ASSERT_TRUE(r.next(f));
    EXPECT_EQ(f.stream.offset, 0u);
    EXPECT_EQ(f.stream.data.size(), sizeof(text));
    EXPECT_FALSE(r.next(f));
    EXPECT_FALSE(r.error());
}

TEST(UdpWireTest, ALiveFrameIsAWholeMessageOrAPieceOfOne) {
    uint8_t buf[128];
    const char whole[] = "\x01\x00\x00\x00ping";        // an inner message: header + payload
    const char piece[] = "middle of a frame";
    uint8_t* p = put_live_header(buf, 7, 150, sizeof(whole), 0, sizeof(whole));
    EXPECT_EQ(static_cast<size_t>(p - buf), live_header_size(7, 150, sizeof(whole), 0, sizeof(whole)));
    std::memcpy(p, whole, sizeof(whole));
    p += sizeof(whole);
    uint8_t* q = put_live_header(p, 70000, 30000, 100000, 4000, sizeof(piece));
    EXPECT_EQ(static_cast<size_t>(q - p), live_header_size(70000, 30000, 100000, 4000, sizeof(piece)));
    EXPECT_GT(q - p, p - buf - static_cast<std::ptrdiff_t>(sizeof(whole))) << "a piece names its size and offset";
    std::memcpy(q, piece, sizeof(piece));
    q += sizeof(piece);

    FrameReader r(buf, static_cast<size_t>(q - buf));
    Frame f;
    ASSERT_TRUE(r.next(f));
    ASSERT_EQ(f.type, kLive);
    EXPECT_EQ(f.live.id, 7u);
    EXPECT_EQ(f.live.lifetime, 150u);
    EXPECT_TRUE(f.live.whole());
    EXPECT_EQ(f.live.size, sizeof(whole));
    EXPECT_EQ(std::memcmp(f.live.data.data(), whole, sizeof(whole)), 0);

    ASSERT_TRUE(r.next(f));
    ASSERT_EQ(f.type, kLive);
    EXPECT_EQ(f.live.id, 70000u);
    EXPECT_EQ(f.live.lifetime, 30000u);
    EXPECT_FALSE(f.live.whole());
    EXPECT_EQ(f.live.size, 100000u);
    EXPECT_EQ(f.live.offset, 4000u);
    ASSERT_EQ(f.live.data.size(), sizeof(piece));
    EXPECT_EQ(std::memcmp(f.live.data.data(), piece, sizeof(piece)), 0);
    EXPECT_FALSE(r.next(f));
    EXPECT_FALSE(r.error());
}

TEST(UdpWireTest, MalformedFramesAreErrors) {
    const auto rejects = [](std::vector<uint8_t> bytes) {
        FrameReader r(bytes.data(), bytes.size());
        Frame f;
        while (r.next(f)) {}
        return r.error();
    };
    EXPECT_TRUE(rejects({0x3f}))                     << "an unknown frame type";
    EXPECT_TRUE(rejects({0x09, 0x01, 0x41}))         << "a stream frame with FIN";
    EXPECT_TRUE(rejects({0x0a, 0x01, 0x05, 'a'}))    << "a stream length past the packet";
    EXPECT_TRUE(rejects({kAck, 0x05, 0x00, 0x00, 0x06})) << "a first range below packet 0";
    // largest 10, first range 2 (8..10), then a gap of 7 would need packet -1.
    EXPECT_TRUE(rejects({kAck, 0x0a, 0x00, 0x01, 0x02, 0x07, 0x00})) << "a later range below 0";
    EXPECT_TRUE(rejects({kAck, 0x0a, 0x00}))         << "a truncated ACK";
    EXPECT_TRUE(rejects({kResetToken, 1, 2, 3}))     << "a short reset token";
    EXPECT_TRUE(rejects({kMaxData}))                 << "a value frame with no value";
    // LIVE: id, lifetime, [size, offset], length, data.
    EXPECT_TRUE(rejects({kLive, 0x01, 0x05, 0x03, 'a', 'b', 'c'})) << "a live message shorter than a header";
    EXPECT_TRUE(rejects({kLive, 0x01, 0x05, 0x05, 'a', 'b', 'c', 'd'})) << "a live length past the packet";
    EXPECT_TRUE(rejects({kLive | kLivePieceBit, 0x01, 0x05, 0x08, 0x06, 0x03, 'a', 'b', 'c'}))
        << "a piece reaching past the end of its message";
    EXPECT_TRUE(rejects({kLive | kLivePieceBit, 0x01, 0x05, 0x08, 0x09, 0x00}))
        << "a piece starting past the end of its message";
    // A one-byte piece at offset 0 of a message `size` bytes long.
    const auto piece_of = [](uint64_t size) {
        std::vector<uint8_t> bytes{kLive | kLivePieceBit, 0x01, 0x05};
        uint8_t buf[8];
        bytes.insert(bytes.end(), buf, put_varint(buf, size));
        bytes.insert(bytes.end(), {0x00, 0x01, 'a'});
        return bytes;
    };
    EXPECT_TRUE(rejects(piece_of(kMaxLiveMessage + 1))) << "a live message past the size limit";
    EXPECT_FALSE(rejects(piece_of(kMaxLiveMessage)))    << "a live message at the size limit";
    EXPECT_FALSE(rejects({kLive | kLivePieceBit, 0x01, 0x05, 0x08, 0x05, 0x03, 'a', 'b', 'c'}));
    EXPECT_FALSE(rejects({kPadding, kPadding, kPing}));
}
