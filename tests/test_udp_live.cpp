// Live messages on a datagram connection (udp_live.h): the sender and receiver
// on their own, then two connections in virtual time over a path a test controls.
// What has to hold: a live message arrives whole and once, or not at all; what is
// lost is repaired while the repair can still make it; what cannot make it is
// dropped — whole, and before it is sent if it never was — and nothing stale
// stands in front of what is fresh.

#include <gtest/gtest.h>

#include "udp_test_net.h"

#include "librats/core/io_poller.h"   // PollIn
#include "librats/transport/udp_live.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

using namespace librats;
using namespace udptest;

namespace {

using udp::LiveReceiver;
using udp::LiveSender;

constexpr Clock::time_point kT0 = Clock::time_point{} + std::chrono::hours(1);

/// Inner message bytes for a payload, as the receiver hands them over.
std::string inner(const std::string& payload, uint16_t channel = 0) {
    std::string s(framer::kHeaderSize, '\0');
    framer::encode_header(reinterpret_cast<uint8_t*>(&s[0]), FrameHeader{MessageType::App, 0, channel});
    return s + payload;
}

/// Everything the sender would put on the wire, piece by piece, as frames.
struct Piece {
    uint64_t    id;
    uint32_t    offset, size;
    std::string data;
    bool        repair;
    bool        parity = false;   ///< repair symbol `offset`, of symbols data.size() long
};

/// Take what the sender offers next, in pieces of up to `max` bytes — and, given
/// `rows`, with every message protected by that many repair symbols per block of
/// `max`-byte symbols, as the connection would.
std::vector<Piece> drain(LiveSender& s, size_t max = 1000, size_t limit = 1000, uint32_t rows = 0) {
    std::vector<Piece> out;
    LiveSender::Piece p;
    while (out.size() < limit && s.peek(p)) {
        if (p.fresh && rows > 0) {
            s.protect(p.id, udp::fec::Layout::fit(p.size, static_cast<uint32_t>(max)), rows);
            continue;
        }
        if (p.parity) {
            out.push_back({p.id, p.index, p.size,
                           std::string(reinterpret_cast<const char*>(s.parity_bytes(p.id, p.index)), p.len),
                           false, true});
            s.take(p, p.len);
            continue;
        }
        size_t len = (std::min<size_t>)(p.len, max);
        if (p.symbol) len = (std::min<size_t>)(len, p.symbol - p.offset % p.symbol);
        out.push_back({p.id, p.offset, p.size,
                       std::string(reinterpret_cast<const char*>(s.bytes(p.id, p.offset)), len), p.repair});
        s.take(p, len);
    }
    return out;
}

udp::LiveFrame frame_of(const Piece& p, uint64_t lifetime = 1000) {
    udp::LiveFrame f;
    f.id       = p.id;
    f.lifetime = lifetime;
    f.size     = p.size;
    f.offset   = p.offset;
    f.data     = ByteView(reinterpret_cast<const uint8_t*>(p.data.data()), p.data.size());
    return f;
}

udp::LiveRepairFrame repair_of(const Piece& p, uint64_t lifetime = 1000) {
    udp::LiveRepairFrame f;
    f.id       = p.id;
    f.lifetime = lifetime;
    f.size     = p.size;
    f.symbol   = p.data.size();
    f.index    = p.offset;
    f.data     = ByteView(reinterpret_cast<const uint8_t*>(p.data.data()), p.data.size());
    return f;
}

std::vector<std::string> delivered(LiveReceiver& r) {
    std::vector<std::string> out;
    bool stopped = false;
    r.deliver([&](ByteView m) {
        out.emplace_back(m.begin(), m.end());
        return true;
    }, stopped);
    return out;
}

bool carries_live(const Bytes& d) {
    for (const auto& f : frames_of(d))
        if (f.type == udp::kLive) return true;
    return false;
}

} // namespace

// ── The sender ──────────────────────────────────────────────────────────────

TEST(LiveSenderTest, TheNearestDeadlineGoesFirst) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string("slow")),   kT0 + 300ms);
    s.push(FrameHeader{}, ByteView(std::string("urgent")), kT0 + 100ms);
    s.push(FrameHeader{}, ByteView(std::string("middle")), kT0 + 200ms);
    const auto pieces = drain(s);
    ASSERT_EQ(pieces.size(), 3u);
    EXPECT_EQ(pieces[0].id, 1u);
    EXPECT_EQ(pieces[1].id, 2u);
    EXPECT_EQ(pieces[2].id, 0u);
    EXPECT_EQ(pieces[2].data, inner("slow"));
    EXPECT_FALSE(s.has_pending());
    EXPECT_FALSE(s.empty()) << "sent is not delivered: it is held until acknowledged";
}

// A lower rank goes first whatever its deadline — a call's sound ahead of the
// keyframe it was captured after — and the nearest deadline within a rank. Ranks
// past the last are the last.
TEST(LiveSenderTest, ALowerRankGoesFirstWhateverItsDeadline) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string("keyframe")), kT0 + 100ms, 0, 1);
    s.push(FrameHeader{}, ByteView(std::string("sound")),    kT0 + 300ms, 0, 0);
    s.push(FrameHeader{}, ByteView(std::string("delta")),    kT0 + 50ms,  0, 200);
    s.push(FrameHeader{}, ByteView(std::string("sound 2")),  kT0 + 200ms, 0, 0);
    s.push(FrameHeader{}, ByteView(std::string("enhance")),  kT0 + 10ms,  0, LiveSender::kRanks - 1);
    const auto pieces = drain(s);
    std::vector<uint64_t> ids;
    for (const auto& piece : pieces) ids.push_back(piece.id);
    EXPECT_EQ(ids, (std::vector<uint64_t>{3, 1, 0, 4, 2}));
}

// Whatever its rank, a message that can no longer make it is dropped, and is
// what the next expiry is set by.
TEST(LiveSenderTest, WhatExpiresIsFoundInAnyRank) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string("sound")),    kT0 + 300ms, 0, 0);
    s.push(FrameHeader{}, ByteView(std::string("keyframe")), kT0 + 50ms,  0, 2);
    EXPECT_EQ(s.next_expiry(10ms), kT0 + 40ms);
    s.expire(kT0 + 45ms, 10ms);
    EXPECT_EQ(s.expired(), 1u);
    const auto pieces = drain(s);
    ASSERT_EQ(pieces.size(), 1u);
    EXPECT_EQ(pieces[0].id, 0u);
}

// Under overload, what leaves ahead of a message is what is of a lower rank or
// due sooner: that is what it is shed for.
TEST(LiveSenderTest, UnderOverloadAMessageIsShedForTheLowerRanksAheadOfIt) {
    const cc::PacingRate rate = cc::PacingRate::per_second(100'000);   // 10 KB per 100 ms
    const auto payload = std::string(10'000 - framer::kHeaderSize, 'v');
    LiveSender s;
    s.push(FrameHeader{}, ByteView(payload), kT0 + 150ms, 0, 1);   // would leave by 100 ms alone
    s.push(FrameHeader{}, ByteView(payload), kT0 + 300ms, 0, 0);   // goes first: the 1 goes by 200
    s.push(FrameHeader{}, ByteView(payload), kT0 + 300ms, 0, 1);   // the last waiting
    s.expire(kT0, 0ms, rate);
    EXPECT_EQ(s.expired(), 1u);
    const auto pieces = drain(s, 10'000);
    ASSERT_EQ(pieces.size(), 2u);
    EXPECT_EQ(pieces[0].id, 1u);
    EXPECT_EQ(pieces[1].id, 2u);
}

TEST(LiveSenderTest, OnlyWhatIsStillMissingIsRepairedAndRepairsComeFirst) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string(2996, 'x')), kT0 + 1s);   // 3000 bytes inner
    auto first = drain(s, 1000, 2);
    ASSERT_EQ(first.size(), 2u);
    s.on_acked(0, 1000, 1000);
    s.on_lost(0, 0, 2000);   // a late report covering both: only [0, 1000) is still missing
    EXPECT_EQ(s.lost_bytes(), 1000u);
    auto next = drain(s);
    ASSERT_EQ(next.size(), 2u);
    EXPECT_TRUE(next[0].repair);
    EXPECT_EQ(next[0].offset, 0u);
    EXPECT_EQ(next[0].data.size(), 1000u);
    EXPECT_FALSE(next[1].repair);
    EXPECT_EQ(next[1].offset, 2000u);
    s.on_acked(0, 0, 1000);
    s.on_acked(0, 2000, 1000);
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.expired(), 0u);
}

TEST(LiveSenderTest, ALateAcknowledgementSettlesARepairStillOwed) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string("frame")), kT0 + 1s);
    drain(s);
    s.on_lost(0, 0, 9);
    EXPECT_TRUE(s.has_pending());
    s.on_acked(0, 0, 9);   // the packet given up on arrived after all
    EXPECT_FALSE(s.has_pending());
    EXPECT_TRUE(s.empty());
    LiveSender::Piece p;
    EXPECT_FALSE(s.peek(p)) << "a stale entry was offered";
}

TEST(LiveSenderTest, WhatCannotArriveInTimeIsDroppedWhole) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string(5000, 'k')), kT0 + 100ms);
    s.push(FrameHeader{}, ByteView(std::string("later")),   kT0 + 500ms);
    drain(s, 1000, 2);   // two pieces of the first sent, the rest still to go
    ASSERT_TRUE(s.next_expiry(30ms));
    EXPECT_EQ(*s.next_expiry(30ms), kT0 + 70ms);
    s.expire(kT0 + 69ms, 30ms);
    EXPECT_EQ(s.expired(), 0u);
    s.expire(kT0 + 70ms, 30ms);
    EXPECT_EQ(s.expired(), 1u);
    EXPECT_EQ(s.unsent(), inner("later").size()) << "the expired message's remainder still counted";
    const auto rest = drain(s);
    ASSERT_EQ(rest.size(), 1u);
    EXPECT_EQ(rest[0].id, 1u);
    // Pieces of the expired one that were already out are of no interest any more.
    s.on_lost(0, 0, 1000);
    s.on_acked(0, 1000, 1000);
    EXPECT_FALSE(s.has_pending());
}

TEST(LiveSenderTest, ASentMessageIsNotGivenUpWhileItMayStillArrive) {
    // Everything of it is out: whether it is in time is the path's business now.
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string("out")), kT0 + 100ms);
    drain(s);
    s.expire(kT0 + 500ms, 10ms);
    EXPECT_EQ(s.expired(), 0u);
    EXPECT_FALSE(s.next_expiry(10ms));
    // ...but once it is lost, a repair that cannot make it is not sent.
    s.on_lost(0, 0, 7);
    s.expire(kT0 + 500ms, 10ms);
    EXPECT_EQ(s.expired(), 1u);
    EXPECT_TRUE(s.empty());
}

// More than the connection can send in time: a message that has not started and
// would leave too late behind what is ahead of it is dropped before it costs a
// byte — so the rest go whole instead of every one running out half sent. Never
// the last one waiting, which no one is waiting behind, and never one under way.
TEST(LiveSenderTest, UnderOverloadWhatCannotLeaveInTimeIsDroppedBeforeItStarts) {
    const cc::PacingRate rate = cc::PacingRate::per_second(100'000);   // 10 KB per 100 ms
    const auto payload = std::string(10'000 - framer::kHeaderSize, 'v');
    LiveSender s;
    for (int i = 0; i < 4; ++i) s.push(FrameHeader{}, ByteView(payload), kT0 + 150ms);
    s.expire(kT0, 0ms, rate);
    // The first leaves by 100 ms; the second by 200, too late; the third the same
    // behind the first; the fourth is the last waiting.
    EXPECT_EQ(s.expired(), 2u);
    const auto pieces = drain(s, 10'000);
    ASSERT_EQ(pieces.size(), 2u);
    EXPECT_EQ(pieces[0].id, 0u);
    EXPECT_EQ(pieces[1].id, 3u);

    // A message under way is left to make it or not, and so is one alone.
    LiveSender t;
    t.push(FrameHeader{}, ByteView(payload), kT0 + 50ms);
    t.expire(kT0, 0ms, rate);
    EXPECT_EQ(t.expired(), 0u) << "the only message was shed";
    drain(t, 1000, 1);
    t.push(FrameHeader{}, ByteView(payload), kT0 + 300ms);
    t.expire(kT0, 0ms, rate);
    EXPECT_EQ(t.expired(), 0u) << "a message already started was shed";
    // Without a rate to judge by, nothing is.
    t.push(FrameHeader{}, ByteView(payload), kT0 + 10ms);
    t.push(FrameHeader{}, ByteView(payload), kT0 + 400ms);
    t.expire(kT0, 0ms);
    EXPECT_EQ(t.expired(), 0u);
}

TEST(LiveSenderTest, AFullWindowGivesUpTheOldest) {
    LiveSender s;
    for (uint64_t i = 0; i < LiveSender::kWindow + 3; ++i)
        s.push(FrameHeader{}, ByteView(std::string("m")), kT0 + 1s);
    EXPECT_EQ(s.sent(), LiveSender::kWindow + 3);
    EXPECT_EQ(s.expired(), 3u);
    const auto pieces = drain(s, 1000, 2 * LiveSender::kWindow);
    ASSERT_EQ(pieces.size(), LiveSender::kWindow);
    EXPECT_EQ(pieces.front().id, 3u);
    EXPECT_EQ(pieces.back().id, LiveSender::kWindow + 2);
}

// A tagged message leaves word of what became of it once that is settled —
// acknowledged, or given up on however that came about — and an untagged one none.
TEST(LiveSenderTest, ATaggedMessageSaysWhatBecameOfIt) {
    const cc::PacingRate rate = cc::PacingRate::per_second(100'000);   // 10 KB per 100 ms
    const auto big = std::string(10'000 - framer::kHeaderSize, 'v');
    LiveSender s;
    s.push(FrameHeader{MessageType::Media}, ByteView(std::string("acked")), kT0 + 1s, 1);
    s.push(FrameHeader{MessageType::Media}, ByteView(std::string("untagged")), kT0 + 1s);
    s.push(FrameHeader{MessageType::Media}, ByteView(std::string("late")), kT0 + 50ms, 3);
    drain(s);
    EXPECT_FALSE(s.has_outcomes()) << "sent is not settled";
    s.on_acked(0, 0, inner("acked").size());
    s.on_acked(1, 0, inner("untagged").size());
    s.on_lost(2, 0, inner("late").size());
    s.expire(kT0 + 40ms, 10ms);   // too late to send again
    // Shed under overload: the second of three that cannot all leave in time.
    s.push(FrameHeader{MessageType::Media}, ByteView(big), kT0 + 150ms, 4);
    s.push(FrameHeader{MessageType::Media}, ByteView(big), kT0 + 150ms, 5);
    s.push(FrameHeader{MessageType::Media}, ByteView(big), kT0 + 150ms, 6);
    s.expire(kT0 + 40ms, 0ms, rate);

    ASSERT_TRUE(s.has_outcomes());
    const auto outcomes = s.take_outcomes();
    ASSERT_EQ(outcomes.size(), 3u);
    EXPECT_EQ(outcomes[0].type, MessageType::Media);
    EXPECT_EQ(outcomes[0].tag, 1u);
    EXPECT_TRUE(outcomes[0].delivered);
    EXPECT_EQ(outcomes[1].tag, 3u);
    EXPECT_FALSE(outcomes[1].delivered);
    EXPECT_EQ(outcomes[2].tag, 5u);
    EXPECT_FALSE(outcomes[2].delivered);
    EXPECT_FALSE(s.has_outcomes());

    // The connection going away takes what it held with it, untold.
    s.clear();
    EXPECT_FALSE(s.has_outcomes());
}

TEST(LiveSenderTest, AProbeRepeatsOnlyWhatIsStillWorthIt) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string(1996, 'p')), kT0 + 100ms);
    drain(s);
    LiveSender::Piece p;
    ASSERT_TRUE(s.repeat(0, 0, 1000, kT0 + 50ms, p));
    EXPECT_EQ(p.size, 2000u);
    EXPECT_FALSE(s.repeat(0, 0, 1000, kT0 + 100ms, p)) << "a copy that would arrive too late";
    s.on_acked(0, 0, 1000);
    EXPECT_FALSE(s.repeat(0, 0, 1000, kT0 + 50ms, p)) << "a piece already delivered";
    EXPECT_FALSE(s.repeat(9, 0, 1, kT0, p)) << "a message never sent";
}

// ── The sender, with repair symbols ─────────────────────────────────────────

// Repairs fill time nothing else wants: they go after the data of every message
// waiting, the nearest deadline first again.
TEST(LiveSenderTest, RepairSymbolsGoAfterEveryMessagesData) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string(2996, 'a')), kT0 + 300ms);   // three symbols
    s.push(FrameHeader{}, ByteView(std::string(496, 'b')),  kT0 + 200ms);   // one
    const auto pieces = drain(s, 1000, 100, /*rows=*/1);
    ASSERT_EQ(pieces.size(), 6u);
    EXPECT_EQ(pieces[0].id, 1u);
    EXPECT_FALSE(pieces[0].parity);
    for (int i = 1; i < 4; ++i) EXPECT_FALSE(pieces[i].parity) << i;
    EXPECT_TRUE(pieces[4].parity);
    EXPECT_EQ(pieces[4].id, 1u) << "the nearer deadline's repair first";
    EXPECT_EQ(pieces[4].data.size(), 500u) << "a one-symbol message's repair is its own size";
    EXPECT_TRUE(pieces[5].parity);
    EXPECT_EQ(pieces[5].id, 0u);
    EXPECT_EQ(pieces[5].data.size(), 1000u);
    EXPECT_EQ(s.parity_sent(), 1500u);
    EXPECT_EQ(s.parity_unsent(), 0u);
    EXPECT_EQ(s.unsent(), 0u);
}

// To the sender a message is delivered once the receiver can put it together:
// as many of a block's symbols acknowledged as it has source symbols.
TEST(LiveSenderTest, AMessageIsDeliveredOnceEnoughOfItsSymbolsAreAcknowledged) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string(2996, 'a')), kT0 + 300ms);
    drain(s, 1000, 100, 1);
    s.on_acked(0, 0, 1000);
    s.on_lost(0, 1000, 1000);
    EXPECT_EQ(s.lost_bytes(), 1000u) << "sent again while there is time: a repair can be lost too";
    s.on_acked(0, 2000, 1000);
    EXPECT_FALSE(s.empty());
    s.on_parity_acked(0, 0);
    EXPECT_TRUE(s.empty()) << "two source symbols and the repair are all three";
    EXPECT_EQ(s.lost_bytes(), 0u);
    EXPECT_EQ(s.expired(), 0u);
}

// Past the point a piece sent again could make it, a message whose blocks have
// lost no more than their repairs is left to them — not given up on.
TEST(LiveSenderTest, AtTheDeadlineALossTheRepairsCanStandInForIsLeftToThem) {
    for (const bool repair_lost : {false, true}) {
        SCOPED_TRACE(repair_lost);
        LiveSender s;
        s.push(FrameHeader{}, ByteView(std::string(2996, 'a')), kT0 + 100ms);
        drain(s, 1000, 100, 1);
        s.on_lost(0, 1000, 1000);
        s.expire(kT0 + 70ms, 30ms);
        EXPECT_EQ(s.expired(), 0u);
        EXPECT_FALSE(s.has_pending()) << "the loss was still to be sent again, too late";
        EXPECT_FALSE(s.empty());
        s.on_acked(0, 0, 1000);
        s.on_acked(0, 2000, 1000);
        if (repair_lost) {
            s.on_parity_lost(0, 0);   // two symbols lost to one repair
            s.expire(kT0 + 70ms, 30ms);
            EXPECT_EQ(s.expired(), 1u);
        } else {
            s.on_parity_acked(0, 0);
            EXPECT_EQ(s.expired(), 0u);
        }
        EXPECT_TRUE(s.empty());
    }
}

TEST(LiveSenderTest, RepairsThatCouldOnlyLandTooLateAreNotSent) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string(2996, 'a')), kT0 + 100ms);
    drain(s, 1000, 3, 2);   // the data, not the repairs
    EXPECT_EQ(s.parity_unsent(), 2000u);
    ASSERT_TRUE(s.next_expiry(30ms));
    EXPECT_EQ(*s.next_expiry(30ms), kT0 + 70ms);
    s.expire(kT0 + 70ms, 30ms);
    EXPECT_EQ(s.parity_unsent(), 0u);
    EXPECT_FALSE(s.has_pending());
    EXPECT_EQ(s.expired(), 0u) << "the data is out, and may still arrive";
    // With both repairs gone, the block can lose nothing more.
    s.on_lost(0, 0, 1000);
    s.expire(kT0 + 70ms, 30ms);
    EXPECT_EQ(s.expired(), 1u);
}

TEST(LiveSenderTest, AProbeRepeatsARepairSymbolOnlyWhileItIsWorthIt) {
    LiveSender s;
    s.push(FrameHeader{}, ByteView(std::string(1996, 'p')), kT0 + 100ms);
    drain(s, 1000, 100, 1);
    LiveSender::Piece p;
    ASSERT_TRUE(s.repeat_parity(0, 0, kT0 + 50ms, p));
    EXPECT_TRUE(p.parity);
    EXPECT_EQ(p.len, 1000u);
    EXPECT_FALSE(s.repeat_parity(0, 1, kT0 + 50ms, p)) << "a repair never sent";
    EXPECT_FALSE(s.repeat_parity(0, 0, kT0 + 100ms, p)) << "a copy that would arrive too late";
    s.on_parity_acked(0, 0);
    EXPECT_FALSE(s.repeat_parity(0, 0, kT0 + 50ms, p));
}

// ── The receiver ────────────────────────────────────────────────────────────

TEST(LiveReceiverTest, PutsPiecesTogetherInAnyOrderAndDeliversOnce) {
    LiveSender s;
    s.push(FrameHeader{MessageType::App, 0, 4}, ByteView(std::string(2500, 'a')), kT0 + 1s);
    s.push(FrameHeader{MessageType::App, 0, 5}, ByteView(std::string("small")), kT0 + 1s);
    const auto pieces = drain(s, 1000);
    ASSERT_EQ(pieces.size(), 4u);
    udp::HoldAccount account;
    LiveReceiver r;
    for (size_t i : {3u, 2u, 0u, 1u})   // the small one first, the large one backwards
        EXPECT_EQ(r.on_frame(frame_of(pieces[i]), kT0, 10ms, account), LiveReceiver::Result::Taken);
    const auto got = delivered(r);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(got[0], inner("small", 5));
    EXPECT_EQ(got[1], inner(std::string(2500, 'a'), 4));
    EXPECT_EQ(account.held, 0u);
    // Every piece again — a late repair, a probe's copy: none of it is delivered twice.
    for (const Piece& p : pieces) r.on_frame(frame_of(p), kT0, 10ms, account);
    EXPECT_TRUE(delivered(r).empty());
    EXPECT_EQ(r.buffered(), 0u);
}

TEST(LiveReceiverTest, PiecesThatDisagreeAboutTheirMessageAreInvalid) {
    udp::HoldAccount account;
    LiveReceiver r;
    const std::string bytes(100, 'q');
    udp::LiveFrame f;
    f.id = 1; f.lifetime = 100; f.size = 1000; f.offset = 0;
    f.data = ByteView(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    EXPECT_EQ(r.on_frame(f, kT0, 10ms, account), LiveReceiver::Result::Taken);
    f.size = 2000; f.offset = 100;
    EXPECT_EQ(r.on_frame(f, kT0, 10ms, account), LiveReceiver::Result::Invalid);
}

TEST(LiveReceiverTest, AnUnfinishedMessageIsGivenUpAfterItsLifetime) {
    udp::HoldAccount account;
    LiveReceiver r;
    const std::string bytes(600, 'g');
    udp::LiveFrame f;
    f.id = 0; f.lifetime = 100; f.size = 1200; f.offset = 0;
    f.data = ByteView(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    ASSERT_EQ(r.on_frame(f, kT0, 20ms, account), LiveReceiver::Result::Taken);
    EXPECT_GT(account.held, 1200u);
    ASSERT_TRUE(r.next_expiry());
    EXPECT_EQ(*r.next_expiry(), kT0 + 120ms);
    r.expire(kT0 + 119ms, account);
    EXPECT_GT(r.buffered(), 0u);
    r.expire(kT0 + 120ms, account);
    EXPECT_EQ(r.buffered(), 0u);
    EXPECT_EQ(account.held, 0u);
    EXPECT_FALSE(r.next_expiry());
    // The rest of it, arriving after all: the message is not started over.
    f.offset = 600;
    EXPECT_EQ(r.on_frame(f, kT0 + 121ms, 20ms, account), LiveReceiver::Result::Taken);
    EXPECT_EQ(r.buffered(), 0u);
    EXPECT_TRUE(delivered(r).empty());
}

TEST(LiveReceiverTest, TheWindowForgetsWhatFallsBehindIt) {
    udp::HoldAccount account;
    LiveReceiver r;
    const std::string whole = inner("w");
    const std::string half(500, 'h');
    udp::LiveFrame w;
    w.lifetime = 1000;
    w.size     = whole.size();
    w.data     = ByteView(reinterpret_cast<const uint8_t*>(whole.data()), whole.size());
    udp::LiveFrame part;
    part.id = 3; part.lifetime = 1000; part.size = 1000;
    part.data = ByteView(reinterpret_cast<const uint8_t*>(half.data()), half.size());

    w.id = 0;
    r.on_frame(w, kT0, 10ms, account);
    r.on_frame(part, kT0, 10ms, account);
    EXPECT_EQ(delivered(r).size(), 1u);
    EXPECT_GT(account.held, 0u);

    // An id a whole window ahead: everything below its window is done with.
    w.id = LiveReceiver::kWindow + 10;
    r.on_frame(w, kT0, 10ms, account);
    EXPECT_EQ(delivered(r).size(), 1u);
    EXPECT_EQ(account.held, 0u) << "the message left behind is still held";
    for (uint64_t id : {uint64_t{0}, uint64_t{5}, LiveReceiver::kWindow + 10}) {
        w.id = id;
        r.on_frame(w, kT0, 10ms, account);
        EXPECT_TRUE(delivered(r).empty()) << id;
    }
    // Inside the window, the slot an old id used is clear for the new one.
    w.id = LiveReceiver::kWindow + 11;
    r.on_frame(w, kT0, 10ms, account);
    EXPECT_EQ(delivered(r).size(), 1u);
}

TEST(LiveReceiverTest, WhatDoesNotFitIsRefused) {
    udp::UdpReceiveBudget budget(0);
    udp::HoldAccount account;
    account.shared = &budget;
    LiveReceiver r;
    const std::string bytes(1000, 'r');
    udp::LiveFrame f;
    f.lifetime = 1000;
    f.data     = ByteView(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    // Past the connection's guarantee, with nothing left in the shared budget.
    f.id = 0; f.size = udp::UdpReceiveBudget::kGuaranteed + 1;
    EXPECT_EQ(r.on_frame(f, kT0, 10ms, account), LiveReceiver::Result::Refused);
    EXPECT_EQ(account.held, 0u);
    // A message that comes whole needs no room to be put together in.
    f.id = 1; f.size = bytes.size();
    EXPECT_EQ(r.on_frame(f, kT0, 10ms, account), LiveReceiver::Result::Taken);
    EXPECT_EQ(delivered(r).size(), 1u);
}

// ── The receiver, with repair symbols ───────────────────────────────────────

namespace {

/// A message of `size` inner bytes, sent in 1000-byte symbols with `rows` repairs.
std::vector<Piece> protected_message(size_t size, uint32_t rows, uint64_t id_skip = 0) {
    LiveSender s;
    for (uint64_t i = 0; i < id_skip; ++i) s.push(FrameHeader{}, ByteView(std::string("x")), kT0 + 1s);
    drain(s);
    std::string payload(size - framer::kHeaderSize, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i * 7 + i / 251);
    s.push(FrameHeader{}, ByteView(payload), kT0 + 1s);
    return drain(s, 1000, 1000, rows);
}

} // namespace

TEST(LiveReceiverTest, WhatThePathLostIsRebuiltFromRepairSymbols) {
    const auto pieces = protected_message(5500, 2);   // six symbols, two repairs
    ASSERT_EQ(pieces.size(), 8u);
    const std::string expected = [&] {
        std::string m;
        for (const Piece& p : pieces)
            if (!p.parity) m += p.data;
        return m;
    }();
    // Any two of the eight lost — here a source symbol and a repair, then two
    // source symbols — and it comes back, whole and once.
    for (const std::pair<size_t, size_t> lost : {std::pair<size_t, size_t>{2, 6}, {0, 5}}) {
        LiveReceiver r;
        udp::HoldAccount account;
        for (size_t i = 0; i < pieces.size(); ++i) {
            if (i == lost.first || i == lost.second) continue;
            const auto res = pieces[i].parity ? r.on_repair(repair_of(pieces[i]), kT0, 10ms, account)
                                              : r.on_frame(frame_of(pieces[i]), kT0, 10ms, account);
            EXPECT_EQ(res, LiveReceiver::Result::Taken);
        }
        const auto got = delivered(r);
        ASSERT_EQ(got.size(), 1u);
        EXPECT_EQ(got[0], expected);
        EXPECT_EQ(account.held, 0u) << "the pieces and repairs are still charged";
        // What arrives late of it is a duplicate.
        EXPECT_EQ(r.on_frame(frame_of(pieces[lost.first]), kT0, 10ms, account), LiveReceiver::Result::Taken);
        EXPECT_TRUE(delivered(r).empty());
    }
}

TEST(LiveReceiverTest, ARepairSymbolMayComeFirst) {
    const auto pieces = protected_message(900, 1);   // one symbol, and its repair
    ASSERT_EQ(pieces.size(), 2u);
    LiveReceiver r;
    udp::HoldAccount account;
    // The message itself never arrives: its repair alone is all of it.
    EXPECT_EQ(r.on_repair(repair_of(pieces[1]), kT0, 10ms, account), LiveReceiver::Result::Taken);
    const auto got = delivered(r);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0], pieces[0].data);
    EXPECT_EQ(account.held, 0u);
}

TEST(LiveReceiverTest, ARepairSymbolThatDisagreesWithItsMessageIsInvalid) {
    const auto pieces = protected_message(3000, 1);
    LiveReceiver r;
    udp::HoldAccount account;
    ASSERT_EQ(r.on_frame(frame_of(pieces[0]), kT0, 10ms, account), LiveReceiver::Result::Taken);
    udp::LiveRepairFrame f = repair_of(pieces[3]);
    f.size = 3001;
    EXPECT_EQ(r.on_repair(f, kT0, 10ms, account), LiveReceiver::Result::Invalid) << "another size";
    f = repair_of(pieces[3]);
    f.index = udp::fec::kMaxRows;   // one block, so rows 0..kMaxRows-1
    EXPECT_EQ(r.on_repair(f, kT0, 10ms, account), LiveReceiver::Result::Invalid) << "a row past the code";
    ASSERT_EQ(r.on_repair(repair_of(pieces[3]), kT0, 10ms, account), LiveReceiver::Result::Taken);
    f = repair_of(pieces[3]);
    f.symbol = 500;
    f.data   = ByteView(f.data.data(), 500);
    EXPECT_EQ(r.on_repair(f, kT0, 10ms, account), LiveReceiver::Result::Invalid) << "another symbol size";
}

TEST(LiveReceiverTest, RepairsHeldForAMessageGivenUpOnAreReleased) {
    const auto pieces = protected_message(5500, 2);
    LiveReceiver r;
    udp::HoldAccount account;
    r.on_frame(frame_of(pieces[0], 50), kT0, 10ms, account);
    r.on_repair(repair_of(pieces[6], 50), kT0, 10ms, account);
    r.on_repair(repair_of(pieces[6], 50), kT0, 10ms, account);   // a probe's copy
    EXPECT_GT(account.held, 5500u);
    r.expire(kT0 + 60ms, account);
    EXPECT_EQ(account.held, 0u);
    EXPECT_FALSE(r.next_expiry());
    EXPECT_EQ(r.on_repair(repair_of(pieces[7], 50), kT0 + 61ms, 10ms, account), LiveReceiver::Result::Taken);
    EXPECT_EQ(account.held, 0u) << "a stray repair started a message given up on";
}

// ── Two connections ─────────────────────────────────────────────────────────

namespace {

/// Queue a live message on a, and let it send what it may.
void send_live(Pair& p, const std::string& payload, Clock::duration lifetime, uint16_t channel = 0,
               uint8_t rank = 0) {
    ASSERT_TRUE(p.a.send_live(MessageType::App, payload, p.now + lifetime, channel, 0, rank));
    p.a.conn->flush(p.now);
}

size_t count(const std::vector<Message>& messages, const std::string& payload) {
    return static_cast<size_t>(std::count_if(messages.begin(), messages.end(),
                                             [&](const Message& m) { return m.payload == payload; }));
}

} // namespace

TEST(UdpLiveTest, ArriveWholeWhateverTheirSize) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    const std::string big(200000, 'v');
    send_live(p, "small", 1s, 3);
    send_live(p, big, 1s, 3);
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 2; }));
    EXPECT_EQ(count(p.b.messages, "small"), 1u);
    EXPECT_EQ(count(p.b.messages, big), 1u);
    EXPECT_EQ(p.b.messages[0].channel, 3);
    p.run(200ms);
    EXPECT_TRUE(p.a.conn->flushed()) << "delivered messages are still held";
    EXPECT_EQ(p.b.conn->buffered_bytes(), 0u);
    const PathStats st = p.a.conn->path_stats();
    EXPECT_EQ(st.live_sent, 2u);
    EXPECT_EQ(st.live_expired, 0u);
}

// Two keyframes of the largest size a live message may have, frames behind
// them, and a path losing one packet in fifty: a receiver puts both together at
// once (LiveReceiver::kMaxAssembling) and delivers every one whole. Lifetimes
// long enough for the rate a fresh connection starts at: by that, what has not
// started could not leave in time and would be shed (LiveSender::shed).
TEST(UdpLiveTest, TheLargestMessagesArriveWholeWithFramesBehindThem) {
    Pair p(false);
    ASSERT_TRUE(p.connect());
    size_t packets = 0, dropped = 0;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from != p.a.addr() || !carries_live(d) || ++packets % 50 != 0) return false;
        ++dropped;
        return true;
    };
    const std::string key1(SendOptions::kMaxLivePayload, '1'), key2(SendOptions::kMaxLivePayload, '2');
    send_live(p, key1, 20s);
    send_live(p, key2, 20s);
    for (int i = 0; i < 4; ++i) send_live(p, "frame " + std::to_string(i), 20s);
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 6; }, 20s));
    EXPECT_GT(dropped, 0u);
    EXPECT_EQ(count(p.b.messages, key1), 1u);
    EXPECT_EQ(count(p.b.messages, key2), 1u);
    p.run(200ms);
    EXPECT_EQ(p.a.conn->path_stats().live_expired, 0u);
    EXPECT_EQ(p.b.conn->buffered_bytes(), 0u);
    EXPECT_EQ(p.b.conn->held_bytes(), 0u);
}

// The lost tail of a message has nothing behind it to reveal the loss: a probe
// does, and repeats what is still worth repeating.
TEST(UdpLiveTest, ALostPieceIsRepairedWhileTheMessageCanStillMakeIt) {
    Pair p(false, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(100ms);
    int dropped = 0;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from != p.a.addr() || !carries_live(d) || dropped >= 2) return false;
        ++dropped;
        return true;
    };
    const auto sent = p.now;
    send_live(p, std::string(3000, 'r'), 400ms);   // three packets, the first two lost
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }, 1s));
    EXPECT_EQ(dropped, 2);
    EXPECT_LT(p.now - sent, 400ms);
    dropped = 1;
    send_live(p, "tail", 400ms);   // one packet, lost: only a probe can tell
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 2; }, 1s));
    EXPECT_EQ(dropped, 2);
    EXPECT_EQ(p.a.conn->path_stats().live_expired, 0u);
}

TEST(UdpLiveTest, WhatCannotMakeItIsDroppedWholeAndNeverDeliveredInPart) {
    Pair p(false, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(100ms);
    // The first piece of the large message never gets through; the rest does.
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from != p.a.addr()) return false;
        for (const auto& f : frames_of(d))
            if (f.type == udp::kLive && f.live.size > 1000 && f.live.offset == 0) return true;
        return false;
    };
    send_live(p, std::string(30000, 'd'), 150ms);
    p.run(1s);
    EXPECT_TRUE(p.b.messages.empty()) << "a message was delivered without all of it";
    EXPECT_EQ(p.a.conn->path_stats().live_expired, 1u);
    EXPECT_EQ(p.a.conn->queued_bytes(), 0u) << "the sender kept trying past the deadline";
    EXPECT_TRUE(p.a.conn->flushed());
    EXPECT_EQ(p.b.conn->buffered_bytes(), 0u) << "the receiver kept the pieces";
    EXPECT_EQ(p.b.conn->held_bytes(), 0u);
    // And the connection is none the worse for it.
    send_live(p, "next", 150ms);
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }, 200ms));
}

// The sender hears what became of a tagged message as soon as it knows: one
// acknowledged, one given up on at its deadline — and is woken for each.
TEST(UdpLiveTest, TheSenderHearsWhatBecameOfATaggedMessage) {
    Pair p(false, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(100ms);
    const auto sent = p.now;
    ASSERT_TRUE(p.a.send_live(MessageType::Media, std::string(5000, 'k'), p.now + 200ms, 0, 41));
    p.a.conn->flush(p.now);
    p.a.events = 0;
    std::vector<LiveOutcome> outcomes;
    ASSERT_TRUE(p.run_until([&] {
        for (const LiveOutcome& o : p.a.conn->take_live_outcomes()) outcomes.push_back(o);
        return !outcomes.empty();
    }, 1s));
    EXPECT_NE(p.a.events & PollIn, 0u) << "nothing woke the sender to read it";
    EXPECT_LT(p.now - sent, 100ms) << "heard of later than the acknowledgement";
    ASSERT_EQ(outcomes.size(), 1u);
    EXPECT_EQ(outcomes[0].type, MessageType::Media);
    EXPECT_EQ(outcomes[0].tag, 41u);
    EXPECT_TRUE(outcomes[0].delivered);
    ASSERT_EQ(p.b.messages.size(), 1u);

    // Nothing of the next gets through: given up on once it can no longer arrive.
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        return from == p.a.addr() && carries_live(d);
    };
    ASSERT_TRUE(p.a.send_live(MessageType::Media, "lost", p.now + 150ms, 0, 42));
    p.a.conn->flush(p.now);
    outcomes.clear();
    ASSERT_TRUE(p.run_until([&] {
        for (const LiveOutcome& o : p.a.conn->take_live_outcomes()) outcomes.push_back(o);
        return !outcomes.empty();
    }, 1s));
    ASSERT_EQ(outcomes.size(), 1u);
    EXPECT_EQ(outcomes[0].tag, 42u);
    EXPECT_FALSE(outcomes[0].delivered);
    EXPECT_EQ(p.b.messages.size(), 1u);
}

TEST(UdpLiveTest, AMessageAlreadyTooLateIsNeverSent) {
    Pair p(false, 30ms);
    ASSERT_TRUE(p.connect());
    p.run(200ms);
    size_t live_packets = 0;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from == p.a.addr() && carries_live(d)) ++live_packets;
        return false;
    };
    send_live(p, "stale", 20ms);   // under the one-way delay
    p.run(300ms);
    EXPECT_EQ(live_packets, 0u);
    EXPECT_TRUE(p.b.messages.empty());
    EXPECT_EQ(p.a.conn->path_stats().live_expired, 1u);
}

// What the whole feature is for: a source that keeps producing through an
// outage has, when the path comes back, a second of frames nobody wants any
// more. A reliable lane sends them all, and every fresh frame waits behind them;
// live messages drop them, and the first frame across is a fresh one.
TEST(UdpLiveTest, AfterAnOutageTheFreshFramesGoFirst) {
    Pair p(true, 20ms);
    ASSERT_TRUE(p.connect());
    p.run(200ms);
    constexpr auto kLifetime = 150ms;
    const auto outage_from = p.now + 1s, outage_to = p.now + 2s;
    std::map<int, Clock::time_point> sent_at;
    std::map<std::string, Clock::time_point> arrived_at;
    int frame = 0;
    auto next_frame = p.now;
    const auto end = p.now + 3s;
    while (p.now < end) {
        p.net.blackout = p.now >= outage_from && p.now < outage_to;
        if (p.now >= next_frame) {
            sent_at[frame] = p.now;
            send_live(p, std::to_string(frame) + "|" + std::string(6000, 'f'), kLifetime);
            ++frame;
            next_frame += 33ms;
        }
        p.step();
        for (const Message& m : p.b.messages) arrived_at.emplace(m.payload, p.now);
    }
    // Every frame that arrived made its deadline.
    std::vector<int> got;
    for (const auto& [payload, at] : arrived_at) {
        const int n = std::stoi(payload.substr(0, payload.find('|')));
        got.push_back(n);
        EXPECT_LE(at - sent_at[n], kLifetime + 5ms) << "frame " << n << " was late";
    }
    // The first to arrive after the outage was fresh: sent no earlier than a
    // lifetime before the path came back.
    Clock::time_point first_after = (Clock::time_point::max)();
    int first_frame = -1;
    for (const auto& [payload, at] : arrived_at) {
        if (at < outage_to || at >= first_after) continue;
        first_after = at;
        first_frame = std::stoi(payload.substr(0, payload.find('|')));
    }
    ASSERT_GE(first_frame, 0) << "nothing arrived after the outage";
    EXPECT_GE(sent_at[first_frame], outage_to - kLifetime);
    // The path's return is noticed within a probe timeout — the sender does not
    // back off while live messages wait (Recovery::set_impatient) — and the first
    // answer gives the window back (BbrController::on_ack), so a frame follows a
    // round trip later. A reliable lane took seconds here; backing off alone,
    // 0.8 s; rebuilding the window from one packet, 0.17 s.
    EXPECT_LE(first_after - outage_to, 150ms) << "the path came back but the frames did not";
    EXPECT_EQ(p.b.messages.size(), arrived_at.size()) << "a frame was delivered twice";
    EXPECT_GT(p.a.conn->path_stats().live_expired, 20u);
    EXPECT_GT(got.size(), 50u);
    // What the outage wrote off is no loss rate to protect against.
    EXPECT_EQ(p.a.conn->path_stats().live_repair_bytes, 0u);
}

TEST(UdpLiveTest, LiveMessagesGoAheadOfABacklog) {
    Pair p(true, 20ms);
    ASSERT_TRUE(p.connect());
    for (int i = 0; i < 32; ++i) p.send(MessageType::App, std::string(64 * 1024, 'n'));
    p.run(100ms);
    ASSERT_GT(p.a.conn->queued_bytes(), 1u << 20) << "no backlog to overtake";
    const auto sent = p.now;
    send_live(p, "frame", 500ms);
    ASSERT_TRUE(p.run_until([&] { return count(p.b.messages, "frame") == 1; }, 2s));
    EXPECT_LE(p.now - sent, 30ms) << "the live message waited behind the backlog";
}

// A keyframe takes a fresh connection several round trips; a message of a lower
// rank sent behind it — a call's sound — goes ahead of the rest of it, while one
// of the same rank and a later deadline waits for all of it.
TEST(UdpLiveTest, ALowerRankOvertakesAKeyframeUnderWay) {
    for (const uint8_t sound_rank : {uint8_t{0}, uint8_t{1}}) {
        Pair p(true, 20ms);
        ASSERT_TRUE(p.connect());
        const std::string keyframe(512 * 1024, 'k');
        send_live(p, keyframe, 2s, 0, 1);
        p.run(30ms);   // under way
        send_live(p, "sound", 3s, 0, sound_rank);
        ASSERT_TRUE(p.run_until([&] { return count(p.b.messages, "sound") == 1; }, 5s));
        // (Not the order the two were handed over in: a message that came in
        // one packet is handed over ahead of one put together in the same read.)
        if (sound_rank == 0) {
            EXPECT_EQ(count(p.b.messages, keyframe), 0u) << "the sound waited for the keyframe";
        } else {
            EXPECT_EQ(count(p.b.messages, keyframe), 1u) << "same rank: the nearer deadline first";
        }
    }
}

TEST(UdpLiveTest, DuplicatedDatagramsDeliverOnce) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    p.net.hook = [&](Bytes& d, const Address& from, const Address& to) {
        p.net.inject(from, to, d);
        return false;
    };
    for (int i = 0; i < 40; ++i) send_live(p, std::to_string(i) + std::string(i % 4 ? 300 : 5000, '.'), 1s);
    p.run(500ms);
    ASSERT_EQ(p.b.messages.size(), 40u);
    for (int i = 0; i < 40; ++i)
        EXPECT_EQ(count(p.b.messages, std::to_string(i) + std::string(i % 4 ? 300 : 5000, '.')), 1u) << i;
}

TEST(UdpLiveTest, AnOrderlyCloseWaitsForLiveMessagesButNotPastTheirLifetime) {
    Pair p(false, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(100ms);
    send_live(p, "delivered", 300ms);
    p.a.conn->close(CloseReason::LocalClose, p.now);
    ASSERT_TRUE(p.run_until([&] { return p.b.conn->dead(); }, 1s));
    EXPECT_EQ(count(p.b.messages, "delivered"), 1u);

    Pair q(false, 10ms);
    ASSERT_TRUE(q.connect());
    q.run(100ms);
    q.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        return from == q.a.addr() && carries_live(d);
    };
    ASSERT_TRUE(q.a.send_live(MessageType::App, "never", q.now + 200ms));
    q.a.conn->close(CloseReason::LocalClose, q.now);
    const auto closed = q.now;
    ASSERT_TRUE(q.run_until([&] { return q.b.conn->dead(); }, 2s)) << "the close waited for good";
    EXPECT_LE(q.now - closed, 400ms);
    EXPECT_EQ(q.b.conn->close_reason(), CloseReason::PeerClosed);
}

// A connection nobody reads takes nothing in, live messages included.
TEST(UdpLiveTest, AConnectionNobodyReadsHoldsNoLiveMessages) {
    Pair p(false);
    ASSERT_TRUE(p.connect());
    p.b.conn->stop_reading();
    for (int i = 0; i < 10; ++i) send_live(p, std::string(i % 2 ? 100 : 20000, 's'), 1s);
    size_t peak = 0;
    p.run_until([&] {
        peak = (std::max)(peak, p.b.conn->buffered_bytes() + p.b.conn->held_bytes());
        return false;
    }, 500ms);
    EXPECT_EQ(peak, 0u);
    EXPECT_TRUE(p.b.messages.empty());
    EXPECT_TRUE(p.a.conn->flushed()) << "acknowledged and dropped is still acknowledged";
}

// ── Two connections, with repair symbols ────────────────────────────────────

namespace {

struct LossyLongPath {
    size_t sent = 0, arrived = 0, expired = 0;
    uint64_t repair_bytes = 0;
};

/// 30 frames a second of 15 KB over a 200 ms round trip that loses one live packet
/// in 25: no piece lost can be sent again in time for a 160 ms lifetime. Counted
/// once the window has grown to hold a frame, three seconds in.
LossyLongPath run_lossy_long_path(bool fec) {
    UdpConnectionConfig cfg;
    cfg.live_fec = fec;
    Pair p(false, 100ms, cfg, cfg);
    EXPECT_TRUE(p.connect());
    p.run(300ms);
    size_t live_packets = 0;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from != p.a.addr() || !carries_live(d)) return false;
        return ++live_packets % 25 == 0;
    };
    constexpr int kWarmUp = 90, kFrames = 300;
    PathStats before;
    for (int frame = 0; frame < kWarmUp + kFrames; ++frame) {
        if (frame == kWarmUp) before = p.a.conn->path_stats();
        send_live(p, std::to_string(frame) + "|" + std::string(15000, 'f'), 160ms);
        p.run(33ms);
    }
    p.run(1s);
    LossyLongPath out;
    out.sent = kFrames;
    for (const Message& m : p.b.messages)
        if (std::stoi(m.payload.substr(0, m.payload.find('|'))) >= kWarmUp) ++out.arrived;
    const PathStats after = p.a.conn->path_stats();
    out.expired      = after.live_expired - before.live_expired;
    out.repair_bytes = after.live_repair_bytes - before.live_repair_bytes;
    return out;
}

} // namespace

// What repair symbols are for: a path long enough that nothing lost can be sent
// again in time. Without them about every second frame of 13 packets is missing;
// with them all arrive — and the sender knows which did not.
TEST(UdpLiveTest, OnALongLossyPathRepairSymbolsDeliverWhatARepairCannot) {
    const LossyLongPath with = run_lossy_long_path(true);
    const LossyLongPath without = run_lossy_long_path(false);
    EXPECT_EQ(without.repair_bytes, 0u);
    EXPECT_LT(without.arrived, without.sent * 7 / 10);
    EXPECT_GT(with.arrived, with.sent * 95 / 100) << "repair bytes " << with.repair_bytes;
    EXPECT_GT(with.repair_bytes, 0u);
    EXPECT_LT(with.repair_bytes, with.sent * 15000 / 4) << "far more repairs than the loss needs";
    EXPECT_NEAR(double(with.expired), double(with.sent - with.arrived), 2)
        << "the sender's count of what was given up is wrong";
}

// A protected message goes out as fast as an unprotected one — its repairs are
// queued as it starts, which once read as a packet that sent nothing and held
// the rest of it back until the next acknowledgement — and a symbol to a frame,
// so a lost packet costs one symbol, not two.
TEST(UdpLiveTest, AProtectedMessageGoesOutWholeASymbolToAFrame) {
    Pair p(false, 20ms);
    ASSERT_TRUE(p.connect());
    p.run(100ms);
    size_t live_packets = 0;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        return from == p.a.addr() && carries_live(d) && ++live_packets % 40 == 0;
    };
    for (int frame = 0; frame < 60; ++frame) {
        send_live(p, std::string(15000, 'w'), 500ms);
        p.run(33ms);
    }
    std::vector<udp::Frame> frames;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from == p.a.addr())
            for (const auto& f : frames_of(d))
                if (f.type == udp::kLive || f.type == udp::kLiveRepair) frames.push_back(f);
        return false;
    };
    p.run(300ms);
    frames.clear();
    const uint64_t repairs = p.a.conn->path_stats().live_repair_bytes;
    ASSERT_GT(repairs, 0u) << "a path that lost one packet in 40 is believed clean";
    p.b.messages.clear();
    const auto sent = p.now;
    send_live(p, std::string(15000, 'n'), 500ms);
    ASSERT_TRUE(p.run_until([&] { return !p.b.messages.empty(); }, 1s));
    EXPECT_LE(p.now - sent, 25ms) << "the message waited for an acknowledgement";
    p.run(10ms);
    EXPECT_EQ(p.a.conn->path_stats().live_repair_bytes - repairs, 1155u) << "one repair, of 13 symbols";
    for (const udp::Frame& f : frames)
        if (f.type == udp::kLive) {
            EXPECT_EQ(f.live.offset % 1155, 0u);
            EXPECT_EQ(f.live.data.size(), (std::min<size_t>)(1155, f.live.size - f.live.offset));
        }
}

TEST(UdpLiveTest, APathThatLosesNothingCarriesNoRepairSymbols) {
    Pair p(false, 20ms);
    ASSERT_TRUE(p.connect());
    p.run(100ms);
    for (int frame = 0; frame < 100; ++frame) {
        send_live(p, std::string(15000, 'c'), 150ms);
        p.run(33ms);
    }
    p.run(300ms);
    EXPECT_EQ(p.b.messages.size(), 100u);
    EXPECT_EQ(p.a.conn->path_stats().live_repair_bytes, 0u);
}
