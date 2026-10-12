// Live messages on a datagram connection (udp_live.h): the sender and receiver
// on their own, then two connections in virtual time over a path a test controls.
// What has to hold: a live message arrives whole and once, or not at all; what is
// lost is repaired while the repair can still make it; what cannot make it is
// dropped — whole, and before it is sent if it never was — and nothing stale
// stands in front of what is fresh.

#include <gtest/gtest.h>

#include "udp_test_net.h"

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
};

/// Take what the sender offers next, in pieces of up to `max` bytes.
std::vector<Piece> drain(LiveSender& s, size_t max = 1000, size_t limit = 1000) {
    std::vector<Piece> out;
    LiveSender::Piece p;
    while (out.size() < limit && s.peek(p)) {
        const size_t len = (std::min<size_t>)(p.len, max);
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

// ── Two connections ─────────────────────────────────────────────────────────

namespace {

/// Queue a live message on a, and let it send what it may.
void send_live(Pair& p, const std::string& payload, Clock::duration lifetime, uint16_t channel = 0) {
    ASSERT_TRUE(p.a.send_live(MessageType::App, payload, p.now + lifetime, channel));
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
    Clock::time_point first_after = Clock::time_point::max();
    int first_frame = -1;
    for (const auto& [payload, at] : arrived_at) {
        if (at < outage_to || at >= first_after) continue;
        first_after = at;
        first_frame = std::stoi(payload.substr(0, payload.find('|')));
    }
    ASSERT_GE(first_frame, 0) << "nothing arrived after the outage";
    EXPECT_GE(sent_at[first_frame], outage_to - kLifetime);
    // The path's return is noticed within a probe timeout — the sender does not
    // back off while live messages wait (Recovery::set_impatient) — and what is
    // left after that is the controller rebuilding its window from the outage's
    // losses. A reliable lane took seconds here; backing off alone, 0.8 s.
    EXPECT_LE(first_after - outage_to, 250ms) << "the path came back but the frames did not";
    EXPECT_EQ(p.b.messages.size(), arrived_at.size()) << "a frame was delivered twice";
    EXPECT_GT(p.a.conn->path_stats().live_expired, 20u);
    EXPECT_GT(got.size(), 50u);
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
