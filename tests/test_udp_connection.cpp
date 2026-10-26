// A datagram connection (udp_connection.h) driven in virtual time over a path a
// test controls: the handshake, packet protection, the streams, recovery, flow
// control and the lifecycle. Congestion control against a path with a rate and a
// queue is test_udp_congestion.cpp's; the shared socket is test_transport_udp.cpp's.

#include <gtest/gtest.h>

#include "udp_test_net.h"

#include "librats/transport/udp_recovery.h"
#include "librats/transport/udp_streams.h"

#include <algorithm>
#include <deque>
#include <functional>
#include <map>
#include <set>

using namespace librats;
using namespace udptest;
using namespace std::chrono_literals;

// ── The handshake ───────────────────────────────────────────────────────────

TEST(UdpConnectionTest, NoiseBringsBothSidesUpAndMeasuresTheRoundTrip) {
    Pair p(true, 15ms);
    ASSERT_TRUE(p.connect());
    EXPECT_EQ(p.a.conn->remote_id(), p.id_b.id);
    EXPECT_EQ(p.b.conn->remote_id(), p.id_a.id);
    EXPECT_TRUE(p.a.conn->is_secure());
    EXPECT_EQ(p.b.conn->local_cid(), udp::paired_cid(p.a.conn->local_cid()));
    // Both ends have a round trip from the handshake alone, before any data.
    ASSERT_TRUE(p.a.conn->recovery().rtt().have_rtt);
    ASSERT_TRUE(p.b.conn->recovery().rtt().have_rtt);
    const double srtt_ms = std::chrono::duration<double, std::milli>(p.a.conn->recovery().rtt().srtt).count();
    EXPECT_NEAR(srtt_ms, 30, 3);
}

TEST(UdpConnectionTest, PlaintextNeedsNoThirdMessage) {
    Pair p(false);
    ASSERT_TRUE(p.connect());
    EXPECT_FALSE(p.a.conn->is_secure());
    p.send(MessageType::App, "hello");
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }));
    EXPECT_EQ(p.b.messages[0].payload, "hello");
}

TEST(UdpConnectionTest, ALostHandshakeMessageIsRepeated) {
    // Each of the three messages lost once, in turn.
    for (auto lose : {udp::LongType::Initial, udp::LongType::Handshake}) {
        for (int nth = 0; nth < 2; ++nth) {
            Pair p(true);
            int seen = 0;
            bool lost = false;
            p.net.hook = [&](Bytes& d, const Address&, const Address&) {
                if (lost || !is_handshake(d, lose)) return false;
                if (seen++ < nth) return false;
                lost = true;
                return true;
            };
            if (lose == udp::LongType::Initial && nth == 1) continue;   // only one Initial is sent
            ASSERT_TRUE(p.connect()) << "type " << int(lose) << " #" << nth;
            EXPECT_TRUE(lost);
            p.send(MessageType::App, "after");
            ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }));
        }
    }
}

TEST(UdpConnectionTest, DataThatOvertakesTheLastHandshakeMessageIsKept) {
    Pair p(true);
    // Hold the dialer's third message back and let what follows it overtake it.
    Bytes held;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from == p.a.addr() && held.empty() && is_handshake(d, udp::LongType::Handshake)) {
            held = d;
            return true;
        }
        return false;
    };
    p.dial();
    ASSERT_TRUE(p.run_until([&] { return p.a.established(); }));
    p.send(MessageType::App, "early");
    p.step();
    ASSERT_FALSE(held.empty());
    p.net.inject(p.a.addr(), p.b.addr(), held);
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }, 50ms))
        << "data that arrived before the keys was thrown away";
    EXPECT_EQ(p.a.conn->recovery().retransmits(), 0u);
}

TEST(UdpConnectionTest, AnUnansweredDialGivesUp) {
    Pair p(true);
    p.b.listening = false;
    size_t initials = 0;
    p.net.hook = [&](Bytes& d, const Address&, const Address&) {
        if (is_handshake(d, udp::LongType::Initial)) ++initials;
        return false;
    };
    p.dial();
    ASSERT_TRUE(p.run_until([&] { return p.a.conn->dead(); }, 10s));
    EXPECT_EQ(p.a.conn->close_reason(), CloseReason::ConnectFailed);
    EXPECT_EQ(initials, 3u) << "the default profile is three Initials";
    // 500 + 1000 + 2000 ms.
    EXPECT_GE(p.now - Clock::time_point{}, 3400ms);
    EXPECT_LE(p.now - Clock::time_point{}, 3700ms);
}

TEST(UdpConnectionTest, ThePunchProfileIsDenseAndFlat) {
    UdpConnectionConfig cfg;
    cfg.dial = DialProfile::punch();
    Pair p(true, 10ms, cfg);
    p.b.listening = false;
    std::vector<Clock::time_point> at;
    p.net.hook = [&](Bytes& d, const Address&, const Address&) {
        if (is_handshake(d, udp::LongType::Initial)) at.push_back(p.now);
        return false;
    };
    p.dial();
    ASSERT_TRUE(p.run_until([&] { return p.a.conn->dead(); }, 10s));
    ASSERT_EQ(at.size(), 8u);
    for (size_t i = 1; i < at.size(); ++i) EXPECT_EQ(at[i] - at[i - 1], 200ms) << i;
}

TEST(UdpConnectionTest, AnAbsurdDialProfileIsClamped) {
    UdpConnectionConfig cfg;
    cfg.dial = DialProfile{0, 1, false};
    Pair p(true, 10ms, cfg);
    p.b.listening = false;
    size_t initials = 0;
    p.net.hook = [&](Bytes& d, const Address&, const Address&) {
        if (is_handshake(d, udp::LongType::Initial)) ++initials;
        return false;
    };
    p.dial();
    ASSERT_TRUE(p.run_until([&] { return p.a.conn->dead(); }, 10s));
    EXPECT_EQ(initials, 1u) << "zero attempts is one";
    EXPECT_GE(p.now - Clock::time_point{}, 100ms) << "a 1 ms interval is the timer's floor";
}

// Before the dialer has shown it receives at its address, the responder answers
// with at most three times what it was sent — a forged source cannot turn it into
// an amplifier, however much it has queued.
TEST(UdpConnectionTest, AnUnprovenDialerGetsNoMoreThanThreeTimesWhatItSent) {
    Pair p(false);   // plaintext: the responder is established on the first message
    size_t from_b = 0;
    bool   first  = true;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from == p.b.addr()) { from_b += d.size(); return false; }
        if (first) { first = false; return false; }   // the Initial gets through
        return true;                                  // and nothing after it
    };
    p.dial();
    ASSERT_TRUE(p.run_until([&] { return p.b.established(); }));
    ASSERT_TRUE(p.b.send(MessageType::App, std::string(100000, 'x')));
    p.b.conn->flush(p.now);
    p.run(2s);
    EXPECT_GT(from_b, 0u);
    EXPECT_LE(from_b, UdpConnection::kAmplificationFactor * udp::kMaxDatagram);
}

// What an unproven dialer has earned can run out at any size, down to a bare
// header. Whatever is owed then — the reset token, a window update, data after a
// timeout wrote the flight off — must stay inside that room (and inside the
// datagram), and a keep-alive with no room to go must not leave its deadline in
// the past, where it would spin the reactor until the idle timeout.
TEST(UdpConnectionTest, AnUnprovenDialerCannotPushTheResponderPastItsRoomOrIntoASpin) {
    for (size_t first = 1; first <= 1300; first += 37) {
        Pair p(false);   // plaintext: the responder is established on the first message
        size_t from_b = 0, largest = 0;
        bool   initial = true;
        p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
            if (from == p.b.addr()) {
                from_b += d.size();
                largest = (std::max)(largest, d.size());
                return false;
            }
            if (initial) { initial = false; return false; }   // the Initial gets through
            return true;                                      // and nothing after it
        };
        p.dial();
        ASSERT_TRUE(p.run_until([&] { return p.b.established(); }));
        // A first message of varying size leaves a different remainder of the
        // allowance for everything after it.
        ASSERT_TRUE(p.b.send(MessageType::App, std::string(first, 'x')));
        ASSERT_TRUE(p.b.send(MessageType::Gossip, std::string(50000, 'y')));
        p.b.conn->flush(p.now);
        p.run(12s, 2ms);   // past the probes, a timeout and the keep-alive
        ASSERT_TRUE(p.b.conn && !p.b.conn->dead()) << first;
        EXPECT_LE(largest, udp::kMaxDatagram) << first;
        EXPECT_LE(from_b, UdpConnection::kAmplificationFactor * udp::kMaxDatagram) << first;
        const auto due = p.b.conn->next_deadline();
        ASSERT_TRUE(due.has_value());
        EXPECT_GT(*due, p.now) << "a deadline nothing can meet is due at once, forever (first=" << first << ")";
    }
}

// ── Messages ────────────────────────────────────────────────────────────────

TEST(UdpConnectionTest, CarriesMessagesBothWaysWholeWhateverTheirSize) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    const std::string big(300000, 'z');
    p.send(MessageType::App, "small", 7);
    p.send(MessageType::App, big, 7);
    ASSERT_TRUE(p.b.send(MessageType::Gossip, "back"));
    p.b.conn->flush(p.now);
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 2 && p.a.messages.size() == 1; }));
    EXPECT_EQ(p.b.messages[0].payload, "small");
    EXPECT_EQ(p.b.messages[0].channel, 7);
    EXPECT_EQ(p.b.messages[1].payload, big);
    EXPECT_EQ(p.a.messages[0].type, MessageType::Gossip);
}

TEST(UdpConnectionTest, OneLaneArrivesInTheOrderItWasSentWhateverThePath) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    // Every third datagram lost, once, and the rest reordered in pairs.
    size_t n = 0;
    Bytes  delayed;
    p.net.hook = [&](Bytes& d, const Address& from, const Address& to) {
        if (from != p.a.addr()) return false;
        ++n;
        if (n % 3 == 0 && n < 300) return true;
        if (n % 2 == 1 && delayed.empty()) { delayed = d; return true; }
        if (!delayed.empty()) {
            p.net.inject(from, to, d);
            p.net.inject(from, to, delayed);
            delayed.clear();
            return true;
        }
        return false;
    };
    // An application's channels are one lane: their order holds across them too.
    for (int i = 0; i < 200; ++i)
        p.send(MessageType::App, std::to_string(i) + std::string(static_cast<size_t>(i * 37 % 3000), '.'),
               static_cast<uint16_t>(i % 3));
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 200; }, 20s));
    for (int i = 0; i < 200; ++i)
        EXPECT_EQ(p.b.messages[static_cast<size_t>(i)].payload.substr(0, std::to_string(i).size()),
                  std::to_string(i)) << i;
}

TEST(UdpConnectionTest, DuplicatedDatagramsAreDeliveredOnce) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    p.net.hook = [&](Bytes& d, const Address& from, const Address& to) {
        p.net.inject(from, to, d);
        return false;
    };
    for (int i = 0; i < 50; ++i) p.send(MessageType::App, std::string(2000, char('a' + i % 26)));
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() >= 50; }));
    p.run(200ms);
    EXPECT_EQ(p.b.messages.size(), 50u);
}

// The point of separate streams: a hole in one lane holds up nothing in another.
// Over a single byte stream the ping would wait for the repair of the file.
TEST(UdpConnectionTest, AHoleInOneLaneDoesNotHoldUpAnother) {
    Pair p(false, 25ms);
    ASSERT_TRUE(p.connect());
    // A warmed-up connection, so the window has room for the ping as well as for
    // the lost file: this is about the receiver's lanes, not the sender's window.
    p.send(MessageType::App, std::string(300000, 'w'));
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }));
    p.run(100ms);
    p.b.messages.clear();
    // Every packet carrying the file and nothing else is lost for the first 200 ms.
    const auto until = p.now + 200ms;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        return from == p.a.addr() && p.now < until && carries_stream(d, MessageType::FileChunk) &&
               !carries_stream(d, MessageType::Ping);
    };
    p.send(MessageType::FileChunk, std::string(20000, 'f'));
    p.run(5ms);
    p.send(MessageType::Ping, "ping");
    const auto sent = p.now;
    ASSERT_TRUE(p.run_until([&] {
        return std::any_of(p.b.messages.begin(), p.b.messages.end(),
                           [](const Message& m) { return m.type == MessageType::Ping; });
    }, 1s));
    EXPECT_LT(p.now - sent, 40ms) << "the ping waited for the file";
    EXPECT_TRUE(std::none_of(p.b.messages.begin(), p.b.messages.end(),
                             [](const Message& m) { return m.type == MessageType::FileChunk; }))
        << "the test lost nothing";
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 2; }, 3s)) << "the file never made it";
}

// Priority is decided per packet, so a ping queued behind megabytes of file goes
// out next, not after them.
TEST(UdpConnectionTest, AnUrgentMessageOvertakesABulkBacklog) {
    Pair p(true, 20ms);
    ASSERT_TRUE(p.connect());
    for (int i = 0; i < 64; ++i) p.send(MessageType::FileChunk, std::string(64 * 1024, 'f'));
    p.run(100ms);
    ASSERT_GT(p.a.conn->queued_bytes(), 1u << 20) << "no backlog to overtake";
    p.send(MessageType::Ping, "ping");
    const auto sent = p.now;
    ASSERT_TRUE(p.run_until([&] {
        return std::any_of(p.b.messages.begin(), p.b.messages.end(),
                           [](const Message& m) { return m.type == MessageType::Ping; });
    }, 2s));
    EXPECT_LE(p.now - sent, 30ms) << "the ping waited behind the backlog";
    EXPECT_LT(p.b.messages.size(), 65u);
}

// ── Recovery ────────────────────────────────────────────────────────────────

TEST(UdpConnectionTest, WhatIsLostIsSentAgainInNewPackets) {
    Pair p(false);
    ASSERT_TRUE(p.connect());
    size_t lost = 0;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from != p.a.addr()) return false;
        if (carries_stream(d, MessageType::App) && lost < 3 && (p.a.sent % 4) == 0) { ++lost; return true; }
        return false;
    };
    for (int i = 0; i < 40; ++i) p.send(MessageType::App, std::string(3000, char('a' + i % 26)));
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 40; }));
    ASSERT_EQ(lost, 3u);
    EXPECT_GE(p.a.conn->recovery().retransmits(), 3u);
    for (size_t i = 0; i < 40; ++i) EXPECT_EQ(p.b.messages[i].payload, std::string(3000, char('a' + i % 26)));
}

TEST(UdpConnectionTest, ALostTailIsProbedRatherThanTimedOut) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(200ms);   // settle the estimate
    bool dropped = false;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (dropped || from != p.a.addr() || !is_short(d)) return false;
        dropped = true;
        return true;
    };
    const auto rto_events = p.a.conn->recovery().congestion_events();
    p.send(MessageType::App, "the last word");
    const auto sent = p.now;
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }, 2s));
    ASSERT_TRUE(dropped);
    // A probe goes after a round trip and the ack delay — well inside the 100 ms
    // a timeout could not have come sooner than.
    EXPECT_LT(p.now - sent, 100ms);
    EXPECT_GE(p.a.conn->recovery().retransmits(), 1u);
    p.run(100ms);
    EXPECT_LE(p.a.conn->recovery().congestion_events(), rto_events + 1);
}

TEST(UdpConnectionTest, OneLossEpisodeIsOneReduction) {
    Pair p(false, 20ms);
    ASSERT_TRUE(p.connect());
    for (int i = 0; i < 16; ++i) p.send(MessageType::App, std::string(64 * 1024, 'x'));
    p.run(300ms);
    const uint32_t before = p.a.conn->recovery().congestion_events();
    // Three packets in a row lost in the middle of a window.
    int to_drop = 3;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (to_drop > 0 && from == p.a.addr() && carries_stream(d, MessageType::App)) { --to_drop; return true; }
        return false;
    };
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 16; }, 10s));
    EXPECT_EQ(p.a.conn->recovery().congestion_events(), before + 1);
}

TEST(UdpConnectionTest, ATimeoutWritesOffTheFlightAndTheTransferRecovers) {
    Pair p(false, 10ms);
    ASSERT_TRUE(p.connect());
    for (int i = 0; i < 32; ++i) p.send(MessageType::App, std::string(32 * 1024, 'x'));
    p.run(30ms);
    p.net.blackout = true;
    p.run(1500ms);
    EXPECT_GT(p.a.conn->recovery().congestion_events(), 0u) << "a whole second of silence was not a timeout";
    p.net.blackout = false;
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 32; }, 20s));
    EXPECT_TRUE(p.a.conn->established());
}

TEST(UdpConnectionTest, AnAbsurdAckDelayCannotBreakTheRoundTripEstimate) {
    // The delay field is a 62-bit varint the peer fills in. Multiplied out before
    // it was capped, some values overflowed into a negative delay, which the
    // estimator then added to the sample (and 2^57 overflowed it outright).
    struct NullSink final : udp::FrameSink {
        void frames_acked(const RingBuffer<udp::SentFrame>&, size_t, size_t) override {}
        void frames_lost(const RingBuffer<udp::SentFrame>&, size_t, size_t) override {}
        bool repairs_pending() const override { return false; }
    } sink;
    for (const uint64_t delay : {uint64_t{1} << 57, udp::kMaxVarint, uint64_t{1152921504606847}}) {
        Clock::time_point now{};
        udp::Recovery r(CongestionAlgorithm::Reno, now, 1);
        const auto exchange = [&](uint64_t ack_delay) {
            const uint64_t pn = r.next_pn();
            r.add_frame(udp::SentFrame{udp::SentFrame::Ping});
            r.on_packet_sent(now, 100, /*ack_eliciting=*/true, false, false, false);
            now += 50ms;
            udp::AckFrame ack;
            ack.largest = pn;
            ack.delay   = ack_delay;
            ASSERT_TRUE(r.on_ack(ack, now, sink));
        };
        exchange(0);   // the first sample takes no delay off
        exchange(delay);
        exchange(delay);
        SCOPED_TRACE(delay);
        EXPECT_GT(r.rtt().srtt, Clock::duration::zero());
        EXPECT_LE(r.rtt().srtt, Clock::duration(50ms));
        EXPECT_LT(r.rtt().rttvar, Clock::duration(50ms));
    }
}

TEST(UdpConnectionTest, APacketOfDataIsAcknowledgedLateAndTwoAtOnce) {
    Pair p(false, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(500ms);
    std::vector<Clock::time_point> acks;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from != p.b.addr()) return false;
        for (const auto& f : frames_of(d))
            if (f.type == udp::kAck) acks.push_back(p.now);
        return false;
    };
    p.send(MessageType::App, "one");
    const auto sent = p.now;
    ASSERT_TRUE(p.run_until([&] { return !acks.empty(); }, 1s));
    // One packet waits out the delayed-ack timer for company.
    EXPECT_GE(acks.front() - sent, 10ms + UdpConnection::kDelayedAck);

    acks.clear();
    p.run(200ms);
    acks.clear();
    p.a.send(MessageType::App, std::string(1500, 'a'));   // two packets
    p.a.conn->flush(p.now);
    const auto two = p.now;
    ASSERT_TRUE(p.run_until([&] { return !acks.empty(); }, 1s));
    EXPECT_LT(acks.front() - two, 10ms + UdpConnection::kDelayedAck) << "the second packet did not force an ACK";
}

TEST(UdpConnectionTest, ADamagedPacketIsDroppedAndRepaired) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    bool damaged = false;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (!damaged && from == p.a.addr() && is_short(d) && d.size() > 200) {
            d[d.size() / 2] ^= 0x10;
            damaged = true;
        }
        return false;
    };
    p.send(MessageType::App, std::string(5000, 'q'));
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }));
    EXPECT_TRUE(damaged);
    EXPECT_TRUE(p.b.conn->established()) << "one bad packet broke the connection";
}

// A packet number travels truncated and is read against the highest one the
// receiver has seen. The first packet of a burst after a quiet spell — a keyframe's
// — is sent with everything before it acknowledged; held back on the path while
// the burst overtakes it, it lands hundreds of numbers behind. It is still itself:
// under a cipher, not a packet that fails to open; in plaintext, not a later one,
// whose acknowledgement would then vouch for data that never came (the transfer
// stalls) or for a packet never sent (a protocol error).
TEST(UdpConnectionTest, APacketOvertakenByAWholeBurstIsReadAsItself) {
    for (const bool noise : {true, false}) {
        SCOPED_TRACE(noise ? "noise" : "plaintext");
        Pair p(noise, 10ms);
        ASSERT_TRUE(p.connect());
        // A window that lets hundreds of packets go at once.
        p.send(MessageType::App, std::string(4 << 20, 'w'));
        ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }));
        p.run(100ms);

        Bytes  held;
        size_t behind = 0;
        p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
            if (from != p.a.addr() || !is_short(d)) return false;
            if (held.empty()) {
                held = d;
                return true;
            }
            ++behind;
            return false;
        };
        p.send(MessageType::App, std::string(600000, 'k'));
        ASSERT_TRUE(p.run_until([&] { return behind >= 200; }, 1s));
        p.net.hook = nullptr;
        p.net.inject(p.a.addr(), p.b.addr(), held);
        ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 2 || p.a.conn->dead(); }))
            << "the late packet was taken for another: what that one carried never came";
        EXPECT_FALSE(p.a.conn->dead()) << "the late packet was acknowledged as one never sent";
        EXPECT_EQ(p.a.conn->recovery().retransmits(), 0u) << "the late packet was not taken in";
    }
}

// A path that holds packets back while those behind them overtake. The sender
// gives each one up for lost and sends its data again; when it comes after all,
// the receiver takes it in and acknowledges it, and that is how the sender
// learns it was only late — the window, BBR and FEC then leave it out of the
// path's loss. Taken for a duplicate instead, it stayed a loss: so it was with
// more gaps open behind it than one ACK names, ...
TEST(UdpConnectionTest, APacketLateBehindManyGapsIsTakenIn) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    // A window that lets hundreds of packets go at once.
    p.send(MessageType::App, std::string(4 << 20, 'w'));
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }));
    p.run(100ms);

    std::vector<Bytes> held;
    size_t passed = 0;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from != p.a.addr() || !is_short(d) || held.size() == 2 * udp::kMaxAckRanges) return false;
        if (passed++ % 3 != 0) return false;
        held.push_back(d);
        return true;
    };
    p.send(MessageType::App, std::string(1 << 20, 'k'));
    ASSERT_TRUE(p.run_until([&] { return held.size() == 2 * udp::kMaxAckRanges; }, 1s));
    p.net.hook = nullptr;
    // Every other one is lost for good, so the gaps stay open behind those that
    // do come: more than one ACK has room to name.
    p.run(15ms);
    uint64_t late = 0;
    for (size_t i = 0; i < held.size(); i += 2) {
        late += held[i].size();
        p.net.inject(p.a.addr(), p.b.addr(), held[i]);
    }
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 2; }));
    p.run(100ms);
    EXPECT_EQ(p.a.conn->recovery().spurious(), late) << "a late packet was taken for a duplicate";
}

// ... or with the sender already holding an ACK that named the packets around it.
TEST(UdpConnectionTest, APacketLatePastAnAcknowledgedAckIsTakenIn) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(100ms);

    Bytes held;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from != p.a.addr() || !is_short(d) || !held.empty()) return false;
        held = d;
        return true;
    };
    // Both ways, so each side's ACKs ride on data the other acknowledges.
    for (int i = 0; i < 60; ++i) {
        ASSERT_TRUE(p.a.send(MessageType::App, std::string(1000, 'a')));
        ASSERT_TRUE(p.b.send(MessageType::App, std::string(1000, 'b')));
        p.a.conn->flush(p.now);
        p.b.conn->flush(p.now);
        p.step();
    }
    ASSERT_FALSE(held.empty());
    p.net.hook = nullptr;
    p.net.inject(p.a.addr(), p.b.addr(), held);
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 60; }));
    p.run(100ms);
    EXPECT_EQ(p.a.conn->recovery().spurious(), held.size()) << "the late packet was taken for a duplicate";
}

// Header protection: the packet number a datagram carries is not readable on the
// path — consecutive packets do not show consecutive numbers.
TEST(UdpConnectionTest, ThePathCannotReadPacketNumbers) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    std::vector<uint8_t> first_pn_byte;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from == p.a.addr() && is_short(d)) first_pn_byte.push_back(d[udp::kShortHeaderSize]);
        return false;
    };
    for (int i = 0; i < 64; ++i) p.send(MessageType::App, std::string(1100, 'n'));
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 64; }));
    ASSERT_GT(first_pn_byte.size(), 50u);
    size_t sequential = 0;
    for (size_t i = 1; i < first_pn_byte.size(); ++i)
        if (static_cast<uint8_t>(first_pn_byte[i - 1] + 1) == first_pn_byte[i]) ++sequential;
    EXPECT_LT(sequential, first_pn_byte.size() / 8) << "packet numbers travel in the clear";
}

// ── Flow control ────────────────────────────────────────────────────────────

TEST(UdpConnectionTest, AWindowTooSmallForThePathGrowsAndShrinksBackAfterSilence) {
    Pair p(false, 50ms);
    ASSERT_TRUE(p.connect());
    p.b.count_only = true;
    for (int i = 0; i < 160; ++i) p.send(MessageType::App, std::string(64 * 1024, 'w'));
    ASSERT_TRUE(p.run_until([&] { return p.b.messages_in == 160; }, 60s));
    EXPECT_GT(p.b.conn->receive_window(), UdpConnection::kInitialWindow)
        << "a sender held back by the window never made it grow";
    p.run(UdpConnection::kWindowDecay + 1s, 10ms);
    EXPECT_EQ(p.b.conn->receive_window(), UdpConnection::kInitialWindow);
}

TEST(UdpConnectionTest, TheSharedBudgetBoundsWhatHolesCanHold) {
    udp::UdpReceiveBudget budget(256 * 1024);
    UdpConnectionConfig b_cfg;
    b_cfg.budget = &budget;
    Pair p(false, 20ms, {}, b_cfg);
    ASSERT_TRUE(p.connect());
    p.b.count_only = true;
    // The first packet of the file is lost for a while, so everything behind it
    // has to be held.
    const auto until = p.now + 400ms;
    bool first = true;
    size_t peak = 0;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (from != p.a.addr() || !carries_stream(d, MessageType::App)) return false;
        if (first) { first = false; return true; }
        for (const auto& f : frames_of(d))
            if (f.type == udp::kStream && f.stream.offset == 0 && p.now < until) return true;
        return false;
    };
    for (int i = 0; i < 64; ++i) p.send(MessageType::App, std::string(32 * 1024, 'h'));
    ASSERT_TRUE(p.run_until([&] {
        peak = (std::max)(peak, budget.used());
        return p.b.messages_in == 64;
    }, 30s));
    EXPECT_LE(peak, (std::max)(budget.limit(), udp::UdpReceiveBudget::kGuaranteed) + udp::kMaxDatagram + 96);
    EXPECT_EQ(budget.used(), 0u) << "held bytes were never released";
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

// Flow control counts a byte as consumed once it is in order, but a message is
// delivered only whole, so every stream can hold one unfinished message. Several
// large ones on streams that take turns are legitimate, and the sender keeps the
// receiver's count of them under max_unfinished by finishing the largest first —
// everything still arrives, nothing is refused.
TEST(UdpConnectionTest, LargeMessagesOnManyLanesStayUnderTheUnfinishedLimit) {
    UdpConnectionConfig cfg;
    cfg.max_unfinished = 64 * 1024;
    Pair p(false, 10ms, cfg, cfg);
    ASSERT_TRUE(p.connect());
    p.b.count_only = true;
    // Same priority, so a packet at a time each: all four would be under way at once.
    for (MessageType t : {MessageType::App, MessageType::Gossip, MessageType::Typed, MessageType::Pex})
        p.send(t, std::string(300 * 1024, 'm'));
    ASSERT_TRUE(p.run_until([&] { return p.b.messages_in == 4 || p.b.conn->dead(); }, 30s));
    EXPECT_FALSE(p.b.conn->dead()) << "a sender keeping to the limit was refused";
    EXPECT_EQ(p.b.messages_in, 4u);
}

// ...and a peer that does not keep to it is a protocol error, not memory: without
// the limit it could start a maximal message on each of 255 streams and finish
// none, ~16 GiB that neither the window nor the receive budget counts.
TEST(UdpConnectionTest, APeerLeavingTooMuchUnfinishedIsCutOff) {
    UdpConnectionConfig sender;
    sender.max_unfinished = SIZE_MAX;   // keeps to nothing
    UdpConnectionConfig receiver;
    receiver.max_unfinished = 64 * 1024;
    Pair p(false, 10ms, sender, receiver);
    ASSERT_TRUE(p.connect());
    p.b.count_only = true;
    for (uint8_t t = 20; t < 30; ++t) p.send(static_cast<MessageType>(t), std::string(300 * 1024, 'u'));
    ASSERT_TRUE(p.run_until([&] { return p.b.conn->dead(); }, 10s)) << "the receiver kept holding";
    EXPECT_EQ(p.b.conn->close_reason(), CloseReason::ProtocolError);
    EXPECT_EQ(p.b.messages_in, 0u);
}

// A message announced past the block ceiling is a protocol error — caught from its
// length, which on a connection nobody is reading yet is all there is to check.
TEST(UdpConnectionTest, AnOversizedMessageIsAProtocolError) {
    Pair p(false);
    ASSERT_TRUE(p.connect());
    // Rewrite the first message's length to one past the ceiling (plaintext: the
    // packet is readable and unsealed).
    bool rewritten = false;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (rewritten || from != p.a.addr() || !is_short(d)) return false;
        for (const auto& f : frames_of(d)) {
            if (f.type != udp::kStream || f.stream.offset != 0 || f.stream.data.size() < 8) continue;
            const size_t at = static_cast<size_t>(f.stream.data.data() - d.data());
            udp::put_varint(d.data() + at, uint64_t{framer::kMaxBlockSize} + 1);
            rewritten = true;
        }
        return false;
    };
    // Varint widths must match: a 70000-byte message also has a 4-byte length.
    p.send(MessageType::App, std::string(70000, 'o'));
    ASSERT_TRUE(p.run_until([&] { return p.b.conn->dead(); }, 5s));
    EXPECT_TRUE(rewritten);
    EXPECT_EQ(p.b.conn->close_reason(), CloseReason::ProtocolError);
    EXPECT_TRUE(p.b.messages.empty());
}

// A connection that only lingers to hand over what it owes has nobody reading it.
// What the peer still sends is acknowledged and dropped — not kept in an inbox
// that grows for as long as the linger lasts — and no more window is granted.
TEST(UdpConnectionTest, AConnectionNobodyReadsHoldsNothingAndGrantsNoMoreWindow) {
    Pair p(false);
    ASSERT_TRUE(p.connect());
    p.b.conn->stop_reading();
    const size_t total = 8 * 1024 * 1024;
    for (int i = 0; i < 8; ++i) p.send(MessageType::App, std::string(total / 8, 's'));
    size_t peak = 0;
    p.run_until([&] {
        peak = (std::max)(peak, p.b.conn->buffered_bytes() + p.b.conn->held_bytes());
        return false;
    }, 3s);
    EXPECT_FALSE(p.b.conn->dead());
    EXPECT_EQ(peak, 0u) << "a connection nobody reads kept what arrived";
    EXPECT_TRUE(p.b.messages.empty());
    // Stopped at the window it already had: the rest is still waiting at a.
    EXPECT_GE(p.a.conn->queued_bytes(), total - 2 * UdpConnection::kInitialWindow);
}

TEST(UdpConnectionTest, AnOrderlyCloseDeliversEverythingFirst) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    p.send(MessageType::App, std::string(50000, 'l'));
    p.a.conn->close(CloseReason::LocalClose, p.now);
    ASSERT_TRUE(p.run_until([&] { return p.b.conn->dead(); }));
    ASSERT_EQ(p.b.messages.size(), 1u) << "the last message was lost to the close";
    EXPECT_EQ(p.b.conn->close_reason(), CloseReason::PeerClosed);
    EXPECT_TRUE(p.a.conn->dead());
    EXPECT_EQ(p.a.conn->close_reason(), CloseReason::LocalClose);
}

TEST(UdpConnectionTest, AnAbortTellsThePeerAtOnce) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    p.a.conn->abort(p.now);
    ASSERT_TRUE(p.run_until([&] { return p.b.conn->dead(); }, 100ms));
    EXPECT_EQ(p.b.conn->close_reason(), CloseReason::PeerReset);
}

TEST(UdpConnectionTest, ThePathSaysWhenThePeerWasLastHeard) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(1s);  // keep-alives only
    const auto heard = p.a.conn->path_stats().heard_at;
    EXPECT_GT(heard, p.now - UdpConnection::kKeepAlive - 100ms) << "keep-alives are heard";
    EXPECT_LE(heard, p.now);

    EXPECT_EQ(p.a.conn->path_stats().unanswered_since, UdpConnection::Clock::time_point{})
        << "nothing owed an answer";

    p.net.blackout = true;
    p.run(20s);
    EXPECT_LE(p.a.conn->path_stats().heard_at, heard + 100ms) << "nothing heard since";
    EXPECT_TRUE(p.a.conn->established()) << "quiet, not yet given up on";
    EXPECT_EQ(p.a.conn->path_stats().unanswered_since, UdpConnection::Clock::time_point{})
        << "a peer we ask nothing of may simply have nothing to say";

    const auto asked = p.now;
    p.send(MessageType::App, "anyone there?");
    p.run(3s);
    EXPECT_GE(p.a.conn->path_stats().unanswered_since, asked);
    EXPECT_LE(p.a.conn->path_stats().unanswered_since, asked + 100ms) << "the first unanswered";

    p.net.blackout = false;
    ASSERT_TRUE(p.run_until([&] { return p.a.conn->path_stats().heard_at > asked; }, 5s));
    EXPECT_EQ(p.a.conn->path_stats().unanswered_since, UdpConnection::Clock::time_point{})
        << "answered";
}

TEST(UdpConnectionTest, ANodeStoppingSaysAnOrderlyGoodbyeAtOnce) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    p.send(MessageType::App, std::string(50000, 'l'));
    p.a.conn->close(CloseReason::ReactorShutdown, p.now);
    EXPECT_TRUE(p.a.conn->dead()) << "nothing queued is waited for";
    ASSERT_TRUE(p.run_until([&] { return p.b.conn->dead(); }, 100ms));
    EXPECT_EQ(p.b.conn->close_reason(), CloseReason::PeerClosed) << "a leaving, not a failure";
}

TEST(UdpConnectionTest, AStatelessResetEndsTheConnection) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    p.run(100ms);   // the reset tokens are exchanged
    // What b's node would send for a packet to b's id after forgetting it.
    Bytes reset(udp::kMinShortPacket + 4, 0x33);
    reset[0] = 0x41;
    const udp::Cid to = p.a.conn->local_cid();
    for (int i = 0; i < 8; ++i) reset[1 + i] = static_cast<uint8_t>(to >> (56 - 8 * i));
    Bytes wrong = reset;
    p.b.reset_token(p.b.conn->local_cid(), reset.data() + reset.size() - udp::kResetTokenSize);

    p.net.inject(p.b.addr(), p.a.addr(), wrong);
    p.run(20ms);
    EXPECT_TRUE(p.a.conn->established()) << "a datagram without the token reset the connection";
    p.net.inject(p.b.addr(), p.a.addr(), reset);
    ASSERT_TRUE(p.run_until([&] { return p.a.conn->dead(); }, 100ms));
    EXPECT_EQ(p.a.conn->close_reason(), CloseReason::PeerReset);
}

// Under a session that appends no tag, a packet's last bytes are its last frame's,
// and a RESET_TOKEN frame sent last — as a repeat of a lost one goes — ends with
// exactly the token: a stateless reset by its tail. Only a datagram that is not a
// packet of ours is one.
TEST(UdpConnectionTest, APacketEndingInTheResetTokenIsNoReset) {
    Pair p(false);
    ASSERT_TRUE(p.connect());
    p.run(100ms);   // the reset tokens are exchanged
    uint8_t token[udp::kResetTokenSize];
    p.b.reset_token(p.b.conn->local_cid(), token);

    // b's next packet to a, its token appended as the last frame.
    Bytes sent;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (!sent.empty() || from != p.b.addr() || !is_short(d)) return false;
        const size_t at = d.size();
        d.resize(at + 1 + udp::kResetTokenSize);
        udp::put_reset_token(d.data() + at, token);
        sent = d;
        return false;
    };
    p.send(MessageType::App, "ping");   // b answers it
    ASSERT_TRUE(p.run_until([&] { return !sent.empty(); }, 200ms));
    p.run(50ms);
    EXPECT_TRUE(p.a.conn->established()) << "a packet of ours ending in the token reset the connection";
    // The same bytes again are a duplicate, no packet of ours: a reset.
    p.net.inject(p.b.addr(), p.a.addr(), sent);
    ASSERT_TRUE(p.run_until([&] { return p.a.conn->dead(); }, 100ms));
    EXPECT_EQ(p.a.conn->close_reason(), CloseReason::PeerReset);
}

TEST(UdpConnectionTest, KeepAliveBreaksASilenceAndASilentPeerTimesOut) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    const size_t sent = p.a.sent;
    p.run(UdpConnection::kKeepAlive + 1s, 10ms);
    EXPECT_GT(p.a.sent, sent) << "nothing went out in a long silence";
    EXPECT_TRUE(p.a.conn->established());

    p.net.blackout = true;
    p.run(UdpConnection::kIdleTimeout + 1s, 50ms);
    ASSERT_TRUE(p.a.conn->dead());
    EXPECT_EQ(p.a.conn->close_reason(), CloseReason::IdleTimeout);
}

TEST(UdpConnectionTest, AnIdleConnectionSleepsUntilItsKeepAlive) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    p.run(1s);
    const auto due = p.a.conn->next_deadline();
    ASSERT_TRUE(due);
    EXPECT_GE(*due - p.now, 8s) << "an idle connection asked to be woken early";
    p.send(MessageType::App, "wake");
    const auto armed = p.a.conn->next_deadline();
    ASSERT_TRUE(armed);
    EXPECT_LE(*armed - p.now, udp::Recovery::kInitialRto) << "a packet in flight has no loss timer";
}

// ── Migration ───────────────────────────────────────────────────────────────

namespace {

const Address kRebound{*IpAddress::parse("10.0.0.1"), 4444};   // a's NAT, another port
const Address kElsewhere{*IpAddress::parse("10.0.0.9"), 1111};   // a's new network
const Address kForger{*IpAddress::parse("10.6.6.6"), 6666};

/// Both ends sending to each other, so both have something in flight when the
/// path changes: a's 32 messages to b, b's 32 to a.
void start_both_ways(Pair& p) {
    for (int i = 0; i < 32; ++i) {
        ASSERT_TRUE(p.a.send(MessageType::App, std::string(16 * 1024, 'a')));
        ASSERT_TRUE(p.b.send(MessageType::App, std::string(16 * 1024, 'b')));
    }
    p.a.conn->flush(p.now);
    p.b.conn->flush(p.now);
}

bool all_arrived(const Pair& p) { return p.a.messages.size() == 32 && p.b.messages.size() == 32; }

} // namespace

// A NAT hands a's socket a new port mid-transfer. b follows a there, a proves it
// receives there, and the transfer goes on — the same path, so what was learnt
// of it stands.
TEST(UdpConnectionTest, APeerWhosePortChangesIsFollowedAndKeepsWhatWasLearnt) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    start_both_ways(p);
    p.run(30ms);
    const uint64_t a_off = p.a.conn->recovery().written_off(), b_off = p.b.conn->recovery().written_off();
    p.net.map(p.a, kRebound);

    ASSERT_TRUE(p.run_until([&] { return all_arrived(p); }, 10s));
    EXPECT_EQ(p.b.conn->remote(), kRebound);
    EXPECT_EQ(p.b.moves, 1u);
    EXPECT_TRUE(p.a.conn->take_moved()) << "a was never told it is seen somewhere new";
    EXPECT_TRUE(p.b.conn->take_moved());
    EXPECT_EQ(p.a.conn->recovery().written_off(), a_off) << "a port alone started a's path again";
    EXPECT_EQ(p.b.conn->recovery().written_off(), b_off) << "a port alone started b's path again";
}

// a goes from one network to another: a new IP is another path. Once a is
// proven there, both ends start their estimate of it again, and what was in
// flight on the old one goes again on the new.
TEST(UdpConnectionTest, APeerOnAnotherNetworkIsFollowedAndThePathStartsAgain) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    start_both_ways(p);
    p.run(30ms);
    const uint64_t a_off = p.a.conn->recovery().written_off(), b_off = p.b.conn->recovery().written_off();
    p.net.map(p.a, kElsewhere);

    ASSERT_TRUE(p.run_until([&] { return all_arrived(p); }, 10s));
    EXPECT_EQ(p.b.conn->remote(), kElsewhere);
    EXPECT_EQ(p.b.moves, 1u);
    EXPECT_GT(p.a.conn->recovery().written_off(), a_off) << "a kept its estimate of the old path";
    EXPECT_GT(p.b.conn->recovery().written_off(), b_off) << "b kept its estimate of the old path";
    for (const auto& m : p.a.messages) EXPECT_EQ(m.payload, std::string(16 * 1024, 'b'));
    for (const auto& m : p.b.messages) EXPECT_EQ(m.payload, std::string(16 * 1024, 'a'));
}

// Until the new address answers its challenge, b sends there no more than three
// times what came from there: a forged move cannot aim b's transfer at anyone.
TEST(UdpConnectionTest, AnUnprovenAddressGetsNoMoreThanThreeTimesWhatCameFromIt) {
    Pair p(false, 10ms);   // plaintext, so the hook can see the frames
    ASSERT_TRUE(p.connect());
    for (int i = 0; i < 64; ++i) ASSERT_TRUE(p.b.send(MessageType::App, std::string(16 * 1024, 'b')));
    p.b.conn->flush(p.now);
    p.run(30ms);

    size_t to_new = 0, from_new = 0;
    bool answer = false, over = false;
    p.net.hook = [&](Bytes& d, const Address& from, const Address& to) {
        if (from == kRebound) {
            for (const auto& f : frames_of(d))
                if (f.type == udp::kPathResponse && !answer) return true;   // held back
            from_new += d.size();
        }
        if (to == kRebound) {
            to_new += d.size();
            if (!answer && to_new > UdpConnection::kAmplificationFactor * from_new) over = true;
        }
        return false;
    };
    p.net.map(p.a, kRebound);
    p.run(300ms);
    EXPECT_GT(to_new, 0u);
    EXPECT_FALSE(over) << to_new << " bytes went to an address that sent " << from_new;
    EXPECT_EQ(p.b.moves, 0u);

    answer = true;   // the next challenge is answered
    ASSERT_TRUE(p.run_until([&] { return p.a.messages.size() == 64; }, 10s));
    EXPECT_EQ(p.b.moves, 1u);
}

// Someone on the path sends a copy of a's newest packet from elsewhere, ahead of
// it. b goes there for a moment — the copy opened under its keys — but a's next
// packet brings it back, and nothing of the transfer is lost.
TEST(UdpConnectionTest, ACopyFromElsewhereMovesTheConnectionOnlyUntilThePeerSpeaks) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    for (int i = 0; i < 32; ++i) ASSERT_TRUE(p.a.send(MessageType::App, std::string(16 * 1024, 'a')));
    p.a.conn->flush(p.now);
    p.run(30ms);

    bool copied = false;
    size_t to_forger = 0;
    p.net.hook = [&](Bytes& d, const Address& from, const Address& to) {
        if (to == kForger) to_forger += d.size();
        if (!copied && from == p.a.addr() && is_short(d)) {
            copied = true;
            p.net.inject(kForger, to, d);   // queued first, so it arrives first
        }
        return false;
    };
    ASSERT_TRUE(p.run_until([&] { return copied; }, 1s));
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 32; }, 10s));
    EXPECT_EQ(p.b.conn->remote(), p.a.addr());
    EXPECT_EQ(p.b.moves, 0u);
    EXPECT_LE(to_forger, UdpConnection::kAmplificationFactor * udp::kMaxDatagram);
}

// The same copy, and then a goes quiet: the challenge goes unanswered, and b goes
// back to where a was proven rather than staying where the copy came from.
TEST(UdpConnectionTest, AnUnansweredChallengeMovesTheConnectionBack) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(100ms);
    bool copied = false, quiet = false;
    p.net.hook = [&](Bytes& d, const Address& from, const Address& to) {
        if (from == p.a.addr() && quiet) return true;
        if (!copied && from == p.a.addr() && is_short(d)) {
            copied = true;
            quiet  = true;
            p.net.inject(kForger, to, d);
            return true;   // and the original never arrives
        }
        return false;
    };
    p.send(MessageType::App, "x");
    ASSERT_TRUE(p.run_until([&] { return p.b.conn->remote() == kForger; }, 1s));
    ASSERT_TRUE(p.run_until([&] { return p.b.conn->remote() == p.a.addr(); }, 5s))
        << "an address that never answered kept the connection";
    EXPECT_EQ(p.b.moves, 0u);
    quiet = false;
    p.send(MessageType::App, "y");
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 2; }, 5s));
}

// Only the newest packet says where the peer is. One that the path held back
// while the peer moved — sent before the move, arriving just after it — is the
// peer's and opens, but moves nothing back.
TEST(UdpConnectionTest, APacketOvertakenByTheMoveMovesNothingBack) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    for (int i = 0; i < 32; ++i) ASSERT_TRUE(p.a.send(MessageType::App, std::string(16 * 1024, 'a')));
    p.a.conn->flush(p.now);
    p.run(30ms);
    Bytes held;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        if (!held.empty() || from != p.a.addr() || !is_short(d)) return false;
        held = d;
        p.net.map(p.a, kRebound);   // the packets after it leave from elsewhere
        return true;
    };
    ASSERT_TRUE(p.run_until([&] { return p.b.conn->remote() == kRebound; }, 1s));

    size_t to_old = 0;
    p.net.hook = [&](Bytes&, const Address&, const Address& to) {
        if (to == p.a.addr()) ++to_old;
        return false;
    };
    p.net.inject(p.a.addr(), p.b.addr(), held);
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 32; }, 10s));
    EXPECT_EQ(p.b.conn->remote(), kRebound);
    EXPECT_EQ(p.b.moves, 1u);
    EXPECT_EQ(to_old, 0u) << "an overtaken packet drew b back to where a was";
}

// Nothing moves before the handshake is done: until then the address is all a
// responder knows of its dialer.
TEST(UdpConnectionTest, NothingMovesDuringTheHandshake) {
    Pair p(true, 10ms);
    bool moved = false;
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        // The dialer's second handshake message is lost, and its repeats come
        // from elsewhere.
        if (!moved && from == p.a.addr() && is_handshake(d, udp::LongType::Handshake)) {
            moved = true;
            p.net.map(p.a, kRebound);
            return true;
        }
        return false;
    };
    p.dial();
    p.run(2s);
    ASSERT_TRUE(p.b.conn);
    EXPECT_EQ(p.b.conn->remote(), p.a.addr());
    EXPECT_FALSE(p.b.established()) << "a handshake finished from an address it did not begin at";
}

// Nor does a dialer that has not yet shown it receives where it dials from: its
// address is not proven, so there is nothing to have moved from.
TEST(UdpConnectionTest, ADialerThatHasNotProvedItsAddressCannotMove) {
    Pair p(false, 10ms);   // plaintext: the responder is established on the Initial
    // The dialer's first packets after the handshake are lost, which is what
    // would have proved its address; the next ones come from elsewhere.
    p.net.hook = [&](Bytes& d, const Address& from, const Address&) {
        return from == p.a.addr() && is_short(d);
    };
    p.dial();
    ASSERT_TRUE(p.run_until([&] { return p.a.established(); }));
    p.net.map(p.a, kRebound);
    p.send(MessageType::App, "x");
    p.run(1s);
    ASSERT_TRUE(p.b.conn);
    EXPECT_EQ(p.b.conn->remote(), p.a.addr());
    EXPECT_EQ(p.b.moves, 0u);
    EXPECT_TRUE(p.b.messages.empty());
}

// A peer told a stateless reset only it could make is told it from wherever it
// comes: the token is the secret, not the address.
TEST(UdpConnectionTest, AStatelessResetFromANewAddressEndsTheConnection) {
    Pair p(true);
    ASSERT_TRUE(p.connect());
    p.run(100ms);
    Bytes reset(udp::kMinShortPacket + 4, 0x33);
    reset[0] = 0x41;
    const udp::Cid to = p.a.conn->local_cid();
    for (int i = 0; i < 8; ++i) reset[1 + i] = static_cast<uint8_t>(to >> (56 - 8 * i));
    p.b.reset_token(p.b.conn->local_cid(), reset.data() + reset.size() - udp::kResetTokenSize);
    p.net.inject(kForger, p.a.addr(), reset);
    ASSERT_TRUE(p.run_until([&] { return p.a.conn->dead(); }, 100ms));
    EXPECT_EQ(p.a.conn->close_reason(), CloseReason::PeerReset);
}

// What a relay does when the packets of a connection it forwards come from an
// address the forward does not know (udp_mux.h): it asks the peer whether it is
// there. Answered from there, the connection moves; asked of an address nobody
// is at, nothing does.
TEST(UdpConnectionTest, AProbedAddressIsMovedToOnlyWhenTheAnswerComesFromIt) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(100ms);
    p.b.conn->probe_path(kForger, p.now);
    p.run(3s);
    EXPECT_EQ(p.b.conn->remote(), p.a.addr());
    EXPECT_EQ(p.b.moves, 0u);

    // a's NAT gives it a new port; a says nothing. b, told where to look, asks.
    p.net.map(p.a, kRebound);
    p.b.conn->probe_path(kRebound, p.now);
    ASSERT_TRUE(p.run_until([&] { return p.b.moves == 1; }, 1s));
    EXPECT_EQ(p.b.conn->remote(), kRebound);
    p.send(MessageType::App, "after");
    ASSERT_TRUE(p.run_until([&] { return p.b.messages.size() == 1; }, 1s));
}

// A host whose network changed has every connection say something at once, so
// the peer learns the new address now rather than at the next keep-alive — and
// what the peer had to send in the meantime is not left to wait on it.
TEST(UdpConnectionTest, ANudgeShowsThePeerWhereAnIdleConnectionIsNow) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(1s);
    p.net.map(p.a, kElsewhere);
    p.a.conn->nudge(p.now);
    ASSERT_TRUE(p.run_until([&] { return p.b.moves == 1; }, 200ms));
    EXPECT_EQ(p.b.conn->remote(), kElsewhere);
    ASSERT_TRUE(p.b.send(MessageType::App, "to the new place"));
    p.b.conn->flush(p.now);
    ASSERT_TRUE(p.run_until([&] { return p.a.messages.size() == 1; }, 200ms));
}

// A viewer — it only receives — loses its network for a moment and comes back
// on another. Nothing tells the sender, whose packets go where the viewer was; but
// the viewer notices the stream has stopped and speaks up from where it is now,
// so it is found again at once rather than at its next keep-alive.
TEST(UdpConnectionTest, AListenerOnANewNetworkIsFoundAgainWithoutBeingTold) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    const auto frame = [&] {
        ASSERT_TRUE(p.b.send(MessageType::App, std::string(3000, 'v')));
        p.b.conn->flush(p.now);
    };
    for (int i = 0; i < 60; ++i) { frame(); p.run(33ms); }
    p.net.blackout = true;
    p.run(300ms);
    p.net.map(p.a, kElsewhere);
    p.net.blackout = false;
    const auto back = p.now;
    const size_t before = p.a.messages.size();
    bool found = false;
    for (int i = 0; i < 30 && !found; ++i) {
        frame();
        p.run(33ms);
        found = p.b.moves == 1;
    }
    ASSERT_TRUE(found) << "the sender never found the viewer again";
    EXPECT_LE(p.now - back, UdpConnection::kQuietProbe + 100ms);
    ASSERT_TRUE(p.run_until([&] { return p.a.messages.size() > before; }, 1s));
}

// A peer whose messages come seconds apart is not "quiet" between them: nothing
// is sent to it for that — only the acknowledgements its messages draw.
TEST(UdpConnectionTest, ASparsePeerIsNotProbedForItsPauses) {
    Pair p(true, 10ms);
    ASSERT_TRUE(p.connect());
    p.run(1s);
    const size_t before = p.a.sent;
    for (int i = 0; i < 9; ++i) {
        ASSERT_TRUE(p.b.send(MessageType::App, "tick"));
        p.b.conn->flush(p.now);
        p.run(1s, 5ms);
    }
    EXPECT_LE(p.a.sent - before, 2u * 9) << "a pause between sparse messages was taken for a stream gone quiet";
}

// ── Streams on their own ────────────────────────────────────────────────────

TEST(UdpStreamsTest, ASendStreamOwesWhatWasLostAndForgetsWhatArrived) {
    udp::SendStream s;
    std::string data(50000, '\0');
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<char>(i * 31);
    s.write(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    EXPECT_EQ(s.unsent(), data.size());

    udp::SendStream::Piece piece;
    ASSERT_TRUE(s.peek(UINT64_MAX, piece));
    EXPECT_FALSE(piece.repair);
    s.take(piece, 30000);
    s.on_lost(10000, 5000);
    EXPECT_EQ(s.lost_bytes(), 5000u);
    s.on_acked(12000, 1000);   // part of it turned up after all
    EXPECT_EQ(s.lost_bytes(), 4000u);
    ASSERT_TRUE(s.peek(UINT64_MAX, piece));
    EXPECT_TRUE(piece.repair);
    EXPECT_EQ(piece.offset, 10000u);
    EXPECT_EQ(piece.len, 2000u);

    std::string out(2000, '\0');
    s.copy(piece.offset, piece.len, reinterpret_cast<uint8_t*>(&out[0]));
    EXPECT_EQ(out, data.substr(10000, 2000));

    s.take(piece, 2000);
    ASSERT_TRUE(s.peek(UINT64_MAX, piece));
    EXPECT_EQ(piece.offset, 13000u);
    s.take(piece, piece.len);
    ASSERT_TRUE(s.peek(100, piece)) << "new data within the budget";
    EXPECT_EQ(piece.offset, 30000u);
    EXPECT_EQ(piece.len, 100u);
    s.take(piece, 100);
    s.take(udp::SendStream::Piece{30100, 19900, false}, 19900);

    s.on_acked(0, 50000);
    EXPECT_TRUE(s.flushed());
    EXPECT_EQ(s.allocated(), 0u) << "a delivered stream holds memory";
}

TEST(UdpStreamsTest, ARepeatIsCutToWhatIsStillHeld) {
    // A probe repeats an older frame. If the front of it was delivered since by
    // another packet and the chunk it sat in was released, copying the frame
    // whole read freed memory; only the part from the acknowledged edge may go.
    udp::SendStream s;
    std::string data(20000, '\0');
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<char>(i * 7);
    s.write(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    s.take(udp::SendStream::Piece{0, data.size(), false}, data.size());
    s.on_acked(0, 16700);   // past the first 16 KiB chunk, which goes back
    ASSERT_LT(s.allocated(), 2 * udp::SendStream::kChunk);

    uint64_t offset = 16300;
    size_t   len    = 1190;
    ASSERT_TRUE(s.unacked_part(offset, len));
    EXPECT_EQ(offset, 16700u);
    EXPECT_EQ(len, 790u);
    std::string out(len, '\0');
    s.copy(offset, len, reinterpret_cast<uint8_t*>(&out[0]));
    EXPECT_EQ(out, data.substr(16700, 790));

    offset = 15000;
    len    = 1000;
    EXPECT_FALSE(s.unacked_part(offset, len)) << "a frame delivered whole is not repeated";
    s.on_acked(17000, 500);
    offset = 17000;
    len    = 500;
    EXPECT_FALSE(s.unacked_part(offset, len)) << "nor one acknowledged above the edge";
}

TEST(UdpStreamsTest, ARecvStreamReassemblesOverlappingRepairs) {
    udp::RecvStream r;
    udp::HoldAccount account;
    std::string data(10000, '\0');
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<char>('a' + i % 26);
    const auto piece = [&](size_t off, size_t len) {
        return ByteView(reinterpret_cast<const uint8_t*>(data.data()) + off, len);
    };
    // Out of order, overlapping, and cut differently than the first time.
    ASSERT_TRUE(r.on_data(6000, piece(6000, 2000), account));
    ASSERT_TRUE(r.on_data(3000, piece(3000, 1000), account));
    ASSERT_TRUE(r.on_data(2500, piece(2500, 4500), account));   // overlaps both
    ASSERT_TRUE(r.on_data(9000, piece(9000, 1000), account));
    EXPECT_EQ(r.in_order(), 0u);
    EXPECT_GT(account.held, 0u);
    ASSERT_TRUE(r.on_data(0, piece(0, 3000), account));   // fills the front
    EXPECT_EQ(r.in_order(), 8000u);
    ASSERT_TRUE(r.on_data(7500, piece(7500, 2000), account));
    EXPECT_EQ(r.in_order(), 10000u);
    EXPECT_EQ(account.held, 0u);
}

