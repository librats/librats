#include <gtest/gtest.h>

#include "librats/bittorrent/utp_packet.h"
#include "librats/bittorrent/utp_stream.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

using namespace librats;
using namespace librats::bittorrent;
using namespace librats::bittorrent::utp;

// uTP (BEP 29) without a socket in sight.
//
// A Stream is deliberately a pure state machine: it takes datagrams and a clock and
// produces datagrams, and everything else — the socket, the thread, the timers — is
// somebody else's. That is what makes it testable like this, with two streams wired
// to each other through a fake network that can drop, reorder and duplicate at will,
// and a clock the test advances by hand. Nothing here sleeps, nothing here is timing
// dependent, and a loss scenario that would take a lucky afternoon to reproduce
// against a real network is three lines.
//
// The wire-format tests come first and are deliberately literal: uTP's only value is
// that uTorrent and libtorrent understand it, so the bytes are pinned against BEP 29
// rather than against our own encoder.

namespace {

using Clock = Stream::Clock;

// Not the epoch: a time_point of zero is indistinguishable from "never", and using
// it would hide bugs where an uninitialised deadline reads as already due.
const Clock::time_point kT0 = Clock::time_point{} + std::chrono::hours(24);

Bytes make_data(std::size_t n, std::uint32_t seed = 0x5EEDu) {
    Bytes d(n);
    std::uint32_t x = seed;
    for (std::size_t i = 0; i < n; ++i) {
        x    = x * 1103515245u + 12345u;
        d[i] = std::uint8_t(x >> 16);
    }
    return d;
}

/// Reads everything the stream offers, the way a PeerConnection would.
struct Recorder : Stream::Observer {
    Stream*     stream = nullptr;
    Bytes       received;
    bool        connected = false;
    bool        eof       = false;
    bool        failed    = false;
    std::string error;
    int         writable_events = 0;
    /// Set to stop draining, so the flow-control path can be exercised.
    bool        stalled = false;

    void on_utp_connected() override { connected = true; }
    void on_utp_readable() override { drain(); }
    void on_utp_writable() override { ++writable_events; }
    void on_utp_error(const std::string& why) override {
        failed = true;
        error  = why;
    }

    void drain() {
        if (stalled || stream == nullptr) return;
        std::uint8_t buf[16384];
        for (;;) {
            const auto r = stream->read(ByteSpan(buf, sizeof(buf)));
            if (r.status == Stream::Status::Ok) {
                received.insert(received.end(), buf, buf + r.bytes);
                continue;
            }
            if (r.status == Stream::Status::Eof) eof = true;
            return;
        }
    }
};

/// Two endpoints joined by a network the test controls completely.
class FakeNet : public Host {
public:
    /// Return true to drop the datagram. Sees the raw bytes, so it can single out a
    /// packet type or a sequence number.
    std::function<bool(const Address& to, const std::uint8_t*, std::size_t)> drop_fn;
    /// Deliver each round's datagrams back to front.
    bool reorder = false;
    /// Deliver every datagram twice.
    bool duplicate = false;

    int sent = 0, dropped = 0, delivered = 0;

    void utp_send(const Address& to, const std::uint8_t* data, std::size_t len) override {
        ++sent;
        if (drop_fn && drop_fn(to, data, len)) {
            ++dropped;
            return;
        }
        queue_.push_back(Packet{to, Bytes(data, data + len)});
    }

    void utp_defer_ack(Stream& s) override { deferred_.push_back(&s); }

    void register_stream(const Address& at, Stream& s) { streams_[at] = &s; }

    Clock::time_point now() const { return now_; }
    void advance(std::chrono::milliseconds d) { now_ += d; }

    /// Deliver queued datagrams (and whatever they provoke) until the network goes
    /// quiet. Retransmission timers cannot fire in here at all — only tick_all()
    /// runs them — so anything that completes during a pump() did so without the
    /// help of a single timeout.
    ///
    /// Each round costs a little simulated time. That is not decoration: uTP's
    /// congestion control is driven by the one-way delay each side measures, so a
    /// clock frozen at one instant reports a delay of exactly zero, which BEP 29
    /// defines as "no sample" — and the window would never move off its initial
    /// single packet. A hundred microseconds per hop is roughly a loopback.
    void pump(int rounds = 64) {
        for (int r = 0; r < rounds; ++r) {
            flush_acks();
            if (queue_.empty()) return;
            std::vector<Packet> batch;
            batch.swap(queue_);
            if (reorder) std::reverse(batch.begin(), batch.end());
            now_ += std::chrono::microseconds(100);
            for (const Packet& p : batch) {
                deliver(p);
                if (duplicate) deliver(p);
            }
        }
        flush_acks();
    }

    void tick_all() {
        std::vector<Stream*> all;
        for (auto& [addr, s] : streams_) all.push_back(s);
        for (Stream* s : all) s->tick(now_);
        flush_acks();
    }

    /// Pump, then let @p ms of simulated time pass in 20 ms steps with a tick at
    /// each, so retransmission timers get a chance to fire.
    void run(int ms) {
        pump();
        for (int elapsed = 0; elapsed < ms; elapsed += 20) {
            advance(std::chrono::milliseconds(20));
            tick_all();
            pump();
        }
    }

private:
    struct Packet {
        Address to;
        Bytes   data;
    };

    void deliver(const Packet& p) {
        auto it = streams_.find(p.to);
        if (it == streams_.end()) return;
        ++delivered;
        // The sender is whichever endpoint is not the destination — a two-node
        // network needs nothing cleverer, and the streams check the address.
        Address from{};
        for (const auto& [addr, s] : streams_) {
            if (!(addr == p.to)) from = addr;
        }
        it->second->on_packet(p.data.data(), p.data.size(), from, now_);
    }

    void flush_acks() {
        if (deferred_.empty()) return;
        std::vector<Stream*> batch;
        batch.swap(deferred_);
        for (Stream* s : batch) s->send_deferred_ack(now_);
    }

    std::map<Address, Stream*> streams_;
    std::vector<Packet>        queue_;
    std::vector<Stream*>       deferred_;
    Clock::time_point          now_ = kT0;
};

/// A connected pair, set up the way utp::Manager does it: the initiator picks the id
/// it will receive on, the responder derives its pair from the SYN.
struct Pair {
    static constexpr std::uint16_t kInitiatorRecvId = 4000;

    FakeNet  net;
    Address  a_addr{IpAddress::parse("10.0.0.1").value(), 1000};
    Address  b_addr{IpAddress::parse("10.0.0.2").value(), 2000};
    Stream   a{net, kInitiatorRecvId, std::uint16_t(kInitiatorRecvId + 1)};
    Stream   b{net, std::uint16_t(kInitiatorRecvId + 1), kInitiatorRecvId};
    Recorder ra, rb;

    Pair() {
        ra.stream = &a;
        rb.stream = &b;
        a.set_observer(&ra);
        b.set_observer(&rb);
        net.register_stream(a_addr, a);
        net.register_stream(b_addr, b);
    }

    /// Run the handshake to completion.
    void connect() {
        a.connect(b_addr, net.now());
        net.pump();
    }

    void write_from_a(const Bytes& data) {
        const ByteView v(data);
        a.write(&v, 1, net.now());
    }
};

} // namespace

// ---- wire format -------------------------------------------------------------

// The single most error-prone byte in BEP 29: the diagram shows "type" first and
// "ver" second, but they are the high and low *nibbles* of one byte, not two fields.
// Get this backwards and every packet is a version-4 ST_DATA.
TEST(BtUtpPacket, TypeIsTheHighNibbleAndVersionTheLow) {
    Header h;
    h.type = PacketType::Syn;
    std::uint8_t buf[kHeaderSize];
    write_header(buf, h);
    EXPECT_EQ(buf[0], 0x41u);  // ST_SYN (4) << 4 | version 1

    Header back;
    ASSERT_TRUE(parse_header(buf, sizeof(buf), back));
    EXPECT_EQ(back.type, PacketType::Syn);
    EXPECT_EQ(back.version, 1u);
}

// A literal byte vector, so a change to the encoder that still round-trips through
// our own decoder cannot silently make us unintelligible to the rest of the swarm.
TEST(BtUtpPacket, GoldenHeaderBytes) {
    Header h;
    h.type           = PacketType::Data;
    h.extension      = 1;
    h.connection_id  = 0x1234;
    h.timestamp      = 0xDEADBEEF;
    h.timestamp_diff = 0x00C0FFEE;
    h.wnd_size       = 0x00040000;
    h.seq_nr         = 0xABCD;
    h.ack_nr         = 0x0042;

    std::uint8_t buf[kHeaderSize];
    write_header(buf, h);
    const std::uint8_t want[kHeaderSize] = {
        0x01, 0x01, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xC0,
        0xFF, 0xEE, 0x00, 0x04, 0x00, 0x00, 0xAB, 0xCD, 0x00, 0x42,
    };
    EXPECT_EQ(std::memcmp(buf, want, kHeaderSize), 0);
}

TEST(BtUtpPacket, HeaderRoundTrip) {
    Header h;
    h.type           = PacketType::Fin;
    h.extension      = 0;
    h.connection_id  = 65535;
    h.timestamp      = 4000000000u;
    h.timestamp_diff = 123456;
    h.wnd_size       = 1048576;
    h.seq_nr         = 1;
    h.ack_nr         = 65534;

    std::uint8_t buf[kHeaderSize];
    write_header(buf, h);
    Header back;
    ASSERT_TRUE(parse_header(buf, sizeof(buf), back));
    EXPECT_EQ(back.type, h.type);
    EXPECT_EQ(back.connection_id, h.connection_id);
    EXPECT_EQ(back.timestamp, h.timestamp);
    EXPECT_EQ(back.timestamp_diff, h.timestamp_diff);
    EXPECT_EQ(back.wnd_size, h.wnd_size);
    EXPECT_EQ(back.seq_nr, h.seq_nr);
    EXPECT_EQ(back.ack_nr, h.ack_nr);
}

TEST(BtUtpPacket, RejectsShortAndWrongVersion) {
    std::uint8_t buf[kHeaderSize] = {};
    Header       h;
    EXPECT_FALSE(parse_header(buf, kHeaderSize - 1, h));  // too short
    buf[0] = 0x02;                                        // ST_DATA, version 2
    EXPECT_FALSE(parse_header(buf, kHeaderSize, h));
}

TEST(BtUtpPacket, WalkExtensionsFindsSackAndSkipsTheRest) {
    std::uint8_t buf[64] = {};
    Header       h;
    h.type      = PacketType::State;
    h.extension = std::uint8_t(ExtensionType::CloseReason);
    write_header(buf, h);
    // close-reason (4 bytes) -> sack (4 bytes) -> end
    buf[20] = std::uint8_t(ExtensionType::Sack);
    buf[21] = 4;
    buf[26] = 0;
    buf[27] = 4;
    buf[28] = 0xAB;

    Header parsed;
    ASSERT_TRUE(parse_header(buf, 32, parsed));
    int         sacks = 0;
    std::size_t first = 0;
    const std::size_t payload_off = walk_extensions(buf, 32, parsed, [&](const Extension& e) {
        if (e.type == ExtensionType::Sack) {
            ++sacks;
            first = e.data[0];
        }
    });
    EXPECT_EQ(sacks, 1);
    EXPECT_EQ(first, 0xABu);
    EXPECT_EQ(payload_off, 32u);
}

// A record that claims to run past the end of the datagram is the obvious way to
// try to walk us off the buffer. It must be reported as malformed, not clamped.
TEST(BtUtpPacket, WalkExtensionsRejectsAnOverlongRecord) {
    std::uint8_t buf[32] = {};
    Header       h;
    h.extension = std::uint8_t(ExtensionType::Sack);
    write_header(buf, h);
    buf[20] = 0;
    buf[21] = 200;  // claims 200 bytes in a 24-byte datagram

    Header parsed;
    ASSERT_TRUE(parse_header(buf, 24, parsed));
    EXPECT_EQ(walk_extensions(buf, 24, parsed, [](const Extension&) {}), 0u);
}

TEST(BtUtpPacket, SequenceComparesAreCorrectAcrossTheWrap) {
    EXPECT_TRUE(seq_less(1, 2));
    EXPECT_FALSE(seq_less(2, 1));
    EXPECT_FALSE(seq_less(5, 5));
    // The whole point: 65535 precedes 1.
    EXPECT_TRUE(seq_less(65535, 1));
    EXPECT_FALSE(seq_less(1, 65535));
    EXPECT_EQ(seq_diff(1, 65535), 2);
    EXPECT_EQ(seq_diff(65535, 1), -2);
    EXPECT_EQ(seq_diff(100, 100), 0);
}

TEST(BtUtpPacket, U32SequenceComparesWrap) {
    EXPECT_TRUE(seq_less_u32(1, 2));
    EXPECT_TRUE(seq_less_u32(0xffffffffu, 1));
    EXPECT_FALSE(seq_less_u32(1, 0xffffffffu));
}

// ---- delay history / RTT estimator -------------------------------------------

TEST(BtUtpDelay, HistoryReportsSamplesRelativeToTheLowestSeen) {
    DelayHistory h;
    EXPECT_FALSE(h.initialized());
    EXPECT_EQ(h.add_sample(1000, false), 0u);  // the first sample defines the base
    EXPECT_TRUE(h.initialized());
    EXPECT_EQ(h.base(), 1000u);
    EXPECT_EQ(h.add_sample(1500, false), 500u);
    // A lower sample moves the base, and everything after is relative to it.
    EXPECT_EQ(h.add_sample(800, false), 0u);
    EXPECT_EQ(h.base(), 800u);
    EXPECT_EQ(h.add_sample(1000, false), 200u);
}

// The base has to be able to rise, or a clock that drifts one way would leave us
// permanently convinced the path is congested.
TEST(BtUtpDelay, AdjustBaseShiftsTheWholeHistory) {
    DelayHistory h;
    h.add_sample(1000, false);
    h.adjust_base(500);
    EXPECT_EQ(h.base(), 1500u);
    EXPECT_EQ(h.add_sample(2000, false), 500u);
}

TEST(BtUtpDelay, SlidingAverageTracksMeanAndDeviation) {
    SlidingAverage avg;
    EXPECT_EQ(avg.mean(), 0);
    EXPECT_EQ(avg.avg_deviation(), 0);
    for (int i = 0; i < 20; ++i) avg.add_sample(100);
    EXPECT_EQ(avg.mean(), 100);
    EXPECT_EQ(avg.avg_deviation(), 0);  // no variation at all
    for (int i = 0; i < 20; ++i) avg.add_sample(200);
    EXPECT_GT(avg.mean(), 150);
    EXPECT_GT(avg.avg_deviation(), 0);
}

// ---- handshake ---------------------------------------------------------------

TEST(BtUtpStream, HandshakeConnectsBothEnds) {
    Pair p;
    p.connect();
    EXPECT_TRUE(p.ra.connected);
    EXPECT_EQ(p.a.state(), Stream::State::Connected);
    EXPECT_EQ(p.b.state(), Stream::State::Connected);
    EXPECT_FALSE(p.ra.failed);
    EXPECT_FALSE(p.rb.failed);
}

// A responder that never answers must not be retried forever. An endpoint we have
// never heard from could just as easily be a made-up address, so it fails on the
// first timeout rather than spending the full retransmission budget on it.
TEST(BtUtpStream, UnansweredSynTimesOut) {
    Pair p;
    p.net.drop_fn = [](const Address&, const std::uint8_t*, std::size_t) { return true; };
    p.a.connect(p.b_addr, p.net.now());
    p.net.pump();
    EXPECT_FALSE(p.ra.failed);

    p.net.advance(std::chrono::milliseconds(3100));
    p.a.tick(p.net.now());
    EXPECT_TRUE(p.ra.failed);
    EXPECT_EQ(p.a.state(), Stream::State::Closed);
}

// The SYN-ack was lost, so the peer retransmits its SYN. The connection id it
// carries is not the one our stream is registered under, which is exactly the case
// utp::Manager has to special-case; from the stream's side the duplicate must be
// harmless rather than a second connection.
TEST(BtUtpStream, DuplicateSynIsIgnored) {
    Pair p;
    p.connect();
    ASSERT_TRUE(p.ra.connected);
    const std::uint16_t before = p.b.ack_nr();

    // Replay a SYN at the responder.
    std::uint8_t syn[kHeaderSize];
    Header       h;
    h.type          = PacketType::Syn;
    h.connection_id = Pair::kInitiatorRecvId;
    h.seq_nr        = 12345;
    write_header(syn, h);
    EXPECT_TRUE(p.b.on_packet(syn, sizeof(syn), p.a_addr, p.net.now()));
    EXPECT_EQ(p.b.ack_nr(), before);
    EXPECT_EQ(p.b.state(), Stream::State::Connected);
}

// ---- data transfer -----------------------------------------------------------

TEST(BtUtpStream, TransfersDataInOrder) {
    Pair        p;
    p.connect();
    const Bytes payload = make_data(4000);  // spans several packets
    p.write_from_a(payload);
    p.net.pump();
    EXPECT_EQ(p.rb.received, payload);
}

// Small writes must not each cost a packet. Nagle holds a part-full packet while
// anything is unacknowledged, so a burst of little messages leaves as one.
TEST(BtUtpStream, CoalescesSmallWritesIntoOnePacket) {
    Pair p;
    p.connect();
    const int before = p.net.sent;

    Bytes all;
    for (int i = 0; i < 20; ++i) {
        const Bytes chunk = make_data(10, std::uint32_t(i));
        p.write_from_a(chunk);
        all.insert(all.end(), chunk.begin(), chunk.end());
        // No pumping in between: the writes pile into the same packet.
    }
    p.net.pump();
    EXPECT_EQ(p.rb.received, all);
    // One data packet plus its acknowledgement, not twenty of each.
    EXPECT_LE(p.net.sent - before, 4);
}

// Delivering every round back to front is a far harsher reordering than any real
// path produces, and the receiver must still hand the bytes over in order.
TEST(BtUtpStream, ReorderedPacketsAreDeliveredInOrder) {
    Pair p;
    p.connect();
    p.net.reorder = true;

    const Bytes payload = make_data(64 * 1024);
    p.write_from_a(payload);
    p.net.run(2000);
    EXPECT_EQ(p.rb.received.size(), payload.size());
    EXPECT_EQ(p.rb.received, payload);
}

TEST(BtUtpStream, DuplicatePacketsAreNotDeliveredTwice) {
    Pair p;
    p.connect();
    p.net.duplicate = true;

    const Bytes payload = make_data(16 * 1024);
    p.write_from_a(payload);
    p.net.run(1000);
    EXPECT_EQ(p.rb.received, payload);
}

// The clock never moves here, so no retransmission timer can possibly fire: the
// only thing that can repair the hole is the selective ack telling the sender which
// packet is missing. That is the whole point of implementing SACK at all.
TEST(BtUtpStream, FastRetransmitRepairsAHoleWithNoTimeoutAtAll) {
    Pair p;
    p.connect();

    // Warm up so the congestion window is wide enough to keep several packets in
    // flight — with one packet in flight there is nothing behind the hole to notice.
    const Bytes warmup = make_data(128 * 1024, 1);
    p.write_from_a(warmup);
    p.net.pump(512);
    ASSERT_EQ(p.rb.received.size(), warmup.size());
    ASSERT_GT(p.a.cwnd(), 4 * kMaxPayload) << "the window never grew; the rest proves nothing";

    // Drop exactly one data packet, then keep sending.
    int drops = 0;
    p.net.drop_fn = [&drops](const Address&, const std::uint8_t* d, std::size_t len) {
        Header h;
        if (drops > 0 || !parse_header(d, len, h) || h.type != PacketType::Data) return false;
        ++drops;
        return true;
    };

    const Bytes more = make_data(64 * 1024, 2);
    p.write_from_a(more);
    p.net.pump(512);

    ASSERT_EQ(drops, 1) << "no packet was actually dropped";
    Bytes expected = warmup;
    expected.insert(expected.end(), more.begin(), more.end());
    EXPECT_EQ(p.rb.received, expected)
        << "the hole was never repaired without a retransmission timeout";
}

// The other recovery path: when nothing follows the lost packet there is no later
// arrival to describe it, so only the timer can notice.
TEST(BtUtpStream, TimeoutRetransmitRepairsALostPacketWithNothingBehindIt) {
    Pair p;
    p.connect();

    int drops = 0;
    p.net.drop_fn = [&drops](const Address&, const std::uint8_t* d, std::size_t len) {
        Header h;
        if (drops > 0 || !parse_header(d, len, h) || h.type != PacketType::Data) return false;
        ++drops;
        return true;
    };

    const Bytes payload = make_data(500);  // one packet, and nothing after it
    p.write_from_a(payload);
    p.net.pump();
    ASSERT_EQ(drops, 1);
    EXPECT_TRUE(p.rb.received.empty());

    // Past the minimum retransmission timeout.
    p.net.run(1200);
    EXPECT_EQ(p.rb.received, payload);
}

// A quarter of everything dropped, in both directions, plus reordering. This is far
// worse than any usable network, and the transfer must still be byte-exact — that is
// the entire contract a reliability layer offers.
TEST(BtUtpStream, LargeTransferSurvivesHeavyLossAndReordering) {
    Pair p;
    p.connect();
    p.net.reorder = true;

    int n = 0;
    p.net.drop_fn = [&n](const Address&, const std::uint8_t*, std::size_t) {
        return (++n % 4) == 0;
    };

    const Bytes payload = make_data(128 * 1024, 7);
    p.write_from_a(payload);
    p.net.run(60000);

    EXPECT_FALSE(p.ra.failed) << p.ra.error;
    EXPECT_FALSE(p.rb.failed) << p.rb.error;
    EXPECT_EQ(p.rb.received.size(), payload.size());
    EXPECT_EQ(p.rb.received, payload);
}

TEST(BtUtpStream, TransfersInBothDirectionsAtOnce) {
    Pair p;
    p.connect();

    const Bytes from_a = make_data(40000, 11);
    const Bytes from_b = make_data(40000, 22);
    const ByteView va(from_a), vb(from_b);
    p.a.write(&va, 1, p.net.now());
    p.b.write(&vb, 1, p.net.now());
    p.net.run(2000);

    EXPECT_EQ(p.rb.received, from_a);
    EXPECT_EQ(p.ra.received, from_b);
}

// The window has to actually open. uTP starts at a single packet, and if slow start
// were broken every transfer would still *work* — it would just crawl at one packet
// per round trip, which no assertion about correctness would ever catch.
TEST(BtUtpStream, SlowStartOpensTheWindow) {
    Pair p;
    p.connect();
    EXPECT_EQ(p.a.cwnd(), kMaxPayload) << "a connection should start at one packet";

    const Bytes payload = make_data(200 * 1024, 3);
    p.write_from_a(payload);
    p.net.pump(1024);
    ASSERT_EQ(p.rb.received.size(), payload.size());

    // ~170 packets delivered, and slow start doubles once per round trip, so the
    // window should be tens of packets wide by the end rather than still at one.
    EXPECT_GT(p.a.cwnd(), 16 * kMaxPayload);
}

// ---- flow control and backpressure -------------------------------------------

// A reader that stops draining must stop the sender, not let it fill memory. The
// receiver advertises a shrinking window; the sender respects it.
TEST(BtUtpStream, AStalledReaderStopsTheSender) {
    Pair p;
    p.connect();
    p.rb.stalled = true;  // B stops reading, but keeps acknowledging

    // Far more than either the receive buffer or the send high-water mark.
    const Bytes payload = make_data(4 * kRecvBufferCapacity);
    const ByteView v(payload);
    std::size_t accepted = 0;
    for (int i = 0; i < 200; ++i) {
        const ByteView rest(payload.data() + accepted, payload.size() - accepted);
        const auto     r = p.a.write(&rest, 1, p.net.now());
        accepted += r.bytes;
        p.net.run(200);
        if (r.status == Stream::Status::WouldBlock) break;
    }

    EXPECT_LT(accepted, payload.size()) << "a stalled reader never applied backpressure";
    EXPECT_LE(p.a.send_queue_bytes(), kSendHighWater + kMaxPayload);

    // And once the reader comes back, the rest flows.
    p.rb.stalled = false;
    p.rb.drain();
    p.net.run(2000);
    EXPECT_GT(p.rb.received.size(), 0u);
}

// The recovery half of the case above: a window that reopens has to be noticed even
// if the update announcing it is lost, or the connection stalls forever. That is
// what the zero-window probe is for.
TEST(BtUtpStream, ReopenedWindowResumesTheTransfer) {
    Pair p;
    p.connect();
    p.rb.stalled = true;

    const Bytes    payload = make_data(kRecvBufferCapacity + 64 * 1024);
    const ByteView v(payload);
    std::size_t    accepted = p.a.write(&v, 1, p.net.now()).bytes;
    p.net.run(3000);
    const std::size_t stalled_at = p.rb.received.size();

    p.rb.stalled = false;
    p.rb.drain();  // drains what arrived; the window reopens
    p.net.run(5000);

    const ByteView rest(payload.data() + accepted, payload.size() - accepted);
    accepted += p.a.write(&rest, 1, p.net.now()).bytes;
    p.net.run(10000);

    EXPECT_GT(p.rb.received.size(), stalled_at) << "the transfer never restarted";
    ASSERT_LE(p.rb.received.size(), payload.size());
    EXPECT_TRUE(std::equal(p.rb.received.begin(), p.rb.received.end(), payload.begin()));
}

// ---- shutdown ----------------------------------------------------------------

TEST(BtUtpStream, FinDeliversEofAfterTheLastByte) {
    Pair p;
    p.connect();

    const Bytes payload = make_data(9000);
    p.write_from_a(payload);
    p.a.close(p.net.now());
    p.net.run(1000);

    EXPECT_EQ(p.rb.received, payload) << "the FIN truncated the stream";
    EXPECT_TRUE(p.rb.eof);
}

// A FIN that overtakes a retransmission must not be allowed to cut the stream short:
// end-of-stream is only reported once everything before it has been delivered.
TEST(BtUtpStream, EofIsWithheldUntilEveryEarlierPacketArrives) {
    Pair p;
    p.connect();

    int drops = 0;
    p.net.drop_fn = [&drops](const Address&, const std::uint8_t* d, std::size_t len) {
        Header h;
        if (drops > 0 || !parse_header(d, len, h) || h.type != PacketType::Data) return false;
        ++drops;
        return true;
    };

    const Bytes payload = make_data(3000);
    p.write_from_a(payload);
    p.a.close(p.net.now());
    p.net.pump();
    ASSERT_EQ(drops, 1);
    EXPECT_FALSE(p.rb.eof) << "end-of-stream was reported with a packet still missing";

    p.net.run(2000);
    EXPECT_EQ(p.rb.received, payload);
    EXPECT_TRUE(p.rb.eof);
}

TEST(BtUtpStream, ResetFailsTheOtherEnd) {
    Pair p;
    p.connect();
    p.b.reset(p.net.now());
    p.net.pump();
    EXPECT_TRUE(p.ra.failed);
    EXPECT_EQ(p.a.state(), Stream::State::Closed);
}

// A closed stream is not reaped the instant it is closed: it still owes the peer a
// FIN, and the manager leans on reapable() to know when that debt is settled.
TEST(BtUtpStream, ClosedStreamBecomesReapableOnceBothEndsAreDone) {
    Pair p;
    p.connect();
    EXPECT_FALSE(p.a.reapable(p.net.now()));

    p.a.close(p.net.now());
    p.b.close(p.net.now());
    p.net.run(500);
    EXPECT_TRUE(p.a.reapable(p.net.now()));
    EXPECT_TRUE(p.b.reapable(p.net.now()));
}

// ---- hostile input -----------------------------------------------------------

// Everything below is what a third party who can guess a connection id might inject.
// None of it may disturb a live connection.
TEST(BtUtpStream, IgnoresPacketsForAnotherConnectionId) {
    Pair p;
    p.connect();
    const std::uint16_t before = p.b.ack_nr();

    std::uint8_t buf[kHeaderSize];
    Header       h;
    h.type          = PacketType::Data;
    h.connection_id = 9999;  // not ours
    h.seq_nr        = std::uint16_t(before + 1);
    write_header(buf, h);
    EXPECT_FALSE(p.b.on_packet(buf, sizeof(buf), p.a_addr, p.net.now()));
    EXPECT_EQ(p.b.ack_nr(), before);
}

TEST(BtUtpStream, IgnoresAnAckForSomethingNeverSent) {
    Pair p;
    p.connect();
    const Bytes payload = make_data(2000);
    p.write_from_a(payload);
    p.net.pump();

    std::uint8_t buf[kHeaderSize];
    Header       h;
    h.type          = PacketType::State;
    h.connection_id = p.a.recv_id();
    h.ack_nr        = std::uint16_t(p.a.seq_nr() + 5000);  // far beyond anything sent
    h.seq_nr        = p.a.ack_nr();
    write_header(buf, h);
    p.a.on_packet(buf, sizeof(buf), p.b_addr, p.net.now());

    EXPECT_FALSE(p.ra.failed);
    EXPECT_EQ(p.a.state(), Stream::State::Connected);
}

// A reset only counts if it acknowledges something we actually sent — otherwise
// anyone able to guess a connection id could tear down any connection at will.
TEST(BtUtpStream, IgnoresAResetThatAcknowledgesNothingWeSent) {
    Pair p;
    p.connect();

    std::uint8_t buf[kHeaderSize];
    Header       h;
    h.type          = PacketType::Reset;
    h.connection_id = p.a.recv_id();
    h.ack_nr        = std::uint16_t(p.a.seq_nr() + 1000);
    write_header(buf, h);
    p.a.on_packet(buf, sizeof(buf), p.b_addr, p.net.now());

    EXPECT_FALSE(p.ra.failed);
    EXPECT_EQ(p.a.state(), Stream::State::Connected);
}

TEST(BtUtpStream, IgnoresAPacketFromTheWrongAddress) {
    Pair p;
    p.connect();
    const Address elsewhere{IpAddress::parse("10.9.9.9").value(), 5555};
    EXPECT_FALSE(p.b.matches(elsewhere, p.b.recv_id()));
    EXPECT_TRUE(p.b.matches(p.a_addr, p.b.recv_id()));
}

// A sequence number wildly ahead of what we can reorder is either an attack or a
// connection beyond saving; either way it must not be buffered.
TEST(BtUtpStream, DropsAPacketTooFarAheadToReorder) {
    Pair p;
    p.connect();
    const Bytes payload = make_data(100);
    p.write_from_a(payload);
    p.net.pump();

    std::uint8_t buf[kHeaderSize + 4];
    Header       h;
    h.type          = PacketType::Data;
    h.connection_id = p.b.recv_id();
    h.seq_nr        = std::uint16_t(p.b.ack_nr() + 10000);
    h.ack_nr        = p.b.ack_nr();
    write_header(buf, h);
    p.b.on_packet(buf, sizeof(buf), p.a_addr, p.net.now());

    EXPECT_EQ(p.rb.received, payload);  // nothing extra, nothing lost
    EXPECT_FALSE(p.rb.failed);
}
