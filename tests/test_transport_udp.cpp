#include <gtest/gtest.h>

#include "librats/core/socket.h"
#include "librats/node/node.h"
#include "librats/transport/udp_mux.h"
#include "librats/transport/udp_packet.h"
#include "librats/transport/udp_stream.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 15s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

// ── A simulated network for driving two streams against each other ──────────
//
// Datagrams are queued rather than delivered inline, so a test can decide what
// the "path" does with them: deliver in order, deliver reversed, drop every Nth,
// or drop a specific one. Nothing here is timing-dependent except where a test
// deliberately waits out a retransmission timeout.
class FakeNet : public UdpStreamHost {
public:
    void attach(const Address& addr, UdpStream* stream) { endpoints_[addr] = stream; }

    void send_datagram(const Address& to, const uint8_t* data, size_t len) override {
        ++sent_;
        if (drop_next_ > 0) { --drop_next_; ++dropped_; return; }
        if (drop_every_ > 0 && (sent_ % drop_every_) == 0) { ++dropped_; return; }
        queue_.push_back({to, Bytes(data, data + len)});
    }

    void stream_events(UdpStream&, uint32_t) override {}

    /// Deliver everything queued. `reverse` hands the batch over backwards, which
    /// is the cheapest way to make a receiver see a gap.
    void deliver(bool reverse = false) {
        deliver_at(std::chrono::steady_clock::now(), reverse);
    }

    /// Deliver everything queued, stamping arrival at `now` rather than at the
    /// wall clock. This is what lets a test drive the parts of the stream that
    /// are functions of time — the pacer, the idle-restart rule, HyStart++ —
    /// without sleeping and without depending on how fast the machine is.
    void deliver_at(std::chrono::steady_clock::time_point now, bool reverse = false) {
        std::deque<Datagram> batch;
        batch.swap(queue_);
        if (reverse) std::reverse(batch.begin(), batch.end());

        for (const Datagram& d : batch) {
            auto it = endpoints_.find(d.to);
            if (it == endpoints_.end()) continue;
            rudp::Packet p;
            if (!rudp::decode(d.bytes.data(), d.bytes.size(), p)) continue;
            it->second->on_packet(p, now);
        }
    }

    /// Run the pair to a standstill: deliver, tick, repeat until nothing moves.
    void settle(UdpStream& a, UdpStream& b, int rounds = 32) {
        for (int i = 0; i < rounds && !queue_.empty(); ++i) {
            deliver();
            const auto now = std::chrono::steady_clock::now();
            a.tick(now);
            b.tick(now);
        }
    }

    /// Deliver only what is addressed to `only`, leaving the other direction
    /// queued. Lets a test hold one side's packet genuinely in flight — neither
    /// lost nor arrived — while the other side keeps talking.
    void deliver_to(const Address& only) {
        std::deque<Datagram> batch;
        batch.swap(queue_);

        const auto now = std::chrono::steady_clock::now();
        for (const Datagram& d : batch) {
            if (d.to != only) { queue_.push_back(d); continue; }
            auto it = endpoints_.find(d.to);
            if (it == endpoints_.end()) continue;
            rudp::Packet p;
            if (!rudp::decode(d.bytes.data(), d.bytes.size(), p)) continue;
            it->second->on_packet(p, now);
        }
    }

    void set_drop_every(size_t n) { drop_every_ = n; sent_ = 0; }
    /// Lose the next `count` datagrams and nothing after them, so a test can open
    /// a hole of a known size and watch exactly one loss episode play out.
    void drop_next(size_t count = 1) { drop_next_ = count; }
    size_t dropped() const        { return dropped_; }
    size_t queued() const         { return queue_.size(); }
    /// Datagrams handed to the "wire", dropped ones included. What a test watches
    /// when the question is whether a stream said anything at all — a keep-alive or
    /// a delayed ack has nothing to deliver and no side effect to observe.
    size_t sent() const           { return sent_; }

    /// Decode the most recently queued datagram, so a test can read a field off the
    /// wire (a window, an ack) rather than infer it from behaviour. `out.payload`
    /// points into the queue and is valid only until it next moves.
    bool peek_last(rudp::Packet& out) const {
        if (queue_.empty()) return false;
        const Datagram& d = queue_.back();
        return rudp::decode(d.bytes.data(), d.bytes.size(), out);
    }

private:
    struct Datagram {
        Address to;
        Bytes   bytes;
    };

    std::map<Address, UdpStream*> endpoints_;
    std::deque<Datagram>          queue_;
    size_t                        sent_       = 0;
    size_t                        dropped_    = 0;
    size_t                        drop_every_ = 0;
    size_t                        drop_next_  = 0;
};

/// Read everything currently readable out of `s`.
std::string drain(UdpStream& s) {
    std::string out;
    uint8_t     buf[4096];
    for (;;) {
        const size_t n = s.read(buf, sizeof(buf));
        if (n == 0) break;
        out.append(reinterpret_cast<const char*>(buf), n);
    }
    return out;
}

size_t write_all(UdpStream& s, const std::string& data) {
    const ByteView slice(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return s.write(&slice, 1, std::chrono::steady_clock::now());
}

size_t write_all_at(UdpStream& s, const std::string& data,
                    std::chrono::steady_clock::time_point now) {
    const ByteView slice(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return s.write(&slice, 1, now);
}

const Address kAlice{"127.0.0.1", 4001};
const Address kBob{"127.0.0.1", 4002};

/// A connected pair: `initiator` dialed `responder`, both handshakes settled.
struct Pair {
    FakeNet                    net;
    std::unique_ptr<UdpStream> initiator;
    std::unique_ptr<UdpStream> responder;

    Pair() {
        const auto now = std::chrono::steady_clock::now();
        // Alice dials Bob. The id pairing mirrors the mux: the dialer keeps
        // `base` and sends under `base + 1`; the responder is the mirror image.
        constexpr uint32_t kBase = 0x11223344;
        initiator = std::make_unique<UdpStream>(net, kBob, kBase, kBase + 1,
                                                ConnRole::Outbound, now);
        responder = std::make_unique<UdpStream>(net, kAlice, kBase + 1, kBase,
                                                ConnRole::Inbound, now);
        net.attach(kBob, responder.get());
        net.attach(kAlice, initiator.get());
        net.settle(*initiator, *responder);
    }
};

/// A connected pair on a *virtual* clock and a path with a real round trip.
///
/// The Pair above settles instantly, which is all most tests need — but it also
/// means every round trip it measures is near zero, so anything derived from the
/// round-trip estimate (the pacing rate, the retransmission timeout, HyStart++'s
/// comparison between rounds) is degenerate there. This drives time by hand
/// instead: each hop advances half a round trip and hands over what is in
/// flight, so both ends measure exactly `rtt` and a test can make the path
/// slower simply by assigning to it.
struct TimedPair {
    using Clock = std::chrono::steady_clock;

    FakeNet                    net;
    std::unique_ptr<UdpStream> initiator;
    std::unique_ptr<UdpStream> responder;
    Clock::time_point          now{};
    Clock::duration            rtt;

    explicit TimedPair(Clock::duration round_trip = 40ms) : rtt(round_trip) {
        constexpr uint32_t kBase = 0x11223344;
        initiator = std::make_unique<UdpStream>(net, kBob, kBase, kBase + 1,
                                                ConnRole::Outbound, now);
        responder = std::make_unique<UdpStream>(net, kAlice, kBase + 1, kBase,
                                                ConnRole::Inbound, now);
        net.attach(kBob, responder.get());
        net.attach(kAlice, initiator.get());
        hops(4);   // the Syn, its acknowledgement, and the first round-trip sample
    }

    /// Half a round trip: advance the clock and deliver whatever is on the wire.
    void hop() {
        now += rtt / 2;
        net.deliver_at(now);
        initiator->tick(now);
        responder->tick(now);
    }
    void hops(int n) { for (int i = 0; i < n; ++i) hop(); }

    /// Offer `bytes` and run the path until every one of them has arrived, so the
    /// pipe is empty again when this returns. Draining matters: a test that left
    /// a backlog behind would be measuring the leftovers rather than what it
    /// meant to.
    size_t transfer(size_t bytes, int max_hops = 2000) {
        const std::string payload(bytes, 'x');
        const size_t offered = write_all_at(*initiator, payload, now);
        size_t got = 0;
        for (int i = 0; i < max_hops && got < offered; ++i) {
            hop();
            got += drain(*responder).size();
        }
        return got;
    }
};

NodeConfig base_config() {
    NodeConfig c;
    c.listen_port  = 0;
    c.bind_address = "127.0.0.1";
    c.security     = NodeConfig::Security::Noise;
    return c;
}

// ── A mux driven by hand, on real sockets ───────────────────────────────────
//
// The stream tests above run against a simulated path so they can control loss
// and ordering. These run the mux itself — id pairing, admission, resets and the
// linger — over two real loopback sockets, with the test standing in for the
// reactor: it calls on_readable()/tick() instead of a poll loop.

/// The reactor's side of UdpMuxDelegate, reduced to bookkeeping.
class MuxHost : public UdpMuxDelegate {
public:
    ConnId adopt_inbound_link(std::unique_ptr<Link> link) override {
        // Refusing destroys the link, which releases the stream the mux just
        // created — the path where a leak or a use-after-free would hide.
        if (refuse) { ++refused; return kInvalidConnId; }

        const ConnId id = next_id++;
        link->attach(id);  // exactly what Reactor::adopt() does after adopting
        links.emplace(id, std::move(link));
        ++adopted;
        return id;
    }

    void dispatch_link_events(ConnId id, uint32_t events) override {
        delivered[id] |= events;
        ++dispatches;
    }

    Link* only_link() {
        return links.size() == 1 ? links.begin()->second.get() : nullptr;
    }

    std::unordered_map<ConnId, std::unique_ptr<Link>> links;
    std::unordered_map<ConnId, uint32_t>              delivered;
    ConnId                                            next_id  = 1;
    int                                               adopted  = 0;
    int                                               refused  = 0;
    size_t                                            dispatches = 0;
    bool                                              refuse   = false;
};

UdpStream& stream_of(Link& link) { return static_cast<UdpStreamLink&>(link).stream(); }

/// Is anything waiting on `sock`? Peeks, so the caller still gets to read it.
bool probe_has_data(socket_t sock) {
    // A one-byte MSG_PEEK is not enough on Windows: peeking less than the whole
    // datagram completes with WSAEMSGSIZE, which reads as "nothing here" — the same
    // quirk the IOCP poller works around. Peek a full datagram's worth instead.
    uint8_t buf[rudp::kMaxDatagram];
    return ::recv(sock, reinterpret_cast<char*>(buf), sizeof(buf), MSG_PEEK) >= 0;
}

std::string read_all(Link& link) {
    std::string out;
    uint8_t     buf[4096];
    for (;;) {
        const Link::IoResult r = link.read(ByteSpan(buf, sizeof(buf)));
        if (r.status != Link::Status::Ok || r.bytes == 0) break;
        out.append(reinterpret_cast<const char*>(buf), r.bytes);
    }
    return out;
}

/// Two muxes on two loopback sockets. Destruction order matters exactly as it
/// does in the Reactor: every Link tells its mux, on destruction, that its stream
/// may go — so the links have to be dropped before the muxes are.
struct MuxPair {
    MuxHost                 host_a, host_b;
    socket_t                sock_a = RATS_INVALID_SOCKET, sock_b = RATS_INVALID_SOCKET;
    std::unique_ptr<UdpMux> a, b;
    Address                 addr_a, addr_b;

    /// `b_limits` is what the *responder* admits with; the defaults never make a
    /// test node validate anything, so a test that wants the loaded-node behaviour
    /// asks for it explicitly rather than opening a thousand streams to earn it.
    explicit MuxPair(UdpMuxLimits b_limits = {}) {
        init_socket_library();
        sock_a = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
        sock_b = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
        EXPECT_TRUE(is_valid_socket(sock_a));
        EXPECT_TRUE(is_valid_socket(sock_b));
        set_socket_nonblocking(sock_a);
        set_socket_nonblocking(sock_b);
        addr_a = Address{"127.0.0.1", static_cast<uint16_t>(get_bound_port(sock_a))};
        addr_b = Address{"127.0.0.1", static_cast<uint16_t>(get_bound_port(sock_b))};
        a = std::make_unique<UdpMux>(sock_a, AddressFamily::IPv4, host_a);
        b = std::make_unique<UdpMux>(sock_b, AddressFamily::IPv4, host_b, b_limits);
    }

    ~MuxPair() {
        host_a.links.clear();
        host_b.links.clear();
        a.reset();
        b.reset();
        if (is_valid_socket(sock_a)) close_socket(sock_a);
        if (is_valid_socket(sock_b)) close_socket(sock_b);
    }

    /// Drive both muxes until `pred` holds. Ticking far more often than the real
    /// 20 ms costs nothing — every deadline inside a stream is timestamp-based.
    template <typename Pred>
    bool pump_until(Pred pred, std::chrono::milliseconds timeout = 10s) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;) {
            a->on_readable();
            b->on_readable();
            if (pred()) return true;
            if (std::chrono::steady_clock::now() >= deadline) return pred();
            a->tick();
            b->tick();
            std::this_thread::sleep_for(1ms);
        }
    }

    /// Open a stream from A to B and adopt it on both sides.
    std::unique_ptr<Link> dial() {
        auto link = a->connect(addr_b);
        if (link) link->attach(host_a.next_id++);  // the reactor's job
        return link;
    }
};

} // namespace

// ── Wire format ─────────────────────────────────────────────────────────────

TEST(RudpPacketTest, RoundTripsEveryField) {
    const std::string payload = "the quick brown fox";

    rudp::Packet in;
    in.type    = rudp::PacketType::Data;
    in.flags   = rudp::FlagSack;
    in.window  = 123;
    in.conn_id = 0xDEADBEEF;
    in.seq     = 0x01020304;
    in.ack     = 0x05060708;
    in.sack    = 0xF0F0F0F0;
    in.payload = ByteView(payload);

    uint8_t      buf[rudp::kMaxDatagram];
    const size_t n = rudp::encode(in, buf);
    EXPECT_EQ(n, rudp::kHeaderSize + rudp::kSackSize + payload.size());

    rudp::Packet out;
    ASSERT_TRUE(rudp::decode(buf, n, out));
    EXPECT_EQ(out.type, rudp::PacketType::Data);
    EXPECT_TRUE(out.has_sack());
    EXPECT_EQ(out.window, 123);
    EXPECT_EQ(out.conn_id, 0xDEADBEEFu);
    EXPECT_EQ(out.seq, 0x01020304u);
    EXPECT_EQ(out.ack, 0x05060708u);
    EXPECT_EQ(out.sack, 0xF0F0F0F0u);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(out.payload.data()), out.payload.size()),
              payload);
}

TEST(RudpPacketTest, EncodeHeaderMatchesEncodeAndDecodesInPlace) {
    // The send path writes the header into headroom sitting directly in front of
    // a payload it never copies, so encode_header() has to produce byte-for-byte
    // what encode() would have put there — and the result has to decode as one
    // datagram once the two are adjacent.
    const std::string payload(rudp::kMaxPayload, 'p');

    for (const bool with_sack : {false, true}) {
        rudp::Packet in;
        in.type    = rudp::PacketType::Data;
        in.flags   = with_sack ? rudp::FlagSack : rudp::FlagNone;
        in.window  = 4321;
        in.conn_id = 0x0BADC0DE;
        in.seq     = 42;
        in.ack     = 41;
        in.sack    = with_sack ? 0x00FF00FFu : 0;
        in.payload = ByteView(payload);

        uint8_t reference[rudp::kMaxDatagram];
        const size_t whole = rudp::encode(in, reference);

        // Lay the packet out the way the stream does: kMaxHeaderSize of headroom,
        // payload behind it, header written into the tail of the headroom.
        uint8_t framed[rudp::kMaxDatagram];
        std::memcpy(framed + rudp::kMaxHeaderSize, payload.data(), payload.size());
        const size_t hdr = rudp::header_size(in);
        EXPECT_EQ(hdr, with_sack ? rudp::kHeaderSize + rudp::kSackSize : rudp::kHeaderSize);

        uint8_t* const start = framed + (rudp::kMaxHeaderSize - hdr);
        EXPECT_EQ(rudp::encode_header(in, start), hdr);
        ASSERT_EQ(hdr + payload.size(), whole);
        EXPECT_EQ(std::memcmp(start, reference, whole), 0);

        rudp::Packet out;
        ASSERT_TRUE(rudp::decode(start, whole, out));
        EXPECT_EQ(out.seq, 42u);
        EXPECT_EQ(out.has_sack(), with_sack);
        EXPECT_EQ(std::string(reinterpret_cast<const char*>(out.payload.data()),
                              out.payload.size()), payload);
    }
}

TEST(RudpPacketTest, RejectsMalformed) {
    rudp::Packet p;
    p.type    = rudp::PacketType::Ack;
    p.conn_id = 7;

    uint8_t      buf[rudp::kMaxDatagram];
    const size_t n = rudp::encode(p, buf);

    rudp::Packet out;
    EXPECT_TRUE(rudp::decode(buf, n, out));

    // Truncated below the fixed header.
    EXPECT_FALSE(rudp::decode(buf, n - 1, out));
    // A sack flag with no sack word behind it.
    uint8_t truncated_sack[rudp::kMaxDatagram];
    std::memcpy(truncated_sack, buf, n);
    truncated_sack[1] |= rudp::FlagSack;
    EXPECT_FALSE(rudp::decode(truncated_sack, n, out));
    // Unknown version.
    uint8_t bad_version[rudp::kMaxDatagram];
    std::memcpy(bad_version, buf, n);
    bad_version[0] = static_cast<uint8_t>((15 << 4) | 1);
    EXPECT_FALSE(rudp::decode(bad_version, n, out));
    // Unknown type.
    uint8_t bad_type[rudp::kMaxDatagram];
    std::memcpy(bad_type, buf, n);
    bad_type[0] = static_cast<uint8_t>((rudp::kVersion << 4) | 9);
    EXPECT_FALSE(rudp::decode(bad_type, n, out));
    // Payload on a type that cannot carry one.
    uint8_t padded[rudp::kMaxDatagram];
    std::memcpy(padded, buf, n);
    padded[n] = 0xAA;
    EXPECT_FALSE(rudp::decode(padded, n + 1, out));
}

// Syn and Retry carry the address-validation cookie — and only that. Letting a
// Syn carry an arbitrary payload would hand an attacker a way to push bytes at a
// responder that has not agreed to hold anything for it, and would put those
// bytes in front of the stream the handshake is about to run over.
TEST(RudpPacketTest, OnlyACookieSizedPayloadRidesOnSynAndRetry) {
    const uint8_t cookie[rudp::kCookieSize] = {0xDE, 0xAD, 0xBE, 0xEF};

    for (const rudp::PacketType type : {rudp::PacketType::Syn, rudp::PacketType::Retry}) {
        rudp::Packet p;
        p.type    = type;
        p.conn_id = 0x1234;
        p.seq     = 1;

        uint8_t      buf[rudp::kMaxDatagram];
        rudp::Packet out;

        // Bare is fine: only a loaded responder asks for a cookie at all.
        EXPECT_TRUE(rudp::decode(buf, rudp::encode(p, buf), out)) << to_string(type);
        EXPECT_TRUE(out.payload.empty());

        // Exactly a cookie is fine, and survives the round trip.
        p.payload = ByteView(cookie, sizeof(cookie));
        const size_t n = rudp::encode(p, buf);
        ASSERT_TRUE(rudp::decode(buf, n, out)) << to_string(type);
        ASSERT_EQ(out.payload.size(), rudp::kCookieSize);
        EXPECT_EQ(std::memcmp(out.payload.data(), cookie, sizeof(cookie)), 0);

        // Anything else is not a cookie, whichever side of the width it falls.
        EXPECT_FALSE(rudp::decode(buf, n - 1, out)) << to_string(type) << " short";
        buf[n] = 0x00;
        EXPECT_FALSE(rudp::decode(buf, n + 1, out)) << to_string(type) << " long";
    }
}

// Sequence numbers advance forever in a 32-bit space and wrap. Every window check
// in the stream — "has this been acknowledged", "is this past the gap", "is this
// ack ahead of anything we sent" — goes through these three functions, so the wrap
// is handled in exactly one place. Comparing the raw values instead would invert
// the moment the counter rolls over: a sender would decide the peer had
// acknowledged packets it had never sent, and a receiver would treat everything
// arriving after the roll as already delivered.
//
// Reaching the wrap for real costs 2^32 packets (~5 TB on one stream), so it is
// the arithmetic that is tested here rather than a stream that has been driven
// there. That is where the whole risk lives: the stream only ever *uses* these.
TEST(RudpPacketTest, SequenceComparisonSurvivesTheWrap) {
    constexpr uint32_t kLast = 0xFFFFFFFFu;  // the number just before the roll

    // Ordinary ordering, far from the boundary.
    EXPECT_TRUE(rudp::seq_less(5, 6));
    EXPECT_FALSE(rudp::seq_less(6, 5));
    EXPECT_FALSE(rudp::seq_less(5, 5));
    EXPECT_TRUE(rudp::seq_le(5, 5));
    EXPECT_EQ(rudp::seq_diff(9, 5), 4);

    // Across the roll: 0 and 1 come *after* 0xFFFFFFFF, not billions before it.
    EXPECT_TRUE(rudp::seq_less(kLast, 0)) << "the wrap inverted the ordering";
    EXPECT_TRUE(rudp::seq_less(kLast - 3, 2));
    EXPECT_FALSE(rudp::seq_less(2, kLast - 3));
    EXPECT_TRUE(rudp::seq_le(kLast, kLast));

    // Distance is signed and stays exact across the roll — this is what resolves a
    // selective-ack bit to an index in the retransmission queue.
    EXPECT_EQ(rudp::seq_diff(2, kLast), 3);
    EXPECT_EQ(rudp::seq_diff(kLast, 2), -3);
    EXPECT_EQ(rudp::seq_diff(0, kLast), 1);

    // A window's worth of packets astride the boundary keeps its order throughout,
    // which is the only span the stream ever compares over.
    for (uint32_t i = 0; i + 1 < rudp::kMaxWindowPackets; ++i) {
        const uint32_t a = kLast - rudp::kMaxWindowPackets / 2 + i;
        EXPECT_TRUE(rudp::seq_less(a, a + 1)) << "at offset " << i;
        EXPECT_EQ(rudp::seq_diff(a + 1, a), 1) << "at offset " << i;
    }
}

// The header carries the raw 32-bit value, so nothing about the wrap may be lost
// on the wire — a boundary sequence number has to survive the round trip intact.
TEST(RudpPacketTest, CarriesSequenceNumbersAtTheBoundary) {
    for (const uint32_t seq : {uint32_t{0}, uint32_t{1}, uint32_t{0x7FFFFFFF},
                               uint32_t{0x80000000}, uint32_t{0xFFFFFFFF}}) {
        rudp::Packet in;
        in.type    = rudp::PacketType::Ack;
        in.conn_id = 0xABCDEF01;
        in.seq     = seq;
        in.ack     = seq - 1;  // wraps to 0xFFFFFFFF when seq is 0

        uint8_t      buf[rudp::kMaxDatagram];
        rudp::Packet out;
        ASSERT_TRUE(rudp::decode(buf, rudp::encode(in, buf), out)) << "seq " << seq;
        EXPECT_EQ(out.seq, seq);
        EXPECT_EQ(out.ack, static_cast<uint32_t>(seq - 1));
    }
}

// ── Stream behaviour ────────────────────────────────────────────────────────

TEST(UdpStreamTest, HandshakeBringsBothSidesUp) {
    Pair pair;
    EXPECT_TRUE(pair.initiator->connected());
    EXPECT_TRUE(pair.responder->connected());
}

TEST(UdpStreamTest, CarriesDataBothWays) {
    Pair pair;

    const std::string forward = "hello from the dialer";
    const std::string back    = "and hello back";
    EXPECT_EQ(write_all(*pair.initiator, forward), forward.size());
    EXPECT_EQ(write_all(*pair.responder, back), back.size());
    pair.net.settle(*pair.initiator, *pair.responder);

    EXPECT_EQ(drain(*pair.responder), forward);
    EXPECT_EQ(drain(*pair.initiator), back);
}

TEST(UdpStreamTest, SplitsAndReassemblesAcrossPackets) {
    Pair pair;

    // Several packets' worth, so the payload must be split on the way out and put
    // back together in order on the way in.
    std::string payload(rudp::kMaxPayload * 5 + 137, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>((i * 31 + 11) & 0xFF);

    ASSERT_EQ(write_all(*pair.initiator, payload), payload.size());
    pair.net.settle(*pair.initiator, *pair.responder, 128);

    EXPECT_EQ(drain(*pair.responder), payload);
}

TEST(UdpStreamTest, ReordersOutOfOrderDelivery) {
    Pair pair;

    std::string payload(rudp::kMaxPayload * 4, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i & 0xFF);
    ASSERT_EQ(write_all(*pair.initiator, payload), payload.size());

    // Hand the whole burst over backwards: the receiver sees the last packet
    // first and must hold everything until the gap in front of it fills.
    pair.net.deliver(/*reverse=*/true);
    pair.net.settle(*pair.initiator, *pair.responder, 64);

    EXPECT_EQ(drain(*pair.responder), payload);
}

TEST(UdpStreamTest, RetransmitsWhatTheNetworkDrops) {
    Pair pair;

    std::string payload(rudp::kMaxPayload * 8, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>((i * 7) & 0xFF);

    pair.net.set_drop_every(3);  // lose a third of everything, in both directions
    ASSERT_EQ(write_all(*pair.initiator, payload), payload.size());

    // Retransmission is timer-driven, so this one test has to let real time pass.
    std::string received;
    const auto deadline = std::chrono::steady_clock::now() + 20s;
    while (received.size() < payload.size() && std::chrono::steady_clock::now() < deadline) {
        pair.net.deliver();
        const auto now = std::chrono::steady_clock::now();
        pair.initiator->tick(now);
        pair.responder->tick(now);
        received += drain(*pair.responder);
        if (pair.net.queued() == 0) std::this_thread::sleep_for(5ms);
    }

    EXPECT_GT(pair.net.dropped(), 0u) << "the test never actually dropped anything";
    EXPECT_EQ(received, payload);
}

// What a retransmission timeout owes the sender's accounting.
//
// A timeout means everything outstanding is presumed gone from the path, and the
// window has just been collapsed to a single packet to say so. If those bytes stay
// counted as in flight, the sender is measuring a whole window against a one-packet
// budget: it can transmit neither the repairs it owes nor the data queued behind
// them, and creeps forward one packet per timeout instead. A brief outage then
// costs not a round trip but the rest of the transfer — the stream keeps its
// connection and delivers at a few tens of kilobytes per second until the window
// has been unpicked packet by packet.
TEST(UdpStreamTest, ATimeoutReleasesTheWindowItGaveUpOn) {
    Pair pair;

    const std::string payload(rudp::kMaxPayload * 200, 'x');
    ASSERT_EQ(write_all(*pair.initiator, payload), payload.size());

    // A path that swallows everything, held long enough for the timeout to fire.
    pair.net.drop_next(1000 * 1000);
    const auto blackout_until = std::chrono::steady_clock::now() + 400ms;
    while (std::chrono::steady_clock::now() < blackout_until) {
        const auto now = std::chrono::steady_clock::now();
        pair.net.deliver();
        pair.initiator->tick(now);
        pair.responder->tick(now);
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_GT(pair.initiator->retransmits(), 0u) << "the timeout never fired";

    // The invariant the whole thing turns on: whatever the sender still counts as
    // in flight has to fit in the window it is allowed to use, or nothing can move.
    EXPECT_LE(pair.initiator->bytes_in_flight(), pair.initiator->cwnd())
        << "a window the timeout abandoned is still counted against the sender";

    pair.net.drop_next(0);  // the path comes back

    std::string received;
    const auto deadline = std::chrono::steady_clock::now() + 20s;
    while (received.size() < payload.size() && std::chrono::steady_clock::now() < deadline) {
        const auto now = std::chrono::steady_clock::now();
        pair.net.deliver();
        pair.initiator->tick(now);
        pair.responder->tick(now);
        received += drain(*pair.responder);
        std::this_thread::sleep_for(1ms);
    }

    EXPECT_EQ(received, payload) << "the transfer never recovered from the outage";
    EXPECT_GT(pair.initiator->cwnd(), UdpStream::kMinCwnd)
        << "the window never grew back after the outage";
}

TEST(UdpStreamTest, ReducesTheWindowOnceForOneLossEpisode) {
    Pair pair;

    // Warm the window up so a whole burst can go out at once — a hole is only
    // interesting when there is enough behind it to selectively acknowledge.
    const std::string warmup(rudp::kMaxPayload * 64, 'w');
    ASSERT_EQ(write_all(*pair.initiator, warmup), warmup.size());
    pair.net.settle(*pair.initiator, *pair.responder, 128);
    ASSERT_EQ(drain(*pair.responder).size(), warmup.size());

    const uint32_t before      = pair.initiator->cwnd();
    const uint32_t before_cuts = pair.initiator->window_reductions();
    ASSERT_GT(before, UdpStream::kMinCwnd * 8) << "the warm-up never grew the window";

    // One loss episode, but a wide one: 24 consecutive packets go missing and the
    // 40 behind them arrive. The receiver answers each of those with a selective
    // ack naming the same 24 holes, and the sender repairs at most
    // kMaxRepairsPerAck of them per ack — so the repair spans several acks.
    constexpr size_t kHoles = 24;
    const std::string payload(rudp::kMaxPayload * 64, 'x');
    pair.net.drop_next(kHoles);
    ASSERT_EQ(write_all(*pair.initiator, payload), payload.size());

    // Let the repair-spacing floor expire before any ack is seen, so every hole is
    // eligible at once and the repair really does spread across acks rather than
    // being skipped as "re-sent very recently".
    std::this_thread::sleep_for(UdpStream::kMinRepairSpacing + 5ms);

    std::string received;
    const auto  deadline = std::chrono::steady_clock::now() + 20s;
    while (received.size() < payload.size() && std::chrono::steady_clock::now() < deadline) {
        pair.net.deliver();
        const auto now = std::chrono::steady_clock::now();
        pair.initiator->tick(now);
        pair.responder->tick(now);
        received += drain(*pair.responder);
        if (pair.net.queued() == 0) std::this_thread::sleep_for(2ms);
    }
    ASSERT_EQ(pair.net.dropped(), kHoles) << "the test dropped more than it meant to";
    ASSERT_EQ(received, payload);

    // The whole point: one episode costs one reduction. Reducing per repairing
    // ack instead — kHoles / kMaxRepairsPerAck of them here — halves the window
    // three times over for a loss that warranted one halving, and on a longer
    // recovery walks it all the way to kMinCwnd.
    const uint32_t cuts = pair.initiator->window_reductions() - before_cuts;
    EXPECT_EQ(cuts, 1u) << "the window was reduced " << cuts << " times for one loss episode";
    EXPECT_LT(pair.initiator->cwnd(), before) << "the loss was not accounted for at all";
}

// A duplicate acknowledgement has to be a *pure* acknowledgement.
//
// Every packet on this wire carries the ack field, so on a two-way stream the
// peer's own data rides over the same cumulative ack until our next packet
// reaches it. Counted as duplicate acks, three of those are a loss signal that no
// loss produced: the window is halved and a packet that was merely still in
// flight is sent again. On a peer-to-peer link — gossip during a transfer, any
// request while a response streams back — that is the ordinary shape of traffic
// rather than a corner case, so a sender would spend the whole connection with
// its window pinned near the floor and every small message duplicated.
TEST(UdpStreamTest, AWindowIsReleasedOverTimeRatherThanAllAtOnce) {
    TimedPair pair(40ms);
    ASSERT_TRUE(pair.initiator->connected());

    // Grow the window so there is something worth pacing. Each round drains
    // completely, so what is measured below starts from an empty pipe.
    for (int round = 0; round < 8; ++round)
        ASSERT_GT(pair.transfer(rudp::kMaxPayload * 40), 0u) << "round " << round;

    const size_t window_pkts = pair.initiator->cwnd() / rudp::kMaxPayload;
    ASSERT_GT(window_pkts, 16u) << "the warm-up never grew the window";

    // Offer far more than the window in one call. The window alone would let
    // `window_pkts` go out this instant; the pacer should release roughly one
    // millisecond's worth — at a 40 ms round trip that is a twentieth of it.
    const size_t before = pair.net.sent();
    const std::string payload(rudp::kMaxPayload * 400, 'p');
    ASSERT_GT(write_all_at(*pair.initiator, payload, pair.now), 0u);

    const size_t burst = pair.net.sent() - before;
    EXPECT_GT(burst, 0u) << "the pacer stalled a stream with an empty pipe";
    EXPECT_LT(burst, window_pkts / 2)
        << "the whole window went out at once (" << burst << " of " << window_pkts
        << " packets) — this is the burst that overruns a drop-tail queue";

    // And it is only a delay, not a cap: time passing releases the rest.
    pair.hops(2);
    EXPECT_GT(pair.net.sent(), before + burst) << "the pacer never let go";
}

TEST(UdpStreamTest, AWindowThatWentUnusedIsGivenBack) {
    TimedPair pair(40ms);

    for (int round = 0; round < 8; ++round)
        ASSERT_GT(pair.transfer(rudp::kMaxPayload * 40), 0u) << "round " << round;
    // The last bytes have arrived, but the acknowledgements for them are still on
    // their way back — a couple of hops to let the sender's pipe actually empty.
    pair.hops(6);
    ASSERT_EQ(pair.initiator->bytes_in_flight(), 0u) << "the transfer never drained";
    ASSERT_GT(pair.initiator->cwnd(), UdpStream::kInitialCwnd * 4)
        << "the warm-up never grew the window";

    // Thirty seconds of application silence — comfortably more than the
    // retransmission timeout, comfortably less than the idle timeout that would
    // end the stream. Nothing is outstanding, so nothing is retransmitted; the
    // stream simply stops learning anything about the path.
    for (int i = 0; i < 30; ++i) {
        pair.now += 1s;
        pair.initiator->tick(pair.now);
        pair.responder->tick(pair.now);
        pair.net.deliver_at(pair.now);
    }
    ASSERT_FALSE(pair.initiator->dead()) << "the idle timeout fired too early";

    EXPECT_EQ(pair.initiator->cwnd(), UdpStream::kInitialCwnd)
        << "a window nobody validated for thirty seconds was still believed; the "
           "next burst would go out on what the path looked like back then";

    // Given back, not taken away: the stream still sends.
    const std::string payload(rudp::kMaxPayload * 4, 'r');
    EXPECT_GT(write_all_at(*pair.initiator, payload, pair.now), 0u);
    pair.hops(6);
    EXPECT_EQ(drain(*pair.responder).size(), payload.size());
}

TEST(UdpStreamTest, SlowStartEndsOnARisingRoundTripWithoutALoss) {
    TimedPair pair(20ms);

    // A steady path: slow start doubles away, and nothing has told it to stop.
    for (int round = 0; round < 6; ++round) pair.transfer(rudp::kMaxPayload * 40);
    ASSERT_EQ(pair.initiator->ssthresh(), UdpStream::kMaxCwnd)
        << "slow start ended before the path gave any reason to";

    // The path starts queueing — the round trip quadruples. No packet is lost;
    // the only signal is that everything now takes longer to come back.
    pair.rtt = 80ms;
    for (int round = 0; round < 14; ++round) pair.transfer(rudp::kMaxPayload * 40);

    EXPECT_LT(pair.initiator->ssthresh(), UdpStream::kMaxCwnd)
        << "slow start kept doubling into a queue that was visibly building";
    EXPECT_EQ(pair.initiator->window_reductions(), 0u)
        << "the exit from slow start cost a loss — which is exactly what watching "
           "the round-trip time is supposed to avoid";
    EXPECT_EQ(pair.initiator->retransmits(), 0u) << "nothing should have been lost";
}

TEST(UdpStreamTest, PeerDataIsNotADuplicateAck) {
    Pair pair;

    // One exchange the peer really does acknowledge, so the sender has a "highest
    // ack seen" for a later one to look like a repeat of.
    ASSERT_GT(write_all(*pair.initiator, std::string(100, 'A')), 0u);
    pair.net.settle(*pair.initiator, *pair.responder);
    ASSERT_EQ(drain(*pair.responder).size(), 100u);

    const uint32_t cwnd_before = pair.initiator->cwnd();
    ASSERT_EQ(pair.initiator->retransmits(), 0u);
    ASSERT_EQ(pair.initiator->window_reductions(), 0u);

    // Our next packet stays in flight: queued on the path, neither delivered nor
    // dropped, exactly as a packet mid-flight on a real link.
    ASSERT_GT(write_all(*pair.initiator, std::string(100, 'B')), 0u);

    // Meanwhile the peer sends traffic of its own. Every one of these carries the
    // same cumulative ack, because 'B' has not reached it yet — and well past the
    // three that the duplicate-ack rule treats as a loss.
    for (int i = 0; i < 6; ++i) {
        ASSERT_GT(write_all(*pair.responder, std::string(200, 'x')), 0u);
        pair.net.deliver_to(kAlice);  // responder → initiator only
    }

    EXPECT_EQ(pair.initiator->retransmits(), 0u)
        << "the peer's own data was mistaken for a duplicate ack";
    EXPECT_EQ(pair.initiator->window_reductions(), 0u)
        << "the window was reduced for a loss that never happened";
    EXPECT_GE(pair.initiator->cwnd(), cwnd_before);

    // Nothing was actually lost, so the stream still owes nothing once the held
    // packet finally lands.
    pair.net.settle(*pair.initiator, *pair.responder);
    EXPECT_EQ(drain(*pair.responder), std::string(100, 'B'));
}

TEST(UdpStreamTest, FillsAWindowLargerThanTheOldCeiling) {
    Pair pair;

    // Slow start doubles the window every round trip, so a transfer long enough
    // to keep the pipe full runs it up until something stops it. Nothing is lost
    // here and the receiver is drained every round, so the only thing that can
    // stop it is the window ceiling itself.
    const std::string payload(1400 * 1024, 'z');
    ASSERT_EQ(write_all(*pair.initiator, payload), payload.size());

    size_t peak = 0;
    for (int round = 0; round < 256 && pair.net.queued() > 0; ++round) {
        pair.net.deliver();
        peak = (std::max)(peak, pair.initiator->bytes_in_flight());
        const auto now = std::chrono::steady_clock::now();
        pair.initiator->tick(now);
        pair.responder->tick(now);
        drain(*pair.responder);  // keep the receiver's advertised window open
    }

    // The old 256-packet window capped in-flight data at ~300 KiB, which on a
    // 100 ms path is ~24 Mbit/s however fast the link underneath is.
    constexpr size_t kOldCeiling = 256 * rudp::kMaxPayload;
    EXPECT_GT(peak, kOldCeiling) << "in-flight data still capped at the old window";
}

TEST(UdpStreamTest, SendQueueOutgrowsAFullWindow) {
    // The send queue bounds `sent_` and `unsent_` together, so at or below a full
    // window it — not the window — would silently become the throughput ceiling,
    // and nothing would be queued behind what is in flight to keep the pipe fed.
    static_assert(UdpStream::kSendQueueLimit >
                      size_t{rudp::kMaxWindowPackets} * rudp::kMaxPayload,
                  "send queue must hold more than one full window");
    SUCCEED();
}

TEST(UdpStreamTest, SendQueueIsBounded) {
    Pair pair;

    // Nothing is delivered, so nothing is acknowledged: the queue fills and the
    // stream must start refusing rather than buffering without limit.
    const std::string chunk(64 * 1024, 'x');
    size_t            accepted = 0;
    for (int i = 0; i < 100; ++i) {
        const size_t n = write_all(*pair.initiator, chunk);
        accepted += n;
        if (n == 0) break;
    }
    EXPECT_LE(accepted, UdpStream::kSendQueueLimit);
    EXPECT_EQ(write_all(*pair.initiator, chunk), 0u) << "queue limit not enforced";
}

TEST(UdpStreamTest, FinEndsTheStream) {
    Pair pair;

    const std::string last = "goodbye";
    ASSERT_EQ(write_all(*pair.initiator, last), last.size());
    pair.initiator->begin_close(std::chrono::steady_clock::now());
    pair.net.settle(*pair.initiator, *pair.responder);

    // Everything written before the Fin is still delivered, and only then does
    // the peer see the end of the stream.
    EXPECT_EQ(drain(*pair.responder), last);
    EXPECT_TRUE(pair.responder->eof());
}

TEST(UdpStreamTest, ResetKillsTheStream) {
    Pair pair;

    pair.initiator->abort(std::chrono::steady_clock::now());
    pair.net.deliver();

    EXPECT_TRUE(pair.initiator->dead());
    EXPECT_TRUE(pair.responder->dead());
    EXPECT_EQ(pair.responder->close_reason(), CloseReason::PeerReset);
}

TEST(UdpStreamTest, UnansweredDialGivesUp) {
    FakeNet    net;
    const auto now = std::chrono::steady_clock::now();
    UdpStream  dialer(net, kBob, 100, 101, ConnRole::Outbound, now);
    // Nothing is attached at kBob: the Syn goes nowhere, exactly as it would on a
    // network that blocks UDP.

    const auto deadline = std::chrono::steady_clock::now() + 20s;
    while (!dialer.dead() && std::chrono::steady_clock::now() < deadline) {
        dialer.tick(std::chrono::steady_clock::now());
        std::this_thread::sleep_for(10ms);
    }

    ASSERT_TRUE(dialer.dead()) << "a dial into the void never gave up";
    EXPECT_EQ(dialer.close_reason(), CloseReason::ConnectFailed);
}

// Flow control is separate from congestion control and absolute: the receiver says
// how much more it will buffer, and the sender does not exceed it whatever the
// congestion window would allow. Without it a peer that stops reading decides how
// much memory we spend on it — the receive buffer would grow to everything the
// sender is willing to queue, and the only bound left would be the send queue at
// the far end.
//
// The far more interesting half is the recovery: a window that closes has to
// reopen without either side being told to look. The sender is not sending (it has
// no room to send into), so nothing of its own will carry the news back, and the
// receiver has no traffic to append the update to.
TEST(UdpStreamTest, AClosedReceiveWindowStopsTheSenderAndResumesOnRead) {
    Pair pair;

    // More than a full receive window, so the receiver's buffer really does fill
    // while nothing reads it. That the send queue can hold more than one window is
    // exactly what makes this reachable — see SendQueueOutgrowsAFullWindow.
    constexpr size_t kWindowBytes = size_t{rudp::kMaxWindowPackets} * rudp::kMaxPayload;
    std::string      payload(UdpStream::kSendQueueLimit, '\0');
    for (size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>((i * 13 + 7) & 0xFF);
    ASSERT_GT(payload.size(), kWindowBytes) << "the transfer cannot fill a window";
    ASSERT_EQ(write_all(*pair.initiator, payload), payload.size());

    // Phase one: run the path with the receiver never reading a byte.
    const auto stall_until = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < stall_until) {
        pair.net.deliver();
        const auto now = std::chrono::steady_clock::now();
        pair.initiator->tick(now);
        pair.responder->tick(now);
        if (pair.net.queued() == 0) std::this_thread::sleep_for(1ms);
    }

    // The stall is the point: the sender still owes data it cannot send.
    EXPECT_GT(pair.initiator->queued_bytes(), 0u)
        << "the sender handed over everything despite a closed window";
    // Neither side may treat a stopped peer as a dead one. The sender probes a
    // zero window with a single packet on the retransmission timeout, and the
    // receiver acknowledges each probe — so the attempt counter never builds up
    // and nothing here is on a path to being declared gone.
    EXPECT_FALSE(pair.initiator->dead()) << "a full receiver was mistaken for a lost one";
    EXPECT_FALSE(pair.responder->dead());

    const std::string first = drain(*pair.responder);
    EXPECT_LT(first.size(), payload.size()) << "flow control never stopped the sender";
    EXPECT_GT(first.size(), kWindowBytes / 2) << "the sender stopped far short of the window";

    // Phase two: the buffer has just been drained, so the window is open again and
    // the transfer has to pick itself back up with no help from the test.
    std::string received = first;
    const auto  deadline = std::chrono::steady_clock::now() + 20s;
    while (received.size() < payload.size() && std::chrono::steady_clock::now() < deadline) {
        pair.net.deliver();
        const auto now = std::chrono::steady_clock::now();
        pair.initiator->tick(now);
        pair.responder->tick(now);
        received += drain(*pair.responder);
        if (pair.net.queued() == 0) std::this_thread::sleep_for(1ms);
    }

    EXPECT_EQ(received, payload) << "the transfer never resumed after the window reopened";
}

// A window that re-opens has to be announced, with nothing to announce it on.
//
// The test above lets the sender find out for itself: a stopped sender still probes,
// and the acknowledgement of a probe carries the current window, so the transfer
// recovers whether or not the receiver ever volunteers anything. That hides the
// contract this test pins down. While the window is zero there is, by construction,
// no traffic for an acknowledgement to ride on — so if draining the buffer does not
// make the receiver speak up by itself, the only thing left to restart the transfer
// is whatever the peer happens to probe with, at whatever interval its retransmission
// timeout has backed off to. read() records that the window re-opened; the point here
// is that the record is acted on.
//
// It also matters ahead of any tightening of flow control: a receiver that starts
// *refusing* data past the window it advertised (as TCP does) has no probe to answer,
// and this ack becomes the only way out of a zero window at all.
TEST(UdpStreamTest, AReopenedWindowIsAnnouncedWithoutPeerTraffic) {
    Pair pair;

    // Fill the receive buffer by hand rather than by running a real transfer: what
    // is under test is the *receiver's* behaviour once it is full, and getting there
    // through the sender would spend a thousand round trips on setup.
    const Bytes body(rudp::kMaxPayload, 'x');
    const auto  now = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < rudp::kMaxWindowPackets; ++i) {
        rudp::Packet p;
        p.type    = rudp::PacketType::Data;
        p.conn_id = pair.responder->recv_id();
        p.seq     = 2 + i;   // the Syn took sequence number 1
        p.ack     = 0;       // nothing of the responder's is outstanding to retire
        p.window  = rudp::kMaxWindowPackets;
        p.payload = ByteView(body);
        pair.responder->on_packet(p, now);
    }

    rudp::Packet closed;
    ASSERT_TRUE(pair.net.peek_last(closed)) << "the receiver acknowledged nothing at all";
    ASSERT_EQ(closed.window, 0) << "the receive buffer never actually filled";

    // From here the peer says nothing more — it is stopped on a zero window and,
    // correctly, will not send again until it is told otherwise.
    const size_t before = pair.net.sent();
    EXPECT_EQ(drain(*pair.responder).size(),
              size_t{rudp::kMaxWindowPackets} * rudp::kMaxPayload);

    pair.responder->tick(std::chrono::steady_clock::now());

    ASSERT_GT(pair.net.sent(), before) << "the window re-opened and nobody was told";
    rudp::Packet update;
    ASSERT_TRUE(pair.net.peek_last(update));
    EXPECT_GT(update.window, 0) << "the update carried the same closed window";
}

// A hole is repaired from what the selective ack names, not from a timeout.
//
// The sender's queue here is far longer than a selective ack can reach: one word
// names the 32 packets after the hole, while the queue behind it runs to hundreds.
// That gap is load-bearing — repair_sacked_holes() bounds its search by the reach
// of the ack rather than by the length of the queue, which is only sound because a
// bit cannot mark anything further out. If that bound were ever tightened past the
// real reach, this is the test that would notice: the repair would silently stop
// happening and recovery would fall back to waiting out a retransmission timeout,
// with the transfer still completing and nothing else looking wrong.
TEST(UdpStreamTest, AHoleBehindALongQueueIsRepairedWithoutATimeout) {
    Pair pair;

    // Warm the window up, so the burst that follows is long enough to outrun what
    // one selective ack can describe.
    const std::string warmup(rudp::kMaxPayload * 64, 'w');
    ASSERT_EQ(write_all(*pair.initiator, warmup), warmup.size());
    pair.net.settle(*pair.initiator, *pair.responder, 128);
    ASSERT_EQ(drain(*pair.responder).size(), warmup.size());
    ASSERT_EQ(pair.initiator->window_reductions(), 0u) << "the warm-up lost something";

    const uint32_t repairs_before = pair.initiator->retransmits();

    // Lose the four packets at the front of the next burst; everything behind them
    // arrives. Four, not one: a single hole is repaired by the duplicate-ack rule
    // long before the selective ack is consulted — which is exactly what a mutation
    // test showed, so a one-packet hole proves nothing about this path. The
    // duplicate-ack rule resends only sent_.front(), and only once per episode, so
    // the three holes behind it can be closed by nothing but the selective ack (or,
    // if that fails, by a timeout — which is what the clock below rules out).
    constexpr size_t kHoles        = 4;
    constexpr size_t kBurstPackets = 64;
    ASSERT_GT(kBurstPackets, rudp::kSackBits) << "the queue must outrun one sack word";
    pair.net.drop_next(kHoles);
    const std::string payload(rudp::kMaxPayload * kBurstPackets, 'x');
    ASSERT_EQ(write_all(*pair.initiator, payload), payload.size());

    // Let the repair-spacing floor expire before any ack lands, so the repair is
    // not skipped as "re-sent very recently" and the clock below measures the
    // decision rather than the floor.
    std::this_thread::sleep_for(UdpStream::kMinRepairSpacing + 5ms);

    // Watch for the repairs themselves, not for the transfer to finish: a
    // retransmission that happens sooner than the *minimum* retransmission timeout
    // could not have come from a timeout, so it can only have come from the
    // acknowledgement. All kHoles of them, so the count cannot be satisfied by the
    // one packet the duplicate-ack rule is entitled to resend.
    const auto started  = std::chrono::steady_clock::now();
    const auto give_up  = started + 5s;
    while (pair.initiator->retransmits() - repairs_before < kHoles &&
           std::chrono::steady_clock::now() < give_up) {
        pair.net.deliver();
        const auto now = std::chrono::steady_clock::now();
        pair.initiator->tick(now);
        pair.responder->tick(now);
        drain(*pair.responder);
        if (pair.net.queued() == 0) std::this_thread::sleep_for(1ms);
    }
    const auto took = std::chrono::steady_clock::now() - started;

    ASSERT_GE(pair.initiator->retransmits() - repairs_before, kHoles)
        << "only " << (pair.initiator->retransmits() - repairs_before) << " of " << kHoles
        << " holes were repaired; the rest were left to a timeout";
    EXPECT_LT(took, UdpStream::kMinRto)
        << "the holes waited out a retransmission timeout instead of being repaired from the ack";
    // A timeout would have collapsed the window to a single packet; a repair driven
    // by an acknowledgement halves it, because packets are demonstrably still
    // flowing. One episode, either way — but only one of them leaves room to send.
    EXPECT_GT(pair.initiator->cwnd(), rudp::kMaxPayload)
        << "the window collapsed as it would on a timeout";
    EXPECT_EQ(pair.initiator->window_reductions(), 1u);
}

// A pure acknowledgement is worth a datagram of its own only when it has to be.
// Every packet carries the ack field, so one that waits a moment usually finds
// something to ride along on for free; one sent per arriving packet doubles the
// packet count of every bulk transfer for nothing.
TEST(UdpStreamTest, APureAckIsDelayedRatherThanSentPerPacket) {
    Pair pair;

    const size_t before = pair.net.sent();

    // One in-order packet: no gap in front of it, and the ack-every-other-packet
    // rule not yet reached. There is nothing to say that cannot wait.
    ASSERT_GT(write_all(*pair.initiator, std::string(64, 'q')), 0u);
    pair.net.deliver();
    EXPECT_EQ(pair.net.sent(), before + 1)
        << "a lone in-order packet was acknowledged with a datagram of its own";

    // Waiting is not forgetting: the delayed-ack deadline is what gets it out when
    // nothing came along to carry it.
    pair.responder->tick(std::chrono::steady_clock::now() + UdpStream::kDelayedAck + 5ms);
    EXPECT_EQ(pair.net.sent(), before + 2) << "the delayed acknowledgement never went out";
}

// The other half of that rule: a bulk sender must not have to wait out the delay
// on every second packet, or its window opens one delayed ack at a time.
TEST(UdpStreamTest, EveryOtherPacketIsAcknowledgedAtOnce) {
    Pair pair;

    const size_t before = pair.net.sent();

    // Two packets' worth in one write, so the second arrival reaches the
    // ack-every-other-segment threshold within the same batch.
    const std::string payload(rudp::kMaxPayload + 100, 'z');
    ASSERT_EQ(write_all(*pair.initiator, payload), payload.size());
    pair.net.deliver();

    // Two data packets out, one acknowledgement straight back — no timer involved.
    EXPECT_EQ(pair.net.sent(), before + 3)
        << "the second packet did not draw an immediate acknowledgement";
    EXPECT_EQ(drain(*pair.responder), payload);
}

// An idle stream still has to say something now and then. It keeps the peer's idle
// timer from firing, and — the reason it matters more here than it would on TCP —
// it keeps the NAT mapping for this port from being reclaimed underneath a node
// that is simply not busy.
TEST(UdpStreamTest, KeepAliveBreaksALongSilence) {
    Pair pair;
    ASSERT_TRUE(pair.initiator->connected());

    const size_t before = pair.net.sent();

    // Well short of the interval: nothing is owed, so nothing is said.
    pair.initiator->tick(std::chrono::steady_clock::now() + UdpStream::kKeepAlive / 2);
    EXPECT_EQ(pair.net.sent(), before) << "an idle stream chattered";

    // Past it: an acknowledgement goes out for its own sake.
    pair.initiator->tick(std::chrono::steady_clock::now() + UdpStream::kKeepAlive + 1s);
    EXPECT_EQ(pair.net.sent(), before + 1) << "the keep-alive never went out";
}

// And the converse: silence long enough to outlast several keep-alives is a peer
// that is gone, not one that is quiet. Holding the stream open would leak it —
// a datagram transport gets no close notification from anywhere.
TEST(UdpStreamTest, ASilentPeerTimesOut) {
    Pair pair;
    ASSERT_TRUE(pair.responder->connected());

    // Just short of the timeout, with nothing arriving: still a live stream.
    pair.responder->tick(std::chrono::steady_clock::now() + UdpStream::kIdleTimeout - 1s);
    EXPECT_FALSE(pair.responder->dead()) << "a quiet stream was closed too early";

    pair.responder->tick(std::chrono::steady_clock::now() + UdpStream::kIdleTimeout + 1s);
    EXPECT_TRUE(pair.responder->dead()) << "a stream whose peer vanished was held open";
    EXPECT_EQ(pair.responder->close_reason(), CloseReason::IdleTimeout);
}

// ── The mux: demultiplexing, admission, resets, linger ──────────────────────

// The dialer picks `base`, keeps it as its recv id and sends under `base + 1`, so
// the responder derives both ids from the Syn alone — no negotiation round trip.
TEST(UdpMuxTest, PairsConnectionIdsFromTheSynAlone) {
    MuxPair net;

    auto dial = net.dial();
    ASSERT_TRUE(dial);
    ASSERT_TRUE(net.pump_until([&] { return net.host_b.adopted == 1; }))
        << "the Syn never produced an inbound stream";

    Link* accepted = net.host_b.only_link();
    ASSERT_NE(accepted, nullptr);

    UdpStream& out = stream_of(*dial);
    UdpStream& in  = stream_of(*accepted);

    EXPECT_EQ(out.send_id(), out.recv_id() + 1) << "the dialer's id pairing is what B relies on";
    EXPECT_EQ(in.recv_id(), out.send_id());
    EXPECT_EQ(in.send_id(), out.recv_id());
    EXPECT_EQ(in.role(), ConnRole::Inbound);

    EXPECT_TRUE(net.pump_until([&] { return out.connected() && in.connected(); }));
    EXPECT_EQ(net.a->stream_count(), 1u);
    EXPECT_EQ(net.b->stream_count(), 1u);
}

// The same round trip the stream tests do, but through the Link vocabulary and
// two real sockets — so encode, sendto, demux and decode are all in the path.
TEST(UdpMuxTest, CarriesDataOverTheSharedSocket) {
    MuxPair net;

    auto dial = net.dial();
    ASSERT_TRUE(dial);
    ASSERT_TRUE(net.pump_until([&] { return net.host_b.adopted == 1; }));
    ASSERT_TRUE(net.pump_until([&] { return stream_of(*dial).connected(); }));

    Link* accepted = net.host_b.only_link();
    ASSERT_NE(accepted, nullptr);

    const std::string out_msg = "dialer speaking";
    const std::string in_msg  = "and the other end";
    const ByteView    out_slice(out_msg), in_slice(in_msg);
    ASSERT_EQ(dial->write(&out_slice, 1).bytes, out_msg.size());
    ASSERT_EQ(accepted->write(&in_slice, 1).bytes, in_msg.size());

    std::string got_b, got_a;
    EXPECT_TRUE(net.pump_until([&] {
        got_b += read_all(*accepted);
        got_a += read_all(*dial);
        return got_b == out_msg && got_a == in_msg;
    })) << "b got '" << got_b << "', a got '" << got_a << "'";
}

// Adoption may be refused (the node is at capacity). Refusing destroys the link,
// which releases the stream the mux created a moment earlier — so nothing may be
// left behind, and the dialer has to be told rather than retransmitting into a void.
TEST(UdpMuxTest, RefusedInboundStreamLeavesNothingBehind) {
    MuxPair net;
    net.host_b.refuse = true;

    auto dial = net.dial();
    ASSERT_TRUE(dial);
    ASSERT_TRUE(net.pump_until([&] { return net.host_b.refused >= 1; }))
        << "admission was never asked";

    EXPECT_EQ(net.host_b.adopted, 0);
    EXPECT_EQ(net.b->stream_count(), 0u) << "a refused stream was kept";

    EXPECT_TRUE(net.pump_until([&] { return stream_of(*dial).dead(); }))
        << "the dialer was never told it had been turned away";
    EXPECT_EQ(stream_of(*dial).close_reason(), CloseReason::PeerReset);
}

// A datagram for a stream nobody has is answered with a Reset — and that Reset
// can only echo the id the *sender* uses, which is not the id the sender is keyed
// by. find_for_reset() bridges the two; without it the peer would retransmit for
// a minute against a mux that has already forgotten it.
TEST(UdpMuxTest, ResetForAForgottenStreamFindsItsWayHome) {
    MuxPair net;

    auto dial = net.dial();
    ASSERT_TRUE(dial);
    ASSERT_TRUE(net.pump_until([&] { return net.host_b.adopted == 1; }));
    ASSERT_TRUE(net.pump_until([&] { return stream_of(*dial).connected(); }));

    // B's connection goes away with nothing owed, so the stream is dropped at once.
    net.host_b.links.clear();
    ASSERT_EQ(net.b->stream_count(), 0u);

    const std::string msg = "still there?";
    const ByteView    slice(msg);
    ASSERT_GT(dial->write(&slice, 1).bytes, 0u);

    EXPECT_TRUE(net.pump_until([&] { return stream_of(*dial).dead(); }))
        << "the reset never got routed back to the stream that provoked it";
    EXPECT_EQ(stream_of(*dial).close_reason(), CloseReason::PeerReset);
}

// TCP gets this from the kernel, which keeps retransmitting after close(). Here it
// is the mux's job: a node that writes one last message and disconnects must still
// have it delivered, and the stream must then be reclaimed rather than kept forever.
TEST(UdpMuxTest, LingersLongEnoughToDeliverTheLastBytes) {
    MuxPair net;

    auto dial = net.dial();
    ASSERT_TRUE(dial);
    ASSERT_TRUE(net.pump_until([&] { return net.host_b.adopted == 1; }));
    ASSERT_TRUE(net.pump_until([&] { return stream_of(*dial).connected(); }));

    Link* accepted = net.host_b.only_link();
    ASSERT_NE(accepted, nullptr);

    const std::string farewell = "one last thing";
    const ByteView    slice(farewell);
    ASSERT_EQ(dial->write(&slice, 1).bytes, farewell.size());

    // The connection disappears immediately after the write — before a single byte
    // has been acknowledged. This is exactly what the linger exists for.
    dial.reset();
    EXPECT_EQ(net.a->stream_count(), 1u) << "the stream was dropped with data still owed";

    std::string got;
    EXPECT_TRUE(net.pump_until([&] { got += read_all(*accepted); return got == farewell; }))
        << "the last message was lost; got '" << got << "'";

    // ...and once it is all acknowledged, the mux stops holding it.
    EXPECT_TRUE(net.pump_until([&] { return net.a->stream_count() == 0; }))
        << "a flushed lingering stream was never reclaimed";
}

// ── Admission: what an unproven dial is allowed to cost ─────────────────────
//
// A TCP listener is protected by arithmetic it never has to write: an inbound
// connection costs a file descriptor, and no forged source address can make the
// kernel hand one out, because the three-way handshake has to complete first.
// A datagram listener has neither. Without the two checks these tests cover, a
// sixteen-byte Syn from an address that does not exist buys an attacker a stream,
// a connection and a half-built Noise handshake, held for the establish timeout —
// and nothing at all bounds how many of those they can buy at once.

TEST(UdpMuxTest, AnUnprovenDialCostsTheResponderNothing) {
    UdpMuxLimits validate_everything;
    validate_everything.validate_above = 0;
    MuxPair net{validate_everything};

    socket_t probe = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(probe));
    set_socket_nonblocking(probe);

    // A Syn from an address B has never heard from. This is the forged datagram.
    constexpr uint32_t kBase = 0x0BADC0DEu;
    rudp::Packet syn;
    syn.type    = rudp::PacketType::Syn;
    syn.conn_id = kBase + 1;   // dialers send under base + 1 and listen on base
    syn.seq     = 1;
    uint8_t syn_buf[rudp::kMaxDatagram];
    ASSERT_GT(send_udp_to(probe, syn_buf, rudp::encode(syn, syn_buf), net.addr_b,
                          AddressFamily::IPv4), 0);

    ASSERT_TRUE(wait_for([&] { net.b->on_readable(); return net.b->stream_count() > 0
                                                          || net.host_b.adopted > 0
                                                          || probe_has_data(probe); }))
        << "the dial was neither answered nor refused";

    EXPECT_EQ(net.b->stream_count(), 0u) << "an unproven dial created a stream";
    EXPECT_EQ(net.host_b.adopted, 0)     << "an unproven dial reached the connection layer";

    // What came back instead is a cookie, addressed to the id the dialer listens on.
    uint8_t      buf[rudp::kMaxDatagram];
    Address      from;
    const auto   n = recv_udp_from(probe, buf, sizeof(buf), from);
    ASSERT_GE(n, 0);
    rudp::Packet retry;
    ASSERT_TRUE(rudp::decode(buf, static_cast<size_t>(n), retry));
    ASSERT_EQ(retry.type, rudp::PacketType::Retry);
    EXPECT_EQ(retry.conn_id, kBase) << "the Retry went to the wrong id";
    ASSERT_EQ(retry.payload.size(), rudp::kCookieSize);
    const Bytes cookie = retry.payload.to_bytes();

    // A cookie that was not issued buys nothing either.
    Bytes forged = cookie;
    forged[0] ^= 0xFF;
    syn.payload = ByteView(forged);
    ASSERT_GT(send_udp_to(probe, syn_buf, rudp::encode(syn, syn_buf), net.addr_b,
                          AddressFamily::IPv4), 0);
    for (int i = 0; i < 50; ++i) { net.b->on_readable(); std::this_thread::sleep_for(1ms); }
    EXPECT_EQ(net.b->stream_count(), 0u) << "a forged cookie was accepted";

    // The real one does, because only something that can receive at this address
    // could have got hold of it.
    syn.payload = ByteView(cookie);
    ASSERT_GT(send_udp_to(probe, syn_buf, rudp::encode(syn, syn_buf), net.addr_b,
                          AddressFamily::IPv4), 0);
    EXPECT_TRUE(wait_for([&] { net.b->on_readable(); return net.host_b.adopted == 1; }))
        << "a validated dial was still refused";
    EXPECT_EQ(net.b->stream_count(), 1u);

    close_socket(probe);
}

// The property the whole mechanism exists for, stated directly: however many
// dials arrive from addresses that never answer, the memory they can make this
// node hold does not grow past the validation threshold. Before there was one,
// each of these bought a stream, a connection and a half-built Noise handshake
// for fifteen seconds — and nothing capped how many.
TEST(UdpMuxTest, AFloodOfUnansweredDialsCannotGrowPastTheThreshold) {
    UdpMuxLimits limits;
    limits.validate_above = 8;      // small, so the flood needed to pass it is small
    limits.max_streams    = 4096;   // well clear, so it is the threshold being tested
    MuxPair net{limits};

    socket_t probe = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(probe));
    set_socket_nonblocking(probe);

    // Two thousand distinct dials, none of which ever comes back with its cookie —
    // which is exactly what an attacker with a forged source address looks like,
    // since the cookie is delivered to the address they claimed to be.
    constexpr int kDials = 2000;
    for (int i = 0; i < kDials; ++i) {
        rudp::Packet syn;
        syn.type    = rudp::PacketType::Syn;
        syn.conn_id = 0x0100'0000u + static_cast<uint32_t>(i) * 2 + 1;
        syn.seq     = 1;

        uint8_t buf[rudp::kMaxDatagram];
        send_udp_to(probe, buf, rudp::encode(syn, buf), net.addr_b, AddressFamily::IPv4);

        // Keep the socket drained so the flood is processed rather than dropped by
        // the kernel — the point is what the mux does with it, not what it misses.
        if (i % 16 == 0) { net.b->on_readable(); net.b->tick(); }
    }
    for (int i = 0; i < 100; ++i) { net.b->on_readable(); net.b->tick();
                                    std::this_thread::sleep_for(1ms); }

    // Exactly the threshold: enough of the flood got through to fill every slot the
    // node is willing to hand out unproven (so the test is not passing vacuously),
    // and not one dial beyond it cost anything at all.
    EXPECT_EQ(net.b->stream_count(), limits.validate_above);
    EXPECT_EQ(static_cast<size_t>(net.host_b.adopted), limits.validate_above);

    close_socket(probe);
}

// The extra round trip is the transport's business, not the caller's: a dialer
// that is asked to prove its address does so and connects, with nothing above the
// stream aware that anything happened.
TEST(UdpMuxTest, ValidationIsInvisibleToARealDial) {
    UdpMuxLimits validate_everything;
    validate_everything.validate_above = 0;
    MuxPair net{validate_everything};

    auto dial = net.dial();
    ASSERT_TRUE(dial);

    ASSERT_TRUE(net.pump_until([&] { return net.host_b.adopted == 1; }))
        << "the dialer never came back with the cookie it was given";
    ASSERT_TRUE(net.pump_until([&] { return stream_of(*dial).connected(); }));

    Link* accepted = net.host_b.only_link();
    ASSERT_NE(accepted, nullptr);

    // And the cookie is not mistaken for stream content: the first bytes the peer
    // reads must be the ones actually written, not four bytes of hash in front.
    const std::string msg = "first bytes on the stream";
    const ByteView    slice(msg);
    ASSERT_EQ(dial->write(&slice, 1).bytes, msg.size());

    std::string got;
    EXPECT_TRUE(net.pump_until([&] { got += read_all(*accepted); return got == msg; }))
        << "got '" << got << "'";
}

// The backstop under the cookie. Everything counted here has already proved its
// address, so reaching it means real peers — but the ceiling has to exist, or
// "validated" would still mean "unbounded".
TEST(UdpMuxTest, RefusesDialsAtTheStreamCeiling) {
    UdpMuxLimits tiny;
    tiny.max_streams    = 1;
    tiny.validate_above = SIZE_MAX;   // isolate the ceiling from the cookie
    MuxPair net{tiny};

    auto first = net.dial();
    ASSERT_TRUE(first);
    ASSERT_TRUE(net.pump_until([&] { return net.host_b.adopted == 1; }));
    ASSERT_EQ(net.b->stream_count(), 1u);

    // A second dial from a different socket, so it is a genuinely new stream.
    socket_t probe = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(probe));
    set_socket_nonblocking(probe);

    rudp::Packet syn;
    syn.type    = rudp::PacketType::Syn;
    syn.conn_id = 0x5EC0'0DE1u;
    syn.seq     = 1;
    uint8_t syn_buf[rudp::kMaxDatagram];
    ASSERT_GT(send_udp_to(probe, syn_buf, rudp::encode(syn, syn_buf), net.addr_b,
                          AddressFamily::IPv4), 0);

    ASSERT_TRUE(wait_for([&] { net.b->on_readable(); return probe_has_data(probe); }))
        << "the dial at the ceiling was ignored rather than refused";

    uint8_t    buf[rudp::kMaxDatagram];
    Address    from;
    const auto n = recv_udp_from(probe, buf, sizeof(buf), from);
    ASSERT_GE(n, 0);
    rudp::Packet reply;
    ASSERT_TRUE(rudp::decode(buf, static_cast<size_t>(n), reply));
    EXPECT_EQ(reply.type, rudp::PacketType::Reset) << "a refused dial should be told so";

    EXPECT_EQ(net.b->stream_count(), 1u) << "the ceiling was crossed";
    EXPECT_EQ(net.host_b.adopted, 1);

    close_socket(probe);
}

// How a burst of packets for one stream turns into readable events decides two
// things at once, and they pull in opposite directions.
//
// A stream raises PollIn for every packet it delivers, so the naive answer — one
// dispatch each — spends a map lookup and a read attempt per packet, and all but
// the first find the buffer already drained. Coalescing fixes that.
//
// The opposite mistake is to coalesce so well that the whole drain becomes one
// dispatch. Delivered bytes wait in the stream's in-order buffer until its
// connection reads them out, so a single dispatch at the end lets that buffer grow
// to everything the peer managed to send — through main memory rather than cache,
// and far enough to close the receive window mid-drain. So the events are handed
// over once per receive batch: often enough to bound the buffer, rarely enough
// that the per-packet cost is gone.
TEST(UdpMuxTest, BurstsCoalesceIntoOneEventPerBatchRatherThanOnePerPacket) {
    MuxPair net;

    auto dial = net.dial();
    ASSERT_TRUE(dial);
    ASSERT_TRUE(net.pump_until([&] { return net.host_b.adopted == 1; }));
    ASSERT_TRUE(net.pump_until([&] { return stream_of(*dial).connected(); }));

    Link* accepted = net.host_b.only_link();
    ASSERT_NE(accepted, nullptr);
    const uint32_t stream_id = stream_of(*accepted).recv_id();

    // Hand-built packets rather than a real write, so the burst is not shaped by
    // the sender's congestion window: this is about what the receiver does with a
    // pile of datagrams, and the pile has to be bigger than one batch to tell the
    // two failure modes apart. They come from A's socket because a stream only
    // accepts datagrams from the address it was established with. The Syn took
    // sequence number 1, so the data starts at 2.
    constexpr size_t kPackets = kUdpBatchMax * 2 + 6;
    for (size_t i = 0; i < kPackets; ++i) {
        rudp::Packet p;
        p.type    = rudp::PacketType::Data;
        p.conn_id = stream_id;
        p.seq     = static_cast<uint32_t>(2 + i);
        p.window  = rudp::kMaxWindowPackets;
        const uint8_t byte = 'x';
        p.payload = ByteView(&byte, 1);

        uint8_t buf[rudp::kMaxDatagram];
        ASSERT_GT(send_udp_to(net.sock_a, buf, rudp::encode(p, buf), net.addr_b,
                              AddressFamily::IPv4), 0);
    }

    // Let the whole burst land before B looks at the socket even once.
    std::this_thread::sleep_for(100ms);
    net.host_b.dispatches = 0;
    net.b->on_readable();

    const size_t consumed = read_all(*accepted).size();  // one byte per packet
    ASSERT_GE(consumed, kUdpBatchMax * 2)
        << "the burst did not arrive as one readable event; there is nothing to measure";

    EXPECT_LT(net.host_b.dispatches, consumed)
        << "one dispatch per packet — the events were not coalesced";
    EXPECT_GE(net.host_b.dispatches, 2u)
        << "one dispatch for the whole drain — the in-order buffer is free to grow "
           "to everything the peer sent before the connection is ever told to read";
    EXPECT_LE(net.host_b.dispatches, 6u)
        << "more dispatches than there were receive batches";
}

// The mux stages outgoing datagrams so a burst leaves in one syscall instead of
// dozens. Staging is only sound if nothing is ever left waiting for a later timer,
// so every entry point flushes before it returns — which is what this pins down.
// A dial that sat in the staging buffer until the next tick would still work, and
// would still be a 20 ms regression on every connection the node makes.
TEST(UdpMuxTest, StagedDatagramsLeaveBeforeTheCallThatMadeThemReturns) {
    MuxPair net;

    socket_t probe = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(probe));
    set_socket_nonblocking(probe);
    const Address probe_addr{"127.0.0.1", static_cast<uint16_t>(get_bound_port(probe))};

    // Read one packet from the probe, without ever ticking the mux. The decoded
    // payload points into `into`, so that buffer belongs to the caller and has to
    // outlive every use of the packet.
    uint8_t    into[rudp::kMaxDatagram];
    const auto next_packet = [&](rudp::Packet& out) {
        for (int attempt = 0; attempt < 500; ++attempt) {
            Address    from;
            const auto n = recv_udp_from(probe, into, sizeof(into), from);
            if (n >= 0 && rudp::decode(into, static_cast<size_t>(n), out)) return true;
            std::this_thread::sleep_for(1ms);
        }
        return false;
    };

    // connect(): the Syn IS the dial, so it cannot wait for company.
    auto dial = net.a->connect(probe_addr);
    ASSERT_TRUE(dial);
    dial->attach(net.host_a.next_id++);

    rudp::Packet syn;
    ASSERT_TRUE(next_packet(syn)) << "the Syn never left the staging buffer";
    EXPECT_EQ(syn.type, rudp::PacketType::Syn);

    // on_readable(): the ack for what just arrived goes out with it. Answering the
    // Syn by hand is enough to bring the dialer's stream up.
    rudp::Packet ack;
    ack.type    = rudp::PacketType::Ack;
    ack.conn_id = syn.conn_id - 1;   // the id pairing the dialer chose
    ack.seq     = 1;
    ack.ack     = syn.seq;
    ack.window  = rudp::kMaxWindowPackets;
    uint8_t ack_buf[rudp::kMaxDatagram];
    ASSERT_GT(send_udp_to(probe, ack_buf, rudp::encode(ack, ack_buf), net.addr_a,
                          AddressFamily::IPv4), 0);

    ASSERT_TRUE(wait_for([&] { net.a->on_readable(); return stream_of(*dial).connected(); }))
        << "the hand-written ack never brought the stream up";

    // A write now produces a Data packet from outside any datagram batch, exactly
    // as an application send does. It must not wait for the next tick either — the
    // Reactor flushes at the end of its loop turn, and MuxPair has no reactor, so
    // this leans on release()/on_readable() rather than on tick().
    const std::string msg = "no waiting";
    const ByteView    slice(msg);
    ASSERT_EQ(dial->write(&slice, 1).bytes, msg.size());
    net.a->flush_output();

    rudp::Packet data;
    ASSERT_TRUE(next_packet(data)) << "the payload never left the staging buffer";
    EXPECT_EQ(data.type, rudp::PacketType::Data);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(data.payload.data()),
                          data.payload.size()), msg);

    // release(): the Connection says goodbye through the Link and only then lets go
    // of it, so the Fin is staged by a call that is not itself a mux entry point.
    // Handing the stream back is what has to put it on the wire.
    dial->close(CloseReason::LocalClose);   // stages a Fin; flushes nothing
    dial.reset();                           // release() → flush_output()

    rudp::Packet bye;
    ASSERT_TRUE(next_packet(bye)) << "the stream went away without saying so";
    EXPECT_EQ(bye.type, rudp::PacketType::Fin);

    close_socket(probe);
}

// Every unknown datagram gets a Reset, which is a reflector unless it is capped.
// The budget is a sliding window on the clock rather than a per-tick counter (the
// mux has no fixed tick to hang it on, and a node with no streams — the one a
// junk flood is aimed at — would never tick at all), so the property to test is a
// *rate*: a burst drained inside one window may not outrun one window's budget.
TEST(UdpMuxTest, ResetsAreCappedSoTheSocketCannotReflect) {
    MuxPair net;

    socket_t probe = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(probe));
    set_socket_nonblocking(probe);

    constexpr int kJunk = UdpMux::kMaxUnsolicitedReplies * 3;
    for (int i = 0; i < kJunk; ++i) {
        rudp::Packet p;
        p.type    = rudp::PacketType::Data;   // not a Syn: nothing may be created
        p.conn_id = 0xC0FFEE00u + static_cast<uint32_t>(i);
        p.seq     = 1;
        const uint8_t byte = 'x';
        p.payload = ByteView(&byte, 1);

        uint8_t buf[rudp::kMaxDatagram];
        send_udp_to(probe, buf, rudp::encode(p, buf), net.addr_b, AddressFamily::IPv4);
    }

    // Drain the whole burst as fast as the socket will give it up, with no sleeps:
    // three windows' worth of junk delivered inside as little of one window as this
    // machine allows. (The replies are staged, and on_readable() flushes them before
    // it returns, so they are all on the wire by the end of this loop.)
    const auto drain_from = std::chrono::steady_clock::now();
    for (int i = 0; i < 50; ++i) net.b->on_readable();
    const auto drain_to = std::chrono::steady_clock::now();
    EXPECT_EQ(net.b->stream_count(), 0u) << "junk datagrams created streams";

    int resets = 0, quiet = 0;
    while (quiet < 50) {
        uint8_t      buf[rudp::kMaxDatagram];
        Address      from;
        const auto   n = recv_udp_from(probe, buf, sizeof(buf), from);
        if (n < 0) { ++quiet; std::this_thread::sleep_for(1ms); continue; }
        quiet = 0;
        rudp::Packet p;
        if (rudp::decode(buf, static_cast<size_t>(n), p) && p.type == rudp::PacketType::Reset)
            ++resets;
    }
    close_socket(probe);

    // What the limiter is entitled to have emitted: one window's budget for every
    // window the drain spanned, plus the one it started inside. Deriving the bound
    // from measured time rather than fixing it keeps this a test of the rate even
    // if the scheduler takes the drain loop away for a while.
    const auto spanned = std::chrono::duration_cast<std::chrono::milliseconds>(drain_to - drain_from);
    const int  windows = static_cast<int>(spanned / UdpMux::kUnsolicitedReplyWindow) + 1;

    EXPECT_GT(resets, 0) << "an unknown stream should be answered, not ignored";
    EXPECT_LE(resets, UdpMux::kMaxUnsolicitedReplies * windows)
        << "the reset budget was not enforced (drain spanned " << spanned.count() << " ms)";
    EXPECT_LT(resets, kJunk) << "every junk datagram was answered; the budget did nothing";
}

// ── Scheduling: what the mux asks the reactor to wake up for ────────────────
//
// Every stream owes its peer work on a deadline — a retransmission timeout, a
// delayed ack, a keep-alive, the idle timer. Serving those by sweeping every
// stream on a fixed 20 ms cadence woke the reactor fifty times a second for the
// life of the process, whether or not any stream had anything to do, and whether
// or not the node had any streams at all. These fix the replacement: a deadline
// queue that asks for nothing when there is nothing due, sleeps all the way to
// the next real deadline when there is, and is told whenever one moves earlier.

TEST(UdpMuxTest, AMuxWithNoStreamsAsksForNoWakeups) {
    MuxPair net;
    // The cap is what a caller offers as "I would sleep this long anyway". Handing
    // it straight back is the mux saying it needs nothing sooner.
    EXPECT_EQ(net.a->next_timeout_ms(60'000), 60'000)
        << "a mux with no streams at all still wanted waking";
}

/// Drive `net` until A's mux has settled to a genuinely idle schedule.
///
/// Settling is not instant, and deliberately so: a deadline that moves *later*
/// (the dial's retransmission timeout giving way to the keep-alive once the Syn is
/// acknowledged) does not get a heap slot of its own. The stale slot is left to
/// fire, find nothing to do, and re-arm from there — one early wake-up, once,
/// against a heap push on every packet if it were kept exact. So the property
/// under test is where it converges, not what it reports mid-flight.
namespace {
bool settle_idle(MuxPair& net, std::unique_ptr<Link>& dial) {
    if (!net.pump_until([&] { return stream_of(*dial).connected(); })) return false;
    if (!net.pump_until([&] { return stream_of(*dial).flushed(); })) return false;
    return net.pump_until([&] { return net.a->next_timeout_ms(60'000) > 1000; }, 3s);
}
} // namespace

TEST(UdpMuxTest, AnIdleStreamSleepsUntilItsKeepAlive) {
    MuxPair net;

    auto dial = net.dial();
    ASSERT_TRUE(dial);
    ASSERT_TRUE(settle_idle(net, dial));

    // Nothing outstanding, nothing to acknowledge: the earliest deadline is the
    // keep-alive, three orders of magnitude past the 20 ms sweep this replaced.
    const int ms = net.a->next_timeout_ms(60'000);
    const auto keep_alive_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(UdpStream::kKeepAlive).count();
    EXPECT_GT(ms, 1000) << "an idle stream still asked to be woken in " << ms << " ms";
    EXPECT_LE(ms, keep_alive_ms) << "the keep-alive would have been missed";
}

TEST(UdpMuxTest, DataToSendBringsTheNextWakeupForward) {
    MuxPair net;

    auto dial = net.dial();
    ASSERT_TRUE(dial);
    ASSERT_TRUE(settle_idle(net, dial));

    const int idle_ms = net.a->next_timeout_ms(60'000);
    ASSERT_GT(idle_ms, 1000) << "the stream was not actually idle";

    // A write starts the retransmission timer, which is due long before the
    // keep-alive the mux had scheduled. Nothing on the datagram path was involved,
    // so the mux learns of it only because UdpStreamLink::write tells it — and if
    // it did not, this packet would go unrepaired until the keep-alive fired.
    const std::string payload = "wake me sooner than that";
    const ByteView    slice(payload);
    ASSERT_GT(dial->write(&slice, 1).bytes, 0u);

    const int armed_ms = net.a->next_timeout_ms(60'000);
    const auto rto_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(UdpStream::kInitialRto).count();
    EXPECT_LT(armed_ms, idle_ms) << "a deadline that moved earlier never reached the mux";
    EXPECT_LE(armed_ms, rto_ms)  << "the retransmission timeout would have been missed";
}

// ── End to end, through a Node ──────────────────────────────────────────────

// ── Backpressure: an application can tell it is outrunning the link ─────────
//
// Without this the only thing that ever tells a sender it is going too fast is
// the disconnection — the send queue fills silently, crosses the high-water mark
// and the peer is dropped as a slow consumer, with nothing the application could
// have checked beforehand. So send() answers "is there room?" and, once there is
// again, on_peer_writable says so.
//
// The marks are driven from the config here rather than the default 8 MiB, which
// is what makes this deterministic instead of a race: send() weighs the queue
// *before* it flushes, so a single message larger than the low-water mark takes
// the queue over it on the spot, whatever the link does afterwards.
TEST(TransportUdpTest, AnApplicationThatHeedsBackpressureKeepsItsPeer) {
    NodeConfig server_cfg = base_config();
    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen = false;
    // A deliberately small queue: 256 KiB before the peer would be dropped as a
    // slow consumer, so 64 KiB before send() starts saying "no room". Moving four
    // megabytes through it is only possible if the signal works.
    client_cfg.send_queue_limit = 256 * 1024;

    Node server(server_cfg), client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    std::atomic<size_t> got{0};
    server.on("bulk", [&](Peer, ByteView payload) { got += payload.size(); });

    std::atomic<int> openings{0};
    client.on_peer_writable([&](const Peer&) { ++openings; });

    std::atomic<int> lost{0};
    client.on_peer_disconnected([&](const PeerId&) { ++lost; });

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    const PeerId peer = client.peers().front().id;
    EXPECT_TRUE(client.peer_writable(peer)) << "an idle peer reported no room";
    EXPECT_FALSE(client.peer_writable(PeerId{})) << "a peer that is not there has no room";

    // Offer far more than the queue can hold, but stop whenever told to and wait
    // for the opening. This is the whole contract, and it is what an application
    // could not do at all before: without the answer there is nothing to wait on
    // and the only outcome is the disconnection.
    constexpr size_t kChunk = 32 * 1024;
    constexpr size_t kTotal = 4 * 1024 * 1024;
    const std::string chunk(kChunk, 'b');

    int  seen   = 0;
    bool paused = false;
    for (size_t offered = 0; offered < kTotal; offered += kChunk) {
        if (!client.send(peer, "bulk", ByteView(chunk))) {
            paused = true;
            ASSERT_TRUE(wait_for([&] { return openings.load() > seen || lost.load() > 0; }))
                << "the queue filled and never reported draining — a sender doing "
                   "the right thing would wait forever";
            seen = openings.load();
        }
        ASSERT_EQ(lost.load(), 0) << "the peer was dropped despite the sender pausing "
                                     "every time it was asked to";
    }

    EXPECT_TRUE(paused) << "the queue never filled, so this proved nothing — raise "
                           "the offered volume or lower send_queue_limit";
    ASSERT_TRUE(wait_for([&] { return got.load() == kTotal; }, 30s))
        << "backpressure dropped data it should only have delayed (" << got.load()
        << " of " << kTotal << " B)";
    EXPECT_EQ(lost.load(), 0);

    client.stop();
    server.stop();
}

TEST(TransportUdpTest, TwoNodesConnectOverUdp) {
    NodeConfig server_cfg = base_config();
    server_cfg.enable_tcp = false;              // UDP is the only way in
    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen = false;
    client_cfg.enable_tcp    = false;

    Node server(server_cfg), client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    EXPECT_EQ(server.transports(), PeerTransportUdp);

    std::mutex               mutex;
    std::vector<std::string> received;
    server.on("echo", [&](Peer peer, ByteView payload) {
        std::lock_guard<std::mutex> lock(mutex);
        received.emplace_back(reinterpret_cast<const char*>(payload.data()), payload.size());
    });

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }))
        << "no UDP connection was established";

    const auto peers = client.peers();
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].transport, TransportKind::Udp);

    const std::string msg = "over datagrams";
    client.broadcast("echo", ByteView(msg));
    ASSERT_TRUE(wait_for([&] {
        std::lock_guard<std::mutex> lock(mutex);
        return received.size() == 1;
    })) << "message never arrived";
    {
        std::lock_guard<std::mutex> lock(mutex);
        EXPECT_EQ(received[0], msg);
    }

    client.stop();
    server.stop();
}

// Eight megabytes through the user-space reliability layer, in one direction,
// with the connection's own backpressure in play.
TEST(TransportUdpTest, CarriesABulkTransfer) {
    NodeConfig server_cfg = base_config();
    server_cfg.enable_tcp = false;
    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen = false;
    client_cfg.enable_tcp    = false;

    Node server(server_cfg), client(client_cfg);

    std::atomic<size_t> total{0};
    std::atomic<int>    frames{0};
    server.on("bulk", [&](Peer, ByteView payload) {
        total += payload.size();
        ++frames;
    });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; }));

    constexpr int    kFrames    = 512;
    constexpr size_t kFrameSize = 16 * 1024;
    const std::string chunk(kFrameSize, 'z');
    for (int i = 0; i < kFrames; ++i) client.broadcast("bulk", ByteView(chunk));

    ASSERT_TRUE(wait_for([&] { return frames.load() == kFrames; }, 30s))
        << "got " << frames.load() << "/" << kFrames << " frames ("
        << total.load() << " bytes)";
    EXPECT_EQ(total.load(), kFrames * kFrameSize);

    client.stop();
    server.stop();
}

// A peer that only speaks TCP is still reachable: the UDP attempt fails and the
// dialer brings the other transport in without the caller doing anything.
TEST(TransportUdpTest, FallsBackToTcpWhenTheServerHasNoUdp) {
    NodeConfig server_cfg = base_config();
    server_cfg.enable_udp = false;              // TCP only
    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen        = false;
    client_cfg.preferred_transport  = TransportKind::Udp;
    client_cfg.transport_fallback_ms = 300;     // keep the test brisk

    Node server(server_cfg), client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    EXPECT_EQ(server.transports(), PeerTransportTcp);

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }))
        << "the dialer never fell back to TCP";

    const auto peers = client.peers();
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].transport, TransportKind::Tcp);

    client.stop();
    server.stop();
}

// With both transports on both ends, the preferred one wins outright — the
// fallback is never even started, so exactly one connection exists.
TEST(TransportUdpTest, PrefersUdpWhenBothAreAvailable) {
    Node server(base_config());
    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen = false;

    Node client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    EXPECT_EQ(server.transports(), PeerTransportTcp | PeerTransportUdp);

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    // Give a racing TCP attempt every chance to show up before asserting it did not.
    std::this_thread::sleep_for(500ms);
    const auto peers = client.peers();
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].transport, TransportKind::Udp);
    EXPECT_EQ(server.peer_count(), 1u);

    client.stop();
    server.stop();
}

// With no fallback delay both transports really are in flight at once, so the
// supersede path is exercised rather than skipped: the first handshake to finish
// wins and closes its sibling, and neither end may be left holding a duplicate.
TEST(TransportUdpTest, RacingAttemptsLeaveExactlyOnePeer) {
    Node       server(base_config());
    NodeConfig client_cfg           = base_config();
    client_cfg.enable_listen        = false;
    client_cfg.transport_fallback_ms = 1;   // race both from the very start

    Node client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    // Let the losing attempt finish whatever it was doing before asserting that it
    // did not survive it.
    std::this_thread::sleep_for(1s);
    EXPECT_EQ(client.peer_count(), 1u) << "a superseded attempt was kept";
    EXPECT_EQ(server.peer_count(), 1u) << "the server kept a duplicate of the same peer";

    client.stop();
    server.stop();
}

// Both transports bind the same port, so one advertised address is dialable
// either way — and identify tells the peer which of them are actually open.
TEST(TransportUdpTest, BothTransportsShareOnePort) {
    Node server(base_config());
    ASSERT_TRUE(server.start());

    const uint16_t port = server.listen_port();
    ASSERT_NE(port, 0);
    EXPECT_EQ(server.transports(), PeerTransportTcp | PeerTransportUdp);

    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen = false;
    Node client(client_cfg);
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", port);
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; }));
    ASSERT_TRUE(wait_for([&] {
        const auto peers = client.peers();
        return !peers.empty() && peers[0].supported_transports ==
                                     (PeerTransportTcp | PeerTransportUdp);
    })) << "identify never reported the peer's transports";

    client.stop();
    server.stop();
}
