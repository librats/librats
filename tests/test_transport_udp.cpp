#include <gtest/gtest.h>
#include "test_paths.h"

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

    /// Run the pair to a standstill: deliver, tick, repeat until neither side has
    /// anything left in flight or waiting to go out.
    ///
    /// An empty queue is NOT a standstill. The sender is paced against the real
    /// clock — it releases roughly cwnd/srtt of data per unit of wall time — so a
    /// round that delivered everything and got nothing back has not finished the
    /// transfer, it has hit the pacer, and the only thing that moves it on is time
    /// actually passing. Stopping there instead ends the loop mid-transfer, and
    /// how far it got becomes a function of how loaded the machine is: a busy box
    /// inflates the round-trip sample the pace rate is derived from, so the same
    /// loop delivers a fraction of what it does on an idle one. Waiting on
    /// flushed() and letting the clock move is what makes the outcome the same in
    /// both. `stalls` bounds the waiting so a test that drops packets for good
    /// still returns promptly rather than sitting out a transfer that can never
    /// complete.
    void settle(UdpStream& a, UdpStream& b, int rounds = 32, int stalls = 400) {
        int stalled = 0;
        for (int i = 0; i < rounds;) {
            if (queue_.empty() && a.flushed() && b.flushed()) return;
            if (queue_.empty()) {
                if (++stalled > stalls) return;
                std::this_thread::sleep_for(500us);
            } else {
                stalled = 0;
                ++i;
            }
            deliver();
            const auto now = std::chrono::steady_clock::now();
            a.tick(now);
            b.tick(now);
        }
    }

    /// Deliver only what is addressed to `only`, leaving the other direction
    /// queued. Lets a test hold one side's packet genuinely in flight — neither
    /// lost nor arrived — while the other side keeps talking.
    void deliver_to(const Address& only, std::chrono::steady_clock::time_point now) {
        std::deque<Datagram> batch;
        batch.swap(queue_);

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

    /// The simulated "now" that pump() drives this pair with. Deliberately taken
    /// *after* the handshake has settled, so it is never behind a timestamp the
    /// two streams already recorded.
    std::chrono::steady_clock::time_point now;

    Pair() {
        const auto start = std::chrono::steady_clock::now();
        // Alice dials Bob. The id pairing mirrors the mux: the dialer keeps
        // `base` and sends under `base + 1`; the responder is the mirror image.
        constexpr uint32_t kBase = 0x11223344;
        initiator = std::make_unique<UdpStream>(net, kBob, kBase, kBase + 1,
                                                ConnRole::Outbound, start);
        responder = std::make_unique<UdpStream>(net, kAlice, kBase + 1, kBase,
                                                ConnRole::Inbound, start);
        net.attach(kBob, responder.get());
        net.attach(kAlice, initiator.get());
        net.settle(*initiator, *responder);
        now = std::chrono::steady_clock::now();
    }
};

/// Drive `pair` on an injected clock until `until` holds, advancing its simulated
/// clock by `step` each round.
///
/// UdpStream reads no clock of its own: every deadline it has — the retransmission
/// timeout, the pacer, the delayed ack, the keep-alive — is a function of the
/// timestamp it is handed. So simulated time buys a timer-driven test exactly what
/// slept-through time does, at no wall-clock cost, and it is the more faithful of
/// the two: real sleeps overshoot on a loaded machine, which moves the round-trip
/// estimate all of those deadlines derive from, and the same loop then covers a
/// different amount of ground on every run.
///
/// `until` runs once per round, after the wire has been handed over — which is
/// where a test that has to read does it, whether to collect what arrived or to
/// keep the receive window open. False if `budget` of simulated time ran out
/// first, so a test that stops converging fails instead of spinning.
template <typename Pred>
bool pump(Pair& pair, Pred until,
          std::chrono::steady_clock::duration budget = std::chrono::seconds(60),
          std::chrono::steady_clock::duration step   = std::chrono::milliseconds(1)) {
    const auto limit = pair.now + budget;
    for (;;) {
        pair.net.deliver_at(pair.now);
        pair.initiator->tick(pair.now);
        pair.responder->tick(pair.now);
        if (until()) return true;
        if (pair.now >= limit) return false;
        pair.now += step;
    }
}

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
    c.protocol = librats_test::test_protocol();
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
    ASSERT_EQ(write_all_at(*pair.initiator, payload, pair.now), payload.size());

    // Retransmission is timer-driven, so this one has to let time pass — simulated
    // time, which is the only kind the stream knows about (see pump()).
    std::string received;
    const bool  done = pump(pair, [&] {
        received += drain(*pair.responder);
        return received.size() >= payload.size();
    });

    ASSERT_TRUE(done) << "a third of the packets lost was never repaired";
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
    ASSERT_EQ(write_all_at(*pair.initiator, payload, pair.now), payload.size());

    // A path that swallows everything, held long enough for the timeout to fire.
    pair.net.drop_next(1000 * 1000);
    const auto blackout_ends = pair.now + 400ms;
    pump(pair, [&] { return pair.now >= blackout_ends; }, 1s);
    ASSERT_GT(pair.initiator->retransmits(), 0u) << "the timeout never fired";

    // The invariant the whole thing turns on: whatever the sender still counts as
    // in flight has to fit in the window it is allowed to use, or nothing can move.
    EXPECT_LE(pair.initiator->bytes_in_flight(), pair.initiator->cwnd())
        << "a window the timeout abandoned is still counted against the sender";

    pair.net.drop_next(0);  // the path comes back

    std::string received;
    const bool  done = pump(pair, [&] {
        received += drain(*pair.responder);
        return received.size() >= payload.size();
    });

    ASSERT_TRUE(done) << "the transfer never recovered from the outage";
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

TEST(UdpStreamTest, ALostTailIsProbedRatherThanTimedOut) {
    TimedPair pair(40ms);

    // Warm up so there is a window worth protecting, and so the round-trip
    // estimate the probe timer is derived from is real.
    for (int round = 0; round < 6; ++round)
        ASSERT_GT(pair.transfer(rudp::kMaxPayload * 20), 0u) << "round " << round;
    pair.hops(6);
    ASSERT_EQ(pair.initiator->bytes_in_flight(), 0u);

    const uint32_t cwnd_before = pair.initiator->cwnd();
    const uint32_t cuts_before = pair.initiator->window_reductions();
    ASSERT_GT(cwnd_before, UdpStream::kInitialCwnd * 2) << "the warm-up never grew the window";

    // A single small message whose one packet is lost. This is the case nothing
    // else can see: the receiver has everything before it, so it sends no
    // duplicate acknowledgements and names no hole — it simply has nothing to say.
    const std::string tail(64, 't');
    pair.net.drop_next(1);
    ASSERT_EQ(write_all_at(*pair.initiator, tail, pair.now), tail.size());

    // Give it well under a retransmission timeout to recover. Without the probe
    // the only thing that could rescue this is the RTO, which cannot fire before
    // kMinRto and would collapse the window when it did.
    const auto deadline = pair.now + UdpStream::kMinRto;
    std::string received;
    while (pair.now < deadline && received.size() < tail.size()) {
        pair.hop();
        received += drain(*pair.responder);
    }

    EXPECT_EQ(received, tail)
        << "a lost tail packet was not recovered inside a retransmission timeout — "
           "which is the whole point of probing for it";
    EXPECT_GE(pair.initiator->tail_probes(), 1) << "nothing probed";
    EXPECT_EQ(pair.initiator->window_reductions(), cuts_before)
        << "the probe was treated as congestion and cost the window, which is what "
           "it exists to avoid";
    EXPECT_EQ(pair.initiator->cwnd(), cwnd_before) << "the window moved on a probe";
}

TEST(UdpStreamTest, AProbeNamesTheHolesBehindItSoALostBurstStillCostsTheWindow) {
    TimedPair pair(40ms);

    for (int round = 0; round < 6; ++round)
        ASSERT_GT(pair.transfer(rudp::kMaxPayload * 20), 0u) << "round " << round;
    pair.hops(6);
    ASSERT_EQ(pair.initiator->bytes_in_flight(), 0u);

    const uint32_t cwnd_before = pair.initiator->cwnd();
    const uint32_t cuts_before = pair.initiator->window_reductions();
    ASSERT_GT(cwnd_before, UdpStream::kInitialCwnd * 2) << "the warm-up never grew the window";

    // A whole burst lost at the tail — the shape a queue that has just overflowed
    // actually produces. Nothing gets through, so as in the single-packet case the
    // receiver has no duplicate acknowledgement to send and no hole to name, and
    // only a probe can break the silence. Unlike that case, though, this one IS
    // congestion, and the probe must lead to the stream admitting it.
    constexpr size_t kLost = 8;
    const std::string tail(rudp::kMaxPayload * kLost, 't');
    pair.net.drop_next(kLost);
    ASSERT_EQ(write_all_at(*pair.initiator, tail, pair.now), tail.size());

    // Generous, because the point here is not the exact timing: probing the wrong
    // end recovers one packet per probe and takes several times this.
    const auto deadline = pair.now + 8 * UdpStream::kMinRto;
    std::string received;
    while (pair.now < deadline && received.size() < tail.size()) {
        pair.hop();
        received += drain(*pair.responder);
    }

    EXPECT_EQ(received, tail)
        << "a lost burst at the tail was not repaired — probing the front of the "
           "queue recovers one packet at a time, because that acknowledgement names "
           "no hole and resets the probe budget before the timeout can escalate";
    EXPECT_GT(pair.initiator->window_reductions(), cuts_before)
        << "eight packets were lost and the window was never reduced: the probe "
           "answered every silence and the stream never noticed the congestion";
    EXPECT_LT(pair.initiator->cwnd(), cwnd_before)
        << "the window came out of a total loss no smaller than it went in";
}

// The whole point is that nothing here fires a *timer*, so the clock is injected
// rather than left to run: settling this by hand on the wall clock takes a
// hundred-odd sub-millisecond sleeps, which on a busy machine can overshoot the
// retransmission timeout — and the test would then be reporting a stall in its own
// pacing loop as a duplicate-ack bug.
TEST(UdpStreamTest, PeerDataIsNotADuplicateAck) {
    Pair pair;

    // One exchange the peer really does acknowledge, so the sender has a "highest
    // ack seen" for a later one to look like a repeat of.
    ASSERT_GT(write_all_at(*pair.initiator, std::string(100, 'A'), pair.now), 0u);
    std::string first;
    ASSERT_TRUE(pump(pair, [&] {
        first += drain(*pair.responder);
        return first.size() == 100 && pair.initiator->flushed();
    }, 2s)) << "the first exchange never completed";

    const uint32_t cwnd_before = pair.initiator->cwnd();
    ASSERT_EQ(pair.initiator->retransmits(), 0u);
    ASSERT_EQ(pair.initiator->window_reductions(), 0u);

    // Our next packet stays in flight: queued on the path, neither delivered nor
    // dropped, exactly as a packet mid-flight on a real link.
    ASSERT_GT(write_all_at(*pair.initiator, std::string(100, 'B'), pair.now), 0u);

    // Meanwhile the peer sends traffic of its own. Every one of these carries the
    // same cumulative ack, because 'B' has not reached it yet — and well past the
    // three that the duplicate-ack rule treats as a loss.
    for (int i = 0; i < 6; ++i) {
        ASSERT_GT(write_all_at(*pair.responder, std::string(200, 'x'), pair.now), 0u);
        pair.net.deliver_to(kAlice, pair.now);  // responder → initiator only
    }

    EXPECT_EQ(pair.initiator->retransmits(), 0u)
        << "the peer's own data was mistaken for a duplicate ack";
    EXPECT_EQ(pair.initiator->window_reductions(), 0u)
        << "the window was reduced for a loss that never happened";
    EXPECT_GE(pair.initiator->cwnd(), cwnd_before);

    // Nothing was actually lost, so the stream still owes nothing once the held
    // packet finally lands.
    std::string rest;
    EXPECT_TRUE(pump(pair, [&] {
        rest += drain(*pair.responder);
        return rest.size() == 100 && pair.initiator->flushed();
    }, 2s));
    EXPECT_EQ(rest, std::string(100, 'B'));
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
    // An empty queue means the pacer is holding the next burst, not that the
    // transfer is over — and the pace rate comes off a wall-clock round-trip
    // sample, so on a loaded machine it collapses and this loop would stop with
    // the window barely off the floor. Run until the sender has genuinely nothing
    // left, giving the clock the chance to move whenever the pacer is what is in
    // the way, and bound the waiting so the test cannot hang.
    for (int round = 0, stalled = 0; round < 256 && stalled < 400;) {
        if (pair.net.queued() == 0) {
            if (pair.initiator->flushed()) break;
            ++stalled;
            std::this_thread::sleep_for(500us);
        } else {
            stalled = 0;
            ++round;
        }
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

// Nothing answers a Syn on a network that swallows datagrams, so the only thing
// that can end the attempt is the Syn budget running out. The transport race is
// built on that happening promptly (see node/dialer.h), which makes *how long* it
// takes as much the subject here as the fact that it happens — so the clock is
// injected rather than waited out: the stream reads no clock of its own, and the
// budget is then pinned exactly, at no wall-clock cost and with no dependence on
// how loaded the machine is.
TEST(UdpStreamTest, UnansweredDialGivesUp) {
    FakeNet    net;
    const auto start = std::chrono::steady_clock::now();
    UdpStream  dialer(net, kBob, 100, 101, ConnRole::Outbound, start);
    // Nothing is attached at kBob: the Syn goes nowhere, exactly as it would on a
    // network that blocks UDP.

    // A bound on the *simulated* elapsed time, generous enough that a budget which
    // stopped expiring shows up as a failure rather than a hang.
    auto       now = start;
    const auto limit = start + 60s;
    while (!dialer.dead() && now < limit) {
        now += 10ms;
        dialer.tick(now);
    }

    ASSERT_TRUE(dialer.dead()) << "a dial into the void never gave up";
    EXPECT_EQ(dialer.close_reason(), CloseReason::ConnectFailed);

    // The Syn is transmitted its full budget of times and no more: one fewer and a
    // lossy path would be mistaken for a blocked one, one more and the race waits
    // longer than the fallback was sized for.
    EXPECT_EQ(net.sent(), static_cast<size_t>(UdpStream::kSynMaxAttempts))
        << "the dial did not spend exactly its Syn budget";

    // And it spends them on a doubling timeout, so the cost of a blocked path is
    // bounded and known — that bound is what the dialer's fallback is sized against.
    const auto waited = now - start;
    EXPECT_GE(waited, UdpStream::kInitialRto) << "the dial gave up before its first retry";
    EXPECT_LE(waited, 10s) << "an unanswered dial held the transport race far too long";
}

// ── The dial's retry shape (DialProfile) ────────────────────────────────────
//
// The ordinary dial above is patient and sparse: three Syns spread over seconds,
// sized so a UDP-blocked path is recognised quickly. A hole punch needs the exact
// opposite and can ask for it — see the tests below for why the difference is not
// cosmetic.

/// A NAT in front of Bob: inbound datagrams are dropped except during a window,
/// which is what a peer's own outbound burst opens on the far side. Only Bob is
/// gated; his replies come back freely, exactly as a filter works.
class GatedNet final : public FakeNet {
public:
    using Clock = std::chrono::steady_clock;

    explicit GatedNet(Clock::time_point now) : now_(now) {}

    void set_now(Clock::time_point now) { now_ = now; }
    void open_between(Clock::time_point from, Clock::time_point to) { from_ = from; to_ = to; }

    void send_datagram(const Address& to, const uint8_t* data, size_t len) override {
        if (to == kBob) {
            ++toward_bob_;
            if (now_ < from_ || now_ >= to_) return;  // the filter has nothing open
        }
        FakeNet::send_datagram(to, data, len);
    }

    /// Datagrams aimed at Bob, whether or not the filter let them through — i.e.
    /// how many probes the dial actually spent.
    size_t probes() const { return toward_bob_; }

private:
    Clock::time_point now_;
    Clock::time_point from_{(Clock::time_point::max)()};
    Clock::time_point to_{(Clock::time_point::max)()};
    size_t            toward_bob_ = 0;
};

/// Dial into `net` with `profile` and run the clock until the stream resolves.
/// Returns the simulated time it took.
std::chrono::steady_clock::duration run_dial(GatedNet& net, UdpStream& dialer,
                                             UdpStream* responder,
                                             std::chrono::steady_clock::time_point start,
                                             std::chrono::steady_clock::duration budget = 8s) {
    auto now = start;
    while (!dialer.dead() && !dialer.connected() && now - start < budget) {
        now += 10ms;
        net.set_now(now);
        net.deliver_at(now);
        dialer.tick(now);
        if (responder) responder->tick(now);
    }
    return now - start;
}

// The punch profile trades the long patient tail for a dense burst: more probes,
// evenly spaced, all of them inside a window a NAT might plausibly hold open.
TEST(UdpStreamTest, ThePunchProfileSpendsMoreProbesAndDoesNotBackOff) {
    const auto start = std::chrono::steady_clock::now();
    GatedNet   net(start);   // never opened: the dial spends its whole budget
    UdpStream  dialer(net, kBob, 100, 101, ConnRole::Outbound, start, DialProfile::punch());

    const auto waited = run_dial(net, dialer, nullptr, start);

    ASSERT_TRUE(dialer.dead());
    EXPECT_EQ(dialer.close_reason(), CloseReason::ConnectFailed);
    EXPECT_EQ(net.probes(), 8u) << "the punch profile did not spend its probe budget";

    // Eight probes 200 ms apart with no backoff: the last one goes out at ~1.4 s.
    // A profile that quietly kept the doubling would run past four seconds here,
    // which is the failure this bound is here to catch.
    EXPECT_GE(waited, 1400ms) << "the probes were spent faster than the profile asked";
    EXPECT_LE(waited, 2s)     << "the punch dial backed off when it was told not to";
}

// Why density is the whole point. A punch lands only while BOTH sides are probing,
// and that overlap is short — the peer's burst is finite and its filter closes
// again after it. A dial whose probes are seconds apart can miss such a window
// entirely; one that probes every 200 ms cannot miss a window wider than that.
TEST(UdpStreamTest, ADenseDialCrossesAShortWindowThatASpacedOneMisses) {
    // 550–750 ms after the dial starts: after the default profile's 500 ms probe
    // and long before its next one at ~1.5 s.
    constexpr auto kOpensAt  = 550ms;
    constexpr auto kClosesAt = 750ms;
    constexpr uint32_t kBase = 0x2A2A2A2A;

    {   // The ordinary dial: nothing of its is in the air while the filter is open.
        const auto start = std::chrono::steady_clock::now();
        GatedNet   net(start);
        net.open_between(start + kOpensAt, start + kClosesAt);

        UdpStream dialer(net, kBob, kBase, kBase + 1, ConnRole::Outbound, start);
        UdpStream responder(net, kAlice, kBase + 1, kBase, ConnRole::Inbound, start);
        net.attach(kBob, &responder);
        net.attach(kAlice, &dialer);

        run_dial(net, dialer, &responder, start);
        EXPECT_TRUE(dialer.dead()) << "the spaced dial should have missed the window";
        EXPECT_FALSE(dialer.connected());
    }

    {   // The punch profile: probes at 0, 200, 400, 600 … — 600 ms lands inside it.
        const auto start = std::chrono::steady_clock::now();
        GatedNet   net(start);
        net.open_between(start + kOpensAt, start + kClosesAt);

        UdpStream dialer(net, kBob, kBase, kBase + 1, ConnRole::Outbound, start,
                         DialProfile::punch());
        UdpStream responder(net, kAlice, kBase + 1, kBase, ConnRole::Inbound, start);
        net.attach(kBob, &responder);
        net.attach(kAlice, &dialer);

        run_dial(net, dialer, &responder, start);
        EXPECT_TRUE(dialer.connected()) << "the punch dial missed a window wider than its spacing";
        EXPECT_FALSE(dialer.dead());
    }
}

// A profile is a request, not an instruction: zero attempts would be a dial that
// dies on its first timeout having never retried, and an interval outside what the
// timer can honour would either spin or stall past the establish deadline.
TEST(UdpStreamTest, AnAbsurdDialProfileIsClampedRatherThanObeyed) {
    const auto start = std::chrono::steady_clock::now();
    GatedNet   net(start);
    UdpStream  dialer(net, kBob, 100, 101, ConnRole::Outbound, start,
                      DialProfile{/*syn_attempts=*/0, /*syn_rto_ms=*/1, /*syn_backoff=*/false});

    const auto waited = run_dial(net, dialer, nullptr, start);

    ASSERT_TRUE(dialer.dead());
    EXPECT_GE(net.probes(), 1u) << "a dial that never sent anything at all";
    EXPECT_GE(waited, UdpStream::kMinRto) << "the retry interval was not clamped upward";
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
    ASSERT_EQ(write_all_at(*pair.initiator, payload, pair.now), payload.size());

    // Phase one: run the path with the receiver never reading a byte, for longer
    // than a stream is allowed to go without hearing from its peer at all.
    // Simulated time is what makes that affordable, and the length is the point
    // twice over: the liveness check below says nothing over a stall shorter than
    // the idle timeout, and a sender that leaks past a closed window leaks slowly
    // — over a few seconds that looks exactly like a sender that stopped.
    const auto stall_ends = pair.now + UdpStream::kIdleTimeout + 5s;
    pump(pair, [&] { return pair.now >= stall_ends; }, UdpStream::kIdleTimeout + 10s, 5ms);

    // The stall is the point: the sender still owes data it cannot send.
    EXPECT_GT(pair.initiator->queued_bytes(), 0u)
        << "the sender handed over everything despite a closed window";
    // Neither side may treat a stopped peer as a dead one. A sender held by a
    // closed window sends nothing at all, so there is no retransmission to count
    // against it — what carries both sides past the idle timeout is the keep-alive,
    // and that is the only thing holding this stream up for the stall above.
    EXPECT_FALSE(pair.initiator->dead()) << "a full receiver was mistaken for a lost one";
    EXPECT_FALSE(pair.responder->dead());

    const std::string first = drain(*pair.responder);
    EXPECT_LT(first.size(), payload.size()) << "flow control never stopped the sender";
    EXPECT_GT(first.size(), kWindowBytes / 2) << "the sender stopped far short of the window";
    // And it is the advertised window that stopped it — not the send queue running
    // dry much later. This is the whole promise: what the receiver spends on a peer
    // is what the receiver said it would spend, so admitting one more packet every
    // time the pipe drains (which a peer holding data it will not read does keep
    // acknowledging) is not a probe, it is the bound quietly going away.
    EXPECT_LE(first.size(), kWindowBytes)
        << "the receiver buffered " << first.size() << " bytes against a window of "
        << kWindowBytes;

    // Phase two: the buffer has just been drained, so the window is open again and
    // the transfer has to pick itself back up with no help from the test.
    std::string received = first;
    const bool  done     = pump(pair, [&] {
        received += drain(*pair.responder);
        return received.size() >= payload.size();
    });

    ASSERT_TRUE(done) << "the transfer never resumed after the window reopened";
    EXPECT_EQ(received, payload) << "the transfer never resumed after the window reopened";
}

// A window that re-opens has to be announced, with nothing to announce it on.
//
// This is the only way out of a zero window there is. A sender held by one sends
// nothing — not a probe, not a byte — so there is, by construction, no traffic for
// an acknowledgement to ride on and nothing the receiver can wait for. If draining
// the buffer does not make it speak up unprompted, the transfer does not resume at
// all until the keep-alive happens to carry the news, ten seconds later. read()
// records that the window re-opened; the point here is that the record is acted on.
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

// ...and announced more than once, because nothing retransmits it.
//
// The update rides on a bare acknowledgement, which no part of this transport ever
// re-sends: it is repaired by the next one, and on a stopped stream there is no next
// one. So a single dropped datagram would leave a sender that has data to send and a
// receiver with room to take it both sitting until the keep-alive — ten seconds of
// silence bought by one lost packet, on a path that is otherwise fine. The receiver
// volunteering it again is what turns that into a round trip.
TEST(UdpStreamTest, ALostWindowUpdateIsAnnouncedAgain) {
    Pair pair;

    // Fill the receive buffer by hand, as above: the receiver's own behaviour once
    // it is full is the whole subject.
    const Bytes body(rudp::kMaxPayload, 'x');
    for (uint32_t i = 0; i < rudp::kMaxWindowPackets; ++i) {
        rudp::Packet p;
        p.type    = rudp::PacketType::Data;
        p.conn_id = pair.responder->recv_id();
        p.seq     = 2 + i;   // the Syn took sequence number 1
        p.ack     = 0;
        p.window  = rudp::kMaxWindowPackets;
        p.payload = ByteView(body);
        pair.responder->on_packet(p, pair.now);
    }
    rudp::Packet closed;
    ASSERT_TRUE(pair.net.peek_last(closed));
    ASSERT_EQ(closed.window, 0) << "the receive buffer never actually filled";

    // Drain it, and lose exactly the datagram that says so.
    EXPECT_GT(drain(*pair.responder).size(), 0u);
    pair.net.drop_next(1);
    const size_t before = pair.net.dropped();
    pair.responder->tick(pair.now);
    ASSERT_GT(pair.net.dropped(), before) << "there was no update to lose";

    // Nothing else happens on this path: the peer is stopped, and the only packet
    // that could restart it has just been thrown away. What follows has to be the
    // receiver's own doing.
    const auto   opened_at = pair.now;
    rudp::Packet update;
    const bool   told = pump(pair, [&] {
        return pair.net.peek_last(update) && update.window > 0;
    }, 2s);

    ASSERT_TRUE(told) << "a lost window update was never repeated; the transfer would "
                         "have waited out a keep-alive";
    EXPECT_LT(pair.now - opened_at, UdpStream::kKeepAlive)
        << "the repeat was the keep-alive rather than an announcement of its own";
}

// ...and the repeats stop the moment the peer proves it heard.
//
// Volunteering an update is only worth anything while the peer is stopped: it has
// no traffic for one to ride on, and no way to ask. A packet from it says both
// conditions are over — so the remaining repeats have nobody to inform, and going
// on with them spends acknowledgements on a conversation that has already resumed.
//
// The proof has to be a *sequenced* packet, which is why this is not simply "any
// traffic". A sender stuck on a window it believes is closed still keep-alives, and
// those are bare acknowledgements: reading one as an answer would call off exactly
// the repeats it is waiting for, which is the case the whole mechanism exists for.
TEST(UdpStreamTest, WindowAnnouncementsStopOnceThePeerSpeaksAgain) {
    Pair pair;

    const Bytes body(rudp::kMaxPayload, 'x');
    const auto  deliver_data = [&](uint32_t seq) {
        rudp::Packet p;
        p.type    = rudp::PacketType::Data;
        p.conn_id = pair.responder->recv_id();
        p.seq     = seq;
        p.ack     = 0;
        p.window  = rudp::kMaxWindowPackets;
        p.payload = ByteView(body);
        pair.responder->on_packet(p, pair.now);
    };

    // Fill the receive buffer, so that draining it re-opens a window that really
    // was closed — nothing is announced otherwise.
    for (uint32_t i = 0; i < rudp::kMaxWindowPackets; ++i) deliver_data(2 + i);  // Syn took 1
    rudp::Packet closed;
    ASSERT_TRUE(pair.net.peek_last(closed));
    ASSERT_EQ(closed.window, 0) << "the receive buffer never actually filled";

    EXPECT_GT(drain(*pair.responder).size(), 0u);
    pair.responder->tick(pair.now);   // the first announcement, sent at once
    rudp::Packet update;
    ASSERT_TRUE(pair.net.peek_last(update));
    ASSERT_GT(update.window, 0) << "the window was never announced in the first place";

    // The peer answers with a packet of its own: it is plainly no longer stopped.
    deliver_data(2 + rudp::kMaxWindowPackets);

    // That packet owes an acknowledgement of its own, which is not what is being
    // counted here — let it go out first, and count from after it.
    const auto answered_at = pair.now + UdpStream::kDelayedAck + 100ms;
    pump(pair, [&] { return pair.now >= answered_at; }, 1s);
    const size_t settled = pair.net.sent();

    // Long enough for every remaining announcement to have come due (they are
    // spaced by the retransmission timeout, which nothing here has moved off its
    // initial value), and comfortably short of the keep-alive, which would produce
    // one legitimately.
    const auto quiet_until = pair.now + UdpStream::kMaxWindowAnnounces * UdpStream::kInitialRto;
    ASSERT_LT(quiet_until - pair.now, UdpStream::kKeepAlive) << "the window covers a keep-alive";
    pump(pair, [&] { return pair.now >= quiet_until; }, 10s);

    EXPECT_EQ(pair.net.sent(), settled)
        << "the receiver went on announcing a window to a peer that had already answered";
}

// The other half of that rule, and the one it exists for: a keep-alive is not an
// answer.
//
// A sender stopped on a window it believes is closed still says something every ten
// seconds — it has to, or the peer's idle timer would end a stream that is merely
// blocked. What it says is a bare acknowledgement, which is precisely the shape of
// "I am here and I have heard nothing". Reading it as proof would call off the
// repeats meant for that very sender, and the two would then wait on each other
// until one of them timed out.
TEST(UdpStreamTest, AKeepAliveIsNotAnAnswerToAWindowAnnouncement) {
    Pair pair;

    // Fill the receive buffer, as above, so that draining it re-opens a window that
    // really was closed.
    const Bytes body(rudp::kMaxPayload, 'x');
    for (uint32_t i = 0; i < rudp::kMaxWindowPackets; ++i) {
        rudp::Packet p;
        p.type    = rudp::PacketType::Data;
        p.conn_id = pair.responder->recv_id();
        p.seq     = 2 + i;   // the Syn took sequence number 1
        p.ack     = 0;
        p.window  = rudp::kMaxWindowPackets;
        p.payload = ByteView(body);
        pair.responder->on_packet(p, pair.now);
    }
    rudp::Packet closed;
    ASSERT_TRUE(pair.net.peek_last(closed));
    ASSERT_EQ(closed.window, 0) << "the receive buffer never actually filled";

    EXPECT_GT(drain(*pair.responder).size(), 0u);
    pair.responder->tick(pair.now);   // the first announcement, sent at once
    rudp::Packet update;
    ASSERT_TRUE(pair.net.peek_last(update));
    ASSERT_GT(update.window, 0) << "the window was never announced in the first place";

    // The stopped sender's keep-alive: a bare acknowledgement, occupying no
    // sequence number and telling the receiver nothing it did not already know.
    rudp::Packet keep_alive;
    keep_alive.type    = rudp::PacketType::Ack;
    keep_alive.conn_id = pair.responder->recv_id();
    keep_alive.seq     = 2 + rudp::kMaxWindowPackets;
    keep_alive.ack     = 0;
    keep_alive.window  = rudp::kMaxWindowPackets;
    pair.responder->on_packet(keep_alive, pair.now);

    // Nothing else on this stream is due inside the interval below — no delayed
    // ack is owed, the keep-alive of our own is ten seconds out — so a packet
    // appearing here can only be the repeat.
    const size_t before = pair.net.sent();
    const auto   next_due = pair.now + UdpStream::kInitialRto + 100ms;
    pump(pair, [&] { return pair.now >= next_due; }, 2s);

    EXPECT_GT(pair.net.sent(), before)
        << "a keep-alive was taken as proof the peer had heard, and the announcement "
           "the peer is waiting for was called off";
}

// A window from the past does not stop a sender the receiver has made room for.
//
// Nothing on the wire is ordered by arrival: a path may duplicate a datagram or
// deliver two out of order, and an acknowledgement from when the receiver was full
// then lands after the one saying it is empty. Latching that stale zero costs more
// than it used to — there is no probe to discover the mistake with (see
// window_allows), and the receiver has already said its piece and will not repeat
// itself, so the stream sits until the next keep-alive. The cumulative
// acknowledgement is what dates the two apart.
TEST(UdpStreamTest, AStaleWindowUpdateDoesNotStopTheSender) {
    Pair pair;

    // A short transfer run right through: nothing left in flight, nothing queued,
    // and a receiver that has read every byte and owes nobody anything.
    const std::string first(50000, 'a');
    ASSERT_EQ(write_all_at(*pair.initiator, first, pair.now), first.size());
    size_t got = 0;
    ASSERT_TRUE(pump(pair, [&] { got += drain(*pair.responder).size();
                                 return got >= first.size(); }, 10s));
    ASSERT_TRUE(pump(pair, [&] { drain(*pair.responder);
                                 return pair.initiator->flushed(); }, 5s));

    // One datagram from the past. Its acknowledgement is far behind what the peer
    // has really confirmed, which is exactly what makes it recognisable.
    rudp::Packet stale;
    stale.type    = rudp::PacketType::Ack;
    stale.conn_id = pair.initiator->recv_id();
    stale.seq     = 1;
    stale.ack     = 0;
    stale.window  = 0;
    pair.initiator->on_packet(stale, pair.now);

    // The application writes again. The receiver's buffer is empty and it has
    // nothing to announce, so nothing is coming to correct a sender that believed
    // the stale zero — the write simply never leaves.
    const std::string second(20000, 'b');
    ASSERT_EQ(write_all_at(*pair.initiator, second, pair.now), second.size());

    const auto  wrote_at = pair.now;
    std::string received;
    ASSERT_TRUE(pump(pair, [&] { received += drain(*pair.responder);
                                 return received.size() >= second.size(); }, 30s))
        << "a window from the past stopped the sender for good";
    EXPECT_EQ(received, second);
    EXPECT_LT(pair.now - wrote_at, UdpStream::kKeepAlive)
        << "the transfer waited out a keep-alive to undo a window from the past";
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
    client.on_peer_disconnected([&](const PeerId&, CloseReason) { ++lost; });

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

// A message larger than the whole send queue is not a slow consumer, and must not
// be answered with a disconnection.
//
// It used to be. The high-water mark was weighed AFTER the message had been added
// to the queue, so any single message bigger than the mark crossed it by itself and
// the peer was dropped on the spot — on an idle connection, over a link draining at
// full speed, with nothing about the peer being slow at all. With the default 8 MiB
// mark that made node.send(peer, ch, 10 MiB) a guaranteed disconnect on the first
// call, delivering none of it, while the wire itself carries blocks up to 64 MiB.
//
// A message cannot be queued by halves, so the size of ONE of them can never be
// evidence that a peer is not keeping up. What is evidence — and what still closes
// the connection — is a caller piling on MORE while the queue is already over the
// mark (the test after this one).
TEST(TransportUdpTest, OneLargeMessageIsNotASlowConsumer) {
    NodeConfig server_cfg = base_config();
    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen = false;
    // 256 KiB before a slow consumer would be dropped, and one message four times
    // that. Under the old rule this was fatal; nothing else about it is unusual.
    client_cfg.send_queue_limit = 256 * 1024;
    constexpr size_t kMessage = 1024 * 1024;

    Node server(server_cfg), client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    std::atomic<size_t> got{0};
    server.on("bulk", [&](Peer, ByteView payload) { got += payload.size(); });

    std::atomic<int>         lost{0};
    std::atomic<CloseReason> why{CloseReason::PeerClosed};
    client.on_peer_disconnected([&](const PeerId&, CloseReason reason) {
        why.store(reason);
        ++lost;
    });

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));
    const PeerId peer = client.peers().front().id;

    const std::string big(kMessage, 'B');
    // The answer is still "no room" — the queue really is over its low-water mark —
    // but that is a request to wait, not a death sentence.
    EXPECT_FALSE(client.send(peer, "bulk", ByteView(big)))
        << "a message four times the queue limit reported room to spare";

    ASSERT_TRUE(wait_for([&] { return got.load() == kMessage || lost.load() > 0; }, 30s));
    EXPECT_EQ(lost.load(), 0) << "the peer was dropped for ONE message ("
                              << to_string(why.load()) << ") — nothing was slow here";
    EXPECT_EQ(got.load(), kMessage) << "the message was not delivered in full";
    EXPECT_EQ(client.peer_count(), 1u);

    // And the connection is still usable afterwards, once it has drained.
    ASSERT_TRUE(wait_for([&] { return client.peer_writable(peer); }, 30s));
    const std::string after(16, 'a');
    EXPECT_TRUE(client.send(peer, "bulk", ByteView(after)));
    ASSERT_TRUE(wait_for([&] { return got.load() == kMessage + after.size(); }));

    client.stop();
    server.stop();
}

// The other half of the rule above: ignoring the answer entirely IS what gets a
// peer dropped, and the application is told exactly that. Before CloseReason
// reached on_peer_disconnected, this was indistinguishable from the peer simply
// leaving — so the natural response was to redial and do it all again.
TEST(TransportUdpTest, IgnoringBackpressureDropsThePeerAndSaysWhy) {
    NodeConfig server_cfg = base_config();
    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen = false;
    client_cfg.send_queue_limit = 256 * 1024;

    Node server(server_cfg), client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    server.on("bulk", [](Peer, ByteView) {});

    std::atomic<int>         lost{0};
    std::atomic<CloseReason> why{CloseReason::PeerClosed};
    client.on_peer_disconnected([&](const PeerId&, CloseReason reason) {
        why.store(reason);
        ++lost;
    });

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));
    const PeerId peer = client.peers().front().id;

    // Never stop, never wait, never look at the answer — the behaviour the mark
    // exists to catch. 64 MiB offered against a 256 KiB queue.
    const std::string chunk(64 * 1024, 'x');
    for (int i = 0; i < 1024 && lost.load() == 0; ++i)
        client.send(peer, "bulk", ByteView(chunk));

    ASSERT_TRUE(wait_for([&] { return lost.load() > 0; }, 30s))
        << "a sender that ignored every answer kept its peer — the queue is unbounded";
    EXPECT_EQ(why.load(), CloseReason::SlowConsumer)
        << "the peer was dropped for the right thing but told the wrong reason: "
        << to_string(why.load());

    client.stop();
    server.stop();
}

// A message past the wire's own ceiling can never be sent, however long anyone
// waits — so it is refused, and refusing is all that happens. Queueing it would
// hand the peer a block its decoder is obliged to reject, turning "too big" into a
// protocol error and a dead connection at the far end.
TEST(TransportUdpTest, AMessagePastTheBlockCeilingIsRefusedNotFatal) {
    NodeConfig server_cfg = base_config();
    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen = false;

    Node server(server_cfg), client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    std::atomic<size_t> got{0};
    server.on("bulk", [&](Peer, ByteView payload) { got += payload.size(); });
    std::atomic<int> lost{0};
    client.on_peer_disconnected([&](const PeerId&, CloseReason) { ++lost; });

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));
    const PeerId peer = client.peers().front().id;

    {   // released before the assertions below, so the test does not sit on it
        const std::string toobig(framer::kMaxBlockSize, 'X');  // + header + tag ⇒ past the cap
        EXPECT_FALSE(client.send(peer, "bulk", ByteView(toobig)));
    }

    // A small message right behind it still arrives, which is the point: the
    // refusal cost the connection nothing.
    const std::string ok(32, 'o');
    EXPECT_TRUE(client.send(peer, "bulk", ByteView(ok)));
    ASSERT_TRUE(wait_for([&] { return got.load() == ok.size(); }, 30s));
    EXPECT_EQ(lost.load(), 0) << "an oversized message took the connection with it";

    client.stop();
    server.stop();
}

// A Peer handle is what every callback is handed, so replying through it is the
// most ordinary way to write to a peer — and it has to be able to feel
// backpressure like any other sender. While Peer::send() returned void it could
// not: a handler could fill a queue with no way to know, and the bytes it queued
// were invisible to peer_writable() as well, because that path skipped the
// in-transit counter entirely.
TEST(TransportUdpTest, PeerHandleReportsBackpressure) {
    NodeConfig server_cfg = base_config();
    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen = false;
    client_cfg.send_queue_limit = 256 * 1024;   // ⇒ 64 KiB before "no room"

    Node server(server_cfg), client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    server.on("bulk", [](Peer, ByteView) {});

    std::atomic<int> lost{0};
    client.on_peer_disconnected([&](const PeerId&, CloseReason) { ++lost; });

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));
    const PeerId peer_id = client.peers().front().id;

    auto handle = client.peer(peer_id);
    ASSERT_TRUE(handle.has_value());
    EXPECT_TRUE(client.peer_writable(peer_id)) << "an idle peer reported no room";

    const std::string chunk(32 * 1024, 'p');
    bool refused = false;
    for (int i = 0; i < 64 && !refused; ++i) refused = !handle->send("bulk", ByteView(chunk));

    EXPECT_TRUE(refused) << "Peer::send() never reported the queue filling up";
    // The handle's bytes are charged to the peer, so the other way of asking sees
    // them too — the two must never contradict each other.
    EXPECT_FALSE(client.peer_writable(peer_id))
        << "Peer::send() said no room while peer_writable() said there was";
    EXPECT_EQ(lost.load(), 0) << "heeding the answer should have kept the peer";

    ASSERT_TRUE(wait_for([&] { return client.peer_writable(peer_id); }, 30s))
        << "the queue filled and never reported draining";

    client.stop();
    server.stop();
}

// The two ways of asking "may I send more?" must not contradict each other.
// send() weighs both halves of what a peer is carrying — what the reactor has
// queued, and what a caller has handed over that the reactor has not taken up
// yet — and peer_writable() has to weigh the same two. If it reports only the
// first, an application pacing itself by waiting on it is told "there is room"
// about a queue it has just filled itself: the connection has not looked at
// those bytes, so nothing about it has changed and no event is coming. It then
// keeps filling until the peer is dropped as a slow consumer.
//
// Parking the client's reactor inside a message handler is what makes this
// deterministic rather than a race with the drain: while it cannot run, nothing
// handed to it can reach the connection, so the in-transit half is the only
// place the bytes are counted.
TEST(TransportUdpTest, PeerWritableWeighsBytesTheReactorHasNotTakenUpYet) {
    NodeConfig server_cfg = base_config();
    NodeConfig client_cfg = base_config();
    client_cfg.enable_listen = false;
    // 1 MiB before the peer would be dropped, so 256 KiB before send() says stop.
    client_cfg.send_queue_limit = 1024 * 1024;

    Node server(server_cfg), client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    std::atomic<size_t> got{0};
    server.on("bulk", [&](Peer, ByteView payload) { got += payload.size(); });

    std::atomic<bool> parked{false}, release{false};
    client.on("park", [&](Peer, ByteView) {
        parked = true;
        while (!release.load()) std::this_thread::sleep_for(1ms);
    });

    std::atomic<int> lost{0};
    client.on_peer_disconnected([&](const PeerId&, CloseReason) { ++lost; });

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    const PeerId peer = client.peers().front().id;
    EXPECT_TRUE(client.peer_writable(peer)) << "an idle peer reported no room";

    const std::string park_msg = "park";
    server.broadcast("park", ByteView(park_msg));
    ASSERT_TRUE(wait_for([&] { return parked.load(); })) << "the reactor never parked";

    // Hand over chunks until the mark is crossed. The reactor cannot be running,
    // so every one of them is still in transit and none of it has been queued.
    constexpr size_t kChunk = 32 * 1024;
    const std::string chunk(kChunk, 'c');
    size_t offered = 0;
    bool   refused = false;
    for (int i = 0; i < 64 && !refused; ++i) {
        refused = !client.send(peer, "bulk", ByteView(chunk));
        offered += kChunk;
    }
    ASSERT_TRUE(refused) << "offering " << offered << " B never crossed the low-water mark";
    EXPECT_FALSE(client.peer_writable(peer))
        << "reported room in a queue the caller had just filled: send() and "
           "peer_writable() answered the same question differently";

    release = true;
    EXPECT_TRUE(wait_for([&] { return client.peer_writable(peer); }))
        << "the room never came back once the reactor could drain";
    ASSERT_TRUE(wait_for([&] { return got.load() == offered; }, 30s))
        << "backpressure dropped data it should only have delayed (" << got.load()
        << " of " << offered << " B)";
    EXPECT_EQ(lost.load(), 0) << "the peer was dropped although it was never over the mark";

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

// The mux is one socket in one address family, and a dial outside it can never
// be carried. That has to be settled before the Syn goes out: the kernel refuses
// each such datagram individually and says nothing a stream can act on, so an
// attempt allowed to start looks exactly like a peer that has not answered yet
// and costs the full give-up. Here the client's socket is IPv4 and the target is
// IPv6, so the datagram attempt must be abandoned outright and TCP must carry the
// connection — well inside the fallback delay, which is the proof that nothing
// waited on a timer.
TEST(TransportUdpTest, ADialOutsideTheMuxFamilyGoesStraightToTcp) {
    NodeConfig server_cfg = base_config();
    server_cfg.bind_address = "::1";             // IPv6 listener, both transports

    Node server(server_cfg);
    if (!server.start()) GTEST_SKIP() << "host has no IPv6 loopback";

    NodeConfig client_cfg = base_config();       // binds 127.0.0.1 → IPv4 mux
    client_cfg.enable_listen         = false;
    client_cfg.preferred_transport   = TransportKind::Udp;
    client_cfg.transport_fallback_ms = 5000;     // long enough that waiting it out would show
    Node client(client_cfg);
    ASSERT_TRUE(client.start());

    const auto started = std::chrono::steady_clock::now();
    client.connect("::1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }))
        << "an IPv6 target was never reached at all";

    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, 2s) << "the unreachable datagram attempt was waited out "
                              "instead of being abandoned at once";

    const auto peers = client.peers();
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].transport, TransportKind::Tcp);

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
    // A shortened fallback delay is what gives the assertion below its teeth: the
    // wait after the dial has to outlast the moment the second transport would have
    // been brought in, or "no TCP attempt appeared" only means "not yet". Still two
    // orders of magnitude above the millisecond a loopback handshake takes, so the
    // preferred transport is in no danger of losing its own race.
    client_cfg.transport_fallback_ms = 300;

    Node client(client_cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    // Fatal on purpose: without a UDP listener every assertion below fails as a
    // consequence, and the run should name the cause rather than the fallout.
    ASSERT_EQ(server.transports(), PeerTransportTcp | PeerTransportUdp);

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    // Several fallback delays' worth of chances for a racing TCP attempt to show up
    // before asserting that it did not. Watching for the duplicate rather than
    // sleeping through the window costs the same when it never comes, and says when
    // it did when it does.
    EXPECT_FALSE(wait_for([&] { return client.peer_count() != 1; }, 500ms))
        << "the fallback transport was raced despite the preferred one winning";
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
    // did not survive it. Watching for the duplicate rather than sleeping through
    // the window costs the same when none appears, and pins the moment it did when
    // one does — a handshake on loopback settles in a millisecond or two, so this
    // is two orders of magnitude more room than a late arrival needs.
    EXPECT_FALSE(wait_for([&] { return client.peer_count() != 1 || server.peer_count() != 1; },
                          400ms))
        << "a superseded attempt survived: client=" << client.peer_count()
        << " server=" << server.peer_count();

    client.stop();
    server.stop();
}

// The same race, with the two attempts on different reactor threads. UDP is pinned
// to the mux's reactor while TCP round-robins, so the supersede crosses a thread
// boundary: the winner's close for the sibling is a task the other reactor runs
// whenever it gets to it, which may well be after that sibling has finished its own
// handshake. Nothing about the outcome may depend on which side gets there first.
TEST(TransportUdpTest, RacingAttemptsAcrossReactorsLeaveExactlyOnePeer) {
    NodeConfig client_cfg            = base_config();
    client_cfg.enable_listen         = false;
    client_cfg.transport_fallback_ms = 1;   // race both from the very start
    client_cfg.reactor_threads       = 2;

    Node client(client_cfg);
    ASSERT_TRUE(client.start());

    // The round-robin starts at reactor 0, which is the mux's reactor too, so a
    // pool's *first* dial puts both attempts on one thread and only the next one
    // splits them. Walking it with a second server rather than a second dial to the
    // same one keeps the peer table's duplicate resolution out of the picture.
    std::vector<std::unique_ptr<Node>> servers;
    for (size_t i = 0; i < 2; ++i) {
        servers.push_back(std::make_unique<Node>(base_config()));
        ASSERT_TRUE(servers.back()->start());
        client.connect("127.0.0.1", servers.back()->listen_port());
        ASSERT_TRUE(wait_for([&] { return client.peer_count() == i + 1; }))
            << "dial " << i << " never produced a peer";
    }

    // Let the losing attempts finish whatever they were doing before asserting that
    // none of them took a winner down with it — and watch for that happening rather
    // than sleeping past it, so a cross-thread supersede that closes the wrong
    // connection is caught where it happens.
    EXPECT_FALSE(wait_for([&] { return client.peer_count() != 2; }, 400ms))
        << "a superseded attempt took its winner down (peers=" << client.peer_count() << ")";
    for (const auto& server : servers)
        EXPECT_EQ(server->peer_count(), 1u) << "a server was left without its peer";

    client.stop();
    for (auto& server : servers) server->stop();
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
