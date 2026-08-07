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
        std::deque<Datagram> batch;
        batch.swap(queue_);
        if (reverse) std::reverse(batch.begin(), batch.end());

        const auto now = std::chrono::steady_clock::now();
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

    void set_drop_every(size_t n) { drop_every_ = n; sent_ = 0; }
    /// Lose the next `count` datagrams and nothing after them, so a test can open
    /// a hole of a known size and watch exactly one loss episode play out.
    void drop_next(size_t count = 1) { drop_next_ = count; }
    size_t dropped() const        { return dropped_; }
    size_t queued() const         { return queue_.size(); }

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
    uint8_t byte = 0;
    return ::recv(sock, reinterpret_cast<char*>(&byte), 1, MSG_PEEK) >= 0;
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
// The budget refills per tick, so draining a burst without ticking must yield no
// more than one tick's worth of replies.
TEST(UdpMuxTest, ResetsAreCappedSoTheSocketCannotReflect) {
    MuxPair net;

    socket_t probe = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(probe));
    set_socket_nonblocking(probe);

    constexpr int kJunk = UdpMux::kMaxUnsolicitedRepliesPerTick * 3;
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

    // Drain them all WITHOUT a tick — the budget is only refilled by tick().
    for (int i = 0; i < 100; ++i) {
        net.b->on_readable();
        std::this_thread::sleep_for(1ms);
    }
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

    EXPECT_GT(resets, 0) << "an unknown stream should be answered, not ignored";
    EXPECT_LE(resets, UdpMux::kMaxUnsolicitedRepliesPerTick) << "the per-tick reset budget was not enforced";
}

// ── End to end, through a Node ──────────────────────────────────────────────

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
