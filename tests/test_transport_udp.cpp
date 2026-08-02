#include <gtest/gtest.h>

#include "librats/core/socket.h"
#include "librats/node/node.h"
#include "librats/transport/udp_packet.h"
#include "librats/transport/udp_stream.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
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
