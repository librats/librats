// The datagram transport on real sockets: the mux (one socket shared by every
// peer, admission, stateless resets, the linger) driven by hand, and then whole
// nodes over UDP. A connection on its own, in virtual time, is
// test_udp_connection.cpp's.

#include <gtest/gtest.h>
#include "test_paths.h"

#include "librats/core/socket.h"
#include "librats/node/node.h"
#include "librats/security/noise_security.h"
#include "librats/transport/udp_connection.h"
#include "librats/transport/udp_mux.h"
#include "librats/transport/udp_transport.h"
#include "librats/transport/udp_wire.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
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
// The test stands in for the reactor: it calls on_readable()/tick() instead of a
// poll loop, adopts what the mux accepts, and hands each transport the events the
// mux dispatches — exactly what Reactor::dispatch_events does with them.

/// What a Connection would be told, recorded.
class Sink final : public TransportSink {
public:
    void transport_connected() override { connected = true; }
    void transport_established(const PeerId& id) override { established = true; remote = id; }
    bool transport_frame(const Frame& f) override {
        frames.emplace_back(f.payload.begin(), f.payload.end());
        return true;
    }
    bool                     connected = false, established = false;
    PeerId                   remote;
    std::vector<std::string> frames;
};

/// One side's transports and their sinks.
struct Side {
    struct Held {
        std::unique_ptr<Transport> transport;
        std::unique_ptr<Sink>      sink;
        bool                       broken = false;
        CloseReason                reason = CloseReason::PeerClosed;
    };

    ConnId add(std::unique_ptr<Transport> t, bool inbound) {
        const ConnId id = next_id++;
        Held h;
        h.transport = std::move(t);
        h.sink      = std::make_unique<Sink>();
        h.transport->attach(id, *h.sink);
        if (inbound && !h.transport->start()) { h.broken = true; h.reason = h.transport->error_reason(); }
        held.emplace(id, std::move(h));
        return id;
    }

    void dispatch(ConnId id, uint32_t events) {
        ++dispatches;
        auto it = held.find(id);
        if (it == held.end() || it->second.broken) return;
        Held& h = it->second;
        bool ok = true;
        if (events & PollErr) ok = h.transport->on_error();
        else {
            if (ok && (events & PollIn))  ok = h.transport->on_readable();
            if (ok && (events & PollOut)) ok = h.transport->on_writable();
        }
        if (!ok) { h.broken = true; h.reason = h.transport->error_reason(); }
    }

    Held* only() { return held.size() == 1 ? &held.begin()->second : nullptr; }

    std::map<ConnId, Held> held;
    ConnId                 next_id    = 1;
    size_t                 dispatches = 0;
};

class MuxHost final : public UdpMuxDelegate {
public:
    ConnId adopt_inbound(std::unique_ptr<Transport> transport) override {
        // Refusing destroys the transport, which releases the connection the mux
        // just made — the path where a leak or a use-after-free would hide.
        if (refuse) { ++refused; return kInvalidConnId; }
        ++adopted;
        return side.add(std::move(transport), /*inbound=*/true);
    }
    bool admit_inbound() override { return admit; }
    void dispatch_link_events(ConnId id, uint32_t events) override { side.dispatch(id, events); }

    Side side;
    int  adopted = 0;
    int  refused = 0;
    bool refuse  = false;   ///< refuse at adoption, after the handshake reply
    bool admit   = true;    ///< false: refuse before it
};

/// A SecurityProvider that counts the handshakes it is asked to start: what an
/// Initial costs a responder in DH work.
class CountingSecurity final : public SecurityProvider {
public:
    explicit CountingSecurity(const Identity& id) : inner_(id) {}
    std::unique_ptr<Handshaker> create(ConnRole role) override {
        ++created;
        return inner_.create(role);
    }
    const PeerId& local_id() const override { return inner_.local_id(); }
    int created = 0;

private:
    NoiseSecurity inner_;
};

socket_t loopback_socket(uint16_t port = 0) {
    socket_t s = create_udp_socket(port, "127.0.0.1", AddressFamily::IPv4);
    EXPECT_TRUE(is_valid_socket(s));
    set_socket_nonblocking(s);
    return s;
}

/// Two muxes on two loopback sockets. Transports go before muxes, as in the
/// Reactor: each tells its mux on destruction that its connection may go.
struct MuxPair {
    explicit MuxPair(UdpMuxLimits b_limits = {})
        : id_a(Identity::generate()), id_b(Identity::generate()), sec_a(id_a), sec_b(id_b) {
        init_socket_library();
        sock_a = loopback_socket();
        sock_b = loopback_socket();
        addr_a = Address{"127.0.0.1", static_cast<uint16_t>(get_bound_port(sock_a))};
        addr_b = Address{"127.0.0.1", static_cast<uint16_t>(get_bound_port(sock_b))};
        a = std::make_unique<UdpMux>(sock_a, AddressFamily::IPv4, host_a, sec_a);
        b = std::make_unique<UdpMux>(sock_b, AddressFamily::IPv4, host_b, sec_b, b_limits);
    }

    ~MuxPair() {
        host_a.side.held.clear();
        host_b.side.held.clear();
        a.reset();
        b.reset();
        if (is_valid_socket(sock_a)) close_socket(sock_a);
        if (is_valid_socket(sock_b)) close_socket(sock_b);
    }

    template <typename Pred>
    bool pump_until(Pred pred, std::chrono::milliseconds timeout = 10s) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;) {
            if (a) a->on_readable();
            if (b) b->on_readable();
            if (pred()) return true;
            if (std::chrono::steady_clock::now() >= deadline) return pred();
            if (a) a->tick();
            if (b) b->tick();
            std::this_thread::sleep_for(1ms);
        }
    }

    /// Dial B from A; the id of the dialing transport on A's side.
    ConnId dial() {
        auto t = a->connect(addr_b);
        return t ? host_a.side.add(std::move(t), /*inbound=*/false) : kInvalidConnId;
    }

    Side::Held& out(ConnId id) { return host_a.side.held.at(id); }
    UdpConnection& conn_of(Side::Held& h) { return static_cast<UdpTransport&>(*h.transport).connection(); }

    bool connect(ConnId& id) {
        id = dial();
        return id != kInvalidConnId && pump_until([&] {
            return out(id).sink->established && host_b.side.only() && host_b.side.only()->sink->established;
        });
    }

    Identity      id_a, id_b;
    NoiseSecurity sec_a, sec_b;
    MuxHost       host_a, host_b;
    socket_t      sock_a = RATS_INVALID_SOCKET, sock_b = RATS_INVALID_SOCKET;
    std::unique_ptr<UdpMux> a, b;
    Address       addr_a, addr_b;
};

/// A Noise first message, as a dialer would put it in an Initial.
Bytes noise_opening(SecurityProvider& security) {
    Bytes out;
    security.create(ConnRole::Outbound)->start(out);
    return out;
}

/// Read one datagram from a raw socket, waiting briefly.
bool read_datagram(socket_t sock, Bytes& out, std::chrono::milliseconds timeout = 2s) {
    uint8_t buf[2048];
    Address from;
    return wait_for([&] {
        const auto n = recv_udp_from(sock, buf, sizeof(buf), from);
        if (n < 0) return false;
        out.assign(buf, buf + n);
        return true;
    }, timeout);
}

} // namespace

TEST(UdpMuxTest, DialsAndCarriesMessagesOverTheSharedSocket) {
    MuxPair net;
    ConnId id = kInvalidConnId;
    ASSERT_TRUE(net.connect(id));
    EXPECT_EQ(net.out(id).sink->remote, net.id_b.id);
    Side::Held& in = *net.host_b.side.only();
    EXPECT_EQ(in.sink->remote, net.id_a.id);

    // The ids come in a pair, from the dialer's one random number.
    UdpConnection& a = net.conn_of(net.out(id));
    UdpConnection& b = net.conn_of(in);
    EXPECT_EQ(a.local_cid() % 2, 0u);
    EXPECT_EQ(b.local_cid(), udp::paired_cid(a.local_cid()));

    ASSERT_TRUE(net.out(id).transport->send(FrameHeader{MessageType::App, 0, 1}, ByteView(std::string("dialer speaking"))));
    ASSERT_TRUE(net.out(id).transport->flush());
    ASSERT_TRUE(in.transport->send(FrameHeader{MessageType::App, 0, 1}, ByteView(std::string("and the other end"))));
    ASSERT_TRUE(in.transport->flush());
    EXPECT_TRUE(net.pump_until([&] { return in.sink->frames.size() == 1 && net.out(id).sink->frames.size() == 1; }));
    EXPECT_EQ(in.sink->frames[0], "dialer speaking");
    EXPECT_EQ(net.out(id).sink->frames[0], "and the other end");
}

// Adoption may be refused (the node is at capacity). Nothing may be left behind,
// and the dialer has to be told rather than repeating itself into a void.
TEST(UdpMuxTest, ARefusedDialLeavesNothingBehindAndIsTold) {
    MuxPair net;
    net.host_b.refuse = true;
    const ConnId id = net.dial();
    ASSERT_TRUE(net.pump_until([&] { return net.host_b.refused >= 1; }));
    EXPECT_EQ(net.b->stream_count(), 0u) << "a refused connection was kept";
    ASSERT_TRUE(net.pump_until([&] { return net.out(id).broken; }, 2s)) << "the dialer was never told";
    EXPECT_EQ(net.out(id).reason, CloseReason::PeerReset);
}

// A node that has forgotten a connection — restarted on the same port, say —
// answers its peer's next packet with a stateless reset, and the peer gives up at
// once instead of retransmitting for a minute. Only a node holding the key the
// reset token was made from can do that.
TEST(UdpMuxTest, ARestartedNodeResetsWhatItForgot) {
    UdpMuxLimits keyed;
    keyed.reset_key.fill(0x42);
    MuxPair net(keyed);
    ConnId id = kInvalidConnId;
    ASSERT_TRUE(net.connect(id));
    ASSERT_TRUE(net.pump_until([&] { return false; }, 200ms) || true);   // let the tokens cross

    // B goes away without a word: its socket first, so no goodbye leaves.
    const uint16_t port = net.addr_b.port;
    close_socket(net.sock_b);
    net.sock_b = RATS_INVALID_SOCKET;
    net.host_b.side.held.clear();
    net.b.reset();
    // ...and comes back on the same port, with the same key.
    net.sock_b = loopback_socket(port);
    net.b = std::make_unique<UdpMux>(net.sock_b, AddressFamily::IPv4, net.host_b, net.sec_b, keyed);

    ASSERT_TRUE(net.out(id).transport->send(FrameHeader{MessageType::App, 0, 1}, ByteView(std::string("still there?"))));
    ASSERT_TRUE(net.out(id).transport->flush());
    ASSERT_TRUE(net.pump_until([&] { return net.out(id).broken; }, 3s))
        << "the reset never reached the connection it was for";
    EXPECT_EQ(net.out(id).reason, CloseReason::PeerReset);
}

// TCP gets this from the kernel, which keeps retransmitting after close(). Here
// it is the mux's job: a last message written just before the transport goes
// still arrives, and the connection is then reclaimed.
TEST(UdpMuxTest, LingersLongEnoughToDeliverTheLastMessage) {
    MuxPair net;
    ConnId id = kInvalidConnId;
    ASSERT_TRUE(net.connect(id));
    Side::Held& in = *net.host_b.side.only();

    const std::string farewell(40000, 'f');
    ASSERT_TRUE(net.out(id).transport->send(FrameHeader{MessageType::App, 0, 1}, ByteView(farewell)));
    net.out(id).transport->close(CloseReason::LocalClose);
    net.host_a.side.held.erase(id);   // gone before a byte is acknowledged
    EXPECT_EQ(net.a->stream_count(), 1u) << "the connection was dropped with data still owed";

    ASSERT_TRUE(net.pump_until([&] { return in.sink->frames.size() == 1; })) << "the last message was lost";
    EXPECT_EQ(in.sink->frames[0], farewell);
    EXPECT_TRUE(net.pump_until([&] { return net.a->stream_count() == 0; })) << "never reclaimed";
    EXPECT_TRUE(net.pump_until([&] { return in.broken; }));
    EXPECT_EQ(in.reason, CloseReason::PeerClosed) << "the goodbye did not follow the data";
}

// ── Admission: what an unproven dial may cost ───────────────────────────────
//
// A TCP listener is protected by arithmetic it never has to write: no forged
// source address can make the kernel hand out a file descriptor, because the
// three-way handshake has to complete first. A datagram listener has neither, so
// without these an Initial from an address that does not exist buys a connection
// and a half-built Noise handshake.

TEST(UdpMuxTest, AnUnprovenDialCostsTheResponderNothingUntilItBringsTheToken) {
    UdpMuxLimits validate_everything;
    validate_everything.validate_above = 0;
    MuxPair net(validate_everything);
    socket_t probe = loopback_socket();

    const udp::Cid cid = 0x0BADC0DE00;
    const Bytes opening = noise_opening(net.sec_a);
    uint8_t buf[udp::kMaxDatagram];
    size_t n = udp::encode_initial(buf, udp::paired_cid(cid), cid, ByteView{}, ByteView(opening));
    ASSERT_GT(send_udp_to(probe, buf, n, net.addr_b, AddressFamily::IPv4), 0);

    Bytes reply;
    ASSERT_TRUE(wait_for([&] { net.b->on_readable(); return read_datagram(probe, reply, 1ms); }));
    EXPECT_EQ(net.b->stream_count(), 0u) << "an unproven dial created a connection";
    EXPECT_EQ(net.host_b.adopted, 0);
    udp::LongPacket retry;
    ASSERT_TRUE(udp::decode_long(reply.data(), reply.size(), retry));
    ASSERT_EQ(retry.type, udp::LongType::Retry);
    EXPECT_EQ(retry.dcid, cid);
    const Bytes token(retry.token.begin(), retry.token.end());

    // A token that was not issued buys nothing either.
    Bytes forged = token;
    forged[0] ^= 1;
    n = udp::encode_initial(buf, udp::paired_cid(cid), cid, ByteView(forged), ByteView(opening));
    ASSERT_GT(send_udp_to(probe, buf, n, net.addr_b, AddressFamily::IPv4), 0);
    ASSERT_TRUE(wait_for([&] { net.b->on_readable(); return read_datagram(probe, reply, 1ms); }));
    EXPECT_EQ(net.b->stream_count(), 0u);

    // The real one does.
    n = udp::encode_initial(buf, udp::paired_cid(cid), cid, ByteView(token), ByteView(opening));
    ASSERT_GT(send_udp_to(probe, buf, n, net.addr_b, AddressFamily::IPv4), 0);
    ASSERT_TRUE(wait_for([&] { net.b->on_readable(); return net.host_b.adopted == 1; }));
    close_socket(probe);
}

// A node at its peer limit refuses a dial before computing the Noise reply. Asked
// only at adoption, every forged Initial would cost a DH and leave nothing behind
// — so nothing would ever count towards validate_above either.
TEST(UdpMuxTest, ADialTheNodeWouldNotAdoptCostsNoHandshake) {
    init_socket_library();
    const Identity id_a = Identity::generate();
    const Identity id_b = Identity::generate();
    NoiseSecurity    sec_a(id_a);
    CountingSecurity sec_b(id_b);
    MuxHost host_b;
    host_b.admit = false;
    socket_t sock_b = loopback_socket();
    const Address addr_b{"127.0.0.1", static_cast<uint16_t>(get_bound_port(sock_b))};
    auto b = std::make_unique<UdpMux>(sock_b, AddressFamily::IPv4, host_b, sec_b);
    socket_t probe = loopback_socket();

    const udp::Cid cid = 0x5EED00;
    const Bytes opening = noise_opening(sec_a);
    uint8_t buf[udp::kMaxDatagram];
    const size_t n = udp::encode_initial(buf, udp::paired_cid(cid), cid, ByteView{}, ByteView(opening));
    ASSERT_GT(send_udp_to(probe, buf, n, addr_b, AddressFamily::IPv4), 0);

    Bytes reply;
    ASSERT_TRUE(wait_for([&] { b->on_readable(); return read_datagram(probe, reply, 1ms); }));
    udp::LongPacket close;
    ASSERT_TRUE(udp::decode_long(reply.data(), reply.size(), close));
    EXPECT_EQ(close.type, udp::LongType::Close) << "the dialer was not told";
    EXPECT_EQ(sec_b.created, 0) << "a handshake was started for a dial that was going to be refused";
    EXPECT_EQ(host_b.adopted + host_b.refused, 0);
    EXPECT_EQ(b->stream_count(), 0u);

    b.reset();
    close_socket(sock_b);
    close_socket(probe);
}

TEST(UdpMuxTest, AFloodOfUnprovenDialsCannotGrowPastTheThreshold) {
    UdpMuxLimits limits;
    limits.validate_above = 4;
    MuxPair net(limits);
    socket_t probe = loopback_socket();
    const Bytes opening = noise_opening(net.sec_a);
    for (udp::Cid i = 0; i < 50; ++i) {
        uint8_t buf[udp::kMaxDatagram];
        const udp::Cid cid = 0x7000 + 2 * i;
        const size_t n = udp::encode_initial(buf, udp::paired_cid(cid), cid, ByteView{}, ByteView(opening));
        send_udp_to(probe, buf, n, net.addr_b, AddressFamily::IPv4);
    }
    wait_for([&] { net.b->on_readable(); return false; }, 300ms);
    EXPECT_EQ(net.b->stream_count(), 4u) << "unproven state grew past validate_above";
    close_socket(probe);
}

TEST(UdpMuxTest, ValidationIsInvisibleToARealDial) {
    UdpMuxLimits validate_everything;
    validate_everything.validate_above = 0;
    MuxPair net(validate_everything);
    ConnId id = kInvalidConnId;
    ASSERT_TRUE(net.connect(id)) << "a dialer that answers the Retry did not get through";
}

TEST(UdpMuxTest, RefusesDialsAtTheCeiling) {
    UdpMuxLimits one;
    one.max_streams = 1;
    MuxPair net(one);
    ConnId first = kInvalidConnId;
    ASSERT_TRUE(net.connect(first));
    const ConnId second = net.dial();
    ASSERT_TRUE(net.pump_until([&] { return net.out(second).broken; }, 3s));
    EXPECT_EQ(net.out(second).reason, CloseReason::PeerReset);
    EXPECT_EQ(net.b->stream_count(), 1u);
}

// Every reply to traffic no connection owns is budgeted, so the socket cannot be
// turned into a reflector.
TEST(UdpMuxTest, RepliesToStrangersAreCapped) {
    MuxPair net;
    socket_t probe = loopback_socket();
    for (int i = 0; i < 400; ++i) {
        uint8_t junk[200];
        std::memset(junk, i, sizeof(junk));
        junk[0] = 0x40;   // shaped like a short packet for an id nobody has
        send_udp_to(probe, junk, sizeof(junk), net.addr_b, AddressFamily::IPv4);
    }
    wait_for([&] { net.b->on_readable(); return false; }, 100ms);
    size_t replies = 0;
    Bytes  reply;
    while (read_datagram(probe, reply, 50ms)) {
        ++replies;
        EXPECT_LT(reply.size(), 200u) << "a reset as large as what provoked it";
    }
    EXPECT_GT(replies, 0u);
    EXPECT_LE(replies, static_cast<size_t>(UdpMux::kMaxUnsolicitedReplies) * 6);
    close_socket(probe);
}

TEST(UdpMuxTest, AMuxWithNoConnectionsAsksForNoWakeups) {
    MuxPair net;
    EXPECT_EQ(net.a->next_timeout_ms(60000), 60000);
    ConnId id = kInvalidConnId;
    ASSERT_TRUE(net.connect(id));
    // Long enough for the slots the handshake's timers left behind to surface:
    // the heap deletes lazily, and each costs one early, empty wake-up.
    net.pump_until([&] { return false; }, 1500ms);
    // Connected and idle: woken for the keep-alive, not every few milliseconds.
    EXPECT_GT(net.a->next_timeout_ms(60000), 5000);
}

// What one receive brings a connection is one burst, and its events coalesce:
// the transport is told once per batch, not once per datagram.
TEST(UdpMuxTest, ABurstIsDispatchedOncePerBatchRatherThanPerDatagram) {
    MuxPair net;
    ConnId id = kInvalidConnId;
    ASSERT_TRUE(net.connect(id));
    Side::Held& in = *net.host_b.side.only();
    for (int i = 0; i < 200; ++i)
        ASSERT_TRUE(net.out(id).transport->send(FrameHeader{MessageType::App, 0, 1}, ByteView(std::string(1000, 'm'))));
    ASSERT_TRUE(net.out(id).transport->flush());
    const size_t before = net.host_b.side.dispatches;
    ASSERT_TRUE(net.pump_until([&] { return in.sink->frames.size() == 200; }));
    EXPECT_LT(net.host_b.side.dispatches - before, 100u) << "one dispatch per datagram";
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

// Path samples reach the application: a handler sees every connected peer's
// estimate on a cadence, and path_stats() answers the same from any thread.
// Over UDP the figures are the stream's own; over TCP (Linux) the kernel's.
TEST(TransportUdpTest, PathSamplesReachTheApplication) {
    std::vector<TransportKind> wires{TransportKind::Udp};
#if defined(__linux__)
    wires.push_back(TransportKind::Tcp);
#endif
    for (const TransportKind wire : wires) {
        SCOPED_TRACE(to_string(wire));
        NodeConfig server_cfg = base_config();
        NodeConfig client_cfg = base_config();
        client_cfg.enable_listen       = false;
        client_cfg.preferred_transport = wire;
        client_cfg.transport_fallback_ms = 0;

        Node server(server_cfg), client(client_cfg);
        std::atomic<size_t> got{0};
        server.on("bulk", [&](Peer, ByteView payload) { got += payload.size(); });

        std::mutex           mu;
        std::vector<PathStats> samples;
        client.on_peer_path([&](const Peer&, const PathStats& st) {
            std::lock_guard<std::mutex> lock(mu);
            samples.push_back(st);
        });
        ASSERT_TRUE(server.start());
        ASSERT_TRUE(client.start());

        client.connect("127.0.0.1", server.listen_port());
        ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; }));
        const PeerInfo info = client.peers().front();
        ASSERT_EQ(info.transport, wire);

        const std::string chunk(64 * 1024, 'b');
        constexpr size_t  kTotal = 4 * 1024 * 1024;
        for (size_t sent = 0; sent < kTotal; sent += chunk.size()) {
            while (!client.peer_writable(info.id)) std::this_thread::sleep_for(1ms);
            client.send(info.id, "bulk", ByteView(chunk));
        }
        ASSERT_TRUE(wait_for([&] { return got.load() == kTotal; }, 30s));
        ASSERT_TRUE(wait_for([&] {
            const auto st = client.path_stats(info.id);
            return st && st->bytes_delivered >= kTotal;
        })) << "no sample saw the transfer delivered";

        const auto st = client.path_stats(info.id);
        ASSERT_TRUE(st);
        EXPECT_TRUE(st->valid);
        EXPECT_GT(st->bandwidth_bps, 0u);
        EXPECT_GT(st->srtt_us, 0u);
        EXPECT_TRUE(wait_for([&] {
            std::lock_guard<std::mutex> lock(mu);
            return samples.size() >= 3;
        })) << "the handler is not called on a cadence";
        EXPECT_FALSE(server.path_stats(client.local_id())) << "nobody asked the server to sample";

        client.stop();
        server.stop();
    }
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

    // Those bytes were charged against the peer the moment they were handed over
    // and are discharged when the reactor reaches them — which is also where they
    // are refused. Until that happens the peer honestly reports no room, so asking
    // any sooner asks about the refused message rather than about the connection.
    // (Copying 64 MiB into the reactor takes long enough for the two to race, which
    // is how this first showed up: on the machine that was slower at it.)
    ASSERT_TRUE(wait_for([&] { return client.peer_writable(peer); }, 30s))
        << "the refused message left the peer charged for bytes nobody is carrying";

    // A small message behind it still arrives, which is the point: the refusal cost
    // the connection nothing.
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
    std::atomic<size_t> got{0};
    server.on("bulk", [&](Peer, ByteView payload) { got += payload.size(); });

    std::atomic<int> lost{0};
    client.on_peer_disconnected([&](const PeerId&, CloseReason) { ++lost; });

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));
    const PeerId peer_id = client.peers().front().id;

    auto handle = client.peer(peer_id);
    ASSERT_TRUE(handle.has_value());
    EXPECT_TRUE(client.peer_writable(peer_id)) << "an idle peer reported no room";

    // One message past the mark, so the answer does not depend on how fast the
    // reactor drains: the bytes are charged to the peer by this very thread before
    // send() returns, and 128 KiB is already past the 64 KiB mark on its own.
    // Anything that waits for the reactor here races it instead of testing it.
    const std::string over_the_mark(128 * 1024, 'p');
    EXPECT_FALSE(handle->send("bulk", ByteView(over_the_mark)))
        << "Peer::send() reported room after being handed twice the mark";
    EXPECT_EQ(lost.load(), 0) << "one message over the mark is not a slow consumer";

    // "No room" meant wait, not lost: it arrives, and then there is room again.
    ASSERT_TRUE(wait_for([&] { return got.load() == over_the_mark.size(); }, 30s))
        << "Peer::send() answered no room and dropped the message with it";
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
