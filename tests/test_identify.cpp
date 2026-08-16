#include <gtest/gtest.h>
#include "test_paths.h"

#include "librats/node/identify.h"
#include "librats/node/node.h"
#include "librats/core/address.h"
#include "librats/peer/peer.h"

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

using namespace librats;
using namespace std::chrono_literals;

// ─────────────────────────────────────────────────────────────────────────────
// IdentifyMessage codec — round-trips, bounds, and hostile-input rejection.
// ─────────────────────────────────────────────────────────────────────────────

TEST(IdentifyCodec, RoundTripFull) {
    IdentifyMessage msg;
    msg.listen_port = 51820;
    msg.addresses = {Address{"192.168.0.5", 4242}, Address{"fe80::1", 9000}};
    msg.observed = Address{"203.0.113.7", 6881};

    const auto decoded = IdentifyMessage::decode(ByteView(msg.encode()));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->listen_port, 51820);
    ASSERT_EQ(decoded->addresses.size(), 2u);
    EXPECT_EQ(decoded->addresses[0], (Address{"192.168.0.5", 4242}));
    EXPECT_EQ(decoded->addresses[1], (Address{"fe80::1", 9000}));
    ASSERT_TRUE(decoded->observed.has_value());
    EXPECT_EQ(*decoded->observed, (Address{"203.0.113.7", 6881}));
}

TEST(IdentifyCodec, RoundTripEmpty) {
    IdentifyMessage msg;  // listen_port 0, no addresses, no observed
    const auto decoded = IdentifyMessage::decode(ByteView(msg.encode()));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->listen_port, 0);
    EXPECT_TRUE(decoded->addresses.empty());
    EXPECT_FALSE(decoded->observed.has_value());
}

TEST(IdentifyCodec, ObservedAbsentIsNullopt) {
    IdentifyMessage msg;
    msg.listen_port = 1234;
    msg.addresses = {Address{"10.0.0.1", 5000}};
    // observed left unset
    const auto decoded = IdentifyMessage::decode(ByteView(msg.encode()));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_FALSE(decoded->observed.has_value());
}

TEST(IdentifyCodec, EncodeSkipsInvalidAddresses) {
    IdentifyMessage msg;
    msg.listen_port = 80;
    msg.addresses = {
        Address{"1.2.3.4", 0},        // zero port        → skipped
        Address{IpAddress{}, 5000},   // unspecified ip    → skipped
        Address{"5.6.7.8", 90},       // valid             → kept
    };
    const auto decoded = IdentifyMessage::decode(ByteView(msg.encode()));
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->addresses.size(), 1u);
    EXPECT_EQ(decoded->addresses[0], (Address{"5.6.7.8", 90}));
}

TEST(IdentifyCodec, EncodeCapsAddressCount) {
    IdentifyMessage msg;
    msg.listen_port = 1;
    for (int i = 0; i < 50; ++i) msg.addresses.push_back(Address{"10.0.0." + std::to_string(i % 200 + 1), 7000});
    const auto decoded = IdentifyMessage::decode(ByteView(msg.encode()));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->addresses.size(), IdentifyMessage::kMaxAddresses);
}

TEST(IdentifyCodec, RejectsUnknownVersion) {
    Bytes buf = IdentifyMessage{}.encode();
    buf[0] = 99;  // an unknown version (current is kVersion == 1)
    EXPECT_FALSE(IdentifyMessage::decode(ByteView(buf)).has_value());
}

TEST(IdentifyCodec, RejectsOverlargeCount) {
    // version=kVersion, listen_port=0, count>kMaxAddresses — no address bytes follow.
    Bytes buf = {IdentifyMessage::kVersion, 0, 0, static_cast<uint8_t>(IdentifyMessage::kMaxAddresses + 1)};
    EXPECT_FALSE(IdentifyMessage::decode(ByteView(buf)).has_value());
}

TEST(IdentifyCodec, RejectsTruncation) {
    IdentifyMessage msg;
    msg.listen_port = 4040;
    msg.addresses = {Address{"172.16.0.9", 1111}};
    msg.observed = Address{"8.8.8.8", 53};
    const Bytes full = msg.encode();

    // Every strict prefix shorter than the whole must fail to decode (each cut
    // lands mid-field), never crash and never silently accept partial data.
    for (size_t len = 1; len < full.size(); ++len) {
        const auto decoded = IdentifyMessage::decode(ByteView(full.data(), len));
        if (decoded.has_value()) {
            // The only acceptable early-success is a prefix that happens to be a
            // complete, smaller-but-valid message — assert it never claims data
            // beyond what the prefix actually contained.
            EXPECT_LE(decoded->addresses.size(), msg.addresses.size());
        }
    }
    // The full buffer decodes.
    EXPECT_TRUE(IdentifyMessage::decode(ByteView(full)).has_value());
}

TEST(IdentifyCodec, IgnoresTrailingBytes) {
    IdentifyMessage msg;
    msg.listen_port = 4242;
    Bytes buf = msg.encode();
    buf.push_back(0xAB);  // a future minor extension
    buf.push_back(0xCD);
    const auto decoded = IdentifyMessage::decode(ByteView(buf));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->listen_port, 4242);
}

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end: two live nodes exchange identify over the encrypted link, so each
// learns the OTHER's dialable address — the inbound side included, which is the
// whole point (its socket only exposes an ephemeral source port).
// ─────────────────────────────────────────────────────────────────────────────

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 10s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

NodeConfig listening_config() {
    NodeConfig c;
    c.bind_address = "127.0.0.1";   // IPv4-only → remote_ip is deterministically 127.0.0.1
    c.security = NodeConfig::Security::Noise;
    c.protocol = librats_test::test_protocol();
    return c;
}

std::vector<Address> addresses_of(Node& node, const PeerId& id) {
    auto p = node.peer(id);
    if (!p) return {};
    auto info = p->info();
    return info ? info->addresses : std::vector<Address>{};
}

size_t count_address(const std::vector<Address>& v, const Address& a) {
    return static_cast<size_t>(std::count(v.begin(), v.end(), a));
}

} // namespace

TEST(IdentifyE2E, InboundPeerBecomesDialable) {
    Node server(listening_config());
    Node client(listening_config());  // client also listens, so it has a dialable port

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    const Address client_dialable{"127.0.0.1", client.listen_port()};
    const Address server_dialable{"127.0.0.1", server.listen_port()};

    // The server's view of the client is an INBOUND connection: without identify it
    // would have no dialable address at all. After identify it must know one.
    ASSERT_TRUE(wait_for([&] {
        return count_address(addresses_of(server, client.local_id()), client_dialable) == 1;
    })) << "server never learned the inbound client's dialable address";

    // The client's view of the server (outbound) already had the dialed address;
    // identify must NOT duplicate it — uniqueness is enforced.
    EXPECT_EQ(count_address(addresses_of(client, server.local_id()), server_dialable), 1u);

    server.stop();
    client.stop();
}

TEST(IdentifyE2E, LearnsOwnObservedAddress) {
    Node server(listening_config());
    Node client(listening_config());

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    // The client told the server "I see you at 127.0.0.1"; the server pairs that
    // with its own listen port to learn its publicly-observed address.
    const Address server_self{"127.0.0.1", server.listen_port()};
    ASSERT_TRUE(wait_for([&] {
        const auto obs = server.observed_addresses();
        return std::find(obs.begin(), obs.end(), server_self) != obs.end();
    })) << "server never learned its own observed address";

    server.stop();
    client.stop();
}

// On a DATAGRAM link the source port a peer sees is not ephemeral: every UDP peer
// shares one socket, so it is that socket's mapping — the port a third party would
// have to aim at, and the only thing a hole punch can be pointed at. Identify
// carries it, and the node keeps it apart from the listen-port-derived addresses.
TEST(IdentifyE2E, DatagramPeersReportTheObservedPortToo) {
    NodeConfig cfg = listening_config();
    cfg.preferred_transport = TransportKind::Udp;

    Node server(cfg);
    Node client(cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));
    ASSERT_TRUE(wait_for([&] {
        const auto peers = client.peers();
        return !peers.empty() && peers[0].transport == TransportKind::Udp;
    })) << "the link did not come up over the datagram transport";

    // With no NAT between them the mapping is the identity, so each side is
    // observed at exactly the port it listens on — which is also what tells the
    // node there is nothing in the path to punch through.
    const Address client_endpoint{"127.0.0.1", client.listen_port()};
    ASSERT_TRUE(wait_for([&] {
        const auto endpoints = client.nat_status().external_udp_endpoints();
        return std::find(endpoints.begin(), endpoints.end(), client_endpoint) != endpoints.end();
    })) << "the client never learned the endpoint its datagram socket is seen at";
    EXPECT_EQ(client.nat_status().udp_mapping(), NatMapping::Open);

    server.stop();
    client.stop();
}

// The same port over TCP is an ephemeral one the peer's OS picked for that one
// socket. Reporting it would teach the peer an endpoint that is gone the moment the
// connection is, so a TCP-only pair learns no datagram endpoint at all.
TEST(IdentifyE2E, TcpPeersReportNoObservedPort) {
    NodeConfig cfg = listening_config();
    cfg.enable_udp = false;   // TCP is the only wire either of them has

    Node server(cfg);
    Node client(cfg);
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    // Give identify time to have arrived — the observed-address path below fires
    // from the same message, so once it is there the datagram half has had its
    // chance too.
    const Address client_self{"127.0.0.1", client.listen_port()};
    ASSERT_TRUE(wait_for([&] {
        const auto obs = client.observed_addresses();
        return std::find(obs.begin(), obs.end(), client_self) != obs.end();
    }));

    EXPECT_TRUE(client.nat_status().external_udp_endpoints().empty())
        << "a TCP source port was mistaken for a datagram mapping";
    EXPECT_EQ(client.nat_status().udp_mapping(), NatMapping::Unknown);

    server.stop();
    client.stop();
}
