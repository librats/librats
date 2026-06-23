#include <gtest/gtest.h>

#include "node/node.h"
#include "core/address.h"
#include "core/socket.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace librats;
using namespace std::chrono_literals;

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

std::string str(ByteView v) {
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

NodeConfig server_config() {
    NodeConfig c;
    c.listen_port = 0;          // ephemeral
    c.bind_address = "127.0.0.1";
    c.security = NodeConfig::Security::Noise;
    return c;
}

NodeConfig client_config() {
    NodeConfig c = server_config();
    c.enable_listen = false;    // dial-only
    return c;
}

// A repeating byte pattern, large enough to span many frames / recv boundaries.
std::string big_payload(size_t n) {
    std::string s(n, '\0');
    for (size_t i = 0; i < n; ++i) s[i] = static_cast<char>((i * 131 + 7) & 0xFF);
    return s;
}

} // namespace

// Connect, send on a named channel, get a reply — all encrypted end to end.
TEST(NodeTest, ConnectAndEchoMessage) {
    Node server(server_config());
    Node client(client_config());

    std::atomic<int> server_peers{0}, client_peers{0};
    server.on_peer_connected([&](const Peer&) { server_peers++; });
    client.on_peer_connected([&](const Peer&) { client_peers++; });

    // Server echoes whatever arrives on "chat" back to the sender.
    server.on("chat", [](const Peer& from, ByteView msg) { from.send("chat", msg); });

    std::mutex mu;
    std::string got;
    client.on("chat", [&](const Peer&, ByteView msg) {
        std::lock_guard<std::mutex> lock(mu);
        got = str(msg);
    });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }))
        << "peers: client=" << client.peer_count() << " server=" << server.peer_count();

    EXPECT_EQ(server_peers.load(), 1);
    EXPECT_EQ(client_peers.load(), 1);

    // Both directories learned the other's self-certifying id.
    EXPECT_TRUE(client.peer(server.local_id()).has_value());
    EXPECT_TRUE(server.peer(client.local_id()).has_value());

    client.send(server.local_id(), "chat", ByteView(std::string("hello node")));
    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(mu); return got == "hello node"; }))
        << "no echo received";

    client.stop();
    server.stop();
}

// Replying through the Peer handle passed to the message callback.
TEST(NodeTest, ReplyViaPeerHandle) {
    Node server(server_config());
    Node client(client_config());

    server.on("ping", [](const Peer& from, ByteView) { from.send("pong", ByteView(std::string("ok"))); });

    std::atomic<bool> ponged{false};
    client.on("pong", [&](const Peer&, ByteView msg) { if (str(msg) == "ok") ponged = true; });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; }));

    client.send(server.local_id(), "ping", ByteView());
    ASSERT_TRUE(wait_for([&] { return ponged.load(); }));

    client.stop();
    server.stop();
}

// Hub broadcasts to all connected spokes.
TEST(NodeTest, BroadcastToAllPeers) {
    Node hub(server_config());
    Node a(client_config());
    Node b(client_config());

    std::atomic<int> got_a{0}, got_b{0};
    a.on("news", [&](const Peer&, ByteView m) { if (str(m) == "extra") got_a++; });
    b.on("news", [&](const Peer&, ByteView m) { if (str(m) == "extra") got_b++; });

    ASSERT_TRUE(hub.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    a.connect("127.0.0.1", hub.listen_port());
    b.connect("127.0.0.1", hub.listen_port());
    ASSERT_TRUE(wait_for([&] { return hub.peer_count() == 2; }))
        << "hub peers: " << hub.peer_count();

    hub.broadcast("news", ByteView(std::string("extra")));
    ASSERT_TRUE(wait_for([&] { return got_a.load() == 1 && got_b.load() == 1; }))
        << "a=" << got_a.load() << " b=" << got_b.load();

    a.stop();
    b.stop();
    hub.stop();
}

// A server with max_peers=1 admits one inbound peer and rejects the next.
TEST(NodeTest, MaxPeersRejectsInbound) {
    NodeConfig sc = server_config();
    sc.max_peers = 1;
    Node server(sc);
    Node a(client_config());
    Node b(client_config());

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    a.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.peer_count() == 1; }));
    EXPECT_TRUE(server.peer_limit_reached());

    // b's inbound is refused (at accept or by the on_established backstop); the
    // server never exceeds its cap and b never establishes a peer to it.
    b.connect("127.0.0.1", server.listen_port());
    std::this_thread::sleep_for(700ms);
    EXPECT_EQ(server.peer_count(), 1u);
    EXPECT_EQ(b.peer_count(), 0u);

    a.stop();
    b.stop();
    server.stop();
}

// Raising the limit at runtime lets a previously-refused peer in.
TEST(NodeTest, MaxPeersRuntimeRaise) {
    NodeConfig sc = server_config();
    sc.max_peers = 1;
    Node server(sc);
    Node a(client_config());
    Node b(client_config());

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    a.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.peer_count() == 1; }));

    server.set_max_peers(2);
    EXPECT_EQ(server.max_peers(), 2u);

    b.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.peer_count() == 2; }))
        << "b not admitted after raising the limit; server peers=" << server.peer_count();
    EXPECT_TRUE(server.peer_limit_reached());  // now full again at 2/2

    a.stop();
    b.stop();
    server.stop();
}

// Nodes with a different protocol id cannot connect (the handshake prologue
// diverges, failing the Noise handshake). Cross-application isolation.
TEST(NodeTest, ProtocolMismatchPreventsConnection) {
    NodeConfig sc = server_config(); sc.protocol_name = "app-a";
    NodeConfig cc = client_config(); cc.protocol_name = "app-b";
    Node server(sc);
    Node client(cc);

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", server.listen_port());

    std::this_thread::sleep_for(700ms);  // ample time for a handshake to fail
    EXPECT_EQ(server.peer_count(), 0u);
    EXPECT_EQ(client.peer_count(), 0u);

    client.stop();
    server.stop();
}

// A matching custom protocol (name + version) connects normally.
TEST(NodeTest, MatchingCustomProtocolConnects) {
    NodeConfig sc = server_config(); sc.protocol_name = "myapp"; sc.protocol_version = "3.1";
    NodeConfig cc = client_config(); cc.protocol_name = "myapp"; cc.protocol_version = "3.1";
    Node server(sc);
    Node client(cc);

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.peer_count() == 1 && client.peer_count() == 1; }));

    client.stop();
    server.stop();
}

// Disconnecting one side fires the peer-disconnected event on the other.
TEST(NodeTest, DisconnectNotifiesPeer) {
    Node server(server_config());
    Node client(client_config());

    std::atomic<int> server_disconnects{0};
    server.on_peer_disconnected([&](PeerId) { server_disconnects++; });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return server.peer_count() == 1; }));

    client.stop();  // drops the connection
    ASSERT_TRUE(wait_for([&] { return server_disconnects.load() == 1; }));
    EXPECT_EQ(server.peer_count(), 0u);

    server.stop();
}

// A multi-megabyte payload round-trips byte-exact, under both security modes.
// Exercises frame chunking + reassembly across recv boundaries (and per-frame
// AEAD when encrypted). Parameterized over Noise / Plaintext.
class NodeLargePayloadTest : public ::testing::TestWithParam<NodeConfig::Security> {};

TEST_P(NodeLargePayloadTest, RoundTripsIntact) {
    NodeConfig sc = server_config(); sc.security = GetParam();
    NodeConfig cc = client_config(); cc.security = GetParam();
    Node server(sc);
    Node client(cc);

    server.on("blob", [](const Peer& from, ByteView msg) { from.send("blob", msg); });

    std::mutex mu;
    std::string got;
    client.on("blob", [&](const Peer&, ByteView msg) {
        std::lock_guard<std::mutex> l(mu); got = str(msg);
    });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    const std::string payload = big_payload(2 * 1024 * 1024 + 333);  // ~2MB, not frame-aligned
    client.send(server.local_id(), "blob", ByteView(payload));
    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(mu); return got.size() == payload.size(); }))
        << "large payload not fully received";
    {
        std::lock_guard<std::mutex> l(mu);
        EXPECT_EQ(got, payload);  // byte-exact, not just same length
    }

    client.stop();
    server.stop();
}

INSTANTIATE_TEST_SUITE_P(Security, NodeLargePayloadTest,
                         ::testing::Values(NodeConfig::Security::Noise, NodeConfig::Security::Plaintext));

// Empty and single-byte payloads survive framing end to end (classic off-by-one
// territory for length-prefixed frames).
TEST(NodeTest, TinyPayloadsRoundTrip) {
    Node server(server_config());
    Node client(client_config());

    server.on("echo", [](const Peer& from, ByteView msg) { from.send("echo", msg); });

    std::mutex mu;
    std::vector<size_t> sizes;
    client.on("echo", [&](const Peer&, ByteView msg) {
        std::lock_guard<std::mutex> l(mu); sizes.push_back(msg.size());
    });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    client.send(server.local_id(), "echo", ByteView());                       // empty
    client.send(server.local_id(), "echo", ByteView(std::string("x")));       // one byte
    ASSERT_TRUE(wait_for([&] { std::lock_guard<std::mutex> l(mu); return sizes.size() == 2; }));
    {
        std::lock_guard<std::mutex> l(mu);
        std::sort(sizes.begin(), sizes.end());
        EXPECT_EQ(sizes[0], 0u);
        EXPECT_EQ(sizes[1], 1u);
    }

    client.stop();
    server.stop();
}

// N near-simultaneous dials to the same peer collapse to a single connection
// (duplicate-connection dedup), not N peers on either side.
TEST(NodeTest, DuplicateDialsDedupToOnePeer) {
    Node server(server_config());
    Node client(client_config());

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    const uint16_t port = server.listen_port();
    for (int i = 0; i < 6; ++i) client.connect("127.0.0.1", port);  // fire before any handshake settles

    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }))
        << "client=" << client.peer_count() << " server=" << server.peer_count();
    std::this_thread::sleep_for(500ms);  // let any duplicates that were in flight surface
    EXPECT_EQ(client.peer_count(), 1u);
    EXPECT_EQ(server.peer_count(), 1u);

    client.stop();
    server.stop();
}

// One Node instance can be started, stopped, and started again — sockets rebind
// and threads relaunch cleanly across cycles.
TEST(NodeTest, RestartCycles) {
    Node server(server_config());
    Node client(client_config());

    for (int cycle = 0; cycle < 3; ++cycle) {
        ASSERT_TRUE(server.start()) << "server start failed on cycle " << cycle;
        ASSERT_TRUE(client.start()) << "client start failed on cycle " << cycle;

        client.connect("127.0.0.1", server.listen_port());
        ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }))
            << "no connection on cycle " << cycle;

        client.stop();
        server.stop();
    }
}

// Hostile / degenerate inputs are no-ops, not crashes.
TEST(NodeTest, RobustAgainstBadInputs) {
    // start() fails (returns false) when the bind address is not a local interface.
    {
        NodeConfig bad = server_config();
        bad.bind_address = "192.0.2.123";  // TEST-NET-1: never a local address
        Node node(bad);
        EXPECT_FALSE(node.start()) << "start() should fail on an un-bindable address";
    }

    // A live node tolerates sends to unknown peers and dials to dead ports.
    Node node(server_config());
    ASSERT_TRUE(node.start());
    EXPECT_NO_THROW(node.send(PeerId{}, "chat", ByteView(std::string("nobody"))));  // unknown id
    EXPECT_NO_THROW(node.broadcast("chat", ByteView(std::string("noone"))));        // zero peers
    EXPECT_NO_THROW(node.connect("127.0.0.1", 1));      // nothing listening on port 1
    EXPECT_NO_THROW(node.connect("127.0.0.1", 0));      // degenerate port
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(node.peer_count(), 0u);
    node.stop();
}

// Address serialises IPv6 bracketed and round-trips exactly through parse().
TEST(AddressTest, RoundTripsIPv4AndIPv6) {
    auto v4 = Address::parse("127.0.0.1:8080");
    ASSERT_TRUE(v4);
    EXPECT_EQ(v4->ip, "127.0.0.1");
    EXPECT_EQ(v4->port, 8080);
    EXPECT_EQ(v4->to_string(), "127.0.0.1:8080");

    auto v6 = Address::parse("[::1]:9000");
    ASSERT_TRUE(v6);
    EXPECT_EQ(v6->ip, "::1");                 // stored bare, no brackets
    EXPECT_EQ(v6->port, 9000);
    EXPECT_EQ(v6->to_string(), "[::1]:9000"); // rendered bracketed

    auto v6full = Address::parse("[2001:db8::ff00:42:8329]:443");
    ASSERT_TRUE(v6full);
    EXPECT_EQ(v6full->ip, "2001:db8::ff00:42:8329");
    EXPECT_EQ(v6full->port, 443);

    // to_string() is the exact inverse of parse() for a constructed IPv6 endpoint
    // (this is the path PeerTable persistence relies on).
    Address a{"fe80::1", 1234};
    EXPECT_EQ(a.to_string(), "[fe80::1]:1234");
    auto reparsed = Address::parse(a.to_string());
    ASSERT_TRUE(reparsed);
    EXPECT_EQ(*reparsed, a);
}

TEST(AddressTest, RejectsMalformed) {
    EXPECT_FALSE(Address::parse("127.0.0.1"));        // no port
    EXPECT_FALSE(Address::parse("127.0.0.1:"));       // empty port
    EXPECT_FALSE(Address::parse("127.0.0.1:0"));      // zero port
    EXPECT_FALSE(Address::parse("127.0.0.1:70000"));  // out of range
    EXPECT_FALSE(Address::parse("::1"));              // bare IPv6 — ambiguous port
    EXPECT_FALSE(Address::parse("[::1]"));            // bracketed, no port
    EXPECT_FALSE(Address::parse("[::1]:"));           // bracketed, empty port
    EXPECT_FALSE(Address::parse(""));                 // empty
}

// A dual-stack listener ("::") is reachable over BOTH IPv4 and IPv6 loopback on
// the same port — the core of restored dual-stack support.
TEST(NodeTest, DualStackListenerAcceptsV4AndV6) {
    NodeConfig scfg;
    scfg.listen_port = 0;          // ephemeral
    scfg.bind_address = "::";      // dual-stack wildcard
    scfg.security = NodeConfig::Security::Noise;
    Node server(scfg);
    ASSERT_TRUE(server.start()) << "dual-stack listener failed to bind";
    const uint16_t port = server.listen_port();
    ASSERT_NE(port, 0);

    // IPv4 dial reaches the dual-stack (IPv6) socket via IPv4-mapping.
    Node clientV4(client_config());
    ASSERT_TRUE(clientV4.start());
    clientV4.connect("127.0.0.1", port);
    ASSERT_TRUE(wait_for([&] { return clientV4.peer_count() == 1; }))
        << "IPv4 dial to dual-stack listener did not establish";

    // IPv6 dial reaches the same socket natively. Skip only if the host has no
    // IPv6 loopback at all (rare; then the IPv4 path above already proved dual-stack).
    const bool have_v6 = [] {
        socket_t s = create_tcp_server(0, 1, "::1", AddressFamily::IPv6);
        if (!is_valid_socket(s)) return false;
        close_socket(s);
        return true;
    }();
    if (!have_v6) {
        clientV4.stop();
        server.stop();
        GTEST_SKIP() << "host has no IPv6 loopback; verified the IPv4-mapped path only";
    }

    Node clientV6(client_config());
    ASSERT_TRUE(clientV6.start());
    clientV6.connect("::1", port);
    ASSERT_TRUE(wait_for([&] { return clientV6.peer_count() == 1; }))
        << "IPv6 dial to dual-stack listener did not establish";

    ASSERT_TRUE(wait_for([&] { return server.peer_count() == 2; }))
        << "server should hold both the IPv4 and IPv6 peers";

    clientV6.stop();
    clientV4.stop();
    server.stop();
}
