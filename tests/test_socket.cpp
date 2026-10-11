#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "librats/core/socket.h"
#include "librats/core/udp_io.h"
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

using namespace librats;

class SocketTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(init_socket_library());
    }
    
    void TearDown() override {
        cleanup_socket_library();
    }
};

// Test socket library initialization
TEST_F(SocketTest, InitializationTest) {
    // Should already be initialized in SetUp
    EXPECT_TRUE(true);
}

// Test Peer structure
TEST_F(SocketTest, PeerTest) {
    Address peer1("127.0.0.1", 8080);
    EXPECT_EQ(peer1.ip.to_string(), "127.0.0.1");
    EXPECT_EQ(peer1.port, 8080);
    
    Address peer2("127.0.0.1", 8080);
    EXPECT_EQ(peer1, peer2);
    
    Address peer3("127.0.0.1", 8081);
    EXPECT_NE(peer1, peer3);
}

// Test socket validity check
TEST_F(SocketTest, SocketValidityTest) {
    socket_t valid_socket = create_tcp_server(0);  // Use port 0 for automatic port assignment
    EXPECT_TRUE(is_valid_socket(valid_socket));
    
    close_socket(valid_socket);
    
    socket_t invalid_socket = RATS_INVALID_SOCKET;
    EXPECT_FALSE(is_valid_socket(invalid_socket));
}

// Test TCP server creation with AddressFamily
TEST_F(SocketTest, TCPServerCreationTest) {
    // Test dual-stack server (default)
    socket_t server = create_tcp_server(0);
    EXPECT_TRUE(is_valid_socket(server));
    close_socket(server);
    
    // Test IPv4 server
    socket_t server_v4 = create_tcp_server(0, 5, "", AddressFamily::IPv4);
    EXPECT_TRUE(is_valid_socket(server_v4));
    close_socket(server_v4);
    
    // Test IPv6 server
    socket_t server_v6 = create_tcp_server(0, 5, "", AddressFamily::IPv6);
    EXPECT_TRUE(is_valid_socket(server_v6));
    close_socket(server_v6);
}

// Test UDP socket creation with AddressFamily
TEST_F(SocketTest, UDPSocketCreationTest) {
    // Test dual-stack UDP socket
    socket_t udp_socket = create_udp_socket(0);
    EXPECT_TRUE(is_valid_socket(udp_socket));
    close_socket(udp_socket);
    
    // Test IPv4 UDP socket
    socket_t udp_v4 = create_udp_socket(0, "", AddressFamily::IPv4);
    EXPECT_TRUE(is_valid_socket(udp_v4));
    close_socket(udp_v4);
    
    // Test IPv6 UDP socket
    socket_t udp_v6 = create_udp_socket(0, "", AddressFamily::IPv6);
    EXPECT_TRUE(is_valid_socket(udp_v6));
    close_socket(udp_v6);
}

// A datagram port is not implicitly shareable, and a caller that says so is obeyed.
//
// The three tests below pin the behaviour that decides whether the BitTorrent uTP
// mux and the DHT can both claim the torrent port. They used to both succeed and
// then silently split the arriving datagrams between them, which reads at every
// layer above as unexplained packet loss on both.
TEST_F(SocketTest, ExclusiveUdpBindRefusesAPortSomebodyElseHolds) {
    socket_t held = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(held));
    const int port = get_bound_port(held);
    ASSERT_GT(port, 0);

    socket_t second = create_udp_socket(port, "127.0.0.1", AddressFamily::IPv4,
                                        UdpPortMode::Exclusive);
    EXPECT_FALSE(is_valid_socket(second))
        << "an Exclusive bind took a port another socket is already serving";
    if (is_valid_socket(second)) close_socket(second);
    close_socket(held);
}

// The other half of the contract: Exclusive must not be a bind that always fails.
TEST_F(SocketTest, ExclusiveUdpBindTakesAFreePort) {
    // Learn a port that is free by binding and releasing it. Racy in principle,
    // which is why the assertion below is only about the mode, not the number.
    socket_t probe = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(probe));
    const int port = get_bound_port(probe);
    close_socket(probe);

    socket_t s = create_udp_socket(port, "127.0.0.1", AddressFamily::IPv4,
                                   UdpPortMode::Exclusive);
    ASSERT_TRUE(is_valid_socket(s));
    EXPECT_EQ(get_bound_port(s), port);
    close_socket(s);

    // Port 0 is exclusive by construction — the kernel does not hand out a port it
    // has already given away — so the mode must not get in the way of an ephemeral
    // bind either.
    socket_t eph = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4,
                                     UdpPortMode::Exclusive);
    EXPECT_TRUE(is_valid_socket(eph));
    close_socket(eph);
}

// And the reverse direction: once a socket has claimed a port exclusively, a later
// Shared bind must not be able to take it away. Only Windows can enforce this (via
// SO_EXCLUSIVEADDRUSE); elsewhere a plain bind already refuses to share a unicast
// datagram port, so the expectation holds for a different reason.
TEST_F(SocketTest, AnExclusivelyHeldUdpPortCannotBeSharedAfterwards) {
    socket_t probe = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(probe));
    const int port = get_bound_port(probe);
    close_socket(probe);

    socket_t owner = create_udp_socket(port, "127.0.0.1", AddressFamily::IPv4,
                                       UdpPortMode::Exclusive);
    ASSERT_TRUE(is_valid_socket(owner));

    socket_t sharer = create_udp_socket(port, "127.0.0.1", AddressFamily::IPv4,
                                        UdpPortMode::Shared);
    EXPECT_FALSE(is_valid_socket(sharer))
        << "a Shared bind took a port held exclusively";
    if (is_valid_socket(sharer)) close_socket(sharer);
    close_socket(owner);
}

// A bounded receive must be able to say WHY it came back empty: "nothing yet"
// and "the peer hung up" are the difference between waiting again and giving up,
// and a reader with a deadline (see util/http.cpp) is built on that distinction.
TEST_F(SocketTest, ReceiveTcpDataReportsTimeoutThenClose) {
    socket_t server = create_tcp_server(0, 4, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(server));
    const int port = get_bound_port(server);
    ASSERT_GT(port, 0);

    socket_t accepted = RATS_INVALID_SOCKET;
    std::thread server_thread([&]() { accepted = accept_client(server); });

    socket_t client = create_tcp_client("127.0.0.1", port, 2000);
    ASSERT_TRUE(is_valid_socket(client));
    server_thread.join();
    ASSERT_TRUE(is_valid_socket(accepted));

    // Nobody sent anything: the wait expires and says so, instead of blocking.
    const auto start = std::chrono::steady_clock::now();
    TcpRecvStatus status = TcpRecvStatus::Data;
    auto data = receive_tcp_data(client, 1024, 200, RATS_INVALID_SOCKET, &status);
    const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - start).count();
    EXPECT_TRUE(data.empty());
    EXPECT_EQ(status, TcpRecvStatus::Timeout);
    EXPECT_GE(waited, 150);

    // Real data outranks the deadline.
    EXPECT_GT(send_tcp_string(accepted, "hi"), 0);
    data = receive_tcp_data(client, 1024, 2000, RATS_INVALID_SOCKET, &status);
    EXPECT_EQ(status, TcpRecvStatus::Data);
    EXPECT_EQ(std::string(data.begin(), data.end()), "hi");

    // An orderly hang-up is Closed, not Error — it is how a length-less HTTP body ends.
    close_socket(accepted);
    data = receive_tcp_data(client, 1024, 2000, RATS_INVALID_SOCKET, &status);
    EXPECT_TRUE(data.empty());
    EXPECT_EQ(status, TcpRecvStatus::Closed);

    close_socket(client);
    close_socket(server);
}

// Test TCP client-server communication
TEST_F(SocketTest, TCPClientServerCommunicationTest) {
    // Create server
    socket_t server = create_tcp_server(0);
    ASSERT_TRUE(is_valid_socket(server));
    
    // Get the actual port the server is listening on
    int port = get_bound_port(server);
    ASSERT_GT(port, 0);
    
    // Test connection in separate thread
    std::thread server_thread([&]() {
        socket_t client = accept_client(server);
        EXPECT_TRUE(is_valid_socket(client));
        
        if (is_valid_socket(client)) {
            auto received = receive_tcp_data(client);
            std::string received_str(received.begin(), received.end());
            EXPECT_EQ(received_str, "Hello Server!");
            
            int sent = send_tcp_string(client, "Hello Client!");
            EXPECT_GT(sent, 0);
            
            close_socket(client);
        }
    });
    
    // Give server time to start listening
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Create client and connect
    socket_t client = create_tcp_client("127.0.0.1", port);
    ASSERT_TRUE(is_valid_socket(client));
    
    // Send data
    int sent = send_tcp_string(client, "Hello Server!");
    EXPECT_GT(sent, 0);
    
    // Receive response
    auto response = receive_tcp_data(client);
    std::string response_str(response.begin(), response.end());
    EXPECT_EQ(response_str, "Hello Client!");
    
    close_socket(client);
    server_thread.join();
    close_socket(server);
}

// Test get peer address
TEST_F(SocketTest, GetPeerAddressTest) {
    socket_t server = create_tcp_server(0);
    ASSERT_TRUE(is_valid_socket(server));
    
    int port = get_bound_port(server);
    ASSERT_GT(port, 0);
    
    std::thread server_thread([&]() {
        socket_t client = accept_client(server);
        if (is_valid_socket(client)) {
            std::string peer_addr = get_peer_address(client);
            EXPECT_FALSE(peer_addr.empty());
            EXPECT_THAT(peer_addr, testing::HasSubstr("127.0.0.1"));
            close_socket(client);
        }
    });
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    socket_t client = create_tcp_client("127.0.0.1", port);
    ASSERT_TRUE(is_valid_socket(client));
    
    close_socket(client);
    server_thread.join();
    close_socket(server);
}

// Test get_bound_port
TEST_F(SocketTest, GetBoundPortTest) {
    socket_t server = create_tcp_server(0);
    ASSERT_TRUE(is_valid_socket(server));
    
    int port = get_bound_port(server);
    EXPECT_GT(port, 0);
    EXPECT_LE(port, 65535);
    
    close_socket(server);
    
    // Test with UDP socket
    socket_t udp = create_udp_socket(0);
    ASSERT_TRUE(is_valid_socket(udp));
    
    int udp_port = get_bound_port(udp);
    EXPECT_GT(udp_port, 0);
    EXPECT_LE(udp_port, 65535);
    
    close_socket(udp);
}

// Test non-blocking socket
TEST_F(SocketTest, NonBlockingSocketTest) {
    socket_t socket = create_tcp_server(0);
    ASSERT_TRUE(is_valid_socket(socket));
    
    bool result = set_socket_nonblocking(socket);
    EXPECT_TRUE(result);
    
    close_socket(socket);
}

// Test socket close
TEST_F(SocketTest, SocketCloseTest) {
    socket_t socket = create_tcp_server(0);
    ASSERT_TRUE(is_valid_socket(socket));
    
    close_socket(socket);
    
    // After closing, socket should be invalid
    // Note: We can't easily test this without platform-specific code
    // as the socket value might be reused
}

// Test invalid operations
TEST_F(SocketTest, InvalidOperationsTest) {
    socket_t invalid_socket = RATS_INVALID_SOCKET;
    
    // Test sending to invalid socket
    int result = send_tcp_string(invalid_socket, "test");
    EXPECT_LE(result, 0);  // Should fail
    
    // Test receiving from invalid socket
    auto data = receive_tcp_data(invalid_socket);
    EXPECT_TRUE(data.empty());  // Should return empty
    
    // Test getting peer address from invalid socket
    std::string peer_addr = get_peer_address(invalid_socket);
    EXPECT_TRUE(peer_addr.empty());  // Should return empty string
}

// Test edge cases
TEST_F(SocketTest, EdgeCasesTest) {
    // Test creating server on invalid port
    socket_t server = create_tcp_server(-1);
    EXPECT_FALSE(is_valid_socket(server));
    
    // Test creating client with invalid host
    socket_t client = create_tcp_client("invalid.host.example", 80);
    EXPECT_FALSE(is_valid_socket(client));
    
    // Test creating client with invalid port
    socket_t client2 = create_tcp_client("127.0.0.1", -1);
    EXPECT_FALSE(is_valid_socket(client2));
}

// ── Batched datagram I/O ────────────────────────────────────────────────────
//
// One trip through the kernel per datagram is the dominant cost of a user-space
// reliability layer, so UdpSendBatch/UdpRecvBatch move many at a time: batched
// syscalls (sendmmsg/recvmmsg) where the platform has them, and segmentation
// offload (a run of equal-size datagrams as one buffer the kernel cuts up, and
// the same coming back) where the running kernel has that. What matters at the
// call site is that every shape is indistinguishable: same datagrams, same
// order, same senders — which is what these tests pin down.

namespace {

/// A datagram whose every byte names its index, so a reordered, merged, split or
/// mis-sized result cannot pass.
std::vector<uint8_t> numbered(size_t index, size_t len) {
    return std::vector<uint8_t>(len, static_cast<uint8_t>('a' + index % 26));
}

/// Everything `socket` receives within ~2 s or until `want` datagrams arrived,
/// split back into datagrams. `runs` counts buffers that held more than one.
std::vector<std::vector<uint8_t>> receive_datagrams(socket_t socket, UdpRecvBatch& in,
                                                    size_t want, size_t* runs = nullptr,
                                                    Address* from = nullptr) {
    std::vector<std::vector<uint8_t>> out;
    for (int attempt = 0; attempt < 2000 && out.size() < want; ++attempt) {
        const std::ptrdiff_t n = in.receive(socket, kUdpBatchMax);
        if (n <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        for (std::ptrdiff_t i = 0; i < n; ++i) {
            size_t here = 0;
            in.for_each_datagram(static_cast<size_t>(i), [&](const uint8_t* data, size_t len) {
                out.emplace_back(data, data + len);
                ++here;
            });
            if (runs && here > 1) ++*runs;
            if (from) *from = in[static_cast<size_t>(i)].from;
        }
    }
    return out;
}

struct UdpPair {
    socket_t sender   = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    socket_t receiver = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    Address  sender_addr;
    Address  dest;

    UdpPair() {
        set_socket_nonblocking(receiver);
        sender_addr = Address{"127.0.0.1", static_cast<uint16_t>(get_bound_port(sender))};
        dest        = Address{"127.0.0.1", static_cast<uint16_t>(get_bound_port(receiver))};
    }
    ~UdpPair() {
        close_socket(sender);
        close_socket(receiver);
    }
    bool ok() const { return is_valid_socket(sender) && is_valid_socket(receiver); }
};

} // namespace

TEST_F(SocketTest, UdpBatchRoundTripsEveryDatagramInOrder) {
    UdpPair net;
    ASSERT_TRUE(net.ok());

    // Lengths that grow, so no two datagrams can share a run whatever the offload:
    // this is the one-datagram-per-message shape every platform has.
    constexpr size_t kCount = 8;
    UdpSendBatch out(kUdpMaxSegments);
    for (size_t i = 0; i < kCount; ++i) {
        const auto d = numbered(i, 16 + i * 7);
        ASSERT_TRUE(out.add(net.dest, d.data(), d.size()));
    }
    EXPECT_EQ(out.runs().size(), kCount);
    ASSERT_EQ(out.flush(net.sender, AddressFamily::IPv4), kCount);
    EXPECT_TRUE(out.empty());

    UdpRecvBatch in(1500, /*coalesced=*/false);
    Address      from;
    const auto   got = receive_datagrams(net.receiver, in, kCount, nullptr, &from);
    ASSERT_EQ(got.size(), kCount) << "only " << got.size() << " of " << kCount << " arrived";
    for (size_t i = 0; i < kCount; ++i)
        EXPECT_EQ(got[i], numbered(i, 16 + i * 7)) << "datagram " << i << " is not itself";
    EXPECT_EQ(from.port, net.sender_addr.port);
}

TEST_F(SocketTest, UdpBatchReceiveReportsWouldBlockOnAnEmptySocket) {
    socket_t sock = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(sock));
    set_socket_nonblocking(sock);

    UdpRecvBatch plain(1500, false);
    EXPECT_EQ(plain.receive(sock, kUdpBatchMax), kUdpRecvWouldBlock);
    UdpRecvBatch coalescing(1500, true);
    EXPECT_EQ(coalescing.receive(sock, kUdpBatchMax), kUdpRecvWouldBlock);

    close_socket(sock);
}

// The staging rules are what segmentation offload demands of a send: one
// destination, every segment the same size, only the last one shorter.
TEST(UdpSendBatchTest, CoalescesOnlyWhatOneSegmentedSendCanCarry) {
    const Address a{"10.0.0.1", 1000};
    const Address b{"10.0.0.2", 1000};
    const std::vector<uint8_t> full(1220, 'x'), short_one(300, 'y'), tiny(20, 'z');

    UdpSendBatch batch(kUdpMaxSegments);
    ASSERT_TRUE(batch.add(a, full.data(), full.size()));
    ASSERT_TRUE(batch.add(a, full.data(), full.size()));
    ASSERT_TRUE(batch.add(a, short_one.data(), short_one.size()));  // ends the run
    ASSERT_TRUE(batch.add(a, tiny.data(), tiny.size()));            // so this starts one
    ASSERT_TRUE(batch.add(a, full.data(), full.size()));            // longer: new run
    ASSERT_TRUE(batch.add(b, full.data(), full.size()));            // elsewhere: new run
    ASSERT_TRUE(batch.add(a, full.data(), full.size()));            // not adjacent: new run

    const auto& runs = batch.runs();
    ASSERT_EQ(runs.size(), 5u);
    EXPECT_EQ(runs[0].count, 3u);
    EXPECT_EQ(runs[0].segment, 1220u);
    EXPECT_EQ(runs[0].bytes, 2 * 1220u + 300u);
    EXPECT_FALSE(runs[0].open);
    EXPECT_EQ(runs[1].count, 1u);
    EXPECT_EQ(runs[1].segment, 20u);
    EXPECT_EQ(runs[2].count, 1u);
    EXPECT_EQ(runs[3].to, b);
    EXPECT_EQ(runs[4].to, a);
    EXPECT_EQ(batch.datagrams(), 7u);

    // Laid out back to back, so a run is one contiguous buffer.
    EXPECT_EQ(runs[1].offset, runs[0].offset + runs[0].bytes);
    EXPECT_EQ(std::memcmp(batch.data() + runs[0].offset + 2 * 1220, short_one.data(), 300), 0);
}

TEST(UdpSendBatchTest, RunsStopAtTheSegmentAndByteLimits) {
    const Address a{"10.0.0.1", 1000};
    const std::vector<uint8_t> full(1220, 'x'), small(100, 's');

    // Bytes: 52 x 1220 fits in one send, the 53rd does not.
    UdpSendBatch bytes(kUdpMaxSegments);
    for (int i = 0; i < 53; ++i) ASSERT_TRUE(bytes.add(a, full.data(), full.size()));
    ASSERT_EQ(bytes.runs().size(), 2u);
    EXPECT_EQ(bytes.runs()[0].count, kUdpMaxSendBytes / 1220);
    EXPECT_LE(bytes.runs()[0].bytes, kUdpMaxSendBytes);

    // Segments: 64 small datagrams are well under the byte limit, but one run.
    UdpSendBatch segments(kUdpMaxSegments);
    for (size_t i = 0; i < kUdpMaxSegments + 1; ++i)
        ASSERT_TRUE(segments.add(a, small.data(), small.size()));
    ASSERT_EQ(segments.runs().size(), 2u);
    EXPECT_EQ(segments.runs()[0].count, kUdpMaxSegments);

    // Without offload every datagram is a run of its own.
    UdpSendBatch single(1);
    for (int i = 0; i < 3; ++i) ASSERT_TRUE(single.add(a, full.data(), full.size()));
    EXPECT_EQ(single.runs().size(), 3u);

    // Full is reported, not overrun; nothing oversized or empty is taken.
    UdpSendBatch cap(kUdpMaxSegments);
    size_t taken = 0;
    while (cap.add(a, full.data(), full.size())) ++taken;
    EXPECT_EQ(taken, UdpSendBatch::kCapacity / 1220);
    const std::vector<uint8_t> huge(kUdpMaxSendBytes + 1, 'h');
    UdpSendBatch empty(kUdpMaxSegments);
    EXPECT_FALSE(empty.add(a, huge.data(), huge.size()));
    EXPECT_FALSE(empty.add(a, full.data(), 0));
}

// The two receive shapes a segmented send can meet: a socket that takes the
// run whole, and one that has the kernel cut it up first. Both must yield the
// same datagrams, in order, with the short last one intact.
TEST_F(SocketTest, UdpSegmentedSendArrivesAsTheSameDatagramsEitherWay) {
    for (const bool coalescing_receiver : {false, true}) {
        SCOPED_TRACE(coalescing_receiver ? "receiver coalesces" : "receiver does not coalesce");
        UdpPair net;
        ASSERT_TRUE(net.ok());

        const UdpOffload tx = enable_udp_offload(net.sender);
        if (tx.max_segments == 1) GTEST_SKIP() << "no segmentation offload on this system";
        bool coalesced = false;
        if (coalescing_receiver) {
            coalesced = enable_udp_offload(net.receiver).coalesced_receive;
            if (!coalesced) GTEST_SKIP() << "no coalesced receive on this system";
        }

        constexpr size_t kCount = 41;   // 40 of 1000 bytes, then a short one
        UdpSendBatch out(tx.max_segments);
        for (size_t i = 0; i < kCount; ++i) {
            const auto d = numbered(i, i + 1 < kCount ? 1000 : 123);
            ASSERT_TRUE(out.add(net.dest, d.data(), d.size()));
        }
        ASSERT_EQ(out.runs().size(), 1u) << "the datagrams should have formed one run";
        ASSERT_EQ(out.flush(net.sender, AddressFamily::IPv4), kCount);
        EXPECT_GT(out.max_segments(), 1u) << "the kernel refused a segmented send";

        UdpRecvBatch in(1500, coalesced);
        size_t       runs = 0;
        const auto   got  = receive_datagrams(net.receiver, in, kCount, &runs);
        ASSERT_EQ(got.size(), kCount);
        for (size_t i = 0; i < kCount; ++i)
            ASSERT_EQ(got[i], numbered(i, i + 1 < kCount ? 1000 : 123)) << "datagram " << i;
        if (coalesced) EXPECT_GE(runs, 1u) << "nothing arrived coalesced; the split went untested";
        else           EXPECT_EQ(runs, 0u);
    }
}

#ifdef __linux__
// A device that cannot segment refuses the send outright (EIO; EINVAL for a
// socket that skips checksums, which is how this test provokes it). Losing the
// run would be dozens of packets gone at once, so the batch must notice, turn
// segmentation off for good and send the same datagrams one apiece.
TEST_F(SocketTest, UdpSegmentedSendThatTheKernelRefusesGoesOutUnsegmented) {
    UdpPair net;
    ASSERT_TRUE(net.ok());
    const UdpOffload tx = enable_udp_offload(net.sender);
    if (tx.max_segments == 1) GTEST_SKIP() << "no segmentation offload on this system";

    const int on = 1;   // SO_NO_CHECK: the kernel will not segment without a checksum
    ASSERT_EQ(setsockopt(net.sender, SOL_SOCKET, SO_NO_CHECK, &on, sizeof(on)), 0);

    constexpr size_t kCount = 30;
    UdpSendBatch out(tx.max_segments);
    for (size_t i = 0; i < kCount; ++i) {
        const auto d = numbered(i, 900);
        ASSERT_TRUE(out.add(net.dest, d.data(), d.size()));
    }
    EXPECT_EQ(out.flush(net.sender, AddressFamily::IPv4), kCount);
    EXPECT_EQ(out.max_segments(), 1u) << "segmentation should be off after a refusal";

    UdpRecvBatch in(1500, false);
    const auto   got = receive_datagrams(net.receiver, in, kCount);
    ASSERT_EQ(got.size(), kCount);
    for (size_t i = 0; i < kCount; ++i) EXPECT_EQ(got[i], numbered(i, 900));
}
#endif
