#include <gtest/gtest.h>
#include "librats/core/io_poller.h"
#include "librats/core/socket.h"

#include <thread>
#include <chrono>
#include <vector>
#include <atomic>
#include <memory>
#include <set>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

using namespace librats;

//=============================================================================
// Test fixture
//=============================================================================

class IOPollerTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(init_socket_library());
        poller_ = IOPoller::create();
        ASSERT_NE(poller_, nullptr);
    }
    
    void TearDown() override {
        poller_.reset();
        cleanup_socket_library();
    }
    
    /// Create a TCP socketpair via loopback (returns server-accepted socket + client socket)
    struct SocketPair {
        socket_t server;   ///< Accepted connection (server side)
        socket_t client;   ///< Client side
    };
    
    SocketPair create_connected_pair() {
        // Create listen socket
        socket_t listen_sock = create_tcp_server(0, 5, "127.0.0.1", AddressFamily::IPv4);
        EXPECT_TRUE(is_valid_socket(listen_sock));

        int port = get_bound_port(listen_sock);
        EXPECT_GT(port, 0);

        // Create client and connect
        socket_t client = socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_TRUE(is_valid_socket(client));

        sockaddr_in addr = loopback_addr(port);
        int ret = connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        EXPECT_EQ(ret, 0);

        // Accept
        socket_t server = accept_client(listen_sock);
        EXPECT_TRUE(is_valid_socket(server));

        close_socket(listen_sock);

        // Set both to non-blocking
        set_socket_nonblocking(client);
        set_socket_nonblocking(server);

        return {server, client};
    }

    void close_pair(SocketPair& pair) {
        if (is_valid_socket(pair.server)) close_socket(pair.server);
        if (is_valid_socket(pair.client)) close_socket(pair.client);
        pair.server = RATS_INVALID_SOCKET;
        pair.client = RATS_INVALID_SOCKET;
    }

    /// sockaddr for 127.0.0.1:port
    static sockaddr_in loopback_addr(int port) {
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        return addr;
    }

    /// Start a non-blocking connect to 127.0.0.1:port. The socket comes back with
    /// the attempt already in flight — on loopback it may even be finished.
    static socket_t start_connect(int port) {
        socket_t s = socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_TRUE(is_valid_socket(s));
        set_socket_nonblocking(s);
        sockaddr_in addr = loopback_addr(port);
        connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        return s;
    }

    /// A loopback port with nothing listening on it: bind one to learn a free
    /// number, then hand it straight back.
    static int dead_loopback_port() {
        socket_t s = create_tcp_server(0, 1, "127.0.0.1", AddressFamily::IPv4);
        EXPECT_TRUE(is_valid_socket(s));
        const int port = get_bound_port(s);
        close_socket(s);
        return port;
    }

    /// Non-blocking UDP socket bound to an ephemeral loopback port.
    static socket_t make_udp_socket(int* port_out) {
        socket_t s = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
        EXPECT_TRUE(is_valid_socket(s));
        set_socket_nonblocking(s);
        if (port_out) {
            *port_out = get_bound_port(s);
            EXPECT_GT(*port_out, 0);
        }
        return s;
    }

    /// A bound UDP socket built by hand, deliberately WITHOUT the hardening
    /// create_udp_socket() applies. That helper turns off SIO_UDP_CONNRESET, which
    /// is what suppresses the "an earlier send drew an ICMP Port Unreachable"
    /// report Windows would otherwise deliver to the next receive. Here we want
    /// that report: it is the only portable way to make a datagram socket produce
    /// an error without breaking it, which is the case the poller has to survive.
    static socket_t make_raw_udp_socket(int* port_out) {
        socket_t s = socket(AF_INET, SOCK_DGRAM, 0);
        EXPECT_TRUE(is_valid_socket(s));
        sockaddr_in addr = loopback_addr(0);
        EXPECT_EQ(::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        set_socket_nonblocking(s);
        if (port_out) {
            *port_out = get_bound_port(s);
            EXPECT_GT(*port_out, 0);
        }
        return s;
    }

    /// A datagram whose bytes are checkable and which is comfortably longer than
    /// the one-byte probe the Windows backend uses on a datagram socket.
    static std::vector<uint8_t> make_payload(uint8_t seed, size_t len = 512) {
        std::vector<uint8_t> p(len);
        for (size_t i = 0; i < len; ++i)
            p[i] = static_cast<uint8_t>(i * 31 + seed);
        return p;
    }

    /// Non-blocking listen socket on an ephemeral loopback port.
    static socket_t make_listener(int* port_out) {
        socket_t s = create_tcp_server(0, 5, "127.0.0.1", AddressFamily::IPv4);
        EXPECT_TRUE(is_valid_socket(s));
        set_socket_nonblocking(s);
        *port_out = get_bound_port(s);
        EXPECT_GT(*port_out, 0);
        return s;
    }

    using clock_t_ = std::chrono::steady_clock;

    static long long ms_since(clock_t_::time_point t) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            clock_t_::now() - t).count();
    }

    /// Pump wait() until `fd` reports something, or `budget_ms` of wall clock is
    /// gone. Returns the accumulated events (0 if none arrived) and, in
    /// `latency_ms`, how long it took measured from `since`.
    uint32_t await_events(socket_t fd, int wait_timeout_ms, long long budget_ms,
                          clock_t_::time_point since, long long* latency_ms) {
        PollResult results[8];
        const auto deadline_start = clock_t_::now();
        while (ms_since(deadline_start) < budget_ms) {
            const int n = poller_->wait(results, 8, wait_timeout_ms);
            const long long took = ms_since(since);
            uint32_t events = 0;
            for (int i = 0; i < n; ++i)
                if (results[i].fd == fd) events |= results[i].events;
            if (events != 0) {
                if (latency_ms) *latency_ms = took;
                return events;
            }
        }
        if (latency_ms) *latency_ms = ms_since(since);
        return 0;
    }

    std::unique_ptr<IOPoller> poller_;
};

//=============================================================================
// Factory & Basic Tests
//=============================================================================

TEST_F(IOPollerTest, CreateReturnsValidPoller) {
    EXPECT_NE(poller_, nullptr);
    
    const char* name = poller_->name();
    EXPECT_NE(name, nullptr);
    EXPECT_GT(strlen(name), 0u);
    
    // Should be one of the known backends
    std::string backend(name);
    EXPECT_TRUE(backend == "epoll" || backend == "kqueue" || 
                backend == "IOCP" || backend == "poll" || backend == "WSAPoll")
        << "Unknown backend: " << backend;
}

TEST_F(IOPollerTest, TimeoutWithNoSockets) {
    PollResult results[8];
    
    auto start = std::chrono::steady_clock::now();
    int n = poller_->wait(results, 8, 50);  // 50ms timeout
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    
    EXPECT_EQ(n, 0);
    // Should have waited at least ~30ms (some slack for scheduling)
    EXPECT_GE(elapsed, 20);
}

TEST_F(IOPollerTest, NonBlockingWaitReturnsImmediately) {
    PollResult results[8];
    
    auto start = std::chrono::steady_clock::now();
    int n = poller_->wait(results, 8, 0);  // Non-blocking
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    
    EXPECT_EQ(n, 0);
    EXPECT_LE(elapsed, 50);  // Should return almost immediately
}

//=============================================================================
// Add / Remove / Modify
//=============================================================================

TEST_F(IOPollerTest, AddAndRemoveSocket) {
    auto pair = create_connected_pair();
    
    EXPECT_TRUE(poller_->add(pair.client, PollIn));
    EXPECT_TRUE(poller_->remove(pair.client));
    
    close_pair(pair);
}

TEST_F(IOPollerTest, RemoveUnregisteredReturnsFalse) {
    auto pair = create_connected_pair();
    
    // Should return false — not registered
    EXPECT_FALSE(poller_->remove(pair.client));
    
    close_pair(pair);
}

TEST_F(IOPollerTest, ModifyRegisteredSocket) {
    auto pair = create_connected_pair();
    
    EXPECT_TRUE(poller_->add(pair.client, PollIn));
    EXPECT_TRUE(poller_->modify(pair.client, PollIn | PollOut));
    EXPECT_TRUE(poller_->remove(pair.client));
    
    close_pair(pair);
}

TEST_F(IOPollerTest, ModifyUnregisteredReturnsFalse) {
    auto pair = create_connected_pair();
    
    EXPECT_FALSE(poller_->modify(pair.client, PollIn));
    
    close_pair(pair);
}

//=============================================================================
// Read Readiness
//=============================================================================

TEST_F(IOPollerTest, DetectsReadableAfterSend) {
    auto pair = create_connected_pair();
    
    // Monitor server side for readable
    EXPECT_TRUE(poller_->add(pair.server, PollIn));
    
    // Nothing readable yet → timeout
    PollResult results[8];
    int n = poller_->wait(results, 8, 0);
    EXPECT_EQ(n, 0);
    
    // Send data from client → server becomes readable
    const char msg[] = "hello";
    send(pair.client, msg, sizeof(msg), 0);
    
    // Wait for readability
    n = poller_->wait(results, 8, 500);
    EXPECT_GE(n, 1);
    
    bool found = false;
    for (int i = 0; i < n; ++i) {
        if (results[i].fd == pair.server && (results[i].events & PollIn)) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found) << "Server socket should be readable after client sent data";
    
    // Read the data
    char buf[64];
    int received = recv(pair.server, buf, sizeof(buf), 0);
    EXPECT_EQ(received, static_cast<int>(sizeof(msg)));
    
    poller_->remove(pair.server);
    close_pair(pair);
}

TEST_F(IOPollerTest, DetectsReadableMultipleSockets) {
    auto pair1 = create_connected_pair();
    auto pair2 = create_connected_pair();
    
    EXPECT_TRUE(poller_->add(pair1.server, PollIn));
    EXPECT_TRUE(poller_->add(pair2.server, PollIn));
    
    // Send data to both
    const char msg[] = "data";
    send(pair1.client, msg, sizeof(msg), 0);
    send(pair2.client, msg, sizeof(msg), 0);
    
    // Both should become readable
    PollResult results[8];
    
    // May need multiple waits if events come separately
    int total = 0;
    bool found1 = false, found2 = false;
    
    for (int attempt = 0; attempt < 5 && !(found1 && found2); ++attempt) {
        int n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair1.server && (results[i].events & PollIn)) found1 = true;
            if (results[i].fd == pair2.server && (results[i].events & PollIn)) found2 = true;
        }
        total += n;
    }
    
    EXPECT_TRUE(found1) << "pair1.server should be readable";
    EXPECT_TRUE(found2) << "pair2.server should be readable";
    
    poller_->remove(pair1.server);
    poller_->remove(pair2.server);
    
    // Drain data
    char buf[64];
    recv(pair1.server, buf, sizeof(buf), 0);
    recv(pair2.server, buf, sizeof(buf), 0);
    
    close_pair(pair1);
    close_pair(pair2);
}

//=============================================================================
// Write Readiness
//=============================================================================

TEST_F(IOPollerTest, DetectsWritable) {
    auto pair = create_connected_pair();
    
    // Connected socket should be writable immediately
    EXPECT_TRUE(poller_->add(pair.client, PollOut));
    
    PollResult results[8];
    int n = poller_->wait(results, 8, 500);
    EXPECT_GE(n, 1);
    
    bool found = false;
    for (int i = 0; i < n; ++i) {
        if (results[i].fd == pair.client && (results[i].events & PollOut)) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found) << "Connected socket should be writable";
    
    poller_->remove(pair.client);
    close_pair(pair);
}

TEST_F(IOPollerTest, ReadAndWriteSimultaneous) {
    auto pair = create_connected_pair();
    
    // Monitor server for read + write
    EXPECT_TRUE(poller_->add(pair.server, PollIn | PollOut));
    
    // Send data from client so server is readable AND writable
    const char msg[] = "test";
    send(pair.client, msg, sizeof(msg), 0);
    
    PollResult results[8];
    uint32_t combined = 0;
    
    for (int attempt = 0; attempt < 5; ++attempt) {
        int n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.server) {
                combined |= results[i].events;
            }
        }
        if ((combined & PollIn) && (combined & PollOut)) break;
    }
    
    EXPECT_TRUE(combined & PollIn) << "Should be readable";
    EXPECT_TRUE(combined & PollOut) << "Should be writable";
    
    poller_->remove(pair.server);
    
    char buf[64];
    recv(pair.server, buf, sizeof(buf), 0);
    
    close_pair(pair);
}

//=============================================================================
// Modify behavior
//=============================================================================

TEST_F(IOPollerTest, ModifyAddsWriteInterest) {
    auto pair = create_connected_pair();
    
    // Start with only PollIn
    EXPECT_TRUE(poller_->add(pair.client, PollIn));
    
    // No data → not readable, and we're not watching for write
    PollResult results[8];
    int n = poller_->wait(results, 8, 0);
    EXPECT_EQ(n, 0);
    
    // Modify to add write interest
    EXPECT_TRUE(poller_->modify(pair.client, PollIn | PollOut));
    
    // Now should be writable
    n = poller_->wait(results, 8, 500);
    EXPECT_GE(n, 1);
    
    bool writable = false;
    for (int i = 0; i < n; ++i) {
        if (results[i].fd == pair.client && (results[i].events & PollOut)) {
            writable = true;
        }
    }
    EXPECT_TRUE(writable) << "Should be writable after modify";
    
    poller_->remove(pair.client);
    close_pair(pair);
}

TEST_F(IOPollerTest, ModifyRemovesWriteInterest) {
    auto pair = create_connected_pair();
    
    // Start with PollIn | PollOut
    EXPECT_TRUE(poller_->add(pair.client, PollIn | PollOut));
    
    // Should be writable
    PollResult results[8];
    int n = poller_->wait(results, 8, 500);
    EXPECT_GE(n, 1);
    
    // Modify to only PollIn (remove write interest)
    EXPECT_TRUE(poller_->modify(pair.client, PollIn));
    
    // Should no longer report writable (no data to read either)
    n = poller_->wait(results, 8, 50);
    
    bool writable = false;
    for (int i = 0; i < n; ++i) {
        if (results[i].fd == pair.client && (results[i].events & PollOut)) {
            writable = true;
        }
    }
    EXPECT_FALSE(writable) << "Should NOT be writable after removing write interest";
    
    poller_->remove(pair.client);
    close_pair(pair);
}

//=============================================================================
// Disconnect / HUP detection
//=============================================================================

TEST_F(IOPollerTest, DetectsPeerClose) {
    auto pair = create_connected_pair();
    
    EXPECT_TRUE(poller_->add(pair.server, PollIn));
    
    // Close client side → server should get PollIn (0-byte read) or PollHup
    close_socket(pair.client);
    pair.client = RATS_INVALID_SOCKET;
    
    PollResult results[8];
    uint32_t combined = 0;
    
    for (int attempt = 0; attempt < 5; ++attempt) {
        int n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.server) {
                combined |= results[i].events;
            }
        }
        if (combined) break;
    }
    
    // Should detect the close — either PollIn (read returns 0) or PollHup
    EXPECT_TRUE((combined & PollIn) || (combined & PollHup))
        << "Should detect peer close (got events: " << combined << ")";
    
    poller_->remove(pair.server);
    close_pair(pair);
}

//=============================================================================
// Listen socket: accept readiness
//=============================================================================

TEST_F(IOPollerTest, DetectsIncomingConnection) {
    int port = 0;
    socket_t listen_sock = make_listener(&port);
    ASSERT_TRUE(is_valid_socket(listen_sock));

    EXPECT_TRUE(poller_->add(listen_sock, PollIn));

    // No connections yet → timeout
    PollResult results[8];
    EXPECT_EQ(poller_->wait(results, 8, 0), 0);

    // Connect from a client
    socket_t client = start_connect(port);
    ASSERT_TRUE(is_valid_socket(client));

    // Listen socket should become readable (pending accept)
    long long latency = 0;
    const uint32_t events = await_events(listen_sock, 200, 1000,
                                         clock_t_::now(), &latency);
    EXPECT_TRUE(events & PollIn)
        << "Listen socket should be readable when connection is pending";

    // Accept the connection
    socket_t accepted = accept_client(listen_sock);
    EXPECT_TRUE(is_valid_socket(accepted));

    poller_->remove(listen_sock);
    close_socket(accepted);
    close_socket(client);
    close_socket(listen_sock);
}

//=============================================================================
// Connect readiness (non-blocking connect)
//=============================================================================

TEST_F(IOPollerTest, DetectsConnectCompletion) {
    int port = 0;
    socket_t listen_sock = make_listener(&port);
    ASSERT_TRUE(is_valid_socket(listen_sock));

    // On loopback, connect may succeed immediately or return EINPROGRESS/WSAEWOULDBLOCK
    socket_t client = start_connect(port);
    ASSERT_TRUE(is_valid_socket(client));

    // Monitor for PollOut (connect completion)
    EXPECT_TRUE(poller_->add(client, PollOut));

    long long latency = 0;
    const uint32_t events = await_events(client, 200, 2000, clock_t_::now(), &latency);
    EXPECT_TRUE(events & PollOut) << "Should detect connect completion via PollOut";
    EXPECT_FALSE(events & PollErr) << "A connect to a live listener must not fail";

    // Verify the connection is actually established. Read SO_ERROR exactly once:
    // it is read-and-clear, and a backend that probes it has already taken it.
    int sock_error = 0;
    socklen_t len = sizeof(sock_error);
    getsockopt(client, SOL_SOCKET, SO_ERROR,
              reinterpret_cast<char*>(&sock_error), &len);
    EXPECT_EQ(sock_error, 0) << "Socket should have no error after connect";

    poller_->remove(client);

    socket_t accepted = accept_client(listen_sock);
    if (is_valid_socket(accepted)) close_socket(accepted);
    close_socket(client);
    close_socket(listen_sock);
}

//=============================================================================
// Datagram sockets
//
// A completion-port backend cannot get readiness on a datagram socket the way it
// does on a stream one: the zero-byte WSARecv it would post completes with
// WSAEMSGSIZE and Windows DISCARDS the datagram that satisfied it, losing one
// datagram per notification. The backend therefore probes with a one-byte
// MSG_PEEK, which reports the same readiness while leaving the queue untouched.
//
// Both properties below are invisible to a test that only asks "did PollIn
// arrive?" — a probe that ATE the datagram raises PollIn just as convincingly.
// It is the payload that separates the two.
//=============================================================================

TEST_F(IOPollerTest, DatagramReadinessLeavesDatagramIntact) {
    int      port = 0;
    socket_t rx   = make_udp_socket(&port);
    socket_t tx   = make_udp_socket(nullptr);
    ASSERT_TRUE(is_valid_socket(rx));
    ASSERT_TRUE(is_valid_socket(tx));
    ASSERT_TRUE(poller_->add(rx, PollIn));

    PollResult results[8];
    ASSERT_EQ(poller_->wait(results, 8, 0), 0) << "nothing has been sent yet";

    const std::vector<uint8_t> payload = make_payload(0xA5);
    ASSERT_EQ(send_udp_data(tx, payload, "127.0.0.1", port, AddressFamily::IPv4),
              static_cast<int>(payload.size()));

    long long latency = 0;
    EXPECT_TRUE(await_events(rx, 200, 1000, clock_t_::now(), &latency) & PollIn)
        << "a queued datagram should make the socket readable";

    std::vector<uint8_t> buf(2048);
    Address              from;
    const std::ptrdiff_t got = recv_udp_from(rx, buf.data(), buf.size(), from);
    ASSERT_EQ(got, static_cast<std::ptrdiff_t>(payload.size()))
        << "the readiness probe consumed or truncated the datagram";
    buf.resize(static_cast<size_t>(got));
    EXPECT_EQ(buf, payload) << "datagram came back altered";

    poller_->remove(rx);
    close_socket(rx);
    close_socket(tx);
}

TEST_F(IOPollerTest, DatagramReadinessRepeatsAcrossDatagrams) {
    // The probe has to be re-armed after every completion. One round would also
    // pass on a backend that arms it once and then goes deaf.
    int      port = 0;
    socket_t rx   = make_udp_socket(&port);
    socket_t tx   = make_udp_socket(nullptr);
    ASSERT_TRUE(is_valid_socket(rx));
    ASSERT_TRUE(is_valid_socket(tx));
    ASSERT_TRUE(poller_->add(rx, PollIn));

    for (int round = 0; round < 5; ++round) {
        const std::vector<uint8_t> payload =
            make_payload(static_cast<uint8_t>(round), 200u + round * 100u);
        ASSERT_EQ(send_udp_data(tx, payload, "127.0.0.1", port, AddressFamily::IPv4),
                  static_cast<int>(payload.size()))
            << "round " << round;

        long long latency = 0;
        ASSERT_TRUE(await_events(rx, 200, 1000, clock_t_::now(), &latency) & PollIn)
            << "round " << round << ": readiness stopped being reported";

        // Drain fully, so the next round's PollIn can only come from the next
        // datagram rather than from what is still sitting in the queue.
        std::vector<uint8_t> buf(2048);
        Address              from;
        const std::ptrdiff_t got = recv_udp_from(rx, buf.data(), buf.size(), from);
        ASSERT_EQ(got, static_cast<std::ptrdiff_t>(payload.size())) << "round " << round;
        buf.resize(static_cast<size_t>(got));
        EXPECT_EQ(buf, payload) << "round " << round << ": datagram came back altered";
        while (recv_udp_from(rx, buf.data(), buf.size(), from) >= 0) {}
    }

    poller_->remove(rx);
    close_socket(rx);
    close_socket(tx);
}

TEST_F(IOPollerTest, DatagramSurvivesErrorAndKeepsReporting) {
    // An error on a datagram socket belongs to ONE datagram, not to the socket.
    // Here it is provoked by sending to a port nobody is bound to: the ICMP Port
    // Unreachable that comes back is handed to the next receive on the *sending*
    // socket as an error rather than as data. The socket itself stays perfectly
    // usable, so everything sent to it afterwards must still be reported.
    //
    // This is the one case a completion-port backend gets wrong by omission: it
    // arms readiness with an overlapped receive, and if an error completion is
    // treated as terminal — no fresh receive posted — nothing ever arms it again,
    // because the reactor only calls modify() when the watched events change and
    // for this socket they never do. The socket is then deaf for good, silently,
    // which is how an entire UDP transport disappears without a single log line.
    int      port      = 0;
    socket_t rx        = make_raw_udp_socket(&port);
    socket_t peer      = make_raw_udp_socket(nullptr);
    ASSERT_TRUE(is_valid_socket(rx));
    ASSERT_TRUE(is_valid_socket(peer));
    ASSERT_TRUE(poller_->add(rx, PollIn));

    const int dead_port = dead_loopback_port();
    ASSERT_GT(dead_port, 0);
    const std::vector<uint8_t> probe = make_payload(0x11, 64);
    for (int i = 0; i < 3; ++i)
        send_udp_data(rx, probe, "127.0.0.1", dead_port, AddressFamily::IPv4);

    // Let the ICMP reports land and turn into a pending error on rx, and give the
    // poller a chance to observe it — this is the moment the socket goes deaf.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    PollResult results[8];
    poller_->wait(results, 8, 50);   // may report PollErr, may report nothing

    const std::vector<uint8_t> payload = make_payload(0x5A);
    ASSERT_EQ(send_udp_data(peer, payload, "127.0.0.1", port, AddressFamily::IPv4),
              static_cast<int>(payload.size()));

    // Pump until the datagram is delivered. Which flag carries the readiness is the
    // backend's business — the queued errors are handed out one per receive and may
    // well be reported before the data — but the datagram has to arrive, and it has
    // to arrive because the poller pointed at the socket, not because we read blind.
    std::vector<uint8_t> received;
    PollResult           pump[8];
    const auto           start = clock_t_::now();
    while (received.empty() && ms_since(start) < 3000) {
        const int n = poller_->wait(pump, 8, 200);
        bool      reported = false;
        for (int i = 0; i < n; ++i)
            if (pump[i].fd == rx) reported = true;
        if (!reported) continue;

        std::vector<uint8_t> buf(2048);
        Address              from;
        const std::ptrdiff_t got = recv_udp_from(rx, buf.data(), buf.size(), from);
        if (got < 0) continue;                  // a queued error, not the data
        buf.resize(static_cast<size_t>(got));
        received = buf;
    }

    ASSERT_FALSE(received.empty())
        << "the socket stopped reporting readiness after a per-datagram error";
    EXPECT_EQ(received, payload);

    poller_->remove(rx);
    close_socket(rx);
    close_socket(peer);
}

//=============================================================================
// Out-of-band readiness: sockets a completion-port backend cannot watch
//
// A listen socket, and a socket whose connect is still in flight, carry no
// overlapped I/O — so on Windows IOCP has nothing to say about them and the
// poller must watch them by other means. These tests pin down the part of that
// contract which costs the most when it is wrong: readiness on such a socket
// has to INTERRUPT a wait() that is already blocked. They deliberately pass a
// wait() timeout far longer than the latency they accept. With a short timeout
// a backend that only glances at these sockets on the way *into* wait() still
// looks correct, while every accept and every dial silently pays the timeout.
//=============================================================================

TEST_F(IOPollerTest, ListenSocketWakesBlockedWait) {
    static constexpr int       kWaitTimeoutMs = 2000;
    static constexpr long long kMaxLatencyMs  = 400;

    int port = 0;
    socket_t listen_sock = make_listener(&port);
    ASSERT_TRUE(is_valid_socket(listen_sock));
    ASSERT_TRUE(poller_->add(listen_sock, PollIn));

    PollResult results[8];
    ASSERT_EQ(poller_->wait(results, 8, 0), 0) << "nothing is pending before the first dial";

    // Several rounds: one alone would also pass on a backend that arms its watch
    // once and never re-arms it after reporting.
    for (int round = 0; round < 4; ++round) {
        std::atomic<long long> dialed_at{0};
        socket_t client = RATS_INVALID_SOCKET;

        std::thread dialer([&] {
            // Long enough that the main thread is parked inside wait() by the
            // time the connection lands.
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            dialed_at.store(clock_t_::now().time_since_epoch().count());
            client = start_connect(port);
        });

        uint32_t  events  = 0;
        long long latency = 0;
        const auto start = clock_t_::now();
        while (events == 0 && ms_since(start) < kWaitTimeoutMs) {
            const int n = poller_->wait(results, 8, kWaitTimeoutMs);
            const auto woke = clock_t_::now();
            for (int i = 0; i < n; ++i)
                if (results[i].fd == listen_sock) events |= results[i].events;
            if (events != 0) {
                latency = std::chrono::duration_cast<std::chrono::milliseconds>(
                    woke - clock_t_::time_point(clock_t_::duration(dialed_at.load()))).count();
            }
        }
        dialer.join();

        ASSERT_TRUE(events & PollIn)
            << "round " << round << ": listen socket never became readable";
        EXPECT_LT(latency, kMaxLatencyMs)
            << "round " << round << ": accept took " << latency
            << " ms to surface — wait() sat out its timeout instead of being woken";

        socket_t accepted = accept_client(listen_sock);
        EXPECT_TRUE(is_valid_socket(accepted)) << "round " << round;
        if (is_valid_socket(accepted)) close_socket(accepted);
        if (is_valid_socket(client))   close_socket(client);
    }

    poller_->remove(listen_sock);
    close_socket(listen_sock);
}

TEST_F(IOPollerTest, FailedConnectWakesBlockedWait) {
    // A dial nobody answers. Windows spends a couple of seconds retransmitting
    // the SYN before giving up, even on loopback — which is what makes this a
    // real test: the failure necessarily arrives while wait() is already parked.
    // Left unreported it would hang the connection until the caller's own
    // establish deadline (15 s in Reactor) reaps it.
    static constexpr int       kWaitTimeoutMs = 8000;
    static constexpr long long kBudgetMs      = 5000;

    const int port = dead_loopback_port();
    ASSERT_GT(port, 0);

    const auto start = clock_t_::now();
    socket_t client = start_connect(port);
    ASSERT_TRUE(is_valid_socket(client));
    ASSERT_TRUE(poller_->add(client, PollOut));

    long long latency = 0;
    const uint32_t events = await_events(client, kWaitTimeoutMs, kBudgetMs, start, &latency);

    // Which flag carries it is the backend's business — epoll raises
    // EPOLLERR|EPOLLHUP|EPOLLOUT, kqueue an EV_EOF write event, WSAPoll
    // POLLERR|POLLHUP|POLLWRNORM. The caller resolves the outcome with SO_ERROR
    // either way; what matters here is that *something* is reported, promptly.
    EXPECT_NE(events, 0u)
        << "a refused connect must be reported (waited " << latency << " ms)";
    EXPECT_LT(latency, kBudgetMs)
        << "refused connect surfaced only after " << latency << " ms";

    poller_->remove(client);
    close_socket(client);
}

TEST_F(IOPollerTest, ListenSocketRemovedFromAnotherThreadDuringWait) {
    // Two listen sockets; one is removed and closed from another thread while
    // wait() is parked. A backend keeping a private copy of the watched set is
    // then holding a descriptor that is about to be recycled — it must not act
    // on it, and the survivor must keep reporting.
    int port_a = 0, port_b = 0;
    socket_t a = make_listener(&port_a);
    socket_t b = make_listener(&port_b);
    ASSERT_TRUE(is_valid_socket(a));
    ASSERT_TRUE(is_valid_socket(b));
    ASSERT_TRUE(poller_->add(a, PollIn));
    ASSERT_TRUE(poller_->add(b, PollIn));

    socket_t client = RATS_INVALID_SOCKET;
    std::atomic<bool> removed{false};

    std::thread worker([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        poller_->remove(a);
        close_socket(a);          // a is the worker's to close from here on
        removed = true;
        client = start_connect(port_b);
    });

    long long latency = 0;
    const uint32_t events = await_events(b, 2000, 3000, clock_t_::now(), &latency);
    worker.join();

    EXPECT_TRUE(removed.load());
    EXPECT_TRUE(events & PollIn)
        << "the surviving listen socket should still report after its sibling went away";

    socket_t accepted = accept_client(b);
    EXPECT_TRUE(is_valid_socket(accepted));
    if (is_valid_socket(accepted)) close_socket(accepted);
    if (is_valid_socket(client))   close_socket(client);

    poller_->remove(b);
    close_socket(b);
}

TEST_F(IOPollerTest, MultipleListenSocketsAllReport) {
    // More than the one listen socket a node normally has, so a backend that
    // indexes these sockets separately from its main table is exercised with a
    // set rather than with a single special case.
    constexpr int kCount = 4;
    socket_t listeners[kCount];
    socket_t clients[kCount];
    int      ports[kCount] = {0};

    for (int i = 0; i < kCount; ++i) {
        listeners[i] = make_listener(&ports[i]);
        ASSERT_TRUE(is_valid_socket(listeners[i]));
        ASSERT_TRUE(poller_->add(listeners[i], PollIn));
        clients[i] = RATS_INVALID_SOCKET;
    }
    for (int i = 0; i < kCount; ++i) clients[i] = start_connect(ports[i]);

    std::set<socket_t> seen;
    PollResult results[8];
    const auto start = clock_t_::now();
    while (seen.size() < static_cast<size_t>(kCount) && ms_since(start) < 3000) {
        const int n = poller_->wait(results, 8, 500);
        for (int i = 0; i < n; ++i) {
            if (!(results[i].events & PollIn)) continue;
            seen.insert(results[i].fd);
            // Drain the backlog so this listener stops firing.
            socket_t accepted = accept_client(results[i].fd);
            if (is_valid_socket(accepted)) close_socket(accepted);
        }
    }

    EXPECT_EQ(seen.size(), static_cast<size_t>(kCount))
        << "every registered listen socket should report its pending connection";

    for (int i = 0; i < kCount; ++i) {
        poller_->remove(listeners[i]);
        close_socket(listeners[i]);
        if (is_valid_socket(clients[i])) close_socket(clients[i]);
    }
}

//=============================================================================
// Stress / Multiple sockets
//=============================================================================

TEST_F(IOPollerTest, MultipleSockets) {
    const int NUM_PAIRS = 10;
    std::vector<SocketPair> pairs;
    
    // Create many connected pairs
    for (int i = 0; i < NUM_PAIRS; ++i) {
        pairs.push_back(create_connected_pair());
        EXPECT_TRUE(poller_->add(pairs.back().server, PollIn));
    }
    
    // Send data to all
    const char msg[] = "ping";
    for (auto& p : pairs) {
        send(p.client, msg, sizeof(msg), 0);
    }
    
    // Wait and collect events
    PollResult results[64];
    std::vector<bool> got_event(NUM_PAIRS, false);
    
    for (int attempt = 0; attempt < 20; ++attempt) {
        int n = poller_->wait(results, 64, 100);
        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < NUM_PAIRS; ++j) {
                if (results[i].fd == pairs[j].server && (results[i].events & PollIn)) {
                    got_event[j] = true;
                }
            }
        }
        
        bool all = true;
        for (bool b : got_event) if (!b) { all = false; break; }
        if (all) break;
    }
    
    for (int i = 0; i < NUM_PAIRS; ++i) {
        EXPECT_TRUE(got_event[i]) << "Socket pair " << i << " should have been readable";
    }
    
    // Cleanup
    for (auto& p : pairs) {
        poller_->remove(p.server);
        char buf[64];
        recv(p.server, buf, sizeof(buf), 0);
        close_pair(p);
    }
}

TEST_F(IOPollerTest, AddRemoveManyRapidly) {
    const int NUM = 20;
    std::vector<SocketPair> pairs;
    
    for (int i = 0; i < NUM; ++i) {
        pairs.push_back(create_connected_pair());
    }
    
    // Add all
    for (auto& p : pairs) {
        EXPECT_TRUE(poller_->add(p.server, PollIn));
    }
    
    // Remove all
    for (auto& p : pairs) {
        EXPECT_TRUE(poller_->remove(p.server));
    }
    
    // Wait should return 0 (nothing registered)
    PollResult results[8];
    int n = poller_->wait(results, 8, 0);
    EXPECT_EQ(n, 0);
    
    // Add some back
    for (int i = 0; i < NUM / 2; ++i) {
        EXPECT_TRUE(poller_->add(pairs[i].server, PollIn));
    }
    
    // Send data to those
    const char msg[] = "x";
    for (int i = 0; i < NUM / 2; ++i) {
        send(pairs[i].client, msg, sizeof(msg), 0);
    }
    
    // Should detect readability on re-added sockets
    std::vector<bool> got_event(NUM / 2, false);
    for (int attempt = 0; attempt < 10; ++attempt) {
        n = poller_->wait(results, 8, 100);
        for (int j = 0; j < n; ++j) {
            for (int i = 0; i < NUM / 2; ++i) {
                if (results[j].fd == pairs[i].server && (results[j].events & PollIn)) {
                    got_event[i] = true;
                }
            }
        }
        bool all = true;
        for (bool b : got_event) if (!b) { all = false; break; }
        if (all) break;
    }
    
    for (int i = 0; i < NUM / 2; ++i) {
        EXPECT_TRUE(got_event[i]) << "Re-added socket " << i << " should be readable";
    }
    
    // Cleanup
    for (int i = 0; i < NUM / 2; ++i) {
        poller_->remove(pairs[i].server);
    }
    for (auto& p : pairs) {
        char buf[64];
        recv(p.server, buf, sizeof(buf), 0);
        close_pair(p);
    }
}

//=============================================================================
// Cross-thread notification (modify from another thread wakes wait)
//=============================================================================

TEST_F(IOPollerTest, CrossThreadModifyWakesWait) {
    auto pair = create_connected_pair();
    
    // Start with PollIn only (no data → wait will block)
    EXPECT_TRUE(poller_->add(pair.server, PollIn));
    
    std::atomic<bool> got_event{false};
    
    // Spawn thread that will modify after a delay to add PollOut
    std::thread modifier([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // Add write interest — connected socket is always writable
        poller_->modify(pair.server, PollIn | PollOut);
    });
    
    // Wait with long timeout — should be woken by modify
    PollResult results[8];
    auto start = std::chrono::steady_clock::now();
    
    for (int attempt = 0; attempt < 5 && !got_event; ++attempt) {
        int n = poller_->wait(results, 8, 1000);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.server && (results[i].events & PollOut)) {
                got_event = true;
            }
        }
    }
    
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    
    modifier.join();
    
    EXPECT_TRUE(got_event.load()) << "Cross-thread modify should wake up wait";
    // Should have woken reasonably fast (not the full 1s timeout)
    EXPECT_LT(elapsed, 800) << "Should not have waited for full timeout";
    
    poller_->remove(pair.server);
    close_pair(pair);
}

//=============================================================================
// Data transfer through polled sockets
//=============================================================================

//=============================================================================
// PollErr detection (connection refused)
//=============================================================================

TEST_F(IOPollerTest, DetectsConnectionRefusedAsError) {
    // A connected socket whose peer does a hard RST should produce
    // PollErr or PollHup (or PollIn with 0-byte read), depending on platform.
    
    auto pair = create_connected_pair();
    
    EXPECT_TRUE(poller_->add(pair.server, PollIn));
    
    // Force RST by setting SO_LINGER with timeout 0, then closing client
    struct linger lg = {1, 0};  // linger on, timeout 0 → RST on close
    setsockopt(pair.client, SOL_SOCKET, SO_LINGER,
               reinterpret_cast<const char*>(&lg), sizeof(lg));
    close_socket(pair.client, true);  // Sends RST instead of FIN
    pair.client = RATS_INVALID_SOCKET;
    
    PollResult results[8];
    uint32_t combined = 0;
    
    for (int attempt = 0; attempt < 10; ++attempt) {
        int n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.server) {
                combined |= results[i].events;
            }
        }
        if (combined & (PollErr | PollHup | PollIn)) break;
    }
    
    // Should detect the RST — either PollErr, PollHup, or PollIn (read returns error/0)
    EXPECT_NE(combined, 0u)
        << "Should detect connection reset (got events: " << combined << ")";
    EXPECT_TRUE((combined & PollErr) || (combined & PollHup) || (combined & PollIn))
        << "Should report error, hangup, or readable (for error read)";
    
    poller_->remove(pair.server);
    close_pair(pair);
}

//=============================================================================
// Concurrent add/remove from another thread during wait()
//=============================================================================

TEST_F(IOPollerTest, ConcurrentAddDuringWait) {
    // Spawn a thread that adds a writable socket while main thread is waiting.
    // The new socket's events should be picked up.
    
    auto pair = create_connected_pair();
    
    std::atomic<bool> got_event{false};
    
    std::thread adder([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // Add a connected socket — it should be immediately writable
        poller_->add(pair.client, PollOut);
    });
    
    PollResult results[8];
    
    for (int attempt = 0; attempt < 10 && !got_event; ++attempt) {
        int n = poller_->wait(results, 8, 300);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.client && (results[i].events & PollOut)) {
                got_event = true;
            }
        }
    }
    
    adder.join();
    
    EXPECT_TRUE(got_event.load()) << "Socket added from another thread should produce events";
    
    poller_->remove(pair.client);
    close_pair(pair);
}

TEST_F(IOPollerTest, ConcurrentRemoveDuringWait) {
    // Add sockets, then remove one from another thread while wait() is blocking.
    // Should not crash or hang.
    
    auto pair1 = create_connected_pair();
    auto pair2 = create_connected_pair();
    
    EXPECT_TRUE(poller_->add(pair1.server, PollIn));
    EXPECT_TRUE(poller_->add(pair2.server, PollIn));
    
    // Send data to pair2 so it becomes readable
    const char msg[] = "data";
    send(pair2.client, msg, sizeof(msg), 0);
    
    std::atomic<bool> removed{false};
    
    std::thread remover([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        poller_->remove(pair1.server);
        removed = true;
    });
    
    PollResult results[8];
    bool got_pair2 = false;
    
    for (int attempt = 0; attempt < 10 && !got_pair2; ++attempt) {
        int n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair2.server && (results[i].events & PollIn)) {
                got_pair2 = true;
            }
        }
    }
    
    remover.join();
    
    EXPECT_TRUE(removed.load());
    EXPECT_TRUE(got_pair2) << "pair2 should still get events after pair1 removed from another thread";
    
    poller_->remove(pair2.server);
    
    char buf[64];
    recv(pair2.server, buf, sizeof(buf), 0);
    
    close_pair(pair1);
    close_pair(pair2);
}

//=============================================================================
// Edge-triggered re-arming: repeated PollIn after partial read
//=============================================================================

TEST_F(IOPollerTest, RepeatedReadNotificationAfterNewData) {
    // Verify that after reading data and then sending more, the poller
    // fires PollIn again. This is critical for edge-triggered backends
    // (kqueue EV_CLEAR, IOCP re-arm).
    
    auto pair = create_connected_pair();
    
    EXPECT_TRUE(poller_->add(pair.server, PollIn));
    
    // Round 1: send data, detect readable, read it
    const char msg1[] = "first";
    send(pair.client, msg1, sizeof(msg1), 0);
    
    PollResult results[8];
    bool readable = false;
    for (int attempt = 0; attempt < 5 && !readable; ++attempt) {
        int n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.server && (results[i].events & PollIn))
                readable = true;
        }
    }
    ASSERT_TRUE(readable) << "Round 1: should be readable";
    
    // Read all available data
    char buf[256];
    while (recv(pair.server, buf, sizeof(buf), 0) > 0) {}
    
    // Verify poller returns 0 after draining (no data left)
    int n = poller_->wait(results, 8, 50);
    // May or may not return 0 (platform-dependent), that's okay
    
    // Round 2: send new data → poller MUST fire PollIn again
    const char msg2[] = "second";
    send(pair.client, msg2, sizeof(msg2), 0);
    
    readable = false;
    for (int attempt = 0; attempt < 5 && !readable; ++attempt) {
        n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.server && (results[i].events & PollIn))
                readable = true;
        }
    }
    EXPECT_TRUE(readable) << "Round 2: should be readable again after new data (edge re-arm)";
    
    // Drain
    while (recv(pair.server, buf, sizeof(buf), 0) > 0) {}
    
    poller_->remove(pair.server);
    close_pair(pair);
}

TEST_F(IOPollerTest, ReadinessCostsOneReportPerBurst) {
    // One burst of data should cost one readiness report. A completion-port backend
    // that arms its next receive while the data is still unread gets a second,
    // empty one for free: the fresh zero-byte receive completes on the spot, and the
    // caller comes back to a socket with nothing in it. That doubles wakeups and
    // reads across the entire receive path — measured at exactly 2.00 reports per
    // message, half of them finding an empty socket.

    auto pair = create_connected_pair();
    ASSERT_TRUE(poller_->add(pair.server, PollIn));

    constexpr int kMessages = 200;
    int           reports   = 0;

    for (int i = 0; i < kMessages; ++i) {
        char msg[64];
        std::memset(msg, 'x', sizeof(msg));
        ASSERT_GT(send(pair.client, msg, sizeof(msg), 0), 0);

        // Exactly how the reactor drives it: one blocking wait, read the socket dry,
        // then keep asking until wait() has nothing left to say. Only the first wait
        // of a round may block — the follow-ups ask "anything else?" and must not
        // sit out a timeout to answer no.
        for (bool first = true;; first = false) {
            PollResult results[8];
            const int  n = poller_->wait(results, 8, first ? 500 : 0);
            if (n <= 0) break;
            for (int r = 0; r < n; ++r) {
                if (results[r].fd != pair.server) continue;
                if (!(results[r].events & PollIn)) continue;
                ++reports;
                char buf[256];
                while (recv(pair.server, buf, sizeof(buf), 0) > 0) {}
            }
        }
    }

    EXPECT_GE(reports, kMessages) << "every message has to be reported";
    // The doubling is exactly 2.00 per message, so 1.5 separates "fixed" from
    // "regressed" with room to spare for a send the stack legitimately splits.
    EXPECT_LT(reports, kMessages * 3 / 2)
        << reports << " readiness reports for " << kMessages
        << " messages — a burst is costing more than one wakeup";

    poller_->remove(pair.server);
    close_pair(pair);
}

//=============================================================================
// Double add: adding the same fd twice
//=============================================================================

TEST_F(IOPollerTest, DoubleAddSameFd) {
    // Adding the same fd a second time is rejected on every backend, and leaves the
    // first registration working untouched.

    auto pair = create_connected_pair();

    EXPECT_TRUE(poller_->add(pair.server, PollIn));

    // epoll answers EEXIST; the backends that keep their own table answer the same
    // rather than layering a second registration on top of the first.
    EXPECT_FALSE(poller_->add(pair.server, PollIn))
        << "a second add of a registered fd must be rejected; use modify()";

    // Send data and verify events still fire
    const char msg[] = "test";
    send(pair.client, msg, sizeof(msg), 0);
    
    PollResult results[8];
    bool readable = false;
    for (int attempt = 0; attempt < 5 && !readable; ++attempt) {
        int n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.server && (results[i].events & PollIn))
                readable = true;
        }
    }
    EXPECT_TRUE(readable) << "Socket should still be functional after double add";
    
    char buf[64];
    recv(pair.server, buf, sizeof(buf), 0);
    
    poller_->remove(pair.server);
    close_pair(pair);
}

TEST_F(IOPollerTest, RemoveIsFinalAfterDoubleAdd) {
    // One remove has to undo everything a double add left behind. A backend that
    // let the second add create a parallel registration is still holding it here,
    // and will report this fd after the caller was told it is gone — by which time
    // the descriptor number may have been recycled onto an unrelated socket.

    auto pair = create_connected_pair();

    ASSERT_TRUE(poller_->add(pair.server, PollIn));
    poller_->add(pair.server, PollIn);          // rejected; must leave nothing behind

    ASSERT_TRUE(poller_->remove(pair.server));
    EXPECT_FALSE(poller_->remove(pair.server)) << "nothing should be left to remove";

    // Make the socket as loud as it can be: readable, then hung up.
    const char msg[] = "data";
    send(pair.client, msg, sizeof(msg), 0);
    close_socket(pair.client);
    pair.client = RATS_INVALID_SOCKET;

    PollResult results[8];
    const auto start = clock_t_::now();
    while (ms_since(start) < 400) {
        const int n = poller_->wait(results, 8, 50);
        for (int i = 0; i < n; ++i)
            EXPECT_NE(results[i].fd, pair.server)
                << "wait() reported an fd that was removed";
    }

    close_pair(pair);
}

//=============================================================================
// Re-add with different events after remove
//=============================================================================

TEST_F(IOPollerTest, ReAddWithDifferentEvents) {
    // Pattern: add(PollIn) → remove() → add(PollOut)
    // Simulates a socket being removed and re-registered with different interest.
    
    auto pair = create_connected_pair();
    
    // First: register for read only
    EXPECT_TRUE(poller_->add(pair.client, PollIn));
    
    // No data to read → should timeout
    PollResult results[8];
    int n = poller_->wait(results, 8, 0);
    EXPECT_EQ(n, 0);
    
    // Remove
    EXPECT_TRUE(poller_->remove(pair.client));
    
    // Re-add with PollOut
    EXPECT_TRUE(poller_->add(pair.client, PollOut));
    
    // Connected socket should be writable
    bool writable = false;
    for (int attempt = 0; attempt < 5 && !writable; ++attempt) {
        n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.client && (results[i].events & PollOut))
                writable = true;
        }
    }
    EXPECT_TRUE(writable) << "Re-added socket with PollOut should be writable";
    
    poller_->remove(pair.client);
    close_pair(pair);
}

//=============================================================================
// max_results boundary: fewer slots than ready sockets
//=============================================================================

TEST_F(IOPollerTest, MaxResultsTruncation) {
    // Register multiple readable sockets but request max_results=1.
    // Should return at most 1 event per wait() call, and not lose events.
    
    auto pair1 = create_connected_pair();
    auto pair2 = create_connected_pair();
    auto pair3 = create_connected_pair();
    
    EXPECT_TRUE(poller_->add(pair1.server, PollIn));
    EXPECT_TRUE(poller_->add(pair2.server, PollIn));
    EXPECT_TRUE(poller_->add(pair3.server, PollIn));
    
    const char msg[] = "data";
    send(pair1.client, msg, sizeof(msg), 0);
    send(pair2.client, msg, sizeof(msg), 0);
    send(pair3.client, msg, sizeof(msg), 0);
    
    // Give data time to arrive
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    PollResult results[1];  // Only 1 slot!
    
    std::set<socket_t> seen;
    for (int attempt = 0; attempt < 20 && seen.size() < 3; ++attempt) {
        int n = poller_->wait(results, 1, 100);
        EXPECT_LE(n, 1) << "max_results=1 should return at most 1 event";
        for (int i = 0; i < n; ++i) {
            seen.insert(results[i].fd);
            // Drain data so this socket doesn't fire again
            char buf[64];
            recv(results[i].fd, buf, sizeof(buf), 0);
        }
    }
    
    EXPECT_EQ(seen.size(), 3u) << "All 3 sockets should eventually be reported";
    
    poller_->remove(pair1.server);
    poller_->remove(pair2.server);
    poller_->remove(pair3.server);
    
    close_pair(pair1);
    close_pair(pair2);
    close_pair(pair3);
}

//=============================================================================
// Remove + close safety: poller survives closed fd
//=============================================================================

TEST_F(IOPollerTest, RemoveThenCloseSafety) {
    // Production pattern: poller_remove(fd) then close_socket(fd).
    // Verify no crash in subsequent wait() calls.
    
    auto pair = create_connected_pair();
    
    EXPECT_TRUE(poller_->add(pair.server, PollIn));
    EXPECT_TRUE(poller_->add(pair.client, PollIn));
    
    // Remove and close server side
    EXPECT_TRUE(poller_->remove(pair.server));
    close_socket(pair.server);
    pair.server = RATS_INVALID_SOCKET;
    
    // Subsequent wait() should not crash — only client is registered.
    // The client may receive the server-close event on this very first call
    // (edge-triggered backends like kqueue EV_CLEAR fire it only once).
    PollResult results[8];
    bool client_event = false;
    
    for (int attempt = 0; attempt < 5 && !client_event; ++attempt) {
        int n = poller_->wait(results, 8, 200);
        EXPECT_GE(n, 0) << "wait() should not return error after remove+close";
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.client) {
                client_event = true;
            }
        }
    }
    // Client should detect the broken connection
    EXPECT_TRUE(client_event) << "Client should detect server-side close";
    
    poller_->remove(pair.client);
    close_pair(pair);
}

//=============================================================================
// Data transfer through polled sockets
//=============================================================================

TEST_F(IOPollerTest, FullDataTransferRoundtrip) {
    auto pair = create_connected_pair();
    
    // Monitor both sides
    EXPECT_TRUE(poller_->add(pair.client, PollOut));  // Client wants to write
    EXPECT_TRUE(poller_->add(pair.server, PollIn));   // Server wants to read
    
    // Wait for client to be writable
    PollResult results[8];
    int n = poller_->wait(results, 8, 500);
    EXPECT_GE(n, 1);
    
    // Send data
    const char request[] = "GET / HTTP/1.0\r\n\r\n";
    int sent = send(pair.client, request, sizeof(request), 0);
    EXPECT_GT(sent, 0);
    
    // Client done writing — switch to read
    poller_->modify(pair.client, PollIn);
    
    // Wait for server to be readable
    bool server_readable = false;
    for (int attempt = 0; attempt < 5 && !server_readable; ++attempt) {
        n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.server && (results[i].events & PollIn)) {
                server_readable = true;
            }
        }
    }
    EXPECT_TRUE(server_readable);
    
    // Read and echo back
    char buf[256];
    int received = recv(pair.server, buf, sizeof(buf), 0);
    EXPECT_EQ(received, static_cast<int>(sizeof(request)));
    
    // Server sends response
    poller_->modify(pair.server, PollOut);
    
    bool server_writable = false;
    for (int attempt = 0; attempt < 5 && !server_writable; ++attempt) {
        n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.server && (results[i].events & PollOut)) {
                server_writable = true;
            }
        }
    }
    EXPECT_TRUE(server_writable);
    
    const char response[] = "HTTP/1.0 200 OK\r\n\r\n";
    sent = send(pair.server, response, sizeof(response), 0);
    EXPECT_GT(sent, 0);
    
    // Client should receive it
    bool client_readable = false;
    for (int attempt = 0; attempt < 5 && !client_readable; ++attempt) {
        n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == pair.client && (results[i].events & PollIn)) {
                client_readable = true;
            }
        }
    }
    EXPECT_TRUE(client_readable);
    
    received = recv(pair.client, buf, sizeof(buf), 0);
    EXPECT_EQ(received, static_cast<int>(sizeof(response)));
    EXPECT_EQ(std::string(buf, received), std::string(response, sizeof(response)));
    
    poller_->remove(pair.client);
    poller_->remove(pair.server);
    close_pair(pair);
}
