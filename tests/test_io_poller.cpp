#include <gtest/gtest.h>
#include "io_poller.h"
#include "socket.h"
#include "logger.h"

#include <thread>
#include <chrono>
#include <vector>
#include <atomic>
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
        Logger::getInstance().set_log_level(LogLevel::DEBUG);
        ASSERT_TRUE(init_socket_library());
        poller_ = IOPoller::create();
        ASSERT_NE(poller_, nullptr);
    }
    
    void TearDown() override {
        poller_.reset();
        cleanup_socket_library();
        Logger::getInstance().set_log_level(LogLevel::INFO);
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
        
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        
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
        pair.server = INVALID_SOCKET_VALUE;
        pair.client = INVALID_SOCKET_VALUE;
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
    pair.client = INVALID_SOCKET_VALUE;
    
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
    // Create listen socket
    socket_t listen_sock = create_tcp_server(0, 5, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(listen_sock));
    set_socket_nonblocking(listen_sock);
    
    int port = get_bound_port(listen_sock);
    ASSERT_GT(port, 0);
    
    EXPECT_TRUE(poller_->add(listen_sock, PollIn));
    
    // No connections yet → timeout
    PollResult results[8];
    int n = poller_->wait(results, 8, 0);
    EXPECT_EQ(n, 0);
    
    // Connect from a client
    socket_t client = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_TRUE(is_valid_socket(client));
    
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    
    // Listen socket should become readable (pending accept)
    bool found = false;
    for (int attempt = 0; attempt < 5 && !found; ++attempt) {
        n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == listen_sock && (results[i].events & PollIn)) {
                found = true;
            }
        }
    }
    EXPECT_TRUE(found) << "Listen socket should be readable when connection is pending";
    
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
    // Create listen socket
    socket_t listen_sock = create_tcp_server(0, 5, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(listen_sock));
    
    int port = get_bound_port(listen_sock);
    ASSERT_GT(port, 0);
    
    // Create non-blocking client
    socket_t client = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_TRUE(is_valid_socket(client));
    set_socket_nonblocking(client);
    
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    
    int ret = connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    // On loopback, connect may succeed immediately or return EINPROGRESS/WSAEWOULDBLOCK
    
    // Monitor for PollOut (connect completion)
    EXPECT_TRUE(poller_->add(client, PollOut));
    
    PollResult results[8];
    bool connected = false;
    
    for (int attempt = 0; attempt < 10 && !connected; ++attempt) {
        int n = poller_->wait(results, 8, 200);
        for (int i = 0; i < n; ++i) {
            if (results[i].fd == client && (results[i].events & PollOut)) {
                connected = true;
            }
        }
    }
    EXPECT_TRUE(connected) << "Should detect connect completion via PollOut";
    
    // Verify connection is actually established
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
    pair.client = INVALID_SOCKET_VALUE;
    
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

//=============================================================================
// Double add: adding the same fd twice
//=============================================================================

TEST_F(IOPollerTest, DoubleAddSameFd) {
    // Adding the same fd a second time should either fail or succeed
    // (platform-dependent), but must not crash. Events should still work.
    
    auto pair = create_connected_pair();
    
    EXPECT_TRUE(poller_->add(pair.server, PollIn));
    
    // Second add of same fd — may return true or false depending on backend
    // (epoll returns EEXIST → false, IOCP may succeed)
    // The key contract: should NOT crash, and events should still work.
    poller_->add(pair.server, PollIn);
    
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
    pair.server = INVALID_SOCKET_VALUE;
    
    // Subsequent wait() should not crash — only client is registered
    PollResult results[8];
    int n = poller_->wait(results, 8, 50);
    EXPECT_GE(n, 0) << "wait() should not return error after remove+close";
    
    // Client should still work
    // (pair.server is closed, so client may get PollIn with 0-byte read or PollHup)
    bool client_event = false;
    for (int attempt = 0; attempt < 5 && !client_event; ++attempt) {
        n = poller_->wait(results, 8, 200);
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
