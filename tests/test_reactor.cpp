#include <gtest/gtest.h>

#include "core/reactor.h"
#include "core/connection.h"
#include "net/frame.h"
#include "socket.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace librats;
using namespace std::chrono_literals;

namespace {

// Spin until `pred()` is true or the timeout elapses. Returns the final value.
template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 10s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

/// Server-side delegate: bounce every frame straight back to the sender.
class EchoDelegate : public ConnectionDelegate {
public:
    void on_established(Connection&) override { established_++; }
    void on_frame(Connection& conn, const Frame& frame) override {
        conn.send(frame.header, frame.payload);
    }
    void on_closed(Connection&, CloseReason) override { closed_++; }

    std::atomic<int> established_{0};
    std::atomic<int> closed_{0};
};

/// Client-side delegate: record establishment and echoed payloads.
class CollectDelegate : public ConnectionDelegate {
public:
    void on_established(Connection& conn) override {
        last_conn_id_.store(conn.id());
        established_++;
    }
    void on_frame(Connection&, const Frame& frame) override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            received_.emplace_back(reinterpret_cast<const char*>(frame.payload.data()),
                                   frame.payload.size());
        }
        frames_++;
    }
    void on_closed(Connection&, CloseReason) override { closed_++; }

    std::atomic<int>    established_{0};
    std::atomic<int>    frames_{0};
    std::atomic<int>    closed_{0};
    std::atomic<ConnId> last_conn_id_{kInvalidConnId};

    std::mutex               mutex_;
    std::vector<std::string> received_;
};

// Bind an ephemeral TCP server and return {socket, port}.
std::pair<socket_t, int> make_server() {
    socket_t s = create_tcp_server(0, 1024, "127.0.0.1", AddressFamily::IPv4);
    EXPECT_TRUE(is_valid_socket(s));
    return {s, get_bound_port(s)};
}

class ReactorTest : public ::testing::Test {
protected:
    void SetUp() override { init_socket_library(); }
};

} // namespace

// A single round trip: connect, send one frame, receive its echo verbatim.
TEST_F(ReactorTest, EchoesSingleFrame) {
    auto [server_sock, port] = make_server();

    EchoDelegate echo;
    Reactor server(0, echo);
    server.listen(server_sock);
    server.start();

    CollectDelegate collect;
    Reactor client(1, collect);
    client.start();

    client.connect("127.0.0.1", port);
    ASSERT_TRUE(wait_for([&] { return collect.established_.load() == 1; }))
        << "client never established";

    const ConnId cid = collect.last_conn_id_.load();
    const std::string msg = "hello reactor";
    client.execute([&, cid] {
        if (auto* c = client.find(cid)) c->send(/*channel=*/0, ByteView(msg));
    });

    ASSERT_TRUE(wait_for([&] { return collect.frames_.load() >= 1; }))
        << "client never received echo";

    {
        std::lock_guard<std::mutex> lock(collect.mutex_);
        ASSERT_EQ(collect.received_.size(), 1u);
        EXPECT_EQ(collect.received_[0], msg);
    }

    client.stop();
    server.stop();
}

// Many frames on one connection arrive in order and intact.
TEST_F(ReactorTest, EchoesManyFramesInOrder) {
    auto [server_sock, port] = make_server();

    EchoDelegate echo;
    Reactor server(0, echo);
    server.listen(server_sock);
    server.start();

    CollectDelegate collect;
    Reactor client(1, collect);
    client.start();

    client.connect("127.0.0.1", port);
    ASSERT_TRUE(wait_for([&] { return collect.established_.load() == 1; }));

    const ConnId cid = collect.last_conn_id_.load();
    constexpr int kCount = 500;
    client.execute([&, cid] {
        auto* c = client.find(cid);
        if (!c) return;
        for (int i = 0; i < kCount; ++i) c->send(0, ByteView(std::to_string(i)));
    });

    ASSERT_TRUE(wait_for([&] { return collect.frames_.load() >= kCount; }))
        << "got " << collect.frames_.load() << "/" << kCount;

    std::lock_guard<std::mutex> lock(collect.mutex_);
    ASSERT_EQ(collect.received_.size(), static_cast<size_t>(kCount));
    for (int i = 0; i < kCount; ++i) EXPECT_EQ(collect.received_[i], std::to_string(i));

    client.stop();
    server.stop();
}

// Scale check: 1000 concurrent connections, each gets one echoed frame.
// Proves the single reactor sustains 1000+ peers with no per-peer threads.
TEST_F(ReactorTest, Sustains1000Connections) {
    constexpr int kConns = 1000;

    auto [server_sock, port] = make_server();

    EchoDelegate echo;
    Reactor server(0, echo);
    server.listen(server_sock);
    server.start();

    CollectDelegate collect;
    Reactor client(1, collect);
    client.start();

    // Dial in waves so the number of in-flight (not-yet-accepted) connects stays
    // bounded — real applications ramp rather than firing a thundering herd, and
    // this isolates steady-state capacity from a transient connect storm.
    constexpr int kWave = 100;
    const auto t0 = std::chrono::steady_clock::now();
    for (int sent = 0; sent < kConns; sent += kWave) {
        const int n = std::min(kWave, kConns - sent);
        for (int i = 0; i < n; ++i) client.connect("127.0.0.1", port);
        ASSERT_TRUE(wait_for([&] { return collect.established_.load() >= sent + n; }, 15s))
            << "established " << collect.established_.load() << " after dialing " << (sent + n);
    }
    const auto t_conn = std::chrono::steady_clock::now();

    // Fire one frame on every client connection and wait for all echoes.
    client.execute([&] {
        for (ConnId id = 1; id <= static_cast<ConnId>(kConns); ++id) {
            if (auto* c = client.find(id)) c->send(0, ByteView(std::string("ping")));
        }
    });
    ASSERT_TRUE(wait_for([&] { return collect.frames_.load() == kConns; }, 30s))
        << "echoed " << collect.frames_.load() << "/" << kConns;
    const auto t_echo = std::chrono::steady_clock::now();

    const auto connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_conn - t0).count();
    const auto echo_ms    = std::chrono::duration_cast<std::chrono::milliseconds>(t_echo - t_conn).count();
    std::cout << "[ reactor ] " << kConns << " connections established in " << connect_ms
              << " ms; " << kConns << " round-trips in " << echo_ms << " ms\n";

    EXPECT_EQ(server.connection_count(), static_cast<size_t>(kConns));
    EXPECT_EQ(client.connection_count(), static_cast<size_t>(kConns));

    client.stop();
    server.stop();

    // Every connection should have been reported closed on both sides.
    EXPECT_TRUE(wait_for([&] { return collect.closed_.load() == kConns; }));
}
