#include <gtest/gtest.h>

#include "bittorrent/reactor.h"
#include "core/socket.h"

#include <atomic>
#include <chrono>
#include <thread>

using namespace librats;
using namespace librats::bittorrent;

namespace {

// A connected loopback TCP pair, both ends non-blocking.
bool make_socket_pair(socket_t& a, socket_t& b) {
    socket_t listener = create_tcp_server(0, 1, "127.0.0.1", AddressFamily::IPv4);
    if (!is_valid_socket(listener)) return false;
    const int port = get_bound_port(listener);
    a = tcp_connect_start("127.0.0.1", port);
    if (!is_valid_socket(a)) { close_socket(listener); return false; }
    b = accept_client(listener);
    close_socket(listener);
    if (!is_valid_socket(b)) { close_socket(a); return false; }
    set_socket_nonblocking(a);
    set_socket_nonblocking(b);
    return true;
}

} // namespace

TEST(BtReactor, PostRunsTaskOnLoop) {
    Reactor r;
    bool ran = false;
    r.post([&] { ran = true; });
    r.run_one(50);
    EXPECT_TRUE(ran);
}

TEST(BtReactor, TimerFires) {
    Reactor r;
    bool fired = false;
    r.schedule(std::chrono::milliseconds(5), [&] { fired = true; });
    for (int i = 0; i < 100 && !fired; ++i) r.run_one(5);
    EXPECT_TRUE(fired);
}

TEST(BtReactor, SocketReadableCallback) {
    socket_t a, b;
    ASSERT_TRUE(make_socket_pair(a, b));

    Reactor r;
    bool readable = false;
    r.add(a, PollIn, [&](std::uint32_t) {
        readable = true;
        char buf[16];
        ::recv(a, buf, sizeof(buf), 0);
    });

    const std::uint8_t byte = 42;
    ::send(b, reinterpret_cast<const char*>(&byte), 1, 0);

    for (int i = 0; i < 100 && !readable; ++i) r.run_one(10);
    EXPECT_TRUE(readable);

    r.remove(a);
    close_socket(a);
    close_socket(b);
}

TEST(BtReactor, BackgroundThreadRunsPostedTask) {
    Reactor r;
    r.start();

    std::atomic<bool> ran{false};
    r.post([&] { ran = true; });

    for (int i = 0; i < 200 && !ran.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(2));

    r.stop();
    EXPECT_TRUE(ran.load());
}
