#include <gtest/gtest.h>
#include "librats/dht/dht_runner.h"
#include "librats/dht/node.h"
#include "librats/dht/udp_transport.h"
#include "librats/core/socket.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <thread>

using namespace librats::dht;
using librats::AddressFamily;

namespace {

NodeId nid(uint8_t v) { NodeId id; id.fill(v); return id; }

// A started runner over a loopback socket — the minimum needed to exercise the
// loop/stop handshake without any network traffic.
struct RunnerFixture {
    UdpTransport transport{0, "127.0.0.1", AddressFamily::IPv4};
    Node         node{transport, nid(0x42), /*ipv6=*/false};
    DhtRunner    runner{node, transport};

    RunnerFixture() { librats::init_socket_library(); }
};

} // namespace

// A task posted after stop() would never run: nothing is left to drain the queue.
// post() must say so rather than accept it silently — DhtClient's getters wait on a
// promise the task is supposed to fulfil, and an accepted-but-never-run task hangs
// the calling thread for good (a UI stats poll racing shutdown, say).
TEST(DhtRunnerShutdown, PostAfterStopIsRefused) {
    RunnerFixture f;
    ASSERT_TRUE(f.transport.is_open());
    f.runner.start();
    EXPECT_TRUE(f.runner.post([] {}));

    f.runner.stop();

    std::atomic<bool> ran{false};
    EXPECT_FALSE(f.runner.post([&] { ran.store(true); }));
    EXPECT_FALSE(ran.load());
}

// A task accepted just before stop() flips the flag can miss the loop's last drain.
// stop() must run those leftovers itself once the thread is joined, so a caller
// blocked on the task's result is released instead of waiting forever.
TEST(DhtRunnerShutdown, StopRunsTasksTheLoopNeverGotTo) {
    RunnerFixture f;
    ASSERT_TRUE(f.transport.is_open());
    f.runner.start();

    // Park the loop inside a task, so anything posted from here lands in the *next*
    // batch — the one the loop will never reach once stop() clears the flag.
    std::mutex m;
    std::condition_variable cv;
    bool entered = false, release = false;
    ASSERT_TRUE(f.runner.post([&] {
        std::unique_lock<std::mutex> lock(m);
        entered = true;
        cv.notify_all();
        cv.wait(lock, [&] { return release; });
    }));
    {
        std::unique_lock<std::mutex> lock(m);
        ASSERT_TRUE(cv.wait_for(lock, std::chrono::seconds(5), [&] { return entered; }));
    }

    std::promise<int> p;
    auto fut = p.get_future();
    ASSERT_TRUE(f.runner.post([&] { p.set_value(7); }));

    std::thread stopper([&] { f.runner.stop(); });

    // Wait until stop() has actually cleared the flag before letting the loop go —
    // otherwise the loop gets one more iteration and drains the task itself, and the
    // test would pass without exercising stop()'s drain at all. A refused post is the
    // observable proof that the flag is down; the loop cannot have run anything
    // meanwhile, since it is parked inside the first task.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (f.runner.post([] {}) && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    ASSERT_EQ(fut.wait_for(std::chrono::milliseconds(0)), std::future_status::timeout);

    {
        std::lock_guard<std::mutex> lock(m);
        release = true;
    }
    cv.notify_all();
    stopper.join();

    ASSERT_EQ(fut.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_EQ(fut.get(), 7);
}

// stop() on a runner that was never started, and a second stop(), are both no-ops
// (the second must not block on an already-joined thread).
TEST(DhtRunnerShutdown, StopIsIdempotent) {
    RunnerFixture f;
    ASSERT_TRUE(f.transport.is_open());
    f.runner.stop();
    f.runner.start();
    f.runner.stop();
    f.runner.stop();
    EXPECT_FALSE(f.runner.post([] {}));
}
