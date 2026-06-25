#include <gtest/gtest.h>
#include "dht/node.h"
#include "dht/udp_transport.h"
#include "dht/dht_runner.h"
#include "core/socket.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <thread>
#include <vector>

using namespace librats::dht;
using librats::Address;
using librats::AddressFamily;

namespace {

NodeId nid(uint8_t v) { NodeId id; id.fill(v); return id; }

// Read Node state from the test thread by hopping onto the runner's loop thread —
// the Node is single-threaded and must only be touched there.
std::size_t table_size(DhtRunner& runner, Node& node) {
    std::promise<std::size_t> p;
    auto fut = p.get_future();
    runner.post([&] { p.set_value(node.routing_table().size()); });
    return fut.get();
}

template <class Pred>
bool wait_until(Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return pred();
}

} // namespace

// Two real nodes on loopback: B bootstraps off A, A announces under an info-hash, and
// a subsequent lookup finds that announced peer — exercising the whole stack (UDP
// socket, runner loop, server handlers, tokens, traversal) end to end.
TEST(DhtUdp, TwoNodesAnnounceAndFind) {
    librats::init_socket_library();

    UdpTransport ta(0, "127.0.0.1", AddressFamily::IPv4);
    UdpTransport tb(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(ta.is_open());
    ASSERT_TRUE(tb.is_open());

    Node a(ta, nid(0x11), /*ipv6=*/false);
    Node b(tb, nid(0x22), false);
    DhtRunner ra(a, ta), rb(b, tb);
    ra.start();
    rb.start();

    const Address a_addr("127.0.0.1", ta.port());
    const auto now = [] { return std::chrono::steady_clock::now(); };

    // B bootstraps off A; after the round trip each should know the other.
    rb.post([&] { b.bootstrap({a_addr}, now()); });
    ASSERT_TRUE(wait_until([&] { return table_size(ra, a) >= 1 && table_size(rb, b) >= 1; },
                           std::chrono::seconds(5)))
        << "nodes did not discover each other";

    const InfoHash info_hash = nid(0x55);

    std::mutex m;
    std::condition_variable cv;
    bool announced = false;
    ra.post([&] {
        a.announce_peer(info_hash, ta.port(), /*implied_port=*/false,
                        [&](const std::vector<Address>&) {
                            std::lock_guard<std::mutex> lk(m);
                            announced = true;
                            cv.notify_all();
                        },
                        now());
    });
    {
        std::unique_lock<std::mutex> lk(m);
        ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return announced; }));
    }

    // Give B a beat to process the announce_peer datagram before we look it up.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::vector<Address> found;
    bool find_done = false;
    ra.post([&] {
        a.find_peers(info_hash, {},
                     [&](const std::vector<Address>& peers) {
                         std::lock_guard<std::mutex> lk(m);
                         found = peers;
                         find_done = true;
                         cv.notify_all();
                     },
                     now());
    });
    {
        std::unique_lock<std::mutex> lk(m);
        ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(5), [&] { return find_done; }));
    }

    ra.stop();
    rb.stop();

    bool has_announced_peer = false;
    for (const auto& p : found)
        if (p.ip == "127.0.0.1" && p.port == ta.port()) has_announced_peer = true;
    EXPECT_TRUE(has_announced_peer) << "lookup did not return the announced peer";
}

// set_periodic must invoke its callback on the loop thread at roughly the configured
// cadence — this is the mechanism the routing-table autosave rides on. A short interval
// keeps the test fast; the loop's recv timeout bounds how often it can actually fire.
TEST(DhtUdp, RunnerFiresPeriodicHookOnLoopThread) {
    librats::init_socket_library();

    UdpTransport t(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(t.is_open());

    Node node(t, nid(0x33), /*ipv6=*/false);
    DhtRunner runner(node, t);

    std::atomic<int> ticks{0};
    std::thread::id cb_thread{};
    runner.set_periodic(std::chrono::milliseconds(50), [&] {
        cb_thread = std::this_thread::get_id();  // read after join() — no data race
        ticks.fetch_add(1);
    });

    const std::thread::id main_thread = std::this_thread::get_id();
    runner.start();
    const bool fired = wait_until([&] { return ticks.load() >= 3; }, std::chrono::seconds(3));
    runner.stop();  // joins the loop thread

    EXPECT_TRUE(fired) << "periodic hook fired " << ticks.load() << " times, expected >= 3";
    EXPECT_NE(cb_thread, main_thread) << "periodic hook must run on the loop thread";
}
