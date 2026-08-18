#include <gtest/gtest.h>
#include "librats/dht/dht.h"
#include "librats/dht/dht_runner.h"
#include "librats/dht/node.h"
#include "librats/dht/udp_transport.h"
#include "librats/core/socket.h"

#include <atomic>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

using librats::AddressFamily;
using librats::DhtClient;
using librats::NodeId;

namespace {

librats::dht::NodeId nid(uint8_t v) { librats::dht::NodeId id; id.fill(v); return id; }

bool all_zero(const NodeId& id) {
    for (uint8_t b : id) if (b) return false;
    return true;
}

// Enough repetitions to land inside the ~microsecond window between a public call
// reading `running` and stop() freeing the engine behind it. The unguarded version
// segfaulted well inside this range on a plain Debug build; under TSAN it reports on
// the first few. Each round is a loopback socket plus two short-lived threads, so the
// whole thing stays well under a second.
constexpr int kRounds = 400;

} // namespace

// stop() on a runner that was never started, and a second stop(), are both no-ops
// (the second must not block on an already-joined thread).
TEST(DhtShutdown, RunnerStopIsIdempotent) {
    librats::init_socket_library();
    librats::dht::UdpTransport transport{0, "127.0.0.1", AddressFamily::IPv4};
    ASSERT_TRUE(transport.is_open());
    librats::dht::Node      node{transport, nid(0x42), /*ipv6=*/false};
    librats::dht::DhtRunner runner{node, transport};

    runner.stop();
    runner.start();
    runner.stop();
    runner.stop();
}

// A public call that has passed the `running` check must not be left holding a freed
// engine when stop() lands right behind it. The facade's getters marshal onto the loop
// thread through impl_->runner and read impl_->node, both of which stop() destroys —
// without the lifetime lock this is a use-after-free that crashes outright.
TEST(DhtShutdown, PublicCallsRacingStopAreSafe) {
    librats::init_socket_library();
    for (int i = 0; i < kRounds; ++i) {
        DhtClient client(0, "127.0.0.1", "", AddressFamily::IPv4);
        ASSERT_TRUE(client.start());

        std::atomic<bool> go{false};
        std::thread caller([&] {
            while (!go.load()) {}
            for (int k = 0; k < 20; ++k) {
                client.get_node_id();
                client.get_routing_table_size();
                client.get_port();
                client.cancel_search(librats::InfoHash{});
            }
        });
        std::thread stopper([&] { while (!go.load()) {} client.stop(); });
        go.store(true);
        caller.join();
        stopper.join();
    }
}

// save_routing_table() racing stop() must never persist a placeholder identity: the
// file is rewritten in full, and nothing validates node_id on the way back in, so one
// bad write costs the node its identity and its whole warm contact set on next start.
TEST(DhtShutdown, SaveRoutingTableRacingStopKeepsIdentity) {
    librats::init_socket_library();
    const std::string dir  = "./test_dht_shutdown_dir";
    const std::string path = dir + "/dht_routing.json";
    std::remove(path.c_str());

    for (int i = 0; i < kRounds; ++i) {
        DhtClient client(0, "127.0.0.1", dir, AddressFamily::IPv4);
        ASSERT_TRUE(client.start());

        std::atomic<bool> go{false};
        std::atomic<int>  zero_ids{0};
        std::thread caller([&] {
            while (!go.load()) {}
            for (int k = 0; k < 20; ++k) {
                if (all_zero(client.get_node_id())) zero_ids.fetch_add(1);
                client.save_routing_table();
            }
        });
        std::thread stopper([&] { while (!go.load()) {} client.stop(); });
        go.store(true);
        caller.join();
        stopper.join();

        ASSERT_EQ(zero_ids.load(), 0) << "get_node_id() handed out a placeholder id (round " << i << ")";

        std::ifstream f(path);
        if (!f.is_open()) continue;  // no data dir write yet
        std::stringstream ss;
        ss << f.rdbuf();
        ASSERT_EQ(ss.str().find("\"node_id\": \"0000000000000000000000000000000000000000\""),
                  std::string::npos)
            << "routing table on disk was overwritten with a zero identity (round " << i << ")";
    }
    std::remove(path.c_str());
}

// The lifetime lock must not turn the shutdown race into a shutdown *deadlock*. A
// peer-discovery callback runs on the DHT loop thread and may legitimately call back
// into the facade ("got what I wanted — cancel the search"); stop() meanwhile holds
// the lock exclusively and then joins that very thread. Without the loop-thread bypass
// the callback blocks on the lock forever and stop() blocks on the join forever —
// exactly the hang this module was fixed for, one layer up.
TEST(DhtShutdown, LoopThreadCallbackCanCallBackIntoTheFacadeDuringStop) {
    librats::init_socket_library();
    // Heap-allocated so a regression can be leaked rather than hung on: if the callback
    // is stuck, stop() never returns and ~DhtClient would block on it too.
    auto client = std::make_unique<DhtClient>(0, "127.0.0.1", "", AddressFamily::IPv4);
    ASSERT_TRUE(client->start());

    std::atomic<bool> entered{false}, finished{false};
    // No bootstrap contacts, so the lookup completes immediately and the callback fires
    // on the loop thread right away.
    ASSERT_TRUE(client->find_peers(librats::InfoHash{},
                                   [&](const std::vector<librats::Address>&, const librats::InfoHash& h) {
        entered.store(true);
        // Stay inside the callback long enough for stop() to take the lock and enter
        // its join(), which is the only configuration that deadlocks.
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        client->cancel_search(h);           // post-only call
        client->get_routing_table_size();   // on_loop round-trip
        client->get_port();                 // plain guarded getter
        finished.store(true);
    }));

    auto wait_for = [](const std::atomic<bool>& flag, std::chrono::seconds limit) {
        const auto deadline = std::chrono::steady_clock::now() + limit;
        while (!flag.load() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return flag.load();
    };
    ASSERT_TRUE(wait_for(entered, std::chrono::seconds(10))) << "callback never ran";

    std::thread stopper([&] { client->stop(); });
    if (!wait_for(finished, std::chrono::seconds(10))) {
        stopper.detach();       // both threads are wedged; leak them and fail loudly
        client.release();       // its loop thread is still inside the callback
        FAIL() << "callback deadlocked calling into DhtClient from the loop thread";
    }
    stopper.join();
}
