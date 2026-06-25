#pragma once

/**
 * @file dht_runner.h
 * @brief The single thread that drives a dht::Node over a real socket.
 *
 * This is where real time and threading enter the otherwise pure, single-threaded
 * Node. The loop pumps incoming datagrams into Node::on_datagram, runs Node::tick on
 * a fixed cadence, and executes tasks posted from other threads — all on this one
 * thread, so the Node itself never needs a lock. External callers must reach the Node
 * through post() rather than touching it directly.
 */

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace librats {
namespace dht {

class Node;
class UdpTransport;

class DhtRunner {
public:
    DhtRunner(Node& node, UdpTransport& transport);
    ~DhtRunner();

    DhtRunner(const DhtRunner&) = delete;
    DhtRunner& operator=(const DhtRunner&) = delete;

    void start();
    void stop();

    // Run `task` on the loop thread. The only safe way to touch the Node from outside.
    void post(std::function<void()> task);

    // Register a callback invoked on the loop thread every `interval` (e.g. persisting
    // the routing table). The first invocation is one interval after start(), never at
    // t=0. Must be set before start(); call with a null fn to disable. The runner stays
    // oblivious to what the work is — the I/O concern lives in the caller.
    void set_periodic(std::chrono::milliseconds interval, std::function<void()> fn);

private:
    void loop();
    void drain_tasks();

    Node&         node_;
    UdpTransport& transport_;
    std::thread   thread_;
    std::atomic<bool> running_{false};
    std::mutex    mutex_;
    std::vector<std::function<void()>> tasks_;

    std::chrono::milliseconds          periodic_interval_{0};  // 0 = disabled
    std::function<void()>              periodic_fn_;
};

} // namespace dht
} // namespace librats
