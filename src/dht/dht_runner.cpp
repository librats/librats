#include "dht/dht_runner.h"
#include "dht/node.h"
#include "dht/udp_transport.h"
#include "dht/log.h"

#include <chrono>
#include <utility>

namespace librats {
namespace dht {

namespace {
constexpr int kRecvTimeoutMs = 100;                          // loop responsiveness
constexpr std::chrono::milliseconds kTickInterval{1000};     // Node maintenance cadence
}

DhtRunner::DhtRunner(Node& node, UdpTransport& transport)
    : node_(node), transport_(transport) {}

DhtRunner::~DhtRunner() {
    stop();
}

void DhtRunner::start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread([this] { loop(); });
}

void DhtRunner::stop() {
    if (!running_.exchange(false)) return;
    wakeup_.signal();  // wake the loop now instead of waiting out the recv timeout
    if (thread_.joinable()) thread_.join();
}

void DhtRunner::post(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        tasks_.push_back(std::move(task));
    }
    // The task is queued before we signal, so whenever a wakeup byte exists the task is
    // already visible to drain_tasks() — the loop can never block past a pending task.
    wakeup_.signal();
}

void DhtRunner::set_periodic(std::chrono::milliseconds interval, std::function<void()> fn) {
    periodic_interval_ = interval;
    periodic_fn_       = std::move(fn);
}

void DhtRunner::loop() {
    const auto start = std::chrono::steady_clock::now();
    auto last_tick = start;
    auto last_periodic = start;  // first periodic fires one full interval in, not at t=0
    while (running_.load()) {
        Address from;
        // recv() returns early (as nullopt) the moment post()/stop() signals the wakeup
        // pipe, so a posted task runs without waiting out kRecvTimeoutMs.
        auto data = transport_.recv(kRecvTimeoutMs, from, wakeup_.fd());
        const auto now = std::chrono::steady_clock::now();

        // Consume the wakeup byte(s) before processing, so the next recv() blocks again.
        // Draining here (not after drain_tasks) means any task posted during processing
        // leaves an un-drained byte that wakes the following recv() — no lost wakeups.
        wakeup_.drain();

        if (data) node_.on_datagram(*data, from, now);

        drain_tasks();

        if (now - last_tick >= kTickInterval) {
            node_.tick(now);
            last_tick = now;
        }

        if (periodic_fn_ && periodic_interval_.count() > 0 && now - last_periodic >= periodic_interval_) {
            periodic_fn_();
            last_periodic = now;
        }
    }
}

void DhtRunner::drain_tasks() {
    std::vector<std::function<void()>> pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending.swap(tasks_);
    }
    for (auto& task : pending) task();
}

} // namespace dht
} // namespace librats
