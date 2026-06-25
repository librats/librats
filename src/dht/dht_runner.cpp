#include "dht/dht_runner.h"
#include "dht/node.h"
#include "dht/udp_transport.h"

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
    if (thread_.joinable()) thread_.join();
}

void DhtRunner::post(std::function<void()> task) {
    std::lock_guard<std::mutex> lock(mutex_);
    tasks_.push_back(std::move(task));
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
        auto data = transport_.recv(kRecvTimeoutMs, from);
        const auto now = std::chrono::steady_clock::now();

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
