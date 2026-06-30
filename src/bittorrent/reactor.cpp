#include "bittorrent/reactor.h"

namespace librats::bittorrent {

Reactor::Reactor() : poller_(IOPoller::create()) {
    if (is_valid_socket(notifier_.fd())) poller_->add(notifier_.fd(), PollIn);
}

Reactor::~Reactor() {
    stop();
}

void Reactor::start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread([this] {
        loop_thread_ = std::this_thread::get_id();
        while (running_.load()) run_one(1000);
    });
}

void Reactor::run() {
    running_.store(true);
    loop_thread_ = std::this_thread::get_id();
    while (running_.load()) run_one(1000);
}

void Reactor::stop() {
    if (!running_.exchange(false)) {
        if (thread_.joinable()) thread_.join();
        return;
    }
    notifier_.signal();  // break the poll wait so the loop sees running_ == false
    if (thread_.joinable()) thread_.join();
}

void Reactor::post(Task task) {
    tasks_.push(std::move(task));
    notifier_.signal();
}

void Reactor::run_one(int timeout_ms) {
    if (loop_thread_ == std::thread::id{}) loop_thread_ = std::this_thread::get_id();

    const int wait_ms = timers_.next_timeout_ms(timeout_ms);
    PollResult results[128];
    const int n = poller_->wait(results, 128, wait_ms);

    for (int i = 0; i < n; ++i) {
        if (results[i].fd == notifier_.fd()) {
            notifier_.drain();
            continue;
        }
        auto it = handlers_.find(results[i].fd);
        if (it == handlers_.end()) continue;
        // Copy the callback: it may remove this very fd (and destroy the stored
        // std::function) while running.
        IoCallback cb = it->second;
        cb(results[i].events);
    }

    run_tasks();
    timers_.run_due();
}

void Reactor::run_tasks() {
    tasks_.drain(task_scratch_);
    for (auto& t : task_scratch_) t();
    task_scratch_.clear();
}

bool Reactor::add(socket_t fd, std::uint32_t events, IoCallback cb) {
    handlers_[fd] = std::move(cb);
    if (!poller_->add(fd, events)) {
        handlers_.erase(fd);
        return false;
    }
    return true;
}

bool Reactor::modify(socket_t fd, std::uint32_t events) {
    return poller_->modify(fd, events);
}

void Reactor::remove(socket_t fd) {
    poller_->remove(fd);
    handlers_.erase(fd);
}

TimerId Reactor::schedule(std::chrono::milliseconds delay, TimerCallback cb) {
    return timers_.schedule(delay, std::move(cb));
}

void Reactor::cancel(TimerId id) {
    timers_.cancel(id);
}

} // namespace librats::bittorrent
