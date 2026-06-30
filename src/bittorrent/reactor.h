#pragma once

/**
 * @file reactor.h
 * @brief Single-threaded event loop for the BitTorrent peer transport.
 *
 * BitTorrent peers speak a plaintext wire protocol that is unrelated to the
 * node's Noise mesh, so rather than bend `transport::Reactor` (which is tied to
 * the Noise handshake) we assemble a dedicated loop from the same reusable
 * primitives: an IOPoller, a TimerQueue, an MPSC task queue and a Notifier
 * self-pipe to break the poll wait.
 *
 * One thread owns the loop and therefore all protocol state hung off it — peers,
 * pickers, torrents — so none of that needs locks. Other threads reach in only
 * through post(), which enqueues a task and wakes the loop. Socket registration
 * (add/modify/remove) and timers are reactor-thread-only; call them from a task
 * if you are elsewhere.
 */

#include "core/io_poller.h"
#include "core/mpsc_queue.h"
#include "core/notifier.h"
#include "core/socket.h"
#include "core/timer_queue.h"
#include "core/types.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <thread>
#include <unordered_map>

namespace librats::bittorrent {

class Reactor {
public:
    using Task          = std::function<void()>;
    using IoCallback    = std::function<void(std::uint32_t events)>;
    using TimerCallback = std::function<void()>;

    Reactor();
    ~Reactor();

    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;

    /// Run the loop on a dedicated thread until stop().
    void start();
    /// Stop the loop and join its thread (if any). Idempotent.
    void stop();
    /// Run the loop on the calling thread until stop().
    void run();
    /// Run a single loop iteration: poll, dispatch I/O, run posted tasks and due
    /// timers. Exposed for tests and for embedding in another loop.
    void run_one(int timeout_ms);

    bool running() const noexcept { return running_.load(); }
    bool on_reactor_thread() const noexcept { return std::this_thread::get_id() == loop_thread_; }

    /// Enqueue a task to run on the reactor thread. Thread-safe.
    void post(Task task);

    // ---- reactor-thread only ----
    bool add(socket_t fd, std::uint32_t events, IoCallback cb);
    bool modify(socket_t fd, std::uint32_t events);
    void remove(socket_t fd);

    TimerId schedule(std::chrono::milliseconds delay, TimerCallback cb);
    void    cancel(TimerId id);

private:
    void dispatch_io();
    void run_tasks();

    std::unique_ptr<IOPoller>                    poller_;
    TimerQueue                                   timers_;
    MpscQueue<Task>                              tasks_;
    Notifier                                     notifier_;
    std::unordered_map<socket_t, IoCallback>     handlers_;
    std::vector<Task>                            task_scratch_;

    std::atomic<bool> running_{false};
    std::thread       thread_;
    std::thread::id   loop_thread_;
};

} // namespace librats::bittorrent
