#pragma once

/**
 * @file reactor.h
 * @brief Single-threaded I/O reactor owning a shard of connections.
 *
 * A Reactor runs one thread that drives an IOPoller and owns every Connection
 * assigned to it. ALL connection state lives behind this one thread, so the
 * data path has zero locks. Other threads interact with it only by:
 *
 *   - post(task)    — run a closure on the reactor thread (wakes it);
 *   - execute(task) — same, but runs inline if already on the reactor thread;
 *   - connect()/close() — convenience wrappers that post the right task.
 *
 * The single synchronisation point is the MPSC task queue plus a WakeupPipe to
 * interrupt the poll wait. Timers (handshake timeouts, backoff) ride on the same
 * loop via a TimerQueue that also sizes each poll wait.
 *
 * A ReactorPool (see reactor_pool.h) runs N of these and shards connections
 * across them; with N == 1 this is a classic single-threaded reactor.
 */

#include "core/types.h"
#include "transport/connection.h"
#include "core/mpsc_queue.h"
#include "core/timer_queue.h"
#include "core/io_poller.h"
#include "core/notifier.h"
#include "core/socket.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace librats {

class Reactor {
public:
    using Task = std::function<void()>;

    /// @param index    This reactor's slot in its pool (for sharding/logging).
    /// @param delegate Sink for all connection lifecycle/frame events.
    /// @param security Mints a Handshaker per connection (Noise / plaintext).
    Reactor(uint8_t index, ConnectionDelegate& delegate, SecurityProvider& security);
    ~Reactor();

    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;

    /// Adopt an already-bound, listening server socket. Call before start().
    void listen(socket_t server_socket);

    void start();  ///< spawn the reactor thread
    void stop();   ///< signal shutdown and join; closes all connections

    // — cross-thread work submission —
    void post(Task task);                 ///< enqueue + wake (any thread)
    void execute(Task task);              ///< inline if on-thread, else post()
    bool on_reactor_thread() const noexcept;

    /// Begin a non-blocking outbound connection (thread-safe).
    void connect(std::string host, int port);

    /// Close a connection by id (thread-safe; deferred to the reactor thread).
    void close(ConnId id, CloseReason reason);

    /// Send a frame to every Established connection on this reactor. Thread-safe:
    /// the iteration runs on the reactor thread. The payload is shared across
    /// connections (the per-peer encryption still happens in each Connection).
    void broadcast(FrameHeader header, std::shared_ptr<const Bytes> payload);

    // — timers (reactor thread, or via post/execute) —
    TimerId schedule(std::chrono::milliseconds delay, Task on_fire);
    void    cancel(TimerId id);

    /// Look up an owned connection. Reactor thread only.
    Connection* find(ConnId id) noexcept;

    /// Adjust poll interest for a socket. Called by Connection; reactor thread.
    void set_interest(socket_t sock, uint32_t events);

    /// The security provider used to mint per-connection handshakers.
    SecurityProvider& security() noexcept { return security_; }

    /// Approximate live connection count (lock-free, eventually consistent).
    size_t connection_count() const noexcept {
        return conn_count_.load(std::memory_order_relaxed);
    }

    uint8_t index() const noexcept { return index_; }

private:
    void run();
    void drain_tasks(std::vector<Task>& scratch);
    void drain_wakeup();
    void handle_event(const PollResult& ev);
    void do_accept();
    void schedule_maintenance();
    Connection* adopt(socket_t sock, ConnRole role);
    void mark_for_close(socket_t sock, CloseReason reason);
    void process_pending_close();
    void remove(socket_t sock, CloseReason reason);
    void shutdown_connections();

    static constexpr int kMaxEvents = 256;
    // Idle poll cap. Kept short as a stopgap for an IOCP quirk: connecting
    // sockets live in WSAPoll-fallback mode and are only re-checked once per
    // wait() iteration, so connect-completion latency is bounded by this value.
    // Negligible idle cost; on epoll/kqueue the loop still wakes on real events,
    // so this only caps idle latency.
    static constexpr int kMaxPollMs = 50;
    /// Deadline from adopt() to reaching Established (covers connect + handshake).
    static constexpr std::chrono::milliseconds kEstablishTimeout{15000};
    /// Cadence of the housekeeping sweep over this reactor's connections (currently
    /// only Connection::on_maintenance_tick, which ages idle receive buffers). One
    /// timer per reactor rather than one per connection: the work is a few pointer
    /// comparisons per peer, so a sweep is cheaper than N timer entries.
    static constexpr std::chrono::milliseconds kMaintenanceInterval{10000};

    uint8_t                   index_;
    ConnectionDelegate&       delegate_;
    SecurityProvider&         security_;
    std::unique_ptr<IOPoller> poller_;
    Notifier                  wakeup_;
    MpscQueue<Task>           tasks_;
    TimerQueue                timers_;

    // Connections keyed by socket for O(1) event dispatch; id_to_socket_ maps
    // the stable external handle back to the socket.
    std::unordered_map<socket_t, std::unique_ptr<Connection>> conns_;
    std::unordered_map<ConnId, socket_t>                       id_to_socket_;
    std::unordered_map<socket_t, CloseReason>                  pending_close_;

    socket_t            server_socket_ = INVALID_SOCKET_VALUE;
    ConnId              next_conn_id_ = 1;
    std::atomic<size_t> conn_count_{0};
    std::atomic<bool>   running_{false};
    std::thread         thread_;
    // Published with release by the reactor thread in run(), read with acquire by
    // any thread in on_reactor_thread(); plain access would be a data race.
    std::atomic<std::thread::id> thread_id_{};
};

} // namespace librats
