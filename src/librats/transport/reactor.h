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
 * ── Two transports, one loop ────────────────────────────────────────────────
 * Connections are keyed by ConnId, not by socket, because only one of the two
 * transports has a socket per connection:
 *
 *   - TCP: one kernel socket per peer, registered with the poller. A poll event
 *     names a socket, which the fd → ConnId map turns into a connection.
 *   - UDP: every peer shares one socket, owned by the UdpMux. A poll event on it
 *     means "datagrams arrived"; the mux routes them to streams by connection id
 *     and hands back the same readable/writable/error events the poller would
 *     have produced. From dispatch_events() down, the two are indistinguishable.
 *
 * Both listeners are optional and independent: a reactor can accept TCP, accept
 * UDP, both, or neither (dial-only). Only the reactor that owns the mux can dial
 * over UDP, which is why the pool routes UDP dials to it (see reactor_pool.h).
 *
 * A ReactorPool (see reactor_pool.h) runs N of these and shards connections
 * across them; with N == 1 this is a classic single-threaded reactor.
 */

#include "librats/core/types.h"
#include "librats/transport/connection.h"
#include "librats/transport/udp_mux.h"
#include "librats/core/mpsc_queue.h"
#include "librats/core/timer_queue.h"
#include "librats/core/io_poller.h"
#include "librats/core/notifier.h"
#include "librats/core/socket.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace librats {

class Reactor final : public UdpMuxDelegate {
public:
    using Task = std::function<void()>;

    /// @param index    This reactor's slot in its pool (for sharding/logging).
    /// @param delegate Sink for all connection lifecycle/frame events.
    /// @param security Mints a Handshaker per connection (Noise / plaintext).
    Reactor(uint8_t index, ConnectionDelegate& delegate, SecurityProvider& security);
    ~Reactor() override;

    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;

    /// Adopt an already-bound, listening TCP socket. Call before start().
    void listen(socket_t server_socket);

    /// Adopt an already-bound UDP socket and run the datagram transport on it.
    /// Call before start(). This is what makes the reactor able to accept *and*
    /// dial over UDP; without it, UDP dials are refused.
    void listen_udp(socket_t udp_socket, AddressFamily family);

    /// Whether this reactor can carry UDP connections (i.e. it owns the mux).
    bool has_udp() const noexcept { return mux_ != nullptr; }

    void start();  ///< spawn the reactor thread
    void stop();   ///< signal shutdown and join; closes all connections

    // — cross-thread work submission —
    void post(Task task);                 ///< enqueue + wake (any thread)
    void execute(Task task);              ///< inline if on-thread, else post()
    bool on_reactor_thread() const noexcept;

    /// Begin a non-blocking outbound connection over `kind` (thread-safe).
    ///
    /// Returns the ConnId the connection *will* have, reserved synchronously so a
    /// caller can cancel the attempt with close() before it has even started —
    /// which is what lets the node race a UDP dial against a TCP one and drop the
    /// loser cleanly. kInvalidConnId if the transport is unavailable here.
    ConnId connect(std::string host, int port, TransportKind kind = TransportKind::Tcp);

    /// Close a connection by id (thread-safe; deferred to the reactor thread).
    /// Valid for an id whose dial has not started yet — it is cancelled instead.
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

    /// Adjust poll interest for a socket. Called by TcpLink; reactor thread.
    void set_interest(socket_t sock, uint32_t events);

    /// Book a flush for the end of this turn: `id` has frames queued that have
    /// not been written yet. Called by Connection::send, which aggregates rather
    /// than writing through — see the note there. Reactor thread; each connection
    /// books at most one flush per turn.
    void mark_dirty(ConnId id) { dirty_.push_back(id); }

    /// The security provider used to mint per-connection handshakers.
    SecurityProvider& security() noexcept { return security_; }

    /// Approximate live connection count (lock-free, eventually consistent).
    size_t connection_count() const noexcept {
        return conn_count_.load(std::memory_order_relaxed);
    }

    uint8_t index() const noexcept { return index_; }

private:
    // — UdpMuxDelegate —
    ConnId adopt_inbound_link(std::unique_ptr<Link> link) override;
    void   dispatch_link_events(ConnId id, uint32_t events) override;

    void run();
    void drain_tasks(std::vector<Task>& scratch);
    void drain_wakeup();
    void handle_event(const PollResult& ev);
    void dispatch_events(ConnId id, uint32_t events);
    void do_accept();
    void schedule_maintenance();
    void start_dial(ConnId id, const std::string& host, int port, TransportKind kind);
    void abort_dial(ConnId id, const std::string& host, int port);
    Connection* adopt(std::unique_ptr<Link> link, ConnRole role, ConnId id);
    bool resolve_dial(ConnId id);
    void mark_for_close(ConnId id, CloseReason reason);
    void process_pending_close();
    void flush_dirty();          ///< write out what send() queued this turn
    void remove(ConnId id, CloseReason reason);
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

    // Declared before conns_ so it is destroyed *after* them: every UDP
    // connection's Link points into the mux and tells it, on destruction, that its
    // stream may go. Reversing these two would have that run against freed memory.
    std::unique_ptr<UdpMux> mux_;

    // Connections are keyed by their stable ConnId, since a UDP connection has no
    // socket of its own; fd_to_conn_ maps the sockets that do exist (TCP, and the
    // listener) back to that key for poll dispatch.
    std::unordered_map<ConnId, std::unique_ptr<Connection>> conns_;
    std::unordered_map<socket_t, ConnId>                    fd_to_conn_;
    std::unordered_map<ConnId, CloseReason>                 pending_close_;
    /// Connections with frames queued but not yet written this turn. Holds ids,
    /// not pointers, so a connection torn down in between is simply not found.
    std::vector<ConnId>                                     dirty_;
    /// Dials cancelled before their connect task ran (see connect()/close()).
    std::unordered_set<ConnId>                              cancelled_dials_;
    /// Highest ConnId that has already been adopted or abandoned; anything at or
    /// below it has resolved, so a late close() for it needs no cancellation slot.
    ConnId                                                  resolved_watermark_ = 0;

    socket_t             server_socket_ = RATS_INVALID_SOCKET;
    std::atomic<ConnId>  next_conn_id_{1};
    std::atomic<size_t>  conn_count_{0};
    std::atomic<bool>    running_{false};
    std::thread          thread_;
    // Published with release by the reactor thread in run(), read with acquire by
    // any thread in on_reactor_thread(); plain access would be a data race.
    std::atomic<std::thread::id> thread_id_{};
};

} // namespace librats
