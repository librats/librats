#include "core/reactor.h"
#include "logger.h"

#include <cstring>

namespace librats {

Reactor::Reactor(uint8_t index, ConnectionDelegate& delegate, SecurityProvider& security)
    : index_(index), delegate_(delegate), security_(security), poller_(IOPoller::create()) {}

Reactor::~Reactor() {
    stop();
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

void Reactor::listen(socket_t server_socket) {
    server_socket_ = server_socket;
}

void Reactor::start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread(&Reactor::run, this);
}

void Reactor::stop() {
    if (!running_.exchange(false)) {
        if (thread_.joinable()) thread_.join();
        return;
    }
    wakeup_.signal();              // break the poll wait
    if (thread_.joinable()) thread_.join();
}

// ── Work submission ─────────────────────────────────────────────────────────

bool Reactor::on_reactor_thread() const noexcept {
    return std::this_thread::get_id() == thread_id_;
}

void Reactor::post(Task task) {
    tasks_.push(std::move(task));
    wakeup_.signal();
}

void Reactor::execute(Task task) {
    if (on_reactor_thread()) task();
    else                     post(std::move(task));
}

void Reactor::connect(std::string host, int port) {
    post([this, host = std::move(host), port] {
        socket_t s = tcp_connect_start(host, port);
        if (!is_valid_socket(s)) {
            LOG_DEBUG("reactor", "Outbound connect to " << host << ":" << port << " failed to start");
            return;
        }
        adopt(s, ConnRole::Outbound);
    });
}

void Reactor::close(ConnId id, CloseReason reason) {
    execute([this, id, reason] {
        auto it = id_to_socket_.find(id);
        if (it != id_to_socket_.end()) mark_for_close(it->second, reason);
    });
}

// ── Timers ──────────────────────────────────────────────────────────────────

TimerId Reactor::schedule(std::chrono::milliseconds delay, Task on_fire) {
    return timers_.schedule(delay, std::move(on_fire));
}

void Reactor::cancel(TimerId id) {
    timers_.cancel(id);
}

// ── Lookups / interest ──────────────────────────────────────────────────────

Connection* Reactor::find(ConnId id) noexcept {
    auto it = id_to_socket_.find(id);
    if (it == id_to_socket_.end()) return nullptr;
    auto cit = conns_.find(it->second);
    return cit == conns_.end() ? nullptr : cit->second.get();
}

void Reactor::set_interest(socket_t sock, uint32_t events) {
    poller_->modify(sock, events);
}

// ── Reactor loop ────────────────────────────────────────────────────────────

void Reactor::run() {
    thread_id_ = std::this_thread::get_id();
    LOG_INFO("reactor", "Reactor " << static_cast<int>(index_)
             << " started (backend: " << poller_->name() << ")");

    set_socket_nonblocking(wakeup_.fd());
    poller_->add(wakeup_.fd(), PollIn);
    if (is_valid_socket(server_socket_)) {
        set_socket_nonblocking(server_socket_);
        poller_->add(server_socket_, PollIn);
    }

    PollResult        events[kMaxEvents];
    std::vector<Task> task_batch;

    while (running_.load(std::memory_order_relaxed)) {
        const int timeout = timers_.next_timeout_ms(kMaxPollMs);
        const int n = poller_->wait(events, kMaxEvents, timeout);

        drain_tasks(task_batch);                         // connect/close/send-arm
        for (int i = 0; i < n; ++i) handle_event(events[i]);
        timers_.run_due();
        process_pending_close();
    }

    shutdown_connections();
    LOG_INFO("reactor", "Reactor " << static_cast<int>(index_) << " stopped");
}

void Reactor::drain_tasks(std::vector<Task>& scratch) {
    tasks_.drain(scratch);
    for (auto& task : scratch) task();
}

void Reactor::drain_wakeup() {
    wakeup_.drain();
}

void Reactor::handle_event(const PollResult& ev) {
    const socket_t fd = ev.fd;

    if (fd == wakeup_.fd()) { drain_wakeup(); return; }
    if (fd == server_socket_) { if (ev.events & PollIn) do_accept(); return; }

    auto it = conns_.find(fd);
    if (it == conns_.end()) return;
    Connection* conn = it->second.get();
    if (conn->state() == ConnState::Closing || conn->state() == ConnState::Closed) return;

    bool keep = true;
    if (ev.events & (PollErr | PollHup)) {
        keep = conn->on_error();
    } else {
        if (keep && (ev.events & PollIn))  keep = conn->on_readable();
        if (keep && (ev.events & PollOut)) keep = conn->on_writable();
    }

    if (!keep) mark_for_close(fd, conn->close_reason());
}

void Reactor::do_accept() {
    // Level-triggered: drain all pending connections this tick. Use a raw,
    // non-logging accept — accept_client() logs an error on every EWOULDBLOCK,
    // which is the normal "no more pending" signal here.
    while (true) {
        socket_t client = ::accept(server_socket_, nullptr, nullptr);
        if (!is_valid_socket(client)) break;  // EWOULDBLOCK / error → done this tick
        Connection* conn = adopt(client, ConnRole::Inbound);
        conn->start_handshake();  // accepted sockets are already connected
    }
}

Connection* Reactor::adopt(socket_t sock, ConnRole role) {
    set_socket_nonblocking(sock);

    const ConnId id = next_conn_id_++;
    auto conn = std::make_unique<Connection>(id, sock, role, *this, delegate_);
    Connection* raw = conn.get();

    conns_.emplace(sock, std::move(conn));
    id_to_socket_.emplace(id, sock);
    conn_count_.fetch_add(1, std::memory_order_relaxed);

    // Inbound sockets are connected: watch for readable. Outbound sockets are
    // still connecting: watch for writable, which signals connect completion.
    poller_->add(sock, role == ConnRole::Inbound ? PollIn : PollOut);

    // Reap connections that never reach Established (stuck connect or handshake).
    TimerId timer = timers_.schedule(kEstablishTimeout, [this, sock] {
        auto it = conns_.find(sock);
        if (it == conns_.end()) return;
        const ConnState st = it->second->state();
        if (st != ConnState::Established && st != ConnState::Closing && st != ConnState::Closed) {
            mark_for_close(sock, st == ConnState::Connecting ? CloseReason::ConnectFailed
                                                             : CloseReason::HandshakeFailed);
        }
    });
    raw->set_establish_timer(timer);
    return raw;
}

// ── Teardown ────────────────────────────────────────────────────────────────

void Reactor::mark_for_close(socket_t sock, CloseReason reason) {
    pending_close_.emplace(sock, reason);  // first reason wins
}

void Reactor::process_pending_close() {
    if (pending_close_.empty()) return;
    auto batch = std::move(pending_close_);
    pending_close_.clear();
    for (const auto& [sock, reason] : batch) remove(sock, reason);
}

void Reactor::remove(socket_t sock, CloseReason reason) {
    auto it = conns_.find(sock);
    if (it == conns_.end()) return;

    std::unique_ptr<Connection> conn = std::move(it->second);
    conns_.erase(it);
    id_to_socket_.erase(conn->id());
    poller_->remove(sock);
    conn_count_.fetch_sub(1, std::memory_order_relaxed);

    LOG_DEBUG("reactor", "Peer " << conn->id() << " closed (" << to_string(reason) << ")");
    delegate_.on_closed(*conn, reason);
    close_socket(sock);
}

void Reactor::shutdown_connections() {
    for (auto& [sock, conn] : conns_) {
        poller_->remove(sock);
        delegate_.on_closed(*conn, CloseReason::ReactorShutdown);
        close_socket(sock);
    }
    conns_.clear();
    id_to_socket_.clear();
    pending_close_.clear();
    conn_count_.store(0, std::memory_order_relaxed);
}

} // namespace librats
