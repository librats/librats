#include "librats/transport/reactor.h"
#include "librats/transport/tcp_link.h"
#include "librats/core/ip_address.h"
#include "librats/util/logger.h"
#include "librats/util/network_utils.h"

#include <cstring>
#include <utility>

namespace librats {

namespace {

/// Turn a dial target into the numeric endpoint the datagram transport needs.
/// A literal is used as-is; a hostname goes through the resolver, preferring IPv6
/// exactly as tcp_connect_start() does, so both transports reach the same host.
std::optional<Address> resolve_dial_target(const std::string& host, int port) {
    if (auto ip = IpAddress::parse(host))
        return Address{*ip, static_cast<uint16_t>(port)};

    for (const std::string& text : {network_utils::resolve_hostname_v6(host),
                                    network_utils::resolve_hostname(host)}) {
        if (text.empty()) continue;
        if (auto ip = IpAddress::parse(text))
            return Address{*ip, static_cast<uint16_t>(port)};
    }
    return std::nullopt;
}

} // namespace

Reactor::Reactor(uint8_t index, ConnectionDelegate& delegate, SecurityProvider& security)
    : index_(index), delegate_(delegate), security_(security), poller_(IOPoller::create()) {}

Reactor::~Reactor() {
    stop();
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

void Reactor::listen(socket_t server_socket) {
    server_socket_ = server_socket;
}

void Reactor::listen_udp(socket_t udp_socket, AddressFamily family) {
    mux_ = std::make_unique<UdpMux>(udp_socket, family, *this);
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
    return std::this_thread::get_id() == thread_id_.load(std::memory_order_acquire);
}

void Reactor::post(Task task) {
    // After stop() the loop has exited and (apart from the brief stopping window
    // caught by the final drain in run()) the task will never run. Enqueue anyway
    // so its captures are released at destruction, but flag the dropped work.
    if (!running_.load(std::memory_order_acquire))
        LOG_DEBUG("reactor", "Reactor " << static_cast<int>(index_)
                  << " post() after stop; task may not run");
    tasks_.push(std::move(task));
    wakeup_.signal();
}

void Reactor::execute(Task task) {
    if (on_reactor_thread()) task();
    else                     post(std::move(task));
}

ConnId Reactor::connect(std::string host, int port, TransportKind kind) {
    if (kind == TransportKind::Udp && !mux_) {
        LOG_DEBUG("reactor", "Reactor " << static_cast<int>(index_)
                  << " has no datagram transport; refusing UDP dial to " << host << ":" << port);
        return kInvalidConnId;
    }

    // Reserve the id here, on the calling thread, rather than inside the task. The
    // caller can then cancel this exact attempt (close()) before the task has even
    // run — which is what makes racing one transport against the other cancellable
    // instead of a matter of luck.
    const ConnId id = next_conn_id_.fetch_add(1, std::memory_order_relaxed);
    post([this, host = std::move(host), port, kind, id] { start_dial(id, host, port, kind); });
    return id;
}

void Reactor::start_dial(ConnId id, const std::string& host, int port, TransportKind kind) {
    if (kind == TransportKind::Udp) {
        const auto target = resolve_dial_target(host, port);
        if (!target) {
            LOG_DEBUG("reactor", "Cannot resolve " << host << " for a UDP dial");
            abort_dial(id, host, port);
            return;
        }
        std::unique_ptr<Link> link = mux_->connect(*target);
        if (!link) { abort_dial(id, host, port); return; }

        Connection* conn = adopt(std::move(link), ConnRole::Outbound, id);
        if (conn) conn->set_dial_address(host, static_cast<uint16_t>(port));
        return;
    }

    socket_t sock = tcp_connect_start(host, port);
    if (!is_valid_socket(sock)) {
        LOG_DEBUG("reactor", "Outbound connect to " << host << ":" << port << " failed to start");
        abort_dial(id, host, port);
        return;
    }
    Connection* conn = adopt(std::make_unique<TcpLink>(sock, *this), ConnRole::Outbound, id);
    if (!conn) { close_socket(sock); return; }   // the dial was cancelled while queued
    conn->set_dial_address(host, static_cast<uint16_t>(port));
}

void Reactor::abort_dial(ConnId id, const std::string& host, int port) {
    resolve_dial(id);  // the id is spent either way; release any cancellation slot
    delegate_.on_dial_aborted(index_, id, host, static_cast<uint16_t>(port));
}

void Reactor::close(ConnId id, CloseReason reason) {
    execute([this, id, reason] {
        if (conns_.count(id)) { mark_for_close(id, reason); return; }
        // Not adopted yet: its connect task is still queued behind this one. Leave
        // a note so adopt() drops it on arrival. Ids at or below the watermark have
        // already come and gone, so they need no slot (and cannot leak one).
        if (id != kInvalidConnId && id > resolved_watermark_) cancelled_dials_.insert(id);
    });
}

void Reactor::broadcast(FrameHeader header, std::shared_ptr<const Bytes> payload) {
    execute([this, header, payload = std::move(payload)] {
        for (auto& [id, conn] : conns_) {
            if (conn->state() == ConnState::Established)
                conn->send(header, ByteView(*payload));
        }
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
    auto it = conns_.find(id);
    return it == conns_.end() ? nullptr : it->second.get();
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
    if (mux_) {
        set_socket_nonblocking(mux_->socket());
        poller_->add(mux_->socket(), PollIn);
        schedule_udp_tick();
    }

    PollResult        events[kMaxEvents];
    std::vector<Task> task_batch;

    schedule_maintenance();

    while (running_.load(std::memory_order_relaxed)) {
        const int timeout = timers_.next_timeout_ms(kMaxPollMs);
        const int n = poller_->wait(events, kMaxEvents, timeout);

        drain_tasks(task_batch);                         // connect/close/send-arm
        for (int i = 0; i < n; ++i) handle_event(events[i]);
        timers_.run_due();
        process_pending_close();
        // The mux batches its datagrams; the ones it collected inside a readable
        // event or a tick have already gone out, but an application send reaches a
        // UDP stream from a task, outside any batch of its own. Flushing once here
        // covers those without giving any of them a timer to wait on.
        if (mux_) mux_->flush_output();
    }

    // Graceful drain: run whatever was queued before/around stop() so in-flight
    // sends flush and explicit closes settle, then tear everything down. (post()
    // may still race in after this; such tasks are dropped — see post().)
    drain_tasks(task_batch);
    process_pending_close();
    shutdown_connections();
    if (mux_) mux_->shutdown();   // after the connections, so no Link outlives it
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
    if (mux_ && fd == mux_->socket()) {
        // Stopped short of draining the socket: come straight back rather than
        // waiting for the next datagram to re-arm an edge-triggered poller.
        if ((ev.events & PollIn) && mux_->on_readable()) wakeup_.signal();
        return;
    }

    auto it = fd_to_conn_.find(fd);
    if (it == fd_to_conn_.end()) return;
    dispatch_events(it->second, ev.events);
}

void Reactor::dispatch_events(ConnId id, uint32_t events) {
    Connection* conn = find(id);
    if (!conn) return;
    if (conn->state() == ConnState::Closing || conn->state() == ConnState::Closed) return;

    bool keep = true;
    if (events & (PollErr | PollHup)) {
        keep = conn->on_error();
    } else {
        if (keep && (events & PollIn))  keep = conn->on_readable();
        if (keep && (events & PollOut)) keep = conn->on_writable();
    }

    if (!keep) mark_for_close(id, conn->close_reason());
}

void Reactor::dispatch_link_events(ConnId id, uint32_t events) {
    dispatch_events(id, events);
}

void Reactor::schedule_maintenance() {
    timers_.schedule(kMaintenanceInterval, [this] {
        // Connections being torn down this tick are still in conns_; the sweep is
        // read-only with respect to the map, and on_maintenance_tick() never closes.
        for (auto& [id, conn] : conns_) conn->on_maintenance_tick();
        schedule_maintenance();
    });
}

void Reactor::schedule_udp_tick() {
    timers_.schedule(UdpMux::kTickInterval, [this] {
        if (!mux_) return;
        mux_->tick();
        schedule_udp_tick();
    });
}

void Reactor::do_accept() {
    // Level-triggered: drain all pending connections this tick. Use a raw,
    // non-logging accept — accept_client() logs an error on every EWOULDBLOCK,
    // which is the normal "no more pending" signal here.
    while (true) {
        socket_t client = ::accept(server_socket_, nullptr, nullptr);
        if (!is_valid_socket(client)) break;  // EWOULDBLOCK / error → done this tick
        suppress_sigpipe(client);  // not inherited from the listener; raw accept()

        // Admission control: refuse new inbound peers when at capacity, before
        // paying any handshake cost. Keep draining the backlog so the listener
        // doesn't stay readable. The precise per-peer cap is enforced again at
        // on_established (this coarse gate can't yet know the remote's identity).
        if (!delegate_.admit_inbound()) {
            close_socket(client);
            continue;
        }

        Connection* conn = adopt(std::make_unique<TcpLink>(client, *this), ConnRole::Inbound,
                                 next_conn_id_.fetch_add(1, std::memory_order_relaxed));
        if (!conn) { close_socket(client); continue; }
        conn->start_handshake();  // accepted sockets are already connected
    }
}

ConnId Reactor::adopt_inbound_link(std::unique_ptr<Link> link) {
    // Same coarse admission gate the TCP listener applies, for the same reason:
    // turn a flood away before any handshake work is done for it.
    if (!delegate_.admit_inbound()) return kInvalidConnId;

    const ConnId id = next_conn_id_.fetch_add(1, std::memory_order_relaxed);
    Connection* conn = adopt(std::move(link), ConnRole::Inbound, id);
    if (!conn) return kInvalidConnId;
    conn->start_handshake();  // an accepted stream is already connected
    return id;
}

bool Reactor::resolve_dial(ConnId id) {
    if (id > resolved_watermark_) resolved_watermark_ = id;
    return cancelled_dials_.erase(id) > 0;
}

Connection* Reactor::adopt(std::unique_ptr<Link> link, ConnRole role, ConnId id) {
    // A dial cancelled while its task sat in the queue never becomes a connection;
    // dropping `link` here is what actually calls the attempt off.
    if (resolve_dial(id)) return nullptr;

    const socket_t fd = link->fd();
    if (is_valid_socket(fd)) set_socket_nonblocking(fd);

    auto conn = std::make_unique<Connection>(id, std::move(link), role, *this, delegate_);
    Connection* raw = conn.get();
    raw->link().attach(id);

    conns_.emplace(id, std::move(conn));
    conn_count_.fetch_add(1, std::memory_order_relaxed);

    if (is_valid_socket(fd)) {
        fd_to_conn_.emplace(fd, id);
        // Inbound sockets are connected: watch for readable. Outbound sockets are
        // still connecting: watch for writable, which signals connect completion.
        poller_->add(fd, role == ConnRole::Inbound ? PollIn : PollOut);
    }

    // Reap connections that never reach Established (stuck connect or handshake).
    TimerId timer = timers_.schedule(kEstablishTimeout, [this, id] {
        auto it = conns_.find(id);
        if (it == conns_.end()) return;
        const ConnState st = it->second->state();
        if (st != ConnState::Established && st != ConnState::Closing && st != ConnState::Closed) {
            mark_for_close(id, st == ConnState::Connecting ? CloseReason::ConnectFailed
                                                           : CloseReason::HandshakeFailed);
        }
    });
    raw->set_establish_timer(timer);
    return raw;
}

// ── Teardown ────────────────────────────────────────────────────────────────

void Reactor::mark_for_close(ConnId id, CloseReason reason) {
    pending_close_.emplace(id, reason);  // first reason wins
}

void Reactor::process_pending_close() {
    if (pending_close_.empty()) return;
    auto batch = std::move(pending_close_);
    pending_close_.clear();
    for (const auto& [id, reason] : batch) remove(id, reason);
}

void Reactor::remove(ConnId id, CloseReason reason) {
    auto it = conns_.find(id);
    if (it == conns_.end()) return;

    std::unique_ptr<Connection> conn = std::move(it->second);
    conns_.erase(it);

    const socket_t fd = conn->socket();
    if (is_valid_socket(fd)) {
        fd_to_conn_.erase(fd);
        poller_->remove(fd);
    }
    conn->cancel_establish_timer();  // stop the reaper before this fd can be reused
    conn_count_.fetch_sub(1, std::memory_order_relaxed);

    LOG_DEBUG("reactor", "Connection " << id << " closed (" << to_string(reason) << ")");
    conn->shutdown_link(reason);     // let the transport say goodbye / flush
    delegate_.on_closed(*conn, reason);
    if (is_valid_socket(fd)) close_socket(fd);
    // ~Connection here releases the Link, which is what hands a UDP stream back to
    // the mux (to linger briefly or go straight away).
}

void Reactor::shutdown_connections() {
    for (auto& [id, conn] : conns_) {
        const socket_t fd = conn->socket();
        if (is_valid_socket(fd)) poller_->remove(fd);
        conn->shutdown_link(CloseReason::ReactorShutdown);
        delegate_.on_closed(*conn, CloseReason::ReactorShutdown);
        if (is_valid_socket(fd)) close_socket(fd);
    }
    conns_.clear();
    fd_to_conn_.clear();
    pending_close_.clear();
    cancelled_dials_.clear();
    conn_count_.store(0, std::memory_order_relaxed);
}

} // namespace librats
