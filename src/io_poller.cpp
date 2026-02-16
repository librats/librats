#include "io_poller.h"
#include "logger.h"

#include <cstring>
#include <algorithm>
#include <set>

//=============================================================================
// Platform detection
//=============================================================================

#if defined(__linux__)
    #define POLLER_USE_EPOLL 1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #define POLLER_USE_KQUEUE 1
#elif defined(_WIN32)
    #define POLLER_USE_IOCP 1
#else
    // Fallback: use poll() on other POSIX systems
    #define POLLER_USE_POLL 1
#endif

//=============================================================================
// Platform includes
//=============================================================================

#if defined(POLLER_USE_EPOLL)
    #include <sys/epoll.h>
    #include <unistd.h>
    #include <errno.h>
#elif defined(POLLER_USE_KQUEUE)
    #include <sys/types.h>
    #include <sys/event.h>
    #include <sys/time.h>
    #include <unistd.h>
    #include <errno.h>
#elif defined(POLLER_USE_IOCP)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <mutex>
    #include <unordered_map>
    #include <vector>
    #include <memory>
#elif defined(POLLER_USE_POLL)
    #include <poll.h>
    #include <errno.h>
#endif

// Logging macros
#define LOG_POLLER_DEBUG(msg) LOG_DEBUG("IOPoller", msg)
#define LOG_POLLER_INFO(msg)  LOG_INFO("IOPoller", msg)
#define LOG_POLLER_WARN(msg)  LOG_WARN("IOPoller", msg)
#define LOG_POLLER_ERROR(msg) LOG_ERROR("IOPoller", msg)

namespace librats {

//=============================================================================
// Linux: epoll implementation
//=============================================================================

#if defined(POLLER_USE_EPOLL)

class EpollPoller final : public IOPoller {
public:
    EpollPoller() {
        epfd_ = epoll_create1(EPOLL_CLOEXEC);
        if (epfd_ < 0) {
            LOG_POLLER_ERROR("epoll_create1 failed: " + std::string(strerror(errno)));
        } else {
            LOG_POLLER_INFO("Created epoll instance (fd=" + std::to_string(epfd_) + ")");
        }
    }
    
    ~EpollPoller() override {
        if (epfd_ >= 0) {
            ::close(epfd_);
        }
    }
    
    bool add(socket_t fd, uint32_t events) override {
        struct epoll_event ev;
        std::memset(&ev, 0, sizeof(ev));
        ev.data.fd = fd;
        ev.events = to_epoll_events(events);
        
        if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
            LOG_POLLER_ERROR("epoll_ctl ADD failed for fd " + std::to_string(fd) + 
                            ": " + std::string(strerror(errno)));
            return false;
        }
        return true;
    }
    
    bool modify(socket_t fd, uint32_t events) override {
        struct epoll_event ev;
        std::memset(&ev, 0, sizeof(ev));
        ev.data.fd = fd;
        ev.events = to_epoll_events(events);
        
        if (epoll_ctl(epfd_, EPOLL_CTL_MOD, fd, &ev) < 0) {
            // ENOENT is expected during disconnect races —
            // another thread removed the fd between lookup and modify
            if (errno == ENOENT) {
                LOG_POLLER_DEBUG("epoll_ctl MOD: fd " + std::to_string(fd) + 
                                " already removed (race with disconnect)");
                return false;
            }
            LOG_POLLER_ERROR("epoll_ctl MOD failed for fd " + std::to_string(fd) + 
                            ": " + std::string(strerror(errno)));
            return false;
        }
        return true;
    }
    
    bool remove(socket_t fd) override {
        if (epoll_ctl(epfd_, EPOLL_CTL_DEL, fd, nullptr) < 0) {
            // ENOENT is expected if fd was already closed/removed
            if (errno != ENOENT) {
                LOG_POLLER_ERROR("epoll_ctl DEL failed for fd " + std::to_string(fd) + 
                                ": " + std::string(strerror(errno)));
            }
            return false;
        }
        return true;
    }
    
    int wait(PollResult* results, int max_results, int timeout_ms) override {
        struct epoll_event events[max_results];
        
        int n = epoll_wait(epfd_, events, max_results, timeout_ms);
        
        if (n < 0) {
            if (errno != EINTR) {
                LOG_POLLER_ERROR("epoll_wait failed: " + std::string(strerror(errno)));
            }
            return -1;
        }
        
        for (int i = 0; i < n; ++i) {
            results[i].fd = static_cast<socket_t>(events[i].data.fd);
            results[i].events = from_epoll_events(events[i].events);
        }
        
        return n;
    }
    
    const char* name() const override { return "epoll"; }
    
private:
    int epfd_ = -1;
    
    static uint32_t to_epoll_events(uint32_t flags) {
        uint32_t e = 0;
        if (flags & PollIn)  e |= EPOLLIN;
        if (flags & PollOut) e |= EPOLLOUT;
        // EPOLLERR and EPOLLHUP are always reported, no need to set
        return e;
    }
    
    static uint32_t from_epoll_events(uint32_t epoll_events) {
        uint32_t flags = 0;
        if (epoll_events & EPOLLIN)  flags |= PollIn;
        if (epoll_events & EPOLLOUT) flags |= PollOut;
        if (epoll_events & EPOLLERR) flags |= PollErr;
        if (epoll_events & EPOLLHUP) flags |= PollHup;
        return flags;
    }
};

#endif // POLLER_USE_EPOLL

//=============================================================================
// macOS/BSD: kqueue implementation
//=============================================================================

#if defined(POLLER_USE_KQUEUE)

class KqueuePoller final : public IOPoller {
public:
    KqueuePoller() {
        kqfd_ = kqueue();
        if (kqfd_ < 0) {
            LOG_POLLER_ERROR("kqueue() failed: " + std::string(strerror(errno)));
        } else {
            LOG_POLLER_INFO("Created kqueue instance (fd=" + std::to_string(kqfd_) + ")");
        }
    }
    
    ~KqueuePoller() override {
        if (kqfd_ >= 0) {
            ::close(kqfd_);
        }
    }
    
    bool add(socket_t fd, uint32_t events) override {
        if (!apply_changes(fd, events, EV_ADD | EV_CLEAR))
            return false;
        registered_.insert(fd);
        return true;
    }
    
    bool modify(socket_t fd, uint32_t events) override {
        if (registered_.find(fd) == registered_.end()) return false;
        
        // kqueue: adding a filter that already exists replaces it.
        // We also need to delete filters that are no longer wanted.
        struct kevent changes[4];
        int nchanges = 0;
        
        if (events & PollIn) {
            EV_SET(&changes[nchanges++], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, nullptr);
        } else {
            EV_SET(&changes[nchanges++], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        }
        
        if (events & PollOut) {
            EV_SET(&changes[nchanges++], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, nullptr);
        } else {
            EV_SET(&changes[nchanges++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        }
        
        // Apply changes (ignore ENOENT errors from deleting non-existent filters)
        int ret = kevent(kqfd_, changes, nchanges, nullptr, 0, nullptr);
        if (ret < 0 && errno != ENOENT) {
            LOG_POLLER_ERROR("kevent modify failed for fd " + std::to_string(fd) + 
                            ": " + std::string(strerror(errno)));
            return false;
        }
        return true;
    }
    
    bool remove(socket_t fd) override {
        if (registered_.erase(fd) == 0) return false;
        
        struct kevent changes[2];
        // Delete both read and write filters. Ignore errors (filter may not exist).
        EV_SET(&changes[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        EV_SET(&changes[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        kevent(kqfd_, changes, 2, nullptr, 0, nullptr);
        return true;
    }
    
    int wait(PollResult* results, int max_results, int timeout_ms) override {
        struct timespec ts;
        struct timespec* ts_ptr = nullptr;
        
        if (timeout_ms >= 0) {
            ts.tv_sec = timeout_ms / 1000;
            ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
            ts_ptr = &ts;
        }
        
        // kqueue may return separate events for read and write on the same fd.
        // We fetch at most max_results raw events — after merging we may get
        // fewer results, but we never lose events (un-fetched events stay in
        // the kqueue for the next call).  Fetching more than max_results would
        // risk silently discarding events with EV_CLEAR (edge-triggered).
        struct kevent kevents[max_results > 256 ? 256 : max_results];
        int kevents_size = (max_results > 256) ? 256 : max_results;
        
        int n = kevent(kqfd_, nullptr, 0, kevents, kevents_size, ts_ptr);
        
        if (n < 0) {
            if (errno != EINTR) {
                LOG_POLLER_ERROR("kevent wait failed: " + std::string(strerror(errno)));
            }
            return -1;
        }
        
        // Merge events for the same fd
        int count = 0;
        for (int i = 0; i < n && count < max_results; ++i) {
            socket_t fd = static_cast<socket_t>(kevents[i].ident);
            uint32_t flags = 0;
            
            if (kevents[i].filter == EVFILT_READ) {
                flags |= PollIn;
                if (kevents[i].flags & EV_EOF) flags |= PollHup;
            }
            if (kevents[i].filter == EVFILT_WRITE) {
                flags |= PollOut;
            }
            if (kevents[i].flags & EV_ERROR) {
                flags |= PollErr;
            }
            
            // Check if we already have an entry for this fd
            bool merged = false;
            for (int j = 0; j < count; ++j) {
                if (results[j].fd == fd) {
                    results[j].events |= flags;
                    merged = true;
                    break;
                }
            }
            
            if (!merged) {
                results[count].fd = fd;
                results[count].events = flags;
                ++count;
            }
        }
        
        return count;
    }
    
    const char* name() const override { return "kqueue"; }
    
private:
    int kqfd_ = -1;
    std::set<socket_t> registered_;  ///< Track registered fds
    
    bool apply_changes(socket_t fd, uint32_t events, uint16_t kq_flags) {
        struct kevent changes[2];
        int nchanges = 0;
        
        if (events & PollIn) {
            EV_SET(&changes[nchanges++], fd, EVFILT_READ, kq_flags, 0, 0, nullptr);
        }
        if (events & PollOut) {
            EV_SET(&changes[nchanges++], fd, EVFILT_WRITE, kq_flags, 0, 0, nullptr);
        }
        
        if (nchanges == 0) return true;
        
        if (kevent(kqfd_, changes, nchanges, nullptr, 0, nullptr) < 0) {
            LOG_POLLER_ERROR("kevent add/modify failed for fd " + std::to_string(fd) + 
                            ": " + std::string(strerror(errno)));
            return false;
        }
        return true;
    }
};

#endif // POLLER_USE_KQUEUE

//=============================================================================
// Windows: IOCP (I/O Completion Ports) implementation
//=============================================================================
//
// Architecture:
//   Connected sockets use zero-byte overlapped WSARecv/WSASend to get
//   readiness notifications through the IOCP completion port (proactor
//   model adapted to reactor semantics).
//
//   Listen sockets and connecting sockets (where overlapped recv/send
//   cannot be used) fall back to a non-blocking WSAPoll check done
//   inside wait() — typically only 1 listen + ~30 connecting sockets,
//   so this is negligible overhead.
//
//   When send_to_peer() on another thread arms a write via modify(),
//   the zero-byte WSASend completes and wakes GQCS immediately —
//   the I/O thread gets notified with zero latency.
//
//   Memory safety: SocketState objects are never freed while IOCP
//   operations may reference them (they are kept alive in all_states_).
//   Removed sockets are marked with removed=true and their completions
//   are silently discarded in wait().
//=============================================================================

#if defined(POLLER_USE_IOCP)

class IocpPoller final : public IOPoller {
public:
    IocpPoller() {
        iocp_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        if (!iocp_) {
            LOG_POLLER_ERROR("CreateIoCompletionPort failed: " + 
                            std::to_string(GetLastError()));
        } else {
            LOG_POLLER_INFO("Created IOCP poller");
        }
    }
    
    ~IocpPoller() override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            // Cancel all pending I/O before destroying
            for (auto& [fd, state] : active_) {
                if (state->read_pending || state->write_pending) {
                    CancelIoEx(reinterpret_cast<HANDLE>(fd), nullptr);
                }
            }
            active_.clear();
            all_states_.clear();
        }
        if (iocp_) {
            CloseHandle(iocp_);
            iocp_ = nullptr;
        }
    }
    
    bool add(socket_t fd, uint32_t events) override {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto state_ptr = std::make_unique<IocpSocketState>(fd);
        auto* state = state_ptr.get();
        state->desired_events = events;
        
        // Associate socket with IOCP (needed for overlapped I/O)
        CreateIoCompletionPort(reinterpret_cast<HANDLE>(fd), iocp_, 0, 0);
        
        // Determine socket mode:
        // - Try zero-byte WSARecv to detect if socket is connected (IOCP mode)
        // - Listen sockets and connecting sockets use WSAPoll fallback
        if (events & PollIn) {
            if (arm_read(state)) {
                state->mode = SocketMode::Iocp;
            } else {
                // WSARecv failed (WSAENOTCONN) — listen socket or not yet connected
                state->mode = SocketMode::WsaPoll;
            }
        } else {
            // PollOut only → connecting socket → WSAPoll mode
            state->mode = SocketMode::WsaPoll;
        }
        
        // Arm write notification if IOCP mode and interested
        if (state->mode == SocketMode::Iocp && (events & PollOut)) {
            arm_write(state);
        }
        
        active_[fd] = state;
        all_states_.push_back(std::move(state_ptr));
        
        return true;
    }
    
    bool modify(socket_t fd, uint32_t events) override {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = active_.find(fd);
        if (it == active_.end()) return false;
        auto* state = it->second;
        if (state->removed) return false;
        
        state->desired_events = events;
        
        // Transition WSAPoll → IOCP when PollIn is added
        // (connecting socket completed its TCP handshake and became connected)
        if (state->mode == SocketMode::WsaPoll && (events & PollIn)) {
            if (arm_read(state)) {
                state->mode = SocketMode::Iocp;
            }
        }
        
        // Arm overlapped ops as needed for IOCP-mode sockets
        if (state->mode == SocketMode::Iocp) {
            if ((events & PollIn) && !state->read_pending) {
                arm_read(state);
            }
            if ((events & PollOut) && !state->write_pending) {
                arm_write(state);
            }
        }
        
        return true;
    }
    
    bool remove(socket_t fd) override {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = active_.find(fd);
        if (it == active_.end()) return false;
        
        auto* state = it->second;
        state->removed = true;
        state->desired_events = 0;
        
        // Cancel pending I/O — completions will arrive with error status
        // and will be discarded because state->removed is true.
        if (state->read_pending || state->write_pending) {
            CancelIoEx(reinterpret_cast<HANDLE>(fd), nullptr);
        }
        
        active_.erase(it);
        ++removed_count_;
        // Note: SocketState is NOT freed yet — it stays in all_states_ so
        // that the OVERLAPPED pointers remain valid until cancelled
        // completions are dequeued from GQCS.  gc_removed_states() will
        // free it once no I/O is in flight.
        return true;
    }
    
    int wait(PollResult* results, int max_results, int timeout_ms) override {
        int count = 0;
        
        //------------------------------------------------------------------
        // Step 1: Check WSAPoll-mode sockets (listen + connecting)
        //         Non-blocking check (timeout=0), typically <= 31 sockets
        //------------------------------------------------------------------
        {
            std::lock_guard<std::mutex> lock(mutex_);
            count = check_wsapoll_sockets(results, max_results);
        }
        
        //------------------------------------------------------------------
        // Step 2: Wait for IOCP completions (connected data sockets)
        //         If Step 1 already found events, don't block (timeout=0)
        //------------------------------------------------------------------
        static constexpr ULONG MAX_ENTRIES = 128;
        OVERLAPPED_ENTRY entries[MAX_ENTRIES];
        ULONG iocp_count = 0;
        
        DWORD iocp_timeout = (count > 0) ? 0 : static_cast<DWORD>(timeout_ms);
        ULONG max_dequeue = static_cast<ULONG>(
            (std::min)(static_cast<int>(MAX_ENTRIES), max_results - count));
        
        if (max_dequeue > 0 && iocp_) {
            BOOL ok = GetQueuedCompletionStatusEx(
                iocp_, entries, max_dequeue, &iocp_count, iocp_timeout, FALSE);
            
            if (!ok) {
                DWORD err = GetLastError();
                if (err != WAIT_TIMEOUT && err != ERROR_ABANDONED_WAIT_0) {
                    LOG_POLLER_ERROR("GQCS failed: " + std::to_string(err));
                }
                iocp_count = 0;
            }
        }
        
        //------------------------------------------------------------------
        // Step 3: Process IOCP completions into PollResults
        //         Also GC removed states once their I/O has drained.
        //------------------------------------------------------------------
        if (iocp_count > 0) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (ULONG i = 0; i < iocp_count && count < max_results; ++i) {
                if (!entries[i].lpOverlapped) continue;
                
                auto* io = reinterpret_cast<IocpOverlapped*>(entries[i].lpOverlapped);
                auto* state = io->state;
                if (!state) continue;
                
                // Mark the overlapped operation as completed (even for removed states,
                // so GC can later free them once no I/O is in flight)
                if (io->event_type & PollIn)  state->read_pending = false;
                if (io->event_type & PollOut) state->write_pending = false;
                
                if (state->removed) continue;
                
                // Check the NTSTATUS from the overlapped result
                // 0 = STATUS_SUCCESS, non-zero = error (e.g. connection reset)
                ULONG_PTR internal_status = io->overlapped.Internal;
                
                uint32_t reported_events = 0;
                if (internal_status == 0) {
                    // Success — report readiness for the event type we were watching
                    reported_events = io->event_type & state->desired_events;
                    
                    // Re-arm overlapped I/O for next notification.
                    // Without this, the socket becomes deaf after the first
                    // completion because sync_poller() only calls modify()
                    // when desired_events change — which they don't for a
                    // socket that stays PollIn-only.
                    if ((io->event_type & PollIn) && (state->desired_events & PollIn)) {
                        arm_read(state);
                    }
                    if ((io->event_type & PollOut) && (state->desired_events & PollOut)) {
                        arm_write(state);
                    }
                } else {
                    // I/O error (connection reset, cancelled, etc.)
                    reported_events = PollErr;
                }
                
                if (reported_events == 0) continue;
                
                // Merge events for the same fd (read + write may fire together)
                bool merged = false;
                for (int j = 0; j < count; ++j) {
                    if (results[j].fd == state->fd) {
                        results[j].events |= reported_events;
                        merged = true;
                        break;
                    }
                }
                if (!merged) {
                    results[count].fd = state->fd;
                    results[count].events = reported_events;
                    ++count;
                }
            }
            
            // GC removed states whose cancelled I/O has fully drained.
            // Threshold: at least 64 removed, or removed > half of total —
            // avoids running the sweep on every wait() call.
            if (removed_count_ >= 64 ||
                (removed_count_ > 0 && removed_count_ * 2 >= all_states_.size())) {
                gc_removed_states();
            }
        }
        
        return count;
    }
    
    const char* name() const override { return "IOCP"; }
    
private:
    HANDLE iocp_ = nullptr;
    
    /// Socket operating mode
    enum class SocketMode {
        WsaPoll,  ///< Listen/connecting socket — checked via WSAPoll
        Iocp      ///< Connected socket — uses overlapped zero-byte I/O
    };
    
    struct IocpSocketState;  // Forward declaration
    
    /// Extended OVERLAPPED that carries back-pointers for GQCS dispatch
    struct IocpOverlapped {
        OVERLAPPED overlapped;          ///< Must be first member (cast compatibility)
        IocpSocketState* state;         ///< Owning socket state
        uint32_t event_type;            ///< PollIn or PollOut
        
        IocpOverlapped() : state(nullptr), event_type(0) {
            std::memset(&overlapped, 0, sizeof(overlapped));
        }
    };
    
    /// Per-socket tracking state
    struct IocpSocketState {
        socket_t fd;
        uint32_t desired_events;
        SocketMode mode;
        bool read_pending;              ///< Zero-byte WSARecv in flight
        bool write_pending;             ///< Zero-byte WSASend in flight
        bool removed;                   ///< Marked for removal
        IocpOverlapped read_io;         ///< Overlapped for read notification
        IocpOverlapped write_io;        ///< Overlapped for write notification
        
        explicit IocpSocketState(socket_t f)
            : fd(f), desired_events(0), mode(SocketMode::WsaPoll),
              read_pending(false), write_pending(false), removed(false) {
            read_io.state = this;
            read_io.event_type = PollIn;
            write_io.state = this;
            write_io.event_type = PollOut;
        }
    };
    
    std::mutex mutex_;
    std::unordered_map<socket_t, IocpSocketState*> active_;     ///< fd → state lookup
    std::vector<std::unique_ptr<IocpSocketState>> all_states_;  ///< Owns all states
    std::vector<WSAPOLLFD> wsapoll_fds_;                    ///< Reusable WSAPoll buffer
    size_t removed_count_ = 0;                              ///< Number of removed states awaiting GC
    
    //----------------------------------------------------------------------
    // Zero-byte overlapped I/O: readiness notification via IOCP
    //----------------------------------------------------------------------
    
    /// Post a zero-byte WSARecv. Completes when data is available to read.
    /// Returns false if the socket is not connected (listen socket).
    bool arm_read(IocpSocketState* state) {
        if (state->read_pending) return true;
        
        std::memset(&state->read_io.overlapped, 0, sizeof(OVERLAPPED));
        
        WSABUF buf;
        buf.buf = nullptr;
        buf.len = 0;
        DWORD flags = 0;
        DWORD bytes = 0;
        
        int ret = WSARecv(state->fd, &buf, 1, &bytes, &flags,
                          &state->read_io.overlapped, nullptr);
        
        if (ret == 0) {
            // Completed immediately — completion still posted to IOCP
            state->read_pending = true;
            return true;
        }
        
        int err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
            state->read_pending = true;
            return true;
        }
        
        // WSAENOTCONN (10057) = listen socket, can't do WSARecv
        // Other errors also mean we can't use IOCP mode for this socket
        return false;
    }
    
    /// Post a zero-byte WSASend. Completes when send buffer has space.
    /// Also wakes GQCS when called from another thread (via modify/send_to_peer).
    bool arm_write(IocpSocketState* state) {
        if (state->write_pending) return true;
        
        std::memset(&state->write_io.overlapped, 0, sizeof(OVERLAPPED));
        
        WSABUF buf;
        buf.buf = nullptr;
        buf.len = 0;
        DWORD bytes = 0;
        
        int ret = WSASend(state->fd, &buf, 1, &bytes, 0,
                          &state->write_io.overlapped, nullptr);
        
        if (ret == 0) {
            state->write_pending = true;
            return true;
        }
        
        int err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
            state->write_pending = true;
            return true;
        }
        
        return false;
    }
    
    //----------------------------------------------------------------------
    // GC: free removed states whose I/O has fully drained. Called under mutex.
    //----------------------------------------------------------------------
    
    void gc_removed_states() {
        if (removed_count_ == 0) return;
        
        size_t before = all_states_.size();
        all_states_.erase(
            std::remove_if(all_states_.begin(), all_states_.end(),
                [](const std::unique_ptr<IocpSocketState>& s) {
                    return s->removed && !s->read_pending && !s->write_pending;
                }),
            all_states_.end());
        
        size_t freed = before - all_states_.size();
        if (freed > 0) {
            removed_count_ -= freed;
        }
    }
    
    //----------------------------------------------------------------------
    // WSAPoll fallback for listen + connecting sockets
    //----------------------------------------------------------------------
    
    /// Non-blocking check of WSAPoll-mode sockets. Called under mutex.
    int check_wsapoll_sockets(PollResult* results, int max_results) {
        wsapoll_fds_.clear();
        
        for (auto& [fd, state] : active_) {
            if (state->removed || state->mode != SocketMode::WsaPoll) continue;
            
            WSAPOLLFD pfd;
            pfd.fd = fd;
            pfd.events = 0;
            if (state->desired_events & PollIn)  pfd.events |= POLLIN;
            if (state->desired_events & PollOut) pfd.events |= POLLOUT;
            pfd.revents = 0;
            
            wsapoll_fds_.push_back(pfd);
        }
        
        if (wsapoll_fds_.empty()) return 0;
        
        // Non-blocking poll (timeout = 0)
        int n = WSAPoll(wsapoll_fds_.data(),
                        static_cast<ULONG>(wsapoll_fds_.size()), 0);
        if (n <= 0) return 0;
        
        int count = 0;
        for (auto& pfd : wsapoll_fds_) {
            if (count >= max_results) break;
            if (pfd.revents == 0) continue;
            
            uint32_t events = 0;
            if (pfd.revents & POLLIN)  events |= PollIn;
            if (pfd.revents & POLLOUT) events |= PollOut;
            if (pfd.revents & POLLERR) events |= PollErr;
            if (pfd.revents & POLLHUP) events |= PollHup;
            
            results[count].fd = pfd.fd;
            results[count].events = events;
            ++count;
        }
        
        return count;
    }
};

#endif // POLLER_USE_IOCP

//=============================================================================
// POSIX fallback: poll() implementation
//=============================================================================

#if defined(POLLER_USE_POLL)

#include <mutex>
#include <unordered_map>
#include <vector>

class PollPoller final : public IOPoller {
public:
    PollPoller() {
        LOG_POLLER_INFO("Created poll() poller");
    }
    
    ~PollPoller() override = default;
    
    bool add(socket_t fd, uint32_t events) override {
        std::lock_guard<std::mutex> lock(mutex_);
        registered_[fd] = events;
        dirty_ = true;
        return true;
    }
    
    bool modify(socket_t fd, uint32_t events) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = registered_.find(fd);
        if (it == registered_.end()) return false;
        it->second = events;
        dirty_ = true;
        return true;
    }
    
    bool remove(socket_t fd) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto erased = registered_.erase(fd);
        dirty_ = true;
        return erased > 0;
    }
    
    int wait(PollResult* results, int max_results, int timeout_ms) override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (dirty_) {
                rebuild_pollfd_array();
                dirty_ = false;
            }
        }
        
        if (pollfds_.empty()) {
            if (timeout_ms > 0) {
                struct timespec ts;
                ts.tv_sec = timeout_ms / 1000;
                ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
                nanosleep(&ts, nullptr);
            }
            return 0;
        }
        
        int n = poll(pollfds_.data(), static_cast<nfds_t>(pollfds_.size()), timeout_ms);
        
        if (n < 0) {
            if (errno != EINTR) {
                LOG_POLLER_ERROR("poll() failed: " + std::string(strerror(errno)));
            }
            return -1;
        }
        
        if (n == 0) return 0;
        
        int count = 0;
        for (size_t i = 0; i < pollfds_.size() && count < max_results; ++i) {
            if (pollfds_[i].revents == 0) continue;
            
            results[count].fd = pollfds_[i].fd;
            results[count].events = 0;
            if (pollfds_[i].revents & POLLIN)  results[count].events |= PollIn;
            if (pollfds_[i].revents & POLLOUT) results[count].events |= PollOut;
            if (pollfds_[i].revents & POLLERR) results[count].events |= PollErr;
            if (pollfds_[i].revents & POLLHUP) results[count].events |= PollHup;
            ++count;
        }
        
        return count;
    }
    
    const char* name() const override { return "poll"; }
    
private:
    std::mutex mutex_;
    std::unordered_map<socket_t, uint32_t> registered_;
    std::vector<struct pollfd> pollfds_;
    bool dirty_ = false;
    
    void rebuild_pollfd_array() {
        pollfds_.clear();
        pollfds_.reserve(registered_.size());
        
        for (auto& [fd, events] : registered_) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = 0;
            if (events & PollIn)  pfd.events |= POLLIN;
            if (events & PollOut) pfd.events |= POLLOUT;
            pfd.revents = 0;
            pollfds_.push_back(pfd);
        }
    }
};

#endif // POLLER_USE_POLL

//=============================================================================
// Factory
//=============================================================================

std::unique_ptr<IOPoller> IOPoller::create() {
#if defined(POLLER_USE_EPOLL)
    return std::make_unique<EpollPoller>();
#elif defined(POLLER_USE_KQUEUE)
    return std::make_unique<KqueuePoller>();
#elif defined(POLLER_USE_IOCP)
    return std::make_unique<IocpPoller>();
#elif defined(POLLER_USE_POLL)
    return std::make_unique<PollPoller>();
#else
    #error "No I/O multiplexer available for this platform"
#endif
}

} // namespace librats
