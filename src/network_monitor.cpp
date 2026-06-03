/**
 * @file network_monitor.cpp
 * @brief Platform backends for NetworkMonitor (see network_monitor.h).
 */

// socket.h pulls in winsock2.h/ws2tcpip.h first on Windows (must precede the
// iphlpapi / windows headers below to avoid the classic winsock2/windows.h clash).
#include "socket.h"
#include "network_monitor.h"
#include "network_utils.h"
#include "logger.h"

#include <algorithm>

#ifdef _WIN32
    #include <iphlpapi.h>
    #include <netioapi.h>
#elif defined(__linux__)
    #include <sys/socket.h>
    #include <linux/netlink.h>
    #include <linux/rtnetlink.h>
    #include <unistd.h>
    #include <poll.h>
    #include <cstring>
    #include <cerrno>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
      defined(__OpenBSD__) || defined(__DragonFly__)
    #define RATS_MONITOR_BSD_ROUTES 1
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <net/route.h>
    #include <net/if.h>
    #include <unistd.h>
    #include <poll.h>
    #include <cerrno>
#endif

#define LOG_NETMON_DEBUG(message) LOG_DEBUG("netmon", message)
#define LOG_NETMON_INFO(message)  LOG_INFO("netmon", message)
#define LOG_NETMON_WARN(message)  LOG_WARN("netmon", message)
#define LOG_NETMON_ERROR(message) LOG_ERROR("netmon", message)

namespace librats {

namespace {

std::vector<std::string> snapshot_addresses() {
    auto addrs = network_utils::get_local_interface_addresses();
    std::sort(addrs.begin(), addrs.end());
    addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
    return addrs;
}

} // namespace

// ============================================================================
// Platform backend state
// ============================================================================

struct NetworkMonitor::Impl {
#ifdef _WIN32
    HANDLE handle = nullptr;
#elif defined(__linux__) || defined(RATS_MONITOR_BSD_ROUTES)
    int fd = -1;            // netlink (Linux) or PF_ROUTE (BSD) socket
    int stop_pipe[2] = {-1, -1};
    std::thread reader;
#endif
};

#ifdef _WIN32
// NotifyUnicastIpAddressChange invokes this from an OS worker thread on any
// unicast address add/remove/change. Windows gives no usable detail here, so we
// just trigger a re-enumeration (matches the cross-platform "something changed"
// contract). Must be __stdcall (WINAPI) to match PUNICAST_IPADDRESS_CHANGE_CALLBACK.
static void WINAPI rats_ip_change_cb(void* ctx, MIB_UNICASTIPADDRESS_ROW* /*row*/,
                                     MIB_NOTIFICATION_TYPE /*type*/) {
    auto* self = static_cast<NetworkMonitor*>(ctx);
    if (self) self->check_now();
}
#endif

// ============================================================================
// Lifecycle
// ============================================================================

NetworkMonitor::NetworkMonitor() = default;

NetworkMonitor::~NetworkMonitor() {
    stop();
}

bool NetworkMonitor::start(ChangeCallback on_change) {
    if (running_.exchange(true)) {
        return event_backend_active_;
    }
    on_change_ = std::move(on_change);
    impl_ = std::make_unique<Impl>();
    last_addresses_ = snapshot_addresses();

    event_backend_active_ = backend_start();
    LOG_NETMON_INFO("Network monitor started ("
                    << (event_backend_active_ ? "event-driven" : "polling")
                    << ", " << last_addresses_.size() << " local address(es))");

    worker_ = std::thread([this]() { worker_loop(); });
    return event_backend_active_;
}

void NetworkMonitor::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    cv_.notify_all();   // wake the worker out of its wait
    backend_stop();     // stop OS notifications / join the reader thread
    if (worker_.joinable()) {
        worker_.join();
    }
    impl_.reset();
    event_backend_active_ = false;
    LOG_NETMON_INFO("Network monitor stopped");
}

void NetworkMonitor::check_now() {
    if (!running_.load()) return;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        change_pending_ = true;
    }
    cv_.notify_all();
}

// ============================================================================
// Worker: debounce + diff + dispatch
// ============================================================================

void NetworkMonitor::worker_loop() {
    // When push notifications are active, the long interval is just a safety net
    // for events the OS might drop (e.g. across suspend/resume). Without them,
    // this interval is the actual detection latency.
    const auto poll_interval = event_backend_active_
        ? std::chrono::milliseconds(30000)
        : std::chrono::milliseconds(5000);

    while (running_.load()) {
        bool was_event = false;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait_for(lock, poll_interval,
                         [this]() { return !running_.load() || change_pending_; });
            if (!running_.load()) break;

            was_event = change_pending_;
            change_pending_ = false;

            if (was_event) {
                // Coalesce the burst: wait out a quiet debounce window (only a
                // stop interrupts it), then drop any events that arrived during it.
                cv_.wait_for(lock, debounce_, [this]() { return !running_.load(); });
                if (!running_.load()) break;
                change_pending_ = false;
            }
        }

        auto current = snapshot_addresses();
        if (current != last_addresses_) {
            LOG_NETMON_INFO("Local address set changed (" << last_addresses_.size()
                            << " -> " << current.size() << ")");
            last_addresses_ = current;
            if (on_change_) {
                on_change_(current);
            }
        } else if (was_event) {
            LOG_NETMON_DEBUG("Network event with no effective address change; ignored");
        }
    }
}

// ============================================================================
// Windows backend: NotifyUnicastIpAddressChange
// ============================================================================
#ifdef _WIN32

bool NetworkMonitor::backend_start() {
    DWORD rv = NotifyUnicastIpAddressChange(AF_UNSPEC, &rats_ip_change_cb, this,
                                            FALSE, &impl_->handle);
    if (rv != NO_ERROR) {
        LOG_NETMON_WARN("NotifyUnicastIpAddressChange failed (" << rv
                        << "); falling back to polling");
        impl_->handle = nullptr;
        return false;
    }
    return true;
}

void NetworkMonitor::backend_stop() {
    if (impl_ && impl_->handle != nullptr) {
        // Cancels and waits for any in-flight callback to return, so no callback
        // can run against a half-destroyed monitor afterwards.
        CancelMibChangeNotify2(impl_->handle);
        impl_->handle = nullptr;
    }
}

// ============================================================================
// Linux backend: NETLINK_ROUTE socket
// ============================================================================
#elif defined(__linux__)

bool NetworkMonitor::backend_start() {
    int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        LOG_NETMON_WARN("netlink socket() failed (" << errno << "); falling back to polling");
        return false;
    }

    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
                   | RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_NETMON_WARN("netlink bind() failed (" << errno << "); falling back to polling");
        ::close(fd);
        return false;
    }

    if (::pipe(impl_->stop_pipe) < 0) {
        ::close(fd);
        return false;
    }
    impl_->fd = fd;

    impl_->reader = std::thread([this]() {
        char buf[4096];
        struct pollfd fds[2];
        fds[0].fd = impl_->fd;        fds[0].events = POLLIN;
        fds[1].fd = impl_->stop_pipe[0]; fds[1].events = POLLIN;

        while (running_.load()) {
            int pr = ::poll(fds, 2, -1);
            if (pr < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (fds[1].revents & POLLIN) break;   // stop requested
            if (!(fds[0].revents & POLLIN)) continue;

            ssize_t len = ::recv(impl_->fd, buf, sizeof(buf), 0);
            if (len <= 0) {
                // ENOBUFS just means we missed messages under load — treat as a change.
                if (len < 0 && errno == ENOBUFS) { check_now(); continue; }
                if (len < 0 && errno == EINTR) continue;
                break;
            }

            bool pertinent = false;
            for (auto* nh = reinterpret_cast<nlmsghdr*>(buf);
                 NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
                switch (nh->nlmsg_type) {
                    case RTM_NEWADDR: case RTM_DELADDR:
                    case RTM_NEWLINK: case RTM_DELLINK:
                    case RTM_NEWROUTE: case RTM_DELROUTE:
                        pertinent = true;
                        break;
                    default:
                        break;
                }
            }
            if (pertinent) check_now();
        }
    });
    return true;
}

void NetworkMonitor::backend_stop() {
    if (!impl_) return;
    if (impl_->stop_pipe[1] >= 0) {
        char b = 1;
        ssize_t n = ::write(impl_->stop_pipe[1], &b, 1);
        (void)n;
    }
    if (impl_->reader.joinable()) impl_->reader.join();
    if (impl_->fd >= 0) { ::close(impl_->fd); impl_->fd = -1; }
    if (impl_->stop_pipe[0] >= 0) { ::close(impl_->stop_pipe[0]); impl_->stop_pipe[0] = -1; }
    if (impl_->stop_pipe[1] >= 0) { ::close(impl_->stop_pipe[1]); impl_->stop_pipe[1] = -1; }
}

// ============================================================================
// macOS / BSD backend: PF_ROUTE routing socket
// ============================================================================
#elif defined(RATS_MONITOR_BSD_ROUTES)

bool NetworkMonitor::backend_start() {
    int fd = ::socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (fd < 0) {
        LOG_NETMON_WARN("PF_ROUTE socket() failed (" << errno << "); falling back to polling");
        return false;
    }
    if (::pipe(impl_->stop_pipe) < 0) {
        ::close(fd);
        return false;
    }
    impl_->fd = fd;

    impl_->reader = std::thread([this]() {
        char buf[2048];
        struct pollfd fds[2];
        fds[0].fd = impl_->fd;           fds[0].events = POLLIN;
        fds[1].fd = impl_->stop_pipe[0]; fds[1].events = POLLIN;

        while (running_.load()) {
            int pr = ::poll(fds, 2, -1);
            if (pr < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (fds[1].revents & POLLIN) break;   // stop requested
            if (!(fds[0].revents & POLLIN)) continue;

            ssize_t len = ::read(impl_->fd, buf, sizeof(buf));
            if (len <= 0) {
                if (len < 0 && errno == EINTR) continue;
                break;
            }
            if (static_cast<size_t>(len) < sizeof(rt_msghdr)) continue;

            auto* rtm = reinterpret_cast<rt_msghdr*>(buf);
            switch (rtm->rtm_type) {
                case RTM_NEWADDR: case RTM_DELADDR:
                case RTM_IFINFO:
#ifdef RTM_IFANNOUNCE
                case RTM_IFANNOUNCE:
#endif
                case RTM_ADD: case RTM_DELETE: case RTM_CHANGE:
                    check_now();
                    break;
                default:
                    break;
            }
        }
    });
    return true;
}

void NetworkMonitor::backend_stop() {
    if (!impl_) return;
    if (impl_->stop_pipe[1] >= 0) {
        char b = 1;
        ssize_t n = ::write(impl_->stop_pipe[1], &b, 1);
        (void)n;
    }
    if (impl_->reader.joinable()) impl_->reader.join();
    if (impl_->fd >= 0) { ::close(impl_->fd); impl_->fd = -1; }
    if (impl_->stop_pipe[0] >= 0) { ::close(impl_->stop_pipe[0]); impl_->stop_pipe[0] = -1; }
    if (impl_->stop_pipe[1] >= 0) { ::close(impl_->stop_pipe[1]); impl_->stop_pipe[1] = -1; }
}

// ============================================================================
// Fallback backend: polling only (worker_loop diffs on its poll interval)
// ============================================================================
#else

bool NetworkMonitor::backend_start() { return false; }
void NetworkMonitor::backend_stop()  {}

#endif

} // namespace librats
