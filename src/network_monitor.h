#pragma once

/**
 * @file network_monitor.h
 * @brief Detects host network configuration changes (IP / interface / route).
 *
 * When the machine's connectivity changes — a new interface comes up, an IP
 * address is added or removed, the default route flips (Wi-Fi <-> cellular,
 * dock/undock, VPN up/down, wake-from-sleep) — a long-lived P2P node must react:
 * re-create router port mappings, re-discover its public address via STUN, and
 * re-announce to the DHT. Otherwise it keeps advertising a stale, unreachable
 * endpoint until the next periodic refresh.
 *
 * NetworkMonitor provides an event-driven signal for exactly that. The design
 * mirrors libtorrent's aux::ip_notifier but is adapted to librats' own threading
 * model (no boost::asio): each platform backend only signals "something changed",
 * and the monitor itself re-enumerates the local interface addresses and invokes
 * the callback ONLY when the address set actually differs. Bursts of OS events
 * (a single interface transition typically emits several) are coalesced with a
 * short debounce window.
 *
 * Platform backends:
 *   - Windows:    NotifyUnicastIpAddressChange()        (iphlpapi)
 *   - Linux:      NETLINK_ROUTE socket, RTMGRP_*_IFADDR / *_LINK groups
 *   - macOS/BSD:  PF_ROUTE routing socket
 *   - otherwise:  periodic polling of the interface address list
 *
 * The callback runs on the monitor's worker thread, so it must not block for
 * long; offload slow recovery work (STUN, port mapping) to another thread.
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace librats {

class NetworkMonitor {
public:
    /// Invoked (debounced) whenever the set of local interface addresses changes.
    /// @param current_addresses the new, full list of local interface addresses.
    using ChangeCallback = std::function<void(const std::vector<std::string>& current_addresses)>;

    NetworkMonitor();
    ~NetworkMonitor();

    NetworkMonitor(const NetworkMonitor&) = delete;
    NetworkMonitor& operator=(const NetworkMonitor&) = delete;

    /**
     * Start monitoring. The callback fires on each detected change (after the
     * debounce window) on the monitor's worker thread.
     *
     * @return true if an OS push-notification backend is active; false if the
     *         monitor fell back to periodic polling. The monitor works either
     *         way, so the return value is informational only.
     */
    bool start(ChangeCallback on_change);

    /// Stop monitoring and join the worker thread. Idempotent.
    void stop();

    bool is_running() const { return running_.load(); }

    /// Whether OS push notifications (vs. polling) are in use. Valid after start().
    bool is_event_driven() const { return event_backend_active_; }

    /**
     * Request an immediate re-check, coalesced/debounced exactly like a real OS
     * event. Thread-safe. Useful to call after the device wakes from sleep, or
     * from the platform backends themselves. A no-op if not running.
     */
    void check_now();

    /// Override the debounce window used to coalesce event bursts (default 2s).
    void set_debounce(std::chrono::milliseconds d) { debounce_ = d; }

private:
    void worker_loop();
    bool backend_start();   // set up the OS notifier; returns true if event-driven
    void backend_stop();    // tear the OS notifier / reader thread down

    ChangeCallback on_change_;
    std::atomic<bool> running_{false};
    bool change_pending_ = false;        // guarded by mutex_
    bool event_backend_active_ = false;  // true once an OS backend is confirmed up
    std::thread worker_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::chrono::milliseconds debounce_{2000};
    std::vector<std::string> last_addresses_;

    // Platform-specific backend state (fds, OS handles, reader thread).
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace librats
