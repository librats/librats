#pragma once

/**
 * @file natpmp.h
 * @brief NAT-PMP (NAT Port Mapping Protocol, RFC 6886) client
 *
 * NAT-PMP is the simple, Apple-originated alternative to UPnP for asking a home
 * router to forward an external port to a host on the LAN. It is a tiny binary
 * UDP protocol spoken directly to the default gateway on port 5351.
 *
 * @ref NatPmpClient discovers the gateway (or uses one supplied by the caller),
 * requests the public IPv4 address, installs the requested port mappings and
 * keeps them alive by renewing each lease before it expires, all on a dedicated
 * background thread. Results are delivered through a @ref PortMapCallback.
 *
 * Usage:
 * @code
 *   NatPmpClient natpmp;
 *   natpmp.set_callback([](const PortMapResult& r) { ... });
 *   natpmp.add_mapping(PortMapProtocol::TCP, listen_port);
 *   natpmp.start();        // discovers gateway and maps in the background
 *   ...
 *   natpmp.stop();         // removes the mappings and joins the worker
 * @endcode
 */

#include "port_mapping.h"
#include "socket.h"
#include "wakeup_pipe.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <chrono>

namespace librats {

/// Default NAT-PMP / PCP server port (the gateway listens here).
constexpr uint16_t NATPMP_PORT = 5351;

/// NAT-PMP protocol version byte (RFC 6886).
constexpr uint8_t NATPMP_VERSION = 0;

/// Default requested lease lifetime, in seconds.
constexpr uint32_t NATPMP_DEFAULT_LIFETIME = 3600;

/**
 * NAT-PMP client. Thread-safe public API; all network activity happens on an
 * internal worker thread started by @ref start().
 */
class NatPmpClient {
public:
    NatPmpClient();
    ~NatPmpClient();

    NatPmpClient(const NatPmpClient&) = delete;
    NatPmpClient& operator=(const NatPmpClient&) = delete;

    /**
     * Register a mapping to install once the client starts (or immediately, if it
     * is already running). External port defaults to the internal port.
     * @param protocol TCP or UDP
     * @param internal_port Local port to expose
     * @param external_port Suggested public port (0 = same as internal)
     */
    void add_mapping(PortMapProtocol protocol, uint16_t internal_port, uint16_t external_port = 0);

    /**
     * Set the requested lease lifetime in seconds (default 3600). Must be called
     * before start() to take effect on the initial mapping.
     */
    void set_lease_duration(uint32_t seconds) { lease_duration_ = seconds == 0 ? NATPMP_DEFAULT_LIFETIME : seconds; }

    /**
     * Override gateway auto-detection with an explicit gateway IPv4 address.
     * Pass an empty string to restore auto-detection.
     */
    void set_gateway(const std::string& gateway_ip) { forced_gateway_ = gateway_ip; }

    /// Set the result callback (invoked from the worker thread).
    void set_callback(PortMapCallback cb) { callback_ = std::move(cb); }

    /**
     * Start the background worker: discover the gateway, request the external IP
     * and install/refresh all registered mappings.
     * @return false if already running
     */
    bool start();

    /// Remove all installed mappings (best-effort) and stop the worker thread.
    void stop();

    /// Whether the worker thread is currently running.
    bool is_running() const { return running_.load(); }

    /// Discovered public IPv4 address, or empty if unknown.
    std::string external_ip() const;

private:
    struct Mapping {
        PortMapProtocol protocol;
        uint16_t internal_port;
        uint16_t external_port;       // suggested then assigned
        bool active = false;
        std::chrono::steady_clock::time_point expires{};
    };

    void worker_loop();
    bool ensure_gateway();            // pick a responding gateway
    bool request_external_ip(socket_t sock);
    bool send_map_request(socket_t sock, Mapping& m, bool remove);
    void remove_all_mappings();       // sends delete requests for active mappings
    void notify(const Mapping& m, bool success, const std::string& error);

    std::string forced_gateway_;
    std::string gateway_;
    std::string external_ip_;
    uint32_t lease_duration_ = NATPMP_DEFAULT_LIFETIME;

    PortMapCallback callback_;

    mutable std::mutex mutex_;        // guards mappings_, gateway_, external_ip_
    std::vector<Mapping> mappings_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::condition_variable cv_;
    std::mutex cv_mutex_;
    // Set under cv_mutex_ to break the refresh sleep early when a mapping is added
    // or stop() is requested. Guarding it with the same mutex the worker waits on
    // is what makes the wakeup race-free (no lost notifications).
    bool wake_worker_ = false;
    WakeupPipe wakeup_;                 // interrupts blocking gateway receives on stop()
    std::thread worker_;
};

} // namespace librats
