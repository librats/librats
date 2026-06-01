#pragma once

/**
 * @file upnp.h
 * @brief UPnP Internet Gateway Device (IGD) port mapping client
 *
 * Implements the client side of automatic port forwarding via UPnP:
 *   1. Discover the IGD on the LAN with an SSDP M-SEARCH (UDP multicast to
 *      239.255.255.250:1900).
 *   2. Fetch and parse the device description XML to locate the
 *      WANIPConnection / WANPPPConnection service control URL.
 *   3. Issue SOAP actions (AddPortMapping / DeletePortMapping /
 *      GetExternalIPAddress) over HTTP to the control URL.
 *   4. Periodically refresh the mappings so the lease never expires.
 *
 * All network activity runs on a dedicated worker thread. Results are reported
 * through a @ref PortMapCallback. The implementation is self-contained (no
 * external XML/HTTP libraries) using librats' own socket primitives.
 */

#include "port_mapping.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <chrono>

namespace librats {

/// SSDP multicast address / port used to discover UPnP devices.
constexpr const char* SSDP_MULTICAST_ADDR = "239.255.255.250";
constexpr uint16_t SSDP_PORT = 1900;

/// Default UPnP lease duration in seconds (0 means request a permanent mapping).
constexpr uint32_t UPNP_DEFAULT_LEASE = 3600;

/**
 * UPnP IGD port mapping client. Thread-safe public API; all SSDP/HTTP/SOAP
 * traffic happens on the internal worker thread started by @ref start().
 */
class UpnpClient {
public:
    UpnpClient();
    ~UpnpClient();

    UpnpClient(const UpnpClient&) = delete;
    UpnpClient& operator=(const UpnpClient&) = delete;

    /**
     * Register a mapping to install. External port defaults to the internal port.
     * Safe to call before or after @ref start().
     */
    void add_mapping(PortMapProtocol protocol, uint16_t internal_port, uint16_t external_port = 0,
                     const std::string& description = "librats");

    /// Request lease duration in seconds (0 = permanent). Effective on next refresh.
    void set_lease_duration(uint32_t seconds) { lease_duration_ = seconds; }

    /// Set the result callback (invoked from the worker thread).
    void set_callback(PortMapCallback cb) { callback_ = std::move(cb); }

    /// Start discovery + mapping on the worker thread. Returns false if running.
    bool start();

    /// Remove installed mappings (best-effort) and stop the worker thread.
    void stop();

    bool is_running() const { return running_.load(); }

    /// Discovered external IP address reported by the IGD, or empty.
    std::string external_ip() const;

private:
    struct Mapping {
        PortMapProtocol protocol;
        uint16_t internal_port;
        uint16_t external_port;
        std::string description;
        bool active = false;
        std::chrono::steady_clock::time_point expires{};
    };

    // Parsed IGD endpoint discovered via SSDP + device description.
    struct Device {
        std::string control_url;        // absolute http URL of the control endpoint
        std::string service_type;       // urn:schemas-upnp-org:service:WANIPConnection:1 ...
        std::string control_host;       // host of control_url
        uint16_t    control_port = 0;   // port of control_url
        std::string control_path;       // path of control_url
        std::string local_ip;           // our LAN IP facing this device
        bool valid() const { return !control_url.empty() && !service_type.empty(); }
    };

    void worker_loop();
    bool discover_device(Device& out);          // SSDP + description fetch/parse
    bool fetch_description(const std::string& location, const std::string& local_ip, Device& out);
    bool add_port_mapping(const Device& dev, Mapping& m);
    bool delete_port_mapping(const Device& dev, const Mapping& m);
    bool query_external_ip(const Device& dev);
    void remove_all_mappings(const Device& dev);
    void notify(const Mapping& m, bool success, const std::string& error);

    // SOAP helper: POST an action to the device control URL, returns body on 200.
    bool soap_action(const Device& dev, const std::string& action,
                     const std::string& body_args, std::string& response_body);

    PortMapCallback callback_;
    uint32_t lease_duration_ = UPNP_DEFAULT_LEASE;

    mutable std::mutex mutex_;          // guards mappings_, external_ip_, device_
    std::vector<Mapping> mappings_;
    std::string external_ip_;
    Device device_;
    bool device_found_ = false;

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::condition_variable cv_;
    std::mutex cv_mutex_;
    std::thread worker_;
};

} // namespace librats
