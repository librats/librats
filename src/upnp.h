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
#include "wakeup_pipe.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <chrono>

namespace librats {

/**
 * Pure parsing helpers used by the UPnP client. Exposed (rather than file-local)
 * so the SSDP/SOAP XML and URL handling — the most error-prone part of the
 * protocol — can be unit tested directly.
 */
namespace upnp_detail {

/// Extract the trimmed text of the first <tag ...>...</tag> (case-insensitive),
/// searching from @p from. Returns "" when the tag is absent.
std::string extract_xml_tag(const std::string& xml, const std::string& tag, size_t from = 0);

/// Parse "http://host[:port][/path]". Defaults port to 80 and path to "/".
/// Returns false if the scheme is missing or the host is empty.
bool parse_http_url(const std::string& url, std::string& host, uint16_t& port, std::string& path);

/// Resolve a device's controlURL (which may be absolute, root-relative or
/// path-relative) into an absolute http URL. @p url_base is the device's optional
/// <URLBase>; @p desc_host / @p desc_port are the host the description was fetched
/// from, used when no URLBase is present.
std::string resolve_control_url(std::string control_url, std::string url_base,
                                const std::string& desc_host, uint16_t desc_port);

} // namespace upnp_detail

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

    // SOAP helper: POST an action to the device control URL. Returns true only on
    // a successful (HTTP 200, no SOAP fault) response. When the IGD reports a UPnP
    // error, *upnp_error receives its numeric code (e.g. 718 conflict, 725 permanent
    // lease only) so the caller can react; it is set to 0 on success.
    bool soap_action(const Device& dev, const std::string& action,
                     const std::string& body_args, std::string& response_body,
                     int* upnp_error = nullptr);

    PortMapCallback callback_;
    uint32_t lease_duration_ = UPNP_DEFAULT_LEASE;
    // Set once an IGD rejects a timed lease with error 725; subsequent requests ask
    // for a permanent (0) lease. Touched only from the worker thread.
    bool permanent_lease_only_ = false;

    mutable std::mutex mutex_;          // guards mappings_, external_ip_, device_
    std::vector<Mapping> mappings_;
    std::string external_ip_;
    Device device_;
    bool device_found_ = false;

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::condition_variable cv_;
    std::mutex cv_mutex_;
    // Set under cv_mutex_ to break the refresh sleep early when a mapping is added
    // or stop() is requested. Guarding it with the same mutex the worker waits on
    // is what makes the wakeup race-free (no lost notifications).
    bool wake_worker_ = false;
    WakeupPipe wakeup_;                 // interrupts blocking SSDP receives on stop()
    std::thread worker_;
};

} // namespace librats
