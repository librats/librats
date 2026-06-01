/**
 * @file upnp.cpp
 * @brief UPnP IGD port mapping client implementation
 */

#include "upnp.h"
#include "socket.h"
#include "logger.h"

#include <cstring>
#include <cstdio>
#include <algorithm>
#include <cctype>
#include <sstream>

#define LOG_UPNP_DEBUG(message) LOG_DEBUG("upnp", message)
#define LOG_UPNP_INFO(message)  LOG_INFO("upnp", message)
#define LOG_UPNP_WARN(message)  LOG_WARN("upnp", message)
#define LOG_UPNP_ERROR(message) LOG_ERROR("upnp", message)

namespace librats {

namespace {

// Service types we know how to drive, in preference order.
const char* kWantedServices[] = {
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
};

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

// Case-insensitive search for `needle` in `haystack` starting at `from`.
size_t ifind(const std::string& haystack, const std::string& needle, size_t from = 0) {
    auto it = std::search(haystack.begin() + from, haystack.end(), needle.begin(), needle.end(),
                          [](char a, char b) { return std::tolower((unsigned char)a) == std::tolower((unsigned char)b); });
    if (it == haystack.end()) return std::string::npos;
    return static_cast<size_t>(it - haystack.begin());
}

// Extract the text content of the first <tag>...</tag> (case-insensitive tag).
std::string extract_tag(const std::string& xml, const std::string& tag, size_t from = 0) {
    std::string open = "<" + tag;
    size_t s = ifind(xml, open, from);
    if (s == std::string::npos) return "";
    size_t gt = xml.find('>', s);
    if (gt == std::string::npos) return "";
    std::string close = "</" + tag + ">";
    size_t e = ifind(xml, close, gt + 1);
    if (e == std::string::npos) return "";
    std::string value = xml.substr(gt + 1, e - gt - 1);
    // trim whitespace
    size_t b = value.find_first_not_of(" \t\r\n");
    size_t en = value.find_last_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    return value.substr(b, en - b + 1);
}

// Minimal URL parser for "http://host[:port][/path]".
bool parse_http_url(const std::string& url, std::string& host, uint16_t& port, std::string& path) {
    std::string lower = to_lower(url);
    const std::string prefix = "http://";
    if (lower.compare(0, prefix.size(), prefix) != 0) return false;
    size_t host_start = prefix.size();
    size_t path_start = url.find('/', host_start);
    std::string authority = (path_start == std::string::npos)
        ? url.substr(host_start)
        : url.substr(host_start, path_start - host_start);
    path = (path_start == std::string::npos) ? "/" : url.substr(path_start);
    size_t colon = authority.find(':');
    if (colon == std::string::npos) {
        host = authority;
        port = 80;
    } else {
        host = authority.substr(0, colon);
        port = static_cast<uint16_t>(std::atoi(authority.substr(colon + 1).c_str()));
        if (port == 0) port = 80;
    }
    return !host.empty();
}

// Determine which local IPv4 address the OS would use to reach `dest_ip`.
std::string local_ip_for_destination(const std::string& dest_ip, uint16_t dest_port) {
    socket_t s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (!is_valid_socket(s)) return "";
    struct sockaddr_in dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip.c_str(), &dest.sin_addr);

    std::string result;
    if (::connect(s, reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest)) == 0) {
        struct sockaddr_in local;
        socklen_t len = sizeof(local);
        if (::getsockname(s, reinterpret_cast<struct sockaddr*>(&local), &len) == 0) {
            char ip[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip))) {
                result = ip;
            }
        }
    }
    close_socket(s);
    return result;
}

// Perform a blocking HTTP/1.1 request (Connection: close) and return the body.
// `extra_headers` must each end with CRLF. Returns false on transport failure.
bool http_request(const std::string& host, uint16_t port, const std::string& method,
                  const std::string& path, const std::string& extra_headers,
                  const std::string& body, int& status_code, std::string& response_body) {
    socket_t sock = create_tcp_client(host, port, 10000);
    if (!is_valid_socket(sock)) {
        return false;
    }

    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n"
        << "Host: " << host << ":" << port << "\r\n"
        << "Connection: close\r\n"
        << extra_headers;
    if (!body.empty()) {
        req << "Content-Length: " << body.size() << "\r\n";
    }
    req << "\r\n" << body;

    if (send_tcp_string(sock, req.str()) < 0) {
        close_socket(sock);
        return false;
    }

    std::string raw;
    while (true) {
        auto chunk = receive_tcp_data(sock, 4096);
        if (chunk.empty()) break;
        raw.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        if (raw.size() > 256 * 1024) break; // sanity cap for IGD descriptions
    }
    close_socket(sock);

    if (raw.empty()) return false;

    // Parse status line
    status_code = 0;
    size_t sp = raw.find(' ');
    if (sp != std::string::npos) {
        status_code = std::atoi(raw.substr(sp + 1, 4).c_str());
    }

    size_t header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        response_body = "";
    } else {
        response_body = raw.substr(header_end + 4);
    }
    return true;
}

} // anonymous namespace

UpnpClient::UpnpClient() = default;

UpnpClient::~UpnpClient() {
    stop();
}

void UpnpClient::add_mapping(PortMapProtocol protocol, uint16_t internal_port, uint16_t external_port,
                             const std::string& description) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& m : mappings_) {
        if (m.protocol == protocol && m.internal_port == internal_port) {
            return;
        }
    }
    Mapping m;
    m.protocol = protocol;
    m.internal_port = internal_port;
    m.external_port = external_port == 0 ? internal_port : external_port;
    m.description = description;
    mappings_.push_back(m);
    LOG_UPNP_DEBUG("Registered mapping " << to_string(protocol) << " internal=" << internal_port
                   << " external=" << m.external_port);
    if (running_.load()) {
        cv_.notify_all();
    }
}

std::string UpnpClient::external_ip() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return external_ip_;
}

bool UpnpClient::start() {
    if (running_.exchange(true)) {
        return false;
    }
    stop_requested_.store(false);
    worker_ = std::thread(&UpnpClient::worker_loop, this);
    return true;
}

void UpnpClient::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    stop_requested_.store(true);
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void UpnpClient::notify(const Mapping& m, bool success, const std::string& error) {
    if (!callback_) return;
    PortMapResult r;
    r.transport = PortMapTransport::UPnP;
    r.protocol = m.protocol;
    r.success = success;
    r.internal_port = m.internal_port;
    r.external_port = m.external_port;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        r.external_ip = external_ip_;
    }
    r.error = error;
    callback_(r);
}

bool UpnpClient::discover_device(Device& out) {
    socket_t sock = create_udp_socket(0, "", AddressFamily::IPv4);
    if (!is_valid_socket(sock)) {
        LOG_UPNP_ERROR("Failed to create SSDP socket");
        return false;
    }

    // SSDP M-SEARCH. MX=2 asks devices to spread responses over up to 2 seconds.
    std::string msearch =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        "\r\n";
    std::vector<uint8_t> payload(msearch.begin(), msearch.end());

    bool found = false;
    // Send a few bursts (UDP is lossy) and harvest responses for a few seconds.
    for (int attempt = 0; attempt < 3 && !found && !stop_requested_.load(); ++attempt) {
        send_udp_data(sock, payload, SSDP_MULTICAST_ADDR, SSDP_PORT, AddressFamily::IPv4);

        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (std::chrono::steady_clock::now() < deadline && !stop_requested_.load()) {
            Peer from;
            auto resp = receive_udp_data(sock, 2048, from, 1000);
            if (resp.empty()) continue;

            std::string text(reinterpret_cast<const char*>(resp.data()), resp.size());
            size_t loc = ifind(text, "location:");
            if (loc == std::string::npos) continue;
            size_t value_start = loc + std::string("location:").size();
            size_t line_end = text.find("\r\n", value_start);
            std::string location = text.substr(value_start, line_end - value_start);
            // trim
            size_t b = location.find_first_not_of(" \t");
            size_t e = location.find_last_not_of(" \t\r\n");
            if (b == std::string::npos) continue;
            location = location.substr(b, e - b + 1);

            std::string local_ip = local_ip_for_destination(from.ip, from.port);
            LOG_UPNP_DEBUG("SSDP reply from " << from.ip << " location=" << location);
            if (fetch_description(location, local_ip, out)) {
                found = true;
                break;
            }
        }
    }

    close_socket(sock);
    return found;
}

bool UpnpClient::fetch_description(const std::string& location, const std::string& local_ip, Device& out) {
    std::string host, path;
    uint16_t port = 0;
    if (!parse_http_url(location, host, port, path)) {
        return false;
    }

    int status = 0;
    std::string body;
    if (!http_request(host, port, "GET", path, "", "", status, body) || status != 200) {
        LOG_UPNP_DEBUG("Failed to fetch device description from " << location << " (status " << status << ")");
        return false;
    }

    // Find a usable WAN connection service and its control URL.
    std::string service_type, control_url;
    size_t pos = 0;
    while (true) {
        size_t svc_start = ifind(body, "<service", pos);
        if (svc_start == std::string::npos) break;
        size_t svc_end = ifind(body, "</service>", svc_start);
        if (svc_end == std::string::npos) break;
        std::string segment = body.substr(svc_start, svc_end - svc_start);
        std::string type = extract_tag(segment, "serviceType");
        for (const char* wanted : kWantedServices) {
            if (to_lower(type) == to_lower(wanted)) {
                std::string ctrl = extract_tag(segment, "controlURL");
                if (!ctrl.empty()) {
                    service_type = type;
                    control_url = ctrl;
                }
                break;
            }
        }
        if (!service_type.empty()) break;
        pos = svc_end + 1;
    }

    if (service_type.empty() || control_url.empty()) {
        LOG_UPNP_DEBUG("No WAN connection service found at " << location);
        return false;
    }

    // Resolve control URL: it may be absolute, or relative to <URLBase> / the
    // description host.
    std::string control_absolute;
    if (to_lower(control_url).compare(0, 7, "http://") == 0) {
        control_absolute = control_url;
    } else {
        std::string url_base = extract_tag(body, "URLBase");
        if (!url_base.empty()) {
            if (url_base.back() == '/' && !control_url.empty() && control_url.front() == '/') {
                url_base.pop_back();
            }
            // URLBase is typically http://host:port
            if (control_url.front() != '/') control_url = "/" + control_url;
            control_absolute = url_base + control_url;
        } else {
            if (control_url.front() != '/') control_url = "/" + control_url;
            control_absolute = "http://" + host + ":" + std::to_string(port) + control_url;
        }
    }

    std::string c_host, c_path;
    uint16_t c_port = 0;
    if (!parse_http_url(control_absolute, c_host, c_port, c_path)) {
        return false;
    }

    out.control_url = control_absolute;
    out.service_type = service_type;
    out.control_host = c_host;
    out.control_port = c_port;
    out.control_path = c_path;
    out.local_ip = !local_ip.empty() ? local_ip : local_ip_for_destination(c_host, c_port);

    LOG_UPNP_INFO("Found UPnP IGD: service=" << service_type << " control=" << control_absolute
                  << " localIP=" << out.local_ip);
    return out.valid();
}

bool UpnpClient::soap_action(const Device& dev, const std::string& action,
                             const std::string& body_args, std::string& response_body) {
    std::ostringstream soap;
    soap << "<?xml version=\"1.0\"?>\r\n"
         << "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
         << "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
         << "<s:Body><u:" << action << " xmlns:u=\"" << dev.service_type << "\">"
         << body_args
         << "</u:" << action << "></s:Body></s:Envelope>";
    std::string body = soap.str();

    std::ostringstream headers;
    headers << "Content-Type: text/xml; charset=\"utf-8\"\r\n"
            << "SOAPAction: \"" << dev.service_type << "#" << action << "\"\r\n";

    int status = 0;
    if (!http_request(dev.control_host, dev.control_port, "POST", dev.control_path,
                      headers.str(), body, status, response_body)) {
        return false;
    }

    if (status != 200) {
        std::string err_code = extract_tag(response_body, "errorCode");
        LOG_UPNP_DEBUG("SOAP " << action << " returned status " << status
                       << (err_code.empty() ? "" : " upnp errorCode " + err_code));
        return false;
    }
    return true;
}

bool UpnpClient::add_port_mapping(const Device& dev, Mapping& m) {
    std::ostringstream args;
    args << "<NewRemoteHost></NewRemoteHost>"
         << "<NewExternalPort>" << m.external_port << "</NewExternalPort>"
         << "<NewProtocol>" << to_string(m.protocol) << "</NewProtocol>"
         << "<NewInternalPort>" << m.internal_port << "</NewInternalPort>"
         << "<NewInternalClient>" << dev.local_ip << "</NewInternalClient>"
         << "<NewEnabled>1</NewEnabled>"
         << "<NewPortMappingDescription>" << m.description << "</NewPortMappingDescription>"
         << "<NewLeaseDuration>" << lease_duration_ << "</NewLeaseDuration>";

    std::string resp;
    if (!soap_action(dev, "AddPortMapping", args.str(), resp)) {
        notify(m, false, "AddPortMapping failed");
        return false;
    }

    m.active = true;
    uint32_t refresh = lease_duration_ > 0 ? lease_duration_ / 2 : 1800;
    if (refresh < 60) refresh = 60;
    m.expires = std::chrono::steady_clock::now() + std::chrono::seconds(refresh);

    LOG_UPNP_INFO("UPnP mapped " << to_string(m.protocol) << " external " << m.external_port
                  << " -> " << dev.local_ip << ":" << m.internal_port
                  << " (lease " << lease_duration_ << "s)");
    notify(m, true, "");
    return true;
}

bool UpnpClient::delete_port_mapping(const Device& dev, const Mapping& m) {
    std::ostringstream args;
    args << "<NewRemoteHost></NewRemoteHost>"
         << "<NewExternalPort>" << m.external_port << "</NewExternalPort>"
         << "<NewProtocol>" << to_string(m.protocol) << "</NewProtocol>";
    std::string resp;
    bool ok = soap_action(dev, "DeletePortMapping", args.str(), resp);
    if (ok) {
        LOG_UPNP_INFO("UPnP removed mapping " << to_string(m.protocol) << " external " << m.external_port);
    }
    return ok;
}

bool UpnpClient::query_external_ip(const Device& dev) {
    std::string resp;
    if (!soap_action(dev, "GetExternalIPAddress", "", resp)) {
        return false;
    }
    std::string ip = extract_tag(resp, "NewExternalIPAddress");
    if (!ip.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        external_ip_ = ip;
        LOG_UPNP_INFO("UPnP external IP: " << ip);
        return true;
    }
    return false;
}

void UpnpClient::remove_all_mappings(const Device& dev) {
    std::vector<Mapping> snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        snapshot = mappings_;
    }
    for (const auto& m : snapshot) {
        if (m.active) {
            delete_port_mapping(dev, m);
        }
    }
}

void UpnpClient::worker_loop() {
    LOG_UPNP_DEBUG("UPnP worker started");

    Device dev;
    if (!discover_device(dev)) {
        LOG_UPNP_WARN("UPnP disabled: no Internet Gateway Device found");
        running_.store(false);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        device_ = dev;
        device_found_ = true;
    }

    query_external_ip(dev);

    while (!stop_requested_.load()) {
        auto now = std::chrono::steady_clock::now();

        // Install / refresh mappings that are due.
        std::vector<size_t> indices;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (size_t i = 0; i < mappings_.size(); ++i) {
                if (!mappings_[i].active || mappings_[i].expires <= now) {
                    indices.push_back(i);
                }
            }
        }
        for (size_t idx : indices) {
            if (stop_requested_.load()) break;
            Mapping local;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (idx >= mappings_.size()) continue;
                local = mappings_[idx];
            }
            bool ok = add_port_mapping(dev, local);
            std::lock_guard<std::mutex> lock(mutex_);
            if (idx < mappings_.size() && ok) {
                mappings_[idx].active = local.active;
                mappings_[idx].expires = local.expires;
                mappings_[idx].external_port = local.external_port;
            }
        }

        // Sleep until the soonest refresh (default: lease/2).
        auto next_wake = std::chrono::steady_clock::now() +
                         std::chrono::seconds(lease_duration_ > 0 ? lease_duration_ / 2 : 1800);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& m : mappings_) {
                if (m.active && m.expires < next_wake) {
                    next_wake = m.expires;
                }
            }
        }

        std::unique_lock<std::mutex> lk(cv_mutex_);
        cv_.wait_until(lk, next_wake, [this] { return stop_requested_.load(); });
    }

    remove_all_mappings(dev);
    LOG_UPNP_DEBUG("UPnP worker stopped");
}

} // namespace librats
