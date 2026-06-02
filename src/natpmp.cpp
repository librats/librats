/**
 * @file natpmp.cpp
 * @brief NAT-PMP (RFC 6886) client implementation
 */

#include "natpmp.h"
#include "network_utils.h"
#include "logger.h"

#include <cstring>

#define LOG_NATPMP_DEBUG(message) LOG_DEBUG("natpmp", message)
#define LOG_NATPMP_INFO(message)  LOG_INFO("natpmp", message)
#define LOG_NATPMP_WARN(message)  LOG_WARN("natpmp", message)
#define LOG_NATPMP_ERROR(message) LOG_ERROR("natpmp", message)

namespace librats {

namespace {

// NAT-PMP opcodes
constexpr uint8_t OP_EXTERNAL_IP = 0;
constexpr uint8_t OP_MAP_UDP     = 1;
constexpr uint8_t OP_MAP_TCP     = 2;
constexpr uint8_t OP_RESPONSE_BIT = 0x80;

// Retransmission schedule (ms). RFC 6886 doubles from 250ms; we cap retries to
// stay responsive while still tolerating a couple of dropped UDP packets.
const int kRetryTimeouts[] = { 250, 500, 1000 };

void put_u16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

void put_u32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

uint16_t get_u16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t get_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint8_t map_opcode(PortMapProtocol p) {
    return p == PortMapProtocol::UDP ? OP_MAP_UDP : OP_MAP_TCP;
}

// Translate a NAT-PMP result code into a readable message (RFC 6886 §3.5).
const char* result_message(uint16_t code) {
    switch (code) {
        case 0: return "success";
        case 1: return "unsupported version";
        case 2: return "not authorized / refused";
        case 3: return "network failure";
        case 4: return "out of resources";
        case 5: return "unsupported opcode";
        default: return "unknown error";
    }
}

} // anonymous namespace

NatPmpClient::NatPmpClient() = default;

NatPmpClient::~NatPmpClient() {
    stop();
}

void NatPmpClient::add_mapping(PortMapProtocol protocol, uint16_t internal_port, uint16_t external_port) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& m : mappings_) {
        if (m.protocol == protocol && m.internal_port == internal_port) {
            return; // already registered
        }
    }
    Mapping m;
    m.protocol = protocol;
    m.internal_port = internal_port;
    m.external_port = external_port == 0 ? internal_port : external_port;
    mappings_.push_back(m);
    LOG_NATPMP_DEBUG("Registered mapping " << to_string(protocol) << " internal=" << internal_port
                     << " external=" << m.external_port);
    // If the worker is already running, wake it up to install the new mapping.
    // wake_worker_ must be set under cv_mutex_ (the mutex the worker waits on) so
    // the notification can't be lost in the gap between the worker evaluating its
    // wait predicate and actually blocking.
    if (running_.load()) {
        {
            std::lock_guard<std::mutex> lk(cv_mutex_);
            wake_worker_ = true;
        }
        cv_.notify_all();
    }
}

std::string NatPmpClient::external_ip() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return external_ip_;
}

bool NatPmpClient::start() {
    if (running_.exchange(true)) {
        return false;
    }
    stop_requested_.store(false);
    worker_ = std::thread(&NatPmpClient::worker_loop, this);
    return true;
}

void NatPmpClient::stop() {
    // Guard idempotency on stop_requested_, NOT running_: the worker clears
    // running_ itself when gateway discovery fails (see worker_loop), so gating
    // the join on running_ would skip it and leave the thread joinable —
    // destroying it then calls std::terminate ("terminate called without an
    // active exception").
    if (stop_requested_.exchange(true)) {
        return;
    }
    {
        // Take cv_mutex_ before notifying so a worker about to sleep can't miss the
        // stop request (same lost-wakeup hazard as add_mapping).
        std::lock_guard<std::mutex> lk(cv_mutex_);
        wake_worker_ = true;
    }
    cv_.notify_all();
    wakeup_.signal();  // unblock an in-flight gateway receive so the join is immediate
    if (worker_.joinable()) {
        worker_.join();
    }
    running_.store(false);
}

void NatPmpClient::notify(const Mapping& m, bool success, const std::string& error) {
    if (!callback_) return;
    PortMapResult r;
    r.transport = PortMapTransport::NatPMP;
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

bool NatPmpClient::ensure_gateway() {
    std::vector<std::string> candidates;
    if (!forced_gateway_.empty()) {
        candidates.push_back(forced_gateway_);
    } else {
        candidates = network_utils::get_default_gateways();
    }

    if (candidates.empty()) {
        LOG_NATPMP_WARN("No gateway candidates found for NAT-PMP");
        return false;
    }

    // Probe each candidate with an external-IP request; the first that answers
    // becomes our gateway. If none answer, fall back to the first candidate so
    // we still attempt a mapping (some routers only reply to MAP requests).
    for (const auto& gw : candidates) {
        socket_t sock = create_udp_socket(0, "", AddressFamily::IPv4);
        if (!is_valid_socket(sock)) continue;

        std::vector<uint8_t> req = { NATPMP_VERSION, OP_EXTERNAL_IP };
        bool answered = false;
        for (int timeout : kRetryTimeouts) {
            if (stop_requested_.load()) { close_socket(sock); return false; }
            if (send_udp_data(sock, req, gw, NATPMP_PORT, AddressFamily::IPv4) < 0) break;
            Peer from;
            auto resp = receive_udp_data(sock, 64, from, timeout, wakeup_.fd());
            if (resp.size() >= 12 && from.ip == gw && resp[0] == NATPMP_VERSION &&
                resp[1] == (OP_EXTERNAL_IP | OP_RESPONSE_BIT)) {
                uint16_t result = get_u16(&resp[2]);
                if (result == 0) {
                    char ip[INET_ADDRSTRLEN];
                    struct in_addr addr;
                    std::memcpy(&addr, &resp[8], 4);
                    if (inet_ntop(AF_INET, &addr, ip, sizeof(ip))) {
                        std::lock_guard<std::mutex> lock(mutex_);
                        external_ip_ = ip;
                    }
                }
                answered = true;
                break;
            }
        }
        close_socket(sock);

        if (answered) {
            std::lock_guard<std::mutex> lock(mutex_);
            gateway_ = gw;
            LOG_NATPMP_INFO("NAT-PMP gateway responding at " << gw
                            << (external_ip_.empty() ? "" : " (external IP " + external_ip_ + ")"));
            return true;
        }
    }

    // Nobody answered the external-IP probe — keep the first candidate to try MAP.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        gateway_ = candidates.front();
    }
    LOG_NATPMP_DEBUG("No NAT-PMP external-IP reply; will still try MAP against " << candidates.front());
    return true;
}

bool NatPmpClient::request_external_ip(socket_t sock) {
    std::string gw;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        gw = gateway_;
    }
    if (gw.empty()) return false;

    std::vector<uint8_t> req = { NATPMP_VERSION, OP_EXTERNAL_IP };
    for (int timeout : kRetryTimeouts) {
        if (stop_requested_.load()) return false;
        if (send_udp_data(sock, req, gw, NATPMP_PORT, AddressFamily::IPv4) < 0) return false;
        Peer from;
        auto resp = receive_udp_data(sock, 64, from, timeout, wakeup_.fd());
        if (resp.size() >= 12 && from.ip == gw && resp[0] == NATPMP_VERSION &&
            resp[1] == (OP_EXTERNAL_IP | OP_RESPONSE_BIT) && get_u16(&resp[2]) == 0) {
            char ip[INET_ADDRSTRLEN];
            struct in_addr addr;
            std::memcpy(&addr, &resp[8], 4);
            if (inet_ntop(AF_INET, &addr, ip, sizeof(ip))) {
                std::lock_guard<std::mutex> lock(mutex_);
                external_ip_ = ip;
                return true;
            }
        }
    }
    return false;
}

bool NatPmpClient::send_map_request(socket_t sock, Mapping& m, bool remove) {
    std::string gw;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        gw = gateway_;
    }
    if (gw.empty()) return false;

    const uint32_t lifetime = remove ? 0 : lease_duration_;
    const uint16_t requested_external = remove ? 0 : m.external_port;

    std::vector<uint8_t> req;
    req.push_back(NATPMP_VERSION);
    req.push_back(map_opcode(m.protocol));
    put_u16(req, 0); // reserved
    put_u16(req, m.internal_port);
    put_u16(req, requested_external);
    put_u32(req, lifetime);

    if (remove) {
        // Best-effort teardown. A NAT-PMP delete is just a MAP request with lifetime 0;
        // we deliberately do NOT wait for the reply. stop() has already signalled the
        // wakeup pipe so the worker exits promptly (tests churn through open/close
        // cycles): a blocking receive here would either return instantly (confirming
        // nothing) or, if the pipe were drained, stall for the full retransmit timeout
        // when the gateway is silent. So we send the datagram twice — to ride out UDP
        // loss — and return immediately. The lease caps the mapping lifetime as a
        // backstop if both packets are lost.
        bool sent = false;
        for (int i = 0; i < 2; ++i) {
            if (send_udp_data(sock, req, gw, NATPMP_PORT, AddressFamily::IPv4) >= 0) sent = true;
        }
        if (sent) {
            LOG_NATPMP_INFO("NAT-PMP delete request sent (best-effort) for "
                            << to_string(m.protocol) << " port " << m.internal_port);
        }
        return sent;
    }

    const uint8_t expected_opcode = static_cast<uint8_t>(map_opcode(m.protocol) | OP_RESPONSE_BIT);

    for (int timeout : kRetryTimeouts) {
        if (stop_requested_.load()) return false;
        if (send_udp_data(sock, req, gw, NATPMP_PORT, AddressFamily::IPv4) < 0) return false;

        Peer from;
        auto resp = receive_udp_data(sock, 64, from, timeout, wakeup_.fd());
        if (resp.size() < 16 || from.ip != gw) continue;
        if (resp[0] != NATPMP_VERSION || resp[1] != expected_opcode) continue;

        uint16_t result = get_u16(&resp[2]);
        uint16_t resp_internal = get_u16(&resp[8]);
        if (resp_internal != m.internal_port) continue; // not our mapping

        if (result != 0) {
            std::string err = result_message(result);
            LOG_NATPMP_WARN("NAT-PMP map " << to_string(m.protocol) << " port " << m.internal_port
                            << " failed: " << err);
            notify(m, false, err);
            return false;
        }

        uint16_t mapped_external = get_u16(&resp[10]);
        uint32_t granted_lifetime = get_u32(&resp[12]);

        m.external_port = mapped_external;
        m.active = true;
        // Refresh at half the granted lifetime (RFC 6886 §3.3.1 recommendation).
        uint32_t refresh = granted_lifetime > 0 ? granted_lifetime / 2 : lease_duration_ / 2;
        if (refresh < 30) refresh = 30;
        m.expires = std::chrono::steady_clock::now() + std::chrono::seconds(refresh);

        LOG_NATPMP_INFO("NAT-PMP mapped " << to_string(m.protocol) << " internal " << m.internal_port
                        << " -> external " << mapped_external << " (lease " << granted_lifetime << "s)");
        notify(m, true, "");
        return true;
    }

    LOG_NATPMP_DEBUG("NAT-PMP map request timed out for port " << m.internal_port);
    return false;
}

void NatPmpClient::remove_all_mappings() {
    socket_t sock = create_udp_socket(0, "", AddressFamily::IPv4);
    if (!is_valid_socket(sock)) return;
    std::vector<Mapping> snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        snapshot = mappings_;
    }
    for (auto& m : snapshot) {
        if (m.active) {
            send_map_request(sock, m, /*remove=*/true);
        }
    }
    close_socket(sock);
}

void NatPmpClient::worker_loop() {
    LOG_NATPMP_DEBUG("NAT-PMP worker started");

    if (!ensure_gateway()) {
        LOG_NATPMP_WARN("NAT-PMP disabled: no usable gateway");
        running_.store(false);
        return;
    }

    while (!stop_requested_.load()) {
        socket_t sock = create_udp_socket(0, "", AddressFamily::IPv4);
        if (!is_valid_socket(sock)) {
            LOG_NATPMP_ERROR("Failed to create NAT-PMP UDP socket");
            break;
        }

        request_external_ip(sock);

        // Install / refresh any mapping that needs it.
        auto now = std::chrono::steady_clock::now();
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
            bool ok = send_map_request(sock, local, /*remove=*/false);
            std::lock_guard<std::mutex> lock(mutex_);
            if (idx < mappings_.size() && ok) {
                mappings_[idx].external_port = local.external_port;
                mappings_[idx].active = local.active;
                mappings_[idx].expires = local.expires;
            }
        }

        close_socket(sock);

        // Sleep until the soonest refresh is due (or a default poll interval).
        auto next_wake = std::chrono::steady_clock::now() + std::chrono::seconds(lease_duration_ / 2);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& m : mappings_) {
                if (m.active && m.expires < next_wake) {
                    next_wake = m.expires;
                }
            }
        }

        std::unique_lock<std::mutex> lk(cv_mutex_);
        cv_.wait_until(lk, next_wake, [this] { return stop_requested_.load() || wake_worker_; });
        wake_worker_ = false;
    }

    // Clean up mappings on the way out.
    remove_all_mappings();
    LOG_NATPMP_DEBUG("NAT-PMP worker stopped");
}

} // namespace librats
