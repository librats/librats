/**
 * @file librats_portmap.cpp
 * @brief Automatic port forwarding (UPnP IGD + NAT-PMP) integration for RatsClient
 *
 * Wires the standalone @ref UpnpClient and @ref NatPmpClient backends into the
 * RatsClient lifecycle. Both run in parallel; whichever the router supports maps
 * the TCP listen port so peers behind NAT can accept inbound connections. The
 * backends are started from RatsClient::start() and torn down in stop().
 */

#include "librats.h"
#include "network_utils.h"
#include "logger.h"

namespace librats {

// ============================================================================
// Configuration
// ============================================================================

void RatsClient::set_port_mapping_enabled(bool enabled) {
    bool was_enabled;
    {
        std::lock_guard<std::mutex> lock(port_mapping_mutex_);
        was_enabled = port_mapping_config_.enabled;
        port_mapping_config_.enabled = enabled;
    }

    if (was_enabled != enabled) {
        LOG_INFO("portmap", "Automatic port forwarding " << (enabled ? "enabled" : "disabled"));
        if (running_.load()) {
            if (enabled) {
                start_port_mapping();
            } else {
                stop_port_mapping();
            }
        }
        // Persist the new preference
        save_configuration();
    }
}

bool RatsClient::is_port_mapping_enabled() const {
    std::lock_guard<std::mutex> lock(port_mapping_mutex_);
    return port_mapping_config_.enabled;
}

void RatsClient::set_port_mapping_config(const PortMappingConfig& config) {
    {
        std::lock_guard<std::mutex> lock(port_mapping_mutex_);
        port_mapping_config_ = config;
    }
    LOG_DEBUG("portmap", "Port mapping config updated (upnp=" << config.enable_upnp
              << " natpmp=" << config.enable_natpmp << " lease=" << config.lease_duration_seconds << ")");
}

PortMappingConfig RatsClient::get_port_mapping_config() const {
    std::lock_guard<std::mutex> lock(port_mapping_mutex_);
    return port_mapping_config_;
}

void RatsClient::on_port_mapping(PortMapCallback callback) {
    std::lock_guard<std::mutex> lock(port_mapping_mutex_);
    port_mapping_callback_ = std::move(callback);
}

std::optional<std::pair<std::string, uint16_t>> RatsClient::get_mapped_public_address() const {
    std::lock_guard<std::mutex> lock(port_mapping_mutex_);
    // The "public address" peers should reach us on is the TCP peer-listen mapping.
    if (mapped_external_tcp_port_ == 0 || mapped_external_ip_.empty()) {
        return std::nullopt;
    }
    return std::make_pair(mapped_external_ip_, mapped_external_tcp_port_);
}

uint16_t RatsClient::get_advertised_port() const {
    std::lock_guard<std::mutex> lock(port_mapping_mutex_);
    return mapped_external_tcp_port_ != 0
         ? mapped_external_tcp_port_
         : static_cast<uint16_t>(listen_port_);
}

void RatsClient::add_port_mapping(PortMapProtocol protocol, uint16_t port) {
    std::lock_guard<std::mutex> lock(port_mapping_mutex_);
    if (upnp_client_)   upnp_client_->add_mapping(protocol, port);
    if (natpmp_client_) natpmp_client_->add_mapping(protocol, port);
}

// ============================================================================
// Result handling
// ============================================================================

void RatsClient::handle_port_mapping_result(const PortMapResult& result) {
    // A gateway whose reported "external" IP is itself private means we're behind a
    // second NAT (double-NAT): the mapping forwards a port on the inner router, but
    // that doesn't make us reachable from the internet, and the inner port won't
    // match whatever the outer NAT assigns. So such a mapping must NOT be treated as
    // a public endpoint — we leave mapped_external_* untouched and let the advertised
    // address fall back to listen_port_ / the STUN-discovered reflexive address.
    // An empty external IP (gateway didn't report one) is "unknown", not private, so
    // we keep the previous best-effort behavior for it.
    const bool ip_is_private = !result.external_ip.empty() && !network_utils::is_public_ip(result.external_ip);

    PortMapCallback user_cb;
    bool tcp_port_changed = false;
    bool warn_double_nat = false;
    {
        std::lock_guard<std::mutex> lock(port_mapping_mutex_);
        if (result.success && !ip_is_private) {
            if (!result.external_ip.empty()) {
                mapped_external_ip_ = result.external_ip;
            }
            // Track the external port per protocol so the TCP (peer) and UDP (DHT)
            // mappings don't overwrite each other.
            if (result.protocol == PortMapProtocol::TCP) {
                tcp_port_changed = (mapped_external_tcp_port_ != result.external_port);
                mapped_external_tcp_port_ = result.external_port;
            } else {
                mapped_external_udp_port_ = result.external_port;
            }
        } else if (result.success && ip_is_private && !double_nat_warning_logged_) {
            double_nat_warning_logged_ = true;
            warn_double_nat = true;
        }
        user_cb = port_mapping_callback_;
    }

    if (result.success && ip_is_private) {
        LOG_INFO("portmap", to_string(result.transport) << " mapped " << to_string(result.protocol)
                 << " port " << result.internal_port << " -> external " << result.external_ip << ":"
                 << result.external_port << " (gateway external IP is private — not a usable public address)");
        if (warn_double_nat) {
            LOG_WARN("portmap", "Gateway reports a private external IP (" << result.external_ip
                     << ") — likely double-NAT. Port forwarding alone won't make this host publicly "
                        "reachable; relying on STUN for the public address.");
        }
    } else if (result.success) {
        LOG_INFO("portmap", to_string(result.transport) << " mapped " << to_string(result.protocol)
                 << " port " << result.internal_port << " -> external "
                 << (result.external_ip.empty() ? "?" : result.external_ip) << ":" << result.external_port);
        // Avoid trying to connect to ourselves through the public address. Only a
        // genuinely public IP belongs on the ignore list — a private one could be a
        // real LAN peer we still want to reach.
        if (!result.external_ip.empty()) {
            add_ignored_address(result.external_ip);
        }
        // A new/changed public TCP port means the address peers should reach us on
        // changed: re-announce to the DHT so it advertises the mapped port instead
        // of the (NATed) local listen port. Done outside the lock below.
    } else {
        LOG_DEBUG("portmap", to_string(result.transport) << " mapping failed: " << result.error);
    }

    // Invoke the user callback outside the lock to avoid re-entrancy deadlocks.
    if (user_cb) {
        user_cb(result);
    }

    // Re-announce with the freshly mapped public port (outside any lock).
    if (tcp_port_changed && is_dht_running()) {
        announce_rats_peer();
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

void RatsClient::start_port_mapping() {
    PortMappingConfig config;
    int port;
    {
        std::lock_guard<std::mutex> lock(port_mapping_mutex_);
        config = port_mapping_config_;
        // Already started?
        if (upnp_client_ || natpmp_client_) {
            return;
        }
        port = listen_port_;
    }

    if (!config.enabled) {
        return;
    }
    if (port <= 0) {
        LOG_WARN("portmap", "Skipping port mapping: invalid listen port");
        return;
    }

    LOG_INFO("portmap", "Starting automatic port forwarding for TCP port " << port
             << " (upnp=" << config.enable_upnp << " natpmp=" << config.enable_natpmp << ")");

    auto callback = [this](const PortMapResult& r) { handle_port_mapping_result(r); };

    std::unique_ptr<UpnpClient> upnp;
    std::unique_ptr<NatPmpClient> natpmp;

    if (config.enable_upnp) {
        upnp = std::make_unique<UpnpClient>();
        upnp->set_lease_duration(config.lease_duration_seconds);
        upnp->set_callback(callback);
        upnp->add_mapping(PortMapProtocol::TCP, static_cast<uint16_t>(port), 0, "rats");
    }
    if (config.enable_natpmp) {
        natpmp = std::make_unique<NatPmpClient>();
        natpmp->set_lease_duration(config.lease_duration_seconds);
        natpmp->set_callback(callback);
        natpmp->add_mapping(PortMapProtocol::TCP, static_cast<uint16_t>(port));
    }

    // Publish the clients before starting their workers so add_port_mapping() can
    // reach them, then kick off discovery.
    {
        std::lock_guard<std::mutex> lock(port_mapping_mutex_);
        upnp_client_ = std::move(upnp);
        natpmp_client_ = std::move(natpmp);
    }
    {
        std::lock_guard<std::mutex> lock(port_mapping_mutex_);
        if (upnp_client_)   upnp_client_->start();
        if (natpmp_client_) natpmp_client_->start();
    }
}

void RatsClient::stop_port_mapping() {
    // Move the clients out under the lock, then stop() them outside it: stop()
    // joins worker threads which may call handle_port_mapping_result() (and thus
    // re-acquire port_mapping_mutex_), so holding it here would deadlock.
    std::unique_ptr<UpnpClient> upnp;
    std::unique_ptr<NatPmpClient> natpmp;
    {
        std::lock_guard<std::mutex> lock(port_mapping_mutex_);
        upnp = std::move(upnp_client_);
        natpmp = std::move(natpmp_client_);
    }

    if (upnp || natpmp) {
        LOG_INFO("portmap", "Removing port mappings and stopping backends");
    }
    if (upnp)   upnp->stop();
    if (natpmp) natpmp->stop();
}

} // namespace librats
