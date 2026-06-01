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
    if (mapped_external_port_ == 0 || mapped_external_ip_.empty()) {
        return std::nullopt;
    }
    return std::make_pair(mapped_external_ip_, mapped_external_port_);
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
    PortMapCallback user_cb;
    {
        std::lock_guard<std::mutex> lock(port_mapping_mutex_);
        if (result.success) {
            if (!result.external_ip.empty()) {
                mapped_external_ip_ = result.external_ip;
            }
            mapped_external_port_ = result.external_port;
        }
        user_cb = port_mapping_callback_;
    }

    if (result.success) {
        LOG_INFO("portmap", to_string(result.transport) << " mapped " << to_string(result.protocol)
                 << " port " << result.internal_port << " -> external "
                 << (result.external_ip.empty() ? "?" : result.external_ip) << ":" << result.external_port);
        // Avoid trying to connect to ourselves through the public address.
        if (!result.external_ip.empty()) {
            add_ignored_address(result.external_ip);
        }
    } else {
        LOG_DEBUG("portmap", to_string(result.transport) << " mapping failed: " << result.error);
    }

    // Invoke the user callback outside the lock to avoid re-entrancy deadlocks.
    if (user_cb) {
        user_cb(result);
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
