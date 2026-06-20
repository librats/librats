#include "subsystems/port_mapping_service.h"
#include "node/node_context.h"
#include "node/host_events.h"
#include "nat/upnp.h"
#include "nat/natpmp.h"
#include "util/network_utils.h"
#include "util/logger.h"

namespace librats {

PortMappingService::PortMappingService(PortMappingConfig config) : config_(config) {}

PortMappingService::~PortMappingService() { stop(); }

void PortMappingService::attach(NodeContext& ctx) {
    network_ = &ctx.network;
    // On a host network change the LAN IP and/or gateway likely changed, so existing
    // UPnP/NAT-PMP leases are stale or aimed at the wrong internal address. Tear them
    // down and re-run discovery from scratch. The handler runs on the node's
    // maintenance thread (dedicated to recovery), so the blocking stop()/start() is
    // fine here.
    ctx.events.on<NetworkChanged>([this](const NetworkChanged&) {
        if (!config_.enabled) return;
        LOG_INFO("portmap", "Network changed — renewing port mappings");
        stop();
        if (network_) start();
    });
}

void PortMappingService::start() {
    if (!config_.enabled) {
        LOG_DEBUG("portmap", "Automatic port forwarding disabled by config");
        return;
    }

    const uint16_t port = network_ ? network_->listen_port() : 0;
    if (port == 0) {
        LOG_WARN("portmap", "Skipping port mapping: node has no TCP listen port");
        return;
    }

    auto callback = [this](const PortMapResult& r) { handle_result(r); };

    std::unique_ptr<UpnpClient>   upnp;
    std::unique_ptr<NatPmpClient> natpmp;

    if (config_.enable_upnp) {
        upnp = std::make_unique<UpnpClient>();
        upnp->set_lease_duration(config_.lease_duration_seconds);
        upnp->set_callback(callback);
        upnp->add_mapping(PortMapProtocol::TCP, port, /*external_port=*/0, "rats");
    }
    if (config_.enable_natpmp) {
        natpmp = std::make_unique<NatPmpClient>();
        natpmp->set_lease_duration(config_.lease_duration_seconds);
        natpmp->set_callback(callback);
        natpmp->add_mapping(PortMapProtocol::TCP, port);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (upnp_ || natpmp_) return;  // already started
        upnp_   = std::move(upnp);
        natpmp_ = std::move(natpmp);
        // Start the workers under the lock so a result callback (which takes the
        // lock from its own thread) cannot observe a half-published state.
        if (upnp_)   upnp_->start();
        if (natpmp_) natpmp_->start();
    }

    LOG_INFO("portmap", "Started automatic port forwarding for TCP port " << port
             << " (upnp=" << config_.enable_upnp << " natpmp=" << config_.enable_natpmp
             << " lease=" << config_.lease_duration_seconds << "s)");
}

void PortMappingService::stop() {
    // Move the clients out under the lock, then stop() them outside it: stop()
    // joins worker threads that call handle_result() (which re-takes mutex_), so
    // holding it across stop() would deadlock.
    std::unique_ptr<UpnpClient>   upnp;
    std::unique_ptr<NatPmpClient> natpmp;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        upnp   = std::move(upnp_);
        natpmp = std::move(natpmp_);
    }

    if (upnp || natpmp) LOG_INFO("portmap", "Removing port mappings and stopping backends");
    if (upnp)   upnp->stop();
    if (natpmp) natpmp->stop();
}

void PortMappingService::handle_result(const PortMapResult& result) {
    // A gateway whose reported "external" IP is itself private means we're behind
    // a second NAT (double-NAT): the mapping forwards a port on the inner router,
    // but that doesn't make us reachable from the internet. Such a mapping must
    // NOT be recorded as a usable public endpoint.
    const bool ip_is_private =
        !result.external_ip.empty() && !network_utils::is_public_ip(result.external_ip);

    PortMapCallback user_cb;
    bool warn_double_nat = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (result.success && !ip_is_private && result.protocol == PortMapProtocol::TCP) {
            if (!result.external_ip.empty()) mapped_external_ip_ = result.external_ip;
            mapped_external_tcp_port_ = result.external_port;
        } else if (result.success && ip_is_private && !double_nat_warned_) {
            double_nat_warned_ = true;
            warn_double_nat = true;
        }
        user_cb = user_callback_;
    }

    if (result.success && ip_is_private) {
        LOG_INFO("portmap", to_string(result.transport) << " mapped " << to_string(result.protocol)
                 << " port " << result.internal_port << " -> external " << result.external_ip << ":"
                 << result.external_port << " (gateway external IP is private — not a usable public address)");
        if (warn_double_nat) {
            LOG_WARN("portmap", "Gateway reports a private external IP (" << result.external_ip
                     << ") — likely double-NAT. Port forwarding alone won't make this host publicly reachable.");
        }
    } else if (result.success) {
        LOG_INFO("portmap", to_string(result.transport) << " mapped " << to_string(result.protocol)
                 << " port " << result.internal_port << " -> external "
                 << (result.external_ip.empty() ? "?" : result.external_ip) << ":" << result.external_port);
    } else {
        LOG_DEBUG("portmap", to_string(result.transport) << " mapping failed: " << result.error);
    }

    // Invoke the user callback outside the lock to avoid re-entrancy deadlocks.
    if (user_cb) user_cb(result);
}

std::optional<std::pair<std::string, uint16_t>> PortMappingService::mapped_public_address() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (mapped_external_tcp_port_ == 0 || mapped_external_ip_.empty()) return std::nullopt;
    return std::make_pair(mapped_external_ip_, mapped_external_tcp_port_);
}

} // namespace librats
