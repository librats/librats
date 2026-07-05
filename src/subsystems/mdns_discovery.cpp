#include "subsystems/mdns_discovery.h"
#include "node/node_context.h"
#include "util/logger.h"

namespace librats {

MdnsDiscovery::MdnsDiscovery() : MdnsDiscovery(Config()) {}

MdnsDiscovery::MdnsDiscovery(Config config) : config_(std::move(config)) {}

MdnsDiscovery::~MdnsDiscovery() { stop(); }

void MdnsDiscovery::attach(NodeContext& ctx) { network_ = &ctx.network; }

void MdnsDiscovery::start() {
    if (running_.exchange(true)) return;

    instance_ = config_.instance_name.empty() ? ("rats-" + network_->local_id().short_hex())
                                              : config_.instance_name;
    const uint16_t port = network_->listen_port();

    mdns_ = std::make_unique<MdnsClient>(instance_, port);
    mdns_->set_service_callback([this](const MdnsService& service, bool is_new) { on_service(service, is_new); });
    if (!mdns_->start()) {
        LOG_ERROR("mdns-discovery", "Failed to start mDNS client");
        running_.store(false);
        mdns_.reset();
        return;
    }
    mdns_->announce_service(instance_, port);
    mdns_->start_discovery();
    LOG_INFO("mdns-discovery", "Announcing '" << instance_ << "' on port " << port);
}

void MdnsDiscovery::stop() {
    if (!running_.exchange(false)) return;
    if (mdns_) {
        mdns_->stop_discovery();
        mdns_->stop_announcing();
        mdns_->stop();
        mdns_.reset();
    }
}

bool MdnsDiscovery::is_running() const { return running_.load() && mdns_ && mdns_->is_running(); }

void MdnsDiscovery::on_service(const MdnsService& service, bool /*is_new*/) {
    if (service.ip_address.empty() || service.port == 0) return;
    // Skip our own announcement (its name carries our instance label).
    if (service.service_name.find(instance_) != std::string::npos) return;

    // service.ip_address comes off the wire (untrusted); only dial a valid numeric IP.
    const auto ip = IpAddress::parse(service.ip_address);
    if (!ip) return;

    const Address addr{*ip, service.port};
    {
        std::lock_guard<std::mutex> lock(dialed_mutex_);
        if (!dialed_.insert(addr).second) return;  // already dialed this address
    }
    LOG_DEBUG("mdns-discovery", "Dialing discovered service " << service.service_name
                                 << " at " << addr.to_string());
    network_->connect(addr);
}

} // namespace librats
