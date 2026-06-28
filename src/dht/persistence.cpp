#include "dht/persistence.h"
#include "dht/log.h"
#include "util/json.h"

#include <fstream>
#include <iterator>

namespace librats {
namespace dht {

bool save_routing_table(const std::string& path, const NodeId& self,
                        const std::vector<NodeEntry>& contacts) {
    Json root;
    root["version"] = 1;
    root["node_id"] = to_hex(self);

    Json nodes = Json::array();
    for (const auto& n : contacts) {
        if (!n.confirmed()) continue;  // only persist good contacts
        Json e;
        e["id"] = to_hex(n.id);
        e["ip"] = n.endpoint.ip;
        e["port"] = static_cast<int>(n.endpoint.port);
        if (n.rtt != NodeEntry::kRttUnknown) e["rtt"] = static_cast<int>(n.rtt);
        nodes.push_back(e);
    }
    root["nodes"] = nodes;

    std::ofstream file(path);
    if (!file.is_open()) {
        // The headline "saved N contact(s)" lives in the facade; here we surface the
        // failure it can't see — a silent write failure means losing the warm set on restart.
        LOG_WARN("dht", "could not open routing table for writing: " << path);
        return false;
    }
    file << root.dump(2);
    if (!file.good()) {
        LOG_WARN("dht", "failed writing routing table to " << path);
        return false;
    }
    return true;
}

bool load_routing_table(const std::string& path, NodeId& self,
                        std::vector<NodeEntry>& contacts) {
    std::ifstream file(path);
    if (!file.is_open()) return false;
    const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    try {
        Json root = Json::parse(text);
        if (!root.contains("version") || !root.contains("nodes")) {
            LOG_WARN("dht", "routing table at " << path << " missing required fields, ignoring");
            return false;
        }

        NodeId loaded_self = self;
        if (root.contains("node_id")) loaded_self = from_hex(root["node_id"].get<std::string>());

        std::vector<NodeEntry> loaded;
        std::size_t skipped = 0;
        for (const auto& e : root["nodes"]) {
            if (!e.contains("id") || !e.contains("ip") || !e.contains("port")) { ++skipped; continue; }
            NodeEntry n(from_hex(e["id"].get<std::string>()),
                        Address(e["ip"].get<std::string>(),
                                static_cast<uint16_t>(e["port"].get<int>())));
            const uint16_t rtt = e.contains("rtt")
                                     ? static_cast<uint16_t>(e["rtt"].get<int>())
                                     : NodeEntry::kRttUnknown;
            n.record_success(rtt);  // a saved contact starts life confirmed
            loaded.push_back(n);
        }

        self = loaded_self;
        contacts = std::move(loaded);
        // The loaded count is the facade's INFO line; only the malformed-entry detail is
        // new here, so stay silent unless some entries were actually dropped.
        if (skipped)
            LOG_DEBUG("dht", "loaded routing table from " << path << ": " << contacts.size()
                             << " contact(s), " << skipped << " malformed entr(ies) skipped");
        return true;
    } catch (const std::exception& ex) {
        LOG_WARN("dht", "malformed routing table at " << path << " (" << ex.what() << "), ignoring");
        return false;
    }
}

} // namespace dht
} // namespace librats
