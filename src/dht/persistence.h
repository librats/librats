#pragma once

/**
 * @file persistence.h
 * @brief Save/restore the routing table across restarts as JSON.
 *
 * Persists our node id (so our identity is stable) plus the confirmed contacts (a
 * warm set to bootstrap from). The JSON schema is unchanged from earlier releases, so
 * previously saved tables still load (the file is named dht_routing[_v6].json under the
 * data dir; the name is port-independent so an ephemeral node restores on restart).
 */

#include "dht/id.h"
#include "dht/node_entry.h"

#include <string>
#include <vector>

namespace librats {
namespace dht {

// Writes `self` + the given (confirmed) contacts to `path`. Returns false on I/O error.
bool save_routing_table(const std::string& path, const NodeId& self,
                        const std::vector<NodeEntry>& contacts);

// Reads `path` into `self` and `contacts` (restored as confirmed). Returns false if
// the file is missing or malformed; outputs are only written on success.
bool load_routing_table(const std::string& path, NodeId& self,
                        std::vector<NodeEntry>& contacts);

} // namespace dht
} // namespace librats
