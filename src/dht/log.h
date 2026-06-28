#pragma once

/**
 * @file log.h
 * @brief Small logging helpers shared across the DHT modules.
 *
 * Formatting sugar on top of util/logger.h — nothing more. The DHT logs under a set of
 * dot-namespaced tags so each subsystem gets its own stable colour and is easy to grep:
 *
 *   "dht"        — client facade + runner lifecycle (start/stop/bootstrap/external-ip)
 *   "dht.find"   — lookups (find_peers / announce) and their progress
 *   "dht.route"  — routing table (bucket splits, evictions, table summary)
 *   "dht.rpc"    — outgoing/incoming queries, timeouts (mostly DEBUG)
 *   "dht.spider" — the crawl (only under RATS_SEARCH_FEATURES)
 *
 * Endpoints render via Address::to_string(); ids render via short_hex() below.
 */

#include "dht/id.h"
#include "util/logger.h"

#include <cstddef>
#include <string>

namespace librats {
namespace dht {

// A compact, log-friendly rendering of a 160-bit id: its leading `chars` hex digits
// (default 8, like a git short hash). The full 40-char id is unreadable in a log line
// and its leading bytes are more than enough to follow one contact across lines. Reach
// for to_hex(id) only where the complete id genuinely matters (e.g. our own id at start).
inline std::string short_hex(const NodeId& id, std::size_t chars = 8) {
    const std::string full = to_hex(id);
    return chars >= full.size() ? full : full.substr(0, chars);
}

} // namespace dht
} // namespace librats
