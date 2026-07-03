#pragma once

/**
 * @file log.h
 * @brief Small logging helpers shared across the BitTorrent modules.
 *
 * Formatting sugar on top of util/logger.h — nothing more. BitTorrent logs under a
 * set of dot-namespaced tags so each component gets its own stable colour and is
 * easy to grep (mirrors the dht.* scheme):
 *
 *   "bt.client"  — the session: listener, accept/dial, add/remove torrent
 *   "bt.torrent" — one torrent's lifecycle: state transitions, pieces, choking
 *   "bt.peer"    — a peer link: handshake and disconnect (with reason)
 *   "bt.tracker" — per-tracker HTTP/UDP announce results
 *   "bt.meta"    — magnet metadata fetch (BEP 9)
 *   "bt.disk"    — disk I/O failures
 *   "bt.picker"  — piece selection (end-game entry)
 *   "bt.node"    — the Node subsystem wrapper
 *
 * Conventions: an info-hash renders via short_hash() (8 leading hex, like a git
 * short hash); a peer renders as "ip:port". Direction/outcome use glyphs —
 * → outgoing, ← incoming, ✓ success, ✗ failure — matching the DHT logs.
 */

#include "bittorrent/types.h"
#include "util/logger.h"

#include <cstddef>
#include <string>

namespace librats::bittorrent {

/// Compact, log-friendly rendering of a 20-byte info-hash: its leading `chars`
/// hex digits (default 8, like a git short hash). The full 40-char id is
/// unreadable in a log line and its prefix is more than enough to follow one
/// torrent across lines. Use to_hex(id) only where the complete id matters.
inline std::string short_hash(const InfoHash& id, std::size_t chars = 8) {
    const std::string full = to_hex(id);
    return chars >= full.size() ? full : full.substr(0, chars);
}

} // namespace librats::bittorrent
