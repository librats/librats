#pragma once

/**
 * @file bep42.h
 * @brief BEP 42 — deriving a DHT node id from a node's external IP.
 *
 * Binding the id to the IP stops a node from freely choosing where it sits in the
 * keyspace, which is the basis of the DHT's Sybil resistance. The first ~21 bits of
 * the id are a CRC32C of the masked IP plus a one-byte seed (stored in the last id
 * byte); the remaining bits are random. Only publicly routable IPs are constrained —
 * private/loopback/reserved addresses can't be verified and are exempt.
 */

#include "core/ip_address.h"
#include "dht/id.h"

#include <random>
#include <string>

namespace librats {
namespace dht {

// Is `ip` publicly routable? Only public IPs can be (and must be) verified. Thin
// wrapper over network_utils::is_public_ip so every subsystem shares one definition.
bool is_public_address(const IpAddress& ip);

// Build a fresh BEP 42-compliant id for `ip`. Returns false and leaves `out`
// untouched only if `ip` is unspecified. `rng` supplies the seed and random tail.
bool generate_node_id_from_ip(const IpAddress& ip, NodeId& out, std::mt19937& rng);

// Does `id` satisfy BEP 42 for a peer observed at `ip`? Always true for non-public
// or unspecified IPs (they can't be verified), so it never rejects on uncertainty.
// The IpAddress overload is the hot path (routing-table admission); the string one
// parses then delegates, and backs the public DhtClient::verify_node_id_for_ip API.
bool verify_node_id_for_ip(const NodeId& id, const IpAddress& ip);
bool verify_node_id_for_ip(const NodeId& id, const std::string& ip);

// Are `a` and `b` close enough to be treated as one identity for Sybil/eclipse
// resistance? Two addresses count as "too close" when they fall in the same /24
// (IPv4) or /64 (IPv6) block — the granularity at which a single operator typically
// controls every address. Different families (or an unspecified address) are never
// too close. The routing table uses this to keep one subnet from filling a bucket,
// and a lookup to keep it from flooding the candidate set (libtorrent's
// dht_restrict_routing_ips / dht_restrict_search_ips).
bool ip_too_close(const IpAddress& a, const IpAddress& b) noexcept;

} // namespace dht
} // namespace librats
