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

#include "dht/id.h"

#include <random>
#include <string>

namespace librats {
namespace dht {

// Is `ip` publicly routable? Only public IPs can be (and must be) verified. Thin
// wrapper over network_utils::is_public_ip so every subsystem shares one definition.
bool is_public_address(const std::string& ip);

// Build a fresh BEP 42-compliant id for `ip`. Returns false and leaves `out`
// untouched only if `ip` can't be parsed. `rng` supplies the seed and random tail.
bool generate_node_id_from_ip(const std::string& ip, NodeId& out, std::mt19937& rng);

// Does `id` satisfy BEP 42 for a peer observed at `ip`? Always true for non-public
// or unparseable IPs (they can't be verified), so it never rejects on uncertainty.
bool verify_node_id_for_ip(const NodeId& id, const std::string& ip);

} // namespace dht
} // namespace librats
