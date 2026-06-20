#pragma once

/**
 * @file config.h
 * @brief Node construction options.
 */

#include <cstdint>
#include <string>

namespace librats {

struct NodeConfig {
    /// Listen port for inbound peers. 0 picks an ephemeral port. Ignored if
    /// enable_listen is false (client-only node).
    uint16_t listen_port = 0;
    bool     enable_listen = true;

    /// Interface to bind / advertise. IPv4 literal for now (dual-stack is TODO).
    std::string bind_address = "127.0.0.1";

    /// Number of reactor threads. 1 is plenty for thousands of peers; larger
    /// pools shard outbound connections across cores.
    size_t reactor_threads = 1;

    /// Maximum number of established peers. 0 means unlimited. The limit guards
    /// inbound connections (a flood is refused at accept, before any handshake);
    /// outbound dials we initiate are always honored. Runtime-adjustable via
    /// Node::set_max_peers().
    size_t max_peers = 0;

    /// Secure channel to use for peer connections.
    enum class Security { Noise, Plaintext };
    Security security = Security::Noise;

    /// Application protocol identity. Bound into the Noise handshake prologue, so
    /// two nodes whose (name, version) differ cannot complete a handshake — a
    /// cheap, cryptographically-enforced way to keep separate apps from cross-
    /// connecting. Both peers must match exactly. (No effect under Plaintext.)
    std::string protocol_name = "librats";
    std::string protocol_version = "1.0";

    /// Directory for persistent state. Empty = ephemeral (a fresh random
    /// identity each run). When set, the node's Noise keypair is loaded from /
    /// saved to "<data_dir>/identity.key", giving a stable PeerId across restarts.
    std::string data_dir = "";
};

} // namespace librats
