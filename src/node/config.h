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

    /// Secure channel to use for peer connections.
    enum class Security { Noise, Plaintext };
    Security security = Security::Noise;

    /// Directory for persistent state. Empty = ephemeral (a fresh random
    /// identity each run). When set, the node's Noise keypair is loaded from /
    /// saved to "<data_dir>/identity.key", giving a stable PeerId across restarts.
    std::string data_dir = "";
};

} // namespace librats
