#pragma once

/**
 * @file identity.h
 * @brief A node's cryptographic identity: a static keypair and its derived PeerId.
 *
 * The PeerId is SHA-256 of the static public key, so identity travels with the
 * key. Generate a fresh identity for an ephemeral node, or rebuild one from a
 * persisted private key to keep a stable PeerId across restarts.
 */

#include "peer/peer_id.h"
#include "noise.h"

#include <cstring>

namespace librats {

struct Identity {
    rats::NoiseKeyPair static_keypair;
    PeerId             id;

    /// Create a brand-new random identity.
    static Identity generate() {
        Identity ident;
        rats::noise_generate_keypair(ident.static_keypair);
        ident.id = PeerId::from_public_key(ident.static_keypair.public_key, rats::NOISE_DH_SIZE);
        return ident;
    }

    /// Rebuild a stable identity from a persisted 32-byte private key.
    static Identity from_private_key(const uint8_t private_key[rats::NOISE_DH_SIZE]) {
        Identity ident;
        std::memcpy(ident.static_keypair.private_key, private_key, rats::NOISE_DH_SIZE);
        rats::noise_derive_public_key(private_key, ident.static_keypair.public_key);
        ident.static_keypair.has_keys = true;
        ident.id = PeerId::from_public_key(ident.static_keypair.public_key, rats::NOISE_DH_SIZE);
        return ident;
    }
};

} // namespace librats
