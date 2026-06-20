#pragma once

/**
 * @file noise_security.h
 * @brief Noise_XX_25519_ChaChaPoly_SHA256 secure channel with self-certifying ids.
 *
 * Wraps the existing rats::NoiseSession (src/noise.h) behind the
 * SecurityProvider/Handshaker/Session contract. The XX pattern mutually
 * authenticates both static keys, and each side derives the other's PeerId from
 * the static key it proved — so a completed handshake is also identity proof.
 */

#include "security/handshaker.h"
#include "security/identity.h"

#include <memory>
#include <string>

namespace librats {

class NoiseSecurity final : public SecurityProvider {
public:
    /// @param protocol_name/version Application protocol id, bound into the Noise
    ///        handshake prologue. Peers whose (name, version) differ cannot
    ///        complete a handshake — cross-application isolation, enforced
    ///        cryptographically (a mismatch fails the handshake MAC).
    explicit NoiseSecurity(Identity identity, std::string protocol_name = "librats",
                           std::string protocol_version = "1.0");
    std::unique_ptr<Handshaker> create(ConnRole role) override;
    const PeerId& local_id() const override { return identity_.id; }

private:
    Identity    identity_;
    std::string prologue_;  ///< length-prefixed name+version, mixed into every handshake
};

} // namespace librats
