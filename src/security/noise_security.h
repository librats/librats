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

namespace librats {

class NoiseSecurity final : public SecurityProvider {
public:
    explicit NoiseSecurity(Identity identity);
    std::unique_ptr<Handshaker> create(ConnRole role) override;
    const PeerId& local_id() const override { return identity_.id; }

private:
    Identity identity_;
};

} // namespace librats
