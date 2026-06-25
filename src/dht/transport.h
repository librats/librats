#pragma once

/**
 * @file transport.h
 * @brief The outbound datagram sink the DHT sends through.
 *
 * The real implementation (Phase 5) owns a UDP socket; tests substitute a mock that
 * just records what was sent. Sending is fire-and-forget and must never block — the
 * whole DHT runs on one actor thread.
 */

#include "core/address.h"

#include <cstdint>
#include <vector>

namespace librats {
namespace dht {

class Transport {
public:
    virtual ~Transport() = default;
    virtual void send(const Address& to, const std::vector<uint8_t>& datagram) = 0;
};

} // namespace dht
} // namespace librats
