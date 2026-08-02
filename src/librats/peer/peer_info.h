#pragma once

/**
 * @file peer_info.h
 * @brief Addressing/metadata for a peer — the shareable, persistable identity.
 *
 * PeerInfo is the "where / what" of a peer, kept separate from the live
 * transport (Connection) and from the raw identity (PeerId). It is a value type:
 * snapshotted into callbacks and into the PeerTable without touching live state.
 */

#include "librats/core/types.h"   // ConnRole
#include "librats/core/address.h"
#include "librats/peer/peer_id.h"

#include <vector>

namespace librats {

/// Transports a peer says it accepts, as a bitmask (see IdentifyMessage). Kept
/// separate from `transport`, which is the one this connection actually uses.
enum PeerTransports : uint8_t {
    PeerTransportNone = 0,
    PeerTransportTcp  = 1 << 0,
    PeerTransportUdp  = 1 << 1,
};

struct PeerInfo {
    PeerId               id;
    std::vector<Address> addresses;                 ///< known dialable addresses
    ConnRole             direction = ConnRole::Outbound;
    TransportKind        transport = TransportKind::Tcp;  ///< wire this connection runs on
    uint8_t              supported_transports = PeerTransportNone;  ///< what the peer advertised
    std::string          agent_version;             ///< optional remote agent string
};

} // namespace librats
