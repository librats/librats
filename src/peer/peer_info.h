#pragma once

/**
 * @file peer_info.h
 * @brief Addressing/metadata for a peer — the shareable, persistable identity.
 *
 * PeerInfo is the "where / what" of a peer, kept separate from the live
 * transport (Connection) and from the raw identity (PeerId). It is a value type:
 * snapshotted into callbacks and into the PeerStore without touching live state.
 */

#include "core/types.h"   // ConnRole
#include "core/address.h"
#include "peer/peer_id.h"

#include <vector>

namespace librats {

struct PeerInfo {
    PeerId               id;
    std::vector<Address> addresses;                 ///< known dialable addresses
    ConnRole             direction = ConnRole::Outbound;
    std::string          agent_version;             ///< optional remote agent string
};

} // namespace librats
