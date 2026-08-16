#pragma once

/**
 * @file nat_status.h
 * @brief What the mesh has told us about our own side of the NAT.
 *
 * A node behind a NAT cannot see its own external endpoint; only somebody on the
 * other side can. The usual answer is a STUN server, but a connected mesh already
 * carries the same information for free — and, unlike a single STUN reply, it
 * carries it from *several* independent vantage points, which is what turns a bare
 * address into a statement about how the NAT behaves.
 *
 * The source is the identify exchange (node/identify.h). Each peer reports the
 * address it observed us connecting from; on a DATAGRAM link that address is the
 * NAT's rewriting of the one socket every UDP peer shares, so its port is exactly
 * the port a third party must aim at to reach us. (On TCP the port is an ephemeral
 * one our OS picked per connection and means nothing, so it is not reported and
 * never reaches this class.)
 *
 * Two peers are then enough to classify the mapping:
 *
 *   - both see the SAME external port  → the NAT maps our socket to one port
 *     regardless of who we are talking to (endpoint-independent, "cone"). This is
 *     the case a hole punch works in: the port one peer tells us about is the port
 *     another peer can dial.
 *   - they see DIFFERENT ports         → the NAT picks a fresh mapping per
 *     destination (endpoint-dependent, "symmetric"). Nothing we learn from one peer
 *     predicts what a third will see, so punching to an advertised endpoint cannot
 *     work and a relay is the only way through.
 *   - the observed endpoint is one of our own local addresses → there is no NAT in
 *     the path at all, and an ordinary dial already reaches us.
 *
 * Threading: observations arrive on reactor threads (possibly several), readers are
 * application/subsystem threads. One small mutex; nothing on a data path.
 */

#include "librats/util/rats_export.h"
#include "librats/core/address.h"
#include "librats/peer/peer_id.h"

#include <cstddef>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace librats {

/// How the NAT in front of our shared datagram socket maps it, as far as the mesh
/// has been able to show.
enum class NatMapping : uint8_t {
    Unknown,              ///< not enough independent observations yet
    Open,                 ///< no NAT: peers see us at an address we hold ourselves
    EndpointIndependent,  ///< one external port for every destination — punchable
    EndpointDependent,    ///< a fresh mapping per destination (symmetric) — not punchable
};

RATS_API const char* to_string(NatMapping) noexcept;

/// The read side, published in the node's ServiceRegistry so a NAT-traversal module
/// can consult it without holding the Node:
///
///     if (auto* nat = ctx.services.get<ExternalAddressService>())
///         if (nat->udp_mapping() == NatMapping::EndpointDependent) return;  // don't bother
class ExternalAddressService {
public:
    virtual ~ExternalAddressService() = default;

    /// Endpoints peers have reported observing our shared datagram socket at, most
    /// recently confirmed first. Empty until at least one peer has said so over a
    /// datagram link. These are what a hole punch advertises to its target.
    virtual std::vector<Address> external_udp_endpoints() const = 0;

    /// What the observations so far say about the mapping.
    virtual NatMapping udp_mapping() const = 0;
};

class RATS_API NatStatus final : public ExternalAddressService {
public:
    /// Observations kept. One per reporting peer, so a node with many peers does not
    /// grow this without bound and a single peer cannot flood it either — a second
    /// report from the same peer replaces its first rather than adding to it.
    static constexpr size_t kMaxObservers = 32;

    /// Record that `reporter` observed our datagram socket at `external`.
    /// @param is_own_address whether that endpoint is one this node holds locally
    ///        (the caller knows its interfaces; this class does not) — the signal
    ///        that there is no NAT in the path.
    void record_udp_observation(const PeerId& reporter, const Address& external,
                                bool is_own_address);

    /// Forget a reporter's observation — its link is gone and what it saw may have
    /// been a mapping that died with it.
    void forget(const PeerId& reporter);

    /// Drop everything. The node is restarting, or the host's network changed and
    /// every mapping learned under the old one is now a guess.
    void reset();

    /// How many distinct peers have reported an endpoint.
    size_t observation_count() const;

    // — ExternalAddressService —
    std::vector<Address> external_udp_endpoints() const override;
    NatMapping           udp_mapping() const override;

private:
    struct Observation {
        Address  endpoint;
        bool     is_own_address = false;
        uint64_t seq = 0;   ///< arrival order, so the freshest endpoint sorts first
    };

    mutable std::mutex                                       mutex_;
    std::unordered_map<PeerId, Observation, PeerId::Hash>    seen_;
    uint64_t                                                 next_seq_ = 1;
};

} // namespace librats
