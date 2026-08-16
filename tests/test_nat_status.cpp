#include <gtest/gtest.h>

#include "librats/node/nat_status.h"

#include <array>

using namespace librats;

namespace {

PeerId id_with(uint8_t first_byte) {
    std::array<uint8_t, PeerId::kSize> raw{};
    raw[0] = first_byte;
    return *PeerId::from_bytes(ByteView(raw.data(), raw.size()));
}

const Address kExternal{"203.0.113.7", 41000};
const Address kOtherPort{"203.0.113.7", 41001};

} // namespace

// Nothing observed yet: nothing to advertise, and no claim about the NAT.
TEST(NatStatus, StartsEmptyAndUnknown) {
    NatStatus status;
    EXPECT_TRUE(status.external_udp_endpoints().empty());
    EXPECT_EQ(status.udp_mapping(), NatMapping::Unknown);
    EXPECT_EQ(status.observation_count(), 0u);
}

// One vantage point gives an endpoint worth advertising but cannot classify the
// mapping — it has only ever seen the mapping the NAT made for itself.
TEST(NatStatus, SingleObserverYieldsEndpointButNotAVerdict) {
    NatStatus status;
    status.record_udp_observation(id_with(1), kExternal, /*is_own_address=*/false);

    ASSERT_EQ(status.external_udp_endpoints().size(), 1u);
    EXPECT_EQ(status.external_udp_endpoints().front(), kExternal);
    EXPECT_EQ(status.udp_mapping(), NatMapping::Unknown);
}

// Two independent peers seeing the SAME external port is the case a hole punch
// relies on: the mapping does not depend on who we are talking to.
TEST(NatStatus, AgreeingObserversMeanEndpointIndependent) {
    NatStatus status;
    status.record_udp_observation(id_with(1), kExternal, false);
    status.record_udp_observation(id_with(2), kExternal, false);

    EXPECT_EQ(status.udp_mapping(), NatMapping::EndpointIndependent);
    EXPECT_EQ(status.external_udp_endpoints().size(), 1u);  // de-duplicated
}

// Different ports from different peers prove the NAT remaps per destination, so
// no endpoint we could advertise is the one a third peer would reach us on.
TEST(NatStatus, DisagreeingObserversMeanEndpointDependent) {
    NatStatus status;
    status.record_udp_observation(id_with(1), kExternal, false);
    status.record_udp_observation(id_with(2), kOtherPort, false);

    EXPECT_EQ(status.udp_mapping(), NatMapping::EndpointDependent);
    EXPECT_EQ(status.external_udp_endpoints().size(), 2u);
}

// A peer that sees us at an address we hold ourselves saw no NAT in between.
TEST(NatStatus, ObservationOfOwnAddressReadsAsOpen) {
    NatStatus status;
    status.record_udp_observation(id_with(1), Address{"192.168.1.5", 9000}, /*is_own=*/true);
    EXPECT_EQ(status.udp_mapping(), NatMapping::Open);
}

// A LAN peer seeing our own address says nothing about the path to the internet,
// so peers that are actually outside decide the verdict.
TEST(NatStatus, ExternalObserversOutrankLocalOnes) {
    NatStatus status;
    status.record_udp_observation(id_with(1), Address{"192.168.1.5", 9000}, /*is_own=*/true);
    status.record_udp_observation(id_with(2), kExternal, false);
    status.record_udp_observation(id_with(3), kExternal, false);

    EXPECT_EQ(status.udp_mapping(), NatMapping::EndpointIndependent);
}

// One peer, one vote: a peer that reports again replaces what it said before
// rather than out-voting everybody else.
TEST(NatStatus, RepeatedReportFromOnePeerReplacesItsPrevious) {
    NatStatus status;
    status.record_udp_observation(id_with(1), kExternal, false);
    status.record_udp_observation(id_with(1), kOtherPort, false);

    EXPECT_EQ(status.observation_count(), 1u);
    ASSERT_EQ(status.external_udp_endpoints().size(), 1u);
    EXPECT_EQ(status.external_udp_endpoints().front(), kOtherPort);
    EXPECT_EQ(status.udp_mapping(), NatMapping::Unknown);  // still a single voter
}

// The freshest observation leads: under a NAT that has just remapped us, that is
// the endpoint a punch should be aimed at.
TEST(NatStatus, EndpointsAreOrderedFreshestFirst) {
    NatStatus status;
    status.record_udp_observation(id_with(1), kExternal, false);
    status.record_udp_observation(id_with(2), kOtherPort, false);

    const auto endpoints = status.external_udp_endpoints();
    ASSERT_EQ(endpoints.size(), 2u);
    EXPECT_EQ(endpoints.front(), kOtherPort);
}

// A peer's vote leaves with it: the mapping it saw may have been made for its
// link alone, and a departed peer must not keep deciding how our NAT behaves.
TEST(NatStatus, ForgetDropsThatPeersVote) {
    NatStatus status;
    status.record_udp_observation(id_with(1), kExternal, false);
    status.record_udp_observation(id_with(2), kOtherPort, false);
    ASSERT_EQ(status.udp_mapping(), NatMapping::EndpointDependent);

    status.forget(id_with(2));
    EXPECT_EQ(status.observation_count(), 1u);
    EXPECT_EQ(status.udp_mapping(), NatMapping::Unknown);
}

// A host network change invalidates every mapping learned under the old path.
TEST(NatStatus, ResetClearsEverything) {
    NatStatus status;
    status.record_udp_observation(id_with(1), kExternal, false);
    status.record_udp_observation(id_with(2), kExternal, false);
    ASSERT_EQ(status.udp_mapping(), NatMapping::EndpointIndependent);

    status.reset();
    EXPECT_EQ(status.observation_count(), 0u);
    EXPECT_TRUE(status.external_udp_endpoints().empty());
    EXPECT_EQ(status.udp_mapping(), NatMapping::Unknown);
}

// An unusable endpoint is not an observation: it can neither be advertised nor
// dialed, and counting it would let a peer manufacture a second "voter".
TEST(NatStatus, IgnoresUnusableEndpoints) {
    NatStatus status;
    status.record_udp_observation(id_with(1), Address{"203.0.113.7", 0}, false);
    status.record_udp_observation(id_with(2), Address{}, false);

    EXPECT_EQ(status.observation_count(), 0u);
    EXPECT_EQ(status.udp_mapping(), NatMapping::Unknown);
}

// One entry per reporting peer, so neither a large mesh nor a single chatty peer
// grows this without bound.
TEST(NatStatus, BoundsTheNumberOfObservers) {
    NatStatus status;
    for (int i = 0; i < 100; ++i)
        status.record_udp_observation(id_with(static_cast<uint8_t>(i)),
                                      Address{"203.0.113.7", static_cast<uint16_t>(40000 + i)},
                                      false);
    EXPECT_LE(status.observation_count(), NatStatus::kMaxObservers);
}
