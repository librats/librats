#include <gtest/gtest.h>

#include "librats/peer/peer_table.h"

#include <algorithm>
#include <array>
#include <string>
#include <vector>

using namespace librats;

namespace {

PeerId id_with(uint8_t first_byte) {
    std::array<uint8_t, PeerId::kSize> raw{};
    raw[0] = first_byte;
    return *PeerId::from_bytes(ByteView(raw.data(), raw.size()));
}

const PeerId kPeer = id_with(0xAA);

/// One link between the same two nodes, carrying the name BOTH ends know it by.
///
/// This is what makes a symmetry check possible at all. A route is local — the
/// far end has its own ConnIds and they mean nothing here — so a test that asked
/// "did both ends keep the same route" would be asking nothing. `name` records
/// which side dialed and over what wire, which is the one description of a link
/// that is true at both ends; `direction` is the only field that flips between
/// them, and mirrored() is that flip.
struct Link {
    std::string   name;
    ConnRole      direction;  ///< as seen from the end being simulated
    TransportKind transport;
    PeerRoute     route;
};

Link mirrored(const Link& l) {
    Link m      = l;
    m.direction = l.direction == ConnRole::Outbound ? ConnRole::Inbound : ConnRole::Outbound;
    return m;
}

std::vector<Link> mirrored(const std::vector<Link>& links) {
    std::vector<Link> out;
    out.reserve(links.size());
    for (const Link& l : links) out.push_back(mirrored(l));
    return out;
}

PeerInfo info_for(const Link& l) {
    PeerInfo info;
    info.id        = kPeer;
    info.direction = l.direction;
    info.transport = l.transport;
    return info;
}

/// Feed `arrival` into a fresh table in that order and name the link left holding
/// the peer. Losers are not removed, which is what the node does too: a superseded
/// connection's teardown carries its own (now stale) route, and PeerTable::remove
/// ignores it precisely so it cannot evict the link that replaced it.
std::string survivor(bool prefer_outbound, const std::vector<Link>& arrival) {
    PeerTable table;
    for (const Link& l : arrival) table.add(info_for(l), l.route, prefer_outbound);

    const auto route = table.route(kPeer);
    if (!route) return "<nothing survived>";
    for (const Link& l : arrival)
        if (l.route == *route) return l.name;
    return "<unknown route>";
}

// The four links a full simultaneous cross-connect can leave behind: each node
// dialed the other, and each dial raced both transports. Named from the point of
// view of the end being simulated below as `prefer_outbound = true`.
const Link kWeUdp  {"we-dialed/udp",   ConnRole::Outbound, TransportKind::Udp, {0, 1}};
const Link kWeTcp  {"we-dialed/tcp",   ConnRole::Outbound, TransportKind::Tcp, {0, 2}};
const Link kTheyUdp{"they-dialed/udp", ConnRole::Inbound,  TransportKind::Udp, {0, 3}};
const Link kTheyTcp{"they-dialed/tcp", ConnRole::Inbound,  TransportKind::Tcp, {0, 4}};

// And the two a relayed circuit can leave: one we opened through a third node, one
// opened to us the same way.
const Link kWeRelay  {"we-opened/relay",   ConnRole::Outbound, TransportKind::Relay, {0, 5}};
const Link kTheyRelay{"they-opened/relay", ConnRole::Inbound,  TransportKind::Relay, {0, 6}};

} // namespace

// The dial race is settled by local timing, so its verdict is one the far end
// cannot reproduce — it never saw a race, only connections arriving. Two attempts
// that both got through therefore have to be separated by something both ends read
// the same way, and the wire is it: the datagram link wins everywhere.
TEST(PeerTableTest, RacedTransportsConvergeOnTheDatagramLink) {
    EXPECT_EQ(survivor(true, {kWeUdp, kWeTcp}), "we-dialed/udp");
    EXPECT_EQ(survivor(true, {kWeTcp, kWeUdp}), "we-dialed/udp")
        << "the verdict changed with the order the two attempts established in";

    // The far end sees the same two links as inbound and computes the opposite
    // prefer_outbound. It must still keep the same one, or each end tears down the
    // other's choice and the peer is lost entirely.
    EXPECT_EQ(survivor(false, mirrored({kWeUdp, kWeTcp})), "we-dialed/udp");
    EXPECT_EQ(survivor(false, mirrored({kWeTcp, kWeUdp})), "we-dialed/udp");
}

// Which side dialed outranks which wire it used. Both rules are symmetric, so the
// order between them only has to be the same at both ends — but it has to be, and
// a cross-connect where the outbound link is the TCP one is where that shows.
TEST(PeerTableTest, DirectionOutranksTheWire) {
    const std::vector<Link> pair{kWeTcp, kTheyUdp};

    EXPECT_EQ(survivor(true, pair), "we-dialed/tcp");
    EXPECT_EQ(survivor(true, {kTheyUdp, kWeTcp}), "we-dialed/tcp");
    EXPECT_EQ(survivor(false, mirrored(pair)), "we-dialed/tcp")
        << "the two ends ranked direction and transport differently";
    EXPECT_EQ(survivor(false, mirrored({kTheyUdp, kWeTcp})), "we-dialed/tcp");
}

// Same side, same wire is not a simultaneous pair — it is a redial, and the old
// link is stale or already dead. Here, and only here, recency is the right answer,
// and the asymmetry is harmless: the two ends are not resolving one pair between
// them, they are watching one link replace another.
TEST(PeerTableTest, SameRoleAndWireIsAReconnectSoTheNewcomerWins) {
    const Link one{"one", ConnRole::Outbound, TransportKind::Udp, {0, 1}};
    const Link two{"two", ConnRole::Outbound, TransportKind::Udp, {0, 2}};

    EXPECT_EQ(survivor(true, {one, two}), "two");
    EXPECT_EQ(survivor(true, {two, one}), "one")
        << "a reconnect must supersede the link it reconnects over";
}

// The three rules together are a total order over the links to one peer, mirrored
// at the two ends. That is the property the whole design rests on, and it says two
// things at once: the survivor does not depend on the order connections arrive in
// (each end sees its own order), and the two ends never disagree.
TEST(PeerTableTest, EveryArrivalOrderReachesTheSameVerdictAtBothEnds) {
    std::vector<Link> links{kWeUdp, kWeTcp, kTheyUdp, kTheyTcp};
    const auto by_route = [](const Link& a, const Link& b) { return a.route.conn < b.route.conn; };
    std::sort(links.begin(), links.end(), by_route);  // next_permutation needs a start

    int orders = 0;
    do {
        ++orders;
        EXPECT_EQ(survivor(true, links), "we-dialed/udp")
            << "arrival order decided the survivor (order #" << orders << ")";
        EXPECT_EQ(survivor(false, mirrored(links)), "we-dialed/udp")
            << "the far end kept a different link (order #" << orders << ")";
    } while (std::next_permutation(links.begin(), links.end(), by_route));

    EXPECT_EQ(orders, 24) << "not every arrival order was tried";
}

// A relayed link is not a competing dial, it is a stand-in for one — every byte it
// carries costs a third node bandwidth and a round trip. So the moment a direct
// link to the same peer exists, whichever way round it was made, the relayed one
// has to go. This outranks the direction rule on purpose: a relayed link that won
// on "we dialed it" would keep spending a stranger's bandwidth on a peer we can
// reach ourselves, for as long as the peer stayed connected.
TEST(PeerTableTest, ADirectLinkAlwaysSupersedesARelayedOne) {
    for (const Link& relay : {kWeRelay, kTheyRelay}) {
        for (const Link& direct : {kWeUdp, kWeTcp, kTheyUdp, kTheyTcp}) {
            EXPECT_EQ(survivor(true, {relay, direct}), direct.name)
                << "the relayed link survived a direct one arriving after it";
            EXPECT_EQ(survivor(true, {direct, relay}), direct.name)
                << "a relayed link arriving late displaced a direct one";

            // And the far end, which computes the opposite prefer_outbound, has to
            // reach the same verdict — otherwise each end drops the other's choice.
            EXPECT_EQ(survivor(false, mirrored({relay, direct})), direct.name);
            EXPECT_EQ(survivor(false, mirrored({direct, relay})), direct.name);
        }
    }
}

// Two circuits between the same pair — both ends asked a relay at the same moment
// — is an ordinary cross-connect, and the ordinary rule settles it. Nothing about
// relaying changes that; the rule above only ever compares a relayed link with a
// direct one.
TEST(PeerTableTest, TwoRelayedCircuitsAreSettledByDirectionAsUsual) {
    const std::vector<Link> pair{kWeRelay, kTheyRelay};

    EXPECT_EQ(survivor(true, pair), "we-opened/relay");
    EXPECT_EQ(survivor(true, {kTheyRelay, kWeRelay}), "we-opened/relay");
    EXPECT_EQ(survivor(false, mirrored(pair)), "we-opened/relay")
        << "the two ends kept different circuits";
    EXPECT_EQ(survivor(false, mirrored({kTheyRelay, kWeRelay})), "we-opened/relay");
}

// The same total-order property as above, now with a relayed link in the mix. This
// is the case that actually happens in the field: a peer is reached through a relay
// first, and a hole punch or a plain dial catches up afterwards — in whatever order
// the resulting links establish. The direct datagram link must come out on top
// every time, at both ends, which is what makes the upgrade seamless (the peer
// table swaps the route and no disconnect is ever reported).
TEST(PeerTableTest, ARelayedPeerIsUpgradedToADirectLinkWhateverTheOrder) {
    std::vector<Link> links{kWeUdp, kWeTcp, kTheyUdp, kWeRelay};
    const auto by_route = [](const Link& a, const Link& b) { return a.route.conn < b.route.conn; };
    std::sort(links.begin(), links.end(), by_route);

    int orders = 0;
    do {
        ++orders;
        EXPECT_EQ(survivor(true, links), "we-dialed/udp")
            << "arrival order decided the survivor (order #" << orders << ")";
        EXPECT_EQ(survivor(false, mirrored(links)), "we-dialed/udp")
            << "the far end kept a different link (order #" << orders << ")";
    } while (std::next_permutation(links.begin(), links.end(), by_route));

    EXPECT_EQ(orders, 24) << "not every arrival order was tried";
}

// Resolving a duplicate is only half the job: the caller has to be told which
// connection to tear down, and it is not always the newcomer. Getting this back to
// front would either leak the loser or close the link that just won.
TEST(PeerTableTest, TheLoserIsHandedBackToBeClosed) {
    PeerTable table;
    const PeerRoute tcp_route{0, 1}, udp_route{0, 2}, late_tcp_route{0, 3};

    const auto first = table.add(info_for(kWeTcp), tcp_route, /*prefer_outbound=*/true);
    EXPECT_EQ(first.result, PeerTable::AddResult::NewPeer);
    EXPECT_FALSE(first.close.has_value()) << "a first connection has no loser";

    // The datagram sibling arrives second and takes over: the loser is the link
    // already in the table, not the newcomer.
    const auto second = table.add(info_for(kWeUdp), udp_route, true);
    EXPECT_EQ(second.result, PeerTable::AddResult::Replaced);
    ASSERT_TRUE(second.close.has_value());
    EXPECT_EQ(*second.close, tcp_route);

    // The same pair the other way round: the newcomer loses and closes itself.
    const auto third = table.add(info_for(kWeTcp), late_tcp_route, true);
    EXPECT_EQ(third.result, PeerTable::AddResult::Rejected);
    ASSERT_TRUE(third.close.has_value());
    EXPECT_EQ(*third.close, late_tcp_route);

    EXPECT_EQ(table.size(), 1u) << "a duplicate was counted as a second peer";
    EXPECT_EQ(table.route(kPeer), udp_route);

    // The superseded link is still being torn down somewhere, and its teardown
    // carries the route it had. That must not take the survivor down with it.
    EXPECT_FALSE(table.remove(kPeer, tcp_route)) << "a stale teardown evicted the live link";
    EXPECT_EQ(table.route(kPeer), udp_route);
    EXPECT_TRUE(table.remove(kPeer, udp_route));
    EXPECT_EQ(table.size(), 0u);
}
