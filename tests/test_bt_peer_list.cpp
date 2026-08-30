#include <gtest/gtest.h>

#include "librats/bittorrent/peer_list.h"

#include <algorithm>

using namespace librats::bittorrent;

namespace {

using Clock = PeerList::Clock;

// A fixed origin plus explicit offsets: the reconnect backoff is a function of
// time, so every test that touches it advances a value it controls rather than
// the wall clock. T0 is deliberately not the epoch — a peer that has never been
// dialed is recognised by last_attempt == time_point{}, and starting at the epoch
// would make "never dialed" and "dialed at T0" indistinguishable.
const Clock::time_point T0 = Clock::time_point{} + std::chrono::hours(24);

Clock::time_point at(std::chrono::seconds offset) { return T0 + offset; }

bool has(const std::vector<PeerList::Endpoint>& v, const std::string& ip, std::uint16_t port) {
    return std::any_of(v.begin(), v.end(),
                       [&](const PeerList::Endpoint& e) { return e.ip == ip && e.port == port; });
}

} // namespace

TEST(BtPeerList, AddDeduplicates) {
    PeerList pl;
    EXPECT_TRUE(pl.add("1.2.3.4", 5, PeerSource::Tracker));
    EXPECT_FALSE(pl.add("1.2.3.4", 5, PeerSource::Pex));  // same endpoint, just adds a source
    EXPECT_EQ(pl.size(), 1u);
    EXPECT_TRUE(pl.contains("1.2.3.4", 5));
}

TEST(BtPeerList, RejectsInvalid) {
    PeerList pl;
    EXPECT_FALSE(pl.add("", 5, PeerSource::Tracker));
    EXPECT_FALSE(pl.add("1.2.3.4", 0, PeerSource::Tracker));
    EXPECT_EQ(pl.size(), 0u);
}

TEST(BtPeerList, ConnectCandidatesMarkConnecting) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    pl.add("2.2.2.2", 2, PeerSource::Dht);

    auto first = pl.connect_candidates(10, T0);
    EXPECT_EQ(first.size(), 2u);
    // Already handed out (connecting) → not returned again.
    EXPECT_TRUE(pl.connect_candidates(10, T0).empty());
    EXPECT_EQ(pl.num_candidates(T0), 0u);
}

TEST(BtPeerList, NewlyDiscoveredPeerIsDialedImmediately) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);
    // No prior attempt, so the backoff must not hold it back at any time value.
    EXPECT_EQ(pl.num_candidates(T0), 1u);
    EXPECT_EQ(pl.connect_candidates(10, T0).size(), 1u);
}

TEST(BtPeerList, RespectsMaxAndFreesOnFailure) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    pl.add("2.2.2.2", 2, PeerSource::Tracker);

    auto one = pl.connect_candidates(1, T0);
    EXPECT_EQ(one.size(), 1u);              // capped
    EXPECT_EQ(pl.num_candidates(T0), 1u);   // the other is still eligible

    pl.on_connect_failed(one[0].ip, one[0].port, T0);
    // Freed, but now serving a (fail_count + 1) * 60 s backoff — so still not a
    // candidate until it elapses; the untried peer remains one throughout.
    EXPECT_EQ(pl.num_candidates(T0), 1u);
    EXPECT_EQ(pl.num_candidates(at(std::chrono::seconds(119))), 1u);
    EXPECT_EQ(pl.num_candidates(at(std::chrono::seconds(120))), 2u);
}

TEST(BtPeerList, DropsAfterTooManyFailures) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    // Each failure lengthens the backoff, so step the clock well past it every round.
    auto now = T0;
    for (std::uint32_t i = 0; i < PeerList::kMaxFails; ++i) {
        auto c = pl.connect_candidates(1, now);
        ASSERT_FALSE(c.empty()) << "round " << i;
        pl.on_connect_failed(c[0].ip, c[0].port, now);
        now += PeerList::kMinReconnectInterval * (PeerList::kMaxFails + 1);
    }
    EXPECT_EQ(pl.num_candidates(now), 0u);  // exhausted its chances, however long we wait
    EXPECT_EQ(pl.num_candidates(now + std::chrono::hours(24)), 0u);
}

TEST(BtPeerList, ConnectedClearsFailures) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    auto c = pl.connect_candidates(1, T0);
    pl.on_connect_failed(c[0].ip, c[0].port, T0);
    pl.set_connected("1.1.1.1", 1, /*encrypted=*/false);
    EXPECT_EQ(pl.num_candidates(T0), 0u);  // connected, not a candidate

    // Disconnected after a completed handshake: not a failure, so the backoff is the
    // base interval rather than the doubled one the earlier failure would have set.
    const auto closed = at(std::chrono::seconds(10));
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::Clean, closed);
    EXPECT_EQ(pl.num_candidates(closed + std::chrono::seconds(59)), 0u);
    EXPECT_EQ(pl.num_candidates(closed + PeerList::kMinReconnectInterval), 1u);
}

// The log this backoff came from: a peer that accepts TCP and then closes on us
// (a client that requires encryption does exactly that) was re-dialed on every
// one-second torrent tick for the life of the torrent, because a disconnect
// carried no penalty at all.
TEST(BtPeerList, PeerThatDropsUsBeforeHandshakeBacksOff) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);

    auto c = pl.connect_candidates(1, T0);
    ASSERT_EQ(c.size(), 1u);
    // Connected, then closed before the handshake completed → counts as a failure.
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::Failed, T0);

    // One second later — the old dial cadence — it must NOT be handed out again.
    EXPECT_TRUE(pl.connect_candidates(1, at(std::chrono::seconds(1))).empty());
    EXPECT_TRUE(pl.connect_candidates(1, at(std::chrono::seconds(119))).empty());
    // (fail_count 1 + 1) * 60 s = 120 s.
    EXPECT_EQ(pl.connect_candidates(1, at(std::chrono::seconds(120))).size(), 1u);
}

// pause() drops every peer on purpose; resume() must be able to dial them straight
// back. A released peer is therefore neither penalised nor delayed — libtorrent's
// fast_reconnect, which deliberately leaves last_connected unstamped.
TEST(BtPeerList, ReleasedPeerIsImmediatelyRedialable) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);

    ASSERT_EQ(pl.connect_candidates(1, T0).size(), 1u);
    pl.set_connected("1.1.1.1", 1, /*encrypted=*/false);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::Release, T0);

    // No backoff at all: the very next dial round gets it back.
    EXPECT_EQ(pl.num_candidates(T0), 1u);
    EXPECT_EQ(pl.connect_candidates(1, T0).size(), 1u);
}

// A release must not launder away a penalty the peer had already earned.
TEST(BtPeerList, ReleasePreservesEarlierFailures) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);

    pl.connect_candidates(1, T0);
    pl.on_connect_failed("1.1.1.1", 1, T0);          // fail_count = 1

    const auto later = at(std::chrono::seconds(120));
    ASSERT_EQ(pl.connect_candidates(1, later).size(), 1u);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::Release, later);

    // Redialable now, but a further failure still starts from fail_count 1 → 180 s.
    ASSERT_EQ(pl.connect_candidates(1, later).size(), 1u);
    pl.on_connect_failed("1.1.1.1", 1, later);       // fail_count = 2
    EXPECT_EQ(pl.num_candidates(later + std::chrono::seconds(179)), 0u);
    EXPECT_EQ(pl.num_candidates(later + std::chrono::seconds(180)), 1u);
}

TEST(BtPeerList, BackoffGrowsWithFailureCount) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);

    pl.connect_candidates(1, T0);
    pl.on_connect_failed("1.1.1.1", 1, T0);                       // fail_count = 1 → 120 s
    EXPECT_EQ(pl.num_candidates(at(std::chrono::seconds(119))), 0u);

    const auto second = at(std::chrono::seconds(120));
    ASSERT_EQ(pl.connect_candidates(1, second).size(), 1u);
    pl.on_connect_failed("1.1.1.1", 1, second);                   // fail_count = 2 → 180 s
    EXPECT_EQ(pl.num_candidates(second + std::chrono::seconds(179)), 0u);
    EXPECT_EQ(pl.num_candidates(second + std::chrono::seconds(180)), 1u);
}

// Under EncPolicy::Enabled the dialer follows this flag, so a peer that turns away
// one form of handshake is reached with the other on its next turn. It starts
// obfuscated: most of the swarm speaks MSE and a growing part of it accepts
// nothing else.
TEST(BtPeerList, EncryptionPreferenceAlternatesPerAttempt) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);

    auto first = pl.connect_candidates(1, T0);
    ASSERT_EQ(first.size(), 1u);
    EXPECT_TRUE(first[0].prefer_encrypted);

    pl.on_connect_failed("1.1.1.1", 1, T0);
    auto second = pl.connect_candidates(1, at(std::chrono::seconds(120)));
    ASSERT_EQ(second.size(), 1u);
    EXPECT_FALSE(second[0].prefer_encrypted) << "the second attempt must try the other form";

    pl.on_connect_failed("1.1.1.1", 1, at(std::chrono::seconds(120)));
    auto third = pl.connect_candidates(1, at(std::chrono::seconds(500)));
    ASSERT_EQ(third.size(), 1u);
    EXPECT_TRUE(third[0].prefer_encrypted);
}

TEST(BtPeerList, ASuccessfulHandshakePinsTheModeThatWorked) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);

    // First attempt is encrypted and fails; the second, plaintext, gets through.
    ASSERT_TRUE(pl.connect_candidates(1, T0)[0].prefer_encrypted);
    pl.on_connect_failed("1.1.1.1", 1, T0);

    const auto t1 = at(std::chrono::seconds(120));
    ASSERT_FALSE(pl.connect_candidates(1, t1)[0].prefer_encrypted);
    pl.set_connected("1.1.1.1", 1, /*encrypted=*/false);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::Clean, t1);

    // The next dial should go straight back to what worked rather than resume
    // alternating and waste an attempt on the form we know it refuses.
    const auto t2 = at(std::chrono::seconds(300));
    auto again = pl.connect_candidates(1, t2);
    ASSERT_EQ(again.size(), 1u);
    EXPECT_FALSE(again[0].prefer_encrypted);
}

// Learning that a peer wanted the other form of handshake costs one round trip;
// making it cost a minute of backoff on top is the thing this waiver removes.
TEST(BtPeerList, FailedRetryNowSkipsTheBackoff) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);

    auto first = pl.connect_candidates(1, T0);
    ASSERT_EQ(first.size(), 1u);
    ASSERT_TRUE(first[0].prefer_encrypted);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::FailedRetryNow, T0);

    // Eligible again straight away — and with the other form, since the hand-out
    // above already flipped the preference.
    auto second = pl.connect_candidates(1, T0);
    ASSERT_EQ(second.size(), 1u) << "the waiver did not make the peer eligible";
    EXPECT_FALSE(second[0].prefer_encrypted);
}

// The waiver skips the wait, not the penalty: a peer that refuses us whatever we
// open with still runs out of chances rather than being dialed forever.
TEST(BtPeerList, FailedRetryNowStillCountsAsAFailure) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);

    pl.connect_candidates(1, T0);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::FailedRetryNow, T0);
    pl.connect_candidates(1, T0);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::FailedRetryNow, T0);

    // Both waivers are spent, so the third failure serves its time like any other.
    // Each of the three counted, so the wait is (3 + 1) * 60 s.
    auto third = pl.connect_candidates(1, T0);
    ASSERT_EQ(third.size(), 1u);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::FailedRetryNow, T0);
    EXPECT_EQ(pl.num_candidates(T0), 0u) << "a third waiver was granted";
    EXPECT_EQ(pl.num_candidates(at(std::chrono::seconds(239))), 0u);
    EXPECT_EQ(pl.num_candidates(at(std::chrono::seconds(240))), 1u);

    // And the failures still accumulate toward the drop threshold.
    auto now = at(std::chrono::seconds(240));
    while (pl.num_candidates(now) > 0) {
        auto c = pl.connect_candidates(1, now);
        pl.on_disconnected(c[0].ip, c[0].port, PeerList::Disconnect::FailedRetryNow, now);
        now += PeerList::kMinReconnectInterval * (PeerList::kMaxFails + 1);
    }
    EXPECT_EQ(pl.num_candidates(now + std::chrono::hours(24)), 0u)
        << "the peer was never dropped";
}

TEST(BtPeerList, BanRemovesFromCandidates) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    pl.ban("1.1.1.1", 1);
    EXPECT_EQ(pl.num_candidates(T0), 0u);
    EXPECT_TRUE(pl.connect_candidates(10, T0).empty());
}

TEST(BtPeerList, LowerFailureCountRanksFirst) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Tracker);
    pl.add("2.2.2.2", 2, PeerSource::Tracker);
    // Fail .1 once and release it; .2 disconnects cleanly. Both are past their
    // backoff by `later`, but the failed one must rank behind.
    auto c = pl.connect_candidates(2, T0);
    ASSERT_EQ(c.size(), 2u);
    auto fail_ep = c[0];
    pl.on_connect_failed(fail_ep.ip, fail_ep.port, T0);
    pl.on_disconnected(c[1].ip, c[1].port, PeerList::Disconnect::Clean, T0);

    const auto later = at(std::chrono::seconds(120));
    ASSERT_EQ(pl.num_candidates(later), 2u);
    auto next = pl.connect_candidates(1, later);
    ASSERT_EQ(next.size(), 1u);
    EXPECT_FALSE(has(next, fail_ep.ip, fail_ep.port));  // the failed one is not first
}

// ---- uTP preference ----------------------------------------------------------
//
// Unlike the encryption form, which alternates, the uTP preference is a latch:
// every peer is assumed to speak it (most of the swarm does), and the first dial
// that fails to reach a handshake settles the question for good. Re-asking it every
// other attempt would spend a wasted connect timeout on a peer we already have the
// answer for.

TEST(BtPeerList, PeersAreDialedOverUtpUntilOneProvesOtherwise) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);
    auto c = pl.connect_candidates(1, T0);
    ASSERT_EQ(c.size(), 1u);
    EXPECT_TRUE(c[0].prefer_utp) << "a freshly discovered peer should be tried over uTP first";
}

TEST(BtPeerList, AFailedUtpDialSwitchesThePeerToTcp) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);
    ASSERT_TRUE(pl.connect_candidates(1, T0)[0].prefer_utp);

    pl.note_utp_dial_failed("1.1.1.1", 1);
    // FailedRetryNow, so the TCP attempt happens at once rather than a minute later:
    // one wasted round trip is the entire cost of the optimism above.
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::FailedRetryNow, T0);

    auto next = pl.connect_candidates(1, T0);
    ASSERT_EQ(next.size(), 1u) << "the waiver did not make the peer immediately dialable";
    EXPECT_FALSE(next[0].prefer_utp);
}

// The answer has to stick, or every second dial would pay the timeout again.
TEST(BtPeerList, TheUtpVerdictIsRememberedAcrossAttempts) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);
    pl.connect_candidates(1, T0);
    pl.note_utp_dial_failed("1.1.1.1", 1);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::Failed, T0);

    for (int attempt = 1; attempt <= 3; ++attempt) {
        const auto when = at(PeerList::kMinReconnectInterval * (attempt + 1) * (attempt + 1));
        auto       c    = pl.connect_candidates(1, when);
        ASSERT_EQ(c.size(), 1u) << "attempt " << attempt;
        EXPECT_FALSE(c[0].prefer_utp) << "attempt " << attempt << " went back to uTP";
        pl.on_disconnected(c[0].ip, c[0].port, PeerList::Disconnect::Failed, when);
    }
}

// A uTP connection that actually worked outranks the guess, and is never withdrawn:
// a peer that answered once will answer again, and a later failure is far more
// likely to be the peer being gone than the transport being wrong.
TEST(BtPeerList, AWorkingUtpConnectionPinsThePeerToUtp) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);
    pl.connect_candidates(1, T0);
    pl.set_connected("1.1.1.1", 1, /*encrypted=*/false, PeerTransport::Utp);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::Clean, T0);

    const auto later = at(PeerList::kMinReconnectInterval * 2);
    auto       c     = pl.connect_candidates(1, later);
    ASSERT_EQ(c.size(), 1u);
    EXPECT_TRUE(c[0].prefer_utp);

    // Even a subsequent failed uTP dial must not undo a confirmed one.
    pl.note_utp_dial_failed("1.1.1.1", 1);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::Failed, later);
    auto again = pl.connect_candidates(1, at(PeerList::kMinReconnectInterval * 10));
    ASSERT_EQ(again.size(), 1u);
    EXPECT_TRUE(again[0].prefer_utp);
}

// A peer that connects to *us* over uTP has proved the transport just as surely as
// one we dialed, so a later dial to it should start there.
TEST(BtPeerList, AnInboundUtpPeerCountsAsConfirmation) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Incoming);
    pl.note_utp_dial_failed("1.1.1.1", 1);          // an earlier dial had failed
    pl.set_connected("1.1.1.1", 1, false, PeerTransport::Utp);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::Clean, T0);

    auto c = pl.connect_candidates(1, at(PeerList::kMinReconnectInterval * 2));
    ASSERT_EQ(c.size(), 1u);
    EXPECT_TRUE(c[0].prefer_utp);
}

// The two preferences are independent: settling the transport must not disturb the
// encryption alternation, which has its own reason to keep flipping.
TEST(BtPeerList, TheTransportVerdictLeavesTheEncryptionAlternationAlone) {
    PeerList pl;
    pl.add("1.1.1.1", 1, PeerSource::Dht);
    auto first = pl.connect_candidates(1, T0);
    ASSERT_EQ(first.size(), 1u);
    const bool first_enc = first[0].prefer_encrypted;

    pl.note_utp_dial_failed("1.1.1.1", 1);
    pl.on_disconnected("1.1.1.1", 1, PeerList::Disconnect::FailedRetryNow, T0);

    auto second = pl.connect_candidates(1, T0);
    ASSERT_EQ(second.size(), 1u);
    EXPECT_NE(second[0].prefer_encrypted, first_enc);
}
