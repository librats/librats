#include <gtest/gtest.h>
#include "dht/storage.h"
#include "dht/dos_blocker.h"

#include <chrono>

using namespace librats::dht;
using librats::Address;

namespace {
InfoHash hash_of(uint8_t v) { InfoHash h; h.fill(v); return h; }
TimePoint at_min(int m) { return TimePoint{} + std::chrono::minutes(m); }
TimePoint at_sec(int s) { return TimePoint{} + std::chrono::seconds(s); }
}

TEST(DhtTokenManager, GeneratedTokenVerifies) {
    TokenManager tok;
    const Address peer("1.2.3.4", 6881);
    const InfoHash ih = hash_of(0xAA);

    const std::string t = tok.generate(peer, ih, at_min(0));
    EXPECT_FALSE(t.empty());
    EXPECT_TRUE(tok.verify(peer, ih, t, at_min(0)));
}

TEST(DhtTokenManager, RejectsWrongToken) {
    TokenManager tok;
    const Address peer("1.2.3.4", 6881);
    const InfoHash ih = hash_of(0xAA);
    const std::string t = tok.generate(peer, ih, at_min(0));

    EXPECT_FALSE(tok.verify(peer, ih, "bogus", at_min(0)));
    EXPECT_FALSE(tok.verify(peer, ih, "", at_min(0)));
    EXPECT_FALSE(tok.verify(Address("9.9.9.9", 6881), ih, t, at_min(0)));  // different ip
    EXPECT_FALSE(tok.verify(peer, hash_of(0xBB), t, at_min(0)));           // different info-hash
}

TEST(DhtTokenManager, TokenSurvivesOneRotationThenExpires) {
    TokenManager tok;
    const Address peer("1.2.3.4", 6881);
    const InfoHash ih = hash_of(0xAA);
    const std::string t = tok.generate(peer, ih, at_min(0));

    EXPECT_TRUE(tok.verify(peer, ih, t, at_min(6)));    // one rotation: still accepted (prev secret)
    EXPECT_FALSE(tok.verify(peer, ih, t, at_min(12)));  // two rotations: gone
}

TEST(DhtPeerStore, StoreGetDedupAndExpire) {
    PeerStore store;
    const InfoHash ih = hash_of(0x11);
    const Address a("5.5.5.1", 100), b("5.5.5.2", 200);

    store.store(ih, a, at_min(0));
    store.store(ih, a, at_min(0));   // duplicate → no growth
    store.store(ih, b, at_min(0));

    auto peers = store.get(ih);
    EXPECT_EQ(peers.size(), 2u);
    EXPECT_TRUE(store.get(hash_of(0x99)).empty());  // unknown info-hash

    store.expire(at_min(31));         // past the 30-minute TTL
    EXPECT_TRUE(store.get(ih).empty());
    EXPECT_EQ(store.hash_count(), 0u);
}

TEST(DhtDosBlocker, BlocksFloodThenRecovers) {
    DosBlocker dos;
    const std::string ip = "7.7.7.7";

    int allowed = 0;
    for (int i = 0; i < 60; ++i)
        if (dos.allow(ip, at_sec(0))) ++allowed;
    EXPECT_EQ(allowed, DosBlocker::kMaxPerWindow);   // burst capped, rest banned

    EXPECT_FALSE(dos.allow(ip, at_sec(60)));          // still within the 5-minute ban
    EXPECT_TRUE(dos.allow(ip, at_min(6)));            // ban elapsed → allowed again
    EXPECT_TRUE(dos.allow("8.8.8.8", at_sec(0)));     // a different IP is independent
}
