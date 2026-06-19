#include <gtest/gtest.h>

#include "peer/peer_id.h"
#include "security/identity.h"
#include "security/noise_security.h"
#include "security/plaintext_security.h"

#include <memory>
#include <string>

using namespace librats;

namespace {

std::string to_str(const Bytes& b) { return std::string(b.begin(), b.end()); }

// Result of driving two handshakers to completion against each other.
struct HandshakeResult {
    std::unique_ptr<Session> initiator_session;
    std::unique_ptr<Session> responder_session;
    PeerId initiator_view_of_remote;  // what the initiator thinks the responder is
    PeerId responder_view_of_remote;  // what the responder thinks the initiator is
};

// Ping-pong the two handshakers' messages in memory until both produce a Session.
HandshakeResult drive(SecurityProvider& a_provider, SecurityProvider& b_provider) {
    auto a = a_provider.create(ConnRole::Outbound);  // initiator
    auto b = b_provider.create(ConnRole::Inbound);   // responder

    HandshakeResult result;
    Bytes a_to_b, b_to_a, scratch;

    EXPECT_TRUE(a->start(a_to_b));
    EXPECT_TRUE(b->start(scratch));
    EXPECT_TRUE(scratch.empty()) << "responder must not speak first";

    for (int guard = 0; guard < 8; ++guard) {
        if (!a_to_b.empty()) {
            Bytes reply;
            auto oc = b->consume(a_to_b, reply);
            EXPECT_NE(oc.status, Handshaker::Outcome::Failed);
            if (oc.status == Handshaker::Outcome::Done) {
                result.responder_session = std::move(oc.session);
                result.responder_view_of_remote = oc.remote_id;
            }
            a_to_b.clear();
            b_to_a = std::move(reply);
        } else if (!b_to_a.empty()) {
            Bytes reply;
            auto oc = a->consume(b_to_a, reply);
            EXPECT_NE(oc.status, Handshaker::Outcome::Failed);
            if (oc.status == Handshaker::Outcome::Done) {
                result.initiator_session = std::move(oc.session);
                result.initiator_view_of_remote = oc.remote_id;
            }
            b_to_a.clear();
            a_to_b = std::move(reply);
        } else {
            break;
        }
        if (result.initiator_session && result.responder_session) break;
    }
    return result;
}

// Both sessions can talk to each other after the handshake.
void expect_bidirectional(Session& a, Session& b) {
    Bytes ct, pt;
    ASSERT_TRUE(a.encrypt(ByteView(std::string("ping")), ct));
    ASSERT_TRUE(b.decrypt(ct, pt));
    EXPECT_EQ(to_str(pt), "ping");

    ASSERT_TRUE(b.encrypt(ByteView(std::string("pong")), ct));
    ASSERT_TRUE(a.decrypt(ct, pt));
    EXPECT_EQ(to_str(pt), "pong");
}

} // namespace

TEST(PeerIdTest, DerivedFromKeyIsStableAndHex) {
    Identity id = Identity::generate();
    PeerId again = PeerId::from_public_key(id.static_keypair.public_key, rats::NOISE_DH_SIZE);
    EXPECT_EQ(id.id, again);
    EXPECT_EQ(id.id.to_hex().size(), PeerId::kSize * 2);

    auto parsed = PeerId::from_hex(id.id.to_hex());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, id.id);
}

TEST(PeerIdTest, DistinctKeysYieldDistinctIds) {
    EXPECT_NE(Identity::generate().id, Identity::generate().id);
}

TEST(PeerIdTest, FromBytesIsRawNotHashed) {
    Identity id = Identity::generate();
    auto raw = PeerId::from_bytes(ByteView(id.id.bytes().data(), PeerId::kSize));
    ASSERT_TRUE(raw.has_value());
    EXPECT_EQ(*raw, id.id);
    EXPECT_FALSE(PeerId::from_bytes(ByteView(id.id.bytes().data(), 5)).has_value());
}

TEST(HandshakeTest, NoiseXXMutualAuthAndEncryptedTransport) {
    Identity alice = Identity::generate();
    Identity bob   = Identity::generate();
    NoiseSecurity a(alice), b(bob);

    auto r = drive(a, b);
    ASSERT_TRUE(r.initiator_session && r.responder_session);

    // Each side derived the other's self-certifying PeerId from its static key.
    EXPECT_EQ(r.initiator_view_of_remote, bob.id);
    EXPECT_EQ(r.responder_view_of_remote, alice.id);

    EXPECT_TRUE(r.initiator_session->is_secure());
    EXPECT_EQ(r.initiator_session->remote_id(), bob.id);
    expect_bidirectional(*r.initiator_session, *r.responder_session);
}

TEST(HandshakeTest, NoiseCiphertextDiffersFromPlaintext) {
    Identity alice = Identity::generate(), bob = Identity::generate();
    NoiseSecurity a(alice), b(bob);
    auto r = drive(a, b);
    ASSERT_TRUE(r.initiator_session && r.responder_session);

    Bytes ct;
    const std::string secret = "the password is hunter2";
    ASSERT_TRUE(r.initiator_session->encrypt(ByteView(secret), ct));
    EXPECT_NE(to_str(ct), secret);
    EXPECT_GT(ct.size(), secret.size());  // AEAD tag adds overhead
}

TEST(HandshakeTest, PlaintextExchangesIdsButDoesNotEncrypt) {
    Identity alice = Identity::generate(), bob = Identity::generate();
    PlaintextSecurity a(alice), b(bob);

    auto r = drive(a, b);
    ASSERT_TRUE(r.initiator_session && r.responder_session);

    EXPECT_EQ(r.initiator_view_of_remote, bob.id);
    EXPECT_EQ(r.responder_view_of_remote, alice.id);
    EXPECT_FALSE(r.initiator_session->is_secure());
    expect_bidirectional(*r.initiator_session, *r.responder_session);
}
