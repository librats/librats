#include <gtest/gtest.h>

#include "librats/bittorrent/mse.h"
#include "librats/crypto/sha1.h"

#include <cstring>
#include <string>
#include <vector>

using namespace librats;
using namespace librats::bittorrent;
using namespace librats::bittorrent::mse;

namespace {

InfoHash make_hash(std::uint8_t seed) {
    InfoHash ih{};
    for (std::size_t i = 0; i < ih.size(); ++i) ih[i] = std::uint8_t(seed + i);
    return ih;
}

Bytes bt_handshake(const InfoHash& ih) {
    Bytes h;
    h.push_back(19);
    const char proto[] = "BitTorrent protocol";
    h.insert(h.end(), proto, proto + 19);
    h.insert(h.end(), 8, 0);
    h.insert(h.end(), ih.begin(), ih.end());
    const std::string id = "-LR0001-0123456789ab";
    h.insert(h.end(), id.begin(), id.end());
    return h;
}

/// Run two Handshakes against each other over an in-memory wire, delivering bytes
/// in chunks of @p chunk (0 = all at once) to exercise partial reads.
struct Pair {
    Handshake::Status a_status = Handshake::Status::NeedMore;
    Handshake::Status b_status = Handshake::Status::NeedMore;
    bool              stalled  = false;
};

Pair pump(Handshake& a, Handshake& b, std::size_t chunk = 0) {
    Pair r;
    Bytes to_b = a.take_output();
    Bytes to_a;
    for (int round = 0; round < 200; ++round) {
        if (to_a.empty() && to_b.empty()) { r.stalled = true; break; }

        auto deliver = [&](Handshake& side, Bytes& queue, Handshake::Status& status, Bytes& reply) {
            while (!queue.empty()) {
                const std::size_t n = chunk ? (std::min)(chunk, queue.size()) : queue.size();
                status = side.consume(queue.data(), n);
                queue.erase(queue.begin(), queue.begin() + std::ptrdiff_t(n));
                Bytes out = side.take_output();
                reply.insert(reply.end(), out.begin(), out.end());
                if (status != Handshake::Status::NeedMore) break;
            }
        };

        deliver(b, to_b, r.b_status, to_a);
        if (r.b_status == Handshake::Status::Failed) break;
        deliver(a, to_a, r.a_status, to_b);
        if (r.a_status == Handshake::Status::Failed) break;

        if (r.a_status == Handshake::Status::Done && r.b_status == Handshake::Status::Done) break;
    }
    return r;
}

Handshake::SkeyResolver resolver_for(const InfoHash& ih) {
    return [ih](const std::uint8_t* obfuscated, const std::uint8_t* req3, InfoHash& out) {
        if (!skey_matches(obfuscated, req3, ih)) return false;
        out = ih;
        return true;
    };
}

} // namespace

// ---- primitives ----

// The 1024-byte keystream discard is part of the wire format, not an optimisation,
// so it is pinned to a value computed independently (a 15-line reference RC4 in
// Python) rather than to whatever this implementation happens to produce.
TEST(BtMse, Rc4MatchesReferenceAfterTheSpecDiscard) {
    Rc4Cipher c;
    const std::uint8_t key[] = {'K', 'e', 'y'};
    c.init(key, sizeof(key));

    std::uint8_t data[] = {'P', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'};
    c.process(data, sizeof(data));

    const std::uint8_t expect[] = {0x9a, 0xe4, 0x66, 0x36, 0x8e, 0x7e, 0xa8, 0xf2, 0xf5};
    EXPECT_EQ(std::memcmp(data, expect, sizeof(expect)), 0);
}

TEST(BtMse, Rc4IsItsOwnInverse) {
    const std::uint8_t key[] = {1, 2, 3, 4, 5};
    Bytes plain(5000);
    for (std::size_t i = 0; i < plain.size(); ++i) plain[i] = std::uint8_t(i * 7 + 3);

    Bytes buf = plain;
    Rc4Cipher enc, dec;
    enc.init(key, sizeof(key));
    dec.init(key, sizeof(key));
    enc.process(buf.data(), buf.size());
    EXPECT_NE(buf, plain);
    dec.process(buf.data(), buf.size());
    EXPECT_EQ(buf, plain);
}

// A stream cipher only survives being applied piecewise if its state advances
// exactly with the bytes — which is what the whole send/receive path relies on.
TEST(BtMse, Rc4IsPositionIndependentOfChunking) {
    const std::uint8_t key[] = {9, 8, 7};
    Bytes whole(777), piecewise(777);
    for (std::size_t i = 0; i < whole.size(); ++i) whole[i] = piecewise[i] = std::uint8_t(i);

    Rc4Cipher a;
    a.init(key, sizeof(key));
    a.process(whole.data(), whole.size());

    Rc4Cipher b;
    b.init(key, sizeof(key));
    for (std::size_t off = 0; off < piecewise.size();) {
        const std::size_t n = (std::min)(std::size_t(13), piecewise.size() - off);
        b.process(piecewise.data() + off, n);
        off += n;
    }
    EXPECT_EQ(whole, piecewise);
}

TEST(BtMse, DiffieHellmanAgreesOnASharedSecret) {
    DhKeyExchange a, b;
    ASSERT_TRUE(a.compute_secret(b.public_key().data()));
    ASSERT_TRUE(b.compute_secret(a.public_key().data()));
    EXPECT_EQ(a.secret(), b.secret());

    // A 768-bit secret should not be leading-zero padded in practice; a modexp
    // that silently produced 0 or 1 would still "agree" above.
    bool nonzero = false;
    for (std::uint8_t byte : a.secret()) nonzero = nonzero || byte != 0;
    EXPECT_TRUE(nonzero);
}

TEST(BtMse, DiffieHellmanRejectsDegeneratePublicKeys) {
    DhKeyExchange dh;
    std::array<std::uint8_t, kKeyLen> zero{};
    std::array<std::uint8_t, kKeyLen> one{};
    one[kKeyLen - 1] = 1;
    std::array<std::uint8_t, kKeyLen> big{};
    big.fill(0xFF);   // >= P, and P-1 itself is excluded too

    EXPECT_FALSE(dh.compute_secret(zero.data()));
    EXPECT_FALSE(dh.compute_secret(one.data()));
    EXPECT_FALSE(dh.compute_secret(big.data()));
}

TEST(BtMse, SkeyMatchesOnlyTheRightTorrent) {
    // Build an obfuscated hash the way an initiator does, then check the predicate
    // recovers it and rejects a near miss.
    const InfoHash ih    = make_hash(0x40);
    const InfoHash other = make_hash(0x41);

    std::array<std::uint8_t, 20> req3{};
    for (std::size_t i = 0; i < req3.size(); ++i) req3[i] = std::uint8_t(0xA5 ^ i);

    librats::SHA1 h;
    const char tag[] = "req2";
    h.update(reinterpret_cast<const std::uint8_t*>(tag), 4);
    h.update(ih.data(), ih.size());
    const auto req2 = h.finalize_bytes();

    std::array<std::uint8_t, 20> obfuscated{};
    for (std::size_t i = 0; i < obfuscated.size(); ++i)
        obfuscated[i] = std::uint8_t(req2[i] ^ req3[i]);

    EXPECT_TRUE(skey_matches(obfuscated.data(), req3.data(), ih));
    EXPECT_FALSE(skey_matches(obfuscated.data(), req3.data(), other));
}

// ---- the handshake, end to end ----

TEST(BtMse, HandshakeCompletesAndAgreesOnKeys) {
    const InfoHash ih = make_hash(0x10);
    const Bytes    ia = bt_handshake(ih);

    Handshake a(ih, ia, kBoth);
    Handshake b(resolver_for(ih), kBoth);

    const Pair r = pump(a, b);
    ASSERT_EQ(r.a_status, Handshake::Status::Done) << a.error();
    ASSERT_EQ(r.b_status, Handshake::Status::Done) << b.error();

    // The receiver recovered the torrent without it ever being sent in the clear,
    // and got the initiator's payload out intact.
    EXPECT_EQ(b.result().info_hash, ih);
    EXPECT_EQ(b.result().initial_payload, ia);

    // Both agreed on RC4 (it outranks plaintext when both are offered).
    EXPECT_TRUE(a.result().rc4_payload);
    EXPECT_TRUE(b.result().rc4_payload);

    // And the four cipher halves pair up: what A encrypts, B decrypts, and back.
    Bytes msg = {'h', 'e', 'l', 'l', 'o', ' ', 'p', 'e', 'e', 'r'};
    Bytes wire = msg;
    a.result().send_cipher.process(wire.data(), wire.size());
    EXPECT_NE(wire, msg);
    b.result().recv_cipher.process(wire.data(), wire.size());
    EXPECT_EQ(wire, msg);

    Bytes back = msg;
    b.result().send_cipher.process(back.data(), back.size());
    a.result().recv_cipher.process(back.data(), back.size());
    EXPECT_EQ(back, msg);
}

// Both pads are of unpredictable length and the peer never says how long they are,
// so every reader has to scan for a marker. Running the same handshake byte at a
// time is the sharpest test of that: no field can be assumed to arrive whole.
TEST(BtMse, HandshakeSurvivesByteAtATimeDelivery) {
    const InfoHash ih = make_hash(0x20);
    const Bytes    ia = bt_handshake(ih);

    Handshake a(ih, ia, kBoth);
    Handshake b(resolver_for(ih), kBoth);

    const Pair r = pump(a, b, /*chunk=*/1);
    ASSERT_EQ(r.a_status, Handshake::Status::Done) << a.error();
    ASSERT_EQ(r.b_status, Handshake::Status::Done) << b.error();
    EXPECT_EQ(b.result().initial_payload, ia);
}

// Repeat it: the pads are random lengths, so a single run only exercises one
// alignment of markers against field boundaries.
TEST(BtMse, HandshakeIsStableAcrossRandomPadLengths) {
    for (int i = 0; i < 30; ++i) {
        const InfoHash ih = make_hash(std::uint8_t(i));
        const Bytes    ia = bt_handshake(ih);
        Handshake a(ih, ia, kBoth);
        Handshake b(resolver_for(ih), kBoth);
        const Pair r = pump(a, b, /*chunk=*/7);
        ASSERT_EQ(r.a_status, Handshake::Status::Done) << "run " << i << ": " << a.error();
        ASSERT_EQ(r.b_status, Handshake::Status::Done) << "run " << i << ": " << b.error();
        ASSERT_EQ(b.result().initial_payload, ia) << "run " << i;
    }
}

TEST(BtMse, NegotiatesPlaintextWhenThatIsAllOneSideAllows) {
    const InfoHash ih = make_hash(0x30);
    Handshake a(ih, bt_handshake(ih), kPlaintext);   // we only offer plaintext
    Handshake b(resolver_for(ih), kBoth);

    const Pair r = pump(a, b);
    ASSERT_EQ(r.a_status, Handshake::Status::Done) << a.error();
    ASSERT_EQ(r.b_status, Handshake::Status::Done) << b.error();
    // Handshake obfuscated, payload in the clear.
    EXPECT_FALSE(a.result().rc4_payload);
    EXPECT_FALSE(b.result().rc4_payload);
}

TEST(BtMse, FailsWhenNoMethodIsInCommon) {
    const InfoHash ih = make_hash(0x31);
    Handshake a(ih, bt_handshake(ih), kPlaintext);
    Handshake b(resolver_for(ih), kRc4);

    const Pair r = pump(a, b);
    EXPECT_EQ(r.b_status, Handshake::Status::Failed);
    EXPECT_FALSE(b.error().empty());
}

// The receiver holds a different torrent: it cannot derive the RC4 keys at all, so
// it must give up rather than carry on with garbage.
TEST(BtMse, ReceiverRejectsAStreamKeyItCannotResolve) {
    const InfoHash wanted = make_hash(0x50);
    const InfoHash held   = make_hash(0x60);

    Handshake a(wanted, bt_handshake(wanted), kBoth);
    Handshake b(resolver_for(held), kBoth);

    const Pair r = pump(a, b);
    EXPECT_EQ(r.b_status, Handshake::Status::Failed);
    EXPECT_NE(b.error().find("torrent"), std::string::npos) << b.error();
}

TEST(BtMse, GarbageIsRejectedRatherThanBufferedForever) {
    Handshake b(resolver_for(make_hash(0x70)), kBoth);

    // 96 bytes of "public key" then endless noise that never contains the sync
    // hash. The pad budget has to run out and end the connection.
    Bytes junk(4096);
    for (std::size_t i = 0; i < junk.size(); ++i) junk[i] = std::uint8_t(i * 31 + 7);

    Handshake::Status st = Handshake::Status::NeedMore;
    for (int i = 0; i < 8 && st == Handshake::Status::NeedMore; ++i)
        st = b.consume(junk.data(), junk.size());

    EXPECT_EQ(st, Handshake::Status::Failed);
    EXPECT_FALSE(b.error().empty());
}

// Anything the peer pipelines behind its handshake must come back untouched: the
// caller decrypts it (or not) according to what crypto_select settled on, and a
// handshake that swallowed or double-decrypted those bytes would corrupt the first
// message of the session.
TEST(BtMse, PostHandshakeBytesAreHandedBackRaw) {
    const InfoHash ih = make_hash(0x80);
    const Bytes    ia = bt_handshake(ih);

    Handshake a(ih, ia, kBoth);
    Handshake b(resolver_for(ih), kBoth);
    const Pair r = pump(a, b);
    ASSERT_EQ(r.a_status, Handshake::Status::Done) << a.error();
    ASSERT_EQ(r.b_status, Handshake::Status::Done) << b.error();
    ASSERT_TRUE(a.leftover().empty());

    // B sends a payload message immediately after its step 4; A should be able to
    // decrypt it with the receive cipher the handshake handed over.
    Bytes payload = {0x00, 0x00, 0x00, 0x01, 0x01};   // an "unchoke"
    Bytes wire    = payload;
    b.result().send_cipher.process(wire.data(), wire.size());

    Handshake a2(ih, ia, kBoth);
    Handshake b2(resolver_for(ih), kBoth);
    // Re-run so the ciphers line up with a stream that really carried the extra
    // bytes, then feed them in behind the handshake.
    Bytes to_b = a2.take_output();
    ASSERT_EQ(b2.consume(to_b.data(), to_b.size()), Handshake::Status::NeedMore);
    Bytes to_a = b2.take_output();
    ASSERT_EQ(a2.consume(to_a.data(), to_a.size()), Handshake::Status::NeedMore);
    to_b = a2.take_output();
    ASSERT_EQ(b2.consume(to_b.data(), to_b.size()), Handshake::Status::Done) << b2.error();

    Bytes tail = b2.take_output();                    // step 4
    Bytes extra = payload;
    b2.result().send_cipher.process(extra.data(), extra.size());
    tail.insert(tail.end(), extra.begin(), extra.end());

    ASSERT_EQ(a2.consume(tail.data(), tail.size()), Handshake::Status::Done) << a2.error();
    Bytes left = a2.leftover().to_bytes();
    ASSERT_EQ(left.size(), payload.size());
    a2.result().recv_cipher.process(left.data(), left.size());
    EXPECT_EQ(left, payload);
}
