#include "librats/bittorrent/mse.h"
#include "librats/bittorrent/byte_io.h"
#include "librats/bittorrent/log.h"
#include "librats/crypto/sha1.h"

#include <algorithm>
#include <cstring>
#include <random>

namespace librats::bittorrent::mse {

namespace {

// ── Randomness ──────────────────────────────────────────────────────────────
//
// The DH exponent comes straight from random_device: it is drawn once per
// connection, so the cost is irrelevant and seeding a PRNG from a single 32-bit
// value to produce it would be strictly worse. The pads are cosmetic — their only
// job is to vary the message length — so a cheap engine is fine there.

void random_bytes(std::uint8_t* out, std::size_t len) {
    std::random_device rd;
    for (std::size_t i = 0; i < len; ++i) out[i] = std::uint8_t(rd() & 0xFF);
}

void pad_bytes(std::uint8_t* out, std::size_t len) {
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 255);
    for (std::size_t i = 0; i < len; ++i) out[i] = std::uint8_t(dist(gen));
}

std::size_t random_pad_len() {
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<std::size_t> dist(0, kMaxPad - 1);
    return dist(gen);
}

// ── 768-bit modular arithmetic ──────────────────────────────────────────────
//
// MSE fixes one group: generator 2 over the 768-bit prime below (RFC 2409 group
// 1). That is the whole reason this file carries a bignum at all — the project's
// own crypto is curve25519, which cannot do a plain DH over an arbitrary prime.
//
// The implementation is Montgomery multiplication (CIOS) over 24 32-bit limbs,
// little-endian. Montgomery is chosen because it needs no division at all: the
// only alternative, schoolbook long division for the modular reduction, is far
// more code and far easier to get subtly wrong.
//
// No attempt is made at constant time. MSE is obfuscation, not security: the
// shared secret protects nothing an attacker who can time us could not simply
// read off the wire anyway (the info-hash travels in the clear in step 1 of the
// plaintext handshake we would otherwise have sent).

constexpr int kLimbs = 24;  // 24 * 32 = 768 bits
using Num = std::array<std::uint32_t, kLimbs>;

/// P, big-endian. Note the top 64 bits are all ones, so 2^767 < P < 2^768 —
/// relied on below when reducing 2^768 mod P with a single subtraction.
constexpr std::uint8_t kPrimeBE[kKeyLen] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1, 0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22, 0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B, 0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45, 0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x3A,0x36,0x21, 0x00,0x00,0x00,0x00,0x00,0x09,0x05,0x63,
};

Num from_be(const std::uint8_t* be, std::size_t len) {
    Num n{};
    // Big-endian bytes fill limbs from the least significant end backwards.
    for (std::size_t i = 0; i < len; ++i) {
        const std::size_t rev = len - 1 - i;          // 0 = least significant byte
        n[rev / 4] |= std::uint32_t(be[i]) << ((rev % 4) * 8);
    }
    return n;
}

void to_be(const Num& n, std::uint8_t* out) {
    for (std::size_t i = 0; i < kKeyLen; ++i) {
        const std::size_t rev = kKeyLen - 1 - i;
        out[i] = std::uint8_t((n[rev / 4] >> ((rev % 4) * 8)) & 0xFF);
    }
}

int cmp(const Num& a, const Num& b) {
    for (int i = kLimbs - 1; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

/// a += b, returning the carry out of the top limb.
std::uint32_t add_in_place(Num& a, const Num& b) {
    std::uint64_t carry = 0;
    for (int i = 0; i < kLimbs; ++i) {
        const std::uint64_t s = std::uint64_t(a[i]) + b[i] + carry;
        a[i]  = std::uint32_t(s);
        carry = s >> 32;
    }
    return std::uint32_t(carry);
}

/// a -= b, returning the borrow out of the top limb.
std::uint32_t sub_in_place(Num& a, const Num& b) {
    std::uint64_t borrow = 0;
    for (int i = 0; i < kLimbs; ++i) {
        const std::uint64_t d = std::uint64_t(a[i]) - b[i] - borrow;
        a[i]   = std::uint32_t(d);
        borrow = (d >> 32) & 1;
    }
    return std::uint32_t(borrow);
}

/// The group constants, built once: P in limb form, -P^-1 mod 2^32 for the
/// Montgomery reduction, and R^2 mod P for entering Montgomery form.
struct Group {
    Num           p{};
    Num           r2{};      // 2^1536 mod P
    Num           one_mont{};// 2^768 mod P, i.e. Montgomery form of 1
    std::uint32_t n0inv = 0;

    Group() {
        p = from_be(kPrimeBE, kKeyLen);

        // n0inv = -p[0]^-1 mod 2^32. Newton's iteration doubles the number of
        // correct bits each round, so five rounds from a 1-bit seed cover 32.
        std::uint32_t inv = 1;
        for (int i = 0; i < 5; ++i) inv *= 2u - p[0] * inv;
        n0inv = std::uint32_t(0) - inv;

        // R mod P, where R = 2^768. P > 2^767 means R < 2P, so one subtraction
        // does it: R - P, computed as (0 - P) in 768-bit wraparound arithmetic.
        Num r_mod_p{};
        sub_in_place(r_mod_p, p);
        one_mont = r_mod_p;

        // R^2 mod P = (R mod P) * 2^768 mod P — 768 modular doublings. Cheap, and
        // it keeps the constant self-evident instead of a magic literal nobody can
        // check. Each doubling: t += t, then one conditional subtract (2t < 2P, so
        // one is always enough; a carry out of the top limb means 2t > P too).
        r2 = r_mod_p;
        for (int i = 0; i < 768; ++i) {
            const std::uint32_t carry = add_in_place(r2, r2);
            if (carry || cmp(r2, p) >= 0) sub_in_place(r2, p);
        }
    }
};

const Group& group() {
    static const Group g;
    return g;
}

/// out = a * b * R^-1 mod P (Montgomery product), CIOS form.
void mont_mul(const Num& a, const Num& b, Num& out) {
    const Group& g = group();
    std::uint32_t t[kLimbs + 2] = {0};

    for (int i = 0; i < kLimbs; ++i) {
        std::uint64_t carry = 0;
        for (int j = 0; j < kLimbs; ++j) {
            const std::uint64_t s = std::uint64_t(t[j]) + std::uint64_t(a[j]) * b[i] + carry;
            t[j]  = std::uint32_t(s);
            carry = s >> 32;
        }
        std::uint64_t s = std::uint64_t(t[kLimbs]) + carry;
        t[kLimbs]     = std::uint32_t(s);
        t[kLimbs + 1] = std::uint32_t(s >> 32);

        const std::uint32_t m = std::uint32_t(std::uint64_t(t[0]) * g.n0inv);

        // t += m * P, which zeroes t[0]; the result is shifted down one limb as it
        // is written, which is the division by 2^32 the Montgomery step needs.
        carry = (std::uint64_t(t[0]) + std::uint64_t(m) * g.p[0]) >> 32;
        for (int j = 1; j < kLimbs; ++j) {
            const std::uint64_t s2 = std::uint64_t(t[j]) + std::uint64_t(m) * g.p[j] + carry;
            t[j - 1] = std::uint32_t(s2);
            carry    = s2 >> 32;
        }
        s = std::uint64_t(t[kLimbs]) + carry;
        t[kLimbs - 1] = std::uint32_t(s);
        t[kLimbs]     = t[kLimbs + 1] + std::uint32_t(s >> 32);
    }

    for (int i = 0; i < kLimbs; ++i) out[i] = t[i];
    if (t[kLimbs] != 0 || cmp(out, g.p) >= 0) sub_in_place(out, g.p);
}

/// out = base^exp mod P, with `exp` a big-endian byte string.
void mod_exp(const Num& base, const std::uint8_t* exp, std::size_t exp_len, Num& out) {
    const Group& g = group();

    Num base_mont{};
    mont_mul(base, g.r2, base_mont);       // into Montgomery form
    Num acc = g.one_mont;                  // 1, in Montgomery form

    bool started = false;                  // skip the leading zero bits
    for (std::size_t i = 0; i < exp_len; ++i) {
        for (int bit = 7; bit >= 0; --bit) {
            if (started) {
                Num sq{};
                mont_mul(acc, acc, sq);
                acc = sq;
            }
            if ((exp[i] >> bit) & 1) {
                if (!started) { acc = base_mont; started = true; }
                else {
                    Num prod{};
                    mont_mul(acc, base_mont, prod);
                    acc = prod;
                }
            }
        }
    }
    if (!started) { out = g.one_mont; }    // exponent was zero
    else          { out = acc; }

    Num one{};
    one[0] = 1;
    Num plain{};
    mont_mul(out, one, plain);             // out of Montgomery form
    out = plain;
}

// ── SHA-1 helpers ───────────────────────────────────────────────────────────

using Digest = std::array<std::uint8_t, 20>;

/// SHA-1 over a four-character tag followed by up to two more buffers — every
/// hash MSE defines has exactly this shape.
Digest tagged_hash(const char (&tag)[5], const std::uint8_t* a, std::size_t alen,
                   const std::uint8_t* b = nullptr, std::size_t blen = 0) {
    librats::SHA1 h;
    h.update(reinterpret_cast<const std::uint8_t*>(tag), 4);
    if (a && alen) h.update(a, alen);
    if (b && blen) h.update(b, blen);
    return h.finalize_bytes();
}

Digest xor_digest(const Digest& a, const Digest& b) {
    Digest out{};
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = std::uint8_t(a[i] ^ b[i]);
    return out;
}

/// The one method we agree to run, given what the peer offers and what we allow.
/// RC4 wins when both are on the table: it is the point of the exercise, and the
/// obfuscated-header-only mode leaves the payload trivially recognisable.
std::uint32_t select_method(std::uint32_t provided, std::uint32_t allowed) {
    const std::uint32_t common = provided & allowed;
    if (common & kRc4)       return kRc4;
    if (common & kPlaintext) return kPlaintext;
    return 0;
}

void append(Bytes& out, const std::uint8_t* data, std::size_t len) {
    out.insert(out.end(), data, data + len);
}

} // namespace

// ── Free helpers ────────────────────────────────────────────────────────────

bool skey_matches(const std::uint8_t* obfuscated, const std::uint8_t* req3_hash,
                  const InfoHash& candidate) {
    const Digest req2 = tagged_hash("req2", candidate.data(), candidate.size());
    for (std::size_t i = 0; i < req2.size(); ++i)
        if (std::uint8_t(obfuscated[i] ^ req3_hash[i]) != req2[i]) return false;
    return true;
}

// ── Rc4Cipher ───────────────────────────────────────────────────────────────

void Rc4Cipher::init(const std::uint8_t* key, std::size_t key_len) {
    for (int i = 0; i < 256; ++i) s_[i] = std::uint8_t(i);
    std::uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = std::uint8_t(j + s_[i] + key[std::size_t(i) % key_len]);
        std::swap(s_[i], s_[j]);
    }
    i_ = j_ = 0;
    ready_ = true;

    // The spec discards the first 1024 keystream bytes — RC4's early output is
    // measurably biased, and every implementation in the swarm does this, so it is
    // part of the wire format whether or not one cares about the bias.
    std::uint8_t scratch[1024] = {0};
    process(scratch, sizeof(scratch));
}

void Rc4Cipher::process(std::uint8_t* data, std::size_t len) {
    for (std::size_t k = 0; k < len; ++k) {
        i_ = std::uint8_t(i_ + 1);
        j_ = std::uint8_t(j_ + s_[i_]);
        std::swap(s_[i_], s_[j_]);
        data[k] = std::uint8_t(data[k] ^ s_[std::uint8_t(s_[i_] + s_[j_])]);
    }
}

// ── DhKeyExchange ───────────────────────────────────────────────────────────

DhKeyExchange::DhKeyExchange() {
    random_bytes(private_.data(), private_.size());
    // A zero exponent would make the public key 1, which the peer must reject —
    // and which we would then have produced ourselves. Astronomically unlikely,
    // but the fix is one byte.
    private_[0] |= 0x80;

    Num base{};
    base[0] = 2;
    Num pub{};
    mod_exp(base, private_.data(), private_.size(), pub);
    to_be(pub, public_.data());
}

bool DhKeyExchange::compute_secret(const std::uint8_t* remote_public) {
    const Num remote = from_be(remote_public, kKeyLen);
    const Group& g = group();

    Num two{};
    two[0] = 2;
    Num p_minus_1 = g.p;
    Num one{};
    one[0] = 1;
    sub_in_place(p_minus_1, one);

    // Reject anything outside [2, P-2]: those values collapse the shared secret
    // into a subgroup of one or two elements, which anyone can predict.
    if (cmp(remote, two) < 0 || cmp(remote, p_minus_1) >= 0) return false;

    Num s{};
    mod_exp(remote, private_.data(), private_.size(), s);
    to_be(s, secret_.data());
    return true;
}

// ── Handshake ───────────────────────────────────────────────────────────────

Handshake::Handshake(const InfoHash& info_hash, Bytes ia, std::uint32_t provide)
    : initiator_(true)
    , state_(State::ReadYb)
    , info_hash_(info_hash)
    , ia_(std::move(ia))
    , crypto_mask_(provide ? provide : std::uint32_t(kBoth)) {
    // Step 1 goes out immediately — there is nothing to wait for.
    const std::size_t pad = random_pad_len();
    out_.resize(kKeyLen + pad);
    std::memcpy(out_.data(), dh_.public_key().data(), kKeyLen);
    pad_bytes(out_.data() + kKeyLen, pad);
}

Handshake::Handshake(SkeyResolver resolver, std::uint32_t allowed)
    : initiator_(false)
    , state_(State::ReadYa)
    , crypto_mask_(allowed ? allowed : std::uint32_t(kBoth))
    , resolver_(std::move(resolver)) {}

Handshake::Status Handshake::fail(const std::string& why) {
    state_ = State::Failed;
    error_ = why;
    return Status::Failed;
}

Bytes Handshake::take_output() {
    Bytes out;
    out.swap(out_);
    return out;
}

ByteView Handshake::leftover() const {
    return ByteView(buf_.data() + pos_, buf_.size() - pos_);
}

const std::uint8_t* Handshake::take_decrypted(std::size_t n) {
    std::uint8_t* at = buf_.data() + pos_;
    result_.recv_cipher.process(at, n);
    pos_ += n;
    return at;
}

std::size_t Handshake::find_sync(const std::uint8_t* pattern, std::size_t len, std::size_t limit) {
    if (available() < len) {
        // Not even one candidate window yet. Everything before the last len-1 bytes
        // can never start a match, so it is already accounted for against `limit`.
        return std::string::npos;
    }
    const std::uint8_t* begin = buf_.data() + pos_;
    const std::uint8_t* end   = buf_.data() + buf_.size();
    const std::uint8_t* hit   = std::search(begin, end, pattern, pattern + len);
    if (hit != end) return std::size_t(hit - buf_.data());

    // No hit: drop everything that can no longer begin a match, and count it
    // against the pad budget. Past the budget the peer is not speaking MSE (or not
    // to us), and holding the bytes forever would be a slow memory leak.
    const std::size_t droppable = available() - (len - 1);
    scanned_ += droppable;
    pos_     += droppable;
    if (scanned_ > limit) fail("MSE sync marker not found within the pad limit");
    return std::string::npos;
}

Handshake::Status Handshake::consume(const std::uint8_t* data, std::size_t len) {
    if (state_ == State::Failed) return Status::Failed;
    if (state_ == State::Done)   return Status::Done;

    // Compact away what the state machine has already eaten before growing, so a
    // long sync scan does not accumulate discarded pad.
    if (pos_ > 0 && pos_ == buf_.size()) { buf_.clear(); pos_ = 0; }
    buf_.insert(buf_.end(), data, data + len);

    // Bound on what one handshake may buffer. The protocol itself caps every field
    // (96 + 512 key/pad, 40 hashes, 512 pads, a 68-byte IA), so anything near this
    // is a peer that will never complete.
    constexpr std::size_t kMaxBuffered = 64 * 1024;
    if (buf_.size() > kMaxBuffered) return fail("MSE handshake buffer overflow");

    return advance();
}

void Handshake::derive_ciphers(const InfoHash& skey, bool outgoing) {
    const std::uint8_t* s = dh_.secret().data();
    // A encrypts with keyA and decrypts with keyB; B is the mirror image.
    const Digest key_a = tagged_hash("keyA", s, kKeyLen, skey.data(), skey.size());
    const Digest key_b = tagged_hash("keyB", s, kKeyLen, skey.data(), skey.size());
    const Digest& send = outgoing ? key_a : key_b;
    const Digest& recv = outgoing ? key_b : key_a;
    result_.send_cipher.init(send.data(), send.size());
    result_.recv_cipher.init(recv.data(), recv.size());
}

Handshake::Status Handshake::advance() {
    for (;;) {
        switch (state_) {

        // ---- initiator ----

        case State::ReadYb: {
            if (available() < kKeyLen) return Status::NeedMore;
            if (!dh_.compute_secret(buf_.data() + pos_))
                return fail("peer sent a degenerate DH public key");
            pos_ += kKeyLen;

            derive_ciphers(info_hash_, /*outgoing=*/true);

            // Step 3. The two hashes go out in the clear; everything from VC on is
            // encrypted with the send cipher, which is then left positioned exactly
            // where the payload stream picks up.
            const std::uint8_t* s = dh_.secret().data();
            const Digest sync   = tagged_hash("req1", s, kKeyLen);
            const Digest req2   = tagged_hash("req2", info_hash_.data(), info_hash_.size());
            const Digest req3   = tagged_hash("req3", s, kKeyLen);
            const Digest obfusc = xor_digest(req2, req3);

            append(out_, sync.data(), sync.size());
            append(out_, obfusc.data(), obfusc.size());

            const std::size_t pad = random_pad_len();
            Bytes enc;
            enc.resize(kVcLen + 4 + 2 + pad + 2 + ia_.size());
            std::uint8_t* p = enc.data();
            std::memset(p, 0, kVcLen);                       p += kVcLen;   // VC
            write_u32_be(p, crypto_mask_);                   p += 4;
            write_u16_be(p, std::uint16_t(pad));             p += 2;
            pad_bytes(p, pad);                               p += pad;
            write_u16_be(p, std::uint16_t(ia_.size()));      p += 2;
            if (!ia_.empty()) std::memcpy(p, ia_.data(), ia_.size());
            result_.send_cipher.process(enc.data(), enc.size());
            append(out_, enc.data(), enc.size());
            ia_.clear();

            // What the peer's encrypted VC will look like. Computed on a *copy* of
            // the receive cipher so the real one stays at stream position zero —
            // the VC bytes themselves still have to pass through it.
            Rc4Cipher probe = result_.recv_cipher;
            std::memset(expected_vc_.data(), 0, expected_vc_.size());
            probe.process(expected_vc_.data(), expected_vc_.size());

            scanned_ = 0;
            state_   = State::SyncVc;
            break;
        }

        case State::SyncVc: {
            // PadB sits between Yb and step 4 and its length is never sent, so the
            // encrypted VC is the only way to find where step 4 begins.
            const std::size_t at = find_sync(expected_vc_.data(), expected_vc_.size(), kMaxPad);
            if (state_ == State::Failed) return Status::Failed;
            if (at == std::string::npos) return Status::NeedMore;
            scanned_ += at - pos_;
            pos_      = at;              // pos_ now points at the encrypted VC
            state_    = State::ReadVcBody;
            break;
        }

        case State::ReadVcBody: {
            constexpr std::size_t kBody = kVcLen + 4 + 2;   // VC, crypto_select, len(PadD)
            if (available() < kBody) return Status::NeedMore;
            const std::uint8_t* p = take_decrypted(kBody);
            // VC is guaranteed by the sync match, but a peer could have sent the
            // pattern as pad; re-checking costs nothing and keeps the invariant local.
            for (std::size_t i = 0; i < kVcLen; ++i)
                if (p[i] != 0) return fail("MSE verification constant mismatch");

            const std::uint32_t selected = read_u32_be(p + kVcLen);
            if (selected != kRc4 && selected != kPlaintext)
                return fail("peer selected an unknown crypto method");
            if ((selected & crypto_mask_) == 0)
                return fail("peer selected a crypto method we did not offer");
            result_.rc4_payload = (selected == kRc4);

            pad_len_ = read_u16_be(p + kVcLen + 4);
            if (pad_len_ > kMaxPad) return fail("MSE PadD too long");
            state_ = State::ReadPadD;
            break;
        }

        case State::ReadPadD: {
            if (available() < pad_len_) return Status::NeedMore;
            take_decrypted(pad_len_);              // discarded, but the cipher advances
            state_ = State::Done;
            return Status::Done;
        }

        // ---- receiver ----

        case State::ReadYa: {
            if (available() < kKeyLen) return Status::NeedMore;
            if (!dh_.compute_secret(buf_.data() + pos_))
                return fail("peer sent a degenerate DH public key");
            pos_ += kKeyLen;

            // Step 2 out immediately; the ciphers wait for SKEY in step 3.
            const std::size_t pad = random_pad_len();
            append(out_, dh_.public_key().data(), kKeyLen);
            Bytes padding(pad);
            if (pad) pad_bytes(padding.data(), pad);
            append(out_, padding.data(), padding.size());

            scanned_ = 0;
            state_   = State::SyncHash;
            break;
        }

        case State::SyncHash: {
            const Digest sync = tagged_hash("req1", dh_.secret().data(), kKeyLen);
            const std::size_t at = find_sync(sync.data(), sync.size(), kMaxPad);
            if (state_ == State::Failed) return Status::Failed;
            if (at == std::string::npos) return Status::NeedMore;
            scanned_ += at - pos_;
            pos_      = at + sync.size();          // skip PadA and the marker itself
            state_    = State::ReadSkey;
            break;
        }

        case State::ReadSkey: {
            if (available() < 20) return Status::NeedMore;
            const Digest req3 = tagged_hash("req3", dh_.secret().data(), kKeyLen);
            InfoHash resolved{};
            if (!resolver_ || !resolver_(buf_.data() + pos_, req3.data(), resolved))
                return fail("MSE stream key names a torrent we do not have");
            pos_ += 20;

            info_hash_        = resolved;
            result_.info_hash = resolved;
            derive_ciphers(resolved, /*outgoing=*/false);
            state_ = State::ReadVcCrypto;
            break;
        }

        case State::ReadVcCrypto: {
            constexpr std::size_t kBody = kVcLen + 4 + 2;   // VC, crypto_provide, len(PadC)
            if (available() < kBody) return Status::NeedMore;
            const std::uint8_t* p = take_decrypted(kBody);
            for (std::size_t i = 0; i < kVcLen; ++i)
                if (p[i] != 0) return fail("MSE verification constant mismatch");

            const std::uint32_t provided = read_u32_be(p + kVcLen);
            const std::uint32_t selected = select_method(provided, crypto_mask_);
            if (selected == 0) return fail("no crypto method in common with the peer");
            result_.rc4_payload = (selected == kRc4);

            pad_len_ = read_u16_be(p + kVcLen + 4);
            if (pad_len_ > kMaxPad) return fail("MSE PadC too long");

            // Step 4 can be built now: it depends only on the choice just made.
            // Encrypting it here also leaves the send cipher exactly where the
            // payload stream continues.
            const std::size_t pad = random_pad_len();
            Bytes enc;
            enc.resize(kVcLen + 4 + 2 + pad);
            std::uint8_t* q = enc.data();
            std::memset(q, 0, kVcLen);            q += kVcLen;
            write_u32_be(q, selected);            q += 4;
            write_u16_be(q, std::uint16_t(pad));  q += 2;
            pad_bytes(q, pad);
            result_.send_cipher.process(enc.data(), enc.size());
            append(out_, enc.data(), enc.size());

            state_ = State::ReadPadC;
            break;
        }

        case State::ReadPadC: {
            if (available() < pad_len_ + 2) return Status::NeedMore;
            const std::uint8_t* p = take_decrypted(pad_len_ + 2);
            ia_len_ = read_u16_be(p + pad_len_);
            if (ia_len_ > kMaxIa) return fail("MSE initial payload too long");
            state_ = State::ReadIa;
            break;
        }

        case State::ReadIa: {
            if (available() < ia_len_) return Status::NeedMore;
            const std::uint8_t* p = take_decrypted(ia_len_);
            result_.initial_payload.assign(p, p + ia_len_);
            state_ = State::Done;
            return Status::Done;
        }

        case State::Done:   return Status::Done;
        case State::Failed: return Status::Failed;
        }
    }
}

} // namespace librats::bittorrent::mse
