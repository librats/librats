#pragma once

/**
 * @file mse.h
 * @brief MSE/PE — Message Stream Encryption, the BitTorrent connection
 *        obfuscation protocol.
 *
 * Why it exists: a lot of the swarm is configured to *require* an obfuscated
 * connection. Such a peer accepts our TCP connection, reads a plaintext
 * "\x13BitTorrent protocol" handshake and closes without answering a byte — which
 * is exactly what the log this was written for shows. Without MSE those peers are
 * unreachable no matter how many times we dial them.
 *
 * What it is NOT: security. MSE hides *what* protocol is on the wire from a
 * passive observer (and defeats naive traffic shaping); it is unauthenticated, so
 * an active man in the middle can defeat it. It is implemented because the swarm
 * expects it, not because it protects anything. The real transport security in
 * this project is the Noise mesh in `src/librats/security` — unrelated code.
 *
 * The protocol (A dials, B accepts):
 *
 *   1. A->B  Ya                      96-byte DH public key, then 0..512 random pad
 *   2. B->A  Yb                      96-byte DH public key, then 0..512 random pad
 *   3. A->B  HASH('req1', S)                                            (20, plain)
 *            HASH('req2', SKEY) xor HASH('req3', S)                     (20, plain)
 *            RC4( VC | crypto_provide | len(PadC) | PadC | len(IA) | IA )
 *   4. B->A  RC4( VC | crypto_select | len(PadD) | PadD )
 *   5. both  the payload stream, RC4 or plaintext per crypto_select
 *
 * S is the DH shared secret, SKEY the torrent's info-hash, VC eight zero bytes and
 * IA the initiator's first payload (for us: the 68-byte BitTorrent handshake).
 * RC4 keys are HASH('keyA', S, SKEY) for A->B and HASH('keyB', S, SKEY) for B->A,
 * each with the first 1024 keystream bytes discarded.
 *
 * Two consequences shape the code below:
 *
 *   - **Both pads have unknown length**, so a reader cannot simply count bytes: B
 *     has to *scan* for HASH('req1', S) and A has to scan for the encrypted VC.
 *     Everything before the marker is pad and is thrown away.
 *   - **B does not learn which torrent it is until step 3.** It cannot: SKEY is
 *     never sent in the clear. It recovers it by XOR-ing the obfuscated hash with
 *     HASH('req3', S) and comparing against HASH('req2', ih) for each torrent it
 *     holds — hence the SkeyResolver callback.
 *
 * Everything here is plain computation over byte buffers: no sockets, no reactor,
 * no torrent. Handshake is a pure state machine driven by consume(), which is what
 * makes it testable end to end against itself.
 */

#include "librats/bittorrent/types.h"
#include "librats/core/bytes.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace librats::bittorrent::mse {

constexpr std::size_t kKeyLen = 96;   ///< DH public key / shared secret, 768 bits
constexpr std::size_t kMaxPad = 512;  ///< spec ceiling on every pad field
constexpr std::size_t kVcLen  = 8;    ///< verification constant: eight zero bytes

/// crypto_provide / crypto_select bitmask.
enum Method : std::uint32_t {
    kPlaintext = 0x01,  ///< obfuscated handshake, then the payload in the clear
    kRc4       = 0x02,  ///< obfuscated handshake, then RC4 all the way
    kBoth      = 0x03,
};

/// RC4 keystream cipher. Symmetric: process() both encrypts and decrypts, and the
/// caller must apply it to the stream's bytes in order, exactly once each.
/// Copyable on purpose — the initiator clones its receive cipher to work out what
/// the encrypted VC will look like without disturbing the real stream position.
class Rc4Cipher {
public:
    Rc4Cipher() = default;
    /// Key the cipher and discard the first 1024 keystream bytes, per the spec.
    void init(const std::uint8_t* key, std::size_t key_len);
    /// XOR `len` bytes of keystream over `data`, in place.
    void process(std::uint8_t* data, std::size_t len);
    bool ready() const noexcept { return ready_; }

private:
    std::uint8_t s_[256]{};
    std::uint8_t i_     = 0;
    std::uint8_t j_     = 0;
    bool         ready_ = false;
};

/// Diffie-Hellman over the fixed 768-bit MODP group the MSE spec mandates
/// (generator 2). Exposed separately so it can be tested on its own.
class DhKeyExchange {
public:
    /// Draws a fresh 160-bit private exponent and computes Ya = 2^x mod P.
    DhKeyExchange();

    const std::array<std::uint8_t, kKeyLen>& public_key() const noexcept { return public_; }

    /// Compute S = remote^x mod P. Returns false for a degenerate public key
    /// (outside [2, P-2]): those force the shared secret into a tiny subgroup, so
    /// anyone could predict it. libtorrent rejects the same range.
    bool compute_secret(const std::uint8_t* remote_public);

    /// Valid only after a successful compute_secret().
    const std::array<std::uint8_t, kKeyLen>& secret() const noexcept { return secret_; }

private:
    std::array<std::uint8_t, kKeyLen> public_{};
    std::array<std::uint8_t, kKeyLen> secret_{};
    std::array<std::uint8_t, 20>      private_{};
};

/// Does @p candidate explain the obfuscated stream key a peer sent?
///
/// The receiver never learns SKEY directly: the peer sends
/// `HASH('req2', SKEY) xor HASH('req3', S)`, and the only way back is to guess
/// SKEY and check. A node holding N torrents does N of these per inbound
/// connection, which is why it is a cheap standalone predicate rather than
/// something that rebuilds state.
bool skey_matches(const std::uint8_t* obfuscated, const std::uint8_t* req3_hash,
                  const InfoHash& candidate);

/// One side of an MSE handshake, as a state machine over the byte stream.
///
/// Drive it by feeding everything that arrives to consume() and writing whatever
/// take_output() hands back. On Done, result() carries the two ciphers (already
/// advanced past the handshake, so payload encryption just continues them) and
/// leftover() the bytes that arrived after the handshake and still belong to the
/// caller — raw and *not* decrypted, because whether they should be decrypted at
/// all depends on the negotiated method.
class Handshake {
public:
    enum class Status { NeedMore, Done, Failed };

    /// Recover the torrent behind an obfuscated stream key. Called with the peer's
    /// 20-byte `HASH('req2', SKEY) xor HASH('req3', S)` and our own 20-byte
    /// `HASH('req3', S)`; XOR them to get `HASH('req2', SKEY)` and compare against
    /// each torrent's. Returns false if none match (we do not hold that torrent).
    using SkeyResolver = std::function<bool(const std::uint8_t* obfuscated,
                                            const std::uint8_t* req3_hash,
                                            InfoHash& out)>;

    struct Result {
        Rc4Cipher send_cipher;         ///< positioned right after our handshake bytes
        Rc4Cipher recv_cipher;         ///< positioned right after the peer's
        bool      rc4_payload = false; ///< false => crypto_select was plaintext
        InfoHash  info_hash{};         ///< receiver only: the torrent SKEY named
        Bytes     initial_payload;     ///< receiver only: the decrypted IA
    };

    /// Initiator. @p ia is the payload to embed in step 3 — the BitTorrent
    /// handshake. @p provide is the crypto_provide bitmask we offer.
    Handshake(const InfoHash& info_hash, Bytes ia, std::uint32_t provide);
    /// Receiver. @p allowed bounds what we will agree to in crypto_select.
    Handshake(SkeyResolver resolver, std::uint32_t allowed);

    /// Absorb received bytes and advance. Everything offered is taken.
    Status consume(const std::uint8_t* data, std::size_t len);

    /// Bytes to write to the socket, moved out (empty if there are none pending).
    Bytes take_output();

    /// Post-handshake bytes already received. Valid once consume() returns Done.
    ByteView leftover() const;

    const std::string& error()  const noexcept { return error_; }
    Result&            result() noexcept { return result_; }

    /// Largest IA we will accept from a peer. The only legitimate IA is the
    /// 68-byte BitTorrent handshake; the slack covers a client that pipelines a
    /// message or two behind it, and the cap stops a peer naming a huge length.
    static constexpr std::size_t kMaxIa = 4096;

private:
    enum class State {
        ReadYb, SyncVc, ReadVcBody, ReadPadD,                       // initiator
        ReadYa, SyncHash, ReadSkey, ReadVcCrypto, ReadPadC, ReadIa, // receiver
        Done, Failed,
    };

    Status advance();                       ///< run the state machine until it blocks
    Status fail(const std::string& why);
    void   derive_ciphers(const InfoHash& skey, bool outgoing);
    /// Search buf_ from pos_ for `pattern`, giving up once `limit` bytes of the
    /// stream have been scanned without a hit. Returns the absolute offset, or
    /// npos while still searching (scanned_ carries the give-up budget).
    std::size_t find_sync(const std::uint8_t* pattern, std::size_t len, std::size_t limit);
    std::size_t available() const noexcept { return buf_.size() - pos_; }
    /// Decrypt the next @p n buffered bytes in place, advance pos_ past them and
    /// return where they start. Only ever called with a length the protocol has
    /// already pinned down, so the receive cipher never runs past the end of the
    /// encrypted region and into payload that may be plaintext.
    const std::uint8_t* take_decrypted(std::size_t n);

    bool          initiator_ = false;
    State         state_     = State::ReadYb;
    std::string   error_;
    Result        result_;

    DhKeyExchange dh_;
    InfoHash      info_hash_{};      ///< initiator: known up front; receiver: resolved
    Bytes         ia_;               ///< initiator: the payload for step 3
    std::uint32_t crypto_mask_ = 0;  ///< provide (initiator) / allowed (receiver)
    SkeyResolver  resolver_;

    Bytes       buf_;                ///< everything received, raw
    std::size_t pos_     = 0;        ///< how much of buf_ the state machine has eaten
    std::size_t scanned_ = 0;        ///< bytes skipped so far by the current sync scan
    std::size_t pad_len_ = 0;        ///< length of the pad field currently being read
    std::size_t ia_len_  = 0;
    Bytes       out_;                ///< pending bytes for the socket

    std::array<std::uint8_t, kVcLen> expected_vc_{};  ///< initiator: RC4(8 zero bytes)
};

} // namespace librats::bittorrent::mse
