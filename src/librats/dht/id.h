#pragma once

/**
 * @file id.h
 * @brief The 160-bit Kademlia identifier and the pure functions over it.
 *
 * `NodeId` and `InfoHash` share one 160-bit keyspace (BEP 5). Everything here is a
 * header-only, allocation-free leaf primitive — XOR distance, closeness ordering,
 * k-bucket placement, and hex/wire conversions — so the comparators used in the
 * routing table and lookup hot paths can be inlined.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#if defined(_MSC_VER)
#include <intrin.h>  // _BitScanReverse for count_leading_zeros
#endif

namespace librats {
namespace dht {

// Count leading zero bits of a non-zero 32-bit word. One hardware instruction where
// available; a portable loop otherwise. Precondition: x != 0.
inline int count_leading_zeros32(uint32_t x) noexcept {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_clz(x);
#elif defined(_MSC_VER)
    unsigned long idx;
    _BitScanReverse(&idx, x);
    return 31 - static_cast<int>(idx);
#else
    int n = 0;
    while ((x & 0x80000000u) == 0) { ++n; x <<= 1; }
    return n;
#endif
}

// 160-bit identifier space shared by node ids and info-hashes (Kademlia / BEP 5).
inline constexpr std::size_t kIdSize      = 20;   // 160 bits
inline constexpr std::size_t kBucketSize  = 8;    // "k": max contacts kept per bucket
inline constexpr std::size_t kAlpha       = 3;    // lookup concurrency (branch factor)
inline constexpr int         kDefaultPort = 6881; // standard BitTorrent DHT port
inline constexpr int         kBucketCount = static_cast<int>(kIdSize) * 8;  // 160

using NodeId   = std::array<uint8_t, kIdSize>;
using InfoHash = NodeId;  // same keyspace, named for intent at call sites

// Hash functor for using a NodeId/InfoHash as an unordered_map/set key. A node id is
// already a uniformly-distributed 160-bit value (a SHA-1 digest or random id), so the
// fastest sound hash is to reinterpret its leading bytes as size_t — no mixing needed.
// This mirrors libtorrent's std::hash<digest32<N>> (sha1_hash.hpp). Note: most DHT
// id-keyed tables (write tokens, the peer store) deliberately stay std::map — they're
// small/cold and ordered is fine; reach for this only on hot, large id sets.
struct NodeIdHash {
    std::size_t operator()(const NodeId& id) const noexcept {
        std::size_t h;
        std::memcpy(&h, id.data(), sizeof(h));
        return h;
    }
};

// XOR distance metric d(a, b) = a ^ b (Kademlia).
inline NodeId distance(const NodeId& a, const NodeId& b) noexcept {
    NodeId d;
    for (std::size_t i = 0; i < kIdSize; ++i) d[i] = a[i] ^ b[i];
    return d;
}

// True iff `a` is strictly closer to `target` than `b` under the XOR metric.
// Compares a^target against b^target as 160-bit big-endian numbers without
// materialising either distance — this is the lookup/sort comparator.
inline bool closer_to(const NodeId& a, const NodeId& b, const NodeId& target) noexcept {
    for (std::size_t i = 0; i < kIdSize; ++i) {
        const uint8_t da = a[i] ^ target[i];
        const uint8_t db = b[i] ^ target[i];
        if (da != db) return da < db;
    }
    return false;  // equal distance is not "strictly closer"
}

// Number of leading bits `a` and `b` share — equivalently, the count of leading
// zeros of (a ^ b). 0 means they differ in the very first bit (farthest apart);
// kBucketCount (160) is returned only when the ids are identical. This is the raw
// keyspace primitive; the routing table caps it to its current bucket count to get
// an actual bucket index (RoutingTable::bucket_index).
inline int shared_prefix_bits(const NodeId& a, const NodeId& b) noexcept {
    // Process the 160 bits four bytes at a time (kIdSize == 20 == 5 words). Each word
    // is assembled big-endian so its most significant bit is the earliest id bit, then
    // a single count-leading-zeros pins the first differing bit. Bit-identical to the
    // byte-at-a-time form, ~4x faster: the common case is one word load + one CLZ.
    for (std::size_t i = 0; i < kIdSize; i += 4) {
        const uint32_t d = (static_cast<uint32_t>(a[i]     ^ b[i])     << 24)
                         | (static_cast<uint32_t>(a[i + 1] ^ b[i + 1]) << 16)
                         | (static_cast<uint32_t>(a[i + 2] ^ b[i + 2]) << 8)
                         |  static_cast<uint32_t>(a[i + 3] ^ b[i + 3]);
        if (d != 0) return static_cast<int>(i) * 8 + count_leading_zeros32(d);
    }
    return kBucketCount;  // identical ids share the whole 160-bit prefix
}

// Read `n` bits from `id` starting at bit index `start` (MSB-first: bit 0 is the top
// bit of id[0]), returned right-aligned. Bits past the end of the id read as 0. Used
// to classify a node by the handful of sub-prefix bits that follow a bucket's shared
// prefix, so `n` is always small (<= 7).
inline uint32_t bits_at(const NodeId& id, int start, int n) noexcept {
    uint32_t v = 0;
    for (int k = 0; k < n; ++k) {
        const int bit = start + k;
        const int b = (bit >= 0 && bit < kBucketCount)
                          ? ((id[bit >> 3] >> (7 - (bit & 7))) & 1)
                          : 0;
        v = (v << 1) | static_cast<uint32_t>(b);
    }
    return v;
}

// Lowercase 40-char hex. to_hex / from_hex are exact inverses for valid input.
inline std::string to_hex(const NodeId& id) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out(kIdSize * 2, '0');
    for (std::size_t i = 0; i < kIdSize; ++i) {
        out[i * 2]     = kDigits[id[i] >> 4];
        out[i * 2 + 1] = kDigits[id[i] & 0x0f];
    }
    return out;
}

// Parse 40 hex chars. Returns a zero-filled id if the input isn't exactly 40 valid
// hex characters, so a malformed string can never be mistaken for a real id.
inline NodeId from_hex(const std::string& hex) {
    NodeId id{};
    if (hex.size() != kIdSize * 2) return id;
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < kIdSize; ++i) {
        const int hi = nibble(hex[i * 2]);
        const int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return NodeId{};
        id[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return id;
}

// Raw 20-byte wire form, as carried in KRPC messages. Inverses of each other.
inline std::string to_bytes(const NodeId& id) {
    return std::string(reinterpret_cast<const char*>(id.data()), kIdSize);
}

// Returns a zero-filled id if `bytes` isn't exactly 20 bytes.
inline NodeId from_bytes(const std::string& bytes) {
    NodeId id{};
    if (bytes.size() != kIdSize) return id;
    std::copy(bytes.begin(), bytes.end(), id.begin());
    return id;
}

} // namespace dht
} // namespace librats
