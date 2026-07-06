#include "dht/bep42.h"
#include "util/network_utils.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace librats {
namespace dht {

namespace {

// CRC-32C (Castagnoli), the polynomial mandated by BEP 42: reflected, init
// 0xFFFFFFFF, final XOR 0xFFFFFFFF, bytes processed in array order. These exact
// parameters reproduce the BEP 42 reference test vectors.
uint32_t crc32c(const uint8_t* data, std::size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int k = 0; k < 8; ++k)
            crc = (crc & 1u) ? (crc >> 1) ^ 0x82F63B78u : (crc >> 1);
    }
    return crc ^ 0xFFFFFFFFu;
}

// Mask the leading octets of `ip` per BEP 42 (4 for IPv4, 8 for IPv6). Returns the
// number of octets written to `out`, or 0 for the unspecified address. The address
// bytes are already in network order, so no byte-swapping is needed.
int masked_octets(const IpAddress& ip, uint8_t out[8]) {
    static const uint8_t v4_mask[4] = {0x03, 0x0f, 0x3f, 0xff};
    static const uint8_t v6_mask[8] = {0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};

    const uint8_t* b = ip.bytes().data();
    if (ip.is_v6()) {
        for (int i = 0; i < 8; ++i) out[i] = b[i] & v6_mask[i];
        return 8;
    }
    if (ip.is_v4()) {
        for (int i = 0; i < 4; ++i) out[i] = b[i] & v4_mask[i];
        return 4;
    }
    return 0;
}

// Compute the 3 deterministic prefix bytes of the BEP 42 id for (ip, seed). Only
// the high 5 bits of prefix[2] are deterministic — the low 3 are random in a real
// id, so they're returned cleared (and masked off again on verify).
bool bep42_prefix(const IpAddress& ip, uint8_t seed, uint8_t prefix[3]) {
    uint8_t octets[8];
    const int num = masked_octets(ip, octets);
    if (num == 0) return false;
    octets[0] |= static_cast<uint8_t>((seed & 0x7) << 5);
    const uint32_t c = crc32c(octets, static_cast<std::size_t>(num));
    prefix[0] = static_cast<uint8_t>((c >> 24) & 0xff);
    prefix[1] = static_cast<uint8_t>((c >> 16) & 0xff);
    prefix[2] = static_cast<uint8_t>((c >> 8) & 0xf8);
    return true;
}

} // namespace

bool is_public_address(const IpAddress& ip) {
    return network_utils::is_public_ip(ip);
}

bool generate_node_id_from_ip(const IpAddress& ip, NodeId& out, std::mt19937& rng) {
    std::uniform_int_distribution<int> byte(0, 255);
    const uint8_t seed = static_cast<uint8_t>(byte(rng));

    uint8_t prefix[3];
    if (!bep42_prefix(ip, seed, prefix)) return false;

    NodeId id{};
    id[0] = prefix[0];
    id[1] = prefix[1];
    id[2] = static_cast<uint8_t>(prefix[2] | (byte(rng) & 0x7));  // low 3 bits random
    for (int i = 3; i < 19; ++i) id[i] = static_cast<uint8_t>(byte(rng));
    id[19] = seed;
    out = id;
    return true;
}

bool verify_node_id_for_ip(const NodeId& id, const IpAddress& ip) {
    if (!is_public_address(ip)) return true;             // can't verify non-public IPs
    uint8_t prefix[3];
    if (!bep42_prefix(ip, id[19], prefix)) return true;  // unspecified -> don't reject
    return id[0] == prefix[0]
        && id[1] == prefix[1]
        && (id[2] & 0xf8) == prefix[2];
}

bool verify_node_id_for_ip(const NodeId& id, const std::string& ip) {
    const auto a = IpAddress::parse(ip);
    if (!a) return true;  // unparseable -> don't reject on uncertainty
    return verify_node_id_for_ip(id, *a);
}

bool ip_too_close(const IpAddress& a, const IpAddress& b) noexcept {
    if (a.family() != b.family()) return false;  // different networks, never "close"
    // /24 for IPv4, /64 for IPv6: compare the leading network bytes. The address bytes
    // are in network order, so a plain prefix compare is the CIDR test.
    const std::size_t network_bytes = a.is_v6() ? 8 : (a.is_v4() ? 3 : 0);
    if (network_bytes == 0) return false;        // unspecified
    return std::equal(a.bytes().begin(), a.bytes().begin() + network_bytes,
                      b.bytes().begin());
}

} // namespace dht
} // namespace librats
