#include "dht/bep42.h"
#include "util/network_utils.h"

#include <cstddef>
#include <cstdint>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

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
// number of octets written to `out`, or 0 if `ip` doesn't parse.
int masked_octets(const std::string& ip, uint8_t out[8]) {
    static const uint8_t v4_mask[4] = {0x03, 0x0f, 0x3f, 0xff};
    static const uint8_t v6_mask[8] = {0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};

    if (network_utils::is_valid_ipv6(ip)) {
        in6_addr addr6;
        if (inet_pton(AF_INET6, ip.c_str(), &addr6) != 1) return 0;
        for (int i = 0; i < 8; ++i) out[i] = addr6.s6_addr[i] & v6_mask[i];
        return 8;
    }

    in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return 0;
    const uint32_t h = ntohl(addr.s_addr);
    const uint8_t ipb[4] = {
        static_cast<uint8_t>((h >> 24) & 0xff), static_cast<uint8_t>((h >> 16) & 0xff),
        static_cast<uint8_t>((h >> 8) & 0xff),  static_cast<uint8_t>(h & 0xff)};
    for (int i = 0; i < 4; ++i) out[i] = ipb[i] & v4_mask[i];
    return 4;
}

// Compute the 3 deterministic prefix bytes of the BEP 42 id for (ip, seed). Only
// the high 5 bits of prefix[2] are deterministic — the low 3 are random in a real
// id, so they're returned cleared (and masked off again on verify).
bool bep42_prefix(const std::string& ip, uint8_t seed, uint8_t prefix[3]) {
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

bool is_public_address(const std::string& ip) {
    return network_utils::is_public_ip(ip);
}

bool generate_node_id_from_ip(const std::string& ip, NodeId& out, std::mt19937& rng) {
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

bool verify_node_id_for_ip(const NodeId& id, const std::string& ip) {
    if (!is_public_address(ip)) return true;             // can't verify non-public IPs
    uint8_t prefix[3];
    if (!bep42_prefix(ip, id[19], prefix)) return true;  // unparseable -> don't reject
    return id[0] == prefix[0]
        && id[1] == prefix[1]
        && (id[2] & 0xf8) == prefix[2];
}

} // namespace dht
} // namespace librats
