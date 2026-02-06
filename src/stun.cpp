/**
 * @file stun.cpp
 * @brief STUN (Session Traversal Utilities for NAT) Protocol Implementation
 * 
 * Implements RFC 5389 - STUN protocol for NAT traversal.
 */

#include "stun.h"
#include "logger.h"
#include "network_utils.h"
#include <cstring>
#include <algorithm>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace librats {

// ============================================================================
// Logging Macros
// ============================================================================

#define LOG_STUN_DEBUG(msg) LOG_DEBUG("stun", msg)
#define LOG_STUN_INFO(msg) LOG_INFO("stun", msg)
#define LOG_STUN_WARN(msg) LOG_WARN("stun", msg)
#define LOG_STUN_ERROR(msg) LOG_ERROR("stun", msg)

// ============================================================================
// CRC32 Table (ISO 3309 / ITU-T V.42)
// ============================================================================

static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd706b3,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t stun_crc32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

// ============================================================================
// HMAC-SHA1 Implementation (simplified for STUN)
// ============================================================================

// SHA1 implementation for HMAC
namespace {

struct SHA1Context {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];
};

void sha1_init(SHA1Context* ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

inline uint32_t rol32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e;
    uint32_t w[80];
    
    // Convert buffer to 32-bit words
    for (int i = 0; i < 16; i++) {
        w[i] = (static_cast<uint32_t>(buffer[i * 4]) << 24) |
               (static_cast<uint32_t>(buffer[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(buffer[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(buffer[i * 4 + 3]));
    }
    
    // Extend to 80 words
    for (int i = 16; i < 80; i++) {
        w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        
        uint32_t temp = rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = temp;
    }
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void sha1_update(SHA1Context* ctx, const uint8_t* data, size_t len) {
    size_t i = 0;
    size_t index = ctx->count % 64;
    ctx->count += len;
    
    if (index) {
        size_t left = 64 - index;
        if (len < left) {
            memcpy(&ctx->buffer[index], data, len);
            return;
        }
        memcpy(&ctx->buffer[index], data, left);
        sha1_transform(ctx->state, ctx->buffer);
        i = left;
    }
    
    while (i + 64 <= len) {
        sha1_transform(ctx->state, &data[i]);
        i += 64;
    }
    
    if (i < len) {
        memcpy(ctx->buffer, &data[i], len - i);
    }
}

void sha1_final(SHA1Context* ctx, uint8_t digest[20]) {
    uint8_t finalcount[8];
    
    uint64_t bits = ctx->count * 8;
    for (int i = 0; i < 8; i++) {
        finalcount[i] = static_cast<uint8_t>(bits >> ((7 - i) * 8));
    }
    
    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);
    
    while ((ctx->count % 64) != 56) {
        pad = 0x00;
        sha1_update(ctx, &pad, 1);
    }
    
    sha1_update(ctx, finalcount, 8);
    
    for (int i = 0; i < 5; i++) {
        digest[i * 4] = static_cast<uint8_t>(ctx->state[i] >> 24);
        digest[i * 4 + 1] = static_cast<uint8_t>(ctx->state[i] >> 16);
        digest[i * 4 + 2] = static_cast<uint8_t>(ctx->state[i] >> 8);
        digest[i * 4 + 3] = static_cast<uint8_t>(ctx->state[i]);
    }
}

std::array<uint8_t, 20> sha1(const uint8_t* data, size_t len) {
    SHA1Context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    std::array<uint8_t, 20> result;
    sha1_final(&ctx, result.data());
    return result;
}

} // anonymous namespace

std::array<uint8_t, 20> stun_hmac_sha1(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& data) {
    const size_t block_size = 64;
    std::vector<uint8_t> k(block_size, 0);
    
    if (key.size() > block_size) {
        auto hashed = sha1(key.data(), key.size());
        std::copy(hashed.begin(), hashed.end(), k.begin());
    } else {
        std::copy(key.begin(), key.end(), k.begin());
    }
    
    std::vector<uint8_t> o_key_pad(block_size);
    std::vector<uint8_t> i_key_pad(block_size);
    
    for (size_t i = 0; i < block_size; i++) {
        o_key_pad[i] = k[i] ^ 0x5C;
        i_key_pad[i] = k[i] ^ 0x36;
    }
    
    // Inner hash
    std::vector<uint8_t> inner;
    inner.reserve(block_size + data.size());
    inner.insert(inner.end(), i_key_pad.begin(), i_key_pad.end());
    inner.insert(inner.end(), data.begin(), data.end());
    auto inner_hash = sha1(inner.data(), inner.size());
    
    // Outer hash
    std::vector<uint8_t> outer;
    outer.reserve(block_size + 20);
    outer.insert(outer.end(), o_key_pad.begin(), o_key_pad.end());
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    
    return sha1(outer.data(), outer.size());
}

// ============================================================================
// MD5 for long-term credentials (simplified)
// ============================================================================

namespace {

struct MD5Context {
    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[64];
};

void md5_init(MD5Context* ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->count = 0;
}

inline uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
inline uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
inline uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
inline uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    static const uint32_t k[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    static const uint8_t s[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    
    uint32_t m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = static_cast<uint32_t>(block[i * 4]) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
    }
    
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    
    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16) {
            f = md5_f(b, c, d);
            g = i;
        } else if (i < 32) {
            f = md5_g(b, c, d);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = md5_h(b, c, d);
            g = (3 * i + 5) % 16;
        } else {
            f = md5_i(b, c, d);
            g = (7 * i) % 16;
        }
        
        uint32_t temp = d;
        d = c;
        c = b;
        b = b + rol32(a + f + k[i] + m[g], s[i]);
        a = temp;
    }
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void md5_update(MD5Context* ctx, const uint8_t* data, size_t len) {
    size_t index = ctx->count % 64;
    ctx->count += len;
    
    size_t i = 0;
    if (index) {
        size_t left = 64 - index;
        if (len < left) {
            memcpy(&ctx->buffer[index], data, len);
            return;
        }
        memcpy(&ctx->buffer[index], data, left);
        md5_transform(ctx->state, ctx->buffer);
        i = left;
    }
    
    while (i + 64 <= len) {
        md5_transform(ctx->state, &data[i]);
        i += 64;
    }
    
    if (i < len) {
        memcpy(ctx->buffer, &data[i], len - i);
    }
}

void md5_final(MD5Context* ctx, uint8_t digest[16]) {
    uint8_t bits[8];
    uint64_t len = ctx->count * 8;
    for (int i = 0; i < 8; i++) {
        bits[i] = static_cast<uint8_t>(len >> (i * 8));
    }
    
    uint8_t pad = 0x80;
    md5_update(ctx, &pad, 1);
    
    while ((ctx->count % 64) != 56) {
        pad = 0x00;
        md5_update(ctx, &pad, 1);
    }
    
    md5_update(ctx, bits, 8);
    
    for (int i = 0; i < 4; i++) {
        digest[i * 4] = static_cast<uint8_t>(ctx->state[i]);
        digest[i * 4 + 1] = static_cast<uint8_t>(ctx->state[i] >> 8);
        digest[i * 4 + 2] = static_cast<uint8_t>(ctx->state[i] >> 16);
        digest[i * 4 + 3] = static_cast<uint8_t>(ctx->state[i] >> 24);
    }
}

} // anonymous namespace

std::vector<uint8_t> stun_compute_long_term_key(const std::string& username,
                                                 const std::string& realm,
                                                 const std::string& password) {
    std::string data = username + ":" + realm + ":" + password;
    
    MD5Context ctx;
    md5_init(&ctx);
    md5_update(&ctx, reinterpret_cast<const uint8_t*>(data.data()), data.size());
    
    std::vector<uint8_t> result(16);
    md5_final(&ctx, result.data());
    return result;
}

// ============================================================================
// StunMessage Implementation
// ============================================================================

void StunMessage::generate_transaction_id() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(0, 255);
    
    for (auto& byte : transaction_id) {
        byte = static_cast<uint8_t>(dis(gen));
    }
}

StunMessageClass StunMessage::get_class() const {
    uint16_t type_val = static_cast<uint16_t>(type);
    // Class bits are at positions 4 and 8
    uint8_t c0 = (type_val >> 4) & 0x01;
    uint8_t c1 = (type_val >> 8) & 0x01;
    return static_cast<StunMessageClass>((c1 << 1) | c0);
}

StunMethod StunMessage::get_method() const {
    uint16_t type_val = static_cast<uint16_t>(type);
    // Method bits: M0-M3 at bits 0-3, M4-M6 at bits 5-7, M7-M11 at bits 9-13
    uint16_t m0_3 = type_val & 0x000F;
    uint16_t m4_6 = (type_val >> 1) & 0x0070;
    uint16_t m7_11 = (type_val >> 2) & 0x0F80;
    return static_cast<StunMethod>(m0_3 | m4_6 | m7_11);
}

const StunAttribute* StunMessage::find_attribute(StunAttributeType attr_type) const {
    for (const auto& attr : attributes) {
        if (attr.type == attr_type) {
            return &attr;
        }
    }
    return nullptr;
}

void StunMessage::add_attribute(StunAttributeType attr_type, const std::vector<uint8_t>& value) {
    attributes.emplace_back(attr_type, value);
}

void StunMessage::add_xor_mapped_address(const StunMappedAddress& addr) {
    std::vector<uint8_t> value;
    value.push_back(0x00);  // Reserved
    value.push_back(static_cast<uint8_t>(addr.family));
    
    // XOR port with magic cookie high 16 bits
    uint16_t xport = addr.port ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
    value.push_back(static_cast<uint8_t>(xport >> 8));
    value.push_back(static_cast<uint8_t>(xport));
    
    if (addr.family == StunAddressFamily::IPv4) {
        // Parse IPv4 address
        uint32_t ip = 0;
        int a, b, c, d;
        if (sscanf(addr.address.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            ip = (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) |
                 (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
        }
        
        // XOR with magic cookie
        uint32_t xip = ip ^ STUN_MAGIC_COOKIE;
        value.push_back(static_cast<uint8_t>(xip >> 24));
        value.push_back(static_cast<uint8_t>(xip >> 16));
        value.push_back(static_cast<uint8_t>(xip >> 8));
        value.push_back(static_cast<uint8_t>(xip));
    } else {
        // IPv6: XOR with magic cookie + transaction ID
        struct in6_addr in6;
        if (inet_pton(AF_INET6, addr.address.c_str(), &in6) == 1) {
            uint8_t xor_key[16];
            xor_key[0] = static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 24);
            xor_key[1] = static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 16);
            xor_key[2] = static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 8);
            xor_key[3] = static_cast<uint8_t>(STUN_MAGIC_COOKIE);
            memcpy(&xor_key[4], transaction_id.data(), 12);
            
            for (int i = 0; i < 16; i++) {
                value.push_back(in6.s6_addr[i] ^ xor_key[i]);
            }
        }
    }
    
    add_attribute(StunAttributeType::XorMappedAddress, value);
}

void StunMessage::add_xor_relayed_address(const StunMappedAddress& addr) {
    std::vector<uint8_t> value;
    value.push_back(0x00);  // Reserved
    value.push_back(static_cast<uint8_t>(addr.family));
    
    // XOR port with magic cookie high 16 bits
    uint16_t xport = addr.port ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
    value.push_back(static_cast<uint8_t>(xport >> 8));
    value.push_back(static_cast<uint8_t>(xport));
    
    if (addr.family == StunAddressFamily::IPv4) {
        // Parse IPv4 address
        uint32_t ip = 0;
        int a, b, c, d;
        if (sscanf(addr.address.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            ip = (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) |
                 (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
        }
        
        // XOR with magic cookie
        uint32_t xip = ip ^ STUN_MAGIC_COOKIE;
        value.push_back(static_cast<uint8_t>(xip >> 24));
        value.push_back(static_cast<uint8_t>(xip >> 16));
        value.push_back(static_cast<uint8_t>(xip >> 8));
        value.push_back(static_cast<uint8_t>(xip));
    } else {
        // IPv6: XOR with magic cookie + transaction ID
        struct in6_addr in6;
        if (inet_pton(AF_INET6, addr.address.c_str(), &in6) == 1) {
            uint8_t xor_key[16];
            xor_key[0] = static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 24);
            xor_key[1] = static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 16);
            xor_key[2] = static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 8);
            xor_key[3] = static_cast<uint8_t>(STUN_MAGIC_COOKIE);
            memcpy(&xor_key[4], transaction_id.data(), 12);
            
            for (int i = 0; i < 16; i++) {
                value.push_back(in6.s6_addr[i] ^ xor_key[i]);
            }
        }
    }
    
    add_attribute(StunAttributeType::XorRelayedAddress, value);
}

void StunMessage::add_error_code(StunErrorCode code, const std::string& reason) {
    std::vector<uint8_t> value;
    uint16_t code_val = static_cast<uint16_t>(code);
    
    value.push_back(0x00);  // Reserved
    value.push_back(0x00);  // Reserved
    value.push_back(static_cast<uint8_t>(code_val / 100));  // Class
    value.push_back(static_cast<uint8_t>(code_val % 100));  // Number
    
    // Add reason phrase
    for (char c : reason) {
        value.push_back(static_cast<uint8_t>(c));
    }
    
    add_attribute(StunAttributeType::ErrorCode, value);
}

void StunMessage::add_username(const std::string& username) {
    std::vector<uint8_t> value(username.begin(), username.end());
    add_attribute(StunAttributeType::Username, value);
}

void StunMessage::add_realm(const std::string& realm) {
    std::vector<uint8_t> value(realm.begin(), realm.end());
    add_attribute(StunAttributeType::Realm, value);
}

void StunMessage::add_nonce(const std::string& nonce) {
    std::vector<uint8_t> value(nonce.begin(), nonce.end());
    add_attribute(StunAttributeType::Nonce, value);
}

void StunMessage::add_software(const std::string& software) {
    std::vector<uint8_t> value(software.begin(), software.end());
    add_attribute(StunAttributeType::Software, value);
}

void StunMessage::add_lifetime(uint32_t seconds) {
    std::vector<uint8_t> value(4);
    value[0] = static_cast<uint8_t>(seconds >> 24);
    value[1] = static_cast<uint8_t>(seconds >> 16);
    value[2] = static_cast<uint8_t>(seconds >> 8);
    value[3] = static_cast<uint8_t>(seconds);
    add_attribute(StunAttributeType::Lifetime, value);
}

void StunMessage::add_requested_transport(uint8_t protocol) {
    std::vector<uint8_t> value = {protocol, 0, 0, 0};  // Protocol + 3 reserved bytes
    add_attribute(StunAttributeType::RequestedTransport, value);
}

void StunMessage::add_xor_peer_address(const StunMappedAddress& addr) {
    // Same encoding as XOR-MAPPED-ADDRESS
    std::vector<uint8_t> value;
    value.push_back(0x00);
    value.push_back(static_cast<uint8_t>(addr.family));
    
    uint16_t xport = addr.port ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
    value.push_back(static_cast<uint8_t>(xport >> 8));
    value.push_back(static_cast<uint8_t>(xport));
    
    if (addr.family == StunAddressFamily::IPv4) {
        uint32_t ip = 0;
        int a, b, c, d;
        if (sscanf(addr.address.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            ip = (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) |
                 (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
        }
        uint32_t xip = ip ^ STUN_MAGIC_COOKIE;
        value.push_back(static_cast<uint8_t>(xip >> 24));
        value.push_back(static_cast<uint8_t>(xip >> 16));
        value.push_back(static_cast<uint8_t>(xip >> 8));
        value.push_back(static_cast<uint8_t>(xip));
    }
    
    add_attribute(StunAttributeType::XorPeerAddress, value);
}

void StunMessage::add_data(const std::vector<uint8_t>& data) {
    add_attribute(StunAttributeType::Data, data);
}

void StunMessage::add_channel_number(uint16_t channel) {
    std::vector<uint8_t> value = {
        static_cast<uint8_t>(channel >> 8),
        static_cast<uint8_t>(channel),
        0, 0  // Reserved
    };
    add_attribute(StunAttributeType::ChannelNumber, value);
}

std::optional<StunMappedAddress> StunMessage::get_xor_mapped_address() const {
    const StunAttribute* attr = find_attribute(StunAttributeType::XorMappedAddress);
    if (!attr || attr->value.size() < 8) {
        return std::nullopt;
    }
    
    StunMappedAddress addr;
    addr.family = static_cast<StunAddressFamily>(attr->value[1]);
    
    // XOR port
    uint16_t xport = (static_cast<uint16_t>(attr->value[2]) << 8) | attr->value[3];
    addr.port = xport ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
    
    if (addr.family == StunAddressFamily::IPv4) {
        if (attr->value.size() < 8) return std::nullopt;
        
        uint32_t xip = (static_cast<uint32_t>(attr->value[4]) << 24) |
                       (static_cast<uint32_t>(attr->value[5]) << 16) |
                       (static_cast<uint32_t>(attr->value[6]) << 8) |
                       static_cast<uint32_t>(attr->value[7]);
        uint32_t ip = xip ^ STUN_MAGIC_COOKIE;
        
        addr.address = std::to_string((ip >> 24) & 0xFF) + "." +
                       std::to_string((ip >> 16) & 0xFF) + "." +
                       std::to_string((ip >> 8) & 0xFF) + "." +
                       std::to_string(ip & 0xFF);
    } else if (addr.family == StunAddressFamily::IPv6) {
        if (attr->value.size() < 20) return std::nullopt;
        
        uint8_t xor_key[16];
        xor_key[0] = static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 24);
        xor_key[1] = static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 16);
        xor_key[2] = static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 8);
        xor_key[3] = static_cast<uint8_t>(STUN_MAGIC_COOKIE);
        memcpy(&xor_key[4], transaction_id.data(), 12);
        
        struct in6_addr in6;
        for (int i = 0; i < 16; i++) {
            in6.s6_addr[i] = attr->value[4 + i] ^ xor_key[i];
        }
        
        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &in6, buf, sizeof(buf))) {
            addr.address = buf;
        }
    }
    
    return addr;
}

std::optional<StunMappedAddress> StunMessage::get_mapped_address() const {
    const StunAttribute* attr = find_attribute(StunAttributeType::MappedAddress);
    if (!attr || attr->value.size() < 8) {
        return std::nullopt;
    }
    
    StunMappedAddress addr;
    addr.family = static_cast<StunAddressFamily>(attr->value[1]);
    addr.port = (static_cast<uint16_t>(attr->value[2]) << 8) | attr->value[3];
    
    if (addr.family == StunAddressFamily::IPv4) {
        addr.address = std::to_string(attr->value[4]) + "." +
                       std::to_string(attr->value[5]) + "." +
                       std::to_string(attr->value[6]) + "." +
                       std::to_string(attr->value[7]);
    }
    
    return addr;
}

std::optional<StunMappedAddress> StunMessage::get_xor_relayed_address() const {
    const StunAttribute* attr = find_attribute(StunAttributeType::XorRelayedAddress);
    if (!attr) return std::nullopt;
    
    // Same decoding as XOR-MAPPED-ADDRESS
    StunMessage temp = *this;
    temp.attributes.clear();
    temp.attributes.emplace_back(StunAttributeType::XorMappedAddress, attr->value);
    return temp.get_xor_mapped_address();
}

std::optional<StunMappedAddress> StunMessage::get_xor_peer_address() const {
    const StunAttribute* attr = find_attribute(StunAttributeType::XorPeerAddress);
    if (!attr) return std::nullopt;
    
    StunMessage temp = *this;
    temp.attributes.clear();
    temp.attributes.emplace_back(StunAttributeType::XorMappedAddress, attr->value);
    return temp.get_xor_mapped_address();
}

std::optional<StunError> StunMessage::get_error() const {
    const StunAttribute* attr = find_attribute(StunAttributeType::ErrorCode);
    if (!attr || attr->value.size() < 4) {
        return std::nullopt;
    }
    
    StunError error;
    uint16_t error_class = attr->value[2];
    uint16_t error_number = attr->value[3];
    error.code = static_cast<StunErrorCode>(error_class * 100 + error_number);
    
    if (attr->value.size() > 4) {
        error.reason = std::string(attr->value.begin() + 4, attr->value.end());
    }
    
    return error;
}

std::optional<uint32_t> StunMessage::get_lifetime() const {
    const StunAttribute* attr = find_attribute(StunAttributeType::Lifetime);
    if (!attr || attr->value.size() < 4) {
        return std::nullopt;
    }
    
    return (static_cast<uint32_t>(attr->value[0]) << 24) |
           (static_cast<uint32_t>(attr->value[1]) << 16) |
           (static_cast<uint32_t>(attr->value[2]) << 8) |
           static_cast<uint32_t>(attr->value[3]);
}

std::optional<std::vector<uint8_t>> StunMessage::get_data() const {
    const StunAttribute* attr = find_attribute(StunAttributeType::Data);
    if (!attr) return std::nullopt;
    return attr->value;
}

std::optional<std::string> StunMessage::get_realm() const {
    const StunAttribute* attr = find_attribute(StunAttributeType::Realm);
    if (!attr) return std::nullopt;
    return std::string(attr->value.begin(), attr->value.end());
}

std::optional<std::string> StunMessage::get_nonce() const {
    const StunAttribute* attr = find_attribute(StunAttributeType::Nonce);
    if (!attr) return std::nullopt;
    return std::string(attr->value.begin(), attr->value.end());
}

std::vector<uint8_t> StunMessage::serialize() const {
    std::vector<uint8_t> buffer;
    buffer.reserve(STUN_MAX_MESSAGE_SIZE);
    
    // Calculate attributes length
    size_t attrs_length = 0;
    for (const auto& attr : attributes) {
        attrs_length += 4 + attr.padded_length();  // Type(2) + Length(2) + Value(padded)
    }
    
    // Header: Type (2) + Length (2) + Magic Cookie (4) + Transaction ID (12)
    uint16_t type_val = static_cast<uint16_t>(type);
    buffer.push_back(static_cast<uint8_t>(type_val >> 8));
    buffer.push_back(static_cast<uint8_t>(type_val));
    
    buffer.push_back(static_cast<uint8_t>(attrs_length >> 8));
    buffer.push_back(static_cast<uint8_t>(attrs_length));
    
    buffer.push_back(static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 24));
    buffer.push_back(static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 16));
    buffer.push_back(static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 8));
    buffer.push_back(static_cast<uint8_t>(STUN_MAGIC_COOKIE));
    
    buffer.insert(buffer.end(), transaction_id.begin(), transaction_id.end());
    
    // Attributes
    for (const auto& attr : attributes) {
        uint16_t attr_type = static_cast<uint16_t>(attr.type);
        uint16_t attr_length = static_cast<uint16_t>(attr.value.size());
        
        buffer.push_back(static_cast<uint8_t>(attr_type >> 8));
        buffer.push_back(static_cast<uint8_t>(attr_type));
        buffer.push_back(static_cast<uint8_t>(attr_length >> 8));
        buffer.push_back(static_cast<uint8_t>(attr_length));
        
        buffer.insert(buffer.end(), attr.value.begin(), attr.value.end());
        
        // Padding to 4-byte boundary
        size_t padding = attr.padded_length() - attr.value.size();
        for (size_t i = 0; i < padding; i++) {
            buffer.push_back(0x00);
        }
    }
    
    return buffer;
}

std::vector<uint8_t> StunMessage::serialize_with_integrity(const std::string& key) const {
    // First serialize without integrity
    auto buffer = serialize();
    
    // Add MESSAGE-INTEGRITY attribute
    // Update length to include MESSAGE-INTEGRITY (24 bytes: 4 header + 20 HMAC)
    uint16_t new_length = static_cast<uint16_t>(buffer.size() - STUN_HEADER_SIZE + 24);
    buffer[2] = static_cast<uint8_t>(new_length >> 8);
    buffer[3] = static_cast<uint8_t>(new_length);
    
    // Compute HMAC-SHA1
    std::vector<uint8_t> key_bytes(key.begin(), key.end());
    auto hmac = stun_hmac_sha1(key_bytes, buffer);
    
    // Add MESSAGE-INTEGRITY attribute
    buffer.push_back(0x00);
    buffer.push_back(0x08);  // MESSAGE-INTEGRITY type
    buffer.push_back(0x00);
    buffer.push_back(0x14);  // Length: 20 bytes
    buffer.insert(buffer.end(), hmac.begin(), hmac.end());
    
    // Add FINGERPRINT attribute
    new_length = static_cast<uint16_t>(buffer.size() - STUN_HEADER_SIZE + 8);
    buffer[2] = static_cast<uint8_t>(new_length >> 8);
    buffer[3] = static_cast<uint8_t>(new_length);
    
    uint32_t crc = stun_crc32(buffer.data(), buffer.size()) ^ 0x5354554E;
    
    buffer.push_back(0x80);
    buffer.push_back(0x28);  // FINGERPRINT type
    buffer.push_back(0x00);
    buffer.push_back(0x04);  // Length: 4 bytes
    buffer.push_back(static_cast<uint8_t>(crc >> 24));
    buffer.push_back(static_cast<uint8_t>(crc >> 16));
    buffer.push_back(static_cast<uint8_t>(crc >> 8));
    buffer.push_back(static_cast<uint8_t>(crc));
    
    // Update final length
    new_length = static_cast<uint16_t>(buffer.size() - STUN_HEADER_SIZE);
    buffer[2] = static_cast<uint8_t>(new_length >> 8);
    buffer[3] = static_cast<uint8_t>(new_length);
    
    return buffer;
}

bool StunMessage::is_stun_message(const std::vector<uint8_t>& data) {
    if (data.size() < STUN_HEADER_SIZE) {
        return false;
    }
    
    // Check first two bits are zero (STUN requirement)
    if ((data[0] & 0xC0) != 0) {
        return false;
    }
    
    // Check magic cookie
    uint32_t cookie = (static_cast<uint32_t>(data[4]) << 24) |
                      (static_cast<uint32_t>(data[5]) << 16) |
                      (static_cast<uint32_t>(data[6]) << 8) |
                      static_cast<uint32_t>(data[7]);
    
    return cookie == STUN_MAGIC_COOKIE;
}

std::optional<StunMessage> StunMessage::deserialize(const std::vector<uint8_t>& data) {
    if (!is_stun_message(data)) {
        return std::nullopt;
    }
    
    StunMessage msg;
    
    // Parse type
    msg.type = static_cast<StunMessageType>(
        (static_cast<uint16_t>(data[0]) << 8) | data[1]);
    
    // Parse length
    uint16_t length = (static_cast<uint16_t>(data[2]) << 8) | data[3];
    
    if (data.size() < STUN_HEADER_SIZE + length) {
        return std::nullopt;
    }
    
    // Parse transaction ID
    std::copy(data.begin() + 8, data.begin() + 20, msg.transaction_id.begin());
    
    // Parse attributes
    size_t offset = STUN_HEADER_SIZE;
    while (offset + 4 <= STUN_HEADER_SIZE + length) {
        uint16_t attr_type = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        uint16_t attr_length = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
        offset += 4;
        
        if (offset + attr_length > data.size()) {
            break;
        }
        
        StunAttribute attr;
        attr.type = static_cast<StunAttributeType>(attr_type);
        attr.value.assign(data.begin() + offset, data.begin() + offset + attr_length);
        msg.attributes.push_back(std::move(attr));
        
        // Move to next attribute (with padding)
        offset += (attr_length + 3) & ~3;
    }
    
    return msg;
}

// ============================================================================
// StunClient Implementation
// ============================================================================

StunClient::StunClient() : rng_(std::random_device{}()) {}

StunClient::StunClient(const StunClientConfig& config) 
    : config_(config), rng_(std::random_device{}()) {}

StunClient::~StunClient() = default;

StunClient::StunClient(StunClient&&) noexcept = default;
StunClient& StunClient::operator=(StunClient&&) noexcept = default;

StunResult StunClient::binding_request(const std::string& server, 
                                       uint16_t port,
                                       int timeout_ms) {
    LOG_STUN_INFO("Sending STUN binding request to " << server << ":" << port);
    
    // Create UDP socket
    socket_t sock = create_udp_socket(0);
    if (!is_valid_socket(sock)) {
        LOG_STUN_ERROR("Failed to create UDP socket");
        StunResult result;
        result.error = StunError(StunErrorCode::ServerError, "Failed to create socket");
        return result;
    }
    
    auto result = binding_request_with_socket(sock, server, port, timeout_ms);
    close_socket(sock);
    return result;
}

StunResult StunClient::binding_request_with_socket(socket_t socket,
                                                   const std::string& server,
                                                   uint16_t port,
                                                   int timeout_ms) {
    StunResult result;
    
    if (timeout_ms == 0) {
        timeout_ms = config_.total_timeout_ms;
    }
    
    // Create binding request
    StunMessage request(StunMessageType::BindingRequest);
    if (!config_.software.empty()) {
        request.add_software(config_.software);
    }
    
    auto start_time = std::chrono::steady_clock::now();
    
    auto response = send_request(socket, request, server, port, timeout_ms);
    
    auto end_time = std::chrono::steady_clock::now();
    result.rtt_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());
    
    if (!response) {
        LOG_STUN_WARN("STUN binding request timed out");
        result.error = StunError(StunErrorCode::ServerError, "Request timed out");
        return result;
    }
    
    if (response->is_error_response()) {
        result.error = response->get_error();
        LOG_STUN_WARN("STUN error response: " << static_cast<int>(result.error->code));
        return result;
    }
    
    if (response->is_success_response()) {
        // Try XOR-MAPPED-ADDRESS first (preferred)
        result.mapped_address = response->get_xor_mapped_address();
        
        // Fall back to MAPPED-ADDRESS
        if (!result.mapped_address) {
            result.mapped_address = response->get_mapped_address();
        }
        
        if (result.mapped_address) {
            result.success = true;
            LOG_STUN_INFO("STUN binding success: " << result.mapped_address->to_string() 
                         << " (RTT: " << result.rtt_ms << "ms)");
        } else {
            result.error = StunError(StunErrorCode::ServerError, "No mapped address in response");
        }
    }
    
    return result;
}

std::optional<StunMessage> StunClient::send_request(socket_t socket,
                                                    const StunMessage& request,
                                                    const std::string& server,
                                                    uint16_t port,
                                                    int timeout_ms) {
    auto data = request.serialize();
    
    // RFC 5389 retransmission algorithm
    int rto = config_.rto_ms;
    int total_time = 0;
    
    for (int attempt = 0; attempt <= config_.max_retransmissions; attempt++) {
        if (total_time >= timeout_ms) {
            break;
        }
        
        // Send request
        int sent = send_udp_data(socket, data, server, port);
        if (sent <= 0) {
            LOG_STUN_ERROR("Failed to send STUN request");
            return std::nullopt;
        }
        
        LOG_STUN_DEBUG("Sent STUN request (attempt " << (attempt + 1) << ", RTO: " << rto << "ms)");
        
        // Wait for response with current RTO
        int wait_time = (std::min)(rto, timeout_ms - total_time);
        Peer sender;
        
        auto response_data = receive_udp_data(socket, STUN_MAX_MESSAGE_SIZE, sender, wait_time);
        
        total_time += wait_time;
        
        if (!response_data.empty()) {
            auto response = StunMessage::deserialize(response_data);
            if (response && response->transaction_id == request.transaction_id) {
                return response;
            }
            // Wrong transaction ID, continue waiting
        }
        
        // Double RTO for next attempt (RFC 5389)
        rto = (std::min)(rto * 2, 16000);  // Cap at 16 seconds
    }
    
    return std::nullopt;
}

// ============================================================================
// Utility Functions
// ============================================================================

StunMappedAddress stun_xor_address(const StunMappedAddress& addr,
                                   const std::array<uint8_t, STUN_TRANSACTION_ID_SIZE>& transaction_id) {
    StunMappedAddress result = addr;
    result.port ^= static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
    
    if (addr.family == StunAddressFamily::IPv4) {
        uint32_t ip = 0;
        int a, b, c, d;
        if (sscanf(addr.address.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            ip = (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) |
                 (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
        }
        ip ^= STUN_MAGIC_COOKIE;
        
        result.address = std::to_string((ip >> 24) & 0xFF) + "." +
                         std::to_string((ip >> 16) & 0xFF) + "." +
                         std::to_string((ip >> 8) & 0xFF) + "." +
                         std::to_string(ip & 0xFF);
    }
    // IPv6 XOR with magic cookie + transaction ID would be implemented similarly
    
    return result;
}

std::vector<std::pair<std::string, uint16_t>> get_public_stun_servers() {
    return {
        {"stun.l.google.com", 19302},
        {"stun1.l.google.com", 19302},
        {"stun2.l.google.com", 19302},
        {"stun3.l.google.com", 19302},
        {"stun4.l.google.com", 19302},
        {"stun.stunprotocol.org", 3478},
        {"stun.voip.blackberry.com", 3478},
        {"stun.sipgate.net", 3478}
    };
}

} // namespace librats
