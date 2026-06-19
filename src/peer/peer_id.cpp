#include "peer/peer_id.h"

extern "C" {
#include "sha256.h"
}

#include <cstring>

namespace librats {

namespace {
constexpr char kHexDigits[] = "0123456789abcdef";

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
} // namespace

PeerId PeerId::from_public_key(const uint8_t* key, size_t len) {
    PeerId id;
    sha256_hash(id.bytes_.data(), key, len);
    return id;
}

std::optional<PeerId> PeerId::from_bytes(ByteView raw) {
    if (raw.size() != kSize) return std::nullopt;
    PeerId id;
    std::memcpy(id.bytes_.data(), raw.data(), kSize);
    return id;
}

std::optional<PeerId> PeerId::from_hex(std::string_view hex) {
    if (hex.size() != kSize * 2) return std::nullopt;
    PeerId id;
    for (size_t i = 0; i < kSize; ++i) {
        const int hi = hex_value(hex[2 * i]);
        const int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        id.bytes_[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return id;
}

std::string PeerId::to_hex() const {
    std::string out(kSize * 2, '0');
    for (size_t i = 0; i < kSize; ++i) {
        out[2 * i]     = kHexDigits[bytes_[i] >> 4];
        out[2 * i + 1] = kHexDigits[bytes_[i] & 0x0F];
    }
    return out;
}

std::string PeerId::short_hex() const {
    return to_hex().substr(0, 8);
}

bool PeerId::is_zero() const noexcept {
    for (uint8_t b : bytes_) if (b != 0) return false;
    return true;
}

size_t PeerId::Hash::operator()(const PeerId& id) const noexcept {
    // The bytes are already a uniform hash; fold the first word into size_t.
    size_t h = 0;
    std::memcpy(&h, id.bytes_.data(), sizeof(h));
    return h;
}

} // namespace librats
