#include "bittorrent/magnet_uri.h"

#include <algorithm>
#include <cctype>

namespace librats::bittorrent {

namespace {

/// Percent-decode a URL component (leaves '+' as a literal, as magnet links do).
std::string url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int hi = hex(s[i + 1]), lo = hex(s[i + 2]);
            if (hi >= 0 && lo >= 0) { out.push_back(char(hi << 4 | lo)); i += 2; continue; }
        }
        out.push_back(s[i]);
    }
    return out;
}

/// Decode a 32-character RFC 4648 base32 string into a 20-byte info-hash.
std::optional<InfoHash> base32_to_info_hash(const std::string& in) {
    if (in.size() != 32) return std::nullopt;
    auto value = [](char c) -> int {
        c = char(std::toupper(static_cast<unsigned char>(c)));
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= '2' && c <= '7') return c - '2' + 26;
        return -1;
    };
    InfoHash out{};
    std::uint32_t bits = 0;
    int bit_count = 0;
    std::size_t byte = 0;
    for (char c : in) {
        const int v = value(c);
        if (v < 0) return std::nullopt;
        bits = bits << 5 | std::uint32_t(v);
        bit_count += 5;
        if (bit_count >= 8) {
            bit_count -= 8;
            out[byte++] = std::uint8_t(bits >> bit_count);
        }
    }
    return out;  // 32 * 5 = 160 bits = exactly 20 bytes
}

} // namespace

std::optional<MagnetUri> MagnetUri::parse(const std::string& uri) {
    constexpr char kPrefix[] = "magnet:?";
    if (uri.rfind(kPrefix, 0) != 0) return std::nullopt;

    MagnetUri result;
    const std::string query = uri.substr(sizeof(kPrefix) - 1);

    std::size_t pos = 0;
    while (pos < query.size()) {
        std::size_t amp = query.find('&', pos);
        if (amp == std::string::npos) amp = query.size();
        const std::string token = query.substr(pos, amp - pos);
        pos = amp + 1;

        const std::size_t eq = token.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = token.substr(0, eq);
        const std::string val = url_decode(token.substr(eq + 1));

        if (key == "xt") {
            constexpr char kBtih[] = "urn:btih:";
            if (val.rfind(kBtih, 0) == 0) {
                const std::string id = val.substr(sizeof(kBtih) - 1);
                if (auto h = info_hash_from_hex(id)) result.info_hash = *h;
                else if (auto b = base32_to_info_hash(id)) result.info_hash = *b;
            }
            // urn:btmh: (v2) intentionally ignored for now.
        } else if (key == "dn") {
            result.display_name = val;
        } else if (key == "tr") {
            if (!val.empty()) result.trackers.push_back(val);
        } else if (key == "ws") {
            if (!val.empty()) result.web_seeds.push_back(val);
        }
    }

    if (!result.is_valid()) return std::nullopt;
    return result;
}

} // namespace librats::bittorrent
