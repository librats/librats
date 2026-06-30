#include "bittorrent/bitfield.h"

#include <algorithm>
#include <array>

namespace librats::bittorrent {

namespace {

/// 256-entry popcount table, built once. Reading a table beats per-bit work and
/// keeps count() branch-free and portable across compilers (no C++20 std::popcount).
const std::array<std::uint8_t, 256>& popcount_table() {
    static const std::array<std::uint8_t, 256> table = [] {
        std::array<std::uint8_t, 256> t{};
        for (int i = 0; i < 256; ++i) {
            std::uint8_t bits = 0;
            for (int b = i; b; b >>= 1) bits += b & 1;
            t[std::size_t(i)] = bits;
        }
        return t;
    }();
    return table;
}

} // namespace

void Bitfield::resize(std::size_t bits, bool value) {
    const std::size_t old_bits  = bits_;
    const std::size_t new_bytes = (bits + 7) / 8;

    // resize() fills only the *newly appended* bytes with the fill value.
    bytes_.resize(new_bytes, value ? 0xFFu : 0x00u);
    bits_ = bits;

    // When growing with value=true, the spare bits left over in the old (partial)
    // last byte were trailing zeros and weren't touched by resize() — set them.
    if (value && bits > old_bits) {
        const std::size_t old_byte_end = (old_bits + 7) / 8 * 8;  // bit just past old last byte
        for (std::size_t i = old_bits; i < std::min(bits, old_byte_end); ++i) set(i);
    }
    clear_trailing_bits();
}

void Bitfield::assign(const std::uint8_t* data, std::size_t bytes, std::size_t bits) {
    bytes_.assign(data, data + bytes);
    bytes_.resize((bits + 7) / 8, 0x00u);  // tolerate a short/long wire buffer
    bits_ = bits;
    clear_trailing_bits();
}

void Bitfield::clear_trailing_bits() noexcept {
    const std::size_t rem = bits_ & 7;
    if (rem != 0 && !bytes_.empty()) {
        bytes_.back() &= std::uint8_t(0xFFu << (8 - rem));  // keep the top `rem` bits
    }
}

std::size_t Bitfield::count() const noexcept {
    // Spare bits are always zero, so whole-byte popcount is exact.
    const auto& tbl = popcount_table();
    std::size_t n = 0;
    for (std::uint8_t b : bytes_) n += tbl[b];
    return n;
}

bool Bitfield::all_set() const noexcept {
    return find_first_unset() == bits_;
}

bool Bitfield::none_set() const noexcept {
    for (std::uint8_t b : bytes_) if (b != 0) return false;
    return true;
}

void Bitfield::set_all() noexcept {
    std::fill(bytes_.begin(), bytes_.end(), 0xFFu);
    clear_trailing_bits();
}

void Bitfield::clear_all() noexcept {
    std::fill(bytes_.begin(), bytes_.end(), 0x00u);
}

std::size_t Bitfield::find_first_unset() const noexcept {
    for (std::size_t bi = 0; bi < bytes_.size(); ++bi) {
        if (bytes_[bi] == 0xFFu) continue;            // fully set byte — skip fast
        const std::size_t base = bi * 8;
        for (std::size_t k = 0; k < 8; ++k) {
            const std::size_t idx = base + k;
            if (idx >= bits_) return bits_;
            if (!get(idx)) return idx;
        }
    }
    return bits_;
}

} // namespace librats::bittorrent
