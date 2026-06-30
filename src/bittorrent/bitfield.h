#pragma once

/**
 * @file bitfield.h
 * @brief A compact, wire-compatible bit set — the BitTorrent "bitfield".
 *
 * Bits are packed MSB-first within each byte (bit @c i lives in byte @c i/8 at
 * mask @c 0x80>>(i%8)), which is exactly the on-wire layout of the BEP 3
 * `bitfield` message. So data()/data_size() can be sent verbatim and assign()
 * ingests a received message with no conversion. Spare bits in the final byte
 * are always kept zero, which lets count()/none_set() scan whole bytes safely.
 *
 * Owned by a single torrent on the network thread — deliberately not thread-safe.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace librats::bittorrent {

class Bitfield {
public:
    Bitfield() = default;
    explicit Bitfield(std::size_t bits, bool value = false) { resize(bits, value); }

    /// Resize to @p bits bits; any newly added bits take @p value. Existing bits preserved.
    void resize(std::size_t bits, bool value = false);

    /// Ingest a received wire bitfield: @p bytes raw bytes interpreted as @p bits bits.
    /// Spare bits beyond @p bits are cleared so the invariant holds.
    void assign(const std::uint8_t* data, std::size_t bytes, std::size_t bits);

    void clear() noexcept { bytes_.clear(); bits_ = 0; }

    std::size_t size()      const noexcept { return bits_; }
    std::size_t num_bytes() const noexcept { return bytes_.size(); }
    bool        empty()     const noexcept { return bits_ == 0; }

    bool get(std::size_t i) const noexcept {
        return (bytes_[i >> 3] & (0x80u >> (i & 7))) != 0;
    }
    bool operator[](std::size_t i) const noexcept { return get(i); }

    void set(std::size_t i) noexcept   { bytes_[i >> 3] |=  std::uint8_t(0x80u >> (i & 7)); }
    void reset(std::size_t i) noexcept { bytes_[i >> 3] &= std::uint8_t(~(0x80u >> (i & 7))); }
    void set(std::size_t i, bool v) noexcept { if (v) set(i); else reset(i); }

    std::size_t count()    const noexcept;  ///< number of set bits
    bool        all_set()  const noexcept;
    bool        none_set() const noexcept;
    void        set_all()   noexcept;
    void        clear_all() noexcept;

    /// First index whose bit is 0, or size() if all bits are set. Answers
    /// "what is the first piece I still need?".
    std::size_t find_first_unset() const noexcept;

    const std::uint8_t* data()      const noexcept { return bytes_.data(); }
    std::size_t         data_size() const noexcept { return bytes_.size(); }

    bool operator==(const Bitfield& o) const noexcept {
        return bits_ == o.bits_ && bytes_ == o.bytes_;
    }
    bool operator!=(const Bitfield& o) const noexcept { return !(*this == o); }

private:
    void clear_trailing_bits() noexcept;  ///< keep the spare bits of the last byte zero

    std::vector<std::uint8_t> bytes_;
    std::size_t               bits_ = 0;
};

} // namespace librats::bittorrent
