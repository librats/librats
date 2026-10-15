#pragma once

/**
 * @file udp_fec.h
 * @brief Forward error correction for live messages: repair symbols that stand in for lost pieces.
 *
 * A live message on a long path cannot wait for a repair: by the time a loss is
 * known and the piece sent again, its deadline has gone. So behind the message
 * its sender may send a few repair symbols computed from it, and the receiver
 * rebuilds what the path lost from whatever did arrive — no round trip.
 *
 * The code is Reed-Solomon in its Cauchy form over GF(2^8). A message is cut
 * into `count` source symbols of one size (the last padded with zeros), and
 * repair symbol r of a block is the sum over the block's source symbols j of
 * c(r, j) * s_j, with c a Cauchy matrix: every square submatrix of one is
 * invertible, which is exactly what makes ANY `columns` of a block's
 * `columns + rows` symbols enough to give back all of it. The matrix's columns
 * are scaled so its first row is all ones — still Cauchy in that sense — which
 * makes a lone repair symbol the XOR of the message: the cheapest code there is,
 * and the one most messages get.
 *
 * GF(2^8) has 256 elements, which bounds a block at 256 symbols of both kinds;
 * a message of more than kMaxColumns source symbols is coded as several blocks,
 * symbol j in block j % blocks. Interleaved, so a burst of consecutive losses
 * spreads over the blocks instead of exhausting one.
 */

#include <cstddef>
#include <cstdint>

namespace librats {
namespace udp {
namespace fec {

/// Repair symbols a block has at most, and source symbols it has at most: the
/// two together are GF(2^8)'s 256 elements.
constexpr uint32_t kMaxRows    = 48;
constexpr uint32_t kMaxColumns = 256 - kMaxRows;

/// How a message is cut into symbols and blocks. A repair symbol is named by
/// its index: block index % blocks, row index / blocks.
struct Layout {
    uint32_t size   = 0;   ///< bytes of the message
    uint32_t symbol = 0;   ///< bytes of every symbol
    uint32_t count  = 0;   ///< source symbols
    uint32_t blocks = 0;

    Layout() = default;
    /// `size` and `symbol` at least 1.
    Layout(uint32_t size, uint32_t symbol) noexcept;
    /// `size` bytes in the fewest symbols of at most `max_symbol` bytes, all as
    /// alike as they can be — so the padding of the last is as small as it can be.
    static Layout fit(uint32_t size, uint32_t max_symbol) noexcept;

    uint32_t block_of(uint32_t j) const noexcept { return j % blocks; }
    uint32_t column_of(uint32_t j) const noexcept { return j / blocks; }
    /// Source symbols in block `b`; block 0 has the most.
    uint32_t columns(uint32_t b) const noexcept { return count / blocks + (b < count % blocks ? 1 : 0); }
    /// Bytes of source symbol `j` that are the message's: `symbol`, or less for the last.
    uint32_t length(uint32_t j) const noexcept;
    /// Where source symbol `j` begins in the message.
    uint32_t offset(uint32_t j) const noexcept { return j * symbol; }
};

/// Compute `rows` repair symbols for every block of `data` (`layout.size` bytes)
/// into `out`, which has room for rows * blocks symbols: repair `index` at
/// index * symbol.
void encode(const Layout& layout, const uint8_t* data, uint32_t rows, uint8_t* out);

/// A repair symbol a receiver holds: its index, and `layout.symbol` bytes.
struct Repair {
    uint32_t       index = 0;
    const uint8_t* data  = nullptr;
};

/// Rebuild in `data` (`layout.size` bytes) the source symbols of block `block`
/// that `known` (a flag per source symbol) says are missing, from `repairs` of
/// that block — at least as many as are missing, of distinct rows below kMaxRows.
/// False, rebuilding nothing, if there are not enough.
bool recover(const Layout& layout, uint32_t block, uint8_t* data, const uint8_t* known,
             const Repair* repairs, size_t count);

/// Repair symbols per block for a block of `columns` source symbols that, with
/// every packet lost independently with probability `loss`, leave it beyond
/// rebuilding with probability at most `target`. Never more than the block has
/// source symbols, nor more than kMaxRows; 0 for a path that loses nothing.
uint32_t rows_for(uint32_t columns, double loss, double target) noexcept;

/// The share of what a connection sends that the path loses, smoothed over a few
/// hundred packets: fed the running totals of bytes delivered and declared lost
/// (a total that a late acknowledgement may take back).
class LossEstimate {
public:
    /// Bytes resolved per sample: about 64 full packets, so one sample can tell
    /// a loss rate down to a couple of percent and eight of them below one.
    static constexpr uint64_t kInterval = 64 * 1220;

    void   update(uint64_t delivered, uint64_t lost) noexcept;
    /// Measure afresh from these totals on (another path: what the old one lost
    /// says nothing of it).
    void   restart(uint64_t delivered, uint64_t lost) noexcept {
        delivered_ = delivered;
        lost_      = lost;
        rate_      = 0;
    }
    double rate() const noexcept { return rate_; }

private:
    uint64_t delivered_ = 0;   ///< the totals at the last sample
    uint64_t lost_      = 0;
    double   rate_      = 0;
};

} // namespace fec
} // namespace udp
} // namespace librats
