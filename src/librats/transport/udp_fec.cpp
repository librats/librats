#include "librats/transport/udp_fec.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace librats {
namespace udp {
namespace fec {

namespace {

/// GF(2^8) over x^8 + x^4 + x^3 + x^2 + 1 (0x11d), and the code's coefficients.
struct Field {
    uint8_t exp[512];
    uint8_t log[256];
    /// mul[a][b] = a * b: one 256-byte row per factor, so multiplying a symbol by
    /// a constant is a lookup per byte.
    uint8_t mul[256][256];
    uint8_t coef[kMaxRows][kMaxColumns];

    Field() {
        unsigned x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[i] = static_cast<uint8_t>(x);
            log[x] = static_cast<uint8_t>(i);
            x <<= 1;
            if (x & 0x100) x ^= 0x11d;
        }
        for (int i = 255; i < 512; ++i) exp[i] = exp[i - 255];
        log[0] = 0;   // never used: 0 has no logarithm
        for (int a = 0; a < 256; ++a)
            for (int b = 0; b < 256; ++b)
                mul[a][b] = (a && b) ? exp[log[a] + log[b]] : 0;
        // Cauchy: row r is x_r = r, column c is y_c = kMaxRows + c, all distinct, and
        // the entry 1 / (x_r + y_c). Column c scaled by 1 / entry(0, c) = y_c makes
        // row 0 all ones and keeps every square submatrix invertible.
        for (uint32_t r = 0; r < kMaxRows; ++r)
            for (uint32_t c = 0; c < kMaxColumns; ++c) {
                const uint8_t y = static_cast<uint8_t>(kMaxRows + c);
                coef[r][c] = mul[y][inverse(static_cast<uint8_t>(r ^ y))];
            }
    }

    uint8_t inverse(uint8_t a) const noexcept { return exp[255 - log[a]]; }
};

const Field& field() {
    static const Field f;
    return f;
}

/// dst += c * src, over `len` bytes.
void muladd(uint8_t* dst, const uint8_t* src, size_t len, uint8_t c) noexcept {
    if (c == 0) return;
    if (c == 1) {
        for (size_t i = 0; i < len; ++i) dst[i] ^= src[i];
        return;
    }
    const uint8_t* t = field().mul[c];
    for (size_t i = 0; i < len; ++i) dst[i] ^= t[src[i]];
}

/// Invert the n x n matrix `a` (row-major) into `inv`. False if it is singular.
bool invert(std::vector<uint8_t>& a, std::vector<uint8_t>& inv, size_t n) {
    const Field& f = field();
    inv.assign(n * n, 0);
    for (size_t i = 0; i < n; ++i) inv[i * n + i] = 1;
    for (size_t col = 0; col < n; ++col) {
        size_t pivot = col;
        while (pivot < n && a[pivot * n + col] == 0) ++pivot;
        if (pivot == n) return false;
        if (pivot != col)
            for (size_t k = 0; k < n; ++k) {
                std::swap(a[pivot * n + k], a[col * n + k]);
                std::swap(inv[pivot * n + k], inv[col * n + k]);
            }
        const uint8_t* scale = f.mul[f.inverse(a[col * n + col])];
        for (size_t k = 0; k < n; ++k) {
            a[col * n + k]   = scale[a[col * n + k]];
            inv[col * n + k] = scale[inv[col * n + k]];
        }
        for (size_t row = 0; row < n; ++row) {
            const uint8_t factor = a[row * n + col];
            if (row == col || factor == 0) continue;
            const uint8_t* by = f.mul[factor];
            for (size_t k = 0; k < n; ++k) {
                a[row * n + k]   ^= by[a[col * n + k]];
                inv[row * n + k] ^= by[inv[col * n + k]];
            }
        }
    }
    return true;
}

} // namespace

// ── Layout ──────────────────────────────────────────────────────────────────

Layout::Layout(uint32_t size_, uint32_t symbol_) noexcept
    : size(size_), symbol(symbol_), count((size_ + symbol_ - 1) / symbol_),
      blocks((count + kMaxColumns - 1) / kMaxColumns) {}

Layout Layout::fit(uint32_t size, uint32_t max_symbol) noexcept {
    const uint32_t count = (size + max_symbol - 1) / max_symbol;
    return Layout(size, (size + count - 1) / count);
}

uint32_t Layout::length(uint32_t j) const noexcept {
    return j + 1 < count ? symbol : size - offset(j);
}

// ── Coding ──────────────────────────────────────────────────────────────────

void encode(const Layout& l, const uint8_t* data, uint32_t rows, uint8_t* out) {
    std::memset(out, 0, size_t{rows} * l.blocks * l.symbol);
    const Field& f = field();
    for (uint32_t j = 0; j < l.count; ++j) {
        const uint32_t b = l.block_of(j), c = l.column_of(j);
        for (uint32_t r = 0; r < rows; ++r)
            muladd(out + size_t{r * l.blocks + b} * l.symbol, data + l.offset(j), l.length(j), f.coef[r][c]);
    }
}

bool recover(const Layout& l, uint32_t block, uint8_t* data, const uint8_t* known,
             const Repair* repairs, size_t count) {
    std::vector<uint32_t> missing;
    for (uint32_t c = 0; c < l.columns(block); ++c) {
        const uint32_t j = c * l.blocks + block;
        if (!known[j]) missing.push_back(j);
    }
    const size_t n = missing.size();
    if (n == 0) return true;
    if (count < n) return false;

    // What each repair symbol says about the missing ones alone: the known
    // symbols' part of it taken back out.
    const Field& f = field();
    const size_t S = l.symbol;
    std::vector<uint8_t> rest(n * S);
    std::vector<uint8_t> a(n * n);
    for (size_t t = 0; t < n; ++t) {
        const uint32_t row = repairs[t].index / l.blocks;
        uint8_t* s = rest.data() + t * S;
        std::memcpy(s, repairs[t].data, S);
        for (uint32_t c = 0; c < l.columns(block); ++c) {
            const uint32_t j = c * l.blocks + block;
            if (known[j]) muladd(s, data + l.offset(j), l.length(j), f.coef[row][c]);
        }
        for (size_t u = 0; u < n; ++u) a[t * n + u] = f.coef[row][l.column_of(missing[u])];
    }
    // rest = A * missing, so missing = A^-1 * rest.
    std::vector<uint8_t> inv;
    if (!invert(a, inv, n)) return false;
    std::vector<uint8_t> sym(S);
    for (size_t u = 0; u < n; ++u) {
        std::fill(sym.begin(), sym.end(), 0);
        for (size_t t = 0; t < n; ++t) muladd(sym.data(), rest.data() + t * S, S, inv[u * n + t]);
        std::memcpy(data + l.offset(missing[u]), sym.data(), l.length(missing[u]));
    }
    return true;
}

// ── How much ────────────────────────────────────────────────────────────────

uint32_t rows_for(uint32_t columns, double loss, double target) noexcept {
    if (columns == 0 || loss <= 0) return 0;
    loss = (std::min)(loss, 0.5);
    const uint32_t most = (std::min)(kMaxRows, columns);
    for (uint32_t rows = 0; rows < most; ++rows) {
        // P(at most `rows` of the block's columns + rows symbols lost), term by term.
        const uint32_t n = columns + rows;
        double term = 1;
        for (uint32_t i = 0; i < n; ++i) term *= 1 - loss;
        double kept = term;
        for (uint32_t i = 0; i < rows; ++i) {
            term *= double(n - i) / double(i + 1) * loss / (1 - loss);
            kept += term;
        }
        if (1 - kept <= target) return rows;
    }
    return most;
}

void LossEstimate::update(uint64_t delivered, uint64_t lost) noexcept {
    // The loss total can shrink: a packet given up on and acknowledged after all
    // was only reordered, and comes off it again (Recovery::path_lost).
    const uint64_t d = delivered - delivered_, l = lost > lost_ ? lost - lost_ : 0;
    if (d + l < kInterval) return;
    // A long gap between updates is several samples' worth, weighed as such.
    const double sample = double(l) / double(d + l);
    const double weight = (std::min)(1.0, double(d + l) / double(8 * kInterval));
    rate_ += (sample - rate_) * weight;
    delivered_ = delivered;
    lost_      = lost;
}

} // namespace fec
} // namespace udp
} // namespace librats
