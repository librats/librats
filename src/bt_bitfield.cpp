#include "bt_bitfield.h"
#include <algorithm>
#include <stdexcept>
#include <cstring>

namespace librats {

//=============================================================================
// Constructors
//=============================================================================

Bitfield::Bitfield() noexcept
    : num_bits_(0) {
}

Bitfield::Bitfield(size_t num_bits, bool initial_value)
    : num_bits_(num_bits) {
    if (num_bits_ > 0) {
        size_t num_words = (num_bits_ + 31) / 32;
        data_.resize(num_words, initial_value ? 0xFFFFFFFF : 0);
        if (initial_value) {
            clear_trailing_bits();
        }
    }
}

Bitfield::Bitfield(const Bitfield& other)
    : data_(other.data_), num_bits_(other.num_bits_) {
}

Bitfield::Bitfield(Bitfield&& other) noexcept
    : data_(std::move(other.data_)), num_bits_(other.num_bits_) {
    other.num_bits_ = 0;
}

Bitfield& Bitfield::operator=(const Bitfield& other) {
    if (this != &other) {
        data_ = other.data_;
        num_bits_ = other.num_bits_;
    }
    return *this;
}

Bitfield& Bitfield::operator=(Bitfield&& other) noexcept {
    if (this != &other) {
        data_ = std::move(other.data_);
        num_bits_ = other.num_bits_;
        other.num_bits_ = 0;
    }
    return *this;
}

//=============================================================================
// Bit Operations
//=============================================================================

void Bitfield::set_bit(size_t index) {
    if (index >= num_bits_) {
        return;  // Silently ignore out-of-bounds
    }
    
    size_t word_idx = index / 32;
    size_t bit_idx = 31 - (index % 32);  // Big-endian bit order
    data_[word_idx] |= (1U << bit_idx);
}

void Bitfield::clear_bit(size_t index) {
    if (index >= num_bits_) {
        return;
    }
    
    size_t word_idx = index / 32;
    size_t bit_idx = 31 - (index % 32);
    data_[word_idx] &= ~(1U << bit_idx);
}

bool Bitfield::get_bit(size_t index) const {
    if (index >= num_bits_) {
        return false;
    }
    
    size_t word_idx = index / 32;
    size_t bit_idx = 31 - (index % 32);
    return (data_[word_idx] & (1U << bit_idx)) != 0;
}

void Bitfield::set_all() {
    for (auto& word : data_) {
        word = 0xFFFFFFFF;
    }
    clear_trailing_bits();
}

void Bitfield::clear_all() {
    for (auto& word : data_) {
        word = 0;
    }
}

//=============================================================================
// Query Operations
//=============================================================================

bool Bitfield::all_set() const {
    if (num_bits_ == 0) return true;
    
    // Check all complete words
    size_t complete_words = num_bits_ / 32;
    for (size_t i = 0; i < complete_words; ++i) {
        if (data_[i] != 0xFFFFFFFF) return false;
    }
    
    // Check remaining bits in last word
    size_t remaining_bits = num_bits_ % 32;
    if (remaining_bits > 0) {
        uint32_t mask = 0xFFFFFFFF << (32 - remaining_bits);
        if ((data_.back() & mask) != mask) return false;
    }
    
    return true;
}

bool Bitfield::none_set() const {
    for (const auto& word : data_) {
        if (word != 0) return false;
    }
    return true;
}

size_t Bitfield::count() const {
    size_t total = 0;
    for (const auto& word : data_) {
        total += popcount32(word);
    }
    return total;
}

size_t Bitfield::popcount32(uint32_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return static_cast<size_t>(__builtin_popcount(x));
#elif defined(_MSC_VER)
    return static_cast<size_t>(__popcnt(x));
#else
    // Software fallback
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x + (x >> 4)) & 0x0F0F0F0F;
    x = x + (x >> 8);
    x = x + (x >> 16);
    return x & 0x3F;
#endif
}

//=============================================================================
// Bitwise Operations
//=============================================================================

Bitfield& Bitfield::operator&=(const Bitfield& other) {
    size_t min_words = std::min(data_.size(), other.data_.size());
    for (size_t i = 0; i < min_words; ++i) {
        data_[i] &= other.data_[i];
    }
    // Words beyond other's size become 0
    for (size_t i = min_words; i < data_.size(); ++i) {
        data_[i] = 0;
    }
    return *this;
}

Bitfield& Bitfield::operator|=(const Bitfield& other) {
    size_t min_words = std::min(data_.size(), other.data_.size());
    for (size_t i = 0; i < min_words; ++i) {
        data_[i] |= other.data_[i];
    }
    clear_trailing_bits();
    return *this;
}

Bitfield& Bitfield::operator^=(const Bitfield& other) {
    size_t min_words = std::min(data_.size(), other.data_.size());
    for (size_t i = 0; i < min_words; ++i) {
        data_[i] ^= other.data_[i];
    }
    clear_trailing_bits();
    return *this;
}

Bitfield Bitfield::operator~() const {
    Bitfield result(num_bits_);
    for (size_t i = 0; i < data_.size(); ++i) {
        result.data_[i] = ~data_[i];
    }
    result.clear_trailing_bits();
    return result;
}

bool Bitfield::has_bits_not_in(const Bitfield& other) const {
    size_t min_words = std::min(data_.size(), other.data_.size());
    for (size_t i = 0; i < min_words; ++i) {
        if ((data_[i] & ~other.data_[i]) != 0) return true;
    }
    // Check remaining words in this bitfield
    for (size_t i = min_words; i < data_.size(); ++i) {
        if (data_[i] != 0) return true;
    }
    return false;
}

//=============================================================================
// Serialization
//=============================================================================

std::vector<uint8_t> Bitfield::to_bytes() const {
    size_t byte_count = (num_bits_ + 7) / 8;
    std::vector<uint8_t> bytes(byte_count, 0);
    
    for (size_t i = 0; i < num_bits_; ++i) {
        if (get_bit(i)) {
            size_t byte_idx = i / 8;
            size_t bit_idx = 7 - (i % 8);  // Big-endian bit order within byte
            bytes[byte_idx] |= (1 << bit_idx);
        }
    }
    
    return bytes;
}

Bitfield Bitfield::from_bytes(const uint8_t* data, size_t data_len, size_t num_bits) {
    Bitfield bf(num_bits);
    
    size_t bits_to_copy = std::min(num_bits, data_len * 8);
    for (size_t i = 0; i < bits_to_copy; ++i) {
        size_t byte_idx = i / 8;
        size_t bit_idx = 7 - (i % 8);  // Big-endian bit order
        if (data[byte_idx] & (1 << bit_idx)) {
            bf.set_bit(i);
        }
    }
    
    return bf;
}

Bitfield Bitfield::from_bytes(const std::vector<uint8_t>& data, size_t num_bits) {
    return from_bytes(data.data(), data.size(), num_bits);
}

//=============================================================================
// Resize
//=============================================================================

void Bitfield::resize(size_t new_size, bool value) {
    size_t old_size = num_bits_;
    num_bits_ = new_size;
    
    size_t new_words = (new_size + 31) / 32;
    size_t old_words = data_.size();
    
    data_.resize(new_words, value ? 0xFFFFFFFF : 0);
    
    // If growing and value is true, set new bits
    if (new_size > old_size && value) {
        // Set bits from old_size to new_size
        for (size_t i = old_size; i < new_size; ++i) {
            set_bit(i);
        }
    }
    
    clear_trailing_bits();
}

//=============================================================================
// Iteration Helpers
//=============================================================================

size_t Bitfield::find_first_set() const {
    for (size_t w = 0; w < data_.size(); ++w) {
        if (data_[w] != 0) {
            // Find first set bit in this word
            for (int b = 31; b >= 0; --b) {
                size_t bit_idx = w * 32 + (31 - b);
                if (bit_idx >= num_bits_) return num_bits_;
                if (data_[w] & (1U << b)) {
                    return bit_idx;
                }
            }
        }
    }
    return num_bits_;
}

size_t Bitfield::find_first_clear() const {
    for (size_t i = 0; i < num_bits_; ++i) {
        if (!get_bit(i)) return i;
    }
    return num_bits_;
}

size_t Bitfield::find_next_set(size_t start) const {
    for (size_t i = start + 1; i < num_bits_; ++i) {
        if (get_bit(i)) return i;
    }
    return num_bits_;
}

size_t Bitfield::find_next_clear(size_t start) const {
    for (size_t i = start + 1; i < num_bits_; ++i) {
        if (!get_bit(i)) return i;
    }
    return num_bits_;
}

//=============================================================================
// Comparison
//=============================================================================

bool Bitfield::operator==(const Bitfield& other) const {
    if (num_bits_ != other.num_bits_) return false;
    return data_ == other.data_;
}

//=============================================================================
// Debug
//=============================================================================

std::string Bitfield::to_string() const {
    std::string result;
    result.reserve(num_bits_);
    for (size_t i = 0; i < num_bits_; ++i) {
        result += get_bit(i) ? '1' : '0';
    }
    return result;
}

//=============================================================================
// Private Helpers
//=============================================================================

void Bitfield::clear_trailing_bits() {
    if (num_bits_ == 0 || data_.empty()) return;
    
    size_t trailing_bits = num_bits_ % 32;
    if (trailing_bits > 0) {
        // Create mask for valid bits in last word
        // If trailing_bits = 5, we want bits 31, 30, 29, 28, 27 to be valid
        uint32_t mask = 0xFFFFFFFF << (32 - trailing_bits);
        data_.back() &= mask;
    }
}

//=============================================================================
// Free Functions
//=============================================================================

Bitfield operator&(const Bitfield& a, const Bitfield& b) {
    Bitfield result(a);
    result &= b;
    return result;
}

Bitfield operator|(const Bitfield& a, const Bitfield& b) {
    Bitfield result(a);
    result |= b;
    return result;
}

Bitfield operator^(const Bitfield& a, const Bitfield& b) {
    Bitfield result(a);
    result ^= b;
    return result;
}

} // namespace librats
