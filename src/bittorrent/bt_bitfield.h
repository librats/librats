#pragma once

/**
 * @file bt_bitfield.h
 * @brief Efficient bitfield implementation for piece tracking
 * 
 * Provides a memory-efficient bitfield class for tracking which pieces
 * have been downloaded or are available from peers.
 */

#include <vector>
#include <cstdint>
#include <cstddef>
#include <string>

namespace librats {

/**
 * @brief Efficient bit array for tracking pieces
 * 
 * Uses packed uint32_t words for efficient memory usage and fast operations.
 * Bits are stored in big-endian order within each byte to match BitTorrent
 * protocol wire format.
 */
class Bitfield {
public:
    /**
     * @brief Default constructor - creates empty bitfield
     */
    Bitfield() noexcept;
    
    /**
     * @brief Create bitfield with specified number of bits
     * @param num_bits Number of bits in the bitfield
     * @param initial_value Initial value for all bits (default: false)
     */
    explicit Bitfield(size_t num_bits, bool initial_value = false);
    
    /**
     * @brief Copy constructor
     */
    Bitfield(const Bitfield& other);
    
    /**
     * @brief Move constructor
     */
    Bitfield(Bitfield&& other) noexcept;
    
    /**
     * @brief Copy assignment
     */
    Bitfield& operator=(const Bitfield& other);
    
    /**
     * @brief Move assignment
     */
    Bitfield& operator=(Bitfield&& other) noexcept;
    
    /**
     * @brief Destructor
     */
    ~Bitfield() = default;
    
    //=========================================================================
    // Bit Operations
    //=========================================================================
    
    /**
     * @brief Set a bit to 1
     * @param index Bit index (0-based)
     */
    void set_bit(size_t index);
    
    /**
     * @brief Clear a bit to 0
     * @param index Bit index (0-based)
     */
    void clear_bit(size_t index);
    
    /**
     * @brief Get the value of a bit
     * @param index Bit index (0-based)
     * @return true if bit is set, false otherwise
     */
    bool get_bit(size_t index) const;
    
    /**
     * @brief Operator[] for read access
     * @param index Bit index
     * @return true if bit is set
     */
    bool operator[](size_t index) const { return get_bit(index); }
    
    /**
     * @brief Set all bits to 1
     */
    void set_all();
    
    /**
     * @brief Clear all bits to 0
     */
    void clear_all();
    
    //=========================================================================
    // Query Operations
    //=========================================================================
    
    /**
     * @brief Check if all bits are set
     * @return true if all bits are 1
     */
    bool all_set() const;
    
    /**
     * @brief Check if no bits are set
     * @return true if all bits are 0
     */
    bool none_set() const;
    
    /**
     * @brief Count the number of set bits
     * @return Number of bits that are 1
     */
    size_t count() const;
    
    /**
     * @brief Get the total number of bits
     * @return Size of the bitfield in bits
     */
    size_t size() const noexcept { return num_bits_; }
    
    /**
     * @brief Check if bitfield is empty (size 0)
     * @return true if no bits
     */
    bool empty() const noexcept { return num_bits_ == 0; }
    
    /**
     * @brief Get number of bytes needed to store all bits
     * @return Number of bytes
     */
    size_t num_bytes() const noexcept { return (num_bits_ + 7) / 8; }
    
    /**
     * @brief Get number of 32-bit words used
     * @return Number of uint32_t words
     */
    size_t num_words() const noexcept { return data_.size(); }
    
    //=========================================================================
    // Bitwise Operations
    //=========================================================================
    
    /**
     * @brief Bitwise AND with another bitfield
     * @param other Other bitfield (must be same size)
     * @return Reference to this bitfield
     */
    Bitfield& operator&=(const Bitfield& other);
    
    /**
     * @brief Bitwise OR with another bitfield
     * @param other Other bitfield (must be same size)
     * @return Reference to this bitfield
     */
    Bitfield& operator|=(const Bitfield& other);
    
    /**
     * @brief Bitwise XOR with another bitfield
     * @param other Other bitfield (must be same size)
     * @return Reference to this bitfield
     */
    Bitfield& operator^=(const Bitfield& other);
    
    /**
     * @brief Bitwise NOT (complement)
     * @return New bitfield with all bits flipped
     */
    Bitfield operator~() const;
    
    /**
     * @brief Check if this bitfield has any bits that other doesn't have
     * @param other Other bitfield
     * @return true if (this & ~other) is non-zero
     */
    bool has_bits_not_in(const Bitfield& other) const;
    
    //=========================================================================
    // Serialization (Wire Format)
    //=========================================================================
    
    /**
     * @brief Convert to bytes for wire protocol
     * 
     * Returns bytes in big-endian bit order as per BitTorrent spec.
     * Trailing bits in last byte are set to 0.
     * 
     * @return Vector of bytes
     */
    std::vector<uint8_t> to_bytes() const;
    
    /**
     * @brief Create bitfield from bytes
     * 
     * @param data Pointer to byte data
     * @param data_len Length of data in bytes
     * @param num_bits Number of bits (may be less than data_len * 8)
     * @return New Bitfield
     */
    static Bitfield from_bytes(const uint8_t* data, size_t data_len, size_t num_bits);
    
    /**
     * @brief Create bitfield from byte vector
     * 
     * @param data Byte vector
     * @param num_bits Number of bits
     * @return New Bitfield
     */
    static Bitfield from_bytes(const std::vector<uint8_t>& data, size_t num_bits);
    
    //=========================================================================
    // Resize
    //=========================================================================
    
    /**
     * @brief Resize the bitfield
     * 
     * @param new_size New number of bits
     * @param value Value for new bits if growing
     */
    void resize(size_t new_size, bool value = false);
    
    //=========================================================================
    // Iteration Helpers
    //=========================================================================
    
    /**
     * @brief Find the first set bit
     * @return Index of first set bit, or size() if none
     */
    size_t find_first_set() const;
    
    /**
     * @brief Find the first clear bit
     * @return Index of first clear bit, or size() if none
     */
    size_t find_first_clear() const;
    
    /**
     * @brief Find the next set bit after given index
     * @param start Starting index (exclusive)
     * @return Index of next set bit, or size() if none
     */
    size_t find_next_set(size_t start) const;
    
    /**
     * @brief Find the next clear bit after given index
     * @param start Starting index (exclusive)
     * @return Index of next clear bit, or size() if none
     */
    size_t find_next_clear(size_t start) const;
    
    //=========================================================================
    // Comparison
    //=========================================================================
    
    bool operator==(const Bitfield& other) const;
    bool operator!=(const Bitfield& other) const { return !(*this == other); }
    
    //=========================================================================
    // Debug
    //=========================================================================
    
    /**
     * @brief Convert to string representation for debugging
     * @return String of '0' and '1' characters
     */
    std::string to_string() const;
    
private:
    std::vector<uint32_t> data_;  ///< Packed bit storage
    size_t num_bits_;             ///< Total number of bits
    
    /**
     * @brief Clear trailing bits that are beyond num_bits_
     * 
     * Called after operations that might set bits beyond the valid range
     */
    void clear_trailing_bits();
    
    /**
     * @brief Count set bits in a 32-bit word (popcount)
     */
    static size_t popcount32(uint32_t x);
};

//=============================================================================
// Free Functions
//=============================================================================

/**
 * @brief Bitwise AND of two bitfields
 */
Bitfield operator&(const Bitfield& a, const Bitfield& b);

/**
 * @brief Bitwise OR of two bitfields
 */
Bitfield operator|(const Bitfield& a, const Bitfield& b);

/**
 * @brief Bitwise XOR of two bitfields
 */
Bitfield operator^(const Bitfield& a, const Bitfield& b);

} // namespace librats
