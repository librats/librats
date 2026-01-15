#ifndef LIBRATS_CRC32_H
#define LIBRATS_CRC32_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace librats {

/**
 * @brief CRC32 calculator class
 * 
 * Uses the standard CRC32 polynomial (0xEDB88320) which is compatible
 * with zlib, gzip, PNG, and other common CRC32 implementations.
 * 
 * Example usage:
 * @code
 * CRC32 crc;
 * crc.update("Hello", 5);
 * crc.update(" World", 6);
 * uint32_t checksum = crc.finalize();
 * 
 * // Or use static helper:
 * uint32_t checksum2 = CRC32::calculate("Hello World", 11);
 * @endcode
 */
class CRC32 {
public:
    /**
     * @brief Construct a new CRC32 object with initial state
     */
    CRC32();
    
    /**
     * @brief Reset the CRC32 calculator to initial state
     */
    void reset();
    
    /**
     * @brief Update CRC32 with a block of data
     * @param data Pointer to data
     * @param length Length of data in bytes
     */
    void update(const void* data, size_t length);
    
    /**
     * @brief Update CRC32 with a single byte
     * @param byte Single byte to add
     */
    void update(uint8_t byte);
    
    /**
     * @brief Update CRC32 with a string
     * @param str String to add
     */
    void update(const std::string& str);
    
    /**
     * @brief Update CRC32 with a vector of bytes
     * @param data Vector of bytes to add
     */
    void update(const std::vector<uint8_t>& data);
    
    /**
     * @brief Finalize and get the CRC32 value
     * @return uint32_t Final CRC32 checksum
     */
    uint32_t finalize() const;
    
    /**
     * @brief Get current CRC32 value without finalizing
     * @return uint32_t Current CRC32 state
     */
    uint32_t get_value() const;
    
    /**
     * @brief Static helper to calculate CRC32 of a buffer in one call
     * @param data Pointer to data
     * @param length Length of data in bytes
     * @return uint32_t CRC32 checksum
     */
    static uint32_t calculate(const void* data, size_t length);
    
    /**
     * @brief Static helper to calculate CRC32 of a string
     * @param str String to hash
     * @return uint32_t CRC32 checksum
     */
    static uint32_t calculate(const std::string& str);
    
    /**
     * @brief Static helper to calculate CRC32 of a vector
     * @param data Vector of bytes to hash
     * @return uint32_t CRC32 checksum
     */
    static uint32_t calculate(const std::vector<uint8_t>& data);

private:
    uint32_t crc_;
    
    /**
     * @brief Initialize the lookup table (called once, thread-safe)
     */
    static void init_table();
    
    /**
     * @brief CRC32 lookup table
     */
    static uint32_t table_[256];
    
    /**
     * @brief Flag indicating if table is initialized
     */
    static bool table_initialized_;
};

/**
 * @brief Calculate CRC32 checksum (legacy function, kept for compatibility)
 * 
 * @param data Pointer to data buffer
 * @param length Length of data in bytes
 * @return uint32_t CRC32 checksum
 */
uint32_t storage_calculate_crc32(const void* data, size_t length);

} // namespace librats

#endif // LIBRATS_CRC32_H
