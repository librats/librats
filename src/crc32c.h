#pragma once

#include <cstdint>
#include <cstddef>

namespace librats {

/**
 * CRC32C (Castagnoli) implementation
 * Uses the iSCSI polynomial (0x1EDC6F41)
 * 
 * This is used for BEP 42 (DHT Security Extension) node ID generation
 * to ensure node IDs are derived from IP addresses.
 */

/**
 * Calculate CRC32C of a 32-bit value
 * @param value The 32-bit value to hash
 * @return CRC32C hash
 */
uint32_t crc32c_32(uint32_t value);

/**
 * Calculate CRC32C of a buffer
 * @param data Pointer to the data buffer
 * @param length Length of the data in bytes
 * @return CRC32C hash
 */
uint32_t crc32c(const void* data, size_t length);

/**
 * Calculate CRC32C of a 64-bit value
 * @param value The 64-bit value to hash
 * @return CRC32C hash
 */
uint32_t crc32c_64(uint64_t value);

} // namespace librats

