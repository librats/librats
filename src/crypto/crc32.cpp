#include "crc32.h"

namespace librats {

//=============================================================================
// Static members
//=============================================================================

uint32_t CRC32::table_[256];
bool CRC32::table_initialized_ = false;

//=============================================================================
// CRC32 Implementation
//=============================================================================

void CRC32::init_table() {
    if (table_initialized_) return;
    
    // Standard CRC32 polynomial (IEEE 802.3)
    // Same as used by zlib, gzip, PNG, etc.
    constexpr uint32_t POLYNOMIAL = 0xEDB88320;
    
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ POLYNOMIAL;
            } else {
                crc = crc >> 1;
            }
        }
        table_[i] = crc;
    }
    table_initialized_ = true;
}

CRC32::CRC32() : crc_(0xFFFFFFFF) {
    init_table();
}

void CRC32::reset() {
    crc_ = 0xFFFFFFFF;
}

void CRC32::update(const void* data, size_t length) {
    if (data == nullptr || length == 0) return;
    
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    
    for (size_t i = 0; i < length; i++) {
        crc_ = (crc_ >> 8) ^ table_[(crc_ ^ bytes[i]) & 0xFF];
    }
}

void CRC32::update(uint8_t byte) {
    crc_ = (crc_ >> 8) ^ table_[(crc_ ^ byte) & 0xFF];
}

void CRC32::update(const std::string& str) {
    update(str.data(), str.size());
}

void CRC32::update(const std::vector<uint8_t>& data) {
    update(data.data(), data.size());
}

uint32_t CRC32::finalize() const {
    return crc_ ^ 0xFFFFFFFF;
}

uint32_t CRC32::get_value() const {
    return crc_ ^ 0xFFFFFFFF;
}

uint32_t CRC32::calculate(const void* data, size_t length) {
    CRC32 crc;
    crc.update(data, length);
    return crc.finalize();
}

uint32_t CRC32::calculate(const std::string& str) {
    return calculate(str.data(), str.size());
}

uint32_t CRC32::calculate(const std::vector<uint8_t>& data) {
    return calculate(data.data(), data.size());
}

//=============================================================================
// Legacy function for backward compatibility
//=============================================================================

uint32_t storage_calculate_crc32(const void* data, size_t length) {
    return CRC32::calculate(data, length);
}

} // namespace librats
