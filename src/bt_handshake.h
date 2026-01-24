#pragma once

/**
 * @file bt_handshake.h
 * @brief BitTorrent handshake handling
 * 
 * Implements the BitTorrent handshake protocol:
 * <pstrlen><pstr><reserved><info_hash><peer_id>
 * 
 * Where:
 * - pstrlen: 1 byte, length of pstr (19 for "BitTorrent protocol")
 * - pstr: 19 bytes, protocol string
 * - reserved: 8 bytes, extension flags
 * - info_hash: 20 bytes, SHA-1 hash of the info dictionary
 * - peer_id: 20 bytes, unique client identifier
 */

#include "bt_types.h"

#include <vector>
#include <cstdint>
#include <optional>
#include <array>

namespace librats {

//=============================================================================
// Extension Flags
//=============================================================================

/**
 * @brief Extension flags in reserved bytes
 */
struct ExtensionFlags {
    bool dht;               ///< BEP 5: DHT support (reserved[7] & 0x01)
    bool fast;              ///< BEP 6: Fast extension (reserved[7] & 0x04)
    bool extension_protocol;///< BEP 10: Extension protocol (reserved[5] & 0x10)
    
    ExtensionFlags() : dht(false), fast(false), extension_protocol(false) {}
    
    /**
     * @brief Set all standard extensions
     */
    void enable_all() {
        dht = true;
        fast = true;
        extension_protocol = true;
    }
    
    /**
     * @brief Convert to 8-byte reserved field
     */
    std::array<uint8_t, 8> to_reserved() const;
    
    /**
     * @brief Parse from 8-byte reserved field
     */
    static ExtensionFlags from_reserved(const uint8_t* reserved);
};

//=============================================================================
// Handshake Data
//=============================================================================

/**
 * @brief Parsed handshake data
 */
struct Handshake {
    BtInfoHash info_hash;           ///< 20-byte info hash
    PeerID peer_id;                 ///< 20-byte peer ID
    ExtensionFlags extensions;      ///< Parsed extension flags
    std::array<uint8_t, 8> reserved;///< Raw reserved bytes
    
    Handshake() : info_hash{}, peer_id{}, reserved{} {}
    
    /**
     * @brief Check if handshake is valid
     */
    bool is_valid() const { return !is_zero_hash(info_hash); }
    
    /**
     * @brief Get peer ID as string
     */
    std::string peer_id_string() const { return peer_id_to_string(peer_id); }
    
    /**
     * @brief Get info hash as hex string
     */
    std::string info_hash_hex() const { return info_hash_to_hex(info_hash); }
};

//=============================================================================
// Handshake Encoder/Decoder
//=============================================================================

/**
 * @brief Encode and decode BitTorrent handshakes
 */
class BtHandshake {
public:
    /**
     * @brief Create a handshake message
     * 
     * @param info_hash 20-byte info hash
     * @param peer_id 20-byte peer ID
     * @param extensions Extension flags to advertise
     * @return 68-byte handshake message
     */
    static std::vector<uint8_t> encode(const BtInfoHash& info_hash,
                                        const PeerID& peer_id,
                                        const ExtensionFlags& extensions = ExtensionFlags());
    
    /**
     * @brief Create a handshake message with all extensions enabled
     */
    static std::vector<uint8_t> encode_with_extensions(const BtInfoHash& info_hash,
                                                        const PeerID& peer_id);
    
    /**
     * @brief Check if buffer contains a complete handshake
     * 
     * @param data Buffer data
     * @param length Buffer length
     * @return true if at least 68 bytes available
     */
    static bool is_complete(const uint8_t* data, size_t length);
    
    /**
     * @brief Decode a handshake message
     * 
     * @param data Buffer data (at least 68 bytes)
     * @param length Buffer length
     * @return Decoded handshake, or nullopt on error
     */
    static std::optional<Handshake> decode(const uint8_t* data, size_t length);
    
    /**
     * @brief Decode from vector
     */
    static std::optional<Handshake> decode(const std::vector<uint8_t>& data);
    
    /**
     * @brief Validate handshake protocol string
     * 
     * @param data Buffer data
     * @param length Buffer length  
     * @return true if starts with valid protocol string
     */
    static bool validate_protocol(const uint8_t* data, size_t length);
    
    /**
     * @brief Get size of handshake in bytes
     */
    static constexpr size_t size() { return BT_HANDSHAKE_SIZE; }
};

} // namespace librats
