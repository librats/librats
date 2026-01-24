#pragma once

/**
 * @file bt_types.h
 * @brief Core BitTorrent types and constants for librats
 * 
 * This file contains fundamental types used throughout the BitTorrent
 * implementation including PeerID, constants, and utility functions.
 */

#include <array>
#include <cstdint>
#include <string>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace librats {

//=============================================================================
// Constants
//=============================================================================

/// Size of peer ID in bytes (BEP 20)
constexpr size_t BT_PEER_ID_SIZE = 20;

/// Size of info hash in bytes (SHA-1)
constexpr size_t BT_INFO_HASH_SIZE = 20;

/// Standard block size in bytes (16 KB)
constexpr uint32_t BT_BLOCK_SIZE = 16384;

/// Maximum block size allowed (typically 16 KB, some clients allow 32 KB)
constexpr uint32_t BT_MAX_BLOCK_SIZE = 32768;

/// Default piece length for created torrents (256 KB)
constexpr uint32_t BT_DEFAULT_PIECE_LENGTH = 262144;

/// Protocol string for BitTorrent handshake
constexpr char BT_PROTOCOL_STRING[] = "BitTorrent protocol";

/// Length of protocol string
constexpr size_t BT_PROTOCOL_STRING_LEN = 19;

/// Total handshake size: 1 + 19 + 8 + 20 + 20 = 68 bytes
constexpr size_t BT_HANDSHAKE_SIZE = 68;

/// Reserved bytes in handshake (8 bytes)
constexpr size_t BT_RESERVED_SIZE = 8;

/// Metadata block size for BEP 9 (16 KB)
constexpr uint32_t BT_METADATA_PIECE_SIZE = 16384;

/// Maximum number of outstanding requests to a single peer
constexpr size_t BT_MAX_PENDING_REQUESTS = 250;

/// Default request queue size
constexpr size_t BT_DEFAULT_REQUEST_QUEUE_SIZE = 16;

//=============================================================================
// Reserved Bytes Bit Positions (for extensions)
//=============================================================================

namespace ReservedBits {
    /// BEP 5: DHT support (reserved[7] bit 0)
    constexpr uint8_t DHT = 0x01;
    
    /// BEP 6: Fast extension (reserved[7] bit 2)
    constexpr uint8_t FAST = 0x04;
    
    /// BEP 10: Extension protocol (reserved[5] bit 4)
    constexpr uint8_t EXTENSION_PROTOCOL = 0x10;
}

//=============================================================================
// Type Definitions
//=============================================================================

/// 20-byte peer identifier (BEP 20 format)
using PeerID = std::array<uint8_t, BT_PEER_ID_SIZE>;

/// 20-byte info hash (SHA-1 of info dict)
/// Note: Reuses InfoHash from dht.h when available
using BtInfoHash = std::array<uint8_t, BT_INFO_HASH_SIZE>;

//=============================================================================
// Peer ID Generation (BEP 20)
//=============================================================================

/**
 * @brief Generate a peer ID in Azureus-style format (BEP 20)
 * 
 * Format: -XX0000-xxxxxxxxxxxx
 * Where XX is client ID, 0000 is version, x is random
 * 
 * @param client_id Client identifier (e.g., "-LR0001-" for librats v0.0.0.1)
 * @return Generated peer ID
 */
inline PeerID generate_peer_id(const std::string& client_id = "-LR0001-") {
    PeerID peer_id{};
    
    // Copy client ID prefix (up to 8 characters)
    size_t prefix_len = std::min(client_id.size(), static_cast<size_t>(8));
    for (size_t i = 0; i < prefix_len; ++i) {
        peer_id[i] = static_cast<uint8_t>(client_id[i]);
    }
    
    // Fill remaining 12 bytes with random data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);
    
    for (size_t i = prefix_len; i < BT_PEER_ID_SIZE; ++i) {
        peer_id[i] = static_cast<uint8_t>(dis(gen));
    }
    
    return peer_id;
}

/**
 * @brief Generate a peer ID with timestamp-based randomness
 * 
 * Uses current time for additional entropy in the random portion
 * 
 * @param client_id Client identifier prefix
 * @return Generated peer ID
 */
inline PeerID generate_peer_id_with_timestamp(const std::string& client_id = "-LR0001-") {
    PeerID peer_id{};
    
    // Copy client ID prefix
    size_t prefix_len = std::min(client_id.size(), static_cast<size_t>(8));
    for (size_t i = 0; i < prefix_len; ++i) {
        peer_id[i] = static_cast<uint8_t>(client_id[i]);
    }
    
    // Use timestamp for seed
    auto now = std::chrono::high_resolution_clock::now();
    auto seed = static_cast<unsigned int>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()
        ).count()
    );
    
    std::mt19937 gen(seed);
    std::uniform_int_distribution<int> dis(0, 255);
    
    for (size_t i = prefix_len; i < BT_PEER_ID_SIZE; ++i) {
        peer_id[i] = static_cast<uint8_t>(dis(gen));
    }
    
    return peer_id;
}

//=============================================================================
// Conversion Utilities
//=============================================================================

/**
 * @brief Convert peer ID to printable string
 * 
 * Non-printable characters are shown as hex escapes
 * 
 * @param id Peer ID to convert
 * @return String representation
 */
inline std::string peer_id_to_string(const PeerID& id) {
    std::ostringstream oss;
    for (uint8_t byte : id) {
        if (byte >= 32 && byte < 127) {
            oss << static_cast<char>(byte);
        } else {
            oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') 
                << static_cast<int>(byte);
        }
    }
    return oss.str();
}

/**
 * @brief Convert peer ID to hex string
 * 
 * @param id Peer ID to convert
 * @return 40-character hex string
 */
inline std::string peer_id_to_hex(const PeerID& id) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : id) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

/**
 * @brief Convert info hash to hex string
 * 
 * @param hash Info hash to convert
 * @return 40-character hex string
 */
inline std::string info_hash_to_hex(const BtInfoHash& hash) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : hash) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

/**
 * @brief Convert hex string to info hash
 * 
 * @param hex 40-character hex string
 * @return Info hash, or zero-filled array on error
 */
inline BtInfoHash hex_to_info_hash(const std::string& hex) {
    BtInfoHash hash{};
    if (hex.length() != 40) {
        return hash;
    }
    
    for (size_t i = 0; i < 20; ++i) {
        std::string byte_str = hex.substr(i * 2, 2);
        try {
            hash[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        } catch (...) {
            return BtInfoHash{};
        }
    }
    
    return hash;
}

/**
 * @brief Check if info hash is all zeros (invalid)
 * 
 * @param hash Info hash to check
 * @return true if all zeros
 */
inline bool is_zero_hash(const BtInfoHash& hash) {
    for (uint8_t byte : hash) {
        if (byte != 0) return false;
    }
    return true;
}

//=============================================================================
// Client ID Parsing
//=============================================================================

/**
 * @brief Extract client name from peer ID (BEP 20)
 * 
 * Attempts to identify the client from the peer ID prefix
 * 
 * @param id Peer ID to parse
 * @return Client name or "Unknown"
 */
inline std::string identify_client(const PeerID& id) {
    // Azureus-style: -XX1234-
    if (id[0] == '-' && id[7] == '-') {
        char client[3] = {static_cast<char>(id[1]), static_cast<char>(id[2]), '\0'};
        std::string client_code(client);
        
        if (client_code == "LR") return "librats";
        if (client_code == "LT") return "libtorrent";
        if (client_code == "qB") return "qBittorrent";
        if (client_code == "DE") return "Deluge";
        if (client_code == "TR") return "Transmission";
        if (client_code == "UT") return "uTorrent";
        if (client_code == "AZ") return "Azureus/Vuze";
        if (client_code == "BT") return "BitTorrent";
        
        return std::string("Unknown (") + client_code + ")";
    }
    
    // Shadow-style: first byte is client ID
    // Not as common, but still used
    
    return "Unknown";
}

//=============================================================================
// Piece/Block Structures
//=============================================================================

/**
 * @brief Represents a block within a piece
 */
struct BlockInfo {
    uint32_t piece_index;   ///< Index of the piece
    uint32_t offset;        ///< Offset within the piece
    uint32_t length;        ///< Length of the block
    
    BlockInfo() : piece_index(0), offset(0), length(0) {}
    BlockInfo(uint32_t piece, uint32_t off, uint32_t len)
        : piece_index(piece), offset(off), length(len) {}
    
    bool operator==(const BlockInfo& other) const {
        return piece_index == other.piece_index 
            && offset == other.offset 
            && length == other.length;
    }
    
    bool operator!=(const BlockInfo& other) const {
        return !(*this == other);
    }
    
    bool operator<(const BlockInfo& other) const {
        if (piece_index != other.piece_index) return piece_index < other.piece_index;
        if (offset != other.offset) return offset < other.offset;
        return length < other.length;
    }
};

/**
 * @brief Hash function for BlockInfo (for use in unordered containers)
 */
struct BlockInfoHash {
    size_t operator()(const BlockInfo& b) const {
        return std::hash<uint64_t>()(
            (static_cast<uint64_t>(b.piece_index) << 32) | 
            (static_cast<uint64_t>(b.offset) << 16) | 
            b.length
        );
    }
};

} // namespace librats
