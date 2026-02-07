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
#include <cstring>
#include <cstdio>
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
// Extension Protocol Message IDs (BEP 10)
//=============================================================================

/// Our local ID for ut_metadata extension (BEP 9)
constexpr uint8_t BT_EXT_UT_METADATA_ID = 1;

/// Our local ID for ut_pex extension (BEP 11)
constexpr uint8_t BT_EXT_UT_PEX_ID = 2;

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

/**
 * @brief Hash function for BtInfoHash in unordered containers
 */
struct InfoHashHash {
    size_t operator()(const BtInfoHash& hash) const {
        // Simple hash - combine first few bytes
        size_t result = 0;
        for (size_t i = 0; i < (std::min)(sizeof(size_t), hash.size()); ++i) {
            result = (result << 8) | hash[i];
        }
        return result;
    }
};

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
    size_t prefix_len = (std::min)(client_id.size(), static_cast<size_t>(8));
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
    size_t prefix_len = (std::min)(client_id.size(), static_cast<size_t>(8));
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
// Client ID Parsing (BEP 20)
//=============================================================================

namespace detail {

/**
 * @brief Decode a version digit from peer ID (supports 0-9 and A-Z)
 */
inline int decode_version_digit(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    return 0;
}

/**
 * @brief Azureus-style client name lookup table
 * Based on BEP 20 and libtorrent's identify_client implementation
 */
inline const char* lookup_az_client(const char* code) {
    // Sorted alphabetically by 2-char code for binary search potential
    // Using linear search for simplicity - table is small enough
    struct Entry { const char* code; const char* name; };
    static const Entry entries[] = {
        {"7T", "aTorrent"},
        {"AB", "AnyEvent BitTorrent"},
        {"AG", "Ares"},
        {"AR", "Arctic Torrent"},
        {"AT", "Artemis"},
        {"AV", "Avicora"},
        {"AX", "BitPump"},
        {"AZ", "Azureus"},
        {"A~", "Ares"},
        {"BB", "BitBuddy"},
        {"BC", "BitComet"},
        {"BE", "baretorrent"},
        {"BF", "Bitflu"},
        {"BG", "BTG"},
        {"BI", "BiglyBT"},
        {"BL", "BitBlinder"},
        {"BP", "BitTorrent Pro"},
        {"BR", "BitRocket"},
        {"BS", "BTSlave"},
        {"BT", "BitTorrent"},
        {"BU", "BigUp"},
        {"BW", "BitWombat"},
        {"BX", "BittorrentX"},
        {"CD", "Enhanced CTorrent"},
        {"CT", "CTorrent"},
        {"DE", "Deluge"},
        {"DP", "Propagate Data Client"},
        {"EB", "EBit"},
        {"ES", "electric sheep"},
        {"FC", "FileCroc"},
        {"FT", "FoxTorrent"},
        {"FW", "FrostWire"},
        {"FX", "Freebox BitTorrent"},
        {"GS", "GSTorrent"},
        {"HK", "Hekate"},
        {"HL", "Halite"},
        {"HN", "Hydranode"},
        {"IL", "iLivid"},
        {"KC", "Koinonein"},
        {"KG", "KGet"},
        {"KT", "KTorrent"},
        {"LC", "LeechCraft"},
        {"LH", "LH-ABC"},
        {"LK", "Linkage"},
        {"LP", "lphant"},
        {"LR", "librats"},
        {"LT", "libtorrent"},
        {"LW", "Limewire"},
        {"ML", "MLDonkey"},
        {"MO", "Mono Torrent"},
        {"MP", "MooPolice"},
        {"MR", "Miro"},
        {"MT", "Moonlight Torrent"},
        {"NX", "Net Transport"},
        {"OS", "OneSwarm"},
        {"OT", "OmegaTorrent"},
        {"PD", "Pando"},
        {"QD", "QQDownload"},
        {"QT", "Qt 4"},
        {"RT", "Retriever"},
        {"RZ", "RezTorrent"},
        {"SB", "Swiftbit"},
        {"SD", "Xunlei"},
        {"SK", "spark"},
        {"SN", "ShareNet"},
        {"SS", "SwarmScope"},
        {"ST", "SymTorrent"},
        {"SZ", "Shareaza"},
        {"S~", "Shareaza (beta)"},
        {"TB", "Torch"},
        {"TL", "Tribler"},
        {"TN", "Torrent.NET"},
        {"TR", "Transmission"},
        {"TS", "TorrentStorm"},
        {"TT", "TuoTu"},
        {"UL", "uLeecher"},
        {"UM", "uTorrent Mac"},
        {"UT", "uTorrent"},
        {"VG", "Vagaa"},
        {"WT", "BitLet"},
        {"WY", "FireTorrent"},
        {"XF", "Xfplay"},
        {"XL", "Xunlei"},
        {"XS", "XSwifter"},
        {"XT", "XanTorrent"},
        {"XX", "Xtorrent"},
        {"ZO", "Zona"},
        {"ZT", "ZipTorrent"},
        {"lt", "rTorrent"},
        {"pX", "pHoeniX"},
        {"qB", "qBittorrent"},
        {"st", "SharkTorrent"},
    };

    for (const auto& e : entries) {
        if (e.code[0] == code[0] && e.code[1] == code[1]) {
            return e.name;
        }
    }
    return nullptr;
}

/**
 * @brief Generic (non-standard) client name lookup
 */
inline const char* lookup_generic_client(const uint8_t* id) {
    struct Entry { int offset; const char* pattern; const char* name; };
    static const Entry entries[] = {
        {0, "Deadman Walking-", "Deadman"},
        {5, "Azureus", "Azureus 2.0.3.2"},
        {0, "DansClient", "XanTorrent"},
        {4, "btfans", "SimpleBT"},
        {0, "PRC.P---", "Bittorrent Plus! II"},
        {0, "P87.P---", "Bittorrent Plus!"},
        {0, "S587Plus", "Bittorrent Plus!"},
        {0, "martini", "Martini Man"},
        {0, "Plus---", "Bittorrent Plus"},
        {0, "turbobt", "TurboBT"},
        {0, "a00---0", "Swarmy"},
        {0, "a02---0", "Swarmy"},
        {0, "T00---0", "Teeweety"},
        {0, "BTDWV-", "Deadman Walking"},
        {2, "BS", "BitSpirit"},
        {0, "-SP", "BitSpirit 3.6"},
        {0, "Pando-", "Pando"},
        {0, "LIME", "LimeWire"},
        {0, "btuga", "BTugaXP"},
        {0, "oernu", "BTugaXP"},
        {0, "Mbrst", "Burst!"},
        {0, "PEERAPP", "PeerApp"},
        {0, "Plus", "Plus!"},
        {0, "-Qt-", "Qt"},
        {0, "exbc", "BitComet"},
        {0, "DNA", "BitTorrent DNA"},
        {0, "-G3", "G3 Torrent"},
        {0, "-FG", "FlashGet"},
        {0, "-ML", "MLdonkey"},
        {0, "-MG", "Media Get"},
        {0, "XBT", "XBT"},
        {0, "OP", "Opera"},
        {2, "RS", "Rufus"},
        {0, "AZ2500BT", "BitTyrant"},
        {0, "btpd/", "BitTorrent Protocol Daemon"},
        {0, "TIX", "Tixati"},
        {0, "QVOD", "Qvod"},
    };

    for (const auto& e : entries) {
        const char* p = e.pattern;
        const char* s = reinterpret_cast<const char*>(id) + e.offset;
        size_t len = std::strlen(p);
        if (e.offset + len <= BT_PEER_ID_SIZE && std::memcmp(s, p, len) == 0) {
            return e.name;
        }
    }
    return nullptr;
}

} // namespace detail

/**
 * @brief Identify BitTorrent client from peer ID (BEP 20)
 * 
 * Supports three encoding styles:
 * - Azureus-style: -XX1234-xxxxxxxxxxxx
 * - Shadow-style: Xyyy--xxxxxxxxxxxxxx
 * - Mainline-style: M1-2-3--xxxxxxxxxxxx
 * Also recognizes many non-standard encodings.
 * 
 * @param id 20-byte peer ID
 * @return Human-readable client name with version, or "Unknown [...]"
 */
inline std::string identify_client(const PeerID& id) {
    // Check if all zeros
    bool all_zero = true;
    for (uint8_t b : id) { if (b != 0) { all_zero = false; break; } }
    if (all_zero) return "Unknown";
    
    // Check non-standard encodings first
    const char* generic = detail::lookup_generic_client(id.data());
    if (generic) return generic;
    
    // Check Bits on Wheels special case
    if (id[0] == '-' && id[1] == 'B' && id[2] == 'O' && id[3] == 'W' && id[7] == '-') {
        return "Bits on Wheels " + std::string(reinterpret_cast<const char*>(id.data()) + 4, 3);
    }
    
    // Azureus-style: -XX1234-
    if (id[0] == '-' && id[7] == '-' && 
        (id[1] >= 'A' || id[1] >= 'a') &&
        id[3] >= '0' && id[4] >= '0' && id[5] >= '0' && id[6] >= '0') {
        
        char code[3] = {static_cast<char>(id[1]), static_cast<char>(id[2]), '\0'};
        
        int v1 = detail::decode_version_digit(id[3]);
        int v2 = detail::decode_version_digit(id[4]);
        int v3 = detail::decode_version_digit(id[5]);
        int v4 = detail::decode_version_digit(id[6]);
        
        const char* name = detail::lookup_az_client(code);
        std::string client_name = name ? name : std::string("Unknown (") + code + ")";
        
        std::string version = std::to_string(v1) + "." + std::to_string(v2) + "." + std::to_string(v3);
        if (v4 != 0) {
            version += "." + std::to_string(v4);
        }
        
        return client_name + " " + version;
    }
    
    // Shadow-style: first char is client, next 3 are version
    if ((id[0] >= 'A' && id[0] <= 'Z') || (id[0] >= 'a' && id[0] <= 'z')) {
        // Check for shadow format: X + 3 version bytes + "--"
        if (id[4] == '-' && id[5] == '-') {
            if (id[1] >= '0' && id[2] >= '0' && id[3] >= '0') {
                char c = static_cast<char>(id[0]);
                const char* name = nullptr;
                switch (c) {
                    case 'A': name = "ABC"; break;
                    case 'M': name = "Mainline"; break;
                    case 'O': name = "Osprey Permaseed"; break;
                    case 'Q': name = "BTQueue"; break;
                    case 'R': name = "Tribler"; break;
                    case 'S': name = "Shadow"; break;
                    case 'T': name = "BitTornado"; break;
                    case 'U': name = "UPnP"; break;
                    default: break;
                }
                if (name) {
                    int v1 = detail::decode_version_digit(id[1]);
                    int v2 = detail::decode_version_digit(id[2]);
                    int v3 = detail::decode_version_digit(id[3]);
                    return std::string(name) + " " + std::to_string(v1) + "." + 
                           std::to_string(v2) + "." + std::to_string(v3);
                }
            }
        }
        
        // Mainline-style: M1-2-3--
        char ids[21];
        std::memcpy(ids, id.data(), 20);
        ids[20] = '\0';
        char name_ch = '\0';
        int v1 = 0, v2 = 0, v3 = 0;
        if (std::sscanf(ids, "%c%3d-%3d-%3d--", &name_ch, &v1, &v2, &v3) == 4 &&
            name_ch >= 32 && name_ch < 127) {
            const char* name = nullptr;
            switch (name_ch) {
                case 'M': name = "Mainline"; break;
                default: break;
            }
            if (name) {
                return std::string(name) + " " + std::to_string(v1) + "." + 
                       std::to_string(v2) + "." + std::to_string(v3);
            }
        }
    }
    
    // All zeros in first 12 bytes - special cases
    bool first_12_zero = true;
    for (int i = 0; i < 12; ++i) { if (id[i] != 0) { first_12_zero = false; break; } }
    if (first_12_zero) {
        if (id[12] == 0x97) return "Experimental 3.2.1b2";
        if (id[12] == 0x00) return "Experimental 3.1";
        return "Generic";
    }
    
    // Unknown - show printable representation
    std::string unknown("Unknown [");
    for (uint8_t c : id) {
        unknown += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
    }
    unknown += "]";
    return unknown;
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
