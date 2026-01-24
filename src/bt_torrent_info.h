#pragma once

/**
 * @file bt_torrent_info.h
 * @brief Torrent metadata parsing and management
 * 
 * Handles parsing of .torrent files and magnet URIs,
 * computing info hashes, and managing torrent metadata.
 */

#include "bt_types.h"
#include "bt_file_storage.h"
#include "bencode.h"

#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace librats {

/**
 * @brief Tracker tier (for multi-tracker torrents)
 */
using TrackerTier = std::vector<std::string>;

/**
 * @brief Error information for parsing failures
 */
struct TorrentParseError {
    std::string message;
    
    TorrentParseError() = default;
    explicit TorrentParseError(const std::string& msg) : message(msg) {}
};

/**
 * @brief Complete torrent metadata
 * 
 * This class holds all metadata about a torrent, parsed from a .torrent file
 * or received via the ut_metadata extension (BEP 9).
 * 
 * Key data includes:
 * - Info hash (SHA-1 of the bencoded info dictionary)
 * - File structure (single file or directory with multiple files)
 * - Piece hashes (SHA-1 hashes for each piece)
 * - Tracker URLs
 * - Optional metadata (comment, creation date, created by, etc.)
 * 
 * Thread-safe for read operations after construction.
 */
class TorrentInfo {
public:
    /**
     * @brief Default constructor - creates empty/invalid torrent info
     */
    TorrentInfo();
    
    /**
     * @brief Copy constructor
     */
    TorrentInfo(const TorrentInfo& other);
    
    /**
     * @brief Move constructor
     */
    TorrentInfo(TorrentInfo&& other) noexcept;
    
    /**
     * @brief Copy assignment
     */
    TorrentInfo& operator=(const TorrentInfo& other);
    
    /**
     * @brief Move assignment
     */
    TorrentInfo& operator=(TorrentInfo&& other) noexcept;
    
    /**
     * @brief Destructor
     */
    ~TorrentInfo();
    
    //=========================================================================
    // Static Factory Methods
    //=========================================================================
    
    /**
     * @brief Parse a .torrent file from bytes
     * 
     * @param data Bencoded .torrent file data
     * @param error Optional output for error information
     * @return Parsed TorrentInfo, or empty if parsing failed
     */
    static std::optional<TorrentInfo> from_bytes(
        const std::vector<uint8_t>& data,
        TorrentParseError* error = nullptr);
    
    /**
     * @brief Parse a .torrent file from a file path
     * 
     * @param path Path to the .torrent file
     * @param error Optional output for error information
     * @return Parsed TorrentInfo, or empty if parsing failed
     */
    static std::optional<TorrentInfo> from_file(
        const std::string& path,
        TorrentParseError* error = nullptr);
    
    /**
     * @brief Create TorrentInfo from a magnet URI
     * 
     * Note: This creates a partial TorrentInfo with only the info hash.
     * Full metadata must be obtained via DHT or ut_metadata extension.
     * 
     * @param magnet_uri Magnet URI string
     * @param error Optional output for error information
     * @return Parsed TorrentInfo, or empty if parsing failed
     */
    static std::optional<TorrentInfo> from_magnet(
        const std::string& magnet_uri,
        TorrentParseError* error = nullptr);
    
    /**
     * @brief Create TorrentInfo from raw info dictionary bytes
     * 
     * Used when receiving metadata via ut_metadata extension.
     * 
     * @param info_dict_bytes Raw bencoded info dictionary
     * @param expected_hash Expected info hash (for verification)
     * @param error Optional output for error information
     * @return Parsed TorrentInfo, or empty if parsing failed
     */
    static std::optional<TorrentInfo> from_info_dict(
        const std::vector<uint8_t>& info_dict_bytes,
        const BtInfoHash& expected_hash,
        TorrentParseError* error = nullptr);
    
    //=========================================================================
    // Core Properties
    //=========================================================================
    
    /**
     * @brief Check if this torrent info is valid
     * 
     * A TorrentInfo is valid if it has at least an info hash.
     * It may not have full metadata (e.g., from magnet link).
     */
    bool is_valid() const { return !is_zero_hash(info_hash_); }
    
    /**
     * @brief Check if full metadata is available
     * 
     * Returns false for magnet links until metadata is received.
     */
    bool has_metadata() const { return has_metadata_; }
    
    /**
     * @brief Get the 20-byte info hash
     */
    const BtInfoHash& info_hash() const { return info_hash_; }
    
    /**
     * @brief Get info hash as hex string
     */
    std::string info_hash_hex() const { return info_hash_to_hex(info_hash_); }
    
    /**
     * @brief Get the torrent name
     */
    const std::string& name() const { return name_; }
    
    /**
     * @brief Get the comment (if present)
     */
    const std::string& comment() const { return comment_; }
    
    /**
     * @brief Get the "created by" string (if present)
     */
    const std::string& created_by() const { return created_by_; }
    
    /**
     * @brief Get creation date as Unix timestamp (0 if not present)
     */
    int64_t creation_date() const { return creation_date_; }
    
    /**
     * @brief Check if this is a private torrent
     */
    bool is_private() const { return is_private_; }
    
    //=========================================================================
    // File and Piece Information
    //=========================================================================
    
    /**
     * @brief Get the file storage (file layout)
     */
    const FileStorage& files() const { return files_; }
    
    /**
     * @brief Get total size of all files in bytes
     */
    int64_t total_size() const { return files_.total_size(); }
    
    /**
     * @brief Get number of files
     */
    size_t num_files() const { return files_.num_files(); }
    
    /**
     * @brief Get piece length
     */
    uint32_t piece_length() const { return files_.piece_length(); }
    
    /**
     * @brief Get number of pieces
     */
    uint32_t num_pieces() const { return files_.num_pieces(); }
    
    /**
     * @brief Get size of a specific piece
     */
    uint32_t piece_size(uint32_t index) const { return files_.piece_size(index); }
    
    /**
     * @brief Get the SHA-1 hash for a piece
     * @param index Piece index
     * @return 20-byte hash, or empty array if index invalid
     */
    std::array<uint8_t, 20> piece_hash(uint32_t index) const;
    
    /**
     * @brief Get all piece hashes (concatenated 20-byte hashes)
     */
    const std::vector<uint8_t>& piece_hashes() const { return piece_hashes_; }
    
    //=========================================================================
    // Trackers
    //=========================================================================
    
    /**
     * @brief Get the primary tracker URL (announce)
     */
    const std::string& announce() const { return announce_; }
    
    /**
     * @brief Get all tracker tiers (announce-list)
     */
    const std::vector<TrackerTier>& announce_list() const { return announce_list_; }
    
    /**
     * @brief Get a flat list of all tracker URLs
     */
    std::vector<std::string> all_trackers() const;
    
    //=========================================================================
    // Web Seeds
    //=========================================================================
    
    /**
     * @brief Get web seed URLs (url-list)
     */
    const std::vector<std::string>& web_seeds() const { return web_seeds_; }
    
    //=========================================================================
    // DHT Nodes
    //=========================================================================
    
    /**
     * @brief DHT node entry (host, port)
     */
    struct DhtNode {
        std::string host;
        uint16_t port;
    };
    
    /**
     * @brief Get DHT nodes embedded in torrent
     */
    const std::vector<DhtNode>& dht_nodes() const { return dht_nodes_; }
    
    //=========================================================================
    // Raw Data Access
    //=========================================================================
    
    /**
     * @brief Get the raw info dictionary bytes
     * 
     * This is the exact bytes that hash to the info_hash.
     * Used for ut_metadata exchange.
     */
    const std::vector<uint8_t>& info_dict_bytes() const { return info_dict_bytes_; }
    
    /**
     * @brief Get size of info dictionary in bytes
     */
    size_t metadata_size() const { return info_dict_bytes_.size(); }
    
    //=========================================================================
    // Magnet URI
    //=========================================================================
    
    /**
     * @brief Generate a magnet URI for this torrent
     * @param include_trackers Include tracker URLs in magnet
     * @return Magnet URI string
     */
    std::string to_magnet_uri(bool include_trackers = true) const;
    
    //=========================================================================
    // Metadata Update (for magnet links)
    //=========================================================================
    
    /**
     * @brief Set metadata received from ut_metadata
     * 
     * Used to complete a TorrentInfo that was created from a magnet link.
     * 
     * @param info_dict_bytes Raw info dictionary
     * @return true if metadata is valid and matches info hash
     */
    bool set_metadata(const std::vector<uint8_t>& info_dict_bytes);
    
private:
    // Core data
    BtInfoHash info_hash_;
    std::string name_;
    std::string comment_;
    std::string created_by_;
    int64_t creation_date_;
    bool is_private_;
    bool has_metadata_;
    
    // File layout
    FileStorage files_;
    
    // Piece hashes (concatenated 20-byte SHA-1 hashes)
    std::vector<uint8_t> piece_hashes_;
    
    // Trackers
    std::string announce_;
    std::vector<TrackerTier> announce_list_;
    
    // Web seeds
    std::vector<std::string> web_seeds_;
    
    // DHT nodes
    std::vector<DhtNode> dht_nodes_;
    
    // Raw info dict for ut_metadata
    std::vector<uint8_t> info_dict_bytes_;
    
    //=========================================================================
    // Private Helpers
    //=========================================================================
    
    /**
     * @brief Parse the info dictionary
     */
    bool parse_info_dict(const BencodeValue& info_dict, TorrentParseError* error);
    
    /**
     * @brief Calculate info hash from raw bytes
     */
    static BtInfoHash calculate_info_hash(const std::vector<uint8_t>& info_bytes);
    
    /**
     * @brief URL encode a string for magnet URI
     */
    static std::string url_encode(const std::string& str);
};

//=============================================================================
// Magnet URI Parsing Helpers
//=============================================================================

/**
 * @brief Parse a magnet URI and extract components
 */
struct MagnetUri {
    BtInfoHash info_hash;
    std::string display_name;
    std::vector<std::string> trackers;
    std::vector<std::string> web_seeds;
    
    /**
     * @brief Parse a magnet URI string
     * @param uri The magnet URI
     * @return Parsed components, or nullopt on failure
     */
    static std::optional<MagnetUri> parse(const std::string& uri);
    
    /**
     * @brief Check if info hash is valid
     */
    bool is_valid() const { return !is_zero_hash(info_hash); }
};

} // namespace librats
