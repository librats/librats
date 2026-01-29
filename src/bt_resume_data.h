#pragma once

/**
 * @file bt_resume_data.h
 * @brief BitTorrent torrent resume data for fast resumption
 * 
 * Resume data allows a torrent to quickly resume downloading from where
 * it left off, without re-checking all downloaded data. It stores:
 * - Which pieces have been verified and are complete
 * - Partially downloaded pieces and which blocks are complete
 * - Download statistics
 * - Configuration settings
 * 
 * This is similar to libtorrent's fast-resume feature.
 */

#include "bt_types.h"
#include "bt_bitfield.h"
#include "bt_torrent_info.h"
#include "bencode.h"

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <optional>

namespace librats {

//=============================================================================
// Resume Data Structure
//=============================================================================

/**
 * @brief Stores the state of a partially downloaded piece
 * 
 * For each piece that is partially downloaded, we track which 16KB blocks
 * have been written to disk. This allows resuming without losing progress
 * on pieces that were in-flight when the client stopped.
 */
struct UnfinishedPiece {
    uint32_t piece_index;       ///< Index of the piece
    Bitfield blocks_have;       ///< Which blocks are written to disk
    
    UnfinishedPiece() : piece_index(0) {}
    UnfinishedPiece(uint32_t idx, const Bitfield& blocks) 
        : piece_index(idx), blocks_have(blocks) {}
};

/**
 * @brief Resume data for a torrent
 * 
 * This structure contains all the information needed to resume a torrent
 * download without re-checking existing data.
 */
struct TorrentResumeData {
    //=========================================================================
    // Identification
    //=========================================================================
    
    /// Info hash of the torrent (for verification)
    BtInfoHash info_hash;
    
    /// Torrent name (for display)
    std::string name;
    
    //=========================================================================
    // Paths
    //=========================================================================
    
    /// Directory where files are saved
    std::string save_path;
    
    //=========================================================================
    // Progress - Complete Pieces
    //=========================================================================
    
    /// Bitfield indicating which pieces we have verified and complete
    Bitfield have_pieces;
    
    //=========================================================================
    // Progress - Partial Pieces
    //=========================================================================
    
    /// Map of piece index to bitfield of blocks we have for incomplete pieces
    /// Key: piece_index, Value: bitfield of blocks that are written to disk
    std::map<uint32_t, Bitfield> unfinished_pieces;
    
    //=========================================================================
    // Statistics
    //=========================================================================
    
    /// Total bytes uploaded (all-time)
    uint64_t total_uploaded = 0;
    
    /// Total bytes downloaded (all-time)  
    uint64_t total_downloaded = 0;
    
    /// Time spent actively downloading (seconds)
    int64_t active_time = 0;
    
    /// Time spent seeding (seconds)
    int64_t seeding_time = 0;
    
    /// Timestamp when torrent was added (Unix time)
    int64_t added_time = 0;
    
    /// Timestamp when download completed (Unix time, 0 if not complete)
    int64_t completed_time = 0;
    
    //=========================================================================
    // Configuration
    //=========================================================================
    
    /// Download pieces in order (for streaming)
    bool sequential_download = false;
    
    /// Maximum connections for this torrent
    int max_connections = -1;
    
    /// Maximum upload slots for this torrent  
    int max_uploads = -1;
    
    /// Download rate limit (bytes/sec, -1 = unlimited)
    int64_t download_limit = -1;
    
    /// Upload rate limit (bytes/sec, -1 = unlimited)
    int64_t upload_limit = -1;
    
    //=========================================================================
    // Optional: Torrent metadata (for magnet links that completed metadata)
    //=========================================================================
    
    /// Raw info dictionary (optional, for torrents added via magnet)
    std::vector<uint8_t> info_dict;
    
    //=========================================================================
    // Optional: Cached peer information
    //=========================================================================
    
    /// List of peers to try connecting to (ip:port pairs)
    std::vector<std::pair<std::string, uint16_t>> peers;
    
    //=========================================================================
    // Validation
    //=========================================================================
    
    /**
     * @brief Check if resume data is valid for use
     * @return true if all required fields are set correctly
     */
    bool is_valid() const {
        // Must have info_hash
        bool has_hash = false;
        for (uint8_t b : info_hash) {
            if (b != 0) { has_hash = true; break; }
        }
        return has_hash;
    }
    
    /**
     * @brief Check if resume data matches a torrent info
     * @param info TorrentInfo to check against
     * @return true if the resume data is compatible
     */
    bool matches(const TorrentInfo& info) const {
        return info_hash == info.info_hash();
    }
};

//=============================================================================
// Resume Data Serialization (Bencoding)
//=============================================================================

/**
 * @brief Write resume data to a bencoded format
 * 
 * The bencoded format is compatible with libtorrent's resume file format:
 * - "file-format": "librats resume file"
 * - "file-version": 1
 * - "info-hash": 20-byte SHA1 hash
 * - "save_path": string
 * - "pieces": string (one byte per piece: 0=don't have, 1=have)
 * - "unfinished": list of dicts with "piece" and "bitmask"
 * - "total_uploaded": integer
 * - "total_downloaded": integer
 * - etc.
 * 
 * @param data Resume data to serialize
 * @return Bencoded data as byte vector
 */
std::vector<uint8_t> write_resume_data(const TorrentResumeData& data);

/**
 * @brief Write resume data to a file
 * 
 * @param data Resume data to save
 * @param path Path to save file
 * @return true on success
 */
bool write_resume_data_file(const TorrentResumeData& data, const std::string& path);

/**
 * @brief Read resume data from bencoded format
 * 
 * @param buffer Bencoded data
 * @param error_out Optional error message on failure
 * @return Resume data if successful, nullopt on error
 */
std::optional<TorrentResumeData> read_resume_data(
    const std::vector<uint8_t>& buffer,
    std::string* error_out = nullptr);

/**
 * @brief Read resume data from a file
 * 
 * @param path Path to resume file
 * @param error_out Optional error message on failure
 * @return Resume data if successful, nullopt on error
 */
std::optional<TorrentResumeData> read_resume_data_file(
    const std::string& path,
    std::string* error_out = nullptr);

//=============================================================================
// Resume Data Helper Functions
//=============================================================================

/**
 * @brief Generate default resume file path for a torrent
 * 
 * Creates a path in the form: {save_path}/{info_hash_hex}.resume
 * 
 * @param save_path Torrent save directory
 * @param info_hash Torrent info hash
 * @return Path to resume file
 */
std::string get_resume_file_path(const std::string& save_path, const BtInfoHash& info_hash);

/**
 * @brief Check if a resume file exists for a torrent
 * 
 * @param save_path Torrent save directory
 * @param info_hash Torrent info hash
 * @return true if resume file exists
 */
bool resume_file_exists(const std::string& save_path, const BtInfoHash& info_hash);

} // namespace librats
