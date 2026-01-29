#pragma once

/**
 * @file bt_create_torrent.h
 * @brief Torrent file creation and generation
 * 
 * Provides functionality to create .torrent files from files or directories.
 * Supports both single-file and multi-file torrents.
 */

#include "bt_types.h"
#include "bt_file_storage.h"
#include "bt_torrent_info.h"
#include "bencode.h"

#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <ctime>

namespace librats {

/**
 * @brief Error information for torrent creation failures
 */
struct TorrentCreateError {
    std::string message;
    
    TorrentCreateError() = default;
    explicit TorrentCreateError(const std::string& msg) : message(msg) {}
};

/**
 * @brief Configuration for torrent creation
 */
struct TorrentCreatorConfig {
    uint32_t piece_size = 0;            ///< Piece size in bytes (0 = auto-detect)
    bool is_private = false;            ///< Private torrent flag
    std::string comment;                ///< Optional comment
    std::string created_by;             ///< Optional creator string
    std::time_t creation_date = 0;      ///< Creation timestamp (0 = current time)
    bool include_hidden_files = false;  ///< Include hidden files when adding directories
    
    TorrentCreatorConfig() : creation_date(std::time(nullptr)) {}
};

/**
 * @brief Progress callback for piece hashing
 * 
 * @param current_piece Current piece being hashed (0-indexed)
 * @param total_pieces Total number of pieces
 */
using PieceHashProgressCallback = std::function<void(uint32_t current_piece, uint32_t total_pieces)>;

/**
 * @brief File filter callback for directory traversal
 * 
 * @param path Full path to the file or directory
 * @return true to include the file/traverse the directory, false to skip
 */
using FileFilterCallback = std::function<bool(const std::string& path)>;

/**
 * @brief Creates torrent files from files or directories
 * 
 * This class provides a simple API to create .torrent files:
 * 
 * 1. Create TorrentCreator with base path
 * 2. Add files or let it scan directories
 * 3. Set properties (trackers, comment, etc.)
 * 4. Call set_piece_hashes() to compute hashes
 * 5. Call generate() to get the bencoded torrent data
 * 
 * Example usage:
 * @code
 * TorrentCreator creator("./my_folder");
 * creator.add_tracker("http://tracker.example.com/announce");
 * creator.set_comment("My torrent");
 * 
 * // Hash pieces (this reads all file content)
 * creator.set_piece_hashes([](uint32_t current, uint32_t total) {
 *     std::cout << "Hashing piece " << current << "/" << total << std::endl;
 * });
 * 
 * // Generate torrent data
 * auto torrent_data = creator.generate();
 * @endcode
 * 
 * Thread-safety: Not thread-safe during construction/modification.
 * After generate() is called, the resulting data can be used from any thread.
 */
class TorrentCreator {
public:
    /**
     * @brief Create a torrent creator for a file or directory
     * 
     * If path points to a directory, all files in it will be included.
     * If path points to a file, a single-file torrent will be created.
     * 
     * @param path Path to file or directory
     * @param config Optional configuration
     */
    explicit TorrentCreator(const std::string& path, 
                            const TorrentCreatorConfig& config = TorrentCreatorConfig());
    
    /**
     * @brief Create a torrent creator with custom file storage
     * 
     * Use this when you want manual control over which files are included.
     * 
     * @param storage Pre-configured file storage
     * @param base_path Base path where files are located
     * @param config Optional configuration
     */
    TorrentCreator(FileStorage&& storage, 
                   const std::string& base_path,
                   const TorrentCreatorConfig& config = TorrentCreatorConfig());
    
    ~TorrentCreator() = default;
    
    // Non-copyable, moveable
    TorrentCreator(const TorrentCreator&) = delete;
    TorrentCreator& operator=(const TorrentCreator&) = delete;
    TorrentCreator(TorrentCreator&&) noexcept = default;
    TorrentCreator& operator=(TorrentCreator&&) noexcept = default;
    
    //=========================================================================
    // File Management
    //=========================================================================
    
    /**
     * @brief Scan path and add all files
     * 
     * If the creator was constructed with a directory path, this is called
     * automatically. Call this to re-scan or to scan with a custom filter.
     * 
     * @param filter Optional filter callback
     * @return Number of files added
     */
    size_t scan_files(FileFilterCallback filter = nullptr);
    
    /**
     * @brief Add a single file manually
     * 
     * @param relative_path Path relative to the base path
     * @param size File size in bytes
     * @return true if added successfully
     */
    bool add_file(const std::string& relative_path, int64_t size);
    
    /**
     * @brief Get the file storage
     */
    const FileStorage& files() const { return files_; }
    
    /**
     * @brief Get number of files
     */
    size_t num_files() const { return files_.num_files(); }
    
    /**
     * @brief Get total size of all files
     */
    int64_t total_size() const { return files_.total_size(); }
    
    //=========================================================================
    // Torrent Properties
    //=========================================================================
    
    /**
     * @brief Set the torrent name
     * 
     * By default, the name is derived from the path.
     * 
     * @param name Torrent name
     */
    void set_name(const std::string& name);
    
    /**
     * @brief Get the torrent name
     */
    const std::string& name() const { return files_.name(); }
    
    /**
     * @brief Set the comment
     */
    void set_comment(const std::string& comment) { comment_ = comment; }
    
    /**
     * @brief Get the comment
     */
    const std::string& comment() const { return comment_; }
    
    /**
     * @brief Set the creator string
     */
    void set_creator(const std::string& creator) { created_by_ = creator; }
    
    /**
     * @brief Get the creator string
     */
    const std::string& creator() const { return created_by_; }
    
    /**
     * @brief Set the creation date
     * @param timestamp Unix timestamp (0 to omit from torrent)
     */
    void set_creation_date(std::time_t timestamp) { creation_date_ = timestamp; }
    
    /**
     * @brief Get the creation date
     */
    std::time_t creation_date() const { return creation_date_; }
    
    /**
     * @brief Set private flag
     */
    void set_private(bool is_private) { is_private_ = is_private; }
    
    /**
     * @brief Check if private flag is set
     */
    bool is_private() const { return is_private_; }
    
    /**
     * @brief Set piece size manually
     * 
     * If not set (or 0), an appropriate piece size will be chosen automatically
     * based on the total file size.
     * 
     * @param size Piece size in bytes (must be power of 2, >= 16 KiB)
     */
    void set_piece_size(uint32_t size);
    
    /**
     * @brief Get piece size
     */
    uint32_t piece_size() const { return piece_size_; }
    
    /**
     * @brief Get number of pieces
     */
    uint32_t num_pieces() const { return files_.num_pieces(); }
    
    //=========================================================================
    // Trackers
    //=========================================================================
    
    /**
     * @brief Add a tracker URL
     * 
     * @param url Tracker URL (http:// or udp://)
     * @param tier Tracker tier (0 = primary, higher = fallback)
     */
    void add_tracker(const std::string& url, int tier = 0);
    
    /**
     * @brief Get all tracker URLs
     */
    std::vector<std::string> trackers() const;
    
    /**
     * @brief Clear all trackers
     */
    void clear_trackers() { trackers_.clear(); }
    
    //=========================================================================
    // Web Seeds
    //=========================================================================
    
    /**
     * @brief Add a web seed URL
     */
    void add_url_seed(const std::string& url);
    
    /**
     * @brief Add an HTTP seed URL
     */
    void add_http_seed(const std::string& url);
    
    /**
     * @brief Get URL seeds
     */
    const std::vector<std::string>& url_seeds() const { return url_seeds_; }
    
    /**
     * @brief Get HTTP seeds
     */
    const std::vector<std::string>& http_seeds() const { return http_seeds_; }
    
    //=========================================================================
    // DHT Nodes
    //=========================================================================
    
    /**
     * @brief Add a DHT bootstrap node
     */
    void add_dht_node(const std::string& host, uint16_t port);
    
    //=========================================================================
    // Piece Hashing
    //=========================================================================
    
    /**
     * @brief Compute piece hashes by reading all files
     * 
     * This is a potentially long operation as it reads all file content.
     * Call this before generate().
     * 
     * @param progress_callback Optional callback for progress updates
     * @param error Optional output for error information
     * @return true if all pieces were hashed successfully
     */
    bool set_piece_hashes(PieceHashProgressCallback progress_callback = nullptr,
                          TorrentCreateError* error = nullptr);
    
    /**
     * @brief Check if piece hashes have been computed
     */
    bool has_piece_hashes() const { return !piece_hashes_.empty(); }
    
    //=========================================================================
    // Generation
    //=========================================================================
    
    /**
     * @brief Generate the bencoded torrent data
     * 
     * Requires set_piece_hashes() to have been called first.
     * 
     * @param error Optional output for error information
     * @return Bencoded torrent data, or empty vector on failure
     */
    std::vector<uint8_t> generate(TorrentCreateError* error = nullptr) const;
    
    /**
     * @brief Generate and save to a file
     * 
     * @param output_path Path to save the .torrent file
     * @param error Optional output for error information
     * @return true if saved successfully
     */
    bool save_to_file(const std::string& output_path, 
                      TorrentCreateError* error = nullptr) const;
    
    /**
     * @brief Generate and return a TorrentInfo object
     * 
     * @param error Optional output for error information
     * @return TorrentInfo object, or empty if generation failed
     */
    std::optional<TorrentInfo> generate_torrent_info(TorrentCreateError* error = nullptr) const;
    
    /**
     * @brief Get the info hash without generating full torrent
     * 
     * Requires set_piece_hashes() to have been called.
     * 
     * @return Info hash, or zero hash if not ready
     */
    BtInfoHash info_hash() const;
    
    /**
     * @brief Get the info hash as hex string
     */
    std::string info_hash_hex() const;
    
private:
    std::string base_path_;
    FileStorage files_;
    
    // Torrent metadata
    std::string comment_;
    std::string created_by_;
    std::time_t creation_date_;
    bool is_private_;
    uint32_t piece_size_;
    
    // Trackers (url, tier)
    std::vector<std::pair<std::string, int>> trackers_;
    
    // Seeds
    std::vector<std::string> url_seeds_;
    std::vector<std::string> http_seeds_;
    
    // DHT nodes (host, port)
    std::vector<std::pair<std::string, uint16_t>> dht_nodes_;
    
    // Piece hashes (concatenated 20-byte SHA-1 hashes)
    std::vector<uint8_t> piece_hashes_;
    
    // Cached info hash
    mutable BtInfoHash cached_info_hash_;
    mutable bool info_hash_valid_;
    
    /**
     * @brief Auto-detect optimal piece size
     */
    uint32_t auto_detect_piece_size() const;
    
    /**
     * @brief Scan directory recursively
     */
    void scan_directory(const std::string& dir_path, 
                        const std::string& relative_prefix,
                        FileFilterCallback filter);
    
    /**
     * @brief Build the info dictionary
     */
    BencodeValue build_info_dict() const;
    
    /**
     * @brief Build the complete torrent dictionary
     */
    BencodeValue build_torrent_dict() const;
};

//=============================================================================
// Convenience Functions
//=============================================================================

/**
 * @brief Add files from a path to FileStorage
 * 
 * Recursively adds all files from a directory, or adds a single file.
 * 
 * @param storage FileStorage to add files to
 * @param path Path to file or directory
 * @param filter Optional filter callback
 * @return Number of files added
 */
size_t add_files(FileStorage& storage, const std::string& path,
                 FileFilterCallback filter = nullptr);

/**
 * @brief Create a torrent from a file or directory
 * 
 * Convenience function that creates a torrent in one call.
 * 
 * @param path Path to file or directory
 * @param output_path Path to save the .torrent file
 * @param trackers Optional list of tracker URLs
 * @param comment Optional comment
 * @param progress_callback Optional progress callback
 * @param error Optional output for error information
 * @return true if torrent was created successfully
 */
bool create_torrent(const std::string& path,
                    const std::string& output_path,
                    const std::vector<std::string>& trackers = {},
                    const std::string& comment = "",
                    PieceHashProgressCallback progress_callback = nullptr,
                    TorrentCreateError* error = nullptr);

/**
 * @brief Create a torrent and return the data
 * 
 * @param path Path to file or directory
 * @param trackers Optional list of tracker URLs
 * @param comment Optional comment  
 * @param progress_callback Optional progress callback
 * @param error Optional output for error information
 * @return Bencoded torrent data, or empty vector on failure
 */
std::vector<uint8_t> create_torrent_data(const std::string& path,
                                          const std::vector<std::string>& trackers = {},
                                          const std::string& comment = "",
                                          PieceHashProgressCallback progress_callback = nullptr,
                                          TorrentCreateError* error = nullptr);

} // namespace librats
