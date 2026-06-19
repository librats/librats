#pragma once

/**
 * @file bt_file_storage.h
 * @brief File storage layout for BitTorrent torrents
 * 
 * Handles mapping between pieces/blocks and files in a torrent.
 * Supports both single-file and multi-file torrents.
 */

#include <string>
#include <vector>
#include <cstdint>

namespace librats {

/**
 * @brief Information about a single file in the torrent
 */
struct FileEntry {
    std::string path;           ///< Relative path of the file
    int64_t size;               ///< Size in bytes
    int64_t offset;             ///< Offset from start of torrent data
    bool pad_file;              ///< True if this is a padding file (not real data)
    bool executable;            ///< Executable attribute (Unix)
    bool hidden;                ///< Hidden attribute (Windows)
    
    FileEntry() 
        : size(0), offset(0), pad_file(false), executable(false), hidden(false) {}
    
    FileEntry(const std::string& p, int64_t s, int64_t off = 0)
        : path(p), size(s), offset(off), pad_file(false), executable(false), hidden(false) {}
};

/**
 * @brief A slice of a file that corresponds to part of a piece
 */
struct FileSlice {
    size_t file_index;          ///< Index of the file in FileStorage
    int64_t offset;             ///< Offset within the file
    int64_t size;               ///< Number of bytes in this slice
    
    FileSlice() : file_index(0), offset(0), size(0) {}
    FileSlice(size_t idx, int64_t off, int64_t sz) 
        : file_index(idx), offset(off), size(sz) {}
};

/**
 * @brief Result of mapping a file position to piece/block
 */
struct PiecePosition {
    uint32_t piece;             ///< Piece index
    uint32_t offset;            ///< Offset within piece
    uint32_t length;            ///< Length of data
    
    PiecePosition() : piece(0), offset(0), length(0) {}
    PiecePosition(uint32_t p, uint32_t off, uint32_t len)
        : piece(p), offset(off), length(len) {}
};

/**
 * @brief Manages file layout and piece-to-file mapping for a torrent
 * 
 * This class stores information about all files in a torrent and provides
 * efficient mapping between:
 * - Piece/block positions and file positions
 * - File positions and piece positions
 * 
 * Thread-safe for read operations after construction.
 */
class FileStorage {
public:
    /**
     * @brief Default constructor - creates empty storage
     */
    FileStorage();
    
    /**
     * @brief Constructor with piece length
     * @param piece_length Length of each piece in bytes
     */
    explicit FileStorage(uint32_t piece_length);
    
    /**
     * @brief Copy constructor
     */
    FileStorage(const FileStorage& other) = default;
    
    /**
     * @brief Move constructor
     */
    FileStorage(FileStorage&& other) noexcept = default;
    
    /**
     * @brief Copy assignment
     */
    FileStorage& operator=(const FileStorage& other) = default;
    
    /**
     * @brief Move assignment
     */
    FileStorage& operator=(FileStorage&& other) noexcept = default;
    
    //=========================================================================
    // File Management
    //=========================================================================
    
    /**
     * @brief Add a file to the storage
     * 
     * Files are added in order and their offsets are computed automatically.
     * 
     * @param path Relative path of the file
     * @param size Size of the file in bytes
     * @param pad_file True if this is a padding file
     * @param executable True if file has executable attribute
     * @param hidden True if file has hidden attribute
     */
    void add_file(const std::string& path, int64_t size, 
                  bool pad_file = false, bool executable = false, bool hidden = false);
    
    /**
     * @brief Add a FileEntry directly
     * @param entry File entry to add (offset will be computed)
     */
    void add_file(const FileEntry& entry);
    
    /**
     * @brief Reserve space for files (optimization)
     * @param num_files Expected number of files
     */
    void reserve(size_t num_files);
    
    /**
     * @brief Set the piece length
     * @param length Piece length in bytes
     */
    void set_piece_length(uint32_t length);
    
    /**
     * @brief Finalize the storage after all files are added
     * 
     * Computes the total number of pieces based on total size and piece length.
     * Must be called before using mapping functions.
     */
    void finalize();
    
    //=========================================================================
    // Accessors
    //=========================================================================
    
    /**
     * @brief Get number of files
     */
    size_t num_files() const { return files_.size(); }
    
    /**
     * @brief Get total size of all files
     */
    int64_t total_size() const { return total_size_; }
    
    /**
     * @brief Get piece length
     */
    uint32_t piece_length() const { return piece_length_; }
    
    /**
     * @brief Get total number of pieces
     */
    uint32_t num_pieces() const { return num_pieces_; }
    
    /**
     * @brief Get size of a specific piece
     * 
     * All pieces have the same size except possibly the last one.
     * 
     * @param piece_index Index of the piece
     * @return Size of the piece in bytes
     */
    uint32_t piece_size(uint32_t piece_index) const;
    
    /**
     * @brief Get file entry by index
     * @param index File index
     * @return Reference to file entry
     */
    const FileEntry& file_at(size_t index) const { return files_[index]; }
    
    /**
     * @brief Get all file entries
     */
    const std::vector<FileEntry>& files() const { return files_; }
    
    /**
     * @brief Check if storage is empty
     */
    bool empty() const { return files_.empty(); }
    
    /**
     * @brief Check if storage is finalized
     */
    bool is_finalized() const { return finalized_; }
    
    //=========================================================================
    // Piece-to-File Mapping
    //=========================================================================
    
    /**
     * @brief Map a piece/block to file slices
     * 
     * Given a piece index, offset within piece, and size, returns the list
     * of file slices that need to be read/written.
     * 
     * @param piece Piece index
     * @param offset Offset within the piece
     * @param size Number of bytes
     * @return Vector of file slices
     */
    std::vector<FileSlice> map_block(uint32_t piece, uint32_t offset, uint32_t size) const;
    
    /**
     * @brief Find which file contains a given byte offset
     * @param torrent_offset Absolute offset from start of torrent data
     * @return File index, or num_files() if offset is out of range
     */
    size_t file_at_offset(int64_t torrent_offset) const;
    
    /**
     * @brief Get the file index at a given piece
     * @param piece Piece index
     * @return File index of the first file that starts in or spans this piece
     */
    size_t file_at_piece(uint32_t piece) const;
    
    //=========================================================================
    // File-to-Piece Mapping
    //=========================================================================
    
    /**
     * @brief Map a file position to piece position
     * 
     * @param file_index Index of the file
     * @param file_offset Offset within the file
     * @param size Number of bytes
     * @return Piece position
     */
    PiecePosition map_file(size_t file_index, int64_t file_offset, uint32_t size) const;
    
    /**
     * @brief Get the first piece that contains data from a file
     * @param file_index File index
     * @return First piece index
     */
    uint32_t file_first_piece(size_t file_index) const;
    
    /**
     * @brief Get the last piece that contains data from a file
     * @param file_index File index
     * @return Last piece index
     */
    uint32_t file_last_piece(size_t file_index) const;
    
    /**
     * @brief Get number of pieces a file spans
     * @param file_index File index
     * @return Number of pieces
     */
    uint32_t file_num_pieces(size_t file_index) const;
    
    //=========================================================================
    // Torrent Name
    //=========================================================================
    
    /**
     * @brief Set the torrent name (root directory for multi-file)
     */
    void set_name(const std::string& name) { name_ = name; }
    
    /**
     * @brief Get the torrent name
     */
    const std::string& name() const { return name_; }
    
private:
    std::vector<FileEntry> files_;
    std::string name_;
    int64_t total_size_;
    uint32_t piece_length_;
    uint32_t num_pieces_;
    bool finalized_;
    
    /**
     * @brief Binary search to find file at offset (helper)
     */
    size_t find_file_at_offset(int64_t offset) const;
};

} // namespace librats
