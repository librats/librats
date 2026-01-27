#include "bt_file_storage.h"
#include <algorithm>
#include <stdexcept>

namespace librats {

//=============================================================================
// Constructors
//=============================================================================

FileStorage::FileStorage()
    : total_size_(0)
    , piece_length_(0)
    , num_pieces_(0)
    , finalized_(false) {
}

FileStorage::FileStorage(uint32_t piece_length)
    : total_size_(0)
    , piece_length_(piece_length)
    , num_pieces_(0)
    , finalized_(false) {
}

//=============================================================================
// File Management
//=============================================================================

void FileStorage::add_file(const std::string& path, int64_t size,
                           bool pad_file, bool executable, bool hidden) {
    if (finalized_) {
        return; // Cannot add files after finalization
    }
    
    FileEntry entry;
    entry.path = path;
    entry.size = size;
    entry.offset = total_size_;
    entry.pad_file = pad_file;
    entry.executable = executable;
    entry.hidden = hidden;
    
    files_.push_back(std::move(entry));
    total_size_ += size;
}

void FileStorage::add_file(const FileEntry& entry) {
    if (finalized_) {
        return;
    }
    
    FileEntry new_entry = entry;
    new_entry.offset = total_size_;
    
    files_.push_back(std::move(new_entry));
    total_size_ += entry.size;
}

void FileStorage::reserve(size_t num_files) {
    files_.reserve(num_files);
}

void FileStorage::set_piece_length(uint32_t length) {
    piece_length_ = length;
    if (finalized_ && piece_length_ > 0) {
        // Recalculate number of pieces
        num_pieces_ = static_cast<uint32_t>((total_size_ + piece_length_ - 1) / piece_length_);
    }
}

void FileStorage::finalize() {
    if (piece_length_ > 0 && total_size_ > 0) {
        num_pieces_ = static_cast<uint32_t>((total_size_ + piece_length_ - 1) / piece_length_);
    } else {
        num_pieces_ = 0;
    }
    finalized_ = true;
}

//=============================================================================
// Accessors
//=============================================================================

uint32_t FileStorage::piece_size(uint32_t piece_index) const {
    if (piece_index >= num_pieces_) {
        return 0;
    }
    
    // Last piece may be smaller
    if (piece_index == num_pieces_ - 1) {
        int64_t remaining = total_size_ - static_cast<int64_t>(piece_index) * piece_length_;
        return static_cast<uint32_t>(remaining);
    }
    
    return piece_length_;
}

//=============================================================================
// Piece-to-File Mapping
//=============================================================================

std::vector<FileSlice> FileStorage::map_block(uint32_t piece, uint32_t offset, uint32_t size) const {
    std::vector<FileSlice> result;
    
    if (!finalized_ || files_.empty() || piece >= num_pieces_) {
        return result;
    }
    
    // Calculate absolute offset in torrent
    int64_t torrent_offset = static_cast<int64_t>(piece) * piece_length_ + offset;
    
    // Clamp size to not exceed total size
    if (torrent_offset + size > total_size_) {
        size = static_cast<uint32_t>(total_size_ - torrent_offset);
    }
    
    if (size == 0) {
        return result;
    }
    
    // Find starting file
    size_t file_idx = find_file_at_offset(torrent_offset);
    if (file_idx >= files_.size()) {
        return result;
    }
    
    int64_t remaining = size;
    int64_t current_offset = torrent_offset;
    
    while (remaining > 0 && file_idx < files_.size()) {
        const FileEntry& file = files_[file_idx];
        
        // Offset within this file
        int64_t file_offset = current_offset - file.offset;
        
        // How much can we read from this file?
        int64_t bytes_in_file = file.size - file_offset;
        int64_t bytes_to_read = (std::min)(remaining, bytes_in_file);
        
        if (bytes_to_read > 0 && !file.pad_file) {
            result.emplace_back(file_idx, file_offset, bytes_to_read);
        }
        
        current_offset += bytes_to_read;
        remaining -= bytes_to_read;
        ++file_idx;
    }
    
    return result;
}

size_t FileStorage::file_at_offset(int64_t torrent_offset) const {
    if (torrent_offset < 0 || torrent_offset >= total_size_) {
        return files_.size();
    }
    return find_file_at_offset(torrent_offset);
}

size_t FileStorage::file_at_piece(uint32_t piece) const {
    if (piece >= num_pieces_) {
        return files_.size();
    }
    int64_t offset = static_cast<int64_t>(piece) * piece_length_;
    return find_file_at_offset(offset);
}

size_t FileStorage::find_file_at_offset(int64_t offset) const {
    if (files_.empty()) {
        return 0;
    }
    
    // Binary search for file containing this offset
    size_t left = 0;
    size_t right = files_.size();
    
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        const FileEntry& file = files_[mid];
        
        if (offset < file.offset) {
            right = mid;
        } else if (offset >= file.offset + file.size) {
            left = mid + 1;
        } else {
            return mid;
        }
    }
    
    // Clamp to last file if offset is at the very end
    if (left >= files_.size() && !files_.empty()) {
        return files_.size() - 1;
    }
    
    return left;
}

//=============================================================================
// File-to-Piece Mapping
//=============================================================================

PiecePosition FileStorage::map_file(size_t file_index, int64_t file_offset, uint32_t size) const {
    if (file_index >= files_.size() || !finalized_) {
        return PiecePosition();
    }
    
    const FileEntry& file = files_[file_index];
    
    // Clamp file_offset
    if (file_offset < 0) file_offset = 0;
    if (file_offset >= file.size) {
        return PiecePosition();
    }
    
    // Calculate absolute torrent offset
    int64_t torrent_offset = file.offset + file_offset;
    
    // Calculate piece and offset within piece
    uint32_t piece = static_cast<uint32_t>(torrent_offset / piece_length_);
    uint32_t piece_offset = static_cast<uint32_t>(torrent_offset % piece_length_);
    
    // Clamp size to file boundary
    int64_t max_size = file.size - file_offset;
    if (size > max_size) {
        size = static_cast<uint32_t>(max_size);
    }
    
    return PiecePosition(piece, piece_offset, size);
}

uint32_t FileStorage::file_first_piece(size_t file_index) const {
    if (file_index >= files_.size() || piece_length_ == 0) {
        return 0;
    }
    
    const FileEntry& file = files_[file_index];
    return static_cast<uint32_t>(file.offset / piece_length_);
}

uint32_t FileStorage::file_last_piece(size_t file_index) const {
    if (file_index >= files_.size() || piece_length_ == 0) {
        return 0;
    }
    
    const FileEntry& file = files_[file_index];
    if (file.size == 0) {
        return file_first_piece(file_index);
    }
    
    int64_t last_byte = file.offset + file.size - 1;
    return static_cast<uint32_t>(last_byte / piece_length_);
}

uint32_t FileStorage::file_num_pieces(size_t file_index) const {
    if (file_index >= files_.size()) {
        return 0;
    }
    
    return file_last_piece(file_index) - file_first_piece(file_index) + 1;
}

} // namespace librats
