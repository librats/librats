#include "bt_create_torrent.h"
#include "sha1.h"
#include "fs.h"

#include <fstream>
#include <algorithm>
#include <cstring>

namespace librats {

//=============================================================================
// TorrentCreator Implementation
//=============================================================================

TorrentCreator::TorrentCreator(const std::string& path, 
                               const TorrentCreatorConfig& config)
    : base_path_(path)
    , comment_(config.comment)
    , created_by_(config.created_by)
    , creation_date_(config.creation_date)
    , is_private_(config.is_private)
    , piece_size_(config.piece_size)
    , info_hash_valid_(false) {
    
    // Determine name from path
    std::string name = get_filename_from_path(path);
    if (name.empty()) {
        name = path;
    }
    files_.set_name(name);
    
    // Scan files if path exists
    if (file_exists(path) || directory_exists(path)) {
        if (config.include_hidden_files) {
            scan_files(nullptr);
        } else {
            scan_files([](const std::string& p) {
                std::string filename = get_filename_from_path(p);
                return filename.empty() || filename[0] != '.';
            });
        }
    }
}

TorrentCreator::TorrentCreator(FileStorage&& storage, 
                               const std::string& base_path,
                               const TorrentCreatorConfig& config)
    : base_path_(base_path)
    , files_(std::move(storage))
    , comment_(config.comment)
    , created_by_(config.created_by)
    , creation_date_(config.creation_date)
    , is_private_(config.is_private)
    , piece_size_(config.piece_size)
    , info_hash_valid_(false) {
}

//=============================================================================
// File Management
//=============================================================================

size_t TorrentCreator::scan_files(FileFilterCallback filter) {
    // Clear existing files but keep name
    std::string name = files_.name();
    files_ = FileStorage();
    files_.set_name(name);
    piece_hashes_.clear();
    info_hash_valid_ = false;
    
    if (is_directory(base_path_.c_str())) {
        scan_directory(base_path_, "", filter);
    } else if (file_exists(base_path_.c_str())) {
        // Single file
        int64_t size = get_file_size(base_path_.c_str());
        if (size >= 0) {
            std::string filename = get_filename_from_path(base_path_);
            files_.add_file(filename, size);
        }
    }
    
    return files_.num_files();
}

void TorrentCreator::scan_directory(const std::string& dir_path, 
                                    const std::string& relative_prefix,
                                    FileFilterCallback filter) {
    std::vector<DirectoryEntry> entries;
    if (!list_directory(dir_path.c_str(), entries)) {
        return;
    }
    
    // Sort entries for consistent ordering
    std::sort(entries.begin(), entries.end(), 
        [](const DirectoryEntry& a, const DirectoryEntry& b) {
            return a.name < b.name;
        });
    
    for (const auto& entry : entries) {
        // Skip . and ..
        if (entry.name == "." || entry.name == "..") {
            continue;
        }
        
        std::string full_path = combine_paths(dir_path, entry.name);
        std::string relative_path = relative_prefix.empty() 
            ? entry.name 
            : relative_prefix + "/" + entry.name;
        
        // Apply filter
        if (filter && !filter(full_path)) {
            continue;
        }
        
        if (entry.is_directory) {
            // Recurse into directory
            scan_directory(full_path, relative_path, filter);
        } else {
            // Add file
            files_.add_file(relative_path, static_cast<int64_t>(entry.size));
        }
    }
}

bool TorrentCreator::add_file(const std::string& relative_path, int64_t size) {
    if (relative_path.empty() || size < 0) {
        return false;
    }
    
    files_.add_file(relative_path, size);
    piece_hashes_.clear();
    info_hash_valid_ = false;
    return true;
}

//=============================================================================
// Properties
//=============================================================================

void TorrentCreator::set_name(const std::string& name) {
    files_.set_name(name);
    info_hash_valid_ = false;
}

void TorrentCreator::set_piece_size(uint32_t size) {
    // Validate piece size (must be power of 2, >= 16 KiB)
    if (size > 0) {
        if (size < 16 * 1024) {
            size = 16 * 1024;
        }
        // Round up to power of 2
        uint32_t power = 1;
        while (power < size) {
            power *= 2;
        }
        size = power;
    }
    
    piece_size_ = size;
    piece_hashes_.clear();
    info_hash_valid_ = false;
}

uint32_t TorrentCreator::auto_detect_piece_size() const {
    int64_t total = total_size();
    
    // Size thresholds and corresponding piece sizes
    // Based on libtorrent's algorithm
    static const struct {
        int64_t threshold;
        uint32_t piece_size;
    } size_table[] = {
        {       2684355LL, 16 * 1024 },       // -> 16 KiB
        {      10737418LL, 32 * 1024 },       // -> 32 KiB
        {      42949673LL, 64 * 1024 },       // -> 64 KiB
        {     171798692LL, 128 * 1024 },      // -> 128 KiB
        {     687194767LL, 256 * 1024 },      // -> 256 KiB
        {    2748779069LL, 512 * 1024 },      // -> 512 KiB
        {   10995116278LL, 1024 * 1024 },     // -> 1 MiB
        {   43980465111LL, 2 * 1024 * 1024 }, // -> 2 MiB
        {  175921860444LL, 4 * 1024 * 1024 }, // -> 4 MiB
        {  703687441777LL, 8 * 1024 * 1024 }, // -> 8 MiB
        { 2814749767106LL, 16 * 1024 * 1024 } // -> 16 MiB
    };
    
    for (const auto& entry : size_table) {
        if (total < entry.threshold) {
            return entry.piece_size;
        }
    }
    
    return 16 * 1024 * 1024; // Max 16 MiB
}

//=============================================================================
// Trackers and Seeds
//=============================================================================

void TorrentCreator::add_tracker(const std::string& url, int tier) {
    if (url.empty()) return;
    
    // Check for duplicates
    for (const auto& t : trackers_) {
        if (t.first == url) return;
    }
    
    trackers_.emplace_back(url, tier);
    
    // Sort by tier
    std::sort(trackers_.begin(), trackers_.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
}

std::vector<std::string> TorrentCreator::trackers() const {
    std::vector<std::string> result;
    result.reserve(trackers_.size());
    for (const auto& t : trackers_) {
        result.push_back(t.first);
    }
    return result;
}

void TorrentCreator::add_url_seed(const std::string& url) {
    if (!url.empty()) {
        url_seeds_.push_back(url);
    }
}

void TorrentCreator::add_http_seed(const std::string& url) {
    if (!url.empty()) {
        http_seeds_.push_back(url);
    }
}

void TorrentCreator::add_dht_node(const std::string& host, uint16_t port) {
    if (!host.empty() && port > 0) {
        dht_nodes_.emplace_back(host, port);
    }
}

//=============================================================================
// Piece Hashing
//=============================================================================

bool TorrentCreator::set_piece_hashes(PieceHashProgressCallback progress_callback,
                                       TorrentCreateError* error) {
    if (files_.num_files() == 0) {
        if (error) error->message = "No files to hash";
        return false;
    }
    
    if (total_size() == 0) {
        if (error) error->message = "Total size is zero";
        return false;
    }
    
    // Determine piece size
    uint32_t psize = piece_size_;
    if (psize == 0) {
        psize = auto_detect_piece_size();
    }
    piece_size_ = psize;
    
    // Finalize file storage with piece size
    files_.set_piece_length(psize);
    files_.finalize();
    
    uint32_t num_pcs = files_.num_pieces();
    piece_hashes_.clear();
    piece_hashes_.reserve(num_pcs * 20);
    
    // Buffer for reading file data
    std::vector<uint8_t> piece_buffer(psize);
    
    // Current position in file storage
    uint32_t current_piece = 0;
    uint32_t piece_offset = 0;
    
    // For each file
    for (size_t file_idx = 0; file_idx < files_.num_files(); ++file_idx) {
        const FileEntry& entry = files_.file_at(file_idx);
        
        // Build full path to file
        std::string file_path;
        if (is_directory(base_path_.c_str())) {
            file_path = combine_paths(base_path_, entry.path);
        } else {
            file_path = base_path_;
        }
        
        // Open file
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            if (error) error->message = "Failed to open file: " + file_path;
            return false;
        }
        
        int64_t remaining = entry.size;
        while (remaining > 0) {
            // How much to read for current piece
            uint32_t space_in_piece = psize - piece_offset;
            uint32_t to_read = static_cast<uint32_t>(std::min(static_cast<int64_t>(space_in_piece), remaining));
            
            // Read data
            if (!file.read(reinterpret_cast<char*>(piece_buffer.data() + piece_offset), to_read)) {
                if (error) error->message = "Failed to read file: " + file_path;
                return false;
            }
            
            piece_offset += to_read;
            remaining -= to_read;
            
            // If piece is complete, hash it
            if (piece_offset == psize) {
                SHA1 hasher;
                hasher.update(piece_buffer.data(), psize);
                std::string hex_hash = hasher.finalize();
                
                // Convert hex to bytes
                for (size_t i = 0; i < 40; i += 2) {
                    uint8_t byte = static_cast<uint8_t>(
                        std::stoul(hex_hash.substr(i, 2), nullptr, 16));
                    piece_hashes_.push_back(byte);
                }
                
                ++current_piece;
                piece_offset = 0;
                
                // Progress callback
                if (progress_callback) {
                    progress_callback(current_piece, num_pcs);
                }
            }
        }
    }
    
    // Hash final partial piece if any
    if (piece_offset > 0) {
        SHA1 hasher;
        hasher.update(piece_buffer.data(), piece_offset);
        std::string hex_hash = hasher.finalize();
        
        // Convert hex to bytes
        for (size_t i = 0; i < 40; i += 2) {
            uint8_t byte = static_cast<uint8_t>(
                std::stoul(hex_hash.substr(i, 2), nullptr, 16));
            piece_hashes_.push_back(byte);
        }
        
        ++current_piece;
        
        // Final progress callback
        if (progress_callback) {
            progress_callback(current_piece, num_pcs);
        }
    }
    
    info_hash_valid_ = false;
    return true;
}

//=============================================================================
// Generation
//=============================================================================

BencodeValue TorrentCreator::build_info_dict() const {
    BencodeValue info = BencodeValue::create_dict();
    
    // Name (required)
    info["name"] = BencodeValue(files_.name());
    
    // Piece length (required)
    info["piece length"] = BencodeValue(static_cast<int64_t>(piece_size_));
    
    // Pieces (required) - concatenated SHA-1 hashes
    std::string pieces_str(piece_hashes_.begin(), piece_hashes_.end());
    info["pieces"] = BencodeValue(pieces_str);
    
    // Private flag
    if (is_private_) {
        info["private"] = BencodeValue(static_cast<int64_t>(1));
    }
    
    // File(s)
    if (files_.num_files() == 1) {
        // Single-file mode
        info["length"] = BencodeValue(files_.file_at(0).size);
    } else {
        // Multi-file mode
        BencodeValue files_list = BencodeValue::create_list();
        
        for (size_t i = 0; i < files_.num_files(); ++i) {
            const FileEntry& entry = files_.file_at(i);
            
            BencodeValue file_dict = BencodeValue::create_dict();
            file_dict["length"] = BencodeValue(entry.size);
            
            // Path components
            BencodeValue path_list = BencodeValue::create_list();
            std::string path = entry.path;
            
            // Split path by /
            size_t pos = 0;
            while (pos < path.size()) {
                size_t next = path.find('/', pos);
                if (next == std::string::npos) {
                    next = path.size();
                }
                if (next > pos) {
                    path_list.push_back(BencodeValue(path.substr(pos, next - pos)));
                }
                pos = next + 1;
            }
            
            file_dict["path"] = std::move(path_list);
            files_list.push_back(std::move(file_dict));
        }
        
        info["files"] = std::move(files_list);
    }
    
    return info;
}

BencodeValue TorrentCreator::build_torrent_dict() const {
    BencodeValue dict = BencodeValue::create_dict();
    
    // Info dictionary (required)
    dict["info"] = build_info_dict();
    
    // Announce (primary tracker)
    if (!trackers_.empty()) {
        dict["announce"] = BencodeValue(trackers_[0].first);
    }
    
    // Announce-list (multi-tracker)
    if (trackers_.size() > 1) {
        BencodeValue announce_list = BencodeValue::create_list();
        BencodeValue current_tier = BencodeValue::create_list();
        int current_tier_num = trackers_[0].second;
        
        for (const auto& tracker : trackers_) {
            if (tracker.second != current_tier_num) {
                announce_list.push_back(std::move(current_tier));
                current_tier = BencodeValue::create_list();
                current_tier_num = tracker.second;
            }
            current_tier.push_back(BencodeValue(tracker.first));
        }
        announce_list.push_back(std::move(current_tier));
        
        dict["announce-list"] = std::move(announce_list);
    }
    
    // Comment
    if (!comment_.empty()) {
        dict["comment"] = BencodeValue(comment_);
    }
    
    // Created by
    if (!created_by_.empty()) {
        dict["created by"] = BencodeValue(created_by_);
    }
    
    // Creation date
    if (creation_date_ != 0) {
        dict["creation date"] = BencodeValue(static_cast<int64_t>(creation_date_));
    }
    
    // URL seeds
    if (!url_seeds_.empty()) {
        if (url_seeds_.size() == 1) {
            dict["url-list"] = BencodeValue(url_seeds_[0]);
        } else {
            BencodeValue list = BencodeValue::create_list();
            for (const auto& seed : url_seeds_) {
                list.push_back(BencodeValue(seed));
            }
            dict["url-list"] = std::move(list);
        }
    }
    
    // HTTP seeds
    if (!http_seeds_.empty()) {
        if (http_seeds_.size() == 1) {
            dict["httpseeds"] = BencodeValue(http_seeds_[0]);
        } else {
            BencodeValue list = BencodeValue::create_list();
            for (const auto& seed : http_seeds_) {
                list.push_back(BencodeValue(seed));
            }
            dict["httpseeds"] = std::move(list);
        }
    }
    
    // DHT nodes
    if (!dht_nodes_.empty()) {
        BencodeValue nodes = BencodeValue::create_list();
        for (const auto& node : dht_nodes_) {
            BencodeValue node_entry = BencodeValue::create_list();
            node_entry.push_back(BencodeValue(node.first));
            node_entry.push_back(BencodeValue(static_cast<int64_t>(node.second)));
            nodes.push_back(std::move(node_entry));
        }
        dict["nodes"] = std::move(nodes);
    }
    
    return dict;
}

std::vector<uint8_t> TorrentCreator::generate(TorrentCreateError* error) const {
    if (piece_hashes_.empty()) {
        if (error) error->message = "Piece hashes not computed. Call set_piece_hashes() first.";
        return {};
    }
    
    if (files_.num_files() == 0) {
        if (error) error->message = "No files in torrent";
        return {};
    }
    
    BencodeValue torrent = build_torrent_dict();
    return torrent.encode();
}

bool TorrentCreator::save_to_file(const std::string& output_path, 
                                   TorrentCreateError* error) const {
    auto data = generate(error);
    if (data.empty()) {
        return false;
    }
    
    std::ofstream file(output_path, std::ios::binary);
    if (!file) {
        if (error) error->message = "Failed to open output file: " + output_path;
        return false;
    }
    
    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        if (error) error->message = "Failed to write output file: " + output_path;
        return false;
    }
    
    return true;
}

std::optional<TorrentInfo> TorrentCreator::generate_torrent_info(TorrentCreateError* error) const {
    auto data = generate(error);
    if (data.empty()) {
        return std::nullopt;
    }
    
    TorrentParseError parse_error;
    auto result = TorrentInfo::from_bytes(data, &parse_error);
    if (!result && error) {
        error->message = parse_error.message;
    }
    return result;
}

BtInfoHash TorrentCreator::info_hash() const {
    if (info_hash_valid_) {
        return cached_info_hash_;
    }
    
    if (piece_hashes_.empty()) {
        return BtInfoHash{};
    }
    
    BencodeValue info_dict = build_info_dict();
    std::vector<uint8_t> info_bytes = info_dict.encode();
    
    SHA1 hasher;
    hasher.update(info_bytes.data(), info_bytes.size());
    std::string hex_hash = hasher.finalize();
    
    cached_info_hash_ = hex_to_info_hash(hex_hash);
    info_hash_valid_ = true;
    
    return cached_info_hash_;
}

std::string TorrentCreator::info_hash_hex() const {
    BtInfoHash hash = info_hash();
    return info_hash_to_hex(hash);
}

//=============================================================================
// Convenience Functions
//=============================================================================

size_t add_files(FileStorage& storage, const std::string& path,
                 FileFilterCallback filter) {
    size_t count = 0;
    
    if (is_directory(path.c_str())) {
        std::vector<DirectoryEntry> entries;
        if (!list_directory(path.c_str(), entries)) {
            return 0;
        }
        
        std::sort(entries.begin(), entries.end(),
            [](const DirectoryEntry& a, const DirectoryEntry& b) {
                return a.name < b.name;
            });
        
        for (const auto& entry : entries) {
            if (entry.name == "." || entry.name == "..") continue;
            
            std::string full_path = combine_paths(path, entry.name);
            
            if (filter && !filter(full_path)) continue;
            
            if (entry.is_directory) {
                count += add_files(storage, full_path, filter);
            } else {
                storage.add_file(entry.name, static_cast<int64_t>(entry.size));
                ++count;
            }
        }
    } else if (file_exists(path.c_str())) {
        if (!filter || filter(path)) {
            int64_t size = get_file_size(path.c_str());
            std::string filename = get_filename_from_path(path);
            storage.add_file(filename, size);
            ++count;
        }
    }
    
    return count;
}

bool create_torrent(const std::string& path,
                    const std::string& output_path,
                    const std::vector<std::string>& trackers,
                    const std::string& comment,
                    PieceHashProgressCallback progress_callback,
                    TorrentCreateError* error) {
    TorrentCreatorConfig config;
    config.comment = comment;
    config.created_by = "librats";
    
    TorrentCreator creator(path, config);
    
    for (const auto& tracker : trackers) {
        creator.add_tracker(tracker);
    }
    
    if (!creator.set_piece_hashes(progress_callback, error)) {
        return false;
    }
    
    return creator.save_to_file(output_path, error);
}

std::vector<uint8_t> create_torrent_data(const std::string& path,
                                          const std::vector<std::string>& trackers,
                                          const std::string& comment,
                                          PieceHashProgressCallback progress_callback,
                                          TorrentCreateError* error) {
    TorrentCreatorConfig config;
    config.comment = comment;
    config.created_by = "librats";
    
    TorrentCreator creator(path, config);
    
    for (const auto& tracker : trackers) {
        creator.add_tracker(tracker);
    }
    
    if (!creator.set_piece_hashes(progress_callback, error)) {
        return {};
    }
    
    return creator.generate(error);
}

} // namespace librats
