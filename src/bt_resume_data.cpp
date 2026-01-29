#include "bt_resume_data.h"
#include "fs.h"
#include "logger.h"

#include <fstream>
#include <sstream>

namespace librats {

//=============================================================================
// Constants
//=============================================================================

static constexpr const char* RESUME_FILE_FORMAT = "librats resume file";
static constexpr int RESUME_FILE_VERSION = 1;

//=============================================================================
// Write Resume Data
//=============================================================================

std::vector<uint8_t> write_resume_data(const TorrentResumeData& data) {
    BencodeValue dict = BencodeValue::create_dict();
    
    // File format identification
    dict["file-format"] = BencodeValue(std::string(RESUME_FILE_FORMAT));
    dict["file-version"] = BencodeValue(static_cast<int64_t>(RESUME_FILE_VERSION));
    dict["librats-version"] = BencodeValue(std::string("1.0.0"));
    
    // Info hash (as raw 20-byte string)
    std::string hash_str(reinterpret_cast<const char*>(data.info_hash.data()), 
                         data.info_hash.size());
    dict["info-hash"] = BencodeValue(hash_str);
    
    // Name and save path
    if (!data.name.empty()) {
        dict["name"] = BencodeValue(data.name);
    }
    dict["save_path"] = BencodeValue(data.save_path);
    
    // Have pieces bitfield
    // Store as a string where each byte represents one piece:
    // 0 = don't have, 1 = have (verified)
    if (data.have_pieces.size() > 0) {
        std::string pieces_str;
        pieces_str.resize(data.have_pieces.size());
        for (size_t i = 0; i < data.have_pieces.size(); ++i) {
            pieces_str[i] = data.have_pieces.get_bit(static_cast<uint32_t>(i)) ? 1 : 0;
        }
        dict["pieces"] = BencodeValue(pieces_str);
    }
    
    // Unfinished pieces (partial downloads)
    if (!data.unfinished_pieces.empty()) {
        BencodeValue unfinished_list = BencodeValue::create_list();
        
        for (const auto& [piece_idx, blocks] : data.unfinished_pieces) {
            BencodeValue piece_dict = BencodeValue::create_dict();
            piece_dict["piece"] = BencodeValue(static_cast<int64_t>(piece_idx));
            
            // Pack blocks bitfield into bytes
            // Each bit represents a 16KB block
            size_t num_bytes = (blocks.size() + 7) / 8;
            std::string bitmask;
            bitmask.resize(num_bytes, 0);
            
            for (size_t i = 0; i < blocks.size(); ++i) {
                if (blocks.get_bit(static_cast<uint32_t>(i))) {
                    bitmask[i / 8] |= static_cast<char>(0x80 >> (i % 8));
                }
            }
            
            piece_dict["bitmask"] = BencodeValue(bitmask);
            piece_dict["num_blocks"] = BencodeValue(static_cast<int64_t>(blocks.size()));
            
            unfinished_list.push_back(piece_dict);
        }
        
        dict["unfinished"] = unfinished_list;
    }
    
    // Statistics
    dict["total_uploaded"] = BencodeValue(static_cast<int64_t>(data.total_uploaded));
    dict["total_downloaded"] = BencodeValue(static_cast<int64_t>(data.total_downloaded));
    dict["active_time"] = BencodeValue(data.active_time);
    dict["seeding_time"] = BencodeValue(data.seeding_time);
    dict["added_time"] = BencodeValue(data.added_time);
    dict["completed_time"] = BencodeValue(data.completed_time);
    
    // Configuration
    dict["sequential_download"] = BencodeValue(data.sequential_download ? int64_t(1) : int64_t(0));
    if (data.max_connections >= 0) {
        dict["max_connections"] = BencodeValue(static_cast<int64_t>(data.max_connections));
    }
    if (data.max_uploads >= 0) {
        dict["max_uploads"] = BencodeValue(static_cast<int64_t>(data.max_uploads));
    }
    if (data.download_limit >= 0) {
        dict["download_rate_limit"] = BencodeValue(data.download_limit);
    }
    if (data.upload_limit >= 0) {
        dict["upload_rate_limit"] = BencodeValue(data.upload_limit);
    }
    
    // Optional: info dict (for magnet links that downloaded metadata)
    if (!data.info_dict.empty()) {
        std::string info_str(reinterpret_cast<const char*>(data.info_dict.data()),
                            data.info_dict.size());
        dict["info"] = BencodeValue(info_str);
    }
    
    // Optional: peers cache
    if (!data.peers.empty()) {
        // IPv4 peers: 6 bytes each (4 byte IP + 2 byte port)
        std::string peers_str;
        for (const auto& [ip, port] : data.peers) {
            // Parse IP address to 4 bytes
            uint32_t ip_num = 0;
            int a, b, c, d;
            if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
                ip_num = (static_cast<uint32_t>(a) << 24) |
                         (static_cast<uint32_t>(b) << 16) |
                         (static_cast<uint32_t>(c) << 8) |
                         static_cast<uint32_t>(d);
                
                peers_str.push_back(static_cast<char>((ip_num >> 24) & 0xFF));
                peers_str.push_back(static_cast<char>((ip_num >> 16) & 0xFF));
                peers_str.push_back(static_cast<char>((ip_num >> 8) & 0xFF));
                peers_str.push_back(static_cast<char>(ip_num & 0xFF));
                peers_str.push_back(static_cast<char>((port >> 8) & 0xFF));
                peers_str.push_back(static_cast<char>(port & 0xFF));
            }
        }
        if (!peers_str.empty()) {
            dict["peers"] = BencodeValue(peers_str);
        }
    }
    
    return dict.encode();
}

bool write_resume_data_file(const TorrentResumeData& data, const std::string& path) {
    auto encoded = write_resume_data(data);
    if (encoded.empty()) {
        LOG_ERROR("ResumeData", "Failed to encode resume data");
        return false;
    }
    
    // Create parent directory if needed
    std::string parent = get_parent_directory(path);
    if (!parent.empty() && !file_exists(parent.c_str())) {
        create_directories(parent.c_str());
    }
    
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        LOG_ERROR("ResumeData", "Failed to open resume file for writing: " + path);
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(encoded.data()), 
               static_cast<std::streamsize>(encoded.size()));
    
    if (!file) {
        LOG_ERROR("ResumeData", "Failed to write resume file: " + path);
        return false;
    }
    
    LOG_DEBUG("ResumeData", "Saved resume data to " + path + 
              " (" + std::to_string(encoded.size()) + " bytes)");
    
    return true;
}

//=============================================================================
// Read Resume Data
//=============================================================================

std::optional<TorrentResumeData> read_resume_data(
    const std::vector<uint8_t>& buffer,
    std::string* error_out) {
    
    BencodeValue decoded;
    try {
        decoded = BencodeDecoder::decode(buffer);
    } catch (const std::exception& e) {
        if (error_out) *error_out = std::string("Failed to decode bencode: ") + e.what();
        return std::nullopt;
    }
    
    if (!decoded.is_dict()) {
        if (error_out) *error_out = "Resume data is not a dictionary";
        return std::nullopt;
    }
    
    const auto& dict = decoded.as_dict();
    
    // Verify file format
    auto format_it = dict.find("file-format");
    if (format_it == dict.end() || !format_it->second.is_string()) {
        if (error_out) *error_out = "Missing or invalid file-format";
        return std::nullopt;
    }
    
    if (format_it->second.as_string() != RESUME_FILE_FORMAT) {
        if (error_out) *error_out = "Unknown resume file format: " + format_it->second.as_string();
        return std::nullopt;
    }
    
    // Check version
    auto version_it = dict.find("file-version");
    if (version_it != dict.end() && version_it->second.is_integer()) {
        int version = static_cast<int>(version_it->second.as_integer());
        if (version > RESUME_FILE_VERSION) {
            if (error_out) *error_out = "Resume file version too new: " + std::to_string(version);
            return std::nullopt;
        }
    }
    
    TorrentResumeData data;
    
    // Info hash (required)
    auto hash_it = dict.find("info-hash");
    if (hash_it == dict.end() || !hash_it->second.is_string()) {
        if (error_out) *error_out = "Missing info-hash";
        return std::nullopt;
    }
    
    const auto& hash_str = hash_it->second.as_string();
    if (hash_str.size() != 20) {
        if (error_out) *error_out = "Invalid info-hash size";
        return std::nullopt;
    }
    std::copy(hash_str.begin(), hash_str.end(), data.info_hash.begin());
    
    // Name
    auto name_it = dict.find("name");
    if (name_it != dict.end() && name_it->second.is_string()) {
        data.name = name_it->second.as_string();
    }
    
    // Save path
    auto path_it = dict.find("save_path");
    if (path_it != dict.end() && path_it->second.is_string()) {
        data.save_path = path_it->second.as_string();
    }
    
    // Have pieces
    auto pieces_it = dict.find("pieces");
    if (pieces_it != dict.end() && pieces_it->second.is_string()) {
        const auto& pieces_str = pieces_it->second.as_string();
        data.have_pieces = Bitfield(static_cast<uint32_t>(pieces_str.size()));
        
        for (size_t i = 0; i < pieces_str.size(); ++i) {
            if (pieces_str[i] & 1) {
                data.have_pieces.set_bit(static_cast<uint32_t>(i));
            }
        }
    }
    
    // Unfinished pieces
    auto unfinished_it = dict.find("unfinished");
    if (unfinished_it != dict.end() && unfinished_it->second.is_list()) {
        const auto& unfinished_list = unfinished_it->second.as_list();
        
        for (const auto& entry : unfinished_list) {
            if (!entry.is_dict()) continue;
            
            const auto& piece_dict = entry.as_dict();
            
            auto piece_it = piece_dict.find("piece");
            if (piece_it == piece_dict.end() || !piece_it->second.is_integer()) {
                continue;
            }
            uint32_t piece_idx = static_cast<uint32_t>(piece_it->second.as_integer());
            
            auto bitmask_it = piece_dict.find("bitmask");
            if (bitmask_it == piece_dict.end() || !bitmask_it->second.is_string()) {
                continue;
            }
            const auto& bitmask = bitmask_it->second.as_string();
            
            // Get number of blocks (optional, for accurate size)
            size_t num_blocks = bitmask.size() * 8;
            auto num_blocks_it = piece_dict.find("num_blocks");
            if (num_blocks_it != piece_dict.end() && num_blocks_it->second.is_integer()) {
                num_blocks = static_cast<size_t>(num_blocks_it->second.as_integer());
            }
            
            Bitfield blocks(static_cast<uint32_t>(num_blocks));
            for (size_t i = 0; i < num_blocks; ++i) {
                if (i / 8 < bitmask.size()) {
                    if (bitmask[i / 8] & (0x80 >> (i % 8))) {
                        blocks.set_bit(static_cast<uint32_t>(i));
                    }
                }
            }
            
            data.unfinished_pieces[piece_idx] = blocks;
        }
    }
    
    // Statistics
    auto read_int = [&dict](const char* key, int64_t default_val = 0) -> int64_t {
        auto it = dict.find(key);
        if (it != dict.end() && it->second.is_integer()) {
            return it->second.as_integer();
        }
        return default_val;
    };
    
    data.total_uploaded = static_cast<uint64_t>(read_int("total_uploaded"));
    data.total_downloaded = static_cast<uint64_t>(read_int("total_downloaded"));
    data.active_time = read_int("active_time");
    data.seeding_time = read_int("seeding_time");
    data.added_time = read_int("added_time");
    data.completed_time = read_int("completed_time");
    
    // Configuration
    data.sequential_download = read_int("sequential_download") != 0;
    data.max_connections = static_cast<int>(read_int("max_connections", -1));
    data.max_uploads = static_cast<int>(read_int("max_uploads", -1));
    data.download_limit = read_int("download_rate_limit", -1);
    data.upload_limit = read_int("upload_rate_limit", -1);
    
    // Optional: info dict
    auto info_it = dict.find("info");
    if (info_it != dict.end() && info_it->second.is_string()) {
        const auto& info_str = info_it->second.as_string();
        data.info_dict.assign(info_str.begin(), info_str.end());
    }
    
    // Optional: peers
    auto peers_it = dict.find("peers");
    if (peers_it != dict.end() && peers_it->second.is_string()) {
        const auto& peers_str = peers_it->second.as_string();
        
        // Each peer is 6 bytes: 4 byte IP + 2 byte port
        for (size_t i = 0; i + 6 <= peers_str.size(); i += 6) {
            uint8_t a = static_cast<uint8_t>(peers_str[i]);
            uint8_t b = static_cast<uint8_t>(peers_str[i + 1]);
            uint8_t c = static_cast<uint8_t>(peers_str[i + 2]);
            uint8_t d = static_cast<uint8_t>(peers_str[i + 3]);
            uint16_t port = (static_cast<uint16_t>(static_cast<uint8_t>(peers_str[i + 4])) << 8) |
                            static_cast<uint16_t>(static_cast<uint8_t>(peers_str[i + 5]));
            
            std::string ip = std::to_string(a) + "." + std::to_string(b) + "." +
                            std::to_string(c) + "." + std::to_string(d);
            data.peers.emplace_back(ip, port);
        }
    }
    
    return data;
}

std::optional<TorrentResumeData> read_resume_data_file(
    const std::string& path,
    std::string* error_out) {
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        if (error_out) *error_out = "Failed to open resume file: " + path;
        return std::nullopt;
    }
    
    // Read entire file
    file.seekg(0, std::ios::end);
    size_t size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size));
    
    if (!file) {
        if (error_out) *error_out = "Failed to read resume file: " + path;
        return std::nullopt;
    }
    
    LOG_DEBUG("ResumeData", "Read resume file: " + path + 
              " (" + std::to_string(size) + " bytes)");
    
    return read_resume_data(buffer, error_out);
}

//=============================================================================
// Helper Functions
//=============================================================================

std::string get_resume_file_path(const std::string& save_path, const BtInfoHash& info_hash) {
    std::string hash_hex = info_hash_to_hex(info_hash);
    
    // Use save_path/.resume/{hash}.resume
    std::string resume_dir = save_path;
    if (!resume_dir.empty() && resume_dir.back() != '/' && resume_dir.back() != '\\') {
        resume_dir += '/';
    }
    resume_dir += ".resume";
    
    return resume_dir + "/" + hash_hex + ".resume";
}

bool resume_file_exists(const std::string& save_path, const BtInfoHash& info_hash) {
    std::string path = get_resume_file_path(save_path, info_hash);
    return file_exists(path.c_str());
}

} // namespace librats
