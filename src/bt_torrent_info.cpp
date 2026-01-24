#include "bt_torrent_info.h"
#include "sha1.h"

#include <fstream>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>

namespace librats {

//=============================================================================
// Constructors
//=============================================================================

TorrentInfo::TorrentInfo()
    : info_hash_{}
    , creation_date_(0)
    , is_private_(false)
    , has_metadata_(false) {
}

TorrentInfo::TorrentInfo(const TorrentInfo& other)
    : info_hash_(other.info_hash_)
    , name_(other.name_)
    , comment_(other.comment_)
    , created_by_(other.created_by_)
    , creation_date_(other.creation_date_)
    , is_private_(other.is_private_)
    , has_metadata_(other.has_metadata_)
    , files_(other.files_)
    , piece_hashes_(other.piece_hashes_)
    , announce_(other.announce_)
    , announce_list_(other.announce_list_)
    , web_seeds_(other.web_seeds_)
    , dht_nodes_(other.dht_nodes_)
    , info_dict_bytes_(other.info_dict_bytes_) {
}

TorrentInfo::TorrentInfo(TorrentInfo&& other) noexcept
    : info_hash_(std::move(other.info_hash_))
    , name_(std::move(other.name_))
    , comment_(std::move(other.comment_))
    , created_by_(std::move(other.created_by_))
    , creation_date_(other.creation_date_)
    , is_private_(other.is_private_)
    , has_metadata_(other.has_metadata_)
    , files_(std::move(other.files_))
    , piece_hashes_(std::move(other.piece_hashes_))
    , announce_(std::move(other.announce_))
    , announce_list_(std::move(other.announce_list_))
    , web_seeds_(std::move(other.web_seeds_))
    , dht_nodes_(std::move(other.dht_nodes_))
    , info_dict_bytes_(std::move(other.info_dict_bytes_)) {
    other.has_metadata_ = false;
}

TorrentInfo& TorrentInfo::operator=(const TorrentInfo& other) {
    if (this != &other) {
        info_hash_ = other.info_hash_;
        name_ = other.name_;
        comment_ = other.comment_;
        created_by_ = other.created_by_;
        creation_date_ = other.creation_date_;
        is_private_ = other.is_private_;
        has_metadata_ = other.has_metadata_;
        files_ = other.files_;
        piece_hashes_ = other.piece_hashes_;
        announce_ = other.announce_;
        announce_list_ = other.announce_list_;
        web_seeds_ = other.web_seeds_;
        dht_nodes_ = other.dht_nodes_;
        info_dict_bytes_ = other.info_dict_bytes_;
    }
    return *this;
}

TorrentInfo& TorrentInfo::operator=(TorrentInfo&& other) noexcept {
    if (this != &other) {
        info_hash_ = std::move(other.info_hash_);
        name_ = std::move(other.name_);
        comment_ = std::move(other.comment_);
        created_by_ = std::move(other.created_by_);
        creation_date_ = other.creation_date_;
        is_private_ = other.is_private_;
        has_metadata_ = other.has_metadata_;
        files_ = std::move(other.files_);
        piece_hashes_ = std::move(other.piece_hashes_);
        announce_ = std::move(other.announce_);
        announce_list_ = std::move(other.announce_list_);
        web_seeds_ = std::move(other.web_seeds_);
        dht_nodes_ = std::move(other.dht_nodes_);
        info_dict_bytes_ = std::move(other.info_dict_bytes_);
        other.has_metadata_ = false;
    }
    return *this;
}

TorrentInfo::~TorrentInfo() = default;

//=============================================================================
// Static Factory Methods
//=============================================================================

std::optional<TorrentInfo> TorrentInfo::from_bytes(
    const std::vector<uint8_t>& data,
    TorrentParseError* error) {
    
    if (data.empty()) {
        if (error) error->message = "Empty data";
        return std::nullopt;
    }
    
    // Decode bencoded data
    BencodeValue decoded;
    try {
        decoded = BencodeDecoder::decode(data);
    } catch (...) {
        if (error) error->message = "Failed to decode bencoded data";
        return std::nullopt;
    }
    
    if (!decoded.is_dict()) {
        if (error) error->message = "Root element is not a dictionary";
        return std::nullopt;
    }
    
    const auto& root = decoded.as_dict();
    
    // Info dictionary is required
    auto info_it = root.find("info");
    if (info_it == root.end() || !info_it->second.is_dict()) {
        if (error) error->message = "Missing or invalid 'info' dictionary";
        return std::nullopt;
    }
    
    TorrentInfo info;
    
    // Extract info dictionary bytes for hash calculation
    // We need to find the raw bytes of the info dict in the original data
    // For now, re-encode it (this is correct as bencode is canonical)
    info.info_dict_bytes_ = info_it->second.encode();
    info.info_hash_ = calculate_info_hash(info.info_dict_bytes_);
    
    // Parse info dictionary
    if (!info.parse_info_dict(info_it->second, error)) {
        return std::nullopt;
    }
    
    // Parse announce (primary tracker)
    auto announce_it = root.find("announce");
    if (announce_it != root.end() && announce_it->second.is_string()) {
        info.announce_ = announce_it->second.as_string();
    }
    
    // Parse announce-list (multi-tracker)
    auto announce_list_it = root.find("announce-list");
    if (announce_list_it != root.end() && announce_list_it->second.is_list()) {
        for (const auto& tier : announce_list_it->second.as_list()) {
            if (tier.is_list()) {
                TrackerTier tracker_tier;
                for (const auto& tracker : tier.as_list()) {
                    if (tracker.is_string()) {
                        tracker_tier.push_back(tracker.as_string());
                    }
                }
                if (!tracker_tier.empty()) {
                    info.announce_list_.push_back(std::move(tracker_tier));
                }
            }
        }
    }
    
    // Parse comment
    auto comment_it = root.find("comment");
    if (comment_it != root.end() && comment_it->second.is_string()) {
        info.comment_ = comment_it->second.as_string();
    }
    
    // Parse created by
    auto created_by_it = root.find("created by");
    if (created_by_it != root.end() && created_by_it->second.is_string()) {
        info.created_by_ = created_by_it->second.as_string();
    }
    
    // Parse creation date
    auto creation_date_it = root.find("creation date");
    if (creation_date_it != root.end() && creation_date_it->second.is_integer()) {
        info.creation_date_ = creation_date_it->second.as_integer();
    }
    
    // Parse url-list (web seeds)
    auto url_list_it = root.find("url-list");
    if (url_list_it != root.end()) {
        if (url_list_it->second.is_string()) {
            info.web_seeds_.push_back(url_list_it->second.as_string());
        } else if (url_list_it->second.is_list()) {
            for (const auto& url : url_list_it->second.as_list()) {
                if (url.is_string()) {
                    info.web_seeds_.push_back(url.as_string());
                }
            }
        }
    }
    
    // Parse nodes (DHT bootstrap nodes)
    auto nodes_it = root.find("nodes");
    if (nodes_it != root.end() && nodes_it->second.is_list()) {
        for (const auto& node : nodes_it->second.as_list()) {
            if (node.is_list() && node.size() >= 2) {
                const auto& node_list = node.as_list();
                if (node_list[0].is_string() && node_list[1].is_integer()) {
                    DhtNode dht_node;
                    dht_node.host = node_list[0].as_string();
                    dht_node.port = static_cast<uint16_t>(node_list[1].as_integer());
                    info.dht_nodes_.push_back(std::move(dht_node));
                }
            }
        }
    }
    
    info.has_metadata_ = true;
    return info;
}

std::optional<TorrentInfo> TorrentInfo::from_file(
    const std::string& path,
    TorrentParseError* error) {
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        if (error) error->message = "Failed to open file: " + path;
        return std::nullopt;
    }
    
    // Read entire file
    file.seekg(0, std::ios::end);
    size_t size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> data(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        if (error) error->message = "Failed to read file: " + path;
        return std::nullopt;
    }
    
    return from_bytes(data, error);
}

std::optional<TorrentInfo> TorrentInfo::from_magnet(
    const std::string& magnet_uri,
    TorrentParseError* error) {
    
    auto parsed = MagnetUri::parse(magnet_uri);
    if (!parsed) {
        if (error) error->message = "Failed to parse magnet URI";
        return std::nullopt;
    }
    
    if (!parsed->is_valid()) {
        if (error) error->message = "Invalid info hash in magnet URI";
        return std::nullopt;
    }
    
    TorrentInfo info;
    info.info_hash_ = parsed->info_hash;
    info.name_ = parsed->display_name;
    
    // Add trackers
    for (const auto& tracker : parsed->trackers) {
        if (info.announce_.empty()) {
            info.announce_ = tracker;
        }
        // Each tracker is its own tier in announce-list
        info.announce_list_.push_back({tracker});
    }
    
    // Add web seeds
    info.web_seeds_ = std::move(parsed->web_seeds);
    
    // Note: has_metadata_ remains false
    return info;
}

std::optional<TorrentInfo> TorrentInfo::from_info_dict(
    const std::vector<uint8_t>& info_dict_bytes,
    const BtInfoHash& expected_hash,
    TorrentParseError* error) {
    
    // Calculate hash and verify
    BtInfoHash actual_hash = calculate_info_hash(info_dict_bytes);
    if (actual_hash != expected_hash) {
        if (error) error->message = "Info hash mismatch";
        return std::nullopt;
    }
    
    // Decode info dictionary
    BencodeValue decoded;
    try {
        decoded = BencodeDecoder::decode(info_dict_bytes);
    } catch (...) {
        if (error) error->message = "Failed to decode info dictionary";
        return std::nullopt;
    }
    
    if (!decoded.is_dict()) {
        if (error) error->message = "Failed to decode info dictionary";
        return std::nullopt;
    }
    
    TorrentInfo info;
    info.info_hash_ = actual_hash;
    info.info_dict_bytes_ = info_dict_bytes;
    
    if (!info.parse_info_dict(decoded, error)) {
        return std::nullopt;
    }
    
    info.has_metadata_ = true;
    return info;
}

//=============================================================================
// Parsing Helpers
//=============================================================================

bool TorrentInfo::parse_info_dict(const BencodeValue& info_dict, TorrentParseError* error) {
    const auto& info = info_dict.as_dict();
    
    // Name is required
    auto name_it = info.find("name");
    if (name_it == info.end() || !name_it->second.is_string()) {
        if (error) error->message = "Missing or invalid 'name' in info dictionary";
        return false;
    }
    name_ = name_it->second.as_string();
    files_.set_name(name_);
    
    // Piece length is required
    auto piece_length_it = info.find("piece length");
    if (piece_length_it == info.end() || !piece_length_it->second.is_integer()) {
        if (error) error->message = "Missing or invalid 'piece length' in info dictionary";
        return false;
    }
    uint32_t piece_length = static_cast<uint32_t>(piece_length_it->second.as_integer());
    files_.set_piece_length(piece_length);
    
    // Pieces (concatenated SHA-1 hashes) is required
    auto pieces_it = info.find("pieces");
    if (pieces_it == info.end() || !pieces_it->second.is_string()) {
        if (error) error->message = "Missing or invalid 'pieces' in info dictionary";
        return false;
    }
    const std::string& pieces_str = pieces_it->second.as_string();
    if (pieces_str.size() % 20 != 0) {
        if (error) error->message = "Invalid 'pieces' length (not multiple of 20)";
        return false;
    }
    piece_hashes_.assign(pieces_str.begin(), pieces_str.end());
    
    // Private flag
    auto private_it = info.find("private");
    if (private_it != info.end() && private_it->second.is_integer()) {
        is_private_ = private_it->second.as_integer() != 0;
    }
    
    // Check for single-file or multi-file torrent
    auto files_it = info.find("files");
    if (files_it != info.end() && files_it->second.is_list()) {
        // Multi-file torrent
        for (const auto& file_entry : files_it->second.as_list()) {
            if (!file_entry.is_dict()) continue;
            
            const auto& file_dict = file_entry.as_dict();
            
            // Length is required
            auto length_it = file_dict.find("length");
            if (length_it == file_dict.end() || !length_it->second.is_integer()) {
                continue;
            }
            int64_t length = length_it->second.as_integer();
            
            // Path is required (list of path components)
            auto path_it = file_dict.find("path");
            if (path_it == file_dict.end() || !path_it->second.is_list()) {
                continue;
            }
            
            std::string path;
            for (const auto& component : path_it->second.as_list()) {
                if (component.is_string()) {
                    if (!path.empty()) path += "/";
                    path += component.as_string();
                }
            }
            
            if (path.empty()) continue;
            
            // Check for attributes
            bool executable = false;
            bool hidden = false;
            bool pad_file = false;
            
            auto attr_it = file_dict.find("attr");
            if (attr_it != file_dict.end() && attr_it->second.is_string()) {
                const std::string& attr = attr_it->second.as_string();
                executable = attr.find('x') != std::string::npos;
                hidden = attr.find('h') != std::string::npos;
                pad_file = attr.find('p') != std::string::npos;
            }
            
            files_.add_file(path, length, pad_file, executable, hidden);
        }
    } else {
        // Single-file torrent
        auto length_it = info.find("length");
        if (length_it == info.end() || !length_it->second.is_integer()) {
            if (error) error->message = "Missing 'length' for single-file torrent";
            return false;
        }
        int64_t length = length_it->second.as_integer();
        files_.add_file(name_, length);
    }
    
    files_.finalize();
    
    // Verify piece count matches
    size_t expected_pieces = piece_hashes_.size() / 20;
    if (files_.num_pieces() != expected_pieces) {
        if (error) {
            error->message = "Piece count mismatch: expected " + 
                std::to_string(expected_pieces) + ", got " + 
                std::to_string(files_.num_pieces());
        }
        return false;
    }
    
    return true;
}

BtInfoHash TorrentInfo::calculate_info_hash(const std::vector<uint8_t>& info_bytes) {
    SHA1 hasher;
    hasher.update(info_bytes.data(), info_bytes.size());
    std::string hex_hash = hasher.finalize();
    return hex_to_info_hash(hex_hash);
}

//=============================================================================
// Accessors
//=============================================================================

std::array<uint8_t, 20> TorrentInfo::piece_hash(uint32_t index) const {
    std::array<uint8_t, 20> hash{};
    if (index >= num_pieces()) {
        return hash;
    }
    
    size_t offset = static_cast<size_t>(index) * 20;
    std::copy(piece_hashes_.begin() + offset, 
              piece_hashes_.begin() + offset + 20,
              hash.begin());
    return hash;
}

std::vector<std::string> TorrentInfo::all_trackers() const {
    std::vector<std::string> result;
    
    // Add primary announce if not in announce-list
    if (!announce_.empty()) {
        result.push_back(announce_);
    }
    
    // Add all from announce-list
    for (const auto& tier : announce_list_) {
        for (const auto& tracker : tier) {
            // Avoid duplicates
            if (std::find(result.begin(), result.end(), tracker) == result.end()) {
                result.push_back(tracker);
            }
        }
    }
    
    return result;
}

//=============================================================================
// Magnet URI
//=============================================================================

std::string TorrentInfo::to_magnet_uri(bool include_trackers) const {
    std::ostringstream oss;
    
    oss << "magnet:?xt=urn:btih:" << info_hash_hex();
    
    if (!name_.empty()) {
        oss << "&dn=" << url_encode(name_);
    }
    
    if (include_trackers) {
        for (const auto& tracker : all_trackers()) {
            oss << "&tr=" << url_encode(tracker);
        }
    }
    
    for (const auto& ws : web_seeds_) {
        oss << "&ws=" << url_encode(ws);
    }
    
    return oss.str();
}

std::string TorrentInfo::url_encode(const std::string& str) {
    std::ostringstream encoded;
    encoded << std::hex << std::uppercase;
    
    for (char c : str) {
        if (std::isalnum(static_cast<unsigned char>(c)) || 
            c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << c;
        } else {
            encoded << '%' << std::setw(2) << std::setfill('0') 
                    << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    
    return encoded.str();
}

//=============================================================================
// Metadata Update
//=============================================================================

bool TorrentInfo::set_metadata(const std::vector<uint8_t>& info_dict_bytes) {
    BtInfoHash actual_hash = calculate_info_hash(info_dict_bytes);
    if (actual_hash != info_hash_) {
        return false;
    }
    
    BencodeValue decoded;
    try {
        decoded = BencodeDecoder::decode(info_dict_bytes);
    } catch (...) {
        return false;
    }
    
    if (!decoded.is_dict()) {
        return false;
    }
    
    info_dict_bytes_ = info_dict_bytes;
    
    TorrentParseError error;
    if (!parse_info_dict(decoded, &error)) {
        return false;
    }
    
    has_metadata_ = true;
    return true;
}

//=============================================================================
// MagnetUri
//=============================================================================

std::optional<MagnetUri> MagnetUri::parse(const std::string& uri) {
    // Check prefix
    if (uri.substr(0, 8) != "magnet:?") {
        return std::nullopt;
    }
    
    MagnetUri result;
    
    // Parse query parameters
    std::string query = uri.substr(8);
    size_t pos = 0;
    
    while (pos < query.size()) {
        // Find next parameter
        size_t eq_pos = query.find('=', pos);
        if (eq_pos == std::string::npos) break;
        
        std::string key = query.substr(pos, eq_pos - pos);
        
        size_t amp_pos = query.find('&', eq_pos);
        std::string value;
        if (amp_pos == std::string::npos) {
            value = query.substr(eq_pos + 1);
            pos = query.size();
        } else {
            value = query.substr(eq_pos + 1, amp_pos - eq_pos - 1);
            pos = amp_pos + 1;
        }
        
        // URL decode value
        std::string decoded_value;
        for (size_t i = 0; i < value.size(); ++i) {
            if (value[i] == '%' && i + 2 < value.size()) {
                std::string hex = value.substr(i + 1, 2);
                try {
                    decoded_value += static_cast<char>(std::stoul(hex, nullptr, 16));
                    i += 2;
                } catch (...) {
                    decoded_value += value[i];
                }
            } else if (value[i] == '+') {
                decoded_value += ' ';
            } else {
                decoded_value += value[i];
            }
        }
        
        // Process parameter
        if (key == "xt") {
            // Extract info hash from urn:btih:HASH
            if (decoded_value.substr(0, 9) == "urn:btih:") {
                std::string hash_str = decoded_value.substr(9);
                
                if (hash_str.size() == 40) {
                    // Hex-encoded hash
                    result.info_hash = hex_to_info_hash(hash_str);
                } else if (hash_str.size() == 32) {
                    // Base32-encoded hash
                    // TODO: Implement base32 decoding
                }
            }
        } else if (key == "dn") {
            result.display_name = decoded_value;
        } else if (key == "tr") {
            result.trackers.push_back(decoded_value);
        } else if (key == "ws") {
            result.web_seeds.push_back(decoded_value);
        }
    }
    
    return result;
}

} // namespace librats
