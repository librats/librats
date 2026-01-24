#include "bt_extension.h"
#include "bt_peer_connection.h"

#include <algorithm>
#include <cstring>

namespace librats {

//=============================================================================
// ExtensionManager
//=============================================================================

ExtensionManager::ExtensionManager(BtPeerConnection* conn)
    : conn_(conn) {
}

void ExtensionManager::register_extension(std::shared_ptr<BtExtension> extension, 
                                          uint8_t local_id) {
    extensions_[extension->name()] = extension;
    local_id_map_[local_id] = extension;
}

std::shared_ptr<BtExtension> ExtensionManager::get_extension(const std::string& name) {
    auto it = extensions_.find(name);
    if (it != extensions_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<uint8_t> ExtensionManager::create_handshake() {
    BencodeValue handshake = BencodeValue::create_dict();
    
    // Build 'm' dictionary with extension name -> our local ID
    BencodeValue m = BencodeValue::create_dict();
    for (const auto& [local_id, ext] : local_id_map_) {
        m[ext->name()] = BencodeValue(static_cast<int64_t>(local_id));
    }
    handshake["m"] = m;
    
    // Let each extension add its data
    for (const auto& [name, ext] : extensions_) {
        ext->add_handshake_data(handshake.as_dict());
    }
    
    // Add client ID
    handshake["v"] = BencodeValue("librats");
    
    return handshake.encode();
}

void ExtensionManager::process_handshake(const std::vector<uint8_t>& payload) {
    // Decode bencoded handshake
    BencodeValue decoded;
    try {
        decoded = BencodeDecoder::decode(payload);
    } catch (...) {
        return;
    }
    
    if (!decoded.is_dict()) {
        return;
    }
    
    const auto& dict = decoded.as_dict();
    
    // Extract metadata_size if present
    auto metadata_size_it = dict.find("metadata_size");
    if (metadata_size_it != dict.end() && metadata_size_it->second.is_integer()) {
        metadata_size_ = static_cast<size_t>(metadata_size_it->second.as_integer());
    }
    
    // Parse 'm' dictionary for extension IDs
    auto m_it = dict.find("m");
    if (m_it != dict.end() && m_it->second.is_dict()) {
        const auto& m = m_it->second.as_dict();
        
        for (const auto& [name, ext] : extensions_) {
            auto ext_it = m.find(name);
            if (ext_it != m.end() && ext_it->second.is_integer()) {
                uint8_t peer_id = static_cast<uint8_t>(ext_it->second.as_integer());
                ext->set_peer_msg_id(peer_id);
                if (peer_id != 0) {
                    peer_id_map_[peer_id] = ext;
                }
            }
        }
    }
    
    // Notify all extensions of handshake
    for (const auto& [name, ext] : extensions_) {
        ext->on_handshake(dict);
    }
}

bool ExtensionManager::handle_message(uint8_t extension_id, 
                                      const std::vector<uint8_t>& payload) {
    // Extension ID 0 is handshake
    if (extension_id == 0) {
        process_handshake(payload);
        return true;
    }
    
    // Find extension by our local ID
    auto it = local_id_map_.find(extension_id);
    if (it != local_id_map_.end()) {
        return it->second->on_message(extension_id, payload);
    }
    
    return false;
}

void ExtensionManager::send_message(const std::string& extension_name,
                                    const std::vector<uint8_t>& payload) {
    auto ext = get_extension(extension_name);
    if (!ext || !ext->peer_supports()) {
        return;
    }
    
    // Send using peer's message ID
    if (conn_) {
        conn_->send_extended(ext->peer_msg_id(), payload);
    }
}

//=============================================================================
// UtMetadataExtension
//=============================================================================

UtMetadataExtension::UtMetadataExtension(size_t metadata_size,
                                         const std::vector<uint8_t>* our_metadata)
    : metadata_size_(metadata_size)
    , our_metadata_(our_metadata)
    , metadata_complete_(false) {
    
    if (metadata_size_ > 0) {
        uint32_t pieces = num_pieces();
        pieces_received_.resize(pieces, false);
        pieces_requested_.resize(pieces, false);
        received_metadata_.resize(metadata_size_);
    }
}

void UtMetadataExtension::on_handshake(const BencodeDict& handshake) {
    auto it = handshake.find("metadata_size");
    if (it != handshake.end() && it->second.is_integer()) {
        size_t new_size = static_cast<size_t>(it->second.as_integer());
        
        if (metadata_size_ == 0 && new_size > 0) {
            metadata_size_ = new_size;
            uint32_t pieces = num_pieces();
            pieces_received_.resize(pieces, false);
            pieces_requested_.resize(pieces, false);
            received_metadata_.resize(metadata_size_);
        }
    }
}

bool UtMetadataExtension::on_message(uint8_t /*msg_id*/, 
                                     const std::vector<uint8_t>& payload) {
    // Decode the message
    BencodeValue decoded;
    try {
        decoded = BencodeDecoder::decode(payload);
    } catch (...) {
        return false;
    }
    
    if (!decoded.is_dict()) {
        return false;
    }
    
    const auto& dict = decoded.as_dict();
    
    auto msg_type_it = dict.find("msg_type");
    if (msg_type_it == dict.end() || !msg_type_it->second.is_integer()) {
        return false;
    }
    
    uint8_t msg_type = static_cast<uint8_t>(msg_type_it->second.as_integer());
    
    switch (static_cast<UtMetadataMessageType>(msg_type)) {
        case UtMetadataMessageType::Request:
            handle_request(dict);
            break;
        case UtMetadataMessageType::Data:
            handle_data(dict, payload);
            break;
        case UtMetadataMessageType::Reject:
            handle_reject(dict);
            break;
        default:
            return false;
    }
    
    return true;
}

void UtMetadataExtension::add_handshake_data(BencodeDict& handshake) {
    if (our_metadata_ && !our_metadata_->empty()) {
        handshake["metadata_size"] = BencodeValue(static_cast<int64_t>(our_metadata_->size()));
    }
}

std::vector<uint8_t> UtMetadataExtension::create_request(uint32_t piece) {
    BencodeValue msg = BencodeValue::create_dict();
    msg["msg_type"] = BencodeValue(static_cast<int64_t>(UtMetadataMessageType::Request));
    msg["piece"] = BencodeValue(static_cast<int64_t>(piece));
    
    if (piece < pieces_requested_.size()) {
        pieces_requested_[piece] = true;
    }
    
    return msg.encode();
}

std::vector<uint8_t> UtMetadataExtension::create_data(uint32_t piece, 
                                                       const std::vector<uint8_t>& data) {
    BencodeValue msg = BencodeValue::create_dict();
    msg["msg_type"] = BencodeValue(static_cast<int64_t>(UtMetadataMessageType::Data));
    msg["piece"] = BencodeValue(static_cast<int64_t>(piece));
    msg["total_size"] = BencodeValue(static_cast<int64_t>(metadata_size_));
    
    std::vector<uint8_t> result = msg.encode();
    
    // Append raw data after bencoded dict
    result.insert(result.end(), data.begin(), data.end());
    
    return result;
}

std::vector<uint8_t> UtMetadataExtension::create_reject(uint32_t piece) {
    BencodeValue msg = BencodeValue::create_dict();
    msg["msg_type"] = BencodeValue(static_cast<int64_t>(UtMetadataMessageType::Reject));
    msg["piece"] = BencodeValue(static_cast<int64_t>(piece));
    return msg.encode();
}

uint32_t UtMetadataExtension::num_pieces() const {
    if (metadata_size_ == 0) return 0;
    return static_cast<uint32_t>((metadata_size_ + BT_METADATA_PIECE_SIZE - 1) / BT_METADATA_PIECE_SIZE);
}

void UtMetadataExtension::handle_request(const BencodeDict& msg) {
    auto piece_it = msg.find("piece");
    if (piece_it == msg.end() || !piece_it->second.is_integer()) {
        return;
    }
    
    uint32_t piece = static_cast<uint32_t>(piece_it->second.as_integer());
    
    // If we have metadata, we could respond here
    // This would require access to the connection to send
    (void)piece;
}

void UtMetadataExtension::handle_data(const BencodeDict& msg, 
                                      const std::vector<uint8_t>& payload) {
    auto piece_it = msg.find("piece");
    if (piece_it == msg.end() || !piece_it->second.is_integer()) {
        return;
    }
    
    uint32_t piece = static_cast<uint32_t>(piece_it->second.as_integer());
    
    if (piece >= num_pieces()) {
        return;
    }
    
    // Find where the data starts (after the bencoded dict)
    // The dict ends with 'e', so we need to find the end of the dict
    size_t dict_end = 0;
    int depth = 0;
    for (size_t i = 0; i < payload.size(); ++i) {
        if (payload[i] == 'd' || payload[i] == 'l') {
            ++depth;
        } else if (payload[i] == 'e') {
            --depth;
            if (depth == 0) {
                dict_end = i + 1;
                break;
            }
        } else if (std::isdigit(payload[i])) {
            // Skip string
            size_t len = 0;
            while (i < payload.size() && std::isdigit(payload[i])) {
                len = len * 10 + (payload[i] - '0');
                ++i;
            }
            if (i < payload.size() && payload[i] == ':') {
                i += len;  // Skip the string content
            }
        } else if (payload[i] == 'i') {
            // Skip integer
            while (i < payload.size() && payload[i] != 'e') {
                ++i;
            }
        }
    }
    
    if (dict_end >= payload.size()) {
        return;
    }
    
    // Copy data to correct position
    size_t offset = static_cast<size_t>(piece) * BT_METADATA_PIECE_SIZE;
    size_t data_size = payload.size() - dict_end;
    size_t to_copy = std::min(data_size, metadata_size_ - offset);
    
    if (offset + to_copy <= received_metadata_.size()) {
        std::memcpy(received_metadata_.data() + offset, payload.data() + dict_end, to_copy);
        pieces_received_[piece] = true;
        
        check_complete();
    }
}

void UtMetadataExtension::handle_reject(const BencodeDict& msg) {
    auto piece_it = msg.find("piece");
    if (piece_it == msg.end() || !piece_it->second.is_integer()) {
        return;
    }
    
    uint32_t piece = static_cast<uint32_t>(piece_it->second.as_integer());
    
    if (piece < pieces_requested_.size()) {
        pieces_requested_[piece] = false;  // Can retry later
    }
}

void UtMetadataExtension::check_complete() {
    for (bool received : pieces_received_) {
        if (!received) return;
    }
    
    metadata_complete_ = true;
    
    if (on_metadata_complete_) {
        on_metadata_complete_(received_metadata_);
    }
}

uint32_t UtMetadataExtension::next_piece_to_request() const {
    for (uint32_t i = 0; i < num_pieces(); ++i) {
        if (!pieces_received_[i] && !pieces_requested_[i]) {
            return i;
        }
    }
    return num_pieces();
}

//=============================================================================
// UtPexExtension
//=============================================================================

UtPexExtension::UtPexExtension() {
}

void UtPexExtension::on_handshake(const BencodeDict& /*handshake*/) {
    // Nothing to do
}

bool UtPexExtension::on_message(uint8_t /*msg_id*/, 
                                const std::vector<uint8_t>& payload) {
    BencodeValue decoded;
    try {
        decoded = BencodeDecoder::decode(payload);
    } catch (...) {
        return false;
    }
    
    if (!decoded.is_dict()) {
        return false;
    }
    
    const auto& dict = decoded.as_dict();
    
    std::vector<PexPeer> added, dropped;
    
    // Parse added peers (IPv4)
    auto added_it = dict.find("added");
    if (added_it != dict.end() && added_it->second.is_string()) {
        added = parse_peers(added_it->second.as_string());
    }
    
    // Parse dropped peers
    auto dropped_it = dict.find("dropped");
    if (dropped_it != dict.end() && dropped_it->second.is_string()) {
        dropped = parse_peers(dropped_it->second.as_string());
    }
    
    if (on_peers_) {
        on_peers_(added, dropped);
    }
    
    return true;
}

void UtPexExtension::add_handshake_data(BencodeDict& /*handshake*/) {
    // Nothing to add
}

std::vector<uint8_t> UtPexExtension::create_message(const std::vector<PexPeer>& added,
                                                     const std::vector<PexPeer>& dropped) {
    BencodeValue msg = BencodeValue::create_dict();
    
    // Encode added peers in compact format (6 bytes each: 4 IP + 2 port)
    std::string added_compact;
    for (const auto& peer : added) {
        // Parse IP
        uint32_t ip_parts[4];
        if (sscanf(peer.ip.c_str(), "%u.%u.%u.%u", 
                   &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]) == 4) {
            added_compact += static_cast<char>(ip_parts[0]);
            added_compact += static_cast<char>(ip_parts[1]);
            added_compact += static_cast<char>(ip_parts[2]);
            added_compact += static_cast<char>(ip_parts[3]);
            added_compact += static_cast<char>((peer.port >> 8) & 0xFF);
            added_compact += static_cast<char>(peer.port & 0xFF);
        }
    }
    msg["added"] = BencodeValue(added_compact);
    
    // Encode dropped peers
    std::string dropped_compact;
    for (const auto& peer : dropped) {
        uint32_t ip_parts[4];
        if (sscanf(peer.ip.c_str(), "%u.%u.%u.%u",
                   &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]) == 4) {
            dropped_compact += static_cast<char>(ip_parts[0]);
            dropped_compact += static_cast<char>(ip_parts[1]);
            dropped_compact += static_cast<char>(ip_parts[2]);
            dropped_compact += static_cast<char>(ip_parts[3]);
            dropped_compact += static_cast<char>((peer.port >> 8) & 0xFF);
            dropped_compact += static_cast<char>(peer.port & 0xFF);
        }
    }
    msg["dropped"] = BencodeValue(dropped_compact);
    
    return msg.encode();
}

std::vector<PexPeer> UtPexExtension::parse_peers(const std::string& compact_peers) {
    std::vector<PexPeer> peers;
    
    // Each peer is 6 bytes: 4 for IP, 2 for port
    for (size_t i = 0; i + 6 <= compact_peers.size(); i += 6) {
        PexPeer peer;
        
        // Parse IP
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                static_cast<unsigned char>(compact_peers[i]),
                static_cast<unsigned char>(compact_peers[i + 1]),
                static_cast<unsigned char>(compact_peers[i + 2]),
                static_cast<unsigned char>(compact_peers[i + 3]));
        peer.ip = ip_str;
        
        // Parse port (big-endian)
        peer.port = (static_cast<uint16_t>(static_cast<unsigned char>(compact_peers[i + 4])) << 8) |
                    static_cast<uint16_t>(static_cast<unsigned char>(compact_peers[i + 5]));
        
        peers.push_back(peer);
    }
    
    return peers;
}

} // namespace librats
