#include "bittorrent.h"
#include "tracker.h"
#include "fs.h"
#include "network_utils.h"
#include "socket.h"
#include <iostream>
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <climits>
#include <cerrno>  // For errno on POSIX systems

#define LOG_BT_DEBUG(message) LOG_DEBUG("bittorrent", message)
#define LOG_BT_INFO(message)  LOG_INFO("bittorrent", message)
#define LOG_BT_WARN(message)  LOG_WARN("bittorrent", message)
#define LOG_BT_ERROR(message) LOG_ERROR("bittorrent", message)

namespace librats {

//=============================================================================
// TorrentInfo Implementation
//=============================================================================

TorrentInfo::TorrentInfo() 
    : total_length_(0), piece_length_(0), private_(false) {
    info_hash_.fill(0);
}

TorrentInfo::~TorrentInfo() = default;

bool TorrentInfo::load_from_file(const std::string& torrent_file) {
    LOG_BT_INFO("Loading torrent from file: " << torrent_file);
    
    std::string content = read_file_text_cpp(torrent_file);
    if (content.empty()) {
        LOG_BT_ERROR("Failed to read torrent file: " << torrent_file);
        return false;
    }
    
    std::vector<uint8_t> data(content.begin(), content.end());
    return load_from_data(data);
}

bool TorrentInfo::load_from_data(const std::vector<uint8_t>& data) {
    LOG_BT_DEBUG("Parsing torrent data (" << data.size() << " bytes)");
    
    try {
        BencodeValue torrent = bencode::decode(data);
        return load_from_bencode(torrent);
    } catch (const std::exception& e) {
        LOG_BT_ERROR("Failed to decode torrent bencode: " << e.what());
        return false;
    }
}

bool TorrentInfo::load_from_bencode(const BencodeValue& torrent_data) {
    try {
        if (!torrent_data.is_dict()) {
            LOG_BT_ERROR("Torrent data is not a dictionary");
            return false;
        }
        
        // Parse announce URL
        if (torrent_data.has_key("announce")) {
            announce_ = torrent_data["announce"].as_string();
        }
        
        // Parse announce-list
        if (torrent_data.has_key("announce-list")) {
            const auto& announce_list = torrent_data["announce-list"];
            if (announce_list.is_list()) {
                for (size_t i = 0; i < announce_list.size(); ++i) {
                    const auto& tier = announce_list[i];
                    if (tier.is_list() && tier.size() > 0) {
                        announce_list_.push_back(tier[0].as_string());
                    }
                }
            }
        }
        
        // Parse info dictionary
        if (!torrent_data.has_key("info")) {
            LOG_BT_ERROR("Torrent data missing 'info' dictionary");
            return false;
        }
        
        const auto& info_dict = torrent_data["info"];
        if (!parse_info_dict(info_dict)) {
            return false;
        }
        
        // Calculate info hash
        calculate_info_hash(info_dict);
        
        LOG_BT_INFO("Successfully parsed torrent: " << name_);
        LOG_BT_INFO("  Info hash: " << info_hash_to_hex(info_hash_));
        LOG_BT_INFO("  Total size: " << total_length_ << " bytes");
        LOG_BT_INFO("  Piece length: " << piece_length_ << " bytes");
        LOG_BT_INFO("  Number of pieces: " << piece_hashes_.size());
        LOG_BT_INFO("  Number of files: " << files_.size());
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_BT_ERROR("Failed to parse torrent: " << e.what());
        return false;
    }
}

bool TorrentInfo::parse_info_dict(const BencodeValue& info_dict) {
    if (!info_dict.is_dict()) {
        LOG_BT_ERROR("Info is not a dictionary");
        return false;
    }
    
    // Parse name
    if (!info_dict.has_key("name")) {
        LOG_BT_ERROR("Info dictionary missing 'name'");
        return false;
    }
    name_ = info_dict["name"].as_string();
    
    // Parse piece length
    if (!info_dict.has_key("piece length")) {
        LOG_BT_ERROR("Info dictionary missing 'piece length'");
        return false;
    }
    piece_length_ = static_cast<uint32_t>(info_dict["piece length"].as_integer());
    
    // Parse pieces hashes
    if (!info_dict.has_key("pieces")) {
        LOG_BT_ERROR("Info dictionary missing 'pieces'");
        return false;
    }
    
    const std::string& pieces_data = info_dict["pieces"].as_string();
    if (pieces_data.length() % 20 != 0) {
        LOG_BT_ERROR("Invalid pieces length: " << pieces_data.length());
        return false;
    }
    
    size_t num_pieces = pieces_data.length() / 20;
    piece_hashes_.reserve(num_pieces);
    
    for (size_t i = 0; i < num_pieces; ++i) {
        std::array<uint8_t, 20> hash;
        std::memcpy(hash.data(), pieces_data.data() + i * 20, 20);
        piece_hashes_.push_back(hash);
    }
    
    // Parse private flag
    if (info_dict.has_key("private")) {
        private_ = info_dict["private"].as_integer() != 0;
    }
    
    // Build file list
    build_file_list(info_dict);
    
    return true;
}

void TorrentInfo::calculate_info_hash(const BencodeValue& info_dict) {
    // Encode the info dictionary and calculate SHA1 hash
    std::vector<uint8_t> encoded = info_dict.encode();
    std::string hash_string = SHA1::hash_bytes(encoded);
    
    // Convert hex string to bytes
    for (size_t i = 0; i < 20; ++i) {
        std::string byte_str = hash_string.substr(i * 2, 2);
        info_hash_[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
}

void TorrentInfo::build_file_list(const BencodeValue& info_dict) {
    files_.clear();
    total_length_ = 0;
    
    if (info_dict.has_key("files")) {
        // Multi-file torrent
        const auto& files_list = info_dict["files"];
        if (!files_list.is_list()) {
            LOG_BT_ERROR("Files is not a list");
            return;
        }
        
        uint64_t offset = 0;
        for (size_t i = 0; i < files_list.size(); ++i) {
            const auto& file_info = files_list[i];
            if (!file_info.is_dict()) {
                continue;
            }
            
            if (!file_info.has_key("length") || !file_info.has_key("path")) {
                continue;
            }
            
            uint64_t length = static_cast<uint64_t>(file_info["length"].as_integer());
            const auto& path_list = file_info["path"];
            
            std::string path;
            if (path_list.is_list()) {
                for (size_t j = 0; j < path_list.size(); ++j) {
                    if (j > 0) path += "/";
                    path += path_list[j].as_string();
                }
            }
            
            files_.emplace_back(path, length, offset);
            offset += length;
            total_length_ += length;
        }
    } else {
        // Single-file torrent
        if (!info_dict.has_key("length")) {
            LOG_BT_ERROR("Single-file torrent missing 'length'");
            return;
        }
        
        uint64_t length = static_cast<uint64_t>(info_dict["length"].as_integer());
        files_.emplace_back(name_, length, 0);
        total_length_ = length;
    }
}

uint32_t TorrentInfo::get_piece_length(PieceIndex piece_index) const {
    if (piece_index >= piece_hashes_.size()) {
        return 0;
    }
    
    if (piece_index == piece_hashes_.size() - 1) {
        // Last piece might be smaller
        uint32_t remainder = static_cast<uint32_t>(total_length_ % piece_length_);
        return remainder > 0 ? remainder : piece_length_;
    }
    
    return piece_length_;
}

bool TorrentInfo::is_valid() const {
    return !name_.empty() && 
           !piece_hashes_.empty() && 
           piece_length_ > 0 && 
           total_length_ > 0 && 
           !files_.empty();
}

TorrentInfo TorrentInfo::create_for_metadata_exchange(const InfoHash& info_hash) {
    TorrentInfo torrent;
    
    // Set the info hash directly
    torrent.info_hash_ = info_hash;
    
    // Set minimal required fields to make it valid
    torrent.name_ = "metadata_download_" + info_hash_to_hex(info_hash).substr(0, 8);
    torrent.piece_length_ = 16384;  // Standard piece length
    torrent.total_length_ = 1;      // Minimal length
    torrent.private_ = false;
    
    // Add a dummy piece hash (will be replaced when metadata is downloaded)
    std::array<uint8_t, 20> dummy_hash;
    dummy_hash.fill(0);
    torrent.piece_hashes_.push_back(dummy_hash);
    
    // Add a dummy file
    torrent.files_.emplace_back("temp", 1, 0);
    
    LOG_BT_DEBUG("Created metadata exchange TorrentInfo for hash: " << info_hash_to_hex(info_hash));
    
    return torrent;
}

//=============================================================================
// PeerMessage Implementation
//=============================================================================

std::vector<uint8_t> PeerMessage::serialize() const {
    std::vector<uint8_t> result;
    
    // Length prefix (4 bytes)
    uint32_t length = 1 + static_cast<uint32_t>(payload.size());  // 1 byte for message type + payload
    result.push_back((length >> 24) & 0xFF);
    result.push_back((length >> 16) & 0xFF);
    result.push_back((length >> 8) & 0xFF);
    result.push_back(length & 0xFF);
    
    // Message type (1 byte)
    result.push_back(static_cast<uint8_t>(type));
    
    // Payload
    result.insert(result.end(), payload.begin(), payload.end());
    
    return result;
}

PeerMessage PeerMessage::create_choke() {
    return PeerMessage(MessageType::CHOKE);
}

PeerMessage PeerMessage::create_unchoke() {
    return PeerMessage(MessageType::UNCHOKE);
}

PeerMessage PeerMessage::create_interested() {
    return PeerMessage(MessageType::INTERESTED);
}

PeerMessage PeerMessage::create_not_interested() {
    return PeerMessage(MessageType::NOT_INTERESTED);
}

PeerMessage PeerMessage::create_have(PieceIndex piece_index) {
    std::vector<uint8_t> payload(4);
    payload[0] = (piece_index >> 24) & 0xFF;
    payload[1] = (piece_index >> 16) & 0xFF;
    payload[2] = (piece_index >> 8) & 0xFF;
    payload[3] = piece_index & 0xFF;
    return PeerMessage(MessageType::HAVE, payload);
}

PeerMessage PeerMessage::create_bitfield(const std::vector<bool>& bitfield) {
    std::vector<uint8_t> payload((bitfield.size() + 7) / 8, 0);
    
    for (size_t i = 0; i < bitfield.size(); ++i) {
        if (bitfield[i]) {
            size_t byte_index = i / 8;
            size_t bit_index = 7 - (i % 8);
            payload[byte_index] |= (1 << bit_index);
        }
    }
    
    return PeerMessage(MessageType::BITFIELD, payload);
}

PeerMessage PeerMessage::create_request(PieceIndex piece_index, uint32_t offset, uint32_t length) {
    std::vector<uint8_t> payload(12);
    
    // Piece index
    payload[0] = (piece_index >> 24) & 0xFF;
    payload[1] = (piece_index >> 16) & 0xFF;
    payload[2] = (piece_index >> 8) & 0xFF;
    payload[3] = piece_index & 0xFF;
    
    // Offset
    payload[4] = (offset >> 24) & 0xFF;
    payload[5] = (offset >> 16) & 0xFF;
    payload[6] = (offset >> 8) & 0xFF;
    payload[7] = offset & 0xFF;
    
    // Length
    payload[8] = (length >> 24) & 0xFF;
    payload[9] = (length >> 16) & 0xFF;
    payload[10] = (length >> 8) & 0xFF;
    payload[11] = length & 0xFF;
    
    return PeerMessage(MessageType::REQUEST, payload);
}

PeerMessage PeerMessage::create_piece(PieceIndex piece_index, uint32_t offset, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> payload(8 + data.size());
    
    // Piece index
    payload[0] = (piece_index >> 24) & 0xFF;
    payload[1] = (piece_index >> 16) & 0xFF;
    payload[2] = (piece_index >> 8) & 0xFF;
    payload[3] = piece_index & 0xFF;
    
    // Offset
    payload[4] = (offset >> 24) & 0xFF;
    payload[5] = (offset >> 16) & 0xFF;
    payload[6] = (offset >> 8) & 0xFF;
    payload[7] = offset & 0xFF;
    
    // Data
    std::copy(data.begin(), data.end(), payload.begin() + 8);
    
    return PeerMessage(MessageType::PIECE, payload);
}

PeerMessage PeerMessage::create_cancel(PieceIndex piece_index, uint32_t offset, uint32_t length) {
    std::vector<uint8_t> payload(12);
    
    // Piece index
    payload[0] = (piece_index >> 24) & 0xFF;
    payload[1] = (piece_index >> 16) & 0xFF;
    payload[2] = (piece_index >> 8) & 0xFF;
    payload[3] = piece_index & 0xFF;
    
    // Offset
    payload[4] = (offset >> 24) & 0xFF;
    payload[5] = (offset >> 16) & 0xFF;
    payload[6] = (offset >> 8) & 0xFF;
    payload[7] = offset & 0xFF;
    
    // Length
    payload[8] = (length >> 24) & 0xFF;
    payload[9] = (length >> 16) & 0xFF;
    payload[10] = (length >> 8) & 0xFF;
    payload[11] = length & 0xFF;
    
    return PeerMessage(MessageType::CANCEL, payload);
}

PeerMessage PeerMessage::create_port(uint16_t port) {
    std::vector<uint8_t> payload(2);
    payload[0] = (port >> 8) & 0xFF;
    payload[1] = port & 0xFF;
    return PeerMessage(MessageType::PORT, payload);
}

//=============================================================================
// PeerConnection Implementation
//=============================================================================

PeerConnection::PeerConnection(TorrentDownload* torrent, const Peer& peer_info, socket_t socket)
    : torrent_(torrent), peer_info_(peer_info), socket_(socket), 
      state_(PeerState::CONNECTING), should_disconnect_(false), handshake_completed_(false),
      peer_choked_(true), am_choked_(true), peer_interested_(false), 
      am_interested_(false), am_choking_(true),
      downloaded_bytes_(0), uploaded_bytes_(0),
      last_speed_update_time_(std::chrono::steady_clock::now()),
      last_speed_downloaded_(0), last_speed_uploaded_(0),
      download_speed_(0.0), upload_speed_(0.0),
      expected_message_length_(0),
      supports_extensions_(false), supports_metadata_exchange_(false),
      peer_ut_metadata_id_(0), peer_metadata_size_(0) {
    
    peer_id_.fill(0);
    
    // If socket is already provided, it means handshake is already done (incoming connection)
    if (is_valid_socket(socket)) {
        handshake_completed_ = true;
        state_.store(PeerState::HANDSHAKING);  // Will move to CONNECTED after extended handshake
        LOG_BT_DEBUG("Created peer connection for incoming connection from " << peer_info_.ip << ":" << peer_info_.port);
    } else {
        LOG_BT_DEBUG("Created peer connection to " << peer_info_.ip << ":" << peer_info_.port);
    }
}

PeerConnection::~PeerConnection() {
    disconnect();
}

bool PeerConnection::connect() {
    if (state_.load() != PeerState::CONNECTING) {
        return false;
    }
    
    LOG_BT_INFO("Connecting to peer " << peer_info_.ip << ":" << peer_info_.port);
    
    // Start connection thread - socket creation happens inside the thread for async behavior
    // This prevents blocking the caller when connecting to unresponsive peers
    connection_thread_ = std::thread(&PeerConnection::connection_loop, this);
    
    return true;
}

void PeerConnection::disconnect() {
    should_disconnect_ = true;
    
    // Reset all pending block requests so they can be requested from other peers
    {
        std::lock_guard<std::mutex> lock(requests_mutex_);
        for (const auto& req : pending_requests_) {
            uint32_t block_index = req.offset / BLOCK_SIZE;
            torrent_->reset_block_request(req.piece_index, block_index);
        }
        pending_requests_.clear();
    }
    
    if (is_valid_socket(socket_)) {
        // Force shutdown for TCP socket to ensure immediate disconnect
        close_socket(socket_, true);
        socket_ = INVALID_SOCKET_VALUE;
    }
    
    if (connection_thread_.joinable()) {
        connection_thread_.join();
    }
    
    state_.store(PeerState::DISCONNECTED);
}

void PeerConnection::connection_loop() {
    LOG_BT_DEBUG("Starting connection loop for peer " << peer_info_.ip << ":" << peer_info_.port);
    
    // Create socket if not already provided (outgoing connection)
    // This is done in the thread to avoid blocking the caller
    if (!is_valid_socket(socket_)) {
        socket_ = create_tcp_client(peer_info_.ip, peer_info_.port, 5000); // 5-second timeout for faster failure
        if (!is_valid_socket(socket_)) {
            LOG_BT_ERROR("Failed to create connection to " << peer_info_.ip << ":" << peer_info_.port);
            state_.store(PeerState::ERROR);
            return;
        }
    }
    
    // Perform handshake only if not already completed (for outgoing connections)
    if (!handshake_completed_) {
        if (!perform_handshake()) {
            LOG_BT_ERROR("Handshake failed with peer " << peer_info_.ip << ":" << peer_info_.port);
            state_.store(PeerState::ERROR);
            return;
        }
    } else {
        LOG_BT_DEBUG("Handshake already completed for incoming peer " << peer_info_.ip << ":" << peer_info_.port);
        // For incoming connections, send extended handshake if needed
        send_extended_handshake();
    }
    
    state_.store(PeerState::CONNECTED);
    LOG_BT_INFO("Successfully connected to peer " << peer_info_.ip << ":" << peer_info_.port);
    
    // Initialize peer bitfield
    const auto& torrent_info = torrent_->get_torrent_info();
    peer_bitfield_.resize(torrent_info.get_num_pieces(), false);
    
    // Send our bitfield to the peer (for seeding)
    send_bitfield();
    
    // Automatically unchoke the peer (optimistic unchoking for now)
    // In a more sophisticated implementation, we'd have choke/unchoke algorithms
    set_choke(false);
    
    // Main message processing loop
    while (!should_disconnect_.load() && state_.load() == PeerState::CONNECTED) {
        process_messages();
        
        // Cleanup expired requests
        cleanup_expired_requests();
        
        // Use conditional variable for responsive shutdown
        {
            std::unique_lock<std::mutex> lock(shutdown_mutex_);
            if (shutdown_cv_.wait_for(lock, std::chrono::milliseconds(10), [this] { return should_disconnect_.load(); })) {
                break;
            }
        }
    }
    
    // Log reason for connection loop exit
    PeerState exit_state = state_.load();
    if (exit_state == PeerState::ERROR) {
        LOG_BT_WARN("Connection loop ended for peer " << peer_info_.ip << ":" << peer_info_.port << " due to error");
    } else if (should_disconnect_.load()) {
        LOG_BT_DEBUG("Connection loop ended for peer " << peer_info_.ip << ":" << peer_info_.port << " - disconnect requested");
    } else {
        LOG_BT_DEBUG("Connection loop ended for peer " << peer_info_.ip << ":" << peer_info_.port 
                     << " (state: " << static_cast<int>(exit_state) << ")");
    }
}

bool PeerConnection::perform_handshake() {
    state_.store(PeerState::HANDSHAKING);
    
    if (!send_handshake()) {
        return false;
    }
    
    if (!receive_handshake()) {
        return false;
    }
    
    return true;
}

bool PeerConnection::send_handshake() {
    const auto& torrent_info = torrent_->get_torrent_info();
    PeerID our_peer_id = generate_peer_id();
    
    auto handshake_data = create_handshake_message(torrent_info.get_info_hash(), our_peer_id);
    
    // Set extension protocol bit (BEP 10) - bit 20 in reserved bytes (byte 5, bit 3)
    handshake_data[25] |= 0x10;  // 0x10 = 0001 0000 (bit 4 from right)
    
    return write_data(handshake_data);
}

bool PeerConnection::receive_handshake() {
    std::vector<uint8_t> handshake_data(68);  // Fixed handshake size
    
    if (!read_data(handshake_data, 68)) {
        LOG_BT_ERROR("Failed to read handshake from peer");
        return false;
    }
    
    InfoHash received_info_hash;
    if (!parse_handshake_message(handshake_data, received_info_hash, peer_id_)) {
        LOG_BT_ERROR("Failed to parse handshake from peer");
        return false;
    }
    
    // Verify info hash matches
    const auto& expected_info_hash = torrent_->get_torrent_info().get_info_hash();
    if (received_info_hash != expected_info_hash) {
        LOG_BT_ERROR("Info hash mismatch in handshake");
        return false;
    }
    
    // Check if peer supports extension protocol (BEP 10) - bit 20 in reserved bytes (byte 5, bit 3)
    supports_extensions_ = (handshake_data[25] & 0x10) != 0;
    
    if (supports_extensions_) {
        LOG_BT_DEBUG("Peer " << peer_info_.ip << ":" << peer_info_.port << " supports extension protocol");
        // Send extended handshake
        send_extended_handshake();
    } else {
        LOG_BT_DEBUG("Peer " << peer_info_.ip << ":" << peer_info_.port << " does not support extension protocol");
    }
    
    LOG_BT_DEBUG("Handshake successful with peer " << peer_info_.ip << ":" << peer_info_.port);
    return true;
}

bool PeerConnection::send_message(const PeerMessage& message) {
    auto data = message.serialize();
    return write_data(data);
}

void PeerConnection::process_messages() {
    // Check if we're still connected before processing
    if (state_.load() != PeerState::CONNECTED) {
        return;
    }
    
    // Try to read message length first
    if (expected_message_length_ == 0) {
        std::vector<uint8_t> length_buffer(4);
        if (read_data(length_buffer, 4)) {
            expected_message_length_ = (static_cast<size_t>(length_buffer[0]) << 24) | 
                                     (static_cast<size_t>(length_buffer[1]) << 16) | 
                                     (static_cast<size_t>(length_buffer[2]) << 8) | 
                                     static_cast<size_t>(length_buffer[3]);
            
            if (expected_message_length_ == 0) {
                // Keep-alive message
                expected_message_length_ = 0;
                return;
            }
            
            message_buffer_.clear();
            message_buffer_.reserve(expected_message_length_);
        } else {
            return;  // No data available or connection error (state already updated)
        }
    }
    
    // Try to read the message payload
    if (expected_message_length_ > 0 && message_buffer_.size() < expected_message_length_) {
        // Check state again in case it changed during previous read
        if (state_.load() != PeerState::CONNECTED) {
            return;
        }
        
        size_t remaining = expected_message_length_ - message_buffer_.size();
        std::vector<uint8_t> temp_buffer(remaining);
        
        if (read_data(temp_buffer, remaining)) {
            message_buffer_.insert(message_buffer_.end(), temp_buffer.begin(), temp_buffer.end());
        } else {
            return;  // Read failed, state already updated if error
        }
    }
    
    // Process complete message
    if (message_buffer_.size() >= expected_message_length_) {
        auto message = parse_message(message_buffer_);
        if (message) {
            handle_message(*message);
        }
        
        // Reset for next message
        expected_message_length_ = 0;
        message_buffer_.clear();
    }
}

std::unique_ptr<PeerMessage> PeerConnection::parse_message(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return nullptr;
    }
    
    MessageType type = static_cast<MessageType>(data[0]);
    std::vector<uint8_t> payload(data.begin() + 1, data.end());
    
    return std::make_unique<PeerMessage>(type, payload);
}

void PeerConnection::handle_message(const PeerMessage& message) {
    LOG_BT_DEBUG("Received message type " << static_cast<int>(message.type) << " from peer " << peer_info_.ip << ":" << peer_info_.port);
    
    switch (message.type) {
        case MessageType::CHOKE:
            handle_choke();
            break;
        case MessageType::UNCHOKE:
            handle_unchoke();
            break;
        case MessageType::INTERESTED:
            handle_interested();
            break;
        case MessageType::NOT_INTERESTED:
            handle_not_interested();
            break;
        case MessageType::HAVE:
            handle_have(message.payload);
            break;
        case MessageType::BITFIELD:
            handle_bitfield(message.payload);
            break;
        case MessageType::REQUEST:
            handle_request(message.payload);
            break;
        case MessageType::PIECE:
            handle_piece(message.payload);
            break;
        case MessageType::CANCEL:
            handle_cancel(message.payload);
            break;
        case MessageType::EXTENDED:
            handle_extended(message.payload);
            break;
        default:
            LOG_BT_WARN("Unknown message type: " << static_cast<int>(message.type));
            break;
    }
}

void PeerConnection::handle_choke() {
    peer_choked_ = true;
    cancel_all_requests();
    LOG_BT_DEBUG("Peer " << peer_info_.ip << ":" << peer_info_.port << " choked us");
}

void PeerConnection::handle_unchoke() {
    peer_choked_ = false;
    LOG_BT_DEBUG("Peer " << peer_info_.ip << ":" << peer_info_.port << " unchoked us");
}

void PeerConnection::handle_interested() {
    peer_interested_ = true;
    LOG_BT_DEBUG("Peer " << peer_info_.ip << ":" << peer_info_.port << " is interested");
    
    // Automatically unchoke interested peers (optimistic unchoking)
    // In a more sophisticated implementation, we'd have a proper choke algorithm
    if (am_choking_) {
        set_choke(false);
        LOG_BT_DEBUG("Unchoked interested peer " << peer_info_.ip << ":" << peer_info_.port);
    }
}

void PeerConnection::handle_not_interested() {
    peer_interested_ = false;
    LOG_BT_DEBUG("Peer " << peer_info_.ip << ":" << peer_info_.port << " is not interested");
}

void PeerConnection::handle_have(const std::vector<uint8_t>& payload) {
    if (payload.size() != 4) {
        LOG_BT_WARN("Invalid HAVE message size: " << payload.size());
        return;
    }
    
    PieceIndex piece_index = (static_cast<uint32_t>(payload[0]) << 24) | 
                              (static_cast<uint32_t>(payload[1]) << 16) | 
                              (static_cast<uint32_t>(payload[2]) << 8) | 
                              static_cast<uint32_t>(payload[3]);
    
    if (piece_index < peer_bitfield_.size()) {
        peer_bitfield_[piece_index] = true;
        LOG_BT_DEBUG("Peer " << peer_info_.ip << ":" << peer_info_.port << " has piece " << piece_index);
    }
}

void PeerConnection::handle_bitfield(const std::vector<uint8_t>& payload) {
    const auto& torrent_info = torrent_->get_torrent_info();
    uint32_t num_pieces = torrent_info.get_num_pieces();
    
    peer_bitfield_.clear();
    peer_bitfield_.resize(num_pieces, false);
    
    for (uint32_t i = 0; i < num_pieces && i / 8 < payload.size(); ++i) {
        size_t byte_index = i / 8;
        size_t bit_index = 7 - (i % 8);
        peer_bitfield_[i] = (payload[byte_index] & (1 << bit_index)) != 0;
    }
    
    LOG_BT_DEBUG("Received bitfield from peer " << peer_info_.ip << ":" << peer_info_.port);
}

void PeerConnection::handle_request(const std::vector<uint8_t>& payload) {
    if (payload.size() != 12) {
        LOG_BT_WARN("Invalid REQUEST message size: " << payload.size());
        return;
    }
    
    PieceIndex piece_index = (static_cast<uint32_t>(payload[0]) << 24) | 
                              (static_cast<uint32_t>(payload[1]) << 16) | 
                              (static_cast<uint32_t>(payload[2]) << 8) | 
                              static_cast<uint32_t>(payload[3]);
    uint32_t offset = (static_cast<uint32_t>(payload[4]) << 24) | 
                      (static_cast<uint32_t>(payload[5]) << 16) | 
                      (static_cast<uint32_t>(payload[6]) << 8) | 
                      static_cast<uint32_t>(payload[7]);
    uint32_t length = (static_cast<uint32_t>(payload[8]) << 24) | 
                      (static_cast<uint32_t>(payload[9]) << 16) | 
                      (static_cast<uint32_t>(payload[10]) << 8) | 
                      static_cast<uint32_t>(payload[11]);
    
    LOG_BT_DEBUG("Peer " << peer_info_.ip << ":" << peer_info_.port << " requested piece " << piece_index << " offset " << offset << " length " << length);
    
    // Check if we're choking this peer
    if (am_choking_) {
        LOG_BT_DEBUG("Ignoring request from choked peer " << peer_info_.ip << ":" << peer_info_.port);
        return;
    }
    
    // Validate request parameters
    const auto& torrent_info = torrent_->get_torrent_info();
    if (piece_index >= torrent_info.get_num_pieces()) {
        LOG_BT_WARN("Invalid piece index requested: " << piece_index);
        return;
    }
    
    uint32_t piece_length = torrent_info.get_piece_length(piece_index);
    if (offset >= piece_length || offset + length > piece_length) {
        LOG_BT_WARN("Invalid offset/length in request: offset=" << offset << " length=" << length << " piece_length=" << piece_length);
        return;
    }
    
    // Validate request length (up to BLOCK_SIZE, smaller is allowed for last block)
    if (length > BLOCK_SIZE || length == 0) {
        LOG_BT_WARN("Invalid request length: " << length);
        return;
    }
    
    // Check if we have this piece
    if (!torrent_->is_piece_complete(piece_index)) {
        LOG_BT_DEBUG("Don't have piece " << piece_index << " yet, can't serve to peer");
        return;
    }
    
    // Read the piece from disk
    std::vector<uint8_t> piece_data;
    if (!torrent_->read_piece_from_disk(piece_index, piece_data)) {
        LOG_BT_ERROR("Failed to read piece " << piece_index << " from disk for upload");
        return;
    }
    
    // Extract the requested block
    if (offset + length > piece_data.size()) {
        LOG_BT_ERROR("Block exceeds piece data size: offset=" << offset << " length=" << length << " piece_size=" << piece_data.size());
        return;
    }
    
    std::vector<uint8_t> block_data(piece_data.begin() + offset, piece_data.begin() + offset + length);
    
    // Send the piece message
    auto piece_msg = PeerMessage::create_piece(piece_index, offset, block_data);
    if (send_message(piece_msg)) {
        uploaded_bytes_ += block_data.size();
        LOG_BT_DEBUG("Sent piece " << piece_index << " offset " << offset << " length " << length << " to peer " << peer_info_.ip << ":" << peer_info_.port);
    } else {
        LOG_BT_ERROR("Failed to send piece data to peer " << peer_info_.ip << ":" << peer_info_.port);
    }
}

void PeerConnection::handle_piece(const std::vector<uint8_t>& payload) {
    if (payload.size() < 8) {
        LOG_BT_WARN("Invalid PIECE message size: " << payload.size());
        return;
    }
    
    PieceIndex piece_index = (static_cast<uint32_t>(payload[0]) << 24) | 
                              (static_cast<uint32_t>(payload[1]) << 16) | 
                              (static_cast<uint32_t>(payload[2]) << 8) | 
                              static_cast<uint32_t>(payload[3]);
    uint32_t offset = (static_cast<uint32_t>(payload[4]) << 24) | 
                      (static_cast<uint32_t>(payload[5]) << 16) | 
                      (static_cast<uint32_t>(payload[6]) << 8) | 
                      static_cast<uint32_t>(payload[7]);
    
    std::vector<uint8_t> block_data(payload.begin() + 8, payload.end());
    downloaded_bytes_ += block_data.size();
    
    LOG_BT_DEBUG("Received piece " << piece_index << " offset " << offset << " length " << block_data.size() << " from peer " << peer_info_.ip << ":" << peer_info_.port);
    
    // Store the piece block
    if (torrent_->store_piece_block(piece_index, offset, block_data)) {
        // Remove corresponding request
        std::lock_guard<std::mutex> lock(requests_mutex_);
        pending_requests_.erase(
            std::remove_if(pending_requests_.begin(), pending_requests_.end(),
                [piece_index, offset](const PeerRequest& req) {
                    return req.piece_index == piece_index && req.offset == offset;
                }),
            pending_requests_.end());
    }
}

void PeerConnection::handle_cancel(const std::vector<uint8_t>& payload) {
    if (payload.size() != 12) {
        LOG_BT_WARN("Invalid CANCEL message size: " << payload.size());
        return;
    }
    
    PieceIndex piece_index = (static_cast<uint32_t>(payload[0]) << 24) | 
                              (static_cast<uint32_t>(payload[1]) << 16) | 
                              (static_cast<uint32_t>(payload[2]) << 8) | 
                              static_cast<uint32_t>(payload[3]);
    uint32_t offset = (static_cast<uint32_t>(payload[4]) << 24) | 
                      (static_cast<uint32_t>(payload[5]) << 16) | 
                      (static_cast<uint32_t>(payload[6]) << 8) | 
                      static_cast<uint32_t>(payload[7]);
    uint32_t length = (static_cast<uint32_t>(payload[8]) << 24) | 
                      (static_cast<uint32_t>(payload[9]) << 16) | 
                      (static_cast<uint32_t>(payload[10]) << 8) | 
                      static_cast<uint32_t>(payload[11]);
    
    LOG_BT_DEBUG("Peer " << peer_info_.ip << ":" << peer_info_.port << " cancelled request for piece " << piece_index << " offset " << offset << " length " << length);
    
    // Note: For a simple implementation, we don't queue outgoing requests
    // If we were queuing them, we'd remove this request from the queue here
    // For now, just acknowledge the cancel
}

void PeerConnection::handle_extended(const std::vector<uint8_t>& payload) {
    if (payload.empty()) {
        LOG_BT_WARN("Empty extended message payload");
        return;
    }
    
    uint8_t extended_id = payload[0];
    std::vector<uint8_t> extended_payload(payload.begin() + 1, payload.end());
    
    LOG_BT_DEBUG("Received extended message with ID " << static_cast<int>(extended_id) << " from peer " << peer_info_.ip << ":" << peer_info_.port);
    
    if (extended_id == static_cast<uint8_t>(ExtendedMessageType::HANDSHAKE)) {
        handle_extended_handshake(extended_payload);
    } else if (extended_id == static_cast<uint8_t>(ExtendedMessageType::UT_METADATA) && supports_metadata_exchange_) {
        // Note: Peers send messages using OUR extension ID (what we advertised in our handshake),
        // not their ID. We use peer_ut_metadata_id_ only when SENDING to them.
        handle_metadata_message(extended_payload);
    } else {
        LOG_BT_DEBUG("Unknown or unsupported extended message ID: " << static_cast<int>(extended_id));
    }
}

void PeerConnection::send_extended_handshake() {
    // Create extended handshake bencode dictionary
    BencodeValue handshake = BencodeValue::create_dict();
    
    // Add supported extensions
    BencodeValue extensions = BencodeValue::create_dict();
    extensions["ut_metadata"] = BencodeValue::create_integer(static_cast<uint8_t>(ExtendedMessageType::UT_METADATA));
    handshake["m"] = extensions;
    
    // Add metadata size if we have metadata download
    auto* metadata_download = torrent_->get_metadata_download();
    if (metadata_download) {
        handshake["metadata_size"] = BencodeValue::create_integer(static_cast<int64_t>(metadata_download->get_metadata_size()));
    }
    
    // Encode the handshake
    std::vector<uint8_t> encoded = handshake.encode();
    
    // Create extended message payload: [extended_id][bencode_data]
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>(ExtendedMessageType::HANDSHAKE));
    payload.insert(payload.end(), encoded.begin(), encoded.end());
    
    // Send as extended message
    PeerMessage message(MessageType::EXTENDED, payload);
    send_message(message);
    
    LOG_BT_DEBUG("Sent extended handshake to peer " << peer_info_.ip << ":" << peer_info_.port);
}

void PeerConnection::send_bitfield() {
    // Get our bitfield from the torrent
    std::vector<bool> our_bitfield = torrent_->get_piece_bitfield();
    
    // Don't send empty bitfield or if we have no pieces
    bool has_any_piece = false;
    for (bool has_piece : our_bitfield) {
        if (has_piece) {
            has_any_piece = true;
            break;
        }
    }
    
    if (!has_any_piece) {
        LOG_BT_DEBUG("No pieces to advertise to peer " << peer_info_.ip << ":" << peer_info_.port);
        return;
    }
    
    // Create and send bitfield message
    auto bitfield_msg = PeerMessage::create_bitfield(our_bitfield);
    if (send_message(bitfield_msg)) {
        LOG_BT_DEBUG("Sent bitfield to peer " << peer_info_.ip << ":" << peer_info_.port);
    } else {
        LOG_BT_WARN("Failed to send bitfield to peer " << peer_info_.ip << ":" << peer_info_.port);
    }
}

void PeerConnection::handle_extended_handshake(const std::vector<uint8_t>& payload) {
    LOG_BT_DEBUG("Handling extended handshake from peer " << peer_info_.ip << ":" << peer_info_.port);
    
    try {
        BencodeValue handshake = bencode::decode(payload);
        
        if (!handshake.is_dict()) {
            LOG_BT_WARN("Extended handshake is not a dictionary");
            return;
        }
        
        // Check if peer supports ut_metadata extension
        if (handshake.has_key("m")) {
            const auto& extensions = handshake["m"];
            if (extensions.is_dict() && extensions.has_key("ut_metadata")) {
                peer_ut_metadata_id_ = static_cast<uint8_t>(extensions["ut_metadata"].as_integer());
                supports_metadata_exchange_ = true;
                LOG_BT_INFO("Peer " << peer_info_.ip << ":" << peer_info_.port 
                            << " supports metadata exchange (ID: " << static_cast<int>(peer_ut_metadata_id_) << ")");
            }
        }
        
        // Get metadata size if available
        if (handshake.has_key("metadata_size")) {
            peer_metadata_size_ = static_cast<size_t>(handshake["metadata_size"].as_integer());
            LOG_BT_DEBUG("Peer has metadata size: " << peer_metadata_size_ << " bytes");
            
            // Check if we need to create a metadata download
            auto* metadata_download = torrent_->get_metadata_download();
            
            if (!metadata_download && peer_metadata_size_ > 0 && peer_metadata_size_ <= MAX_METADATA_SIZE) {
                // Create metadata download with the correct size
                const auto& info_hash = torrent_->get_torrent_info().get_info_hash();
                LOG_BT_INFO("Creating metadata download for hash " << info_hash_to_hex(info_hash) 
                           << " with size " << peer_metadata_size_ << " bytes");
                
                auto new_metadata_download = std::make_shared<MetadataDownload>(info_hash, peer_metadata_size_);
                
                // Set completion callback - need to use a custom approach since we need to call back through TorrentDownload
                // For now, we'll leave the completion callback to be set by add_torrent_by_hash after metadata download is created
                // The BitTorrentClient will need to monitor metadata downloads and set their callbacks appropriately
                
                torrent_->set_metadata_download(new_metadata_download);
                metadata_download = new_metadata_download.get();
                
                LOG_BT_INFO("Metadata download created and ready");
            }
            
            // If we are downloading metadata, start requesting pieces
            if (metadata_download && supports_metadata_exchange_) {
                // Request first metadata piece
                uint32_t next_piece = metadata_download->get_next_piece_to_request();
                if (next_piece < metadata_download->get_num_pieces()) {
                    request_metadata_piece(next_piece);
                }
            }
        }
        
    } catch (const std::exception& e) {
        LOG_BT_ERROR("Failed to parse extended handshake: " << e.what());
    }
}

void PeerConnection::handle_metadata_message(const std::vector<uint8_t>& payload) {
    LOG_BT_DEBUG("Handling metadata message from peer " << peer_info_.ip << ":" << peer_info_.port);
    
    try {
        // Decode bencode dictionary at the start of payload
        BencodeValue msg_dict = bencode::decode(payload);
        
        if (!msg_dict.is_dict()) {
            LOG_BT_WARN("Metadata message is not a dictionary");
            return;
        }
        
        if (!msg_dict.has_key("msg_type") || !msg_dict.has_key("piece")) {
            LOG_BT_WARN("Metadata message missing required fields");
            return;
        }
        
        uint8_t msg_type = static_cast<uint8_t>(msg_dict["msg_type"].as_integer());
        uint32_t piece_index = static_cast<uint32_t>(msg_dict["piece"].as_integer());
        
        LOG_BT_DEBUG("Metadata message type: " << static_cast<int>(msg_type) << ", piece: " << piece_index);
        
        auto* metadata_download = torrent_->get_metadata_download();
        if (!metadata_download) {
            LOG_BT_DEBUG("No metadata download in progress, ignoring metadata message");
            return;
        }
        
        if (msg_type == static_cast<uint8_t>(MetadataMessageType::DATA)) {
            // Extract metadata piece data (comes after bencode dictionary)
            std::vector<uint8_t> encoded = msg_dict.encode();
            if (payload.size() <= encoded.size()) {
                LOG_BT_WARN("Metadata DATA message has no piece data");
                return;
            }
            
            std::vector<uint8_t> piece_data(payload.begin() + encoded.size(), payload.end());
            
            LOG_BT_INFO("Received metadata piece " << piece_index << " (" << piece_data.size() << " bytes) from peer " 
                        << peer_info_.ip << ":" << peer_info_.port);
            
            // Store the piece
            if (metadata_download->store_metadata_piece(piece_index, piece_data)) {
                // Request next piece if available
                if (!metadata_download->is_complete()) {
                    uint32_t next_piece = metadata_download->get_next_piece_to_request();
                    if (next_piece < metadata_download->get_num_pieces()) {
                        request_metadata_piece(next_piece);
                    }
                }
            }
        } else if (msg_type == static_cast<uint8_t>(MetadataMessageType::REJECT)) {
            LOG_BT_WARN("Peer " << peer_info_.ip << ":" << peer_info_.port 
                        << " rejected metadata piece " << piece_index << " request");
        }
        
    } catch (const std::exception& e) {
        LOG_BT_ERROR("Failed to parse metadata message: " << e.what());
    }
}

void PeerConnection::request_metadata_piece(uint32_t piece_index) {
    if (!supports_metadata_exchange_) {
        LOG_BT_WARN("Peer does not support metadata exchange");
        return;
    }
    
    LOG_BT_DEBUG("Requesting metadata piece " << piece_index << " from peer " << peer_info_.ip << ":" << peer_info_.port);
    
    // Create metadata request message
    BencodeValue msg_dict = BencodeValue::create_dict();
    msg_dict["msg_type"] = BencodeValue::create_integer(static_cast<int>(MetadataMessageType::REQUEST));
    msg_dict["piece"] = BencodeValue::create_integer(piece_index);
    
    // Encode the message
    std::vector<uint8_t> encoded = msg_dict.encode();
    
    // Create extended message payload: [peer_ut_metadata_id][bencode_data]
    std::vector<uint8_t> payload;
    payload.push_back(peer_ut_metadata_id_);
    payload.insert(payload.end(), encoded.begin(), encoded.end());
    
    // Send as extended message
    PeerMessage message(MessageType::EXTENDED, payload);
    send_message(message);
}

bool PeerConnection::request_piece_block(PieceIndex piece_index, uint32_t offset, uint32_t length) {
    if (peer_choked_ || state_ != PeerState::CONNECTED) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(requests_mutex_);
    
    if (pending_requests_.size() >= MAX_REQUESTS_PER_PEER) {
        return false;  // Too many pending requests
    }
    
    auto request_msg = PeerMessage::create_request(piece_index, offset, length);
    if (send_message(request_msg)) {
        pending_requests_.emplace_back(piece_index, offset, length);
        LOG_BT_DEBUG("Requested piece " << piece_index << " offset " << offset << " length " << length << " from peer " << peer_info_.ip << ":" << peer_info_.port);
        return true;
    }
    
    return false;
}

bool PeerConnection::is_block_requested(PieceIndex piece_index, uint32_t offset) const {
    std::lock_guard<std::mutex> lock(requests_mutex_);
    for (const auto& req : pending_requests_) {
        if (req.piece_index == piece_index && req.offset == offset) {
            return true;
        }
    }
    return false;
}

void PeerConnection::cancel_request(PieceIndex piece_index, uint32_t offset, uint32_t length) {
    auto cancel_msg = PeerMessage::create_cancel(piece_index, offset, length);
    send_message(cancel_msg);
    
    {
        std::lock_guard<std::mutex> lock(requests_mutex_);
        pending_requests_.erase(
            std::remove_if(pending_requests_.begin(), pending_requests_.end(),
                [piece_index, offset, length](const PeerRequest& req) {
                    return req.piece_index == piece_index && req.offset == offset && req.length == length;
                }),
            pending_requests_.end());
    }
    
    // Reset block request status so block can be requested from other peers
    uint32_t block_index = offset / BLOCK_SIZE;
    torrent_->reset_block_request(piece_index, block_index);
}

void PeerConnection::cancel_all_requests() {
    std::vector<PeerRequest> requests_to_reset;
    
    {
        std::lock_guard<std::mutex> lock(requests_mutex_);
        
        for (const auto& request : pending_requests_) {
            auto cancel_msg = PeerMessage::create_cancel(request.piece_index, request.offset, request.length);
            send_message(cancel_msg);
            requests_to_reset.push_back(request);
        }
        
        pending_requests_.clear();
    }
    
    // Reset block request status so blocks can be requested from other peers
    for (const auto& req : requests_to_reset) {
        uint32_t block_index = req.offset / BLOCK_SIZE;
        torrent_->reset_block_request(req.piece_index, block_index);
    }
}

void PeerConnection::set_interested(bool interested) {
    if (am_interested_ != interested) {
        am_interested_ = interested;
        auto msg = interested ? PeerMessage::create_interested() : PeerMessage::create_not_interested();
        send_message(msg);
    }
}

void PeerConnection::set_choke(bool choke) {
    if (am_choking_ != choke) {
        am_choking_ = choke;
        auto msg = choke ? PeerMessage::create_choke() : PeerMessage::create_unchoke();
        send_message(msg);
    }
}

bool PeerConnection::has_piece(PieceIndex piece_index) const {
    return piece_index < peer_bitfield_.size() && peer_bitfield_[piece_index];
}

void PeerConnection::update_bitfield(const std::vector<bool>& bitfield) {
    peer_bitfield_ = bitfield;
}

void PeerConnection::cleanup_expired_requests() {
    std::vector<PeerRequest> expired_requests;
    
    {
        std::lock_guard<std::mutex> lock(requests_mutex_);
        
        auto now = std::chrono::steady_clock::now();
        auto timeout = std::chrono::milliseconds(REQUEST_TIMEOUT_MS);
        
        // Collect expired requests before removing them
        for (const auto& req : pending_requests_) {
            if (now - req.requested_at > timeout) {
                expired_requests.push_back(req);
            }
        }
        
        pending_requests_.erase(
            std::remove_if(pending_requests_.begin(), pending_requests_.end(),
                [now, timeout](const PeerRequest& req) {
                    return now - req.requested_at > timeout;
                }),
            pending_requests_.end());
    }
    
    // Reset block request status for expired requests (so they can be requested again)
    for (const auto& req : expired_requests) {
        uint32_t block_index = req.offset / BLOCK_SIZE;
        torrent_->reset_block_request(req.piece_index, block_index);
        LOG_BT_DEBUG("Request timeout: piece " << req.piece_index << " block " << block_index 
                     << " from peer " << peer_info_.ip << ":" << peer_info_.port);
    }
}

void PeerConnection::update_speed_stats() {
    std::lock_guard<std::mutex> lock(speed_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    double elapsed_seconds = std::chrono::duration<double>(now - last_speed_update_time_).count();
    
    // Update speed every second at minimum to avoid division by very small numbers
    if (elapsed_seconds >= 1.0) {
        uint64_t current_downloaded = downloaded_bytes_.load();
        uint64_t current_uploaded = uploaded_bytes_.load();
        
        uint64_t downloaded_delta = current_downloaded - last_speed_downloaded_;
        uint64_t uploaded_delta = current_uploaded - last_speed_uploaded_;
        
        download_speed_.store(static_cast<double>(downloaded_delta) / elapsed_seconds);
        upload_speed_.store(static_cast<double>(uploaded_delta) / elapsed_seconds);
        
        last_speed_downloaded_ = current_downloaded;
        last_speed_uploaded_ = current_uploaded;
        last_speed_update_time_ = now;
    }
}

double PeerConnection::get_download_speed() const {
    return download_speed_.load();
}

double PeerConnection::get_upload_speed() const {
    return upload_speed_.load();
}

bool PeerConnection::read_data(std::vector<uint8_t>& buffer, size_t length) {
    if (!is_valid_socket(socket_)) {
        return false;
    }
    
    // Use the existing socket function to read exact bytes
    std::vector<uint8_t> data = receive_exact_bytes(socket_, length);
    if (data.size() != length) {
        // receive_exact_bytes returns empty on socket error or connection closed
        // If we got 0 bytes, the socket is likely dead - mark connection as error
        if (data.empty()) {
            LOG_BT_DEBUG("Socket read returned empty - connection likely closed by peer " 
                         << peer_info_.ip << ":" << peer_info_.port);
            state_.store(PeerState::ERROR);
        } else {
            LOG_BT_DEBUG("Failed to read exact amount of data from socket (got " 
                         << data.size() << " of " << length << " bytes)");
        }
        return false;
    }
    
    buffer = std::move(data);
    return true;
}

bool PeerConnection::write_data(const std::vector<uint8_t>& data) {
    if (!is_valid_socket(socket_)) {
        return false;
    }
    
    // Use the existing socket function for binary data directly
    int sent = send_tcp_data(socket_, data);
    return sent > 0 && static_cast<size_t>(sent) == data.size();
}

//=============================================================================
// MetadataDownload Implementation
//=============================================================================

MetadataDownload::MetadataDownload(const InfoHash& info_hash, size_t metadata_size)
    : info_hash_(info_hash), metadata_size_(metadata_size) {
    
    // Calculate number of pieces needed
    num_pieces_ = (metadata_size + METADATA_PIECE_SIZE - 1) / METADATA_PIECE_SIZE;
    
    // Initialize piece storage
    pieces_.resize(num_pieces_);
    pieces_complete_.resize(num_pieces_, false);
    
    LOG_BT_INFO("Created metadata download for info hash " << info_hash_to_hex(info_hash) 
                << " (size: " << metadata_size << " bytes, " << num_pieces_ << " pieces)");
}

MetadataDownload::~MetadataDownload() = default;

bool MetadataDownload::store_metadata_piece(uint32_t piece_index, const std::vector<uint8_t>& data) {
    MetadataCompleteCallback callback_to_invoke;
    TorrentInfo completed_torrent_info;
    bool should_invoke_callback = false;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (piece_index >= num_pieces_) {
            LOG_BT_ERROR("Invalid metadata piece index: " << piece_index << " (max: " << num_pieces_ - 1 << ")");
            return false;
        }
        
        // Calculate expected piece size
        size_t expected_size;
        if (piece_index == num_pieces_ - 1) {
            // Last piece might be smaller
            expected_size = metadata_size_ - (piece_index * METADATA_PIECE_SIZE);
        } else {
            expected_size = METADATA_PIECE_SIZE;
        }
        
        if (data.size() != expected_size) {
            LOG_BT_ERROR("Invalid metadata piece size for piece " << piece_index 
                         << ": expected " << expected_size << ", got " << data.size());
            return false;
        }
        
        pieces_[piece_index] = data;
        pieces_complete_[piece_index] = true;
        
        LOG_BT_DEBUG("Stored metadata piece " << piece_index << " (" << data.size() << " bytes)");
        
        // Check if download is complete and prepare callback data
        // (callback will be invoked outside of lock to prevent deadlock)
        bool all_complete = std::all_of(pieces_complete_.begin(), pieces_complete_.end(), 
                                        [](bool complete) { return complete; });
        
        if (all_complete) {
            LOG_BT_INFO("Metadata download complete for info hash " << info_hash_to_hex(info_hash_));
            
            // Verify metadata (use unlocked version since we already hold the mutex)
            if (verify_metadata_unlocked()) {
                // Parse metadata into TorrentInfo (use unlocked version)
                std::vector<uint8_t> metadata = get_metadata_unlocked();
                
                try {
                    BencodeValue info_dict = bencode::decode(metadata);
                    
                    // Create a fake torrent dictionary with just the info dict
                    BencodeValue torrent_data = BencodeValue::create_dict();
                    torrent_data["info"] = info_dict;
                    
                    if (completed_torrent_info.load_from_bencode(torrent_data)) {
                        callback_to_invoke = completion_callback_;
                        should_invoke_callback = true;
                    } else {
                        LOG_BT_ERROR("Failed to parse metadata into TorrentInfo");
                    }
                } catch (const std::exception& e) {
                    LOG_BT_ERROR("Failed to decode metadata: " << e.what());
                }
            } else {
                LOG_BT_ERROR("Metadata verification failed - hash mismatch");
            }
        }
    }  // mutex_ released here
    
    // Invoke callback OUTSIDE of lock to prevent deadlock
    // (as documented: "never call callbacks while holding this mutex!")
    if (should_invoke_callback && callback_to_invoke) {
        callback_to_invoke(completed_torrent_info);
    }
    
    return true;
}

bool MetadataDownload::is_complete() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::all_of(pieces_complete_.begin(), pieces_complete_.end(), [](bool complete) { return complete; });
}

std::vector<uint8_t> MetadataDownload::get_metadata_unlocked() const {
    // Internal version - must be called with mutex_ already held
    std::vector<uint8_t> metadata;
    metadata.reserve(metadata_size_);
    
    for (const auto& piece : pieces_) {
        metadata.insert(metadata.end(), piece.begin(), piece.end());
    }
    
    return metadata;
}

std::vector<uint8_t> MetadataDownload::get_metadata() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return get_metadata_unlocked();
}

bool MetadataDownload::verify_metadata_unlocked() const {
    // Internal version - must be called with mutex_ already held
    
    // Reconstruct full metadata
    std::vector<uint8_t> metadata;
    metadata.reserve(metadata_size_);
    
    for (const auto& piece : pieces_) {
        metadata.insert(metadata.end(), piece.begin(), piece.end());
    }
    
    // Calculate SHA1 hash
    std::string calculated_hash = SHA1::hash_bytes(metadata);
    
    // Convert stored info hash to hex string for comparison
    std::ostringstream stored_hash_hex;
    for (size_t i = 0; i < info_hash_.size(); ++i) {
        stored_hash_hex << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(info_hash_[i]);
    }
    
    bool verified = (calculated_hash == stored_hash_hex.str());
    
    if (verified) {
        LOG_BT_INFO("Metadata verification PASSED for info hash " << info_hash_to_hex(info_hash_));
    } else {
        LOG_BT_ERROR("Metadata verification FAILED for info hash " << info_hash_to_hex(info_hash_));
        LOG_BT_ERROR("  Expected: " << stored_hash_hex.str());
        LOG_BT_ERROR("  Calculated: " << calculated_hash);
    }
    
    return verified;
}

bool MetadataDownload::verify_metadata() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return verify_metadata_unlocked();
}

uint32_t MetadataDownload::get_next_piece_to_request() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (uint32_t i = 0; i < num_pieces_; ++i) {
        if (!pieces_complete_[i]) {
            return i;
        }
    }
    
    return num_pieces_;  // All pieces complete
}

bool MetadataDownload::is_piece_complete(uint32_t piece_index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (piece_index >= num_pieces_) {
        return false;
    }
    
    return pieces_complete_[piece_index];
}

//=============================================================================
// TorrentDownload Implementation
//=============================================================================

TorrentDownload::TorrentDownload(const TorrentInfo& torrent_info, const std::string& download_path)
    : torrent_info_(torrent_info), download_path_(download_path), 
      running_(false), paused_(false), total_downloaded_(0), total_uploaded_(0),
      last_speed_update_time_(std::chrono::steady_clock::now()),
      last_speed_downloaded_(0), last_speed_uploaded_(0),
      download_speed_(0.0), upload_speed_(0.0),
      last_logged_progress_(0.0), last_state_log_time_(std::chrono::steady_clock::now()) {
    
    // Initialize pieces
    uint32_t num_pieces = torrent_info_.get_num_pieces();
    pieces_.reserve(num_pieces);
    piece_completed_.resize(num_pieces, false);
    piece_downloading_.resize(num_pieces, false);
    
    const auto& piece_hashes = torrent_info_.get_piece_hashes();
    for (uint32_t i = 0; i < num_pieces; ++i) {
        uint32_t piece_length = torrent_info_.get_piece_length(i);
        pieces_.push_back(std::make_unique<PieceInfo>(i, piece_hashes[i], piece_length));
    }
    
    // Generate peer ID
    our_peer_id_ = generate_peer_id();
    
    // Create tracker manager
    tracker_manager_ = std::make_unique<TrackerManager>(torrent_info_);
    
    LOG_BT_INFO("Created torrent download for: " << torrent_info_.get_name());
    LOG_BT_INFO("  Download path: " << download_path_);
    LOG_BT_INFO("  Total size: " << torrent_info_.get_total_length() << " bytes");
    LOG_BT_INFO("  Number of pieces: " << num_pieces);
    LOG_BT_INFO("  Trackers: " << tracker_manager_->get_tracker_urls().size());
}

TorrentDownload::~TorrentDownload() {
    stop();
}

bool TorrentDownload::start() {
    if (running_) {
        return true;
    }
    
    LOG_BT_INFO("Starting torrent download: " << torrent_info_.get_name());
    
    // Skip file/directory operations for metadata-only downloads (empty download path)
    if (!download_path_.empty()) {
        // Create directory structure
        if (!create_directory_structure()) {
            LOG_BT_ERROR("Failed to create directory structure");
            return false;
        }
        
        // Open files
        if (!open_files()) {
            LOG_BT_ERROR("Failed to open files");
            return false;
        }
    } else {
        LOG_BT_DEBUG("Skipping file operations for metadata-only torrent");
    }
    
    running_ = true;
    paused_ = false;
    
    // Start download threads
    download_thread_ = std::thread(&TorrentDownload::download_loop, this);
    peer_management_thread_ = std::thread(&TorrentDownload::peer_management_loop, this);
    
    LOG_BT_INFO("Torrent download started: " << torrent_info_.get_name());
    return true;
}

void TorrentDownload::stop() {
    if (!running_) {
        return;
    }
    
    LOG_BT_INFO("Stopping torrent download: " << torrent_info_.get_name());
    
    running_ = false;
    
    // Stop all peer connections
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto& peer : peer_connections_) {
            peer->disconnect();
        }
        peer_connections_.clear();
    }
    
    // Wait for threads to finish
    if (download_thread_.joinable()) {
        download_thread_.join();
    }
    if (peer_management_thread_.joinable()) {
        peer_management_thread_.join();
    }
    
    // Close files
    close_files();
    
    LOG_BT_INFO("Torrent download stopped: " << torrent_info_.get_name());
}

void TorrentDownload::pause() {
    paused_ = true;
    LOG_BT_INFO("Paused torrent download: " << torrent_info_.get_name());
}

void TorrentDownload::resume() {
    paused_ = false;
    LOG_BT_INFO("Resumed torrent download: " << torrent_info_.get_name());
}

bool TorrentDownload::is_complete() const {
    std::lock_guard<std::mutex> lock(pieces_mutex_);
    return std::all_of(piece_completed_.begin(), piece_completed_.end(), [](bool completed) { return completed; });
}

bool TorrentDownload::add_peer(const Peer& peer) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    // Check if peer already exists
    for (const auto& conn : peer_connections_) {
        if (conn->get_peer_info().ip == peer.ip && conn->get_peer_info().port == peer.port) {
            return false;  // Peer already exists
        }
    }
    
    // Check peer limit
    if (peer_connections_.size() >= MAX_PEERS_PER_TORRENT) {
        LOG_BT_DEBUG("Peer limit reached for torrent " << torrent_info_.get_name());
        return false;
    }
    
    // Create new peer connection
    auto peer_conn = std::make_unique<PeerConnection>(this, peer);
    if (peer_conn->connect()) {
        peer_connections_.push_back(std::move(peer_conn));
        
        if (peer_connected_callback_) {
            peer_connected_callback_(peer);
        }
        
        LOG_BT_INFO("Added peer " << peer.ip << ":" << peer.port << " to torrent " << torrent_info_.get_name());
        return true;
    }
    
    return false;
}

bool TorrentDownload::add_peer(const Peer& peer, socket_t existing_socket) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    // Check if peer already exists
    for (const auto& conn : peer_connections_) {
        if (conn->get_peer_info().ip == peer.ip && conn->get_peer_info().port == peer.port) {
            LOG_BT_DEBUG("Peer already exists: " << peer.ip << ":" << peer.port);
            close_socket(existing_socket);  // Close the duplicate incoming connection
            return false;
        }
    }
    
    // Check peer limit
    if (peer_connections_.size() >= MAX_PEERS_PER_TORRENT) {
        LOG_BT_DEBUG("Peer limit reached for torrent " << torrent_info_.get_name());
        close_socket(existing_socket);
        return false;
    }
    
    // Create peer connection with existing socket
    auto peer_conn = std::make_unique<PeerConnection>(this, peer, existing_socket);
    if (peer_conn->connect()) {
        peer_connections_.push_back(std::move(peer_conn));
        
        if (peer_connected_callback_) {
            peer_connected_callback_(peer);
        }
        
        LOG_BT_INFO("Added incoming peer " << peer.ip << ":" << peer.port << " to torrent " << torrent_info_.get_name());
        return true;
    }
    
    return false;
}

void TorrentDownload::remove_peer(const Peer& peer) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    peer_connections_.erase(
        std::remove_if(peer_connections_.begin(), peer_connections_.end(),
            [&peer](const std::unique_ptr<PeerConnection>& conn) {
                return conn->get_peer_info().ip == peer.ip && conn->get_peer_info().port == peer.port;
            }),
        peer_connections_.end());
    
    if (peer_disconnected_callback_) {
        peer_disconnected_callback_(peer);
    }
    
    LOG_BT_DEBUG("Removed peer " << peer.ip << ":" << peer.port << " from torrent " << torrent_info_.get_name());
}

size_t TorrentDownload::get_peer_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return peer_connections_.size();
}

std::vector<Peer> TorrentDownload::get_connected_peers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    std::vector<Peer> peers;
    for (const auto& conn : peer_connections_) {
        if (conn->is_connected()) {
            peers.push_back(conn->get_peer_info());
        }
    }
    
    return peers;
}

bool TorrentDownload::is_piece_complete(PieceIndex piece_index) const {
    std::lock_guard<std::mutex> lock(pieces_mutex_);
    return piece_index < piece_completed_.size() && piece_completed_[piece_index];
}

bool TorrentDownload::is_piece_downloading(PieceIndex piece_index) const {
    std::lock_guard<std::mutex> lock(pieces_mutex_);
    return piece_index < piece_downloading_.size() && piece_downloading_[piece_index];
}

bool TorrentDownload::store_piece_block(PieceIndex piece_index, uint32_t offset, const std::vector<uint8_t>& data) {
    bool piece_just_completed = false;
    bool verification_failed = false;
    
    {
        std::lock_guard<std::mutex> lock(pieces_mutex_);
        
        if (piece_index >= pieces_.size()) {
            LOG_BT_ERROR("Invalid piece index: " << piece_index);
            return false;
        }
        
        auto& piece = pieces_[piece_index];
        
        // Validate offset and data size
        if (offset + data.size() > piece->length) {
            LOG_BT_ERROR("Block data exceeds piece length for piece " << piece_index);
            return false;
        }
        
        // Calculate block index
        uint32_t block_index = offset / BLOCK_SIZE;
        if (block_index >= piece->get_num_blocks()) {
            LOG_BT_ERROR("Invalid block index: " << block_index << " for piece " << piece_index);
            return false;
        }
        
        // Ensure piece data buffer is allocated (lazy allocation)
        piece->ensure_data_allocated();
        
        // Store the block data
        std::copy(data.begin(), data.end(), piece->data.begin() + offset);
        piece->blocks_downloaded[block_index] = true;
        
        LOG_BT_DEBUG("Stored block " << block_index << " for piece " << piece_index 
                     << " (offset: " << offset << ", size: " << data.size() << ")");
        
        // Check if piece is complete
        if (piece->is_complete() && !piece->verified) {
            LOG_BT_INFO("Piece " << piece_index << " downloaded, verifying...");
            if (verify_piece(piece_index)) {
                piece_completed_[piece_index] = true;
                piece_downloading_[piece_index] = false;
                
                // Write piece to disk (files_mutex_ is after pieces_mutex_ in lock order)
                write_piece_to_disk(piece_index);
                
                // Update statistics
                total_downloaded_ += piece->length;
                
                piece_just_completed = true;
                LOG_BT_INFO("Piece " << piece_index << " verified and saved");
            } else {
                LOG_BT_ERROR("Piece " << piece_index << " verification failed, requesting re-download");
                // Reset piece for re-download - must reset both downloaded and requested status
                std::fill(piece->blocks_downloaded.begin(), piece->blocks_downloaded.end(), false);
                std::fill(piece->blocks_requested.begin(), piece->blocks_requested.end(), false);
                piece_downloading_[piece_index] = false;
                verification_failed = true;
            }
        }
    }  // pieces_mutex_ released here
    
    // Notify completion AFTER releasing pieces_mutex_ to respect lock order:
    // peers_mutex_ -> pieces_mutex_
    if (piece_just_completed) {
        on_piece_completed(piece_index);
    }
    
    return !verification_failed;
}

bool TorrentDownload::verify_piece(PieceIndex piece_index) {
    if (piece_index >= pieces_.size()) {
        return false;
    }
    
    auto& piece = pieces_[piece_index];
    
    // Check that piece data is allocated
    if (piece->data.empty()) {
        LOG_BT_ERROR("Cannot verify piece " << piece_index << " - data not allocated");
        return false;
    }
    
    // Calculate SHA1 hash of piece data
    std::string calculated_hash = SHA1::hash_bytes(piece->data);
    
    // Convert stored hash to hex string for comparison
    std::ostringstream stored_hash_hex;
    for (size_t i = 0; i < piece->hash.size(); ++i) {
        stored_hash_hex << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(piece->hash[i]);
    }
    
    bool verified = (calculated_hash == stored_hash_hex.str());
    piece->verified = verified;
    
    LOG_BT_DEBUG("Piece " << piece_index << " verification: " << (verified ? "PASSED" : "FAILED"));
    return verified;
}

void TorrentDownload::write_piece_to_disk(PieceIndex piece_index) {
    std::lock_guard<std::mutex> lock(files_mutex_);
    
    // Skip for metadata-only torrents
    if (download_path_.empty()) {
        return;
    }
    
    if (piece_index >= pieces_.size()) {
        LOG_BT_ERROR("Invalid piece index for disk write: " << piece_index);
        return;
    }
    
    auto& piece = pieces_[piece_index];
    if (!piece->verified) {
        LOG_BT_ERROR("Attempting to write unverified piece " << piece_index << " to disk");
        return;
    }
    
    // Calculate piece offset in the torrent
    uint64_t piece_offset = static_cast<uint64_t>(piece_index) * torrent_info_.get_piece_length();
    uint64_t remaining_data = piece->length;
    uint64_t data_offset = 0;
    
    // Write piece data to the appropriate files
    for (const auto& file_info : torrent_info_.get_files()) {
        if (piece_offset >= file_info.offset + file_info.length) {
            continue; // This piece doesn't overlap with this file
        }
        
        if (piece_offset + piece->length <= file_info.offset) {
            break; // No more files will be affected by this piece
        }
        
        // Calculate overlap
        uint64_t file_start_in_piece = (file_info.offset > piece_offset) ? 
                                      file_info.offset - piece_offset : 0;
        uint64_t piece_end = piece_offset + piece->length;
        uint64_t file_end = file_info.offset + file_info.length;
        uint64_t write_end = (std::min)(piece_end, file_end);
        uint64_t write_length = write_end - (piece_offset + file_start_in_piece);
        
        if (write_length == 0) {
            continue;
        }
        
        // Calculate file offset
        uint64_t file_offset = (piece_offset > file_info.offset) ? 
                              piece_offset - file_info.offset : 0;
        
        // Write data chunk to file using fs module
        std::string file_path = download_path_ + "/" + file_info.path;
        const void* write_data = piece->data.data() + file_start_in_piece;
        
        if (!write_file_chunk(file_path.c_str(), file_offset, write_data, write_length)) {
            LOG_BT_ERROR("Failed to write data to file: " << file_path);
            continue;
        }
        
        LOG_BT_DEBUG("Wrote " << write_length << " bytes to file " << file_info.path 
                     << " at offset " << file_offset);
    }
    
    // Free piece data from memory after successful write to disk
    piece->free_data();
    LOG_BT_DEBUG("Freed piece " << piece_index << " data from memory after write to disk");
}

bool TorrentDownload::read_piece_from_disk(PieceIndex piece_index, std::vector<uint8_t>& data) {
    // Lock order: pieces_mutex_ -> files_mutex_
    std::lock_guard<std::mutex> pieces_lock(pieces_mutex_);
    std::lock_guard<std::mutex> files_lock(files_mutex_);
    
    // Skip for metadata-only torrents
    if (download_path_.empty()) {
        return false;
    }
    
    if (piece_index >= pieces_.size()) {
        LOG_BT_ERROR("Invalid piece index for disk read: " << piece_index);
        return false;
    }
    
    // Check if piece is complete
    if (!piece_completed_[piece_index]) {
        LOG_BT_DEBUG("Piece " << piece_index << " is not complete, can't read from disk");
        return false;
    }
    
    auto& piece = pieces_[piece_index];
    
    // Allocate buffer for piece data
    data.resize(piece->length);
    
    // Calculate piece offset in the torrent
    uint64_t piece_offset = static_cast<uint64_t>(piece_index) * torrent_info_.get_piece_length();
    uint64_t data_offset = 0;
    
    // Read piece data from the appropriate files
    for (const auto& file_info : torrent_info_.get_files()) {
        if (piece_offset >= file_info.offset + file_info.length) {
            continue; // This piece doesn't overlap with this file
        }
        
        if (piece_offset + piece->length <= file_info.offset) {
            break; // No more files will be affected by this piece
        }
        
        // Calculate overlap
        uint64_t file_start_in_piece = (file_info.offset > piece_offset) ? 
                                      file_info.offset - piece_offset : 0;
        uint64_t piece_end = piece_offset + piece->length;
        uint64_t file_end = file_info.offset + file_info.length;
        uint64_t read_end = (std::min)(piece_end, file_end);
        uint64_t read_length = read_end - (piece_offset + file_start_in_piece);
        
        if (read_length == 0) {
            continue;
        }
        
        // Calculate file offset
        uint64_t file_offset = (piece_offset > file_info.offset) ? 
                              piece_offset - file_info.offset : 0;
        
        // Read data chunk from file using fs module
        std::string file_path = download_path_ + "/" + file_info.path;
        void* read_buffer = data.data() + file_start_in_piece;
        
        if (!read_file_chunk(file_path.c_str(), file_offset, read_buffer, read_length)) {
            LOG_BT_ERROR("Failed to read data from file: " << file_path);
            return false;
        }
        
        LOG_BT_DEBUG("Read " << read_length << " bytes from file " << file_info.path 
                     << " at offset " << file_offset);
    }
    
    return true;
}

void TorrentDownload::reset_block_request(PieceIndex piece_index, uint32_t block_index) {
    std::lock_guard<std::mutex> lock(pieces_mutex_);
    
    if (piece_index >= pieces_.size()) {
        return;
    }
    
    auto& piece = pieces_[piece_index];
    if (block_index < piece->blocks_requested.size()) {
        // Only reset if not already downloaded
        if (!piece->blocks_downloaded[block_index]) {
            piece->blocks_requested[block_index] = false;
        }
    }
}

std::vector<PieceIndex> TorrentDownload::get_available_pieces() const {
    std::lock_guard<std::mutex> lock(pieces_mutex_);
    std::vector<PieceIndex> available_pieces;
    
    for (PieceIndex i = 0; i < piece_completed_.size(); ++i) {
        if (piece_completed_[i]) {
            available_pieces.push_back(i);
        }
    }
    
    return available_pieces;
}

std::vector<PieceIndex> TorrentDownload::get_needed_pieces(const std::vector<bool>& peer_bitfield) const {
    std::lock_guard<std::mutex> lock(pieces_mutex_);
    std::vector<PieceIndex> needed_pieces;
    
    size_t min_size = (std::min)(peer_bitfield.size(), piece_completed_.size());
    for (size_t i = 0; i < min_size; ++i) {
        // Include pieces that are not complete (even if downloading - peer can help complete them)
        if (peer_bitfield[i] && !piece_completed_[i]) {
            needed_pieces.push_back(static_cast<PieceIndex>(i));
        }
    }
    
    return needed_pieces;
}

uint64_t TorrentDownload::get_downloaded_bytes() const {
    return total_downloaded_.load();
}

uint64_t TorrentDownload::get_uploaded_bytes() const {
    return total_uploaded_.load();
}

double TorrentDownload::get_progress_percentage() const {
    if (torrent_info_.get_total_length() == 0) {
        return 0.0;
    }
    
    uint64_t downloaded = get_downloaded_bytes();
    return (static_cast<double>(downloaded) / torrent_info_.get_total_length()) * 100.0;
}

uint32_t TorrentDownload::get_completed_pieces() const {
    std::lock_guard<std::mutex> lock(pieces_mutex_);
    return static_cast<uint32_t>(std::count(piece_completed_.begin(), piece_completed_.end(), true));
}

std::vector<bool> TorrentDownload::get_piece_bitfield() const {
    std::lock_guard<std::mutex> lock(pieces_mutex_);
    return piece_completed_;
}

void TorrentDownload::update_speed_stats() {
    std::lock_guard<std::mutex> lock(speed_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    double elapsed_seconds = std::chrono::duration<double>(now - last_speed_update_time_).count();
    
    // Update speed every second at minimum to avoid division by very small numbers
    if (elapsed_seconds >= 1.0) {
        uint64_t current_downloaded = total_downloaded_.load();
        uint64_t current_uploaded = total_uploaded_.load();
        
        uint64_t downloaded_delta = current_downloaded - last_speed_downloaded_;
        uint64_t uploaded_delta = current_uploaded - last_speed_uploaded_;
        
        download_speed_.store(static_cast<double>(downloaded_delta) / elapsed_seconds);
        upload_speed_.store(static_cast<double>(uploaded_delta) / elapsed_seconds);
        
        last_speed_downloaded_ = current_downloaded;
        last_speed_uploaded_ = current_uploaded;
        last_speed_update_time_ = now;
    }
    
    // Also update speed stats for all peer connections
    {
        std::lock_guard<std::mutex> peers_lock(peers_mutex_);
        for (auto& peer : peer_connections_) {
            peer->update_speed_stats();
        }
    }
}

double TorrentDownload::get_download_speed() const {
    return download_speed_.load();
}

double TorrentDownload::get_upload_speed() const {
    return upload_speed_.load();
}

void TorrentDownload::download_loop() {
    LOG_BT_INFO("Download loop started for torrent: " << torrent_info_.get_name());
    
    while (running_ && !is_complete()) {
        if (paused_) {
            // Use conditional variable for responsive shutdown
            {
                std::unique_lock<std::mutex> lock(shutdown_mutex_);
                if (shutdown_cv_.wait_for(lock, std::chrono::milliseconds(100), [this] { return !running_.load() || !paused_.load(); })) {
                    if (!running_) break;
                }
            }
            continue;
        }
        
        // Schedule piece requests to peers
        schedule_piece_requests();
        
        // Update progress
        update_progress();
        
        // Check for completion
        check_torrent_completion();
        
        // Use conditional variable for responsive shutdown
        {
            std::unique_lock<std::mutex> lock(shutdown_mutex_);
            if (shutdown_cv_.wait_for(lock, std::chrono::milliseconds(50), [this] { return !running_.load(); })) {
                break;
            }
        }
    }
    
    LOG_BT_INFO("Download loop ended for torrent: " << torrent_info_.get_name());
}

void TorrentDownload::peer_management_loop() {
    LOG_BT_INFO("Peer management loop started for torrent: " << torrent_info_.get_name());
    
    while (running_) {
        // Clean up disconnected peers
        cleanup_disconnected_peers();
        
        // Periodically log detailed torrent state (every 10 seconds when actively downloading)
        auto now = std::chrono::steady_clock::now();
        bool is_actively_downloading = !is_complete() && !paused_.load();
        
        // Log every 10 seconds when downloading, every 30 seconds when seeding/idle
        auto log_interval = is_actively_downloading ? std::chrono::seconds(10) : std::chrono::seconds(30);
        
        if (now - last_state_log_time_ > log_interval) {
            last_state_log_time_ = now;
            
            // Only log detailed state if we have peers or are actively doing something
            size_t peer_count = get_peer_count();
            if (peer_count > 0 || is_actively_downloading) {
                log_detailed_state();
            }
        }
        
        // Use conditional variable for responsive shutdown
        {
            std::unique_lock<std::mutex> lock(shutdown_mutex_);
            if (shutdown_cv_.wait_for(lock, std::chrono::seconds(1), [this] { return !running_.load(); })) {
                break;
            }
        }
    }
    
    LOG_BT_INFO("Peer management loop ended for torrent: " << torrent_info_.get_name());
}

void TorrentDownload::schedule_piece_requests() {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    for (auto& peer : peer_connections_) {
        if (!peer->is_connected()) {
            continue;
        }
        
        // Get pieces we need that this peer has
        std::vector<PieceIndex> needed_pieces = get_needed_pieces(peer->get_bitfield());
        
        // IMPORTANT: Express interest BEFORE checking choke state
        // We must send INTERESTED to get unchoked, even if we're currently choked
        if (!needed_pieces.empty() && !peer->is_interested()) {
            peer->set_interested(true);
            LOG_BT_DEBUG("Expressed interest to peer " << peer->get_peer_info().ip << ":" << peer->get_peer_info().port);
        }
        
        // Skip actual piece requests if we're choked or have no needed pieces
        if (peer->is_choked() || needed_pieces.empty()) {
            continue;
        }
        
        // Select pieces to download using our piece selection strategy
        std::vector<PieceIndex> selected_pieces = select_pieces_for_download();
        
        // Request blocks from selected pieces
        for (PieceIndex piece_index : selected_pieces) {
            if (peer->get_pending_requests() >= MAX_REQUESTS_PER_PEER) {
                break; // Don't overwhelm this peer
            }
            
            if (!peer->has_piece(piece_index)) {
                continue;
            }
            
            // Find blocks we need for this piece
            {
                std::lock_guard<std::mutex> pieces_lock(pieces_mutex_);
                if (piece_index >= pieces_.size() || piece_completed_[piece_index]) {
                    continue;
                }
                
                auto& piece = pieces_[piece_index];
                uint32_t block_size = BLOCK_SIZE;
                
                for (uint32_t block_index = 0; block_index < piece->get_num_blocks(); ++block_index) {
                    if (piece->blocks_downloaded[block_index]) {
                        continue; // Already have this block
                    }
                    
                    // Check if this block is already requested globally (from any peer)
                    if (piece->blocks_requested[block_index]) {
                        continue; // Already requested from another peer
                    }
                    
                    uint32_t offset = block_index * BLOCK_SIZE;
                    uint32_t length = (std::min)(block_size, piece->length - offset);
                    
                    if (peer->request_piece_block(piece_index, offset, length)) {
                        piece->blocks_requested[block_index] = true;  // Mark as globally requested
                        piece_downloading_[piece_index] = true;
                        LOG_BT_DEBUG("Requested block " << block_index << " of piece " << piece_index 
                                     << " from peer " << peer->get_peer_info().ip);
                        break; // Request one block at a time per piece per peer
                    }
                }
            }
        }
    }
}

void TorrentDownload::cleanup_disconnected_peers() {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    peer_connections_.erase(
        std::remove_if(peer_connections_.begin(), peer_connections_.end(),
            [](const std::unique_ptr<PeerConnection>& peer) {
                return !peer->is_connected();
            }),
        peer_connections_.end());
}

bool TorrentDownload::open_files() {
    std::lock_guard<std::mutex> lock(files_mutex_);
    
    const auto& files = torrent_info_.get_files();
    
    for (const auto& file_info : files) {
        std::string file_path = download_path_ + "/" + file_info.path;
        
        // Pre-allocate file with correct size using fs module
        if (!create_file_with_size(file_path.c_str(), file_info.length)) {
            LOG_BT_ERROR("Failed to create file: " << file_path);
            return false;
        }
        
        LOG_BT_DEBUG("Created file: " << file_path << " (size: " << file_info.length << ")");
    }
    
    return true;
}

void TorrentDownload::close_files() {
    std::lock_guard<std::mutex> lock(files_mutex_);
    
    // With fs module, files are opened/closed per operation
    // No persistent file handles to close
    LOG_BT_DEBUG("Files closed (using fs module, no persistent handles)");
}

bool TorrentDownload::create_directory_structure() {
    const auto& files = torrent_info_.get_files();
    
    for (const auto& file_info : files) {
        std::string file_path = download_path_ + "/" + file_info.path;
        
        // Extract directory path
        size_t last_slash = file_path.find_last_of('/');
        if (last_slash != std::string::npos) {
            std::string dir_path = file_path.substr(0, last_slash);
            
            // Create directory structure
            if (!create_directories(dir_path.c_str())) {
                LOG_BT_ERROR("Failed to create directory: " << dir_path);
                return false;
            }
        }
    }
    
    return true;
}

std::vector<PieceIndex> TorrentDownload::select_pieces_for_download() {
    std::lock_guard<std::mutex> lock(pieces_mutex_);
    
    std::vector<PieceIndex> downloading_pieces;
    std::vector<PieceIndex> new_pieces;
    
    // Find pieces we need - prioritize pieces already being downloaded
    for (PieceIndex i = 0; i < piece_completed_.size(); ++i) {
        if (!piece_completed_[i]) {
            if (piece_downloading_[i]) {
                // Prioritize completing pieces we've already started
                downloading_pieces.push_back(i);
            } else {
                new_pieces.push_back(i);
            }
        }
    }
    
    // Implement piece selection strategy: complete existing pieces first, then start new ones
    std::vector<PieceIndex> selected_pieces;
    
    // First, add pieces we're already downloading (prioritize completing them)
    for (PieceIndex piece : downloading_pieces) {
        selected_pieces.push_back(piece);
        if (selected_pieces.size() >= 10) break;
    }
    
    // Then add new pieces if we have room
    for (PieceIndex piece : new_pieces) {
        if (selected_pieces.size() >= 10) break;
        selected_pieces.push_back(piece);
    }
    
    return selected_pieces;
}

PieceIndex TorrentDownload::select_rarest_piece(const std::vector<bool>& available_pieces) {
    // Lock order: peers_mutex_ -> pieces_mutex_
    std::lock_guard<std::mutex> peers_lock(peers_mutex_);
    std::lock_guard<std::mutex> pieces_lock(pieces_mutex_);
    
    // Count how many peers have each piece
    std::vector<int> piece_counts(piece_completed_.size(), 0);
    
    for (const auto& peer : peer_connections_) {
        if (!peer->is_connected()) {
            continue;
        }
        
        const auto& peer_bitfield = peer->get_bitfield();
        for (size_t i = 0; i < peer_bitfield.size() && i < piece_counts.size(); ++i) {
            if (peer_bitfield[i]) {
                piece_counts[i]++;
            }
        }
    }
    
    // Find the rarest piece we need and is available
    int min_count = INT_MAX;
    PieceIndex rarest_piece = static_cast<PieceIndex>(-1);
    
    for (size_t i = 0; i < available_pieces.size() && i < piece_completed_.size(); ++i) {
        if (available_pieces[i] && !piece_completed_[i] && !piece_downloading_[i]) {
            if (piece_counts[i] < min_count) {
                min_count = piece_counts[i];
                rarest_piece = static_cast<PieceIndex>(i);
            }
        }
    }
    
    return rarest_piece;
}

// Helper function to format bytes per second as human-readable string
static std::string format_speed(double bytes_per_second) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    
    if (bytes_per_second >= 1024 * 1024) {
        oss << (bytes_per_second / (1024 * 1024)) << " MB/s";
    } else if (bytes_per_second >= 1024) {
        oss << (bytes_per_second / 1024) << " KB/s";
    } else {
        oss << bytes_per_second << " B/s";
    }
    
    return oss.str();
}

// Helper function to format bytes as human-readable string
static std::string format_bytes(uint64_t bytes) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    
    if (bytes >= 1024ULL * 1024 * 1024) {
        oss << (static_cast<double>(bytes) / (1024 * 1024 * 1024)) << " GB";
    } else if (bytes >= 1024 * 1024) {
        oss << (static_cast<double>(bytes) / (1024 * 1024)) << " MB";
    } else if (bytes >= 1024) {
        oss << (static_cast<double>(bytes) / 1024) << " KB";
    } else {
        oss << bytes << " B";
    }
    
    return oss.str();
}

void TorrentDownload::update_progress() {
    // Update speed statistics
    update_speed_stats();
    
    uint64_t downloaded = get_downloaded_bytes();
    uint64_t total = torrent_info_.get_total_length();
    double percentage = get_progress_percentage();
    
    // Call progress callback
    if (progress_callback_) {
        progress_callback_(downloaded, total, percentage);
    }
    
    // Only log progress if it changed by at least 1% or we went from 0 to non-zero
    double progress_delta = percentage - last_logged_progress_;
    bool should_log_progress = (progress_delta >= 1.0) || 
                                (last_logged_progress_ == 0.0 && percentage > 0.0);
    
    if (should_log_progress) {
        double dl_speed = get_download_speed();
        double ul_speed = get_upload_speed();
        
        LOG_BT_INFO("Progress [" << torrent_info_.get_name() << "]: " 
                    << std::fixed << std::setprecision(1) << percentage << "% "
                    << "(" << format_bytes(downloaded) << " / " << format_bytes(total) << ") "
                    << "DL: " << format_speed(dl_speed) << " "
                    << "UL: " << format_speed(ul_speed));
        
        last_logged_progress_ = percentage;
    }
}

void TorrentDownload::on_piece_completed(PieceIndex piece_index) {
    if (piece_complete_callback_) {
        piece_complete_callback_(piece_index);
    }
    
    // Notify all peers that we have this piece (for seeding)
    notify_peers_have_piece(piece_index);
    
    double dl_speed = get_download_speed();
    LOG_BT_INFO("Piece " << piece_index << " completed. Progress: " 
                << std::fixed << std::setprecision(1) << get_progress_percentage() << "% (" 
                << get_completed_pieces() << "/" << torrent_info_.get_num_pieces() << " pieces) "
                << "@ " << format_speed(dl_speed));
}

void TorrentDownload::notify_peers_have_piece(PieceIndex piece_index) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    // Send HAVE message to all connected peers
    auto have_msg = PeerMessage::create_have(piece_index);
    
    for (auto& peer : peer_connections_) {
        if (peer->is_connected()) {
            peer->send_message(have_msg);
        }
    }
    
    LOG_BT_DEBUG("Notified " << peer_connections_.size() << " peers that we have piece " << piece_index);
}

void TorrentDownload::check_torrent_completion() {
    if (is_complete() && torrent_complete_callback_) {
        torrent_complete_callback_(torrent_info_.get_name());
        LOG_BT_INFO("Torrent download completed: " << torrent_info_.get_name());
    }
}

void TorrentDownload::log_detailed_state() {
    // Get current stats - be careful with lock ordering (peers_mutex_ -> pieces_mutex_)
    uint32_t completed_pieces = 0;
    uint32_t downloading_pieces = 0;
    uint32_t total_pieces = 0;
    std::vector<PieceIndex> currently_downloading;
    
    {
        std::lock_guard<std::mutex> lock(pieces_mutex_);
        total_pieces = static_cast<uint32_t>(piece_completed_.size());
        completed_pieces = static_cast<uint32_t>(std::count(piece_completed_.begin(), piece_completed_.end(), true));
        
        for (size_t i = 0; i < piece_downloading_.size(); ++i) {
            if (piece_downloading_[i] && !piece_completed_[i]) {
                downloading_pieces++;
                if (currently_downloading.size() < 10) {  // Limit to first 10
                    currently_downloading.push_back(static_cast<PieceIndex>(i));
                }
            }
        }
    }
    
    // Get peer information
    size_t total_peers = 0;
    size_t connected_peers = 0;
    size_t unchoked_peers = 0;
    size_t interested_peers = 0;
    std::vector<std::tuple<std::string, double, double, size_t, bool>> peer_stats;  // ip:port, dl_speed, ul_speed, pending_requests, choked
    
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        total_peers = peer_connections_.size();
        
        for (const auto& peer : peer_connections_) {
            if (peer->is_connected()) {
                connected_peers++;
                if (!peer->is_choked()) {
                    unchoked_peers++;
                }
                if (peer->peer_is_interested()) {
                    interested_peers++;
                }
                
                std::string peer_addr = peer->get_peer_info().ip + ":" + std::to_string(peer->get_peer_info().port);
                peer_stats.emplace_back(
                    peer_addr,
                    peer->get_download_speed(),
                    peer->get_upload_speed(),
                    peer->get_pending_requests(),
                    peer->is_choked()
                );
            }
        }
    }
    
    // Calculate overall speeds
    double dl_speed = get_download_speed();
    double ul_speed = get_upload_speed();
    uint64_t downloaded = get_downloaded_bytes();
    uint64_t uploaded = get_uploaded_bytes();
    uint64_t total_size = torrent_info_.get_total_length();
    double progress = get_progress_percentage();
    
    // Calculate ETA
    std::string eta_str = "N/A";
    if (dl_speed > 0 && !is_complete()) {
        uint64_t remaining = total_size - downloaded;
        double eta_seconds = static_cast<double>(remaining) / dl_speed;
        
        if (eta_seconds < 60) {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(0) << eta_seconds << "s";
            eta_str = oss.str();
        } else if (eta_seconds < 3600) {
            int minutes = static_cast<int>(eta_seconds / 60);
            int seconds = static_cast<int>(eta_seconds) % 60;
            std::ostringstream oss;
            oss << minutes << "m " << seconds << "s";
            eta_str = oss.str();
        } else {
            int hours = static_cast<int>(eta_seconds / 3600);
            int minutes = static_cast<int>((static_cast<int>(eta_seconds) % 3600) / 60);
            std::ostringstream oss;
            oss << hours << "h " << minutes << "m";
            eta_str = oss.str();
        }
    } else if (is_complete()) {
        eta_str = "Complete";
    }
    
    // Log detailed state
    LOG_BT_INFO("=== Torrent State: " << torrent_info_.get_name() << " ===");
    LOG_BT_INFO("  Progress: " << std::fixed << std::setprecision(1) << progress << "% "
                << "(" << format_bytes(downloaded) << " / " << format_bytes(total_size) << ")");
    LOG_BT_INFO("  Pieces: " << completed_pieces << "/" << total_pieces << " complete, "
                << downloading_pieces << " downloading");
    LOG_BT_INFO("  Speed: DL " << format_speed(dl_speed) << " | UL " << format_speed(ul_speed));
    LOG_BT_INFO("  Uploaded: " << format_bytes(uploaded) << " | ETA: " << eta_str);
    LOG_BT_INFO("  Peers: " << connected_peers << "/" << total_peers << " connected, "
                << unchoked_peers << " unchoked, " << interested_peers << " interested in us");
    
    // Log pieces being downloaded (if any)
    if (!currently_downloading.empty()) {
        std::ostringstream pieces_oss;
        pieces_oss << "  Downloading pieces: [";
        for (size_t i = 0; i < currently_downloading.size(); ++i) {
            if (i > 0) pieces_oss << ", ";
            pieces_oss << currently_downloading[i];
        }
        if (downloading_pieces > currently_downloading.size()) {
            pieces_oss << ", ... +" << (downloading_pieces - currently_downloading.size()) << " more";
        }
        pieces_oss << "]";
        LOG_BT_INFO(pieces_oss.str());
    }
    
    // Log per-peer stats if we have peers
    if (!peer_stats.empty()) {
        LOG_BT_INFO("  Per-peer stats:");
        for (const auto& [addr, peer_dl, peer_ul, pending, choked] : peer_stats) {
            LOG_BT_INFO("    " << addr << ": DL " << format_speed(peer_dl) 
                        << " | UL " << format_speed(peer_ul)
                        << " | Pending: " << pending 
                        << " | " << (choked ? "CHOKED" : "unchoked"));
        }
    }
    
    LOG_BT_INFO("=== End Torrent State ===");
}

void TorrentDownload::announce_to_dht(DhtClient* dht_client) {
    if (!dht_client || !dht_client->is_running()) {
        LOG_BT_WARN("DHT client not available for torrent announcement");
        return;
    }
    
    // Convert info hash to DHT format
    InfoHash dht_info_hash;
    const auto& torrent_hash = torrent_info_.get_info_hash();
    std::copy(torrent_hash.begin(), torrent_hash.end(), dht_info_hash.begin());
    
    // Announce with default BitTorrent port (we don't have a BitTorrent listen port yet)
    uint16_t announce_port = 6881; // Default BitTorrent port
    
    if (dht_client->announce_peer(dht_info_hash, announce_port)) {
        LOG_BT_INFO("Announced torrent to DHT: " << torrent_info_.get_name());
    } else {
        LOG_BT_WARN("Failed to announce torrent to DHT: " << torrent_info_.get_name());
    }
}

void TorrentDownload::request_peers_from_dht(DhtClient* dht_client) {
    if (!dht_client || !dht_client->is_running()) {
        LOG_BT_WARN("DHT client not available for peer discovery");
        return;
    }
    
    // Convert info hash to DHT format
    InfoHash dht_info_hash;
    const auto& torrent_hash = torrent_info_.get_info_hash();
    std::copy(torrent_hash.begin(), torrent_hash.end(), dht_info_hash.begin());
    
    LOG_BT_INFO("Requesting peers from DHT for torrent: " << torrent_info_.get_name());
    
    dht_client->find_peers(dht_info_hash, [this](const std::vector<Peer>& peers, const InfoHash& info_hash) {
        // Check if torrent is still running
        if (!running_.load()) {
            LOG_BT_DEBUG("Torrent stopped, ignoring DHT peer discovery results");
            return;
        }
        
        LOG_BT_INFO("DHT discovered " << peers.size() << " peers for torrent: " << torrent_info_.get_name());
        
        if (peers.empty()) {
            LOG_BT_WARN("No peers found via DHT for torrent: " << torrent_info_.get_name());
            return;
        }
        
        size_t peers_added = 0;
        for (const auto& peer : peers) {
            if (get_peer_count() >= MAX_PEERS_PER_TORRENT) {
                LOG_BT_DEBUG("Peer limit reached, stopping peer additions");
                break;
            }
            
            if (add_peer(peer)) {
                peers_added++;
            }
        }
        
        LOG_BT_INFO("Added " << peers_added << " of " << peers.size() << " DHT peers for torrent: " << torrent_info_.get_name());
    });
}

void TorrentDownload::announce_to_trackers() {
    if (!tracker_manager_) {
        LOG_BT_WARN("No tracker manager available");
        return;
    }
    
    LOG_BT_INFO("Announcing to trackers for torrent: " << torrent_info_.get_name());
    
    // Prepare tracker request
    TrackerRequest request;
    request.info_hash = torrent_info_.get_info_hash();
    request.peer_id = our_peer_id_;
    request.port = 6881;  // Default BitTorrent port (should come from BitTorrentClient)
    request.uploaded = total_uploaded_.load();
    request.downloaded = total_downloaded_.load();
    request.left = torrent_info_.get_total_length() - total_downloaded_.load();
    
    // Determine event
    if (total_downloaded_.load() == 0 && !running_) {
        request.event = TrackerEvent::STARTED;
    } else if (is_complete()) {
        request.event = TrackerEvent::COMPLETED;
    } else {
        request.event = TrackerEvent::NONE;
    }
    
    // Announce to all trackers
    tracker_manager_->announce(request, [this](const TrackerResponse& response, const std::string& tracker_url) {
        if (!response.success) {
            LOG_BT_WARN("Tracker announce failed (" << tracker_url << "): " << response.failure_reason);
            return;
        }
        
        LOG_BT_INFO("Tracker announce successful (" << tracker_url << ")");
        LOG_BT_INFO("  Peers: " << response.peers.size() 
                   << ", Seeders: " << response.complete 
                   << ", Leechers: " << response.incomplete);
        
        // Add discovered peers
        for (const auto& peer : response.peers) {
            if (get_peer_count() >= MAX_PEERS_PER_TORRENT) {
                break;
            }
            
            add_peer(peer);
        }
    });
}

void TorrentDownload::request_peers_from_trackers() {
    if (!tracker_manager_) {
        LOG_BT_WARN("No tracker manager available");
        return;
    }
    
    // Same as announce - trackers provide peer lists in announce responses
    announce_to_trackers();
}

void TorrentDownload::set_metadata_download(std::shared_ptr<MetadataDownload> metadata_download) {
    metadata_download_ = metadata_download;
    
    // Set up the completion callback to forward to our metadata_complete_callback_
    if (metadata_download_) {
        metadata_download_->set_completion_callback([this](const TorrentInfo& torrent_info) {
            LOG_BT_INFO("Metadata download completed, notifying callback");
            if (metadata_complete_callback_) {
                metadata_complete_callback_(torrent_info);
            }
        });
    }
}

//=============================================================================
// BitTorrentClient Implementation
//=============================================================================

BitTorrentClient::BitTorrentClient()
    : running_(false), listen_port_(0), listen_socket_(INVALID_SOCKET_VALUE),
      dht_client_(nullptr), max_connections_per_torrent_(MAX_PEERS_PER_TORRENT),
      download_rate_limit_(0), upload_rate_limit_(0) {
    
    LOG_BT_INFO("BitTorrent client created");
}

BitTorrentClient::~BitTorrentClient() {
    stop();
}

bool BitTorrentClient::start(int listen_port) {
    if (running_.load()) {
        LOG_BT_WARN("BitTorrent client is already running");
        return false;
    }
    
    listen_port_ = listen_port;
    if (listen_port_ == 0) {
        listen_port_ = 6881; // Default BitTorrent port
    }
    
    LOG_BT_INFO("Starting BitTorrent client on port " << listen_port_);
    
    // Initialize socket library (safe to call multiple times)
    if (!init_socket_library()) {
        LOG_BT_ERROR("Failed to initialize socket library");
        return false;
    }
    
    // Create listen socket
    listen_socket_ = create_tcp_server(listen_port_);
    if (!is_valid_socket(listen_socket_)) {
        LOG_BT_ERROR("Failed to create BitTorrent listen socket on port " << listen_port_);
        return false;
    }
    
    running_.store(true);
    
    // Start incoming connections handler
    incoming_connections_thread_ = std::thread(&BitTorrentClient::handle_incoming_connections, this);
    
    LOG_BT_INFO("BitTorrent client started successfully");
    return true;
}

void BitTorrentClient::stop() {
    if (!running_.load()) {
        return;
    }
    
    LOG_BT_INFO("Stopping BitTorrent client");
    running_.store(false);
    
    // Stop all torrents
    {
        std::lock_guard<std::mutex> lock(torrents_mutex_);
        for (auto& pair : torrents_) {
            pair.second->stop();
        }
        torrents_.clear();
    }
    
    // Close listen socket
    if (is_valid_socket(listen_socket_)) {
        close_socket(listen_socket_);
        listen_socket_ = INVALID_SOCKET_VALUE;
    }
    
    // Wait for threads
    if (incoming_connections_thread_.joinable()) {
        incoming_connections_thread_.join();
    }
    
    LOG_BT_INFO("BitTorrent client stopped");
}

std::shared_ptr<TorrentDownload> BitTorrentClient::add_torrent(const std::string& torrent_file, 
                                                              const std::string& download_path) {
    TorrentInfo torrent_info;
    if (!torrent_info.load_from_file(torrent_file)) {
        LOG_BT_ERROR("Failed to load torrent file: " << torrent_file);
        return nullptr;
    }
    
    return add_torrent(torrent_info, download_path);
}

std::shared_ptr<TorrentDownload> BitTorrentClient::add_torrent(const TorrentInfo& torrent_info, 
                                                              const std::string& download_path) {
    if (!running_.load()) {
        LOG_BT_ERROR("BitTorrent client is not running");
        return nullptr;
    }
    
    const InfoHash& info_hash = torrent_info.get_info_hash();
    
    {
        std::lock_guard<std::mutex> lock(torrents_mutex_);
        
        // Check if torrent already exists
        if (torrents_.find(info_hash) != torrents_.end()) {
            LOG_BT_WARN("Torrent already exists: " << torrent_info.get_name());
            return torrents_[info_hash];
        }
        
        // Create new torrent download
        auto torrent_download = std::make_shared<TorrentDownload>(torrent_info, download_path);
        
        // Set up callbacks
        torrent_download->set_progress_callback([this, info_hash](uint64_t downloaded, uint64_t total, double percentage) {
            LOG_BT_DEBUG("Torrent progress: " << percentage << "% (" << downloaded << "/" << total << " bytes)");
        });
        
        torrent_download->set_torrent_complete_callback([this, info_hash](const std::string& torrent_name) {
            LOG_BT_INFO("Torrent completed: " << torrent_name);
            if (torrent_completed_callback_) {
                torrent_completed_callback_(info_hash);
            }
        });
        
        torrents_[info_hash] = torrent_download;
        
        // Start the download
        if (!torrent_download->start()) {
            LOG_BT_ERROR("Failed to start torrent download: " << torrent_info.get_name());
            torrents_.erase(info_hash);
            return nullptr;
        }
        
        // Announce to trackers
        torrent_download->announce_to_trackers();
        
        // Announce to DHT if available
        if (dht_client_) {
            torrent_download->announce_to_dht(dht_client_);
            torrent_download->request_peers_from_dht(dht_client_);
        }
        
        LOG_BT_INFO("Added torrent: " << torrent_info.get_name());
        
        if (torrent_added_callback_) {
            torrent_added_callback_(info_hash);
        }
        
        return torrent_download;
    }
}

std::shared_ptr<TorrentDownload> BitTorrentClient::add_torrent_by_hash(const InfoHash& info_hash, 
                                                                        const std::string& download_path) {
    if (!running_.load()) {
        LOG_BT_ERROR("BitTorrent client is not running");
        return nullptr;
    }
    
    if (!dht_client_ || !dht_client_->is_running()) {
        LOG_BT_ERROR("DHT client is required for adding torrents by hash. DHT is not available.");
        return nullptr;
    }
    
    LOG_BT_INFO("Adding torrent by hash: " << info_hash_to_hex(info_hash));
    LOG_BT_INFO("This will use DHT to find peers and download metadata via BEP 9...");
    
    {
        std::lock_guard<std::mutex> lock(torrents_mutex_);
        
        // Check if torrent already exists
        if (torrents_.find(info_hash) != torrents_.end()) {
            LOG_BT_WARN("Torrent already exists with hash: " << info_hash_to_hex(info_hash));
            return torrents_[info_hash];
        }
    }
    
    // Check if metadata download already in progress
    {
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        if (metadata_downloads_.find(info_hash) != metadata_downloads_.end()) {
            LOG_BT_WARN("Metadata download already in progress for hash: " << info_hash_to_hex(info_hash));
            return nullptr;
        }
        
        // Store download path for later use
        metadata_download_paths_[info_hash] = download_path;
    }
    
    // Create a minimal TorrentInfo for metadata exchange
    // We need a valid TorrentInfo to create peer connections, but we don't have the real metadata yet
    TorrentInfo metadata_torrent_info = TorrentInfo::create_for_metadata_exchange(info_hash);
    
    // Create a temporary torrent download for metadata exchange only
    auto metadata_torrent = std::make_shared<TorrentDownload>(metadata_torrent_info, download_path);
    
    // Set up metadata completion callback
    // When metadata download completes, we'll stop the temporary torrent and create the real one
    // IMPORTANT: This callback is invoked from within a PeerConnection's thread, so we must NOT
    // call stop() directly (which would try to join the calling thread, causing a deadlock).
    // Instead, we defer the cleanup to a detached thread.
    metadata_torrent->set_metadata_complete_callback([this, info_hash, download_path, metadata_torrent](const TorrentInfo& torrent_info) {
        LOG_BT_INFO("Metadata download completed for " << torrent_info.get_name());
        
        // Capture torrent_info by value since we're deferring to another thread
        TorrentInfo captured_info = torrent_info;
        
        // Defer stop() and cleanup to a separate thread to avoid deadlock
        // (callback is called from PeerConnection::connection_thread_ which would try to join itself)
        std::thread([this, info_hash, download_path, metadata_torrent, captured_info]() {
            // Stop the temporary metadata torrent
            metadata_torrent->stop();
            
            // Complete the metadata download and create the real torrent
            complete_metadata_download(info_hash, captured_info, download_path);
        }).detach();
    });
    
    // Note: We don't create MetadataDownload here yet
    // It will be created dynamically when we get the metadata size from a peer's extended handshake
    // This happens in handle_extended_handshake when peer sends metadata_size
    // When set_metadata_download() is called, it will automatically set up the completion callback chain
    
    // Start the metadata torrent (just for peer connections)
    if (!metadata_torrent->start()) {
        LOG_BT_ERROR("Failed to start metadata download torrent");
        return nullptr;
    }
    
    // Use DHT to find peers for this info hash
    LOG_BT_INFO("Discovering peers via DHT for hash: " << info_hash_to_hex(info_hash));
    
    // Find peers via DHT
    dht_client_->find_peers(info_hash, [this, info_hash, metadata_torrent](const std::vector<Peer>& peers, const InfoHash& hash) {
        // Check if metadata torrent is still running (may have completed or been stopped)
        if (!metadata_torrent->is_running()) {
            LOG_BT_DEBUG("Metadata torrent already stopped, ignoring DHT peer discovery results");
            return;
        }
        
        // Check if metadata is already downloaded
        if (auto* md = metadata_torrent->get_metadata_download()) {
            if (md->is_complete()) {
                LOG_BT_DEBUG("Metadata already downloaded, ignoring DHT peer discovery results");
                return;
            }
        }
        
        LOG_BT_INFO("DHT found " << peers.size() << " peers for hash " << info_hash_to_hex(info_hash));
        
        if (peers.empty()) {
            LOG_BT_WARN("No peers found via DHT for hash " << info_hash_to_hex(info_hash));
            return;
        }
        
        // Connect to peers to get metadata
        size_t max_peers_to_try = (std::min)(peers.size(), static_cast<size_t>(10));
        size_t peers_added = 0;
        for (size_t i = 0; i < max_peers_to_try; ++i) {
            // Check again if metadata is complete (could have completed during loop)
            if (auto* md = metadata_torrent->get_metadata_download()) {
                if (md->is_complete()) {
                    LOG_BT_DEBUG("Metadata download completed, stopping peer additions");
                    break;
                }
            }
            
            // Check if torrent is still running
            if (!metadata_torrent->is_running()) {
                LOG_BT_DEBUG("Metadata torrent stopped, stopping peer additions");
                break;
            }
            
            const auto& peer = peers[i];
            LOG_BT_INFO("Connecting to peer " << peer.ip << ":" << peer.port << " for metadata exchange");
            
            // Add peer to the metadata torrent
            // The peer connection will automatically:
            // 1. Perform BitTorrent handshake with the info hash
            // 2. Exchange extended handshake
            // 3. Detect metadata support and size
            // 4. Request metadata pieces
            // 5. Complete metadata download via callback
            if (metadata_torrent->add_peer(peer)) {
                peers_added++;
            } else {
                LOG_BT_DEBUG("Failed to add peer " << peer.ip << ":" << peer.port);
            }
        }
        
        LOG_BT_INFO("Added " << peers_added << " peers for metadata exchange");
    });
    
    LOG_BT_INFO("Metadata download initiated for hash " << info_hash_to_hex(info_hash));
    LOG_BT_INFO("Waiting for DHT peer discovery and metadata exchange...");
    LOG_BT_INFO("Note: Metadata download will complete asynchronously via BEP 9");
    
    return nullptr; // Will return the real torrent via completion callback
}

std::shared_ptr<TorrentDownload> BitTorrentClient::add_torrent_by_hash(const std::string& info_hash_hex, 
                                                                        const std::string& download_path) {
    InfoHash info_hash = hex_to_info_hash(info_hash_hex);
    
    // Validate the parsed hash
    bool is_zero = true;
    for (const auto& byte : info_hash) {
        if (byte != 0) {
            is_zero = false;
            break;
        }
    }
    
    if (is_zero && info_hash_hex.length() == 40) {
        LOG_BT_ERROR("Invalid info hash format: " << info_hash_hex);
        return nullptr;
    }
    
    return add_torrent_by_hash(info_hash, download_path);
}

bool BitTorrentClient::remove_torrent(const InfoHash& info_hash) {
    std::lock_guard<std::mutex> lock(torrents_mutex_);
    
    auto it = torrents_.find(info_hash);
    if (it == torrents_.end()) {
        return false;
    }
    
    // Stop the torrent
    it->second->stop();
    torrents_.erase(it);
    
    if (torrent_removed_callback_) {
        torrent_removed_callback_(info_hash);
    }
    
    LOG_BT_INFO("Removed torrent with info hash: " << info_hash_to_hex(info_hash));
    return true;
}

std::shared_ptr<TorrentDownload> BitTorrentClient::get_torrent(const InfoHash& info_hash) {
    std::lock_guard<std::mutex> lock(torrents_mutex_);
    
    auto it = torrents_.find(info_hash);
    return (it != torrents_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<TorrentDownload>> BitTorrentClient::get_all_torrents() {
    std::lock_guard<std::mutex> lock(torrents_mutex_);
    
    std::vector<std::shared_ptr<TorrentDownload>> result;
    result.reserve(torrents_.size());
    
    for (const auto& pair : torrents_) {
        result.push_back(pair.second);
    }
    
    return result;
}

void BitTorrentClient::discover_peers_for_torrent(const InfoHash& info_hash) {
    if (!dht_client_ || !dht_client_->is_running()) {
        LOG_BT_WARN("DHT client not available for peer discovery");
        return;
    }
    
    auto torrent = get_torrent(info_hash);
    if (!torrent) {
        LOG_BT_WARN("Torrent not found for peer discovery");
        return;
    }
    
    torrent->request_peers_from_dht(dht_client_);
}

void BitTorrentClient::announce_torrent_to_dht(const InfoHash& info_hash) {
    if (!dht_client_ || !dht_client_->is_running()) {
        LOG_BT_WARN("DHT client not available for torrent announcement");
        return;
    }
    
    auto torrent = get_torrent(info_hash);
    if (!torrent) {
        LOG_BT_WARN("Torrent not found for DHT announcement");
        return;
    }
    
    torrent->announce_to_dht(dht_client_);
}

size_t BitTorrentClient::get_active_torrents_count() const {
    std::lock_guard<std::mutex> lock(torrents_mutex_);
    return torrents_.size();
}

uint64_t BitTorrentClient::get_total_downloaded() const {
    std::lock_guard<std::mutex> lock(torrents_mutex_);
    
    uint64_t total = 0;
    for (const auto& pair : torrents_) {
        total += pair.second->get_downloaded_bytes();
    }
    
    return total;
}

uint64_t BitTorrentClient::get_total_uploaded() const {
    std::lock_guard<std::mutex> lock(torrents_mutex_);
    
    uint64_t total = 0;
    for (const auto& pair : torrents_) {
        total += pair.second->get_uploaded_bytes();
    }
    
    return total;
}

void BitTorrentClient::handle_incoming_connections() {
    LOG_BT_INFO("BitTorrent incoming connections handler started");
    
    while (running_.load()) {
        socket_t client_socket = accept_client(listen_socket_);
        if (!is_valid_socket(client_socket)) {
            if (running_.load()) {
                LOG_BT_ERROR("Failed to accept BitTorrent client connection");
            }
            continue;
        }
        
        // Handle the connection in a separate thread
        std::thread([this, client_socket]() {
            handle_incoming_connection(client_socket);
        }).detach();
    }
    
    LOG_BT_INFO("BitTorrent incoming connections handler stopped");
}

void BitTorrentClient::handle_incoming_connection(socket_t client_socket) {
    LOG_BT_DEBUG("Handling incoming BitTorrent connection");
    
    InfoHash info_hash;
    PeerID peer_id;
    
    if (!perform_incoming_handshake(client_socket, info_hash, peer_id)) {
        LOG_BT_WARN("Failed to perform incoming handshake");
        close_socket(client_socket);
        return;
    }
    
    // Find the torrent for this info hash
    auto torrent = get_torrent(info_hash);
    if (!torrent) {
        LOG_BT_WARN("Received connection for unknown torrent");
        close_socket(client_socket);
        return;
    }
    
    // Get peer address
    std::string peer_address = get_peer_address(client_socket);
    
    // Parse peer address to get IP and port
    std::string ip;
    int port = 0;
    size_t colon_pos = peer_address.find_last_of(':');
    if (colon_pos != std::string::npos) {
        ip = peer_address.substr(0, colon_pos);
        try {
            port = std::stoi(peer_address.substr(colon_pos + 1));
        } catch (const std::exception&) {
            port = 0;
        }
    }
    
    if (ip.empty() || port == 0) {
        LOG_BT_WARN("Failed to parse peer address: " << peer_address);
        close_socket(client_socket);
        return;
    }
    
    // Create peer object and add to torrent with the existing socket
    Peer peer_info{ip, static_cast<uint16_t>(port)};
    if (torrent->add_peer(peer_info, client_socket)) {
        LOG_BT_INFO("Added incoming peer: " << peer_address);
        // Socket ownership transferred to PeerConnection
    } else {
        LOG_BT_WARN("Failed to add incoming peer: " << peer_address);
        // Socket already closed by add_peer in failure case
    }
}

bool BitTorrentClient::perform_incoming_handshake(socket_t socket, InfoHash& info_hash, PeerID& peer_id) {
    // Receive handshake
    std::vector<uint8_t> handshake_data(68); // Fixed handshake size
    std::string received_data = receive_tcp_string(socket, 68);
    
    if (received_data.length() != 68) {
        LOG_BT_ERROR("Invalid handshake size received: " << received_data.length());
        return false;
    }
    
    std::copy(received_data.begin(), received_data.end(), handshake_data.begin());
    
    if (!parse_handshake_message(handshake_data, info_hash, peer_id)) {
        LOG_BT_ERROR("Failed to parse incoming handshake");
        return false;
    }
    
    // Send our handshake response
    PeerID our_peer_id = generate_peer_id();
    auto response_data = create_handshake_message(info_hash, our_peer_id);
    
    std::string response_str(response_data.begin(), response_data.end());
    if (send_tcp_string(socket, response_str) <= 0) {
        LOG_BT_ERROR("Failed to send handshake response");
        return false;
    }
    
    LOG_BT_DEBUG("Incoming handshake completed successfully");
    return true;
}

std::shared_ptr<MetadataDownload> BitTorrentClient::get_metadata_download(const InfoHash& info_hash) {
    std::lock_guard<std::mutex> lock(metadata_mutex_);
    
    auto it = metadata_downloads_.find(info_hash);
    if (it != metadata_downloads_.end()) {
        return it->second;
    }
    
    return nullptr;
}

void BitTorrentClient::register_metadata_download(const InfoHash& info_hash, std::shared_ptr<MetadataDownload> metadata_download) {
    std::lock_guard<std::mutex> lock(metadata_mutex_);
    metadata_downloads_[info_hash] = metadata_download;
    LOG_BT_INFO("Registered metadata download for info hash " << info_hash_to_hex(info_hash));
}

void BitTorrentClient::complete_metadata_download(const InfoHash& info_hash, const TorrentInfo& torrent_info, const std::string& download_path) {
    LOG_BT_INFO("Completing metadata download for info hash " << info_hash_to_hex(info_hash));
    
    // Remove from metadata downloads
    {
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        metadata_downloads_.erase(info_hash);
        metadata_download_paths_.erase(info_hash);
    }
    
    // Add as regular torrent
    add_torrent(torrent_info, download_path);
}

void BitTorrentClient::get_torrent_metadata_by_hash(const InfoHash& info_hash, MetadataRetrievalCallback callback) {
    if (!running_.load()) {
        LOG_BT_ERROR("BitTorrent client is not running");
        if (callback) {
            callback(TorrentInfo(), false, "BitTorrent client is not running");
        }
        return;
    }
    
    if (!dht_client_ || !dht_client_->is_running()) {
        LOG_BT_ERROR("DHT client is required for metadata retrieval. DHT is not available.");
        if (callback) {
            callback(TorrentInfo(), false, "DHT client is required but not available");
        }
        return;
    }
    
    LOG_BT_INFO("Retrieving metadata for hash: " << info_hash_to_hex(info_hash));
    LOG_BT_INFO("This will use DHT to find peers and download metadata via BEP 9...");
    
    // Check if metadata retrieval already in progress
    {
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        if (metadata_only_torrents_.find(info_hash) != metadata_only_torrents_.end()) {
            LOG_BT_WARN("Metadata retrieval already in progress for hash: " << info_hash_to_hex(info_hash));
            if (callback) {
                callback(TorrentInfo(), false, "Metadata retrieval already in progress");
            }
            return;
        }
        
        // Store the callback
        metadata_retrieval_callbacks_[info_hash] = callback;
    }
    
    // Create a minimal TorrentInfo for metadata exchange
    TorrentInfo metadata_torrent_info = TorrentInfo::create_for_metadata_exchange(info_hash);
    
    // Create a temporary torrent download for metadata exchange only
    auto metadata_torrent = std::make_shared<TorrentDownload>(metadata_torrent_info, ""); // No download path needed
    
    // Set up metadata completion callback
    // IMPORTANT: This callback is invoked from within a PeerConnection's thread, so we must NOT
    // call stop() directly (which would try to join the calling thread, causing a deadlock).
    // Instead, we defer the cleanup to a detached thread.
    metadata_torrent->set_metadata_complete_callback([this, info_hash](const TorrentInfo& torrent_info) {
        LOG_BT_INFO("Metadata retrieval completed for " << torrent_info.get_name());
        
        // Capture torrent_info by value since we're deferring to another thread
        TorrentInfo captured_info = torrent_info;
        
        // Defer stop() and cleanup to a separate thread to avoid deadlock
        // (callback is called from PeerConnection::connection_thread_ which would try to join itself)
        std::thread([this, info_hash, captured_info]() {
            MetadataRetrievalCallback user_callback;
            std::shared_ptr<TorrentDownload> temp_torrent;
            
            // Get callback and cleanup
            {
                std::lock_guard<std::mutex> lock(metadata_mutex_);
                auto it = metadata_retrieval_callbacks_.find(info_hash);
                if (it != metadata_retrieval_callbacks_.end()) {
                    user_callback = it->second;
                    metadata_retrieval_callbacks_.erase(it);
                }
                
                // Get temporary torrent to stop it
                auto torrent_it = metadata_only_torrents_.find(info_hash);
                if (torrent_it != metadata_only_torrents_.end()) {
                    temp_torrent = torrent_it->second;
                    metadata_only_torrents_.erase(torrent_it);
                }
            }
            
            // Stop the temporary torrent
            if (temp_torrent) {
                temp_torrent->stop();
            }
            
            // Call user callback with success
            if (user_callback) {
                user_callback(captured_info, true, "");
            }
        }).detach();
    });
    
    // Store the temporary torrent
    {
        std::lock_guard<std::mutex> lock(metadata_mutex_);
        metadata_only_torrents_[info_hash] = metadata_torrent;
    }
    
    // Start the metadata torrent (just for peer connections)
    if (!metadata_torrent->start()) {
        LOG_BT_ERROR("Failed to start metadata retrieval torrent");
        
        // Cleanup and call callback with error
        {
            std::lock_guard<std::mutex> lock(metadata_mutex_);
            metadata_only_torrents_.erase(info_hash);
            auto it = metadata_retrieval_callbacks_.find(info_hash);
            if (it != metadata_retrieval_callbacks_.end()) {
                if (it->second) {
                    it->second(TorrentInfo(), false, "Failed to start metadata retrieval");
                }
                metadata_retrieval_callbacks_.erase(it);
            }
        }
        return;
    }
    
    // Use DHT to find peers for this info hash
    LOG_BT_INFO("Discovering peers via DHT for hash: " << info_hash_to_hex(info_hash));
    
    // Find peers via DHT
    dht_client_->find_peers(info_hash, [this, info_hash, metadata_torrent](const std::vector<Peer>& peers, const InfoHash& hash) {
        // Check if metadata torrent is still running (may have completed or been stopped)
        if (!metadata_torrent->is_running()) {
            LOG_BT_DEBUG("Metadata torrent already stopped, ignoring DHT peer discovery results");
            return;
        }
        
        // Check if metadata is already downloaded
        if (auto* md = metadata_torrent->get_metadata_download()) {
            if (md->is_complete()) {
                LOG_BT_DEBUG("Metadata already downloaded, ignoring DHT peer discovery results");
                return;
            }
        }
        
        LOG_BT_INFO("DHT found " << peers.size() << " peers for hash " << info_hash_to_hex(info_hash));
        
        if (peers.empty()) {
            LOG_BT_WARN("No peers found via DHT for hash " << info_hash_to_hex(info_hash));
            
            // Call callback with error
            MetadataRetrievalCallback user_callback;
            {
                std::lock_guard<std::mutex> lock(metadata_mutex_);
                auto it = metadata_retrieval_callbacks_.find(info_hash);
                if (it != metadata_retrieval_callbacks_.end()) {
                    user_callback = it->second;
                    metadata_retrieval_callbacks_.erase(it);
                }
                metadata_only_torrents_.erase(info_hash);
            }
            
            metadata_torrent->stop();
            
            if (user_callback) {
                user_callback(TorrentInfo(), false, "No peers found via DHT");
            }
            return;
        }
        
        // Connect to peers to get metadata
        size_t max_peers_to_try = (std::min)(peers.size(), static_cast<size_t>(10));
        size_t peers_added = 0;
        for (size_t i = 0; i < max_peers_to_try; ++i) {
            // Check again if metadata is complete (could have completed during loop)
            if (auto* md = metadata_torrent->get_metadata_download()) {
                if (md->is_complete()) {
                    LOG_BT_DEBUG("Metadata download completed, stopping peer additions");
                    break;
                }
            }
            
            // Check if torrent is still running
            if (!metadata_torrent->is_running()) {
                LOG_BT_DEBUG("Metadata torrent stopped, stopping peer additions");
                break;
            }
            
            const auto& peer = peers[i];
            LOG_BT_INFO("Connecting to peer " << peer.ip << ":" << peer.port << " for metadata retrieval");
            
            if (metadata_torrent->add_peer(peer)) {
                peers_added++;
            } else {
                LOG_BT_DEBUG("Failed to add peer " << peer.ip << ":" << peer.port);
            }
        }
        
        LOG_BT_INFO("Added " << peers_added << " peers for metadata retrieval");
    });
    
    LOG_BT_INFO("Metadata retrieval initiated for hash " << info_hash_to_hex(info_hash));
    LOG_BT_INFO("Waiting for DHT peer discovery and metadata exchange...");
}

void BitTorrentClient::get_torrent_metadata_by_hash(const std::string& info_hash_hex, MetadataRetrievalCallback callback) {
    InfoHash info_hash = hex_to_info_hash(info_hash_hex);
    
    // Validate the parsed hash
    bool is_zero = true;
    for (const auto& byte : info_hash) {
        if (byte != 0) {
            is_zero = false;
            break;
        }
    }
    
    if (is_zero && info_hash_hex.length() == 40) {
        LOG_BT_ERROR("Invalid info hash format: " << info_hash_hex);
        if (callback) {
            callback(TorrentInfo(), false, "Invalid info hash format");
        }
        return;
    }
    
    get_torrent_metadata_by_hash(info_hash, callback);
}

//=============================================================================
// Utility Functions Implementation
//=============================================================================

InfoHash calculate_info_hash(const BencodeValue& info_dict) {
    // Encode the info dictionary and calculate SHA1 hash
    std::vector<uint8_t> encoded = info_dict.encode();
    std::string hash_string = SHA1::hash_bytes(encoded);
    
    InfoHash result;
    // Convert hex string to bytes
    for (size_t i = 0; i < 20; ++i) {
        std::string byte_str = hash_string.substr(i * 2, 2);
        result[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
    
    return result;
}

std::string info_hash_to_hex(const InfoHash& hash) {
    std::ostringstream hex_stream;
    for (size_t i = 0; i < hash.size(); ++i) {
        hex_stream << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(hash[i]);
    }
    return hex_stream.str();
}

InfoHash hex_to_info_hash(const std::string& hex) {
    InfoHash result;
    result.fill(0);
    
    if (hex.length() != 40) { // 20 bytes * 2 hex chars per byte
        return result;
    }
    
    for (size_t i = 0; i < 20; ++i) {
        std::string byte_str = hex.substr(i * 2, 2);
        try {
            result[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        } catch (const std::exception&) {
            result.fill(0);
            return result;
        }
    }
    
    return result;
}

PeerID generate_peer_id() {
    PeerID peer_id;
    
    // Use librats- prefix to identify our client
    std::string prefix = "-LR0001-"; // LR = LibRats, 0001 = version
    std::copy(prefix.begin(), prefix.end(), peer_id.begin());
    
    // Fill the rest with random data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = prefix.length(); i < peer_id.size(); ++i) {
        peer_id[i] = static_cast<uint8_t>(dis(gen));
    }
    
    return peer_id;
}

std::vector<uint8_t> create_handshake_message(const InfoHash& info_hash, const PeerID& peer_id) {
    std::vector<uint8_t> handshake(68);
    
    // Protocol identifier length
    handshake[0] = BITTORRENT_PROTOCOL_ID_LENGTH;
    
    // Protocol identifier
    std::copy_n(BITTORRENT_PROTOCOL_ID, BITTORRENT_PROTOCOL_ID_LENGTH, handshake.begin() + 1);
    
    // Reserved bytes (8 bytes of zeros)
    std::fill_n(handshake.begin() + 20, 8, 0);
    
    // Info hash (20 bytes)
    std::copy(info_hash.begin(), info_hash.end(), handshake.begin() + 28);
    
    // Peer ID (20 bytes)
    std::copy(peer_id.begin(), peer_id.end(), handshake.begin() + 48);
    
    return handshake;
}

bool parse_handshake_message(const std::vector<uint8_t>& data, InfoHash& info_hash, PeerID& peer_id) {
    if (data.size() != 68) {
        return false;
    }
    
    // Check protocol identifier length
    if (data[0] != BITTORRENT_PROTOCOL_ID_LENGTH) {
        return false;
    }
    
    // Check protocol identifier
    std::string protocol_id(data.begin() + 1, data.begin() + 1 + BITTORRENT_PROTOCOL_ID_LENGTH);
    if (protocol_id != std::string(reinterpret_cast<const char*>(BITTORRENT_PROTOCOL_ID), BITTORRENT_PROTOCOL_ID_LENGTH)) {
        return false;
    }
    
    // Extract info hash
    std::copy(data.begin() + 28, data.begin() + 48, info_hash.begin());
    
    // Extract peer ID
    std::copy(data.begin() + 48, data.begin() + 68, peer_id.begin());
    
    return true;
}

} // namespace librats
