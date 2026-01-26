#include "bt_peer_connection.h"
#include "bencode.h"
#include "logger.h"
#include <algorithm>
#include <cstring>

namespace librats {

//=============================================================================
// Helpers
//=============================================================================

const char* peer_state_to_string(PeerConnectionState state) {
    switch (state) {
        case PeerConnectionState::Disconnected: return "Disconnected";
        case PeerConnectionState::Connecting: return "Connecting";
        case PeerConnectionState::Handshaking: return "Handshaking";
        case PeerConnectionState::Connected: return "Connected";
        case PeerConnectionState::Closing: return "Closing";
        default: return "Unknown";
    }
}

double PeerStats::download_rate() const {
    // Simple calculation - would need sliding window for accuracy
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - connected_at).count();
    if (duration <= 0) return 0.0;
    return static_cast<double>(bytes_downloaded) / duration;
}

double PeerStats::upload_rate() const {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - connected_at).count();
    if (duration <= 0) return 0.0;
    return static_cast<double>(bytes_uploaded) / duration;
}

//=============================================================================
// Constructor/Destructor
//=============================================================================

BtPeerConnection::BtPeerConnection(const BtInfoHash& info_hash,
                                   const PeerID& our_peer_id,
                                   uint32_t num_pieces)
    : socket_fd_(-1)
    , port_(0)
    , state_(PeerConnectionState::Disconnected)
    , our_info_hash_(info_hash)
    , our_peer_id_(our_peer_id)
    , num_pieces_(num_pieces)
    , info_hash_known_(true)  // Outgoing: info_hash is known
    , peer_info_hash_{}
    , peer_id_{}
    , handshake_received_(false)
    , handshake_sent_(false)
    , extension_handshake_received_(false)
    , peer_metadata_size_(0)
    , peer_ut_metadata_id_(0)
    , am_choking_(true)
    , am_interested_(false)
    , peer_choking_(true)
    , peer_interested_(false)
    , peer_pieces_(num_pieces)
    , recv_buffer_(8192)  // Initial receive buffer capacity
    , max_pending_requests_(BT_DEFAULT_REQUEST_QUEUE_SIZE) {
}

BtPeerConnection::BtPeerConnection(const PeerID& our_peer_id)
    : socket_fd_(-1)
    , port_(0)
    , state_(PeerConnectionState::Disconnected)
    , our_info_hash_{}
    , our_peer_id_(our_peer_id)
    , num_pieces_(0)
    , info_hash_known_(false)  // Incoming: info_hash unknown until handshake
    , peer_info_hash_{}
    , peer_id_{}
    , handshake_received_(false)
    , handshake_sent_(false)
    , extension_handshake_received_(false)
    , peer_metadata_size_(0)
    , peer_ut_metadata_id_(0)
    , am_choking_(true)
    , am_interested_(false)
    , peer_choking_(true)
    , peer_interested_(false)
    , peer_pieces_(0)  // Will be resized after set_torrent_info
    , recv_buffer_(8192)
    , max_pending_requests_(BT_DEFAULT_REQUEST_QUEUE_SIZE) {
}

BtPeerConnection::~BtPeerConnection() {
    close();
}

BtPeerConnection::BtPeerConnection(BtPeerConnection&& other) noexcept
    : socket_fd_(other.socket_fd_)
    , ip_(std::move(other.ip_))
    , port_(other.port_)
    , state_(other.state_.load())
    , our_info_hash_(std::move(other.our_info_hash_))
    , our_peer_id_(std::move(other.our_peer_id_))
    , num_pieces_(other.num_pieces_)
    , info_hash_known_(other.info_hash_known_)
    , peer_info_hash_(std::move(other.peer_info_hash_))
    , peer_id_(std::move(other.peer_id_))
    , peer_extensions_(other.peer_extensions_)
    , handshake_received_(other.handshake_received_)
    , handshake_sent_(other.handshake_sent_)
    , extension_handshake_received_(other.extension_handshake_received_)
    , peer_metadata_size_(other.peer_metadata_size_)
    , peer_ut_metadata_id_(other.peer_ut_metadata_id_)
    , am_choking_(other.am_choking_)
    , am_interested_(other.am_interested_)
    , peer_choking_(other.peer_choking_)
    , peer_interested_(other.peer_interested_)
    , peer_pieces_(std::move(other.peer_pieces_))
    , recv_buffer_(std::move(other.recv_buffer_))
    , send_buffer_(std::move(other.send_buffer_))
    , pending_requests_(std::move(other.pending_requests_))
    , max_pending_requests_(other.max_pending_requests_)
    , stats_(other.stats_)
    , on_message_(std::move(other.on_message_))
    , on_state_change_(std::move(other.on_state_change_))
    , on_handshake_(std::move(other.on_handshake_))
    , on_error_(std::move(other.on_error_))
    , on_info_hash_(std::move(other.on_info_hash_)) {
    other.socket_fd_ = -1;
    other.state_ = PeerConnectionState::Disconnected;
}

BtPeerConnection& BtPeerConnection::operator=(BtPeerConnection&& other) noexcept {
    if (this != &other) {
        close();
        
        socket_fd_ = other.socket_fd_;
        ip_ = std::move(other.ip_);
        port_ = other.port_;
        state_ = other.state_.load();
        our_info_hash_ = std::move(other.our_info_hash_);
        our_peer_id_ = std::move(other.our_peer_id_);
        num_pieces_ = other.num_pieces_;
        info_hash_known_ = other.info_hash_known_;
        peer_info_hash_ = std::move(other.peer_info_hash_);
        peer_id_ = std::move(other.peer_id_);
        peer_extensions_ = other.peer_extensions_;
        handshake_received_ = other.handshake_received_;
        handshake_sent_ = other.handshake_sent_;
        extension_handshake_received_ = other.extension_handshake_received_;
        peer_metadata_size_ = other.peer_metadata_size_;
        peer_ut_metadata_id_ = other.peer_ut_metadata_id_;
        am_choking_ = other.am_choking_;
        am_interested_ = other.am_interested_;
        peer_choking_ = other.peer_choking_;
        peer_interested_ = other.peer_interested_;
        peer_pieces_ = std::move(other.peer_pieces_);
        recv_buffer_ = std::move(other.recv_buffer_);
        send_buffer_ = std::move(other.send_buffer_);
        pending_requests_ = std::move(other.pending_requests_);
        max_pending_requests_ = other.max_pending_requests_;
        stats_ = other.stats_;
        on_message_ = std::move(other.on_message_);
        on_state_change_ = std::move(other.on_state_change_);
        on_handshake_ = std::move(other.on_handshake_);
        on_error_ = std::move(other.on_error_);
        on_info_hash_ = std::move(other.on_info_hash_);
        
        other.socket_fd_ = -1;
        other.state_ = PeerConnectionState::Disconnected;
    }
    return *this;
}

//=============================================================================
// Connection Management
//=============================================================================

void BtPeerConnection::set_socket(int socket_fd) {
    socket_fd_ = socket_fd;
    if (socket_fd >= 0) {
        set_state(PeerConnectionState::Handshaking);
        stats_.connected_at = std::chrono::steady_clock::now();
    }
}

void BtPeerConnection::set_address(const std::string& ip, uint16_t port) {
    ip_ = ip;
    port_ = port;
}

void BtPeerConnection::start_handshake() {
    if (handshake_sent_) return;
    
    LOG_DEBUG("BtPeerConn", "Sending handshake to " + ip_);
    auto hs = BtHandshake::encode_with_extensions(our_info_hash_, our_peer_id_);
    queue_send(hs);
    handshake_sent_ = true;
}

void BtPeerConnection::close() {
    if (state_ == PeerConnectionState::Disconnected) return;
    
    set_state(PeerConnectionState::Closing);
    
    // Clear buffers
    recv_buffer_.clear();
    send_buffer_.clear();
    pending_requests_.clear();
    
    // Socket closing should be handled by the owner
    socket_fd_ = -1;
    
    set_state(PeerConnectionState::Disconnected);
}

void BtPeerConnection::set_torrent_info(const BtInfoHash& info_hash, uint32_t num_pieces) {
    our_info_hash_ = info_hash;
    num_pieces_ = num_pieces;
    info_hash_known_ = true;
    
    // Resize peer_pieces bitfield if needed
    if (peer_pieces_.size() != num_pieces) {
        peer_pieces_ = Bitfield(num_pieces);
    }
    
    LOG_DEBUG("BtPeerConn", "Set torrent info for " + ip_ + 
              ": info_hash=" + info_hash_to_hex(info_hash).substr(0, 8) + 
              "..., num_pieces=" + std::to_string(num_pieces));
}

void BtPeerConnection::set_state(PeerConnectionState new_state) {
    PeerConnectionState old_state = state_.exchange(new_state);
    if (old_state != new_state && on_state_change_) {
        on_state_change_(this, new_state);
    }
}

//=============================================================================
// Data Processing
//=============================================================================

void BtPeerConnection::process_incoming() {
    if (recv_buffer_.empty()) return;
    
    stats_.last_message_at = std::chrono::steady_clock::now();
    
    LOG_DEBUG("BtPeerConn", "process_incoming: " + std::to_string(recv_buffer_.size()) + 
              " bytes from " + ip_);
    
    // Process handshake first
    if (!handshake_received_) {
        process_handshake();
    }
    
    // Then process messages
    if (handshake_received_) {
        process_messages();
    }
    
    // Periodically normalize buffer to reclaim space
    if (recv_buffer_.front_waste() > 4096) {
        recv_buffer_.normalize();
    }
}

void BtPeerConnection::process_handshake() {
    if (recv_buffer_.size() < BT_HANDSHAKE_SIZE) {
        LOG_DEBUG("BtPeerConn", "process_handshake: waiting for more data, have " + 
                  std::to_string(recv_buffer_.size()) + "/" + std::to_string(BT_HANDSHAKE_SIZE) + " bytes");
        return;  // Wait for more data
    }
    
    auto hs = BtHandshake::decode(recv_buffer_.data(), recv_buffer_.size());
    if (!hs) {
        LOG_ERROR("BtPeerConn", "Invalid handshake from " + ip_);
        if (on_error_) {
            on_error_(this, "Invalid handshake");
        }
        close();
        return;
    }
    
    // Store peer info
    peer_info_hash_ = hs->info_hash;
    peer_id_ = hs->peer_id;
    peer_extensions_ = hs->extensions;
    
    // For incoming connections, we need to notify about the info_hash first
    // so NetworkManager can look up the torrent and call set_torrent_info()
    if (!info_hash_known_) {
        LOG_DEBUG("BtPeerConn", "Incoming connection: notifying info_hash " + 
                  info_hash_to_hex(hs->info_hash).substr(0, 8) + "...");
        
        if (on_info_hash_) {
            on_info_hash_(this, hs->info_hash);
        }
        
        // After callback, info_hash should be set via set_torrent_info()
        // If not, the connection should be closed by the callback handler
        if (!info_hash_known_) {
            LOG_ERROR("BtPeerConn", "Unknown torrent from " + ip_ + 
                      ", info_hash=" + info_hash_to_hex(hs->info_hash).substr(0, 8) + "...");
            if (on_error_) {
                on_error_(this, "Unknown torrent");
            }
            close();
            return;
        }
    }
    
    // Verify info hash matches (for outgoing connections, or after set_torrent_info)
    if (hs->info_hash != our_info_hash_) {
        LOG_ERROR("BtPeerConn", "Info hash mismatch from " + ip_);
        if (on_error_) {
            on_error_(this, "Info hash mismatch");
        }
        close();
        return;
    }
    
    handshake_received_ = true;
    
    // Format peer_id for logging (first 8 chars, printable only)
    std::string peer_id_str;
    for (size_t i = 0; i < 8 && i < peer_id_.size(); ++i) {
        char c = static_cast<char>(peer_id_[i]);
        peer_id_str += (c >= 32 && c < 127) ? c : '.';
    }
    
    LOG_INFO("BtPeerConn", "Handshake received from " + ip_ + ", peer_id=" + peer_id_str + 
             ", ext_protocol=" + (hs->extensions.extension_protocol ? "yes" : "no") +
             ", fast=" + (hs->extensions.fast ? "yes" : "no"));
    
    // Consume handshake from buffer - O(1) operation!
    recv_buffer_.consume(BT_HANDSHAKE_SIZE);
    
    // Notify
    if (on_handshake_) {
        on_handshake_(this, *hs);
    }
    
    // If we haven't sent our handshake yet, do it now
    if (!handshake_sent_) {
        start_handshake();
    }
    
    // Transition to connected
    set_state(PeerConnectionState::Connected);
}

void BtPeerConnection::process_messages() {
    while (!recv_buffer_.empty()) {
        // Check for complete message
        size_t msg_len = BtMessageDecoder::message_length(
            recv_buffer_.data(), recv_buffer_.size());
        
        if (msg_len == 0) {
            break;  // Incomplete message
        }
        
        // Check for keep-alive
        if (BtMessageDecoder::is_keepalive(recv_buffer_.data(), recv_buffer_.size())) {
            LOG_DEBUG("BtPeerConn", "Received keep-alive from " + ip_);
            recv_buffer_.consume(4);  // O(1) operation!
            continue;
        }
        
        // Decode message
        auto msg = BtMessageDecoder::decode(
            recv_buffer_.data(), recv_buffer_.size(), num_pieces_);
        
        if (msg) {
            handle_message(*msg);
            ++stats_.messages_received;
        } else {
            LOG_WARN("BtPeerConn", "Failed to decode message from " + ip_ + 
                     ", msg_len=" + std::to_string(msg_len));
        }
        
        // Consume processed message - O(1) operation!
        recv_buffer_.consume(msg_len);
    }
}

void BtPeerConnection::handle_message(const BtMessage& msg) {
    // Log message details based on type
    std::string log_detail;
    switch (msg.type) {
        case BtMessageType::Have:
            log_detail = " piece=" + std::to_string(msg.have_piece);
            break;
        case BtMessageType::Bitfield:
            if (msg.bitfield) {
                log_detail = " bits=" + std::to_string(msg.bitfield->count());
            }
            break;
        case BtMessageType::Request:
            if (msg.request) {
                log_detail = " piece=" + std::to_string(msg.request->piece_index) +
                             " begin=" + std::to_string(msg.request->begin) +
                             " len=" + std::to_string(msg.request->length);
            }
            break;
        case BtMessageType::Piece:
            if (msg.piece) {
                log_detail = " piece=" + std::to_string(msg.piece->piece_index) +
                             " begin=" + std::to_string(msg.piece->begin) +
                             " len=" + std::to_string(msg.piece->data.size());
            }
            break;
        case BtMessageType::Extended:
            log_detail = " ext_id=" + std::to_string(msg.extension_id) +
                         " payload=" + std::to_string(msg.extension_payload.size()) + " bytes";
            break;
        default:
            break;
    }
    
    LOG_DEBUG("BtPeerConn", "handle_message: " + std::string(message_type_to_string(msg.type)) + 
              " from " + ip_ + log_detail);
    
    switch (msg.type) {
        case BtMessageType::Choke:
            peer_choking_ = true;
            break;
            
        case BtMessageType::Unchoke:
            peer_choking_ = false;
            break;
            
        case BtMessageType::Interested:
            peer_interested_ = true;
            break;
            
        case BtMessageType::NotInterested:
            peer_interested_ = false;
            break;
            
        case BtMessageType::Have:
            if (msg.have_piece < num_pieces_) {
                peer_pieces_.set_bit(msg.have_piece);
            }
            break;
            
        case BtMessageType::Bitfield:
            if (msg.bitfield) {
                peer_pieces_ = *msg.bitfield;
            }
            break;
            
        case BtMessageType::Piece:
            if (msg.piece) {
                stats_.bytes_downloaded += msg.piece->data.size();
                stats_.last_piece_at = std::chrono::steady_clock::now();
                ++stats_.pieces_received;
                
                // Remove from pending
                if (msg.piece) {
                    RequestMessage req(msg.piece->piece_index, msg.piece->begin, 
                                      static_cast<uint32_t>(msg.piece->data.size()));
                    remove_pending_request(req);
                }
            }
            break;
            
        case BtMessageType::HaveAll:
            peer_pieces_.set_all();
            break;
            
        case BtMessageType::HaveNone:
            peer_pieces_.clear_all();
            break;
            
        case BtMessageType::Extended:
            // Parse extension handshake (ext_id=0) and store data for late callback registration
            if (msg.extension_id == 0 && !msg.extension_payload.empty()) {
                parse_extension_handshake(msg.extension_payload);
            }
            break;
            
        default:
            break;
    }
    
    // Notify callback
    if (on_message_) {
        on_message_(this, msg);
    }
}

void BtPeerConnection::parse_extension_handshake(const std::vector<uint8_t>& payload) {
    // Parse the bencoded extension handshake to extract metadata info
    // This data is stored so Torrent can access it even if callback wasn't set yet
    
    BencodeValue decoded;
    try {
        decoded = BencodeDecoder::decode(payload);
    } catch (...) {
        LOG_DEBUG("BtPeerConn", "Failed to decode extension handshake from " + ip_);
        return;
    }
    
    if (!decoded.is_dict()) {
        return;
    }
    
    const auto& dict = decoded.as_dict();
    extension_handshake_received_ = true;
    
    // Extract metadata_size if present
    auto metadata_size_it = dict.find("metadata_size");
    if (metadata_size_it != dict.end() && metadata_size_it->second.is_integer()) {
        peer_metadata_size_ = static_cast<size_t>(metadata_size_it->second.as_integer());
        LOG_DEBUG("BtPeerConn", "Peer " + ip_ + " has metadata_size=" + 
                  std::to_string(peer_metadata_size_));
    }
    
    // Extract ut_metadata message ID from 'm' dictionary
    auto m_it = dict.find("m");
    if (m_it != dict.end() && m_it->second.is_dict()) {
        const auto& m = m_it->second.as_dict();
        auto ut_metadata_it = m.find("ut_metadata");
        if (ut_metadata_it != m.end() && ut_metadata_it->second.is_integer()) {
            peer_ut_metadata_id_ = static_cast<uint8_t>(ut_metadata_it->second.as_integer());
            LOG_DEBUG("BtPeerConn", "Peer " + ip_ + " ut_metadata_id=" + 
                      std::to_string(peer_ut_metadata_id_));
        }
    }
}

void BtPeerConnection::queue_send(const std::vector<uint8_t>& data) {
    send_buffer_.append(data.data(), data.size());
    LOG_DEBUG("BtPeerConn", "queue_send: " + std::to_string(data.size()) + " bytes to " + ip_ + 
              ", buffer now " + std::to_string(send_buffer_.size()) + " bytes");
}

//=============================================================================
// Protocol State
//=============================================================================

bool BtPeerConnection::peer_has_piece(uint32_t piece) const {
    return peer_pieces_.get_bit(piece);
}

//=============================================================================
// Sending Messages
//=============================================================================

void BtPeerConnection::send_choke() {
    LOG_DEBUG("BtPeerConn", "send_choke to " + ip_);
    am_choking_ = true;
    queue_send(BtMessageEncoder::encode_choke());
    ++stats_.messages_sent;
}

void BtPeerConnection::send_unchoke() {
    LOG_DEBUG("BtPeerConn", "send_unchoke to " + ip_);
    am_choking_ = false;
    queue_send(BtMessageEncoder::encode_unchoke());
    ++stats_.messages_sent;
}

void BtPeerConnection::send_interested() {
    LOG_DEBUG("BtPeerConn", "send_interested to " + ip_);
    am_interested_ = true;
    queue_send(BtMessageEncoder::encode_interested());
    ++stats_.messages_sent;
}

void BtPeerConnection::send_not_interested() {
    LOG_DEBUG("BtPeerConn", "send_not_interested to " + ip_);
    am_interested_ = false;
    queue_send(BtMessageEncoder::encode_not_interested());
    ++stats_.messages_sent;
}

void BtPeerConnection::send_have(uint32_t piece_index) {
    LOG_DEBUG("BtPeerConn", "send_have piece=" + std::to_string(piece_index) + " to " + ip_);
    queue_send(BtMessageEncoder::encode_have(piece_index));
    ++stats_.messages_sent;
}

void BtPeerConnection::send_bitfield(const Bitfield& bitfield) {
    LOG_DEBUG("BtPeerConn", "send_bitfield bits=" + std::to_string(bitfield.count()) + " to " + ip_);
    queue_send(BtMessageEncoder::encode_bitfield(bitfield));
    ++stats_.messages_sent;
}

void BtPeerConnection::send_request(uint32_t piece, uint32_t begin, uint32_t length) {
    LOG_DEBUG("BtPeerConn", "send_request piece=" + std::to_string(piece) + 
              " begin=" + std::to_string(begin) + " len=" + std::to_string(length) + " to " + ip_);
    queue_send(BtMessageEncoder::encode_request(piece, begin, length));
    ++stats_.messages_sent;
    
    add_pending_request(RequestMessage(piece, begin, length));
}

void BtPeerConnection::send_piece(uint32_t piece, uint32_t begin, 
                                   const uint8_t* data, size_t length) {
    LOG_DEBUG("BtPeerConn", "send_piece piece=" + std::to_string(piece) + 
              " begin=" + std::to_string(begin) + " len=" + std::to_string(length) + " to " + ip_);
    queue_send(BtMessageEncoder::encode_piece(piece, begin, data, length));
    stats_.bytes_uploaded += length;
    ++stats_.pieces_sent;
    ++stats_.messages_sent;
}

void BtPeerConnection::send_cancel(uint32_t piece, uint32_t begin, uint32_t length) {
    LOG_DEBUG("BtPeerConn", "send_cancel piece=" + std::to_string(piece) + 
              " begin=" + std::to_string(begin) + " len=" + std::to_string(length) + " to " + ip_);
    queue_send(BtMessageEncoder::encode_cancel(piece, begin, length));
    ++stats_.messages_sent;
    
    remove_pending_request(RequestMessage(piece, begin, length));
}

void BtPeerConnection::send_keepalive() {
    LOG_DEBUG("BtPeerConn", "send_keepalive to " + ip_);
    queue_send(BtMessageEncoder::encode_keepalive());
}

void BtPeerConnection::send_extended(uint8_t extension_id, 
                                      const std::vector<uint8_t>& payload) {
    LOG_DEBUG("BtPeerConn", "send_extended ext_id=" + std::to_string(extension_id) + 
              " payload=" + std::to_string(payload.size()) + " bytes to " + ip_);
    queue_send(BtMessageEncoder::encode_extended(extension_id, payload));
    ++stats_.messages_sent;
}

//=============================================================================
// Request Tracking
//=============================================================================

void BtPeerConnection::add_pending_request(const RequestMessage& req) {
    // Avoid duplicates
    auto it = std::find(pending_requests_.begin(), pending_requests_.end(), req);
    if (it == pending_requests_.end()) {
        pending_requests_.push_back(req);
    }
}

void BtPeerConnection::remove_pending_request(const RequestMessage& req) {
    auto it = std::find(pending_requests_.begin(), pending_requests_.end(), req);
    if (it != pending_requests_.end()) {
        pending_requests_.erase(it);
    }
}

void BtPeerConnection::clear_pending_requests() {
    pending_requests_.clear();
}

} // namespace librats
