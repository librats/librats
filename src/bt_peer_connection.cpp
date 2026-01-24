#include "bt_peer_connection.h"
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
    , peer_info_hash_{}
    , peer_id_{}
    , handshake_received_(false)
    , handshake_sent_(false)
    , am_choking_(true)
    , am_interested_(false)
    , peer_choking_(true)
    , peer_interested_(false)
    , peer_pieces_(num_pieces)
    , send_offset_(0)
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
    , peer_info_hash_(std::move(other.peer_info_hash_))
    , peer_id_(std::move(other.peer_id_))
    , peer_extensions_(other.peer_extensions_)
    , handshake_received_(other.handshake_received_)
    , handshake_sent_(other.handshake_sent_)
    , am_choking_(other.am_choking_)
    , am_interested_(other.am_interested_)
    , peer_choking_(other.peer_choking_)
    , peer_interested_(other.peer_interested_)
    , peer_pieces_(std::move(other.peer_pieces_))
    , recv_buffer_(std::move(other.recv_buffer_))
    , send_buffer_(std::move(other.send_buffer_))
    , send_offset_(other.send_offset_)
    , pending_requests_(std::move(other.pending_requests_))
    , max_pending_requests_(other.max_pending_requests_)
    , stats_(other.stats_)
    , on_message_(std::move(other.on_message_))
    , on_state_change_(std::move(other.on_state_change_))
    , on_handshake_(std::move(other.on_handshake_))
    , on_error_(std::move(other.on_error_)) {
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
        peer_info_hash_ = std::move(other.peer_info_hash_);
        peer_id_ = std::move(other.peer_id_);
        peer_extensions_ = other.peer_extensions_;
        handshake_received_ = other.handshake_received_;
        handshake_sent_ = other.handshake_sent_;
        am_choking_ = other.am_choking_;
        am_interested_ = other.am_interested_;
        peer_choking_ = other.peer_choking_;
        peer_interested_ = other.peer_interested_;
        peer_pieces_ = std::move(other.peer_pieces_);
        recv_buffer_ = std::move(other.recv_buffer_);
        send_buffer_ = std::move(other.send_buffer_);
        send_offset_ = other.send_offset_;
        pending_requests_ = std::move(other.pending_requests_);
        max_pending_requests_ = other.max_pending_requests_;
        stats_ = other.stats_;
        on_message_ = std::move(other.on_message_);
        on_state_change_ = std::move(other.on_state_change_);
        on_handshake_ = std::move(other.on_handshake_);
        on_error_ = std::move(other.on_error_);
        
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
    send_offset_ = 0;
    pending_requests_.clear();
    
    // Socket closing should be handled by the owner
    socket_fd_ = -1;
    
    set_state(PeerConnectionState::Disconnected);
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

void BtPeerConnection::on_receive(const uint8_t* data, size_t length) {
    if (length == 0) return;
    
    // Append to receive buffer
    recv_buffer_.insert(recv_buffer_.end(), data, data + length);
    stats_.last_message_at = std::chrono::steady_clock::now();
    
    // Process handshake first
    if (!handshake_received_) {
        process_handshake();
    }
    
    // Then process messages
    if (handshake_received_) {
        process_messages();
    }
}

void BtPeerConnection::process_handshake() {
    if (recv_buffer_.size() < BT_HANDSHAKE_SIZE) {
        return;  // Wait for more data
    }
    
    auto hs = BtHandshake::decode(recv_buffer_.data(), recv_buffer_.size());
    if (!hs) {
        if (on_error_) {
            on_error_(this, "Invalid handshake");
        }
        close();
        return;
    }
    
    // Verify info hash matches
    if (hs->info_hash != our_info_hash_) {
        if (on_error_) {
            on_error_(this, "Info hash mismatch");
        }
        close();
        return;
    }
    
    // Store peer info
    peer_info_hash_ = hs->info_hash;
    peer_id_ = hs->peer_id;
    peer_extensions_ = hs->extensions;
    handshake_received_ = true;
    
    // Remove handshake from buffer
    recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + BT_HANDSHAKE_SIZE);
    
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
            recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + 4);
            continue;
        }
        
        // Decode message
        auto msg = BtMessageDecoder::decode(
            recv_buffer_.data(), recv_buffer_.size(), num_pieces_);
        
        if (msg) {
            handle_message(*msg);
            ++stats_.messages_received;
        }
        
        // Remove processed message
        recv_buffer_.erase(recv_buffer_.begin(), recv_buffer_.begin() + msg_len);
    }
}

void BtPeerConnection::handle_message(const BtMessage& msg) {
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
            
        default:
            break;
    }
    
    // Notify callback
    if (on_message_) {
        on_message_(this, msg);
    }
}

size_t BtPeerConnection::get_send_data(uint8_t* buffer, size_t max_length) {
    size_t available = send_buffer_.size() - send_offset_;
    size_t to_copy = std::min(available, max_length);
    
    if (to_copy > 0) {
        std::memcpy(buffer, send_buffer_.data() + send_offset_, to_copy);
    }
    
    return to_copy;
}

bool BtPeerConnection::has_send_data() const {
    return send_offset_ < send_buffer_.size();
}

void BtPeerConnection::mark_sent(size_t bytes) {
    send_offset_ += bytes;
    
    // If all data sent, clear buffer
    if (send_offset_ >= send_buffer_.size()) {
        send_buffer_.clear();
        send_offset_ = 0;
    }
}

void BtPeerConnection::queue_send(const std::vector<uint8_t>& data) {
    send_buffer_.insert(send_buffer_.end(), data.begin(), data.end());
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
    am_choking_ = true;
    queue_send(BtMessageEncoder::encode_choke());
    ++stats_.messages_sent;
}

void BtPeerConnection::send_unchoke() {
    am_choking_ = false;
    queue_send(BtMessageEncoder::encode_unchoke());
    ++stats_.messages_sent;
}

void BtPeerConnection::send_interested() {
    am_interested_ = true;
    queue_send(BtMessageEncoder::encode_interested());
    ++stats_.messages_sent;
}

void BtPeerConnection::send_not_interested() {
    am_interested_ = false;
    queue_send(BtMessageEncoder::encode_not_interested());
    ++stats_.messages_sent;
}

void BtPeerConnection::send_have(uint32_t piece_index) {
    queue_send(BtMessageEncoder::encode_have(piece_index));
    ++stats_.messages_sent;
}

void BtPeerConnection::send_bitfield(const Bitfield& bitfield) {
    queue_send(BtMessageEncoder::encode_bitfield(bitfield));
    ++stats_.messages_sent;
}

void BtPeerConnection::send_request(uint32_t piece, uint32_t begin, uint32_t length) {
    queue_send(BtMessageEncoder::encode_request(piece, begin, length));
    ++stats_.messages_sent;
    
    add_pending_request(RequestMessage(piece, begin, length));
}

void BtPeerConnection::send_piece(uint32_t piece, uint32_t begin, 
                                   const uint8_t* data, size_t length) {
    queue_send(BtMessageEncoder::encode_piece(piece, begin, data, length));
    stats_.bytes_uploaded += length;
    ++stats_.pieces_sent;
    ++stats_.messages_sent;
}

void BtPeerConnection::send_cancel(uint32_t piece, uint32_t begin, uint32_t length) {
    queue_send(BtMessageEncoder::encode_cancel(piece, begin, length));
    ++stats_.messages_sent;
    
    remove_pending_request(RequestMessage(piece, begin, length));
}

void BtPeerConnection::send_keepalive() {
    queue_send(BtMessageEncoder::encode_keepalive());
}

void BtPeerConnection::send_extended(uint8_t extension_id, 
                                      const std::vector<uint8_t>& payload) {
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
