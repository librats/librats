#include "bt_messages.h"
#include <cstring>

namespace librats {

//=============================================================================
// Helpers
//=============================================================================

const char* message_type_to_string(BtMessageType type) {
    switch (type) {
        case BtMessageType::Choke: return "Choke";
        case BtMessageType::Unchoke: return "Unchoke";
        case BtMessageType::Interested: return "Interested";
        case BtMessageType::NotInterested: return "NotInterested";
        case BtMessageType::Have: return "Have";
        case BtMessageType::Bitfield: return "Bitfield";
        case BtMessageType::Request: return "Request";
        case BtMessageType::Piece: return "Piece";
        case BtMessageType::Cancel: return "Cancel";
        case BtMessageType::Port: return "Port";
        case BtMessageType::SuggestPiece: return "SuggestPiece";
        case BtMessageType::HaveAll: return "HaveAll";
        case BtMessageType::HaveNone: return "HaveNone";
        case BtMessageType::RejectRequest: return "RejectRequest";
        case BtMessageType::AllowedFast: return "AllowedFast";
        case BtMessageType::Extended: return "Extended";
        default: return "Unknown";
    }
}

//=============================================================================
// Encoder Helper Methods
//=============================================================================

void BtMessageEncoder::write_uint32(std::vector<uint8_t>& buf, uint32_t value) {
    buf.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(value & 0xFF));
}

void BtMessageEncoder::write_uint16(std::vector<uint8_t>& buf, uint16_t value) {
    buf.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(value & 0xFF));
}

//=============================================================================
// Core Protocol Encoding (BEP 3)
//=============================================================================

std::vector<uint8_t> BtMessageEncoder::encode_keepalive() {
    std::vector<uint8_t> msg;
    write_uint32(msg, 0);  // length = 0
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_choke() {
    std::vector<uint8_t> msg;
    write_uint32(msg, 1);  // length = 1
    msg.push_back(static_cast<uint8_t>(BtMessageType::Choke));
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_unchoke() {
    std::vector<uint8_t> msg;
    write_uint32(msg, 1);
    msg.push_back(static_cast<uint8_t>(BtMessageType::Unchoke));
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_interested() {
    std::vector<uint8_t> msg;
    write_uint32(msg, 1);
    msg.push_back(static_cast<uint8_t>(BtMessageType::Interested));
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_not_interested() {
    std::vector<uint8_t> msg;
    write_uint32(msg, 1);
    msg.push_back(static_cast<uint8_t>(BtMessageType::NotInterested));
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_have(uint32_t piece_index) {
    std::vector<uint8_t> msg;
    write_uint32(msg, 5);  // length = 1 (type) + 4 (piece index)
    msg.push_back(static_cast<uint8_t>(BtMessageType::Have));
    write_uint32(msg, piece_index);
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_bitfield(const Bitfield& bitfield) {
    std::vector<uint8_t> bf_bytes = bitfield.to_bytes();
    
    std::vector<uint8_t> msg;
    write_uint32(msg, static_cast<uint32_t>(1 + bf_bytes.size()));  // length
    msg.push_back(static_cast<uint8_t>(BtMessageType::Bitfield));
    msg.insert(msg.end(), bf_bytes.begin(), bf_bytes.end());
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_request(uint32_t piece_index,
                                                       uint32_t begin,
                                                       uint32_t length) {
    std::vector<uint8_t> msg;
    write_uint32(msg, 13);  // length = 1 + 4 + 4 + 4
    msg.push_back(static_cast<uint8_t>(BtMessageType::Request));
    write_uint32(msg, piece_index);
    write_uint32(msg, begin);
    write_uint32(msg, length);
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_request(const RequestMessage& req) {
    return encode_request(req.piece_index, req.begin, req.length);
}

std::vector<uint8_t> BtMessageEncoder::encode_piece(uint32_t piece_index,
                                                     uint32_t begin,
                                                     const uint8_t* data,
                                                     size_t length) {
    std::vector<uint8_t> msg;
    write_uint32(msg, static_cast<uint32_t>(9 + length));  // length = 1 + 4 + 4 + data
    msg.push_back(static_cast<uint8_t>(BtMessageType::Piece));
    write_uint32(msg, piece_index);
    write_uint32(msg, begin);
    msg.insert(msg.end(), data, data + length);
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_piece(const PieceMessage& piece) {
    return encode_piece(piece.piece_index, piece.begin, 
                        piece.data.data(), piece.data.size());
}

std::vector<uint8_t> BtMessageEncoder::encode_cancel(uint32_t piece_index,
                                                      uint32_t begin,
                                                      uint32_t length) {
    std::vector<uint8_t> msg;
    write_uint32(msg, 13);  // length = 1 + 4 + 4 + 4
    msg.push_back(static_cast<uint8_t>(BtMessageType::Cancel));
    write_uint32(msg, piece_index);
    write_uint32(msg, begin);
    write_uint32(msg, length);
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_cancel(const RequestMessage& req) {
    return encode_cancel(req.piece_index, req.begin, req.length);
}

std::vector<uint8_t> BtMessageEncoder::encode_port(uint16_t port) {
    std::vector<uint8_t> msg;
    write_uint32(msg, 3);  // length = 1 + 2
    msg.push_back(static_cast<uint8_t>(BtMessageType::Port));
    write_uint16(msg, port);
    return msg;
}

//=============================================================================
// Fast Extension Encoding (BEP 6)
//=============================================================================

std::vector<uint8_t> BtMessageEncoder::encode_have_all() {
    std::vector<uint8_t> msg;
    write_uint32(msg, 1);
    msg.push_back(static_cast<uint8_t>(BtMessageType::HaveAll));
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_have_none() {
    std::vector<uint8_t> msg;
    write_uint32(msg, 1);
    msg.push_back(static_cast<uint8_t>(BtMessageType::HaveNone));
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_suggest_piece(uint32_t piece_index) {
    std::vector<uint8_t> msg;
    write_uint32(msg, 5);
    msg.push_back(static_cast<uint8_t>(BtMessageType::SuggestPiece));
    write_uint32(msg, piece_index);
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_reject_request(uint32_t piece_index,
                                                              uint32_t begin,
                                                              uint32_t length) {
    std::vector<uint8_t> msg;
    write_uint32(msg, 13);
    msg.push_back(static_cast<uint8_t>(BtMessageType::RejectRequest));
    write_uint32(msg, piece_index);
    write_uint32(msg, begin);
    write_uint32(msg, length);
    return msg;
}

std::vector<uint8_t> BtMessageEncoder::encode_allowed_fast(uint32_t piece_index) {
    std::vector<uint8_t> msg;
    write_uint32(msg, 5);
    msg.push_back(static_cast<uint8_t>(BtMessageType::AllowedFast));
    write_uint32(msg, piece_index);
    return msg;
}

//=============================================================================
// Extension Protocol Encoding (BEP 10)
//=============================================================================

std::vector<uint8_t> BtMessageEncoder::encode_extended(uint8_t extension_id,
                                                        const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> msg;
    write_uint32(msg, static_cast<uint32_t>(2 + payload.size()));  // length = 1 + 1 + payload
    msg.push_back(static_cast<uint8_t>(BtMessageType::Extended));
    msg.push_back(extension_id);
    msg.insert(msg.end(), payload.begin(), payload.end());
    return msg;
}

//=============================================================================
// Decoder Helper Methods
//=============================================================================

uint32_t BtMessageDecoder::read_uint32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

uint16_t BtMessageDecoder::read_uint16(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) |
           static_cast<uint16_t>(data[1]);
}

//=============================================================================
// Message Decoding
//=============================================================================

size_t BtMessageDecoder::message_length(const uint8_t* data, size_t length) {
    if (length < 4) {
        return 0;  // Not enough data to read length prefix
    }
    
    uint32_t msg_len = read_uint32(data);
    size_t total_len = 4 + msg_len;  // 4-byte length prefix + message
    
    if (length < total_len) {
        return 0;  // Message not complete
    }
    
    return total_len;
}

bool BtMessageDecoder::is_keepalive(const uint8_t* data, size_t length) {
    if (length < 4) return false;
    return read_uint32(data) == 0;
}

std::optional<BtMessage> BtMessageDecoder::decode(const uint8_t* data,
                                                   size_t length,
                                                   uint32_t num_pieces) {
    if (length < 4) {
        return std::nullopt;
    }
    
    uint32_t msg_len = read_uint32(data);
    
    // Keep-alive: length = 0
    if (msg_len == 0) {
        return BtMessage(BtMessageType::Choke);  // Treat as choke for simplicity
    }
    
    if (length < 4 + msg_len || msg_len < 1) {
        return std::nullopt;
    }
    
    const uint8_t* payload = data + 4;
    uint8_t type_byte = payload[0];
    
    BtMessage msg;
    msg.type = static_cast<BtMessageType>(type_byte);
    
    switch (msg.type) {
        case BtMessageType::Choke:
        case BtMessageType::Unchoke:
        case BtMessageType::Interested:
        case BtMessageType::NotInterested:
        case BtMessageType::HaveAll:
        case BtMessageType::HaveNone:
            // No additional data
            if (msg_len != 1) return std::nullopt;
            break;
            
        case BtMessageType::Have:
        case BtMessageType::SuggestPiece:
        case BtMessageType::AllowedFast:
            // 4-byte piece index
            if (msg_len != 5) return std::nullopt;
            msg.have_piece = read_uint32(payload + 1);
            break;
            
        case BtMessageType::Port:
            // 2-byte port
            if (msg_len != 3) return std::nullopt;
            msg.port = read_uint16(payload + 1);
            break;
            
        case BtMessageType::Bitfield: {
            // Variable length
            size_t bf_len = msg_len - 1;
            size_t expected_bits = num_pieces > 0 ? num_pieces : bf_len * 8;
            msg.bitfield = Bitfield::from_bytes(payload + 1, bf_len, expected_bits);
            break;
        }
            
        case BtMessageType::Request:
        case BtMessageType::Cancel:
        case BtMessageType::RejectRequest:
            // 12 bytes: piece index (4) + begin (4) + length (4)
            if (msg_len != 13) return std::nullopt;
            msg.request = RequestMessage(
                read_uint32(payload + 1),
                read_uint32(payload + 5),
                read_uint32(payload + 9)
            );
            break;
            
        case BtMessageType::Piece: {
            // Variable length: piece index (4) + begin (4) + data
            if (msg_len < 9) return std::nullopt;
            
            uint32_t piece_index = read_uint32(payload + 1);
            uint32_t begin = read_uint32(payload + 5);
            size_t data_len = msg_len - 9;
            
            std::vector<uint8_t> piece_data(payload + 9, payload + 9 + data_len);
            msg.piece = PieceMessage(piece_index, begin, std::move(piece_data));
            break;
        }
            
        case BtMessageType::Extended:
            // 1-byte extension ID + variable payload
            if (msg_len < 2) return std::nullopt;
            msg.extension_id = payload[1];
            msg.extension_payload.assign(payload + 2, payload + msg_len);
            break;
            
        default:
            // Unknown message type
            return std::nullopt;
    }
    
    return msg;
}

std::optional<BtMessage> BtMessageDecoder::decode(const std::vector<uint8_t>& data,
                                                   uint32_t num_pieces) {
    return decode(data.data(), data.size(), num_pieces);
}

} // namespace librats
