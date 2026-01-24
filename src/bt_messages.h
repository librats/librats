#pragma once

/**
 * @file bt_messages.h
 * @brief BitTorrent protocol message encoding and decoding
 * 
 * Implements BEP 3 (BitTorrent Wire Protocol) message types.
 * Also includes BEP 6 (Fast Extension) and BEP 10 (Extension Protocol).
 */

#include "bt_types.h"
#include "bt_bitfield.h"

#include <vector>
#include <cstdint>
#include <optional>
#include <string>

namespace librats {

//=============================================================================
// Message Types (BEP 3)
//=============================================================================

/**
 * @brief BitTorrent message type IDs
 */
enum class BtMessageType : uint8_t {
    // Core protocol (BEP 3)
    Choke = 0,
    Unchoke = 1,
    Interested = 2,
    NotInterested = 3,
    Have = 4,
    Bitfield = 5,
    Request = 6,
    Piece = 7,
    Cancel = 8,
    
    // DHT extension (BEP 5)
    Port = 9,
    
    // Fast extension (BEP 6)
    SuggestPiece = 13,
    HaveAll = 14,
    HaveNone = 15,
    RejectRequest = 16,
    AllowedFast = 17,
    
    // Extension protocol (BEP 10)
    Extended = 20
};

/**
 * @brief Convert message type to string for debugging
 */
const char* message_type_to_string(BtMessageType type);

//=============================================================================
// Message Structures
//=============================================================================

/**
 * @brief Request/Cancel message data
 */
struct RequestMessage {
    uint32_t piece_index;
    uint32_t begin;
    uint32_t length;
    
    RequestMessage() : piece_index(0), begin(0), length(0) {}
    RequestMessage(uint32_t idx, uint32_t b, uint32_t len)
        : piece_index(idx), begin(b), length(len) {}
    
    bool operator==(const RequestMessage& other) const {
        return piece_index == other.piece_index &&
               begin == other.begin &&
               length == other.length;
    }
};

/**
 * @brief Piece message data (block of data)
 */
struct PieceMessage {
    uint32_t piece_index;
    uint32_t begin;
    std::vector<uint8_t> data;
    
    PieceMessage() : piece_index(0), begin(0) {}
    PieceMessage(uint32_t idx, uint32_t b, std::vector<uint8_t> d)
        : piece_index(idx), begin(b), data(std::move(d)) {}
};

/**
 * @brief Parsed message from the wire
 */
struct BtMessage {
    BtMessageType type;
    
    // Data depending on type
    union {
        uint32_t have_piece;        // Have
        uint32_t port;              // Port (DHT)
        uint32_t suggest_piece;     // SuggestPiece
        uint32_t allowed_fast;      // AllowedFast
    };
    
    // For complex message types (stored separately)
    std::optional<Bitfield> bitfield;
    std::optional<RequestMessage> request;
    std::optional<PieceMessage> piece;
    
    // For Extended messages
    uint8_t extension_id;
    std::vector<uint8_t> extension_payload;
    
    BtMessage() : type(BtMessageType::Choke), have_piece(0), extension_id(0) {}
    explicit BtMessage(BtMessageType t) : type(t), have_piece(0), extension_id(0) {}
};

//=============================================================================
// Message Encoder
//=============================================================================

/**
 * @brief Encodes BitTorrent protocol messages to wire format
 */
class BtMessageEncoder {
public:
    /**
     * @brief Encode a keep-alive message (length = 0)
     */
    static std::vector<uint8_t> encode_keepalive();
    
    /**
     * @brief Encode a choke message
     */
    static std::vector<uint8_t> encode_choke();
    
    /**
     * @brief Encode an unchoke message
     */
    static std::vector<uint8_t> encode_unchoke();
    
    /**
     * @brief Encode an interested message
     */
    static std::vector<uint8_t> encode_interested();
    
    /**
     * @brief Encode a not interested message
     */
    static std::vector<uint8_t> encode_not_interested();
    
    /**
     * @brief Encode a have message
     * @param piece_index Index of the piece we now have
     */
    static std::vector<uint8_t> encode_have(uint32_t piece_index);
    
    /**
     * @brief Encode a bitfield message
     * @param bitfield Our have bitfield
     */
    static std::vector<uint8_t> encode_bitfield(const Bitfield& bitfield);
    
    /**
     * @brief Encode a request message
     * @param piece_index Piece index
     * @param begin Offset within piece
     * @param length Length of block (usually 16384)
     */
    static std::vector<uint8_t> encode_request(uint32_t piece_index, 
                                                uint32_t begin, 
                                                uint32_t length);
    
    /**
     * @brief Encode a request message from RequestMessage struct
     */
    static std::vector<uint8_t> encode_request(const RequestMessage& req);
    
    /**
     * @brief Encode a piece message (block data)
     * @param piece_index Piece index
     * @param begin Offset within piece
     * @param data Block data
     */
    static std::vector<uint8_t> encode_piece(uint32_t piece_index,
                                              uint32_t begin,
                                              const uint8_t* data,
                                              size_t length);
    
    /**
     * @brief Encode a piece message from PieceMessage struct
     */
    static std::vector<uint8_t> encode_piece(const PieceMessage& piece);
    
    /**
     * @brief Encode a cancel message
     */
    static std::vector<uint8_t> encode_cancel(uint32_t piece_index,
                                               uint32_t begin,
                                               uint32_t length);
    
    /**
     * @brief Encode a cancel message from RequestMessage struct
     */
    static std::vector<uint8_t> encode_cancel(const RequestMessage& req);
    
    /**
     * @brief Encode a port message (DHT port)
     */
    static std::vector<uint8_t> encode_port(uint16_t port);
    
    //=========================================================================
    // Fast Extension (BEP 6)
    //=========================================================================
    
    /**
     * @brief Encode a have-all message
     */
    static std::vector<uint8_t> encode_have_all();
    
    /**
     * @brief Encode a have-none message
     */
    static std::vector<uint8_t> encode_have_none();
    
    /**
     * @brief Encode a suggest piece message
     */
    static std::vector<uint8_t> encode_suggest_piece(uint32_t piece_index);
    
    /**
     * @brief Encode a reject request message
     */
    static std::vector<uint8_t> encode_reject_request(uint32_t piece_index,
                                                       uint32_t begin,
                                                       uint32_t length);
    
    /**
     * @brief Encode an allowed fast message
     */
    static std::vector<uint8_t> encode_allowed_fast(uint32_t piece_index);
    
    //=========================================================================
    // Extension Protocol (BEP 10)
    //=========================================================================
    
    /**
     * @brief Encode an extended message
     * @param extension_id Extension message ID (0 for handshake)
     * @param payload Bencoded payload
     */
    static std::vector<uint8_t> encode_extended(uint8_t extension_id,
                                                 const std::vector<uint8_t>& payload);
    
private:
    /**
     * @brief Write a 32-bit big-endian integer to buffer
     */
    static void write_uint32(std::vector<uint8_t>& buf, uint32_t value);
    
    /**
     * @brief Write a 16-bit big-endian integer to buffer
     */
    static void write_uint16(std::vector<uint8_t>& buf, uint16_t value);
};

//=============================================================================
// Message Decoder
//=============================================================================

/**
 * @brief Decodes BitTorrent protocol messages from wire format
 */
class BtMessageDecoder {
public:
    /**
     * @brief Check if there's a complete message in the buffer
     * 
     * @param data Buffer data
     * @param length Buffer length
     * @return Size of complete message (including 4-byte length prefix), or 0 if incomplete
     */
    static size_t message_length(const uint8_t* data, size_t length);
    
    /**
     * @brief Check if buffer contains a keep-alive (length = 0)
     */
    static bool is_keepalive(const uint8_t* data, size_t length);
    
    /**
     * @brief Decode a message from the buffer
     * 
     * @param data Buffer data (starting with 4-byte length)
     * @param length Buffer length
     * @param num_pieces Number of pieces (for bitfield validation)
     * @return Decoded message, or nullopt on error
     */
    static std::optional<BtMessage> decode(const uint8_t* data, 
                                           size_t length,
                                           uint32_t num_pieces = 0);
    
    /**
     * @brief Decode a message from vector
     */
    static std::optional<BtMessage> decode(const std::vector<uint8_t>& data,
                                           uint32_t num_pieces = 0);
    
private:
    /**
     * @brief Read a 32-bit big-endian integer from buffer
     */
    static uint32_t read_uint32(const uint8_t* data);
    
    /**
     * @brief Read a 16-bit big-endian integer from buffer
     */
    static uint16_t read_uint16(const uint8_t* data);
};

} // namespace librats
