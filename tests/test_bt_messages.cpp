#include <gtest/gtest.h>
#include "bt_messages.h"

using namespace librats;

//=============================================================================
// Helper Functions
//=============================================================================

void expect_message_roundtrip(const std::vector<uint8_t>& encoded, 
                               BtMessageType expected_type) {
    auto decoded = BtMessageDecoder::decode(encoded);
    ASSERT_TRUE(decoded.has_value()) << "Failed to decode " << message_type_to_string(expected_type);
    EXPECT_EQ(decoded->type, expected_type);
}

//=============================================================================
// Keep-alive Tests
//=============================================================================

TEST(BtMessagesTest, EncodeKeepalive) {
    auto msg = BtMessageEncoder::encode_keepalive();
    
    ASSERT_EQ(msg.size(), 4);
    EXPECT_EQ(msg[0], 0);
    EXPECT_EQ(msg[1], 0);
    EXPECT_EQ(msg[2], 0);
    EXPECT_EQ(msg[3], 0);
}

TEST(BtMessagesTest, IsKeepalive) {
    auto msg = BtMessageEncoder::encode_keepalive();
    EXPECT_TRUE(BtMessageDecoder::is_keepalive(msg.data(), msg.size()));
    
    auto choke = BtMessageEncoder::encode_choke();
    EXPECT_FALSE(BtMessageDecoder::is_keepalive(choke.data(), choke.size()));
}

//=============================================================================
// Simple Message Tests (Choke, Unchoke, Interested, NotInterested)
//=============================================================================

TEST(BtMessagesTest, EncodeChoke) {
    auto msg = BtMessageEncoder::encode_choke();
    
    ASSERT_EQ(msg.size(), 5);
    // Length = 1
    EXPECT_EQ(msg[0], 0); EXPECT_EQ(msg[1], 0);
    EXPECT_EQ(msg[2], 0); EXPECT_EQ(msg[3], 1);
    // Type = 0 (Choke)
    EXPECT_EQ(msg[4], 0);
    
    expect_message_roundtrip(msg, BtMessageType::Choke);
}

TEST(BtMessagesTest, EncodeUnchoke) {
    auto msg = BtMessageEncoder::encode_unchoke();
    
    ASSERT_EQ(msg.size(), 5);
    EXPECT_EQ(msg[4], 1);  // Type = 1 (Unchoke)
    
    expect_message_roundtrip(msg, BtMessageType::Unchoke);
}

TEST(BtMessagesTest, EncodeInterested) {
    auto msg = BtMessageEncoder::encode_interested();
    
    ASSERT_EQ(msg.size(), 5);
    EXPECT_EQ(msg[4], 2);  // Type = 2 (Interested)
    
    expect_message_roundtrip(msg, BtMessageType::Interested);
}

TEST(BtMessagesTest, EncodeNotInterested) {
    auto msg = BtMessageEncoder::encode_not_interested();
    
    ASSERT_EQ(msg.size(), 5);
    EXPECT_EQ(msg[4], 3);  // Type = 3 (NotInterested)
    
    expect_message_roundtrip(msg, BtMessageType::NotInterested);
}

//=============================================================================
// Have Message Tests
//=============================================================================

TEST(BtMessagesTest, EncodeHave) {
    auto msg = BtMessageEncoder::encode_have(42);
    
    ASSERT_EQ(msg.size(), 9);
    // Length = 5
    EXPECT_EQ(msg[3], 5);
    // Type = 4 (Have)
    EXPECT_EQ(msg[4], 4);
    // Piece index = 42 (big-endian)
    EXPECT_EQ(msg[5], 0); EXPECT_EQ(msg[6], 0);
    EXPECT_EQ(msg[7], 0); EXPECT_EQ(msg[8], 42);
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::Have);
    EXPECT_EQ(decoded->have_piece, 42);
}

TEST(BtMessagesTest, EncodeHaveLargeIndex) {
    auto msg = BtMessageEncoder::encode_have(0x12345678);
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->have_piece, 0x12345678);
}

//=============================================================================
// Bitfield Message Tests
//=============================================================================

TEST(BtMessagesTest, EncodeBitfield) {
    Bitfield bf(16);
    bf.set_bit(0);
    bf.set_bit(8);
    bf.set_bit(15);
    
    auto msg = BtMessageEncoder::encode_bitfield(bf);
    
    // Length = 1 (type) + 2 (bitfield bytes)
    EXPECT_EQ(msg[3], 3);
    // Type = 5 (Bitfield)
    EXPECT_EQ(msg[4], 5);
    
    auto decoded = BtMessageDecoder::decode(msg, 16);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::Bitfield);
    ASSERT_TRUE(decoded->bitfield.has_value());
    EXPECT_TRUE(decoded->bitfield->get_bit(0));
    EXPECT_TRUE(decoded->bitfield->get_bit(8));
    EXPECT_TRUE(decoded->bitfield->get_bit(15));
    EXPECT_FALSE(decoded->bitfield->get_bit(1));
}

TEST(BtMessagesTest, EncodeBitfieldLarge) {
    Bitfield bf(100);
    for (int i = 0; i < 100; i += 3) {
        bf.set_bit(i);
    }
    
    auto msg = BtMessageEncoder::encode_bitfield(bf);
    auto decoded = BtMessageDecoder::decode(msg, 100);
    
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(decoded->bitfield.has_value());
    EXPECT_EQ(decoded->bitfield->size(), 100);
    
    for (size_t i = 0; i < 100; ++i) {
        EXPECT_EQ(decoded->bitfield->get_bit(i), i % 3 == 0);
    }
}

//=============================================================================
// Request Message Tests
//=============================================================================

TEST(BtMessagesTest, EncodeRequest) {
    auto msg = BtMessageEncoder::encode_request(10, 16384, 16384);
    
    ASSERT_EQ(msg.size(), 17);
    // Length = 13
    EXPECT_EQ(msg[3], 13);
    // Type = 6 (Request)
    EXPECT_EQ(msg[4], 6);
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::Request);
    ASSERT_TRUE(decoded->request.has_value());
    EXPECT_EQ(decoded->request->piece_index, 10);
    EXPECT_EQ(decoded->request->begin, 16384);
    EXPECT_EQ(decoded->request->length, 16384);
}

TEST(BtMessagesTest, EncodeRequestStruct) {
    RequestMessage req(5, 32768, 16384);
    auto msg = BtMessageEncoder::encode_request(req);
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->request->piece_index, 5);
    EXPECT_EQ(decoded->request->begin, 32768);
    EXPECT_EQ(decoded->request->length, 16384);
}

//=============================================================================
// Piece Message Tests
//=============================================================================

TEST(BtMessagesTest, EncodePiece) {
    std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8};
    auto msg = BtMessageEncoder::encode_piece(3, 16384, data.data(), data.size());
    
    // Length = 9 + 8 = 17
    EXPECT_EQ(msg[3], 17);
    // Type = 7 (Piece)
    EXPECT_EQ(msg[4], 7);
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::Piece);
    ASSERT_TRUE(decoded->piece.has_value());
    EXPECT_EQ(decoded->piece->piece_index, 3);
    EXPECT_EQ(decoded->piece->begin, 16384);
    EXPECT_EQ(decoded->piece->data.size(), 8);
    EXPECT_EQ(decoded->piece->data, data);
}

TEST(BtMessagesTest, EncodePieceStruct) {
    std::vector<uint8_t> data(1000, 0xAB);
    PieceMessage piece(7, 0, data);
    auto msg = BtMessageEncoder::encode_piece(piece);
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->piece->data.size(), 1000);
    EXPECT_EQ(decoded->piece->data[0], 0xAB);
}

//=============================================================================
// Cancel Message Tests
//=============================================================================

TEST(BtMessagesTest, EncodeCancel) {
    auto msg = BtMessageEncoder::encode_cancel(10, 16384, 16384);
    
    EXPECT_EQ(msg[4], 8);  // Type = 8 (Cancel)
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::Cancel);
    EXPECT_EQ(decoded->request->piece_index, 10);
}

//=============================================================================
// Port Message Tests
//=============================================================================

TEST(BtMessagesTest, EncodePort) {
    auto msg = BtMessageEncoder::encode_port(6881);
    
    ASSERT_EQ(msg.size(), 7);
    EXPECT_EQ(msg[4], 9);  // Type = 9 (Port)
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::Port);
    EXPECT_EQ(decoded->port, 6881);
}

//=============================================================================
// Fast Extension Tests (BEP 6)
//=============================================================================

TEST(BtMessagesTest, EncodeHaveAll) {
    auto msg = BtMessageEncoder::encode_have_all();
    
    EXPECT_EQ(msg[4], 14);  // Type = 14 (HaveAll)
    expect_message_roundtrip(msg, BtMessageType::HaveAll);
}

TEST(BtMessagesTest, EncodeHaveNone) {
    auto msg = BtMessageEncoder::encode_have_none();
    
    EXPECT_EQ(msg[4], 15);  // Type = 15 (HaveNone)
    expect_message_roundtrip(msg, BtMessageType::HaveNone);
}

TEST(BtMessagesTest, EncodeSuggestPiece) {
    auto msg = BtMessageEncoder::encode_suggest_piece(99);
    
    EXPECT_EQ(msg[4], 13);  // Type = 13 (SuggestPiece)
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::SuggestPiece);
    EXPECT_EQ(decoded->suggest_piece, 99);
}

TEST(BtMessagesTest, EncodeRejectRequest) {
    auto msg = BtMessageEncoder::encode_reject_request(5, 16384, 16384);
    
    EXPECT_EQ(msg[4], 16);  // Type = 16 (RejectRequest)
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::RejectRequest);
    EXPECT_EQ(decoded->request->piece_index, 5);
}

TEST(BtMessagesTest, EncodeAllowedFast) {
    auto msg = BtMessageEncoder::encode_allowed_fast(77);
    
    EXPECT_EQ(msg[4], 17);  // Type = 17 (AllowedFast)
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::AllowedFast);
    EXPECT_EQ(decoded->allowed_fast, 77);
}

//=============================================================================
// Extended Message Tests (BEP 10)
//=============================================================================

TEST(BtMessagesTest, EncodeExtended) {
    std::vector<uint8_t> payload = {'d', '1', ':', 'v', '4', ':', 't', 'e', 's', 't', 'e'};
    auto msg = BtMessageEncoder::encode_extended(1, payload);
    
    EXPECT_EQ(msg[4], 20);  // Type = 20 (Extended)
    EXPECT_EQ(msg[5], 1);   // Extension ID = 1
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::Extended);
    EXPECT_EQ(decoded->extension_id, 1);
    EXPECT_EQ(decoded->extension_payload, payload);
}

TEST(BtMessagesTest, EncodeExtendedHandshake) {
    std::vector<uint8_t> payload = {'d', 'e'};  // Empty bencoded dict
    auto msg = BtMessageEncoder::encode_extended(0, payload);  // ID 0 = handshake
    
    auto decoded = BtMessageDecoder::decode(msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->extension_id, 0);
}

//=============================================================================
// Message Length Detection
//=============================================================================

TEST(BtMessagesTest, MessageLength) {
    auto msg = BtMessageEncoder::encode_request(0, 0, 16384);
    
    // Should detect complete message
    size_t len = BtMessageDecoder::message_length(msg.data(), msg.size());
    EXPECT_EQ(len, msg.size());
    
    // Incomplete message (missing 1 byte)
    len = BtMessageDecoder::message_length(msg.data(), msg.size() - 1);
    EXPECT_EQ(len, 0);
    
    // Too short to read length
    len = BtMessageDecoder::message_length(msg.data(), 3);
    EXPECT_EQ(len, 0);
}

TEST(BtMessagesTest, MessageLengthKeepalive) {
    auto msg = BtMessageEncoder::encode_keepalive();
    
    size_t len = BtMessageDecoder::message_length(msg.data(), msg.size());
    EXPECT_EQ(len, 4);  // Just the length prefix
}

//=============================================================================
// Error Handling
//=============================================================================

TEST(BtMessagesTest, DecodeInvalidMessageType) {
    // Create message with invalid type
    std::vector<uint8_t> msg = {0, 0, 0, 1, 255};  // Type 255 doesn't exist
    
    auto decoded = BtMessageDecoder::decode(msg);
    EXPECT_FALSE(decoded.has_value());
}

TEST(BtMessagesTest, DecodeIncompleteMessage) {
    // Valid header but incomplete payload
    std::vector<uint8_t> msg = {0, 0, 0, 5, 4, 0, 0};  // Have message, missing 2 bytes
    
    auto decoded = BtMessageDecoder::decode(msg);
    EXPECT_FALSE(decoded.has_value());
}

TEST(BtMessagesTest, DecodeTooShort) {
    std::vector<uint8_t> msg = {0, 0};  // Too short
    
    auto decoded = BtMessageDecoder::decode(msg);
    EXPECT_FALSE(decoded.has_value());
}

TEST(BtMessagesTest, DecodeWrongLength) {
    // Choke should have length 1, not 2
    std::vector<uint8_t> msg = {0, 0, 0, 2, 0, 0};  // Wrong length
    
    auto decoded = BtMessageDecoder::decode(msg);
    EXPECT_FALSE(decoded.has_value());
}

//=============================================================================
// Message Type String Conversion
//=============================================================================

TEST(BtMessagesTest, MessageTypeToString) {
    EXPECT_STREQ(message_type_to_string(BtMessageType::Choke), "Choke");
    EXPECT_STREQ(message_type_to_string(BtMessageType::Unchoke), "Unchoke");
    EXPECT_STREQ(message_type_to_string(BtMessageType::Request), "Request");
    EXPECT_STREQ(message_type_to_string(BtMessageType::Piece), "Piece");
    EXPECT_STREQ(message_type_to_string(BtMessageType::Extended), "Extended");
}
