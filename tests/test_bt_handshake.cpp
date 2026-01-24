#include <gtest/gtest.h>
#include <cstring>
#include "bt_handshake.h"

using namespace librats;

//=============================================================================
// Extension Flags Tests
//=============================================================================

TEST(BtHandshakeTest, ExtensionFlagsDefault) {
    ExtensionFlags flags;
    
    EXPECT_FALSE(flags.dht);
    EXPECT_FALSE(flags.fast);
    EXPECT_FALSE(flags.extension_protocol);
    
    auto reserved = flags.to_reserved();
    for (uint8_t b : reserved) {
        EXPECT_EQ(b, 0);
    }
}

TEST(BtHandshakeTest, ExtensionFlagsEnableAll) {
    ExtensionFlags flags;
    flags.enable_all();
    
    EXPECT_TRUE(flags.dht);
    EXPECT_TRUE(flags.fast);
    EXPECT_TRUE(flags.extension_protocol);
}

TEST(BtHandshakeTest, ExtensionFlagsToReserved) {
    ExtensionFlags flags;
    flags.dht = true;
    flags.fast = true;
    flags.extension_protocol = true;
    
    auto reserved = flags.to_reserved();
    
    // DHT: reserved[7] bit 0
    EXPECT_TRUE(reserved[7] & 0x01);
    
    // Fast: reserved[7] bit 2
    EXPECT_TRUE(reserved[7] & 0x04);
    
    // Extension protocol: reserved[5] bit 4
    EXPECT_TRUE(reserved[5] & 0x10);
}

TEST(BtHandshakeTest, ExtensionFlagsFromReserved) {
    std::array<uint8_t, 8> reserved{};
    reserved[5] = 0x10;  // Extension protocol
    reserved[7] = 0x05;  // DHT (0x01) + Fast (0x04)
    
    auto flags = ExtensionFlags::from_reserved(reserved.data());
    
    EXPECT_TRUE(flags.dht);
    EXPECT_TRUE(flags.fast);
    EXPECT_TRUE(flags.extension_protocol);
}

TEST(BtHandshakeTest, ExtensionFlagsRoundTrip) {
    ExtensionFlags original;
    original.dht = true;
    original.extension_protocol = true;
    original.fast = false;
    
    auto reserved = original.to_reserved();
    auto restored = ExtensionFlags::from_reserved(reserved.data());
    
    EXPECT_EQ(original.dht, restored.dht);
    EXPECT_EQ(original.fast, restored.fast);
    EXPECT_EQ(original.extension_protocol, restored.extension_protocol);
}

//=============================================================================
// Handshake Encoding Tests
//=============================================================================

TEST(BtHandshakeTest, EncodeSize) {
    BtInfoHash hash{};
    PeerID peer_id{};
    
    auto hs = BtHandshake::encode(hash, peer_id);
    
    EXPECT_EQ(hs.size(), BT_HANDSHAKE_SIZE);  // 68 bytes
}

TEST(BtHandshakeTest, EncodeProtocolString) {
    BtInfoHash hash{};
    PeerID peer_id{};
    
    auto hs = BtHandshake::encode(hash, peer_id);
    
    // First byte is protocol string length (19)
    EXPECT_EQ(hs[0], 19);
    
    // Followed by "BitTorrent protocol"
    std::string protocol(reinterpret_cast<char*>(hs.data() + 1), 19);
    EXPECT_EQ(protocol, "BitTorrent protocol");
}

TEST(BtHandshakeTest, EncodeInfoHash) {
    BtInfoHash hash;
    for (size_t i = 0; i < 20; ++i) {
        hash[i] = static_cast<uint8_t>(i);
    }
    
    PeerID peer_id{};
    
    auto hs = BtHandshake::encode(hash, peer_id);
    
    // Info hash is at offset 28 (1 + 19 + 8)
    for (size_t i = 0; i < 20; ++i) {
        EXPECT_EQ(hs[28 + i], i);
    }
}

TEST(BtHandshakeTest, EncodePeerId) {
    BtInfoHash hash{};
    
    PeerID peer_id;
    for (size_t i = 0; i < 20; ++i) {
        peer_id[i] = static_cast<uint8_t>(100 + i);
    }
    
    auto hs = BtHandshake::encode(hash, peer_id);
    
    // Peer ID is at offset 48 (1 + 19 + 8 + 20)
    for (size_t i = 0; i < 20; ++i) {
        EXPECT_EQ(hs[48 + i], 100 + i);
    }
}

TEST(BtHandshakeTest, EncodeWithExtensions) {
    BtInfoHash hash{};
    PeerID peer_id{};
    
    auto hs = BtHandshake::encode_with_extensions(hash, peer_id);
    
    EXPECT_EQ(hs.size(), BT_HANDSHAKE_SIZE);
    
    // Reserved bytes at offset 20
    // DHT and Fast: reserved[7]
    EXPECT_TRUE(hs[20 + 7] & 0x01);  // DHT
    EXPECT_TRUE(hs[20 + 7] & 0x04);  // Fast
    
    // Extension protocol: reserved[5]
    EXPECT_TRUE(hs[20 + 5] & 0x10);
}

//=============================================================================
// Handshake Decoding Tests
//=============================================================================

TEST(BtHandshakeTest, DecodeValid) {
    BtInfoHash hash;
    for (size_t i = 0; i < 20; ++i) {
        hash[i] = static_cast<uint8_t>(i);
    }
    
    PeerID peer_id;
    for (size_t i = 0; i < 20; ++i) {
        peer_id[i] = static_cast<uint8_t>(50 + i);
    }
    
    ExtensionFlags flags;
    flags.dht = true;
    flags.extension_protocol = true;
    
    auto encoded = BtHandshake::encode(hash, peer_id, flags);
    auto decoded = BtHandshake::decode(encoded);
    
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->is_valid());
    EXPECT_EQ(decoded->info_hash, hash);
    EXPECT_EQ(decoded->peer_id, peer_id);
    EXPECT_TRUE(decoded->extensions.dht);
    EXPECT_TRUE(decoded->extensions.extension_protocol);
    EXPECT_FALSE(decoded->extensions.fast);
}

TEST(BtHandshakeTest, DecodeInvalidProtocol) {
    std::vector<uint8_t> data(68, 0);
    data[0] = 18;  // Wrong protocol string length
    
    auto decoded = BtHandshake::decode(data);
    EXPECT_FALSE(decoded.has_value());
}

TEST(BtHandshakeTest, DecodeTooShort) {
    std::vector<uint8_t> data(50, 0);  // Less than 68 bytes
    
    auto decoded = BtHandshake::decode(data);
    EXPECT_FALSE(decoded.has_value());
}

TEST(BtHandshakeTest, DecodeWrongProtocolString) {
    std::vector<uint8_t> data(68, 0);
    data[0] = 19;
    // Write wrong protocol string
    std::memcpy(data.data() + 1, "Wrong protocol!!!!!", 19);
    
    auto decoded = BtHandshake::decode(data);
    EXPECT_FALSE(decoded.has_value());
}

//=============================================================================
// Utility Tests
//=============================================================================

TEST(BtHandshakeTest, IsComplete) {
    std::vector<uint8_t> data(100, 0);
    
    EXPECT_FALSE(BtHandshake::is_complete(data.data(), 67));
    EXPECT_TRUE(BtHandshake::is_complete(data.data(), 68));
    EXPECT_TRUE(BtHandshake::is_complete(data.data(), 100));
}

TEST(BtHandshakeTest, ValidateProtocol) {
    // Valid
    auto valid = BtHandshake::encode({}, {});
    EXPECT_TRUE(BtHandshake::validate_protocol(valid.data(), valid.size()));
    
    // Invalid length byte
    std::vector<uint8_t> invalid1(68, 0);
    invalid1[0] = 18;
    EXPECT_FALSE(BtHandshake::validate_protocol(invalid1.data(), invalid1.size()));
    
    // Too short
    std::vector<uint8_t> short_data(10, 0);
    EXPECT_FALSE(BtHandshake::validate_protocol(short_data.data(), short_data.size()));
}

TEST(BtHandshakeTest, HandshakeSize) {
    EXPECT_EQ(BtHandshake::size(), 68);
}

//=============================================================================
// Handshake Struct Tests
//=============================================================================

TEST(BtHandshakeTest, HandshakePeerIdString) {
    Handshake hs;
    // Set peer ID to "-LR0001-" followed by random
    std::memcpy(hs.peer_id.data(), "-LR0001-", 8);
    for (size_t i = 8; i < 20; ++i) {
        hs.peer_id[i] = static_cast<uint8_t>('A' + i - 8);
    }
    
    std::string str = hs.peer_id_string();
    EXPECT_TRUE(str.find("-LR0001-") != std::string::npos);
}

TEST(BtHandshakeTest, HandshakeInfoHashHex) {
    Handshake hs;
    for (size_t i = 0; i < 20; ++i) {
        hs.info_hash[i] = static_cast<uint8_t>(i * 10);
    }
    
    std::string hex = hs.info_hash_hex();
    EXPECT_EQ(hex.size(), 40);  // 20 bytes * 2 hex chars
}

TEST(BtHandshakeTest, HandshakeIsValid) {
    Handshake hs;
    EXPECT_FALSE(hs.is_valid());  // Zero hash
    
    hs.info_hash[10] = 0x42;
    EXPECT_TRUE(hs.is_valid());  // Non-zero hash
}

//=============================================================================
// Round Trip Tests
//=============================================================================

TEST(BtHandshakeTest, RoundTrip) {
    // Create random-ish info hash and peer ID
    BtInfoHash hash;
    PeerID peer_id;
    
    for (size_t i = 0; i < 20; ++i) {
        hash[i] = static_cast<uint8_t>(i * 13);
        peer_id[i] = static_cast<uint8_t>(i * 7 + 100);
    }
    
    ExtensionFlags flags;
    flags.dht = true;
    flags.fast = true;
    flags.extension_protocol = true;
    
    auto encoded = BtHandshake::encode(hash, peer_id, flags);
    auto decoded = BtHandshake::decode(encoded);
    
    ASSERT_TRUE(decoded.has_value());
    
    // Verify all fields match
    EXPECT_EQ(decoded->info_hash, hash);
    EXPECT_EQ(decoded->peer_id, peer_id);
    EXPECT_EQ(decoded->extensions.dht, flags.dht);
    EXPECT_EQ(decoded->extensions.fast, flags.fast);
    EXPECT_EQ(decoded->extensions.extension_protocol, flags.extension_protocol);
}

TEST(BtHandshakeTest, RoundTripNoExtensions) {
    BtInfoHash hash{};
    hash[0] = 0xAB;
    hash[19] = 0xCD;
    
    PeerID peer_id{};
    peer_id[0] = 0x12;
    peer_id[19] = 0x34;
    
    ExtensionFlags flags;  // All false
    
    auto encoded = BtHandshake::encode(hash, peer_id, flags);
    auto decoded = BtHandshake::decode(encoded);
    
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->info_hash, hash);
    EXPECT_EQ(decoded->peer_id, peer_id);
    EXPECT_FALSE(decoded->extensions.dht);
    EXPECT_FALSE(decoded->extensions.fast);
    EXPECT_FALSE(decoded->extensions.extension_protocol);
}
