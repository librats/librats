#include "bt_handshake.h"
#include <cstring>

namespace librats {

//=============================================================================
// ExtensionFlags
//=============================================================================

std::array<uint8_t, 8> ExtensionFlags::to_reserved() const {
    std::array<uint8_t, 8> reserved{};
    
    // BEP 10: Extension protocol - reserved[5] bit 4
    if (extension_protocol) {
        reserved[5] |= 0x10;
    }
    
    // BEP 5: DHT - reserved[7] bit 0
    if (dht) {
        reserved[7] |= 0x01;
    }
    
    // BEP 6: Fast extension - reserved[7] bit 2
    if (fast) {
        reserved[7] |= 0x04;
    }
    
    return reserved;
}

ExtensionFlags ExtensionFlags::from_reserved(const uint8_t* reserved) {
    ExtensionFlags flags;
    
    // BEP 10: Extension protocol - reserved[5] bit 4
    flags.extension_protocol = (reserved[5] & 0x10) != 0;
    
    // BEP 5: DHT - reserved[7] bit 0
    flags.dht = (reserved[7] & 0x01) != 0;
    
    // BEP 6: Fast extension - reserved[7] bit 2
    flags.fast = (reserved[7] & 0x04) != 0;
    
    return flags;
}

//=============================================================================
// BtHandshake
//=============================================================================

std::vector<uint8_t> BtHandshake::encode(const BtInfoHash& info_hash,
                                          const PeerID& peer_id,
                                          const ExtensionFlags& extensions) {
    std::vector<uint8_t> handshake;
    handshake.reserve(BT_HANDSHAKE_SIZE);
    
    // Protocol string length (1 byte)
    handshake.push_back(static_cast<uint8_t>(BT_PROTOCOL_STRING_LEN));
    
    // Protocol string (19 bytes)
    handshake.insert(handshake.end(), 
                     BT_PROTOCOL_STRING, 
                     BT_PROTOCOL_STRING + BT_PROTOCOL_STRING_LEN);
    
    // Reserved bytes (8 bytes)
    auto reserved = extensions.to_reserved();
    handshake.insert(handshake.end(), reserved.begin(), reserved.end());
    
    // Info hash (20 bytes)
    handshake.insert(handshake.end(), info_hash.begin(), info_hash.end());
    
    // Peer ID (20 bytes)
    handshake.insert(handshake.end(), peer_id.begin(), peer_id.end());
    
    return handshake;
}

std::vector<uint8_t> BtHandshake::encode_with_extensions(const BtInfoHash& info_hash,
                                                          const PeerID& peer_id) {
    ExtensionFlags flags;
    flags.enable_all();
    return encode(info_hash, peer_id, flags);
}

bool BtHandshake::is_complete(const uint8_t* data, size_t length) {
    return length >= BT_HANDSHAKE_SIZE;
}

std::optional<Handshake> BtHandshake::decode(const uint8_t* data, size_t length) {
    if (length < BT_HANDSHAKE_SIZE) {
        return std::nullopt;
    }
    
    // Validate protocol string length
    if (data[0] != BT_PROTOCOL_STRING_LEN) {
        return std::nullopt;
    }
    
    // Validate protocol string
    if (std::memcmp(data + 1, BT_PROTOCOL_STRING, BT_PROTOCOL_STRING_LEN) != 0) {
        return std::nullopt;
    }
    
    Handshake hs;
    
    // Parse reserved bytes (offset 20)
    std::memcpy(hs.reserved.data(), data + 20, 8);
    hs.extensions = ExtensionFlags::from_reserved(data + 20);
    
    // Parse info hash (offset 28)
    std::memcpy(hs.info_hash.data(), data + 28, BT_INFO_HASH_SIZE);
    
    // Parse peer ID (offset 48)
    std::memcpy(hs.peer_id.data(), data + 48, BT_PEER_ID_SIZE);
    
    return hs;
}

std::optional<Handshake> BtHandshake::decode(const std::vector<uint8_t>& data) {
    return decode(data.data(), data.size());
}

bool BtHandshake::validate_protocol(const uint8_t* data, size_t length) {
    if (length < 20) {
        return false;
    }
    
    if (data[0] != BT_PROTOCOL_STRING_LEN) {
        return false;
    }
    
    return std::memcmp(data + 1, BT_PROTOCOL_STRING, BT_PROTOCOL_STRING_LEN) == 0;
}

} // namespace librats
