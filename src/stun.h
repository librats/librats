#ifndef LIBRATS_STUN_H
#define LIBRATS_STUN_H

#include "socket.h"
#include <string>
#include <vector>
#include <cstdint>

namespace librats {

// STUN Protocol Constants
namespace stun {
    // STUN Message Types
    const uint16_t BINDING_REQUEST = 0x0001;
    const uint16_t BINDING_RESPONSE = 0x0101;
    const uint16_t BINDING_ERROR_RESPONSE = 0x0111;
    
    // STUN Magic Cookie (RFC 5389)
    const uint32_t MAGIC_COOKIE = 0x2112A442;
    
    // STUN Attribute Types
    const uint16_t ATTR_MAPPED_ADDRESS = 0x0001;
    const uint16_t ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    
    // Address families
    const uint8_t FAMILY_IPV4 = 0x01;
    const uint8_t FAMILY_IPV6 = 0x02;
    
    // STUN message header size
    const size_t HEADER_SIZE = 20;
    
    // Transaction ID size
    const size_t TRANSACTION_ID_SIZE = 12;
}

// STUN Message Header Structure
struct StunHeader {
    uint16_t message_type;
    uint16_t message_length;
    uint32_t magic_cookie;
    uint8_t transaction_id[stun::TRANSACTION_ID_SIZE];
};

// STUN Attribute Header
struct StunAttribute {
    uint16_t type;
    uint16_t length;
    // Value follows this header
};

// STUN Address Structure
struct StunAddress {
    uint8_t family;
    uint16_t port;
    std::string ip;
};

// STUN Client Class
class StunClient {
public:
    StunClient();
    ~StunClient();
    
    // Get public IP address from STUN server
    bool get_public_address(const std::string& stun_server, 
                           int stun_port, 
                           StunAddress& public_address,
                           int timeout_ms = 5000);
    
    // Get public IP from Google STUN server
    bool get_public_address_from_google(StunAddress& public_address, 
                                       int timeout_ms = 5000);
    
    // Static helper functions
    static std::vector<uint8_t> create_binding_request();
    static bool parse_binding_response(const std::vector<uint8_t>& response, 
                                      StunAddress& mapped_address);
    
private:
    // Helper functions
    void generate_transaction_id(uint8_t* transaction_id);
    bool send_stun_request(socket_t sock, 
                          const std::string& server, 
                          int port,
                          const std::vector<uint8_t>& request);
    bool receive_stun_response(socket_t sock, 
                              std::vector<uint8_t>& response,
                              int timeout_ms);
    
    // Parsing helpers
    static uint16_t parse_uint16(const uint8_t* data);
    static uint32_t parse_uint32(const uint8_t* data);
    static void write_uint16(uint8_t* data, uint16_t value);
    static void write_uint32(uint8_t* data, uint32_t value);
    
    // XOR operations for XOR-MAPPED-ADDRESS
    static void xor_address(StunAddress& address, const uint8_t* transaction_id);
};

} // namespace librats

#endif // LIBRATS_STUN_H 