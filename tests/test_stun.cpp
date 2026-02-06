/**
 * @file test_stun.cpp
 * @brief Unit tests for STUN protocol implementation
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "stun.h"
#include "socket.h"
#include <thread>
#include <chrono>
#include <atomic>

using namespace librats;

// ============================================================================
// Test Fixtures
// ============================================================================

class StunTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(init_socket_library());
    }
    
    void TearDown() override {
        cleanup_socket_library();
    }
};

// ============================================================================
// StunMessage Tests
// ============================================================================

TEST_F(StunTest, MessageTypeClassification) {
    StunMessage request(StunMessageType::BindingRequest);
    EXPECT_TRUE(request.is_request());
    EXPECT_FALSE(request.is_success_response());
    EXPECT_FALSE(request.is_error_response());
    EXPECT_EQ(request.get_class(), StunMessageClass::Request);
    EXPECT_EQ(request.get_method(), StunMethod::Binding);
    
    StunMessage success_response;
    success_response.type = StunMessageType::BindingSuccessResponse;
    EXPECT_FALSE(success_response.is_request());
    EXPECT_TRUE(success_response.is_success_response());
    EXPECT_FALSE(success_response.is_error_response());
    
    StunMessage error_response;
    error_response.type = StunMessageType::BindingErrorResponse;
    EXPECT_FALSE(error_response.is_request());
    EXPECT_FALSE(error_response.is_success_response());
    EXPECT_TRUE(error_response.is_error_response());
}

TEST_F(StunTest, TransactionIdGeneration) {
    StunMessage msg1(StunMessageType::BindingRequest);
    StunMessage msg2(StunMessageType::BindingRequest);
    
    // Transaction IDs should be random and different
    EXPECT_NE(msg1.transaction_id, msg2.transaction_id);
    
    // Should be 12 bytes
    EXPECT_EQ(msg1.transaction_id.size(), STUN_TRANSACTION_ID_SIZE);
}

TEST_F(StunTest, BasicSerialization) {
    StunMessage msg(StunMessageType::BindingRequest);
    
    auto data = msg.serialize();
    
    // Minimum size: 20 bytes header
    EXPECT_GE(data.size(), STUN_HEADER_SIZE);
    
    // Check message type (Binding Request = 0x0001)
    EXPECT_EQ(data[0], 0x00);
    EXPECT_EQ(data[1], 0x01);
    
    // Check magic cookie
    EXPECT_EQ(data[4], 0x21);
    EXPECT_EQ(data[5], 0x12);
    EXPECT_EQ(data[6], 0xA4);
    EXPECT_EQ(data[7], 0x42);
}

TEST_F(StunTest, SerializationDeserialization) {
    StunMessage original(StunMessageType::BindingRequest);
    original.add_software("test-software");
    
    auto data = original.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->type, original.type);
    EXPECT_EQ(parsed->transaction_id, original.transaction_id);
    
    // Check software attribute was preserved
    const auto* attr = parsed->find_attribute(StunAttributeType::Software);
    ASSERT_NE(attr, nullptr);
    std::string software(attr->value.begin(), attr->value.end());
    EXPECT_EQ(software, "test-software");
}

TEST_F(StunTest, IsStunMessage) {
    StunMessage msg(StunMessageType::BindingRequest);
    auto data = msg.serialize();
    
    EXPECT_TRUE(StunMessage::is_stun_message(data));
    
    // Not STUN: too short
    std::vector<uint8_t> short_data = {0x00, 0x01};
    EXPECT_FALSE(StunMessage::is_stun_message(short_data));
    
    // Not STUN: wrong magic cookie
    std::vector<uint8_t> wrong_cookie = data;
    wrong_cookie[4] = 0xFF;
    EXPECT_FALSE(StunMessage::is_stun_message(wrong_cookie));
    
    // Not STUN: first two bits not zero
    std::vector<uint8_t> wrong_bits = data;
    wrong_bits[0] |= 0xC0;
    EXPECT_FALSE(StunMessage::is_stun_message(wrong_bits));
}

// ============================================================================
// XOR-MAPPED-ADDRESS Tests
// ============================================================================

TEST_F(StunTest, XorMappedAddressIPv4) {
    StunMessage msg(StunMessageType::BindingSuccessResponse);
    
    StunMappedAddress addr(StunAddressFamily::IPv4, "192.168.1.100", 12345);
    msg.add_xor_mapped_address(addr);
    
    // Serialize and deserialize
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    auto result = parsed->get_xor_mapped_address();
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->family, StunAddressFamily::IPv4);
    EXPECT_EQ(result->address, "192.168.1.100");
    EXPECT_EQ(result->port, 12345);
}

TEST_F(StunTest, XorMappedAddressIPv6) {
    StunMessage msg(StunMessageType::BindingSuccessResponse);
    
    StunMappedAddress addr(StunAddressFamily::IPv6, "2001:db8::1", 8080);
    msg.add_xor_mapped_address(addr);
    
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    auto result = parsed->get_xor_mapped_address();
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->family, StunAddressFamily::IPv6);
    EXPECT_EQ(result->port, 8080);
    // IPv6 address format may vary, so just check it's valid
    EXPECT_FALSE(result->address.empty());
}

TEST_F(StunTest, MappedAddressToString) {
    StunMappedAddress ipv4(StunAddressFamily::IPv4, "1.2.3.4", 5678);
    EXPECT_EQ(ipv4.to_string(), "1.2.3.4:5678");
    
    StunMappedAddress ipv6(StunAddressFamily::IPv6, "::1", 9999);
    EXPECT_EQ(ipv6.to_string(), "[::1]:9999");
}

// ============================================================================
// ERROR-CODE Tests
// ============================================================================

TEST_F(StunTest, ErrorCodeAttribute) {
    StunMessage msg;
    msg.type = StunMessageType::BindingErrorResponse;
    msg.generate_transaction_id();
    msg.add_error_code(StunErrorCode::BadRequest, "Invalid request format");
    
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    auto error = parsed->get_error();
    
    ASSERT_TRUE(error.has_value());
    EXPECT_EQ(error->code, StunErrorCode::BadRequest);
    EXPECT_EQ(error->reason, "Invalid request format");
}

TEST_F(StunTest, VariousErrorCodes) {
    std::vector<StunErrorCode> codes = {
        StunErrorCode::TryAlternate,
        StunErrorCode::BadRequest,
        StunErrorCode::Unauthorized,
        StunErrorCode::UnknownAttribute,
        StunErrorCode::StaleNonce,
        StunErrorCode::ServerError
    };
    
    for (auto code : codes) {
        StunMessage msg;
        msg.type = StunMessageType::BindingErrorResponse;
        msg.generate_transaction_id();
        msg.add_error_code(code);
        
        auto data = msg.serialize();
        auto parsed = StunMessage::deserialize(data);
        
        ASSERT_TRUE(parsed.has_value());
        auto error = parsed->get_error();
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(error->code, code);
    }
}

// ============================================================================
// Attribute Tests
// ============================================================================

TEST_F(StunTest, UsernameAttribute) {
    StunMessage msg(StunMessageType::BindingRequest);
    msg.add_username("testuser");
    
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    const auto* attr = parsed->find_attribute(StunAttributeType::Username);
    ASSERT_NE(attr, nullptr);
    
    std::string username(attr->value.begin(), attr->value.end());
    EXPECT_EQ(username, "testuser");
}

TEST_F(StunTest, RealmAndNonceAttributes) {
    StunMessage msg(StunMessageType::BindingRequest);
    msg.add_realm("example.com");
    msg.add_nonce("abc123xyz");
    
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    
    auto realm = parsed->get_realm();
    ASSERT_TRUE(realm.has_value());
    EXPECT_EQ(*realm, "example.com");
    
    auto nonce = parsed->get_nonce();
    ASSERT_TRUE(nonce.has_value());
    EXPECT_EQ(*nonce, "abc123xyz");
}

TEST_F(StunTest, SoftwareAttribute) {
    StunMessage msg(StunMessageType::BindingRequest);
    msg.add_software("librats/1.0");
    
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    const auto* attr = parsed->find_attribute(StunAttributeType::Software);
    ASSERT_NE(attr, nullptr);
    
    std::string software(attr->value.begin(), attr->value.end());
    EXPECT_EQ(software, "librats/1.0");
}

TEST_F(StunTest, LifetimeAttribute) {
    StunMessage msg(StunMessageType::AllocateSuccessResponse);
    msg.generate_transaction_id();
    msg.add_lifetime(600);
    
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    auto lifetime = parsed->get_lifetime();
    ASSERT_TRUE(lifetime.has_value());
    EXPECT_EQ(*lifetime, 600u);
}

TEST_F(StunTest, DataAttribute) {
    StunMessage msg(StunMessageType::DataIndication);
    msg.generate_transaction_id();
    
    std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05};
    msg.add_data(payload);
    
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    auto result = parsed->get_data();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, payload);
}

TEST_F(StunTest, ChannelNumberAttribute) {
    StunMessage msg(StunMessageType::ChannelBindRequest);
    msg.generate_transaction_id();
    msg.add_channel_number(0x4000);
    
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    const auto* attr = parsed->find_attribute(StunAttributeType::ChannelNumber);
    ASSERT_NE(attr, nullptr);
    EXPECT_GE(attr->value.size(), 2u);
    
    uint16_t channel = (static_cast<uint16_t>(attr->value[0]) << 8) | attr->value[1];
    EXPECT_EQ(channel, 0x4000);
}

// ============================================================================
// CRC32 Tests
// ============================================================================

TEST_F(StunTest, CRC32Calculation) {
    // Test vector: "123456789" should produce 0xCBF43926
    const uint8_t test_data[] = "123456789";
    uint32_t crc = stun_crc32(test_data, 9);
    EXPECT_EQ(crc, 0xCBF43926);
    
    // Empty data
    uint32_t empty_crc = stun_crc32(nullptr, 0);
    EXPECT_EQ(empty_crc, 0x00000000);
}

// ============================================================================
// HMAC-SHA1 Tests
// ============================================================================

TEST_F(StunTest, HmacSha1Calculation) {
    // Test vector from RFC 2202
    std::vector<uint8_t> key(20, 0x0b);
    std::string data_str = "Hi There";
    std::vector<uint8_t> data(data_str.begin(), data_str.end());
    
    auto hmac = stun_hmac_sha1(key, data);
    
    // Expected: 0xb617318655057264e28bc0b6fb378c8ef146be00
    EXPECT_EQ(hmac.size(), 20u);
    EXPECT_EQ(hmac[0], 0xb6);
    EXPECT_EQ(hmac[1], 0x17);
    EXPECT_EQ(hmac[2], 0x31);
}

// ============================================================================
// Long-term Credential Tests
// ============================================================================

TEST_F(StunTest, LongTermCredentialKey) {
    // The key should be MD5(username:realm:password)
    auto key = stun_compute_long_term_key("user", "realm.example.com", "password");
    
    EXPECT_EQ(key.size(), 16u);  // MD5 produces 16 bytes
    // Just verify it doesn't crash and produces consistent output
    auto key2 = stun_compute_long_term_key("user", "realm.example.com", "password");
    EXPECT_EQ(key, key2);
    
    // Different input should produce different key
    auto key3 = stun_compute_long_term_key("user2", "realm.example.com", "password");
    EXPECT_NE(key, key3);
}

// ============================================================================
// StunClient Tests
// ============================================================================

TEST_F(StunTest, ClientConstruction) {
    StunClient client;
    EXPECT_EQ(client.config().rto_ms, STUN_DEFAULT_RTO_MS);
    EXPECT_EQ(client.config().max_retransmissions, STUN_MAX_RETRANSMISSIONS);
}

TEST_F(StunTest, ClientConfigurable) {
    StunClientConfig config;
    config.rto_ms = 100;
    config.max_retransmissions = 3;
    config.software = "test-client";
    
    StunClient client(config);
    EXPECT_EQ(client.config().rto_ms, 100);
    EXPECT_EQ(client.config().max_retransmissions, 3);
    EXPECT_EQ(client.config().software, "test-client");
}

// ============================================================================
// Mock STUN Server for Integration Tests
// ============================================================================

class MockStunServer {
public:
    MockStunServer(int port = 0) : running_(false), port_(port) {}
    
    ~MockStunServer() {
        stop();
    }
    
    bool start() {
        socket_ = create_udp_socket(port_);
        if (!is_valid_socket(socket_)) {
            return false;
        }
        
        // Get actual port if port was 0
        if (port_ == 0) {
            port_ = get_bound_port(socket_);
        }
        
        running_ = true;
        server_thread_ = std::thread(&MockStunServer::run, this);
        return true;
    }
    
    void stop() {
        running_ = false;
        if (is_valid_socket(socket_)) {
            close_socket(socket_);
            socket_ = INVALID_SOCKET_VALUE;
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }
    
    int get_port() const { return port_; }
    
private:
    void run() {
        while (running_) {
            Peer sender;
            auto data = receive_udp_data(socket_, 1500, sender, 100);
            
            if (data.empty()) continue;
            
            auto request = StunMessage::deserialize(data);
            if (!request || !request->is_request()) continue;
            
            // Create response
            StunMessage response;
            response.type = StunMessageType::BindingSuccessResponse;
            response.transaction_id = request->transaction_id;
            
            // Add XOR-MAPPED-ADDRESS with sender's address
            StunMappedAddress mapped_addr(StunAddressFamily::IPv4, sender.ip, sender.port);
            response.add_xor_mapped_address(mapped_addr);
            response.add_software("MockStunServer/1.0");
            
            auto response_data = response.serialize();
            send_udp_data(socket_, response_data, sender.ip, sender.port);
        }
    }
    
    std::atomic<bool> running_;
    socket_t socket_ = INVALID_SOCKET_VALUE;
    int port_;
    std::thread server_thread_;
};

TEST_F(StunTest, BindingRequestToMockServer) {
    MockStunServer server;
    ASSERT_TRUE(server.start());
    
    // Give server time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    StunClient client;
    auto result = client.binding_request("127.0.0.1", server.get_port(), 2000);
    
    EXPECT_TRUE(result.success);
    ASSERT_TRUE(result.mapped_address.has_value());
    EXPECT_EQ(result.mapped_address->family, StunAddressFamily::IPv4);
    EXPECT_EQ(result.mapped_address->address, "127.0.0.1");
    EXPECT_GT(result.mapped_address->port, 0);
    EXPECT_GE(result.rtt_ms, 0);  // RTT can be 0 on localhost
}

TEST_F(StunTest, BindingRequestWithExistingSocket) {
    MockStunServer server;
    ASSERT_TRUE(server.start());
    
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Create our own socket
    socket_t sock = create_udp_socket(0);
    ASSERT_TRUE(is_valid_socket(sock));
    
    int local_port = get_bound_port(sock);
    EXPECT_GT(local_port, 0);
    
    StunClient client;
    auto result = client.binding_request_with_socket(sock, "127.0.0.1", server.get_port(), 2000);
    
    EXPECT_TRUE(result.success);
    ASSERT_TRUE(result.mapped_address.has_value());
    // The mapped port should match our local socket port
    EXPECT_EQ(result.mapped_address->port, local_port);
    
    close_socket(sock);
}

TEST_F(StunTest, BindingRequestTimeout) {
    // Connect to a port that's not listening
    StunClientConfig config;
    config.rto_ms = 50;
    config.max_retransmissions = 1;
    config.total_timeout_ms = 200;
    
    StunClient client(config);
    auto result = client.binding_request("127.0.0.1", 59999, 200);
    
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.error.has_value());
}

// ============================================================================
// Public STUN Servers List
// ============================================================================

TEST_F(StunTest, PublicStunServersList) {
    auto servers = get_public_stun_servers();
    
    EXPECT_GT(servers.size(), 0u);
    
    for (const auto& [host, port] : servers) {
        EXPECT_FALSE(host.empty());
        EXPECT_GT(port, 0);
    }
}

// ============================================================================
// TURN Message Types
// ============================================================================

TEST_F(StunTest, TurnMessageTypes) {
    StunMessage allocate_req(StunMessageType::AllocateRequest);
    EXPECT_EQ(allocate_req.get_method(), StunMethod::Allocate);
    EXPECT_TRUE(allocate_req.is_request());
    
    StunMessage allocate_resp;
    allocate_resp.type = StunMessageType::AllocateSuccessResponse;
    EXPECT_TRUE(allocate_resp.is_success_response());
    
    StunMessage refresh_req(StunMessageType::RefreshRequest);
    EXPECT_EQ(refresh_req.get_method(), StunMethod::Refresh);
    
    StunMessage send_ind;
    send_ind.type = StunMessageType::SendIndication;
    EXPECT_EQ(send_ind.get_class(), StunMessageClass::Indication);
    
    StunMessage data_ind;
    data_ind.type = StunMessageType::DataIndication;
    EXPECT_EQ(data_ind.get_class(), StunMessageClass::Indication);
}

TEST_F(StunTest, RequestedTransportAttribute) {
    StunMessage msg(StunMessageType::AllocateRequest);
    msg.add_requested_transport(17);  // UDP = 17
    
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    const auto* attr = parsed->find_attribute(StunAttributeType::RequestedTransport);
    ASSERT_NE(attr, nullptr);
    EXPECT_GE(attr->value.size(), 1u);
    EXPECT_EQ(attr->value[0], 17);
}

// ============================================================================
// Attribute Padding Tests
// ============================================================================

TEST_F(StunTest, AttributePadding) {
    // Attribute with 1-byte value should be padded to 4 bytes
    StunAttribute attr;
    attr.value = {0x01};
    EXPECT_EQ(attr.padded_length(), 4u);
    
    // Attribute with 4-byte value should not need padding
    attr.value = {0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(attr.padded_length(), 4u);
    
    // Attribute with 5-byte value should be padded to 8 bytes
    attr.value = {0x01, 0x02, 0x03, 0x04, 0x05};
    EXPECT_EQ(attr.padded_length(), 8u);
}

TEST_F(StunTest, MultipleAttributesSerialization) {
    StunMessage msg(StunMessageType::BindingRequest);
    msg.add_username("user123");
    msg.add_realm("example.com");
    msg.add_software("test/1.0");
    
    auto data = msg.serialize();
    auto parsed = StunMessage::deserialize(data);
    
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->attributes.size(), 3u);
    
    // Verify all attributes are present
    EXPECT_NE(parsed->find_attribute(StunAttributeType::Username), nullptr);
    EXPECT_NE(parsed->find_attribute(StunAttributeType::Realm), nullptr);
    EXPECT_NE(parsed->find_attribute(StunAttributeType::Software), nullptr);
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(StunTest, EmptyMessageDeserialization) {
    std::vector<uint8_t> empty;
    auto result = StunMessage::deserialize(empty);
    EXPECT_FALSE(result.has_value());
}

TEST_F(StunTest, TruncatedMessageDeserialization) {
    StunMessage msg(StunMessageType::BindingRequest);
    auto data = msg.serialize();
    
    // Truncate the message
    data.resize(10);
    auto result = StunMessage::deserialize(data);
    EXPECT_FALSE(result.has_value());
}

TEST_F(StunTest, MessageWithInvalidLength) {
    StunMessage msg(StunMessageType::BindingRequest);
    auto data = msg.serialize();
    
    // Corrupt the length field
    data[2] = 0xFF;
    data[3] = 0xFF;
    
    auto result = StunMessage::deserialize(data);
    // Should either fail or not crash
}

TEST_F(StunTest, FindNonexistentAttribute) {
    StunMessage msg(StunMessageType::BindingRequest);
    
    const auto* attr = msg.find_attribute(StunAttributeType::ErrorCode);
    EXPECT_EQ(attr, nullptr);
}
