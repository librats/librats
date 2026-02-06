/**
 * @file test_turn.cpp
 * @brief Unit tests for TURN client implementation
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "turn.h"
#include "socket.h"
#include <thread>
#include <chrono>
#include <atomic>

using namespace librats;

// ============================================================================
// Test Fixtures
// ============================================================================

class TurnTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(init_socket_library());
    }
    
    void TearDown() override {
        cleanup_socket_library();
    }
};

// ============================================================================
// TurnClientConfig Tests
// ============================================================================

TEST_F(TurnTest, ConfigDefaultValues) {
    TurnClientConfig config;
    
    EXPECT_EQ(config.port, TURN_DEFAULT_PORT);
    EXPECT_EQ(config.requested_lifetime, TURN_DEFAULT_LIFETIME);
    EXPECT_EQ(config.timeout_ms, 5000);
    EXPECT_TRUE(config.auto_refresh);
    EXPECT_EQ(config.software, "librats");
    EXPECT_TRUE(config.server.empty());
    EXPECT_TRUE(config.username.empty());
    EXPECT_TRUE(config.password.empty());
}

TEST_F(TurnTest, ConfigConstructorWithCredentials) {
    TurnClientConfig config("turn.example.com", "testuser", "testpass");
    
    EXPECT_EQ(config.server, "turn.example.com");
    EXPECT_EQ(config.username, "testuser");
    EXPECT_EQ(config.password, "testpass");
    EXPECT_EQ(config.port, TURN_DEFAULT_PORT);
}

// ============================================================================
// TurnClient Construction Tests
// ============================================================================

TEST_F(TurnTest, ClientDefaultConstruction) {
    TurnClient client;
    
    EXPECT_EQ(client.get_state(), TurnAllocationState::None);
    EXPECT_FALSE(client.is_allocated());
    EXPECT_FALSE(client.get_allocation().is_valid());
}

TEST_F(TurnTest, ClientConstructionWithConfig) {
    TurnClientConfig config;
    config.server = "turn.example.com";
    config.username = "user";
    config.password = "pass";
    
    TurnClient client(config);
    
    EXPECT_EQ(client.config().server, "turn.example.com");
    EXPECT_EQ(client.config().username, "user");
    EXPECT_EQ(client.config().password, "pass");
}

TEST_F(TurnTest, ClientSetConfig) {
    TurnClient client;
    
    TurnClientConfig config;
    config.server = "new.server.com";
    config.port = 5349;
    
    client.set_config(config);
    
    EXPECT_EQ(client.config().server, "new.server.com");
    EXPECT_EQ(client.config().port, 5349);
}

TEST_F(TurnTest, ClientMoveConstruction) {
    TurnClientConfig config("turn.example.com", "user", "pass");
    TurnClient client1(config);
    
    TurnClient client2(std::move(client1));
    
    EXPECT_EQ(client2.config().server, "turn.example.com");
    EXPECT_EQ(client2.config().username, "user");
}

TEST_F(TurnTest, ClientMoveAssignment) {
    TurnClientConfig config("turn.example.com", "user", "pass");
    TurnClient client1(config);
    
    TurnClient client2;
    client2 = std::move(client1);
    
    EXPECT_EQ(client2.config().server, "turn.example.com");
}

// ============================================================================
// TurnAllocation Tests
// ============================================================================

TEST_F(TurnTest, AllocationDefaultState) {
    TurnAllocation alloc;
    
    EXPECT_FALSE(alloc.is_valid());
    EXPECT_EQ(alloc.lifetime, 0u);
    EXPECT_EQ(alloc.remaining_lifetime(), 0u);
}

TEST_F(TurnTest, AllocationValidState) {
    TurnAllocation alloc;
    alloc.relay_address = StunMappedAddress(StunAddressFamily::IPv4, "1.2.3.4", 5000);
    alloc.lifetime = 600;
    alloc.allocated_at = std::chrono::steady_clock::now();
    alloc.expires_at = alloc.allocated_at + std::chrono::seconds(600);
    
    EXPECT_TRUE(alloc.is_valid());
    EXPECT_FALSE(alloc.is_expired());
    EXPECT_GT(alloc.remaining_lifetime(), 0u);
    EXPECT_LE(alloc.remaining_lifetime(), 600u);
}

TEST_F(TurnTest, AllocationExpired) {
    TurnAllocation alloc;
    alloc.relay_address = StunMappedAddress(StunAddressFamily::IPv4, "1.2.3.4", 5000);
    alloc.lifetime = 600;
    alloc.allocated_at = std::chrono::steady_clock::now() - std::chrono::seconds(700);
    alloc.expires_at = alloc.allocated_at + std::chrono::seconds(600);
    
    EXPECT_TRUE(alloc.is_expired());
    EXPECT_EQ(alloc.remaining_lifetime(), 0u);
}

// ============================================================================
// TurnPermission Tests
// ============================================================================

TEST_F(TurnTest, PermissionExpiry) {
    TurnPermission perm;
    perm.peer_address = "192.168.1.100";
    perm.expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(5);
    
    EXPECT_FALSE(perm.is_expired());
    
    TurnPermission expired_perm;
    expired_perm.peer_address = "192.168.1.101";
    expired_perm.expires_at = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    
    EXPECT_TRUE(expired_perm.is_expired());
}

// ============================================================================
// TurnChannelBinding Tests
// ============================================================================

TEST_F(TurnTest, ChannelBindingExpiry) {
    TurnChannelBinding binding;
    binding.channel_number = 0x4000;
    binding.peer_address = StunMappedAddress(StunAddressFamily::IPv4, "192.168.1.100", 5000);
    binding.expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(10);
    
    EXPECT_FALSE(binding.is_expired());
    
    TurnChannelBinding expired_binding;
    expired_binding.channel_number = 0x4001;
    expired_binding.peer_address = StunMappedAddress(StunAddressFamily::IPv4, "192.168.1.101", 5001);
    expired_binding.expires_at = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    
    EXPECT_TRUE(expired_binding.is_expired());
}

// ============================================================================
// TurnResult Tests
// ============================================================================

TEST_F(TurnTest, ResultSuccess) {
    auto result = TurnResult::Success();
    
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.error.has_value());
    EXPECT_TRUE(result.error_message.empty());
}

TEST_F(TurnTest, ResultErrorWithMessage) {
    auto result = TurnResult::Error("Something went wrong");
    
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.error_message, "Something went wrong");
}

TEST_F(TurnTest, ResultErrorWithCode) {
    auto result = TurnResult::Error(StunErrorCode::Unauthorized, "Authentication required");
    
    EXPECT_FALSE(result.success);
    ASSERT_TRUE(result.error.has_value());
    EXPECT_EQ(result.error->code, StunErrorCode::Unauthorized);
    EXPECT_EQ(result.error_message, "Authentication required");
}

// ============================================================================
// Channel Number Constants Tests
// ============================================================================

TEST_F(TurnTest, ChannelNumberRange) {
    EXPECT_EQ(TURN_CHANNEL_MIN, 0x4000);
    EXPECT_EQ(TURN_CHANNEL_MAX, 0x7FFF);
    EXPECT_LT(TURN_CHANNEL_MIN, TURN_CHANNEL_MAX);
}

TEST_F(TurnTest, TransportConstants) {
    EXPECT_EQ(TURN_TRANSPORT_UDP, 17);
    EXPECT_EQ(TURN_TRANSPORT_TCP, 6);
}

// ============================================================================
// Operations Without Allocation Tests
// ============================================================================

TEST_F(TurnTest, RefreshWithoutAllocation) {
    TurnClient client;
    
    auto result = client.refresh();
    
    EXPECT_FALSE(result.success);
}

TEST_F(TurnTest, CreatePermissionWithoutAllocation) {
    TurnClient client;
    
    auto result = client.create_permission("192.168.1.100");
    
    EXPECT_FALSE(result.success);
}

TEST_F(TurnTest, BindChannelWithoutAllocation) {
    TurnClient client;
    
    StunMappedAddress peer(StunAddressFamily::IPv4, "192.168.1.100", 5000);
    uint16_t channel = client.bind_channel(peer);
    
    EXPECT_EQ(channel, 0);
}

TEST_F(TurnTest, SendDataWithoutAllocation) {
    TurnClient client;
    
    StunMappedAddress peer(StunAddressFamily::IPv4, "192.168.1.100", 5000);
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    
    bool sent = client.send_data(peer, data);
    
    EXPECT_FALSE(sent);
}

TEST_F(TurnTest, HasPermissionWithoutPermission) {
    TurnClient client;
    
    EXPECT_FALSE(client.has_permission("192.168.1.100"));
}

TEST_F(TurnTest, GetChannelWithoutBinding) {
    TurnClient client;
    
    StunMappedAddress peer(StunAddressFamily::IPv4, "192.168.1.100", 5000);
    uint16_t channel = client.get_channel(peer);
    
    EXPECT_EQ(channel, 0);
}

TEST_F(TurnTest, GetChannelPeerWithoutBinding) {
    TurnClient client;
    
    auto peer = client.get_channel_peer(0x4000);
    
    EXPECT_FALSE(peer.has_value());
}

// ============================================================================
// Socket Tests
// ============================================================================

TEST_F(TurnTest, GetSocketBeforeAllocation) {
    TurnClient client;
    
    socket_t sock = client.get_socket();
    
    EXPECT_EQ(sock, INVALID_SOCKET_VALUE);
}

// ============================================================================
// Mock TURN Server for Integration Tests
// ============================================================================

class MockTurnServer {
public:
    MockTurnServer() : running_(false) {}
    
    ~MockTurnServer() {
        stop();
    }
    
    bool start() {
        socket_ = create_udp_socket(0);
        if (!is_valid_socket(socket_)) {
            return false;
        }
        
        port_ = get_bound_port(socket_);
        running_ = true;
        server_thread_ = std::thread(&MockTurnServer::run, this);
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
    
    void set_nonce(const std::string& nonce) { nonce_ = nonce; }
    void set_realm(const std::string& realm) { realm_ = realm; }
    void set_relay_address(const std::string& addr, uint16_t port) {
        relay_address_ = addr;
        relay_port_ = port;
    }
    
private:
    void run() {
        while (running_) {
            Peer sender;
            auto data = receive_udp_data(socket_, 1500, sender, 100);
            
            if (data.empty()) continue;
            
            auto request = StunMessage::deserialize(data);
            if (!request) continue;
            
            StunMessage response;
            response.transaction_id = request->transaction_id;
            
            switch (request->type) {
                case StunMessageType::AllocateRequest:
                    handle_allocate(*request, response, sender);
                    break;
                case StunMessageType::RefreshRequest:
                    handle_refresh(*request, response);
                    break;
                case StunMessageType::CreatePermissionRequest:
                    handle_create_permission(*request, response);
                    break;
                case StunMessageType::ChannelBindRequest:
                    handle_channel_bind(*request, response);
                    break;
                default:
                    continue;
            }
            
            auto response_data = response.serialize();
            send_udp_data(socket_, response_data, sender.ip, sender.port);
        }
    }
    
    void handle_allocate(const StunMessage& request, StunMessage& response, const Peer& sender) {
        // Check for credentials
        const auto* username_attr = request.find_attribute(StunAttributeType::Username);
        
        if (!username_attr) {
            // First request - send 401 with nonce and realm
            response.type = StunMessageType::AllocateErrorResponse;
            response.add_error_code(StunErrorCode::Unauthorized, "Unauthorized");
            response.add_nonce(nonce_);
            response.add_realm(realm_);
        } else {
            // Has credentials - success
            response.type = StunMessageType::AllocateSuccessResponse;
            
            // Add XOR-RELAYED-ADDRESS (relay address assigned by server)
            StunMappedAddress relay(StunAddressFamily::IPv4, relay_address_, relay_port_);
            response.add_xor_relayed_address(relay);
            
            // Add XOR-MAPPED-ADDRESS (client's reflexive address)
            StunMappedAddress mapped(StunAddressFamily::IPv4, sender.ip, sender.port);
            response.add_xor_mapped_address(mapped);
            
            response.add_lifetime(600);
        }
    }
    
    void handle_refresh(const StunMessage& request, StunMessage& response) {
        auto lifetime = request.get_lifetime();
        
        response.type = StunMessageType::RefreshSuccessResponse;
        response.add_lifetime(lifetime.value_or(600));
    }
    
    void handle_create_permission(const StunMessage& request, StunMessage& response) {
        response.type = StunMessageType::CreatePermissionSuccessResponse;
    }
    
    void handle_channel_bind(const StunMessage& request, StunMessage& response) {
        response.type = StunMessageType::ChannelBindSuccessResponse;
    }
    
    std::atomic<bool> running_;
    socket_t socket_ = INVALID_SOCKET_VALUE;
    int port_ = 0;
    std::thread server_thread_;
    
    std::string nonce_ = "testnonce12345";
    std::string realm_ = "test.realm.com";
    std::string relay_address_ = "1.2.3.4";
    uint16_t relay_port_ = 49152;
};

// ============================================================================
// Integration Tests with Mock Server
// ============================================================================

TEST_F(TurnTest, AllocationWithMockServer) {
    MockTurnServer server;
    ASSERT_TRUE(server.start());
    
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    TurnClientConfig config;
    config.server = "127.0.0.1";
    config.port = server.get_port();
    config.username = "testuser";
    config.password = "testpass";
    config.realm = "test.realm.com";
    config.timeout_ms = 2000;
    config.auto_refresh = false;
    
    TurnClient client(config);
    auto result = client.allocate();
    
    // Note: The mock server uses XOR-MAPPED-ADDRESS for relay address
    // In a real scenario, XOR-RELAYED-ADDRESS would be used
    // This test verifies the basic flow works
    EXPECT_EQ(client.get_state(), TurnAllocationState::Allocated);
}

TEST_F(TurnTest, AllocationTimeout) {
    // Try to allocate from a non-existent server
    TurnClientConfig config;
    config.server = "127.0.0.1";
    config.port = 59998;  // Unlikely to be listening
    config.username = "user";
    config.password = "pass";
    config.timeout_ms = 200;
    config.auto_refresh = false;
    
    TurnClient client(config);
    auto result = client.allocate();
    
    EXPECT_FALSE(result.success);
    EXPECT_EQ(client.get_state(), TurnAllocationState::Failed);
}

// ============================================================================
// State Callback Tests
// ============================================================================

TEST_F(TurnTest, StateCallback) {
    std::vector<TurnAllocationState> states;
    
    TurnClientConfig config;
    config.server = "127.0.0.1";
    config.port = 59997;
    config.timeout_ms = 100;
    config.auto_refresh = false;
    
    TurnClient client(config);
    client.set_state_callback([&states](TurnAllocationState state) {
        states.push_back(state);
    });
    
    client.allocate();  // Will fail due to timeout
    
    // Should have transitioned through states
    ASSERT_GE(states.size(), 1u);
    EXPECT_EQ(states[0], TurnAllocationState::Allocating);
    
    if (states.size() > 1) {
        EXPECT_EQ(states.back(), TurnAllocationState::Failed);
    }
}

// ============================================================================
// Channel Data Format Tests
// ============================================================================

TEST_F(TurnTest, ChannelDataHeaderSize) {
    EXPECT_EQ(TURN_CHANNEL_HEADER_SIZE, 4u);
}

// ============================================================================
// Close Tests
// ============================================================================

TEST_F(TurnTest, CloseBeforeAllocation) {
    TurnClient client;
    
    // Should not crash
    client.close();
    
    EXPECT_EQ(client.get_state(), TurnAllocationState::None);
}

TEST_F(TurnTest, MultipleClose) {
    TurnClient client;
    
    // Should be safe to call multiple times
    client.close();
    client.close();
    client.close();
    
    EXPECT_EQ(client.get_state(), TurnAllocationState::None);
}

// ============================================================================
// Refresh Thread Tests
// ============================================================================

TEST_F(TurnTest, RefreshThreadStartStop) {
    TurnClient client;
    
    // Starting/stopping refresh thread without allocation should be safe
    client.start_refresh_thread();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    client.stop_refresh_thread();
    
    // Multiple starts should be safe
    client.start_refresh_thread();
    client.start_refresh_thread();
    client.stop_refresh_thread();
    
    // Multiple stops should be safe
    client.stop_refresh_thread();
    client.stop_refresh_thread();
}

// ============================================================================
// Receive Data Tests
// ============================================================================

TEST_F(TurnTest, ReceiveDataWithoutSocket) {
    TurnClient client;
    
    auto result = client.receive_data(0);
    
    EXPECT_FALSE(result.has_value());
}

TEST_F(TurnTest, ReceiveDataTimeout) {
    TurnClient client;
    
    // Create socket manually for testing
    TurnClientConfig config;
    config.server = "127.0.0.1";
    config.port = 59996;
    client.set_config(config);
    
    // receive_data without valid socket should return empty
    auto result = client.receive_data(10);
    EXPECT_FALSE(result.has_value());
}
