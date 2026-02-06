/**
 * @file test_ice.cpp
 * @brief Unit tests for ICE-lite implementation
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ice.h"
#include "socket.h"
#include <thread>
#include <chrono>
#include <atomic>

using namespace librats;

// ============================================================================
// Test Fixtures
// ============================================================================

class IceTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(init_socket_library());
    }
    
    void TearDown() override {
        cleanup_socket_library();
    }
};

// ============================================================================
// IceCandidate Tests
// ============================================================================

TEST_F(IceTest, CandidatePriorityHost) {
    uint32_t priority = IceCandidate::compute_priority(IceCandidateType::Host);
    
    // Host should have highest priority
    uint32_t srflx_priority = IceCandidate::compute_priority(IceCandidateType::ServerReflexive);
    uint32_t relay_priority = IceCandidate::compute_priority(IceCandidateType::Relay);
    
    EXPECT_GT(priority, srflx_priority);
    EXPECT_GT(priority, relay_priority);
    EXPECT_GT(srflx_priority, relay_priority);
}

TEST_F(IceTest, CandidatePriorityComponents) {
    // Component 1 should have higher priority than component 2
    uint32_t comp1 = IceCandidate::compute_priority(IceCandidateType::Host, 65535, 1);
    uint32_t comp2 = IceCandidate::compute_priority(IceCandidateType::Host, 65535, 2);
    
    EXPECT_GT(comp1, comp2);
}

TEST_F(IceTest, CandidateFoundationGeneration) {
    auto f1 = IceCandidate::generate_foundation(IceCandidateType::Host, "192.168.1.1");
    auto f2 = IceCandidate::generate_foundation(IceCandidateType::Host, "192.168.1.1");
    auto f3 = IceCandidate::generate_foundation(IceCandidateType::Host, "192.168.1.2");
    auto f4 = IceCandidate::generate_foundation(IceCandidateType::ServerReflexive, "192.168.1.1", "stun.example.com");
    
    // Same inputs should produce same foundation
    EXPECT_EQ(f1, f2);
    
    // Different address should produce different foundation
    EXPECT_NE(f1, f3);
    
    // Different type/server should produce different foundation
    EXPECT_NE(f1, f4);
}

TEST_F(IceTest, CandidateTypeString) {
    IceCandidate host, srflx, prflx, relay;
    host.type = IceCandidateType::Host;
    srflx.type = IceCandidateType::ServerReflexive;
    prflx.type = IceCandidateType::PeerReflexive;
    relay.type = IceCandidateType::Relay;
    
    EXPECT_EQ(host.type_string(), "host");
    EXPECT_EQ(srflx.type_string(), "srflx");
    EXPECT_EQ(prflx.type_string(), "prflx");
    EXPECT_EQ(relay.type_string(), "relay");
}

TEST_F(IceTest, CandidateAddressString) {
    IceCandidate c;
    c.address = "192.168.1.100";
    c.port = 12345;
    
    EXPECT_EQ(c.address_string(), "192.168.1.100:12345");
}

TEST_F(IceTest, CandidateEquality) {
    IceCandidate c1, c2, c3;
    c1.type = IceCandidateType::Host;
    c1.address = "192.168.1.1";
    c1.port = 5000;
    c1.transport = IceTransportProtocol::UDP;
    
    c2 = c1;
    
    c3 = c1;
    c3.port = 5001;
    
    EXPECT_TRUE(c1 == c2);
    EXPECT_FALSE(c1 == c3);
}

// ============================================================================
// SDP Attribute Tests
// ============================================================================

TEST_F(IceTest, CandidateToSdpHost) {
    IceCandidate c;
    c.type = IceCandidateType::Host;
    c.foundation = "host_abc123";
    c.component_id = 1;
    c.transport = IceTransportProtocol::UDP;
    c.priority = 2130706431;
    c.address = "192.168.1.100";
    c.port = 54321;
    
    std::string sdp = c.to_sdp_attribute();
    
    EXPECT_TRUE(sdp.find("candidate:host_abc123") != std::string::npos);
    EXPECT_TRUE(sdp.find("192.168.1.100") != std::string::npos);
    EXPECT_TRUE(sdp.find("54321") != std::string::npos);
    EXPECT_TRUE(sdp.find("typ host") != std::string::npos);
}

TEST_F(IceTest, CandidateToSdpSrflx) {
    IceCandidate c;
    c.type = IceCandidateType::ServerReflexive;
    c.foundation = "srflx_xyz";
    c.component_id = 1;
    c.transport = IceTransportProtocol::UDP;
    c.priority = 1694498815;
    c.address = "203.0.113.5";
    c.port = 45678;
    c.related_address = "192.168.1.100";
    c.related_port = 54321;
    
    std::string sdp = c.to_sdp_attribute();
    
    EXPECT_TRUE(sdp.find("typ srflx") != std::string::npos);
    EXPECT_TRUE(sdp.find("raddr 192.168.1.100") != std::string::npos);
    EXPECT_TRUE(sdp.find("rport 54321") != std::string::npos);
}

TEST_F(IceTest, CandidateFromSdpHost) {
    std::string sdp = "candidate:0 1 UDP 2130706431 192.168.1.100 54321 typ host";
    
    auto candidate = IceCandidate::from_sdp_attribute(sdp);
    
    ASSERT_TRUE(candidate.has_value());
    EXPECT_EQ(candidate->foundation, "0");
    EXPECT_EQ(candidate->component_id, 1u);
    EXPECT_EQ(candidate->transport, IceTransportProtocol::UDP);
    EXPECT_EQ(candidate->priority, 2130706431u);
    EXPECT_EQ(candidate->address, "192.168.1.100");
    EXPECT_EQ(candidate->port, 54321u);
    EXPECT_EQ(candidate->type, IceCandidateType::Host);
}

TEST_F(IceTest, CandidateFromSdpWithPrefix) {
    std::string sdp = "a=candidate:0 1 UDP 2130706431 192.168.1.100 54321 typ host";
    
    auto candidate = IceCandidate::from_sdp_attribute(sdp);
    
    ASSERT_TRUE(candidate.has_value());
    EXPECT_EQ(candidate->type, IceCandidateType::Host);
}

TEST_F(IceTest, CandidateFromSdpSrflx) {
    std::string sdp = "candidate:1 1 UDP 1694498815 203.0.113.5 45678 typ srflx raddr 192.168.1.100 rport 54321";
    
    auto candidate = IceCandidate::from_sdp_attribute(sdp);
    
    ASSERT_TRUE(candidate.has_value());
    EXPECT_EQ(candidate->type, IceCandidateType::ServerReflexive);
    EXPECT_EQ(candidate->address, "203.0.113.5");
    EXPECT_EQ(candidate->port, 45678u);
    EXPECT_EQ(candidate->related_address, "192.168.1.100");
    EXPECT_EQ(candidate->related_port, 54321u);
}

TEST_F(IceTest, CandidateFromSdpRelay) {
    std::string sdp = "candidate:2 1 UDP 16777215 203.0.113.10 12345 typ relay raddr 203.0.113.5 rport 45678";
    
    auto candidate = IceCandidate::from_sdp_attribute(sdp);
    
    ASSERT_TRUE(candidate.has_value());
    EXPECT_EQ(candidate->type, IceCandidateType::Relay);
}

TEST_F(IceTest, CandidateFromSdpInvalid) {
    std::string sdp = "invalid sdp line";
    
    auto candidate = IceCandidate::from_sdp_attribute(sdp);
    
    EXPECT_FALSE(candidate.has_value());
}

TEST_F(IceTest, CandidateRoundTrip) {
    IceCandidate original;
    original.type = IceCandidateType::Host;
    original.foundation = "host_test123";
    original.component_id = 1;
    original.transport = IceTransportProtocol::UDP;
    original.priority = 2130706431;
    original.address = "192.168.1.100";
    original.port = 54321;
    
    std::string sdp = original.to_sdp_attribute();
    auto parsed = IceCandidate::from_sdp_attribute(sdp);
    
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->type, original.type);
    EXPECT_EQ(parsed->foundation, original.foundation);
    EXPECT_EQ(parsed->component_id, original.component_id);
    EXPECT_EQ(parsed->transport, original.transport);
    EXPECT_EQ(parsed->priority, original.priority);
    EXPECT_EQ(parsed->address, original.address);
    EXPECT_EQ(parsed->port, original.port);
}

// ============================================================================
// IceCandidatePair Tests
// ============================================================================

TEST_F(IceTest, PairPriorityCalculation) {
    // RFC 5245 formula
    uint32_t controlling = 2130706431;
    uint32_t controlled = 1694498815;
    
    uint64_t priority_as_controlling = IceCandidatePair::compute_priority(
        controlling, controlled, true);
    uint64_t priority_as_controlled = IceCandidatePair::compute_priority(
        controlling, controlled, false);
    
    // Priorities should be non-zero
    EXPECT_GT(priority_as_controlling, 0u);
    EXPECT_GT(priority_as_controlled, 0u);
    
    // Equal priorities should still produce valid result
    uint64_t equal = IceCandidatePair::compute_priority(1000, 1000, true);
    EXPECT_GT(equal, 0u);
}

TEST_F(IceTest, PairKey) {
    IceCandidatePair pair;
    pair.local.address = "192.168.1.1";
    pair.local.port = 5000;
    pair.remote.address = "10.0.0.1";
    pair.remote.port = 6000;
    
    EXPECT_EQ(pair.key(), "192.168.1.1:5000->10.0.0.1:6000");
}

// ============================================================================
// IceServer Tests
// ============================================================================

TEST_F(IceTest, ServerIsStun) {
    IceServer stun("stun:stun.example.com:3478");
    IceServer turn("turn:turn.example.com:3478");
    
    EXPECT_TRUE(stun.is_stun());
    EXPECT_FALSE(stun.is_turn());
    
    EXPECT_FALSE(turn.is_stun());
    EXPECT_TRUE(turn.is_turn());
}

TEST_F(IceTest, ServerParseUrl) {
    IceServer server1("stun:stun.example.com:3478");
    std::string host1;
    uint16_t port1;
    
    EXPECT_TRUE(server1.parse_url(host1, port1));
    EXPECT_EQ(host1, "stun.example.com");
    EXPECT_EQ(port1, 3478);
    
    // Without port
    IceServer server2("stun:stun.example.com");
    std::string host2;
    uint16_t port2;
    
    EXPECT_TRUE(server2.parse_url(host2, port2));
    EXPECT_EQ(host2, "stun.example.com");
    EXPECT_EQ(port2, STUN_DEFAULT_PORT);
}

TEST_F(IceTest, ServerTurnWithCredentials) {
    IceServer server("turn:turn.example.com:3478", "user", "pass");
    
    EXPECT_TRUE(server.is_turn());
    EXPECT_EQ(server.username, "user");
    EXPECT_EQ(server.password, "pass");
}

// ============================================================================
// IceConfig Tests
// ============================================================================

TEST_F(IceTest, ConfigDefaults) {
    IceConfig config;
    
    EXPECT_TRUE(config.gather_host_candidates);
    EXPECT_TRUE(config.gather_srflx_candidates);
    EXPECT_FALSE(config.gather_relay_candidates);
    EXPECT_EQ(config.gathering_timeout_ms, 5000);
    EXPECT_EQ(config.software, "librats");
    EXPECT_TRUE(config.ice_servers.empty());
}

TEST_F(IceTest, ConfigAddStunServer) {
    IceConfig config;
    config.add_stun_server("stun.example.com", 19302);
    
    EXPECT_EQ(config.ice_servers.size(), 1u);
    EXPECT_TRUE(config.ice_servers[0].is_stun());
    
    std::string host;
    uint16_t port;
    config.ice_servers[0].parse_url(host, port);
    EXPECT_EQ(host, "stun.example.com");
    EXPECT_EQ(port, 19302);
}

TEST_F(IceTest, ConfigAddTurnServer) {
    IceConfig config;
    config.add_turn_server("turn.example.com", 3478, "user", "pass");
    
    EXPECT_EQ(config.ice_servers.size(), 1u);
    EXPECT_TRUE(config.ice_servers[0].is_turn());
    EXPECT_EQ(config.ice_servers[0].username, "user");
    EXPECT_EQ(config.ice_servers[0].password, "pass");
}

// ============================================================================
// IceManager Construction Tests
// ============================================================================

TEST_F(IceTest, ManagerDefaultConstruction) {
    IceManager ice;
    
    EXPECT_EQ(ice.get_gathering_state(), IceGatheringState::New);
    EXPECT_EQ(ice.get_connection_state(), IceConnectionState::New);
    EXPECT_FALSE(ice.is_connected());
    EXPECT_FALSE(ice.is_gathering_complete());
    EXPECT_EQ(ice.get_socket(), INVALID_SOCKET_VALUE);
}

TEST_F(IceTest, ManagerConstructionWithConfig) {
    IceConfig config;
    config.add_stun_server("stun.l.google.com", 19302);
    
    IceManager ice(config);
    
    EXPECT_EQ(ice.config().ice_servers.size(), 1u);
}

TEST_F(IceTest, ManagerSetConfig) {
    IceManager ice;
    
    IceConfig config;
    config.gathering_timeout_ms = 3000;
    ice.set_config(config);
    
    EXPECT_EQ(ice.config().gathering_timeout_ms, 3000);
}

TEST_F(IceTest, ManagerAddServers) {
    IceManager ice;
    
    ice.add_stun_server("stun.example.com");
    ice.add_turn_server("turn.example.com", 3478, "user", "pass");
    
    EXPECT_EQ(ice.config().ice_servers.size(), 2u);
}

TEST_F(IceTest, ManagerClearServers) {
    IceManager ice;
    
    ice.add_stun_server("stun.example.com");
    ice.add_stun_server("stun2.example.com");
    
    EXPECT_EQ(ice.config().ice_servers.size(), 2u);
    
    ice.clear_ice_servers();
    
    EXPECT_TRUE(ice.config().ice_servers.empty());
}

// ============================================================================
// Candidate Gathering Tests
// ============================================================================

TEST_F(IceTest, GatherHostCandidates) {
    IceConfig config;
    config.gather_host_candidates = true;
    config.gather_srflx_candidates = false;  // Don't contact STUN servers
    config.gather_relay_candidates = false;
    
    IceManager ice(config);
    
    std::atomic<bool> gathering_complete{false};
    std::vector<IceCandidate> gathered_candidates;
    
    ice.set_on_candidates_gathered([&](const std::vector<IceCandidate>& candidates) {
        gathered_candidates = candidates;
        gathering_complete = true;
    });
    
    EXPECT_TRUE(ice.gather_candidates());
    
    // Wait for gathering
    for (int i = 0; i < 50 && !gathering_complete; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    EXPECT_TRUE(gathering_complete);
    EXPECT_EQ(ice.get_gathering_state(), IceGatheringState::Complete);
    
    // Should have at least one host candidate (unless no network interfaces)
    auto candidates = ice.get_local_candidates();
    // Note: Some environments might have no non-loopback interfaces
    for (const auto& c : candidates) {
        EXPECT_EQ(c.type, IceCandidateType::Host);
        EXPECT_FALSE(c.address.empty());
        EXPECT_GT(c.port, 0u);
    }
}

TEST_F(IceTest, GatheringStateCallback) {
    IceConfig config;
    config.gather_host_candidates = true;
    config.gather_srflx_candidates = false;
    config.gather_relay_candidates = false;
    
    IceManager ice(config);
    
    std::vector<IceGatheringState> states;
    ice.set_on_gathering_state_changed([&](IceGatheringState state) {
        states.push_back(state);
    });
    
    ice.gather_candidates();
    
    // Wait for gathering
    for (int i = 0; i < 50 && ice.get_gathering_state() != IceGatheringState::Complete; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    EXPECT_GE(states.size(), 1u);
    EXPECT_EQ(states[0], IceGatheringState::Gathering);
    if (states.size() > 1) {
        EXPECT_EQ(states.back(), IceGatheringState::Complete);
    }
}

TEST_F(IceTest, NewCandidateCallback) {
    IceConfig config;
    config.gather_host_candidates = true;
    config.gather_srflx_candidates = false;
    config.gather_relay_candidates = false;
    
    IceManager ice(config);
    
    std::vector<IceCandidate> trickle_candidates;
    ice.set_on_new_candidate([&](const IceCandidate& candidate) {
        trickle_candidates.push_back(candidate);
    });
    
    ice.gather_candidates();
    
    // Wait for gathering
    for (int i = 0; i < 50 && ice.get_gathering_state() != IceGatheringState::Complete; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Each local candidate should have triggered the callback
    EXPECT_EQ(trickle_candidates.size(), ice.get_local_candidates().size());
}

// ============================================================================
// Remote Candidates Tests
// ============================================================================

TEST_F(IceTest, AddRemoteCandidate) {
    IceManager ice;
    
    IceCandidate remote;
    remote.type = IceCandidateType::Host;
    remote.address = "10.0.0.1";
    remote.port = 5000;
    remote.transport = IceTransportProtocol::UDP;
    remote.component_id = 1;
    remote.priority = 2130706431;
    remote.foundation = "abc123";
    
    ice.add_remote_candidate(remote);
    
    auto remotes = ice.get_remote_candidates();
    EXPECT_EQ(remotes.size(), 1u);
    EXPECT_EQ(remotes[0].address, "10.0.0.1");
}

TEST_F(IceTest, AddRemoteCandidatesFromSdp) {
    IceManager ice;
    
    std::vector<std::string> sdp_lines = {
        "candidate:0 1 UDP 2130706431 192.168.1.100 54321 typ host",
        "candidate:1 1 UDP 1694498815 203.0.113.5 45678 typ srflx raddr 192.168.1.100 rport 54321"
    };
    
    ice.add_remote_candidates_from_sdp(sdp_lines);
    
    auto remotes = ice.get_remote_candidates();
    EXPECT_EQ(remotes.size(), 2u);
}

TEST_F(IceTest, DuplicateRemoteCandidatesIgnored) {
    IceManager ice;
    
    IceCandidate remote;
    remote.type = IceCandidateType::Host;
    remote.address = "10.0.0.1";
    remote.port = 5000;
    remote.transport = IceTransportProtocol::UDP;
    remote.component_id = 1;
    
    ice.add_remote_candidate(remote);
    ice.add_remote_candidate(remote);  // Duplicate
    
    EXPECT_EQ(ice.get_remote_candidates().size(), 1u);
}

// ============================================================================
// Connectivity Check Tests
// ============================================================================

TEST_F(IceTest, FormCandidatePairs) {
    IceConfig config;
    config.gather_host_candidates = true;
    config.gather_srflx_candidates = false;
    config.gather_relay_candidates = false;
    
    IceManager ice(config);
    
    // Gather local candidates
    ice.gather_candidates();
    for (int i = 0; i < 50 && !ice.is_gathering_complete(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Add remote candidate
    IceCandidate remote;
    remote.type = IceCandidateType::Host;
    remote.address = "10.0.0.1";
    remote.port = 5000;
    remote.transport = IceTransportProtocol::UDP;
    remote.component_id = 1;
    remote.priority = 2130706431;
    remote.foundation = "remote1";
    
    ice.add_remote_candidate(remote);
    
    // Should form pairs
    auto pairs = ice.get_candidate_pairs();
    auto local_count = ice.get_local_candidates().size();
    EXPECT_EQ(pairs.size(), local_count);
}

TEST_F(IceTest, GetSelectedPairBeforeConnection) {
    IceManager ice;
    
    auto pair = ice.get_selected_pair();
    
    EXPECT_FALSE(pair.has_value());
}

// ============================================================================
// Public Address Discovery Tests
// ============================================================================

TEST_F(IceTest, GetPublicAddressWithoutSrflx) {
    IceConfig config;
    config.gather_host_candidates = true;
    config.gather_srflx_candidates = false;  // No STUN servers
    
    IceManager ice(config);
    
    ice.gather_candidates();
    for (int i = 0; i < 50 && !ice.is_gathering_complete(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    auto public_addr = ice.get_public_address();
    
    // Without srflx gathering, should return nullopt
    EXPECT_FALSE(public_addr.has_value());
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

TEST_F(IceTest, Close) {
    IceManager ice;
    
    ice.gather_candidates();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    ice.close();
    
    EXPECT_EQ(ice.get_connection_state(), IceConnectionState::Closed);
    EXPECT_EQ(ice.get_socket(), INVALID_SOCKET_VALUE);
}

TEST_F(IceTest, MultipleClose) {
    IceManager ice;
    
    // Should be safe to call multiple times
    ice.close();
    ice.close();
    ice.close();
    
    EXPECT_EQ(ice.get_connection_state(), IceConnectionState::Closed);
}

TEST_F(IceTest, Restart) {
    IceConfig config;
    config.gather_host_candidates = true;
    config.gather_srflx_candidates = false;
    
    IceManager ice(config);
    
    // First gather
    ice.gather_candidates();
    for (int i = 0; i < 50 && !ice.is_gathering_complete(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    EXPECT_TRUE(ice.is_gathering_complete());
    
    // Restart
    ice.restart();
    
    // Should be gathering again
    for (int i = 0; i < 50 && !ice.is_gathering_complete(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    EXPECT_TRUE(ice.is_gathering_complete());
}

// ============================================================================
// Connection State Tests
// ============================================================================

TEST_F(IceTest, ConnectionStateCallback) {
    IceManager ice;
    
    std::vector<IceConnectionState> states;
    ice.set_on_connection_state_changed([&](IceConnectionState state) {
        states.push_back(state);
    });
    
    ice.close();
    
    ASSERT_GE(states.size(), 1u);
    EXPECT_EQ(states.back(), IceConnectionState::Closed);
}

TEST_F(IceTest, IsConnectedStates) {
    IceManager ice;
    
    // New state
    EXPECT_FALSE(ice.is_connected());
    
    // Simulate connected (for testing, we just check the logic)
    // In real usage, connection happens through connectivity checks
}

// ============================================================================
// Socket Tests
// ============================================================================

TEST_F(IceTest, SocketCreationOnGather) {
    IceConfig config;
    config.gather_host_candidates = true;
    config.gather_srflx_candidates = false;
    
    IceManager ice(config);
    
    EXPECT_EQ(ice.get_socket(), INVALID_SOCKET_VALUE);
    EXPECT_EQ(ice.get_local_port(), 0u);
    
    ice.gather_candidates();
    
    // Wait a bit for socket to be created
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    EXPECT_NE(ice.get_socket(), INVALID_SOCKET_VALUE);
    EXPECT_GT(ice.get_local_port(), 0u);
    
    ice.close();
}

// ============================================================================
// Integration Test with Mock STUN Server
// ============================================================================

class MockStunServerForIce {
public:
    MockStunServerForIce() : running_(false) {}
    
    ~MockStunServerForIce() {
        stop();
    }
    
    bool start() {
        socket_ = create_udp_socket(0);
        if (!is_valid_socket(socket_)) {
            return false;
        }
        
        port_ = get_bound_port(socket_);
        running_ = true;
        server_thread_ = std::thread(&MockStunServerForIce::run, this);
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
    
    void set_public_address(const std::string& addr, uint16_t port) {
        public_addr_ = addr;
        public_port_ = port;
    }
    
private:
    void run() {
        while (running_) {
            Peer sender;
            auto data = receive_udp_data(socket_, 1500, sender, 100);
            
            if (data.empty()) continue;
            
            auto request = StunMessage::deserialize(data);
            if (!request || !request->is_request()) continue;
            
            StunMessage response;
            response.type = StunMessageType::BindingSuccessResponse;
            response.transaction_id = request->transaction_id;
            
            // Return sender's address (simulating NAT discovery)
            StunMappedAddress mapped(StunAddressFamily::IPv4, 
                                     public_addr_.empty() ? sender.ip : public_addr_,
                                     public_port_ ? public_port_ : sender.port);
            response.add_xor_mapped_address(mapped);
            
            auto response_data = response.serialize();
            send_udp_data(socket_, response_data, sender.ip, sender.port);
        }
    }
    
    std::atomic<bool> running_;
    socket_t socket_ = INVALID_SOCKET_VALUE;
    int port_ = 0;
    std::thread server_thread_;
    std::string public_addr_;
    uint16_t public_port_ = 0;
};

TEST_F(IceTest, GatherSrflxWithMockServer) {
    MockStunServerForIce server;
    server.set_public_address("203.0.113.5", 45678);
    ASSERT_TRUE(server.start());
    
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    IceConfig config;
    config.gather_host_candidates = true;
    config.gather_srflx_candidates = true;
    config.add_stun_server("127.0.0.1", server.get_port());
    config.gathering_timeout_ms = 2000;
    
    IceManager ice(config);
    
    ice.gather_candidates();
    
    // Wait for gathering
    for (int i = 0; i < 30 && !ice.is_gathering_complete(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    EXPECT_TRUE(ice.is_gathering_complete());
    
    auto candidates = ice.get_local_candidates();
    
    // Should have host candidates and possibly srflx
    bool has_srflx = false;
    for (const auto& c : candidates) {
        if (c.type == IceCandidateType::ServerReflexive) {
            has_srflx = true;
            EXPECT_EQ(c.address, "203.0.113.5");
            EXPECT_EQ(c.port, 45678u);
        }
    }
    
    EXPECT_TRUE(has_srflx);
    
    // Check public address
    auto public_addr = ice.get_public_address();
    ASSERT_TRUE(public_addr.has_value());
    EXPECT_EQ(public_addr->first, "203.0.113.5");
    EXPECT_EQ(public_addr->second, 45678u);
}
