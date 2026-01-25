#include <gtest/gtest.h>
#include "bt_peer_connection.h"
#include <cstring>

using namespace librats;

//=============================================================================
// Helper Functions
//=============================================================================

BtInfoHash make_test_hash() {
    BtInfoHash hash{};
    for (size_t i = 0; i < 20; ++i) {
        hash[i] = static_cast<uint8_t>(i);
    }
    return hash;
}

PeerID make_test_peer_id() {
    return generate_peer_id("-TS0001-");
}

// Helper: simulate receiving data into connection's buffer and processing it
void feed_data(BtPeerConnection& conn, const uint8_t* data, size_t length) {
    auto& buf = conn.recv_buffer();
    buf.ensure_space(length);
    std::memcpy(buf.write_ptr(), data, length);
    buf.received(length);
    conn.process_incoming();
}

void feed_data(BtPeerConnection& conn, const std::vector<uint8_t>& data) {
    feed_data(conn, data.data(), data.size());
}

//=============================================================================
// Construction Tests
//=============================================================================

TEST(BtPeerConnectionTest, Construction) {
    auto hash = make_test_hash();
    auto peer_id = make_test_peer_id();
    
    BtPeerConnection conn(hash, peer_id, 100);
    
    EXPECT_EQ(conn.state(), PeerConnectionState::Disconnected);
    EXPECT_EQ(conn.socket(), -1);
    EXPECT_FALSE(conn.is_connected());
    EXPECT_TRUE(conn.am_choking());
    EXPECT_FALSE(conn.am_interested());
    EXPECT_TRUE(conn.peer_choking());
    EXPECT_FALSE(conn.peer_interested());
}

TEST(BtPeerConnectionTest, SetAddress) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    
    conn.set_address("192.168.1.100", 6881);
    
    EXPECT_EQ(conn.ip(), "192.168.1.100");
    EXPECT_EQ(conn.port(), 6881);
}

TEST(BtPeerConnectionTest, SetSocket) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    
    conn.set_socket(42);
    
    EXPECT_EQ(conn.socket(), 42);
    EXPECT_EQ(conn.state(), PeerConnectionState::Handshaking);
}

//=============================================================================
// State Tests
//=============================================================================

TEST(BtPeerConnectionTest, StateToString) {
    EXPECT_STREQ(peer_state_to_string(PeerConnectionState::Disconnected), "Disconnected");
    EXPECT_STREQ(peer_state_to_string(PeerConnectionState::Connecting), "Connecting");
    EXPECT_STREQ(peer_state_to_string(PeerConnectionState::Handshaking), "Handshaking");
    EXPECT_STREQ(peer_state_to_string(PeerConnectionState::Connected), "Connected");
    EXPECT_STREQ(peer_state_to_string(PeerConnectionState::Closing), "Closing");
}

TEST(BtPeerConnectionTest, StateCallback) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    
    PeerConnectionState last_state = PeerConnectionState::Disconnected;
    conn.set_state_callback([&last_state](BtPeerConnection*, PeerConnectionState state) {
        last_state = state;
    });
    
    conn.set_socket(42);
    EXPECT_EQ(last_state, PeerConnectionState::Handshaking);
}

//=============================================================================
// Handshake Tests
//=============================================================================

TEST(BtPeerConnectionTest, StartHandshake) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    conn.set_socket(42);
    
    conn.start_handshake();
    
    EXPECT_FALSE(conn.send_buffer().empty());
    
    // Get the handshake data
    std::vector<uint8_t> buffer(68);
    size_t len = conn.send_buffer().copy_to(buffer.data(), buffer.size());
    
    EXPECT_EQ(len, 68);  // Handshake is 68 bytes
    
    // Validate it's a valid handshake
    auto hs = BtHandshake::decode(buffer);
    ASSERT_TRUE(hs.has_value());
    EXPECT_EQ(hs->info_hash, make_test_hash());
}

TEST(BtPeerConnectionTest, ReceiveHandshake) {
    auto our_hash = make_test_hash();
    auto our_id = make_test_peer_id();
    
    BtPeerConnection conn(our_hash, our_id, 100);
    conn.set_socket(42);
    
    bool handshake_received = false;
    Handshake received_hs;
    
    conn.set_handshake_callback([&](BtPeerConnection*, const Handshake& hs) {
        handshake_received = true;
        received_hs = hs;
    });
    
    // Create a valid handshake from "peer"
    PeerID peer_id{};
    for (size_t i = 0; i < 20; ++i) peer_id[i] = static_cast<uint8_t>(100 + i);
    
    auto hs_data = BtHandshake::encode_with_extensions(our_hash, peer_id);
    
    // Feed to connection
    feed_data(conn, hs_data);
    
    EXPECT_TRUE(handshake_received);
    EXPECT_EQ(received_hs.peer_id, peer_id);
    EXPECT_EQ(conn.state(), PeerConnectionState::Connected);
    EXPECT_EQ(conn.peer_id(), peer_id);
}

TEST(BtPeerConnectionTest, HandshakeMismatch) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    bool error_received = false;
    conn.set_error_callback([&](BtPeerConnection*, const std::string&) {
        error_received = true;
    });
    
    // Create handshake with different info hash
    BtInfoHash wrong_hash{};
    wrong_hash[0] = 0xFF;  // Different
    
    auto hs_data = BtHandshake::encode(wrong_hash, make_test_peer_id());
    feed_data(conn, hs_data);
    
    EXPECT_TRUE(error_received);
    EXPECT_EQ(conn.state(), PeerConnectionState::Disconnected);
}

//=============================================================================
// Message Tests
//=============================================================================

TEST(BtPeerConnectionTest, SendChoke) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    conn.set_socket(42);
    
    EXPECT_TRUE(conn.am_choking());
    
    conn.send_unchoke();
    EXPECT_FALSE(conn.am_choking());
    
    conn.send_choke();
    EXPECT_TRUE(conn.am_choking());
}

TEST(BtPeerConnectionTest, SendInterested) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    conn.set_socket(42);
    
    EXPECT_FALSE(conn.am_interested());
    
    conn.send_interested();
    EXPECT_TRUE(conn.am_interested());
    
    conn.send_not_interested();
    EXPECT_FALSE(conn.am_interested());
}

TEST(BtPeerConnectionTest, ReceiveMessages) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // First receive handshake to get connected
    auto hs_data = BtHandshake::encode(our_hash, make_test_peer_id());
    feed_data(conn, hs_data);
    ASSERT_EQ(conn.state(), PeerConnectionState::Connected);
    
    std::vector<BtMessage> received_msgs;
    conn.set_message_callback([&](BtPeerConnection*, const BtMessage& msg) {
        received_msgs.push_back(msg);
    });
    
    // Send unchoke message
    auto unchoke = BtMessageEncoder::encode_unchoke();
    feed_data(conn, unchoke);
    
    ASSERT_EQ(received_msgs.size(), 1);
    EXPECT_EQ(received_msgs[0].type, BtMessageType::Unchoke);
    EXPECT_FALSE(conn.peer_choking());
}

TEST(BtPeerConnectionTest, ReceiveHave) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Handshake
    auto hs_data = BtHandshake::encode(our_hash, make_test_peer_id());
    feed_data(conn, hs_data);
    
    EXPECT_FALSE(conn.peer_has_piece(42));
    
    // Receive HAVE message
    auto have = BtMessageEncoder::encode_have(42);
    feed_data(conn, have);
    
    EXPECT_TRUE(conn.peer_has_piece(42));
}

TEST(BtPeerConnectionTest, ReceiveBitfield) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Handshake
    auto hs_data = BtHandshake::encode(our_hash, make_test_peer_id());
    feed_data(conn, hs_data);
    
    // Create and send bitfield
    Bitfield bf(100);
    bf.set_bit(0);
    bf.set_bit(50);
    bf.set_bit(99);
    
    auto bf_msg = BtMessageEncoder::encode_bitfield(bf);
    feed_data(conn, bf_msg);
    
    EXPECT_TRUE(conn.peer_has_piece(0));
    EXPECT_TRUE(conn.peer_has_piece(50));
    EXPECT_TRUE(conn.peer_has_piece(99));
    EXPECT_FALSE(conn.peer_has_piece(1));
}

//=============================================================================
// Request Tracking Tests
//=============================================================================

TEST(BtPeerConnectionTest, PendingRequests) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    conn.set_socket(42);
    
    EXPECT_EQ(conn.pending_requests(), 0);
    
    conn.add_pending_request(RequestMessage(5, 0, 16384));
    conn.add_pending_request(RequestMessage(5, 16384, 16384));
    
    EXPECT_EQ(conn.pending_requests(), 2);
    
    conn.remove_pending_request(RequestMessage(5, 0, 16384));
    EXPECT_EQ(conn.pending_requests(), 1);
    
    conn.clear_pending_requests();
    EXPECT_EQ(conn.pending_requests(), 0);
}

TEST(BtPeerConnectionTest, CanRequest) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Peer is choking us initially
    EXPECT_FALSE(conn.can_request());
    
    // Simulate receiving unchoke
    auto our_hash = make_test_hash();
    auto hs = BtHandshake::encode(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    
    auto unchoke = BtMessageEncoder::encode_unchoke();
    feed_data(conn, unchoke);
    
    EXPECT_TRUE(conn.can_request());
    
    // Fill up request queue
    conn.set_max_pending_requests(2);
    conn.add_pending_request(RequestMessage(0, 0, 16384));
    conn.add_pending_request(RequestMessage(0, 16384, 16384));
    
    EXPECT_FALSE(conn.can_request());
}

//=============================================================================
// Message Queuing Tests
//=============================================================================

TEST(BtPeerConnectionTest, SendQueuesSingleMessage) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    conn.set_socket(42);
    
    EXPECT_TRUE(conn.send_buffer().empty());
    
    conn.send_interested();
    
    // Interested message should be queued
    EXPECT_FALSE(conn.send_buffer().empty());
    EXPECT_EQ(conn.send_buffer().size(), 5);  // 4 bytes length + 1 byte type
}

TEST(BtPeerConnectionTest, SendQueuesMultipleMessages) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Queue several messages
    conn.send_interested();    // 5 bytes
    conn.send_have(10);        // 9 bytes
    conn.send_unchoke();       // 5 bytes
    
    EXPECT_EQ(conn.send_buffer().size(), 19);
}

TEST(BtPeerConnectionTest, HandshakeQueued) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    conn.set_socket(42);
    
    conn.start_handshake();
    
    // Handshake is 68 bytes
    EXPECT_EQ(conn.send_buffer().size(), 68);
}

//=============================================================================
// Statistics Tests
//=============================================================================

TEST(BtPeerConnectionTest, Statistics) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Initial stats
    EXPECT_EQ(conn.stats().bytes_downloaded, 0);
    EXPECT_EQ(conn.stats().bytes_uploaded, 0);
    EXPECT_EQ(conn.stats().messages_sent, 0);
    EXPECT_EQ(conn.stats().messages_received, 0);
    
    // Handshake
    auto hs = BtHandshake::encode(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    
    // Send some messages
    conn.send_interested();
    conn.send_have(10);
    
    EXPECT_EQ(conn.stats().messages_sent, 2);
    
    // Receive messages
    auto interested = BtMessageEncoder::encode_interested();
    feed_data(conn, interested);
    
    EXPECT_EQ(conn.stats().messages_received, 1);
}

TEST(BtPeerConnectionTest, DownloadStats) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Handshake
    auto hs = BtHandshake::encode(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    
    // Receive piece data
    std::vector<uint8_t> data(1000, 0xAB);
    auto piece_msg = BtMessageEncoder::encode_piece(0, 0, data.data(), data.size());
    feed_data(conn, piece_msg);
    
    EXPECT_EQ(conn.stats().bytes_downloaded, 1000);
    EXPECT_EQ(conn.stats().pieces_received, 1);
}

//=============================================================================
// Move Semantics Tests
//=============================================================================

TEST(BtPeerConnectionTest, MoveConstructor) {
    BtPeerConnection conn1(make_test_hash(), make_test_peer_id(), 100);
    conn1.set_socket(42);
    conn1.set_address("1.2.3.4", 6881);
    
    BtPeerConnection conn2(std::move(conn1));
    
    EXPECT_EQ(conn2.socket(), 42);
    EXPECT_EQ(conn2.ip(), "1.2.3.4");
    EXPECT_EQ(conn2.port(), 6881);
    
    // Original should be invalidated
    EXPECT_EQ(conn1.socket(), -1);
    EXPECT_EQ(conn1.state(), PeerConnectionState::Disconnected);
}

TEST(BtPeerConnectionTest, MoveAssignment) {
    BtPeerConnection conn1(make_test_hash(), make_test_peer_id(), 100);
    conn1.set_socket(42);
    
    BtPeerConnection conn2(make_test_hash(), make_test_peer_id(), 50);
    conn2 = std::move(conn1);
    
    EXPECT_EQ(conn2.socket(), 42);
    EXPECT_EQ(conn1.socket(), -1);
}

//=============================================================================
// Close Tests
//=============================================================================

TEST(BtPeerConnectionTest, Close) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Handshake to get connected
    auto hs = BtHandshake::encode(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    EXPECT_EQ(conn.state(), PeerConnectionState::Connected);
    
    conn.close();
    
    EXPECT_EQ(conn.state(), PeerConnectionState::Disconnected);
    EXPECT_EQ(conn.socket(), -1);
    EXPECT_EQ(conn.pending_requests(), 0);
}

//=============================================================================
// Extension Handshake Storage Tests
//=============================================================================

TEST(BtPeerConnectionTest, ExtensionHandshakeInitialState) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    
    // Initial state should indicate no extension handshake received
    EXPECT_FALSE(conn.extension_handshake_received());
    EXPECT_EQ(conn.peer_metadata_size(), 0);
    EXPECT_EQ(conn.peer_ut_metadata_id(), 0);
}

TEST(BtPeerConnectionTest, ExtensionHandshakeParsing) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // First receive BT handshake with extension protocol support
    auto hs = BtHandshake::encode_with_extensions(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    ASSERT_EQ(conn.state(), PeerConnectionState::Connected);
    
    // Create extension handshake (bencode keys must be in lexicographic order!)
    // {"m": {"ut_metadata": 3}, "metadata_size": 12345}
    // In bencode: d1:md11:ut_metadatai3ee13:metadata_sizei12345ee
    std::string ext_hs = "d1:md11:ut_metadatai3ee13:metadata_sizei12345ee";
    std::vector<uint8_t> ext_payload(ext_hs.begin(), ext_hs.end());
    
    // Create extended message with extension_id=0 (handshake)
    auto ext_msg = BtMessageEncoder::encode_extended(0, ext_payload);
    feed_data(conn, ext_msg);
    
    // Verify extension handshake data was parsed and stored
    EXPECT_TRUE(conn.extension_handshake_received());
    EXPECT_EQ(conn.peer_metadata_size(), 12345);
    EXPECT_EQ(conn.peer_ut_metadata_id(), 3);
}

TEST(BtPeerConnectionTest, ExtensionHandshakeWithoutMetadata) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // BT handshake
    auto hs = BtHandshake::encode_with_extensions(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    
    // Extension handshake without metadata_size (peer doesn't have metadata)
    // Just has ut_metadata ID: d1:md11:ut_metadatai2eee
    std::string ext_hs = "d1:md11:ut_metadatai2eee";
    std::vector<uint8_t> ext_payload(ext_hs.begin(), ext_hs.end());
    
    auto ext_msg = BtMessageEncoder::encode_extended(0, ext_payload);
    feed_data(conn, ext_msg);
    
    EXPECT_TRUE(conn.extension_handshake_received());
    EXPECT_EQ(conn.peer_metadata_size(), 0);  // Not provided
    EXPECT_EQ(conn.peer_ut_metadata_id(), 2);
}

TEST(BtPeerConnectionTest, ExtensionHandshakeNoUtMetadata) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // BT handshake
    auto hs = BtHandshake::encode_with_extensions(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    
    // Extension handshake with metadata_size but no ut_metadata
    // {"m": {"ut_pex": 1}, "metadata_size": 5000}
    // In bencode: d1:md6:ut_pexi1ee13:metadata_sizei5000ee
    std::string ext_hs = "d1:md6:ut_pexi1ee13:metadata_sizei5000ee";
    std::vector<uint8_t> ext_payload(ext_hs.begin(), ext_hs.end());
    
    auto ext_msg = BtMessageEncoder::encode_extended(0, ext_payload);
    feed_data(conn, ext_msg);
    
    EXPECT_TRUE(conn.extension_handshake_received());
    EXPECT_EQ(conn.peer_metadata_size(), 5000);
    EXPECT_EQ(conn.peer_ut_metadata_id(), 0);  // Not provided
}

TEST(BtPeerConnectionTest, ExtensionHandshakeMovedConnection) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn1(our_hash, make_test_peer_id(), 100);
    conn1.set_socket(42);
    
    // BT handshake + extension handshake
    auto hs = BtHandshake::encode_with_extensions(our_hash, make_test_peer_id());
    feed_data(conn1, hs);
    
    // {"m": {"ut_metadata": 5}, "metadata_size": 99999}
    // In bencode: d1:md11:ut_metadatai5ee13:metadata_sizei99999ee
    std::string ext_hs = "d1:md11:ut_metadatai5ee13:metadata_sizei99999ee";
    std::vector<uint8_t> ext_payload(ext_hs.begin(), ext_hs.end());
    auto ext_msg = BtMessageEncoder::encode_extended(0, ext_payload);
    feed_data(conn1, ext_msg);
    
    // Move the connection
    BtPeerConnection conn2(std::move(conn1));
    
    // Extension handshake data should be preserved
    EXPECT_TRUE(conn2.extension_handshake_received());
    EXPECT_EQ(conn2.peer_metadata_size(), 99999);
    EXPECT_EQ(conn2.peer_ut_metadata_id(), 5);
}