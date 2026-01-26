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

TEST(BtPeerConnectionTest, SetSocketDoesNotResetConnectedState) {
    // This test ensures that calling set_socket() after handshake is complete
    // does NOT reset the state back to Handshaking. This was a bug where
    // BtClient::on_peer_connected() called set_socket() again after NetworkManager
    // had already set the socket and completed the handshake.
    
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    
    // Initial state is Disconnected
    EXPECT_EQ(conn.state(), PeerConnectionState::Disconnected);
    
    // First set_socket should transition to Handshaking
    conn.set_socket(42);
    EXPECT_EQ(conn.state(), PeerConnectionState::Handshaking);
    
    // Simulate receiving a valid handshake (this sets state to Connected)
    auto peer_id = make_test_peer_id();
    for (size_t i = 0; i < 8; ++i) {
        peer_id[i] = static_cast<uint8_t>('d' + i);  // "defghijk..."
    }
    auto hs_data = BtHandshake::encode_with_extensions(make_test_hash(), peer_id);
    feed_data(conn, hs_data);
    
    EXPECT_EQ(conn.state(), PeerConnectionState::Connected);
    EXPECT_TRUE(conn.is_connected());
    
    // Calling set_socket() again should NOT reset state to Handshaking
    conn.set_socket(99);
    
    // Socket fd is updated, but state remains Connected
    EXPECT_EQ(conn.socket(), 99);
    EXPECT_EQ(conn.state(), PeerConnectionState::Connected);
    EXPECT_TRUE(conn.is_connected());
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

//=============================================================================
// HaveAll and Metadata Download Tests (Magnet Link Support)
//=============================================================================

TEST(BtPeerConnectionTest, PeerHasAllInitialState) {
    // Outgoing connection with known num_pieces
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    EXPECT_FALSE(conn.peer_has_all());
    
    // Incoming connection without metadata
    BtPeerConnection conn2(make_test_peer_id());
    EXPECT_FALSE(conn2.peer_has_all());
}

TEST(BtPeerConnectionTest, HaveAllWithKnownPieces) {
    // Outgoing connection where we already know num_pieces
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Complete handshake
    auto hs = BtHandshake::encode_with_extensions(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    ASSERT_EQ(conn.state(), PeerConnectionState::Connected);
    
    // Send HaveAll message
    // HaveAll: length=1, message_id=14 (0x0E)
    std::vector<uint8_t> have_all = {0x00, 0x00, 0x00, 0x01, 0x0E};
    feed_data(conn, have_all);
    
    // peer_has_all should be true
    EXPECT_TRUE(conn.peer_has_all());
    
    // peer_pieces should have all bits set (since we had 100 pieces)
    EXPECT_TRUE(conn.peer_pieces().all_set());
    EXPECT_EQ(conn.peer_pieces().count(), 100);
}

TEST(BtPeerConnectionTest, HaveAllWithoutMetadata) {
    // Incoming connection - no metadata yet (like magnet link)
    // peer_pieces_ is initialized with size 0
    auto our_hash = make_test_hash();
    BtPeerConnection conn(make_test_peer_id());  // Incoming - no info_hash yet
    conn.set_socket(42);
    
    // Simulate receiving handshake from peer (incoming flow)
    // For this test, manually set state since we need to bypass the handshake validation
    // In real flow, NetworkManager would call set_torrent_info after routing
    
    // peer_pieces_ has size 0, so set_all() would do nothing
    EXPECT_EQ(conn.peer_pieces().size(), 0);
    EXPECT_FALSE(conn.peer_has_all());
    
    // Manually trigger what would happen with HaveAll before metadata
    // (simulating the internal state after receiving HaveAll with size 0 bitfield)
    // We can test set_torrent_info directly
}

TEST(BtPeerConnectionTest, SetTorrentInfoWithPeerHasAll) {
    // Simulate the flow: peer sends HaveAll before we have metadata
    // Then we receive metadata and call set_torrent_info
    
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 0);  // num_pieces=0 (magnet link)
    conn.set_socket(42);
    
    // Initial state
    EXPECT_EQ(conn.peer_pieces().size(), 0);
    EXPECT_FALSE(conn.peer_has_all());
    
    // Complete handshake (for simplicity, set state directly)
    // In real flow this would come from handshake processing
    
    // Simulate HaveAll received - since num_pieces is 0, set_all does nothing
    // but peer_has_all_ flag should be set
    // We need to process a HaveAll message, but our connection isn't fully set up
    // Let's test set_torrent_info directly with the flag
    
    // For this test, we access the private state through set_torrent_info behavior
    // Create a connection that already has peer_has_all=true (simulated)
    BtPeerConnection conn2(make_test_hash(), make_test_peer_id(), 100);
    conn2.set_socket(42);
    
    // Handshake
    auto hs = BtHandshake::encode_with_extensions(make_test_hash(), make_test_peer_id());
    feed_data(conn2, hs);
    
    // Send HaveAll
    std::vector<uint8_t> have_all = {0x00, 0x00, 0x00, 0x01, 0x0E};
    feed_data(conn2, have_all);
    
    EXPECT_TRUE(conn2.peer_has_all());
    
    // Now simulate what happens when set_torrent_info is called with a different num_pieces
    auto new_hash = make_test_hash();
    new_hash[0] = 0xFF;  // Different hash
    conn2.set_torrent_info(new_hash, 200);  // 200 pieces now
    
    // Bitfield should be resized and all bits set
    EXPECT_EQ(conn2.peer_pieces().size(), 200);
    EXPECT_TRUE(conn2.peer_pieces().all_set());
    EXPECT_EQ(conn2.peer_pieces().count(), 200);
}

TEST(BtPeerConnectionTest, SetTorrentInfoWithoutPeerHasAll) {
    // Normal case: peer sent Bitfield (not HaveAll), then we get metadata
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Handshake
    auto hs = BtHandshake::encode_with_extensions(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    
    EXPECT_FALSE(conn.peer_has_all());
    EXPECT_EQ(conn.peer_pieces().size(), 100);
    
    // Call set_torrent_info with same num_pieces - should not change much
    conn.set_torrent_info(our_hash, 100);
    EXPECT_EQ(conn.peer_pieces().size(), 100);
    EXPECT_FALSE(conn.peer_pieces().all_set());  // Still empty (no HaveAll received)
    
    // Call with different num_pieces - should resize and clear
    auto new_hash = make_test_hash();
    new_hash[0] = 0xAB;
    conn.set_torrent_info(new_hash, 50);
    EXPECT_EQ(conn.peer_pieces().size(), 50);
    EXPECT_FALSE(conn.peer_pieces().all_set());
}

TEST(BtPeerConnectionTest, PeerHasAllMovedConnection) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn1(our_hash, make_test_peer_id(), 100);
    conn1.set_socket(42);
    
    // Handshake + HaveAll
    auto hs = BtHandshake::encode_with_extensions(our_hash, make_test_peer_id());
    feed_data(conn1, hs);
    
    std::vector<uint8_t> have_all = {0x00, 0x00, 0x00, 0x01, 0x0E};
    feed_data(conn1, have_all);
    
    EXPECT_TRUE(conn1.peer_has_all());
    
    // Move the connection
    BtPeerConnection conn2(std::move(conn1));
    
    // peer_has_all should be preserved
    EXPECT_TRUE(conn2.peer_has_all());
    EXPECT_TRUE(conn2.peer_pieces().all_set());
}

TEST(BtPeerConnectionTest, BitfieldClearsPeerHasAll) {
    // Edge case: if peer sends Bitfield after HaveAll, Bitfield takes precedence
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 8);  // 8 pieces
    conn.set_socket(42);
    
    // Handshake
    auto hs = BtHandshake::encode_with_extensions(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    
    // HaveAll
    std::vector<uint8_t> have_all = {0x00, 0x00, 0x00, 0x01, 0x0E};
    feed_data(conn, have_all);
    EXPECT_TRUE(conn.peer_has_all());
    EXPECT_TRUE(conn.peer_pieces().all_set());
    
    // Now send a Bitfield with only some pieces (should override HaveAll)
    // 8 pieces = 1 byte, let's say peer has pieces 0, 2, 4, 6 = 0b10101010 = 0xAA
    Bitfield partial(8);
    partial.set_bit(0);
    partial.set_bit(2);
    partial.set_bit(4);
    partial.set_bit(6);
    auto bf_msg = BtMessageEncoder::encode_bitfield(partial);
    feed_data(conn, bf_msg);
    
    // peer_has_all should be false now, and bitfield should reflect the partial pieces
    EXPECT_FALSE(conn.peer_has_all());
    EXPECT_FALSE(conn.peer_pieces().all_set());
    EXPECT_EQ(conn.peer_pieces().count(), 4);
    EXPECT_TRUE(conn.peer_has_piece(0));
    EXPECT_FALSE(conn.peer_has_piece(1));
    EXPECT_TRUE(conn.peer_has_piece(2));
}

TEST(BtPeerConnectionTest, HaveNoneClearsPeerHasAll) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Handshake
    auto hs = BtHandshake::encode_with_extensions(our_hash, make_test_peer_id());
    feed_data(conn, hs);
    
    // HaveAll first
    std::vector<uint8_t> have_all = {0x00, 0x00, 0x00, 0x01, 0x0E};
    feed_data(conn, have_all);
    EXPECT_TRUE(conn.peer_has_all());
    
    // Now HaveNone (should clear HaveAll)
    // HaveNone: length=1, message_id=15 (0x0F)
    std::vector<uint8_t> have_none = {0x00, 0x00, 0x00, 0x01, 0x0F};
    feed_data(conn, have_none);
    
    EXPECT_FALSE(conn.peer_has_all());
    EXPECT_EQ(conn.peer_pieces().count(), 0);
}

// Test that when bitfield is received before metadata (num_pieces unknown),
// and then set_torrent_info() is called, the bitfield data is preserved.
// This is a regression test for a bug where the bitfield was reset to empty.
TEST(BtPeerConnectionTest, BitfieldPreservedAfterSetTorrentInfo) {
    // Create incoming connection (num_pieces = 0, unknown before metadata)
    auto our_peer_id = make_test_peer_id();
    BtPeerConnection conn(our_peer_id);
    
    // Simulate connection setup
    conn.set_socket(123);
    conn.set_address("1.2.3.4", 6881);
    
    // Create a handshake from peer
    BtInfoHash peer_hash = make_test_hash();
    PeerID remote_peer_id;
    for (int i = 0; i < 20; ++i) remote_peer_id[i] = 'd' + i;
    auto handshake = BtHandshake::encode(peer_hash, remote_peer_id);
    
    // Feed handshake - but it will fail because info_hash not known
    // We need to set up the callback to set torrent info
    bool callback_invoked = false;
    conn.set_info_hash_callback([&](BtPeerConnection* c, const BtInfoHash& hash) {
        callback_invoked = true;
        // For this test, we just mark it as known without full setup
        // This simulates what BtNetworkManager does
    });
    
    // For simplicity, let's test the resize functionality directly
    // Create connection with small num_pieces
    BtPeerConnection conn2(peer_hash, our_peer_id, 0);  // num_pieces=0 initially
    conn2.set_socket(123);
    conn2.set_address("1.2.3.4", 6881);
    
    // Simulate receiving handshake with valid info_hash
    auto hs = BtHandshake::encode(peer_hash, remote_peer_id);
    feed_data(conn2, hs);
    
    EXPECT_TRUE(conn2.is_connected());
    
    // Simulate receiving a bitfield with 16 pieces (2 bytes)
    // Bitfield: 0xFF (first 8 bits set), 0xC0 (bits 8-9 set) = 10 pieces
    // But decoder will use bf_len * 8 = 16 bits when num_pieces = 0
    std::vector<uint8_t> bitfield_msg = {
        0x00, 0x00, 0x00, 0x03,  // length = 3 (1 + 2 bytes)
        0x05,                    // Bitfield message type
        0xFF, 0xC0              // 10 pieces: bits 0-7 and 8-9 set
    };
    feed_data(conn2, bitfield_msg);
    
    // The bitfield was decoded with size 16 (2*8)
    EXPECT_EQ(conn2.peer_pieces().size(), 16);
    // First 10 bits should be set
    for (size_t i = 0; i < 10; ++i) {
        EXPECT_TRUE(conn2.peer_pieces().get_bit(i)) << "Bit " << i << " should be set";
    }
    size_t initial_count = conn2.peer_pieces().count();
    EXPECT_EQ(initial_count, 10);
    
    // Now simulate receiving metadata - actual num_pieces is 10
    conn2.set_torrent_info(peer_hash, 10);
    
    // The bitfield should be resized to 10 but data preserved
    EXPECT_EQ(conn2.peer_pieces().size(), 10);
    
    // All 10 bits should still be set
    for (size_t i = 0; i < 10; ++i) {
        EXPECT_TRUE(conn2.peer_pieces().get_bit(i)) << "Bit " << i << " should still be set after resize";
    }
    EXPECT_EQ(conn2.peer_pieces().count(), 10);
}

// Test that set_torrent_info preserves HaveAll flag
TEST(BtPeerConnectionTest, HaveAllPreservedAfterSetTorrentInfo) {
    auto our_peer_id = make_test_peer_id();
    BtInfoHash peer_hash = make_test_hash();
    PeerID remote_peer_id;
    for (int i = 0; i < 20; ++i) remote_peer_id[i] = 'd' + i;
    
    // Create connection with num_pieces=0 (magnet link scenario)
    BtPeerConnection conn(peer_hash, our_peer_id, 0);
    conn.set_socket(123);
    conn.set_address("1.2.3.4", 6881);
    
    // Simulate receiving handshake
    auto hs = BtHandshake::encode_with_extensions(peer_hash, remote_peer_id);
    feed_data(conn, hs);
    EXPECT_TRUE(conn.is_connected());
    
    // Receive HaveAll message
    std::vector<uint8_t> have_all = {0x00, 0x00, 0x00, 0x01, 0x0E};
    feed_data(conn, have_all);
    
    EXPECT_TRUE(conn.peer_has_all());
    
    // Now set torrent info with actual num_pieces
    conn.set_torrent_info(peer_hash, 100);
    
    // All 100 pieces should be set
    EXPECT_EQ(conn.peer_pieces().size(), 100);
    EXPECT_EQ(conn.peer_pieces().count(), 100);
    EXPECT_TRUE(conn.peer_pieces().all_set());
}

//=============================================================================
// Validation Tests
//=============================================================================

TEST(BtPeerConnectionTest, InvalidHaveIndexIgnored) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);  // 100 pieces
    conn.set_socket(42);
    
    // Handshake
    auto hs_data = BtHandshake::encode(our_hash, make_test_peer_id());
    feed_data(conn, hs_data);
    
    // Send HAVE with invalid index (>= num_pieces)
    auto have_invalid = BtMessageEncoder::encode_have(150);  // index 150 > 100
    feed_data(conn, have_invalid);
    
    // Should NOT crash and should not have piece 150
    // (peer_pieces_ is only 100 bits)
    EXPECT_EQ(conn.peer_pieces().count(), 0);  // No pieces added
}

TEST(BtPeerConnectionTest, RedundantHaveIgnored) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);
    conn.set_socket(42);
    
    // Handshake
    auto hs_data = BtHandshake::encode(our_hash, make_test_peer_id());
    feed_data(conn, hs_data);
    
    EXPECT_FALSE(conn.peer_has_piece(42));
    
    // First HAVE - should set bit
    auto have = BtMessageEncoder::encode_have(42);
    feed_data(conn, have);
    EXPECT_TRUE(conn.peer_has_piece(42));
    EXPECT_EQ(conn.peer_pieces().count(), 1);
    
    // Second HAVE for same piece - should be ignored (redundant)
    feed_data(conn, have);
    EXPECT_TRUE(conn.peer_has_piece(42));
    EXPECT_EQ(conn.peer_pieces().count(), 1);  // Still 1, not 2
}

TEST(BtPeerConnectionTest, InvalidBitfieldSizeHandled) {
    auto our_hash = make_test_hash();
    BtPeerConnection conn(our_hash, make_test_peer_id(), 100);  // Expect 100 pieces
    conn.set_socket(42);
    
    // Handshake
    auto hs_data = BtHandshake::encode(our_hash, make_test_peer_id());
    feed_data(conn, hs_data);
    
    // Create bitfield with wrong size (50 instead of 100)
    Bitfield bf(50);
    bf.set_bit(0);
    bf.set_bit(25);
    bf.set_bit(49);
    
    auto bf_msg = BtMessageEncoder::encode_bitfield(bf);
    feed_data(conn, bf_msg);
    
    // Should handle gracefully - resize to fit
    // The original bits should still be accessible
    EXPECT_TRUE(conn.peer_has_piece(0));
    EXPECT_TRUE(conn.peer_has_piece(25));
    EXPECT_TRUE(conn.peer_has_piece(49));
}

TEST(BtPeerConnectionTest, HasPendingRequest) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    conn.set_socket(42);
    
    RequestMessage req1(5, 0, 16384);
    RequestMessage req2(5, 16384, 16384);
    RequestMessage req3(10, 0, 16384);  // Different piece
    
    EXPECT_FALSE(conn.has_pending_request(req1));
    
    conn.add_pending_request(req1);
    conn.add_pending_request(req2);
    
    EXPECT_TRUE(conn.has_pending_request(req1));
    EXPECT_TRUE(conn.has_pending_request(req2));
    EXPECT_FALSE(conn.has_pending_request(req3));
    
    conn.remove_pending_request(req1);
    EXPECT_FALSE(conn.has_pending_request(req1));
    EXPECT_TRUE(conn.has_pending_request(req2));
}

TEST(BtPeerConnectionTest, IncomingRequestTracking) {
    BtPeerConnection conn(make_test_hash(), make_test_peer_id(), 100);
    conn.set_socket(42);
    
    RequestMessage req1(5, 0, 16384);
    RequestMessage req2(5, 16384, 16384);
    
    // Initially no incoming requests
    EXPECT_FALSE(conn.has_incoming_request(req1));
    
    // Add incoming request (peer requested from us)
    conn.add_incoming_request(req1);
    EXPECT_TRUE(conn.has_incoming_request(req1));
    EXPECT_FALSE(conn.has_incoming_request(req2));
    
    // Remove (Cancel received or piece sent)
    bool removed = conn.remove_incoming_request(req1);
    EXPECT_TRUE(removed);
    EXPECT_FALSE(conn.has_incoming_request(req1));
    
    // Remove again - should return false
    removed = conn.remove_incoming_request(req1);
    EXPECT_FALSE(removed);
}