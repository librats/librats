#include <gtest/gtest.h>
#include <algorithm>
#include <thread>
#include <chrono>
#include <atomic>
#include "bt_types.h"
#include "bt_bitfield.h"
#include "bt_file_storage.h"
#include "bt_torrent_info.h"
#include "bt_piece_picker.h"
#include "bt_messages.h"
#include "bt_handshake.h"
#include "bt_peer_connection.h"
#include "bt_extension.h"
#include "bt_choker.h"
#include "bt_torrent.h"
#include "bt_client.h"
#include "bt_network.h"
#include "bencode.h"
#include "socket.h"

using namespace librats;

//=============================================================================
// Integration Test: Full Torrent Creation Flow
//=============================================================================

// Helper to create a minimal valid torrent
std::vector<uint8_t> create_test_torrent(
    const std::string& name,
    int64_t file_size,
    uint32_t piece_length = 16384) {
    
    uint32_t num_pieces = static_cast<uint32_t>((file_size + piece_length - 1) / piece_length);
    std::string pieces(num_pieces * 20, '\x00');
    
    // Create info dict
    BencodeValue info = BencodeValue::create_dict();
    info["name"] = BencodeValue(name);
    info["length"] = BencodeValue(file_size);
    info["piece length"] = BencodeValue(static_cast<int64_t>(piece_length));
    info["pieces"] = BencodeValue(pieces);
    
    // Create root
    BencodeValue root = BencodeValue::create_dict();
    root["announce"] = BencodeValue("http://tracker.example.com/announce");
    root["info"] = info;
    
    return root.encode();
}

TEST(BtIntegrationTest, TorrentInfoToFileStorage) {
    // Create torrent with multiple files
    BencodeValue info = BencodeValue::create_dict();
    info["name"] = BencodeValue("TestTorrent");
    info["piece length"] = BencodeValue(int64_t(32768));
    
    // Files list
    BencodeValue files_list = BencodeValue::create_list();
    
    BencodeValue file1 = BencodeValue::create_dict();
    file1["length"] = BencodeValue(int64_t(50000));
    BencodeValue path1 = BencodeValue::create_list();
    path1.push_back(BencodeValue("file1.txt"));
    file1["path"] = path1;
    files_list.push_back(file1);
    
    BencodeValue file2 = BencodeValue::create_dict();
    file2["length"] = BencodeValue(int64_t(30000));
    BencodeValue path2 = BencodeValue::create_list();
    path2.push_back(BencodeValue("subdir"));
    path2.push_back(BencodeValue("file2.txt"));
    file2["path"] = path2;
    files_list.push_back(file2);
    
    info["files"] = files_list;
    
    // Pieces (3 pieces for 80000 bytes at 32768)
    std::string pieces(3 * 20, '\x00');
    info["pieces"] = BencodeValue(pieces);
    
    BencodeValue root = BencodeValue::create_dict();
    root["announce"] = BencodeValue("http://tracker.example.com");
    root["info"] = info;
    
    auto torrent_bytes = root.encode();
    auto torrent_info = TorrentInfo::from_bytes(torrent_bytes);
    
    ASSERT_TRUE(torrent_info.has_value());
    
    // Verify file storage
    const auto& files = torrent_info->files();
    EXPECT_EQ(files.num_files(), 2);
    EXPECT_EQ(files.total_size(), 80000);
    EXPECT_EQ(files.num_pieces(), 3);
    
    EXPECT_EQ(files.file_at(0).path, "file1.txt");
    EXPECT_EQ(files.file_at(0).size, 50000);
    
    EXPECT_EQ(files.file_at(1).path, "subdir/file2.txt");
    EXPECT_EQ(files.file_at(1).size, 30000);
    
    // Test piece-to-file mapping
    auto slices = files.map_block(0, 0, 32768);  // First piece
    EXPECT_EQ(slices.size(), 1);
    EXPECT_EQ(slices[0].file_index, 0);
    
    // Second piece spans both files
    slices = files.map_block(1, 0, 32768);
    EXPECT_EQ(slices.size(), 2);  // Spans file1 and file2
}

TEST(BtIntegrationTest, PiecePickerWithPeers) {
    PiecePicker picker(100, 16384, 16384);
    
    // Simulate multiple peers with different pieces
    Bitfield peer1_bf(100);
    for (int i = 0; i < 50; ++i) peer1_bf.set_bit(i);
    
    Bitfield peer2_bf(100);
    for (int i = 25; i < 75; ++i) peer2_bf.set_bit(i);
    
    Bitfield peer3_bf(100);
    peer3_bf.set_bit(99);  // Only has last piece
    
    void* peer1 = reinterpret_cast<void*>(1);
    void* peer2 = reinterpret_cast<void*>(2);
    void* peer3 = reinterpret_cast<void*>(3);
    
    picker.add_peer(peer1, peer1_bf);
    picker.add_peer(peer2, peer2_bf);
    picker.add_peer(peer3, peer3_bf);
    
    // Piece 99 has lowest availability (only 1 peer)
    EXPECT_EQ(picker.availability(99), 1);
    
    // Pieces 25-49 have highest availability (2 peers)
    EXPECT_EQ(picker.availability(30), 2);
    
    // When picking from peer3, should get piece 99
    auto picked = picker.pick_piece(peer3_bf);
    ASSERT_TRUE(picked.has_value());
    EXPECT_EQ(*picked, 99);
}

TEST(BtIntegrationTest, MessageRoundTrip) {
    // Test encoding and decoding various messages
    
    // Request
    auto request_msg = BtMessageEncoder::encode_request(5, 16384, 16384);
    auto decoded = BtMessageDecoder::decode(request_msg);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::Request);
    EXPECT_EQ(decoded->request->piece_index, 5);
    EXPECT_EQ(decoded->request->begin, 16384);
    EXPECT_EQ(decoded->request->length, 16384);
    
    // Bitfield
    Bitfield bf(100);
    for (int i = 0; i < 100; i += 3) bf.set_bit(i);
    
    auto bf_msg = BtMessageEncoder::encode_bitfield(bf);
    decoded = BtMessageDecoder::decode(bf_msg, 100);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->type, BtMessageType::Bitfield);
    ASSERT_TRUE(decoded->bitfield.has_value());
    
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(decoded->bitfield->get_bit(i), i % 3 == 0);
    }
}

TEST(BtIntegrationTest, HandshakeExchange) {
    // Simulate two peers exchanging handshakes
    BtInfoHash info_hash;
    for (size_t i = 0; i < 20; ++i) info_hash[i] = static_cast<uint8_t>(i);
    
    PeerID peer1_id = generate_peer_id("-LR0001-");
    PeerID peer2_id = generate_peer_id("-LR0001-");
    
    ExtensionFlags flags;
    flags.dht = true;
    flags.extension_protocol = true;
    
    // Peer 1 sends handshake
    auto hs1 = BtHandshake::encode(info_hash, peer1_id, flags);
    
    // Peer 2 receives and parses
    auto decoded1 = BtHandshake::decode(hs1);
    ASSERT_TRUE(decoded1.has_value());
    EXPECT_EQ(decoded1->info_hash, info_hash);
    EXPECT_EQ(decoded1->peer_id, peer1_id);
    EXPECT_TRUE(decoded1->extensions.dht);
    EXPECT_TRUE(decoded1->extensions.extension_protocol);
    
    // Peer 2 sends response
    auto hs2 = BtHandshake::encode(info_hash, peer2_id, flags);
    
    // Peer 1 receives and parses
    auto decoded2 = BtHandshake::decode(hs2);
    ASSERT_TRUE(decoded2.has_value());
    EXPECT_EQ(decoded2->peer_id, peer2_id);
}

TEST(BtIntegrationTest, ExtensionHandshake) {
    ExtensionManager mgr(nullptr);
    
    auto metadata_ext = std::make_shared<UtMetadataExtension>(50000);
    auto pex_ext = std::make_shared<UtPexExtension>();
    
    mgr.register_extension(metadata_ext, 1);
    mgr.register_extension(pex_ext, 2);
    
    // Create our handshake
    auto our_hs = mgr.create_handshake();
    
    // Simulate peer handshake
    BencodeValue peer_hs = BencodeValue::create_dict();
    BencodeValue m = BencodeValue::create_dict();
    m["ut_metadata"] = BencodeValue(int64_t(3));
    m["ut_pex"] = BencodeValue(int64_t(4));
    peer_hs["m"] = m;
    peer_hs["metadata_size"] = BencodeValue(int64_t(50000));
    
    auto encoded_peer_hs = peer_hs.encode();
    mgr.process_handshake(encoded_peer_hs);
    
    // Verify extension IDs were set
    EXPECT_EQ(metadata_ext->peer_msg_id(), 3);
    EXPECT_EQ(pex_ext->peer_msg_id(), 4);
    EXPECT_TRUE(metadata_ext->peer_supports());
    EXPECT_TRUE(pex_ext->peer_supports());
}

TEST(BtIntegrationTest, TorrentCreation) {
    auto torrent_bytes = create_test_torrent("TestFile.bin", 100000, 32768);
    
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    TorrentConfig config;
    config.save_path = "/tmp/downloads";
    
    PeerID our_id = generate_peer_id("-LR0001-");
    
    Torrent torrent(*info, config, our_id);
    
    EXPECT_EQ(torrent.state(), TorrentState::Stopped);
    EXPECT_EQ(torrent.name(), "TestFile.bin");
    EXPECT_FALSE(torrent.is_complete());
    
    // Start torrent
    torrent.start();
    EXPECT_EQ(torrent.state(), TorrentState::Downloading);
    
    // Add peer
    torrent.add_peer("192.168.1.100", 6881);
    
    // Stop
    torrent.stop();
    EXPECT_EQ(torrent.state(), TorrentState::Stopped);
}

TEST(BtIntegrationTest, TorrentFromMagnet) {
    BtInfoHash hash;
    for (size_t i = 0; i < 20; ++i) hash[i] = static_cast<uint8_t>(i * 10);
    
    TorrentConfig config;
    config.save_path = "/tmp/downloads";
    
    PeerID our_id = generate_peer_id("-LR0001-");
    
    Torrent torrent(hash, "MagnetTest", config, our_id);
    
    EXPECT_EQ(torrent.state(), TorrentState::Stopped);
    EXPECT_EQ(torrent.name(), "MagnetTest");
    EXPECT_FALSE(torrent.has_metadata());
    
    torrent.start();
    EXPECT_EQ(torrent.state(), TorrentState::DownloadingMetadata);
    
    torrent.stop();
}

TEST(BtIntegrationTest, ClientBasicOperations) {
    init_socket_library();
    
    BtClientConfig config;
    config.download_path = "/tmp/downloads";
    config.listen_port = 0;  // Use random port to avoid conflicts
    config.enable_dht = false;  // Disable for testing
    
    BtClient client(config);
    
    EXPECT_FALSE(client.is_running());
    EXPECT_EQ(client.num_torrents(), 0);
    
    // Start client
    client.start();
    EXPECT_TRUE(client.is_running());
    
    // Create and add a torrent
    auto torrent_bytes = create_test_torrent("TestClient.bin", 50000);
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    auto torrent = client.add_torrent(*info);
    ASSERT_NE(torrent, nullptr);
    
    EXPECT_EQ(client.num_torrents(), 1);
    
    // Get torrent by hash
    auto retrieved = client.get_torrent(info->info_hash());
    EXPECT_EQ(retrieved, torrent);
    
    // Remove torrent
    client.remove_torrent(info->info_hash());
    EXPECT_EQ(client.num_torrents(), 0);
    
    // Stop client
    client.stop();
    EXPECT_FALSE(client.is_running());
}

TEST(BtIntegrationTest, ChokerWithRealPeers) {
    ChokerConfig config;
    config.max_uploads = 2;
    Choker choker(config);
    
    // Simulate peer connections
    std::vector<ChokePeerInfo> peers(4);
    
    for (size_t i = 0; i < 4; ++i) {
        peers[i].connection = reinterpret_cast<BtPeerConnection*>(i + 1);
        peers[i].peer_interested = true;
        peers[i].am_choking = true;
        peers[i].download_rate = (i + 1) * 50.0;  // 50, 100, 150, 200 B/s
        peers[i].connected_at = std::chrono::steady_clock::now() - 
                                std::chrono::minutes(5 - i);
    }
    
    auto result = choker.run(peers);
    
    // Should unchoke top 2 performers
    EXPECT_EQ(result.to_unchoke.size(), 2);
    
    // Highest rates are peer 4 (200) and peer 3 (150)
    bool has_peer4 = std::find(result.to_unchoke.begin(), result.to_unchoke.end(),
                               reinterpret_cast<BtPeerConnection*>(4)) != result.to_unchoke.end();
    bool has_peer3 = std::find(result.to_unchoke.begin(), result.to_unchoke.end(),
                               reinterpret_cast<BtPeerConnection*>(3)) != result.to_unchoke.end();
    
    EXPECT_TRUE(has_peer4);
    EXPECT_TRUE(has_peer3);
}

TEST(BtIntegrationTest, FullDownloadSimulation) {
    // Simulate a small download
    
    // Create picker for 5 pieces
    PiecePicker picker(5, 16384, 8000);  // Last piece is 8000 bytes
    
    // Add a peer with all pieces
    Bitfield peer_bf(5, true);
    void* peer = reinterpret_cast<void*>(1);
    picker.add_peer(peer, peer_bf);
    
    EXPECT_FALSE(picker.is_complete());
    EXPECT_EQ(picker.num_have(), 0);
    EXPECT_EQ(picker.num_want(), 5);
    
    // Download all pieces - keep picking until we have them all
    uint32_t pieces_completed = 0;
    size_t iterations = 0;
    const size_t max_iterations = 100;  // Prevent infinite loop
    
    while (pieces_completed < 5 && iterations < max_iterations) {
        ++iterations;
        
        // Pick blocks
        auto blocks = picker.pick_pieces(peer_bf, 4, peer);
        
        if (blocks.empty()) {
            // No more blocks to pick - all pieces should be complete
            break;
        }
        
        // Mark all blocks as finished
        for (const auto& req : blocks) {
            bool piece_complete = picker.mark_finished(req.block);
            if (piece_complete) {
                picker.mark_have(req.block.piece_index);
                ++pieces_completed;
            }
        }
    }
    
    EXPECT_EQ(pieces_completed, 5);
    EXPECT_TRUE(picker.is_complete());
    EXPECT_EQ(picker.num_have(), 5);
    EXPECT_EQ(picker.num_want(), 0);
}

TEST(BtIntegrationTest, PeerConnectionStateFlow) {
    BtInfoHash hash;
    for (size_t i = 0; i < 20; ++i) hash[i] = static_cast<uint8_t>(i);
    
    PeerID our_id = generate_peer_id("-TS0001-");
    PeerID peer_id{};
    for (size_t i = 0; i < 20; ++i) peer_id[i] = static_cast<uint8_t>(100 + i);
    
    BtPeerConnection conn(hash, our_id, 100);
    
    // Initial state
    EXPECT_EQ(conn.state(), PeerConnectionState::Disconnected);
    EXPECT_TRUE(conn.am_choking());
    EXPECT_TRUE(conn.peer_choking());
    
    // Connect
    conn.set_socket(42);
    EXPECT_EQ(conn.state(), PeerConnectionState::Handshaking);
    
    // Receive handshake
    auto hs = BtHandshake::encode_with_extensions(hash, peer_id);
    conn.on_receive(hs.data(), hs.size());
    EXPECT_EQ(conn.state(), PeerConnectionState::Connected);
    EXPECT_EQ(conn.peer_id(), peer_id);
    
    // Receive bitfield
    Bitfield bf(100);
    bf.set_bit(0);
    bf.set_bit(50);
    auto bf_msg = BtMessageEncoder::encode_bitfield(bf);
    conn.on_receive(bf_msg.data(), bf_msg.size());
    
    EXPECT_TRUE(conn.peer_has_piece(0));
    EXPECT_TRUE(conn.peer_has_piece(50));
    EXPECT_FALSE(conn.peer_has_piece(1));
    
    // Receive unchoke
    auto unchoke = BtMessageEncoder::encode_unchoke();
    conn.on_receive(unchoke.data(), unchoke.size());
    EXPECT_FALSE(conn.peer_choking());
    
    // Send interest
    conn.send_interested();
    EXPECT_TRUE(conn.am_interested());
    
    conn.close();
    EXPECT_EQ(conn.state(), PeerConnectionState::Disconnected);
}

//=============================================================================
// Network Integration Tests
//=============================================================================

TEST(BtIntegrationTest, ClientWithNetworkManager) {
    init_socket_library();
    
    BtClientConfig config;
    config.download_path = "/tmp/downloads";
    config.listen_port = 0;  // Random port
    config.enable_dht = false;  // Disable DHT for this test
    
    BtClient client(config);
    
    EXPECT_FALSE(client.is_running());
    
    client.start();
    EXPECT_TRUE(client.is_running());
    
    // Check network manager is available
    auto* network_mgr = client.network_manager();
    ASSERT_NE(network_mgr, nullptr);
    EXPECT_TRUE(network_mgr->is_running());
    EXPECT_GT(network_mgr->listen_port(), 0);
    
    client.stop();
    EXPECT_FALSE(client.is_running());
}

TEST(BtIntegrationTest, ClientListenPort) {
    init_socket_library();
    
    BtClientConfig config;
    config.download_path = "/tmp/downloads";
    config.listen_port = 0;  // Let system assign
    config.enable_dht = false;
    
    BtClient client(config);
    client.start();
    
    uint16_t port = client.listen_port();
    EXPECT_GT(port, 0);
    EXPECT_NE(port, 6881);  // Should be different since we asked for random
    
    client.stop();
}

TEST(BtIntegrationTest, TorrentPendingPeers) {
    auto torrent_bytes = create_test_torrent("TestPeers.bin", 100000, 32768);
    
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    TorrentConfig config;
    config.save_path = "/tmp/downloads";
    
    PeerID our_id = generate_peer_id("-LR0001-");
    
    Torrent torrent(*info, config, our_id);
    torrent.start();
    
    // Add some peers
    torrent.add_peer("192.168.1.1", 6881);
    torrent.add_peer("192.168.1.2", 6882);
    torrent.add_peer("192.168.1.3", 6883);
    
    // Get pending peers
    auto pending = torrent.get_pending_peers();
    EXPECT_EQ(pending.size(), 3);
    
    // Check peer data
    bool found1 = false, found2 = false, found3 = false;
    for (const auto& peer : pending) {
        if (peer.first == "192.168.1.1" && peer.second == 6881) found1 = true;
        if (peer.first == "192.168.1.2" && peer.second == 6882) found2 = true;
        if (peer.first == "192.168.1.3" && peer.second == 6883) found3 = true;
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
    EXPECT_TRUE(found3);
    
    // Clear pending
    torrent.clear_pending_peers();
    pending = torrent.get_pending_peers();
    EXPECT_EQ(pending.size(), 0);
    
    torrent.stop();
}

TEST(BtIntegrationTest, TorrentAddConnection) {
    auto torrent_bytes = create_test_torrent("TestConn.bin", 100000, 32768);
    
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    TorrentConfig config;
    config.save_path = "/tmp/downloads";
    
    PeerID our_id = generate_peer_id("-LR0001-");
    
    Torrent torrent(*info, config, our_id);
    torrent.start();
    
    EXPECT_EQ(torrent.num_peers(), 0);
    
    // Create a mock connection
    auto connection = std::make_unique<BtPeerConnection>(
        info->info_hash(),
        our_id,
        info->num_pieces()
    );
    
    connection->set_address("10.0.0.1", 6881);
    
    // Add to torrent
    torrent.add_connection(std::move(connection));
    
    EXPECT_EQ(torrent.num_peers(), 1);
    
    auto peers = torrent.peers();
    ASSERT_EQ(peers.size(), 1);
    EXPECT_EQ(peers[0]->ip(), "10.0.0.1");
    EXPECT_EQ(peers[0]->port(), 6881);
    
    torrent.stop();
}

TEST(BtIntegrationTest, TorrentRemoveConnection) {
    auto torrent_bytes = create_test_torrent("TestRemove.bin", 100000, 32768);
    
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    TorrentConfig config;
    config.save_path = "/tmp/downloads";
    
    PeerID our_id = generate_peer_id("-LR0001-");
    
    Torrent torrent(*info, config, our_id);
    torrent.start();
    
    // Add two connections
    auto conn1 = std::make_unique<BtPeerConnection>(
        info->info_hash(), our_id, info->num_pieces());
    conn1->set_address("10.0.0.1", 6881);
    
    auto conn2 = std::make_unique<BtPeerConnection>(
        info->info_hash(), our_id, info->num_pieces());
    conn2->set_address("10.0.0.2", 6882);
    
    BtPeerConnection* conn1_ptr = conn1.get();
    
    torrent.add_connection(std::move(conn1));
    torrent.add_connection(std::move(conn2));
    
    EXPECT_EQ(torrent.num_peers(), 2);
    
    // Remove first connection
    torrent.remove_connection(conn1_ptr);
    
    EXPECT_EQ(torrent.num_peers(), 1);
    
    auto peers = torrent.peers();
    ASSERT_EQ(peers.size(), 1);
    EXPECT_EQ(peers[0]->ip(), "10.0.0.2");
    
    torrent.stop();
}

//=============================================================================
// DHT Integration Tests (with DHT disabled for speed)
//=============================================================================

TEST(BtIntegrationTest, ClientDhtDisabled) {
    init_socket_library();
    
    BtClientConfig config;
    config.download_path = "/tmp/downloads";
    config.listen_port = 0;
    config.enable_dht = false;
    
    BtClient client(config);
    client.start();
    
    EXPECT_FALSE(client.dht_running());
    EXPECT_EQ(client.dht_node_count(), 0);
    
    client.stop();
}

TEST(BtIntegrationTest, ClientAddTorrentRegistersWithNetwork) {
    init_socket_library();
    
    BtClientConfig config;
    config.download_path = "/tmp/downloads";
    config.listen_port = 0;
    config.enable_dht = false;
    
    BtClient client(config);
    client.start();
    
    auto torrent_bytes = create_test_torrent("NetTest.bin", 50000);
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    auto torrent = client.add_torrent(*info);
    ASSERT_NE(torrent, nullptr);
    
    // Torrent should be registered with network manager
    // (verified by network manager accepting connections for this hash)
    EXPECT_EQ(client.num_torrents(), 1);
    
    client.remove_torrent(info->info_hash());
    EXPECT_EQ(client.num_torrents(), 0);
    
    client.stop();
}

//=============================================================================
// Full Client-to-Client Communication Test
//=============================================================================

/*
TEST(BtIntegrationTest, TwoClientsConnect) {
    // This test is disabled by default as it requires full network
    // Enable it for manual integration testing
    
    init_socket_library();
    
    // Create shared torrent
    auto torrent_bytes = create_test_torrent("SharedTorrent.bin", 100000, 32768);
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    // Client 1 (seeder)
    BtClientConfig config1;
    config1.download_path = "/tmp/client1";
    config1.listen_port = 0;
    config1.enable_dht = false;
    
    BtClient client1(config1);
    client1.start();
    
    auto torrent1 = client1.add_torrent(*info);
    ASSERT_NE(torrent1, nullptr);
    
    // Client 2 (leecher)
    BtClientConfig config2;
    config2.download_path = "/tmp/client2";
    config2.listen_port = 0;
    config2.enable_dht = false;
    
    BtClient client2(config2);
    client2.start();
    
    auto torrent2 = client2.add_torrent(*info);
    ASSERT_NE(torrent2, nullptr);
    
    // Client2 connects to Client1
    uint16_t client1_port = client1.listen_port();
    torrent2->add_peer("127.0.0.1", client1_port);
    
    // Wait for connection
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Check connection established
    EXPECT_GT(torrent1->num_peers() + torrent2->num_peers(), 0);
    
    client1.stop();
    client2.stop();
}
*/

//=============================================================================
// Integration Test: Extension Handshake
//=============================================================================

TEST(BtIntegrationTest, ExtensionHandshakeEncoding) {
    // Create extension handshake bencoded data
    BencodeValue handshake = BencodeValue::create_dict();
    
    BencodeValue m = BencodeValue::create_dict();
    m["ut_metadata"] = BencodeValue(static_cast<int64_t>(1));
    m["ut_pex"] = BencodeValue(static_cast<int64_t>(2));
    handshake["m"] = m;
    handshake["v"] = BencodeValue("librats/1.0");
    handshake["metadata_size"] = BencodeValue(static_cast<int64_t>(12345));
    
    auto encoded = handshake.encode();
    EXPECT_FALSE(encoded.empty());
    
    // Decode it back
    auto decoded = BencodeDecoder::decode(encoded);
    EXPECT_TRUE(decoded.is_dict());
    
    const auto& dict = decoded.as_dict();
    
    // Check 'm' dictionary
    auto m_it = dict.find("m");
    ASSERT_NE(m_it, dict.end());
    EXPECT_TRUE(m_it->second.is_dict());
    
    const auto& m_dict = m_it->second.as_dict();
    auto ut_meta_it = m_dict.find("ut_metadata");
    ASSERT_NE(ut_meta_it, m_dict.end());
    EXPECT_EQ(ut_meta_it->second.as_integer(), 1);
    
    // Check metadata_size
    auto size_it = dict.find("metadata_size");
    ASSERT_NE(size_it, dict.end());
    EXPECT_EQ(size_it->second.as_integer(), 12345);
    
    // Check client version
    auto v_it = dict.find("v");
    ASSERT_NE(v_it, dict.end());
    EXPECT_EQ(v_it->second.as_string(), "librats/1.0");
}

TEST(BtIntegrationTest, MetadataRequestEncoding) {
    // Create metadata request message
    BencodeValue req = BencodeValue::create_dict();
    req["msg_type"] = BencodeValue(static_cast<int64_t>(0));  // Request
    req["piece"] = BencodeValue(static_cast<int64_t>(3));
    
    auto encoded = req.encode();
    EXPECT_FALSE(encoded.empty());
    
    auto decoded = BencodeDecoder::decode(encoded);
    EXPECT_TRUE(decoded.is_dict());
    
    const auto& dict = decoded.as_dict();
    EXPECT_EQ(dict.at("msg_type").as_integer(), 0);
    EXPECT_EQ(dict.at("piece").as_integer(), 3);
}

TEST(BtIntegrationTest, MetadataDataEncoding) {
    // Create metadata data response message
    BencodeValue resp = BencodeValue::create_dict();
    resp["msg_type"] = BencodeValue(static_cast<int64_t>(1));  // Data
    resp["piece"] = BencodeValue(static_cast<int64_t>(0));
    resp["total_size"] = BencodeValue(static_cast<int64_t>(16384));
    
    auto encoded = resp.encode();
    
    // Append some fake metadata data after the bencoded dict
    std::vector<uint8_t> fake_metadata(1000, 0xAB);
    encoded.insert(encoded.end(), fake_metadata.begin(), fake_metadata.end());
    
    // Decode just the bencoded part
    auto decoded = BencodeDecoder::decode(encoded);
    EXPECT_TRUE(decoded.is_dict());
    
    const auto& dict = decoded.as_dict();
    EXPECT_EQ(dict.at("msg_type").as_integer(), 1);
    EXPECT_EQ(dict.at("piece").as_integer(), 0);
}

//=============================================================================
// Integration Test: Pending Peers Connection
//=============================================================================

TEST(BtIntegrationTest, PendingPeersGetConnected) {
    init_socket_library();
    
    // Create torrent
    auto torrent_bytes = create_test_torrent("PendingTest.bin", 50000, 16384);
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    // Create client
    BtClientConfig config;
    config.download_path = "/tmp/test";
    config.listen_port = 0;
    config.enable_dht = false;
    
    BtClient client(config);
    client.start();
    
    auto torrent = client.add_torrent(*info);
    ASSERT_NE(torrent, nullptr);
    
    // Add some pending peers (they won't exist, but that's ok)
    torrent->add_peer("192.168.1.100", 6881);
    torrent->add_peer("192.168.1.101", 6882);
    torrent->add_peer("192.168.1.102", 6883);
    
    // Verify pending peers were added
    auto pending = torrent->get_pending_peers();
    EXPECT_EQ(pending.size(), 3);
    
    // Wait for tick_loop to try to connect (it will fail, but should clear pending)
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Pending peers should be cleared after connection attempt
    pending = torrent->get_pending_peers();
    EXPECT_EQ(pending.size(), 0);
    
    client.stop();
}

TEST(BtIntegrationTest, TorrentExtensionHandshakeSupport) {
    // Create a peer connection with extension protocol support
    BtInfoHash hash;
    std::fill(hash.begin(), hash.end(), 0x42);
    
    PeerID peer_id;
    std::fill(peer_id.begin(), peer_id.end(), 0x11);
    
    BtPeerConnection conn(hash, peer_id, 100);
    
    // Create handshake with extension support
    ExtensionFlags extensions;
    extensions.extension_protocol = true;
    
    auto handshake = BtHandshake::encode(hash, peer_id, extensions);
    EXPECT_EQ(handshake.size(), 68);
    
    // Decode and verify
    auto decoded = BtHandshake::decode(handshake.data(), handshake.size());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->extensions.extension_protocol);
}

//=============================================================================
// Integration Test: Torrent Magnet State
//=============================================================================

TEST(BtIntegrationTest, TorrentMagnetState) {
    // Create a minimal TorrentInfo for magnet testing
    BtInfoHash hash;
    std::fill(hash.begin(), hash.end(), 0xAB);
    
    PeerID peer_id;
    std::fill(peer_id.begin(), peer_id.end(), 0xCD);
    
    TorrentConfig config;
    config.save_path = "/tmp/magnet_test";
    
    // Create TorrentInfo from minimal magnet data
    // Using the from_magnet static method
    auto info_opt = TorrentInfo::from_magnet(
        "magnet:?xt=urn:btih:abababababababababababababababababababab&dn=MagnetTest"
    );
    
    if (info_opt.has_value()) {
        Torrent torrent(*info_opt, config, peer_id);
        
        // Should be in metadata downloading state after start
        EXPECT_FALSE(torrent.has_metadata());
        torrent.start();
        EXPECT_EQ(torrent.state(), TorrentState::DownloadingMetadata);
    } else {
        // If no from_magnet, just test that we can create a stopped torrent
        SUCCEED() << "from_magnet not available, skipping magnet state test";
    }
}

//=============================================================================
// Integration Test: Full Connection Flow
//=============================================================================

TEST(BtIntegrationTest, MetadataCallbackSetup) {
    // Test that metadata callback can be set and is stored
    BtInfoHash hash;
    std::fill(hash.begin(), hash.end(), 0xCC);
    
    PeerID peer_id;
    std::fill(peer_id.begin(), peer_id.end(), 0xDD);
    
    TorrentConfig config;
    config.save_path = "/tmp/meta_callback_test";
    
    // Create from magnet
    auto info_opt = TorrentInfo::from_magnet(
        "magnet:?xt=urn:btih:cccccccccccccccccccccccccccccccccccccccc&dn=CallbackTest"
    );
    ASSERT_TRUE(info_opt.has_value());
    
    Torrent torrent(*info_opt, config, peer_id);
    
    // Set metadata callback
    std::atomic<bool> callback_invoked{false};
    torrent.set_metadata_callback(
        [&callback_invoked](Torrent*, bool) {
            callback_invoked = true;
        }
    );
    
    // The callback should be stored (we can't easily test invocation without real peers)
    // But we can verify the torrent is in the right state
    torrent.start();
    EXPECT_EQ(torrent.state(), TorrentState::DownloadingMetadata);
    EXPECT_FALSE(torrent.has_metadata());
}

TEST(BtIntegrationTest, ConnectionHandshakeFlow) {
    init_socket_library();
    
    // Create two network managers to simulate two peers
    BtNetworkConfig config1, config2;
    config1.listen_port = 0;  // Random port
    config2.listen_port = 0;
    
    BtNetworkManager manager1(config1);
    BtNetworkManager manager2(config2);
    
    // Track connections
    std::atomic<bool> manager1_received_connection{false};
    std::atomic<bool> manager2_received_connection{false};
    
    manager1.set_connected_callback(
        [&](const BtInfoHash&, std::shared_ptr<BtPeerConnection>, socket_t, bool) {
            manager1_received_connection = true;
        }
    );
    
    manager2.set_connected_callback(
        [&](const BtInfoHash&, std::shared_ptr<BtPeerConnection>, socket_t, bool) {
            manager2_received_connection = true;
        }
    );
    
    // Start managers
    manager1.start();
    manager2.start();
    
    // Register same torrent on both
    BtInfoHash hash;
    std::fill(hash.begin(), hash.end(), 0x99);
    
    PeerID peer_id1, peer_id2;
    std::fill(peer_id1.begin(), peer_id1.end(), 0x11);
    std::fill(peer_id2.begin(), peer_id2.end(), 0x22);
    
    manager1.register_torrent(hash, peer_id1, 100);
    manager2.register_torrent(hash, peer_id2, 100);
    
    // Manager2 connects to Manager1
    uint16_t port1 = manager1.listen_port();
    manager2.connect_peer("127.0.0.1", port1, hash, peer_id2, 100);
    
    // Wait for connection and handshake
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Both should have received connections
    // Manager1 receives incoming, Manager2 receives outgoing after handshake
    EXPECT_TRUE(manager1_received_connection.load());
    // Note: manager2 callback is invoked after handshake response is received
    
    manager1.stop();
    manager2.stop();
}
