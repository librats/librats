#include <gtest/gtest.h>
#include <algorithm>
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
#include "bencode.h"

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
    BtClientConfig config;
    config.download_path = "/tmp/downloads";
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
