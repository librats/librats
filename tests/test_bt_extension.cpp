#include <gtest/gtest.h>
#include <algorithm>
#include "bt_extension.h"
#include "bt_peer_connection.h"
#include "bt_choker.h"

using namespace librats;

//=============================================================================
// UtMetadataExtension Tests
//=============================================================================

TEST(BtUtMetadataTest, Construction) {
    UtMetadataExtension ext;
    
    EXPECT_EQ(ext.name(), "ut_metadata");
    EXPECT_EQ(ext.num_pieces(), 0);
    EXPECT_FALSE(ext.have_metadata());
}

TEST(BtUtMetadataTest, ConstructionWithSize) {
    // 50000 bytes = 4 pieces (16384 each, last is smaller)
    UtMetadataExtension ext(50000);
    
    EXPECT_EQ(ext.num_pieces(), 4);
    EXPECT_FALSE(ext.have_metadata());
}

TEST(BtUtMetadataTest, NumPiecesCalculation) {
    // Exactly one piece
    UtMetadataExtension ext1(16384);
    EXPECT_EQ(ext1.num_pieces(), 1);
    
    // Just over one piece
    UtMetadataExtension ext2(16385);
    EXPECT_EQ(ext2.num_pieces(), 2);
    
    // Large metadata
    UtMetadataExtension ext3(100000);
    EXPECT_EQ(ext3.num_pieces(), 7);  // ceil(100000 / 16384)
}

TEST(BtUtMetadataTest, CreateRequest) {
    UtMetadataExtension ext(50000);
    
    auto request = ext.create_request(0);
    
    // Should be valid bencode
    EXPECT_FALSE(request.empty());
    EXPECT_EQ(request[0], 'd');  // Start of dict
}

TEST(BtUtMetadataTest, CreateReject) {
    UtMetadataExtension ext(50000);
    
    auto reject = ext.create_reject(2);
    
    EXPECT_FALSE(reject.empty());
}

TEST(BtUtMetadataTest, CreateData) {
    std::vector<uint8_t> our_data(16384, 0xAB);
    UtMetadataExtension ext(16384, &our_data);
    
    auto data_msg = ext.create_data(0, our_data);
    
    EXPECT_FALSE(data_msg.empty());
    // Should contain both bencode dict and raw data
    EXPECT_GT(data_msg.size(), our_data.size());
}

TEST(BtUtMetadataTest, NextPieceToRequest) {
    UtMetadataExtension ext(50000);
    
    // Initially all pieces need requesting
    EXPECT_EQ(ext.next_piece_to_request(), 0);
    
    // After requesting piece 0
    ext.create_request(0);
    EXPECT_EQ(ext.next_piece_to_request(), 1);
}

TEST(BtUtMetadataTest, HandshakeData) {
    std::vector<uint8_t> metadata(30000);
    UtMetadataExtension ext(0, &metadata);
    
    BencodeDict handshake;
    ext.add_handshake_data(handshake);
    
    EXPECT_TRUE(handshake.find("metadata_size") != handshake.end());
    EXPECT_EQ(handshake["metadata_size"].as_integer(), 30000);
}

TEST(BtUtMetadataTest, ProcessHandshake) {
    UtMetadataExtension ext;
    
    BencodeDict handshake;
    handshake["metadata_size"] = BencodeValue(int64_t(25000));
    
    ext.on_handshake(handshake);
    
    EXPECT_EQ(ext.num_pieces(), 2);  // ceil(25000 / 16384)
}

//=============================================================================
// UtPexExtension Tests
//=============================================================================

TEST(BtUtPexTest, Construction) {
    UtPexExtension ext;
    
    EXPECT_EQ(ext.name(), "ut_pex");
}

TEST(BtUtPexTest, CreateMessage) {
    UtPexExtension ext;
    
    std::vector<PexPeer> added = {
        PexPeer("192.168.1.1", 6881),
        PexPeer("10.0.0.5", 51413)
    };
    
    std::vector<PexPeer> dropped = {
        PexPeer("172.16.0.1", 6969)
    };
    
    auto msg = ext.create_message(added, dropped);
    
    EXPECT_FALSE(msg.empty());
    EXPECT_EQ(msg[0], 'd');  // Start of bencode dict
}

TEST(BtUtPexTest, PeersCallback) {
    UtPexExtension ext;
    
    std::vector<PexPeer> received_added;
    std::vector<PexPeer> received_dropped;
    
    ext.set_peers_callback([&](const std::vector<PexPeer>& added,
                               const std::vector<PexPeer>& dropped) {
        received_added = added;
        received_dropped = dropped;
    });
    
    // Create and process a message
    std::vector<PexPeer> added = {PexPeer("1.2.3.4", 6881)};
    auto msg = ext.create_message(added, {});
    
    ext.on_message(0, msg);
    
    ASSERT_EQ(received_added.size(), 1);
    EXPECT_EQ(received_added[0].ip, "1.2.3.4");
    EXPECT_EQ(received_added[0].port, 6881);
}

//=============================================================================
// ExtensionManager Tests
//=============================================================================

TEST(BtExtensionManagerTest, RegisterExtension) {
    ExtensionManager mgr(nullptr);
    
    auto ext = std::make_shared<UtMetadataExtension>();
    mgr.register_extension(ext, 1);
    
    auto retrieved = mgr.get_extension("ut_metadata");
    EXPECT_EQ(retrieved, ext);
}

TEST(BtExtensionManagerTest, CreateHandshake) {
    ExtensionManager mgr(nullptr);
    
    mgr.register_extension(std::make_shared<UtMetadataExtension>(), 1);
    mgr.register_extension(std::make_shared<UtPexExtension>(), 2);
    
    auto handshake = mgr.create_handshake();
    
    EXPECT_FALSE(handshake.empty());
    EXPECT_EQ(handshake[0], 'd');  // Bencode dict
}

TEST(BtExtensionManagerTest, ProcessHandshake) {
    ExtensionManager mgr(nullptr);
    
    auto metadata_ext = std::make_shared<UtMetadataExtension>();
    mgr.register_extension(metadata_ext, 1);
    
    // Create a handshake message from "peer"
    BencodeValue peer_hs = BencodeValue::create_dict();
    BencodeValue m = BencodeValue::create_dict();
    m["ut_metadata"] = BencodeValue(int64_t(5));  // Peer uses ID 5
    peer_hs["m"] = m;
    peer_hs["metadata_size"] = BencodeValue(int64_t(20000));
    
    auto encoded = peer_hs.encode();
    mgr.process_handshake(encoded);
    
    // Extension should now have peer's message ID
    EXPECT_EQ(metadata_ext->peer_msg_id(), 5);
    EXPECT_TRUE(metadata_ext->peer_supports());
    EXPECT_EQ(mgr.metadata_size(), 20000);
}

TEST(BtExtensionManagerTest, HandleMessage) {
    ExtensionManager mgr(nullptr);
    
    auto metadata_ext = std::make_shared<UtMetadataExtension>(20000);
    mgr.register_extension(metadata_ext, 1);
    
    // Create a metadata request message
    auto request = metadata_ext->create_request(0);
    
    // Handle it (with our local ID)
    bool handled = mgr.handle_message(1, request);
    EXPECT_TRUE(handled);
}

//=============================================================================
// Choker Tests
//=============================================================================

TEST(BtChokerTest, DefaultConfig) {
    Choker choker;
    
    EXPECT_EQ(choker.config().max_uploads, 4);
    EXPECT_FALSE(choker.config().seed_mode);
}

TEST(BtChokerTest, CustomConfig) {
    ChokerConfig config;
    config.max_uploads = 8;
    config.seed_mode = true;
    
    Choker choker(config);
    
    EXPECT_EQ(choker.config().max_uploads, 8);
    EXPECT_TRUE(choker.config().seed_mode);
}

TEST(BtChokerTest, RunWithNoPeers) {
    Choker choker;
    
    std::vector<ChokePeerInfo> peers;
    auto result = choker.run(peers);
    
    EXPECT_TRUE(result.to_choke.empty());
    EXPECT_TRUE(result.to_unchoke.empty());
}

TEST(BtChokerTest, UnchokeInterestedPeers) {
    ChokerConfig config;
    config.max_uploads = 2;
    Choker choker(config);
    
    // Create some fake peer info
    std::vector<ChokePeerInfo> peers(3);
    
    peers[0].peer_interested = true;
    peers[0].am_choking = true;
    peers[0].download_rate = 100.0;
    peers[0].connection = reinterpret_cast<BtPeerConnection*>(1);
    
    peers[1].peer_interested = true;
    peers[1].am_choking = true;
    peers[1].download_rate = 200.0;  // Fastest
    peers[1].connection = reinterpret_cast<BtPeerConnection*>(2);
    
    peers[2].peer_interested = true;
    peers[2].am_choking = true;
    peers[2].download_rate = 50.0;
    peers[2].connection = reinterpret_cast<BtPeerConnection*>(3);
    
    auto result = choker.run(peers);
    
    // Should unchoke top 2 by download rate
    EXPECT_EQ(result.to_unchoke.size(), 2);
    
    // peer[1] (200.0) and peer[0] (100.0) should be unchoked
    auto it1 = std::find(result.to_unchoke.begin(), result.to_unchoke.end(),
                         reinterpret_cast<BtPeerConnection*>(2));
    auto it2 = std::find(result.to_unchoke.begin(), result.to_unchoke.end(),
                         reinterpret_cast<BtPeerConnection*>(1));
    
    EXPECT_TRUE(it1 != result.to_unchoke.end());
    EXPECT_TRUE(it2 != result.to_unchoke.end());
}

TEST(BtChokerTest, ChokeLowPerformers) {
    ChokerConfig config;
    config.max_uploads = 1;
    Choker choker(config);
    
    std::vector<ChokePeerInfo> peers(2);
    
    peers[0].peer_interested = true;
    peers[0].am_choking = false;  // Already unchoked
    peers[0].download_rate = 100.0;
    peers[0].connection = reinterpret_cast<BtPeerConnection*>(1);
    
    peers[1].peer_interested = true;
    peers[1].am_choking = false;  // Already unchoked
    peers[1].download_rate = 50.0;  // Slower
    peers[1].connection = reinterpret_cast<BtPeerConnection*>(2);
    
    auto result = choker.run(peers);
    
    // Should choke the slower peer
    EXPECT_EQ(result.to_choke.size(), 1);
    EXPECT_EQ(result.to_choke[0], reinterpret_cast<BtPeerConnection*>(2));
}

TEST(BtChokerTest, ShouldRechoke) {
    ChokerConfig config;
    config.rechoke_interval = std::chrono::seconds(1);
    Choker choker(config);
    
    // Just after creation, should not need rechoke
    // (Actually depends on implementation, let's just test it doesn't crash)
    
    std::vector<ChokePeerInfo> peers;
    choker.run(peers);
    
    // Immediately after run, should not need rechoke
    EXPECT_FALSE(choker.should_rechoke());
}

TEST(BtChokerTest, SeedMode) {
    ChokerConfig config;
    config.max_uploads = 2;
    config.seed_mode = true;
    Choker choker(config);
    
    std::vector<ChokePeerInfo> peers(3);
    
    for (size_t i = 0; i < 3; ++i) {
        peers[i].peer_interested = true;
        peers[i].am_choking = true;
        peers[i].upload_rate = 100.0 * (i + 1);
        peers[i].connection = reinterpret_cast<BtPeerConnection*>(i + 1);
    }
    
    auto result = choker.run(peers);
    
    EXPECT_EQ(result.to_unchoke.size(), 2);
}
