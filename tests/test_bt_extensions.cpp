#include <gtest/gtest.h>

#include "bittorrent/extensions.h"

using namespace librats::bittorrent;
using librats::Bytes;
using librats::ByteView;

TEST(BtExtensions, HandshakeRoundTrip) {
    Bytes hs = ext::encode_handshake(/*metadata_size=*/12345, /*listen_port=*/6881);
    auto pe = ext::decode_handshake(ByteView(hs));
    ASSERT_TRUE(pe.has_value());
    EXPECT_EQ(pe->ut_metadata_id, ext::kUtMetadataLocalId);
    EXPECT_EQ(pe->ut_pex_id, ext::kUtPexLocalId);
    EXPECT_EQ(pe->metadata_size, 12345u);
    EXPECT_EQ(pe->listen_port, 6881u);
}

TEST(BtExtensions, HandshakeOmitsMetadataSizeWhenZero) {
    Bytes hs = ext::encode_handshake(0, 0);
    auto pe = ext::decode_handshake(ByteView(hs));
    ASSERT_TRUE(pe.has_value());
    EXPECT_EQ(pe->metadata_size, 0u);
    EXPECT_EQ(pe->ut_metadata_id, ext::kUtMetadataLocalId);  // still advertise support
}

TEST(BtExtensions, HandshakeRejectsGarbage) {
    Bytes junk{'n', 'o', 't', 'b', 'e', 'n', 'c', 'o', 'd', 'e'};
    EXPECT_FALSE(ext::decode_handshake(ByteView(junk)).has_value());
}

TEST(BtExtensions, MetadataRequestRoundTrip) {
    Bytes m = ext::encode_metadata_request(7);
    auto msg = ext::decode_metadata(ByteView(m));
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->type, ext::MetadataType::Request);
    EXPECT_EQ(msg->piece, 7u);
    EXPECT_TRUE(msg->block.empty());
}

TEST(BtExtensions, MetadataRejectRoundTrip) {
    auto msg = ext::decode_metadata(ByteView(ext::encode_metadata_reject(3)));
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->type, ext::MetadataType::Reject);
    EXPECT_EQ(msg->piece, 3u);
}

TEST(BtExtensions, MetadataDataCarriesBlock) {
    Bytes block{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
    Bytes m = ext::encode_metadata_data(/*piece=*/2, /*total_size=*/100000, ByteView(block));
    auto msg = ext::decode_metadata(ByteView(m));
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->type, ext::MetadataType::Data);
    EXPECT_EQ(msg->piece, 2u);
    EXPECT_EQ(msg->total_size, 100000u);
    EXPECT_EQ(msg->block, block);
}

TEST(BtExtensions, MetadataDataWithEmptyBlock) {
    Bytes m = ext::encode_metadata_data(0, 16384, ByteView(Bytes{}));
    auto msg = ext::decode_metadata(ByteView(m));
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->type, ext::MetadataType::Data);
    EXPECT_TRUE(msg->block.empty());
}

TEST(BtExtensions, DecodeMetadataRejectsGarbage) {
    Bytes junk{'x', 'y', 'z'};
    EXPECT_FALSE(ext::decode_metadata(ByteView(junk)).has_value());
}

TEST(BtExtensions, PexRoundTrip) {
    std::vector<ext::PexPeer> added{{"127.0.0.1", 6881}, {"10.0.0.5", 51413}};
    std::vector<ext::PexPeer> dropped{{"192.168.1.2", 1234}};
    Bytes m = ext::encode_pex(added, dropped);

    auto msg = ext::decode_pex(ByteView(m));
    ASSERT_TRUE(msg.has_value());
    ASSERT_EQ(msg->added.size(), 2u);
    EXPECT_EQ(msg->added[0].ip, "127.0.0.1");
    EXPECT_EQ(msg->added[0].port, 6881u);
    EXPECT_EQ(msg->added[1].ip, "10.0.0.5");
    EXPECT_EQ(msg->added[1].port, 51413u);
    ASSERT_EQ(msg->dropped.size(), 1u);
    EXPECT_EQ(msg->dropped[0].ip, "192.168.1.2");
    EXPECT_EQ(msg->dropped[0].port, 1234u);
}

TEST(BtExtensions, PexEmpty) {
    auto msg = ext::decode_pex(ByteView(ext::encode_pex({}, {})));
    ASSERT_TRUE(msg.has_value());
    EXPECT_TRUE(msg->added.empty());
    EXPECT_TRUE(msg->dropped.empty());
}

TEST(BtExtensions, PexSkipsNonIpv4) {
    std::vector<ext::PexPeer> added{{"not-an-ip", 1}, {"8.8.8.8", 53}};
    auto msg = ext::decode_pex(ByteView(ext::encode_pex(added, {})));
    ASSERT_TRUE(msg.has_value());
    ASSERT_EQ(msg->added.size(), 1u);  // the bogus one was dropped on encode
    EXPECT_EQ(msg->added[0].ip, "8.8.8.8");
}
