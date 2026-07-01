#include <gtest/gtest.h>

#include "bittorrent/peer_connection.h"
#include "bittorrent/reactor.h"
#include "bittorrent/types.h"
#include "core/socket.h"

#include <functional>

using namespace librats;
using namespace librats::bittorrent;

namespace {

bool make_socket_pair(socket_t& a, socket_t& b) {
    socket_t listener = create_tcp_server(0, 1, "127.0.0.1", AddressFamily::IPv4);
    if (!is_valid_socket(listener)) return false;
    const int port = get_bound_port(listener);
    a = tcp_connect_start("127.0.0.1", port);
    if (!is_valid_socket(a)) { close_socket(listener); return false; }
    b = accept_client(listener);
    close_socket(listener);
    if (!is_valid_socket(b)) { close_socket(a); return false; }
    set_socket_nonblocking(a);
    set_socket_nonblocking(b);
    return true;
}

// Records everything that arrives so tests can assert on it.
struct Recorder : PeerConnection::Observer {
    bool          handshaked = false;
    InfoHash      hs_info{};
    PeerId        hs_peer{};
    bool          got_bitfield = false;
    Bitfield      bitfield;
    bool          got_interest = false, interested = false;
    bool          got_choke = false, choked = true;
    bool          got_have = false;
    int           have_count = 0;
    std::uint32_t have_piece = 0;
    bool          got_request = false;
    std::uint32_t rq_piece = 0, rq_off = 0, rq_len = 0;
    bool          got_piece = false;
    std::uint32_t pc_piece = 0, pc_off = 0;
    Bytes         pc_data;
    bool          got_extended = false;
    std::uint8_t  ext_id = 0;
    Bytes         ext_payload;
    bool          got_port = false;
    std::uint16_t port = 0;
    bool          closed = false;

    void on_handshake(PeerConnection&, const InfoHash& ih, const PeerId& pid) override {
        handshaked = true; hs_info = ih; hs_peer = pid;
    }
    void on_bitfield(PeerConnection&, const Bitfield& bf) override { got_bitfield = true; bitfield = bf; }
    void on_interest(PeerConnection&, bool i) override { got_interest = true; interested = i; }
    void on_choke(PeerConnection&, bool c) override { got_choke = true; choked = c; }
    void on_have(PeerConnection&, std::uint32_t p) override { got_have = true; ++have_count; have_piece = p; }
    void on_request(PeerConnection&, std::uint32_t p, std::uint32_t o, std::uint32_t l) override {
        got_request = true; rq_piece = p; rq_off = o; rq_len = l;
    }
    void on_piece(PeerConnection&, std::uint32_t p, std::uint32_t o, ByteView d) override {
        got_piece = true; pc_piece = p; pc_off = o; pc_data = d.to_bytes();
    }
    void on_extended(PeerConnection&, std::uint8_t id, ByteView p) override {
        got_extended = true; ext_id = id; ext_payload = p.to_bytes();
    }
    void on_port(PeerConnection&, std::uint16_t p) override { got_port = true; port = p; }
    void on_closed(PeerConnection&, const std::string&) override { closed = true; }
};

class BtPeerConnection : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(make_socket_pair(sa_, sb_));
        for (std::size_t i = 0; i < 20; ++i) info_[i] = std::uint8_t(i + 1);
        pa_ = generate_peer_id("-LR0001-");
        pb_ = generate_peer_id("-LR0002-");
        a_ = std::make_unique<PeerConnection>(r_, sa_, /*outgoing=*/true,  info_, pa_, num_pieces_, &obs_a_);
        b_ = std::make_unique<PeerConnection>(r_, sb_, /*outgoing=*/false, info_, pb_, num_pieces_, &obs_b_);
        a_->start();
        b_->start();
    }
    void TearDown() override { a_.reset(); b_.reset(); }

    void pump(std::function<bool()> done) {
        for (int i = 0; i < 4000 && !done(); ++i) r_.run_one(2);
    }

    Reactor       r_;
    socket_t      sa_ = INVALID_SOCKET_VALUE, sb_ = INVALID_SOCKET_VALUE;
    InfoHash      info_{};
    PeerId        pa_{}, pb_{};
    std::uint32_t num_pieces_ = 4;
    Recorder      obs_a_, obs_b_;
    std::unique_ptr<PeerConnection> a_, b_;
};

} // namespace

TEST_F(BtPeerConnection, HandshakeExchangesIdentities) {
    pump([&] { return a_->handshake_done() && b_->handshake_done(); });
    ASSERT_TRUE(a_->handshake_done());
    ASSERT_TRUE(b_->handshake_done());

    EXPECT_TRUE(obs_a_.handshaked);
    EXPECT_TRUE(obs_b_.handshaked);
    EXPECT_EQ(obs_a_.hs_info, info_);
    EXPECT_EQ(obs_a_.hs_peer, pb_);   // A learned B's peer id
    EXPECT_EQ(obs_b_.hs_peer, pa_);   // B learned A's peer id
}

TEST_F(BtPeerConnection, BitfieldAndInterest) {
    pump([&] { return a_->handshake_done() && b_->handshake_done(); });

    Bitfield bf(num_pieces_, false);
    bf.set(0);
    bf.set(2);
    a_->send_bitfield(bf);
    b_->send_interested();

    pump([&] { return obs_b_.got_bitfield && a_->peer_interested(); });
    EXPECT_TRUE(obs_b_.got_bitfield);
    EXPECT_EQ(obs_b_.bitfield, bf);
    EXPECT_TRUE(a_->peer_interested());
    EXPECT_TRUE(obs_a_.got_interest);
    EXPECT_TRUE(obs_a_.interested);
}

TEST_F(BtPeerConnection, ChokeUnchoke) {
    pump([&] { return a_->handshake_done() && b_->handshake_done(); });

    a_->send_unchoke();
    pump([&] { return obs_b_.got_choke; });
    EXPECT_FALSE(b_->peer_choking());
    EXPECT_FALSE(obs_b_.choked);
}

TEST_F(BtPeerConnection, HaveUpdatesPeerBitfield) {
    pump([&] { return a_->handshake_done() && b_->handshake_done(); });

    a_->send_have(3);
    pump([&] { return obs_b_.got_have; });
    EXPECT_EQ(obs_b_.have_piece, 3u);
    EXPECT_TRUE(b_->peer_bitfield().get(3));
}

// A redundant HAVE (a piece the peer already advertised) must not re-fire on_have,
// or the picker would count the peer's availability for that piece twice.
TEST_F(BtPeerConnection, RedundantHaveDoesNotRefire) {
    pump([&] { return a_->handshake_done() && b_->handshake_done(); });

    a_->send_have(2);
    pump([&] { return obs_b_.have_count == 1; });
    ASSERT_EQ(obs_b_.have_count, 1);
    EXPECT_TRUE(b_->peer_bitfield().get(2));

    // Send the same piece again (redundant → must be ignored) followed by a new
    // piece (must fire). The wire is ordered, so once piece 3 arrives we know the
    // redundant piece-2 HAVE has already been processed — and dropped.
    a_->send_have(2);   // redundant
    a_->send_have(3);   // new
    pump([&] { return obs_b_.have_piece == 3; });
    EXPECT_EQ(obs_b_.have_count, 2);   // the two distinct HAVEs, not three
    EXPECT_TRUE(b_->peer_bitfield().get(3));
}

TEST_F(BtPeerConnection, RequestThenPiece) {
    pump([&] { return a_->handshake_done() && b_->handshake_done(); });

    // B requests a block from A.
    b_->send_request(1, 0, 16384);
    pump([&] { return obs_a_.got_request; });
    EXPECT_EQ(obs_a_.rq_piece, 1u);
    EXPECT_EQ(obs_a_.rq_off, 0u);
    EXPECT_EQ(obs_a_.rq_len, 16384u);

    // A serves the block.
    Bytes block(16384);
    for (std::size_t i = 0; i < block.size(); ++i) block[i] = std::uint8_t(i * 7 + 1);
    a_->send_piece(1, 0, ByteView(block));

    pump([&] { return obs_b_.got_piece; });
    EXPECT_EQ(obs_b_.pc_piece, 1u);
    EXPECT_EQ(obs_b_.pc_off, 0u);
    EXPECT_EQ(obs_b_.pc_data, block);
}

TEST_F(BtPeerConnection, ExtendedAndPort) {
    pump([&] { return a_->handshake_done() && b_->handshake_done(); });

    Bytes payload{0x64, 0x65, 0x65};  // "dee" — opaque to this layer
    a_->send_extended(1, ByteView(payload));
    a_->send_port(6881);

    pump([&] { return obs_b_.got_extended && obs_b_.got_port; });
    EXPECT_EQ(obs_b_.ext_id, 1);
    EXPECT_EQ(obs_b_.ext_payload, payload);
    EXPECT_EQ(obs_b_.port, 6881);
}

// Standalone (own sockets): a peer whose info-hash differs rejects the handshake.
TEST(BtPeerConnectionStandalone, MismatchedInfoHashCloses) {
    socket_t sa, sb;
    ASSERT_TRUE(make_socket_pair(sa, sb));

    Reactor r;
    InfoHash mine{};  mine[0]  = 0x01;
    InfoHash other{}; other[0] = 0xFF;
    PeerId pa = generate_peer_id("-LR0001-");
    PeerId pb = generate_peer_id("-LR0002-");
    Recorder oa, ob;

    PeerConnection a(r, sa, /*outgoing=*/true,  mine,  pa, 4, &oa);
    PeerConnection b(r, sb, /*outgoing=*/false, other, pb, 4, &ob);
    a.start();
    b.start();

    for (int i = 0; i < 2000 && !b.closed(); ++i) r.run_one(2);
    EXPECT_TRUE(b.closed());
}
