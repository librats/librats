#include <gtest/gtest.h>

#include "librats/bittorrent/client.h"
#include "librats/bittorrent/torrent_info.h"
#include "librats/bittorrent/bencode.h"
#include "librats/crypto/sha1.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>

using namespace librats::bittorrent;
using librats::BencodeValue;
using librats::Bytes;

// uTP end to end, between two full Clients over real UDP sockets.
//
// The load-bearing trick throughout is turning a transport *off* rather than
// inspecting which one got used: a leecher with outgoing TCP disabled has exactly
// one way to reach the seeder, so a download that completes is itself the proof
// that it happened over uTP. Nothing here reaches into a connection's internals,
// and nothing can pass by accident — the mirrored negative controls are what make
// the positive results mean something.

namespace {

namespace stdfs = std::filesystem;

Bytes make_data(std::size_t n) {
    Bytes         d(n);
    std::uint32_t x = 0xC0FFEEu;
    for (std::size_t i = 0; i < n; ++i) {
        x    = x * 1103515245u + 12345u;
        d[i] = std::uint8_t(x >> 16);
    }
    return d;
}

std::string piece_hashes_for(const Bytes& data, std::uint32_t plen) {
    std::string       pieces;
    const std::size_t n = (data.size() + plen - 1) / plen;
    for (std::size_t p = 0; p < n; ++p) {
        const std::size_t off = p * plen;
        const std::size_t len = (std::min)(std::size_t(plen), data.size() - off);
        auto              h   = librats::SHA1::hash_raw(data.data() + off, len);
        pieces.append(reinterpret_cast<const char*>(h.data()), 20);
    }
    return pieces;
}

TorrentInfo build_and_seed(const std::string& name, const Bytes& data, std::uint32_t plen,
                           const std::string& seed_dir) {
    stdfs::create_directories(seed_dir);
    std::ofstream out((stdfs::path(seed_dir) / name).string(), std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), std::streamsize(data.size()));
    out.close();

    BencodeValue info    = BencodeValue::create_dict();
    info["name"]         = BencodeValue(name);
    info["length"]       = BencodeValue(std::int64_t(data.size()));
    info["piece length"] = BencodeValue(std::int64_t(plen));
    info["pieces"]       = BencodeValue(piece_hashes_for(data, plen));
    return *TorrentInfo::from_info_dict(info.encode(), InfoHash{});
}

/// Hold the UDP half of a port while leaving its TCP half free — the shape a DHT
/// leaves behind when it is serving the torrent port, which mainline BitTorrent
/// says it should be. Shared, exactly as every other UDP socket in the library
/// asks for it. Returns RATS_INVALID_SOCKET if no such port turned up.
librats::socket_t squat_udp_port(std::uint16_t& port) {
    for (int i = 0; i < 32; ++i) {
        // Find a free number, then take it *by number* — which is what makes the
        // squatter a faithful stand-in. A port asked for by number is bound with
        // SO_REUSEADDR, and it is that option on both sides that lets a second
        // socket land on top; an ephemeral bind sets nothing and would refuse the
        // second bind for the wrong reason, quietly making the test prove nothing.
        librats::socket_t probe_udp =
            librats::create_udp_socket(0, "", librats::AddressFamily::IPv4);
        if (!librats::is_valid_socket(probe_udp)) break;
        const int p = librats::get_bound_port(probe_udp);
        librats::close_socket(probe_udp);

        // The client needs the TCP half of this number, or the test would be
        // watching a listener fail rather than a mux move aside.
        librats::socket_t probe_tcp =
            librats::create_tcp_server(p, 4, "", librats::AddressFamily::IPv4);
        if (!librats::is_valid_socket(probe_tcp)) continue;
        librats::close_socket(probe_tcp);

        librats::socket_t udp = librats::create_udp_socket(p, "", librats::AddressFamily::IPv4);
        if (librats::is_valid_socket(udp)) {
            port = std::uint16_t(p);
            return udp;
        }
    }
    return RATS_INVALID_SOCKET;
}

class BtUtpWire : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* ti = ::testing::UnitTest::GetInstance()->current_test_info();
        base_ = (stdfs::path(::testing::TempDir()) / ("librats_utp_" + std::string(ti->name()))).string();
        std::error_code ec;
        stdfs::remove_all(base_, ec);
        stdfs::create_directories(base_, ec);
    }
    void TearDown() override {
        std::error_code ec;
        stdfs::remove_all(base_, ec);
    }

    std::string seed_dir() const { return (stdfs::path(base_) / "seed").string(); }
    std::string dl_dir() const { return (stdfs::path(base_) / "down").string(); }

    Client::Config config(const std::string& dir, const char* prefix) const {
        Client::Config c;
        c.listen_port    = 0;
        c.download_path  = dir;
        c.peer_id_prefix = prefix;
        // Encryption is orthogonal and covered in test_bt_mse_wire.cpp; leaving the
        // default MSE alternation on here would add a second variable to every
        // fallback assertion below.
        c.out_enc_policy = EncPolicy::Disabled;
        c.in_enc_policy  = EncPolicy::Enabled;
        return c;
    }

    bool pump_until(Client& a, Client& b, const std::function<bool()>& done, int iters = 8000) {
        for (int i = 0; i < iters; ++i) {
            if (done()) return true;
            a.reactor().run_one(2);
            b.reactor().run_one(2);
        }
        return done();
    }

    std::string base_;
};

} // namespace

// The headline case: the leecher has no TCP at all, so the only way this file can
// arrive is over uTP.
TEST_F(BtUtpWire, TransfersOverUtpWhenTcpIsUnavailable) {
    const Bytes data = make_data(40000);  // 3 pieces of 16 KiB
    TorrentInfo info = build_and_seed("f.bin", data, 16384, seed_dir());

    Client::Config lc = config(dl_dir(), "-LR0002-");
    lc.enable_outgoing_tcp = false;

    Client seeder(config(seed_dir(), "-LR0001-"));
    Client leecher(lc);
    seeder.open();
    leecher.open();
    ASSERT_GT(seeder.listen_port(), 0);

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    lt->add_peer("127.0.0.1", seeder.listen_port());
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }))
        << "progress=" << lt->progress() << " peers=" << lt->num_peers();

    // Verify the bytes really are the bytes, not just that the state machine
    // declared victory: a reliability bug that duplicated or dropped a range would
    // fail the piece hashes, but this pins the on-disk result too.
    std::ifstream in((stdfs::path(dl_dir()) / "f.bin").string(), std::ios::binary);
    const Bytes   got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(got, data);

    seeder.stop();
    leecher.stop();
}

// The negative control that gives the test above its meaning: with the seeder
// refusing inbound uTP and the leecher unable to speak TCP, nothing may transfer.
// If this passed, the test above would prove nothing about the transport.
TEST_F(BtUtpWire, UtpOnlyDialerCannotReachASeederWithInboundUtpOff) {
    const Bytes data = make_data(40000);
    TorrentInfo info = build_and_seed("f.bin", data, 16384, seed_dir());

    Client::Config sc = config(seed_dir(), "-LR0001-");
    sc.enable_incoming_utp = false;
    Client::Config lc = config(dl_dir(), "-LR0002-");
    lc.enable_outgoing_tcp = false;

    Client seeder(sc);
    Client leecher(lc);
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    lt->add_peer("127.0.0.1", seeder.listen_port());
    EXPECT_FALSE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }, 2000));

    seeder.stop();
    leecher.stop();
}

// The mirror image: TCP alone must keep working exactly as it did before uTP
// existed, for a peer on either side of the switch.
TEST_F(BtUtpWire, TcpStillWorksWithUtpDisabledOnBothSides) {
    const Bytes data = make_data(40000);
    TorrentInfo info = build_and_seed("f.bin", data, 16384, seed_dir());

    Client::Config sc = config(seed_dir(), "-LR0001-");
    sc.enable_outgoing_utp = sc.enable_incoming_utp = false;
    Client::Config lc = config(dl_dir(), "-LR0002-");
    lc.enable_outgoing_utp = lc.enable_incoming_utp = false;

    Client seeder(sc);
    Client leecher(lc);
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    lt->add_peer("127.0.0.1", seeder.listen_port());
    EXPECT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }))
        << "progress=" << lt->progress();

    seeder.stop();
    leecher.stop();
}

// The path a real swarm takes constantly: a peer with no uTP. The default policy
// opens with uTP, gets nothing back, and must fall back to TCP *promptly* — the
// peer earns a backoff waiver precisely so that discovering "no uTP here" costs one
// connect timeout rather than the two-minute reconnect wait it would otherwise.
// It is the time limit that makes this a real test.
TEST_F(BtUtpWire, FallsBackToTcpWithoutServingTheReconnectBackoff) {
    const Bytes data = make_data(40000);
    TorrentInfo info = build_and_seed("f.bin", data, 16384, seed_dir());

    Client::Config sc = config(seed_dir(), "-LR0001-");
    sc.enable_incoming_utp = false;  // TCP only, as far as anyone dialing in can tell

    Client seeder(sc);
    Client leecher(config(dl_dir(), "-LR0002-"));  // defaults: uTP first, then TCP
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    const auto started = std::chrono::steady_clock::now();
    lt->add_peer("127.0.0.1", seeder.listen_port());
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }, 20000))
        << "progress=" << lt->progress() << " peers=" << lt->num_peers();

    // The uTP dial gives up after its own connect timeout (3 s) and the redial rides
    // the torrent's one-second tick, so a handful of seconds is plenty of headroom —
    // and nowhere near a served reconnect backoff.
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "the TCP retry looks like it waited out the reconnect backoff";

    seeder.stop();
    leecher.stop();
}

// Volume is the interesting direction for a reliability layer: enough pieces to
// span thousands of packets, exercise the congestion window past slow start, and
// expose any place where sequence numbers, the reorder buffer or the send queue
// drift apart.
TEST_F(BtUtpWire, LargeTransferOverUtpIsByteExact) {
    const Bytes data = make_data(1200000);  // ~74 pieces, ~1000 uTP packets
    TorrentInfo info = build_and_seed("big.bin", data, 16384, seed_dir());

    Client::Config lc = config(dl_dir(), "-LR0002-");
    lc.enable_outgoing_tcp = false;  // uTP or nothing

    Client seeder(config(seed_dir(), "-LR0001-"));
    Client leecher(lc);
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    lt->add_peer("127.0.0.1", seeder.listen_port());
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }, 60000))
        << "progress=" << lt->progress() << " peers=" << lt->num_peers();

    std::ifstream in((stdfs::path(dl_dir()) / "big.bin").string(), std::ios::binary);
    const Bytes   got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(got.size(), data.size());
    EXPECT_EQ(got, data);

    seeder.stop();
    leecher.stop();
}

// uTP and MSE are independent layers and must compose: obfuscation sits between the
// BitTorrent protocol and the link, so it should neither know nor care which wire
// carries it. A seeder that refuses plaintext plus a leecher that has no TCP means
// the only route through is an obfuscated stream over uTP.
TEST_F(BtUtpWire, ObfuscationWorksOverUtp) {
    const Bytes data = make_data(40000);
    TorrentInfo info = build_and_seed("f.bin", data, 16384, seed_dir());

    Client::Config sc = config(seed_dir(), "-LR0001-");
    sc.in_enc_policy  = EncPolicy::Forced;   // plaintext dialers are turned away
    Client::Config lc = config(dl_dir(), "-LR0002-");
    lc.out_enc_policy      = EncPolicy::Forced;
    lc.enable_outgoing_tcp = false;

    Client seeder(sc);
    Client leecher(lc);
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    lt->add_peer("127.0.0.1", seeder.listen_port());
    EXPECT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }))
        << "progress=" << lt->progress();

    seeder.stop();
    leecher.stop();
}

// One port, both wires. A peer learns a single number for us from the tracker or the
// DHT, so if the two ever drifted apart, half the swarm would be unable to reach us
// and the failure would look like a firewall rather than a bug.
TEST_F(BtUtpWire, TcpAndUtpShareOneListenPort) {
    Client c(config(dl_dir(), "-LR0003-"));
    c.open();
    const std::uint16_t port = c.listen_port();
    ASSERT_GT(port, 0);

    // Dialing that one port over UDP has to reach us: the seeder in every test above
    // is found this way, and this is the assertion that says why.
    Client::Config oc = config(seed_dir(), "-LR0004-");
    oc.enable_outgoing_tcp = false;
    Client other(oc);
    other.open();

    const Bytes data = make_data(20000);
    TorrentInfo info = build_and_seed("f.bin", data, 16384, seed_dir());
    Torrent* st = other.add_torrent(info, seed_dir());
    Torrent* lt = c.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(other, c, [&] { return st->state() == Torrent::State::Seeding; }));

    st->add_peer("127.0.0.1", port);
    EXPECT_TRUE(pump_until(other, c, [&] { return lt->is_complete(); }))
        << "a peer dialing the advertised port over UDP never got through";

    c.stop();
    other.stop();
}

// The port the mux wants is the torrent port, and the DHT is very often already on
// its UDP half — mainline puts them on one number. Binding over it succeeds on
// every platform if you ask to share, and then the kernel splits the arriving
// datagrams between the two sockets: uTP dials time out because their answers went
// to the DHT, and DHT queries go unanswered because their replies came here. The
// mux must decline that port and take one that is really its own.
TEST_F(BtUtpWire, TheUtpMuxMovesAsideWhenTheTorrentPortsUdpHalfIsTaken) {
    std::uint16_t     port = 0;
    librats::socket_t dht_like = squat_udp_port(port);
    ASSERT_TRUE(librats::is_valid_socket(dht_like)) << "could not stage a contested port";

    Client::Config lc      = config(dl_dir(), "-LR0010-");
    lc.listen_port         = port;
    lc.enable_outgoing_tcp = false;  // uTP or nothing, so completing proves it works
    Client leecher(lc);
    leecher.open();

    // TCP keeps the number peers are told about; only the mux moves.
    EXPECT_EQ(leecher.listen_port(), port);
    ASSERT_GT(leecher.utp_port(), 0) << "the mux gave up its transport instead of moving";
    EXPECT_NE(leecher.utp_port(), port);

    // And it is still a working transport. An outgoing dial is answered on the
    // source port of its own SYN, so what number the mux ended up on is the peer's
    // problem to discover, not ours to advertise.
    const Bytes data = make_data(40000);
    TorrentInfo info = build_and_seed("f.bin", data, 16384, seed_dir());
    Client      seeder(config(seed_dir(), "-LR0011-"));
    seeder.open();
    ASSERT_GT(seeder.listen_port(), 0);

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    lt->add_peer("127.0.0.1", seeder.listen_port());
    EXPECT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }))
        << "uTP stopped working once it was not on the advertised port; progress="
        << lt->progress();

    seeder.stop();
    leecher.stop();
    librats::close_socket(dht_like);
}

// The other side of the same bug, and the one that was doing the real damage: the
// socket that already held the port must keep every datagram sent to it. When the
// mux shared the port instead, roughly two thirds of the DHT's replies were handed
// to the mux, which does not know a KRPC message from a hole in the ground and drops
// it — a DHT that looks like it is on a lossy link, with nothing logged anywhere.
TEST_F(BtUtpWire, OpeningAClientDoesNotStealDatagramsFromThePortsOwner) {
    std::uint16_t     port     = 0;
    librats::socket_t incumbent = squat_udp_port(port);
    ASSERT_TRUE(librats::is_valid_socket(incumbent)) << "could not stage a contested port";
    librats::set_socket_nonblocking(incumbent);

    Client::Config lc = config(dl_dir(), "-LR0012-");
    lc.listen_port    = port;
    Client leecher(lc);
    leecher.open();
    // Not an ASSERT: the datagram count below is the measurement this test exists
    // for, and it is worth seeing even when the mux has landed where it should not.
    EXPECT_NE(leecher.utp_port(), port);

    // Send from a third socket so nothing about the delivery depends on which of
    // the two ends opened first.
    librats::socket_t sender = librats::create_udp_socket(0, "", librats::AddressFamily::IPv4);
    ASSERT_TRUE(librats::is_valid_socket(sender));
    const librats::Address dest("127.0.0.1", port);

    constexpr int kDatagrams = 32;
    for (int i = 0; i < kDatagrams; ++i) {
        const std::uint8_t body[4] = {'d', 'h', 't', std::uint8_t(i)};
        ASSERT_GT(librats::send_udp_to(sender, body, sizeof(body), dest,
                                       librats::AddressFamily::IPv4), 0);
    }

    int received = 0;
    for (int spin = 0; spin < 400 && received < kDatagrams; ++spin) {
        std::uint8_t     buf[64];
        librats::Address from;
        const std::ptrdiff_t n = librats::recv_udp_from(incumbent, buf, sizeof(buf), from);
        if (n > 0) { ++received; continue; }
        // Give the loopback a moment; a would-block here is timing, not loss.
        leecher.reactor().run_one(2);
    }
    EXPECT_EQ(received, kDatagrams)
        << "the client's uTP mux is eating datagrams addressed to the port's owner";

    leecher.stop();
    librats::close_socket(sender);
    librats::close_socket(incumbent);
}
