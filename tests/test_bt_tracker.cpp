#include <gtest/gtest.h>

#include "bittorrent/tracker.h"
#include "bittorrent/byte_io.h"
#include "bittorrent/bencode.h"
#include "bittorrent/client.h"
#include "bittorrent/torrent_info.h"
#include "crypto/sha1.h"
#include "core/socket.h"

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <thread>

using namespace librats;
using namespace librats::bittorrent;

namespace {

namespace stdfs = std::filesystem;

// A minimal in-process UDP tracker (BEP 15): answers connect, then announce with
// a single hard-coded peer. Just enough to drive the client offline.
class FakeUdpTracker {
public:
    FakeUdpTracker(std::string peer_ip, std::uint16_t peer_port)
        : peer_ip_(std::move(peer_ip)), peer_port_(peer_port) {
        sock_ = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
        port_ = std::uint16_t(get_bound_port(sock_));
        thread_ = std::thread([this] { run(); });
    }
    ~FakeUdpTracker() { stop(); }

    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
        if (is_valid_socket(sock_)) { close_socket(sock_); sock_ = INVALID_SOCKET_VALUE; }
    }
    std::uint16_t port() const { return port_; }

private:
    void run() {
        while (running_) {
            Address sender;
            Bytes req = receive_udp_data(sock_, 2048, sender, 100);
            if (req.size() < 16) continue;
            const std::uint32_t action = read_u32_be(req.data() + 8);
            const std::uint32_t tid    = read_u32_be(req.data() + 12);
            if (action == 0) {  // connect
                Bytes resp(16);
                write_u32_be(resp.data(), 0);
                write_u32_be(resp.data() + 4, tid);
                write_u64_be(resp.data() + 8, 0x1122334455667788ull);
                send_udp_data(sock_, resp, sender.ip, sender.port, AddressFamily::IPv4);
            } else if (action == 1) {  // announce
                Bytes resp(26);
                write_u32_be(resp.data(), 1);
                write_u32_be(resp.data() + 4, tid);
                write_u32_be(resp.data() + 8, 1800);  // interval
                write_u32_be(resp.data() + 12, 0);    // leechers
                write_u32_be(resp.data() + 16, 1);    // seeders
                unsigned a, b, c, d;
                std::sscanf(peer_ip_.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
                resp[20] = std::uint8_t(a); resp[21] = std::uint8_t(b);
                resp[22] = std::uint8_t(c); resp[23] = std::uint8_t(d);
                write_u16_be(resp.data() + 24, peer_port_);
                send_udp_data(sock_, resp, sender.ip, sender.port, AddressFamily::IPv4);
            }
        }
    }

    std::string       peer_ip_;
    std::uint16_t     peer_port_;
    socket_t          sock_ = INVALID_SOCKET_VALUE;
    std::uint16_t     port_ = 0;
    std::atomic<bool> running_{true};
    std::thread       thread_;
};

Bytes make_data(std::size_t n) {
    Bytes d(n);
    std::uint32_t x = 0x7AC4Eu;
    for (std::size_t i = 0; i < n; ++i) { x = x * 1103515245u + 12345u; d[i] = std::uint8_t(x >> 16); }
    return d;
}

std::string piece_hashes_for(const Bytes& data, std::uint32_t plen) {
    std::string pieces;
    for (std::size_t off = 0; off < data.size(); off += plen) {
        const std::size_t len = std::min<std::size_t>(plen, data.size() - off);
        auto h = SHA1::hash_raw(data.data() + off, len);
        pieces.append(reinterpret_cast<const char*>(h.data()), 20);
    }
    return pieces;
}

// Returns the raw info-dict bytes for a single-file torrent and writes the file.
Bytes build_info_and_seed(const std::string& name, const Bytes& data, std::uint32_t plen,
                          const std::string& seed_dir) {
    stdfs::create_directories(seed_dir);
    std::ofstream out((stdfs::path(seed_dir) / name).string(), std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), std::streamsize(data.size()));
    out.close();

    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(name);
    info["length"]       = BencodeValue(std::int64_t(data.size()));
    info["piece length"] = BencodeValue(std::int64_t(plen));
    info["pieces"]       = BencodeValue(piece_hashes_for(data, plen));
    return info.encode();
}

Bytes make_torrent(const Bytes& info_bytes, const std::string& announce) {
    Bytes out;
    auto put = [&](const std::string& s) { out.insert(out.end(), s.begin(), s.end()); };
    put("d8:announce");
    put(std::to_string(announce.size()) + ":" + announce);
    put("4:info");
    out.insert(out.end(), info_bytes.begin(), info_bytes.end());
    put("e");
    return out;
}

} // namespace

TEST(BtTracker, BuildHttpAnnounceUrl) {
    TrackerRequest req;
    req.info_hash.fill(0xAB);
    req.peer_id.fill('x');
    req.port = 6881;
    req.left = 1000;
    req.event = TrackerEvent::Started;

    const std::string url = tracker_detail::build_http_announce_url("http://t/announce", req);
    EXPECT_NE(url.find("http://t/announce?"), std::string::npos);
    EXPECT_NE(url.find("info_hash=%ab%ab"), std::string::npos);
    EXPECT_NE(url.find("port=6881"), std::string::npos);
    EXPECT_NE(url.find("left=1000"), std::string::npos);
    EXPECT_NE(url.find("compact=1"), std::string::npos);
    EXPECT_NE(url.find("event=started"), std::string::npos);
}

TEST(BtTracker, ParseHttpResponse) {
    BencodeValue d = BencodeValue::create_dict();
    d["interval"]   = BencodeValue(std::int64_t(1800));
    d["complete"]   = BencodeValue(std::int64_t(5));
    d["incomplete"] = BencodeValue(std::int64_t(3));
    d["peers"]      = BencodeValue(std::string{1, 2, 3, 4, 0, 81});  // 1.2.3.4:81

    auto resp = tracker_detail::parse_http_response(d.encode());
    EXPECT_TRUE(resp.success);
    EXPECT_EQ(resp.interval, 1800u);
    EXPECT_EQ(resp.complete, 5u);
    EXPECT_EQ(resp.incomplete, 3u);
    ASSERT_EQ(resp.peers.size(), 1u);
    EXPECT_EQ(resp.peers[0].ip, "1.2.3.4");
    EXPECT_EQ(resp.peers[0].port, 81u);
}

TEST(BtTracker, ParseHttpFailure) {
    BencodeValue d = BencodeValue::create_dict();
    d["failure reason"] = BencodeValue(std::string("torrent not registered"));
    auto resp = tracker_detail::parse_http_response(d.encode());
    EXPECT_FALSE(resp.success);
    EXPECT_EQ(resp.failure_reason, "torrent not registered");
}

TEST(BtTracker, UdpAnnounceLoopback) {
    FakeUdpTracker fake("1.2.3.4", 6881);

    TrackerRequest req;
    req.info_hash.fill(0x11);
    req.peer_id = generate_peer_id();
    req.port = 12345;
    req.left = 500;
    req.event = TrackerEvent::Started;

    auto resp = announce_to_tracker("udp://127.0.0.1:" + std::to_string(fake.port()) + "/announce",
                                    req, 3000);
    ASSERT_TRUE(resp.success) << resp.failure_reason;
    EXPECT_EQ(resp.complete, 1u);
    ASSERT_EQ(resp.peers.size(), 1u);
    EXPECT_EQ(resp.peers[0].ip, "1.2.3.4");
    EXPECT_EQ(resp.peers[0].port, 6881u);
}

// End-to-end: the leecher is given *only* a tracker URL; it discovers the seeder
// through the tracker and downloads.
TEST(BtTracker, DiscoversSeederViaTrackerAndDownloads) {
    const std::string base = (stdfs::path(::testing::TempDir()) / "librats_trk").string();
    std::error_code ec;
    stdfs::remove_all(base, ec);
    const std::string seed_dir = (stdfs::path(base) / "seed").string();
    const std::string dl_dir   = (stdfs::path(base) / "down").string();
    stdfs::create_directories(dl_dir, ec);

    Bytes data = make_data(40000);
    Bytes info_bytes = build_info_and_seed("f.bin", data, 16384, seed_dir);

    Client seeder(Client::Config{0, seed_dir, "-LR0001-"});
    Client leecher(Client::Config{0, dl_dir, "-LR0002-"});
    seeder.open();
    leecher.open();

    // The fake tracker points everyone at the seeder.
    FakeUdpTracker fake("127.0.0.1", seeder.listen_port());
    const std::string announce = "udp://127.0.0.1:" + std::to_string(fake.port()) + "/announce";

    Torrent* st = seeder.add_torrent(*TorrentInfo::from_info_dict(info_bytes, InfoHash{}), seed_dir);
    Torrent* lt = leecher.add_torrent(*TorrentInfo::from_bytes(make_torrent(info_bytes, announce)), dl_dir);
    ASSERT_TRUE(st && lt);

    auto pump = [&](const std::function<bool()>& done) {
        for (int i = 0; i < 8000; ++i) {
            if (done()) return true;
            seeder.reactor().run_one(2);
            leecher.reactor().run_one(2);
        }
        return done();
    };

    ASSERT_TRUE(pump([&] { return st->state() == Torrent::State::Seeding; }));
    // No add_peer — the only way to find the seeder is the tracker.
    ASSERT_TRUE(pump([&] { return lt->is_complete(); }))
        << "progress=" << lt->progress() << " peers=" << lt->num_peers();

    std::ifstream f((stdfs::path(dl_dir) / "f.bin").string(), std::ios::binary);
    Bytes got((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    EXPECT_EQ(got, data);

    seeder.stop();
    leecher.stop();
    fake.stop();
    stdfs::remove_all(base, ec);
}
