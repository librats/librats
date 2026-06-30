#include <gtest/gtest.h>

#include "bittorrent/client.h"
#include "bittorrent/torrent_info.h"
#include "bittorrent/bencode.h"
#include "crypto/sha1.h"

#include <filesystem>
#include <fstream>
#include <functional>
#include <string>

using namespace librats::bittorrent;
using librats::Bytes;
using librats::BencodeValue;

namespace {

namespace stdfs = std::filesystem;

Bytes make_data(std::size_t n) {
    Bytes d(n);
    std::uint32_t x = 0x5EEDu;
    for (std::size_t i = 0; i < n; ++i) { x = x * 1103515245u + 12345u; d[i] = std::uint8_t(x >> 16); }
    return d;
}

std::string piece_hashes_for(const Bytes& data, std::uint32_t plen) {
    std::string pieces;
    const std::size_t n = (data.size() + plen - 1) / plen;
    for (std::size_t p = 0; p < n; ++p) {
        const std::size_t off = p * plen;
        const std::size_t len = std::min<std::size_t>(plen, data.size() - off);
        auto h = librats::SHA1::hash_raw(data.data() + off, len);
        pieces.append(reinterpret_cast<const char*>(h.data()), 20);
    }
    return pieces;
}

TorrentInfo build_and_seed_single(const std::string& name, const Bytes& data,
                                  std::uint32_t plen, const std::string& seed_dir) {
    stdfs::create_directories(seed_dir);
    std::ofstream out((stdfs::path(seed_dir) / name).string(), std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), std::streamsize(data.size()));
    out.close();
    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(name);
    info["length"]       = BencodeValue(std::int64_t(data.size()));
    info["piece length"] = BencodeValue(std::int64_t(plen));
    info["pieces"]       = BencodeValue(piece_hashes_for(data, plen));
    return *TorrentInfo::from_info_dict(info.encode(), InfoHash{});
}

} // namespace

// A seeder introduces two leechers to each other via PEX, so they connect
// directly without ever being told about one another explicitly.
TEST(BtPex, SeederIntroducesLeechersToEachOther) {
    const std::string base = (stdfs::path(::testing::TempDir()) / "librats_pex").string();
    std::error_code ec;
    stdfs::remove_all(base, ec);

    Bytes data = make_data(20000);
    TorrentInfo info = build_and_seed_single("f.bin", data, 16384,
                                             (stdfs::path(base) / "seed").string());

    Client seeder(Client::Config{0, (stdfs::path(base) / "seed").string(), "-LR0001-"});
    Client l1(Client::Config{0, (stdfs::path(base) / "d1").string(), "-LR0002-"});
    Client l2(Client::Config{0, (stdfs::path(base) / "d2").string(), "-LR0003-"});
    seeder.open();
    l1.open();
    l2.open();

    Torrent* st = seeder.add_torrent(info, (stdfs::path(base) / "seed").string());
    Torrent* t1 = l1.add_torrent(info, (stdfs::path(base) / "d1").string());
    Torrent* t2 = l2.add_torrent(info, (stdfs::path(base) / "d2").string());
    ASSERT_TRUE(st && t1 && t2);

    auto pump = [&](const std::function<bool()>& done) {
        for (int i = 0; i < 6000; ++i) {
            if (done()) return true;
            seeder.reactor().run_one(1);
            l1.reactor().run_one(1);
            l2.reactor().run_one(1);
        }
        return done();
    };

    ASSERT_TRUE(pump([&] { return st->state() == Torrent::State::Seeding; }));

    // Both leechers know only the seeder.
    t1->add_peer("127.0.0.1", seeder.listen_port());
    t2->add_peer("127.0.0.1", seeder.listen_port());

    // Once both are attached to the seeder, it has two peers to gossip about.
    ASSERT_TRUE(pump([&] { return st->num_peers() >= 2; }));

    // PEX should let leecher 1 discover leecher 2 (or vice versa) and connect —
    // giving at least one of them a second peer beyond the seeder.
    ASSERT_TRUE(pump([&] { return t1->num_peers() >= 2 || t2->num_peers() >= 2; }))
        << "t1 peers=" << t1->num_peers() << " t2 peers=" << t2->num_peers();

    seeder.stop();
    l1.stop();
    l2.stop();
    stdfs::remove_all(base, ec);
}
