#include <gtest/gtest.h>

#include "bittorrent/client.h"
#include "bittorrent/torrent_info.h"
#include "bittorrent/bencode.h"
#include "crypto/sha1.h"

#include <filesystem>
#include <fstream>
#include <string>

using namespace librats::bittorrent;
using librats::Bytes;
using librats::BencodeValue;

namespace {

namespace stdfs = std::filesystem;

Bytes make_data(std::size_t n) {
    Bytes d(n);
    std::uint32_t x = 0xABCDEFu;
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

TEST(BtMagnetFetch, FetchesMetadataThenDownloads) {
    const auto* ti = ::testing::UnitTest::GetInstance()->current_test_info();
    const std::string base = (stdfs::path(::testing::TempDir()) / ("librats_mag_" + std::string(ti->name()))).string();
    std::error_code ec;
    stdfs::remove_all(base, ec);
    const std::string seed_dir = (stdfs::path(base) / "seed").string();
    const std::string dl_dir   = (stdfs::path(base) / "down").string();
    stdfs::create_directories(dl_dir, ec);

    Bytes data = make_data(70000);  // ~5 pieces of 16 KiB
    TorrentInfo info = build_and_seed_single("payload.bin", data, 16384, seed_dir);
    const std::string magnet = info.to_magnet_uri();

    Client seeder(Client::Config{0, seed_dir, "-LR0001-"});
    Client leecher(Client::Config{0, dl_dir, "-LR0002-"});
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir);
    Torrent* lt = leecher.add_magnet(magnet, dl_dir);   // metadata-less!
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    EXPECT_FALSE(lt->has_metadata());                   // nothing but the info-hash yet
    EXPECT_EQ(lt->info_hash(), info.info_hash());

    auto pump = [&](const std::function<bool()>& done) {
        for (int i = 0; i < 8000; ++i) {
            if (done()) return true;
            seeder.reactor().run_one(2);
            leecher.reactor().run_one(2);
        }
        return done();
    };

    ASSERT_TRUE(pump([&] { return st->state() == Torrent::State::Seeding; }));

    lt->add_peer("127.0.0.1", seeder.listen_port());

    // First the leecher must obtain metadata via BEP 9...
    ASSERT_TRUE(pump([&] { return lt->has_metadata(); }))
        << "metadata not fetched; peers=" << lt->num_peers();
    EXPECT_EQ(lt->num_pieces(), info.num_pieces());

    // ...then download to completion using it.
    ASSERT_TRUE(pump([&] { return lt->is_complete(); })) << "progress=" << lt->progress();
    EXPECT_EQ(lt->state(), Torrent::State::Seeding);

    std::ifstream f((stdfs::path(dl_dir) / "payload.bin").string(), std::ios::binary);
    Bytes got((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    EXPECT_EQ(got, data);

    seeder.stop();
    leecher.stop();
    stdfs::remove_all(base, ec);
}
