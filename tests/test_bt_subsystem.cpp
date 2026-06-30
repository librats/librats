#include <gtest/gtest.h>

#include "subsystems/bittorrent.h"
#include "bittorrent/client.h"
#include "bittorrent/torrent_info.h"
#include "bittorrent/bencode.h"
#include "crypto/sha1.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <string>
#include <thread>

using namespace librats;
using librats::Bytes;
using librats::BencodeValue;

namespace {
namespace stdfs = std::filesystem;

Bytes make_data(std::size_t n, std::uint32_t seed) {
    Bytes d(n);
    for (std::size_t i = 0; i < n; ++i) { seed = seed * 1103515245u + 12345u; d[i] = std::uint8_t(seed >> 16); }
    return d;
}

std::string piece_hashes_for(const Bytes& data, std::uint32_t plen) {
    std::string pieces;
    for (std::size_t off = 0; off < data.size(); off += plen) {
        const std::size_t len = std::min<std::size_t>(plen, data.size() - off);
        auto h = librats::SHA1::hash_raw(data.data() + off, len);
        pieces.append(reinterpret_cast<const char*>(h.data()), 20);
    }
    return pieces;
}

bittorrent::TorrentInfo build_and_seed(const std::string& name, const Bytes& data,
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
    return *bittorrent::TorrentInfo::from_info_dict(info.encode(), bittorrent::InfoHash{});
}
} // namespace

// The subsystem runs standalone (no Node attached): start() brings up the client,
// running DHT-less since no DhtService was provided.
TEST(BtSubsystem, LifecycleWithoutNode) {
    Bittorrent::Config cfg;
    cfg.client.listen_port = 0;
    Bittorrent bt(cfg);

    EXPECT_FALSE(bt.is_running());
    bt.start();
    EXPECT_TRUE(bt.is_running());
    ASSERT_NE(bt.client(), nullptr);
    EXPECT_NE(bt.client()->listen_port(), 0);
    EXPECT_FALSE(bt.using_node_dht());   // no DhtService was attached
    EXPECT_FALSE(bt.is_spider_mode());   // no DHT → spider is a no-op
    bt.stop();
    EXPECT_FALSE(bt.is_running());
}

// Drive the prepared metadata API: one subsystem seeds a torrent, another fetches
// just its metadata (BEP 9) from that peer through get_torrent_metadata_from_peer.
TEST(BtSubsystem, MetadataFetchFromPeer) {
    const std::string base = (stdfs::path(::testing::TempDir()) / "librats_bt_sub").string();
    std::error_code ec;
    stdfs::remove_all(base, ec);
    const std::string seed_dir = (stdfs::path(base) / "seed").string();

    Bytes data = make_data(60000, 99);
    bittorrent::TorrentInfo info = build_and_seed("payload.bin", data, 16384, seed_dir);
    const std::string hex = info.info_hash_hex();

    Bittorrent::Config seed_cfg;
    seed_cfg.client.listen_port   = 0;
    seed_cfg.client.download_path = seed_dir;
    Bittorrent seeder(seed_cfg);
    seeder.start();

    // Register the seed torrent on the client's own reactor thread.
    seeder.client()->reactor().post([&] { seeder.client()->add_torrent(info, seed_dir); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));  // let it register + listen

    Bittorrent fetcher(Bittorrent::Config{});
    fetcher.start();

    std::promise<std::tuple<bool, std::uint32_t, std::int64_t>> done;
    fetcher.get_torrent_metadata_from_peer(
        hex, "127.0.0.1", seeder.client()->listen_port(),
        [&](const bittorrent::TorrentInfo& md, bool ok, const std::string&) {
            done.set_value({ok, md.num_pieces(), md.total_size()});
        },
        15000);

    auto fut = done.get_future();
    ASSERT_EQ(fut.wait_for(std::chrono::seconds(20)), std::future_status::ready);
    auto [ok, pieces, total] = fut.get();
    EXPECT_TRUE(ok);
    EXPECT_EQ(pieces, info.num_pieces());
    EXPECT_EQ(total, info.total_size());

    fetcher.stop();
    seeder.stop();
    stdfs::remove_all(base, ec);
}
