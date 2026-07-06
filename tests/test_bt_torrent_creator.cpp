#include <gtest/gtest.h>

#include "bittorrent/torrent_creator.h"
#include "bittorrent/torrent_info.h"
#include "bittorrent/client.h"

#include <filesystem>
#include <fstream>
#include <functional>
#include <string>

using namespace librats::bittorrent;
using librats::Bytes;

namespace {
namespace stdfs = std::filesystem;

Bytes make_data(std::size_t n, std::uint32_t seed) {
    Bytes d(n);
    for (std::size_t i = 0; i < n; ++i) { seed = seed * 1103515245u + 12345u; d[i] = std::uint8_t(seed >> 16); }
    return d;
}

void write_file(const std::string& path, const Bytes& data) {
    stdfs::create_directories(stdfs::path(path).parent_path());
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), std::streamsize(data.size()));
}

std::string temp_dir(const std::string& tag) {
    const std::string p = (stdfs::path(::testing::TempDir()) / ("librats_create_" + tag)).string();
    std::error_code ec;
    stdfs::remove_all(p, ec);
    stdfs::create_directories(p, ec);
    return p;
}
} // namespace

TEST(BtTorrentCreator, SingleFile) {
    const std::string dir = temp_dir("single");
    Bytes data = make_data(40000, 11);
    write_file((stdfs::path(dir) / "movie.bin").string(), data);

    TorrentCreator c;
    c.set_piece_length(16384);
    c.add_tracker("udp://tracker.example:80/announce");
    auto info = c.create_from_path((stdfs::path(dir) / "movie.bin").string());

    ASSERT_TRUE(info.has_value());
    EXPECT_TRUE(info->is_valid());
    EXPECT_TRUE(info->has_metadata());
    EXPECT_EQ(info->name(), "movie.bin");
    EXPECT_EQ(info->total_size(), 40000);
    EXPECT_EQ(info->num_pieces(), 3u);   // ceil(40000/16384)
    EXPECT_EQ(info->num_files(), 1u);
    EXPECT_EQ(info->announce(), "udp://tracker.example:80/announce");

    // Re-parsing the emitted .torrent yields the same info-hash.
    auto reparsed = TorrentInfo::from_bytes(c.torrent_file());
    ASSERT_TRUE(reparsed.has_value());
    EXPECT_EQ(reparsed->info_hash(), info->info_hash());
}

TEST(BtTorrentCreator, MultiFileDirectory) {
    const std::string dir = temp_dir("multi");
    const std::string root = (stdfs::path(dir) / "mydir").string();
    write_file((stdfs::path(root) / "a.bin").string(), make_data(10000, 1));
    write_file((stdfs::path(root) / "sub" / "b.bin").string(), make_data(20000, 2));

    TorrentCreator c;
    c.set_piece_length(16384);
    auto info = c.create_from_path(root);

    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->name(), "mydir");
    EXPECT_EQ(info->total_size(), 30000);
    EXPECT_EQ(info->num_files(), 2u);
    // File paths are prefixed with the torrent (directory) name.
    bool has_a = false, has_b = false;
    for (std::size_t i = 0; i < info->files().num_files(); ++i) {
        const std::string& p = info->files().file_at(i).path;
        if (p == "mydir/a.bin") has_a = true;
        if (p == "mydir/sub/b.bin") has_b = true;
    }
    EXPECT_TRUE(has_a);
    EXPECT_TRUE(has_b);
}

TEST(BtTorrentCreator, ReportsHashingProgress) {
    const std::string dir = temp_dir("progress");
    // 70000 bytes over a 16384-byte piece length => ceil(70000/16384) = 5 pieces.
    write_file((stdfs::path(dir) / "data.bin").string(), make_data(70000, 7));

    std::vector<std::pair<std::uint32_t, std::uint32_t>> updates;
    TorrentCreator c;
    c.set_piece_length(16384);
    auto info = c.create_from_path(
        (stdfs::path(dir) / "data.bin").string(), nullptr,
        [&](std::uint32_t done, std::uint32_t total) { updates.emplace_back(done, total); });

    ASSERT_TRUE(info.has_value());
    ASSERT_EQ(info->num_pieces(), 5u);

    // One callback per piece, total held constant, current strictly increasing 1..N,
    // and the final call reports completion (N, N).
    ASSERT_EQ(updates.size(), 5u);
    for (std::size_t i = 0; i < updates.size(); ++i) {
        EXPECT_EQ(updates[i].first, std::uint32_t(i + 1));
        EXPECT_EQ(updates[i].second, 5u);
    }
    EXPECT_EQ(updates.back(), std::make_pair(5u, 5u));
}

// Passing no progress callback (the default) must not crash and must still build.
TEST(BtTorrentCreator, NoProgressCallbackIsFine) {
    const std::string dir = temp_dir("noprogress");
    write_file((stdfs::path(dir) / "data.bin").string(), make_data(40000, 3));

    TorrentCreator c;
    c.set_piece_length(16384);
    auto info = c.create_from_path((stdfs::path(dir) / "data.bin").string());
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->num_pieces(), 3u);
}

// The strongest check: a created torrent's piece hashes match the real files, so
// a seeder over the same directory verifies every piece and reaches Seeding.
TEST(BtTorrentCreator, CreatedTorrentSeedsCleanly) {
    const std::string dir = temp_dir("seed");
    write_file((stdfs::path(dir) / "data.bin").string(), make_data(70000, 7));

    TorrentCreator c;
    c.set_piece_length(16384);
    auto info = c.create_from_path((stdfs::path(dir) / "data.bin").string());
    ASSERT_TRUE(info.has_value());

    Client seeder(Client::Config{0, dir, "-LR0001-"});
    seeder.open();
    Torrent* st = seeder.add_torrent(*info, dir);   // full check against the real file
    ASSERT_NE(st, nullptr);

    bool seeding = false;
    for (int i = 0; i < 4000 && !seeding; ++i) {
        seeder.reactor().run_one(2);
        seeding = st->state() == Torrent::State::Seeding;
    }
    EXPECT_TRUE(seeding);   // every created piece hash verified against disk
    EXPECT_TRUE(st->is_complete());

    seeder.stop();
    std::error_code ec;
    stdfs::remove_all(dir, ec);
}
