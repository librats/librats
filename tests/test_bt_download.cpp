#include <gtest/gtest.h>

#include "bittorrent/client.h"
#include "bittorrent/torrent_info.h"
#include "bittorrent/bencode.h"
#include "crypto/sha1.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace librats::bittorrent;
using librats::Bytes;
using librats::BencodeValue;

namespace {

namespace stdfs = std::filesystem;

Bytes make_data(std::size_t n) {
    Bytes d(n);
    std::uint32_t x = 0xC0FFEEu;
    for (std::size_t i = 0; i < n; ++i) { x = x * 1103515245u + 12345u; d[i] = std::uint8_t(x >> 16); }
    return d;
}

std::string piece_hashes_for(const Bytes& data, std::uint32_t piece_length) {
    std::string pieces;
    const std::size_t n = (data.size() + piece_length - 1) / piece_length;
    for (std::size_t p = 0; p < n; ++p) {
        const std::size_t off = p * piece_length;
        const std::size_t len = std::min<std::size_t>(piece_length, data.size() - off);
        auto h = librats::SHA1::hash_raw(data.data() + off, len);
        pieces.append(reinterpret_cast<const char*>(h.data()), 20);
    }
    return pieces;
}

// Build a multi-file TorrentInfo for `layout` over `data`, and write the seeder's
// copy of the files under `seed_dir`.
TorrentInfo build_and_seed(const std::string& name,
                           const std::vector<std::pair<std::string, std::int64_t>>& layout,
                           const Bytes& data, std::uint32_t plen,
                           const std::string& seed_dir) {
    BencodeValue files = BencodeValue::create_list();
    std::int64_t off = 0;
    for (const auto& [rel, size] : layout) {
        BencodeValue f = BencodeValue::create_dict();
        f["length"] = BencodeValue(std::int64_t(size));
        BencodeValue path = BencodeValue::create_list();
        path.push_back(BencodeValue(rel));
        f["path"] = path;
        files.push_back(f);

        const stdfs::path full = stdfs::path(seed_dir) / name / rel;
        stdfs::create_directories(full.parent_path());
        std::ofstream out(full.string(), std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data() + off), size);
        off += size;
    }
    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(name);
    info["files"]        = files;
    info["piece length"] = BencodeValue(std::int64_t(plen));
    info["pieces"]       = BencodeValue(piece_hashes_for(data, plen));
    return *TorrentInfo::from_info_dict(info.encode(), InfoHash{});
}

// True single-file torrent (uses `length`, not a `files` list): the file lives
// directly at <save_path>/<name>.
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

class BtDownload : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* ti = ::testing::UnitTest::GetInstance()->current_test_info();
        base_ = (stdfs::path(::testing::TempDir()) / ("librats_dl_" + std::string(ti->name()))).string();
        std::error_code ec;
        stdfs::remove_all(base_, ec);
        stdfs::create_directories(base_, ec);
    }
    void TearDown() override { std::error_code ec; stdfs::remove_all(base_, ec); }

    std::string seed_dir() const { return (stdfs::path(base_) / "seed").string(); }
    std::string dl_dir()   const { return (stdfs::path(base_) / "down").string(); }

    // Pump both reactors until `done` or a generous iteration cap.
    bool pump_until(Client& a, Client& b, const std::function<bool()>& done) {
        for (int i = 0; i < 8000; ++i) {
            if (done()) return true;
            a.reactor().run_one(2);
            b.reactor().run_one(2);
        }
        return done();
    }

    std::string base_;
};

} // namespace

TEST_F(BtDownload, MagnetlessMultiFileDownloadCompletes) {
    Bytes data = make_data(35000);  // 3 pieces of 16 KiB (last short)
    TorrentInfo info = build_and_seed(
        "mydir", {{"a.bin", 10000}, {"b.bin", 20000}, {"c.bin", 5000}}, data, 16384, seed_dir());

    Client seeder(Client::Config{0, seed_dir(), "-LR0001-"});
    Client leecher(Client::Config{0, dl_dir(), "-LR0002-"});
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);

    // Let the seeder finish checking its on-disk files (it should be complete).
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    // Point the leecher at the seeder and download.
    lt->add_peer("127.0.0.1", seeder.listen_port());
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }))
        << "progress=" << lt->progress() << " peers=" << lt->num_peers();

    EXPECT_TRUE(lt->is_complete());
    EXPECT_EQ(lt->state(), Torrent::State::Seeding);
    EXPECT_GE(lt->num_peers(), 1u);

    // The downloaded files must match the original data byte-for-byte.
    auto read_file = [&](const std::string& rel) {
        std::ifstream f((stdfs::path(dl_dir()) / "mydir" / rel).string(), std::ios::binary);
        return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };
    Bytes a = read_file("a.bin"), b = read_file("b.bin"), c = read_file("c.bin");
    ASSERT_EQ(a.size(), 10000u);
    ASSERT_EQ(b.size(), 20000u);
    ASSERT_EQ(c.size(), 5000u);
    EXPECT_TRUE(std::equal(a.begin(), a.end(), data.begin()));
    EXPECT_TRUE(std::equal(b.begin(), b.end(), data.begin() + 10000));
    EXPECT_TRUE(std::equal(c.begin(), c.end(), data.begin() + 30000));

    seeder.stop();
    leecher.stop();
}

TEST_F(BtDownload, SingleFileDownloadCompletes) {
    Bytes data = make_data(100000);  // ~7 pieces at 16 KiB
    TorrentInfo info = build_and_seed_single("solo.bin", data, 16384, seed_dir());

    Client seeder(Client::Config{0, seed_dir(), "-LR0001-"});
    Client leecher(Client::Config{0, dl_dir(), "-LR0002-"});
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    lt->add_peer("127.0.0.1", seeder.listen_port());
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }))
        << "progress=" << lt->progress();

    std::ifstream f((stdfs::path(dl_dir()) / "solo.bin").string(), std::ios::binary);
    Bytes got((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    EXPECT_EQ(got, data);

    seeder.stop();
    leecher.stop();
}

// Regression: resuming a complete torrent must not double-count downloaded bytes.
// load_resume_data restores the cumulative counter (total_downloaded) AND the
// have-bitfield; the on-disk check must not fold the on-disk pieces back into that
// counter (which previously doubled it and drove `left` to 0 — a false seed claim).
TEST_F(BtDownload, ResumeDoesNotDoubleCountDownloaded) {
    Bytes data = make_data(40000);  // ~3 pieces at 16 KiB
    // Write the complete file into the download dir so every piece is present.
    TorrentInfo info = build_and_seed_single("solo.bin", data, 16384, dl_dir());

    Client c(Client::Config{0, dl_dir(), "-LR0001-"});
    c.open();

    ResumeData rd;
    rd.info_hash        = info.info_hash();
    rd.have             = Bitfield(info.num_pieces(), true);  // all pieces on disk
    rd.total_downloaded = data.size();                        // cumulative from a prior session
    rd.total_uploaded   = 0;

    Torrent* t = c.add_torrent_with_resume(info, rd, dl_dir());
    ASSERT_NE(t, nullptr);

    for (int i = 0; i < 4000 && t->state() != Torrent::State::Seeding; ++i) c.reactor().run_one(2);
    ASSERT_EQ(t->state(), Torrent::State::Seeding);

    // Must equal the restored counter, not twice it.
    EXPECT_EQ(t->bytes_downloaded(), data.size());

    c.stop();
}
