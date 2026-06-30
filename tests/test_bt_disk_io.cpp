#include <gtest/gtest.h>

#include "bittorrent/disk_io.h"
#include "bittorrent/torrent_info.h"
#include "bittorrent/bencode.h"
#include "crypto/sha1.h"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <future>
#include <string>

using namespace librats::bittorrent;
using librats::Bytes;
using librats::BencodeValue;

namespace {

namespace stdfs = std::filesystem;

/// Deterministic pseudo-random payload so tests are reproducible.
Bytes make_data(std::size_t n) {
    Bytes d(n);
    std::uint32_t x = 0x12345678u;
    for (std::size_t i = 0; i < n; ++i) {
        x = x * 1103515245u + 12345u;
        d[i] = std::uint8_t(x >> 16);
    }
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

TorrentInfo single_file_info(const std::string& name, const Bytes& data, std::uint32_t plen) {
    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(name);
    info["length"]       = BencodeValue(std::int64_t(data.size()));
    info["piece length"] = BencodeValue(std::int64_t(plen));
    info["pieces"]       = BencodeValue(piece_hashes_for(data, plen));
    return *TorrentInfo::from_info_dict(info.encode(), InfoHash{});
}

TorrentInfo multi_file_info(const std::string& name,
                            const std::vector<std::pair<std::string, std::int64_t>>& layout,
                            const Bytes& data, std::uint32_t plen) {
    BencodeValue files = BencodeValue::create_list();
    for (const auto& [path, size] : layout) {
        BencodeValue f = BencodeValue::create_dict();
        f["length"] = BencodeValue(std::int64_t(size));
        BencodeValue p = BencodeValue::create_list();
        p.push_back(BencodeValue(path));
        f["path"] = p;
        files.push_back(f);
    }
    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(name);
    info["files"]        = files;
    info["piece length"] = BencodeValue(std::int64_t(plen));
    info["pieces"]       = BencodeValue(piece_hashes_for(data, plen));
    return *TorrentInfo::from_info_dict(info.encode(), InfoHash{});
}

class BtDiskIo : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* ti = ::testing::UnitTest::GetInstance()->current_test_info();
        dir_ = (stdfs::path(::testing::TempDir()) /
                ("librats_bt_" + std::string(ti->test_suite_name()) + "_" + ti->name())).string();
        std::error_code ec;
        stdfs::remove_all(dir_, ec);
        stdfs::create_directories(dir_, ec);
    }
    void TearDown() override {
        std::error_code ec;
        stdfs::remove_all(dir_, ec);
    }

    // Write the whole payload, block by block, blocking until each write lands.
    void write_all(DiskIo& disk, const TorrentInfo& info, const Bytes& data) {
        const std::uint32_t plen = info.piece_length();
        for (std::uint32_t p = 0; p < info.num_pieces(); ++p) {
            const std::uint32_t ps = info.piece_size(p);
            for (std::uint32_t off = 0; off < ps; off += kBlockSize) {
                const std::uint32_t len = std::min(kBlockSize, ps - off);
                const std::size_t abs = std::size_t(p) * plen + off;
                Bytes block(data.begin() + std::ptrdiff_t(abs),
                            data.begin() + std::ptrdiff_t(abs + len));
                std::promise<bool> done;
                disk.async_write(p, off, std::move(block), [&](bool ok) { done.set_value(ok); });
                ASSERT_TRUE(done.get_future().get());
            }
        }
    }

    std::string dir_;
};

} // namespace

TEST_F(BtDiskIo, SingleFileWriteReadHashCheck) {
    Bytes data = make_data(32768 * 2 + 5000);  // 3 pieces (2 full + short)
    TorrentInfo info = single_file_info("payload.bin", data, 32768);
    ThreadedDiskIo disk(info, dir_, /*poster=*/{}, {/*num_threads=*/3});

    write_all(disk, info, data);

    // Read each piece back and compare to the source.
    for (std::uint32_t p = 0; p < info.num_pieces(); ++p) {
        const std::uint32_t ps = info.piece_size(p);
        std::promise<std::pair<bool, Bytes>> pr;
        disk.async_read(p, 0, ps, [&](bool ok, Bytes d) { pr.set_value({ok, std::move(d)}); });
        auto [ok, got] = pr.get_future().get();
        ASSERT_TRUE(ok) << "piece " << p;
        Bytes want(data.begin() + std::ptrdiff_t(std::size_t(p) * info.piece_length()),
                   data.begin() + std::ptrdiff_t(std::size_t(p) * info.piece_length() + ps));
        EXPECT_EQ(got, want) << "piece " << p;
    }

    // Hashes must match the metadata.
    for (std::uint32_t p = 0; p < info.num_pieces(); ++p) {
        std::promise<std::pair<bool, std::array<std::uint8_t, 20>>> pr;
        disk.async_hash(p, [&](bool ok, std::array<std::uint8_t, 20> h) { pr.set_value({ok, h}); });
        auto [ok, h] = pr.get_future().get();
        ASSERT_TRUE(ok) << "piece " << p;
        EXPECT_EQ(h, info.piece_hash(p)) << "piece " << p;
    }

    // check_files should report every piece present.
    std::promise<Bitfield> pr;
    disk.async_check_files(Bitfield{}, nullptr, [&](Bitfield have) { pr.set_value(std::move(have)); });
    Bitfield have = pr.get_future().get();
    EXPECT_EQ(have.count(), info.num_pieces());
}

TEST_F(BtDiskIo, MultiFileWritesToCorrectFiles) {
    Bytes data = make_data(35000);
    TorrentInfo info = multi_file_info(
        "mydir", {{"a.bin", 10000}, {"b.bin", 20000}, {"c.bin", 5000}}, data, 16384);
    ThreadedDiskIo disk(info, dir_, {}, {2});

    write_all(disk, info, data);

    // Every piece verifies (pieces span file boundaries).
    std::promise<Bitfield> pr;
    disk.async_check_files(Bitfield{}, nullptr, [&](Bitfield have) { pr.set_value(std::move(have)); });
    EXPECT_EQ(pr.get_future().get().count(), info.num_pieces());

    // The bytes must have landed in the right files at the right offsets.
    auto read_file = [&](const std::string& rel) {
        std::ifstream f((stdfs::path(dir_) / rel).string(), std::ios::binary);
        return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };
    Bytes a = read_file("mydir/a.bin");
    Bytes b = read_file("mydir/b.bin");
    Bytes c = read_file("mydir/c.bin");
    ASSERT_EQ(a.size(), 10000u);
    ASSERT_EQ(b.size(), 20000u);
    ASSERT_EQ(c.size(), 5000u);
    EXPECT_TRUE(std::equal(a.begin(), a.end(), data.begin()));
    EXPECT_TRUE(std::equal(b.begin(), b.end(), data.begin() + 10000));
    EXPECT_TRUE(std::equal(c.begin(), c.end(), data.begin() + 30000));
}

TEST_F(BtDiskIo, CheckFilesDetectsMissingPieces) {
    Bytes data = make_data(16384 * 4);  // 4 pieces
    TorrentInfo info = single_file_info("f.bin", data, 16384);
    ThreadedDiskIo disk(info, dir_, {}, {2});

    // Write only pieces 0 and 2.
    for (std::uint32_t p : {0u, 2u}) {
        const std::size_t abs = std::size_t(p) * info.piece_length();
        Bytes block(data.begin() + std::ptrdiff_t(abs),
                    data.begin() + std::ptrdiff_t(abs + info.piece_size(p)));
        std::promise<bool> done;
        disk.async_write(p, 0, std::move(block), [&](bool ok) { done.set_value(ok); });
        ASSERT_TRUE(done.get_future().get());
    }

    std::promise<Bitfield> pr;
    disk.async_check_files(Bitfield{}, nullptr, [&](Bitfield have) { pr.set_value(std::move(have)); });
    Bitfield have = pr.get_future().get();
    EXPECT_EQ(have.count(), 2u);
    EXPECT_TRUE(have.get(0));
    EXPECT_FALSE(have.get(1));
    EXPECT_TRUE(have.get(2));
    EXPECT_FALSE(have.get(3));
}

TEST_F(BtDiskIo, CheckFilesTrustsResumeBitsWithoutHashing) {
    Bytes data = make_data(16384 * 3);
    TorrentInfo info = single_file_info("f.bin", data, 16384);
    ThreadedDiskIo disk(info, dir_, {}, {1});

    // Nothing is on disk, but a trusted-have with all bits set is taken at face
    // value (fast resume) — no read, no hash.
    Bitfield trusted(info.num_pieces(), true);
    std::promise<Bitfield> pr;
    disk.async_check_files(trusted, nullptr, [&](Bitfield have) { pr.set_value(std::move(have)); });
    EXPECT_EQ(pr.get_future().get().count(), info.num_pieces());
}

TEST_F(BtDiskIo, ProgressReportsEveryPiece) {
    Bytes data = make_data(16384 * 3);
    TorrentInfo info = single_file_info("f.bin", data, 16384);
    ThreadedDiskIo disk(info, dir_, {}, {1});

    std::atomic<std::uint32_t> last{0};
    std::promise<Bitfield> pr;
    disk.async_check_files(Bitfield{},
                           [&](std::uint32_t done, std::uint32_t total) {
                               EXPECT_EQ(total, info.num_pieces());
                               last = done;
                           },
                           [&](Bitfield have) { pr.set_value(std::move(have)); });
    pr.get_future().get();
    EXPECT_EQ(last.load(), info.num_pieces());
}
