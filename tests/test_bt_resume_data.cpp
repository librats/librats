#include <gtest/gtest.h>

#include "bittorrent/resume_data.h"
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
    std::uint32_t x = 0x1357u;
    for (std::size_t i = 0; i < n; ++i) { x = x * 1103515245u + 12345u; d[i] = std::uint8_t(x >> 16); }
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

Bytes single_file_info(const std::string& name, const Bytes& data, std::uint32_t plen) {
    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(name);
    info["length"]       = BencodeValue(std::int64_t(data.size()));
    info["piece length"] = BencodeValue(std::int64_t(plen));
    info["pieces"]       = BencodeValue(piece_hashes_for(data, plen));
    return info.encode();
}
} // namespace

TEST(BtResumeData, EncodeDecodeRoundTrip) {
    ResumeData rd;
    rd.info_hash.fill(0x42);
    rd.name = "my torrent";
    rd.save_path = "/downloads";
    rd.have = Bitfield(10, false);
    rd.have.set(0);
    rd.have.set(3);
    rd.have.set(9);
    rd.total_uploaded = 111;
    rd.total_downloaded = 222;
    rd.info_dict = Bytes{'d', 'e'};

    auto back = ResumeData::decode(rd.encode());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back->info_hash, rd.info_hash);
    EXPECT_EQ(back->name, "my torrent");
    EXPECT_EQ(back->save_path, "/downloads");
    EXPECT_EQ(back->total_uploaded, 111u);
    EXPECT_EQ(back->total_downloaded, 222u);
    EXPECT_EQ(back->info_dict, rd.info_dict);
    ASSERT_EQ(back->have.size(), 10u);
    EXPECT_TRUE(back->have.get(0));
    EXPECT_TRUE(back->have.get(3));
    EXPECT_TRUE(back->have.get(9));
    EXPECT_FALSE(back->have.get(1));
    EXPECT_EQ(back->have.count(), 3u);
}

TEST(BtResumeData, RejectsForeignData) {
    EXPECT_FALSE(ResumeData::decode(Bytes{'x', 'y', 'z'}).has_value());
    BencodeValue d = BencodeValue::create_dict();
    d["format"] = BencodeValue(std::string("something else"));
    EXPECT_FALSE(ResumeData::decode(d.encode()).has_value());
}

// A completed download's resume data lets a fresh client seed instantly — the
// trusted bitfield means no re-download and no peers are needed.
TEST(BtResumeData, ResumesCompletedTorrentWithoutPeers) {
    const std::string base = (stdfs::path(::testing::TempDir()) / "librats_resume").string();
    std::error_code ec;
    stdfs::remove_all(base, ec);
    const std::string seed_dir = (stdfs::path(base) / "seed").string();
    const std::string dl_dir   = (stdfs::path(base) / "down").string();
    stdfs::create_directories(seed_dir, ec);
    stdfs::create_directories(dl_dir, ec);

    Bytes data = make_data(50000);
    {
        std::ofstream out((stdfs::path(seed_dir) / "f.bin").string(), std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()), std::streamsize(data.size()));
    }
    TorrentInfo info = *TorrentInfo::from_info_dict(single_file_info("f.bin", data, 16384), InfoHash{});

    Client seeder(Client::Config{0, seed_dir, "-LR0001-"});
    Client leecher(Client::Config{0, dl_dir, "-LR0002-"});
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir);
    Torrent* lt = leecher.add_torrent(info, dl_dir);

    auto pump = [&](Client& a, Client& b, const std::function<bool()>& done) {
        for (int i = 0; i < 6000; ++i) { if (done()) return true; a.reactor().run_one(2); b.reactor().run_one(2); }
        return done();
    };
    ASSERT_TRUE(pump(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));
    lt->add_peer("127.0.0.1", seeder.listen_port());
    ASSERT_TRUE(pump(seeder, leecher, [&] { return lt->is_complete(); }));

    // Snapshot resume data from the finished leecher.
    ResumeData rd = lt->generate_resume_data();
    EXPECT_EQ(rd.have.count(), info.num_pieces());

    // A brand-new client over the same download dir resumes to Seeding with no peers.
    Client resumed(Client::Config{0, dl_dir, "-LR0003-"});
    resumed.open();
    Torrent* rt = resumed.add_torrent_with_resume(info, rd, dl_dir);
    ASSERT_NE(rt, nullptr);
    for (int i = 0; i < 2000 && rt->state() != Torrent::State::Seeding; ++i) resumed.reactor().run_one(2);
    EXPECT_EQ(rt->state(), Torrent::State::Seeding);
    EXPECT_TRUE(rt->is_complete());
    EXPECT_EQ(rt->num_peers(), 0u);

    seeder.stop();
    leecher.stop();
    resumed.stop();
    stdfs::remove_all(base, ec);
}

// A hostile/corrupt .resume can claim billions of pieces while carrying a tiny
// (or no) bitfield. num-pieces drives Bitfield::assign's allocation, so decode
// must reject a record whose num-pieces doesn't match the pieces string length
// rather than allocating gigabytes. (C4)
TEST(BtResumeData, RejectsInflatedNumPieces) {
    BencodeValue d = BencodeValue::create_dict();
    d["format"]     = BencodeValue(std::string("librats resume"));
    d["info-hash"]  = BencodeValue(std::string(20, '\x11'));
    d["num-pieces"] = BencodeValue(std::int64_t(40000000000LL));  // absurd
    d["pieces"]     = BencodeValue(std::string(4, '\0'));          // 4 bytes = 32 bits, not 4e10
    EXPECT_FALSE(ResumeData::decode(d.encode()).has_value());

    // A consistent record (num-pieces == 8*len rounded up) still decodes.
    BencodeValue ok = BencodeValue::create_dict();
    ok["format"]     = BencodeValue(std::string("librats resume"));
    ok["info-hash"]  = BencodeValue(std::string(20, '\x11'));
    ok["num-pieces"] = BencodeValue(std::int64_t(20));             // ceil(20/8) = 3 bytes
    ok["pieces"]     = BencodeValue(std::string(3, '\xff'));
    auto back = ResumeData::decode(ok.encode());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back->have.size(), 20u);
}
