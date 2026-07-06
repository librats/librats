#include <gtest/gtest.h>

#include "bittorrent/client.h"
#include "bittorrent/torrent_info.h"
#include "bittorrent/bencode.h"
#include "crypto/sha1.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

// Covers the "add missed api" surface: Torrent pause()/resume() (peer drop, swarm
// silence, reconnect on resume), Client's reactor-marshalled torrent_status /
// pause_torrent / resume_torrent / save_resume_data, and add_magnet_resumed
// (resume file loaded before start()).

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

// True single-file torrent: the file lives directly at <seed_dir>/<name>.
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

class BtPauseResume : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* ti = ::testing::UnitTest::GetInstance()->current_test_info();
        base_ = (stdfs::path(::testing::TempDir()) / ("librats_pr_" + std::string(ti->name()))).string();
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
    // Single-reactor variant (resume-from-disk needs no peer).
    bool pump_until(Client& a, const std::function<bool()>& done) {
        for (int i = 0; i < 8000; ++i) {
            if (done()) return true;
            a.reactor().run_one(2);
        }
        return done();
    }
    std::string base_;
};

} // namespace

// pause() must drop every peer, torrent_status must report the paused state through
// the reactor, and resume() must reconnect and finish the download.
TEST_F(BtPauseResume, PauseDropsPeersAndResumeReconnects) {
    Bytes data = make_data(100000);  // ~7 pieces at 16 KiB
    TorrentInfo info = build_and_seed_single("solo.bin", data, 16384, seed_dir());
    const InfoHash ih = info.info_hash();

    Client seeder(Client::Config{0, seed_dir(), "-LR0001-"});
    Client leecher(Client::Config{0, dl_dir(), "-LR0002-"});
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    // Connect and wait until the leecher actually has the seeder as a peer.
    lt->add_peer("127.0.0.1", seeder.listen_port());
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return lt->num_peers() >= 1; }));

    // Pause through the Client API (marshalled onto the reactor). peers_ is cleared
    // synchronously, so the drop is observable immediately.
    leecher.pause_torrent(ih);
    EXPECT_TRUE(lt->is_paused());
    EXPECT_EQ(lt->num_peers(), 0u) << "paused torrent must drop all peers";

    // torrent_status reflects the paused snapshot.
    TorrentStatus paused = leecher.torrent_status(ih);
    EXPECT_TRUE(paused.exists);
    EXPECT_TRUE(paused.paused);
    EXPECT_EQ(paused.num_peers, 0u);
    EXPECT_EQ(paused.name, info.name());
    EXPECT_TRUE(paused.has_metadata);

    // Let the socket close flush on both ends (event-driven, so this returns as soon
    // as the seeder sees the peer leave — not an idle spin). This also means the
    // leecher's on_closed has run, so the peer is eligible to redial on resume.
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->num_peers() == 0; }));

    // Resume: re-offer the seeder and expect the download to complete.
    leecher.resume_torrent(ih);
    EXPECT_FALSE(lt->is_paused());
    lt->add_peer("127.0.0.1", seeder.listen_port());
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }))
        << "progress=" << lt->progress() << " peers=" << lt->num_peers();

    EXPECT_TRUE(lt->is_complete());
    EXPECT_FALSE(leecher.torrent_status(ih).paused);

    seeder.stop();
    leecher.stop();
}

// A double pause / resume is a no-op and never wedges the state machine.
TEST_F(BtPauseResume, RepeatedPauseResumeIsIdempotent) {
    Bytes data = make_data(40000);
    TorrentInfo info = build_and_seed_single("solo.bin", data, 16384, dl_dir());
    const InfoHash ih = info.info_hash();

    Client c(Client::Config{0, dl_dir(), "-LR0001-"});
    c.open();
    Torrent* t = c.add_torrent(info, dl_dir());
    ASSERT_NE(t, nullptr);
    ASSERT_TRUE(pump_until(c, [&] { return t->state() == Torrent::State::Seeding; }));

    c.pause_torrent(ih);
    c.pause_torrent(ih);              // second pause: no-op
    EXPECT_TRUE(t->is_paused());
    EXPECT_TRUE(c.torrent_status(ih).paused);

    c.resume_torrent(ih);
    c.resume_torrent(ih);            // second resume: no-op
    EXPECT_FALSE(t->is_paused());
    EXPECT_FALSE(c.torrent_status(ih).paused);
    // Still complete on disk — resume must not have dropped the picker/have set.
    EXPECT_TRUE(t->is_complete());

    c.stop();
}

// torrent_status exposes metadata, size and the file list once known.
TEST_F(BtPauseResume, TorrentStatusReportsMetadataAndFiles) {
    Bytes data = make_data(50000);
    TorrentInfo info = build_and_seed_single("solo.bin", data, 16384, dl_dir());
    const InfoHash ih = info.info_hash();

    Client c(Client::Config{0, dl_dir(), "-LR0001-"});
    c.open();
    Torrent* t = c.add_torrent(info, dl_dir());
    ASSERT_NE(t, nullptr);
    ASSERT_TRUE(pump_until(c, [&] { return t->state() == Torrent::State::Seeding; }));

    TorrentStatus s = c.torrent_status(ih);
    EXPECT_TRUE(s.exists);
    EXPECT_TRUE(s.has_metadata);
    EXPECT_TRUE(s.is_complete);
    EXPECT_FALSE(s.paused);
    EXPECT_DOUBLE_EQ(s.progress, 1.0);
    EXPECT_EQ(s.total_size, data.size());
    ASSERT_EQ(s.files.size(), 1u);
    EXPECT_EQ(s.files[0].size, std::int64_t(data.size()));

    c.stop();
}

// Status for an unknown info-hash is a zeroed snapshot with exists=false.
TEST_F(BtPauseResume, StatusForUnknownTorrent) {
    Client c(Client::Config{0, dl_dir(), "-LR0001-"});
    c.open();

    InfoHash ih{};
    ih.fill(0xAB);
    TorrentStatus s = c.torrent_status(ih);
    EXPECT_FALSE(s.exists);
    EXPECT_EQ(s.num_peers, 0u);
    EXPECT_FALSE(s.has_metadata);

    // The other reactor-marshalled mutators tolerate an unknown hash too.
    c.pause_torrent(ih);
    c.resume_torrent(ih);
    EXPECT_FALSE(c.save_resume_data(ih));

    c.stop();
}

// add_magnet_resumed with no resume file behaves like add_magnet: a metadata-less
// magnet torrent that will fetch its info dict from peers.
TEST_F(BtPauseResume, AddMagnetResumedWithoutResumeFile) {
    Client c(Client::Config{0, dl_dir(), "-LR0001-"});
    c.open();

    const std::string magnet = "magnet:?xt=urn:btih:" + std::string(40, 'a');
    Torrent* t = c.add_magnet_resumed(magnet, dl_dir());
    ASSERT_NE(t, nullptr);
    EXPECT_FALSE(t->has_metadata());
    EXPECT_FALSE(t->is_paused());
    EXPECT_EQ(t->state(), Torrent::State::Metadata);

    c.stop();
}

// End-to-end: save a completed torrent's resume data, then re-add it as a magnet.
// add_magnet_resumed must load the resume file (info dict + trusted have) before
// start(), so the torrent comes straight up as a seed with no peers at all.
TEST_F(BtPauseResume, AddMagnetResumedRestoresCompletedTorrentFromDisk) {
    Bytes data = make_data(60000);
    // Seed the complete file into the download dir so every piece is present.
    TorrentInfo info = build_and_seed_single("solo.bin", data, 16384, dl_dir());
    const InfoHash ih = info.info_hash();

    {
        Client c(Client::Config{0, dl_dir(), "-LR0001-"});
        c.open();
        Torrent* t = c.add_torrent(info, dl_dir());
        ASSERT_NE(t, nullptr);
        ASSERT_TRUE(pump_until(c, [&] { return t->state() == Torrent::State::Seeding; }));
        // Persist resume data (embeds the info dict + the all-have bitfield).
        EXPECT_TRUE(c.save_resume_data(ih));
        c.stop();
    }

    // Fresh client, only the magnet (info-hash) — the info dict comes from resume.
    Client c2(Client::Config{0, dl_dir(), "-LR0002-"});
    c2.open();
    const std::string magnet = "magnet:?xt=urn:btih:" + info.info_hash_hex();
    Torrent* t2 = c2.add_magnet_resumed(magnet, dl_dir());
    ASSERT_NE(t2, nullptr);

    // No peers are ever added: reaching Seeding proves the resume file restored the
    // metadata and the trusted have set from disk.
    ASSERT_TRUE(pump_until(c2, [&] { return t2->state() == Torrent::State::Seeding; }))
        << "progress=" << t2->progress() << " has_metadata=" << t2->has_metadata();
    EXPECT_TRUE(t2->has_metadata());
    EXPECT_TRUE(t2->is_complete());
    EXPECT_EQ(t2->num_peers(), 0u);

    c2.stop();
}
