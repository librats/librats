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
using librats::Bytes;
using librats::BencodeValue;

// MSE over real sockets, between two full Clients.
//
// The load-bearing trick in here is the seeder's in_enc_policy: with Forced it
// refuses any plaintext dialer outright, exactly like the peer in the log that
// prompted this work. So a download that *completes* against such a seeder is
// itself the proof that the connection was obfuscated end to end — no accessor
// into the connection's internals needed, and nothing that could pass by accident.

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

TorrentInfo build_and_seed(const std::string& name, const Bytes& data,
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

class BtMseWire : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* ti = ::testing::UnitTest::GetInstance()->current_test_info();
        base_ = (stdfs::path(::testing::TempDir()) / ("librats_mse_" + std::string(ti->name()))).string();
        std::error_code ec;
        stdfs::remove_all(base_, ec);
        stdfs::create_directories(base_, ec);
    }
    void TearDown() override { std::error_code ec; stdfs::remove_all(base_, ec); }

    std::string seed_dir() const { return (stdfs::path(base_) / "seed").string(); }
    std::string dl_dir()   const { return (stdfs::path(base_) / "down").string(); }

    Client::Config config(const std::string& dir, const char* prefix,
                          EncPolicy out, EncPolicy in) const {
        Client::Config c;
        c.listen_port     = 0;
        c.download_path   = dir;
        c.peer_id_prefix  = prefix;
        c.out_enc_policy  = out;
        c.in_enc_policy   = in;
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

    /// Seed a torrent, dial it from the leecher, and report whether it downloaded.
    /// The two policies are the whole point of each test below.
    bool transfer(EncPolicy leecher_out, EncPolicy seeder_in, int iters = 8000) {
        const Bytes data = make_data(40000);           // 3 pieces of 16 KiB
        TorrentInfo info = build_and_seed("f.bin", data, 16384, seed_dir());

        Client seeder(config(seed_dir(), "-LR0001-", EncPolicy::Enabled, seeder_in));
        Client leecher(config(dl_dir(), "-LR0002-", leecher_out, EncPolicy::Enabled));
        seeder.open();
        leecher.open();

        Torrent* st = seeder.add_torrent(info, seed_dir());
        Torrent* lt = leecher.add_torrent(info, dl_dir());
        EXPECT_NE(st, nullptr);
        EXPECT_NE(lt, nullptr);
        if (!st || !lt) return false;

        EXPECT_TRUE(pump_until(seeder, leecher,
                               [&] { return st->state() == Torrent::State::Seeding; }));

        lt->add_peer("127.0.0.1", seeder.listen_port());
        const bool done = pump_until(seeder, leecher, [&] { return lt->is_complete(); }, iters);

        // Verify the bytes really are the bytes, not just that the state machine
        // declared victory: an encryption bug that corrupted the stream would fail
        // the piece hashes, but this pins the on-disk result too.
        if (done) {
            std::ifstream in((stdfs::path(dl_dir()) / "f.bin").string(), std::ios::binary);
            const Bytes got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            EXPECT_EQ(got, data);
        }
        seeder.stop();
        leecher.stop();
        return done;
    }

    std::string base_;
};

} // namespace

// The case this feature exists for: the peer accepts nothing but obfuscated
// connections. Under the default outgoing policy we dial MSE first, so it works
// on the first attempt — where before the fix the peer closed on us every time.
TEST_F(BtMseWire, ReachesAPeerThatRefusesPlaintext) {
    EXPECT_TRUE(transfer(EncPolicy::Enabled, EncPolicy::Forced));
}

TEST_F(BtMseWire, ForcedOnBothSidesTransfersEndToEnd) {
    EXPECT_TRUE(transfer(EncPolicy::Forced, EncPolicy::Forced));
}

// The negative control that gives the tests above their meaning: with the dialer
// unable to obfuscate, the same Forced seeder must refuse it. If this passed, the
// two above would prove nothing.
TEST_F(BtMseWire, ForcedSeederRefusesAPlaintextOnlyDialer) {
    EXPECT_FALSE(transfer(EncPolicy::Disabled, EncPolicy::Forced, /*iters=*/1500));
}

// And the mirror image: a seeder that refuses obfuscation must refuse a dialer
// that will only obfuscate.
TEST_F(BtMseWire, SeederWithEncryptionOffRefusesAnMseOnlyDialer) {
    EXPECT_FALSE(transfer(EncPolicy::Forced, EncPolicy::Disabled, /*iters=*/1500));
}

// Plaintext must keep working exactly as before for peers on both extremes.
TEST_F(BtMseWire, PlaintextStillWorksWithEncryptionDisabled) {
    EXPECT_TRUE(transfer(EncPolicy::Disabled, EncPolicy::Disabled));
}

// The shipping defaults, on both sides.
TEST_F(BtMseWire, DefaultPoliciesInteroperate) {
    EXPECT_TRUE(transfer(EncPolicy::Enabled, EncPolicy::Enabled));
}

// The fast-reconnect path, end to end. The seeder refuses obfuscated connections,
// the leecher's default policy opens with one — so the first dial is rejected and
// the transfer can only happen if the peer is re-dialed in the other form. It is
// the *time limit* that makes this a real test: the reconnect backoff alone would
// be 120 s, so completing inside a few seconds of pumping is only possible because
// a refused handshake waives the wait.
TEST_F(BtMseWire, FallsBackToPlaintextWithoutServingTheBackoff) {
    const Bytes data = make_data(40000);
    TorrentInfo info = build_and_seed("f.bin", data, 16384, seed_dir());

    Client seeder(config(seed_dir(), "-LR0001-", EncPolicy::Enabled, EncPolicy::Disabled));
    Client leecher(config(dl_dir(), "-LR0002-", EncPolicy::Enabled, EncPolicy::Enabled));
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    const auto started = std::chrono::steady_clock::now();
    lt->add_peer("127.0.0.1", seeder.listen_port());
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }, 12000))
        << "progress=" << lt->progress() << " peers=" << lt->num_peers();

    // The redial rides the torrent's one-second tick, so a handful of seconds is
    // plenty of headroom while still being nowhere near a served backoff.
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, std::chrono::seconds(30))
        << "the plaintext retry looks like it waited out the reconnect backoff";

    seeder.stop();
    leecher.stop();
}

// A seeder is the interesting direction for volume: pieces flow seeder -> leecher,
// so a payload large enough to span many messages and partial reads is what would
// expose a cipher whose stream position drifted between the two ends.
TEST_F(BtMseWire, EncryptedTransferSurvivesManyPiecesAndPartialReads) {
    const Bytes data = make_data(600000);          // ~37 pieces
    TorrentInfo info = build_and_seed("big.bin", data, 16384, seed_dir());

    Client seeder(config(seed_dir(), "-LR0001-", EncPolicy::Forced, EncPolicy::Forced));
    Client leecher(config(dl_dir(), "-LR0002-", EncPolicy::Forced, EncPolicy::Forced));
    seeder.open();
    leecher.open();

    Torrent* st = seeder.add_torrent(info, seed_dir());
    Torrent* lt = leecher.add_torrent(info, dl_dir());
    ASSERT_NE(st, nullptr);
    ASSERT_NE(lt, nullptr);
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return st->state() == Torrent::State::Seeding; }));

    lt->add_peer("127.0.0.1", seeder.listen_port());
    ASSERT_TRUE(pump_until(seeder, leecher, [&] { return lt->is_complete(); }, 30000))
        << "progress=" << lt->progress() << " peers=" << lt->num_peers();

    std::ifstream in((stdfs::path(dl_dir()) / "big.bin").string(), std::ios::binary);
    const Bytes got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(got, data);

    seeder.stop();
    leecher.stop();
}
