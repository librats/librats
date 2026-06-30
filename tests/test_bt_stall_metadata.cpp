#include <gtest/gtest.h>

#include "bittorrent/client.h"
#include "bittorrent/torrent_info.h"
#include "bittorrent/extensions.h"
#include "bittorrent/types.h"
#include "bittorrent/bencode.h"
#include "crypto/sha1.h"
#include "core/socket.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>
#include <vector>

using namespace librats;
using namespace librats::bittorrent;

namespace {

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

Bytes make_data(std::size_t n) {
    Bytes d(n);
    std::uint32_t x = 0x1234u;
    for (std::size_t i = 0; i < n; ++i) { x = x * 1103515245u + 12345u; d[i] = std::uint8_t(x >> 16); }
    return d;
}

// A .torrent info dict with fully known metadata (single file).
Bytes build_info(const Bytes& data, std::uint32_t plen) {
    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(std::string("f.bin"));
    info["length"]       = BencodeValue(std::int64_t(data.size()));
    info["piece length"] = BencodeValue(std::int64_t(plen));
    info["pieces"]       = BencodeValue(piece_hashes_for(data, plen));
    return info.encode();
}

// ---- raw BitTorrent wire helpers (this is a hand-rolled fake peer) ----

Bytes make_handshake(const InfoHash& ih, bool extensions) {
    Bytes h;
    h.push_back(19);
    const char proto[] = "BitTorrent protocol";
    h.insert(h.end(), proto, proto + 19);
    std::uint8_t reserved[8] = {0};
    if (extensions) reserved[5] |= 0x10;
    h.insert(h.end(), reserved, reserved + 8);
    h.insert(h.end(), ih.begin(), ih.end());
    for (int i = 0; i < 20; ++i) h.push_back(std::uint8_t('A' + (i % 26)));  // arbitrary peer id
    return h;
}

Bytes wire_msg(std::uint8_t id, const Bytes& payload = {}) {
    Bytes m;
    const std::uint32_t len = std::uint32_t(1 + payload.size());
    m.push_back(std::uint8_t(len >> 24)); m.push_back(std::uint8_t(len >> 16));
    m.push_back(std::uint8_t(len >> 8));  m.push_back(std::uint8_t(len));
    m.push_back(id);
    m.insert(m.end(), payload.begin(), payload.end());
    return m;
}

} // namespace

// C1: a peer that advertises pieces and unchokes us, then never delivers, must be
// snubbed — its outstanding requests are freed — rather than stalling forever.
TEST(BtStall, StalledPeerRequestsAreFreed) {
    const std::string dir = (std::filesystem::path(::testing::TempDir()) / "librats_bt_stall").string();
    std::error_code ec; std::filesystem::remove_all(dir, ec);

    const std::uint32_t plen = 16384;
    const Bytes data = make_data(plen * 8);                 // 8 pieces
    const Bytes info_bytes = build_info(data, plen);
    auto info = TorrentInfo::from_info_dict(info_bytes, InfoHash{});
    ASSERT_TRUE(info);

    Client leecher(Client::Config{0, dir, "-LR0002-"});
    leecher.open();
    Torrent* lt = leecher.add_torrent(*info, dir);
    ASSERT_TRUE(lt);
    lt->set_request_timeout(std::chrono::milliseconds(150));  // snub quickly for the test

    const InfoHash ih = info->info_hash();
    const std::uint32_t np = info->num_pieces();
    const std::uint16_t port = leecher.listen_port();

    std::atomic<bool> stop{false};
    std::thread peer([&] {
        socket_t s = create_tcp_client("127.0.0.1", int(port), 2000);
        if (!is_valid_socket(s)) return;
        send_tcp_data(s, make_handshake(ih, /*extensions=*/false));
        Bytes bf((np + 7) / 8, 0xFF);                        // "I have every piece"
        send_tcp_data(s, wire_msg(5, bf));                   // bitfield
        send_tcp_data(s, wire_msg(1));                       // unchoke — but never send any piece
        while (!stop.load()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        close_socket(s);
    });

    auto pump_until = [&](const std::function<bool()>& done, int ms) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            leecher.reactor().run_one(5);
            if (done()) return true;
        }
        return done();
    };

    // The leecher unchokes → requests blocks from the (stalling) peer.
    ASSERT_TRUE(pump_until([&] { return lt->num_outstanding_requests() > 0; }, 3000))
        << "leecher never sent requests to the peer";

    // The 1 s tick runs check_request_timeouts(); with a 150 ms timeout the stalled
    // peer's blocks are freed, dropping outstanding back to 0.
    EXPECT_TRUE(pump_until([&] { return lt->num_outstanding_requests() == 0; }, 3000))
        << "stalled peer's requests were never freed (C1)";

    stop.store(true);
    peer.join();
    leecher.stop();
    std::filesystem::remove_all(dir, ec);
}

// C2-race: with the reactor running on its own thread (start()), the public Client
// mutators must marshal onto the reactor rather than racing it. This drives the
// run_on_reactor() post-and-wait path — a bug there would deadlock or crash.
TEST(BtClientThreading, MutatorsFromAnotherThreadAreSafe) {
    const std::string dir = (std::filesystem::path(::testing::TempDir()) / "librats_bt_thr").string();
    std::error_code ec; std::filesystem::remove_all(dir, ec);

    const std::uint32_t plen = 16384;
    const Bytes data = make_data(plen * 2);
    auto info = TorrentInfo::from_info_dict(build_info(data, plen), InfoHash{});
    ASSERT_TRUE(info);

    Client c(Client::Config{0, dir, "-LR0003-"});
    c.start();  // reactor now runs on its own thread; this test thread is NOT it

    Torrent* t = c.add_torrent(*info, dir);   // marshalled via run_on_reactor
    EXPECT_NE(t, nullptr);
    EXPECT_EQ(c.num_torrents(), 1u);

    c.remove_torrent(info->info_hash());       // also marshalled
    EXPECT_EQ(c.num_torrents(), 0u);

    c.stop();
    std::filesystem::remove_all(dir, ec);
}

// C3: a peer advertising an absurd ut_metadata size must not drive a huge buffer
// allocation. The leecher stays without metadata and does not crash / OOM.
TEST(BtStall, HugeMetadataSizeIsRejected) {
    const std::string dir = (std::filesystem::path(::testing::TempDir()) / "librats_bt_meta").string();
    std::error_code ec; std::filesystem::remove_all(dir, ec);

    const std::uint32_t plen = 16384;
    const Bytes data = make_data(plen * 4);
    auto info = TorrentInfo::from_info_dict(build_info(data, plen), InfoHash{});
    ASSERT_TRUE(info);
    const InfoHash ih = info->info_hash();
    const std::string magnet = "magnet:?xt=urn:btih:" + to_hex(ih);

    Client leecher(Client::Config{0, dir, "-LR0002-"});
    leecher.open();
    Torrent* lt = leecher.add_magnet(magnet, dir);
    ASSERT_TRUE(lt);
    const std::uint16_t port = leecher.listen_port();

    std::atomic<bool> stop{false};
    std::thread peer([&] {
        socket_t s = create_tcp_client("127.0.0.1", int(port), 2000);
        if (!is_valid_socket(s)) return;
        send_tcp_data(s, make_handshake(ih, /*extensions=*/true));
        // Extended handshake (ext id 0) advertising a ~4 GiB metadata size.
        const Bytes eh = ext::encode_handshake(0xFFFFFFFFu, 6881);
        Bytes payload; payload.push_back(0); payload.insert(payload.end(), eh.begin(), eh.end());
        send_tcp_data(s, wire_msg(20, payload));
        while (!stop.load()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        close_socket(s);
    });

    // Pump well past the point where the handshake is processed. With the cap in
    // place this is a no-op; without it, ensure_metadata_buffer would attempt a
    // multi-gigabyte allocation and crash the test.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
    while (std::chrono::steady_clock::now() < deadline) leecher.reactor().run_one(5);

    EXPECT_FALSE(lt->has_metadata());
    EXPECT_EQ(lt->state(), Torrent::State::Metadata);

    stop.store(true);
    peer.join();
    leecher.stop();
    std::filesystem::remove_all(dir, ec);
}
