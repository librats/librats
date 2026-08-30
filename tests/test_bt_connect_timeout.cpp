#include <gtest/gtest.h>

#include "librats/bittorrent/client.h"
#include "librats/bittorrent/torrent_info.h"
#include "librats/bittorrent/types.h"
#include "librats/bittorrent/bencode.h"
#include "librats/crypto/sha1.h"
#include "librats/core/socket.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>

using namespace librats;
using namespace librats::bittorrent;

// An outbound connect that never completes used to be abandoned only by the OS SYN
// retry — ~21 s on Windows, longer on Linux — and for all that time the address sat
// `connecting` in the PeerList, neither retried nor penalised, holding a socket.
// Client::Config::connect_timeout is the deadline that replaces it. These tests
// cover both halves of the race between that deadline and the connect completing.

namespace {

std::string temp_dir(const char* name) {
    const std::string dir = (std::filesystem::path(::testing::TempDir()) / name).string();
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    return dir;
}

Bytes build_info(std::uint32_t plen, std::uint32_t pieces) {
    std::string hashes;
    for (std::uint32_t p = 0; p < pieces; ++p) {
        const std::uint8_t seed = std::uint8_t(p);
        auto h = librats::SHA1::hash_raw(&seed, 1);
        hashes.append(reinterpret_cast<const char*>(h.data()), 20);
    }
    BencodeValue info = BencodeValue::create_dict();
    info["name"]         = BencodeValue(std::string("f.bin"));
    info["length"]       = BencodeValue(std::int64_t(plen) * pieces);
    info["piece length"] = BencodeValue(std::int64_t(plen));
    info["pieces"]       = BencodeValue(hashes);
    return info.encode();
}

Bytes make_handshake(const InfoHash& ih) {
    Bytes h;
    h.push_back(19);
    const char proto[] = "BitTorrent protocol";
    h.insert(h.end(), proto, proto + 19);
    const std::uint8_t reserved[8] = {0};
    h.insert(h.end(), reserved, reserved + 8);
    h.insert(h.end(), ih.begin(), ih.end());
    const std::string id = "-XX0000-abcdefghijkl";
    h.insert(h.end(), id.begin(), id.end());
    return h;
}

// Pump the reactor until `done` or `ms` elapse. Returns done()'s final value.
bool pump_until(Client& c, const std::function<bool()>& done, int ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < deadline) {
        c.reactor().run_one(5);
        if (done()) return true;
    }
    return done();
}

} // namespace

// 192.0.2.0/24 is TEST-NET-1 (RFC 5737): reserved for documentation and never
// routed, so a SYN to it is dropped rather than answered. Without the deadline the
// socket stays pending until the OS gives up; with it, the client reclaims the
// socket on its own schedule. The 3 s bound is far below every OS connect timeout,
// so this fails without the fix even on the slowest of them.
//
// (If a particular network answers TEST-NET-1 with an ICMP unreachable the connect
// fails immediately instead and the socket is reclaimed through the completion path
// — the assertion below still holds, it just proves less on that machine.)
TEST(BtConnectTimeout, AbandonsUnreachablePeerAtTheDeadline) {
    const std::string dir = temp_dir("librats_bt_connto");
    auto info = TorrentInfo::from_info_dict(build_info(16384, 4), InfoHash{});
    ASSERT_TRUE(info);

    Client::Config cfg{};
    cfg.listen_port      = 0;
    cfg.download_path    = dir;
    cfg.peer_id_prefix   = "-LR0004-";
    cfg.connect_timeout  = std::chrono::milliseconds(200);
    // This is the *TCP* connect deadline, and num_pending_connects() only counts TCP
    // dials — a uTP dial has no half-open state to track (it is a datagram exchange
    // with its own timeout). Left on, the default uTP-first policy would mean no TCP
    // connect ever starts and the test would measure nothing.
    cfg.enable_outgoing_utp = false;

    Client c(cfg);
    c.open();
    Torrent* t = c.add_torrent(*info, dir);
    ASSERT_TRUE(t);

    t->add_peer("192.0.2.1", 6881);
    // add_peer posts try_connect(); one pump is enough to get the dial started.
    ASSERT_TRUE(pump_until(c, [&] { return c.num_pending_connects() == 1; }, 1000))
        << "the dial never started";

    EXPECT_TRUE(pump_until(c, [&] { return c.num_pending_connects() == 0; }, 3000))
        << "an unreachable peer was still pending 3 s in — the connect deadline "
           "did not fire, so only the OS timeout would ever reclaim it";

    c.stop();
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

// The other half of the race: a connect that completes must cancel its deadline.
// If it did not, the timer would later close a socket a live PeerConnection now
// owns, tearing down a working peer (and freeing an fd out from under it).
TEST(BtConnectTimeout, CompletedConnectSurvivesItsDeadline) {
    const std::string dir = temp_dir("librats_bt_connok");
    auto info = TorrentInfo::from_info_dict(build_info(16384, 4), InfoHash{});
    ASSERT_TRUE(info);
    const InfoHash ih = info->info_hash();

    // A listener that accepts once and answers with a valid handshake, so the dial
    // turns into a real peer rather than being dropped as a protocol error.
    socket_t server = create_tcp_server(0, 4, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(server));
    const int server_port = get_bound_port(server);
    ASSERT_GT(server_port, 0);

    std::atomic<bool> stop{false};
    std::thread peer([&] {
        socket_t s = accept_client(server);
        if (!is_valid_socket(s)) return;
        send_tcp_data(s, make_handshake(ih));
        while (!stop.load()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        close_socket(s);
    });

    Client::Config cfg{};
    cfg.listen_port     = 0;
    cfg.download_path   = dir;
    cfg.peer_id_prefix  = "-LR0005-";
    cfg.connect_timeout = std::chrono::milliseconds(100);  // short, so it would bite
    // The fake peer above answers a plaintext handshake and nothing else. This test
    // is about the connect deadline, not about encryption, so dial in the clear
    // rather than have the default MSE-first policy stall against a peer that
    // cannot complete it — see test_bt_mse_wire.cpp for the obfuscated path.
    cfg.out_enc_policy  = EncPolicy::Disabled;
    // Same reason as above, plus: the fake peer is a TCP listener, so a uTP dial
    // would simply spend its 3 s connect timeout before falling back. Nothing to do
    // with the deadline under test.
    cfg.enable_outgoing_utp = false;

    Client c(cfg);
    c.open();
    Torrent* t = c.add_torrent(*info, dir);
    ASSERT_TRUE(t);

    t->add_peer("127.0.0.1", std::uint16_t(server_port));
    // EXPECT, not ASSERT: an early return here would skip the join below and leave
    // a running std::thread to be destroyed, which terminates the whole binary and
    // buries whatever actually went wrong.
    EXPECT_TRUE(pump_until(c, [&] { return c.torrent_status(ih).num_peers == 1; }, 5000))
        << "the local peer never completed its handshake";
    EXPECT_EQ(c.num_pending_connects(), 0u);  // the completion took it off the list

    // Well past connect_timeout: a deadline that was not cancelled fires in here.
    pump_until(c, [] { return false; }, 600);
    EXPECT_EQ(c.torrent_status(ih).num_peers, 1u)
        << "an established peer was torn down by its own (stale) connect deadline";

    stop.store(true);
    peer.join();
    close_socket(server);
    c.stop();
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
