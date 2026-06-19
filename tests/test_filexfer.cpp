#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/file_transfer.h"
#include "fs.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 15s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

NodeConfig listening_config() {
    NodeConfig c; c.bind_address = "127.0.0.1"; c.security = NodeConfig::Security::Noise; return c;
}
NodeConfig dialing_config() { NodeConfig c = listening_config(); c.enable_listen = false; return c; }

std::vector<uint8_t> make_pattern(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>((i * 131 + 7) & 0xFF);
    return v;
}

std::vector<uint8_t> read_all(const std::string& path) {
    size_t n = 0;
    void* p = read_file_binary(path.c_str(), &n);
    if (!p) return {};
    std::vector<uint8_t> v(static_cast<uint8_t*>(p), static_cast<uint8_t*>(p) + n);
    free_file_buffer(p);
    return v;
}

// Two connected nodes, each with a FileTransfer subsystem. `send` lives on the
// dialing client, `recv` on the listening server. Nodes stop on destruction.
struct Pair {
    std::unique_ptr<Node> server, client;
    FileTransfer* recv = nullptr;
    FileTransfer* send = nullptr;
};

Pair make_pair() {
    Pair p;
    p.server = std::make_unique<Node>(listening_config());
    p.client = std::make_unique<Node>(dialing_config());
    auto s = std::make_unique<FileTransfer>(".");
    auto c = std::make_unique<FileTransfer>(".");
    p.recv = s.get();
    p.send = c.get();
    p.server->add_subsystem(std::move(s));
    p.client->add_subsystem(std::move(c));
    return p;
}

bool bring_up(Pair& p) {
    if (!p.server->start() || !p.client->start()) return false;
    p.client->connect("127.0.0.1", p.server->listen_port());
    return wait_for([&] { return p.client->peer_count() == 1 && p.server->peer_count() == 1; });
}

} // namespace

// The path-traversal guard is the fix for the CRITICAL directory-manifest
// vulnerability: a peer must not be able to write outside the chosen directory.
TEST(FilexferUnit, IsSafeRelativePath) {
    EXPECT_TRUE(FileTransfer::is_safe_relative_path("a.txt"));
    EXPECT_TRUE(FileTransfer::is_safe_relative_path("sub/dir/file.bin"));
    EXPECT_FALSE(FileTransfer::is_safe_relative_path(""));
    EXPECT_FALSE(FileTransfer::is_safe_relative_path("/etc/passwd"));
    EXPECT_FALSE(FileTransfer::is_safe_relative_path("../escape"));
    EXPECT_FALSE(FileTransfer::is_safe_relative_path("a/../../b"));
    EXPECT_FALSE(FileTransfer::is_safe_relative_path("..\\..\\x"));
    EXPECT_FALSE(FileTransfer::is_safe_relative_path("C:\\windows"));
    EXPECT_FALSE(FileTransfer::is_safe_relative_path("a/./b"));
}

// send_file on a path that is not a readable file returns 0 (no transfer).
TEST(FilexferTest, SendMissingFileReturnsZero) {
    Pair p = make_pair();
    ASSERT_TRUE(bring_up(p));
    EXPECT_EQ(p.send->send_file(p.server->local_id(), "no_such_file_12345.bin"), 0u);
}

// A zero-byte file round-trips: no chunks, just the per-file SHA marker.
TEST(FilexferTest, SendsEmptyFile) {
    const std::string src = "ft_empty_src.bin", dst = "ft_empty_dst.bin";
    ASSERT_TRUE(create_file_binary(src.c_str(), "", 0));
    delete_file(dst.c_str());

    Pair p = make_pair();
    std::atomic<bool> rdone{false}, rok{false}, sdone{false}, sok{false};
    p.recv->on_offer([&](const FileTransfer::Offer& o) { p.recv->accept(o.from, o.id, dst); });
    p.recv->on_complete([&](uint64_t, bool ok, const std::string&) { rok = ok; rdone = true; });
    p.send->on_complete([&](uint64_t, bool ok, const std::string&) { sok = ok; sdone = true; });
    ASSERT_TRUE(bring_up(p));

    ASSERT_NE(p.send->send_file(p.server->local_id(), src), 0u);
    ASSERT_TRUE(wait_for([&] { return rdone.load() && sdone.load(); }));
    EXPECT_TRUE(rok.load());
    EXPECT_TRUE(sok.load());
    EXPECT_TRUE(file_exists(dst.c_str()));
    EXPECT_EQ(read_all(dst).size(), 0u);

    delete_file(src.c_str());
    delete_file(dst.c_str());
}

// A whole directory tree (with a subdirectory) is streamed and recreated under
// the chosen destination, every file intact.
TEST(FilexferTest, SendsDirectoryTree) {
    delete_directory("ft_srcdir");
    delete_directory("ft_dstdir");
    ASSERT_TRUE(create_directories("ft_srcdir/sub"));
    const auto a = make_pattern(100 * 1024 + 7);
    const auto b = make_pattern(64 * 1024);            // exactly one chunk
    const auto c = make_pattern(5);
    ASSERT_TRUE(create_file_binary("ft_srcdir/a.bin", a.data(), a.size()));
    ASSERT_TRUE(create_file_binary("ft_srcdir/sub/b.bin", b.data(), b.size()));
    ASSERT_TRUE(create_file_binary("ft_srcdir/sub/c.bin", c.data(), c.size()));

    Pair p = make_pair();
    std::atomic<bool> rdone{false}, rok{false};
    p.recv->on_offer([&](const FileTransfer::Offer& o) {
        EXPECT_TRUE(o.is_directory);
        EXPECT_EQ(o.files.size(), 3u);
        p.recv->accept(o.from, o.id, "ft_dstdir");
    });
    p.recv->on_complete([&](uint64_t, bool ok, const std::string&) { rok = ok; rdone = true; });
    ASSERT_TRUE(bring_up(p));

    ASSERT_NE(p.send->send_directory(p.server->local_id(), "ft_srcdir"), 0u);
    ASSERT_TRUE(wait_for([&] { return rdone.load(); }));
    EXPECT_TRUE(rok.load());
    EXPECT_EQ(read_all("ft_dstdir/a.bin"), a);
    EXPECT_EQ(read_all("ft_dstdir/sub/b.bin"), b);
    EXPECT_EQ(read_all("ft_dstdir/sub/c.bin"), c);

    delete_directory("ft_srcdir");
    delete_directory("ft_dstdir");
}

// Cancelling mid-transfer (from the receiver, on first progress) fails both
// sides cleanly and leaves no completed destination file.
TEST(FilexferTest, ReceiverCancelMidTransfer) {
    const std::string src = "ft_cancel_src.bin", dst = "ft_cancel_dst.bin";
    const auto content = make_pattern(4 * 1024 * 1024);
    ASSERT_TRUE(create_file_binary(src.c_str(), content.data(), content.size()));
    delete_file(dst.c_str());

    Pair p = make_pair();
    std::atomic<bool> rdone{false}, rok{true}, sdone{false}, sok{true}, cancelled{false};
    p.recv->on_offer([&](const FileTransfer::Offer& o) { p.recv->accept(o.from, o.id, dst); });
    p.recv->on_progress([&](const FileTransfer::Progress& pr) {
        if (pr.direction == FileTransfer::Direction::Receiving && pr.bytes_transferred > 0 &&
            !cancelled.exchange(true)) {
            p.recv->cancel(pr.peer, pr.id);
        }
    });
    p.recv->on_complete([&](uint64_t, bool ok, const std::string&) { rok = ok; rdone = true; });
    p.send->on_complete([&](uint64_t, bool ok, const std::string&) { sok = ok; sdone = true; });
    ASSERT_TRUE(bring_up(p));

    ASSERT_NE(p.send->send_file(p.server->local_id(), src), 0u);
    ASSERT_TRUE(wait_for([&] { return rdone.load() && sdone.load(); }));
    EXPECT_FALSE(rok.load());
    EXPECT_FALSE(sok.load());
    EXPECT_NE(read_all(dst), content);  // destination never completed

    delete_file(src.c_str());
    delete_file(dst.c_str());
}

// Pausing an in-flight transfer halts streaming; resuming finishes it intact.
TEST(FilexferTest, PauseAndResume) {
    const std::string src = "ft_pause_src.bin", dst = "ft_pause_dst.bin";
    const auto content = make_pattern(4 * 1024 * 1024);
    ASSERT_TRUE(create_file_binary(src.c_str(), content.data(), content.size()));
    delete_file(dst.c_str());

    Pair p = make_pair();
    const PeerId server_id = p.server->local_id();
    std::atomic<bool> rdone{false}, rok{false}, sdone{false}, sok{false}, paused{false};
    std::atomic<uint64_t> tid{0};

    p.recv->on_offer([&](const FileTransfer::Offer& o) { p.recv->accept(o.from, o.id, dst); });
    p.recv->on_complete([&](uint64_t, bool ok, const std::string&) { rok = ok; rdone = true; });
    p.send->on_complete([&](uint64_t, bool ok, const std::string&) { sok = ok; sdone = true; });
    p.send->on_progress([&](const FileTransfer::Progress& pr) {
        if (pr.direction == FileTransfer::Direction::Sending && pr.bytes_transferred > 0 &&
            !paused.exchange(true)) {
            tid = pr.id;
            EXPECT_TRUE(p.send->pause(pr.peer, pr.id));
        }
    });
    ASSERT_TRUE(bring_up(p));

    const uint64_t id = p.send->send_file(server_id, src);
    ASSERT_NE(id, 0u);
    ASSERT_TRUE(wait_for([&] { return paused.load(); }));
    std::this_thread::sleep_for(200ms);
    EXPECT_FALSE(sdone.load()) << "transfer completed while paused";

    EXPECT_TRUE(p.send->resume(server_id, id));
    ASSERT_TRUE(wait_for([&] { return rdone.load() && sdone.load(); }));
    EXPECT_TRUE(rok.load());
    EXPECT_TRUE(sok.load());
    EXPECT_EQ(read_all(dst), content);

    delete_file(src.c_str());
    delete_file(dst.c_str());
}

// Several transfers between the same pair run concurrently and all succeed.
TEST(FilexferTest, ConcurrentTransfers) {
    const std::vector<std::pair<std::string, size_t>> specs = {
        {"ft_c0.bin", 300 * 1024}, {"ft_c1.bin", 17}, {"ft_c2.bin", 1024 * 1024 + 9}};
    std::vector<std::vector<uint8_t>> contents;
    for (auto& s : specs) {
        contents.push_back(make_pattern(s.second));
        ASSERT_TRUE(create_file_binary(s.first.c_str(), contents.back().data(), contents.back().size()));
    }

    Pair p = make_pair();
    std::atomic<int> completed{0}, ok_count{0};
    p.recv->on_offer([&](const FileTransfer::Offer& o) { p.recv->accept(o.from, o.id, "ftd_" + o.name); });
    p.recv->on_complete([&](uint64_t, bool ok, const std::string&) {
        if (ok) ok_count.fetch_add(1);
        completed.fetch_add(1);
    });
    ASSERT_TRUE(bring_up(p));

    for (auto& s : specs) ASSERT_NE(p.send->send_file(p.server->local_id(), s.first), 0u);
    ASSERT_TRUE(wait_for([&] { return completed.load() == static_cast<int>(specs.size()); }));
    EXPECT_EQ(ok_count.load(), static_cast<int>(specs.size()));

    for (size_t i = 0; i < specs.size(); ++i)
        EXPECT_EQ(read_all("ftd_" + specs[i].first), contents[i]);

    for (auto& s : specs) { delete_file(s.first.c_str()); delete_file(("ftd_" + s.first).c_str()); }
}

// Push a multi-MB file end to end (exercising the sliding window + progress
// acks) and verify the bytes arrive intact past the SHA-256 check.
TEST(FilexferTest, SendsFileWithIntegrity) {
    const std::string src = "ft_src.bin";
    const std::string dst = "ft_dst.bin";
    const auto content = make_pattern(2 * 1024 * 1024 + 123);  // ~2MB, not chunk-aligned
    ASSERT_TRUE(create_file_binary(src.c_str(), content.data(), content.size()));
    delete_file(dst.c_str());

    Node server(listening_config());
    Node client(dialing_config());

    auto server_ft = std::make_unique<FileTransfer>(".");
    auto client_ft = std::make_unique<FileTransfer>(".");
    FileTransfer* recv = server_ft.get();
    FileTransfer* send = client_ft.get();
    server.add_subsystem(std::move(server_ft));
    client.add_subsystem(std::move(client_ft));

    std::atomic<bool> recv_done{false}, recv_ok{false};
    std::atomic<bool> send_done{false}, send_ok{false};

    recv->on_offer([&](const FileTransfer::Offer& offer) { recv->accept(offer.from, offer.id, dst); });
    recv->on_complete([&](uint64_t, bool ok, const std::string&) { recv_ok = ok; recv_done = true; });
    send->on_complete([&](uint64_t, bool ok, const std::string&) { send_ok = ok; send_done = true; });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1 && server.peer_count() == 1; }));

    const uint64_t id = send->send_file(server.local_id(), src);
    ASSERT_NE(id, 0u);

    ASSERT_TRUE(wait_for([&] { return recv_done.load() && send_done.load(); }))
        << "transfer did not finish";
    EXPECT_TRUE(recv_ok.load());
    EXPECT_TRUE(send_ok.load());

    EXPECT_EQ(read_all(dst), content);

    client.stop();
    server.stop();
    delete_file(src.c_str());
    delete_file(dst.c_str());
}

// A rejected offer completes (unsuccessfully) on the sender without writing.
TEST(FilexferTest, RejectedOfferFailsCleanly) {
    const std::string src = "ft_reject_src.bin";
    const auto content = make_pattern(4096);
    ASSERT_TRUE(create_file_binary(src.c_str(), content.data(), content.size()));

    Node server(listening_config());
    Node client(dialing_config());

    auto server_ft = std::make_unique<FileTransfer>(".");
    auto client_ft = std::make_unique<FileTransfer>(".");
    FileTransfer* recv = server_ft.get();
    FileTransfer* send = client_ft.get();
    server.add_subsystem(std::move(server_ft));
    client.add_subsystem(std::move(client_ft));

    std::atomic<bool> send_done{false}, send_ok{true};
    recv->on_offer([&](const FileTransfer::Offer& offer) { recv->reject(offer.from, offer.id); });
    send->on_complete([&](uint64_t, bool ok, const std::string&) { send_ok = ok; send_done = true; });

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    client.connect("127.0.0.1", server.listen_port());
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; }));

    send->send_file(server.local_id(), src);
    ASSERT_TRUE(wait_for([&] { return send_done.load(); }));
    EXPECT_FALSE(send_ok.load());

    client.stop();
    server.stop();
    delete_file(src.c_str());
}
