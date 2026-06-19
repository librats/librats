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

} // namespace

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
