#include <gtest/gtest.h>

#include "file_transfer.h"
#include "librats.h"
#include "fs.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

using namespace librats;
using namespace std::chrono_literals;

// =============================================================================
// Helpers
// =============================================================================

namespace {

// Writes `size` bytes of deterministic pseudo-random data.
void write_test_file(const std::string& path, size_t size) {
    std::ofstream f(path, std::ios::binary);
    ASSERT_TRUE(f.is_open()) << "cannot create " << path;
    std::vector<char> buf(size);
    uint32_t s = 0x9E3779B9u ^ static_cast<uint32_t>(size);
    for (size_t i = 0; i < size; ++i) {
        s = s * 1664525u + 1013904223u;
        buf[i] = static_cast<char>(s >> 24);
    }
    if (size) f.write(buf.data(), static_cast<std::streamsize>(size));
}

// True when both files exist and have identical content.
bool files_identical(const std::string& a, const std::string& b) {
    std::string ha = FileTransferManager::compute_file_sha256(a);
    std::string hb = FileTransferManager::compute_file_sha256(b);
    return !ha.empty() && ha == hb;
}

} // namespace

// =============================================================================
// Pure unit tests (no networking)
// =============================================================================

TEST(FileTransferUnit, StatusNames) {
    EXPECT_STREQ("IN_PROGRESS", file_transfer_status_name(FileTransferStatus::IN_PROGRESS));
    EXPECT_STREQ("COMPLETED", file_transfer_status_name(FileTransferStatus::COMPLETED));
    EXPECT_STREQ("FAILED", file_transfer_status_name(FileTransferStatus::FAILED));
}

TEST(FileTransferUnit, ConfigDefaults) {
    FileTransferConfig cfg;
    EXPECT_GT(cfg.chunk_size, 0u);
    EXPECT_GT(cfg.window_bytes, cfg.chunk_size);
    EXPECT_TRUE(cfg.verify_integrity);
}

TEST(FileTransferUnit, Sha256Utility) {
    create_directories("ft_unit");
    write_test_file("ft_unit/a.bin", 4096);
    write_test_file("ft_unit/b.bin", 4096);
    std::string ha = FileTransferManager::compute_file_sha256("ft_unit/a.bin");
    EXPECT_EQ(64u, ha.size());
    EXPECT_EQ(ha, FileTransferManager::compute_file_sha256("ft_unit/b.bin"));
    EXPECT_TRUE(FileTransferManager::compute_file_sha256("ft_unit/missing.bin").empty());
}

// =============================================================================
// End-to-end transfer tests (two connected RatsClients)
// =============================================================================

class FileTransferTest : public ::testing::Test {
protected:
    void SetUp() override {
        create_directories("ft_test");
        create_directories("ft_test/src");
        create_directories("ft_test/dst");

        sender_ = std::make_unique<RatsClient>(kSenderPort, 8);
        receiver_ = std::make_unique<RatsClient>(kReceiverPort, 8);

        ASSERT_TRUE(sender_->is_file_transfer_available());
        ASSERT_TRUE(receiver_->is_file_transfer_available());

        // Small chunks / window so the windowed path and pause/resume are
        // genuinely exercised by modestly-sized test files.
        FileTransferConfig cfg;
        cfg.temp_directory = "ft_test/tmp";
        cfg.chunk_size = 4096;
        cfg.window_bytes = 32 * 1024;
        cfg.progress_interval = 8 * 1024;
        cfg.transfer_timeout_secs = 30;
        sender_->set_file_transfer_config(cfg);
        receiver_->set_file_transfer_config(cfg);

        // Receiver records every incoming offer.
        receiver_->on_file_transfer_request([this](const IncomingTransferOffer& offer) {
            std::lock_guard<std::mutex> lk(mu_);
            offers_.push_back(offer);
            cv_.notify_all();
        });
        // Both sides record completion.
        sender_->on_file_transfer_completed(
            [this](const std::string& id, bool ok, const std::string& err) {
                std::lock_guard<std::mutex> lk(mu_);
                sender_done_[id] = {ok, err};
                cv_.notify_all();
            });
        receiver_->on_file_transfer_completed(
            [this](const std::string& id, bool ok, const std::string& err) {
                std::lock_guard<std::mutex> lk(mu_);
                receiver_done_[id] = {ok, err};
                cv_.notify_all();
            });

        ASSERT_TRUE(sender_->start());
        ASSERT_TRUE(receiver_->start());
        std::this_thread::sleep_for(100ms);

        ASSERT_TRUE(receiver_->connect_to_peer("127.0.0.1", kSenderPort));

        // Wait for the handshake to validate the peer on the sender side.
        for (int i = 0; i < 100 && sender_->get_validated_peers().empty(); ++i) {
            std::this_thread::sleep_for(20ms);
        }
        auto peers = sender_->get_validated_peers();
        ASSERT_FALSE(peers.empty()) << "peers did not connect";
        receiver_peer_id_ = peers.front().peer_id;
    }

    void TearDown() override {
        if (sender_) sender_->stop();
        if (receiver_) receiver_->stop();
        sender_.reset();
        receiver_.reset();
    }

    // Blocks until an offer arrives; returns false on timeout.
    bool wait_offer(IncomingTransferOffer& out, int ms = 5000) {
        std::unique_lock<std::mutex> lk(mu_);
        if (!cv_.wait_for(lk, std::chrono::milliseconds(ms),
                          [this] { return !offers_.empty(); })) {
            return false;
        }
        out = offers_.front();
        offers_.erase(offers_.begin());
        return true;
    }

    bool wait_receiver_done(const std::string& id, bool& ok, int ms = 15000) {
        std::unique_lock<std::mutex> lk(mu_);
        if (!cv_.wait_for(lk, std::chrono::milliseconds(ms),
                          [&] { return receiver_done_.count(id) != 0; })) {
            return false;
        }
        ok = receiver_done_[id].first;
        return true;
    }

    bool wait_sender_done(const std::string& id, bool& ok, int ms = 15000) {
        std::unique_lock<std::mutex> lk(mu_);
        if (!cv_.wait_for(lk, std::chrono::milliseconds(ms),
                          [&] { return sender_done_.count(id) != 0; })) {
            return false;
        }
        ok = sender_done_[id].first;
        return true;
    }

    static constexpr int kSenderPort = 19601;
    static constexpr int kReceiverPort = 19602;

    std::unique_ptr<RatsClient> sender_;
    std::unique_ptr<RatsClient> receiver_;
    std::string receiver_peer_id_;

    std::mutex mu_;
    std::condition_variable cv_;
    std::vector<IncomingTransferOffer> offers_;
    std::map<std::string, std::pair<bool, std::string>> sender_done_;
    std::map<std::string, std::pair<bool, std::string>> receiver_done_;
};

// --- a single file, accepted and fully verified ---
TEST_F(FileTransferTest, SendSingleFile) {
    const std::string src = "ft_test/src/single.bin";
    const std::string dst = "ft_test/dst/single.bin";
    write_test_file(src, 50 * 1024);

    std::string id = sender_->send_file(receiver_peer_id_, src);
    ASSERT_FALSE(id.empty());

    IncomingTransferOffer offer;
    ASSERT_TRUE(wait_offer(offer));
    EXPECT_EQ(id, offer.transfer_id);
    EXPECT_FALSE(offer.is_directory);
    EXPECT_EQ(50u * 1024u, offer.total_size);
    ASSERT_EQ(1u, offer.files.size());

    ASSERT_TRUE(receiver_->accept_file_transfer(offer.transfer_id, dst));

    bool ok = false;
    ASSERT_TRUE(wait_receiver_done(id, ok)) << "receiver did not finish";
    EXPECT_TRUE(ok);
    EXPECT_TRUE(wait_sender_done(id, ok));
    EXPECT_TRUE(ok);

    EXPECT_TRUE(files_identical(src, dst));
}

// --- a zero-byte file ---
TEST_F(FileTransferTest, SendEmptyFile) {
    const std::string src = "ft_test/src/empty.bin";
    const std::string dst = "ft_test/dst/empty.bin";
    write_test_file(src, 0);

    std::string id = sender_->send_file(receiver_peer_id_, src);
    ASSERT_FALSE(id.empty());

    IncomingTransferOffer offer;
    ASSERT_TRUE(wait_offer(offer));
    ASSERT_TRUE(receiver_->accept_file_transfer(offer.transfer_id, dst));

    bool ok = false;
    ASSERT_TRUE(wait_receiver_done(id, ok));
    EXPECT_TRUE(ok);
    EXPECT_TRUE(file_exists(dst));
    EXPECT_EQ(0, get_file_size(dst.c_str()));
}

// --- a file larger than the window, exercising backpressure ---
TEST_F(FileTransferTest, LargeFileBackpressure) {
    const std::string src = "ft_test/src/large.bin";
    const std::string dst = "ft_test/dst/large.bin";
    write_test_file(src, 512 * 1024); // 16x the 32 KiB window

    std::string id = sender_->send_file(receiver_peer_id_, src);
    ASSERT_FALSE(id.empty());

    IncomingTransferOffer offer;
    ASSERT_TRUE(wait_offer(offer));
    ASSERT_TRUE(receiver_->accept_file_transfer(offer.transfer_id, dst));

    bool ok = false;
    ASSERT_TRUE(wait_receiver_done(id, ok));
    EXPECT_TRUE(ok);
    EXPECT_TRUE(files_identical(src, dst));
}

// --- a directory tree, including nested folders and an empty file ---
TEST_F(FileTransferTest, SendDirectory) {
    create_directories("ft_test/src/tree");
    create_directories("ft_test/src/tree/sub");
    create_directories("ft_test/src/tree/sub/deep");
    write_test_file("ft_test/src/tree/root.txt", 3000);
    write_test_file("ft_test/src/tree/blank.txt", 0);
    write_test_file("ft_test/src/tree/sub/mid.bin", 20 * 1024);
    write_test_file("ft_test/src/tree/sub/deep/leaf.bin", 7777);

    std::string id = sender_->send_directory(receiver_peer_id_, "ft_test/src/tree");
    ASSERT_FALSE(id.empty());

    IncomingTransferOffer offer;
    ASSERT_TRUE(wait_offer(offer));
    EXPECT_TRUE(offer.is_directory);
    EXPECT_EQ(4u, offer.files.size());

    ASSERT_TRUE(receiver_->accept_file_transfer(offer.transfer_id, "ft_test/dst/tree"));

    bool ok = false;
    ASSERT_TRUE(wait_receiver_done(id, ok));
    EXPECT_TRUE(ok);

    EXPECT_TRUE(files_identical("ft_test/src/tree/root.txt", "ft_test/dst/tree/root.txt"));
    EXPECT_TRUE(file_exists("ft_test/dst/tree/blank.txt"));
    EXPECT_TRUE(files_identical("ft_test/src/tree/sub/mid.bin",
                                "ft_test/dst/tree/sub/mid.bin"));
    EXPECT_TRUE(files_identical("ft_test/src/tree/sub/deep/leaf.bin",
                                "ft_test/dst/tree/sub/deep/leaf.bin"));
}

// --- the receiver rejects the offer ---
TEST_F(FileTransferTest, RejectOffer) {
    const std::string src = "ft_test/src/reject.bin";
    write_test_file(src, 10 * 1024);

    std::string id = sender_->send_file(receiver_peer_id_, src);
    ASSERT_FALSE(id.empty());

    IncomingTransferOffer offer;
    ASSERT_TRUE(wait_offer(offer));
    ASSERT_TRUE(receiver_->reject_file_transfer(offer.transfer_id, "not now"));

    bool ok = true;
    ASSERT_TRUE(wait_sender_done(id, ok)) << "sender was not told about the rejection";
    EXPECT_FALSE(ok);

    auto progress = sender_->get_file_transfer_progress(id);
    ASSERT_NE(nullptr, progress);
    EXPECT_NE(FileTransferStatus::COMPLETED, progress->status);
}

// --- cancelling a transfer before it is accepted ---
TEST_F(FileTransferTest, CancelBeforeAccept) {
    const std::string src = "ft_test/src/cancel.bin";
    write_test_file(src, 64 * 1024);

    std::string id = sender_->send_file(receiver_peer_id_, src);
    ASSERT_FALSE(id.empty());

    IncomingTransferOffer offer;
    ASSERT_TRUE(wait_offer(offer)); // offer arrived, but we never accept it

    EXPECT_TRUE(sender_->cancel_file_transfer(id));

    bool ok = true;
    ASSERT_TRUE(wait_sender_done(id, ok));
    EXPECT_FALSE(ok);

    auto progress = sender_->get_file_transfer_progress(id);
    ASSERT_NE(nullptr, progress);
    EXPECT_EQ(FileTransferStatus::CANCELLED, progress->status);
}

// --- pause and resume mid-transfer (best-effort: still verifies correctness) ---
TEST_F(FileTransferTest, PauseAndResume) {
    const std::string src = "ft_test/src/pause.bin";
    const std::string dst = "ft_test/dst/pause.bin";
    write_test_file(src, 4 * 1024 * 1024); // big enough to still be running

    std::string id = sender_->send_file(receiver_peer_id_, src);
    ASSERT_FALSE(id.empty());

    IncomingTransferOffer offer;
    ASSERT_TRUE(wait_offer(offer));
    ASSERT_TRUE(receiver_->accept_file_transfer(offer.transfer_id, dst));

    std::this_thread::sleep_for(15ms);
    if (sender_->pause_file_transfer(id)) {
        auto p1 = sender_->get_file_transfer_progress(id);
        ASSERT_NE(nullptr, p1);
        uint64_t at_pause = p1->bytes_transferred;
        std::this_thread::sleep_for(250ms);
        auto p2 = sender_->get_file_transfer_progress(id);
        // While paused, no new chunks beyond the window already in flight.
        EXPECT_LE(p2->bytes_transferred, at_pause + 32u * 1024u);
        EXPECT_TRUE(sender_->resume_file_transfer(id));
    }

    bool ok = false;
    ASSERT_TRUE(wait_receiver_done(id, ok));
    EXPECT_TRUE(ok);
    EXPECT_TRUE(files_identical(src, dst));
}

// --- sending a missing file fails immediately ---
TEST_F(FileTransferTest, SendMissingFileFails) {
    EXPECT_TRUE(sender_->send_file(receiver_peer_id_, "ft_test/src/does_not_exist.bin").empty());
    EXPECT_TRUE(sender_->send_directory(receiver_peer_id_, "ft_test/src/no_such_dir").empty());
}

// --- two concurrent transfers to the same peer (the old single-slot bug) ---
TEST_F(FileTransferTest, ConcurrentTransfers) {
    const std::string src1 = "ft_test/src/c1.bin";
    const std::string src2 = "ft_test/src/c2.bin";
    const std::string dst1 = "ft_test/dst/c1.bin";
    const std::string dst2 = "ft_test/dst/c2.bin";
    write_test_file(src1, 200 * 1024);
    write_test_file(src2, 150 * 1024);

    std::string id1 = sender_->send_file(receiver_peer_id_, src1);
    std::string id2 = sender_->send_file(receiver_peer_id_, src2);
    ASSERT_FALSE(id1.empty());
    ASSERT_FALSE(id2.empty());

    for (int i = 0; i < 2; ++i) {
        IncomingTransferOffer offer;
        ASSERT_TRUE(wait_offer(offer));
        std::string dst = (offer.transfer_id == id1) ? dst1 : dst2;
        ASSERT_TRUE(receiver_->accept_file_transfer(offer.transfer_id, dst));
    }

    bool ok1 = false, ok2 = false;
    ASSERT_TRUE(wait_receiver_done(id1, ok1));
    ASSERT_TRUE(wait_receiver_done(id2, ok2));
    EXPECT_TRUE(ok1);
    EXPECT_TRUE(ok2);
    EXPECT_TRUE(files_identical(src1, dst1));
    EXPECT_TRUE(files_identical(src2, dst2));
}
