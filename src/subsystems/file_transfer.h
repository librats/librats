#pragma once

/**
 * @file file_transfer.h
 * @brief Push a single file to a peer, with integrity check and backpressure.
 *
 * A clean re-implementation on the plugin model. Push-only: the sender offers a
 * file; the receiver accepts (choosing a destination) or rejects; the sender
 * streams it; the receiver verifies a whole-file SHA-256 before moving the temp
 * file into place. All control + data ride on MessageType::FileChunk as compact
 * binary opcodes (no JSON). Flow control is a sliding byte window: the sender
 * keeps at most `window_bytes` un-acked, the receiver acks progress.
 *
 * Disk reads happen on a per-transfer worker thread (kept off the reactor);
 * received chunks are written on the reactor thread (matching the proven legacy
 * behaviour — offloading receive writes is a possible later refinement).
 *
 * Wire (MessageType::FileChunk payload, big-endian):
 *   OFFER    [1][id:u64][size:u64][name_len:u16][name]
 *   RESPONSE [2][id:u64][accept:u8]
 *   CHUNK    [3][id:u64][offset:u64][data]
 *   END      [4][id:u64][sha256:32]
 *   PROGRESS [5][id:u64][received:u64]
 *   COMPLETE [6][id:u64][ok:u8]
 *   CANCEL   [7][id:u64]
 */

#include "node/peer_network.h"
#include "node/peer.h"
#include "core/bytes.h"
#include "net/peer_id.h"

extern "C" {
#include "sha256.h"
}

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace librats {

class FileTransfer final : public Subsystem {
public:
    static constexpr size_t kChunkSize   = 64 * 1024;
    static constexpr size_t kWindowBytes = 1 * 1024 * 1024;

    struct Offer {
        PeerId      from;
        uint64_t    id;
        std::string name;
        uint64_t    size;
    };
    using OfferHandler    = std::function<void(const Offer&)>;
    using CompleteHandler = std::function<void(uint64_t id, bool success, const std::string& path)>;

    explicit FileTransfer(std::string temp_dir = ".");
    ~FileTransfer() override;

    void on_offer(OfferHandler handler)       { offer_handler_ = std::move(handler); }
    void on_complete(CompleteHandler handler) { complete_handler_ = std::move(handler); }

    /// Offer `path` to a peer. Returns the transfer id (0 if the file is unusable).
    uint64_t send_file(const PeerId& to, const std::string& path);

    /// Accept an offered transfer, writing the result to `dest_path`. The
    /// (from, id) pair identifies the offer (ids are sender-local).
    void accept(const PeerId& from, uint64_t id, const std::string& dest_path);
    void reject(const PeerId& from, uint64_t id);

    void attach(PeerNetwork& network) override;
    void start() override {}
    void stop() override;

private:
    struct Outgoing {
        uint64_t    id;
        PeerId      peer;
        std::string path;
        uint64_t    size;
        std::thread worker;
        std::mutex  mutex;
        std::condition_variable cv;
        uint64_t    acked = 0;
        bool        cancelled = false;
    };

    struct Incoming {
        uint64_t         id;
        PeerId           peer;
        std::string      name;
        uint64_t         size;
        std::string      dest;
        std::string      temp;
        uint64_t         cursor = 0;
        uint64_t         since_ack = 0;
        sha256_context_t sha;
        bool             active = false;
    };

    void on_message(const PeerHandle& peer, ByteView payload);
    void run_send(Outgoing* transfer);
    void finish_outgoing(uint64_t id, bool success);
    void fail_incoming(Incoming& in);

    void send_to(const PeerId& peer, const Bytes& msg) { network_->send(peer, MessageType::FileChunk, ByteView(msg)); }

    PeerNetwork*     network_ = nullptr;
    std::string      temp_dir_;
    std::atomic<uint64_t> next_id_{1};
    OfferHandler     offer_handler_;
    CompleteHandler  complete_handler_;

    std::mutex mutex_;  // guards the maps below
    std::unordered_map<uint64_t, std::unique_ptr<Outgoing>> outgoing_;
    std::unordered_map<PeerId, std::unordered_map<uint64_t, std::unique_ptr<Incoming>>, PeerId::Hash> incoming_;
};

} // namespace librats
