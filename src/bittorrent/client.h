#pragma once

/**
 * @file client.h
 * @brief The BitTorrent session: owns the reactor, the listen socket and the
 *        set of torrents, and brokers peer connections between them.
 *
 * Client is the top-level handle an application drives. It accepts incoming peers
 * and routes each (by the info-hash in its handshake) to the matching Torrent;
 * it dials outgoing peers on a Torrent's behalf. All connections are owned here
 * in one pool and reaped once closed, so torrents only ever hold raw pointers.
 *
 * Lifecycle: open() wires up the listener and timers on the reactor thread;
 * start() additionally runs the reactor on its own thread. Tests instead pump
 * reactor().run_one() so everything stays single-threaded and deterministic.
 */

#include "bittorrent/peer_connection.h"
#include "bittorrent/reactor.h"
#include "bittorrent/torrent.h"
#include "bittorrent/torrent_info.h"
#include "bittorrent/types.h"
#include "core/socket.h"
#include "core/types.h"
#include "dht/dht.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace librats::bittorrent {

class Client final : public TorrentHost {
public:
    struct Config {
        std::uint16_t listen_port    = 6881;   ///< 0 = ephemeral
        std::string   download_path;           ///< default save directory
        std::string   peer_id_prefix = "-LR0001-";
    };

    Client();
    explicit Client(Config config);
    ~Client() override;

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    /// Wire up the listener + housekeeping timers. Must run on the reactor thread
    /// (call directly before pumping in tests, or via start()).
    void open();
    /// open() + run the reactor on a background thread.
    void start();
    /// Stop the reactor (joining its thread) and tear everything down.
    void stop();

    bool          is_running()  const noexcept { return opened_; }
    std::uint16_t listen_port() const noexcept { return actual_port_; }
    Reactor&      reactor() noexcept { return reactor_; }

    Torrent* add_torrent(const TorrentInfo& info, const std::string& save_path = "");
    /// Add a magnet link — the torrent starts metadata-less and fetches its info
    /// dict from peers (BEP 9) before downloading.
    Torrent* add_magnet(const std::string& magnet_uri, const std::string& save_path = "");
    /// Add a torrent and apply saved resume state (trusts the recorded pieces).
    Torrent* add_torrent_with_resume(const TorrentInfo& info, const ResumeData& resume,
                                     const std::string& save_path = "");
    /// Add a freshly-created torrent whose files already exist at @p save_path,
    /// trusting every piece so it starts seeding without re-hashing.
    Torrent* add_torrent_for_seeding(const TorrentInfo& info, const std::string& save_path);
    /// Load a .torrent file from disk and add it. Returns nullptr if the file
    /// cannot be read or parsed. Convenience over TorrentInfo::from_file + add_torrent.
    Torrent* add_torrent_file(const std::string& path, const std::string& save_path = "");
    Torrent* get_torrent(const InfoHash& info_hash);
    void     remove_torrent(const InfoHash& info_hash, bool delete_files = false);
    std::vector<Torrent*> torrents();
    /// Persist resume data for every torrent to its default path.
    void     save_all_resume_data();

    // ---- aggregate stats (for status lines / UI) ----
    std::size_t   num_torrents() const noexcept { return torrents_.size(); }
    std::size_t   total_peers()  const;
    /// Swarm-wide transfer rates in bytes/sec, sampled once per second by the
    /// housekeeping timer. Atomic so they can be read from another thread.
    std::uint64_t total_download_rate() const noexcept { return down_rate_.load(std::memory_order_relaxed); }
    std::uint64_t total_upload_rate()   const noexcept { return up_rate_.load(std::memory_order_relaxed); }

    /// Share an externally-owned DHT for peer discovery (e.g. the node's). Its
    /// lifetime is the caller's; Client never starts or stops it.
    void       set_external_dht(DhtClient* dht) noexcept { dht_ = dht; }
    DhtClient* get_dht_client() const noexcept { return dht_; }

    // ---- TorrentHost ----
    void          connect_peer(Torrent& torrent, const std::string& ip, std::uint16_t port) override;
    const PeerId& peer_id() const override { return peer_id_; }
    void          find_peers_via_dht(const InfoHash& info_hash,
                                     std::function<void(const std::string& ip, std::uint16_t port)> on_peer) override;

private:
    void open_listener();
    void on_accept();
    void schedule_reap();
    void reap_closed();
    void sample_rates();  ///< recompute down_rate_/up_rate_ from per-torrent byte counters

    Reactor       reactor_;
    Config        config_;
    PeerId        peer_id_;
    socket_t      listener_     = INVALID_SOCKET_VALUE;
    std::uint16_t actual_port_  = 0;
    bool          opened_       = false;
    TimerId       reap_timer_   = kInvalidTimerId;

    DhtClient*    dht_ = nullptr;   ///< external, non-owning

    std::map<InfoHash, std::unique_ptr<Torrent>>      torrents_;
    std::vector<std::unique_ptr<PeerConnection>>      connections_;

    // Rate sampling (updated on the reactor thread once per second).
    std::atomic<std::uint64_t>            down_rate_{0};
    std::atomic<std::uint64_t>            up_rate_{0};
    std::uint64_t                         last_down_bytes_ = 0;
    std::uint64_t                         last_up_bytes_   = 0;
    std::chrono::steady_clock::time_point last_sample_{};
};

} // namespace librats::bittorrent
