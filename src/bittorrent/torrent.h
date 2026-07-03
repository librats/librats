#pragma once

/**
 * @file torrent.h
 * @brief One active torrent: ties the piece picker, peers, disk and choker
 *        together and drives a download (or seed) to completion.
 *
 * A Torrent is a PeerConnection::Observer — every wire event lands here and is
 * turned into picker/disk work. The flow is event-driven, not polled:
 *
 *   peer unchokes / has new pieces → refill its request pipeline
 *   block arrives                  → write to disk → (piece done) hash & verify
 *   piece verified                 → mark have, announce `have` to peers
 *   peer interested                → recompute the choker and (un)choke
 *
 * A 1 s tick only handles periodic chores (connect more peers, re-run the
 * choker). All of this runs on the reactor thread, so there are no locks.
 *
 * Connections are owned by the host (Client); the Torrent holds raw pointers it
 * learns at handshake and drops at close.
 */

#include "bittorrent/choker.h"
#include "bittorrent/disk_io.h"
#include "bittorrent/extensions.h"
#include "bittorrent/peer_connection.h"
#include "bittorrent/peer_list.h"
#include "bittorrent/piece_picker.h"
#include "bittorrent/reactor.h"
#include "bittorrent/resume_data.h"
#include "bittorrent/torrent_info.h"
#include "bittorrent/tracker.h"
#include "bittorrent/types.h"
#include "core/types.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace librats::bittorrent {

class Torrent;

/// What a Torrent needs from its owning Client: outgoing connects and our id.
class TorrentHost {
public:
    virtual ~TorrentHost() = default;
    virtual void          connect_peer(Torrent& torrent, const std::string& ip, std::uint16_t port) = 0;
    virtual const PeerId& peer_id() const = 0;
    virtual std::uint16_t listen_port() const = 0;
    /// Discover peers for @p info_hash via the DHT (if the host has one); each
    /// found peer is delivered to @p on_peer on the reactor thread. Default no-op.
    virtual void find_peers_via_dht(const InfoHash& /*info_hash*/,
                                    std::function<void(const std::string& ip, std::uint16_t port)> /*on_peer*/) {}
};

class Torrent final : public PeerConnection::Observer {
public:
    enum class State { Stopped, Metadata, Checking, Downloading, Seeding };

    Torrent(Reactor& reactor, TorrentHost& host, TorrentInfo info, std::string save_path);
    ~Torrent() override;

    Torrent(const Torrent&) = delete;
    Torrent& operator=(const Torrent&) = delete;

    void start();
    void stop();

    /// Queue a peer to connect to (deduplicated). Connects promptly if running.
    void add_peer(const std::string& ip, std::uint16_t port);

    // ---- info / progress ----
    const InfoHash&    info_hash()   const { return info_.info_hash(); }
    const TorrentInfo& torrent_info()const { return info_; }
    std::uint32_t      num_pieces()  const { return info_.num_pieces(); }
    State              state()       const noexcept { return state_; }
    bool               is_complete() const { return picker_ && picker_->is_finished(); }
    double             progress()    const;
    std::size_t        num_peers()   const noexcept { return peers_.size(); }
    /// Total block requests currently in flight across all peers.
    std::size_t        num_outstanding_requests() const noexcept;
    /// Override how long a peer may hold requests without delivering before it is
    /// snubbed and its blocks freed. Defaults to kRequestTimeout (30 s).
    void               set_request_timeout(std::chrono::milliseconds t) noexcept { request_timeout_ = t; }
    std::uint64_t      bytes_downloaded() const noexcept { return bytes_downloaded_; }
    std::uint64_t      bytes_uploaded()   const noexcept { return bytes_uploaded_; }

    /// True once we hold the full metadata (always true unless started from a magnet).
    bool has_metadata() const noexcept { return has_metadata_; }

    /// Fired once when a download reaches 100% (not for torrents that start complete).
    void set_complete_callback(std::function<void()> cb) { on_complete_ = std::move(cb); }
    /// Fired once when metadata is obtained for a magnet torrent (with the completed info).
    void set_metadata_callback(std::function<void(const TorrentInfo&)> cb) { on_metadata_ = std::move(cb); }

    // ---- fast resume ----
    /// Apply saved resume state. Call before start(): the recorded have-bitfield
    /// is trusted (those pieces skip the hash check), and an embedded info dict
    /// completes a magnet torrent. Ignored if the info-hash doesn't match.
    void       load_resume_data(const ResumeData& rd);
    ResumeData generate_resume_data() const;
    /// Write resume data to @p path (default: {save_path}/.resume/{info_hash}.resume).
    bool save_resume_data() const;
    bool save_resume_data(const std::string& path) const;

    /// Called by the host when an outgoing connect attempt fails.
    void on_connect_failed(const std::string& ip, std::uint16_t port);

    // ---- PeerConnection::Observer ----
    void on_handshake(PeerConnection&, const InfoHash&, const PeerId&) override;
    void on_bitfield(PeerConnection&, const Bitfield&) override;
    void on_have(PeerConnection&, std::uint32_t piece) override;
    void on_choke(PeerConnection&, bool peer_choking) override;
    void on_interest(PeerConnection&, bool peer_interested) override;
    void on_request(PeerConnection&, std::uint32_t piece, std::uint32_t offset, std::uint32_t length) override;
    void on_piece(PeerConnection&, std::uint32_t piece, std::uint32_t offset, ByteView data) override;
    void on_extended(PeerConnection&, std::uint8_t ext_id, ByteView payload) override;
    void on_closed(PeerConnection&, const std::string& reason) override;

private:
    void on_check_complete(Bitfield have);

    // Extension protocol / metadata (BEP 10 / BEP 9).
    void send_extended_handshake(PeerConnection& pc);
    void handle_ext_handshake(PeerConnection& pc, ByteView payload);
    void handle_ut_metadata(PeerConnection& pc, ByteView payload);
    void ensure_metadata_buffer(std::uint32_t total_size);
    void request_metadata(PeerConnection& pc);
    void on_metadata_piece(std::uint32_t piece, std::uint32_t total_size, ByteView block);
    void try_complete_metadata();
    void promote_to_downloading();
    void schedule_tick();
    void tick();
    void try_connect();
    void update_interest(PeerConnection& pc);
    void refill(PeerConnection& pc);
    void recompute_choker();
    void handle_pex(PeerConnection& pc, ByteView payload);
    void send_pex();
    std::optional<ext::PexPeer> dialable(PeerConnection& pc) const;
    void           announce_trackers(TrackerEvent event);
    TrackerRequest make_tracker_request(TrackerEvent event) const;
    std::string    default_resume_path() const;
    /// Free blocks stuck on peers that have made no progress within
    /// kRequestTimeout so other peers can re-request them (prevents a silent /
    /// keep-alive-only peer from stalling pieces forever). Runs on the 1 s tick.
    void check_request_timeouts();
    void on_block_written(PieceBlock block, bool ok);
    void verify_piece(std::uint32_t piece);
    void on_piece_hashed(std::uint32_t piece, bool ok, std::array<std::uint8_t, 20> hash);
    bool alive(PeerConnection* pc) const;
    void remove_peer(PeerConnection* pc);

    static constexpr int         kPipelineDepth = 16;
    static constexpr std::size_t kMaxPeers      = 50;
    /// A peer that holds outstanding requests but delivers no block for this long
    /// is snubbed: its blocks are freed for other peers. Kept well under the 120 s
    /// idle timeout so a keep-alive-only peer can't stall pieces indefinitely.
    static constexpr std::chrono::seconds kRequestTimeout{30};
    std::chrono::milliseconds request_timeout_{kRequestTimeout};

    Reactor&                     reactor_;
    TorrentHost&                 host_;
    TorrentInfo                  info_;
    std::string                  save_path_;
    std::unique_ptr<PiecePicker>     picker_;
    std::unique_ptr<DiskIo>          disk_;
    std::unique_ptr<TrackerAnnouncer> trackers_;
    Choker                           choker_;
    State                        state_   = State::Stopped;
    bool                         running_ = false;
    bool                         has_metadata_ = false;
    bool                         completed_announced_ = false;
    Bitfield                     resume_have_;   ///< trusted have-set from resume data

    std::vector<PeerConnection*>                            peers_;
    std::unordered_map<PeerConnection*, int>                outstanding_;
    /// Time of the last progress with each peer (a block received, or the moment
    /// we started waiting on a fresh batch). Drives the request-timeout snub.
    std::unordered_map<PeerConnection*, std::chrono::steady_clock::time_point> request_time_;
    std::unordered_map<PeerConnection*, std::uint64_t>      recent_down_;  // tit-for-tat score
    std::unordered_set<PeerConnection*>                     seed_peers_;   // counted via the picker's O(1) seed counter
    std::unordered_map<PeerConnection*, ext::PeerExtensions>           peer_ext_;
    std::unordered_map<PeerConnection*, std::unordered_set<std::string>> pex_sent_;
    PeerList                                                          peer_list_;
    int                                                               tick_count_ = 0;

    // ut_metadata (BEP 9) assembly state, used while we lack metadata.
    Bytes             metadata_buf_;
    std::uint32_t     metadata_size_     = 0;
    std::uint32_t     metadata_pieces_   = 0;
    std::uint32_t     metadata_received_ = 0;
    std::vector<bool> metadata_have_;

    std::uint64_t bytes_downloaded_ = 0;  ///< cumulative payload downloaded (tracker stat / resume)
    std::uint64_t bytes_uploaded_   = 0;
    std::uint64_t verified_bytes_   = 0;  ///< payload currently present & verified on disk (drives `left`)

    TimerId                                  tick_timer_ = kInvalidTimerId;
    std::function<void()>                    on_complete_;
    std::function<void(const TorrentInfo&)>  on_metadata_;
};

} // namespace librats::bittorrent
