#pragma once

/**
 * @file tracker.h
 * @brief Tracker announces (BEP 3 over HTTP, BEP 15 over UDP) and the per-torrent
 *        announcer that drives them.
 *
 * A tracker is a directory: you periodically POST your progress and it hands back
 * a list of peers. The wire work is blocking (a short HTTP request or a two-step
 * UDP connect→announce), so announce_to_tracker() is a self-contained blocking
 * call with no shared state — easy to test and safe to run off-thread.
 *
 * TrackerAnnouncer is what a Torrent owns: it fires announces to every tracker on
 * background threads and delivers discovered peers back through a poster (onto the
 * reactor), exactly like the disk subsystem. stop() joins any in-flight announce
 * so a torrent never tears down underneath one.
 */

#include "bittorrent/types.h"
#include "core/address.h"
#include "core/bytes.h"

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace librats::bittorrent {

enum class TrackerEvent { None, Started, Stopped, Completed };

struct TrackerRequest {
    InfoHash      info_hash{};
    PeerId        peer_id{};
    std::uint16_t port       = 0;
    std::uint64_t uploaded   = 0;
    std::uint64_t downloaded = 0;
    std::uint64_t left       = 0;
    TrackerEvent  event      = TrackerEvent::None;
    int           numwant    = 50;
};

struct TrackerResponse {
    bool                 success    = false;
    std::string          failure_reason;
    std::uint32_t        interval   = 1800;  ///< seconds until the next announce
    std::uint32_t        min_interval = 0;
    std::uint32_t        complete   = 0;     ///< seeders
    std::uint32_t        incomplete = 0;     ///< leechers
    std::vector<Address> peers;
};

/// Perform one blocking announce to @p url (http/https/udp). Self-contained: it
/// opens, uses and closes its own socket and shares no state with anything.
TrackerResponse announce_to_tracker(const std::string& url, const TrackerRequest& req,
                                    int timeout_ms = 10000);

/// Drives announces to a torrent's trackers from background threads, delivering
/// peers via a poster (the reactor). Owned by one Torrent.
class TrackerAnnouncer {
public:
    using Poster       = std::function<void(std::function<void()>)>;
    using PeerCallback = std::function<void(const std::vector<Address>& peers)>;

    TrackerAnnouncer(std::vector<std::string> trackers, Poster poster, int timeout_ms = 10000);
    ~TrackerAnnouncer();

    TrackerAnnouncer(const TrackerAnnouncer&) = delete;
    TrackerAnnouncer& operator=(const TrackerAnnouncer&) = delete;

    /// Announce to every tracker (each on its own worker thread); @p on_peers is
    /// posted onto the reactor for each tracker that returns peers.
    void announce(const TrackerRequest& req, PeerCallback on_peers);
    /// Wait for any in-flight announce to finish. Idempotent; called by the dtor.
    void stop();

    std::size_t tracker_count() const noexcept { return trackers_.size(); }

private:
    std::vector<std::string> trackers_;
    Poster                   poster_;
    int                      timeout_ms_;

    std::mutex               mutex_;
    std::condition_variable  drain_cv_;
    int                      inflight_ = 0;
    bool                     stopping_ = false;
};

// Exposed for unit testing the HTTP wire format without a live tracker.
namespace tracker_detail {
std::string     build_http_announce_url(const std::string& base, const TrackerRequest& req);
TrackerResponse parse_http_response(const Bytes& body);
} // namespace tracker_detail

} // namespace librats::bittorrent
