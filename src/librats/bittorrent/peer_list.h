#pragma once

/**
 * @file peer_list.h
 * @brief The set of *known* peer addresses for a torrent (distinct from the live
 *        connections).
 *
 * Every discovery source — tracker, DHT, PEX, LSD, incoming — funnels addresses
 * here; the Torrent then asks for connect_candidates() to dial. The list
 * deduplicates, remembers which sources vouched for a peer, counts connection
 * failures (so hopeless peers drift to the back and eventually drop out), applies
 * a reconnect backoff to peers that have just failed, and supports banning. Owned
 * by one torrent on the reactor thread — not thread-safe.
 *
 * Time is passed in rather than read from the clock so the backoff is testable;
 * the Torrent supplies Clock::now().
 */

#include "librats/bittorrent/types.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace librats::bittorrent {

enum class PeerSource : std::uint8_t {
    Tracker  = 1,
    Dht      = 2,
    Pex      = 4,
    Lsd      = 8,
    Incoming = 16,
};

class PeerList {
public:
    using Clock = std::chrono::steady_clock;

    struct Endpoint {
        std::string   ip;
        std::uint16_t port;
        /// Whether to open this attempt with an MSE handshake. Only consulted when
        /// the session's policy is EncPolicy::Enabled, where it alternates per
        /// attempt so a peer that refuses one form is reached with the other.
        bool          prefer_encrypted = true;
        /// Whether to dial over uTP rather than TCP. Only consulted when the
        /// session has outgoing uTP enabled.
        bool          prefer_utp = true;
    };

    struct Peer {
        std::string       ip;
        std::uint16_t     port       = 0;
        std::uint8_t      sources    = 0;
        bool              connected  = false;
        bool              connecting = false;
        bool              banned     = false;
        std::uint32_t     fail_count = 0;
        /// When our last connection to this peer *ended*. Zero until one does,
        /// which is what lets a freshly discovered peer be dialed immediately.
        Clock::time_point last_attempt{};
        /// Whether the next dial should be obfuscated. Starts true — nearly every
        /// client in the swarm speaks MSE, and a good part of it accepts nothing
        /// else — and flips on each attempt so a peer is eventually tried both
        /// ways. A completed handshake pins it to whatever actually worked.
        bool              prefer_encrypted = true;
        /// How many backoff waivers this peer has already been granted; see
        /// kMaxFastReconnects.
        std::uint8_t      fast_reconnects  = 0;
        /// Optimism: assume every peer speaks uTP until one proves otherwise, since
        /// most of the swarm does and a peer that does not costs exactly one wasted
        /// dial to discover (which the fast-reconnect waiver then makes free).
        /// Cleared by the first uTP dial that fails to reach a handshake.
        bool              supports_utp = true;
        /// A uTP connection to this peer has actually worked. Outranks the guess
        /// above and is never withdrawn: a peer that answered uTP once will answer
        /// it again, and a later failure is far more likely to be the peer being
        /// gone than the transport being wrong.
        bool              confirmed_supports_utp = false;
    };

    static constexpr std::uint32_t kMaxFails = 5;

    /// Base reconnect delay, scaled by the failure count: a peer is not re-dialed
    /// until (fail_count + 1) * kMinReconnectInterval has passed since the last
    /// attempt. Without it a peer that accepts TCP and then drops us — a client
    /// that requires encryption does exactly this — is re-dialed on every torrent
    /// tick, once a second, forever, while genuinely useful addresses wait behind
    /// it. Mirrors libtorrent's min_reconnect_time (60 s) and its
    /// `session_time - last_connected < (failcount + 1) * min_reconnect_time` gate.
    static constexpr std::chrono::seconds kMinReconnectInterval{60};

    /// How many times a peer may skip that wait to try the *other* encryption
    /// form (see Disconnect::FailedRetryNow). Two covers both alternations; past
    /// that a peer that keeps refusing us waits its turn like any other, which is
    /// what stops an endless one-second ping-pong with a peer that rejects both.
    /// Mirrors libtorrent's cap on torrent_peer::fast_reconnects.
    static constexpr std::uint8_t kMaxFastReconnects = 2;

    /// Add or merge a candidate. Returns true if it was newly created.
    bool add(const std::string& ip, std::uint16_t port, PeerSource source);

    /// Up to @p max eligible peers to dial (not connected/connecting/banned, under
    /// the failure limit, and past their reconnect backoff at @p now), best first.
    /// The returned peers are marked `connecting` so they aren't handed out again
    /// until the attempt resolves.
    std::vector<Endpoint> connect_candidates(std::size_t max, Clock::time_point now);

    /// The peer completed its handshake: it is a live connection, and whatever
    /// failures it accumulated getting here no longer count against it.
    /// @p encrypted records whether that took MSE, so the next dial starts there
    /// instead of paying for the alternation again; @p transport does the same for
    /// the wire it arrived on.
    void set_connected(const std::string& ip, std::uint16_t port, bool encrypted,
                       PeerTransport transport = PeerTransport::Tcp);

    /// An outgoing uTP dial to this peer never reached a handshake. Take it as
    /// evidence the peer has no uTP — the overwhelmingly likely cause, since a peer
    /// whose TCP port is reachable usually has the UDP one blocked rather than the
    /// other way round — and dial it over TCP from here on. Paired with
    /// Disconnect::FailedRetryNow, so the TCP attempt happens immediately rather
    /// than after the backoff: the whole point is that one wasted dial costs
    /// nothing but a round trip.
    void note_utp_dial_failed(const std::string& ip, std::uint16_t port);

    /// Why a connection to this peer ended — the three cases earn different
    /// treatment on the way back in.
    enum class Disconnect {
        /// It never became usable: refused mid-handshake, protocol error, dropped
        /// before the handshake completed. Penalised and backed off.
        Failed,
        /// Failed as above, but we dialed one of two alternating encryption forms
        /// and the other is worth trying at once — the peer very likely refused
        /// the handshake we opened with, not us. Penalised like Failed (so a peer
        /// that rejects both still runs out of chances) but made eligible
        /// immediately instead of waiting out a minute to learn a one-bit answer.
        /// Granted at most kMaxFastReconnects times per peer. libtorrent's
        /// fast_reconnect, which rewinds last_connected for the same reason.
        FailedRetryNow,
        /// It carried a real session and then ended. No penalty, but still backed
        /// off — re-opening a connection the peer just closed helps nobody.
        Clean,
        /// *We* dropped it for our own reasons (pausing the torrent), and nothing
        /// about the peer changed. Neither penalised nor backed off, so a resume
        /// dials straight back. This is libtorrent's fast_reconnect: it is the one
        /// case where last_connected is deliberately left unstamped.
        Release,
    };

    /// A connection to this peer ended; see Disconnect for how @p how is treated.
    void on_disconnected(const std::string& ip, std::uint16_t port, Disconnect how,
                         Clock::time_point now);

    /// The outbound connect itself never completed (refused, unreachable, timed out).
    void on_connect_failed(const std::string& ip, std::uint16_t port, Clock::time_point now);

    void ban(const std::string& ip, std::uint16_t port);

    std::size_t size() const noexcept { return peers_.size(); }
    /// Count of peers currently eligible to dial at @p now (backoff included).
    std::size_t num_candidates(Clock::time_point now) const;
    bool        contains(const std::string& ip, std::uint16_t port) const;

private:
    static std::string key(const std::string& ip, std::uint16_t port) {
        return ip + ":" + std::to_string(port);
    }
    /// Eligible ignoring time: not already in play, not banned, chances left.
    bool eligible(const Peer& p) const noexcept {
        return !p.connected && !p.connecting && !p.banned && p.fail_count < kMaxFails;
    }
    /// Eligible *and* past its reconnect backoff. A peer never dialed
    /// (last_attempt == {}) is always ready.
    bool ready(const Peer& p, Clock::time_point now) const noexcept {
        if (!eligible(p)) return false;
        if (p.last_attempt == Clock::time_point{}) return true;
        return now - p.last_attempt >= (p.fail_count + 1) * kMinReconnectInterval;
    }

    std::unordered_map<std::string, Peer> peers_;
};

} // namespace librats::bittorrent
