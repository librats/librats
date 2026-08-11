#pragma once

/**
 * @file peer_list.h
 * @brief The set of *known* peer addresses for a torrent (distinct from the live
 *        connections).
 *
 * Every discovery source — tracker, DHT, PEX, LSD, incoming — funnels addresses
 * here; the Torrent then asks for connect_candidates() to dial. The list
 * deduplicates, remembers which sources vouched for a peer, counts connection
 * failures (so hopeless peers drift to the back and eventually drop out), and
 * supports banning. Owned by one torrent on the reactor thread — not thread-safe.
 */

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
    struct Endpoint { std::string ip; std::uint16_t port; };

    struct Peer {
        std::string   ip;
        std::uint16_t port       = 0;
        std::uint8_t  sources    = 0;
        bool          connected  = false;
        bool          connecting = false;
        bool          banned     = false;
        std::uint32_t fail_count = 0;
    };

    static constexpr std::uint32_t kMaxFails = 5;

    /// Add or merge a candidate. Returns true if it was newly created.
    bool add(const std::string& ip, std::uint16_t port, PeerSource source);

    /// Up to @p max eligible peers to dial (not connected/connecting/banned, and
    /// under the failure limit), best first. The returned peers are marked
    /// `connecting` so they aren't handed out again until resolved.
    std::vector<Endpoint> connect_candidates(std::size_t max);

    void set_connected(const std::string& ip, std::uint16_t port, bool connected);
    void on_connect_failed(const std::string& ip, std::uint16_t port);
    void ban(const std::string& ip, std::uint16_t port);

    std::size_t size()           const noexcept { return peers_.size(); }
    std::size_t num_candidates() const;          ///< count currently eligible to dial
    bool        contains(const std::string& ip, std::uint16_t port) const;

private:
    static std::string key(const std::string& ip, std::uint16_t port) {
        return ip + ":" + std::to_string(port);
    }
    bool eligible(const Peer& p) const noexcept {
        return !p.connected && !p.connecting && !p.banned && p.fail_count < kMaxFails;
    }

    std::unordered_map<std::string, Peer> peers_;
};

} // namespace librats::bittorrent
