#include "librats/bittorrent/peer_list.h"

#include <algorithm>

namespace librats::bittorrent {

bool PeerList::add(const std::string& ip, std::uint16_t port, PeerSource source) {
    if (ip.empty() || port == 0) return false;
    auto [it, inserted] = peers_.try_emplace(key(ip, port));
    Peer& p = it->second;
    p.sources |= std::uint8_t(source);
    if (inserted) { p.ip = ip; p.port = port; }
    return inserted;
}

std::vector<PeerList::Endpoint> PeerList::connect_candidates(std::size_t max, Clock::time_point now) {
    std::vector<Peer*> eligible_peers;
    for (auto& [k, p] : peers_)
        if (ready(p, now)) eligible_peers.push_back(&p);

    // Fewest past failures first; ties broken by richer source provenance so a
    // tracker/DHT-vouched peer outranks one only seen via PEX.
    std::sort(eligible_peers.begin(), eligible_peers.end(), [](const Peer* a, const Peer* b) {
        if (a->fail_count != b->fail_count) return a->fail_count < b->fail_count;
        return a->sources > b->sources;
    });

    std::vector<Endpoint> out;
    const std::size_t take = (std::min)(max, eligible_peers.size());
    out.reserve(take);
    // Only `connecting` is set here — the backoff clock is started when the attempt
    // *ends*, not when it begins (libtorrent stamps last_connected in
    // connection_closed for the same reason). Stamping on hand-out instead would
    // make Disconnect::Release meaningless: a released peer would still be sitting
    // out a backoff started by the dial we ourselves just tore down. `connecting`
    // is what keeps an in-flight dial from being handed out twice, and every dial
    // now ends in on_connect_failed or on_disconnected — the connect deadline in
    // Client guarantees it — so nothing can leave a peer stamp-less forever.
    for (std::size_t i = 0; i < take; ++i) {
        eligible_peers[i]->connecting = true;
        out.push_back(Endpoint{eligible_peers[i]->ip, eligible_peers[i]->port});
    }
    return out;
}

void PeerList::set_connected(const std::string& ip, std::uint16_t port) {
    auto it = peers_.find(key(ip, port));
    if (it == peers_.end()) return;
    it->second.connected  = true;
    it->second.connecting = false;
    it->second.fail_count = 0;  // reaching a working session clears the penalty
}

void PeerList::on_disconnected(const std::string& ip, std::uint16_t port, Disconnect how,
                               Clock::time_point now) {
    auto it = peers_.find(key(ip, port));
    if (it == peers_.end()) return;
    Peer& p = it->second;
    p.connected  = false;
    p.connecting = false;
    if (how == Disconnect::Release) return;  // our own doing — leave the peer untouched
    // Stamp the attempt even for a clean disconnect: the backoff is what keeps the
    // dial loop from immediately re-opening a connection the peer just closed.
    p.last_attempt = now;
    if (how == Disconnect::Failed && p.fail_count < kMaxFails) ++p.fail_count;
}

void PeerList::on_connect_failed(const std::string& ip, std::uint16_t port, Clock::time_point now) {
    auto it = peers_.find(key(ip, port));
    if (it == peers_.end()) return;
    it->second.connecting   = false;
    it->second.last_attempt = now;
    ++it->second.fail_count;
}

void PeerList::ban(const std::string& ip, std::uint16_t port) {
    auto it = peers_.find(key(ip, port));
    if (it != peers_.end()) it->second.banned = true;
}

std::size_t PeerList::num_candidates(Clock::time_point now) const {
    std::size_t n = 0;
    for (const auto& [k, p] : peers_) if (ready(p, now)) ++n;
    return n;
}

bool PeerList::contains(const std::string& ip, std::uint16_t port) const {
    return peers_.count(key(ip, port)) != 0;
}

} // namespace librats::bittorrent
