#include "bittorrent/peer_list.h"

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

std::vector<PeerList::Endpoint> PeerList::connect_candidates(std::size_t max) {
    std::vector<Peer*> eligible_peers;
    for (auto& [k, p] : peers_)
        if (eligible(p)) eligible_peers.push_back(&p);

    // Fewest past failures first; ties broken by richer source provenance so a
    // tracker/DHT-vouched peer outranks one only seen via PEX.
    std::sort(eligible_peers.begin(), eligible_peers.end(), [](const Peer* a, const Peer* b) {
        if (a->fail_count != b->fail_count) return a->fail_count < b->fail_count;
        return a->sources > b->sources;
    });

    std::vector<Endpoint> out;
    const std::size_t take = (std::min)(max, eligible_peers.size());
    out.reserve(take);
    for (std::size_t i = 0; i < take; ++i) {
        eligible_peers[i]->connecting = true;
        out.push_back(Endpoint{eligible_peers[i]->ip, eligible_peers[i]->port});
    }
    return out;
}

void PeerList::set_connected(const std::string& ip, std::uint16_t port, bool connected) {
    auto it = peers_.find(key(ip, port));
    if (it == peers_.end()) return;
    it->second.connected  = connected;
    it->second.connecting = false;
    if (connected) it->second.fail_count = 0;  // a successful connect clears the penalty
}

void PeerList::on_connect_failed(const std::string& ip, std::uint16_t port) {
    auto it = peers_.find(key(ip, port));
    if (it == peers_.end()) return;
    it->second.connecting = false;
    ++it->second.fail_count;
}

void PeerList::ban(const std::string& ip, std::uint16_t port) {
    auto it = peers_.find(key(ip, port));
    if (it != peers_.end()) it->second.banned = true;
}

std::size_t PeerList::num_candidates() const {
    std::size_t n = 0;
    for (const auto& [k, p] : peers_) if (eligible(p)) ++n;
    return n;
}

bool PeerList::contains(const std::string& ip, std::uint16_t port) const {
    return peers_.count(key(ip, port)) != 0;
}

} // namespace librats::bittorrent
