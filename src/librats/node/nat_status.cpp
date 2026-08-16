#include "librats/node/nat_status.h"

#include <algorithm>

namespace librats {

const char* to_string(NatMapping m) noexcept {
    switch (m) {
        case NatMapping::Unknown:             return "unknown";
        case NatMapping::Open:                return "open";
        case NatMapping::EndpointIndependent: return "endpoint-independent";
        case NatMapping::EndpointDependent:   return "endpoint-dependent";
    }
    return "unknown";
}

void NatStatus::record_udp_observation(const PeerId& reporter, const Address& external,
                                       bool is_own_address) {
    if (!external.is_valid()) return;

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = seen_.find(reporter);
    if (it == seen_.end()) {
        // Bounded by observers rather than by observations, so the cap is only ever
        // reached by a node with a genuinely large mesh — and once it is, the ones
        // already held are the ones that have been confirmed longest.
        if (seen_.size() >= kMaxObservers) return;
        it = seen_.emplace(reporter, Observation{}).first;
    }
    it->second.endpoint       = external;
    it->second.is_own_address = is_own_address;
    it->second.seq            = next_seq_++;
}

void NatStatus::forget(const PeerId& reporter) {
    std::lock_guard<std::mutex> lock(mutex_);
    seen_.erase(reporter);
}

void NatStatus::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    seen_.clear();
    next_seq_ = 1;
}

size_t NatStatus::observation_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return seen_.size();
}

std::vector<Address> NatStatus::external_udp_endpoints() const {
    std::vector<Observation> all;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        all.reserve(seen_.size());
        for (const auto& [id, obs] : seen_) all.push_back(obs);
    }

    // Freshest first: under a NAT that has just remapped us, the endpoint the most
    // recent peer saw is the one a punch should be aimed at, and the stale ones
    // behind it are worth keeping only as fallbacks.
    std::sort(all.begin(), all.end(),
              [](const Observation& a, const Observation& b) { return a.seq > b.seq; });

    std::vector<Address> out;
    out.reserve(all.size());
    for (const Observation& obs : all)
        if (std::find(out.begin(), out.end(), obs.endpoint) == out.end())
            out.push_back(obs.endpoint);
    return out;
}

NatMapping NatStatus::udp_mapping() const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Observations from peers that see us at an address we hold ourselves say
    // nothing about a NAT — they are LAN peers, or there is no NAT at all. They are
    // counted separately so a node whose only peers are on its own segment reports
    // Open rather than the Unknown a bare "not enough samples" would give, while a
    // single peer out on the internet still decides the answer for everybody.
    size_t  own = 0;
    size_t  external = 0;
    bool    all_same = true;
    Address first{};

    for (const auto& [id, obs] : seen_) {
        if (obs.is_own_address) { ++own; continue; }
        if (external == 0) first = obs.endpoint;
        else if (obs.endpoint != first) all_same = false;
        ++external;
    }

    if (external == 0) return own > 0 ? NatMapping::Open : NatMapping::Unknown;

    // One vantage point cannot tell a stable mapping from a per-destination one: it
    // has only ever seen the mapping made for itself. Two disagreeing ones prove the
    // NAT picks per destination; two agreeing ones are what a punch relies on.
    if (external < 2) return NatMapping::Unknown;
    return all_same ? NatMapping::EndpointIndependent : NatMapping::EndpointDependent;
}

} // namespace librats
