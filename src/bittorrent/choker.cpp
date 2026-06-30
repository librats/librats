#include "bittorrent/choker.h"

#include <algorithm>

namespace librats::bittorrent {

std::vector<const void*> Choker::select(std::vector<Candidate> candidates,
                                        const void* optimistic) const {
    // Highest score first; stable so equal-score peers keep a deterministic order.
    std::stable_sort(candidates.begin(), candidates.end(),
                     [](const Candidate& a, const Candidate& b) { return a.score > b.score; });

    std::vector<const void*> chosen;
    const std::size_t take = std::min(slots_, candidates.size());
    chosen.reserve(take + 1);
    for (std::size_t i = 0; i < take; ++i) chosen.push_back(candidates[i].peer);

    if (optimistic &&
        std::find(chosen.begin(), chosen.end(), optimistic) == chosen.end()) {
        chosen.push_back(optimistic);
    }
    return chosen;
}

} // namespace librats::bittorrent
