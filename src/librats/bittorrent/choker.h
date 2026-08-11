#pragma once

/**
 * @file choker.h
 * @brief The unchoke decision — who we upload to.
 *
 * BitTorrent reciprocates: a leecher unchokes the peers that feed it fastest
 * (tit-for-tat), a seed spreads its slots by upload rate. The Choker is a pure
 * policy over a list of *interested* candidates scored by the caller (recent
 * bytes received from them, or served to them when seeding): it returns the
 * subset to unchoke — the top `slots` by score, plus an optional optimistic
 * unchoke that gets a chance regardless of score so newcomers can bootstrap.
 *
 * Stateless and side-effect-free, so the Torrent can recompute it each round and
 * apply the diff against current choke state.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace librats::bittorrent {

class Choker {
public:
    explicit Choker(std::size_t upload_slots = 4) : slots_(upload_slots) {}

    void        set_slots(std::size_t slots) noexcept { slots_ = slots; }
    std::size_t slots() const noexcept { return slots_; }

    struct Candidate {
        const void*   peer  = nullptr;  ///< opaque peer identity
        std::uint64_t score = 0;        ///< higher = more deserving of a slot
    };

    /// Choose who to unchoke. Pass only *interested* peers. The result holds the
    /// top `slots` by score; if @p optimistic is non-null it is always included
    /// (an extra slot if it didn't already make the cut).
    std::vector<const void*> select(std::vector<Candidate> candidates,
                                    const void* optimistic = nullptr) const;

private:
    std::size_t slots_;
};

} // namespace librats::bittorrent
