#include "dht/routing_table.h"
#include "dht/log.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <sstream>
#include <string>

namespace librats {
namespace dht {

namespace {

// Locate a contact by id within one set (live or replacements).
std::vector<NodeEntry>::iterator find_by_id(std::vector<NodeEntry>& v, const NodeId& id) {
    return std::find_if(v.begin(), v.end(), [&](const NodeEntry& n) { return n.id == id; });
}

// The worst contact in `v` (the one every other is "no worse than"), or end() if empty.
std::vector<NodeEntry>::iterator worst_of(std::vector<NodeEntry>& v) {
    auto worst = v.begin();
    for (auto it = v.begin(); it != v.end(); ++it)
        if (it->is_worse_than(*worst)) worst = it;
    return worst;
}

// log2 of a power-of-two bucket size: 8 -> 3 ... 128 -> 7.
constexpr int prefix_bits_for(int bucket_size) noexcept {
    int bits = 0;
    while ((1 << bits) < bucket_size) ++bits;
    return bits;
}

// The largest live-set limit any bucket can have (the widest top bucket); see
// RoutingTable::bucket_limit. The spread classifier yields prefix_bits_for(limit)
// bits, so this caps the number of distinct sub-prefix slots.
constexpr int kMaxBucketLimit = static_cast<int>(kBucketSize) * 16;

// Classify a node by the few sub-prefix bits right after the bucket's shared prefix.
// For a non-last bucket we skip the one bit that *defines* the bucket (it's the same
// for every entry); the last bucket hasn't split yet and holds both sides, so we keep
// it. The result indexes a "spread slot" in [0, bucket_size).
uint8_t classify_prefix(int bucket_idx, bool last_bucket, int bucket_size, const NodeId& id) noexcept {
    const int shift = bucket_idx + (last_bucket ? 0 : 1);
    return static_cast<uint8_t>(bits_at(id, shift, prefix_bits_for(bucket_size)));
}

// True if every live node and `id` carry the same bit at position `idx`: a split at
// that bit wouldn't separate anyone, so it would be pointless.
bool all_on_same_side(const std::vector<NodeEntry>& live, const NodeId& id, int idx) noexcept {
    const int byte = idx >> 3;
    const int bit  = idx & 7;
    const uint8_t mask = static_cast<uint8_t>(0x80u >> bit);
    int count[2] = {0, 0};
    ++count[(id[byte] & mask) ? 1 : 0];
    for (const auto& n : live) ++count[(n.id[byte] & mask) ? 1 : 0];
    return count[0] == 0 || count[1] == 0;
}

} // namespace

RoutingTable::RoutingTable(const NodeId& self, bool extended)
    : self_(self), extended_(extended) {
    buckets_.emplace_back();  // always keep at least the catch-all bucket
}

int RoutingTable::bucket_index(const NodeId& id) const noexcept {
    const int prefix = shared_prefix_bits(self_, id);
    const int last = static_cast<int>(buckets_.size()) - 1;
    return prefix < last ? prefix : last;
}

int RoutingTable::bucket_limit(int index) const noexcept {
    if (!extended_) return static_cast<int>(kBucketSize);
    // The top buckets hold more contacts (16k, 8k, 4k, 2k) — that's where the
    // keyspace and the first lookup hop are densest.
    static constexpr int kMult[4] = {16, 8, 4, 2};
    return static_cast<int>(kBucketSize) * (index < 4 ? kMult[index] : 1);
}

void RoutingTable::heard_about(const NodeId& id, const Address& endpoint, bool verified) {
    if (id == self_) return;
    NodeEntry e(id, endpoint);  // unpinged until it replies
    e.verified = verified;
    add_node(e);
}

bool RoutingTable::node_seen(const NodeId& id, const Address& endpoint,
                             uint16_t rtt, bool verified) {
    if (id == self_) return false;
    NodeEntry entry(id, endpoint);
    entry.verified = verified;
    entry.record_success(rtt);  // confirmed (fail_count = 0), folds in the RTT
    return add_node(entry);
}

bool RoutingTable::add_node(NodeEntry e) {
    if (e.id == self_) return false;
    const int idx = bucket_index(e.id);
    Bucket& b = buckets_[idx];

    // Already live → refresh in place. A confirmed sighting also records success;
    // mere hearsay must not reset a live contact's quality.
    if (auto it = find_by_id(b.live, e.id); it != b.live.end()) {
        it->verified = it->verified || e.verified;
        if (e.pinged()) { it->endpoint = e.endpoint; it->record_success(e.rtt); }
        return true;
    }

    // Sitting in the replacement cache: a confirmed sighting pulls it out to promote,
    // carrying its accumulated quality; mere hearsay leaves it parked.
    if (auto it = find_by_id(b.replacements, e.id); it != b.replacements.end()) {
        if (!e.pinged()) return false;
        NodeEntry promoted = *it;
        promoted.endpoint = e.endpoint;
        promoted.verified = promoted.verified || e.verified;
        promoted.record_success(e.rtt);
        b.replacements.erase(it);
        e = promoted;
    }

    const int limit = bucket_limit(idx);
    if (static_cast<int>(b.live.size()) < limit) {
        b.live.push_back(e);
        return true;
    }

    // The bucket is full. A confirmed contact may split it or displace a weaker one;
    // hearsay just waits in the replacement cache.
    if (e.confirmed()) {
        if (can_split(idx, e)) {
            split_bucket();              // buckets idx and idx + 1 now exist
            const bool added = add_node(e);  // re-home e against the now-deeper table
            // The split freed live slots; pull the best standbys up into them, but
            // only after e has claimed its rightful slot.
            fill_from_replacements(idx);
            fill_from_replacements(idx + 1);
            return added;
        }
        if (replace_for_spread(b, idx, limit, e)) return true;
    }
    stash_replacement(b, e);
    return false;
}

bool RoutingTable::can_split(int index, const NodeEntry& e) const {
    return index + 1 == static_cast<int>(buckets_.size())          // only the last bucket splits
        && static_cast<int>(buckets_.size()) < kBucketCount - 1     // bounded depth
        && e.confirmed()
        && (index == 0 || buckets_[index - 1].live.size() > 1)      // don't deepen into near-empty
        && !all_on_same_side(buckets_[index].live, e.id, index);    // a split must actually separate
}

void RoutingTable::split_bucket() {
    const int last = static_cast<int>(buckets_.size()) - 1;
    buckets_.emplace_back();  // may reallocate buckets_ — hold no Bucket& across this

    Bucket moved = std::move(buckets_[last]);
    buckets_[last] = Bucket{};

    // Contacts sharing exactly `last` prefix bits with us stay; closer ones (longer
    // shared prefix) move to the new, deeper bucket.
    const auto place = [&](std::vector<NodeEntry>& src, bool live) {
        for (auto& n : src) {
            const int dest = shared_prefix_bits(self_, n.id) <= last ? last : last + 1;
            auto& bucket = buckets_[dest];
            (live ? bucket.live : bucket.replacements).push_back(std::move(n));
        }
    };
    place(moved.live, true);
    place(moved.replacements, false);

    // The deeper bucket has a smaller limit, so it may now overflow — spill the rest.
    trim_to_limit(last);
    trim_to_limit(last + 1);

    // Structural milestone, not per-packet churn: a bucket deepens only a bounded number
    // of times as the table grows, so this stays quiet (unlike add/seen/fail, which must
    // never log). The live composition over time is the heartbeat's describe() job.
    LOG_DEBUG("dht.route", "bucket split → " << buckets_.size() << " bucket(s): #" << last
                           << " keeps " << buckets_[last].live.size() << ", #" << (last + 1)
                           << " gets " << buckets_[last + 1].live.size() << " live");
}

bool RoutingTable::replace_for_spread(Bucket& b, int index, int limit, const NodeEntry& e) {
    auto& live = b.live;
    const bool last = (index + 1 == static_cast<int>(buckets_.size()));

    // 1) A node that has actually failed a query is the first to go.
    NodeEntry* stale = nullptr;
    for (auto& n : live)
        if (n.pinged() && n.fail_count > 0 && (!stale || n.fail_count > stale->fail_count))
            stale = &n;
    if (stale) { *stale = e; return true; }

    // 2) Otherwise keep a spread of sub-prefixes. Group the live nodes by their slot.
    // classify_prefix yields prefix_bits_for(limit) bits, so the slot index is in
    // [0, 2^prefix_bits). Size the table to the largest possible bucket limit so a
    // wider top bucket can never index out of bounds (tied to bucket_limit's cap).
    static constexpr int kMaxSlots = 1 << prefix_bits_for(kMaxBucketLimit);
    static_assert(kMaxSlots <= 256, "slot index must fit in the uint8_t classify_prefix returns");
    const uint8_t want = classify_prefix(index, last, limit, e.id);
    std::array<std::vector<NodeEntry*>, kMaxSlots> slot{};
    for (auto& n : live) slot[classify_prefix(index, last, limit, n.id)].push_back(&n);

    const auto worst_in = [](const std::vector<NodeEntry*>& v) {
        NodeEntry* worst = v.front();
        for (auto* n : v) if (n->is_worse_than(*worst)) worst = n;
        return worst;
    };

    if (!slot[want].empty()) {
        // Our slot is taken: displace its worst node only if we're strictly better.
        NodeEntry* worst = worst_in(slot[want]);
        if (worst->is_worse_than(e)) { *worst = e; return true; }
        return false;
    }

    // Our slot is empty: make room by dropping the worst node from an over-full slot,
    // so a healthy contact alone in its slot is never sacrificed.
    NodeEntry* victim = nullptr;
    for (const auto& s : slot)
        if (s.size() > 1)
            for (auto* n : s)
                if (!victim || n->is_worse_than(*victim)) victim = n;
    if (victim) { *victim = e; return true; }
    return false;
}

void RoutingTable::stash_replacement(Bucket& b, const NodeEntry& entry) {
    auto& r = b.replacements;
    if (auto it = find_by_id(r, entry.id); it != r.end()) {
        *it = entry;
        return;
    }
    if (r.size() < kBucketSize) {
        r.push_back(entry);
        return;
    }
    auto worst = worst_of(r);
    if (worst != r.end() && worst->is_worse_than(entry)) *worst = entry;
}

void RoutingTable::trim_to_limit(int index) {
    Bucket& b = buckets_[index];
    const int limit = bucket_limit(index);
    while (static_cast<int>(b.live.size()) > limit) {
        auto worst = worst_of(b.live);
        b.replacements.push_back(std::move(*worst));
        b.live.erase(worst);
    }
    while (b.replacements.size() > kBucketSize)
        b.replacements.erase(worst_of(b.replacements));
}

void RoutingTable::fill_from_replacements(int index) {
    Bucket& b = buckets_[index];
    const int limit = bucket_limit(index);
    while (static_cast<int>(b.live.size()) < limit && !b.replacements.empty()) {
        // Promote the best standby — the one no other standby is better than, so
        // confirmed contacts go before unpinged hearsay.
        auto best = b.replacements.begin();
        for (auto it = b.replacements.begin(); it != b.replacements.end(); ++it)
            if (best->is_worse_than(*it)) best = it;
        b.live.push_back(std::move(*best));
        b.replacements.erase(best);
    }
}

void RoutingTable::node_failed(const NodeId& id, const Address& endpoint) {
    const int idx = bucket_index(id);
    Bucket& b = buckets_[idx];

    auto it = find_by_id(b.live, id);
    if (it == b.live.end()) {
        // A standby we were probing can fail too — drop it if it's spent. Only when the
        // endpoint matches, though: a different node claiming the same id must not knock
        // out the standby we already have for it.
        if (auto r = find_by_id(b.replacements, id);
            r != b.replacements.end() && r->endpoint == endpoint) {
            r->record_failure();
            if (!r->pinged() || r->fail_count >= kMaxFailCount) b.replacements.erase(r);
        }
        return;
    }

    // The id is live but now points at a different endpoint — a more recent sighting from
    // another node overwrote it. This timeout belongs to the old node, so ignore it
    // rather than penalise (or evict) the current, healthy contact.
    if (it->endpoint != endpoint) return;

    it->record_failure();

    // A liveness check already failed here, so if a standby is ready, evict the
    // failed contact and let the best standbys take the freed slot(s).
    if (!b.replacements.empty()) {
        b.live.erase(it);
        fill_from_replacements(idx);
        prune_empty_back();
        return;
    }

    // No standby: keep giving it chances until it's clearly dead.
    if (!it->pinged() || it->fail_count >= kMaxFailCount) b.live.erase(it);
    prune_empty_back();
}

std::vector<NodeEntry> RoutingTable::find_closest(const NodeId& target, std::size_t count,
                                                  bool include_unconfirmed) const {
    std::vector<NodeEntry> result;
    if (count == 0) return result;

    const auto take = [&](const Bucket& b) {
        for (const auto& n : b.live)
            if (include_unconfirmed || n.confirmed()) result.push_back(n);
    };

    // By the XOR metric's prefix structure, the buckets form distance tiers around the
    // target's own bucket `start`:
    //   - bucket `start` is the *closest* tier: every contact in it is strictly nearer
    //     than any contact in a deeper bucket, so if it alone yields `count` we're done.
    //   - the deeper buckets (> start) are all tied at the same leading distance bit and
    //     are unordered among themselves, so they must be taken as one whole tier or not
    //     at all — we can stop before them, never partway through.
    //   - the shallower buckets (< start) are each a strictly farther tier in order, so
    //     they can be walked closest-first with an early stop the moment we have enough.
    const int start = bucket_index(target);
    result.reserve(count + static_cast<std::size_t>(buckets_[start].live.size()));

    take(buckets_[start]);
    if (result.size() < count)  // closest tier short -> the deeper tier is needed in full
        for (int i = start + 1; i < static_cast<int>(buckets_.size()); ++i) take(buckets_[i]);
    for (int i = start - 1; i >= 0 && result.size() < count; --i) take(buckets_[i]);

    const std::size_t k = (std::min)(count, result.size());
    std::partial_sort(result.begin(), result.begin() + k, result.end(),
        [&](const NodeEntry& a, const NodeEntry& c) { return closer_to(a.id, c.id, target); });
    if (result.size() > count) result.resize(count);
    return result;
}

std::optional<NodeEntry> RoutingTable::next_to_refresh(std::chrono::steady_clock::time_point now) {
    // Order by last touch: a never-contacted contact (last_seen == min) sorts first,
    // then the least-recently-touched.
    NodeEntry* best = nullptr;
    for (auto& b : buckets_)
        for (auto& n : b.live)
            if (!best || n.last_seen < best->last_seen) best = &n;

    if (!best) return std::nullopt;

    // Stamp it as touched now: we're about to probe it, so the next refresh moves on to
    // a different contact instead of re-probing this one while its probe is in flight.
    // A reply refreshes last_seen again; a timeout drops the contact (node_failed).
    best->last_seen = now;
    return *best;
}

std::size_t RoutingTable::size() const {
    std::size_t n = 0;
    for (const auto& b : buckets_) n += b.live.size();
    return n;
}

void RoutingTable::set_self(const NodeId& id) {
    if (id == self_) return;

    // Drain every contact, re-root the table to a single bucket, then re-home each
    // one — bucket indices are all relative to self_ and are now stale.
    std::vector<NodeEntry> all;
    for (auto& b : buckets_) {
        for (auto& n : b.live) all.push_back(std::move(n));
        for (auto& n : b.replacements) all.push_back(std::move(n));
    }

    self_ = id;
    buckets_.clear();
    buckets_.emplace_back();
    for (const auto& n : all) add_node(n);
}

std::vector<NodeEntry> RoutingTable::good_contacts() const {
    std::vector<NodeEntry> out;
    for (const auto& b : buckets_)
        for (const auto& n : b.live)
            if (n.confirmed()) out.push_back(n);
    return out;
}

void RoutingTable::load_contacts(const std::vector<NodeEntry>& contacts) {
    for (const auto& n : contacts) add_node(n);
}

std::string RoutingTable::describe() const {
    // One compact line per contact: "<id8> <ip:port> <rtt> <flags>", where flags are
    //   ?  = only heard about (never replied)   !N = N consecutive failures   v = BEP 42-verified
    const auto fmt_contact = [](const NodeEntry& n) {
        std::ostringstream s;
        s << short_hex(n.id) << ' ' << n.endpoint.to_string() << ' ';
        if (n.rtt == NodeEntry::kRttUnknown) s << "-ms";
        else                                 s << n.rtt << "ms";
        if (!n.pinged())           s << " ?";
        else if (n.fail_count > 0) s << " !" << static_cast<int>(n.fail_count);
        if (n.verified)            s << " v";
        return s.str();
    };
    // A 10-cell bar showing how full the live set is relative to this bucket's limit.
    const auto fill_bar = [](std::size_t live, int limit) {
        constexpr int width = 10;
        int filled = limit > 0 ? static_cast<int>((live * width + limit / 2) / limit) : 0;
        if (filled > width) filled = width;
        return std::string(static_cast<std::size_t>(filled), '#') +
               std::string(static_cast<std::size_t>(width - filled), '.');
    };

    std::ostringstream os;
    os << "routing table: " << size() << " node(s) / " << buckets_.size()
       << " bucket(s)  self " << short_hex(self_);
    for (int i = 0; i < static_cast<int>(buckets_.size()); ++i) {
        const Bucket& b = buckets_[i];
        const int limit = bucket_limit(i);

        std::ostringstream cnt;
        cnt << b.live.size() << '/' << limit;

        os << "\n  #" << std::right << std::setw(2) << i << "  "
           << std::left << std::setw(7) << cnt.str()
           << "repl " << std::right << std::setw(2) << b.replacements.size() << "  "
           << '[' << fill_bar(b.live.size(), limit) << "]  ";

        if (b.live.empty()) { os << "(empty)"; continue; }

        // best = the contact no other is better than; worst = the first to be evicted.
        const NodeEntry* best  = &b.live.front();
        const NodeEntry* worst = &b.live.front();
        for (const auto& n : b.live) {
            if (best->is_worse_than(n)) best = &n;
            if (n.is_worse_than(*worst)) worst = &n;
        }
        os << "best " << fmt_contact(*best);
        if (b.live.size() > 1) os << "  worst " << fmt_contact(*worst);
    }
    return os.str();
}

void RoutingTable::prune_empty_back() {
    while (buckets_.size() > 1
           && buckets_.back().live.empty()
           && buckets_.back().replacements.empty())
        buckets_.pop_back();
}

} // namespace dht
} // namespace librats
