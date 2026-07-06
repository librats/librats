#pragma once

/**
 * @file routing_table.h
 * @brief A Kademlia routing table with libtorrent-style dynamic buckets.
 *
 * Pure in-memory state — no sockets, no locks. It lives entirely on the DHT actor
 * thread, so it never synchronises. It also never sends anything itself: liveness
 * pings are issued by the owning Node, which reports the outcome back through
 * node_seen() (it replied) / node_failed() (it timed out). That keeps the table a
 * testable data structure and the I/O in one place.
 *
 * Buckets are an ordered list rooted at our own id: buckets_[0] is the *farthest*
 * region of the keyspace and buckets_.back() the *closest* catch-all. When the last
 * bucket overflows and a split would actually separate its contacts, a new bucket is
 * appended and the contacts re-homed. Buckets near the top are larger (the extended
 * routing table) because that is where the keyspace — and the first hop of almost any
 * lookup — is densest, so more contacts there means fewer hops.
 *
 * Each bucket holds a *live* set — the contacts we route with, up to its size limit —
 * plus a small *replacement cache* of standbys promoted the moment a live contact
 * dies. Contact quality (RTT, failures, BEP 42 verification) lives on the NodeEntry
 * and drives who gets kept, refreshed, or evicted, while a sub-prefix "spread" rule
 * keeps a full bucket covering as many sub-branches as possible.
 *
 * Sybil/eclipse resistance (BEP 42). Admission is IP-diversity limited so no single
 * operator can pack the table with contacts it controls and hijack lookups:
 *   1. at most one contact per IP across the whole table, and
 *   2. at most one contact per /24 (IPv4) or /64 (IPv6) within any single bucket.
 * Only *public* addresses are constrained — private/loopback/CGNAT IPs can't be the
 * source of a real Sybil attack and would wrongly collide on a LAN (this mirrors the
 * BEP 42 exemption already applied by verify_node_id_for_ip). A per-IP count index
 * (ip_count_) makes rule 1 an O(1) check; rule 2 is a small per-bucket scan.
 */

#include "core/address.h"
#include "dht/id.h"
#include "dht/node_entry.h"

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace librats {
namespace dht {

class RoutingTable {
public:
    // Consecutive failures tolerated before a contact with no standby is dropped.
    static constexpr uint8_t kMaxFailCount = 5;

    // `extended` enables the larger top buckets (the extended routing table). On by
    // default for production; tests that want uniform k-sized buckets pass false.
    explicit RoutingTable(const NodeId& self, bool extended = true);

    // -- insertion --------------------------------------------------------------

    // We learned this node exists from someone else's reply. Recorded as unpinged
    // (a candidate to verify); it can fill a live slot but never splits or evicts a
    // confirmed contact. `verified` is the caller's BEP 42 verdict on the (id, ip)
    // pair, used only as a tie-breaker between unpinged candidates.
    void heard_about(const NodeId& id, const Address& endpoint, bool verified = false);

    // This node replied to us: recorded as confirmed with its RTT. A confirmed
    // contact may split a full bucket or displace a weaker one, but a healthy contact
    // alone in its sub-prefix slot is only removed via node_failed(). Returns true if
    // it ended up live.
    bool node_seen(const NodeId& id, const Address& endpoint,
                   uint16_t rtt = NodeEntry::kRttUnknown, bool verified = false);

    // A query to this node timed out. Since this only fires after a real liveness
    // check failed, the contact is replaced immediately if a standby is waiting;
    // otherwise it's kept until it exhausts kMaxFailCount, then dropped.
    void node_failed(const NodeId& id, const Address& endpoint);

    // -- queries ----------------------------------------------------------------

    // Up to `count` contacts closest to `target` (XOR metric), closest first. By
    // default only confirmed contacts are returned (for answering queries); pass
    // include_unconfirmed=true to also seed our own lookups from unpinged contacts.
    std::vector<NodeEntry> find_closest(const NodeId& target, std::size_t count = kBucketSize,
                                        bool include_unconfirmed = false) const;

    // The live contact most in need of a liveness check: the least-recently-touched
    // (a never-contacted contact sorts first). The chosen contact is stamped as touched
    // at `now`, so successive refreshes rotate through different contacts instead of
    // re-probing this one while its probe is still outstanding. nullopt when there are
    // no live contacts.
    std::optional<NodeEntry> next_to_refresh(std::chrono::steady_clock::time_point now);

    std::size_t size() const;                 // number of live contacts
    bool empty() const { return size() == 0; }
    int bucket_count() const noexcept { return static_cast<int>(buckets_.size()); }

    // A pretty, multi-line snapshot for periodic DEBUG logging: a header plus one row
    // per bucket with its live/limit fill bar and best & worst contact. Pure formatting,
    // no I/O — built only when actually logged (callers guard on the log level).
    std::string describe() const;

    // -- node id changes (BEP 42) ----------------------------------------------

    const NodeId& self() const noexcept { return self_; }
    void set_self(const NodeId& id);          // re-buckets every contact against the new id

    // -- persistence ------------------------------------------------------------

    std::vector<NodeEntry> good_contacts() const;                // confirmed live contacts, to save
    void load_contacts(const std::vector<NodeEntry>& contacts);  // bulk restore, preserving quality

    // -- diagnostics ------------------------------------------------------------

    // True iff the per-IP index (ip_count_) matches a fresh count over the buckets.
    // Cheap invariant used by tests to prove the IP accounting stays balanced across
    // arbitrary add/evict/fail churn; not needed at runtime.
    bool ip_index_consistent() const;

private:
    struct Bucket {
        std::vector<NodeEntry> live;          // active contacts, up to bucket_limit(index)
        std::vector<NodeEntry> replacements;  // standbys, up to kBucketSize
    };

    // The bucket `id` belongs to: its shared-prefix length with us, capped to the
    // last (catch-all) bucket. buckets_ is never empty, so this is always valid.
    int bucket_index(const NodeId& id) const noexcept;
    // Live-set size limit for a bucket by position: larger near the top when the
    // extended table is on, otherwise a flat kBucketSize.
    int bucket_limit(int index) const noexcept;

    // The one insertion path. `e` carries its own quality (pinged/confirmed via
    // fail_count). Returns true if it ended up in a live set.
    bool add_node(NodeEntry e);

    // -- IP-diversity admission (Sybil/eclipse resistance) ----------------------

    // May a genuinely new (not-already-known-by-id) contact `e` enter bucket `idx`?
    // Enforces the two rules above for public IPs only; a same-endpoint contact that
    // has quietly changed its id is evicted here as a poisoning signal. Non-public
    // addresses are always admissible. Rare collision handling lives in this one place.
    bool passes_ip_diversity(Bucket& b, int idx, const NodeEntry& e);

    // Locate the contact currently at endpoint `ep` (ip+port) anywhere in the table.
    // Only walked on a public-IP collision, so the O(table) cost is off the hot path.
    struct Located { int bucket; bool live; std::size_t index; };
    std::optional<Located> find_by_endpoint(const Address& ep);

    // Keep ip_count_ in lock-step with the buckets. The invariant is simple and local:
    // every push into a live/replacement set calls ip_track, every removal ip_untrack,
    // and an in-place overwrite goes through assign() (untrack old + track new). Moves
    // between the two sets are therefore self-balancing. Only public IPs are indexed.
    void ip_track(const IpAddress& ip);
    void ip_untrack(const IpAddress& ip);
    void assign(NodeEntry& slot, const NodeEntry& e);  // overwrite a slot, keeping the index synced

    // May the (full, last) bucket at `index` be split to fit a confirmed `e`?
    bool can_split(int index, const NodeEntry& e) const;
    // Append a bucket and re-home the old last bucket's contacts by shared prefix.
    void split_bucket();
    // Bucket `b` (index `index`, limit `limit`) is full and `e` is confirmed: free a
    // slot by evicting the least valuable node while preserving sub-prefix spread.
    bool replace_for_spread(Bucket& b, int index, int limit, const NodeEntry& e);
    // Add/refresh a standby, evicting the worst one if the cache is full.
    void stash_replacement(Bucket& b, const NodeEntry& entry);
    // Spill live-set overflow into replacements and cap the cache (after a split).
    void trim_to_limit(int index);
    // Promote the best standbys into any free live slots a split opened up, so a
    // parked contact isn't stuck (replacements are never pinged or refreshed).
    void fill_from_replacements(int index);
    // Drop trailing empty buckets, but always keep at least one.
    void prune_empty_back();

    NodeId self_;
    bool extended_;
    std::vector<Bucket> buckets_;  // [0] = farthest, back() = closest catch-all

    // Count of live+replacement contacts per *public* IP across the whole table. Backs
    // rule 1 (one contact per IP) as an O(1) lookup; kept balanced by ip_track/untrack.
    std::unordered_map<IpAddress, int> ip_count_;
};

} // namespace dht
} // namespace librats
