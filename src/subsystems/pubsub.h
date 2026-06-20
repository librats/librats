#pragma once

/**
 * @file pubsub.h
 * @brief Topic-based publish/subscribe — a GossipSub implementation over PeerNetwork.
 *
 * This is the real GossipSub, not plain floodsub. Each subscribed topic maintains
 * a bounded *mesh* of full-message peers (formed and torn down with GRAFT/PRUNE),
 * published messages are eagerly pushed along the mesh, and a lazy-pull gossip
 * layer (IHAVE/IWANT, driven by the heartbeat) lets a peer recover a message it
 * missed. Publishing to a topic we are not subscribed to uses a short-lived
 * *fanout* set instead of a mesh. A node-id+sequence dedup key stops a message
 * looping around the mesh, and a message cache keeps recent payloads so IWANT can
 * be answered with real content.
 *
 * It depends on nothing but PeerNetwork — no Node, no reactor internals, no
 * `friend`. A background heartbeat thread (started by start(), joined by stop())
 * runs mesh maintenance and gossip emission once per interval.
 *
 * Wire format (MessageType::Gossip payload), all integers big-endian. The first
 * byte is the op; a 40-byte message id is origin(32 id-bytes) || seqno(u64 BE):
 *   PUBLISH     [0][origin:32][seqno:u64][topic_len:u16][topic][data]
 *   SUBSCRIBE   [1][topic_len:u16][topic]
 *   UNSUBSCRIBE [2][topic_len:u16][topic]
 *   GRAFT       [3][topic_len:u16][topic]          // "add me to your mesh for topic"
 *   PRUNE       [4][topic_len:u16][topic]          // "drop me from your mesh for topic"
 *   IHAVE       [5][topic_len:u16][topic][count:u16][id:40]*   // "I hold these message ids"
 *   IWANT       [6][count:u16][id:40]*                          // "send me these message ids"
 */

#include "node/peer_network.h"
#include "peer/peer.h"
#include "core/bytes.h"
#include "peer/peer_id.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace librats {

/// Outcome of validating an inbound published message before it is delivered or
/// forwarded. REJECT drops it (and would penalise the sender in a scored build);
/// IGNORE drops it silently; ACCEPT delivers locally and forwards along the mesh.
enum class ValidationResult { Accept, Reject, Ignore };

class PubSub final : public Subsystem {
public:
    using Handler   = std::function<void(const PeerId& from, const std::string& topic, ByteView data)>;
    using Validator = std::function<ValidationResult(const PeerId& from, const std::string& topic, ByteView data)>;

    /// GossipSub tuning. Defaults mirror the libp2p reference (D=6, D_low=4,
    /// D_high=12) and are sensible for small-to-medium meshes.
    struct Config {
        int mesh_target   = 6;   ///< D     — desired mesh degree per topic
        int mesh_low      = 4;   ///< D_low — graft more peers below this
        int mesh_high     = 12;  ///< D_high— prune peers above this
        int fanout_size   = 6;   ///< peers used to publish to a topic we are not subscribed to
        int gossip_factor = 6;   ///< D_lazy— peers we emit IHAVE to per heartbeat per topic
        std::chrono::milliseconds fanout_ttl{60000};         ///< drop a fanout set idle this long
        std::chrono::milliseconds heartbeat_interval{1000};  ///< mesh maintenance + gossip cadence
        int    history_length = 5;     ///< heartbeat windows the message cache keeps (for IWANT)
        int    history_gossip = 3;     ///< of those, how many windows IHAVE advertises
        size_t seen_limit     = 8192;  ///< dedup ids remembered
    };

    PubSub();
    explicit PubSub(Config config);
    ~PubSub() override;

    /// Subscribe to a topic and deliver matching messages to `handler`.
    void subscribe(const std::string& topic, Handler handler);
    void unsubscribe(const std::string& topic);

    /// Publish `data` on `topic`: along the mesh if we are subscribed, else via fanout.
    void publish(const std::string& topic, ByteView data);

    bool                     is_subscribed(const std::string& topic) const;
    std::vector<std::string> subscribed_topics() const;
    std::vector<PeerId>      peers_for_topic(const std::string& topic) const;  ///< known subscribers
    std::vector<PeerId>      mesh_peers(const std::string& topic) const;       ///< our mesh for topic

    /// Gate inbound messages for a topic; `topic == ""` installs a global validator
    /// used when no per-topic validator is registered.
    void set_validator(const std::string& topic, Validator validator);

    // Subsystem.
    void attach(NodeContext& ctx) override;
    void start() override;  ///< launch the heartbeat thread
    void stop() override;   ///< stop and join it

private:
    struct Topic {
        std::unordered_set<PeerId, PeerId::Hash> subscribers;  ///< peers that announced interest
        std::unordered_set<PeerId, PeerId::Hash> mesh;         ///< full-message peering (we subscribe)
        std::unordered_set<PeerId, PeerId::Hash> fanout;       ///< publish targets when not subscribed
        std::chrono::steady_clock::time_point    last_fanout{};
    };

    struct CachedMessage {
        std::string topic;
        Bytes       frame;  ///< the whole PUBLISH frame, resent verbatim to answer IWANT
    };

    // Inbound dispatch (all run on a reactor thread).
    void on_new_peer(const Peer& peer);
    void on_peer_gone(const PeerId& id);
    void on_gossip(const Peer& peer, ByteView payload);

    void recv_subscription(const PeerId& from, const std::string& topic, bool subscribe);
    void recv_graft(const PeerId& from, const std::string& topic);
    void recv_prune(const PeerId& from, const std::string& topic);
    void recv_publish(const PeerId& from, ByteView frame, const PeerId& origin, uint64_t seqno,
                      const std::string& topic, ByteView data);
    void recv_ihave(const PeerId& from, const std::string& topic, const std::vector<std::string>& ids);
    void recv_iwant(const PeerId& from, const std::vector<std::string>& ids);

    // Heartbeat (background thread).
    void heartbeat_loop();
    void do_heartbeat();

    /// Bring `topic`'s mesh toward [mesh_low, mesh_high] around mesh_target, queuing
    /// the GRAFT/PRUNE control messages to send after the lock is released. Requires
    /// `mutex_` held; a no-op unless we are subscribed to `topic`.
    using CtrlList = std::vector<std::pair<PeerId, std::string>>;
    void maintain_mesh_locked(const std::string& topic, CtrlList& grafts, CtrlList& prunes);

    // Helpers.
    void send_ctrl(const PeerId& to, uint8_t op, const std::string& topic);
    void broadcast_ctrl(uint8_t op, const std::string& topic);
    void deliver_local(const PeerId& from, const std::string& topic, ByteView data);
    Handler          handler_for(const std::string& topic) const;
    ValidationResult validate(const PeerId& from, const std::string& topic, ByteView data);
    bool             mark_seen(const std::string& id);             ///< false if already seen
    void             cache_message(const std::string& id, const std::string& topic, const Bytes& frame);
    std::vector<PeerId> random_sample(std::vector<PeerId> in, int n);

    PeerNetwork* network_ = nullptr;
    Config       config_;

    mutable std::mutex mutex_;  ///< guards subscriptions_, topics_, validators_, seqno_
    uint64_t           seqno_ = 0;
    std::unordered_map<std::string, Handler>   subscriptions_;  ///< topic -> local handler
    std::unordered_map<std::string, Topic>     topics_;         ///< topic -> peering state
    std::unordered_map<std::string, Validator> validators_;     ///< topic -> validator
    Validator                                  global_validator_;

    mutable std::mutex mcache_mutex_;  ///< guards mcache_, history_, seen_*
    std::unordered_map<std::string, CachedMessage> mcache_;     ///< id -> cached frame (for IWANT)
    std::deque<std::vector<std::string>>           history_;    ///< gossip windows of ids (front = newest)
    std::unordered_set<std::string>                seen_;       ///< dedup set
    std::deque<std::string>                        seen_order_; ///< FIFO eviction order for seen_

    std::mutex   rng_mutex_;
    std::mt19937 rng_;

    std::atomic<bool>       running_{false};
    std::thread             heartbeat_thread_;
    std::mutex              hb_mutex_;
    std::condition_variable hb_cv_;
};

} // namespace librats
