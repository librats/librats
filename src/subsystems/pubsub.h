#pragma once

/**
 * @file pubsub.h
 * @brief Topic-based publish/subscribe over PeerNetwork.
 *
 * A clean re-implementation of the pub/sub subsystem on the redesigned plugin
 * model. It is subscription-aware floodsub: peers announce which topics they are
 * subscribed to, a published message is forwarded only to peers interested in
 * its topic, and a per-message dedup key stops it looping around the mesh.
 *
 * This is the foundation the full GossipSub refinements layer onto later
 * (bounded mesh degree, IHAVE/IWANT lazy push, peer scoring). Depends on nothing
 * but PeerNetwork — no Node, no reactor internals, no `friend`.
 *
 * Wire format (MessageType::Gossip payload), all integers big-endian:
 *   PUBLISH:     [0][origin:32][seqno:u64][topic_len:u16][topic][data]
 *   SUBSCRIBE:   [1][topic_len:u16][topic]
 *   UNSUBSCRIBE: [2][topic_len:u16][topic]
 */

#include "node/peer_network.h"
#include "peer/peer.h"
#include "core/bytes.h"
#include "peer/peer_id.h"

#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace librats {

class PubSub final : public Subsystem {
public:
    using Handler = std::function<void(const PeerId& from, const std::string& topic, ByteView data)>;

    /// Subscribe to a topic and deliver matching messages to `handler`.
    void subscribe(const std::string& topic, Handler handler);
    void unsubscribe(const std::string& topic);

    /// Publish `data` on `topic` to every subscribed peer (and local subscribers).
    void publish(const std::string& topic, ByteView data);

    std::vector<std::string> subscribed_topics() const;
    std::vector<PeerId>      peers_for_topic(const std::string& topic) const;

    // Subsystem (no background thread — fully event-driven).
    void attach(PeerNetwork& network) override;
    void start() override {}
    void stop() override {}

private:
    void on_new_peer(const Peer& peer);
    void on_peer_gone(const PeerId& id);
    void on_gossip(const Peer& peer, ByteView payload);

    void send_subscription(const PeerId& to, const std::string& topic, bool subscribe);
    void deliver_local(const PeerId& from, const std::string& topic, ByteView data);
    bool mark_seen(const std::string& key);   ///< false if the key was already seen

    PeerNetwork* network_ = nullptr;

    mutable std::mutex mutex_;
    uint64_t           seqno_ = 0;
    std::unordered_map<std::string, Handler> subscriptions_;  ///< topic → local handler
    std::unordered_map<PeerId, std::unordered_set<std::string>, PeerId::Hash> remote_subs_;

    std::mutex                      seen_mutex_;
    std::unordered_set<std::string> seen_set_;
    std::deque<std::string>         seen_order_;
    static constexpr size_t         kSeenLimit = 8192;
};

} // namespace librats
