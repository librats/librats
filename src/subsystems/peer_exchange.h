#pragma once

/**
 * @file peer_exchange.h
 * @brief Peer exchange (PEX): peers gossip the addresses of peers they know, so a
 *        node bootstraps the mesh from its existing links — no DHT/tracker needed.
 *
 * A Subsystem built purely on PeerNetwork. This first cut is deliberately
 * **pull-only**: when we connect to a peer we ask it for some of its known peers,
 * and it replies with a random sample (address + id). We then dial the ones we do
 * not already have. Both sides must run PeerExchange — the responder needs it to
 * answer the request.
 *
 * It rides on the node's identify layer: identify is what fills in each peer's
 * dialable address (an inbound peer's listen port is otherwise unknown), and PEX
 * simply forwards those addresses on. A discovered peer we dial becomes an
 * outbound link, so — paired with ReconnectionService — it is then persisted and
 * kept alive automatically.
 *
 * Wire format (MessageType::Pex payload), all integers big-endian:
 *   Request  : [u8 ver=1][u8 op=0][u16 max]
 *   Response : [u8 ver=1][u8 op=1][u16 count] × { [u8 ip_len][ip][u16 port][32B peer_id] }
 *
 * Safety: response size is capped both sides; the receiver bounds how many it
 * dials per response and de-duplicates dials with a TTL'd cooldown set (so a slow
 * dial or a repeated response can't trigger a connect storm); malformed payloads
 * are ignored, never fatal. `public_only` restricts sharing to globally-routable
 * addresses for WAN deployments that must not relay private/LAN endpoints.
 *
 * Threading: handlers run on reactor threads (possibly several with a multi-reactor
 * pool), so the cooldown set is mutex-guarded. The subsystem owns no thread.
 */

#include "node/peer_network.h"
#include "peer/peer.h"
#include "peer/peer_id.h"
#include "core/address.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace librats {

class PeerExchange final : public Subsystem {
public:
    struct Config {
        size_t max_addresses_per_response = 32;  ///< cap entries we send / act on per response
        size_t request_max                = 32;  ///< how many peers we ask for on connect
        bool   request_on_connect         = true;
        bool   public_only                = false;  ///< only share globally-routable addresses
        std::chrono::milliseconds dial_cooldown{std::chrono::minutes(5)};  ///< re-dial suppression
        size_t max_recent_dials           = 4096;  ///< bound the cooldown set
    };

    PeerExchange();
    explicit PeerExchange(Config config);
    ~PeerExchange() override;

    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

private:
    void on_connected(const Peer& peer);
    void handle(const Peer& peer, ByteView payload);
    void handle_request(const Peer& requester, uint16_t max);
    void handle_response(ByteView body);

    const Address* pick_shareable(const std::vector<Address>& addrs) const;
    bool           should_dial(const Address& addr);  ///< cooldown + dedup; records on success

    Config       config_;
    PeerNetwork* network_ = nullptr;
    std::atomic<bool> running_{false};

    std::mutex mutex_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> recent_dials_;
};

} // namespace librats
