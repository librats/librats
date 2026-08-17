#pragma once

/**
 * @file peer_exchange.h
 * @brief Peer exchange (PEX): peers gossip the addresses of peers they know, so a
 *        node bootstraps the mesh from its existing links — no DHT/tracker needed.
 *
 * A Subsystem built on PeerNetwork, plus one optional capability: when a peer it
 * discovered refuses to be dialed and HolePunch is present, it asks for a NAT hole
 * punch to that peer's id instead of writing the peer off (see below). This first
 * cut is deliberately
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
 * ── Punch fallback ──────────────────────────────────────────────────────────
 * A PEX entry carries an id *and* an address, which is exactly what a peer behind a
 * NAT cannot be reached at: its advertised endpoint is unreachable from the outside,
 * so the dial fails and the mesh silently stays one link short. That is the case
 * HolePunch exists for, and PEX is the only module that holds both halves it needs —
 * so each dial started here is remembered by address for `punch_window`, and if
 * on_dial_failed reports that address back, the id is handed to HolePunchService.
 * Entirely optional: with no HolePunch attached the lookup answers nullptr and the
 * failure is simply the end of the story, as before.
 *
 * Safety: response size is capped both sides; the receiver bounds how many it
 * dials per response and de-duplicates dials with a TTL'd cooldown set (so a slow
 * dial or a repeated response can't trigger a connect storm); malformed payloads
 * are ignored, never fatal. `public_only` restricts sharing to globally-routable
 * addresses for WAN deployments that must not relay private/LAN endpoints. The
 * punch fallback inherits those bounds — one punch per dial we ourselves started,
 * and HolePunch caps sessions and cooldowns on top of that.
 *
 * Threading: handlers run on reactor threads (possibly several with a multi-reactor
 * pool), so the cooldown set is mutex-guarded. The subsystem owns no thread.
 */

#include "librats/util/rats_export.h"
#include "librats/node/peer_network.h"
#include "librats/peer/peer.h"
#include "librats/peer/peer_id.h"
#include "librats/core/address.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace librats {

class ServiceRegistry;
struct HolePunchService;

class RATS_API PeerExchange final : public Subsystem {
public:
    struct Config {
        size_t max_addresses_per_response = 32;  ///< cap entries we send / act on per response
        size_t request_max                = 32;  ///< how many peers we ask for on connect
        bool   request_on_connect         = true;
        bool   public_only                = false;  ///< only share globally-routable addresses
        std::chrono::milliseconds dial_cooldown{std::chrono::minutes(5)};  ///< re-dial suppression
        size_t max_recent_dials           = 4096;  ///< bound the cooldown set

        /// Stop dialing discovered peers once this many are connected. 0 (default)
        /// keeps the historical behaviour: grow without bound. Worth setting,
        /// because NodeConfig::max_peers guards *inbound* connections only — every
        /// discovered peer we dial is honored regardless of it, and PEX is the one
        /// discovery source that compounds (each new peer is asked for more peers).
        /// Answering other peers' requests is unaffected: that costs one message.
        size_t peer_target                = 0;

        /// Ask HolePunch to reach a discovered peer whose address would not dial.
        /// A no-op when no HolePunch is attached.
        bool punch_on_dial_failure        = true;
        /// How long a dial started here stays eligible for that fallback. Only has
        /// to outlive the dial itself (connect + handshake, ~15 s worst case).
        std::chrono::milliseconds punch_window{std::chrono::seconds(30)};
        /// Bound on dials awaiting their verdict — one entry is an address and an id.
        size_t max_pending_dials          = 512;
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
    /// An outbound dial resolved as failed. Ours ⇒ punch the peer it was meant for.
    void on_dial_failed(const Address& address);

    const Address* pick_shareable(const std::vector<Address>& addrs) const;
    bool           should_dial(const Address& addr);  ///< cooldown + dedup; records on success
    /// Note who a dial we are about to start was aimed at. Called BEFORE connect():
    /// the failure lands on a reactor thread and may beat us back here otherwise.
    void           remember_dial(const Address& addr, const PeerId& id);

    Config       config_;
    PeerNetwork* network_ = nullptr;
    ServiceRegistry*  services_ = nullptr;
    /// Resolved in start(), cleared in stop(). Atomic because a dial failure can
    /// land on a reactor thread the moment the node is up.
    std::atomic<HolePunchService*> punch_{nullptr};
    std::atomic<bool> running_{false};

    struct PendingDial {
        PeerId                                id;
        std::chrono::steady_clock::time_point started;
    };

    std::mutex mutex_;
    std::unordered_map<Address, std::chrono::steady_clock::time_point> recent_dials_;
    std::unordered_map<Address, PendingDial>                           pending_dials_;
};

} // namespace librats
