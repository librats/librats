#pragma once

/**
 * @file hole_punch.h
 * @brief UDP hole punching: two nodes behind NATs dial each other at the same
 *        instant, arranged through a peer they both already have.
 *
 * ── Why this can work at all ────────────────────────────────────────────────
 * A NAT drops an inbound datagram unless something went out to that peer first.
 * So neither side can be dialed — but if BOTH dial at once, each one's outbound
 * Syn opens the mapping and the filter its peer's Syn needs, and the two cross
 * mid-path. Whichever direction survives becomes an ordinary connection.
 *
 * Everything below that is already in place and is deliberately left alone:
 *
 *   - The punch packet is the Syn. A datagram dial sends one immediately
 *     (UdpMux::connect) and retries it, so a punch needs no new packet type on the
 *     wire — only a different retry shape (DialProfile::punch(): dense probes with
 *     no backoff, because the first Syns are *expected* to die on the peer's NAT).
 *   - One socket, one mapping. Every UDP peer shares the node's single datagram
 *     socket, so the port a peer sees us send from is the port anyone can aim at.
 *     That is what identify now reports on datagram links, and what nat_status.h
 *     turns into "is this mapping stable enough to punch through at all".
 *   - Both sides succeeding is fine. A punch normally lands in both directions,
 *     leaving two connections; PeerTable::add resolves that pair identically at
 *     both ends (the link from the smaller PeerId survives), exactly as it does for
 *     any simultaneous cross-connect.
 *
 * ── The only genuinely hard part: agreeing on "now" ─────────────────────────
 * Punching works when the two bursts overlap, and the peers have no shared clock.
 * The fix (as in libp2p's DCUtR) is to derive the instant from the round trip
 * itself rather than from any clock. With A the initiator, B the target and R a
 * peer both are connected to:
 *
 *   1. A →R→ B   Connect{addrs of A}          A notes the time it sent this
 *   2. B →R→ A   Connect{addrs of B}          B now waits
 *   3. A →R→ B   Sync                         A starts dialing AT ONCE
 *   4.           B receives Sync              B starts dialing AT ONCE
 *
 * A starts half a relayed round trip early and B starts on arrival, so the two
 * bursts meet in the middle of the path. No clock synchronisation, and the accuracy
 * degrades gracefully — a slow relay widens the window rather than breaking it,
 * which is why the punch profile fires several probes instead of one.
 *
 * ── The relay ───────────────────────────────────────────────────────────────
 * R is an ordinary node running this same subsystem. It forwards ONLY control
 * messages, ONLY to a peer it is already connected to, and ONLY within a per-peer
 * budget. It never opens a connection, never resolves an address and never carries
 * application data — so it cannot be turned into an open reflector, and the traffic
 * it does relay is a few dozen bytes per punch.
 *
 * ── Wire format (MessageType::Punch), big-endian ────────────────────────────
 *   envelope : [u8 ver=1][u8 op]
 *              op=0 Relay   : [32B dst_id][inner…]   sender → relay
 *              op=1 Relayed : [32B src_id][inner…]   relay  → destination
 *   inner    : [u8 kind]
 *              kind=0 Connect : [u8 role][u8 n][ n × { u8 ip_len, ip bytes, u16 port } ]
 *              kind=1 Sync    : —
 *
 * `role` says whether a Connect opens a rendezvous (0) or answers one (1). Without
 * it the two are indistinguishable, and an initiator would read the answer it asked
 * for as a competing rendezvous — hand the round to the peer, and the exchange would
 * ping-pong Connects forever with neither side ever sending Sync. It is also what
 * makes the collision case (both ends opening at once) recognisable, and therefore
 * settleable by the same symmetric PeerId rule the peer table uses.
 *
 * The inner message is end-to-end between the two punching peers; the relay copies
 * it across without looking inside. Every length is bounds-checked and every count
 * capped, so a malformed or hostile payload is dropped rather than acted on.
 *
 * ── What this does NOT do ───────────────────────────────────────────────────
 * A symmetric NAT (a fresh mapping per destination) cannot be punched through by
 * any endpoint we can advertise, and this subsystem does not pretend otherwise: it
 * checks NatMapping first and declines rather than firing a burst that cannot land.
 * There is no TCP punching (the datagram wire is the one that fits), no port
 * prediction (it would need more than the one socket the design is built on) and no
 * relaying of data (a punch that fails, fails).
 *
 * Trust: the addresses a peer advertises for itself are its own unverified word, and
 * a relay could forge a Connect naming somebody else's endpoint. Acting on that
 * means sending a handful of 16-byte Syns to an address of another node's choosing —
 * the same exposure PeerExchange already accepts when it dials what a peer told it
 * about, and bounded here by the per-session address cap and the retry limits.
 *
 * Threading: message handlers run on reactor threads; one worker thread drives
 * session timeouts and retries. All session state is behind one mutex, and no
 * blocking work happens on a reactor thread.
 */

#include "librats/util/rats_export.h"
#include "librats/core/address.h"
#include "librats/core/types.h"
#include "librats/node/nat_status.h"
#include "librats/node/peer_network.h"
#include "librats/peer/peer.h"
#include "librats/peer/peer_id.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace librats {

class DialService;

class RATS_API HolePunch final : public Subsystem {
public:
    struct Config {
        /// Peers asked to carry one punch's rendezvous. More than one because we
        /// cannot know which of our peers also has the target; each relay that does
        /// not simply drops the request. Small, because every extra relay is a
        /// duplicate rendezvous the target has to recognise and ignore.
        size_t max_relays = 3;

        /// Endpoints advertised to the target, and therefore dialed by it. Capped:
        /// this is the fan-out one peer's claim can make us produce.
        size_t max_addresses = 4;

        /// Rendezvous rounds before a target is given up on for `cooldown`.
        int attempts = 3;

        /// How long one round may take from the first Connect to a live connection.
        /// Covers two relayed hops plus the punch burst itself.
        std::chrono::milliseconds round_timeout{6000};

        /// How long after giving up before the same target may be punched again.
        /// Only a rendezvous WE opened ever ends in one: a round we merely answered
        /// timing out says nothing about the target, and calling it off there would
        /// silently drop the retries the initiator is already sending.
        std::chrono::milliseconds cooldown{60000};

        /// Concurrent punch sessions. Bounds both memory and how many dial bursts
        /// this node can be talked into producing at once.
        size_t max_sessions = 32;

        /// Serve as a rendezvous for other peers' punches. Cheap (a few dozen bytes
        /// forwarded per punch) but it is still work done on somebody else's behalf,
        /// so it is a choice rather than an assumption.
        bool enable_relay = true;

        /// Relay budget: messages one peer may have forwarded per window. A punch
        /// costs two forwarded messages per round, so the default leaves generous
        /// room for honest use while capping what one peer can spend us.
        size_t                    relay_budget = 12;
        std::chrono::milliseconds relay_window{1000};

        /// Refuse to punch when the mesh says our own mapping is per-destination
        /// (symmetric NAT): no endpoint we could advertise would be the one the
        /// target's packets arrive on, so the burst cannot land. Turn off only to
        /// try anyway (a NAT can be misclassified by an unlucky sample).
        bool skip_when_endpoint_dependent = true;

        /// How hard each punch dial retries its Syn.
        DialProfile profile = DialProfile::punch();

        /// Session bookkeeping cadence — retries, timeouts, cooldown expiry.
        std::chrono::milliseconds tick{250};
    };

    HolePunch();
    explicit HolePunch(Config config);
    ~HolePunch() override;

    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

    /// Try to reach `target` by punching. Non-blocking: the rendezvous runs in the
    /// background and a successful punch surfaces as an ordinary peer-connected
    /// event. A no-op when already connected to the target, when a session for it
    /// is already running, when it is still in cooldown, or when this node has
    /// nothing punchable to advertise (see nat_status.h).
    /// @return whether a session was actually started.
    bool punch(const PeerId& target);

    /// Sessions currently in flight (diagnostics and tests).
    size_t active_sessions() const;
    /// Punch bursts this node has fired (diagnostics and tests).
    uint64_t punches_started() const noexcept { return punches_started_.load(); }
    /// Messages forwarded on behalf of other peers (diagnostics and tests).
    uint64_t relayed() const noexcept { return relayed_.load(); }

private:
    enum class Phase : uint8_t {
        AwaitingPeerConnect,  ///< initiator: our Connect is out, waiting for theirs
        AwaitingSync,         ///< responder: our Connect is out, waiting for Sync
        Punching,             ///< the burst is in flight
    };

    struct Session {
        bool                                  initiator = false;
        Phase                                 phase = Phase::AwaitingPeerConnect;
        int                                   attempt = 0;
        std::vector<Address>                  peer_addresses;
        std::chrono::steady_clock::time_point deadline{};
        /// The relay that last carried something from the target, if any. Once one
        /// hop is known to work, the rest of the exchange goes back the same way —
        /// it is the one path proven to reach the target, and it keeps the fan-out
        /// (and the load on peers that cannot help) to the first message alone.
        PeerId                                via{};
        bool                                  have_via = false;
    };

    // — message handling (reactor threads) —
    void handle(const Peer& from, ByteView payload);
    void handle_relay_request(const Peer& from, const PeerId& dst, ByteView inner);
    void handle_relayed(const Peer& via, const PeerId& src, ByteView inner);
    /// @param opening whether the sender is opening a rendezvous (rather than
    ///        answering ours) — see the `role` byte in the wire format above.
    void handle_connect(const Peer& via, const PeerId& src, bool opening,
                        std::vector<Address> addresses);
    void handle_sync(const PeerId& src);

    // — outgoing —
    /// Wrap `inner` in a Relay envelope and hand it to peers that might reach `dst`:
    /// just `via` when a working hop is already known, otherwise up to max_relays of
    /// our peers. Returns how many were given it.
    size_t relay_to(const PeerId& dst, const Bytes& inner, const PeerId* via);
    bool   send_connect(const PeerId& target, bool opening, const PeerId* via);
    void   send_sync(const PeerId& target, const PeerId* via);
    /// Fire the dial burst at everything the peer advertised. Caller must NOT hold
    /// the mutex: dialing reaches the reactor, which may run callbacks inline.
    void   fire_punch(const PeerId& target, const std::vector<Address>& addresses);

    // — worker —
    void loop();
    void service_sessions();

    // — helpers —
    std::vector<Address> own_punch_addresses() const;
    bool                 relay_budget_ok(const PeerId& from);
    bool                 in_cooldown(const PeerId& target) const;   ///< caller holds mutex_
    void                 begin_cooldown(const PeerId& target);      ///< caller holds mutex_

    Config                 config_;
    PeerNetwork*           network_  = nullptr;
    DialService*           dialer_   = nullptr;
    ExternalAddressService* external_ = nullptr;

    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> punches_started_{0};
    std::atomic<uint64_t> relayed_{0};

    mutable std::mutex      mutex_;
    std::condition_variable cv_;
    std::thread             worker_;
    std::unordered_map<PeerId, Session, PeerId::Hash> sessions_;
    std::unordered_map<PeerId, std::chrono::steady_clock::time_point, PeerId::Hash> cooldown_;

    struct RelayBudget {
        std::chrono::steady_clock::time_point window_started{};
        size_t                                spent = 0;
    };
    std::mutex                                              relay_mutex_;
    std::unordered_map<PeerId, RelayBudget, PeerId::Hash>    relay_budget_;
};

} // namespace librats
