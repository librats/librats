#pragma once

/**
 * @file relay.h
 * @brief Reaching a peer through a node both ends can already reach.
 *
 * The last rung of the connectivity ladder. A direct dial handles the easy cases;
 * PortMappingService and HolePunch handle most of the rest. What is left is the
 * pair of nodes for which no endpoint either one can advertise will ever work —
 * a symmetric NAT on one side, a network that drops UDP and blocks inbound TCP,
 * a punch that simply never lands. For them the only way through is to borrow a
 * path: a node connected to both carries the bytes.
 *
 * ── What is relayed, and what is not ────────────────────────────────────────
 * The relayed thing is a *byte stream*, not a message. It becomes a `Circuit` and
 * a `RelayLink` (transport/relay_link.h), the reactor adopts it as an ordinary
 * Connection, and everything above the Link runs unchanged — which is why:
 *
 *   - the Noise_XX handshake is END TO END. The relay moves ciphertext it cannot
 *     read, cannot forge and cannot replay. It is a pipe, not a party, and it
 *     learns nothing beyond who is talking to whom and how much;
 *   - the peers authenticate each other's real keys, so a relay cannot substitute
 *     itself for either end;
 *   - every subsystem — pub/sub, file transfer, PEX — works over a relayed peer
 *     with no code of its own. To the application it is simply a peer, and
 *     PeerInfo::transport is the only thing that says otherwise.
 *
 * ── Finding a relay ─────────────────────────────────────────────────────────
 * This stage covers the case where the two ends share a peer — the same topology
 * HolePunch already relies on for its rendezvous, and the one a bootstrap or DHT
 * mesh produces on its own. The initiator asks a few of its peers "do you hold
 * this id?" (Probe) and opens a circuit with the first that says yes. Probing
 * first, rather than opening with everybody at once, is what keeps a successful
 * search from producing three redundant connections to the same peer — each with
 * its own handshake — for the peer table to then tear two of down.
 *
 * Not covered here, deliberately: reaching a peer with whom we share NO peer. That
 * needs reservations (a node asking a relay to hold a slot for it) and a way to
 * advertise "reachable via R" as an address, which touches identify and PEX. The
 * version byte and the free op-codes in the wire format leave room for it.
 *
 * ── Getting off the relay again ─────────────────────────────────────────────
 * A circuit is a fallback, not a destination: it costs a third node bandwidth and
 * a round trip. So when one comes up, this module asks HolePunch to try the target
 * again — now that the two ends are peers, they can exchange what a punch needs
 * over the very circuit that is carrying them. If the punch lands, PeerTable::add
 * prefers the direct link at BOTH ends (any direct transport outranks Relay) and
 * swaps the route with no disconnect event: the application never sees the seam.
 *
 * ── Carrying other peers' traffic ───────────────────────────────────────────
 * Serving as a relay is off by default. Forwarding a rendezvous, as HolePunch
 * does, is a few dozen bytes; forwarding a connection is somebody else's file
 * transfer on your uplink, and that is a decision to be made rather than assumed.
 * A node that turns it on is protected by, in order of how much they matter:
 *
 *   - the end-to-end credit window (transport/relay_link.h), which bounds what one
 *     circuit can make the relay hold no matter what either end does. Without it a
 *     slow receiver would grow the relay's send queue until the relay dropped that
 *     peer entirely — losing all of its traffic, not just the circuit's;
 *   - forwarding only between peers it already holds. A relay never dials, never
 *     resolves an address, and can only ever deliver to somebody that chose to
 *     connect to it, so it cannot be turned into an open reflector;
 *   - no chaining. A circuit is refused if either end is itself only reachable
 *     through a relay, which is what stops loops and multi-hop amplification;
 *   - per-circuit byte and duration caps, per-peer and total circuit counts, and a
 *     rate limit on the requests themselves.
 *
 * ── Threading ───────────────────────────────────────────────────────────────
 * Message handlers run on reactor threads; one worker thread drives attempt
 * timeouts and the relay's own expiry. The tables are behind one mutex, which is
 * never held across a call into a circuit or the reactor — a circuit is touched
 * only by the reactor thread that owns its connection, which is by construction
 * the thread that owns its carrier's (see node/circuit_service.h).
 */

#include "librats/util/rats_export.h"
#include "librats/core/service_registry.h"
#include "librats/node/peer_network.h"
#include "librats/peer/peer_id.h"
#include "librats/subsystems/relay_service.h"
#include "librats/transport/relay_link.h"   // Circuit::kDefaultWindow

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>

namespace librats {

class RATS_API Relay final : public Subsystem, public RelayService {
public:
    struct Config {
        // ── Using relays to reach peers we cannot dial ──────────────────────

        /// Open circuits through other peers. Off makes this a relay-only node.
        bool enable_client = true;

        /// Peers asked whether they hold a target, per attempt. Small: each probe
        /// is a question to somebody who probably cannot help, and one useful
        /// answer is all an attempt needs.
        size_t max_probes = 3;

        /// Circuits this node may hold open as a client at once. Bounds both memory
        /// and how many relayed peers a discovery module can talk us into.
        size_t max_outbound_circuits = 8;

        /// How long an attempt may take from the first probe to a live connection.
        /// Covers the probe round trip, the circuit setup, and the handshake across
        /// two hops.
        std::chrono::milliseconds open_timeout{8000};

        /// How long after a failed attempt before the same target may be tried
        /// again. Only an attempt WE started ever ends in one.
        std::chrono::milliseconds cooldown{60000};

        // ── Accepting circuits opened to us ─────────────────────────────────

        /// Accept circuits other peers open toward us. Off makes this node
        /// unreachable by relay, which is a choice a well-connected node can make.
        bool accept_inbound = true;

        /// Circuits opened TO us that may be live at once.
        size_t max_inbound_circuits = 16;

        // ── Carrying other peers' traffic ───────────────────────────────────

        /// Serve as a relay. OFF by default: unlike a hole-punch rendezvous, this
        /// spends real bandwidth on somebody else's connection, so it is opted into
        /// rather than assumed. A mesh in which nobody serves cannot relay at all.
        bool serve = false;

        /// Circuits this node will carry for others at once.
        size_t max_circuits = 32;

        /// Circuits one peer may have us carrying, so a single peer cannot take the
        /// whole budget.
        size_t max_circuits_per_peer = 2;

        /// Bytes one circuit may move before it is closed. 0 removes the cap. The
        /// default is generous for a fallback path and still bounds what one pair
        /// of peers can spend of ours.
        uint64_t max_bytes_per_circuit = 64ull * 1024 * 1024;

        /// How long one circuit may live. 0 removes the cap.
        std::chrono::seconds max_circuit_duration{600};

        /// Requests (probes and circuit openings) one peer may make per window.
        size_t                    request_budget = 8;
        std::chrono::milliseconds request_window{1000};

        // ── Both ends ───────────────────────────────────────────────────────

        /// Bytes this node is willing to have in flight per circuit — the credit
        /// window it advertises (see transport/relay_link.h). Raising it makes a
        /// relayed peer faster on a long path and asks the relay to hold more.
        uint32_t window = Circuit::kDefaultWindow;

        /// When a relayed peer connects, ask HolePunch to try it directly, so the
        /// circuit is replaced by a direct link as soon as one is possible. Costs
        /// nothing when no HolePunch is attached.
        bool upgrade_with_hole_punch = true;

        /// Bookkeeping cadence — attempt timeouts, cooldowns, circuit expiry.
        std::chrono::milliseconds tick{250};
    };

    Relay();
    explicit Relay(Config config);
    ~Relay() override;

    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

    /// @copydoc RelayService::connect_via_relay
    bool connect_via_relay(const PeerId& target) override;

    // — diagnostics and tests —
    /// Circuits this node terminates (relayed peers, live or still being set up).
    size_t circuits() const;
    /// Circuits this node is carrying on behalf of other peers.
    size_t carried_circuits() const;
    /// Bytes forwarded on behalf of other peers.
    uint64_t carried_bytes() const;
    /// Attempts to reach a peer through a relay that are currently running.
    size_t attempts() const;

private:
    /// Everything mutable, held by shared_ptr because a Connection — and therefore
    /// the Link that reports its circuit released — can outlive this subsystem: the
    /// node stops subsystems before it stops the reactors that own the connections.
    struct State;

    Config                 config_;
    std::shared_ptr<State> state_;
    /// Kept from attach() so start() can resolve HolePunchService — which may be
    /// attached after us, and is only guaranteed to have registered by then.
    ServiceRegistry*       services_ = nullptr;

    std::thread             worker_;
    std::atomic<bool>       running_{false};
    std::mutex              worker_mutex_;
    std::condition_variable worker_cv_;

    void loop();
};

} // namespace librats
