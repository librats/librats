#include "librats/subsystems/relay.h"

#include "librats/core/io_poller.h"        // PollIn / PollOut / PollErr
#include "librats/node/circuit_service.h"
#include "librats/node/node_context.h"
#include "librats/peer/peer.h"
#include "librats/peer/peer_info.h"
#include "librats/subsystems/hole_punch_service.h"
#include "librats/util/logger.h"

#include <algorithm>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace librats {

namespace {

// ── Wire format (MessageType::Relay), big-endian ────────────────────────────
//
//   [u8 ver=1][u8 op][u32 circuit][body]
//
//     op=1 Open     [32B dst][u32 window]   client → relay
//     op=2 Incoming [32B src][u32 window]   relay  → target
//     op=3 Accept   [u32 window]            target → relay → client
//     op=4 Deny     [u8 reason]             relay → client, or target → relay → client
//     op=5 Data     [bytes]                 end to end, through the relay
//     op=6 Credit   [u32 bytes]             end to end, through the relay
//     op=7 Close    [u8 reason]             either end, or the relay
//     op=8 Probe    [32B dst]               client → relay        (circuit = 0)
//     op=9 ProbeOk  [32B dst]               relay  → client       (circuit = 0)
//
// `circuit` is scoped to the LINK the message travels on, never globally: the
// relay holds two ids for one circuit, one per side, and translates between them.
// Both ends of a link allocate ids from that one space without coordinating, by
// parity — the smaller PeerId takes the even ids, the larger the odd ones, which
// both compute identically from what they already know. Ids 0 and 1 are reserved.
//
// Every length is bounds-checked and the payload is capped, so a malformed or
// hostile message is dropped rather than acted on.

constexpr uint8_t kVersion    = 1;
constexpr size_t  kHeaderSize = 6;   // ver + op + u32 circuit

constexpr uint8_t kOpOpen     = 1;
constexpr uint8_t kOpIncoming = 2;
constexpr uint8_t kOpAccept   = 3;
constexpr uint8_t kOpDeny     = 4;
constexpr uint8_t kOpData     = 5;
constexpr uint8_t kOpCredit   = 6;
constexpr uint8_t kOpClose    = 7;
constexpr uint8_t kOpProbe    = 8;
constexpr uint8_t kOpProbeOk  = 9;

constexpr uint8_t kDenyNoTarget     = 0;  ///< the relay does not hold that peer
constexpr uint8_t kDenyNotPermitted = 1;  ///< relaying is off here
constexpr uint8_t kDenyResourceLimit = 2; ///< over a circuit or rate budget
constexpr uint8_t kDenyRefused      = 3;  ///< the target itself said no
constexpr uint8_t kDenyLoop         = 4;  ///< one end is itself only reachable by relay

constexpr uint8_t kCloseNormal = 0;  ///< an orderly end of stream
constexpr uint8_t kCloseError  = 1;  ///< anything else

/// Reserved: a message that is about no particular circuit (Probe / ProbeOk).
constexpr uint32_t kNoCircuit = 0;
/// First id either side may allocate; 0 and 1 are reserved so parity still works.
constexpr uint32_t kFirstEvenId = 2;
constexpr uint32_t kFirstOddId  = 3;
/// Where the allocator wraps. Well below UINT32_MAX so the wrap needs no special
/// case for the parity of the last step.
constexpr uint32_t kIdWrap = 0xFFFFFF00u;

const char* deny_text(uint8_t reason) {
    switch (reason) {
        case kDenyNoTarget:      return "the relay does not hold the target";
        case kDenyNotPermitted:  return "relaying is not offered";
        case kDenyResourceLimit: return "the relay is at its limit";
        case kDenyRefused:       return "the target refused";
        case kDenyLoop:          return "one end is itself relayed";
        default:                 return "unspecified";
    }
}

void put_u32(Bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

uint32_t get_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}

/// A message with its header written and room reserved for `body` bytes more.
Bytes message(uint8_t op, uint32_t circuit, size_t body = 0) {
    Bytes out;
    out.reserve(kHeaderSize + body);
    out.push_back(kVersion);
    out.push_back(op);
    put_u32(out, circuit);
    return out;
}

void append_id(Bytes& out, const PeerId& id) {
    const auto& raw = id.bytes();
    out.insert(out.end(), raw.begin(), raw.end());
}

/// How a peer is reachable right now. The distinction that matters everywhere in
/// this file is Direct vs Relayed: a circuit whose either end is itself relayed
/// would be a chain, and chains are what turn a relay mesh into an amplifier.
enum class Reach { None, Direct, Relayed };

Reach reach_of(PeerNetwork& network, const PeerId& id) {
    // A snapshot, which is not free — so this is only ever called on the rare
    // paths (opening a circuit, answering a request), never per data message.
    for (const PeerInfo& info : network.peers())
        if (info.id == id)
            return info.transport == TransportKind::Relay ? Reach::Relayed : Reach::Direct;
    return Reach::None;
}

} // namespace

// ── Shared state ────────────────────────────────────────────────────────────

struct Relay::State : public std::enable_shared_from_this<Relay::State> {
    using Clock = std::chrono::steady_clock;

    /// One circuit this node TERMINATES: a relayed peer of ours.
    struct Leg {
        std::shared_ptr<Circuit> circuit;
        PeerRoute                route{};
        PeerId                   target;            ///< the far end; a hint until the handshake
        bool                     outbound = false;  ///< we opened it
    };

    /// What one circuit this node CARRIES has cost so far. Shared by the circuit's
    /// two legs, so either side's accounting is the same accounting.
    struct Meter {
        uint64_t          bytes = 0;
        Clock::time_point started{};
    };

    /// One circuit this node carries: where its other side is.
    struct Forward {
        PeerId                 peer;
        uint32_t               id;
        std::shared_ptr<Meter> meter;
        /// Whether the peer whose link holds THIS entry is the one that opened the
        /// circuit. Only the opener is charged for it: being a popular destination
        /// is not something a peer chooses, and charging for it would let anyone
        /// use up a third party's budget by opening circuits toward them.
        bool                   opener = false;
    };

    /// Everything about one peer link: the ids we have allocated on it, the
    /// circuits riding it in either role, and what that peer has spent lately.
    struct PeerLink {
        uint32_t                              next_id = 0;
        std::unordered_map<uint32_t, Leg>     legs;
        std::unordered_map<uint32_t, Forward> forwards;
        size_t                                opened = 0;   ///< circuits this peer opened
        Clock::time_point                     window_started{};
        size_t                                requests = 0;
    };

    /// One search for a way to reach a peer.
    struct Attempt {
        Clock::time_point   deadline{};
        std::vector<PeerId> ready;              ///< relays that said they hold the target
        bool                opening = false;    ///< a circuit is in flight right now
        PeerId              via;                ///< the relay it is in flight through
        uint32_t            circuit = kNoCircuit;
    };

    /// The circuit's way out. One per circuit rather than one per module, because
    /// a circuit id means nothing without the link it was allocated on — and this
    /// is where that link is remembered. Defined below.
    class Carrier;

    Config                         config;
    PeerNetwork*                   network  = nullptr;
    CircuitService*                circuits = nullptr;
    std::atomic<HolePunchService*> punch{nullptr};
    std::atomic<bool>              running{false};
    std::atomic<uint64_t>          carried_bytes{0};

    mutable std::mutex                                          mutex;
    std::unordered_map<PeerId, PeerLink, PeerId::Hash>          links;
    std::unordered_map<PeerId, Attempt, PeerId::Hash>           attempts;
    std::unordered_map<PeerId, Clock::time_point, PeerId::Hash> cooldown;
    size_t outbound_circuits = 0;
    size_t inbound_circuits  = 0;
    size_t carried_circuits  = 0;

    // — inbound dispatch (reactor threads) —
    void handle(const Peer& from, ByteView payload);
    void handle_probe(const PeerId& from, ByteView body);
    void handle_probe_ok(const PeerId& from, ByteView body);
    void handle_open(const PeerId& from, uint32_t circuit, ByteView body);
    void handle_incoming(const PeerId& from, uint32_t circuit, ByteView body);
    void handle_accept(const PeerId& from, uint32_t circuit, ByteView body);
    void handle_deny(const PeerId& from, uint32_t circuit, ByteView body);
    void handle_data(const PeerId& from, uint32_t circuit, ByteView body);
    void handle_credit(const PeerId& from, uint32_t circuit, ByteView body);
    void handle_close(const PeerId& from, uint32_t circuit, ByteView body);

    void on_peer_connected(const Peer& peer);
    void on_peer_disconnected(const PeerId& id);
    void on_peer_writable(const PeerId& id);

    // — the client half —
    bool begin_attempt(const PeerId& target);
    /// Move an attempt on to the next relay that answered, or leave it to time out.
    /// Picks the candidate and commits to it under one lock: a relay taken out of
    /// `ready` before the last refusal can check is a relay that is never tried.
    void advance(const PeerId& target);
    /// Detach an attempt from the outbound circuit it was waiting on, so that the
    /// next `advance` may try another relay. Caller holds the mutex. The attempt
    /// itself stays: it keeps its deadline and whatever is left in `ready`.
    void release_attempt(const PeerId& target, const PeerId& carrier, uint32_t circuit);
    void finish_attempt(const PeerId& target, bool succeeded);

    // — bookkeeping —
    /// Caller holds the mutex.
    uint32_t allocate_id(PeerLink& link, const PeerId& peer);
    /// Caller holds the mutex. Whether `peer` may make one more request now.
    bool     spend_request(const PeerId& peer);
    /// Caller holds the mutex.
    bool     in_cooldown(const PeerId& target) const;
    /// Take a circuit we terminate out of the tables, and say what to do with it.
    /// The circuit is NOT closed here — the caller does that outside the mutex.
    struct Dropped {
        std::shared_ptr<Circuit> circuit;
        PeerRoute                route{};
        PeerId                   target;
        bool                     found = false;
        bool                     outbound = false;
    };
    Dropped take_leg(const PeerId& carrier, uint32_t circuit);
    /// Hand `events` to a circuit's connection. No-op for an unset route.
    void     wake(PeerRoute route, uint32_t events);

    // — the relay half —
    /// Erase one entry of a carried circuit and un-charge its opener. Caller holds
    /// the mutex. Returns what it pointed at, if anything.
    std::optional<Forward> erase_forward(const PeerId& peer, uint32_t circuit);
    /// End a circuit we carry and tell whoever still needs telling: `tell_far` for
    /// the side opposite `peer`, `tell_near` for `peer` itself — which is wanted
    /// when WE are ending the circuit, and not when we are passing on an ending
    /// that came from `peer` in the first place. Caller must not hold the mutex.
    void close_carried(const PeerId& peer, uint32_t circuit, uint8_t reason,
                       bool tell_far, bool tell_near);
    void deny(const PeerId& to, uint32_t circuit, uint8_t reason);

    void send(const PeerId& to, const Bytes& msg) {
        if (network) network->send(to, MessageType::Relay, ByteView(msg));
    }

    void tick();
    void shutdown();
};

class Relay::State::Carrier final : public CircuitCarrier {
public:
    Carrier(std::shared_ptr<Relay::State> state, PeerId carrier)
        : state_(std::move(state)), carrier_(std::move(carrier)) {}

    bool circuit_send_data(uint32_t circuit, const ByteView* slices, size_t count) override {
        size_t total = 0;
        for (size_t i = 0; i < count; ++i) total += slices[i].size();

        Bytes msg = message(kOpData, circuit, total);
        for (size_t i = 0; i < count; ++i)
            msg.insert(msg.end(), slices[i].begin(), slices[i].end());

        if (!state_->network) return false;
        return state_->network->send(carrier_, MessageType::Relay, ByteView(msg));
    }

    void circuit_send_credit(uint32_t circuit, uint32_t bytes) override {
        Bytes msg = message(kOpCredit, circuit, 4);
        put_u32(msg, bytes);
        state_->send(carrier_, msg);
    }

    void circuit_send_close(uint32_t circuit, CloseReason reason) override {
        Bytes msg = message(kOpClose, circuit, 1);
        msg.push_back(reason == CloseReason::LocalClose || reason == CloseReason::PeerClosed
                          ? kCloseNormal
                          : kCloseError);
        state_->send(carrier_, msg);
    }

    void circuit_released(uint32_t circuit) override {
        // May arrive on any thread — see CircuitCarrier::circuit_released — so it
        // does the least it possibly can: forget the circuit. Anything that has to
        // follow (retrying an attempt through another relay) is left to the worker,
        // which finds the attempt with nothing in flight on its next tick.
        std::lock_guard<std::mutex> lock(state_->mutex);
        auto link = state_->links.find(carrier_);
        if (link == state_->links.end()) return;
        auto leg = link->second.legs.find(circuit);
        if (leg == link->second.legs.end()) return;

        if (leg->second.outbound) {
            if (state_->outbound_circuits > 0) --state_->outbound_circuits;
            auto attempt = state_->attempts.find(leg->second.target);
            if (attempt != state_->attempts.end() && attempt->second.circuit == circuit &&
                attempt->second.via == carrier_) {
                attempt->second.opening = false;
                attempt->second.circuit = kNoCircuit;
            }
        } else if (state_->inbound_circuits > 0) {
            --state_->inbound_circuits;
        }
        link->second.legs.erase(leg);
    }

private:
    std::shared_ptr<Relay::State> state_;
    PeerId                        carrier_;
};

// ── Dispatch ────────────────────────────────────────────────────────────────

void Relay::State::handle(const Peer& from, ByteView payload) {
    if (!running.load()) return;
    if (payload.size() < kHeaderSize) return;
    // The largest honest message is one data chunk plus its header. Anything past
    // that is malformed by construction and is not worth looking at.
    if (payload.size() > kHeaderSize + Circuit::kMaxDataChunk) return;
    if (payload.data()[0] != kVersion) return;

    const uint8_t  op      = payload.data()[1];
    const uint32_t circuit = get_u32(payload.data() + 2);
    const ByteView body(payload.data() + kHeaderSize, payload.size() - kHeaderSize);
    const PeerId&  peer = from.id();

    switch (op) {
        case kOpProbe:    handle_probe(peer, body); break;
        case kOpProbeOk:  handle_probe_ok(peer, body); break;
        case kOpOpen:     handle_open(peer, circuit, body); break;
        case kOpIncoming: handle_incoming(peer, circuit, body); break;
        case kOpAccept:   handle_accept(peer, circuit, body); break;
        case kOpDeny:     handle_deny(peer, circuit, body); break;
        case kOpData:     handle_data(peer, circuit, body); break;
        case kOpCredit:   handle_credit(peer, circuit, body); break;
        case kOpClose:    handle_close(peer, circuit, body); break;
        default: break;   // an op from a newer version: ignore, never fatal
    }
}

// ── The relay half: answering for peers we hold ─────────────────────────────

void Relay::State::handle_probe(const PeerId& from, ByteView body) {
    if (!config.serve) return;
    if (body.size() < PeerId::kSize) return;
    const auto dst = PeerId::from_bytes(ByteView(body.data(), PeerId::kSize));
    if (!dst || *dst == from || *dst == network->local_id()) return;

    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!spend_request(from)) return;
        if (carried_circuits >= config.max_circuits) return;
    }

    // Only a peer we hold DIRECTLY counts. Answering for a peer we ourselves reach
    // through a relay would offer a chain, and the open would be refused anyway.
    if (reach_of(*network, *dst) != Reach::Direct) return;

    Bytes msg = message(kOpProbeOk, kNoCircuit, PeerId::kSize);
    append_id(msg, *dst);
    send(from, msg);
}

void Relay::State::handle_open(const PeerId& from, uint32_t circuit, ByteView body) {
    if (circuit == kNoCircuit) return;
    if (!config.serve)                       return deny(from, circuit, kDenyNotPermitted);
    if (body.size() < PeerId::kSize + 4)     return deny(from, circuit, kDenyNotPermitted);

    const auto dst = PeerId::from_bytes(ByteView(body.data(), PeerId::kSize));
    if (!dst)                                return deny(from, circuit, kDenyNoTarget);
    if (*dst == from || *dst == network->local_id())
                                             return deny(from, circuit, kDenyNoTarget);
    const uint32_t window = get_u32(body.data() + PeerId::kSize);

    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!spend_request(from))            return deny(from, circuit, kDenyResourceLimit);
        if (carried_circuits >= config.max_circuits)
                                             return deny(from, circuit, kDenyResourceLimit);
        PeerLink& link = links[from];        // spend_request just created it if needed
        if (link.opened >= config.max_circuits_per_peer)
                                             return deny(from, circuit, kDenyResourceLimit);
        // Already known: a retransmitted Open, or a peer reusing an id it still has
        // a circuit on. Either way there is nothing new to set up.
        if (link.forwards.count(circuit) || link.legs.count(circuit)) return;
    }

    // Neither end may itself be relayed. This is the rule that keeps circuits from
    // being chained: a chain multiplies one peer's bytes across several relays and
    // gives a loop somewhere to form.
    if (reach_of(*network, from) != Reach::Direct) return deny(from, circuit, kDenyLoop);
    switch (reach_of(*network, *dst)) {
        case Reach::None:    return deny(from, circuit, kDenyNoTarget);
        case Reach::Relayed: return deny(from, circuit, kDenyLoop);
        case Reach::Direct:  break;
    }

    uint32_t far_id = kNoCircuit;
    {
        // Re-checked: the reachability lookups above ran without the lock, and a
        // burst of Opens could otherwise all pass the test and then all allocate.
        std::lock_guard<std::mutex> lock(mutex);
        if (carried_circuits >= config.max_circuits)
            return deny(from, circuit, kDenyResourceLimit);
        PeerLink& near_link = links[from];
        if (near_link.opened >= config.max_circuits_per_peer)
            return deny(from, circuit, kDenyResourceLimit);
        if (near_link.forwards.count(circuit)) return;

        PeerLink& far_link = links[*dst];
        far_id = allocate_id(far_link, *dst);

        auto meter = std::make_shared<Meter>();
        meter->started = Clock::now();

        links[from].forwards.emplace(circuit, Forward{*dst, far_id, meter, /*opener=*/true});
        links[*dst].forwards.emplace(far_id, Forward{from, circuit, meter, /*opener=*/false});
        ++links[from].opened;
        ++carried_circuits;
    }

    LOG_DEBUG("relay", "Carrying a circuit from " << from.short_hex() << " to "
              << dst->short_hex());

    Bytes msg = message(kOpIncoming, far_id, PeerId::kSize + 4);
    append_id(msg, from);
    put_u32(msg, window);
    send(*dst, msg);
}

// ── The target half: a circuit opened toward us ─────────────────────────────

void Relay::State::handle_incoming(const PeerId& from, uint32_t circuit, ByteView body) {
    if (circuit == kNoCircuit) return;
    if (!config.accept_inbound)          return deny(from, circuit, kDenyRefused);
    if (body.size() < PeerId::kSize + 4) return deny(from, circuit, kDenyRefused);

    const auto src = PeerId::from_bytes(ByteView(body.data(), PeerId::kSize));
    if (!src || *src == network->local_id()) return deny(from, circuit, kDenyRefused);
    const uint32_t peer_window = get_u32(body.data() + PeerId::kSize);

    // `src` is the relay's word, not the far end's — the handshake is what actually
    // establishes who is there. It is used only to turn away a circuit that would
    // duplicate a peer we already hold, which costs the far end a Deny instead of a
    // whole handshake it was going to lose anyway.
    if (reach_of(*network, *src) == Reach::Direct) return deny(from, circuit, kDenyRefused);
    // And the carrier itself must be a direct peer: a circuit inside a circuit is
    // the chain this refuses to be part of.
    if (reach_of(*network, from) != Reach::Direct) return deny(from, circuit, kDenyLoop);

    std::shared_ptr<Circuit> incoming;
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!running.load())                                return deny(from, circuit, kDenyRefused);
        if (inbound_circuits >= config.max_inbound_circuits) return deny(from, circuit, kDenyResourceLimit);
        PeerLink& link = links[from];
        if (link.legs.count(circuit) || link.forwards.count(circuit)) return;  // a repeat

        // Open from the first instant: the far end is already there, and its
        // request carried the window it will receive.
        incoming = Circuit::accepted(circuit, std::make_shared<Carrier>(shared_from_this(), from),
                                     peer_window, config.window);
        link.legs.emplace(circuit, Leg{incoming, PeerRoute{}, *src, /*outbound=*/false});
        ++inbound_circuits;
    }

    const auto route = circuits->adopt_circuit(from, std::make_unique<RelayLink>(incoming),
                                               ConnRole::Inbound, /*connected=*/true);
    if (!route) {
        // The node will not take another peer, or the carrier went away between the
        // two lines above. Either way nothing was started.
        take_leg(from, circuit);
        return deny(from, circuit, kDenyResourceLimit);
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(from);
        if (link != links.end()) {
            auto leg = link->second.legs.find(circuit);
            if (leg != link->second.legs.end()) leg->second.route = *route;
        }
    }

    Bytes msg = message(kOpAccept, circuit, 4);
    put_u32(msg, config.window);
    send(from, msg);
    LOG_DEBUG("relay", "Accepted a circuit from " << src->short_hex() << " via "
              << from.short_hex());
}

// ── Messages that are either ours to act on or ours to forward ──────────────

void Relay::State::handle_accept(const PeerId& from, uint32_t circuit, ByteView body) {
    if (body.size() < 4) return;
    const uint32_t window = get_u32(body.data());

    std::shared_ptr<Circuit> ours;
    PeerRoute                route{};
    std::optional<Forward>   forward;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(from);
        if (link == links.end()) return;
        if (auto leg = link->second.legs.find(circuit); leg != link->second.legs.end()) {
            ours  = leg->second.circuit;
            route = leg->second.route;
        } else if (auto fwd = link->second.forwards.find(circuit);
                   fwd != link->second.forwards.end()) {
            forward = fwd->second;
        }
    }

    if (ours) {
        // The far end is there: the connection may finish connecting and start its
        // handshake, exactly as a completed TCP connect would let it.
        wake(route, ours->on_accept(window));
        return;
    }
    if (forward) {
        Bytes msg = message(kOpAccept, forward->id, 4);
        put_u32(msg, window);
        send(forward->peer, msg);
    }
}

void Relay::State::handle_deny(const PeerId& from, uint32_t circuit, ByteView body) {
    const uint8_t reason = body.empty() ? 0xFF : body.data()[0];

    std::optional<Forward> forward;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(from);
        if (link == links.end()) return;
        if (auto fwd = link->second.forwards.find(circuit); fwd != link->second.forwards.end())
            forward = fwd->second;
    }

    if (forward) {
        Bytes msg = message(kOpDeny, forward->id, 1);
        msg.push_back(reason);
        send(forward->peer, msg);
        // The refusal IS the ending, and both sides have now had it — a Close on
        // top would name a circuit neither of them still has.
        close_carried(from, circuit, kCloseError, /*tell_far=*/false, /*tell_near=*/false);
        return;
    }

    const Dropped dropped = take_leg(from, circuit);
    if (!dropped.found) return;
    LOG_DEBUG("relay", "Circuit through " << from.short_hex() << " refused: "
              << deny_text(reason));
    wake(dropped.route, dropped.circuit->on_closed(CloseReason::ConnectFailed, /*orderly=*/false));
    circuits->close_circuit(dropped.route, CloseReason::ConnectFailed);
    // The attempt is now free to try the next relay that said it could help.
    if (dropped.outbound) advance(dropped.target);
}

void Relay::State::handle_data(const PeerId& from, uint32_t circuit, ByteView body) {
    if (body.empty()) return;

    std::shared_ptr<Circuit> ours;
    PeerRoute                route{};
    std::optional<Forward>   forward;
    bool                     over_budget = false;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(from);
        if (link == links.end()) return;
        if (auto leg = link->second.legs.find(circuit); leg != link->second.legs.end()) {
            ours  = leg->second.circuit;
            route = leg->second.route;
        } else if (auto fwd = link->second.forwards.find(circuit);
                   fwd != link->second.forwards.end()) {
            forward = fwd->second;
            forward->meter->bytes += body.size();
            over_budget = config.max_bytes_per_circuit != 0 &&
                          forward->meter->bytes > config.max_bytes_per_circuit;
        }
    }

    if (ours) {
        // on_data enforces the window we advertised: a far end that sends past it
        // fails the circuit rather than being allowed to grow it.
        wake(route, ours->on_data(body));
        return;
    }
    if (!forward) return;   // a circuit we have already forgotten; nothing to do

    if (over_budget) {
        LOG_DEBUG("relay", "Circuit from " << from.short_hex() << " hit its byte cap");
        close_carried(from, circuit, kCloseError, /*tell_far=*/true, /*tell_near=*/true);
        return;
    }

    Bytes msg = message(kOpData, forward->id, body.size());
    msg.insert(msg.end(), body.begin(), body.end());
    send(forward->peer, msg);
    carried_bytes.fetch_add(body.size(), std::memory_order_relaxed);
}

void Relay::State::handle_credit(const PeerId& from, uint32_t circuit, ByteView body) {
    if (body.size() < 4) return;
    const uint32_t granted = get_u32(body.data());

    std::shared_ptr<Circuit> ours;
    PeerRoute                route{};
    std::optional<Forward>   forward;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(from);
        if (link == links.end()) return;
        if (auto leg = link->second.legs.find(circuit); leg != link->second.legs.end()) {
            ours  = leg->second.circuit;
            route = leg->second.route;
        } else if (auto fwd = link->second.forwards.find(circuit);
                   fwd != link->second.forwards.end()) {
            forward = fwd->second;
        }
    }

    if (ours) { wake(route, ours->on_credit(granted)); return; }
    if (forward) {
        Bytes msg = message(kOpCredit, forward->id, 4);
        put_u32(msg, granted);
        send(forward->peer, msg);
    }
}

void Relay::State::handle_close(const PeerId& from, uint32_t circuit, ByteView body) {
    const uint8_t reason = body.empty() ? kCloseError : body.data()[0];

    bool carries = false;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(from);
        if (link == links.end()) return;
        carries = link->second.forwards.count(circuit) > 0;
    }
    if (carries) {
        close_carried(from, circuit, reason, /*tell_far=*/true, /*tell_near=*/false);
        return;
    }

    const Dropped dropped = take_leg(from, circuit);
    if (!dropped.found) return;
    const bool orderly = reason == kCloseNormal;
    wake(dropped.route, dropped.circuit->on_closed(
                            orderly ? CloseReason::PeerClosed : CloseReason::PeerReset, orderly));
    if (dropped.outbound) advance(dropped.target);
}

// ── The client half: finding a way to a peer ────────────────────────────────

void Relay::State::handle_probe_ok(const PeerId& from, ByteView body) {
    if (body.size() < PeerId::kSize) return;
    const auto target = PeerId::from_bytes(ByteView(body.data(), PeerId::kSize));
    if (!target) return;

    bool open_now = false;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = attempts.find(*target);
        if (it == attempts.end()) return;            // no attempt, or it already ended
        if (std::find(it->second.ready.begin(), it->second.ready.end(), from) !=
            it->second.ready.end())
            return;
        it->second.ready.push_back(from);
        // The first useful answer is acted on at once; the rest are kept in case
        // this one refuses or dies, which is the whole reason for keeping them.
        open_now = !it->second.opening;
    }
    if (open_now) advance(*target);
}

bool Relay::State::begin_attempt(const PeerId& target) {
    std::vector<PeerId> candidates;
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!running.load()) return false;
        if (attempts.count(target)) return false;
        if (in_cooldown(target)) return false;
        if (outbound_circuits >= config.max_outbound_circuits) return false;
    }

    // Peers that could carry the circuit: connected, not the target, and not
    // themselves relayed — asking a relayed peer to relay is the chain we refuse.
    for (const PeerInfo& info : network->peers()) {
        if (info.id == target) return false;              // already reachable directly
        if (info.transport == TransportKind::Relay) continue;
        candidates.push_back(info.id);
    }
    if (candidates.size() > config.max_probes) candidates.resize(config.max_probes);
    if (candidates.empty()) return false;

    {
        std::lock_guard<std::mutex> lock(mutex);
        if (attempts.count(target)) return false;         // another caller got here first
        Attempt attempt;
        attempt.deadline = Clock::now() + config.open_timeout;
        attempts.emplace(target, std::move(attempt));
    }

    Bytes msg = message(kOpProbe, kNoCircuit, PeerId::kSize);
    append_id(msg, target);
    for (const PeerId& candidate : candidates) send(candidate, msg);

    LOG_DEBUG("relay", "Asking " << candidates.size() << " peer(s) for a way to "
              << target.short_hex());
    return true;
}

void Relay::State::advance(const PeerId& target) {
    std::shared_ptr<Circuit> circuit;
    uint32_t                 id = kNoCircuit;
    PeerId                   via;
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!running.load()) return;
        auto it = attempts.find(target);
        if (it == attempts.end() || it->second.opening) return;
        if (it->second.ready.empty()) return;   // nothing left to try; let it time out
        // Every reason to refuse is behind this line, so the candidate taken here is
        // a candidate actually tried. Popping earlier would spend one relay per
        // refusal — at the outbound cap a burst of ProbeOks would empty `ready`
        // against the cap and leave the attempt to time out with relays to spare.
        if (outbound_circuits >= config.max_outbound_circuits) return;

        via = it->second.ready.back();
        it->second.ready.pop_back();

        PeerLink& link = links[via];
        id      = allocate_id(link, via);
        circuit = Circuit::opening(id, std::make_shared<Carrier>(shared_from_this(), via),
                                   config.window);
        link.legs.emplace(id, Leg{circuit, PeerRoute{}, target, /*outbound=*/true});
        ++outbound_circuits;

        it->second.opening = true;
        it->second.via     = via;
        it->second.circuit = id;
    }

    // Adopted BEFORE the request goes out, so the route is on record by the time an
    // answer to it can possibly arrive.
    const auto route = circuits->adopt_circuit(via, std::make_unique<RelayLink>(circuit),
                                               ConnRole::Outbound, /*connected=*/false);
    if (!route) {
        take_leg(via, id);
        advance(target);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(via);
        if (link != links.end()) {
            auto leg = link->second.legs.find(id);
            if (leg != link->second.legs.end()) leg->second.route = *route;
        }
    }

    Bytes msg = message(kOpOpen, id, PeerId::kSize + 4);
    append_id(msg, target);
    put_u32(msg, config.window);
    send(via, msg);
}

void Relay::State::release_attempt(const PeerId& target, const PeerId& carrier,
                                   uint32_t circuit) {
    auto attempt = attempts.find(target);
    if (attempt == attempts.end()) return;
    // Only the circuit the attempt is actually waiting on: a late drop belonging to
    // a superseded leg must not clear the state of the one now in flight.
    if (attempt->second.circuit != circuit || attempt->second.via != carrier) return;
    attempt->second.opening = false;
    attempt->second.circuit = kNoCircuit;
}

void Relay::State::finish_attempt(const PeerId& target, bool succeeded) {
    std::lock_guard<std::mutex> lock(mutex);
    if (attempts.erase(target) == 0) return;
    if (!succeeded) cooldown[target] = Clock::now() + config.cooldown;
}

// ── Peer lifecycle ──────────────────────────────────────────────────────────

void Relay::State::on_peer_connected(const Peer& peer) {
    if (!running.load()) return;
    finish_attempt(peer.id(), /*succeeded=*/true);

    if (!config.upgrade_with_hole_punch) return;
    const auto info = peer.info();
    if (!info || info->transport != TransportKind::Relay) return;

    // A circuit is a fallback, not a destination. Now that the two ends are peers
    // they can arrange a punch over the very circuit carrying them, and if it lands
    // the peer table prefers the direct link at both ends and swaps the route with
    // no disconnect event — the application never sees the seam.
    if (HolePunchService* hole_punch = punch.load()) {
        LOG_DEBUG("relay", "Relayed peer " << peer.id().short_hex()
                  << " is up; trying to replace the circuit with a direct link");
        hole_punch->punch(peer.id());
    }
}

void Relay::State::on_peer_disconnected(const PeerId& id) {
    // Everything riding this link is over: the circuits we terminate through it,
    // and the ones we were carrying across it.
    std::unordered_map<uint32_t, Leg>     legs;
    std::unordered_map<uint32_t, Forward> forwards;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(id);
        if (link == links.end()) return;
        legs     = std::move(link->second.legs);
        forwards = std::move(link->second.forwards);
        links.erase(link);

        // Same bookkeeping take_leg does, which this path deliberately bypasses to
        // empty the whole link at once. Releasing the attempt is the part that must
        // not be skipped: the link entry is gone by the time `advance` runs below,
        // so nothing else would ever clear `opening` and the attempt would sit on a
        // dead carrier until its deadline, with answered relays left untried.
        for (const auto& [circuit, leg] : legs) {
            if (leg.outbound) {
                if (outbound_circuits) --outbound_circuits;
                release_attempt(leg.target, id, circuit);
            } else if (inbound_circuits) {
                --inbound_circuits;
            }
        }
    }

    for (const auto& [circuit, leg] : legs) {
        wake(leg.route, leg.circuit->on_closed(CloseReason::PeerReset, /*orderly=*/false));
        circuits->close_circuit(leg.route, CloseReason::PeerReset);
        if (leg.outbound) advance(leg.target);
    }

    for (const auto& [circuit, fwd] : forwards) {
        // Tell the other side, and take its half out of the tables. This peer's own
        // half went with the link above, charges and all.
        Bytes msg = message(kOpClose, fwd.id, 1);
        msg.push_back(kCloseError);
        send(fwd.peer, msg);
        std::lock_guard<std::mutex> lock(mutex);
        if (erase_forward(fwd.peer, fwd.id) && carried_circuits) --carried_circuits;
    }
}

void Relay::State::on_peer_writable(const PeerId& id) {
    // The carrier's send queue has drained, so circuits that stopped on it may go
    // again. Gathered first, woken after: waking runs the connection's send path.
    std::vector<std::pair<std::shared_ptr<Circuit>, PeerRoute>> waiting;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(id);
        if (link == links.end()) return;
        waiting.reserve(link->second.legs.size());
        for (const auto& [circuit, leg] : link->second.legs)
            waiting.emplace_back(leg.circuit, leg.route);
    }
    for (const auto& [circuit, route] : waiting) wake(route, circuit->on_carrier_writable());
}

// ── Bookkeeping ─────────────────────────────────────────────────────────────

uint32_t Relay::State::allocate_id(PeerLink& link, const PeerId& peer) {
    const bool  even = network->local_id() < peer;
    const uint32_t first = even ? kFirstEvenId : kFirstOddId;
    if (link.next_id < first) link.next_id = first;

    for (int guard = 0; guard < 64; ++guard) {
        const uint32_t id = link.next_id;
        link.next_id = id + 2 >= kIdWrap ? first : id + 2;
        if (!link.legs.count(id) && !link.forwards.count(id)) return id;
    }
    return link.next_id;   // a link with tens of thousands of circuits; not reachable
}

bool Relay::State::spend_request(const PeerId& peer) {
    const auto now = Clock::now();
    // No ceiling and no sweep, deliberately. An entry is only ever created for a
    // peer we hold — nothing else can reach this code — and on_peer_disconnected
    // erases it, so the table is bounded by the peer count. The "drop the whole
    // table when it grows too large" trick that guards the equivalent budget in
    // HolePunch would be actively wrong here: this table holds live circuits, not
    // just counters, and clearing it would orphan every one of them.
    PeerLink& link = links[peer];
    if (now - link.window_started >= config.request_window) {
        link.window_started = now;
        link.requests = 0;
    }
    if (link.requests >= config.request_budget) return false;
    ++link.requests;
    return true;
}

bool Relay::State::in_cooldown(const PeerId& target) const {
    auto it = cooldown.find(target);
    return it != cooldown.end() && Clock::now() < it->second;
}

Relay::State::Dropped Relay::State::take_leg(const PeerId& carrier, uint32_t circuit) {
    std::lock_guard<std::mutex> lock(mutex);
    Dropped out;
    auto link = links.find(carrier);
    if (link == links.end()) return out;
    auto leg = link->second.legs.find(circuit);
    if (leg == link->second.legs.end()) return out;

    out.found    = true;
    out.circuit  = leg->second.circuit;
    out.route    = leg->second.route;
    out.target   = leg->second.target;
    out.outbound = leg->second.outbound;

    if (out.outbound) {
        if (outbound_circuits) --outbound_circuits;
        release_attempt(out.target, carrier, circuit);
    } else if (inbound_circuits) {
        --inbound_circuits;
    }
    link->second.legs.erase(leg);
    return out;
}

void Relay::State::wake(PeerRoute route, uint32_t events) {
    if (events == 0 || route.conn == kInvalidConnId) return;
    circuits->wake_circuit(route, events);
}

std::optional<Relay::State::Forward> Relay::State::erase_forward(const PeerId& peer,
                                                                 uint32_t circuit) {
    auto link = links.find(peer);
    if (link == links.end()) return std::nullopt;
    auto fwd = link->second.forwards.find(circuit);
    if (fwd == link->second.forwards.end()) return std::nullopt;

    const Forward taken = fwd->second;
    if (taken.opener && link->second.opened) --link->second.opened;
    link->second.forwards.erase(fwd);
    return taken;
}

void Relay::State::close_carried(const PeerId& peer, uint32_t circuit, uint8_t reason,
                                 bool tell_far, bool tell_near) {
    std::optional<Forward> forward;
    {
        std::lock_guard<std::mutex> lock(mutex);
        forward = erase_forward(peer, circuit);
        if (!forward) return;
        erase_forward(forward->peer, forward->id);
        if (carried_circuits) --carried_circuits;
    }

    if (tell_far) {
        Bytes msg = message(kOpClose, forward->id, 1);
        msg.push_back(reason);
        send(forward->peer, msg);
    }
    if (tell_near) {
        Bytes msg = message(kOpClose, circuit, 1);
        msg.push_back(reason);
        send(peer, msg);
    }
}

void Relay::State::deny(const PeerId& to, uint32_t circuit, uint8_t reason) {
    Bytes msg = message(kOpDeny, circuit, 1);
    msg.push_back(reason);
    send(to, msg);
}

// ── Periodic work ───────────────────────────────────────────────────────────

void Relay::State::tick() {
    if (!running.load()) return;
    const auto now = Clock::now();

    std::vector<PeerId>                     timed_out;
    std::vector<PeerId>                     to_advance;
    std::vector<std::pair<PeerId, uint32_t>> expired;
    {
        std::lock_guard<std::mutex> lock(mutex);
        for (auto it = cooldown.begin(); it != cooldown.end();) {
            if (now >= it->second) it = cooldown.erase(it);
            else                   ++it;
        }
        for (const auto& [target, attempt] : attempts) {
            if (now >= attempt.deadline)                       timed_out.push_back(target);
            else if (!attempt.opening && !attempt.ready.empty()) to_advance.push_back(target);
        }

        // Circuits we carry that have outstayed their welcome. The byte cap is
        // enforced as the bytes go past (handle_data); this is the clock half.
        if (config.max_circuit_duration.count() != 0) {
            for (const auto& [peer, link] : links)
                for (const auto& [circuit, fwd] : link.forwards)
                    if (now - fwd.meter->started >= config.max_circuit_duration)
                        expired.emplace_back(peer, circuit);
        }
    }

    for (const PeerId& target : timed_out) {
        LOG_DEBUG("relay", "No relay found for " << target.short_hex());
        finish_attempt(target, /*succeeded=*/false);
    }
    for (const PeerId& target : to_advance) advance(target);
    for (const auto& [peer, circuit] : expired)
        close_carried(peer, circuit, kCloseError, /*tell_far=*/true, /*tell_near=*/true);
}

void Relay::State::shutdown() {
    running.store(false);
    punch.store(nullptr);

    // Only the tables. The circuits themselves are deliberately NOT touched here:
    // stop() runs on whatever thread is taking the node down, while a circuit
    // belongs to the reactor thread that owns its connection, and reaching into one
    // from here would be exactly the cross-thread access this design does not have
    // anywhere else. Nothing is left dangling by that — subsystems stop before the
    // reactors do, and each reactor then closes its connections, which shuts each
    // circuit down and releases its link on the one thread that owns it.
    std::lock_guard<std::mutex> lock(mutex);
    links.clear();
    attempts.clear();
    cooldown.clear();
    outbound_circuits = 0;
    inbound_circuits  = 0;
    carried_circuits  = 0;
}

// ── Subsystem ───────────────────────────────────────────────────────────────

Relay::Relay() : Relay(Config()) {}

Relay::Relay(Config config) : config_(std::move(config)), state_(std::make_shared<State>()) {
    state_->config = config_;
}

Relay::~Relay() { stop(); }

void Relay::attach(NodeContext& ctx) {
    state_->network  = &ctx.network;
    // Without it this node can still serve as a relay, but it cannot terminate a
    // circuit — there would be nothing to turn the byte stream into a connection.
    state_->circuits = ctx.services.get<CircuitService>();

    ctx.services.provide<RelayService>(this);

    // The handlers hold the shared state rather than `this`: the router keeps them
    // for the node's life, and the state is what they need anyway.
    auto state = state_;
    ctx.network.on(MessageType::Relay,
                   [state](const Peer& peer, ByteView payload) { state->handle(peer, payload); });
    ctx.network.on_peer_connected([state](const Peer& peer) { state->on_peer_connected(peer); });
    ctx.network.on_peer_disconnected([state](const PeerId& id) { state->on_peer_disconnected(id); });
    ctx.network.on_peer_writable([state](const Peer& peer) { state->on_peer_writable(peer.id()); });

    services_ = &ctx.services;
}

void Relay::start() {
    if (!state_->circuits) {
        LOG_WARN("relay", "No CircuitService is published; this node can relay for others "
                          "but cannot itself be relayed");
    }
    // Resolved here rather than in attach(): HolePunch may be attached after us, and
    // every attach() runs before any start().
    if (services_ && config_.upgrade_with_hole_punch)
        state_->punch.store(services_->get<HolePunchService>());

    state_->running.store(true);
    if (running_.exchange(true)) return;
    worker_ = std::thread([this] { loop(); });
}

void Relay::stop() {
    state_->running.store(false);
    if (running_.exchange(false)) {
        worker_cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }
    state_->shutdown();
}

bool Relay::connect_via_relay(const PeerId& target) {
    if (!state_->running.load() || !config_.enable_client) return false;
    if (!state_->circuits || !state_->network) return false;
    if (target == state_->network->local_id()) return false;
    return state_->begin_attempt(target);
}

void Relay::loop() {
    std::unique_lock<std::mutex> lock(worker_mutex_);
    while (running_.load()) {
        worker_cv_.wait_for(lock, config_.tick, [this] { return !running_.load(); });
        if (!running_.load()) return;
        lock.unlock();
        state_->tick();
        lock.lock();
    }
}

size_t Relay::circuits() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->outbound_circuits + state_->inbound_circuits;
}

size_t Relay::carried_circuits() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->carried_circuits;
}

uint64_t Relay::carried_bytes() const {
    return state_->carried_bytes.load(std::memory_order_relaxed);
}

size_t Relay::attempts() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->attempts.size();
}

} // namespace librats
