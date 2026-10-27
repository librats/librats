#include "librats/subsystems/relay.h"

#include "librats/core/io_poller.h"        // PollIn / PollOut / PollErr
#include "librats/core/token_bucket.h"
#include "librats/node/circuit_service.h"
#include "librats/node/node_context.h"
#include "librats/peer/peer.h"
#include "librats/peer/peer_info.h"
#include "librats/subsystems/hole_punch_service.h"
#include "librats/util/logger.h"

#include <algorithm>
#include <atomic>
#include <optional>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace librats {

namespace {

// ── Wire format (MessageType::Relay), big-endian ────────────────────────────
//
//   [u8 ver=1][u8 op][u32 circuit][body]
//
//     op=1 Open     [32B dst][u32 window][u8 flags]   client → relay
//     op=2 Incoming [32B src][u32 window][u64 cid]    relay  → target
//     op=3 Accept   [u32 window][u64 cid]             target → relay → client
//     op=4 Deny     [u8 reason]             relay → client, or target → relay → client
//     op=5 Data     [bytes]                 end to end, through the relay
//     op=6 Credit   [u32 bytes]             end to end, through the relay
//     op=7 Close    [u8 reason]             either end, or the relay
//     op=8 Probe    [32B dst]               client → relay        (circuit = 0)
//     op=9 ProbeOk  [32B dst]               relay  → client       (circuit = 0)
//     op=10 Serving —                       relay  → every peer   (circuit = 0)
//
// `circuit` is scoped to the LINK the message travels on, never globally: the
// relay holds two ids for one circuit, one per side, and translates between them.
// Both ends of a link allocate ids from that one space without coordinating, by
// parity — the smaller PeerId takes the even ids, the larger the odd ones, which
// both compute identically from what they already know. Ids 0 and 1 are reserved.
//
// The trailing fields are optional, and an older node that sends none or ignores
// them gets a byte stream. Open's flag kOfferDatagrams says the client's leg is a
// datagram connection. If the target's is one too, the relay picks a connection
// id pair, forwards its packets (transport/udp_mux.h, "Relayed connections") and
// names its dialer's half `cid` in Incoming; the target echoes it in Accept, and
// the relay passes that on to the client, which then dials through the relay
// under it: the circuit is an end-to-end datagram connection, and Data and
// Credit are never used on it. No cid, or a target that does not echo it, means
// the circuit is the byte stream of transport/relay_link.h.
//
// Serving is a relay saying, as a peer connects (and again when it reroutes), that
// it carries circuits for others: a client asks those first (Probe), and HolePunch
// sends its rendezvous through them first — the public node two strangers both
// reach, among the many peers of a room that relay nothing.
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
constexpr uint8_t kOpServing  = 10;

constexpr uint8_t kDenyNoTarget     = 0;  ///< the relay does not hold that peer
constexpr uint8_t kDenyNotPermitted = 1;  ///< relaying is off here
constexpr uint8_t kDenyResourceLimit = 2; ///< over a circuit or rate budget
constexpr uint8_t kDenyRefused      = 3;  ///< the target itself said no
constexpr uint8_t kDenyLoop         = 4;  ///< one end is itself only reachable by relay

constexpr uint8_t kOfferDatagrams = 0x01;  ///< Open: our leg can carry forwarded datagrams

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

void put_u64(Bytes& out, uint64_t v) {
    put_u32(out, static_cast<uint32_t>(v >> 32));
    put_u32(out, static_cast<uint32_t>(v));
}

uint64_t get_u64(const uint8_t* p) {
    return (static_cast<uint64_t>(get_u32(p)) << 32) | get_u32(p + 4);
}

/// The connection id a trailing field at `at` names, or 0 for none. Odd ids are
/// the responder's half and never a pair's name, so they read as none too.
uint64_t cid_at(ByteView body, size_t at) {
    if (body.size() < at + 8) return 0;
    const uint64_t cid = get_u64(body.data() + at);
    return (cid & 1) != 0 ? 0 : cid;
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

/// The wire `id` is reached over, nullopt when it is not a peer.
std::optional<TransportKind> transport_of(PeerNetwork& network, const PeerId& id) {
    // A snapshot, which is not free — so this is only ever called on the rare
    // paths (opening a circuit, answering a request), never per data message.
    for (const PeerInfo& info : network.peers())
        if (info.id == id) return info.transport;
    return std::nullopt;
}

Reach reach_of(std::optional<TransportKind> transport) {
    if (!transport) return Reach::None;
    return *transport == TransportKind::Relay ? Reach::Relayed : Reach::Direct;
}

Reach reach_of(PeerNetwork& network, const PeerId& id) {
    return reach_of(transport_of(network, id));
}

} // namespace

// ── Shared state ────────────────────────────────────────────────────────────

struct Relay::State : public std::enable_shared_from_this<Relay::State> {
    using Clock = std::chrono::steady_clock;

    /// One circuit this node TERMINATES: a relayed peer of ours.
    struct Leg {
        /// The byte stream, or null for a circuit whose relay forwards datagrams —
        /// its connection holds a ForwardedCircuit instead.
        std::shared_ptr<Circuit> circuit;
        /// Unset until the connection is made: for a circuit we open, when it is
        /// accepted, in whichever form the relay chose.
        PeerRoute                route{};
        PeerId                   target;            ///< the far end; a hint until the handshake
        bool                     outbound = false;  ///< we opened it
        Clock::time_point        opened{};
    };

    /// What one circuit this node CARRIES has cost so far. Shared by the circuit's
    /// two legs, so either side's accounting is the same accounting.
    struct Meter {
        /// Atomic because a forwarded circuit's bytes are counted by the mux, on
        /// its reactor, while the worker reads them against the cap.
        std::atomic<uint64_t> bytes{0};
        /// The connection id pair the mux forwards, or 0 for a byte stream.
        std::atomic<uint64_t> cid{0};
        Clock::time_point     started{};
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
        /// What the peer whose link holds this entry sends on a byte stream may
        /// cost (Config::max_circuit_rate_bps). Spent as its data goes past;
        /// while it is in debt, the credit the far end grants it is held here.
        TokenBucket            rate{};
        uint32_t               held_credit = 0;
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
    /// Bytes of byte-stream circuits, and of forwarded ones that have ended (a
    /// live one's are its meter's).
    std::atomic<uint64_t>          carried_bytes{0};

    mutable std::mutex                                          mutex;
    std::unordered_map<PeerId, PeerLink, PeerId::Hash>          links;
    std::unordered_map<PeerId, Attempt, PeerId::Hash>           attempts;
    std::unordered_map<PeerId, Clock::time_point, PeerId::Hash> cooldown;
    std::unordered_set<PeerId, PeerId::Hash>                    serving;  ///< said Serving
    size_t outbound_circuits = 0;
    size_t inbound_circuits  = 0;
    size_t carried_circuits  = 0;
    std::mt19937_64 rng{std::random_device{}()};   ///< connection ids we forward under

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
    /// Tell `peer` this node carries circuits, if it does (Serving).
    void tell_serving(const PeerId& peer);
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
    /// Record the connection a leg became, if the leg is still there.
    void     set_route(const PeerId& carrier, uint32_t circuit, PeerRoute route);

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
    /// A carried circuit is over: stop forwarding its datagrams, if it had any,
    /// and book what it moved. Caller must not hold the mutex.
    void retire(Meter& meter);
    void deny(const PeerId& to, uint32_t circuit, uint8_t reason);
    /// The client half of Accept: make the connection in the form the relay chose.
    void accept_leg(const PeerId& carrier, uint32_t circuit, uint32_t window, uint64_t cid);
    /// Drop a circuit we opened that was never accepted, and tell the relay.
    void abandon_leg(const PeerId& carrier, uint32_t circuit);

    /// One direction of a carried circuit may move this many bytes a second, this
    /// many at once (Config::max_circuit_rate_bps).
    uint64_t rate_bytes() const { return config.max_circuit_rate_bps / 8; }
    uint64_t burst_bytes() const {
        return rate_bytes() * static_cast<uint64_t>(config.circuit_burst.count()) / 1000;
    }
    TokenBucket circuit_rate(Clock::time_point now) const {
        return TokenBucket(rate_bytes(), burst_bytes(), now);
    }
    /// Pass on credit the far end granted `to`, unless `to` has spent past its
    /// rate: then it waits in `forward` until tick() finds it repaid. Caller
    /// holds the mutex; returns what to send now (0 for nothing).
    uint32_t pass_credit(Forward& forward, uint32_t granted, Clock::time_point now);

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
        case kOpServing: {
            std::lock_guard<std::mutex> lock(mutex);
            serving.insert(peer);
            break;
        }
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
    const bool     offered = body.size() > PeerId::kSize + 4 &&
                             (body.data()[PeerId::kSize + 4] & kOfferDatagrams) != 0;

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
    const auto from_wire = transport_of(*network, from);
    const auto dst_wire  = transport_of(*network, *dst);
    if (reach_of(from_wire) != Reach::Direct) return deny(from, circuit, kDenyLoop);
    switch (reach_of(dst_wire)) {
        case Reach::None:    return deny(from, circuit, kDenyNoTarget);
        case Reach::Relayed: return deny(from, circuit, kDenyLoop);
        case Reach::Direct:  break;
    }

    // Both legs datagram connections: forward the packets of one the two ends run
    // themselves instead of carrying a byte stream. Filed before the target hears
    // of it, so the forwarding is in place by the time the client can dial.
    auto meter = std::make_shared<Meter>();
    meter->started = Clock::now();
    if (offered && circuits && *from_wire == TransportKind::Udp && *dst_wire == TransportKind::Udp) {
        uint64_t cid = 0;
        {
            std::lock_guard<std::mutex> lock(mutex);
            while (cid == 0) cid = rng() & ~uint64_t{1};   // the dialer's half is even
        }
        if (circuits->forward_datagrams(from, *dst, cid,
                                        std::shared_ptr<std::atomic<uint64_t>>(meter, &meter->bytes),
                                        rate_bytes(), burst_bytes()))
            meter->cid = cid;
    }

    uint32_t far_id  = kNoCircuit;
    bool     refused = false;
    bool     repeat  = false;
    {
        // Re-checked: the reachability lookups above ran without the lock, and a
        // burst of Opens could otherwise all pass the test and then all allocate.
        std::lock_guard<std::mutex> lock(mutex);
        PeerLink& near_link = links[from];
        if (near_link.forwards.count(circuit)) {
            repeat = true;
        } else if (carried_circuits >= config.max_circuits ||
                   near_link.opened >= config.max_circuits_per_peer) {
            refused = true;
        } else {
            PeerLink& far_link = links[*dst];
            far_id = allocate_id(far_link, *dst);

            const auto now = Clock::now();
            links[from].forwards.emplace(
                circuit, Forward{*dst, far_id, meter, /*opener=*/true, circuit_rate(now)});
            links[*dst].forwards.emplace(
                far_id, Forward{from, circuit, meter, /*opener=*/false, circuit_rate(now)});
            ++links[from].opened;
            ++carried_circuits;
        }
    }
    if (refused || repeat) {
        retire(*meter);
        if (refused) deny(from, circuit, kDenyResourceLimit);
        return;
    }

    LOG_INFO("relay", "Carrying a circuit from " << from.short_hex() << " to "
              << dst->short_hex() << (meter->cid ? " (forwarding datagrams)" : ""));

    Bytes msg = message(kOpIncoming, far_id, PeerId::kSize + 4 + 8);
    append_id(msg, from);
    put_u32(msg, window);
    if (const uint64_t cid = meter->cid) put_u64(msg, cid);
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
    const uint64_t cid         = cid_at(body, PeerId::kSize + 4);

    // `src` is the relay's word, not the far end's — the handshake is what actually
    // establishes who is there. It is used only to turn away a circuit that would
    // duplicate a peer we already hold, which costs the far end a Deny instead of a
    // whole handshake it was going to lose anyway — over a link that answers: one
    // gone dead (the far end moved) is what the circuit takes the place of.
    if (reach_of(*network, *src) == Reach::Direct && network->answers(*src))
        return deny(from, circuit, kDenyRefused);
    // And the carrier itself must be a direct peer: a circuit inside a circuit is
    // the chain this refuses to be part of.
    if (reach_of(*network, from) != Reach::Direct) return deny(from, circuit, kDenyLoop);

    auto carrier = std::make_shared<Carrier>(shared_from_this(), from);
    std::shared_ptr<Circuit> incoming;
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!running.load())                                return deny(from, circuit, kDenyRefused);
        if (inbound_circuits >= config.max_inbound_circuits) return deny(from, circuit, kDenyResourceLimit);
        PeerLink& link = links[from];
        if (link.legs.count(circuit) || link.forwards.count(circuit)) return;  // a repeat

        // Open from the first instant: the far end is already there, and its
        // request carried the window it will receive.
        if (cid == 0) incoming = Circuit::accepted(circuit, carrier, peer_window, config.window);
        link.legs.emplace(circuit, Leg{incoming, PeerRoute{}, *src, /*outbound=*/false, Clock::now()});
        ++inbound_circuits;
    }

    std::optional<PeerRoute> route;
    if (cid != 0) {
        route = circuits->expect_relayed(from, cid, ForwardedCircuit(carrier, circuit));
        // Not taken: the ForwardedCircuit has already closed the circuit toward
        // the relay and released the leg.
        if (!route) return;
    } else {
        route = circuits->adopt_circuit(from, std::make_unique<RelayLink>(incoming),
                                        ConnRole::Inbound, /*connected=*/true);
        if (!route) {
            // The node will not take another peer, or the carrier went away between
            // the two lines above. Either way nothing was started.
            take_leg(from, circuit);
            return deny(from, circuit, kDenyResourceLimit);
        }
    }
    set_route(from, circuit, *route);

    // The id echoed is what tells the relay, and through it the client, that this
    // circuit is a datagram connection.
    Bytes msg = message(kOpAccept, circuit, 4 + 8);
    put_u32(msg, config.window);
    if (cid != 0) put_u64(msg, cid);
    send(from, msg);
    LOG_INFO("relay", "Accepted a circuit from " << src->short_hex() << " via "
              << from.short_hex() << (cid ? " (forwarded datagrams)" : ""));
}

// ── Messages that are either ours to act on or ours to forward ──────────────

void Relay::State::handle_accept(const PeerId& from, uint32_t circuit, ByteView body) {
    if (body.size() < 4) return;
    const uint32_t window = get_u32(body.data());
    const uint64_t cid    = cid_at(body, 4);

    bool                   ours = false;
    std::optional<Forward> forward;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(from);
        if (link == links.end()) return;
        if (link->second.legs.count(circuit)) {
            ours = true;
        } else if (auto fwd = link->second.forwards.find(circuit);
                   fwd != link->second.forwards.end()) {
            forward = fwd->second;
        }
    }

    if (ours) return accept_leg(from, circuit, window, cid);
    if (!forward) return;

    // Datagrams only if the target took them: one that answered without the id
    // (an older node) is running a byte stream.
    uint64_t forwarded = forward->meter->cid;
    if (forwarded != 0 && forwarded != cid) {
        retire(*forward->meter);
        forwarded = 0;
    }
    Bytes msg = message(kOpAccept, forward->id, 4 + 8);
    put_u32(msg, window);
    if (forwarded != 0) put_u64(msg, forwarded);
    send(forward->peer, msg);
}

void Relay::State::accept_leg(const PeerId& carrier, uint32_t circuit, uint32_t window,
                              uint64_t cid) {
    std::shared_ptr<Circuit> stream;
    PeerId                   target;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(carrier);
        if (link == links.end()) return;
        auto leg = link->second.legs.find(circuit);
        // Only a circuit we opened is accepted, and only once.
        if (leg == link->second.legs.end() || !leg->second.outbound ||
            leg->second.route.conn != kInvalidConnId)
            return;
        target = leg->second.target;
        if (cid != 0) leg->second.circuit.reset();   // never to carry a byte
        else          stream = leg->second.circuit;
    }

    // The far end is there: the connection may be made and start its handshake,
    // exactly as a completed connect would let it.
    std::optional<PeerRoute> route;
    if (cid != 0) {
        route = circuits->dial_relayed(carrier, cid,
                                       ForwardedCircuit(std::make_shared<Carrier>(shared_from_this(), carrier),
                                                        circuit));
    } else {
        route = circuits->adopt_circuit(carrier, std::make_unique<RelayLink>(stream),
                                        ConnRole::Outbound, /*connected=*/false);
    }
    if (!route) {
        // A forwarded circuit has already said so to the relay and been released;
        // a stream that never became a connection has not.
        if (cid == 0) abandon_leg(carrier, circuit);
        advance(target);
        return;
    }
    set_route(carrier, circuit, *route);
    if (stream) wake(*route, stream->on_accept(window));
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
    if (dropped.circuit)
        wake(dropped.route, dropped.circuit->on_closed(CloseReason::ConnectFailed, /*orderly=*/false));
    circuits->close_circuit(dropped.route, CloseReason::ConnectFailed);
    // The attempt is now free to try the next relay that said it could help.
    if (dropped.outbound) advance(dropped.target);
}

void Relay::State::handle_data(const PeerId& from, uint32_t circuit, ByteView body) {
    if (body.empty()) return;

    std::shared_ptr<Circuit> ours;
    PeerRoute                route{};
    std::optional<PeerId>    to;
    uint32_t                 to_id = kNoCircuit;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(from);
        if (link == links.end()) return;
        if (auto leg = link->second.legs.find(circuit); leg != link->second.legs.end()) {
            ours  = leg->second.circuit;
            route = leg->second.route;
        } else if (auto fwd = link->second.forwards.find(circuit);
                   fwd != link->second.forwards.end()) {
            to    = fwd->second.peer;
            to_id = fwd->second.id;
            fwd->second.meter->bytes += body.size();
            // Passed on regardless — the window allowed it; what it costs is
            // charged, and the sender's next credit waits until it is repaid.
            fwd->second.rate.spend(body.size(), Clock::now());
        }
    }

    if (ours) {
        // on_data enforces the window we advertised: a far end that sends past it
        // fails the circuit rather than being allowed to grow it.
        wake(route, ours->on_data(body));
        return;
    }
    // A circuit we have already forgotten, or one of ours that forwards datagrams
    // and has no stream to put this in.
    if (!to) return;

    Bytes msg = message(kOpData, to_id, body.size());
    msg.insert(msg.end(), body.begin(), body.end());
    send(*to, msg);
    carried_bytes.fetch_add(body.size(), std::memory_order_relaxed);
}

void Relay::State::handle_credit(const PeerId& from, uint32_t circuit, ByteView body) {
    if (body.size() < 4) return;
    const uint32_t granted = get_u32(body.data());

    std::shared_ptr<Circuit> ours;
    PeerRoute                route{};
    std::optional<PeerId>    to;
    uint32_t                 to_id = kNoCircuit;
    uint32_t                 passed = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto link = links.find(from);
        if (link == links.end()) return;
        if (auto leg = link->second.legs.find(circuit); leg != link->second.legs.end()) {
            ours  = leg->second.circuit;
            route = leg->second.route;
        } else if (auto fwd = link->second.forwards.find(circuit);
                   fwd != link->second.forwards.end()) {
            to    = fwd->second.peer;
            to_id = fwd->second.id;
            // The credit is for the far end's data, whose cost its own entry keeps.
            if (auto sender = links.find(*to); sender != links.end()) {
                if (auto entry = sender->second.forwards.find(to_id);
                    entry != sender->second.forwards.end())
                    passed = pass_credit(entry->second, granted, Clock::now());
            }
        }
    }

    if (ours) { wake(route, ours->on_credit(granted)); return; }
    if (to && passed != 0) {
        Bytes msg = message(kOpCredit, to_id, 4);
        put_u32(msg, passed);
        send(*to, msg);
    }
}

uint32_t Relay::State::pass_credit(Forward& sender, uint32_t granted, Clock::time_point now) {
    if (sender.held_credit == 0 && !sender.rate.in_debt(now)) return granted;
    sender.held_credit = granted > UINT32_MAX - sender.held_credit ? UINT32_MAX
                                                                   : sender.held_credit + granted;
    return 0;
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
    if (dropped.circuit) {
        wake(dropped.route, dropped.circuit->on_closed(
                                orderly ? CloseReason::PeerClosed : CloseReason::PeerReset, orderly));
    } else {
        // A datagram connection: an orderly end has reached it end to end already,
        // so whatever is left is the relay giving up on it.
        circuits->close_circuit(dropped.route, orderly ? CloseReason::PeerClosed : CloseReason::PeerReset);
    }
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

    // Already reached over a link that answers: nothing to do. One gone dead —
    // the target moved — is what a circuit takes the place of (Node's standby).
    if (network->answers(target)) return false;
    // Peers that could carry the circuit: connected, not the target, and not
    // themselves relayed — asking a relayed peer to relay is the chain we refuse.
    for (const PeerInfo& info : network->peers()) {
        if (info.id == target || info.transport == TransportKind::Relay) continue;
        candidates.push_back(info.id);
    }
    {
        // Those that said they carry circuits first: the rest most likely do not.
        std::lock_guard<std::mutex> lock(mutex);
        std::stable_partition(candidates.begin(), candidates.end(),
                              [&](const PeerId& id) { return serving.count(id) != 0; });
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
        link.legs.emplace(id, Leg{circuit, PeerRoute{}, target, /*outbound=*/true, Clock::now()});
        ++outbound_circuits;

        it->second.opening = true;
        it->second.via     = via;
        it->second.circuit = id;
    }

    // No connection yet: what it will run on — this stream, or a datagram
    // connection the relay forwards — is the relay's answer (accept_leg). The
    // circuit is made now all the same, so that whatever the far end sends ahead
    // of the acceptance is kept.
    const bool datagrams = circuits && transport_of(*network, via) == TransportKind::Udp;
    Bytes msg = message(kOpOpen, id, PeerId::kSize + 4 + 1);
    append_id(msg, target);
    put_u32(msg, config.window);
    msg.push_back(datagrams ? kOfferDatagrams : 0);
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
    tell_serving(peer.id());
    finish_attempt(peer.id(), /*succeeded=*/true);

    if (!config.upgrade_with_hole_punch) return;
    const auto info = peer.info();
    if (!info || info->transport != TransportKind::Relay) return;

    // A circuit is a fallback, not a destination. Now that the two ends are peers
    // they can arrange a punch over the very circuit carrying them, and if it lands
    // the peer table prefers the direct link at both ends and swaps the route with
    // no disconnect event — the application never sees the seam.
    if (HolePunchService* hole_punch = punch.load()) {
        LOG_INFO("relay", "Relayed peer " << peer.id().short_hex()
                  << " is up; trying to replace the circuit with a direct link");
        hole_punch->punch(peer.id());
    }
}

void Relay::State::tell_serving(const PeerId& peer) {
    if (!config.serve) return;
    const Bytes msg = message(kOpServing, kNoCircuit);
    network->send(peer, MessageType::Relay, ByteView(msg));
}

void Relay::State::on_peer_disconnected(const PeerId& id) {
    // Everything riding this link is over: the circuits we terminate through it,
    // and the ones we were carrying across it.
    std::unordered_map<uint32_t, Leg>     legs;
    std::unordered_map<uint32_t, Forward> forwards;
    {
        std::lock_guard<std::mutex> lock(mutex);
        serving.erase(id);
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
        if (leg.circuit) wake(leg.route, leg.circuit->on_closed(CloseReason::PeerReset, /*orderly=*/false));
        circuits->close_circuit(leg.route, CloseReason::PeerReset);
        if (leg.outbound) advance(leg.target);
    }

    for (const auto& [circuit, fwd] : forwards) {
        // Tell the other side, and take its half out of the tables. This peer's own
        // half went with the link above, charges and all.
        Bytes msg = message(kOpClose, fwd.id, 1);
        msg.push_back(kCloseError);
        send(fwd.peer, msg);
        retire(*fwd.meter);
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
            if (leg.circuit) waiting.emplace_back(leg.circuit, leg.route);
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

void Relay::State::set_route(const PeerId& carrier, uint32_t circuit, PeerRoute route) {
    std::lock_guard<std::mutex> lock(mutex);
    auto link = links.find(carrier);
    if (link == links.end()) return;
    auto leg = link->second.legs.find(circuit);
    if (leg != link->second.legs.end()) leg->second.route = route;
}

void Relay::State::abandon_leg(const PeerId& carrier, uint32_t circuit) {
    // The leg may already be gone — a link that was never adopted releases it as
    // it dies — but the relay has still to hear.
    take_leg(carrier, circuit);
    Bytes msg = message(kOpClose, circuit, 1);
    msg.push_back(kCloseError);
    send(carrier, msg);
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
    retire(*forward->meter);

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

void Relay::State::retire(Meter& meter) {
    // Whoever gets here first: two legs can end the same circuit at once.
    const uint64_t cid = meter.cid.exchange(0);
    if (cid == 0) return;
    circuits->stop_forwarding(cid);
    carried_bytes.fetch_add(meter.bytes.load(std::memory_order_relaxed), std::memory_order_relaxed);
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
    std::vector<std::pair<PeerId, uint32_t>> unanswered;
    struct Credit { PeerId to; uint32_t circuit; uint32_t bytes; };
    std::vector<Credit>                     credits;
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

        for (auto& [peer, link] : links) {
            for (auto& [circuit, fwd] : link.forwards) {
                // Circuits we carry that have outstayed their welcome.
                if (fwd.opener && config.max_circuit_duration.count() != 0 &&
                    now - fwd.meter->started >= config.max_circuit_duration)
                    expired.emplace_back(peer, circuit);
                // Credit held back from a sender that has since come back within
                // its rate.
                if (fwd.held_credit != 0 && !fwd.rate.in_debt(now)) {
                    credits.push_back(Credit{peer, circuit, fwd.held_credit});
                    fwd.held_credit = 0;
                }
            }
            // Circuits we opened that the relay never answered. A stream used to be
            // a connection from the start, reaped by its establish deadline; now
            // the connection is made on acceptance, and until then this is all.
            for (const auto& [circuit, leg] : link.legs)
                if (leg.outbound && leg.route.conn == kInvalidConnId &&
                    now - leg.opened >= config.open_timeout)
                    unanswered.emplace_back(peer, circuit);
        }
    }

    for (const PeerId& target : timed_out) {
        LOG_DEBUG("relay", "No relay found for " << target.short_hex());
        finish_attempt(target, /*succeeded=*/false);
    }
    for (const PeerId& target : to_advance) advance(target);
    for (const auto& [peer, circuit] : expired)
        close_carried(peer, circuit, kCloseError, /*tell_far=*/true, /*tell_near=*/true);
    for (const auto& [peer, circuit] : unanswered) abandon_leg(peer, circuit);
    for (const Credit& credit : credits) {
        Bytes msg = message(kOpCredit, credit.circuit, 4);
        put_u32(msg, credit.bytes);
        send(credit.to, msg);
    }
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
    ctx.network.on_peer_disconnected(
        [state](const PeerId& id, CloseReason) { state->on_peer_disconnected(id); });
    ctx.network.on_peer_writable([state](const Peer& peer) { state->on_peer_writable(peer.id()); });
    // Serving may have gone on the link that lost.
    ctx.network.on_peer_rerouted([state](const Peer& peer) {
        if (state->running.load()) state->tell_serving(peer.id());
    });

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

size_t Relay::forwarded_circuits() const {
    size_t n = 0;
    std::lock_guard<std::mutex> lock(state_->mutex);
    for (const auto& [peer, link] : state_->links)
        for (const auto& [circuit, fwd] : link.forwards)
            if (fwd.opener && fwd.meter->cid != 0) ++n;
    return n;
}

uint64_t Relay::carried_bytes() const {
    uint64_t total = state_->carried_bytes.load(std::memory_order_relaxed);
    // Forwarded circuits still running count in their meters.
    std::lock_guard<std::mutex> lock(state_->mutex);
    for (const auto& [peer, link] : state_->links)
        for (const auto& [circuit, fwd] : link.forwards)
            if (fwd.opener && fwd.meter->cid != 0) total += fwd.meter->bytes;
    return total;
}

bool Relay::serves(const PeerId& peer) const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->serving.count(peer) != 0;
}

size_t Relay::attempts() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->attempts.size();
}

} // namespace librats
