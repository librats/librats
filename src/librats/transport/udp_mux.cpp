#include "librats/transport/udp_mux.h"
#include "librats/core/io_poller.h"
#include "librats/crypto/blake2s.h"
#include "librats/util/logger.h"

#include <algorithm>
#include <cstring>
#include <random>
#include <utility>

namespace librats {

namespace {

/// Fresh bytes for a cookie secret. Straight from the system source rather than
/// the mux's mt19937: that generator is seeded once and its output is predictable
/// from enough samples, which is the wrong property for the one value standing
/// between a forged source address and an allocation.
void fill_random(uint8_t* out, size_t len) {
    std::random_device dev;
    for (size_t i = 0; i < len; i += sizeof(unsigned int)) {
        const unsigned int word = dev();
        const size_t       n    = (std::min)(sizeof(word), len - i);
        std::memcpy(out + i, &word, n);
    }
}

} // namespace

UdpMux::UdpMux(socket_t socket, AddressFamily family, UdpMuxDelegate& delegate,
               UdpMuxLimits limits)
    : socket_(socket), family_(family), delegate_(delegate), limits_(limits),
      recv_storage_(kUdpBatchMax * rudp::kMaxDatagram),
      // Only where a batch is really one syscall. Without that, send_datagram()
      // goes straight to the socket and never stages anything, so this would be
      // 39 KiB per node that is allocated and never touched.
      send_storage_(kUdpBatchIsOneSyscall ? kUdpBatchMax * rudp::kMaxDatagram : 0),
      secret_rotated_at_(Clock::now()),
      rng_(std::random_device{}()) {
    set_socket_buffer_sizes(socket_, kSocketBufferBytes, kSocketBufferBytes);

    // Point each slot at its slice of the storage, once. From here on a batch only
    // ever moves lengths and endpoints around — the buffers never move.
    for (size_t i = 0; i < kUdpBatchMax; ++i) {
        recv_slots_[i].data = recv_storage_.data() + i * rudp::kMaxDatagram;
        if (kUdpBatchIsOneSyscall)
            send_slots_[i].data = send_storage_.data() + i * rudp::kMaxDatagram;
    }

    for (CookieSecret& secret : cookie_secret_) fill_random(secret.data(), secret.size());
}

UdpMux::~UdpMux() {
    shutdown();
}

// ── Wire ────────────────────────────────────────────────────────────────────

void UdpMux::send_datagram(const Address& to, const uint8_t* data, size_t len) {
    if (len == 0 || len > rudp::kMaxDatagram) return;  // nothing this class produces

    // Where the socket cannot take a batch in one call, staging buys nothing:
    // flush_output() would make exactly the per-datagram calls this makes here, and
    // the copy into the staging buffer on the way there would be pure loss — it
    // would also undo the headroom trick in OutPacket, whose whole purpose is to
    // hand the socket the packet where it already lies. So go straight to the wire.
    if constexpr (!kUdpBatchIsOneSyscall) {
        send_udp_to(socket_, data, len, to, family_);
        return;
    }

    // Staged, not sent: a full congestion window is dozens of datagrams produced
    // back to back, and handing each one to the kernel separately is where most of
    // this transport's CPU used to go. They leave together in flush_output(), which
    // every entry point calls before it returns — so nothing waits on a timer.
    if (staged_ == kUdpBatchMax) flush_output();

    UdpBatchSlot& slot = send_slots_[staged_++];
    slot.endpoint      = to;
    slot.len           = len;
    std::memcpy(slot.data, data, len);
}

void UdpMux::flush_output() {
    if (staged_ == 0) return;
    const size_t staged = staged_;
    staged_ = 0;  // spent either way: what the socket refused is a dropped datagram

    const size_t sent = send_udp_batch(socket_, send_slots_.data(), staged, family_);
    if (sent < staged)
        LOG_DEBUG("udp", "Socket took " << sent << "/" << staged
                  << " datagrams; the rest are dropped (retransmission covers them)");
}

void UdpMux::stream_events(UdpStream& stream, uint32_t events) {
    // Recorded, never delivered from here: see the file comment. A stream with no
    // connection (one that is lingering after its connection went away) has
    // nowhere to send events, and quietly drops them.
    const ConnId id = stream.conn_id();
    if (id == kInvalidConnId) return;

    // Coalesce. A stream raises PollIn for every packet it delivers, so a run of
    // datagrams from one peer used to queue one dispatch per packet — and every one
    // after the first found the connection's buffer already drained, having paid a
    // map lookup and a read attempt to find that out.
    //
    // Scanning the tail rather than the whole list is what keeps this O(1) in the
    // size of the node: during a receive batch the list cannot be longer than the
    // batch, so the window covers all of it and the coalescing is exact; in tick(),
    // where the list can hold an entry per stream, each stream is visited once and
    // there is nothing to coalesce anyway.
    const size_t from = pending_events_.size() > kUdpBatchMax
                            ? pending_events_.size() - kUdpBatchMax
                            : 0;
    for (size_t i = from; i < pending_events_.size(); ++i) {
        if (pending_events_[i].first != id) continue;
        pending_events_[i].second |= events;
        return;
    }
    pending_events_.emplace_back(id, events);
}

void UdpMux::send_reset(const Address& to, uint32_t conn_id) {
    uint8_t buf[rudp::kHeaderSize];
    rudp::Packet p;
    p.type    = rudp::PacketType::Reset;
    p.conn_id = conn_id;
    send_datagram(to, buf, rudp::encode(p, buf));
}

void UdpMux::send_retry(const Address& to, uint32_t conn_id, uint32_t cookie) {
    uint8_t cookie_bytes[rudp::kCookieSize] = {
        static_cast<uint8_t>(cookie >> 24), static_cast<uint8_t>(cookie >> 16),
        static_cast<uint8_t>(cookie >> 8),  static_cast<uint8_t>(cookie),
    };

    uint8_t buf[rudp::kHeaderSize + rudp::kCookieSize];
    rudp::Packet p;
    p.type    = rudp::PacketType::Retry;
    p.conn_id = conn_id;
    p.payload = ByteView(cookie_bytes, sizeof(cookie_bytes));
    send_datagram(to, buf, rudp::encode(p, buf));
}

bool UdpMux::spend_reply_budget() {
    if (replies_this_tick_ >= kMaxUnsolicitedRepliesPerTick) return false;
    ++replies_this_tick_;
    return true;
}

// ── Address validation ──────────────────────────────────────────────────────

uint32_t UdpMux::cookie_for(const Address& from, uint32_t conn_id,
                            const CookieSecret& secret) const {
    // A keyed hash of everything the cookie has to be tied to, truncated to the
    // four bytes the wire carries. The secret goes in first: BLAKE2 is designed to
    // be a MAC in exactly this prefix form (it has no length-extension weakness to
    // work around), so there is no reason to reach for HMAC here.
    //
    // Binding the port as well as the address is what makes the cookie useless to
    // anyone but the socket that asked for it, and binding conn_id keeps one cookie
    // from opening a second stream. Nothing binds a timestamp: the secret's own
    // rotation is what expires a cookie.
    const ByteView ip    = from.ip.bytes();
    const uint8_t  tail[6] = {
        static_cast<uint8_t>(from.port >> 8), static_cast<uint8_t>(from.port),
        static_cast<uint8_t>(conn_id >> 24),  static_cast<uint8_t>(conn_id >> 16),
        static_cast<uint8_t>(conn_id >> 8),   static_cast<uint8_t>(conn_id),
    };

    rats_blake2s_context_t ctx;
    rats_blake2s_reset(&ctx);
    rats_blake2s_update(&ctx, secret.data(), secret.size());
    rats_blake2s_update(&ctx, ip.data(), ip.size());
    rats_blake2s_update(&ctx, tail, sizeof(tail));

    uint8_t hash[RATS_BLAKE2S_HASH_SIZE];
    rats_blake2s_finish(&ctx, hash);
    return (static_cast<uint32_t>(hash[0]) << 24) | (static_cast<uint32_t>(hash[1]) << 16) |
           (static_cast<uint32_t>(hash[2]) << 8)  |  static_cast<uint32_t>(hash[3]);
}

bool UdpMux::cookie_valid(const Address& from, uint32_t conn_id, ByteView payload) const {
    if (payload.size() != rudp::kCookieSize) return false;

    const uint8_t* bytes   = payload.data();
    const uint32_t offered = (static_cast<uint32_t>(bytes[0]) << 24) |
                             (static_cast<uint32_t>(bytes[1]) << 16) |
                             (static_cast<uint32_t>(bytes[2]) << 8)  |
                              static_cast<uint32_t>(bytes[3]);

    // Both secrets, so a cookie handed out just before a rotation is still good.
    for (const CookieSecret& secret : cookie_secret_)
        if (cookie_for(from, conn_id, secret) == offered) return true;
    return false;
}

void UdpMux::rotate_cookie_secret(Clock::time_point now) {
    if (now - secret_rotated_at_ < kCookieSecretLifetime) return;
    cookie_secret_[1] = cookie_secret_[0];
    fill_random(cookie_secret_[0].data(), cookie_secret_[0].size());
    secret_rotated_at_ = now;
}

// ── Inbound datagrams ───────────────────────────────────────────────────────

bool UdpMux::on_readable() {
    const auto now = Clock::now();

    size_t drained = 0;
    bool   more    = false;
    for (;;) {
        if (drained >= kMaxDatagramsPerRead) { more = true; break; }

        // Never ask for more than the cap allows, so the bound on how long one
        // flood can hold the loop stays exact rather than approximate.
        const size_t want = (std::min)(kUdpBatchMax, kMaxDatagramsPerRead - drained);
        for (size_t i = 0; i < want; ++i) recv_slots_[i].len = rudp::kMaxDatagram;

        const std::ptrdiff_t got = recv_udp_batch(socket_, recv_slots_.data(), want);
        if (got == kUdpRecvWouldBlock) break;
        // A per-destination error (an ICMP unreachable for an earlier datagram,
        // which Windows in particular reports on the *next* receive) says nothing
        // about the socket, so keep draining rather than abandoning every other
        // peer on it. The loop is bounded, so a persistent error cannot spin.
        if (got == kUdpRecvError) { ++drained; continue; }

        for (std::ptrdiff_t i = 0; i < got; ++i) {
            const UdpBatchSlot& slot = recv_slots_[static_cast<size_t>(i)];
            rudp::Packet p;
            if (!rudp::decode(slot.data, slot.len, p)) continue;
            handle_datagram(p, slot.endpoint, now);
        }
        drained += static_cast<size_t>(got);

        // Hand this batch's events over before reading the next one, rather than
        // saving them all for the end of the drain. What a stream delivers sits in
        // its in-order buffer until its connection reads it out, so deferring the
        // whole drain let that buffer grow to everything one peer managed to send
        // in it — a megabyte and more, written and then read back through main
        // memory, and enough to close the receive window mid-drain. Draining per
        // batch keeps it to one batch's worth, which stays in cache.
        //
        // Safe here and nowhere earlier: the slot loop above has finished, so no
        // reference into streams_ is live, and a handler that closes its connection
        // only marks it — the teardown that would free a stream runs later, on the
        // reactor.
        dispatch_pending();
        // A short batch usually means the queue is empty, but not always (a
        // per-datagram error truncates one too), and the kqueue backend is
        // edge-triggered — so keep going until the socket says would-block.
    }

    dispatch_pending();
    flush_output();  // the acks and repairs the batch above produced leave together
    return more;
}

void UdpMux::handle_datagram(const rudp::Packet& p, const Address& from, Clock::time_point now) {
    auto it = streams_.find(p.conn_id);
    if (it != streams_.end()) {
        UdpStream& stream = *it->second.stream;
        // The connection id is the whole authorisation to touch this stream, and a
        // datagram source address is trivially forged. Pinning the stream to the
        // address it was established with means an attacker would have to guess a
        // random 32-bit id *and* be on the path. (It also means this transport does
        // not follow a peer across a NAT rebind — the peer redials, which the
        // handshake makes cheap and safe.)
        if (stream.remote() != from) return;
        stream.on_packet(p, now);
        return;
    }

    if (p.type == rudp::PacketType::Syn) {
        if (admit_syn(p, from)) accept_inbound(p, from, now);
        return;
    }

    if (p.type == rudp::PacketType::Reset) {
        // A reset for a stream the sender never knew carries the id *it* was
        // given, which is our send id rather than our recv id — see find_for_reset.
        if (UdpStream* stream = find_for_reset(p.conn_id, from)) stream->on_packet(p, now);
        return;
    }

    // Nothing here answers to that id: a stream we closed, or one left over from a
    // previous run of this node. Say so, so the peer gives up now instead of
    // retransmitting for a minute — but never more than a fixed number per tick,
    // so a flood of garbage cannot turn this socket into a reflector.
    if (spend_reply_budget()) send_reset(from, p.conn_id);
}

bool UdpMux::admit_syn(const rudp::Packet& syn, const Address& from) {
    // Everything this function refuses is refused BEFORE a stream exists. That is
    // the whole point: a Syn is sixteen bytes from an address nobody has verified,
    // and answering it with a stream, a connection and a half-built Noise handshake
    // is a trade an attacker with a forged source address would happily make a
    // million times a second. TCP is spared this by its three-way handshake and by
    // the file descriptor an accepted connection costs; here the two checks below
    // stand in for both.
    //
    // The id the dialer listens on is one below the one it sent under, so that is
    // where any answer has to go — the same pairing accept_inbound() relies on.
    const uint32_t reply_id = syn.conn_id - 1;

    if (streams_.size() >= limits_.max_streams) {
        LOG_DEBUG("udp", "Refusing a dial from " << from.to_string() << ": at the stream ceiling ("
                  << limits_.max_streams << ")");
        if (spend_reply_budget()) send_reset(from, reply_id);
        return false;
    }

    if (streams_.size() < limits_.validate_above) return true;  // not under pressure

    if (cookie_valid(from, syn.conn_id, syn.payload)) return true;

    // Unproven. Hand back a cookie and keep nothing: if the address was forged, the
    // cookie goes to whoever really lives there and this dial simply never happens.
    if (spend_reply_budget())
        send_retry(from, reply_id, cookie_for(from, syn.conn_id, cookie_secret_[0]));
    return false;
}

void UdpMux::accept_inbound(const rudp::Packet& syn, const Address& from, Clock::time_point now) {
    // Id pairing: the dialer picked `base`, keeps `base` as its recv id and sends
    // under `base + 1`. So a Syn's conn_id is our recv id, and one less is what we
    // must send under to reach the dialer. One random number, two ids, no
    // negotiation round trip.
    const uint32_t recv_id = syn.conn_id;
    const uint32_t send_id = syn.conn_id - 1;

    auto stream = std::make_unique<UdpStream>(*this, from, recv_id, send_id,
                                              ConnRole::Inbound, now);
    UdpStream* raw = stream.get();
    streams_.emplace(recv_id, Entry{std::move(stream), Clock::time_point{}});

    // Adoption takes the link; refusing it destroys the link, which releases the
    // stream — so `raw` must not be touched again on that path.
    const ConnId id = delegate_.adopt_inbound_link(std::make_unique<UdpStreamLink>(*this, *raw));
    if (id == kInvalidConnId) {
        send_reset(from, send_id);
        return;
    }

    LOG_DEBUG("udp", "Accepted stream " << recv_id << " from " << from.to_string());
    raw->on_packet(syn, now);  // acknowledges the Syn and opens the stream
}

UdpStream* UdpMux::find_for_reset(uint32_t conn_id, const Address& from) {
    // A reset generated for an unknown stream can only echo the id that was in the
    // datagram that provoked it — which is our *send* id, not the recv id the map
    // is keyed by. The two always differ by exactly one (see accept_inbound), so
    // two probes find it, and both are validated against the send id and the peer
    // address before anything is acted on.
    for (const uint32_t candidate : {conn_id - 1, conn_id + 1}) {
        auto it = streams_.find(candidate);
        if (it == streams_.end()) continue;
        UdpStream& stream = *it->second.stream;
        if (stream.send_id() == conn_id && stream.remote() == from) return &stream;
    }
    return nullptr;
}

// ── Outbound ────────────────────────────────────────────────────────────────

bool UdpMux::allocate_ids(uint32_t& recv_id, uint32_t& send_id) {
    std::uniform_int_distribution<uint32_t> pick(1, 0xFFFFFFFEu);  // keeps base+1 non-zero
    for (int attempt = 0; attempt < 32; ++attempt) {
        const uint32_t base = pick(rng_);
        if (streams_.count(base) || streams_.count(base + 1)) continue;
        recv_id = base;
        send_id = base + 1;
        return true;
    }
    return false;  // 32 collisions in a 4-billion space: the map is implausibly full
}

std::unique_ptr<Link> UdpMux::connect(const Address& remote) {
    uint32_t recv_id = 0, send_id = 0;
    if (!allocate_ids(recv_id, send_id)) {
        LOG_WARN("udp", "Could not allocate a connection id for " << remote.to_string());
        return nullptr;
    }

    auto stream = std::make_unique<UdpStream>(*this, remote, recv_id, send_id,
                                              ConnRole::Outbound, Clock::now());
    UdpStream* raw = stream.get();
    streams_.emplace(recv_id, Entry{std::move(stream), Clock::time_point{}});
    flush_output();  // the Syn is the dial; it does not wait for company
    return std::make_unique<UdpStreamLink>(*this, *raw);
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

void UdpMux::release(UdpStream& stream) {
    auto it = streams_.find(stream.recv_id());
    if (it == streams_.end() || it->second.stream.get() != &stream) return;

    stream.set_conn_id(kInvalidConnId);  // events have nowhere to go from here on

    if (stream.connecting()) {
        // A dial that was called off (the other transport won the race, or the
        // node is going down). There is nothing to hand over, and a lingering Syn
        // would keep asking a peer to open a stream nobody will read.
        stream.abort(Clock::now());
        streams_.erase(it);
    } else if (stream.dead() || stream.flushed()) {
        streams_.erase(it);
    } else {
        // Something is still owed to the peer. Keep the stream just long enough to
        // hand it over — this is the user-space equivalent of the kernel continuing
        // to retransmit after close(), and without it a node that sends a final
        // message and disconnects would drop it on the floor.
        it->second.linger_until = Clock::now() + kLingerTimeout;
    }

    // The Connection told the link goodbye just before letting go of it, so a Fin
    // or a Reset is usually staged by the time we get here. It must not outlive the
    // call that produced it.
    flush_output();
}

void UdpMux::tick() {
    const auto now = Clock::now();
    replies_this_tick_ = 0;
    rotate_cookie_secret(now);

    expired_.clear();
    for (auto& entry : streams_) {
        UdpStream& stream = *entry.second.stream;
        stream.tick(now);

        const bool lingering = entry.second.linger_until != Clock::time_point{};
        if (lingering && (stream.flushed() || stream.dead() || now >= entry.second.linger_until))
            expired_.push_back(entry.first);
    }
    for (const uint32_t id : expired_) streams_.erase(id);
    expired_.clear();

    dispatch_pending();
    flush_output();  // one syscall for every stream's retransmissions and keep-alives
}

void UdpMux::shutdown() {
    const auto now = Clock::now();
    for (auto& entry : streams_) entry.second.stream->abort(now);
    flush_output();  // the goodbyes go out before the streams they came from
    streams_.clear();
    pending_events_.clear();
}

void UdpMux::dispatch_pending() {
    if (pending_events_.empty()) return;
    // Swap the batch out first: a handler may close its connection, which releases
    // a stream and can record further events. Those are picked up by the next
    // drain or tick rather than extending the loop we are inside.
    auto batch = std::move(pending_events_);
    pending_events_.clear();
    for (const auto& [id, events] : batch) delegate_.dispatch_link_events(id, events);
}

// ── UdpStreamLink ───────────────────────────────────────────────────────────

Link::IoResult UdpStreamLink::read(ByteSpan into) {
    const size_t n = stream_.read(into.data(), into.size());
    if (n > 0) return {n, Status::Ok};
    if (stream_.eof()) return {0, Status::Closed};
    if (stream_.dead()) return {0, Status::Error};
    return {0, Status::WouldBlock};
}

Link::IoResult UdpStreamLink::write(const ByteView* slices, size_t count) {
    if (stream_.dead()) return {0, Status::Error};
    const size_t n = stream_.write(slices, count, UdpMux::Clock::now());
    return {n, n > 0 ? Status::Ok : Status::WouldBlock};
}

void UdpStreamLink::close(CloseReason reason) {
    const auto now = UdpMux::Clock::now();
    // An application-level close deserves an orderly one: queue a Fin behind
    // whatever is still unsent, so the peer receives every byte and then a clean
    // end of stream. Anything else — a protocol error, a duplicate connection, the
    // node going down — has nothing worth flushing, so say so at once.
    if (reason == CloseReason::LocalClose || reason == CloseReason::PeerClosed)
        stream_.begin_close(now);
    else
        stream_.abort(now);
}

} // namespace librats
