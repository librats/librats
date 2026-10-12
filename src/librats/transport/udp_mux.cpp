#include "librats/transport/udp_mux.h"
#include "librats/core/io_poller.h"
#include "librats/crypto/blake2s.h"
#include "librats/transport/udp_transport.h"
#include "librats/util/logger.h"

#include <algorithm>
#include <cstring>
#include <random>
#include <utility>

namespace librats {

using namespace udp;

namespace {

/// Fresh bytes for a secret, straight from the system source rather than the
/// mux's generator: that one is seeded once and predictable from enough output,
/// the wrong property for what stands between a forged address and an allocation.
void fill_random(uint8_t* out, size_t len) {
    std::random_device dev;
    for (size_t i = 0; i < len; i += sizeof(unsigned int)) {
        const unsigned int word = dev();
        const size_t       n    = (std::min)(sizeof(word), len - i);
        std::memcpy(out + i, &word, n);
    }
}

void put_cid(uint8_t* p, Cid cid) noexcept {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<uint8_t>(cid);
        cid >>= 8;
    }
}

} // namespace

UdpMux::UdpMux(socket_t socket, AddressFamily family, UdpMuxDelegate& delegate,
               SecurityProvider& security, UdpMuxLimits limits, CongestionAlgorithm congestion)
    : socket_(socket), family_(family), delegate_(delegate), security_(security), limits_(limits),
      congestion_(congestion),
      receive_budget_(limits.receive_budget),
      // Probed before the socket buffers are sized or anything is read, so the
      // receive batch is built for what the socket will actually hand it.
      offload_(limits.offload ? enable_udp_offload(socket) : UdpOffload{}),
      send_(offload_.max_segments),
      recv_(kMaxDatagram, offload_.coalesced_receive),
      secret_rotated_at_(Clock::now()),
      rng_(std::random_device{}()) {
    set_socket_buffer_sizes(socket_, kSocketBufferBytes, kSocketBufferBytes);
    for (Secret& secret : token_secret_) fill_random(secret.data(), secret.size());

    const bool keyed = std::any_of(limits.reset_key.begin(), limits.reset_key.end(),
                                   [](uint8_t b) { return b != 0; });
    if (keyed) reset_key_ = limits.reset_key;
    else       fill_random(reset_key_.data(), reset_key_.size());
}

UdpMux::~UdpMux() {
    shutdown();
}

UdpConnectionConfig UdpMux::connection_config(DialProfile profile) noexcept {
    UdpConnectionConfig c;
    c.congestion = congestion_;
    c.dial       = profile;
    c.max_window = limits_.receive_window;
    c.budget     = &receive_budget_;
    return c;
}

// ── Wire ────────────────────────────────────────────────────────────────────

uint8_t* UdpMux::datagram_buffer() {
    // Built where it will leave from. An empty batch always has room for one.
    if (uint8_t* room = send_.stage(kMaxDatagram)) return room;
    flush_output();
    return send_.stage(kMaxDatagram);
}

void UdpMux::send_datagram(const Address& to, size_t len) {
    send_.commit(to, len);
    // Never more at once than one release of the pacer: what one flush hands the
    // socket leaves at line rate, and a batch that kept collecting would glue
    // releases the pacer spread over time back into one burst. That is what a
    // reactor turn of application sends does, and on a busy single-core host it was
    // two hundred datagrams at once and a loss round each time.
    if (send_.bytes() >= Recovery::kPaceMaxBurst) flush_output();
}

void UdpMux::flush_output() {
    if (send_.empty()) return;
    const size_t staged = send_.datagrams();
    // Spent either way: what the socket refused is a dropped datagram.
    const size_t sent = send_.flush(socket_, family_);
    if (sent < staged)
        LOG_DEBUG("udp", "Socket took " << sent << "/" << staged
                  << " datagrams; the rest are dropped (recovery covers them)");
}

void UdpMux::connection_events(UdpConnection& conn, uint32_t events) {
    // Recorded, never delivered from here. A connection with no transport (one
    // lingering after its transport went away) has nowhere to send events.
    const ConnId id = conn.conn_id();
    if (id == kInvalidConnId) return;

    // Coalesced: a connection raises PollIn for every packet that completes data,
    // and only the first dispatch finds anything to do. Scanning only the tail
    // keeps this O(1) in the size of the node: during a receive batch the list is
    // no longer than the batch.
    const size_t from = pending_events_.size() > kUdpBatchMax ? pending_events_.size() - kUdpBatchMax : 0;
    for (size_t i = from; i < pending_events_.size(); ++i) {
        if (pending_events_[i].first != id) continue;
        pending_events_[i].second |= events;
        return;
    }
    pending_events_.emplace_back(id, events);
}

void UdpMux::reset_token(Cid cid, uint8_t* out) {
    uint8_t id[kCidSize];
    put_cid(id, cid);
    rats_blake2s_context_t ctx;
    rats_blake2s_reset(&ctx);
    rats_blake2s_update(&ctx, reset_key_.data(), reset_key_.size());
    rats_blake2s_update(&ctx, id, sizeof(id));
    uint8_t hash[RATS_BLAKE2S_HASH_SIZE];
    rats_blake2s_finish(&ctx, hash);
    std::memcpy(out, hash, kResetTokenSize);
}

bool UdpMux::spend_reply_budget(Clock::time_point now) {
    if (now - reply_window_started_ >= kUnsolicitedReplyWindow) {
        reply_window_started_ = now;
        replies_in_window_    = 0;
    }
    if (replies_in_window_ >= kMaxUnsolicitedReplies) return false;
    ++replies_in_window_;
    return true;
}

void UdpMux::send_refusal(const Address& to, const LongPacket& initial, uint64_t code) {
    uint8_t* buf = datagram_buffer();
    send_datagram(to, encode_close(buf, initial.scid, initial.dcid, code));
}

void UdpMux::send_retry(const Address& to, const LongPacket& initial) {
    uint8_t token[kTokenSize];
    token_for(to, initial.dcid, token_secret_[0], token);
    uint8_t* buf = datagram_buffer();
    send_datagram(to, encode_retry(buf, initial.scid, initial.dcid, ByteView(token, kTokenSize)));
}

void UdpMux::send_stateless_reset(const Address& to, Cid dcid, size_t trigger_len) {
    // Shaped like a short packet — random where a packet's sealed bytes would be —
    // addressed to the peer's half of the pair, and ending with the token our
    // half was given. Always shorter than what provoked it, so two nodes that
    // have both forgotten a connection cannot keep resetting each other, and never
    // longer than it needs to be.
    if (trigger_len <= kMinShortPacket) return;
    const size_t len = (std::min)(trigger_len - 1, kMinShortPacket + 8);
    uint8_t* buf = datagram_buffer();
    for (size_t i = 0; i < len; i += 8) {
        const uint64_t word = rng_();
        std::memcpy(buf + i, &word, (std::min<size_t>)(8, len - i));
    }
    buf[0] = static_cast<uint8_t>(0x40 | (buf[0] & 0x3F));
    put_cid(buf + 1, paired_cid(dcid));
    reset_token(dcid, buf + len - kResetTokenSize);
    send_datagram(to, len);
}

// ── Deadline scheduling ─────────────────────────────────────────────────────

void UdpMux::arm(Cid cid, Entry& entry) {
    std::optional<Clock::time_point> due = entry.conn->next_deadline();

    if (entry.linger_until != Clock::time_point{}) {
        // A released connection is on a clock of its own, and once it has handed
        // over everything — or died trying — it wants collecting at once.
        if (entry.conn->dead() || entry.conn->flushed()) due = Clock::time_point{};
        else if (!due)                                   due = entry.linger_until;
        else                                             due = (std::min)(*due, entry.linger_until);
    }
    if (!due) return;   // dead and still owned: release() drops it

    // A deadline that moved earlier needs a slot of its own; one that moved later
    // needs nothing — the existing slot visits early and re-arms.
    if (entry.armed && *due >= entry.scheduled) return;
    entry.scheduled = *due;
    entry.armed     = true;
    due_.push_back(Due{*due, cid});
    std::push_heap(due_.begin(), due_.end(), LaterFirst{});
}

void UdpMux::compact_due() {
    // Lazy deletion leaves a slot behind for every deadline that moved earlier and
    // every connection that went away; this only stops them piling up.
    if (due_.size() <= 64 || due_.size() <= 4 * conns_.size()) return;
    std::vector<Due> live;
    live.reserve(conns_.size());
    for (const Due& slot : due_) {
        const auto it = conns_.find(slot.cid);
        if (it != conns_.end() && it->second.armed && it->second.scheduled == slot.at)
            live.push_back(slot);
    }
    due_.swap(live);
    std::make_heap(due_.begin(), due_.end(), LaterFirst{});
}

int UdpMux::next_timeout_ms(int max_ms) const noexcept {
    if (due_.empty()) return max_ms;
    const auto now = Clock::now();
    const auto at  = due_.front().at;
    if (at <= now) return 0;
    // Rounded up, as TimerQueue does: truncating a sub-millisecond remainder to 0
    // would spin until the deadline instead of sleeping through it.
    const auto ms = std::chrono::ceil<std::chrono::milliseconds>(at - now).count();
    return static_cast<int>((std::min<long long>)(ms, max_ms));
}

void UdpMux::touch(UdpConnection& conn) {
    const auto it = conns_.find(conn.local_cid());
    if (it == conns_.end() || it->second.conn.get() != &conn) return;
    arm(it->first, it->second);
}

// ── Address validation ──────────────────────────────────────────────────────

void UdpMux::token_for(const Address& from, Cid dcid, const Secret& secret, uint8_t* out) const {
    // A keyed hash of everything the token is tied to. BLAKE2 is a MAC in this
    // prefix form. The port binds it to the one socket that asked, the id to the
    // one connection; nothing binds a time — the secret's rotation expires it.
    const ByteView ip = from.ip.bytes();
    uint8_t tail[2 + kCidSize];
    tail[0] = static_cast<uint8_t>(from.port >> 8);
    tail[1] = static_cast<uint8_t>(from.port);
    put_cid(tail + 2, dcid);

    rats_blake2s_context_t ctx;
    rats_blake2s_reset(&ctx);
    rats_blake2s_update(&ctx, secret.data(), secret.size());
    rats_blake2s_update(&ctx, ip.data(), ip.size());
    rats_blake2s_update(&ctx, tail, sizeof(tail));
    uint8_t hash[RATS_BLAKE2S_HASH_SIZE];
    rats_blake2s_finish(&ctx, hash);
    std::memcpy(out, hash, kTokenSize);
}

bool UdpMux::token_valid(const Address& from, Cid dcid, ByteView token) const {
    if (token.size() != kTokenSize) return false;
    // Both secrets, so a token handed out just before a rotation is still good.
    for (const Secret& secret : token_secret_) {
        uint8_t expect[kTokenSize];
        token_for(from, dcid, secret, expect);
        if (std::memcmp(expect, token.data(), kTokenSize) == 0) return true;
    }
    return false;
}

void UdpMux::rotate_token_secret(Clock::time_point now) {
    if (now - secret_rotated_at_ < kTokenSecretLifetime) return;
    token_secret_[1] = token_secret_[0];
    fill_random(token_secret_[0].data(), token_secret_[0].size());
    secret_rotated_at_ = now;
}

// ── Inbound datagrams ───────────────────────────────────────────────────────

bool UdpMux::on_readable() {
    const auto now = Clock::now();
    // Tokens are minted from here, so this is where the secret has to be current:
    // a node with no connections has no ticks, and that is the node a flood of
    // Initials arrives at.
    rotate_token_secret(now);

    size_t drained        = 0;
    size_t since_dispatch = 0;
    bool   more           = false;
    for (;;) {
        if (drained >= kMaxDatagramsPerRead) { more = true; break; }
        const size_t room = (kMaxDatagramsPerRead - drained) / recv_.max_datagrams_per_buffer();
        const size_t want = (std::max)(size_t{1}, (std::min)(kUdpBatchMax, room));

        const std::ptrdiff_t got = recv_.receive(socket_, want);
        if (got == kUdpRecvWouldBlock) break;
        // A per-destination error (an ICMP unreachable for an earlier datagram,
        // which Windows reports on the next receive) says nothing about the socket.
        if (got == kUdpRecvError) { ++drained; continue; }

        // Stamped per batch, not per drain: handlers run as the drain goes, and on a
        // slow host a drain lasts tens of milliseconds — an ACK read at its end
        // stamped with its start once measured a 33 ms path at 2 ms.
        const auto at = Clock::now();
        for (std::ptrdiff_t i = 0; i < got; ++i) {
            const Address from = recv_[static_cast<size_t>(i)].from;
            recv_.for_each_datagram(static_cast<size_t>(i), [&](uint8_t* data, size_t len) {
                ++drained;
                handle_datagram(data, len, from, at);
                // Events every kUdpBatchMax datagrams rather than at the end of the
                // drain: what a connection completes waits in its inbox until the
                // transport reads it, and holding the events for the whole drain let
                // that grow to everything one peer managed to send in it.
                if (++since_dispatch == kUdpBatchMax) {
                    dispatch_pending();
                    since_dispatch = 0;
                }
            });
        }
        end_bursts();
    }

    dispatch_pending();
    flush_output();   // the ACKs and data the batch above produced leave together
    return more;
}

void UdpMux::handle_datagram(uint8_t* data, size_t len, const Address& from, Clock::time_point now) {
    Cid dcid = 0;
    if (!peek_dcid(data, len, dcid)) return;   // not a packet of this protocol

    if (auto it = conns_.find(dcid); it != conns_.end()) {
        UdpConnection& conn = *it->second.conn;
        // The id is the whole authorisation to touch the connection, and a source
        // address is trivially forged: a connection is pinned to the address it was
        // made with, so an attacker would need a random 64-bit id and the path.
        if (conn.remote() != from) return;
        if (!conn.in_burst()) {
            conn.begin_burst();
            bursts_.push_back(dcid);
        }
        conn.on_datagram(data, len, now);
        arm(it->first, it->second);
        return;
    }

    if (is_long_header(data[0])) {
        LongPacket p;
        if (decode_long(data, len, p) && p.type == LongType::Initial) on_initial(p, len, from, now);
        return;   // a stray handshake packet for nobody: nothing to say
    }

    // A connection we have forgotten (closed, or from before a restart): say so,
    // so the peer stops now — at a bounded rate, so this socket is no reflector.
    if (spend_reply_budget(now)) send_stateless_reset(from, dcid, len);
}

void UdpMux::on_initial(const LongPacket& initial, size_t len, const Address& from,
                        Clock::time_point now) {
    // Everything refused here is refused BEFORE a connection exists. An Initial is
    // one datagram from an address nobody has verified, and a connection with a
    // half-built Noise handshake is a trade an attacker forging addresses would
    // make a million times a second. The dialer's id is even and ours the one
    // above it; an Initial is always full size, which is what lets us answer it
    // with three times as much before the dialer proves its address.
    if (len != kMaxDatagram || initial.scid != paired_cid(initial.dcid) || (initial.dcid & 1) == 0)
        return;

    if (conns_.size() >= limits_.max_streams) {
        LOG_DEBUG("udp", "Refusing a dial from " << from.to_string() << ": at the ceiling ("
                  << limits_.max_streams << ")");
        if (spend_reply_budget(now)) send_refusal(from, initial, UdpConnection::kCloseRefused);
        return;
    }

    bool validated = token_valid(from, initial.dcid, initial.token);
    if (!validated && conns_.size() >= limits_.validate_above) {
        // Unproven: hand back a token and keep nothing. If the address was forged,
        // the token goes to whoever really lives there and this dial never happens.
        if (spend_reply_budget(now)) send_retry(from, initial);
        return;
    }

    auto conn = UdpConnection::accept(*this, security_, from, initial, len, validated, now,
                                      connection_config());
    if (!conn) return;   // not the opening of a handshake
    UdpConnection* raw = conn.get();
    auto inserted = conns_.emplace(initial.dcid, Entry{std::move(conn)});

    // Adoption takes the transport; refusing it destroys the transport, which
    // releases the connection — so `raw` is not touched on that path. Nothing has
    // been sent yet, so the refusal is the only answer the dialer gets.
    const ConnId id = delegate_.adopt_inbound(std::make_unique<UdpTransport>(*this, *raw));
    if (id == kInvalidConnId) {
        send_refusal(from, initial, UdpConnection::kCloseRefused);
        return;
    }
    LOG_DEBUG("udp", "Accepted connection " << initial.dcid << " from " << from.to_string());
    raw->answer(now);
    arm(inserted.first->first, inserted.first->second);
}

void UdpMux::end_bursts() {
    if (bursts_.empty()) return;
    // One clock read for all of them: the ACKs go now, and the delay they report
    // is how long the burst took to read.
    const auto now = Clock::now();
    for (const Cid cid : bursts_) {
        const auto it = conns_.find(cid);
        if (it == conns_.end()) continue;
        it->second.conn->end_burst(now);
        arm(it->first, it->second);
    }
    bursts_.clear();
}

// ── Outbound ────────────────────────────────────────────────────────────────

bool UdpMux::allocate_cid(Cid& cid) {
    for (int attempt = 0; attempt < 32; ++attempt) {
        const Cid base = rng_() & ~Cid{1};   // the dialer's half is even
        if (conns_.count(base) || conns_.count(paired_cid(base))) continue;
        cid = base;
        return true;
    }
    return false;
}

std::unique_ptr<Transport> UdpMux::connect(const Address& remote, DialProfile profile) {
    Cid cid = 0;
    if (!allocate_cid(cid)) {
        LOG_WARN("udp", "Could not allocate a connection id for " << remote.to_string());
        return nullptr;
    }
    auto conn = UdpConnection::dial(*this, security_, remote, cid, Clock::now(), connection_config(profile));
    UdpConnection* raw = conn.get();
    const auto inserted = conns_.emplace(cid, Entry{std::move(conn)});
    arm(cid, inserted.first->second);   // the Initial's repeat
    flush_output();                     // the Initial is the dial; it does not wait for company
    return std::make_unique<UdpTransport>(*this, *raw);
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

void UdpMux::release(UdpConnection& conn) {
    auto it = conns_.find(conn.local_cid());
    if (it == conns_.end() || it->second.conn.get() != &conn) return;

    conn.set_conn_id(kInvalidConnId);   // events have nowhere to go from here on
    const auto now = Clock::now();

    if (conn.handshaking()) {
        // A dial called off (the other transport won the race, the node is going
        // down) or a dialer we never finished with: nothing to hand over.
        conn.abort(now);
        conns_.erase(it);
    } else if (conn.dead()) {
        conns_.erase(it);
    } else {
        // Its transport normally asked for a close already, and this is a no-op;
        // if it did not, the goodbye is orderly. Either way, while data is still
        // owed the connection stays just long enough to hand it over — the user-
        // space equivalent of the kernel retransmitting after close().
        conn.close(CloseReason::LocalClose, now);
        if (conn.dead()) {
            conns_.erase(it);
        } else {
            it->second.linger_until = now + kLingerTimeout;
            arm(it->first, it->second);
        }
    }
    // The goodbye must not outlive the call that produced it.
    flush_output();
}

void UdpMux::tick() {
    if (due_.empty()) return;
    const auto now = Clock::now();
    if (due_.front().at > now) return;

    rotate_token_secret(now);

    // Only the slots already scheduled when this call began: servicing re-arms,
    // and a re-arm landing on "now" is left to the next turn — which the reactor
    // takes at once, since next_timeout_ms() then returns 0.
    size_t budget = due_.size();
    while (budget-- > 0 && !due_.empty() && due_.front().at <= now) {
        const Due slot = due_.front();
        std::pop_heap(due_.begin(), due_.end(), LaterFirst{});
        due_.pop_back();

        const auto it = conns_.find(slot.cid);
        if (it == conns_.end()) continue;   // gone; the slot is litter
        Entry& entry = it->second;
        if (!entry.armed || entry.scheduled != slot.at) continue;   // superseded
        entry.armed = false;

        UdpConnection& conn = *entry.conn;
        conn.tick(now);

        const bool lingering = entry.linger_until != Clock::time_point{};
        if (lingering && !conn.dead() && now >= entry.linger_until) conn.abort(now);
        if (lingering && (conn.dead() || conn.flushed())) {
            conns_.erase(it);
            continue;
        }
        arm(slot.cid, entry);
    }

    compact_due();
    dispatch_pending();
    flush_output();   // one syscall for every connection's repairs and keep-alives
}

void UdpMux::shutdown() {
    const auto now = Clock::now();
    for (auto& entry : conns_) entry.second.conn->abort(now);
    flush_output();   // the goodbyes go out before the connections they came from
    conns_.clear();
    due_.clear();
    pending_events_.clear();
    bursts_.clear();
}

void UdpMux::dispatch_pending() {
    if (pending_events_.empty()) return;
    // Swapped out first: a handler may close its connection, which releases it and
    // can record more events — picked up next time rather than extending this loop.
    auto batch = std::move(pending_events_);
    pending_events_.clear();
    for (const auto& [id, events] : batch) delegate_.dispatch_link_events(id, events);
}

} // namespace librats
