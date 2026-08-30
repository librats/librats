#include "librats/bittorrent/utp_manager.h"

#include "librats/bittorrent/log.h"

#include <algorithm>
#include <random>

namespace librats::bittorrent::utp {

namespace {

std::uint16_t random_id() {
    static thread_local std::mt19937 rng{std::random_device{}()};
    // Leave room for the +1: the pair must not straddle the wrap, or the two ids
    // would not be adjacent in the arithmetic every peer uses to derive them.
    return std::uint16_t(std::uniform_int_distribution<std::uint32_t>(1, 0xfffd)(rng));
}

/// Datagrams read per readable event before we go back to the poller. Without a
/// bound, a peer able to fill the socket faster than we drain it would keep the
/// loop here indefinitely and starve every other connection and timer.
constexpr int kMaxRecvPerWakeup = 256;

} // namespace

Manager::Manager(Reactor& reactor) : reactor_(reactor) {}

Manager::~Manager() {
    close();
}

bool Manager::open(std::uint16_t port, const std::string& bind_address) {
    if (is_open()) return true;
    socket_ = create_udp_socket(int(port), bind_address, AddressFamily::IPv4);
    if (!is_valid_socket(socket_)) return false;
    set_socket_nonblocking(socket_);
    port_ = std::uint16_t(get_bound_port(socket_));
    if (!reactor_.add(socket_, PollIn, [this](std::uint32_t) { on_readable(); })) {
        close_socket(socket_);
        socket_ = RATS_INVALID_SOCKET;
        port_   = 0;
        return false;
    }
    tick_timer_ = reactor_.schedule(kTickInterval, [this] { tick(); });
    LOG_INFO("bt.utp", "uTP listening on UDP port " << port_);
    return true;
}

void Manager::close() {
    if (tick_timer_ != kInvalidTimerId) {
        reactor_.cancel(tick_timer_);
        tick_timer_ = kInvalidTimerId;
    }
    if (is_valid_socket(socket_)) {
        reactor_.remove(socket_);
        close_socket(socket_);
        socket_ = RATS_INVALID_SOCKET;
    }
    port_ = 0;
    deferred_.clear();
    streams_.clear();
}

// ---- Host --------------------------------------------------------------------

void Manager::utp_send(const Address& to, const std::uint8_t* data, std::size_t len) {
    if (!is_valid_socket(socket_)) return;
    // A datagram that will not fit in the socket's send buffer is simply dropped:
    // that is exactly what a congested link does to it a hop later, and the stream's
    // retransmission timer is already the recovery path for it.
    send_udp_to(socket_, data, len, to, AddressFamily::IPv4);
}

void Manager::utp_defer_ack(Stream& s) {
    deferred_.push_back(&s);
}

// ---- Streams -----------------------------------------------------------------

Stream* Manager::find(const Address& from, std::uint16_t id) {
    auto range = streams_.equal_range(id);
    for (auto it = range.first; it != range.second; ++it) {
        if (it->second->matches(from, id)) return it->second.get();
    }
    return nullptr;
}

Stream* Manager::connect(const Address& to) {
    if (!is_open() || streams_.size() >= kMaxStreams) return nullptr;

    // The initiator picks the id it will *receive* on and derives the send id from
    // it. Retry a few times so two live connections to the same peer cannot collide
    // on an id — the pair (id, endpoint) is what identifies a stream.
    std::uint16_t recv_id = 0;
    for (int attempt = 0; attempt < 8; ++attempt) {
        recv_id = random_id();
        if (find(to, recv_id) == nullptr) break;
        recv_id = 0;
    }
    if (recv_id == 0) return nullptr;

    auto    s   = std::make_unique<Stream>(*this, recv_id, std::uint16_t(recv_id + 1));
    Stream* raw = s.get();
    streams_.emplace(recv_id, std::move(s));
    raw->connect(to, Stream::Clock::now());
    return raw;
}

void Manager::release(Stream& s) {
    s.detach();
    s.close(Stream::Clock::now());
    // Not erased here: close() may still owe the peer a FIN, and we may be inside
    // an iteration over streams_ right now. reap() collects it once it is done.
}

// ---- I/O ---------------------------------------------------------------------

void Manager::on_readable() {
    std::uint8_t buf[kMaxRecvDatagram];
    const auto   now = Stream::Clock::now();

    for (int i = 0; i < kMaxRecvPerWakeup; ++i) {
        Address              from;
        const std::ptrdiff_t n = recv_udp_from(socket_, buf, sizeof(buf), from);
        if (n == kUdpRecvWouldBlock) break;
        // kUdpRecvError covers an ICMP unreachable for some *other* destination,
        // reported against the shared socket. It says nothing about this socket, so
        // keep draining rather than dropping every peer over one dead address.
        if (n == kUdpRecvError) continue;
        if (n < std::ptrdiff_t(kHeaderSize)) continue;
        handle_datagram(buf, std::size_t(n), from, now);
    }

    flush_deferred_acks(now);
    reap(now);
}

void Manager::handle_datagram(const std::uint8_t* data, std::size_t len, const Address& from,
                              Stream::Clock::time_point now) {
    Header h;
    if (!parse_header(data, len, h)) return;

    if (Stream* s = find(from, h.connection_id); s != nullptr) {
        s->on_packet(data, len, from, now);
        return;
    }

    // Nothing is registered under that id. Only a SYN may create a stream; anything
    // else names a connection that no longer exists. We answer with silence rather
    // than a reset: the sender is unauthenticated, and a reset would make this
    // socket a reflector that answers every spoofed datagram with one of its own.
    if (h.type != PacketType::Syn) return;

    // A retransmitted SYN — the answer to the first one was lost. The stream it
    // created is registered under id + 1, which is not the id the SYN carries, so
    // it has to be looked up explicitly. Without this a peer whose SYN-ack went
    // missing would leave a duplicate stream behind on every retry.
    if (Stream* s = find(from, std::uint16_t(h.connection_id + 1)); s != nullptr) {
        s->on_packet(data, len, from, now);
        return;
    }

    if (!accept_incoming_ || streams_.size() >= kMaxStreams) return;

    const std::uint16_t send_id = h.connection_id;
    const std::uint16_t recv_id = std::uint16_t(h.connection_id + 1);
    auto                s       = std::make_unique<Stream>(*this, recv_id, send_id);
    Stream*             raw     = s.get();
    streams_.emplace(recv_id, std::move(s));

    if (!raw->on_packet(data, len, from, now)) {
        // The SYN did not survive the stream's own checks; drop the stream again
        // rather than leave an unusable one behind.
        raw->reset(now);
        return;
    }
    LOG_DEBUG("bt.utp", "inbound uTP stream from " << from.to_string()
                        << " (id " << recv_id << ')');
    if (accept_) accept_(*raw);

    // The handler takes ownership by installing an observer. If it declined — the
    // session-wide connection cap, or no handler at all — the stream would otherwise
    // sit here connected and unreaped forever, since nothing would ever close it.
    // Tell the peer rather than let it retransmit into a stream nobody is reading.
    if (!raw->has_observer()) raw->reset(now);
}

void Manager::flush_deferred_acks(Stream::Clock::time_point now) {
    if (deferred_.empty()) return;
    // A stream may have registered more than once during the drain; the second
    // flush is a no-op because send_deferred_ack() clears the flag.
    for (Stream* s : deferred_) s->send_deferred_ack(now);
    deferred_.clear();
}

void Manager::tick() {
    const auto now = Stream::Clock::now();

    // Snapshot first: a stream's timeout fires its observer, which may close a
    // PeerConnection and release streams back to us mid-iteration.
    scratch_.clear();
    scratch_.reserve(streams_.size());
    for (auto& [id, s] : streams_) scratch_.push_back(s.get());
    for (Stream* s : scratch_) s->tick(now);
    scratch_.clear();

    flush_deferred_acks(now);
    reap(now);

    tick_timer_ = reactor_.schedule(kTickInterval, [this] { tick(); });
}

void Manager::reap(Stream::Clock::time_point now) {
    for (auto it = streams_.begin(); it != streams_.end();) {
        // A stream that still has an observer belongs to a live PeerConnection and
        // is that connection's to end, however dead it looks from here.
        if (!it->second->has_observer() && it->second->reapable(now)) {
            it = streams_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace librats::bittorrent::utp
