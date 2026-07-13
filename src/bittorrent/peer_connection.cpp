#include "bittorrent/peer_connection.h"
#include "bittorrent/byte_io.h"
#include "bittorrent/log.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace librats::bittorrent {

namespace {

#ifdef _WIN32
inline bool would_block() { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
inline bool would_block() { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

/// Largest message we will accept. A bitfield for ~16M pieces fits; a piece
/// message is ~16 KiB. Anything larger is treated as a protocol violation.
constexpr std::uint32_t kMaxMessageLen = 2 * 1024 * 1024;

constexpr std::size_t kRecvChunk = 64 * 1024;

/// Ceiling on how far rx_ may be grown on the strength of a *declared* message length
/// alone. Sizing the buffer for the whole message up front (as libtorrent does, growing
/// straight to packet_size) turns a large message into one allocation instead of a
/// 1.5x-at-a-time climb. But the length is the peer's word, so past this we fall back
/// to geometric growth and the allocation only ever tracks bytes that really arrived.
/// Comfortably above anything real (a piece is 16 KiB + 9; the largest honest message
/// is a bitfield, ~1 byte per 8 pieces).
constexpr std::size_t kMaxEagerReserve = 1024 * 1024;

/// Send-buffer high-water mark. If a peer stops draining its socket and our
/// unsent backlog blows past this, the peer is a slow consumer — drop it rather
/// than buffer without bound. Matches librats' own kDefaultSendHighWater (8 MiB);
/// far above any single legitimate message (a piece is <=32 KiB, a bitfield for a
/// realistic torrent well under a MiB).
constexpr std::size_t kSendHighWater = 8 * 1024 * 1024;

// ---- connection timeouts (enforced by tick()) ----
/// Drop an incoming peer that hasn't completed the handshake in this long — stops
/// idle half-open sockets from accumulating (a cheap DoS).
constexpr auto kHandshakeTimeout = std::chrono::seconds(30);
/// Drop a connected peer that has sent us nothing for this long.
constexpr auto kIdleTimeout      = std::chrono::seconds(120);
/// Send a keep-alive if we haven't sent anything for this long (kept below a
/// typical peer's ~120 s idle timeout so we don't get dropped).
constexpr auto kKeepAliveInterval = std::chrono::seconds(100);
/// How often tick() runs. Coarse: it only checks the deadlines above.
constexpr auto kTickInterval     = std::chrono::seconds(10);

} // namespace

PeerConnection::PeerConnection(Reactor& reactor, socket_t sock, bool outgoing,
                               const InfoHash& info_hash, const PeerId& our_peer_id,
                               std::uint32_t num_pieces, Observer* observer,
                               std::string remote_ip, std::uint16_t remote_port)
    : reactor_(reactor)
    , sock_(sock)
    , outgoing_(outgoing)
    , info_hash_(info_hash)
    , our_peer_id_(our_peer_id)
    , num_pieces_(num_pieces)
    , obs_(observer)
    , bound_(true)
    , remote_ip_(std::move(remote_ip))
    , remote_port_(remote_port)
    , peer_have_(num_pieces, false) {}

PeerConnection::PeerConnection(Reactor& reactor, socket_t sock, const PeerId& our_peer_id,
                               Resolver resolver, std::string remote_ip, std::uint16_t remote_port)
    : reactor_(reactor)
    , sock_(sock)
    , outgoing_(false)
    , info_hash_{}
    , our_peer_id_(our_peer_id)
    , num_pieces_(0)
    , obs_(nullptr)
    , resolver_(std::move(resolver))
    , bound_(false)
    , remote_ip_(std::move(remote_ip))
    , remote_port_(remote_port) {}

PeerConnection::~PeerConnection() {
    // Cancel the tick before we die so its captured `this` can never fire on freed
    // memory. Same reactor thread owns both the timer and this destructor.
    if (tick_timer_ != kInvalidTimerId) { reactor_.cancel(tick_timer_); tick_timer_ = kInvalidTimerId; }
    if (!closed_ && is_valid_socket(sock_)) {
        reactor_.remove(sock_);
        close_socket(sock_);
        sock_ = INVALID_SOCKET_VALUE;
    }
}

void PeerConnection::start() {
    if (started_) return;
    started_ = true;
    set_socket_nonblocking(sock_);
    reactor_.add(sock_, PollIn, [this](std::uint32_t ev) { on_io(ev); });

    const auto now = std::chrono::steady_clock::now();
    created_ = last_recv_ = last_sent_ = now;
    tick_timer_ = reactor_.schedule(kTickInterval, [this] { tick(); });

    // An outgoing peer sends its handshake immediately; an incoming one waits to
    // learn the info-hash, then replies (see parse_handshake()).
    if (outgoing_) {
        LOG_DEBUG("bt.peer", remote_ip_ << ':' << remote_port_ << " → handshake sent ("
                             << short_hash(info_hash_) << ')');
        send_handshake();
    }
}

void PeerConnection::send_handshake() {
    std::uint8_t hs[kHandshakeSize];
    hs[0] = std::uint8_t(kProtocolStringLen);
    std::memcpy(hs + 1, kProtocolString, kProtocolStringLen);
    ReservedBytes reserved{};
    reserved::enable_dht(reserved);
    // NOTE: we deliberately do NOT advertise the Fast Extension (BEP 6). We do not
    // implement its messages (Have All / Have None / Suggest / Reject / Allowed
    // Fast), and a peer that sees the Fast bit and also supports it would replace
    // its initial `bitfield` with a `Have All` / `Have None` we'd silently ignore —
    // making fast-capable seeds (i.e. most of the modern swarm) look like they hold
    // nothing, so we'd never download from them. Re-enable only once BEP 6 is
    // actually implemented in dispatch().
    reserved::enable_extensions(reserved);
    std::memcpy(hs + 20, reserved.data(), 8);
    std::memcpy(hs + 28, info_hash_.data(), 20);
    std::memcpy(hs + 48, our_peer_id_.data(), 20);
    handshake_sent_ = true;
    queue(ByteView(hs, kHandshakeSize));
    flush();
}

void PeerConnection::close(const std::string& reason) {
    if (closed_) return;
    closed_ = true;
    // Single choke point for every teardown path (protocol error, timeout, slow
    // consumer, remote close, torrent stop): one greppable line per disconnect.
    LOG_DEBUG("bt.peer", remote_ip_ << ':' << remote_port_ << " disconnect: " << reason);
    if (tick_timer_ != kInvalidTimerId) { reactor_.cancel(tick_timer_); tick_timer_ = kInvalidTimerId; }
    if (is_valid_socket(sock_)) {
        reactor_.remove(sock_);
        close_socket(sock_);
        sock_ = INVALID_SOCKET_VALUE;
    }
    // Drop the send backlog; rx_ is deliberately left alone — close() can be called
    // from inside a message handler that still holds a ByteView into it.
    tx_.clear();
    if (obs_) obs_->on_closed(*this, reason);
}

// ---- I/O ----

void PeerConnection::on_io(std::uint32_t events) {
    if (closed_) return;
    if (events & PollOut) flush();
    if (closed_) return;
    if (events & PollIn) do_read();
    if (closed_) return;
    if (events & (PollErr | PollHup)) close("socket error");
}

void PeerConnection::do_read() {
    // Drain the kernel buffer, parsing after every read. Parsing inside the loop
    // (rather than once the socket is empty) is what bounds rx_ to a single in-flight
    // message — otherwise a seed pushing pieces at line rate would grow it to
    // however much it managed to deliver before we caught up.
    //
    // The loop must run to would-block or to a short read (kernel buffer now empty):
    // the kqueue backend is edge-triggered, so leaving unread data behind would stall
    // the connection until the peer happens to send more.
    for (;;) {
        const ByteSpan into = rx_.prepare(read_size());

        const int n = ::recv(sock_, reinterpret_cast<char*>(into.data()),
                             static_cast<int>(into.size()), 0);
        if (n == 0) { close("peer closed connection"); return; }
        if (n < 0) {
            if (would_block()) return;
            close("recv error");
            return;
        }

        last_recv_ = std::chrono::steady_clock::now();
        rx_.commit(std::size_t(n));

        parse();
        if (closed_) return;

        if (std::size_t(n) < into.size()) return;  // kernel buffer drained
    }
}

std::size_t PeerConnection::read_size() const {
    // Ask for the rest of the message we are mid-way through, so a big one (a bitfield,
    // a metadata piece) lands in a single allocation rather than a series of 1.5x growth
    // steps that memmove everything received so far at each one. Bounded by
    // kMaxEagerReserve — rx_need_ is a length the *peer* declared.
    //
    // Note this asks for the remainder even when it is *smaller* than kRecvChunk. It is
    // tempting to floor it at kRecvChunk ("read as much as we can anyway"), but
    // prepare(n) is a demand for n bytes of free tail, and a buffer sized exactly for
    // the message has no kRecvChunk of tail left near the end of it — so the floor would
    // force one last 1.5x grow (memcpy'ing the whole message that already arrived) for
    // room the message does not need. Nothing is lost by asking for less: prepare()
    // hands back the *entire* free tail regardless, so the recv() is just as big.
    if (rx_need_ > rx_.size()) return (std::min)(rx_need_ - rx_.size(), kMaxEagerReserve);
    return kRecvChunk;
}

void PeerConnection::parse() {
    rx_need_ = 0;  // recomputed below: 0 == no message is mid-flight

    if (!handshake_received_) {
        if (rx_.size() < kHandshakeSize) { rx_need_ = kHandshakeSize; return; }
        if (!parse_handshake()) return;  // consumed 68 bytes (or closed)
    }

    while (!closed_ && rx_.size() >= 4) {
        const std::uint32_t len = read_u32_be(rx_.data());
        if (len > kMaxMessageLen) { close("oversize message"); return; }
        if (rx_.size() < std::size_t(4) + len) {
            rx_need_ = std::size_t(4) + len;  // size rx_ for the whole message
            break;
        }
        if (len == 0) { rx_.consume(4); continue; }     // keep-alive

        const std::uint8_t  id      = rx_.data()[4];
        const std::uint8_t* payload = rx_.data() + 5;
        const std::uint32_t plen    = len - 1;
        dispatch(MessageId(id), payload, plen);
        if (closed_) return;
        rx_.consume(std::size_t(4) + len);
    }
}

bool PeerConnection::parse_handshake() {
    const std::uint8_t* d = rx_.data();
    if (d[0] != kProtocolStringLen || std::memcmp(d + 1, kProtocolString, kProtocolStringLen) != 0) {
        close("bad protocol header");
        return false;
    }
    std::memcpy(peer_reserved_.data(), d + 20, 8);

    InfoHash their_info{};
    std::memcpy(their_info.data(), d + 28, 20);

    if (bound_) {
        // Outgoing: the info-hash must be the one we dialed for.
        if (their_info != info_hash_) { close("info-hash mismatch"); return false; }
    } else {
        // Incoming: resolve which torrent this is for and late-bind to it.
        Binding b;
        if (!resolver_ || !resolver_(their_info, b) || !b.observer) {
            close("unknown torrent");
            return false;
        }
        info_hash_  = their_info;
        obs_        = b.observer;
        num_pieces_ = b.num_pieces;
        peer_have_  = Bitfield(num_pieces_, false);
        bound_      = true;
    }

    std::memcpy(peer_id_.data(), d + 48, 20);
    rx_.consume(kHandshakeSize);
    handshake_received_ = true;

    // An incoming connection now knows which torrent it is for and replies.
    if (!outgoing_ && !handshake_sent_) send_handshake();

    LOG_DEBUG("bt.peer", remote_ip_ << ':' << remote_port_ << " ← handshake "
                         << identify_client(peer_id_) << " (" << short_hash(info_hash_) << ')');
    if (obs_) obs_->on_handshake(*this, info_hash_, peer_id_);
    return true;
}

void PeerConnection::dispatch(MessageId id, const std::uint8_t* payload, std::uint32_t len) {
    auto bad = [&] { close("malformed message"); };

    switch (id) {
        case MessageId::Choke:
            if (len != 0) return bad();
            peer_choking_ = true;
            if (obs_) obs_->on_choke(*this, true);
            break;
        case MessageId::Unchoke:
            if (len != 0) return bad();
            peer_choking_ = false;
            if (obs_) obs_->on_choke(*this, false);
            break;
        case MessageId::Interested:
            if (len != 0) return bad();
            peer_interested_ = true;
            if (obs_) obs_->on_interest(*this, true);
            break;
        case MessageId::NotInterested:
            if (len != 0) return bad();
            peer_interested_ = false;
            if (obs_) obs_->on_interest(*this, false);
            break;
        case MessageId::Have: {
            if (len != 4) return bad();
            piece_state_begun_ = true;  // a HAVE begins the piece-state flow; a later bitfield is invalid
            const std::uint32_t piece = read_u32_be(payload);
            // Only act on a HAVE that actually flips a bit. A redundant HAVE (a piece
            // the peer already advertised, via bitfield or an earlier HAVE) is legal on
            // the wire, but re-notifying the observer would inc availability a second
            // time in the picker while disconnect only decrements once per set bit —
            // leaving the count permanently skewed and corrupting rarest-first. An
            // out-of-range index simply flips nothing and is ignored.
            if (piece < peer_have_.size() && !peer_have_.get(piece)) {
                peer_have_.set(piece);
                if (obs_) obs_->on_have(*this, piece);
            }
            break;
        }
        case MessageId::Bitfield: {
            // BEP 3: a bitfield is valid only as the peer's first piece-state
            // message. A second bitfield (or one after any HAVE) would re-add the
            // peer's whole availability in the picker with no matching decrement —
            // a permanent skew. And when we know the piece count, the payload must
            // be exactly ceil(num_pieces/8) bytes. Reject either as a violation.
            if (piece_state_begun_) return bad();
            if (num_pieces_ != 0 && len != (num_pieces_ + 7) / 8) return bad();
            piece_state_begun_ = true;
            const std::uint32_t bits = num_pieces_ ? num_pieces_ : len * 8;
            peer_have_.assign(payload, len, bits);
            if (obs_) obs_->on_bitfield(*this, peer_have_);
            break;
        }
        case MessageId::Request: {
            if (len != 12) return bad();
            if (obs_) obs_->on_request(*this, read_u32_be(payload), read_u32_be(payload + 4),
                                       read_u32_be(payload + 8));
            break;
        }
        case MessageId::Piece: {
            if (len < 8) return bad();
            if (obs_) obs_->on_piece(*this, read_u32_be(payload), read_u32_be(payload + 4),
                                     ByteView(payload + 8, len - 8));
            break;
        }
        case MessageId::Cancel: {
            if (len != 12) return bad();
            if (obs_) obs_->on_cancel(*this, read_u32_be(payload), read_u32_be(payload + 4),
                                      read_u32_be(payload + 8));
            break;
        }
        case MessageId::Port:
            if (len != 2) return bad();
            if (obs_) obs_->on_port(*this, read_u16_be(payload));
            break;
        case MessageId::Extended:
            if (len < 1) return bad();
            if (obs_) obs_->on_extended(*this, payload[0], ByteView(payload + 1, len - 1));
            break;
        default:
            break;  // unknown id — ignore for forward compatibility
    }
}

// ---- send ----

void PeerConnection::send_message(MessageId id, const std::uint8_t* payload, std::uint32_t len) {
    std::uint8_t header[5];
    write_u32_be(header, len + 1);
    header[4] = std::uint8_t(id);
    queue(ByteView(header, 5));
    if (len) queue(ByteView(payload, len));
    flush();
}

void PeerConnection::send_keepalive() {
    const std::uint8_t z[4] = {0, 0, 0, 0};
    queue(ByteView(z, 4));
    flush();
}
void PeerConnection::send_choke()         { am_choking_ = true;    send_message(MessageId::Choke, nullptr, 0); }
void PeerConnection::send_unchoke()       { am_choking_ = false;   send_message(MessageId::Unchoke, nullptr, 0); }
void PeerConnection::send_interested()    { am_interested_ = true; send_message(MessageId::Interested, nullptr, 0); }
void PeerConnection::send_not_interested(){ am_interested_ = false;send_message(MessageId::NotInterested, nullptr, 0); }

void PeerConnection::send_have(std::uint32_t piece) {
    std::uint8_t p[4];
    write_u32_be(p, piece);
    send_message(MessageId::Have, p, 4);
}

void PeerConnection::send_bitfield(const Bitfield& bitfield) {
    send_message(MessageId::Bitfield, bitfield.data(), std::uint32_t(bitfield.data_size()));
}

void PeerConnection::send_request(std::uint32_t piece, std::uint32_t offset, std::uint32_t length) {
    std::uint8_t p[12];
    write_u32_be(p, piece);
    write_u32_be(p + 4, offset);
    write_u32_be(p + 8, length);
    send_message(MessageId::Request, p, 12);
}

void PeerConnection::send_piece(std::uint32_t piece, std::uint32_t offset, Bytes data) {
    // The 13-byte header packs into the send queue's scratch chunk; the block is moved
    // in as its own chunk, so the buffer the disk read filled is never copied. Gather
    // I/O reunites the two, so this is still one send().
    std::uint8_t header[13];
    write_u32_be(header, std::uint32_t(9 + data.size()));
    header[4] = std::uint8_t(MessageId::Piece);
    write_u32_be(header + 5, piece);
    write_u32_be(header + 9, offset);
    queue(ByteView(header, sizeof(header)));
    if (!data.empty()) queue(std::move(data));
    flush();
}

void PeerConnection::send_cancel(std::uint32_t piece, std::uint32_t offset, std::uint32_t length) {
    std::uint8_t p[12];
    write_u32_be(p, piece);
    write_u32_be(p + 4, offset);
    write_u32_be(p + 8, length);
    send_message(MessageId::Cancel, p, 12);
}

void PeerConnection::send_port(std::uint16_t port) {
    std::uint8_t p[2];
    write_u16_be(p, port);
    send_message(MessageId::Port, p, 2);
}

void PeerConnection::send_extended(std::uint8_t ext_id, ByteView payload) {
    std::uint8_t header[6];
    write_u32_be(header, std::uint32_t(2 + payload.size()));
    header[4] = std::uint8_t(MessageId::Extended);
    header[5] = ext_id;
    queue(ByteView(header, sizeof(header)));
    if (!payload.empty()) queue(payload);
    flush();
}

void PeerConnection::flush() {
    if (closed_) return;

    while (!tx_.empty()) {
        // One syscall for the whole backlog, however many chunks it spans.
        ByteView slices[kMaxSendSlices];
        const std::size_t count = tx_.gather(slices, kMaxSendSlices);

        const std::ptrdiff_t n = send_vectored(sock_, slices, count);
        if (n > 0) {
            last_sent_ = std::chrono::steady_clock::now();
            tx_.pop_front(std::size_t(n));
            continue;
        }
        if (n == 0) break;                 // nothing accepted; retry on PollOut
        if (would_block()) break;          // congested; the backlog waits for PollOut
        close("send error");
        return;
    }

    want_write(!tx_.empty());

    // Backpressure: allocated() is the memory the queue actually holds (a partially
    // sent chunk keeps its whole allocation). Past the high-water mark the peer isn't
    // draining us — drop it rather than buffer without bound.
    if (tx_.allocated() > kSendHighWater) close("slow consumer: send buffer overflow");
}

void PeerConnection::want_write(bool on) {
    if (on == want_write_ || closed_) return;
    want_write_ = on;
    reactor_.modify(sock_, PollIn | (on ? PollOut : PollNone));
}

void PeerConnection::tick() {
    if (closed_) return;
    const auto now = std::chrono::steady_clock::now();

    if (!handshake_done()) {
        // A peer that connects but never completes the handshake is dropped so it
        // can't occupy a socket indefinitely.
        if (now - created_ > kHandshakeTimeout) { close("handshake timeout"); return; }
    } else {
        if (now - last_recv_ > kIdleTimeout) { close("idle timeout"); return; }
        // Keep the link alive if we've been quiet, so the peer doesn't drop us.
        if (now - last_sent_ > kKeepAliveInterval) send_keepalive();  // updates last_sent_ via flush
    }

    if (closed_) return;  // send_keepalive() may have hit a send error and closed us

    // Hand back the receive buffer of a peer that has gone quiet. Without this a peer
    // that sent one big message (a bitfield, a metadata piece) and then went idle would
    // sit on that allocation for as long as the connection lives — the traffic-driven
    // shrink in ReceiveBuffer only ever samples when a message actually arrives.
    rx_.decay();

    tick_timer_ = reactor_.schedule(kTickInterval, [this] { tick(); });
}

} // namespace librats::bittorrent
