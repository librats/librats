#include "transport/connection.h"
#include "transport/reactor.h"
#include "core/io_poller.h"
#include "util/logger.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace librats {

namespace {

constexpr size_t kRecvChunk = 16 * 1024;  ///< bytes offered to each recv()

/// Ceiling on how far rx_ may be grown on the strength of a *declared* block length
/// alone. Sizing the buffer for the whole block up front (as libtorrent does, growing
/// straight to packet_size) turns a large frame into one allocation instead of a
/// 1.5x-at-a-time climb that memmoves everything received so far at every step. But
/// the length is the peer's word: a 4-byte prefix claiming kMaxBlockSize must not
/// make us allocate 64 MiB for a peer that then sends nothing. Past this, growth
/// falls back to geometric, so the allocation only ever tracks bytes that really
/// arrived — a big block still costs a handful of reallocations, not tens.
constexpr size_t kMaxEagerReserve = 1024 * 1024;

/// Frames up to this size are copied into the send queue rather than moved into a
/// chunk of their own (see queue_block). Matches the queue's scratch chunk, so a
/// small frame and its length prefix land in the same allocation.
constexpr size_t kInlineBlockLimit = ChainedSendBuffer::kScratchCapacity;

#ifdef _WIN32
inline bool last_error_would_block() { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
inline bool last_error_would_block() { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

} // namespace

Connection::Connection(ConnId id, socket_t sock, ConnRole role,
                       Reactor& reactor, ConnectionDelegate& delegate)
    : id_(id), socket_(sock), role_(role), reactor_(reactor), delegate_(delegate) {}

Connection::~Connection() = default;

IpAddress Connection::remote_ip() const {
    // The peer's source IP, straight from getpeername() with no textual round-trip.
    // (The source port is ephemeral and not useful here, so it's discarded.)
    const auto ep = get_peer_endpoint(socket_);
    return ep ? ep->ip : IpAddress{};
}

uint8_t Connection::reactor_index() const noexcept { return reactor_.index(); }

// ── Outbound application frames ─────────────────────────────────────────────

void Connection::send(FrameHeader header, ByteView payload) {
    if (state_ != ConnState::Established) return;  // frames only flow post-handshake

    Bytes inner;
    framer::encode_message(inner, header, payload);

    Bytes cipher;
    if (!session_->encrypt(inner, cipher)) {
        LOG_ERROR("connection", "Peer " << remote_id_.short_hex() << " encrypt failed");
        reactor_.close(id_, CloseReason::ProtocolError);
        return;
    }

    queue_block(std::move(cipher));

    // Watch the memory the queue actually holds, not just the bytes still owed to the
    // socket: a partially sent chunk keeps its whole allocation, so allocated() is
    // what a peer that stops reading can make us carry.
    if (tx_.allocated() > send_high_water_) {
        LOG_WARN("connection", "Peer " << remote_id_.short_hex() << " over send high-water ("
                 << tx_.allocated() << " B); closing as slow consumer");
        close_reason_ = CloseReason::SlowConsumer;
        state_ = ConnState::Closing;
        reactor_.close(id_, CloseReason::SlowConsumer);
        return;
    }
    // Write-through: try to send now rather than waiting for a PollOut event.
    if (!flush()) reactor_.close(id_, close_reason_);
}

void Connection::queue_block(Bytes body) {
    // The length prefix is queued as its own slice instead of being spliced in front
    // of `body` — gather I/O reunites them in one writev, so framing costs no copy.
    uint8_t prefix[framer::kLengthPrefixSize];
    framer::encode_block_header(prefix, body.size());
    tx_.append(ByteView(prefix, sizeof(prefix)));

    // Small frame: copy it in, so prefix and body share one packed chunk. A memcpy of
    // a few hundred bytes is cheaper than the allocation it saves — and it keeps a
    // backlog of small frames from costing a chunk each.
    // Large frame: move it, so a megabyte-sized payload is never copied to be framed.
    if (body.size() <= kInlineBlockLimit) tx_.append(ByteView(body));
    else                                  tx_.append(std::move(body));
}

// ── Handshake lifecycle ─────────────────────────────────────────────────────

void Connection::start_handshake() {
    if (state_ == ConnState::Connecting) begin_handshake();
}

void Connection::begin_handshake() {
    state_ = ConnState::Handshaking;
    want_write_ = false;
    reactor_.set_interest(socket_, PollIn);

    handshaker_ = reactor_.security().create(role_);
    Bytes out;
    if (!handshaker_->start(out)) {
        reactor_.close(id_, CloseReason::HandshakeFailed);
        return;
    }
    if (!out.empty()) {
        queue_block(std::move(out));   // initiator's first message
        if (!flush()) { reactor_.close(id_, close_reason_); return; }
    }
}

bool Connection::drive_handshake(ByteView body) {
    Bytes out;
    auto outcome = handshaker_->consume(body, out);
    if (outcome.status == Handshaker::Outcome::Failed) {
        return fail(CloseReason::HandshakeFailed);
    }
    if (!out.empty()) {
        queue_block(std::move(out));   // reply (responder's message, or initiator's final)
        if (!flush()) return false;
    }
    if (outcome.status == Handshaker::Outcome::Done) {
        session_   = std::move(outcome.session);
        remote_id_ = outcome.remote_id;
        handshaker_.reset();
        complete_established();
    }
    return true;
}

void Connection::cancel_establish_timer() {
    if (establish_timer_ != kInvalidTimerId) {
        reactor_.cancel(establish_timer_);
        establish_timer_ = kInvalidTimerId;
    }
}

void Connection::complete_established() {
    state_ = ConnState::Established;
    cancel_establish_timer();
    LOG_DEBUG("connection", "Peer " << remote_id_.short_hex() << " established ("
              << (role_ == ConnRole::Inbound ? "inbound" : "outbound")
              << (is_secure() ? ", encrypted)" : ", plaintext)"));
    delegate_.on_established(*this);
}

// ── Inbound ─────────────────────────────────────────────────────────────────

bool Connection::on_readable() {
    // Drain the kernel buffer (the socket is non-blocking), parsing as we go. The
    // parse step is inside the loop on purpose: it keeps rx_ down to one in-flight
    // block no matter how fast the peer sends, where draining first and parsing
    // afterwards would let rx_ grow to everything the peer managed to deliver.
    //
    // We must drain to would-block (or to a short read, which means the kernel
    // buffer is now empty) — the kqueue backend is edge-triggered, so stopping with
    // data still queued would leave the connection stalled until the *next* byte.
    while (true) {
        const ByteSpan into = rx_.prepare(read_size());

        const int n = ::recv(socket_, reinterpret_cast<char*>(into.data()),
                             static_cast<int>(into.size()), 0);
        if (n == 0) {
            if (!process_blocks()) return false;  // deliver what the peer sent before FIN
            return fail(CloseReason::PeerClosed);
        }
        if (n < 0) {
            if (last_error_would_block()) break;
            return fail(CloseReason::PeerReset);
        }

        rx_.commit(static_cast<size_t>(n));
        if (!process_blocks()) return false;

        if (static_cast<size_t>(n) < into.size()) break;  // kernel buffer drained
    }
    return true;
}

size_t Connection::read_size() const {
    // Not established yet: the peer is still anonymous, so its declared length buys it
    // nothing. A handshake block is a Noise message plus the protocol id — hundreds of
    // bytes — so there is no large allocation to save here, while honouring the length
    // would let four bytes from an unauthenticated socket reserve kMaxEagerReserve. rx_
    // still grows geometrically to hold whatever actually arrives, so an unusually large
    // handshake block is served just as correctly, only without the eager reserve.
    if (state_ != ConnState::Established) return kRecvChunk;

    // Ask for the rest of the block we are mid-way through, so a large frame lands in
    // one allocation rather than a series of 1.5x growth steps. Bounded by
    // kMaxEagerReserve, since rx_need_ is a length the *peer* declared.
    //
    // Note this asks for the remainder even when it is *smaller* than kRecvChunk. It
    // is tempting to floor it at kRecvChunk ("read as much as we can anyway"), but
    // prepare(n) is a demand for n bytes of free tail, and a buffer sized exactly for
    // the block has no kRecvChunk of tail left near the end of it — so the floor would
    // force one last 1.5x grow (memcpy'ing the whole block that already arrived) for
    // room that the block does not need. Nothing is lost by asking for less: prepare()
    // hands back the *entire* free tail regardless, so the recv() is just as big.
    if (rx_need_ > rx_.size()) return (std::min)(rx_need_ - rx_.size(), kMaxEagerReserve);
    return kRecvChunk;
}

bool Connection::process_blocks() {
    rx_need_ = 0;  // recomputed below: 0 == no block is mid-flight

    // Body views point into rx_, so each block must be consumed before the next is
    // decoded (and before any recv() reallocates the buffer under us).
    while (!rx_.empty()) {
        const auto block = framer::try_take_block(rx_.data(), rx_.size());
        if (block.status == framer::Block::Incomplete) {
            rx_need_ = block.needed;  // 0 while even the length prefix is short
            break;
        }
        if (block.status == framer::Block::Error) return fail(CloseReason::ProtocolError);

        const bool keep = (state_ == ConnState::Handshaking) ? drive_handshake(block.body)
                                                             : deliver_frame(block.body);
        rx_.consume(block.consumed);
        if (!keep) return false;
        if (state_ == ConnState::Closing || state_ == ConnState::Closed) return false;
    }
    return true;
}

bool Connection::deliver_frame(ByteView body) {
    if (!session_) return fail(CloseReason::ProtocolError);  // data before handshake

    Bytes plain;
    if (!session_->decrypt(body, plain)) return fail(CloseReason::ProtocolError);

    auto msg = framer::parse_message(plain);
    if (!msg.ok) return fail(CloseReason::ProtocolError);

    delegate_.on_frame(*this, msg.frame);
    return true;
}

bool Connection::on_writable() {
    // Finish a non-blocking connect, then begin the handshake.
    if (state_ == ConnState::Connecting) {
        int err = tcp_connect_result(socket_);
        if (err != 0) {
            LOG_DEBUG("connection", "Peer " << id_ << " connect failed (err " << err << ")");
            return fail(CloseReason::ConnectFailed);
        }
        begin_handshake();
        if (state_ == ConnState::Closing) return false;
    }
    return flush();
}

bool Connection::on_error() {
    return fail(CloseReason::PeerReset);
}

// ── Send buffer flush + write interest ──────────────────────────────────────

bool Connection::flush() {
    while (!tx_.empty()) {
        // Hand the whole backlog to the kernel at once: a burst of queued frames
        // (and the length prefix that precedes each one) leaves in a single syscall
        // instead of one per chunk.
        ByteView slices[kMaxSendSlices];
        const size_t count = tx_.gather(slices, kMaxSendSlices);

        const std::ptrdiff_t n = send_vectored(socket_, slices, count);
        if (n > 0) { tx_.pop_front(static_cast<size_t>(n)); continue; }
        if (n == 0) break;  // nothing accepted; try again on the next writable event
        if (last_error_would_block()) break;
        return fail(CloseReason::PeerReset);
    }

    if (tx_.empty()) disarm_write();
    else             arm_write();
    return true;
}

void Connection::arm_write() {
    if (want_write_) return;
    want_write_ = true;
    reactor_.set_interest(socket_, PollIn | PollOut);
}

void Connection::disarm_write() {
    if (!want_write_) return;
    want_write_ = false;
    reactor_.set_interest(socket_, PollIn);
}

bool Connection::fail(CloseReason reason) {
    close_reason_ = reason;
    state_ = ConnState::Closing;
    return false;  // tells the reactor to tear this connection down
}

} // namespace librats
