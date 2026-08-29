#include "librats/transport/connection.h"
#include "librats/transport/reactor.h"
#include "librats/core/io_poller.h"
#include "librats/util/logger.h"

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

} // namespace

Connection::Connection(ConnId id, std::unique_ptr<Link> link, ConnRole role,
                       Reactor& reactor, ConnectionDelegate& delegate)
    : id_(id), link_(std::move(link)), role_(role), reactor_(reactor), delegate_(delegate) {}

Connection::~Connection() = default;

IpAddress Connection::remote_ip() const {
    // The peer's source IP as the transport sees it, with no textual round-trip.
    // (The source port is not dialable — ephemeral on TCP, NAT-rewritten on UDP —
    // so it is discarded; identify supplies the real listen port.)
    const auto ep = link_->remote_endpoint();
    return ep ? ep->ip : IpAddress{};
}

uint8_t Connection::reactor_index() const noexcept { return reactor_.index(); }

// ── Outbound application frames ─────────────────────────────────────────────

bool Connection::send(FrameHeader header, ByteView payload) {
    if (state_ != ConnState::Established) return false;  // frames only flow post-handshake

    // The one thing that is refused outright rather than queued: a message too
    // large to be framed at all. The block prefix tops out at kMaxBlockSize and the
    // peer's decoder rejects anything past it, so queueing this would spend the
    // link only to have the far end hang up on a protocol error it was handed on
    // purpose. Waiting cannot help either — no amount of draining makes it fit — so
    // the honest answer is a refusal, with the frame unqueued and the connection
    // untouched. Checked before encrypt() because the nonce counters run in
    // lockstep: a message encrypted and then dropped would break every one after.
    if (framer::kHeaderSize + payload.size() + session_->overhead() > framer::kMaxBlockSize) {
        LOG_WARN("connection", "Peer " << remote_id_.short_hex() << " refused a "
                 << payload.size() << " B message: past the " << framer::kMaxBlockSize
                 << " B block ceiling; split it");
        return false;
    }

    // Weighed on the backlog as it stands BEFORE this message, never after it has
    // been added. A message is indivisible — there is no queueing half of one — so
    // judging a caller by the mark its own message has just crossed answers "that
    // message was bigger than a limit nobody published" with a disconnection, on a
    // connection that is idle, healthy and draining at full speed. What the mark is
    // for is a peer that cannot keep up, and the evidence for that is a caller
    // piling MORE on top of a backlog that is already over it.
    //
    // So one message may always be queued, whatever its size — the queue may exceed
    // the mark by exactly that message and no more — and offering another before it
    // has drained is what makes a caller a slow consumer. Nothing is ever dropped
    // or refused here, which is what the layers above rely on: a relayed circuit
    // (transport/relay_link.cpp) reports bytes as written the moment it hands them
    // over, and a byte stream cannot survive one of them going missing.
    const size_t backlog_before = backlog();
    if (backlog_before > send_high_water_) {
        LOG_WARN("connection", "Peer " << remote_id_.short_hex() << " offered more with "
                 << backlog_before << " B still queued past the high-water mark ("
                 << send_high_water_ << " B); closing as slow consumer");
        close_reason_ = CloseReason::SlowConsumer;
        state_ = ConnState::Closing;
        reactor_.close(id_, CloseReason::SlowConsumer);
        return false;
    }

    Bytes inner;
    framer::encode_message(inner, header, payload);

    Bytes cipher;
    if (!session_->encrypt(inner, cipher)) {
        LOG_ERROR("connection", "Peer " << remote_id_.short_hex() << " encrypt failed");
        reactor_.close(id_, CloseReason::ProtocolError);
        return false;
    }

    queue_block(std::move(cipher));

    const size_t backlog_now = backlog();

    // The queue has grown past what a caller should keep adding to. Everything
    // still goes out — nothing is dropped here — but the answer to "may I send
    // more?" becomes no, and stays no until the queue drains back under the mark
    // and on_writable says so. Without this an application has no way at all to
    // tell that it is outrunning the link, and the only thing that eventually
    // tells it is the disconnection above.
    if (!over_low_water_ && backlog_now > send_low_water_) {
        over_low_water_ = true;
        delegate_.on_writable_changed(*this, false);
    }

    // Aggregate rather than write through. Several frames produced in one batch
    // of reactor tasks belong in ONE write, and flushing on each of them costs a
    // system call per frame — measured at roughly ten times the throughput on
    // small messages, on both transports. The flush happens at the end of the
    // reactor turn (Reactor::flush_dirty), which is still the same turn: nothing
    // waits on a timer and no latency is added.
    //
    // Past a point, though, waiting buys nothing: a backlog this size already
    // fills a write, and letting it grow further would only hold memory and
    // delay the bytes. So a large queue goes out at once, exactly as before.
    if (tx_.size() >= kCoalesceLimit) {
        if (!flush()) reactor_.close(id_, close_reason_);
    } else if (!flush_queued_) {
        flush_queued_ = true;
        reactor_.mark_dirty(id_);
    }
    return !over_low_water_;
}

bool Connection::flush_pending() {
    flush_queued_ = false;
    return flush();
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
    // The transport is up, so the write-interest raised for the connect itself is
    // no longer wanted; flush() re-arms it if the handshake outgrows the link.
    want_write_ = false;
    link_->want_write(false);

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

        const Link::IoResult r = link_->read(into);
        if (r.status == Link::Status::Closed) {
            if (!process_blocks()) return false;  // deliver what the peer sent before FIN
            return fail(CloseReason::PeerClosed);
        }
        if (r.status == Link::Status::Error)      return fail(link_->error_reason());
        if (r.status == Link::Status::WouldBlock) break;

        rx_.commit(r.bytes);
        if (!process_blocks()) return false;

        if (r.bytes < into.size()) break;  // link drained
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
    // Finish the transport-level connect (a non-blocking TCP connect, or a Syn
    // that has just been acknowledged), then begin the handshake.
    if (state_ == ConnState::Connecting) {
        if (!link_->connect_completed()) {
            LOG_DEBUG("connection", "Peer " << id_ << " connect failed");
            return fail(CloseReason::ConnectFailed);
        }
        begin_handshake();
        if (state_ == ConnState::Closing) return false;
    }
    return flush();
}

bool Connection::on_error() {
    return fail(link_->error_reason());
}

// ── Send buffer flush + write interest ──────────────────────────────────────

bool Connection::flush() {
    while (!tx_.empty()) {
        // Hand the whole backlog to the kernel at once: a burst of queued frames
        // (and the length prefix that precedes each one) leaves in a single syscall
        // instead of one per chunk.
        ByteView slices[kMaxSendSlices];
        const size_t count = tx_.gather(slices, kMaxSendSlices);

        const Link::IoResult r = link_->write(slices, count);
        if (r.status == Link::Status::Ok) { tx_.pop_front(r.bytes); continue; }
        if (r.status == Link::Status::WouldBlock) break;  // retry on the next writable event
        return fail(link_->error_reason());
    }

    if (tx_.empty()) disarm_write();
    else             arm_write();

    // Drained back under the mark: whoever was told to stop can start again. The
    // re-entrancy guard is what keeps a handler that answers by sending from
    // recursing through flush() — it may queue, and the next drain reports the
    // next opening, but it cannot nest.
    if (over_low_water_ && !in_writable_ && backlog() <= send_low_water_) {
        over_low_water_ = false;
        in_writable_    = true;
        delegate_.on_writable_changed(*this, true);
        in_writable_    = false;
    }
    return true;
}

void Connection::arm_write() {
    if (want_write_) return;
    want_write_ = true;
    link_->want_write(true);
}

void Connection::disarm_write() {
    if (!want_write_) return;
    want_write_ = false;
    link_->want_write(false);
}

bool Connection::fail(CloseReason reason) {
    close_reason_ = reason;
    state_ = ConnState::Closing;
    return false;  // tells the reactor to tear this connection down
}

} // namespace librats
